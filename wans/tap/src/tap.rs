//! Linux TAP WAN plugin

use std::{
    fmt::Debug,
    fs::File,
    io::{IoSlice, Read, Write},
    os::fd::AsRawFd,
    sync::Arc,
    thread::JoinHandle,
};

use anyhow::{anyhow, Result};
use flume::{Receiver, Sender};
use mio::{event::Event, unix::SourceFd, Events, Interest, Poll, Token, Waker};
use nix::{
    libc::{IFF_NO_PI, IFF_TAP, IFNAMSIZ, SIOCGIFHWADDR},
    net::if_::if_nametoindex,
};
use serde::{Deserialize, Serialize};
use shadesmar_core::{
    plugins::{WanCallback, WanPluginConfig},
    types::{
        buffers::{PacketBuffer, PacketBufferPool},
        Ipv4Network,
    },
};
use uuid::Uuid;

/// Maximum number of events mio can processes at one time
const MAX_EVENTS_CAPACITY: usize = 10;

/// Tokens / handles for mio sources
const TOKEN_READ: Token = Token(0);
const TOKEN_WRITE: Token = Token(1);

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TapConfig {
    pub device: String,
    pub ipv4: Ipv4Network,
}

pub enum TapMessage {
    Quit,
    Data(PacketBuffer),
}

pub struct TapDevice {
    /// Unique WAN id
    id: Uuid,

    /// Name of the tun device
    name: String,

    /// Opened file descriptor to the device
    fd: File,

    /// Index of the device
    idx: u32,

    /// IPv4 address / network (cidr) assigned to the device
    ipv4: Ipv4Network,
}

pub struct TapHandle {
    tx: Sender<TapMessage>,
    waker: Arc<Waker>,
    thread: JoinHandle<()>,
}

// ifreq is 40 bytes long
#[repr(C)]
#[derive(Default)]
struct IfReqCreateTun {
    ifrn_name: [u8; IFNAMSIZ], // 16 is IFNAMSIZ from linux/if.h
    ifru_flags: u16,
    padding: [u8; 22],
}

impl TapDevice {
    /// Opens a previously created TAP device
    ///
    /// ### Arguments
    /// * `cfg` - WAN configuration
    pub fn new(cfg: WanPluginConfig<TapConfig>) -> anyhow::Result<Self> {
        let tap = Self::open(cfg.id, cfg.device.device, IFF_TAP, cfg.device.ipv4)?;
        Ok(tap)
    }

    pub fn run(&self, callback: WanCallback) -> anyhow::Result<TapHandle> {
        let poll = Poll::new()?;
        let waker = Waker::new(poll.registry(), TOKEN_WRITE)?;

        let (tx, rx) = flume::unbounded();

        let thread = std::thread::Builder::new()
            .name(String::from("wan-tap"))
            .spawn({
                let device = self.fd.try_clone()?;
                let id = self.id;

                move || {
                    if let Err(error) = run(id, device, poll, callback, rx) {
                        tracing::error!(%error, "tuntap thread crashed");
                    }
                }
            })?;

        let handle = TapHandle {
            tx,
            waker: Arc::new(waker),
            thread,
        };

        Ok(handle)
    }

    fn open(wan_id: Uuid, name: String, flags: i32, ipv4: Ipv4Network) -> Result<Self> {
        // #define TUNSETIFF _IOW('T', 202, int)
        nix::ioctl_write_int!(tunsetiff, b'T', 202);

        // #define TUNSETPERSIST _IOW('T', 203, int)
        //nix::ioctl_write_int!(tunsetpersist, b'T', 203);

        // #define SIOCGIFHWADDR 0x8927
        nix::ioctl_read_bad!(siocgifhwaddr, SIOCGIFHWADDR, nix::libc::ifreq);

        let len = name.len();
        if len > IFNAMSIZ {
            return Err(anyhow!(
                "device name ({name}) is too long, max length is {IFNAMSIZ}, provided length {len}",
            ))?;
        }

        let mut ifreq = IfReqCreateTun::default();
        let len = std::cmp::min(IFNAMSIZ, len);
        ifreq.ifrn_name[0..len].copy_from_slice(&name.as_bytes()[0..len]);
        ifreq.ifru_flags = (flags | IFF_NO_PI) as u16;

        // Create TAP via ioctls
        let fd = File::options()
            .read(true)
            .write(true)
            .open("/dev/net/tun")?;

        unsafe {
            tunsetiff(fd.as_raw_fd(), (&ifreq as *const _) as u64)?;
            //tunsetpersist(fd.as_raw_fd(), 0x1)?;
        };

        let idx = if_nametoindex(&name.as_bytes()[..len])?;
        /*
        let mac = match flags {
            IFF_TAP => MacAddress::from_interface(&name)?,
            _ => MacAddress::generate(),
        };
        */

        Ok(Self {
            id: wan_id,
            name,
            fd,
            idx,
            ipv4,
        })
    }
}

impl Debug for TapDevice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "TapDevice {{ idx: {:02}, name: {}, ip: {} }}",
            self.idx, self.name, self.ipv4
        )
    }
}

impl TapHandle {
    pub fn write(&self, data: &[u8]) {
        let buffer = PacketBufferPool::copy(data);
        self.send_message(TapMessage::Data(buffer));
    }

    pub fn stop(self) -> Result<()> {
        self.send_message(TapMessage::Quit)
            .and_then(|_| self.thread.join().ok());

        Ok(())
    }

    fn send_message(&self, msg: TapMessage) -> Option<()> {
        self.tx.send(msg).ok().and_then(|_| self.waker.wake().ok())
    }
}

fn run(
    wan_id: Uuid,
    mut device: File,
    mut poll: Poll,
    callback: WanCallback,
    rx: Receiver<TapMessage>,
) -> Result<()> {
    let mut events = Events::with_capacity(MAX_EVENTS_CAPACITY);

    poll.registry().register(
        &mut SourceFd(&device.as_raw_fd()),
        TOKEN_READ,
        Interest::READABLE,
    )?;

    'poll: loop {
        poll.poll(&mut events, None)?;

        for event in &events {
            match handle_event(wan_id, event, &mut device, &rx, &callback) {
                Ok(true) => break 'poll,
                Ok(false) => { /* continue / process next event */ }
                Err(error) => {
                    tracing::warn!("unable to handle tap device event: {error:?}");
                }
            }
        }
    }

    Ok(())
}

fn handle_event(
    wan_id: Uuid,
    event: &Event,
    device: &mut File,
    rx: &Receiver<TapMessage>,
    callback: &WanCallback,
) -> Result<bool> {
    let _span = tracing::warn_span!("tap device handle event", %wan_id, ?event).entered();

    match event.token() {
        TOKEN_READ => {
            let mut buffer = PacketBufferPool::with_size(1600);
            let sz = device.read(&mut buffer)?;
            buffer.truncate(sz);
            tracing::debug!("read {sz} bytes from tap");
            tracing::debug!("{:02x?}", &buffer[0..34]);
            callback.exec(wan_id, &buffer);
        }
        TOKEN_WRITE => {
            for msg in rx.drain() {
                match msg {
                    TapMessage::Quit => return Ok(true),
                    TapMessage::Data(pkt) => {
                        let iovs = [IoSlice::new(&pkt)];
                        let sz = device.write_vectored(&iovs)?;

                        tracing::debug!("wrote {sz} bytes to tap");
                        tracing::debug!("{:02x?}", &pkt[0..34]);
                    }
                }
            }
        }
        Token(token) => tracing::trace!(token, "[tap] unknown mio token"),
    }

    Ok(false)
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use shadesmar_core::{plugins::WanPluginConfig, types::Ipv4Network};
    use uuid::Uuid;

    use super::{TapConfig, TapDevice};

    #[test]
    fn open_tap() {
        let cfg = TapConfig {
            device: String::from("oathgate1"),
            ipv4: Ipv4Network::new(Ipv4Addr::new(10, 11, 12, 13), 24),
        };

        TapDevice::new(WanPluginConfig {
            id: Uuid::now_v7(),
            device: cfg,
        })
        .expect("unable to open tap device");
    }
}
