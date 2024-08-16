//! an upstream tap device

use std::{
    borrow::Cow,
    fmt::Debug,
    fs::File,
    io::{self, IoSlice, Read, Write},
    os::fd::AsRawFd,
    sync::Arc,
};

use crate::net::{router::RouterTx, NetworkError};

use flume::{Receiver, Sender};
use mio::{unix::SourceFd, Events, Interest, Poll, Token, Waker};
use nix::{
    libc::{IFF_NO_PI, IFF_TAP, IFNAMSIZ, SIOCGIFHWADDR},
    net::if_::if_nametoindex,
};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use shadesmar_net::{types::Ipv4Network, Ipv4Packet};
use uuid::Uuid;

use super::{Wan, WanStats, WanThreadHandle, WanTx};

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

pub struct TunTap {
    /// Name of the tun device
    name: String,

    /// Opened file descriptor to the device
    fd: Arc<Mutex<File>>,

    /// Index of the device
    idx: u32,

    /// IPv4 address / network (cidr) assigned to the device
    ipv4: Ipv4Network,
}

pub struct TunTapHandle {
    tx: Sender<Ipv4Packet>,
    waker: Arc<Waker>,
}

// ifreq is 40 bytes long
#[repr(C)]
#[derive(Default)]
struct IfReqCreateTun {
    ifrn_name: [u8; IFNAMSIZ], // 16 is IFNAMSIZ from linux/if.h
    ifru_flags: u16,
    padding: [u8; 22],
}

impl TunTap {
    /// Creates a new tap device
    ///
    /// Note: This requires administration privileges or CAP_NET_ADMIN
    pub fn create_tap(cfg: TapConfig) -> Result<Self, NetworkError> {
        Self::create(cfg.device, IFF_TAP, cfg.ipv4)
    }

    fn create(name: String, flags: i32, ipv4: Ipv4Network) -> Result<Self, NetworkError> {
        // #define TUNSETIFF _IOW('T', 202, int)
        nix::ioctl_write_int!(tunsetiff, b'T', 202);

        // #define TUNSETPERSIST _IOW('T', 203, int)
        //nix::ioctl_write_int!(tunsetpersist, b'T', 203);

        // #define SIOCGIFHWADDR 0x8927
        nix::ioctl_read_bad!(siocgifhwaddr, SIOCGIFHWADDR, nix::libc::ifreq);

        let len = name.len();
        if len > IFNAMSIZ {
            return Err(NetworkError::Generic(Cow::Owned(format!(
                "device name ({name}) is too long, max length is {IFNAMSIZ}, provided length {len}",
            ))))?;
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
        let fd = Arc::new(Mutex::new(fd));
        /*
        let mac = match flags {
            IFF_TAP => MacAddress::from_interface(&name)?,
            _ => MacAddress::generate(),
        };
        */

        Ok(Self {
            name,
            fd,
            idx,
            ipv4,
        })
    }
}

impl Debug for TunTap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Tun({:02}:{})", self.idx, self.name)
    }
}

impl Wan for TunTap {
    fn spawn(
        &self,
        _id: Uuid,
        router: RouterTx,
        _stats: WanStats,
    ) -> Result<super::WanThreadHandle, NetworkError> {
        let poll = Poll::new()?;
        let waker = Waker::new(poll.registry(), TOKEN_WRITE)?;

        let (tx, rx) = flume::unbounded();
        let handle = TunTapHandle {
            tx,
            waker: Arc::new(waker),
        };

        let thread = std::thread::Builder::new()
            .name(String::from("wan-tap"))
            .spawn({
                let device = Arc::clone(&self.fd);
                move || {
                    if let Err(error) = run(device, poll, router, rx, _stats) {
                        tracing::error!(%error, "tuntap thread crashed");
                    }
                }
            })?;

        Ok(WanThreadHandle::new(thread, handle))
    }

    fn masquerade_ipv4(&self) -> Option<std::net::Ipv4Addr> {
        Some(self.ipv4.ip())
    }
}

fn run(
    device: Arc<Mutex<File>>,
    mut poll: Poll,
    _router: RouterTx,
    rx: Receiver<Ipv4Packet>,
    _stats: WanStats,
) -> Result<(), NetworkError> {
    let mut events = Events::with_capacity(MAX_EVENTS_CAPACITY);
    let mut device = device.lock();

    poll.registry().register(
        &mut SourceFd(&device.as_raw_fd()),
        TOKEN_READ,
        Interest::READABLE,
    )?;

    loop {
        poll.poll(&mut events, None)?;

        for event in &events {
            match event.token() {
                TOKEN_READ => match read_from_device(&mut *device) {
                    Ok(_) => (),
                    Err(error) => {
                        tracing::warn!(?error, "[upstream] unable to read from tun device")
                    }
                },
                TOKEN_WRITE => {
                    for pkt in rx.drain() {
                        match write_to_device(&mut *device, pkt) {
                            Ok(()) => {
                                tracing::trace!("[upstream] wrote ipv4 packet to tun device")
                            }
                            Err(error) => {
                                tracing::error!(?error, "[upstream] unable to write to tun device")
                            }
                        }
                    }
                }
                Token(token) => tracing::trace!(token, "[tap] unknown mio token"),
            }
        }
    }
}

fn read_from_device<R: Read>(rdr: &mut R) -> io::Result<()> {
    let mut buf = [0u8; 1024];
    let sz = rdr.read(&mut buf)?;
    tracing::trace!("[tap] read {sz} bytes");
    Ok(())
}

fn write_to_device<W: Write>(wr: &mut W, pkt: Ipv4Packet) -> io::Result<()> {
    let iovs = [IoSlice::new(pkt.as_bytes())];
    let sz = wr.write_vectored(&iovs)?;

    tracing::trace!("[tap] wrote {sz} bytes");

    Ok(())
}

impl WanTx for TunTapHandle {
    fn write(&self, pkt: Ipv4Packet) -> Result<(), NetworkError> {
        self.tx.send(pkt).ok();
        self.waker.wake().ok();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use shadesmar_net::types::Ipv4Network;

    use super::{TapConfig, TunTap};

    #[test]
    fn open_tap() {
        let cfg = TapConfig {
            device: String::from("oathgate1"),
            ipv4: Ipv4Network::new(Ipv4Addr::new(10, 11, 12, 13), 24),
        };

        TunTap::create_tap(cfg).expect("unable to open tap");
    }
}
