//! Linux TAP WAN plugin

use std::{
    fmt::Debug,
    fs::File,
    io::{ErrorKind, IoSlice, IoSliceMut, Read, Write},
    net::Ipv4Addr,
    os::{fd::AsRawFd, unix::fs::OpenOptionsExt},
    sync::Arc,
    thread::JoinHandle,
};

use anyhow::{anyhow, Context, Result};
use flume::{Receiver, Sender};
use mio::{event::Event, unix::SourceFd, Events, Interest, Poll, Token, Waker};
use nix::{
    libc::{IFF_NO_PI, IFF_TAP, IFF_TUN, IFF_VNET_HDR, IFNAMSIZ, O_NONBLOCK, TUN_F_CSUM},
    net::if_::if_nametoindex,
};
use serde::{Deserialize, Serialize};
use shadesmar_core::{
    ipv4::{ChecksumFlags, Ipv4Packet, Ipv4PacketMut, MutableIpv4Packet},
    nat::NatTable,
    plugins::{WanCallback, WanPluginConfig},
    protocols::{NET_PROTOCOL_TCP, NET_PROTOCOL_UDP},
    types::{
        buffers::{PacketBuffer, PacketBufferPool},
        EtherType, Ipv4Network, MacAddress,
    },
    EthernetFrame,
};
use uuid::Uuid;

/// Maximum number of events mio can processes at one time
const MAX_EVENTS_CAPACITY: usize = 10;

/// Tokens / handles for mio sources
const TOKEN_READ: Token = Token(0);
const TOKEN_WRITE: Token = Token(1);

#[derive(Copy, Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum TunTapType {
    Tun,
    Tap,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TunTapConfig {
    pub mode: TunTapType,
    pub device: String,
    pub ipv4: Ipv4Network,
}

pub enum TunTapMessage {
    Quit,
    Data(PacketBuffer),
}

pub struct TunTapDevice {
    /// Unique WAN id
    id: Uuid,

    /// Name of the tun device
    name: String,

    /// Type of device
    ty: TunTapType,

    /// Opened file descriptor to the device
    fd: File,

    /// Index of the device
    idx: u32,

    /// IPv4 address / network (cidr) assigned to the device
    ipv4: Ipv4Addr,

    /// MAC address assigned to the device
    mac: MacAddress,
}

pub struct TunTapHandle {
    tx: Sender<TunTapMessage>,
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

#[repr(C)]
#[derive(Default, Debug)]
struct VirtioNetHdr {
    flags: u8,
    gso_type: u8,
    hdr_len: u16,
    gso_size: u16,
    csum_start: u16,
    csum_offset: u16,
    num_buffers: u16,
}

impl TunTapDevice {
    /// Opens a previously created TAP device
    ///
    /// ### Arguments
    /// * `cfg` - WAN configuration
    pub fn new(cfg: WanPluginConfig<TunTapConfig>) -> anyhow::Result<Self> {
        let tap = Self::open(cfg.id, cfg.device.device, cfg.device.mode, cfg.device.ipv4)?;
        Ok(tap)
    }

    pub fn run(&self, callback: WanCallback) -> anyhow::Result<TunTapHandle> {
        let poll = Poll::new()?;
        let waker = Waker::new(poll.registry(), TOKEN_WRITE)?;

        let (tx, rx) = flume::unbounded();

        let thread = std::thread::Builder::new()
            .name(String::from("wan-tap"))
            .spawn({
                let device = self.fd.try_clone()?;
                let id = self.id;
                let mac = self.mac;
                let ip = self.ipv4;
                let ty = self.ty;

                move || {
                    if let Err(error) = run(id, ty, mac, ip, device, poll, callback, rx) {
                        tracing::error!(%error, "tuntap thread crashed");
                    }
                }
            })?;

        let handle = TunTapHandle {
            tx,
            waker: Arc::new(waker),
            thread,
        };

        Ok(handle)
    }

    fn open(wan_id: Uuid, name: String, ty: TunTapType, ipv4: Ipv4Network) -> Result<Self> {
        // The following ioctls are set in "include/uapi/linux/if_tun.h"
        // #define TUNSETIFF _IOW('T', 202, int)
        // #define TUNSETOFFLOAD _IOW('T', 208, unsigned int)
        // #define TUNSETVNETHDRSZ _IOW('T', 216, int)
        // #define TUNSETPERSIST _IOW('T', 203, int)
        nix::ioctl_write_int!(tunsetiff, b'T', 202);
        nix::ioctl_write_int!(tunsetoffload, b'T', 208);
        nix::ioctl_write_int!(tunsetvnethdrsz, b'T', 216);
        //nix::ioctl_write_int!(tunsetpersist, b'T', 203);

        let len = name.len();
        if len > IFNAMSIZ {
            return Err(anyhow!(
                "device name ({name}) is too long, max length is {IFNAMSIZ}, provided length {len}",
            ))?;
        }

        let flags = match ty {
            TunTapType::Tap => IFF_TAP,
            TunTapType::Tun => IFF_TUN,
        };
        let flags = flags | IFF_NO_PI | IFF_VNET_HDR;

        let mut ifreq = IfReqCreateTun::default();
        let len = std::cmp::min(IFNAMSIZ, len);
        ifreq.ifrn_name[0..len].copy_from_slice(&name.as_bytes()[0..len]);
        ifreq.ifru_flags = flags as u16;

        // Create TUN/TAP via ioctls
        let fd = File::options()
            .read(true)
            .write(true)
            .custom_flags(O_NONBLOCK)
            .open("/dev/net/tun")?;

        let vnet_hdr_sz = VirtioNetHdr::size();
        unsafe {
            tunsetiff(fd.as_raw_fd(), (&ifreq as *const _) as u64)?;
            tunsetvnethdrsz(fd.as_raw_fd(), (&vnet_hdr_sz as *const _) as u64)?;
            tunsetoffload(fd.as_raw_fd(), TUN_F_CSUM as u64)?;
            //tunsetpersist(fd.as_raw_fd(), 0x1)?;
        };

        let idx = if_nametoindex(&name.as_bytes()[..len])?;
        let mac = MacAddress::from_interface(&name)?;
        //let ipv4 = Self::get_ipv4(&name)?;
        let ipv4 = ipv4.ip();

        Ok(Self {
            id: wan_id,
            name,
            ty,
            fd,
            idx,
            ipv4,
            mac,
        })
    }
}

impl Debug for TunTapDevice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "TapDevice {{ idx: {:02}, name: {}, ip: {} }}",
            self.idx, self.name, self.ipv4
        )
    }
}

impl TunTapHandle {
    pub fn write(&self, data: &[u8]) {
        let buffer = PacketBufferPool::copy(data);
        self.send_message(TunTapMessage::Data(buffer));
    }

    pub fn stop(self) -> Result<()> {
        self.send_message(TunTapMessage::Quit)
            .and_then(|_| self.thread.join().ok());

        Ok(())
    }

    fn send_message(&self, msg: TunTapMessage) -> Option<()> {
        self.tx.send(msg).ok().and_then(|_| self.waker.wake().ok())
    }
}

impl VirtioNetHdr {
    pub const fn size() -> usize {
        std::mem::size_of::<Self>()
    }

    pub fn as_bytes(&self) -> [u8; Self::size()] {
        let mut data = [0u8; Self::size()];
        data[0] = self.flags;
        data[1] = self.gso_type;
        data[2..4].copy_from_slice(&self.hdr_len.to_le_bytes());
        data[4..6].copy_from_slice(&self.gso_size.to_le_bytes());
        data[6..8].copy_from_slice(&self.csum_start.to_le_bytes());
        data[8..10].copy_from_slice(&self.csum_offset.to_le_bytes());
        data
    }
}

fn run(
    wan_id: Uuid,
    ty: TunTapType,
    mac: MacAddress,
    ip: Ipv4Addr,
    mut device: File,
    mut poll: Poll,
    callback: WanCallback,
    rx: Receiver<TunTapMessage>,
) -> Result<()> {
    let _span = tracing::info_span!("tap device run", %wan_id, ?device).entered();
    let mut events = Events::with_capacity(MAX_EVENTS_CAPACITY);
    let mut nat = NatTable::new();

    poll.registry().register(
        &mut SourceFd(&device.as_raw_fd()),
        TOKEN_READ,
        Interest::READABLE,
    )?;

    'poll: loop {
        poll.poll(&mut events, None)?;

        for event in &events {
            let res = handle_event(
                wan_id,
                ty,
                mac,
                ip,
                event,
                &mut device,
                &rx,
                &mut nat,
                &callback,
            );

            match res {
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
    ty: TunTapType,
    mac: MacAddress,
    ip: Ipv4Addr,
    event: &Event,
    device: &mut File,
    rx: &Receiver<TunTapMessage>,
    nat: &mut NatTable,
    callback: &WanCallback,
) -> Result<bool> {
    let _span = tracing::warn_span!("handle event", ?event).entered();

    match event.token() {
        TOKEN_READ => {
            let _span_write = tracing::info_span!("tun/tap device read event").entered();

            let mut vnet_hdr = [0u8; VirtioNetHdr::size()];
            let mut buffer = PacketBufferPool::with_size(1600);

            'async_read: loop {
                let mut iovs = [IoSliceMut::new(&mut vnet_hdr), IoSliceMut::new(&mut buffer)];
                match device.read_vectored(&mut iovs) {
                    Err(error) if error.kind() == ErrorKind::WouldBlock => {
                        break 'async_read;
                    }
                    Err(error) => Err(error).context("tun/tap read failed")?,
                    Ok(0) => tracing::warn!("read 0 bytes from tun/tap device, did it close?"),
                    Ok(sz) if sz < VirtioNetHdr::size() => tracing::warn!(
                        "read {sz} bytes, need at least {} for vnet header",
                        VirtioNetHdr::size()
                    ),
                    Ok(sz) => {
                        let sz = sz - VirtioNetHdr::size();
                        tracing::trace!("read {sz} bytes from tun/tap (vnet: {vnet_hdr:02x?})",);
                        buffer.truncate(sz);
                        let mut pkt = match ty {
                            TunTapType::Tap => handle_tap_device_read(&mut buffer)?,
                            TunTapType::Tun => handle_tun_device_read(&mut buffer)?,
                        };

                        tracing::trace!("read ipv4 packet: {pkt:?}");
                        if let Some(ip) = nat.get(&pkt) {
                            pkt.unmasquerade(ip, ChecksumFlags::Full);
                        }

                        callback.exec(wan_id, &buffer);
                    }
                }
            }
        }
        TOKEN_WRITE => {
            let _span_write = tracing::info_span!("tap device write event").entered();
            for msg in rx.drain() {
                match msg {
                    TunTapMessage::Quit => return Ok(true),
                    TunTapMessage::Data(mut pkt) => {
                        let mut ipv4 = Ipv4PacketMut::new(&mut pkt)?;
                        nat.insert(&ipv4);
                        ipv4.masquerade(ip, ChecksumFlags::Partial);

                        tracing::trace!("wrote ipv4 packet: {ipv4:?}");
                        let sz = match ty {
                            TunTapType::Tap => {
                                handle_tap_device_write(mac, ipv4.as_bytes(), device)?
                            }
                            TunTapType::Tun => {
                                handle_tun_device_write(ipv4.protocol(), ipv4.as_bytes(), device)?
                            }
                        };

                        tracing::trace!("wrote {sz} bytes to tap");
                    }
                }
            }
        }
        Token(token) => tracing::trace!(token, "[tap] unknown mio token"),
    }

    Ok(false)
}

fn handle_tap_device_read<'a>(buffer: &'a mut [u8]) -> anyhow::Result<Ipv4PacketMut<'a>> {
    if buffer.len() < 14 {
        return Err(anyhow!(
            "read: missing ethernet frame (only read {} bytes)",
            buffer.len()
        ));
    }

    let frame = EthernetFrame::parse(&buffer)?;
    tracing::trace!("read ethernet frame: {frame:02x?}");

    handle_tun_device_read(&mut buffer[14..])
}

fn handle_tun_device_read<'a>(buffer: &'a mut [u8]) -> anyhow::Result<Ipv4PacketMut<'a>> {
    let pkt = Ipv4PacketMut::new(buffer)?;

    Ok(pkt)
}

fn handle_tap_device_write(
    src: MacAddress,
    data: &[u8],
    device: &mut File,
) -> anyhow::Result<usize> {
    //let dst = MacAddress::from([0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    let dst = MacAddress::from([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
    let frame = EthernetFrame::new(src, dst, EtherType::IPv4);
    let frame = frame.to_bytes();

    let iovs = [IoSlice::new(&frame), IoSlice::new(data)];
    let sz = device.write_vectored(&iovs).context("tap write failed")?;

    Ok(sz)
}

fn handle_tun_device_write(proto: u8, data: &[u8], device: &mut File) -> anyhow::Result<usize> {
    let mut vnet_hdr = VirtioNetHdr::default();

    match proto {
        NET_PROTOCOL_TCP => {
            vnet_hdr.flags = 1;
            vnet_hdr.hdr_len = 40;
            vnet_hdr.csum_start = 20;
            vnet_hdr.csum_offset = 16;
        }
        NET_PROTOCOL_UDP => {
            vnet_hdr.flags = 1;
            vnet_hdr.hdr_len = 28;
            vnet_hdr.csum_start = 20;
            vnet_hdr.csum_offset = 6;
        }
        _ => { /* not an checksum offload protocol */ }
    }

    let vnet_hdr = vnet_hdr.as_bytes();
    tracing::trace!("writing vnet hdr: {vnet_hdr:02x?}");
    tracing::trace!("writing packet: {:02x?}", &data[..28]);

    let iovs = [IoSlice::new(&vnet_hdr), IoSlice::new(data)];

    let sz = device.write_vectored(&iovs).context("tun write failed")?;
    Ok(sz)
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use shadesmar_core::{plugins::WanPluginConfig, types::Ipv4Network};
    use uuid::Uuid;

    use super::{TunTapConfig, TunTapDevice, TunTapType};

    #[test]
    fn open_tap() {
        let cfg = TunTapConfig {
            mode: TunTapType::Tap,
            device: String::from("oathgate1"),
            ipv4: Ipv4Network::new(Ipv4Addr::new(10, 11, 12, 13), 24),
        };

        TunTapDevice::new(WanPluginConfig {
            id: Uuid::now_v7(),
            device: cfg,
        })
        .expect("unable to open tap device");
    }
}
