use std::{
    collections::{HashMap, VecDeque},
    fs::File,
    io::{IoSlice, IoSliceMut},
    num::NonZeroUsize,
    os::fd::{AsRawFd, FromRawFd, RawFd},
    sync::Arc,
    usize,
};

use mio::{net::UnixStream, unix::SourceFd, Events, Interest, Poll, Token, Waker};
use nix::{
    errno::Errno,
    sys::{
        mman::{MapFlags, ProtFlags},
        socket::{self, MsgFlags, UnixAddr},
    },
    unistd,
};
use parking_lot::lock_api::Mutex;
use shadesmar_net::{EthernetFrame, EthernetPacket, Switch, SwitchPort};
use vm_memory::{GuestAddress, GuestMemoryAtomic, GuestMemoryMmap, GuestRegionMmap, MmapRegion};

use crate::{
    error::{AppResult, Error, MemoryError, PayloadError},
    queue::VirtQueue,
    types::{
        DeviceRxQueue, GuestMapping, MemoryRegionDescription, VHostHeader,
        VHostUserProtocolFeature, VRingAddr, VRingDescriptor, VRingState, VirtioFeatures,
    },
};

const QUEUE_MAX_SIZE: u16 = 1024;

const VHOST_USER_HEADER_SZ: usize = 12;

const VHOST_USER_GET_FEATURES: u32 = 1;
const VHOST_USER_SET_FEATURES: u32 = 2;
const VHOST_USER_SET_OWNER: u32 = 3;
const VHOST_USER_SET_MEM_TABLE: u32 = 5;
const VHOST_USER_SET_VRING_NUM: u32 = 8;
const VHOST_USER_SET_VRING_ADDR: u32 = 9;
const VHOST_USER_SET_VRING_BASE: u32 = 10;
const VHOST_USER_GET_VRING_BASE: u32 = 11;
const VHOST_USER_SET_VRING_KICK: u32 = 12;
const VHOST_USER_SET_VRING_CALL: u32 = 13;
const VHOST_USER_SET_VRING_ERR: u32 = 14;
const VHOST_USER_GET_PROTOCOL_FEATURES: u32 = 15;
const VHOST_USER_SET_PROTOCOL_FEATURES: u32 = 16;
const VHOST_USER_GET_QUEUE_NUM: u32 = 17;
const VHOST_USER_SET_VRING_ENABLE: u32 = 18;
const VHOST_USER_SET_BACKEND_REQ_FD: u32 = 21;
const VHOST_USER_GET_CONFIG: u32 = 24;
const VHOST_USER_SET_CONFIG: u32 = 25;
const VHOST_USER_GET_MAX_MEM_SLOTS: u32 = 36;
const VHOST_USER_ADD_MEM_REG: u32 = 37;
const VHOST_USER_SET_STATUS: u32 = 39;
const VHOST_USER_GET_STATUS: u32 = 40;

// virtio-net features
// https://docs.oasis-open.org/virtio/virtio/v1.1/cs01/virtio-v1.1-cs01.html#x1-1940001
/// Device handles packets with partial checksum. This “checksum offload” is a common feature on modern network cards.
//const VIRTIO_NET_F_CSUM: u64 = 0x0001;

/// Driver handles packets with partial checksum.
const _VIRTIO_NET_F_GUEST_CSUM: u64 = 0x0002;

/// Control channel offloads reconfiguration support.
const _VIRTIO_NET_F_CTRL_GUEST_OFFLOADS: u64 = 0x0004;

/// Device maximum MTU reporting is supported. If offered by the device, device advises driver about the value of its maximum MTU. If negotiated, the driver uses mtu as the maximum MTU value.
const _VIRTIO_NET_F_MTU: u64 = 0x0008;

/// Device has given MAC address.
const VIRTIO_NET_F_MAC: u64 = 0x0020;

/// Driver can receive TSOv4
const _VIRTIO_NET_F_GUEST_TSO4: u64 = 0x0080;

/// Driver can receive TSOv6.
const _VIRTIO_NET_F_GUEST_TSO6: u64 = 0x0100;

/// Driver can receive TSO with ECN.
const _VIRTIO_NET_F_GUEST_ECN: u64 = 0x0200;

/// Driver can receive UFO.
const _VIRTIO_NET_F_GUEST_UFO: u64 = 0x0400;

/// Device can receive TSOv4.
const _VIRTIO_NET_F_HOST_TSO4: u64 = 0x0800;

/// Device can receive TSOv6.
const _VIRTIO_NET_F_HOST_TSO6: u64 = 0x1000;

/// Device can receive TSO with ECN.
const _VIRTIO_NET_F_HOST_ECN: u64 = 0x2000;

/// Device can receive UFO.
const _VIRTIO_NET_F_HOST_UFO: u64 = 0x4000;

/// Driver can merge receive buffers.
const _VIRTIO_NET_F_MRG_RXBUF: u64 = 0x8000;

/// Configuration status field is available.
const VIRTIO_NET_F_STATUS: u64 = 0x1_0000;

/// Control channel is available.
const _VIRTIO_NET_F_CTRL_VQ: u64 = 0x2_0000;

/// Control channel RX mode support.
const _VIRTIO_NET_F_CTRL_RX: u64 = 0x4_0000;

/// Control channel VLAN filtering.
const _VIRTIO_NET_F_CTRL_VLAN: u64 = 0x8_0000;

/// Driver can send gratuitous packets.
const _VIRTIO_NET_F_GUEST_ANNOUNCE: u64 = 0x20_0000;

/// Device supports multiqueue with automatic receive steering.
const _VIRTIO_NET_F_MQ: u64 = 0x40_0000;

/// Set MAC address through control channel.
const _VIRTIO_NET_F_CTRL_MAC_ADDR: u64 = 0x80_0000;

/// Device can process duplicated ACKs and report number of coalesced segments and duplicated ACKs
const _VIRTIO_NET_F_RSC_EXT: u64 = 0x2000_0000_0000_0000;

/// Device may act as a standby for a primary device with the same MAC address.
const _VIRTIO_NET_F_STANDBY: u64 = 0x4000_0000_0000_0000;

const VHOST_USER_BACKEND_CONFIG_CHANGE_MSG: u32 = 2;

const VHOST_USER_FLAG_VERSION_1: u32 = 0x01;
const VHOST_USER_FLAG_REPLY: u32 = 0x04;

const TOKEN_STRM: Token = Token(0);
const TOKEN_WAKE: Token = Token(1);

/// Helper trait to convert from a slice of bytes into a vhost-user payload type
pub trait TryFromPayload: Sized {
    /// Converts from a slice of bytes into a type, erroring if there is
    /// not enough data.
    ///
    /// ### Arguments
    /// * `pkt` - Data to parse to form the type
    fn try_from_payload(pkt: &[u8]) -> Result<Self, PayloadError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KickFd {
    Rx(RawFd, usize),
    Tx(RawFd, usize),
}

/// A VirtioDevice is the Virio device that will respond to the virtio-host-net driver
/// running in the Qemu VM.
pub struct VirtioDevice<S> {
    /// Instance of mio poller
    poll: Poll,

    /// The backend request channel (used to send messages to the front end)
    channel: Option<File>,

    /// All virtqueues/vrings current running
    queues: Vec<VirtQueue<S>>,

    /// Mapping of guest physical memory address to hypervisor virtual addresses
    mappings: Vec<GuestMapping>,

    /// Current status of the device
    status: u64,

    /// Number of Tx/Rx virtqueue pairs
    num_queues: u64,

    /// Mapping of tokens to kick file descriptors
    kick_fds: HashMap<Token, KickFd>,

    /// Port on the router this device is connected to
    router_port: usize,
}

#[derive(Clone, Debug)]
pub struct VirtioDeviceRxQueue {
    queue: DeviceRxQueue,
    waker: Arc<Waker>,
}

#[derive(Clone, Debug)]
pub struct DeviceOpts {
    /// Number of transmit/receive queue pairs to create
    pub device_queues: u8,
}

impl Default for DeviceOpts {
    fn default() -> Self {
        Self { device_queues: 1 }
    }
}

impl VirtioDeviceRxQueue {
    /// Returns a handle to the underlying packet queue
    pub fn queue(&self) -> DeviceRxQueue {
        Arc::clone(&self.queue)
    }
}

impl SwitchPort for VirtioDeviceRxQueue {
    /// Human-friendly description (type) of switch port
    fn desc(&self) -> &'static str {
        "virtio"
    }

    /// Puts a packet into the queue and notifies the device
    ///
    /// ### Arguments
    /// * `pkt` - Packet to send to the device
    fn enqueue(&self, frame: EthernetFrame, pkt: Vec<u8>) {
        let mut queue = self.queue.lock();
        queue.push_back(EthernetPacket::new(frame, pkt));
        drop(queue);
        self.waker.wake().ok();
    }
}

impl<S: Switch + 'static> VirtioDevice<S> {
    /// Creates a new VirtioDevice with the requested number of tx/rx virtqueue pairs
    ///
    /// ### Arguments
    /// * `num_queues` - Number of trasmit/receive virtqueue pairs for thsi device
    pub fn new(switch: S, opts: DeviceOpts) -> AppResult<Self> {
        let poll = Poll::new()?;
        let waker = Waker::new(poll.registry(), TOKEN_WAKE)?;
        let rx = VirtioDeviceRxQueue {
            queue: Arc::new(Mutex::new(VecDeque::new())),
            waker: Arc::new(waker),
        };

        // for a net device, we need pairs of queues for transmit and received:
        // 0: receive0
        // 1: transmit0
        let txrx_queues: usize = (opts.device_queues * 2) as usize;

        let mut queues = Vec::with_capacity(txrx_queues);
        for _ in 0..txrx_queues {
            queues.push(VirtQueue::new(QUEUE_MAX_SIZE, switch.clone(), rx.queue())?);
        }

        let router_port = switch.connect(rx);

        Ok(Self {
            poll,
            channel: None,
            queues,
            mappings: Vec::new(),
            status: 0,
            num_queues: opts.device_queues.into(),
            kick_fds: HashMap::new(),
            router_port,
        })
    }

    pub fn spawn(mut self, strm: UnixStream) -> AppResult<()> {
        std::thread::Builder::new()
            .name(String::from("oathgate-device"))
            .spawn(move || {
                if let Err(error) = self.run(strm) {
                    tracing::warn!(?error, "unable to run device thread");
                }
            })?;
        Ok(())
    }

    pub fn run(&mut self, mut strm: UnixStream) -> AppResult<()> {
        self.poll
            .registry()
            .register(&mut strm, TOKEN_STRM, Interest::READABLE)?;

        let mut buffer = [0u8; 4096];
        let mut events = Events::with_capacity(1024);
        loop {
            self.poll.poll(&mut events, None)?;

            for event in &events {
                match event.token() {
                    TOKEN_STRM => {
                        let raw_fd = strm.as_raw_fd();
                        'read: loop {
                            match self.read_stream(raw_fd) {
                                Ok(_) => { /* success, do nothing */ }
                                Err(Error::Errno(Errno::EWOULDBLOCK)) => {
                                    // no more data, stop the loop
                                    break 'read;
                                }
                                Err(e) => Err(e)?,
                            }
                        }
                    }
                    TOKEN_WAKE => {
                        let vq = self.get_virtqueue_mut(0)?;
                        vq.handle_rx_queued()?;
                    }
                    token => match self.kick_fds.get(&token) {
                        Some(KickFd::Rx(fd, vq)) => {
                            let sz = unistd::read(*fd, &mut buffer)?;
                            let pkt = &buffer[..sz];
                            tracing::trace!(sz, "[vq][{vq:02x}] read from driver (rx)");
                            tracing::trace!("[vq][{vq:02x}] data: {pkt:x?}");

                            let vq = self.get_virtqueue_mut(*vq)?;
                            vq.kick_rx(&pkt)?;
                        }
                        Some(KickFd::Tx(fd, vq)) => {
                            let sz = unistd::read(*fd, &mut buffer)?;
                            let pkt = &buffer[..sz];
                            tracing::trace!(sz, "[vq][{vq:02x}] read from driver (tx)");
                            tracing::trace!("[vq][{vq:02x}] data: {pkt:x?}");

                            let port = self.router_port;
                            let vq = self.get_virtqueue_mut(*vq)?;
                            vq.kick_tx(&pkt, port)?;
                        }
                        None => tracing::trace!(?token, "[device] unknown mio token"),
                    },
                }
            }
        }
    }

    fn read_stream(&mut self, strm: RawFd) -> AppResult<()> {
        tracing::trace!("reading unix control stream");

        // first read the header
        let mut hdr = {
            let mut hdr = [0u8; 12];
            let mut cmsgs = nix::cmsg_space!([RawFd; 1]);
            let mut iovs = [IoSliceMut::new(&mut hdr)];
            let rmsg =
                socket::recvmsg::<()>(strm, &mut iovs, Some(&mut cmsgs), MsgFlags::MSG_DONTWAIT)?;

            match rmsg.iovs().count() {
                1 => {
                    let ancillary = rmsg.cmsgs()?.collect::<VecDeque<_>>();
                    VHostHeader::parse(&hdr, ancillary)
                }
                _ => {
                    return Err(Error::HeaderMissing);
                }
            }
        };

        if hdr.sz > 0 {
            tracing::trace!(sz = hdr.sz, "attempt to read payload");
            // if there is a payload, read the payload
            let mut pkt = vec![0u8; hdr.sz as usize];
            socket::recvmsg::<UnixAddr>(
                strm,
                &mut [IoSliceMut::new(&mut pkt)],
                None,
                MsgFlags::MSG_DONTWAIT,
            )?;

            hdr.set_payload(pkt);
        }

        self.parse_msg(strm, hdr)?;

        Ok(())
    }

    fn parse_msg(&mut self, strm: RawFd, mut hdr: VHostHeader) -> AppResult<()> {
        if hdr.ack_required() {
            tracing::trace!(ty = hdr.ty, "ack required");
        }

        match hdr.ty {
            VHOST_USER_GET_FEATURES => {
                // Request Type: None
                // Reply Type: u64
                // Ancillary Data: None
                //
                // Get from the underlying vhost implementation the features bitmask.
                // Feature bit VHOST_USER_F_PROTOCOL_FEATURES signals back-end support for
                // VHOST_USER_GET_PROTOCOL_FEATURES and VHOST_USER_SET_PROTOCOL_FEATURES.
                let payload = VirtioFeatures::RING_VERSION_1 | VirtioFeatures::PROTOCOL_FEATURES;
                let payload = payload.bits() | VIRTIO_NET_F_MAC | VIRTIO_NET_F_STATUS;
                tracing::trace!("[get-features] sending virtio features: 0x{:08x}", payload);
                self.send_response(strm, hdr.ty, &payload.to_le_bytes())?;
            }
            VHOST_USER_SET_FEATURES => {
                // Request Type: u64
                // Reply Type: None
                // Ancillary Data: None
                //
                // Enable features in the underlying vhost implementation using a bitmask.
                // Feature bit VHOST_USER_F_PROTOCOL_FEATURES signals back-end support for
                // VHOST_USER_GET_PROTOCOL_FEATURES and VHOST_USER_SET_PROTOCOL_FEATURES.
                let features: u64 = hdr.payload()?;
                tracing::trace!("[set-features] 0x{:08x}", features);
            }
            VHOST_USER_GET_PROTOCOL_FEATURES => {
                // Request Type: None
                // Reply Type: u64
                // Ancillary Data: None
                //
                // Get the protocol feature bitmask from the underlying vhost implementation.
                //
                // Only legal if feature bit VHOST_USER_F_PROTOCOL_FEATURES is present in VHOST_USER_GET_FEATURES.
                // It does not need to be acknowledged by VHOST_USER_SET_FEATURES.
                //
                // **Back-ends that report VHOST_USER_F_PROTOCOL_FEATURES must support this message
                // even before VHOST_USER_SET_FEATURES was called.**
                let payload = VHostUserProtocolFeature::BACKEND_REQ
                    | VHostUserProtocolFeature::CONFIG
                    | VHostUserProtocolFeature::RESET_DEVICE
                    | VHostUserProtocolFeature::DEVICE_STATE
                    | VHostUserProtocolFeature::STATUS;
                tracing::trace!("[get-protocol-features] 0x{:08x}", payload);
                self.send_response(strm, hdr.ty, &payload.bits().to_le_bytes())?
            }
            VHOST_USER_SET_PROTOCOL_FEATURES => {
                // Request Type: u64
                // Reply Type: None
                // Ancillary Data: None
                //
                // Enable protocol features in the underlying vhost implementation.
                //
                // Only legal if feature bit VHOST_USER_F_PROTOCOL_FEATURES is present in VHOST_USER_GET_FEATURES.
                // It does not need to be acknowledged by VHOST_USER_SET_FEATURES.
                //
                // **Back-ends that report VHOST_USER_F_PROTOCOL_FEATURES must support this message
                // even before VHOST_USER_SET_FEATURES was called.**
                let features: u64 = hdr.payload()?;
                tracing::trace!("[set-protocol-features] 0x{:08x}", features);
            }
            VHOST_USER_GET_QUEUE_NUM => {
                // Request Type: None
                // Reply Type: u64
                // Ancillary Data: None
                //
                // Returns the number of queues supported
                self.send_response(strm, hdr.ty, &self.num_queues.to_le_bytes())?;
            }
            VHOST_USER_SET_BACKEND_REQ_FD => {
                // Request Type: None
                // Reply Type: None
                // Ancillary Data: 1x File Descriptor
                //
                // Set the socket file descriptor for back-end initiated requests
                let fd = hdr.extract_fd()?;
                tracing::trace!("[set-backend-fd] {fd:?}");
                let file = unsafe { File::from_raw_fd(fd) };
                self.channel = Some(file);

                if hdr.ack_required() {
                    let payload: u64 = 0;
                    self.send_response(strm, hdr.ty, &payload.to_le_bytes())?;
                }
            }
            VHOST_USER_GET_MAX_MEM_SLOTS => {
                // Request Type: None
                // Reply Type: u64
                // Ancillary Data: None
                // Required Protocol Feature: VHOST_USER_PROTOCOL_F_CONFIGURE_MEM_SLOTS
                //
                // Returns a message with a u64 payload containing the maximum number
                // of memory slots for QEMU to expose to the guest
                let payload: u64 = 0x02;
                self.send_response(strm, hdr.ty, &payload.to_le_bytes())?
            }
            VHOST_USER_SET_VRING_ENABLE => {
                // Request Type: VRingState
                // Reply Type: None
                // Ancillary Data: None
                // Required Feature: VHOST_USER_F_PROTOCOL_FEATURES
                //
                // Signal the back-end to enable or disable corresponding vring.
                // This request should be sent only when VHOST_USER_F_PROTOCOL_FEATURES
                // has been negotiated.
                let state: VRingState = hdr.payload()?;
                tracing::trace!(?state, "enabling vring");
                let vring = self.get_virtqueue_mut(state.index as usize)?;
                vring.set_enabled();
            }
            VHOST_USER_SET_OWNER => {
                // Request Type: None
                // Reply Type: None
                // Ancillary Data: None
                // Required Feature: VHOST_USER_F_PROTOCOL_FEATURES
                //
                // Issued when a new connection is established. It marks the sender as the
                // front-end that owns of the session. This can be used on the back-end as
                // a “session start” flag.
                tracing::trace!("[set-owner] starting session");
                self.send_msg(VHOST_USER_BACKEND_CONFIG_CHANGE_MSG, &[])?;
            }
            VHOST_USER_SET_VRING_CALL => {
                // Request Type: u64
                // Reply Type: None
                // Ancillary Data: 1x File Descriptor
                // Required Feature: None
                //
                // Set the event file descriptor to signal when buffers are used.
                // It is passed in the ancillary data.
                //
                // Bits (0-7) of the payload contain the vring index. Bit 8 is the invalid FD flag.
                // This flag is set when there is no file descriptor in the ancillary data. This
                // signals that polling will be used instead of waiting for the call
                let vring_idx: u64 = hdr.payload()?;
                let fd = hdr.extract_fd()?;
                tracing::trace!(fd, "[vring][{vring_idx:02x}] set call fd");

                let vring = self.get_virtqueue_mut(vring_idx as usize)?;
                vring.set_call_fd(fd);
            }
            VHOST_USER_SET_VRING_ERR => {
                // Request Type: u64
                // Reply Type: None
                // Ancillary Data: 1x File Descriptor
                // Required Feature: None
                //
                // Set the event file descriptor to signal when error occurs.
                // It is passed in the ancillary data.
                //
                // Bits (0-7) of the payload contain the vring index. Bit 8 is the invalid FD flag.
                // This flag is set when there is no file descriptor in the ancillary data. This
                // signals that polling will be used instead of waiting for the call

                let vring_idx: u64 = hdr.payload()?;
                let fd = hdr.extract_fd()?;
                tracing::trace!(fd, "[vring][{vring_idx:02x}] set error fd");

                let vring = self.get_virtqueue_mut(vring_idx as usize)?;
                vring.set_error_fd(fd);
            }
            VHOST_USER_SET_STATUS => {
                // Request Type: u64
                // Reply Type: None
                // Ancillary Data: None
                // Required Protocol Feature: VHOST_USER_PROTOCOL_F_STATUS
                //
                // Status:
                // - 0x01: ACKNOWLEDGE
                // - 0x02: DRIVER
                // - 0x04: DRIVER_OK
                // - 0x08: FEATURES_OK
                // - 0x40: DEVICE_NEEDS_RESET
                // - 0x80: FAILED
                //
                // Receives updated device status as defined in the Virtio specification.
                self.status = hdr.payload()?;
                tracing::trace!("[set-status] 0x{:08x}", self.status);
            }
            VHOST_USER_GET_STATUS => {
                // Request Type: None
                // Reply Type: u64
                // Ancillary Data: None
                // Required Protocol Feature: VHOST_USER_PROTOCOL_F_STATUS
                //
                // Returns the device status as defined in the Virtio specification
                tracing::trace!("returning device status 0x{:08x}", self.status);
                self.send_response(strm, hdr.ty, &self.status.to_le_bytes())?;
            }
            VHOST_USER_SET_VRING_NUM => {
                // Request Type: VRingState
                // Reply Type: None
                // Ancillary Data: None
                // Required Protocol Feature: None
                //
                // Set the size of the queue.
                let state: VRingState = hdr.payload()?;
                tracing::trace!(
                    size = state.num,
                    "[vring][{:02x}] set queue size",
                    state.index
                );
                let vring = self.get_virtqueue_mut(state.index as usize)?;
                vring.set_queue_size(state.num as u16);
            }
            VHOST_USER_SET_VRING_ADDR => {
                // Request Type: VRingAddr
                // Reply Type: None
                // Ancillary Data: None
                // Required Protocol Feature: None
                //
                // Sets the addresses of the different aspects of the vring.
                if self.mappings.is_empty() {
                    return Err(MemoryError::NoMappedMemory)?;
                }

                let addr: VRingAddr = hdr.payload()?;

                let desc = self.compute_guest_address(addr.desc_user_addr)?;
                let avail = self.compute_guest_address(addr.avail_user_addr)?;
                let used = self.compute_guest_address(addr.used_user_addr)?;

                tracing::trace!(
                    "[vring][{:02x}] desc table address: 0x{:08x} -> 0x{:08x}",
                    addr.index,
                    desc,
                    addr.desc_user_addr,
                );
                tracing::trace!(
                    "[vring][{:02x}] avail ring address: 0x{:08x} -> 0x{:08x}",
                    addr.index,
                    avail,
                    addr.avail_user_addr,
                );
                tracing::trace!(
                    "[vring][{:02x}] used ring address: 0{:08x} -> 0x{:08x}",
                    addr.index,
                    used,
                    addr.used_user_addr,
                );

                let vring = self.get_virtqueue_mut(addr.index as usize)?;
                vring.set_queue_addresses(desc, avail, used);
            }
            VHOST_USER_SET_VRING_BASE => {
                // Request Type: VRingDescriptor
                // Reply Type: None
                // Ancillary Data: None
                // Required Protocol Feature: None
                //
                // Sets the next index to use for descriptors in this vring:
                //
                // - For a split virtqueue, sets only the next descriptor index to process in the Available Ring.
                // The device is supposed to read the next index in the Used Ring from the respective vring
                // structure in guest memory.
                //
                // - For a packed virtqueue, both indices are supplied, as they are not explicitly
                // available in memory.
                //
                // Consequently, the payload type is specific to the type of virt queue (a vring descriptor
                // index for split virtqueues vs. vring descriptor indices for packed virtqueues).
                let base: VRingDescriptor = hdr.payload()?;
                tracing::trace!(
                    "[vring][{:02x}] set next avail ring descriptor index to {}",
                    base.index,
                    base.avail
                );

                let vring = self.get_virtqueue_mut(base.index as usize)?;
                vring.set_next_avail(base.avail as u16);
            }
            VHOST_USER_GET_VRING_BASE => {
                // Request Type: vring state description
                // Reply Type: vring descriptor index / indicies
                //
                // Stops the vring and returns the current descriptor index or indices:
                //
                // - For a split virtqueue, returns only the 16-bit next descriptor index to process
                //   in the Available Ring. Note that this may differ from the available ring index
                //   in the vring structure in memory, which points to where the driver will put new
                //   available descriptors. For the Used Ring, the device only needs the next descriptor
                //   index at which to put new descriptors, which is the value in the vring structure in
                //   memory, so this value is not covered by this message.
                //
                // - For a packed virtqueue, neither index is explicitly available to read from memory,
                //   so both indices (as maintained by the device) are returned.
                //
                // Consequently, the payload type is specific to the type of virt queue (a vring descriptor
                // index for split virtqueues vs. vring descriptor indices for packed virtqueues).
                //
                // When and as long as all of a device’s vrings are stopped, it is suspended,
                // see Suspended device state.
                //
                // The request payload’s num field is currently reserved and must be set to 0.
                let state: VRingState = hdr.payload()?;
                tracing::trace!("[vring][{:02x}] stopping", state.index);

                let ((kick, _call, _err), next) = {
                    let vq = self.get_virtqueue_mut(state.index as usize)?;
                    vq.set_not_ready();
                    let fds = vq.clear_fds();
                    let next = vq.get_next_avail();
                    (fds, next)
                };

                if let Some(fd) = kick {
                    self.poll.registry().deregister(&mut SourceFd(&fd))?;
                }

                let resp = VRingDescriptor {
                    index: state.index,
                    avail: u32::from(next),
                };

                self.send_response(strm, hdr.ty, &resp.as_vec())?;
            }
            VHOST_USER_SET_VRING_KICK => {
                // Request Type: u64
                // Reply Type: None
                // Ancillary Data: 1x File Descriptor
                // Required Feature: None
                //
                // Set the event file descriptor for adding buffers to the vring. It is passed
                // in the ancillary data.
                //
                // Bits (0-7) of the payload contain the vring index. Bit 8 is the invalid FD flag.
                // This flag is set when there is no file descriptor in the ancillary data.
                // This signals that polling should be used instead of waiting for the kick
                let vring_idx: u64 = hdr.payload()?;
                let fd = hdr.extract_fd()?;
                tracing::trace!("[vring][{vring_idx:02x}] starting");

                let vring = self.get_virtqueue_mut(vring_idx as usize)?;
                vring.set_kick_fd(fd);

                let token = Token(fd.as_raw_fd() as usize);
                self.poll
                    .registry()
                    .register(&mut SourceFd(&fd), token, Interest::READABLE)?;

                let fd = match vring_idx & 1 == 0 {
                    true => KickFd::Rx(fd, vring_idx as usize),
                    false => KickFd::Tx(fd, vring_idx as usize),
                };
                self.kick_fds.insert(token, fd);
            }
            VHOST_USER_SET_MEM_TABLE => {
                // Request Type: Multiple Memory Region Descriptions
                // Reply Type:(postcopy only) multiple memory regions description
                // Ancillary Data: Vec<File Descriptor>
                // Required Feature: None
                //
                // Sets the memory map regions on the back-end so it can translate the vring addresses.
                // In the ancillary data there is an array of file descriptors for each memory mapped region.
                // The size and ordering of the fds matches the number and ordering of memory regions.
                let region_descs: Vec<MemoryRegionDescription> = hdr.payload()?;
                let files = hdr.extract_fds()?;

                if region_descs.len() != files.len() {
                    return Err(Error::InvalidMessage("set_mem_table: region / fd mismatch"));
                }

                let mut regions = Vec::with_capacity(region_descs.len());
                for (region, fd) in region_descs.iter().zip(files) {
                    tracing::trace!(
                        "[set-mem-table] guest address: 0x{:08x} -> 0x{:08x}",
                        region.guest_address,
                        region.guest_address + region.size,
                    );
                    tracing::trace!(
                        "[set-mem-table] host address: 0x{:08x} -> 0x{:08x}",
                        region.user_address,
                        region.user_address + region.size,
                    );

                    let file = unsafe { File::from_raw_fd(fd) };

                    let mmr = unsafe {
                        let addr = NonZeroUsize::try_from(region.user_address as usize).unwrap();
                        let sz = NonZeroUsize::try_from(region.size as usize).unwrap();

                        let prot = ProtFlags::PROT_WRITE | ProtFlags::PROT_READ;
                        let flags = MapFlags::MAP_SHARED | MapFlags::MAP_NORESERVE;

                        let ptr = nix::sys::mman::mmap(
                            Some(addr),
                            sz,
                            prot,
                            flags,
                            file,
                            region.mmap_offset as i64,
                        )?;

                        MmapRegion::<()>::build_raw(
                            ptr.as_ptr() as *mut u8,
                            region.size as usize,
                            prot.bits(),
                            flags.bits(),
                        )
                    }?;

                    let gm = GuestRegionMmap::new(mmr, GuestAddress(region.guest_address))?;

                    let mapping =
                        GuestMapping::new(region.user_address, region.guest_address, region.size);
                    self.mappings.push(mapping);
                    regions.push(gm);
                }

                let gmm: GuestMemoryMmap<()> = GuestMemoryMmap::from_regions(regions)?;
                let gmm = GuestMemoryAtomic::new(gmm);
                for queue in self.queues.iter_mut() {
                    queue.set_memory(gmm.clone());
                }

                if hdr.ack_required() {
                    self.send_response(strm, hdr.ty, &[])?;
                }
            }
            VHOST_USER_ADD_MEM_REG => {
                // Request Type: None
                // Reply Type: MemoryRegionDescription
                // Ancillary Data: Vec<File Descriptor>
                // Required Protocol Feature: VHOST_USER_PROTOCOL_F_CONFIGURE_MEM_SLOTS
                //
                // Contains a memory region descriptor struct, describing a region of guest memory which the
                // back-end device must map in.
                //
                // When the VHOST_USER_PROTOCOL_F_CONFIGURE_MEM_SLOTS protocol feature has been successfully
                // negotiated, along with the VHOST_USER_REM_MEM_REG message, this message is used to set and
                // update the memory tables of the back-end device.
                //
                // Exactly one file descriptor from which the memory is mapped is passed in the ancillary data.
                let mem: VRingAddr = hdr.payload()?;
                tracing::trace!(?mem, "adding user memory register");
            }
            VHOST_USER_GET_CONFIG => {
                // Request Type: Device Config
                // Reply Type: Device Config
                // Ancillary Data: None
                // Required Protocol Feature: VHOST_USER_PROTOCOL_F_CONFIG
                //
                // Fetch the contents of the virtio device configuration space, vhost-user back-end’s
                // payload size MUST match the front-end’s request, vhost-user back-end uses zero
                // length of payload to indicate an error to the vhost-user front-end
                tracing::trace!("[get-config]: {hdr:x?}");
            }
            VHOST_USER_SET_CONFIG => {
                // Request Type: Device Config
                // Reply Type: None
                // Ancillary Data: None
                // Required Protocol Feature: VHOST_USER_PROTOCOL_F_CONFIG
                //
                // Submitted by the vhost-user front-end when the Guest changes the virtio device
                // configuration space and also can be used for live migration on the destination
                // host. The vhost-user back-end must check the flags field, and back-ends MUST NOT
                // accept SET_CONFIG for read-only configuration space fields unless the live migration
                // bit is set.
                tracing::trace!("[set-config]: {hdr:x?}");
            }
            _ => tracing::warn!(?hdr, "unhandled request type"),
        }

        Ok(())
    }

    fn send_msg(&mut self, id: u32, payload: &[u8]) -> AppResult<()> {
        if let Some(f) = self.channel.as_ref() {
            let payload_sz = payload.len() as u32;
            let mut resp = vec![0u8; VHOST_USER_HEADER_SZ + payload.len()];
            resp[0..4].copy_from_slice(&id.to_le_bytes());
            resp[4..8].copy_from_slice(&VHOST_USER_FLAG_VERSION_1.to_le_bytes());
            resp[8..12].copy_from_slice(&payload_sz.to_le_bytes());
            resp[12..].copy_from_slice(&payload);

            tracing::trace!(?resp, "sending msg");
            unistd::write(f, &resp)?;
        } else {
            tracing::warn!("[send-msg] backend fd not set");
        }

        Ok(())
    }

    fn send_response(&mut self, strm: RawFd, id: u32, payload: &[u8]) -> AppResult<()> {
        let payload_sz = payload.len() as u32;
        let mut resp = vec![0u8; VHOST_USER_HEADER_SZ + payload.len()];
        resp[0..4].copy_from_slice(&id.to_le_bytes());
        resp[4..8]
            .copy_from_slice(&(VHOST_USER_FLAG_VERSION_1 | VHOST_USER_FLAG_REPLY).to_le_bytes());
        resp[8..12].copy_from_slice(&payload_sz.to_le_bytes());
        resp[12..].copy_from_slice(&payload);

        let iov = [IoSlice::new(&resp)];
        tracing::trace!(?resp, strm, "sending response");
        socket::sendmsg::<()>(strm, &iov, &[], MsgFlags::empty(), None)?;

        Ok(())
    }

    /// Coverts a host's (vmm) memory address to a guest memory address
    ///
    /// ### Arguments
    /// * `vmm` - Host address to convert to a guest (vm) address
    fn compute_guest_address(&self, vmm: u64) -> Result<u64, MemoryError> {
        self.mappings
            .iter()
            .find_map(|m| m.guest_addr(vmm))
            .ok_or(MemoryError::NoHostToGuestMappingFound(vmm))
    }

    /// Returns a (mutable) reference to a virtqueue
    ///
    /// ### Arguments
    /// * `idx` - Reference to a virtqueue at the specified index
    fn get_virtqueue_mut(&mut self, idx: usize) -> AppResult<&mut VirtQueue<S>> {
        self.queues.get_mut(idx).ok_or(Error::QueueNotFound(idx))
    }
}
