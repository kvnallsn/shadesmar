//! Virtio vhost types

use std::{collections::VecDeque, fmt::Debug, os::fd::RawFd, sync::Arc};

use bitflags::bitflags;
use nix::sys::socket::ControlMessageOwned;
use parking_lot::Mutex;
use shadesmar_core::EthernetPacket;

use crate::{device::TryFromPayload, error::PayloadError};

const VIRTIO_NET_HDR_SZ: usize = std::mem::size_of::<VirtioNetHeader>();

#[macro_export]
macro_rules! cast {
    (u16, $b:expr) => {
        u16::from_le_bytes([$b[0], $b[1]])
    };

    (be16, $b:expr) => {
        u16::from_be_bytes([$b[0], $b[1]])
    };

    (u32, $b:expr) => {
        u32::from_le_bytes([$b[0], $b[1], $b[2], $b[3]])
    };

    (be32, $b:expr) => {
        u32::from_be_bytes([$b[0], $b[1], $b[2], $b[3]])
    };

    (u64, $b:expr) => {
        u64::from_le_bytes([$b[0], $b[1], $b[2], $b[3], $b[4], $b[5], $b[6], $b[7]])
    };

    (be64, $b:expr) => {
        u64::from_be_bytes([$b[0], $b[1], $b[2], $b[3], $b[4], $b[5], $b[6], $b[7]])
    };

    (u128, $b:expr) => {
        u128::from_le_bytes([
            $b[0], $b[1], $b[2], $b[3], $b[4], $b[5], $b[6], $b[7], $b[8], $b[9], $b[10], $b[11],
            $b[12], $b[13], $b[14], $b[15],
        ])
    };

    (be128, $b:expr) => {
        u128::from_be_bytes([
            $b[0], $b[1], $b[2], $b[3], $b[4], $b[5], $b[6], $b[7], $b[8], $b[9], $b[10], $b[11],
            $b[12], $b[13], $b[14], $b[15],
        ])
    };
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct VirtioFeatures: u64 {
        /// If this feature has been negotiated by driver, the device MUST issue a used buffer
        /// notification if the device runs out of available descriptors on a virtqueue
        /// even though notifications are suppressed using the VIRTQ_AVAIL_F_NO_INTERRUPT flag or
        /// the used_event field
        ///
        /// An example of a driver using this feature is the legacy networking driver: it doesn’t
        /// need to know every time a packet is transmitted, but it does need to free the transmitted
        /// packets a finite time after they are transmitted. It can avoid using a timer if the device
        /// notifies it when all the packets are transmitted.
        const NOTIFY_ON_EMPTY = 1 << 24;

        /// This feature indicates that the device accepts arbitrary descriptor layouts
        ///
        /// REF: Virtio Spec 2.6.4.3
        const ANY_LAYOUT = 1 << 27;

        /// Enable driver support for descriptors with the VIRTQ_DESC_F_INDIRECT flag set
        const RING_INDIRECT_DESC = 1 << 28;

        /// Enables the used_event and the avail_event fields to minimize notifications
        const RING_EVENT_IDX = 1 << 29;

        /// (vhost-user) Negotiate additional protocol features
        const PROTOCOL_FEATURES = 1 << 30;

        /// Indicates compliance with this specification, giving a simple way to detect legacy
        /// devices or drivers.
        const RING_VERSION_1 = 1 << 32;

        /// This feature indicates that the device can be used on a platform where device access
        /// to data in memory is limited and/or translated
        const ACCESS_PLATFORM = 1 << 33;

        /// This feature indicates support for the packed virtqueue layout
        const RING_PACKED = 1 << 34;

        /// This feature indicates that all buffers are used by the device in the same order in
        /// which they have been made available.
        const IN_ORDER = 1 << 35;

        /// This feature indicates that memory accesses by the driver and the device are ordered
        /// in a way described by the platform.
        const ORDER_PLATFORM = 1 << 36;

        /// This feature indicates that the device supports Single Root I/O Virtualization.
        /// Currently only PCI devices support this feature.
        const SR_IOV = 1 << 37;

        /// This feature indicates that the driver passes extra data (besides identifying the virtqueue)
        /// in its device notifications.
        const NOTIFICATION_DATA = 1 << 38;
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct VHostUserProtocolFeature: u64 {
        const MQ = 0x1;
        const LOG_SHMFD = 0x2;
        const RARP = 0x4;
        const REPLY_ACK = 0x8;
        const MTU = 0x010;
        const BACKEND_REQ = 0x20;
        const CROSS_ENDIAN = 0x40;
        const CRYPTO_SESSION = 0x80;
        const PAGEFAULT = 0x100;
        const CONFIG = 0x200;
        const BACKEND_SEND_FD = 0x400;
        const HOST_NOTIFIER = 0x800;
        const INFLIGHT_SHMFD = 0x1000;
        const RESET_DEVICE = 0x2000;
        const INBAND_NOTIFICATIONS = 0x4000;
        const CONFIGURE_MEM_SLOTS = 0x8000;
        const STATUS = 0x1_0000;
        const XEN_MMAP = 0x2_0000;
        const SHARED_OBJECT = 0x4_0000;
        const DEVICE_STATE = 0x8_0000;
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct VqDescriptorEntryFlags: u16 {
        /// Marks a buffer as continuing via the next field
        const NEXT = 0x01;

        /// Marks a buffer as a device write-only (otherwise device read-only)
        const WRITE = 0x02;

        /// Means the buffer contains a list of buffer descriptors
        const INDIRECT = 0x04;
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct VirtioNetHeaderFlags: u8 {
        /// If the packet needs it's checksum computed
        const NEEDS_CSUM = 0x01;

        const DATA_VALID = 0x02;

        const RSC_INFO = 0x04;
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct VirtioNetGso: u8 {
        const NONE = 0x00;
        const TCPV4 = 0x01;
        const UDP = 0x03;
        const TCPV6 = 0x04;
        const ECN = 0x80;
    }
}

pub type DeviceRxQueue = Arc<Mutex<VecDeque<EthernetPacket>>>;

#[derive(Debug)]
pub struct VirtioNetHeader {
    flags: VirtioNetHeaderFlags,
    gso_type: VirtioNetGso,
    hdr_len: u16,
    gso_size: u16,
    csum_start: u16,
    csum_offset: u16,
    num_buffers: u16,
}

#[derive(Clone, Debug)]
pub struct VHostHeader {
    /// Type of request
    pub ty: u32,

    /// Flags:
    /// - Bits 00:01 -> Version (currently 0x01)
    /// - Bits 02:02 -> Reply flag (set on each reply from the backend)
    /// - Bits 03:03 -> Reply needed flag (set by frontend to request a reply)
    pub flags: u32,

    /// Size of the payload
    pub sz: u32,

    /// Any ancillary data / control messages received
    ancillary: VecDeque<ControlMessageOwned>,

    /// Payload data
    payload: Option<Vec<u8>>,
}

#[derive(Clone, Debug, Default)]
pub struct VRingState {
    pub index: u32,
    pub num: u32,
}

/// Address descriptions for a vring
#[derive(Clone, Default)]
pub struct VRingAddr {
    /// vring index
    pub index: u32,

    /// vring flags
    pub flags: u32,

    /// Ring address of the vring descriptor table
    pub desc_user_addr: u64,

    /// Ring address of the vring used ring
    pub used_user_addr: u64,

    /// Ring address of the vring available ring
    pub avail_user_addr: u64,

    /// Guess address for logging
    pub log_guest_addr: u64,
}

/// vring descriptor index for split virtqueues
#[derive(Clone, Debug, Default)]
pub struct VRingDescriptor {
    /// Index of the respective virtqueue
    pub index: u32,

    /// Only lower 16 bits are used
    /// - Bits 00:15: Index of the next Available Ring descriptor that the backend will process.
    ///              Free-running index that is not wrapped by the ring size
    ///
    /// - Bits 16:31: Reserved (set to zero)
    pub avail: u32,
}

#[derive(Clone, Default)]
pub struct MemoryRegionDescription {
    /// Guest address of the region
    pub guest_address: u64,

    /// Size of region
    pub size: u64,

    /// User address of the region
    pub user_address: u64,

    /// Offset where region starts in mapped memory
    pub mmap_offset: u64,
}

/// Represents the mapping from a host/guest address to a guest/host address
#[derive(Clone, Default)]
pub struct GuestMapping {
    /// Host (hypervisor) start address
    pub host_start: u64,

    /// Host(hypervisor) end address
    pub host_end: u64,

    /// Guest (VM) start address
    pub guest: u64,

    /// Size of the mapped memory section
    #[allow(dead_code)]
    pub size: u64,
}

impl GuestMapping {
    /// Creates a new guest/host address mapping
    ///
    /// ### Arguments
    /// * `host` - Address in the host or virtual machine monitor (vmm)
    /// * `guest` - Address in the guest (or vm)
    /// * `size` - Size of the address space
    pub fn new(host: u64, guest: u64, size: u64) -> Self {
        Self {
            host_start: host,
            host_end: host + size,
            guest,
            size,
        }
    }

    /// Returns the guest address corresponding to the provided host (vmm) address
    /// if it falls within the range of this guest memory mapping.
    ///
    /// If not withing this range, returns None
    ///
    /// ### Arguments
    /// * `vmm` - Host (vmm) memory address
    pub fn guest_addr(&self, vmm: u64) -> Option<u64> {
        if vmm >= self.host_start && vmm <= self.host_end {
            Some((vmm - self.host_start) + self.guest)
        } else {
            None
        }
    }
}

impl VHostHeader {
    pub fn parse(pkt: &[u8], ancillary: VecDeque<ControlMessageOwned>) -> Self {
        let ty = u32::from_le_bytes([pkt[0], pkt[1], pkt[2], pkt[3]]);
        let flags = u32::from_le_bytes([pkt[4], pkt[5], pkt[6], pkt[7]]);
        let sz = u32::from_le_bytes([pkt[8], pkt[9], pkt[10], pkt[11]]);

        VHostHeader {
            ty,
            flags,
            sz,
            ancillary,
            payload: None,
        }
    }

    pub fn ack_required(&self) -> bool {
        self.flags & 0x08 == 0x08
    }

    /// Returns a single file descriptor from the control message
    ///
    /// If more than one file descriptor was returned, the rest are discarded
    pub fn extract_fd(&mut self) -> Result<RawFd, PayloadError> {
        self.ancillary
            .pop_front()
            .ok_or(PayloadError::MissingControlData)
            .and_then(|msg| match msg {
                ControlMessageOwned::ScmRights(fds) => match fds.is_empty() {
                    true => Err(PayloadError::NoFileDescriptorsFound),
                    false => Ok(fds[0]),
                },
                _ => Err(PayloadError::ControlDataMismatch),
            })
    }

    /// Returns all file descriptors from the control message
    pub fn extract_fds(&mut self) -> Result<Vec<RawFd>, PayloadError> {
        self.ancillary
            .pop_front()
            .ok_or(PayloadError::MissingControlData)
            .and_then(|msg| match msg {
                ControlMessageOwned::ScmRights(fds) => Ok(fds),
                _ => Err(PayloadError::ControlDataMismatch),
            })
    }

    pub fn set_payload(&mut self, payload: Vec<u8>) {
        self.payload = Some(payload);
    }

    pub fn payload<T>(&self) -> Result<T, PayloadError>
    where
        T: TryFromPayload,
    {
        self.payload
            .as_ref()
            .map(|p| p.as_slice())
            .ok_or(PayloadError::Missing)
            .and_then(|p| T::try_from_payload(p))
    }
}

impl VirtioNetHeader {
    pub fn new() -> Self {
        VirtioNetHeader {
            flags: VirtioNetHeaderFlags::empty(),
            gso_type: VirtioNetGso::NONE,
            hdr_len: 0,
            gso_size: 0,
            csum_start: 0,
            csum_offset: 0,
            num_buffers: 1,
        }
    }

    pub fn extract(mut pkt: Vec<u8>) -> Result<(Self, Vec<u8>), PayloadError> {
        if pkt.len() < VIRTIO_NET_HDR_SZ {
            return Err(PayloadError::NotEnoughData(pkt.len(), VIRTIO_NET_HDR_SZ));
        }

        let hdr = pkt.drain(..VIRTIO_NET_HDR_SZ).collect::<Vec<_>>();

        let flags = hdr[0];
        let gso_type = hdr[1];
        let hdr_len = cast!(u16, hdr[2..4]);
        let gso_size = cast!(u16, hdr[4..6]);
        let csum_start = cast!(u16, hdr[6..8]);
        let csum_offset = cast!(u16, hdr[8..10]);
        let num_buffers = cast!(u16, hdr[10..12]);

        let hdr = Self {
            flags: VirtioNetHeaderFlags::from_bits(flags)
                .unwrap_or_else(|| VirtioNetHeaderFlags::empty()),
            gso_type: VirtioNetGso::from_bits(gso_type).unwrap_or_else(|| VirtioNetGso::empty()),
            hdr_len,
            gso_size,
            csum_start,
            csum_offset,
            num_buffers,
        };

        Ok((hdr, pkt))
    }

    pub fn as_bytes(&self) -> [u8; VIRTIO_NET_HDR_SZ] {
        let mut bytes = [0u8; VIRTIO_NET_HDR_SZ];
        bytes[0] = self.flags.bits();
        bytes[1] = self.gso_type.bits();
        bytes[2..4].copy_from_slice(&self.hdr_len.to_le_bytes());
        bytes[4..6].copy_from_slice(&self.gso_size.to_le_bytes());
        bytes[6..8].copy_from_slice(&self.csum_start.to_le_bytes());
        bytes[8..10].copy_from_slice(&self.csum_offset.to_le_bytes());
        bytes[10..12].copy_from_slice(&self.num_buffers.to_le_bytes());
        bytes
    }
}

impl TryFromPayload for u64 {
    fn try_from_payload(pkt: &[u8]) -> Result<Self, PayloadError> {
        if pkt.len() < 8 {
            return Err(PayloadError::NotEnoughData(pkt.len(), 8));
        }

        let val = cast!(u64, pkt[0..8]);
        Ok(val)
    }
}

impl TryFromPayload for VRingState {
    fn try_from_payload(pkt: &[u8]) -> Result<Self, PayloadError> {
        if pkt.len() < 8 {
            return Err(PayloadError::NotEnoughData(pkt.len(), 8));
        }

        let index = cast!(u32, pkt[0..4]);
        let num = cast!(u32, pkt[4..8]);
        Ok(Self { index, num })
    }
}

impl TryFromPayload for VRingDescriptor {
    fn try_from_payload(pkt: &[u8]) -> Result<Self, PayloadError> {
        if pkt.len() < 8 {
            return Err(PayloadError::NotEnoughData(pkt.len(), 8));
        }

        let index = cast!(u32, pkt[0..4]);
        let avail = cast!(u32, pkt[4..8]);
        Ok(Self { index, avail })
    }
}

impl TryFromPayload for VRingAddr {
    fn try_from_payload(pkt: &[u8]) -> Result<Self, PayloadError> {
        if pkt.len() < 40 {
            return Err(PayloadError::NotEnoughData(pkt.len(), 40));
        }

        let index = cast!(u32, pkt[..4]);
        let flags = cast!(u32, pkt[4..8]);
        let desc_user_addr = cast!(u64, pkt[8..16]);
        let used_user_addr = cast!(u64, pkt[16..24]);
        let avail_user_addr = cast!(u64, pkt[24..32]);
        let log_guest_addr = cast!(u64, pkt[32..40]);

        Ok(Self {
            index,
            flags,
            desc_user_addr,
            used_user_addr,
            avail_user_addr,
            log_guest_addr,
        })
    }
}

impl TryFromPayload for MemoryRegionDescription {
    fn try_from_payload(pkt: &[u8]) -> Result<Self, PayloadError> {
        if pkt.len() < 32 {
            return Err(PayloadError::NotEnoughData(pkt.len(), 32));
        }

        let guest_address = cast!(u64, pkt[0..8]);
        let size = cast!(u64, pkt[8..16]);
        let user_address = cast!(u64, pkt[16..24]);
        let mmap_offset = cast!(u64, pkt[24..32]);
        Ok(Self {
            guest_address,
            size,
            user_address,
            mmap_offset,
        })
    }
}

impl TryFromPayload for Vec<MemoryRegionDescription> {
    fn try_from_payload(pkt: &[u8]) -> Result<Self, PayloadError> {
        if pkt.len() < 40 {
            return Err(PayloadError::NotEnoughData(pkt.len(), 40));
        }

        let num_regions = cast!(u32, pkt[0..4]) as usize;
        if pkt.len() < (num_regions * 32) + 8 {
            // each region is 32-bytes, plus the 8-byte padding
            return Err(PayloadError::NotEnoughData(pkt.len(), 40));
        }

        let mut regions = Vec::with_capacity(num_regions);
        for i in 0..num_regions {
            let start = (i * 32) + 8;
            let end = start + 32;
            let region = MemoryRegionDescription::try_from_payload(&pkt[start..end])?;
            regions.push(region);
        }

        Ok(regions)
    }
}

impl VRingDescriptor {
    pub fn as_vec(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(8);
        data.extend_from_slice(&self.index.to_le_bytes());
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        data
    }
}

impl Debug for VRingAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "VRingAddr {{ index: {}, flags: 0x{:x}, desc_user_addr: 0x{:02x}, used_user_addr: 0x{:02x}, avail_user_addr: 0x{:02x}, log_guest_addr: 0x{:02x} }}", self.index, self.flags, self.desc_user_addr, self.used_user_addr, self.avail_user_addr, self.log_guest_addr)
    }
}

impl Debug for MemoryRegionDescription {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MemoryRegionDescription {{ guest_address: 0x{:08x}, size: 0x{:08x}, user_address: 0x{:08x}, mmap_offset: 0x{:08x} }}", self.guest_address, self.size, self.user_address, self.mmap_offset)
    }
}
