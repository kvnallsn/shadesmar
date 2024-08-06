//! Collection of higher-level protocols

mod arp;
pub mod icmp;
pub mod tcp;
pub mod udp;

pub const NET_PROTOCOL_ICMP: u8 = 1;
pub const NET_PROTOCOL_TCP: u8 = 6;
pub const NET_PROTOCOL_UDP: u8 = 17;

pub const UDP_HDR_SZ: usize = 8;

pub use self::{arp::ArpPacket, icmp::IcmpPacket};
