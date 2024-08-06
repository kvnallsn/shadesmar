//! Various Networking  Types

mod mac;
mod netaddress;

use std::fmt::Debug;

use crate::{cast, ProtocolError};

pub use self::{
    mac::MacAddress,
    netaddress::{IpNetwork, Ipv4Network, Ipv6Network},
};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum EtherType {
    IPv4 = 0x0800,
    IPv6 = 0x86DD,
    ARP = 0x0806,
}

impl TryFrom<u16> for EtherType {
    type Error = ProtocolError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            x if x == EtherType::IPv4 as u16 => Ok(EtherType::IPv4),
            x if x == EtherType::IPv6 as u16 => Ok(EtherType::IPv6),
            x if x == EtherType::ARP as u16 => Ok(EtherType::ARP),
            _ => Err(ProtocolError::MalformedPacket(format!(
                "unknown ethertype: 0x{value:04x}"
            ))),
        }
    }
}

impl TryFrom<&[u8]> for EtherType {
    type Error = ProtocolError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        match value.len() {
            0 | 1 => Err(ProtocolError::NotEnoughData(value.len(), 2)),
            _ => EtherType::try_from(cast!(be16, value[0..2])),
        }
    }
}

impl Debug for EtherType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "EtherType(0x{:04x})", self.as_u16())
    }
}

impl EtherType {
    pub fn as_u16(self) -> u16 {
        self as u16
    }
}
