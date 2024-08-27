//! ARP protocol

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::{
    cast,
    types::{EtherType, MacAddress},
    ProtocolError,
};

const ARP4_PKT_SIZE: usize = 28;
const ARP6_PKT_SIZE: usize = 52;

#[derive(Debug)]
pub struct ArpPacket {
    /// Netlink link protocol type (e.g. Ethernet => 1)
    pub hardware_type: u16,

    /// Internetwork protocol for which the ARP packet is intended
    pub protocol_type: EtherType,

    /// Length (in octects) of a hardware address
    pub hardware_len: u8,

    /// Length (in octets) of internetwork address (e.g. ipv4 => 4)
    pub protocol_len: u8,

    /// Specifices the operation the sender is performing
    /// 1: Request
    /// 2: Reply
    pub operation: u16,

    /// MAC address of the sender
    /// - Request => address of host sending request
    /// - Reply => address of host the request was looking for
    pub sha: MacAddress,

    /// Internetwork address of the sender
    pub spa: IpAddr,

    /// MAC address of the intended receiver
    /// - Request => ignored / zeros
    /// - Reply => address of host that sent the request
    pub tha: MacAddress,

    /// Internetwork address of the intended receiver
    pub tpa: IpAddr,
}

impl ArpPacket {
    /// Parses an ARP packet from a byte buffer
    ///
    /// The byte buffer is expected to be in network (big) endian format
    ///
    /// ### Arguments
    /// * `bytes` - Series of bytes to parse ARP packet from
    pub fn parse(bytes: &[u8]) -> Result<Self, ProtocolError> {
        /// A 28-byte packet is an ARP IPv4 packet
        const MIN_SZ: usize = 28;
        if bytes.len() < MIN_SZ {
            return Err(ProtocolError::NotEnoughData(bytes.len(), MIN_SZ));
        }

        let hardware_type = cast!(be16, bytes[0..2]);
        let protocol_type = EtherType::try_from(&bytes[2..4])?;
        let hardware_len = bytes[4];
        let protocol_len = bytes[5];
        let operation = cast!(be16, bytes[6..8]);

        match (hardware_type, hardware_len) {
            (1, 6) => { /* do nothing, good match */ }
            (1, _) => {
                return Err(ProtocolError::MalformedPacket(format!(
                    "hardware type (ethernet) does have expected length (6), has length {hardware_len}"
                )));
            }
            _ => {
                return Err(ProtocolError::MalformedPacket(format!(
                    "unknown hardware type: 0x{hardware_type:04x}"
                )))
            }
        }

        // compute dynamic offsets for addresses
        let hlu: usize = hardware_len.into();
        let plu: usize = protocol_len.into();

        let sha_start: usize = 8;
        let sha_end = sha_start + hlu;
        let spa_start = sha_end;
        let spa_end = spa_start + plu;

        let tha_start = spa_end;
        let tha_end = tha_start + hlu;
        let tpa_start = tha_end;
        let tpa_end = tpa_start + plu;

        let sha = MacAddress::parse(&bytes[sha_start..sha_end])?;
        let tha = MacAddress::parse(&bytes[tha_start..tha_end])?;

        let (spa, tpa) = match (protocol_type, protocol_len) {
            (EtherType::IPv4, 4) => {
                let spa = Ipv4Addr::from(cast!(be32, &bytes[spa_start..spa_end]));
                let tpa = Ipv4Addr::from(cast!(be32, &bytes[tpa_start..tpa_end]));
                (IpAddr::V4(spa), IpAddr::V4(tpa))
            }
            (EtherType::IPv6, 16) => {
                let spa = Ipv6Addr::from(cast!(be128, &bytes[spa_start..spa_end]));
                let tpa = Ipv6Addr::from(cast!(be128, &bytes[tpa_start..tpa_end]));
                (IpAddr::V6(spa), IpAddr::V6(tpa))
            }
            (EtherType::IPv4, _) => {
                return Err(ProtocolError::MalformedPacket(format!("protocol type (ipv4) does not have expected length (4), has length {protocol_len}")));
            }
            (EtherType::IPv6, _) => {
                return Err(ProtocolError::MalformedPacket(format!("protocol type (ipv6) does not have expected length (16), has length {protocol_len}")));
            }
            _ => {
                return Err(ProtocolError::MalformedPacket(format!(
                    "invalid ethertype for ARP packet: {protocol_type:?}"
                )));
            }
        };

        Ok(Self {
            hardware_type,
            protocol_type,
            hardware_len,
            protocol_len,
            operation,
            sha,
            spa,
            tha,
            tpa,
        })
    }

    /// Builds an ARP reply packet based on this packet
    pub fn to_reply(&mut self, mac: MacAddress) {
        let tpa = self.tpa;
        self.tpa = self.spa;
        self.tha = self.sha;
        self.spa = tpa;
        self.sha = mac;
        self.operation = 2;
    }

    pub fn size(&self) -> usize {
        match (self.spa, self.tpa) {
            (IpAddr::V4(_), IpAddr::V4(_)) => ARP4_PKT_SIZE,
            (IpAddr::V6(_), IpAddr::V6(_)) => ARP6_PKT_SIZE,
            _ => 0,
        }
    }

    pub fn as_bytes(&self, pkt: &mut [u8]) {
        // FIX: This should probably return an error if ip4/ip6 mismatch

        pkt[0..2].copy_from_slice(&self.hardware_type.to_be_bytes());
        pkt[2..4].copy_from_slice(&self.protocol_type.as_u16().to_be_bytes());
        pkt[4] = self.hardware_len;
        pkt[5] = self.protocol_len;
        pkt[6..8].copy_from_slice(&self.operation.to_be_bytes());
        pkt[8..14].copy_from_slice(&self.sha.as_bytes());
        match (self.spa, self.tpa) {
            (IpAddr::V4(spa), IpAddr::V4(tpa)) => {
                pkt[14..18].copy_from_slice(spa.octets().as_slice());
                pkt[18..24].copy_from_slice(&self.tha.as_bytes());
                pkt[24..28].copy_from_slice(tpa.octets().as_slice());
            }
            (IpAddr::V6(spa), IpAddr::V6(tpa)) => {
                pkt[14..30].copy_from_slice(spa.octets().as_slice());
                pkt[30..36].copy_from_slice(&self.tha.as_bytes());
                pkt[36..52].copy_from_slice(tpa.octets().as_slice());
            }
            _ => (),
        }
    }
}
