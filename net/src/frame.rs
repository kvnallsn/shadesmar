//! Ethernet Frame

use crate::{
    types::{EtherType, MacAddress},
    ProtocolError,
};

const ETHERNET_FRAME_SIZE: usize = 14;

#[derive(Clone, Copy, Debug)]
pub struct EthernetFrame {
    pub dst: MacAddress,
    pub src: MacAddress,
    pub ethertype: EtherType,
}

/// An `EthernetPacket` consists of an `EthernetFrame` and its associated payload
#[derive(Debug)]
pub struct EthernetPacket {
    pub frame: EthernetFrame,
    pub payload: Vec<u8>,
}

impl EthernetFrame {
    /// Creates a new EthernetFrame
    pub fn new(src: MacAddress, dst: MacAddress, ethertype: EtherType) -> Self {
        Self {
            dst,
            src,
            ethertype,
        }
    }

    /// Extracts an EthernetFrame from a packet received over the wire.
    /// Returns an error if not enough data is provided to build an EthernetFrame.
    ///
    /// ### Arguments
    /// * `pkt` - Bytes to extract etherframe from from
    pub fn extract(pkt: &mut Vec<u8>) -> Result<Self, ProtocolError> {
        if pkt.len() < 14 {
            return Err(ProtocolError::NotEnoughData(pkt.len(), 14));
        }

        let hdr = pkt.drain(0..14).collect::<Vec<_>>();
        let dst = MacAddress::parse(&hdr[0..6])?;
        let src = MacAddress::parse(&hdr[6..12])?;
        let ethertype = EtherType::try_from(&hdr[12..14])?;

        Ok(Self {
            dst,
            src,
            ethertype,
        })
    }

    pub fn size() -> usize {
        ETHERNET_FRAME_SIZE
    }

    pub fn gen_reply(&self) -> Self {
        Self {
            dst: self.src,
            src: self.dst,
            ethertype: self.ethertype,
        }
    }

    pub fn as_bytes(&self, pkt: &mut [u8]) {
        pkt[0..6].copy_from_slice(&self.dst.as_bytes());
        pkt[6..12].copy_from_slice(&self.src.as_bytes());
        pkt[12..14].copy_from_slice(&self.ethertype.as_u16().to_be_bytes());
    }

    pub fn to_bytes(&self) -> [u8; ETHERNET_FRAME_SIZE] {
        let mut bytes = [0u8; ETHERNET_FRAME_SIZE];
        self.as_bytes(&mut bytes);
        bytes
    }
}

impl EthernetPacket {
    /// Creates a new `EthernetPacket`
    ///
    /// ### Arguments
    /// * `frame` - The ethernet frame header
    /// * `payload` - The Layer3+ payload data
    pub fn new(frame: EthernetFrame, payload: Vec<u8>) -> Self {
        Self { frame, payload }
    }
}
