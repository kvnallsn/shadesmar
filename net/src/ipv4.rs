//! IPv4 related structures

use std::{fmt::Display, net::Ipv4Addr};

use bitflags::bitflags;
use rand::Rng;

use crate::{
    cast, ph_checksum,
    protocols::{NET_PROTOCOL_TCP, NET_PROTOCOL_UDP},
    ProtocolError,
};

/// A DWORD is a "double word", or 4 bytes (32-bits)
const DWORD_SIZE: usize = 4;

/// Represents the Ipv4 header
///
/// For more information, view: https://en.wikipedia.org/wiki/IPv4
#[derive(Debug)]
pub struct Ipv4Header {
    pub version: u8,
    pub ihl: u8,
    pub length: u16,
    pub id: u16,
    pub flags: Ipv4Flags,
    pub frag_offset: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub checksum: u16,
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
}

/// An IPv4 packet consists of a the IPv4 header and a payload
#[derive(Debug)]
pub struct Ipv4Packet {
    header: Ipv4Header,
    data: Vec<u8>,
}

bitflags! {
    /// Represents the flags that can be set on a IPv4 packet
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct Ipv4Flags: u8 {
        const MoreFragments = 0b001;
        const DontFragment  = 0b010;
        const Reserved = 0b100;
    }
}

impl Ipv4Header {
    /// Creates a new IPv4 header from the supplied values
    ///
    /// ### Arguments
    /// * `src` - Source address
    /// * `dst` - Destination address
    /// * `protocol` - Next header protocol (e.g., TCP, UDP, etc)
    /// * `length` - Length of the expected payload data
    pub fn new(src: Ipv4Addr, dst: Ipv4Addr, protocol: u8, length: u16) -> Self {
        let mut rng = rand::thread_rng();

        Self {
            version: 4,
            ihl: 5,
            length: length + 20,
            id: rng.gen(),
            flags: Ipv4Flags::DontFragment,
            frag_offset: 0,
            ttl: 64,
            protocol,
            checksum: 0,
            src,
            dst,
        }
    }

    /// Extracts the IPv4 header from a vector of bytes, or returns an error
    /// if the supplied buffer is too small
    ///
    /// The first 20 bytes will be drained from the vector
    ///
    /// ### Arguments
    /// * `pkt` - Vector containing ipv4 header
    pub fn extract(pkt: &mut Vec<u8>) -> Result<Self, ProtocolError> {
        if pkt.len() < 20 {
            return Err(ProtocolError::NotEnoughData(pkt.len(), 20));
        }

        let hdr = pkt.drain(0..20).collect::<Vec<_>>();
        Self::extract_from_slice(&hdr)
    }

    /// Extracts the IPv4 header from a vector of bytes, or returns an error
    /// if the supplied buffer is too small
    ///
    /// ### Arguments
    /// * `hdr` - Buffer containing ipv4 header
    pub fn extract_from_slice(hdr: &[u8]) -> Result<Self, ProtocolError> {
        if hdr.is_empty() {
            return Err(ProtocolError::NotEnoughData(0, 20));
        }

        let ihl = hdr[0] & 0x0F;
        let header_sz = usize::from(ihl) * 4;

        if hdr.len() < header_sz {
            return Err(ProtocolError::NotEnoughData(hdr.len(), header_sz));
        }

        let version = hdr[0] >> 4;
        let length = cast!(be16, hdr[2..4]);
        let id = cast!(be16, hdr[4..6]);
        let flags = Ipv4Flags::from_bits(hdr[6] >> 5).unwrap_or(Ipv4Flags::empty());
        let frag_offset = (cast!(be16, hdr[6..8]) & 0x1FFF) * 8;
        let ttl = hdr[8];
        let protocol = hdr[9];
        let checksum = cast!(be16, hdr[10..12]);
        let src = Ipv4Addr::from(cast!(be32, hdr[12..16]));
        let dst = Ipv4Addr::from(cast!(be32, hdr[16..20]));

        Ok(Self {
            version,
            ihl,
            length,
            id,
            flags,
            frag_offset,
            ttl,
            protocol,
            checksum,
            src,
            dst,
        })
    }

    /// Returns the length, in bytes, of the header
    pub fn header_length(&self) -> usize {
        usize::from(self.ihl) * DWORD_SIZE
    }

    /// Reverses the IPv4 source and destination addresses, generates a new id, and computes
    /// the internet checksum over the provided payload length
    ///
    /// ### Arguments
    /// * `payload` - Payload used to fill length field and generate checksum
    pub fn gen_reply(&self, payload: &[u8]) -> Self {
        Ipv4Header::new(self.dst, self.src, self.protocol, payload.len() as u16)
    }

    /// Replaces the source address with the supplied value and returns
    /// the original ipv4 address
    ///
    /// ### Arguments
    /// * `src` - New IPv4 src address
    fn masquerade(&mut self, src: Ipv4Addr) -> Ipv4Addr {
        let old = self.src;
        self.src = src;
        old
    }

    /// Replaces the destinaton address with the supplied value and returns
    /// the original ipv4 address
    ///
    /// ### Arguments
    /// * `src` - New IPv4 destination address
    fn unmasquerade(&mut self, dst: Ipv4Addr) -> Ipv4Addr {
        let old = self.dst;
        self.dst = dst;
        old
    }

    /// Returns this header as a byte slice / array.
    ///
    /// This does not append the payload but the length field and checksum
    /// are calcuated from the payload length
    pub fn as_bytes(&self, rpkt: &mut [u8]) {
        let flags = u16::from(self.flags.bits());
        let flags_frag = (flags << 13) | self.frag_offset;

        rpkt[0] = (self.version << 4) | 5; // Generally 0x45
        rpkt[2..4].copy_from_slice(&self.length.to_be_bytes());
        rpkt[4..6].copy_from_slice(&self.id.to_be_bytes());
        rpkt[6..8].copy_from_slice(&flags_frag.to_be_bytes());
        rpkt[8] = self.ttl;
        rpkt[9] = self.protocol;
        rpkt[10..12].copy_from_slice(&[0x00, 0x00]); // clear checksum
        rpkt[12..16].copy_from_slice(&self.src.octets());
        rpkt[16..20].copy_from_slice(&self.dst.octets());

        let csum = crate::checksum(&rpkt[0..20]);
        rpkt[10..12].copy_from_slice(&csum.to_be_bytes());
    }

    /// Returns this header an array of bytes
    pub fn into_bytes(self) -> [u8; 20] {
        let mut buf = [0u8; 20];
        self.as_bytes(&mut buf);
        buf
    }
}

impl Ipv4Packet {
    /// Parses an IPv4 packet, extracting the header from the start of the data vector
    ///
    /// Note: This does not drain the header from the vector. Use the `payload` function
    /// to access the transport layer header
    ///
    /// ### Arguments
    /// * `data` - An Ipv4 packet, including the header
    pub fn parse(data: Vec<u8>) -> Result<Self, ProtocolError> {
        let header = Ipv4Header::extract_from_slice(&data)?;
        Ok(Self { header, data })
    }

    /// Returns the unique identifer for this packet
    pub fn id(&self) -> u16 {
        self.header.id
    }

    /// Returns the flags set on this packet
    pub fn flags(&self) -> Ipv4Flags {
        self.header.flags
    }

    /// Returns true if this packet contains fragments
    pub fn has_fragments(&self) -> bool {
        self.header.flags.contains(Ipv4Flags::MoreFragments)
    }

    /// Returns the offset of the fragment (or zero, if no fragments)
    pub fn fragment_offset(&self) -> u16 {
        self.header.frag_offset
    }

    /// Returns the next layer (i.e., transport) layer protocol
    pub fn protocol(&self) -> u8 {
        self.header.protocol
    }

    /// Returns the total length of the packet, as stored in the ipv4
    /// header (includes header + payload)
    pub fn len(&self) -> u16 {
        self.header.length
    }

    /// Returns the source ip address
    pub fn src(&self) -> Ipv4Addr {
        self.header.src
    }

    /// Returns the destination ip address
    pub fn dest(&self) -> Ipv4Addr {
        self.header.dst
    }

    /// Returns the size of this header, in bytes
    pub fn header_length(&self) -> usize {
        self.header.header_length()
    }

    /// Returns the slice of data containing the Ipv4 packet's payload (aka the transport layer
    /// data)
    pub fn payload(&self) -> &[u8] {
        let offset = self.header.header_length();
        &self.data[offset..]
    }

    /// Returns the slice of data containing the Ipv4 packet's payload (aka the transport layer
    /// data)
    pub fn payload_mut(&mut self) -> &mut [u8] {
        let offset = self.header.header_length();
        &mut self.data[offset..]
    }

    /// Returns this packet as a slice of bytes, including the header
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Returns this packet as a vector of bytes
    pub fn into_bytes(self) -> Vec<u8> {
        self.data
    }

    /// Appends data to the end of this packet (useful for fragmented packets)
    pub fn add_fragment_data(&mut self, offset: u16, payload: &[u8]) {
        tracing::trace!(
            "appending {} bytes to ipv4 packet at offset 0x{offset:02x}",
            payload.len()
        );
        let uoffset = usize::from(offset);
        let end = self.payload().len();

        if uoffset == end {
            self.data.extend_from_slice(&payload);
            self.header.length += payload.len() as u16;
        } else if uoffset > end {
            // need to pad the data until we reach the offset?
            self.data.resize(uoffset, 0);
            self.data.extend_from_slice(&payload);
            self.header.length = offset + (payload.len() as u16);
        } else {
            let end = uoffset + payload.len();
            self.data[uoffset..end].copy_from_slice(&payload);
        }
    }

    /// Applies changes from the header field to the underlying data
    pub fn finalize(&mut self) {
        self.header.flags = Ipv4Flags::empty();
        self.header.frag_offset = 0;
        self.header.as_bytes(&mut self.data);
    }

    /// Sets the source ip address to the provided value and recomputes the header checksum
    ///
    /// ### Arguments
    /// * `ip` - New src ip address
    pub fn masquerade(&mut self, ip: Ipv4Addr) {
        self.header.masquerade(ip);
        self.header.as_bytes(&mut self.data);
        self.fix_transport_checksum();
    }

    /// Computes the checksum for this packet
    pub fn checksum(&self) -> u16 {
        u16::from_be_bytes([self.data[10], self.data[11]])
    }

    /// Sets the destination ip address to the provided value and recomputes the header checksum
    ///
    /// ### Arguments
    /// * `ip` - New destinaton ip address
    pub fn unmasquerade(&mut self, ip: Ipv4Addr) {
        self.header.unmasquerade(ip);
        self.header.as_bytes(&mut self.data);
        self.fix_transport_checksum();
    }

    /// TCP and UDP both use a pseudo-ip header in their checksum fields
    /// so we'll need to update the TCP/UDP checksum (if necessary)
    fn fix_transport_checksum(&mut self) {
        let src = self.src();
        let dst = self.dest();
        let proto = self.protocol();
        let payload = self.payload_mut();

        let (s, e) = match proto {
            NET_PROTOCOL_TCP => (16, 18),
            NET_PROTOCOL_UDP => (6, 8),
            _ => {
                // no need to fixup anything
                return;
            }
        };

        payload[s..e].copy_from_slice(&[0, 0]);
        let sum = ph_checksum(src, dst, proto, payload);
        payload[s..e].copy_from_slice(&sum.to_be_bytes());
    }

    /// Generates a new Ipv4 header to use as a reply message
    ///
    /// ### Arguments
    /// * `payload` - Payload that will be set in the reply
    pub fn reply(&self, payload: &[u8]) -> Ipv4Header {
        self.header.gen_reply(payload)
    }
}

impl Display for Ipv4Flags {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:02x}", self.bits())
    }
}

#[cfg(test)]
mod tests {
    use std::{io::Read, net::Ipv4Addr};

    use crate::ipv4::Ipv4Flags;

    use super::Ipv4Packet;

    fn init_tracing() {
        tracing_subscriber::FmtSubscriber::builder()
            .with_max_level(tracing::Level::DEBUG)
            .pretty()
            .init();
    }

    fn read_file(path: &str) -> Ipv4Packet {
        use std::fs::File;

        let mut data = Vec::new();
        let mut fd = File::open(path).unwrap();
        fd.read_to_end(&mut data).unwrap();

        let pkt = Ipv4Packet::parse(data).unwrap();
        tracing::debug!("ipv4 packet id: 0x{:04x}", pkt.header.id);
        pkt
    }

    #[test]
    fn validate_ipv4_flags() {
        let pkt = read_file("data/checksum.bin");
        let expected = Ipv4Flags::DontFragment;
        assert_eq!(pkt.flags(), expected, "flags did not match expected values");
    }

    #[test]
    fn fixup_tcp_checksum() {
        init_tracing();
        let mut pkt = read_file("data/checksum.bin");
        pkt.unmasquerade(Ipv4Addr::from([10, 10, 10, 10]));
        let payload = pkt.payload();
        let tcp_csum = u16::from_be_bytes([payload[16], payload[17]]);
        assert_eq!(tcp_csum, 0xE6E7, "checksum mismatch");
    }
}
