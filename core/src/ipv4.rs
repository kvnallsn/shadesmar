//! IPv4 related structures

use std::{fmt::Display, net::Ipv4Addr};

use bitflags::bitflags;
use rand::Rng;

use crate::{
    cast, ph_checksum,
    protocols::{NET_PROTOCOL_TCP, NET_PROTOCOL_UDP},
    types::buffers::PacketBuffer,
    ProtocolError,
};

/// A DWORD is a "double word", or 4 bytes (32-bits)
const DWORD_SIZE: usize = 4;

bitflags! {
    /// Represents the flags that can be set on a IPv4 packet
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct Ipv4Flags: u8 {
        const MoreFragments = 0b001;
        const DontFragment  = 0b010;
        const Reserved = 0b100;
    }
}

/// Represents the Ipv4 header
///
/// For more information, view: https://en.wikipedia.org/wiki/IPv4
#[derive(Copy, Clone, Debug)]
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
pub struct Ipv4PacketMut<'a> {
    data: &'a mut [u8],
}
pub struct Ipv4PacketRef<'a> {
    data: &'a [u8],
}

pub struct Ipv4PacketOwned {
    data: PacketBuffer,
}

pub trait Ipv4Packet {
    /// Returns a reference underlying byte buffer (including the IPv4 header)
    fn as_bytes(&self) -> &[u8];

    /// Returns a slice of bytes containing the IPv4 header
    fn header_bytes(&self) -> &[u8] {
        let end = self.header_length();
        &self.as_bytes()[0..end]
    }

    /// Returns the size of this header, in bytes
    fn header_length(&self) -> usize {
        let b = self.as_bytes();
        usize::from(b[0] & 0x0F) * DWORD_SIZE
    }

    /// Returns the identification value in the IPv4 header
    fn id(&self) -> u16 {
        let b = self.as_bytes();
        u16::from_be_bytes([b[0], b[1]])
    }

    /// Returns the source ip address
    fn src(&self) -> Ipv4Addr {
        let b = self.as_bytes();
        let ip = u32::from_be_bytes([b[12], b[13], b[14], b[15]]);
        Ipv4Addr::from(ip)
    }

    /// Returns the destination ip address
    fn dst(&self) -> Ipv4Addr {
        let b = self.as_bytes();
        let ip = u32::from_be_bytes([b[16], b[17], b[18], b[19]]);
        Ipv4Addr::from(ip)
    }

    /// Returns the next layer (i.e., transport) layer protocol
    fn protocol(&self) -> u8 {
        let b = self.as_bytes();
        b[9]
    }

    /// Returns the flags set on this packet
    fn flags(&self) -> Ipv4Flags {
        let b = self.as_bytes();
        Ipv4Flags::from_bits(b[6] >> 5).unwrap_or(Ipv4Flags::empty())
    }

    /// Returns true if this packet contains fragments
    fn has_fragments(&self) -> bool {
        self.flags().contains(Ipv4Flags::MoreFragments)
    }

    /// Returns the offset of the fragment (or zero, if no fragments)
    fn fragment_offset(&self) -> u16 {
        let b = self.as_bytes();
        let fo = u16::from_be_bytes([b[6], b[7]]);
        (fo & 0x1FFF) * 8
    }

    /// Returns the IP checksum of the packet, as stored in the IPv4 header
    fn checksum(&self) -> u16 {
        let data = self.as_bytes();
        u16::from_be_bytes([data[10], data[11]])
    }

    /// Returns the total length of the packet, as stored in the ipv4
    /// header (includes header + payload)
    fn len(&self) -> u16 {
        let b = self.as_bytes();
        u16::from_be_bytes([b[2], b[3]])
    }

    /// Returns a reference to the data containing the IPv4 packet's payload
    ///
    /// The packet's payload starts with (generally) the transport protocols header
    /// (i.e., TCP header, UDP header, etc.)
    fn payload(&self) -> &[u8] {
        let offset = self.header_length();
        &self.as_bytes()[offset..]
    }

    /// Reverses the IPv4 source and destination addresses, generates a new id, and computes
    /// the internet checksum over the provided payload length
    ///
    /// ### Arguments
    /// * `flags` - IPv4 flags to set on packet
    /// * `pkt` - Layer 3 Packet (including Layer 4+ data) for which to store header in first 20 bytes
    fn gen_response_header(
        &self,
        flags: Ipv4Flags,
        pkt: &mut [u8],
    ) -> Result<Ipv4Addr, ProtocolError> {
        //Ipv4Header::new(self.dst, self.src, self.protocol, payload.len() as u16)
        let mut rng = rand::thread_rng();

        let length = (&pkt[20..]).len();
        let length: u16 = length
            .try_into()
            .map_err(|_| ProtocolError::FragmentationRequired(length))?;

        let id: u16 = rng.gen();

        pkt[0] = 0x45; // 4: IPv4 | 5: header length
        pkt[2..4].copy_from_slice(&length.to_be_bytes());
        pkt[4..6].copy_from_slice(&id.to_be_bytes());
        pkt[6] = flags.bits() << 5;
        pkt[7] = 0x00; // no fragmentation
        pkt[8] = 64; // default TTL is 64
        pkt[9] = self.protocol();
        pkt[10..12].copy_from_slice(&[0x00, 0x00]); // clear checksum
        pkt[12..16].copy_from_slice(&self.dst().octets());
        pkt[16..20].copy_from_slice(&self.src().octets());

        let csum = crate::checksum(&pkt[0..20]);
        pkt[10..12].copy_from_slice(&csum.to_be_bytes());

        Ok(self.src())
    }
}

/// Actions that mutate the current packet
pub trait MutableIpv4Packet: Ipv4Packet {
    /// Returns a mutable reference underlying byte buffer (including the IPv4 header)
    fn as_mut(&mut self) -> &mut [u8];

    /// Returns a mutable reference to the data containing the IPv4 packet's payload
    ///
    /// The packet's payload starts with (generally) the transport protocols header
    /// (i.e., TCP header, UDP header, etc.)
    fn payload_mut(&mut self) -> &mut [u8] {
        let offset = self.header_length();
        &mut self.as_mut()[offset..]
    }

    /// Sets the length field of the IPv4 header
    fn set_length(&mut self, len: u16) {
        let b = self.as_mut();
        b[2..3].copy_from_slice(&len.to_be_bytes());
    }

    /// Sets the source ip address to the provided value and recomputes the header checksum
    ///
    /// ### Arguments
    /// * `ip` - New src ip address
    fn masquerade(&mut self, ip: Ipv4Addr) {
        let b = self.as_mut();
        b[12..16].copy_from_slice(&u32::from(ip).to_be_bytes());

        self.fix_transport_checksum();
    }

    /// Sets the destination ip address to the provided value and recomputes the header checksum
    ///
    /// ### Arguments
    /// * `ip` - New destinaton ip address
    fn unmasquerade(&mut self, ip: Ipv4Addr) {
        let b = self.as_mut();
        b[16..20].copy_from_slice(&u32::from(ip).to_be_bytes());

        self.fix_transport_checksum();
    }

    /// Clears the flags iset on this packet
    fn clear_flags(&mut self) {
        let b = self.as_mut();
        b[6] &= 0x1F;
    }

    /// Clears the fragment offset (sets to zero) for this packet
    fn clear_frag_offset(&mut self) {
        let b = self.as_mut();
        b[6] &= 0xE0;
        b[7] = 0x00;
    }

    /// TCP and UDP both use a pseudo-ip header in their checksum fields
    /// so we'll need to update the TCP/UDP checksum (if necessary)
    fn fix_transport_checksum(&mut self) {
        let src = self.src();
        let dst = self.dst();
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
}

impl<'a> Ipv4PacketRef<'a> {
    /// Creates a new Ipv4Packet that can mutate the underlying data
    pub fn new(data: &'a [u8]) -> Result<Self, ProtocolError> {
        Ok(Self { data })
    }

    /// Takes ownership of the underlying data
    ///
    /// NOTE: this function will allocate a new vector and copy the data in the packet
    /// to the newly allocated space
    pub fn to_owned(self) -> Ipv4PacketOwned {
        Ipv4PacketOwned {
            data: PacketBuffer::new(self.data.to_vec()),
        }
    }
}

impl<'a> Ipv4PacketMut<'a> {
    /// Creates a new Ipv4Packet that can mutate the underlying data
    pub fn new(data: &'a mut [u8]) -> Result<Self, ProtocolError> {
        Ok(Self { data })
    }

    /// Takes ownership of the underlying data
    ///
    /// NOTE: this function will allocate a new vector and copy the data in the packet
    /// to the newly allocated space
    pub fn to_owned(self) -> Ipv4PacketOwned {
        Ipv4PacketOwned {
            data: PacketBuffer::new(self.data.to_vec()),
        }
    }
}

impl Ipv4PacketOwned {
    pub fn new<T: Into<PacketBuffer>>(data: T) -> Result<Self, ProtocolError> {
        let data = data.into();
        Ok(Self { data })
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
            let len = self.len() + (payload.len() as u16);
            self.set_length(len);
        } else if uoffset > end {
            // need to pad the data until we reach the offset?
            self.data.reserve(uoffset);
            self.data.extend_from_slice(&payload);
            let len = offset + (payload.len() as u16);
            self.set_length(len);
        } else {
            let end = uoffset + payload.len();
            self.data[uoffset..end].copy_from_slice(&payload);
        }
    }

    /// Returns an immutable reference to the packet data
    pub fn as_ref(&self) -> Ipv4PacketRef<'_> {
        Ipv4PacketRef { data: &self.data }
    }

    /// Returns a mutable reference to the packet data
    pub fn as_mut(&mut self) -> Ipv4PacketMut<'_> {
        Ipv4PacketMut {
            data: &mut self.data,
        }
    }

    /// Returns the amount of allocated data in the underlying vector
    pub fn capacity(&self) -> usize {
        self.data.capacity()
    }

    /// Consumes this IPv4 packet, returning the underlying packet buffer
    pub fn consume(self) -> PacketBuffer {
        self.data
    }
}

impl Ipv4Packet for Ipv4PacketOwned {
    fn as_bytes(&self) -> &[u8] {
        &self.data
    }
}

impl<'a> Ipv4Packet for Ipv4PacketRef<'a> {
    fn as_bytes(&self) -> &[u8] {
        &self.data
    }
}

impl<'a> Ipv4Packet for Ipv4PacketMut<'a> {
    fn as_bytes(&self) -> &[u8] {
        &self.data
    }
}

impl MutableIpv4Packet for Ipv4PacketOwned {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }
}

impl<'a> MutableIpv4Packet for Ipv4PacketMut<'a> {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }
}

impl AsRef<[u8]> for Ipv4PacketOwned {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

impl<'a> AsRef<[u8]> for Ipv4PacketRef<'a> {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

impl<'a> AsRef<[u8]> for Ipv4PacketMut<'a> {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

impl AsMut<[u8]> for Ipv4PacketOwned {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }
}

impl<'a> AsMut<[u8]> for Ipv4PacketMut<'a> {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.data
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

    use super::{Ipv4Packet, Ipv4PacketOwned, MutableIpv4Packet};

    fn init_tracing() {
        tracing_subscriber::FmtSubscriber::builder()
            .with_max_level(tracing::Level::DEBUG)
            .pretty()
            .init();
    }

    fn read_file(path: &str) -> Ipv4PacketOwned {
        use std::fs::File;

        let mut data = Vec::new();
        let mut fd = File::open(path).unwrap();
        fd.read_to_end(&mut data).unwrap();

        let pkt = Ipv4PacketOwned::new(data).unwrap();
        tracing::debug!("ipv4 packet id: 0x{:04x}", pkt.id());
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
