//! UDP header and packet

use crate::ProtocolError;

/// Represents a UDP header
#[derive(Debug, Clone, Copy)]
pub struct UdpHeader {
    /// Identifies the source (sender's) port
    pub src_port: u16,

    /// Identifies the destination (receiver's) port
    pub dst_port: u16,

    /// Length of the UDP header + UDP data
    pub length: u16,

    /// Used for error-checking on destination, optional in IPv4
    pub checksum: u16,
}

/// UDP headers are always 8 bytes (or 64-bits)
const UDP_HDR_SZ: usize = 8;

impl UdpHeader {
    /// returns the size of a UDP header
    pub const fn size() -> usize {
        UDP_HDR_SZ
    }

    /// Extracts the header fields from a slice of data
    ///
    /// The UDP header is expected to be a the start of the byte slice.  The data
    /// is expected to be in network (big) endian format.
    pub fn extract_from_slice(data: &[u8]) -> Result<Self, ProtocolError> {
        if data.is_empty() || data.len() < Self::size() {
            return Err(ProtocolError::NotEnoughData(0, Self::size()));
        }

        let src_port = u16::from_be_bytes([data[0], data[1]]);
        let dst_port = u16::from_be_bytes([data[2], data[3]]);
        let length = u16::from_be_bytes([data[4], data[5]]);
        let checksum = u16::from_be_bytes([data[6], data[7]]);

        Ok(Self {
            src_port,
            dst_port,
            length,
            checksum,
        })
    }
}
