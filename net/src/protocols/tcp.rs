//! TCP header and packet

use std::fmt::Display;

use bitflags::bitflags;

use crate::ProtocolError;

/// Represents a TCP header
#[derive(Debug, Clone, Copy)]
pub struct TcpHeader {
    /// Identifies the source (sender's) port
    pub src_port: u16,

    /// Identifies the destination (receiver's) port
    pub dst_port: u16,

    /// Sequence Number
    /// - If SYN is set, this is the initial sequence number
    /// - If SYN is unset, this is the accumulated sequence number
    pub seq_num: u32,

    /// Acknowledgment number (if the ACK flag is set)
    pub ack_num: u32,

    /// Size of the TCP header in DWORDs, minimum size is 5, max is 15
    pub data_offset: u8,

    /// Various TCP control flags
    pub flags: TcpFlags,

    /// Size of the receive window
    pub window_size: u16,

    /// Used for error-checking on destination, incorporates the IP pseudo-header
    pub checksum: u16,

    /// If URG is set, offset from sequence number indiciating the last urgent data byte
    pub urgent_pointer: u16,
}

bitflags! {
    /// Represents the flags that can be set on a TCP packet
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct TcpFlags: u8 {
        /// Last packet from sender
        const FIN = 0b00000001;

        /// SYNchronize sequence numbers (first packet from sender)
        const SYN = 0b00000010;

        /// Reset the connection
        const RST = 0b00000100;

        /// Push function -- push buffered data to the receiving application
        const PSH = 0b00001000;

        /// Acknowledgment field is significant (aka contains the seq_num of the last recv'd packet)
        const ACK = 0b00010000;

        /// Urgent pointer field is significant (set)
        const URG = 0b00100000;

        /// ECN-Echo, varies based on SYN flag:
        /// - SYN is set (1): TCP peer is ECN capable
        /// - SYN is unset (0): possible network congestion
        const ECE = 0b01000000;

        /// Congestion Window Reduced
        /// Set by sending host to indicate it received a TCP segment with the ECE flag set
        const CWR = 0b10000000;
    }
}

/// TCP headers are at least 20 bytes
const TCP_MIN_HDR_SZ: usize = 20;

impl TcpHeader {
    /// returns the size of a TCP header
    pub const fn min_size() -> usize {
        TCP_MIN_HDR_SZ
    }

    /// Extracts the header fields from a slice of data
    ///
    /// The TCP header is expected to be a the start of the byte slice.  The data
    /// is expected to be in network (big) endian format.
    pub fn extract_from_slice(data: &[u8]) -> Result<Self, ProtocolError> {
        if data.is_empty() || data.len() < Self::min_size() {
            return Err(ProtocolError::NotEnoughData(0, Self::min_size()));
        }

        let src_port = u16::from_be_bytes([data[0], data[1]]);
        let dst_port = u16::from_be_bytes([data[2], data[3]]);
        let seq_num = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        let ack_num = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
        let data_offset: u8 = data[12] >> 0x04;
        let flags = TcpFlags::from_bits_truncate(data[13]);
        let window_size = u16::from_be_bytes([data[14], data[15]]);
        let checksum = u16::from_be_bytes([data[16], data[17]]);
        let urgent_pointer = u16::from_be_bytes([data[18], data[19]]);

        Ok(Self {
            src_port,
            dst_port,
            seq_num,
            ack_num,
            data_offset,
            flags,
            window_size,
            checksum,
            urgent_pointer,
        })
    }

    /// Returns the size of the header based on the data_offset field
    pub fn size(&self) -> usize {
        usize::from(self.data_offset) * 4
    }
}

macro_rules! flag_append {
    ($str:expr, $flags:expr, $flag:expr, $set:expr, $unset:expr) => {
        if $flags.contains($flag) {
            $str.push($set);
        } else {
            $str.push($unset);
        }
    };
}

impl Display for TcpFlags {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut flags = String::from("");
        flag_append!(flags, self, TcpFlags::FIN, 'F', '_');
        flag_append!(flags, self, TcpFlags::SYN, 'S', '_');
        flag_append!(flags, self, TcpFlags::RST, 'R', '_');
        flag_append!(flags, self, TcpFlags::PSH, 'P', '_');
        flag_append!(flags, self, TcpFlags::ACK, 'A', '_');
        flag_append!(flags, self, TcpFlags::URG, 'U', '_');
        flag_append!(flags, self, TcpFlags::ECE, 'E', '_');
        flag_append!(flags, self, TcpFlags::CWR, 'C', '_');

        write!(f, "{flags}")
    }
}
