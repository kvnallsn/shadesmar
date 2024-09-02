mod frame;
pub mod ipv4;
mod macros;
pub mod nat;
pub mod plugins;
pub mod protocols;
pub mod queue;
pub mod switch;
pub mod types;

use std::net::Ipv4Addr;

pub use self::frame::{EthernetFrame, EthernetPacket};

/// Initializes the logging / tracing library
pub fn init_tracinig(level: u8) {
    let tracing_level = match level {
        0 => tracing::Level::WARN,
        1 => tracing::Level::INFO,
        2 => tracing::Level::DEBUG,
        _ => tracing::Level::TRACE,
    };

    tracing_subscriber::FmtSubscriber::builder()
        .with_max_level(tracing_level)
        .pretty()
        .init();
}

#[derive(thiserror::Error, Debug)]
pub enum ProtocolError {
    #[error("not enough data for payload, got = {0}, expected = {1}")]
    NotEnoughData(usize, usize),

    #[error("malformed packet: {0}")]
    MalformedPacket(String),

    #[error("packet fragmentation required. size = {0}")]
    FragmentationRequired(usize),

    #[error("{0}")]
    Other(String),
}

/// Computes the checksum used in various networking protocols
///
/// Algorithm is the one's complement of the sum of the data as big-ending u16 values
///
/// ### Arguments
/// * `data` - Data to checksum
pub fn checksum(data: &[u8]) -> u16 {
    let mut sum = 0;
    for b in data.chunks(2) {
        let b0 = b[0];
        let b1 = match b.len() {
            1 => 0x00,
            _ => b[1],
        };

        sum += u32::from_be_bytes([0x00, 0x00, b0, b1]);
    }

    !(((sum & 0xFFFF) + ((sum >> 16) & 0xFFFF)) as u16)
}

/// Computes the pseudo-header checksum as used by TCP and UDP
///
/// ### Arguments
/// * `src` - Source IPv4 Address
/// * `dst` - Destination IPv4 Address
/// * `proto` - Protocol Number (i.e. 6 for TCP)
/// * `data` - TCP/UDP header + payload
pub fn ph_checksum(src: Ipv4Addr, dst: Ipv4Addr, proto: u8, data: &[u8]) -> u16 {
    let mut sum = 0;
    let ip = src.octets();
    sum += u32::from_be_bytes([0x00, 0x00, ip[2], ip[3]]);
    sum += u32::from_be_bytes([0x00, 0x00, ip[0], ip[1]]);
    let ip = dst.octets();
    sum += u32::from_be_bytes([0x00, 0x00, ip[2], ip[3]]);
    sum += u32::from_be_bytes([0x00, 0x00, ip[0], ip[1]]);
    sum += u32::from(proto);

    let len = data.len();
    sum += (len & 0xFFFF) as u32;

    for b in data.chunks(2) {
        let b0 = b[0];
        let b1 = match b.len() {
            1 => 0x00,
            _ => b[1],
        };

        sum += u32::from_be_bytes([0x00, 0x00, b0, b1]);
    }

    !(((sum & 0xFFFF) + ((sum >> 16) & 0xFFFF)) as u16)
}
