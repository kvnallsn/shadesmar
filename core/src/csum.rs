//! Checksum related functions

use std::net::Ipv4Addr;

/// Computes the checksum used in various networking protocols
///
/// Algorithm is the one's complement of the sum of the data as big-ending u16 values
///
/// ### Arguments
/// * `data` - Data to checksum
pub fn checksum(data: &[u8]) -> u16 {
    let sum = checksum_common(data);
    !(((sum & 0xFFFF) + ((sum >> 16) & 0xFFFF)) as u16)
}

/// Computes the partial pseudo-header checksum as used by TCP and UDP
///
/// The partial psuedo-header checksum is used for TCP/UDP checksum offloading
/// and only includes:
/// * Source IP (32 bits)
/// * Destination IP (32 bits)
/// * Protocol (16 bits)
/// * Header + Payload Length (16 bits)
///
/// It is expected the network interface card (NIC) will compute the checksum over
/// the remaining data before the packet is sent over the wire (or air, or other
/// transmission means)
///
/// ### Arguments
/// * `src` - Source IPv4 Address
/// * `dst` - Destination IPv4 Address
/// * `proto` - Protocol Number (i.e. 6 for TCP)
/// * `data` - TCP/UDP header + payload
pub fn ph_partial_checksum(src: Ipv4Addr, dst: Ipv4Addr, proto: u8, data: &[u8]) -> u16 {
    let mut sum = 0;
    sum += checksum_common(&src.octets());
    sum += checksum_common(&dst.octets());
    sum += u32::from(proto);
    sum += (data.len() & 0xFFFF) as u32;

    ((sum & 0xFFFF) + ((sum >> 16) & 0xFFFF)) as u16
}

/// Computes the pseudo-header checksum as used by TCP and UDP
///
/// ### Arguments
/// * `src` - Source IPv4 Address
/// * `dst` - Destination IPv4 Address
/// * `proto` - Protocol Number (i.e. 6 for TCP)
/// * `data` - TCP/UDP header + payload
pub fn ph_full_checksum(src: Ipv4Addr, dst: Ipv4Addr, proto: u8, data: &[u8]) -> u16 {
    let partial_sum = ph_partial_checksum(src, dst, proto, data) as u32;
    let payload_sum = checksum_common(data);

    let csum = partial_sum + payload_sum;
    !(((csum & 0xFFFF) + ((csum >> 16) & 0xFFFF)) as u16)
}

/// Helper function to compute the sum of a slice of data
fn checksum_common(data: &[u8]) -> u32 {
    let mut sum = 0;
    for b in data.chunks(2) {
        let b0 = b[0];
        let b1 = match b.len() {
            1 => 0x00,
            _ => b[1],
        };

        sum += u32::from_be_bytes([0x00, 0x00, b0, b1]);
    }

    sum
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use crate::csum::ph_full_checksum;

    use super::{checksum, ph_partial_checksum};

    // TCP/IP packet with checksums zero'd out
    const PKT: [u8; 144] = [
        0x52, 0x54, 0x00, 0x81, 0xf1, 0x33, 0x00, 0x56, 0x50, 0xde, 0xad, 0x00, 0x08, 0x00, 0x45,
        0x00, 0x00, 0x82, 0x42, 0xcd, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 0x0a, 0x43, 0xd5, 0x64,
        0x22, 0xa0, 0x6f, 0x91, 0x88, 0xce, 0x00, 0x50, 0xe1, 0xff, 0xf9, 0x7d, 0x3a, 0x1b, 0xca,
        0x1e, 0x80, 0x18, 0x03, 0xec, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x08, 0x0a, 0x0b, 0xeb,
        0x07, 0x19, 0x71, 0xcb, 0x4d, 0xf2, 0x47, 0x45, 0x54, 0x20, 0x2f, 0x70, 0x6c, 0x61, 0x69,
        0x6e, 0x20, 0x48, 0x54, 0x54, 0x50, 0x2f, 0x31, 0x2e, 0x31, 0x0d, 0x0a, 0x48, 0x6f, 0x73,
        0x74, 0x3a, 0x20, 0x69, 0x70, 0x65, 0x63, 0x68, 0x6f, 0x2e, 0x6e, 0x65, 0x74, 0x0d, 0x0a,
        0x55, 0x73, 0x65, 0x72, 0x2d, 0x41, 0x67, 0x65, 0x6e, 0x74, 0x3a, 0x20, 0x57, 0x67, 0x65,
        0x74, 0x0d, 0x0a, 0x43, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x3a, 0x20,
        0x63, 0x6c, 0x6f, 0x73, 0x65, 0x0d, 0x0a, 0x0d, 0x0a,
    ];

    fn get_ipv4_src() -> Ipv4Addr {
        Ipv4Addr::new(PKT[26], PKT[27], PKT[28], PKT[29])
    }

    fn get_ipv4_dst() -> Ipv4Addr {
        Ipv4Addr::new(PKT[30], PKT[31], PKT[32], PKT[33])
    }

    fn get_ipv4_proto() -> u8 {
        PKT[23]
    }

    fn get_ipv4_payload() -> &'static [u8] {
        &PKT[34..]
    }

    #[test]
    fn valid_ip_checksum() {
        let csum = checksum(&PKT[14..34]);
        assert_eq!(csum, 0x85d0, "bad ip checksum");
    }

    #[test]
    fn invalid_ip_checksum() {
        let csum = checksum(&PKT[13..33]);
        assert_ne!(csum, 0x85d0, "got correct ip checksum, expected bad value");
    }

    #[test]
    fn valid_partial_csum() {
        let partial = ph_partial_checksum(
            get_ipv4_src(),
            get_ipv4_dst(),
            get_ipv4_proto(),
            get_ipv4_payload(),
        );
        assert_eq!(partial, 0x724d, "bad partial psuedo-header checksum");
    }

    #[test]
    fn invalid_partial_csum() {
        let partial = ph_partial_checksum(
            Ipv4Addr::new(0, 0, 0, 0),
            get_ipv4_dst(),
            get_ipv4_proto(),
            get_ipv4_payload(),
        );
        assert_ne!(
            partial, 0x724d,
            "got correct partial checksum, expected bad value"
        );
    }

    #[test]
    fn valid_full_cusm() {
        let full = ph_full_checksum(
            get_ipv4_src(),
            get_ipv4_dst(),
            get_ipv4_proto(),
            get_ipv4_payload(),
        );
        assert_eq!(full, 0x854c, "bad full psuedo-header checksum");
    }

    #[test]
    fn invalid_full_csum() {
        let full = ph_full_checksum(
            Ipv4Addr::new(0, 0, 0, 0),
            get_ipv4_dst(),
            get_ipv4_proto(),
            get_ipv4_payload(),
        );
        assert_ne!(
            full, 0x854c,
            "got correct full checksum, expected bad value"
        );
    }
}
