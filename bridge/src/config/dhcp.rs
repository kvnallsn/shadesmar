//! DHCP server configuration

use std::{net::Ipv4Addr, str::FromStr};

use serde::{Deserialize, Serialize};

/// Configuration for the internal DHCP server
#[derive(Debug, Deserialize, Serialize)]
pub struct DhcpConfig {
    /// Start address for the DHCP pool
    pub start: Ipv4Addr,

    /// End address for the DHCP pool
    pub end: Ipv4Addr,
}

impl FromStr for DhcpConfig {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut parts = s.split("-");
        let start = parts.next().ok_or_else(|| "start address not specified")?;
        let end = parts.next().ok_or_else(|| "end address not specified")?;

        let start = start
            .parse::<Ipv4Addr>()
            .map_err(|_| "invalid start address")?;
        let end = end.parse::<Ipv4Addr>().map_err(|_| "invalid end address")?;

        if end < start {
            return Err("end address is before start address");
        }

        Ok(Self { start, end })
    }
}

#[cfg(test)]
mod tests {
    use super::DhcpConfig;

    #[test]
    fn dhcp_parse_string_good() {
        let input = "192.168.2.100-192.168.2.130";
        let cfg = input.parse::<DhcpConfig>();
        assert!(cfg.is_ok())
    }

    #[test]
    fn dhcp_parse_string_end_before_start() {
        let input = "192.168.2.200-192.168.2.130";
        let cfg = input.parse::<DhcpConfig>();
        assert!(cfg.is_err())
    }

    #[test]
    fn dhcp_parse_invalid_start_ip() {
        let input = "192.168.2-192.168.2.130";
        let cfg = input.parse::<DhcpConfig>();
        assert!(cfg.is_err())
    }

    #[test]
    fn dhcp_parse_invalid_end_ip() {
        let input = "192.168.2.100-192.168.2";
        let cfg = input.parse::<DhcpConfig>();
        assert!(cfg.is_err())
    }

    #[test]
    fn dhcp_parse_no_end_ip() {
        let input = "192.168.2.100";
        let cfg = input.parse::<DhcpConfig>();
        assert!(cfg.is_err())
    }
}
