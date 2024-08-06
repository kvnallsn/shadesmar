//! Network Address

use std::{
    fmt::Display,
    net::{Ipv4Addr, Ipv6Addr},
    str::FromStr,
};

use serde::{de::Visitor, Deserialize, Serialize};

#[derive(Debug)]
pub enum IpNetwork {
    V4(Ipv4Network),
    V6(Ipv6Network),
}

#[derive(Clone, Copy, Debug)]
pub struct Ipv4Network {
    ip: Ipv4Addr,
    mask: Ipv4Addr,
}

#[derive(Clone, Copy, Debug)]
pub struct Ipv6Network {
    ip: Ipv6Addr,
    mask: Ipv6Addr,
}

impl Ipv4Network {
    /// Creats a new IPv4 network address (aka IP address with a subnet)
    ///
    /// ### Arguments
    /// * `ip` - IPv4 Address
    /// * `mask` - Subnet mask
    pub fn new<I: Into<Ipv4Addr>>(ip: I, mask: u8) -> Self {
        let mut subnet: u32 = u32::MAX;
        for idx in 0..(32 - mask) {
            subnet = subnet ^ (1 << idx);
        }

        Self {
            ip: ip.into(),
            mask: subnet.into(),
        }
    }

    /// Returns the subnet mask of this network
    pub fn subnet_mask(&self) -> Ipv4Addr {
        self.mask
    }

    /// Returns the subnet mask of this network
    pub fn subnet_mask_bits(&self) -> u8 {
        u32::from(self.mask).count_ones() as u8
    }

    /// Returns the IPv4 address used to create this network
    pub fn ip(&self) -> Ipv4Addr {
        self.ip
    }

    /// Returns the network address of this network
    pub fn network(&self) -> Ipv4Addr {
        self.ip & self.mask
    }

    /// Returns the broadcast address of this network
    pub fn broadcast(&self) -> Ipv4Addr {
        self.ip | !self.mask
    }

    /// Returns true if the IP address is contained within the network
    pub fn contains<I: Into<Ipv4Addr>>(&self, ip: I) -> bool {
        (ip.into() & self.mask) == self.network()
    }

    /// Returns the next IP from in the subnet
    pub fn next(&self) -> Option<Ipv4Network> {
        let ip = u32::from(self.ip).wrapping_add(1);
        let ip = Ipv4Addr::from(ip);

        if ip == self.network() || ip == self.broadcast() {
            None
        } else {
            Some(Self::new(ip, self.subnet_mask_bits()))
        }
    }
}

impl Ipv6Network {
    /// Creats a new IPv6 network address (aka IP address with a subnet)
    ///
    /// ### Arguments
    /// * `ip` - IPv6 Address
    /// * `mask` - Subnet mask
    pub fn new<I: Into<Ipv6Addr>>(ip: I, mask: u8) -> Self {
        let mut subnet: u128 = u128::MAX;
        for idx in 0..(128 - mask) {
            subnet = subnet ^ (1 << idx);
        }

        Self {
            ip: ip.into(),
            mask: subnet.into(),
        }
    }

    /// Returns the subnet mask of this network
    pub fn subnet_mask(&self) -> Ipv6Addr {
        self.mask
    }

    /// Returns the subnet mask of this network
    pub fn subnet_mask_bits(&self) -> u8 {
        u128::from(self.mask).count_ones() as u8
    }

    /// Returns the IPv6 address used to create this network
    pub fn ip(&self) -> Ipv6Addr {
        self.ip
    }

    /// Returns the network address of this network
    pub fn network(&self) -> Ipv6Addr {
        self.ip & self.mask
    }

    /// Returns the broadcast address of this network
    pub fn broadcast(&self) -> Ipv6Addr {
        self.ip | !self.mask
    }

    /// Returns true if the IP address is contained within the network
    pub fn contains<I: Into<Ipv6Addr>>(&self, ip: I) -> bool {
        (ip.into() & self.mask) == self.network()
    }

    /// Returns the next IP from in the subnet
    pub fn next(&self) -> Option<Ipv6Network> {
        let ip = u128::from(self.ip).wrapping_add(1);
        let ip = Ipv6Addr::from(ip);

        if ip == self.network() || ip == self.broadcast() {
            None
        } else {
            Some(Self::new(ip, self.subnet_mask_bits()))
        }
    }
}

impl Display for Ipv4Network {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mask = u32::from(self.mask).count_ones();
        write!(f, "{}/{}", self.ip, mask)
    }
}

impl FromStr for Ipv4Network {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut parts = s.split("/");
        let ip = parts.next().ok_or_else(|| "missing ip component")?;
        let mask = parts.next().unwrap_or_else(|| "32");

        let ip: Ipv4Addr = ip.parse().map_err(|_| "unable to parse ip address")?;
        let mask: u8 = mask.parse().map_err(|_| "unable to parse subnet mask")?;

        Ok(Self::new(ip, mask))
    }
}

impl PartialEq<Ipv4Addr> for Ipv4Network {
    fn eq(&self, other: &Ipv4Addr) -> bool {
        self.ip == *other
    }
}

struct Ipv4NetworkVisitor;

impl<'de> Visitor<'de> for Ipv4NetworkVisitor {
    type Value = Ipv4Network;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("a network address, like 192.168.2.1/24")
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        v.parse::<Ipv4Network>()
            .map_err(|e| E::custom(e.to_string()))
    }
}

impl<'de> Deserialize<'de> for Ipv4Network {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_str(Ipv4NetworkVisitor)
    }
}

impl Serialize for Ipv4Network {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::Ipv4Network;

    #[test]
    fn create_cidr_ipv4() {
        let cidr = Ipv4Network::new([10, 10, 10, 1], 24);
        assert_eq!("10.10.10.1/24", &cidr.to_string());
    }

    #[test]
    fn get_subnet_mask_bits() {
        let cidr = Ipv4Network::new([10, 10, 10, 1], 24);
        assert_eq!(cidr.subnet_mask_bits(), 24);
    }

    #[test]
    fn get_next_address_good() {
        let cidr = Ipv4Network::new([10, 10, 10, 1], 24);
        let expected = Ipv4Addr::from([10, 10, 10, 2]);

        let next = cidr.next();
        assert!(next.is_some());
        let next = next.unwrap();
        assert_eq!(next.ip(), expected);
    }

    #[test]
    fn get_next_address_bad_broadcast() {
        let cidr = Ipv4Network::new([10, 10, 10, 254], 24);

        let next = cidr.next();
        assert!(next.is_none());
    }

    #[test]
    fn get_network_addresss_ipv4() {
        let cidr = Ipv4Network::new([10, 10, 10, 1], 24);
        let net = cidr.network();
        assert_eq!("10.10.10.0", &net.to_string());
    }

    #[test]
    fn get_broadcast_addresss_ipv4() {
        let cidr = Ipv4Network::new([10, 10, 10, 1], 24);
        let net = cidr.broadcast();
        assert_eq!("10.10.10.255", &net.to_string());
    }

    #[test]
    fn contains_ipv4_good() {
        let cidr = Ipv4Network::new([10, 10, 10, 1], 24);
        let val = cidr.contains(Ipv4Addr::from([10, 10, 10, 45]));
        assert_eq!(val, true, "10.10.10.0/24 cidr should contain 10.10.10.45");
    }

    #[test]
    fn contains_ipv4_bad() {
        let cidr = Ipv4Network::new([10, 10, 10, 1], 24);
        let val = cidr.contains(Ipv4Addr::from([10, 10, 11, 45]));
        assert_eq!(
            val, false,
            "10.10.10.0/24 cidr should not contain 10.10.11.45"
        );
    }

    #[test]
    fn parse_ipv4_string() {
        let cidr: Ipv4Network = "10.10.10.213/25".parse().unwrap();
        let net = cidr.network();
        let broadcast = cidr.broadcast();
        assert_eq!("10.10.10.128", &net.to_string(), "network mismatch");
        assert_eq!("10.10.10.255", &broadcast.to_string(), "broadcast mismatch");
    }
}
