//! MAC Address

use std::{
    fmt::{Debug, Display},
    os::fd::AsRawFd,
    str::FromStr,
};

use nix::{
    libc::{IFNAMSIZ, SIOCGIFHWADDR},
    sys::socket::SockFlag,
};
use rand::RngCore;
use serde::{de::Visitor, Deserialize, Serialize};

use crate::ProtocolError;

/// Representation of  MAC address
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct MacAddress([u8; 6]);

impl MacAddress {
    /// Returns the broadcast MacAddress (FF:FF:FF:FF:FF:FF)
    pub const fn broadcast() -> Self {
        Self([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF])
    }

    /// Parses a MAC address from a byte buffer
    ///
    /// ### Arguments
    /// * `bytes` - Bytes to extract MAC address from
    pub fn parse(bytes: &[u8]) -> Result<Self, ProtocolError> {
        let mut mac = [0u8; 6];
        if bytes.len() < mac.len() {
            return Err(ProtocolError::NotEnoughData(bytes.len(), mac.len()));
        }

        mac.copy_from_slice(&bytes[0..6]);
        Ok(Self(mac))
    }

    /// Attempts to read the MAC address from a specified interface
    ///
    /// ### Arguments
    /// * `name` - Name of the ethernet inferface (i.e., eth0, ens18)
    pub fn from_interface(name: &str) -> Result<Self, ProtocolError> {
        // #define SIOCGIFHWADDR 0x8927
        nix::ioctl_read_bad!(siocgifhwaddr, SIOCGIFHWADDR, nix::libc::ifreq);

        let mut ifr_name = [0i8; IFNAMSIZ];
        for (idx, b) in name.as_bytes().iter().enumerate() {
            ifr_name[idx] = *b as i8;
        }

        // get the mac address
        let mut req = nix::libc::ifreq {
            ifr_name,
            ifr_ifru: nix::libc::__c_anonymous_ifr_ifru {
                ifru_hwaddr: nix::libc::sockaddr {
                    sa_family: 0,
                    sa_data: [0; 14],
                },
            },
        };

        let sock = nix::sys::socket::socket(
            nix::sys::socket::AddressFamily::Inet,
            nix::sys::socket::SockType::Datagram,
            SockFlag::empty(),
            None,
        )
        .map_err(|e| ProtocolError::Other(e.to_string()))?;

        let mac = unsafe {
            siocgifhwaddr(sock.as_raw_fd(), &mut req as *mut _)
                .map_err(|e| ProtocolError::Other(e.to_string()))?;
            req.ifr_ifru.ifru_hwaddr.sa_data
        };

        MacAddress::try_from(mac.as_slice())
    }

    /// Generates a new MAC address with the prefix 52:54:00
    pub fn generate() -> Self {
        let mut rng = rand::thread_rng();
        let mut mac = [0x52, 0x54, 0x00, 0x00, 0x00, 0x00];
        rng.fill_bytes(&mut mac[3..6]);
        Self(mac)
    }

    /// Returns a reference to the underlying bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Returns true if this MAC is the broadcast address
    pub fn is_broadcast(&self) -> bool {
        *self == Self::broadcast()
    }
}

impl TryFrom<&[i8]> for MacAddress {
    type Error = ProtocolError;

    fn try_from(bytes: &[i8]) -> Result<Self, Self::Error> {
        let mut mac = [0u8; 6];
        if bytes.len() < mac.len() {
            return Err(ProtocolError::NotEnoughData(bytes.len(), mac.len()));
        }

        for i in 0..6 {
            mac[i] = bytes[i] as u8;
        }
        Ok(Self(mac))
    }
}

impl Debug for MacAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "MacAddress({:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x})",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}

impl Display for MacAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}

impl FromStr for MacAddress {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<_> = s
            .split(&[':', '-'])
            .filter_map(|s| u8::from_str_radix(s, 16).ok())
            .collect();
        if parts.len() != 6 {
            return Err("invalid MAC format, expected: 01:02:03:04:05:05");
        } else {
            let mut mac = [0u8; 6];
            mac.copy_from_slice(&parts[0..6]);
            Ok(Self(mac))
        }
    }
}

struct MacAddressVisitor;

impl<'de> Visitor<'de> for MacAddressVisitor {
    type Value = MacAddress;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("expected mac address in format 01:02:03:04:05:06 or 01-02-03-04-05-06")
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        v.parse::<MacAddress>()
            .map_err(|e| E::custom(e.to_string()))
    }
}

impl<'de> Deserialize<'de> for MacAddress {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_str(MacAddressVisitor)
    }
}

impl Serialize for MacAddress {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::MacAddress;

    #[test]
    fn parse_mac_good_colons() {
        let input = "52:54:00:de:ad:01";
        let mac: MacAddress = input.parse().unwrap();
        assert_eq!(&mac.to_string(), &input, "failed to parse mac address");
    }

    #[test]
    fn parse_mac_good_hyphens() {
        let input = "52-54-00-de-ad-01";
        let expected = "52:54:00:de:ad:01";
        let mac = input.parse::<MacAddress>().unwrap();
        assert_eq!(&mac.to_string(), &expected, "failed to parse mac address");
    }

    #[test]
    fn parse_mac_bad_too_short() {
        let input = "52:54";
        let res = input.parse::<MacAddress>();
        assert!(res.is_err());
    }

    #[test]
    fn parse_mac_bad_too_long() {
        let input = "52:54:00:de:ad:01:04";
        let res = input.parse::<MacAddress>();
        assert!(res.is_err());
    }

    #[test]
    fn parse_mac_bad_not_hex() {
        let input = "52:54:00:dg:ad:01";
        let res = input.parse::<MacAddress>();
        assert!(res.is_err());
    }
}
