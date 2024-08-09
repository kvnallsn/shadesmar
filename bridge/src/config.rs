//! Configuration file module

pub(crate) mod dhcp;

use std::{collections::HashMap, fs::File, io, net::SocketAddr, path::Path};

use serde::{Deserialize, Serialize};
use shadesmar_net::types::Ipv4Network;

use crate::{config::dhcp::DhcpConfig, net::wan::WgConfig};

/// Shadesmar network configuration
///
/// A network config consists of three main sections:
/// - wan: The various upstream / wide area network connections
/// - router: Various router configuration settings
/// - virtio: Virtio configuration settings
#[derive(Debug, Deserialize, Serialize)]
pub struct Config {
    pub wan: Vec<WanConfig>,
    pub router: RouterConfig,
    pub virtio: VirtioConfig,
}

/// Contains all information needed to initialize a WAN connection
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub struct WanConfig {
    /// Human-friendly name for WAN connection
    pub name: String,

    /// The IPv4 address to assign to this WAN device
    pub ipv4: Ipv4Network,

    /// WAN-device specific configuration
    pub device: WanDevice,
}

/// Various different types of WAN devices supported by shadesmar
#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum WanDevice {
    /// A generic tap device
    Tap(TapConfig),

    /// Forwards traffic to a UDP socket
    Udp(UdpConfig),

    /// Forwards all traffic over a wireguard socket
    Wireguard(WgConfig),
}

#[derive(Debug, Deserialize, Serialize)]
pub struct TapConfig {
    pub device: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct UdpConfig {
    pub endpoint: SocketAddr,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct RouterConfig {
    pub ipv4: Ipv4Network,
    pub dhcp: DhcpConfig,
    pub dns: bool,
    pub table: HashMap<Ipv4Network, String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct VirtioConfig {
    pub queues: u8,
}

impl Config {
    /// Loads a configuration file from disk
    ///
    /// ### Arguments
    /// * `path` - Path to the configuration file
    pub fn load<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        let f = File::open(path)?;
        let cfg: Config =
            serde_yaml::from_reader(f).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        Ok(cfg)
    }
}
