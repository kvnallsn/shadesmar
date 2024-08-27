//! Simple network switch

use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

use parking_lot::RwLock;

use serde::{Deserialize, Serialize};
use shadesmar_core::{types::MacAddress, EthernetFrame, ProtocolError, Switch, SwitchPort};

use super::{pcap::PcapLogger, NetworkError, ETHERNET_HDR_SZ};

/// A simple layer-2 switch for virtio devices
#[derive(Clone)]
pub struct VirtioSwitch {
    /// Handles to devices connected to switch ports
    ports: Arc<RwLock<Vec<Box<dyn SwitchPort>>>>,

    /// Map of MacAddress to switch ports
    cache: Arc<RwLock<HashMap<MacAddress, usize>>>,

    /// Pcap logger, if configured
    logger: Arc<PcapLogger>,

    /// Total packets that traversed this switch
    pkt_stats: Arc<AtomicU64>,
}

/// Contains the status about an individual port
#[derive(Debug, Deserialize, Serialize)]
pub struct PortStatus {
    pub desc: String,
    pub macs: Vec<MacAddress>,
}

/// Contains the status of a switch
#[derive(Debug, Deserialize, Serialize)]
pub struct SwitchStatus {
    /// Mapping of ports to known mac addresses
    pub ports: Vec<PortStatus>,

    /// Total amount (in bytes) that traverse this switch
    pub pkt_stats: u64,
}

impl VirtioSwitch {
    /// Creates a new, empty switch with no ports connected
    ///
    /// ### Arguments
    /// * `logger` - Handle to Pcap logging thread
    pub fn new(logger: Arc<PcapLogger>) -> Result<Self, NetworkError> {
        Ok(Self {
            logger,
            ports: Arc::new(RwLock::new(Vec::new())),
            cache: Arc::new(RwLock::new(HashMap::new())),
            pkt_stats: Arc::new(AtomicU64::new(0)),
        })
    }

    /// Maps a switch port to a MAC address for later retrieval
    ///
    /// ### Arguments
    /// * `port` - Switch port number
    /// * `mac` - MAC address to associate with port
    fn associate_port(&self, port: usize, mac: MacAddress) {
        let mut cache = self.cache.write();

        // associate MAC address of source with port
        match cache.insert(mac, port) {
            Some(old_port) if port == old_port => { /* do nothing, no port change */ }
            Some(old_port) => {
                tracing::trace!(
                    port,
                    old_port,
                    "[switch] associating mac ({}) with new port",
                    mac
                )
            }
            None => tracing::trace!("[switch] associating mac ({}) with port {}", mac, port),
        }
    }

    /// Returns the switch port associated with a MAC address, or None if no port was found
    fn get_port(&self, mac: MacAddress) -> Option<usize> {
        let cache = self.cache.read();
        cache.get(&mac).map(|port| *port)
    }

    /// Registers a new tap to receive pcap/netflow
    ///
    /// ### Arguments
    /// * `socket` - Path to unix datagram socket
    pub fn register_tap<P: Into<PathBuf>>(&self, socket: P) {
        self.logger.add_tap(socket);
    }

    /// Returns the status of this switch
    ///
    /// Status information includes:
    /// - Port / Mac mappings
    /// - WAN configuration
    pub fn get_status(&self) -> Result<SwitchStatus, NetworkError> {
        let mut ports: HashMap<usize, Vec<MacAddress>> = HashMap::new();

        let cache = self.cache.read();
        for (mac, port) in cache.iter() {
            let port_macs = ports.entry(*port).or_default();
            port_macs.push(*mac);
        }

        let mut status: Vec<PortStatus> = Vec::new();
        for (idx, port) in self.ports.read().iter().enumerate() {
            let port_status = PortStatus {
                desc: port.desc().to_string(),
                macs: ports.remove(&idx).unwrap_or_else(|| Vec::new()),
            };

            status.push(port_status);
        }

        Ok(SwitchStatus {
            ports: status,
            pkt_stats: self.pkt_stats.load(Ordering::Relaxed),
        })
    }
}

impl Switch for VirtioSwitch {
    /// Connects a new device to the router, returning the port it is connected to
    ///
    /// ### Arguments
    /// * `port` - Device to connect to this switch
    fn connect<P: SwitchPort + 'static>(&self, port: P) -> usize {
        let mut ports = self.ports.write();
        let idx = ports.len();
        ports.push(Box::new(port));

        idx
    }

    /// Processes a packet through the switch, sending it to the desired port
    /// or flooding it to all ports if the mac is not known
    ///
    /// ### Arguments
    /// * `port` - Port id this packet was sent from
    /// * `pkt` - Ethernet Framed packet (Layer 2)
    fn process(&self, port: usize, mut pkt: Vec<u8>) -> Result<(), ProtocolError> {
        self.pkt_stats
            .fetch_add(pkt.len() as u64, Ordering::Relaxed);

        if pkt.len() < ETHERNET_HDR_SZ {
            return Err(ProtocolError::NotEnoughData(pkt.len(), ETHERNET_HDR_SZ));
        }

        self.logger.log_switch(&pkt);

        let frame = EthernetFrame::extract(&mut pkt)?;

        // update our cached mac address / port cache mapping if needed for the source port
        match self.get_port(frame.src) {
            Some(p) if p == port => { /* do nothing, no need to update cache */ }
            Some(_) | None => self.associate_port(port, frame.src),
        }

        // write packet to destination port
        let ports = self.ports.read();
        if frame.dst.is_broadcast() {
            // write to all ports (but originator)
            tracing::trace!(
                ?frame,
                "[switch] got broadcast message, writing to all ports"
            );
            for (_, dev) in ports.iter().enumerate().filter(|(idx, _)| *idx != port) {
                dev.enqueue(frame, pkt.clone());
            }
        } else {
            match self.get_port(frame.dst) {
                Some(port) => match ports.get(port) {
                    Some(dev) => dev.enqueue(frame, pkt),
                    None => tracing::warn!(port, "[switch] device not connected to port!"),
                },
                None => tracing::warn!("[switch] mac ({}) not associated with port", frame.dst),
            }
        }

        Ok(())
    }
}
