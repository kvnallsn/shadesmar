//! Simple L3 Router

pub mod handler;
pub mod table;

use std::{
    collections::{BTreeMap, HashMap},
    net::IpAddr,
    path::Path,
    sync::Arc,
};

use flume::{Receiver, Sender};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use shadesmar_net::{
    protocols::ArpPacket,
    types::{EtherType, Ipv4Network, MacAddress},
    EthernetFrame, EthernetPacket, Ipv4Packet, ProtocolError, Switch, SwitchPort,
};
use table::{ArcRouteTable, RouteTable};

use crate::config::{WanConfig, WanDevice};
pub use crate::net::{
    switch::VirtioSwitch,
    wan::{Wan, WanHandle},
};

use self::handler::ProtocolHandler;

use super::{
    wan::{PcapDevice, TunTap, UdpDevice, WgDevice},
    NetworkError,
};

const IPV4_HDR_SZ: usize = 20;

/// Message that is sent over the router's channel to queue a packet
/// to be processed/routed
pub enum RouterMsg {
    /// Queues a packet received over a LAN port from a local device
    FromLan(EthernetPacket),

    /// Queues a packet received from the WAN port
    FromWan4(Ipv4Packet),
}

/// The action a router will take after processing a packet
pub enum RouterAction {
    /// Queues a packet to be sent over a LAN port to a local device
    ToLan(EtherType, IpAddr, Vec<u8>),

    /// Queues a packet to be send over the WAN port
    ToWan(Ipv4Packet),

    /// Drops / ignores the packet (no response generated)
    Drop(Vec<u8>),
}

/// Provides means to send packets to be handle/routed by the router
#[derive(Clone)]
pub struct RouterTx(Sender<RouterMsg>);

/// Provides a means of queueing packets to be processed by a `Router`
#[derive(Clone)]
pub struct RouterHandle {
    /// MAC address of the router
    mac: MacAddress,

    /// Network for which the router is responsible
    network: Ipv4Network,

    /// A reference to the router's route table
    route_table: ArcRouteTable,

    /// Currently active WAN connections for the router
    wans: Arc<RwLock<Vec<WanHandle>>>,
}

/// A Layer 3 IPv4 Router
pub struct Router {
    /// Map of IP address (L3) to their corresponding MAC (L2) address
    arp: HashMap<IpAddr, MacAddress>,

    /// Switching fabric used to communicate with connected devices
    switch: VirtioSwitch,

    /// Port on the switch to which this router is assigned
    port: usize,

    /// Currently active WAN connections for the router
    wans: Arc<RwLock<Vec<WanHandle>>>,

    /// WAN routing table, maps IPv4 cidrs to wan index
    table: ArcRouteTable,

    /// MAC address of this router
    mac: MacAddress,

    /// IPv4 network this router for which this router is responsible
    network: Ipv4Network,

    /// Layer 4 protocol handlers to handle packets destined for this router
    ip4_handlers: HashMap<u8, Box<dyn ProtocolHandler>>,
}

/// A `RouteBuilder` provides convenience methods for building routers
#[derive(Default)]
pub struct RouterBuilder {
    /// Mapping of ipv4 protocol numbers to a handler to run when a packet
    /// matching the protocol is received
    ip4_handlers: HashMap<u8, Box<dyn ProtocolHandler>>,

    /// Wide Area Network (WAN) connections
    wans: Vec<Box<dyn Wan>>,

    /// WAN routing table, maps IPv4 cidrs to wan index
    table: HashMap<Ipv4Network, String>,
}

/// Contains the status of the router, when requested by a control message
#[derive(Debug, Deserialize, Serialize)]
pub struct RouterStatus {
    /// MAC (L2) address of the router
    pub mac: MacAddress,

    /// Network router is responsible for
    pub network: Ipv4Network,

    /// Map of routes to WAN connectinos
    pub route_table: BTreeMap<Ipv4Network, (String, u64)>,

    /// Map of WAN connections to related information
    pub wan_stats: BTreeMap<String, (bool, String, u64, u64)>,
}

impl RouterTx {
    /// Creates a new channel to communicate with the router
    pub fn new() -> (Self, Receiver<RouterMsg>) {
        let (tx, rx) = flume::unbounded();
        (Self(tx), rx)
    }

    /// Queues an IPv4 packet to be routed
    ///
    /// ### Arguments
    /// * `pkt` - IPv4 packet to route
    pub fn route_ipv4(&self, pkt: Ipv4Packet) {
        self.0.send(RouterMsg::FromWan4(pkt)).ok();
    }

    /// Queues an IPv6 packet to be routed
    ///
    /// ### Arguments
    /// * `pkt` - IPv6 packet to route
    pub fn route_ipv6(&self, _pkt: Vec<u8>) {
        tracing::warn!("[router] no ipv6 support");
    }
}

#[allow(dead_code)]
impl RouterBuilder {
    /// Registers a series of WAN configurations with this router
    ///
    /// The WAN device will handle all unknown/non-local packets process
    /// by the router.  A non-local packet is any packet that's destination
    /// IP address does not reside inside the router's subnet / network.
    ///
    /// ### Arguments
    /// * `wans` - Upstream providers for unknown/non-local packets
    /// * `data_dir` - Path to data directory to store any wan-persistent files
    pub fn register_wans(
        mut self,
        wans: &[WanConfig],
        data_dir: &Path,
    ) -> Result<Self, NetworkError> {
        let parse_wan = |cfg: &WanConfig| match &cfg.device {
            WanDevice::Pcap => {
                // generate a name for the pcap file
                let ts = jiff::Timestamp::now().as_second();
                let file = format!("capture_{}_{ts}", cfg.name);
                let file = data_dir.join(file).with_extension("pcap");
                let wan = PcapDevice::new(&cfg.name, &file);
                Ok(Box::new(wan) as Box<dyn Wan>)
            }
            WanDevice::Tap(opts) => {
                let wan = TunTap::create_tap(&opts.device)?;
                Ok::<Box<dyn Wan>, NetworkError>(Box::new(wan) as Box<dyn Wan>)
            }
            WanDevice::Udp(opts) => {
                let wan = UdpDevice::connect(&cfg.name, opts.endpoint)?;
                Ok(Box::new(wan) as Box<dyn Wan>)
            }
            WanDevice::Wireguard(opts) => {
                let wan = WgDevice::create(&cfg.name, cfg.ipv4.ip(), opts)?;
                Ok(Box::new(wan) as Box<dyn Wan>)
            }
        };

        for wan in wans {
            let wan = parse_wan(wan)?;
            self.wans.push(wan);
        }

        Ok(self)
    }

    /// Install a new routing table for WAN connections
    ///
    /// The routing table maps IPv4 addresses and networks (CIDRs) to indexs in the WAN
    /// array/vector.  If an entry is not found, then the default (0) WAN connection
    /// is used.
    ///
    /// ### Arguments
    /// * `table` - Map of IPv4 networks (CIDRs) to WAN index
    pub fn routing_table(mut self, table: &HashMap<Ipv4Network, String>) -> Self {
        self.table = table.clone();
        self
    }

    /// Adds a (layer-4) protocol handler for this router
    ///
    /// A protocol handler provides a way to dynamically handle various layer 4 (i.e., tcp/udp/icmp)
    /// are seen by this router.
    ///
    /// ### Arguments
    /// * `handler` - The handler to call when the layer 4 protocol is encountered
    pub fn register_l4_proto_handler<P: ProtocolHandler + 'static>(mut self, handler: P) -> Self {
        let proto = handler.protocol();
        self.ip4_handlers.insert(proto, Box::new(handler));
        self
    }

    /// Create the router, spawning a new thread to run the core logic
    ///
    /// ### Arguments
    /// * `network` - Network address and subnet mask
    pub fn spawn(
        self,
        network: Ipv4Network,
        switch: VirtioSwitch,
    ) -> Result<RouterHandle, NetworkError> {
        let (tx, rx) = RouterTx::new();

        let table = RouteTable::new(self.table, &self.wans);
        let route_table = Arc::clone(&table);

        let port = switch.connect(tx.clone());

        let mut wans = Vec::with_capacity(self.wans.len());
        for wan in self.wans {
            let wan_handle = wan.spawn(tx.clone())?;
            wans.push(wan_handle);
        }
        let wans = Arc::new(RwLock::new(wans));

        let mac = MacAddress::generate();
        let handle = RouterHandle {
            mac,
            route_table,
            network,
            wans: Arc::clone(&wans),
        };

        let router = Router {
            arp: HashMap::new(),
            switch,
            port,
            wans,
            table,
            mac,
            network,
            ip4_handlers: self.ip4_handlers,
        };

        std::thread::Builder::new()
            .name(String::from("router"))
            .spawn(move || router.run(rx))?;

        Ok(handle)
    }
}

impl Router {
    /// Returns a default `RouterBuilder`
    pub fn builder() -> RouterBuilder {
        RouterBuilder::default()
    }

    /// Runs the router
    ///
    /// Continuously listens for messages from the LAN/WAN ports and forwards
    /// them as appropriate to their intended destinations
    ///
    /// ### Arguments
    /// * `rx` - Receive side of the router message channel of which packets will be received
    pub fn run(mut self, rx: Receiver<RouterMsg>) {
        loop {
            match rx.recv() {
                Ok(RouterMsg::FromLan(pkt)) => match self.route(pkt) {
                    Ok(_) => (),
                    Err(error) => tracing::warn!(?error, "unable to route lan packet"),
                },
                Ok(RouterMsg::FromWan4(pkt)) => {
                    //self.table.update_stats(wan_idx, tx, rx)
                    //self.wan_traffic_rx
                    //    .fetch_add(pkt.len() as u64, Ordering::Relaxed);

                    if let Err(error) = self
                        .route_ip4(pkt)
                        .and_then(|action| self.handle_action(action, None))
                    {
                        tracing::warn!(?error, "unable to route wan packet");
                    }
                }
                Err(error) => {
                    tracing::error!(?error, "unable to receive packet");
                    break;
                }
            }
        }

        tracing::info!("router died");
    }

    /// Routes a packet based on it's packet type
    ///
    /// ### Arguments
    /// * `ethertype` - What type of data is contained in the packet
    /// * `pkt` - Packet data (based on ethertype)
    fn route(&mut self, pkt: EthernetPacket) -> Result<(), ProtocolError> {
        let action = match pkt.frame.ethertype {
            EtherType::ARP => self.handle_arp(pkt.payload),
            EtherType::IPv4 => {
                let pkt = Ipv4Packet::parse(pkt.payload)?;
                self.route_ip4(pkt)
            }
            EtherType::IPv6 => self.route_ip6(pkt.payload),
        }?;

        self.handle_action(action, Some(pkt.frame.src))
    }

    /// Converts a `RouterAction` into an appropriate on-network response
    ///
    /// ### Arguments
    /// * `action` - The router action from which to build (or not build) a network packet
    /// * `dst` - The destination MAC address, if known
    fn handle_action(
        &mut self,
        action: RouterAction,
        dst: Option<MacAddress>,
    ) -> Result<(), ProtocolError> {
        match action {
            RouterAction::ToLan(ethertype, dst_ip, pkt) => {
                let dst = dst.or_else(|| self.arp.get(&dst_ip).copied());

                match dst {
                    Some(dst) => self.write_to_switch(dst, ethertype, pkt),
                    None => {
                        tracing::warn!(ip = ?dst_ip, "[router] mac not found in arp cache, dropping packet")
                    }
                }
            }
            RouterAction::ToWan(pkt) => match self.forward_packet(pkt) {
                Ok(_) => tracing::trace!("[router] forwarded packet"),
                Err(error) => tracing::warn!(?error, "[router] unable to forward packet"),
            },
            RouterAction::Drop(_pkt) => tracing::debug!("[router] dropping packet"),
        }

        Ok(())
    }

    /// Returns true if a packet is destined for this local device or if
    /// the it is a broadcast packet
    fn is_local<A: Into<IpAddr>>(&self, dst: A) -> bool {
        match dst.into() {
            IpAddr::V4(ip) => self.network == ip,
            IpAddr::V6(_ip) => false,
        }
    }

    // Returns true if the IP is the global broadcast IP
    fn is_global_broadcast(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(ip) => ip.is_broadcast(),
            IpAddr::V6(_ip) => false,
        }
    }

    /// Handles an ARP packet sent to this router's IPv4 address
    ///
    /// ### Arguments
    /// * `pkt` - Byte buffer containing the ARP packet starting at index 0
    fn handle_arp(&mut self, pkt: Vec<u8>) -> Result<RouterAction, ProtocolError> {
        tracing::trace!("handling arp packet");
        let mut arp = ArpPacket::parse(&pkt)?;

        tracing::trace!(
            "[router] associating mac to ip: {:?} -> {}",
            arp.spa,
            arp.sha
        );
        self.arp.insert(arp.spa, arp.sha);

        if self.is_local(arp.tpa) || self.is_global_broadcast(arp.tpa) {
            // responsd with router's mac
            let mut rpkt = vec![0u8; arp.size()];
            arp.to_reply(self.mac);
            arp.as_bytes(&mut rpkt);
            Ok(RouterAction::ToLan(EtherType::ARP, arp.tpa, rpkt))
        } else {
            // Not for us..ignore the packet
            Ok(RouterAction::Drop(pkt))
        }
    }

    /// Forwards this packet over the WAN connection
    ///
    /// If no WAN device is registered, drops the packet
    ///
    /// ### Arguments
    /// * `pkt` - A layer 3 (IPv4) packet to write to the ether
    fn forward_packet(&mut self, pkt: Ipv4Packet) -> Result<(), NetworkError> {
        let wan_idx = self.table.get_route_wan_idx(pkt.dest())?;

        tracing::debug!("routing packet with dest {} over wan {wan_idx}", pkt.dest());

        if let Some(ref wan) = self.wans.read().get(wan_idx) {
            if let Err(error) = wan.write(pkt) {
                tracing::warn!(?error, "unable to write to wan, dropping packet");
            }
        } else {
            tracing::warn!("[router] no wan device with index {wan_idx}, dropping packet");
        }

        Ok(())
    }

    /// Routes an IPv4 packet to the appropriate destination
    ///
    /// Checks to see if the destination is local (aka in the router's subnet) or if
    /// the packet needs to be forwarded over the WAN connection.
    ///
    /// If the destination can be handled by the router, checks to see if the destination
    /// is the router's IP, and if so, responds to the packet.  If not, queues the packet
    /// to be sent out a LAN port.
    ///
    /// ### Arguments
    /// * `pkt` - The IPv4 packet received by the router
    fn route_ip4(&mut self, pkt: Ipv4Packet) -> Result<RouterAction, ProtocolError> {
        match self.network.contains(pkt.dest()) || pkt.dest().is_broadcast() {
            true => match self.is_local(pkt.dest()) || pkt.dest().is_broadcast() {
                true => Ok(self.handle_local_ipv4(pkt)),
                false => {
                    let dst = pkt.dest();
                    Ok(RouterAction::ToLan(
                        EtherType::IPv4,
                        IpAddr::V4(dst),
                        pkt.into_bytes(),
                    ))
                }
            },
            false => Ok(RouterAction::ToWan(pkt)),
        }
    }

    /// Routes an IPv6 packet...or not because IPv6 is not current supported
    ///
    /// All packets are dropped
    ///
    /// ### Arguments
    /// * `pkt` -  The (unsupported) IPv6 packet
    fn route_ip6(&self, pkt: Vec<u8>) -> Result<RouterAction, ProtocolError> {
        tracing::debug!("ipv6 not supported, dropping packet");
        Ok(RouterAction::Drop(pkt))
    }

    /// Handles an IPv4 packet with a destination IP of this router
    ///
    /// This function calls the pre-registered L4 protocol handlers assigned
    /// by the `RouterBuilder`.
    ///
    /// If a specific protocol does not have a handler, the packet is dropped.
    ///
    /// ### Arguments
    /// * `pkt` - The IPv4 packet received over the wire/air/string
    fn handle_local_ipv4(&mut self, pkt: Ipv4Packet) -> RouterAction {
        let mut rpkt = vec![0u8; 1560];

        match self.ip4_handlers.get_mut(&pkt.protocol()) {
            Some(ref mut handler) => {
                match handler.handle_protocol(&pkt, &mut rpkt[IPV4_HDR_SZ..]) {
                    Ok(0) => RouterAction::Drop(Vec::new()),
                    Ok(sz) => {
                        rpkt.truncate(IPV4_HDR_SZ + sz);

                        // build response ipv4 header
                        let hdr = pkt.reply(&rpkt[IPV4_HDR_SZ..]);
                        hdr.as_bytes(&mut rpkt[0..IPV4_HDR_SZ]);

                        RouterAction::ToLan(EtherType::IPv4, hdr.dst.into(), rpkt)
                    }
                    Err(error) => {
                        tracing::warn!(
                            ?error,
                            protocol = pkt.protocol(),
                            "unable to handle packet"
                        );
                        RouterAction::Drop(Vec::new())
                    }
                }
            }
            None => RouterAction::Drop(vec![]),
        }
    }

    /// Writes a packet to the local switching fabric (i.e., local lan)
    ///
    /// ### Arguments
    /// * `dst` - Destination MAC address
    /// * `ethertype` - Type of packet to write (i.e., 0x0800 (IPv4), 0x0806 (ARP))
    /// * `pkt` - Layer 3 (i.e., IP) packet contents / data
    fn write_to_switch(&self, dst: MacAddress, ethertype: EtherType, mut pkt: Vec<u8>) {
        let mut data = Vec::with_capacity(14 + pkt.len());
        data.extend_from_slice(&dst.as_bytes());
        data.extend_from_slice(&self.mac.as_bytes());
        data.extend_from_slice(&ethertype.as_u16().to_be_bytes());
        data.append(&mut pkt);

        tracing::trace!("[router] write to switch: {:02x?}", &data[14..34]);

        if let Err(error) = self.switch.process(self.port, data) {
            tracing::warn!(?error, "unable to write to switch");
        }
    }
}

impl RouterHandle {
    /// Returns the MAC address of the router
    pub fn mac(&self) -> MacAddress {
        self.mac
    }

    /// Returns the status of the router
    pub fn status(&self) -> RouterStatus {
        let wan_stats = self
            .wans
            .read()
            .iter()
            .map(|wan| {
                (
                    wan.name().to_owned(),
                    (
                        wan.is_running(),
                        wan.ty().to_owned(),
                        wan.stats_tx(),
                        wan.stats_rx(),
                    ),
                )
            })
            .collect();

        RouterStatus {
            mac: self.mac,
            network: self.network,
            route_table: self.route_table.routes(),
            wan_stats,
        }
    }

    /// Adds a route to the routing table
    ///
    /// ### Arguments
    /// * `dst` - Destintation network
    pub fn add_route<S: Into<String>>(&self, dst: Ipv4Network, wan: S) -> Result<(), NetworkError> {
        let wan_name = wan.into();

        match self
            .wans
            .read()
            .iter()
            .position(|wan| wan.name() == &wan_name)
        {
            None => {
                tracing::warn!("wan {wan_name} not found, not adding route");
                return Err(NetworkError::WanDeviceNotFound(wan_name));
            }
            Some(idx) => self.route_table.add_route(dst, idx),
        }

        Ok(())
    }

    /// Deletes a route from the routing table
    ///
    /// ### Arguments
    /// * `route` - Route to delete
    pub fn del_route(&self, route: Ipv4Network) -> Result<(), NetworkError> {
        self.route_table.remove_route(route)
    }

    /// Adds a new WAN connection
    pub fn add_wan(&self) -> Result<(), NetworkError> {
        Ok(())
    }

    /// Deletes a WAN connection
    pub fn del_wan<S: AsRef<str>>(&self, name: S) -> Result<(), NetworkError> {
        let name = name.as_ref();
        tracing::info!("stopping wan device {name}");

        match self.wans.read().iter().find(|wan| wan.name() == name) {
            None => Err(NetworkError::WanDeviceNotFound(name.to_owned())),
            Some(wan) => wan.stop(),
        }
    }
}

impl SwitchPort for RouterTx {
    fn desc(&self) -> &'static str {
        "router"
    }

    fn enqueue(&self, frame: EthernetFrame, pkt: Vec<u8>) {
        let pkt = EthernetPacket::new(frame, pkt);
        self.0.send(RouterMsg::FromLan(pkt)).ok();
    }
}
