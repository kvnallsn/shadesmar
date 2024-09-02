//! Simple L3 Router

pub mod builder;
pub mod handle;
pub mod handler;
pub mod table;

use std::{
    collections::{BTreeMap, HashMap},
    fmt::Display,
    net::IpAddr,
    os::raw::c_void,
    sync::Arc,
};

use builder::RouterBuilder;
use flume::{Receiver, Sender};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use shadesmar_core::{
    ipv4::{Ipv4Flags, Ipv4Packet, Ipv4PacketOwned},
    protocols::ArpPacket,
    switch::{Switch, SwitchPort},
    types::{
        buffers::{PacketBuffer, PacketBufferPool},
        EtherType, Ipv4Network, MacAddress,
    },
    EthernetFrame, EthernetPacket, ProtocolError,
};
use table::ArcRouteTable;
use uuid::Uuid;

pub use crate::net::{switch::VirtioSwitch, wan::WanHandle};

use self::handler::ProtocolHandler;

use super::{pcap::PcapLogger, NetworkError};

const IPV4_HDR_SZ: usize = 20;

/// Message that is sent over the router's channel to queue a packet
/// to be processed/routed
pub enum RouterMsg {
    /// Queues a packet received over a LAN port from a local device
    FromLan(EthernetPacket),

    /// Attempt to write WAN packets (if the WAN is ready)
    FromWan(Ipv4PacketOwned),

    /// Tells the router to stop and exit
    Quit,
}

/// The action a router will take after processing a packet
pub enum RouterAction {
    /// Queues a packet to be sent over a LAN port to a local device
    ToLan(EtherType, IpAddr, PacketBuffer),

    /// Queues a packet to be send over the WAN port
    ToWan(Ipv4PacketOwned),

    /// Drops / ignores the packet (no response generated)
    Drop(Option<PacketBuffer>),
}

/// Provides means to send packets to be handle/routed by the router
#[derive(Clone)]
pub struct RouterTx(Sender<RouterMsg>);

/// A Layer 3 IPv4 Router
pub struct Router {
    /// Map of IP address (L3) to their corresponding MAC (L2) address
    arp: RwLock<HashMap<IpAddr, MacAddress>>,

    /// Switching fabric used to communicate with connected devices
    switch: VirtioSwitch,

    /// Port on the switch to which this router is assigned
    port: usize,

    /// WAN routing table, maps IPv4 cidrs to wan index
    table: ArcRouteTable,

    /// MAC address of this router
    mac: MacAddress,

    /// IPv4 network this router for which this router is responsible
    network: Ipv4Network,

    /// Layer 4 protocol handlers to handle packets destined for this router
    ip4_handlers: HashMap<u8, Box<dyn ProtocolHandler>>,

    /// Handle to the pcap logging thread
    pcap: Arc<PcapLogger>,

    /// Currently active WAN connections for the router
    wans: Arc<RwLock<HashMap<Uuid, WanHandle>>>,
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

pub extern "C" fn router_callback(target: *const c_void, data: *const u8, len: usize) -> i32 {
    tracing::trace!("caught router callback (data len: {})", len);

    let data = match target.is_null() || data.is_null() || len == 0 {
        true => return -1,
        false => unsafe { std::slice::from_raw_parts(data, len) },
    };

    let mut buffer = PacketBufferPool::get();
    buffer.extend_from_slice(data);

    unsafe { (*(target as *const RouterTx)).route(buffer) };

    0
}

impl RouterTx {
    /// Creates a new channel to communicate with the router
    pub fn new() -> Result<(Self, Receiver<RouterMsg>), NetworkError> {
        let (tx, rx) = flume::unbounded();

        Ok((Self(tx), rx))
    }

    /// Sends a quit message down the channel
    pub fn quit(&self) {
        self.0.send(RouterMsg::Quit).ok();
    }

    pub fn route(&self, data: PacketBuffer) {
        match Ipv4PacketOwned::new(data) {
            Ok(pkt) => {
                self.0.send(RouterMsg::FromWan(pkt)).ok();
            }
            Err(error) => tracing::warn!("unable to route packet: {error:?}"),
        }
    }

    /// Queues an IPv6 packet to be routed
    ///
    /// ### Arguments
    /// * `pkt` - IPv6 packet to route
    pub fn route_ipv6(&self, _pkt: Vec<u8>) {
        tracing::warn!("[router] no ipv6 support");
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
    pub fn run(self, rx: Receiver<RouterMsg>) {
        while let Ok(msg) = rx.recv() {
            match msg {
                RouterMsg::Quit => break,
                RouterMsg::FromWan(pkt) => {
                    let _span = tracing::info_span!("from wan").entered();
                    match self.route_ip4(pkt) {
                        Ok(action) => match self.handle_action(action, None) {
                            Ok(_) => (),
                            Err(error) => tracing::warn!("unable to route ipv4 packet: {error:?}"),
                        },
                        Err(error) => {
                            tracing::warn!("unable to route packet (source: wan): {error:?}")
                        }
                    }
                }
                RouterMsg::FromLan(frame) => {
                    let _span = tracing::info_span!("from lan").entered();
                    match self.route_eth_frame(frame) {
                        Ok(_) => tracing::trace!("routed packet!"),
                        Err(error) => {
                            tracing::warn!("unable to route packet (source :lan): {error:?}")
                        }
                    }
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
    fn route_eth_frame(&self, pkt: EthernetPacket) -> Result<(), ProtocolError> {
        let _span =
            tracing::info_span!("route frame", len = pkt.len(), cap = pkt.capacity()).entered();

        let action = match pkt.frame.ethertype {
            EtherType::ARP => self.handle_arp(pkt.payload),
            EtherType::IPv4 => {
                let pkt = Ipv4PacketOwned::new(pkt.payload)?;
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
        &self,
        action: RouterAction,
        dst: Option<MacAddress>,
    ) -> Result<(), ProtocolError> {
        let _span = tracing::info_span!("handle router action", action = %action).entered();

        match action {
            RouterAction::ToLan(ethertype, dst_ip, pkt) => {
                let dst = dst.or_else(|| self.arp.read().get(&dst_ip).copied());

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
            RouterAction::Drop(_pkt) => tracing::warn!("[router] dropping packet"),
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
    fn handle_arp(&self, pkt: PacketBuffer) -> Result<RouterAction, ProtocolError> {
        let _span = tracing::info_span!("handle arp packet").entered();

        let mut arp = ArpPacket::parse(&pkt)?;

        tracing::trace!(
            "[router] associating mac to ip: {:?} -> {}",
            arp.spa,
            arp.sha
        );
        self.arp.write().insert(arp.spa, arp.sha);

        if self.is_local(arp.tpa) || self.is_global_broadcast(arp.tpa) {
            // responsd with router's mac
            let mut rpkt = PacketBufferPool::with_size(arp.size());
            arp.to_reply(self.mac);
            arp.as_bytes(&mut rpkt);
            Ok(RouterAction::ToLan(EtherType::ARP, arp.tpa, rpkt))
        } else {
            // Not for us..ignore the packet
            Ok(RouterAction::Drop(Some(pkt)))
        }
    }

    /// Forwards this packet over the WAN connection
    ///
    /// If no WAN device is registered, drops the packet
    ///
    /// ### Arguments
    /// * `pkt` - A layer 3 (IPv4) packet to write to the ether
    fn forward_packet(&self, pkt: Ipv4PacketOwned) -> Result<(), NetworkError> {
        let wan_id = self.table.get_route_wan_idx(pkt.dst())?;
        tracing::trace!("routing packet to {} over wan:{wan_id}", pkt.dst());

        let wans = self.wans.read();
        if let Some(wan) = wans.get(&wan_id) {
            self.pcap.log_wan(wan.id(), pkt.as_bytes());
            wan.write(pkt.as_bytes()).ok();
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
    fn route_ip4(&self, pkt: Ipv4PacketOwned) -> Result<RouterAction, ProtocolError> {
        let _span = tracing::info_span!(
            "route ipv4",
            id = pkt.id(),
            len = pkt.len(),
            src = %pkt.src(),
            dst = %pkt.dst(),
            protocol = %pkt.protocol()
        )
        .entered();

        match self.network.contains(pkt.dst()) || pkt.dst().is_broadcast() {
            true => match self.is_local(pkt.dst()) || pkt.dst().is_broadcast() {
                true => {
                    tracing::trace!("destination: router");
                    Ok(self.handle_local_ipv4(pkt))
                }
                false => {
                    tracing::trace!("destination: lan");

                    let dst = pkt.dst();
                    Ok(RouterAction::ToLan(
                        EtherType::IPv4,
                        IpAddr::V4(dst),
                        pkt.consume(),
                    ))
                }
            },
            false => {
                tracing::trace!("destination: wan");
                Ok(RouterAction::ToWan(pkt))
            }
        }
    }

    /// Routes an IPv6 packet...or not because IPv6 is not current supported
    ///
    /// All packets are dropped
    ///
    /// ### Arguments
    /// * `pkt` -  The (unsupported) IPv6 packet
    fn route_ip6(&self, pkt: PacketBuffer) -> Result<RouterAction, ProtocolError> {
        tracing::warn!("ipv6 not supported, dropping packet");
        Ok(RouterAction::Drop(Some(pkt)))
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
    fn handle_local_ipv4(&self, pkt: Ipv4PacketOwned) -> RouterAction {
        let _span = tracing::info_span!("handle local ipv4 packet").entered();

        let mut rpkt = PacketBufferPool::with_size(1600);

        match self.ip4_handlers.get(&pkt.protocol()) {
            Some(ref mut handler) => {
                match handler.handle_protocol(&pkt, &mut rpkt[IPV4_HDR_SZ..]) {
                    Ok(0) => RouterAction::Drop(Some(pkt.consume())),
                    Ok(sz) => {
                        rpkt.truncate(IPV4_HDR_SZ + sz);

                        // build response ipv4 header
                        match pkt.gen_response_header(Ipv4Flags::empty(), &mut rpkt) {
                            Ok(dst) => RouterAction::ToLan(EtherType::IPv4, dst.into(), rpkt),
                            Err(error) => {
                                tracing::warn!("packet requires fragmentation but fragmention not supported: {error}");
                                RouterAction::Drop(Some(pkt.consume()))
                            }
                        }
                    }
                    Err(error) => {
                        tracing::warn!(
                            ?error,
                            protocol = pkt.protocol(),
                            "unable to handle packet"
                        );
                        RouterAction::Drop(Some(pkt.consume()))
                    }
                }
            }
            None => {
                tracing::warn!(
                    "dropping local packet, no handler for protocol: 0x{:02x}",
                    pkt.protocol()
                );
                RouterAction::Drop(None)
            }
        }
    }

    /// Writes a packet to the local switching fabric (i.e., local lan)
    ///
    /// ### Arguments
    /// * `dst` - Destination MAC address
    /// * `ethertype` - Type of packet to write (i.e., 0x0800 (IPv4), 0x0806 (ARP))
    /// * `pkt` - Layer 3 (i.e., IP) packet contents / data
    fn write_to_switch(&self, dst: MacAddress, ethertype: EtherType, pkt: PacketBuffer) {
        //let pkt_len: usize = pkt.len().into();
        let mut data = PacketBufferPool::get();
        data.extend_from_slice(&dst.as_bytes());
        data.extend_from_slice(&self.mac.as_bytes());
        data.extend_from_slice(&ethertype.as_u16().to_be_bytes());
        data.extend_from_slice(&pkt);

        tracing::trace!("[router] write to switch: 0x{:02x?}", &data[..14]);

        if let Err(error) = self.switch.process(self.port, data) {
            tracing::warn!(?error, "unable to write to switch");
        }
    }
}

impl SwitchPort for RouterTx {
    fn desc(&self) -> &'static str {
        "router"
    }

    fn enqueue(&self, frame: EthernetFrame, pkt: PacketBuffer) {
        tracing::trace!("sending ethernet frame to router");
        let pkt = EthernetPacket::new(frame, pkt);

        if let Err(error) = self
            .0
            .send(RouterMsg::FromLan(pkt))
            .map_err(|err| std::io::Error::other(err))
        {
            tracing::warn!("unable to queue packet to router: {error}");
        }
    }
}

impl Display for RouterAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match &self {
            Self::Drop(_) => "drop",
            Self::ToLan(_, _, _) => "to lan",
            Self::ToWan(_) => "to wan",
        };

        write!(f, "{s}")
    }
}
