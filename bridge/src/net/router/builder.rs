//! The RouterBuilder helper

use std::{collections::HashMap, sync::Arc};

use parking_lot::RwLock;
use shadesmar_core::{
    switch::Switch,
    types::{Ipv4Network, MacAddress},
};

use crate::{
    config::WanConfig,
    net::{pcap::PcapLogger, NetworkError},
};

use super::{
    handle::RouterHandle, handler::ProtocolHandler, table::RouteTable, Router, RouterTx,
    VirtioSwitch, WanHandle,
};

/// A `RouteBuilder` provides convenience methods for building routers
#[derive(Default)]
pub struct RouterBuilder {
    /// Mapping of ipv4 protocol numbers to a handler to run when a packet
    /// matching the protocol is received
    ip4_handlers: HashMap<u8, Box<dyn ProtocolHandler>>,

    /// Wide Area Network (WAN) connections
    wans: Vec<WanConfig>,

    /// WAN routing table, maps IPv4 cidrs to wan index
    table: HashMap<Ipv4Network, String>,
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
    /// * `wans` - Upstream provider configuration for unknown/non-local packets
    pub fn register_wans(mut self, wans: &[WanConfig]) -> Self {
        self.wans.extend_from_slice(wans);
        self
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
    /// * `switch` - L2 switch this router to which this router is connected
    /// * `pcap` - Handle to Pcap logging thread
    pub fn spawn(
        self,
        network: Ipv4Network,
        switch: VirtioSwitch,
        pcap: Arc<PcapLogger>,
    ) -> Result<RouterHandle, NetworkError> {
        let router_span = tracing::info_span!("create router", network = %network);
        let _enter = router_span.enter();

        let (tx, rx) = RouterTx::new()?;
        let tx = Box::new(tx);

        let wans = Arc::new(RwLock::new(HashMap::new()));
        for wan in self.wans {
            let _span = tracing::info_span!("create wan adapter", name = wan.name).entered();

            let mut wan = WanHandle::new(wan)?;
            if wan.pcap_enabled() {
                pcap.capture_wan(wan.id());
            }

            wan.start(tx.clone(), super::router_callback)?;
            wans.write().insert(wan.id(), wan);
        }

        let table = RouteTable::new();

        let port = switch.connect(tx.clone());
        let mac = MacAddress::generate();

        let router = Router {
            arp: RwLock::new(HashMap::new()),
            switch,
            port,
            table: Arc::clone(&table),
            mac,
            network,
            ip4_handlers: self.ip4_handlers,
            pcap,
            wans: wans.clone(),
        };
        drop(_enter);

        let thread = std::thread::Builder::new()
            .name(String::from("router"))
            .spawn(move || router.run(rx))?;

        let handle = RouterHandle::new(mac, network, table, wans, tx, thread);

        for (net, wan) in self.table {
            match handle.add_route(net, &wan) {
                Ok(_) => tracing::debug!("added route to {net} over {wan}"),
                Err(error) => tracing::warn!(%error, "unable to add route to {net} over {wan}"),
            }
        }

        Ok(handle)
    }
}
