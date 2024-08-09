//! A simple routing table

use std::{collections::HashMap, net::Ipv4Addr, sync::Arc};

use ip_network_table_deps_treebitmap::IpLookupTable;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use shadesmar_net::types::Ipv4Network;

use super::Wan;

/// A `RouteTable` that can be freely shared between threads
pub type ArcRouteTable = Arc<RouteTable>;

/// Tracks the amount of data that has traversed a WAN connection
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize)]
pub struct RouteStats {
    /// Amount of data sent over the WAN connection
    pub tx: usize,

    /// Amount of data received over the WAN connection
    pub rx: usize,
}

/// A routing table implementation
///
/// Matches IPs (and subnets/CIDRs) to interface ids and tracks statistics per interface
#[derive(Default)]
pub struct RouteTable {
    table: RwLock<IpLookupTable<Ipv4Addr, usize>>,

    /// Mapping of interface ids to names
    names: RwLock<HashMap<usize, String>>,

    /// Mapping of interface ids to statistics
    stats: RwLock<HashMap<usize, RouteStats>>,
}

impl RouteTable {
    /// Creates a new table from a set of routes
    ///
    /// ### Arguments
    /// * `routes` - Table matching CIDRs to WAN interface ids
    pub fn new(routes: HashMap<Ipv4Network, String>, wans: &[Box<dyn Wan>]) -> ArcRouteTable {
        let mut table = IpLookupTable::new();
        let mut names = HashMap::default();
        let mut stats = HashMap::default();

        for (ipnet, wan_name) in routes {
            // get the index of wan
            match wans.iter().position(|wan| wan.name() == &wan_name) {
                Some(wan_idx) => {
                    tracing::debug!("adding route to {ipnet} via {wan_name} (idx = {wan_idx})");
                    table.insert(ipnet.ip(), u32::from(ipnet.subnet_mask_bits()), wan_idx);
                    stats.insert(wan_idx, RouteStats::default());
                    names.insert(wan_idx, wan_name);
                }
                None => {
                    tracing::warn!("wan {wan_name} not found, skipping route");
                }
            }
        }

        let table = Self {
            table: RwLock::new(table),
            names: RwLock::new(names),
            stats: RwLock::new(stats),
        };

        Arc::new(table)
    }

    /// Returns the index of the WAN adapter to route an IP
    ///
    /// ### Arguments
    /// * `ip` - IPv4 address to route
    pub fn get_route_wan_idx(&self, ip: Ipv4Addr) -> usize {
        match self.table.read().longest_match(ip) {
            None => 0,
            Some((_ip, _mask, idx)) => *idx,
        }
    }

    /// Inserts a new route to a given subnet via the specificed WAN index
    ///
    /// ### Arguments
    /// * `ip` - Subnet/IPv4 address for which to route traffic
    /// * `wan` - Index of the WAN adapter that will handle the traffic
    pub fn add_route(&self, ip: Ipv4Network, wan: usize) {
        self.table
            .write()
            .insert(ip.ip(), u32::from(ip.subnet_mask_bits()), wan);
    }

    /// Removes a route from the routing table
    ///
    /// This will cause the specified network to route over the default route
    ///
    /// ### Arguments
    /// * `ip` - Subnet/IPv4 address for which to remove a specific route
    pub fn remove_route(&self, ip: Ipv4Network) {
        self.table
            .write()
            .remove(ip.ip(), u32::from(ip.subnet_mask_bits()));
    }

    /// Returns a mapping of subnets/prefixes to interface ids
    pub fn routes(&self) -> HashMap<Ipv4Network, String> {
        self.table
            .read()
            .iter()
            .map(|(ip, mask, idx)| {
                let net = Ipv4Network::new(ip, mask as u8);
                match self.names.read().get(idx) {
                    Some(name) => (net, name.clone()),
                    None => (net, String::from("unnamed")),
                }
            })
            .collect()
    }

    /// Updates the stats associated with a route
    ///
    /// ### Arguments
    /// * `wan_idx` - Index of the WAN connection to update
    /// * `tx` - Amount of additional data sent over the WAN connection
    /// * `rx` - Amount of additional data received over the WAN connection
    pub fn update_stats<TX, RX>(&self, wan_idx: usize, tx: TX, rx: RX)
    where
        TX: Into<usize>,
        RX: Into<usize>,
    {
        self.stats
            .write()
            .entry(wan_idx)
            .and_modify(|stats| {
                stats.tx += tx.into();
                stats.rx += rx.into();
            })
            .or_insert(RouteStats::default());
    }

    /// Returns the stats for a WAN connection, or none if the index is not associated with a WAN
    ///
    /// WAN stats include:
    /// - Amount of data transmitted (in bytes)
    /// - Amount of data received (in bytes)
    pub fn stats(&self) -> HashMap<String, RouteStats> {
        self.stats
            .read()
            .iter()
            .map(|(wan_idx, stats)| match self.names.read().get(wan_idx) {
                Some(name) => (name.clone(), *stats),
                None => (String::from("unnamed"), *stats),
            })
            .collect::<HashMap<_, _>>()
    }
}
