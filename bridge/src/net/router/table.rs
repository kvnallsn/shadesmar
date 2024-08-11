//! A simple routing table

use std::{collections::HashMap, net::Ipv4Addr, sync::Arc};

use ip_network_table_deps_treebitmap::IpLookupTable;
use parking_lot::RwLock;
use shadesmar_net::types::Ipv4Network;

use crate::net::NetworkError;

use super::Wan;

/// A `RouteTable` that can be freely shared between threads
pub type ArcRouteTable = Arc<RouteTable>;

/// A routing table implementation
///
/// Matches IPs (and subnets/CIDRs) to interface ids and tracks statistics per interface
#[derive(Default)]
pub struct RouteTable {
    /// Ipv4 routing table
    table: RwLock<IpLookupTable<Ipv4Addr, usize>>,

    /// Stats for amount of data traversed over a route
    stats: RwLock<HashMap<Ipv4Network, u64>>,

    /// Mapping of interface ids to names
    names: RwLock<HashMap<usize, String>>,
}

impl RouteTable {
    /// Creates a new table from a set of routes
    ///
    /// ### Arguments
    /// * `routes` - Table matching CIDRs to WAN interface ids
    pub fn new(routes: HashMap<Ipv4Network, String>, wans: &[Box<dyn Wan>]) -> ArcRouteTable {
        let mut table = IpLookupTable::new();
        let stats = HashMap::new();
        let mut names = HashMap::default();

        for (ipnet, wan_name) in routes {
            // get the index of wan
            match wans.iter().position(|wan| wan.name() == &wan_name) {
                Some(wan_idx) => {
                    tracing::debug!("adding route to {ipnet} via {wan_name} (idx = {wan_idx})");
                    table.insert(ipnet.ip(), u32::from(ipnet.subnet_mask_bits()), wan_idx);
                    names.insert(wan_idx, wan_name);
                }
                None => {
                    tracing::warn!("wan {wan_name} not found, skipping route");
                }
            }
        }

        let table = Self {
            table: RwLock::new(table),
            stats: RwLock::new(stats),
            names: RwLock::new(names),
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
            Some((ip, mask, idx)) => {
                self.stats
                    .write()
                    .entry(Ipv4Network::new(ip, mask as u8))
                    .and_modify(|count| {
                        *count += 1;
                    })
                    .or_insert(1);
                *idx
            }
        }
    }

    /// Inserts a new route to a given subnet via the specificed WAN index
    ///
    /// ### Arguments
    /// * `ip` - Subnet/IPv4 address for which to route traffic
    /// * `wan` - Index of the WAN adapter that will handle the traffic
    pub fn add_route(&self, ip: Ipv4Network, wan: usize) {
        tracing::trace!("adding route: {ip} via {wan}");
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
    pub fn remove_route(&self, ip: Ipv4Network) -> Result<(), NetworkError> {
        tracing::trace!("removing route: {ip}");
        self.table
            .write()
            .remove(ip.ip(), u32::from(ip.subnet_mask_bits()))
            .ok_or_else(|| NetworkError::RouteNotFound(ip))?;

        Ok(())
    }

    /// Returns a mapping of subnets/prefixes to interface ids
    pub fn routes(&self) -> HashMap<Ipv4Network, (String, u64)> {
        self.table
            .read()
            .iter()
            .map(|(ip, mask, idx)| {
                let net = Ipv4Network::new(ip, mask as u8);

                let name = match self.names.read().get(idx) {
                    Some(name) => name.clone(),
                    None => String::from("unnamed"),
                };

                let num_packets = self.stats.read().get(&net).map(|count| *count).unwrap_or(0);

                (net, (name, num_packets))
            })
            .collect()
    }
}
