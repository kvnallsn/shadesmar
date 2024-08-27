//! A simple routing table

use std::{
    collections::{BTreeMap, HashMap},
    net::Ipv4Addr,
    sync::Arc,
};

use ip_network_table_deps_treebitmap::IpLookupTable;
use parking_lot::RwLock;
use shadesmar_core::types::Ipv4Network;
use uuid::Uuid;

use crate::net::NetworkError;

use super::WanHandle;

/// A `RouteTable` that can be freely shared between threads
pub type ArcRouteTable = Arc<RouteTable>;

/// A routing table implementation
///
/// Matches IPs (and subnets/CIDRs) to interface ids and tracks statistics per interface
#[derive(Default)]
pub struct RouteTable {
    /// Ipv4 routing table
    table: RwLock<IpLookupTable<Ipv4Addr, (Uuid, String)>>,

    /// Stats for amount of data traversed over a route
    stats: RwLock<HashMap<Ipv4Network, u64>>,
}

impl RouteTable {
    /// Creates a new table from a set of routes
    ///
    /// ### Arguments
    /// * `routes` - Table matching CIDRs to WAN interface ids
    pub fn new() -> ArcRouteTable {
        let table = IpLookupTable::new();
        let stats = HashMap::new();

        let table = Self {
            table: RwLock::new(table),
            stats: RwLock::new(stats),
        };

        Arc::new(table)
    }

    /// Returns the index of the WAN adapter to route an IP
    ///
    /// ### Arguments
    /// * `ip` - IPv4 address to route
    pub fn get_route_wan_idx(&self, ip: Ipv4Addr) -> Result<Uuid, NetworkError> {
        let (ip, mask, idx) = self
            .table
            .read()
            .longest_match(ip)
            .map(|(ip, mask, (idx, _name))| (ip, mask, *idx))
            .ok_or_else(|| NetworkError::RouteNotFound(Ipv4Network::new(ip, 32)))?;

        self.stats
            .write()
            .entry(Ipv4Network::new(ip, mask as u8))
            .and_modify(|count| {
                *count += 1;
            })
            .or_insert(1);

        Ok(idx)
    }

    /// Inserts a new route to a given subnet via the specificed WAN index
    ///
    /// ### Arguments
    /// * `ip` - Subnet/IPv4 address for which to route traffic
    /// * `wan` - Index of the WAN adapter that will handle the traffic
    pub fn add_route(&self, ip: Ipv4Network, wan: &WanHandle) {
        tracing::trace!("adding route: {ip} via {}", wan.name());
        self.table.write().insert(
            ip.ip(),
            u32::from(ip.subnet_mask_bits()),
            (wan.id(), wan.name().to_owned()),
        );
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

    /// Removes all routes associated with a WAN's index
    ///
    /// ### Arguments
    /// * `idx` - Index value of WAN to remove
    pub fn remove_routes_by_wan(&self, wan: &str) -> Result<(), NetworkError> {
        let mut table = self.table.write();

        let routes = table
            .iter()
            .filter_map(|(ip, mask, (_idx, name))| match name == wan {
                true => Some((ip, mask)),
                false => None,
            })
            .collect::<Vec<_>>();

        for (ip, masklen) in routes {
            tracing::trace!("remove route {ip}/{masklen}");
            table.remove(ip, masklen);
        }
        Ok(())
    }

    /// Returns a mapping of subnets/prefixes to interface ids
    pub fn routes(&self) -> BTreeMap<Ipv4Network, (String, u64)> {
        self.table
            .read()
            .iter()
            .map(|(ip, mask, (_idx, name))| {
                let net = Ipv4Network::new(ip, mask as u8);
                let num_packets = self.stats.read().get(&net).map(|count| *count).unwrap_or(0);
                (net, (name.to_owned(), num_packets))
            })
            .collect()
    }
}
