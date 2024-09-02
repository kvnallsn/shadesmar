//! The Router Handle

use std::{collections::HashMap, sync::Arc, thread::JoinHandle};

use parking_lot::RwLock;
use shadesmar_core::types::{Ipv4Network, MacAddress};
use uuid::Uuid;

use crate::{config::WanConfig, net::NetworkError};

use super::{table::ArcRouteTable, RouterStatus, RouterTx, WanHandle};

/// Provides a means of queueing packets to be processed by a `Router`
pub struct RouterHandle {
    /// MAC address of the router
    mac: MacAddress,

    /// Network for which the router is responsible
    network: Ipv4Network,

    /// A reference to the router's route table
    route_table: ArcRouteTable,

    /// Active WANs
    wans: Arc<RwLock<HashMap<Uuid, WanHandle>>>,

    /// Handle to send messages to the router thread
    tx: Box<RouterTx>,

    /// Handle to the spawned router thread
    thread: JoinHandle<()>,
}

impl RouterHandle {
    pub fn new(
        mac: MacAddress,
        net: Ipv4Network,
        rt: ArcRouteTable,
        wans: Arc<RwLock<HashMap<Uuid, WanHandle>>>,
        tx: Box<RouterTx>,
        thread: JoinHandle<()>,
    ) -> Self {
        Self {
            mac,
            network: net,
            route_table: rt,
            wans,
            tx,
            thread,
        }
    }

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
            .map(|(_, wan)| {
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
        let wans = self.wans.read();
        let wan = wans
            .iter()
            .find(|(_id, wan)| wan.name() == wan_name)
            .map(|(_id, wan)| wan)
            .ok_or_else(|| NetworkError::WanDeviceNotFound(wan_name.clone()))?;

        self.route_table.add_route(dst, wan);

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
    ///
    /// ### Arguments
    /// * `name` - Name of the wan connection
    /// * `cfg` - WAN device configuration
    pub fn add_wan(&self, _cfg: WanConfig) -> Result<(), NetworkError> {
        /*
        let mut wan = WanHandle::new(cfg)?;
        if wan.pcap_enabled() {
            //pcap.capture_wan(wan.id());
        }

        wan.start(self.tx.clone())?;
        self.wans.write().insert(wan.id(), wan);
        */

        Ok(())
    }

    /// Deletes a WAN connection
    ///
    /// ### Arguments
    /// * `name` - Name of WAN connection to delete
    /// * `cleanup` - True to remove associated routes, false to leave them
    pub fn del_wan<S: AsRef<str>>(&mut self, name: S, _cleanup: bool) -> Result<(), NetworkError> {
        let _name = name.as_ref();
        /*
        let id = self
            .wans
            .find_by_name(name)
            .ok_or_else(|| NetworkError::WanDeviceNotFound(name.to_owned()))?;

        tracing::info!("stopping wan device {name}");

        let mut wan = self
            .wans
            .remove(id)
            .ok_or_else(|| NetworkError::WanDeviceNotFound(name.to_owned()))?;

        wan.stop()?;

        if cleanup {
            self.route_table.remove_routes_by_wan(name)?;
        }
        */

        Ok(())
    }

    /// Attempts to stop the router thread and cleanup and allocated memory
    pub fn stop(self) -> Result<(), NetworkError> {
        // stop all wans
        //for (_id, mut wan) in self.wans.write().into_iter() {
        //    wan.stop()?;
        //}

        // signal the thread to stop
        self.tx.quit();
        self.thread.join().ok();

        Ok(())
    }
}
