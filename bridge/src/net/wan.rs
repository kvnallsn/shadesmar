//! Various WAN providers

//mod blackhole;
//mod tap;
//mod udp;
//mod wireguard;

use std::{
    collections::HashMap,
    net::Ipv4Addr,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

use mio::net::UnixDatagram;
use parking_lot::RwLock;
use shadesmar_core::{
    plugins::{WanDevice, WanInstance, WanPlugin, WanPlugins},
    Ipv4Packet,
};
use uuid::Uuid;

use crate::config::WanConfig;

use super::NetworkError;

/// Mapping of WAN unique ids to unix datagram socket paths
pub type WanSocketMap = Arc<RwLock<HashMap<Uuid, WanSocket>>>;

/// A `WanMap` stores all active WAN connections
#[derive(Default)]
pub struct WanMap<'a> {
    /// Map of wan unique ids (uuid) to wan handle
    devices: HashMap<Uuid, WanHandle<'a>>,

    /// Map of wan unique ids to their respective sockets
    sockets: WanSocketMap,
}

/// A `WanHandle` provides a method to communicate with a WAN device
pub struct WanHandle<'a> {
    /// Unique id of WAN device
    id: Uuid,

    /// Name of the WAN device
    name: String,

    /// Type of WAN device (i.e., WireGuard)
    ty: String,

    /// Flag to check if pcap is enabled on this WAN
    pcap: bool,

    /// Path to the WAN's listening unix (datagram) socket
    socket: PathBuf,

    /// WAN plugin functions
    vtable: WanPlugin<'a>,

    /// WAN device (created by vtable)
    device: WanDevice,

    /// Handle to running instance (if running)
    instance: Option<WanInstance>,

    /// Send/Receive stats
    stats: WanStats,
}

/// Represents a socket that can feed/send packets to a WAN driver/device
pub struct WanSocket {
    /// Full path to the WAN's unix datagram socket
    path: PathBuf,

    /// WAN statistics
    stats: WanStats,
}

/// Represents statistics for a WAN device
///
/// Current statistics include:
/// - number of bytes transmitted (tx)
/// - number of bytes received (rx)
#[derive(Clone, Debug)]
pub struct WanStats(Arc<WanStatsInner>);

#[derive(Debug)]
struct WanStatsInner {
    /// Total bytes transmitted (sent/write) over WAN device
    tx: AtomicU64,

    /// Total bytes received (recv/read) over WAN device
    rx: AtomicU64,
}

impl WanStats {
    /// Creates a new WanStats, with counters initialized to zero
    ///
    /// ### Arguments
    /// * `ty` - WAN device description / type
    pub fn new() -> Self {
        let inner = WanStatsInner {
            tx: AtomicU64::new(0),
            rx: AtomicU64::new(0),
        };

        Self(Arc::new(inner))
    }

    /// Adds transmitted bytes to the internal counter
    ///
    /// ### Arguments
    /// * `tx` - Number of bytes to add to the internal counter
    pub fn tx_add<U: Into<u64>>(&self, tx: U) {
        self.0.tx.fetch_add(tx.into(), Ordering::Relaxed);
    }

    /// Adds received bytes to the internal counter
    ///
    /// ### Arguments
    /// * `tx` - Number of bytes to add to the internal counter
    pub fn rx_add<U: Into<u64>>(&self, rx: U) {
        self.0.rx.fetch_add(rx.into(), Ordering::Relaxed);
    }

    /// Returns the current amount of bytes transmitted over this WAN
    pub fn tx(&self) -> u64 {
        self.0.tx.load(Ordering::Relaxed)
    }

    /// Returns the current amount of bytes received over this WAN
    pub fn rx(&self) -> u64 {
        self.0.rx.load(Ordering::Relaxed)
    }
}

impl<'a> WanMap<'a> {
    /// Adds a new WanHandle into the map
    ///
    /// ### Arguments
    /// * `handle` - WAN handle to insert into the map
    pub fn insert(&mut self, handle: WanHandle<'a>) {
        self.sockets.write().insert(
            handle.id(),
            WanSocket {
                path: handle.socket().to_path_buf(),
                stats: handle.stats(),
            },
        );

        self.devices.insert(handle.id(), handle);
    }

    /// Returns the wan with the corresponding id
    ///
    /// ### Arguments
    /// * `id` - Unique id of the WAN device
    pub fn get(&self, id: Uuid) -> Option<&WanHandle<'_>> {
        self.devices.get(&id)
    }

    /// Returns a new (shared) reference to the WAN socket map
    pub fn sockets(&self) -> WanSocketMap {
        Arc::clone(&self.sockets)
    }

    /// Returns the WAN id corresponding to the provided name, or None if no
    /// WAN is found
    ///
    /// ### Arguments
    /// * `name` - Name of the WAN device
    pub fn find_by_name<S: AsRef<str>>(&self, name: S) -> Option<Uuid> {
        let name = name.as_ref();
        self.devices
            .values()
            .find_map(|handle| match handle.name() == name {
                true => Some(handle.id()),
                false => None,
            })
    }

    /// Returns an iterator over the WAN devices
    pub fn iter(&self) -> std::collections::hash_map::Iter<Uuid, WanHandle<'_>> {
        self.devices.iter()
    }

    /// Returns a consuming iteartor over the WAN devices
    pub fn into_iter(self) -> std::collections::hash_map::IntoIter<Uuid, WanHandle<'a>> {
        self.devices.into_iter()
    }

    /// Removes a WAN device from the map
    ///
    /// ### Arguments
    /// * `id` - Unique id of WAN device to remove
    pub fn remove(&mut self, id: Uuid) -> Option<WanHandle<'_>> {
        self.sockets.write().remove(&id);
        self.devices.remove(&id)
    }
}

impl<'a> WanHandle<'a> {
    /// Creates a new WAN device
    ///
    /// A WAN device represents a connection to the outside world and
    /// is used to forward packets to non-local destinations.
    ///
    /// ### Arguments
    /// * `cfg` - Wan Configuration
    pub fn new<P: AsRef<Path>>(
        cfg: WanConfig,
        rundir: &P,
        plugins: &'a WanPlugins,
    ) -> Result<Self, NetworkError> {
        let wan_type = cfg
            .device
            .get("type")
            .ok_or_else(|| NetworkError::Generic("wan plugin type not specified".into()))?;

        let vtable = plugins.get_vtable(wan_type)?;

        let stats = WanStats::new();
        let socket = rundir.as_ref().join(&cfg.name).with_extension("sock");

        let device = vtable.create(cfg.id, &cfg.device)?;

        Ok(Self {
            id: cfg.id,
            name: cfg.name,
            ty: wan_type.into(),
            socket,
            pcap: cfg.pcap,
            stats,
            vtable,
            device,
            instance: None,
        })
    }

    /// Returns the unique id of the WAN device
    pub fn id(&self) -> Uuid {
        self.id
    }

    /// Returns the name of the WAN device
    pub fn name(&self) -> &str {
        self.name.as_str()
    }

    /// Returns the type of WAN attached to this WAN handle
    pub fn ty(&self) -> &str {
        self.ty.as_str()
    }

    /// Returns true if traffic is being captured on this WAN
    pub fn pcap_enabled(&self) -> bool {
        self.pcap
    }

    /// Returns the path to the bound unix datagram socket for a WAN device
    pub fn socket(&self) -> &Path {
        &self.socket
    }

    /// Returns the IPv4 address of this WAN device
    pub fn ipv4(&self) -> Option<Ipv4Addr> {
        None
    }

    /// Returns true if this WAN is running, false if it has stopped
    pub fn is_running(&self) -> bool {
        self.instance.is_some()
    }

    /// Returns a new (ref-counted) reference to the WAN's stats
    pub fn stats(&self) -> WanStats {
        self.stats.clone()
    }

    /// Returns the number of bytes transmitted/sent over this WAN
    pub fn stats_tx(&self) -> u64 {
        self.stats.tx()
    }

    /// Returns the number of bytes received/read from this WAN
    pub fn stats_rx(&self) -> u64 {
        self.stats.rx()
    }

    /// Starts the WAN device, if not already running
    ///
    /// Spawns a thread to handle the send/receive functions of the WAN device
    ///
    /// ### Arguments
    /// * `router` - Transmit/send channel to router
    pub fn start(&mut self, router: &Path) -> Result<(), NetworkError> {
        tracing::debug!("starting wan adapter");
        if self.is_running() {
            tracing::debug!("wan already running");
        }

        let instance = self.vtable.start(&self.device, router, &self.socket)?;
        self.instance = Some(instance);

        tracing::debug!("started wan adapter");
        Ok(())
    }

    /// Attempts to stop this WAN device
    pub fn stop(&mut self) -> Result<(), NetworkError> {
        if let Some(instance) = self.instance.take() {
            self.vtable.stop(instance)?;
        }

        Ok(())
    }
}

impl<'a> Drop for WanHandle<'a> {
    fn drop(&mut self) {
        if let Err(error) = self.vtable.destroy(&self.device) {
            tracing::warn!(
                "[MEMORY LEAK] failed to destroy wan device ({}): {error}",
                self.name
            );
        }
    }
}

impl WanSocket {
    /// Sends a packet to the specified socket
    ///
    /// Increases the WAN stats tx field by the amount sent
    ///
    /// ### Arguments
    /// * `sock` - Sock to use as sender
    /// * `pkt` - Ipv4 Packet to transmit
    pub fn send(&self, sock: &UnixDatagram, pkt: &Ipv4Packet) -> std::io::Result<()> {
        let sz = sock.send_to(pkt.as_bytes(), &self.path)?;
        self.stats.tx_add(sz as u64);
        Ok(())
    }

    /// Increases the WAN stats rx field by the amount received
    ///
    /// ### Arguments
    /// * `sz` - Amount of data received
    pub fn update_rx(&self, sz: u64) {
        self.stats.rx_add(sz);
    }
}
