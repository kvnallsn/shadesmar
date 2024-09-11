//! Various WAN providers

use std::{
    ffi::c_void,
    net::Ipv4Addr,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

use mio::net::UnixDatagram;
use shadesmar_core::{
    ipv4::Ipv4Packet,
    plugins::{FnCallback, PluginError, WanDevice, WanInstance, WanPlugin},
};
use uuid::Uuid;

use crate::{config::WanConfig, get_wan_plugins};

use super::{router::RouterTx, NetworkError};

/// A `WanHandle` provides a method to communicate with a WAN device
pub struct WanHandle {
    /// Unique id of WAN device
    id: Uuid,

    /// Name of the WAN device
    name: String,

    /// Type of WAN device (i.e., WireGuard)
    ty: String,

    /// Flag to check if pcap is enabled on this WAN
    pcap: bool,

    /// Send/Receive stats
    stats: WanStats,

    /// Table of WAN functions
    vtable: WanPlugin<'static>,

    /// Device configuration
    device: WanDevice,

    /// Running WAN device (or None if not running)
    instance: Option<WanInstance>,
}

/// Represents a socket that can feed/send packets to a WAN driver/device
pub struct WanSocket {
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

impl WanHandle {
    /// Creates a new WAN device
    ///
    /// A WAN device represents a connection to the outside world and
    /// is used to forward packets to non-local destinations.
    ///
    /// ### Arguments
    /// * `cfg` - Wan Configuration
    pub fn new(cfg: WanConfig) -> Result<Self, NetworkError> {
        let wan_type = cfg
            .device
            .get("type")
            .ok_or_else(|| NetworkError::Generic("wan plugin type not specified".into()))?;

        let vtable = get_wan_plugins()?.get_vtable(wan_type)?;
        let device = vtable.create(cfg.id, &cfg.device)?;

        Ok(Self {
            id: cfg.id,
            name: cfg.name,
            ty: wan_type.into(),
            pcap: cfg.pcap,
            stats: WanStats::new(),
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
    pub fn start(&mut self, channel: Box<RouterTx>, cb: FnCallback) -> Result<(), NetworkError> {
        let _span = tracing::warn_span!("start wan device", name = self.name());

        if self.is_running() {
            tracing::warn!("wan device already running");
            return Ok(());
        }

        // leak the channel...we'll recapture it in the instance object
        let channel = Box::into_raw(channel);

        let instance = self
            .vtable
            .start(&self.device, channel as *mut c_void, cb)?;

        self.instance = Some(instance);

        tracing::trace!("started wan adapter");
        Ok(())
    }

    /// Writes data to the WAN device
    ///
    /// ### Arguments
    /// * `data` - Data to write to WAN device
    pub fn write(&self, data: &[u8]) -> Result<(), PluginError> {
        if let Some(ref instance) = self.instance {
            self.vtable.write(instance, data)?;
            self.stats.tx_add(data.len() as u64);
        } else {
            tracing::warn!("attempted to write to non-running wan: {}", self.name);
        }

        Ok(())
    }

    /// Attempts to stop this WAN device
    pub fn stop(&mut self) -> Result<(), NetworkError> {
        if let Some(instance) = self.instance.take() {
            let channel = self.vtable.stop(instance)?;
            let channel = unsafe { Box::from_raw(channel as *mut RouterTx) };
            drop(channel);
        }

        Ok(())
    }
}

impl Drop for WanHandle {
    fn drop(&mut self) {
        if let Err(error) = self.stop() {
            tracing::warn!("[POTENTIAL MEMORY LEAK] failed to stop wan device '{}' and cleanup instance handle: {error:?}", self.name);
        }

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
    pub fn send<P: Ipv4Packet>(&self, _sock: &UnixDatagram, _pkt: &P) -> std::io::Result<()> {
        //self.stats.tx_add(sz as u64);
        Ok(())
    }

    /// Increases the WAN stats tx field by the amount received
    ///
    /// ### Arguments
    /// * `sz` - Amount of data sent
    pub fn update_tx(&self, sz: u64) {
        self.stats.tx_add(sz);
    }

    /// Increases the WAN stats rx field by the amount received
    ///
    /// ### Arguments
    /// * `sz` - Amount of data received
    pub fn update_rx(&self, sz: u64) {
        self.stats.rx_add(sz);
    }
}
