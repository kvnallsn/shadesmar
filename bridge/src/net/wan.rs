//! Various WAN providers

mod pcap;
mod tap;
mod udp;
mod wireguard;

use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};

use shadesmar_net::Ipv4Packet;

pub use self::{
    pcap::PcapDevice,
    tap::TunTap,
    udp::UdpDevice,
    wireguard::{WgConfig, WgDevice},
};

use super::{router::RouterHandle, NetworkError};

/// Represents statistics for a WAN device
///
/// Current statistics include:
/// - number of bytes transmitted (tx)
/// - number of bytes received (rx)
#[derive(Clone, Debug)]
pub struct WanStats(Arc<WanStatsInner>);

#[derive(Debug)]
struct WanStatsInner {
    /// Type of WAN device
    ty: String,

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
    pub fn new<S: Into<String>>(ty: S) -> Self {
        let inner = WanStatsInner {
            ty: ty.into(),
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

    /// Returns the type of this WAN device
    pub fn wan_type(&self) -> &str {
        self.0.ty.as_str()
    }
}

pub trait Wan: Send + Sync
where
    Self: 'static,
{
    /// Human-friendly name of the WAN device
    fn name(&self) -> &str;

    /// Returns the number of bytes transmitted (tx) and received (tx)
    /// over this WAN connection.
    ///
    /// Return value: (tx, rx)
    fn stats(&self) -> WanStats;

    fn as_wan_handle(&self) -> Result<Box<dyn WanHandle>, NetworkError>;

    fn run(self: Box<Self>, router: RouterHandle) -> Result<(), NetworkError>;

    fn spawn(self: Box<Self>, router: RouterHandle) -> Result<Box<dyn WanHandle>, NetworkError> {
        let handle = self.as_wan_handle()?;

        std::thread::Builder::new()
            .name(String::from("wan-thread"))
            .spawn(move || match self.run(router) {
                Ok(_) => tracing::trace!("wan thread exited successfully"),
                Err(error) => tracing::warn!(?error, "unable to run wan thread"),
            })?;

        Ok(handle)
    }
}

pub trait WanHandle: Send + Sync {
    /// Writes a packet to the upstream device
    fn write(&self, pkt: Ipv4Packet) -> Result<(), NetworkError>;
}
