//! Various WAN providers

mod pcap;
mod tap;
mod udp;
mod wireguard;

use std::{
    os::unix::thread::JoinHandleExt,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    thread::JoinHandle,
};

use nix::sys::signal::Signal;
use shadesmar_net::Ipv4Packet;

pub use self::{
    pcap::PcapDevice,
    tap::TunTap,
    udp::UdpDevice,
    wireguard::{WgConfig, WgDevice},
};

use super::{router::RouterTx, NetworkError};

pub struct WanHandle {
    name: String,
    ty: String,
    thread: JoinHandle<()>,
    tx: Box<dyn WanTx>,
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

pub trait Wan: Send + Sync
where
    Self: 'static,
{
    /// Human-friendly name of the WAN device
    fn name(&self) -> &str;

    /// Returns the type of this WAN connection
    fn ty(&self) -> &str;

    /// Returns the number of bytes transmitted (tx) and received (tx)
    /// over this WAN connection.
    ///
    /// Return value: (tx, rx)
    fn stats(&self) -> WanStats;

    fn tx(&self) -> Result<Box<dyn WanTx>, NetworkError>;

    fn run(self: Box<Self>, router: RouterTx) -> Result<(), NetworkError>;

    fn spawn(self: Box<Self>, router: RouterTx) -> Result<WanHandle, NetworkError> {
        let tx = self.tx()?;
        let ty = self.ty().to_owned();
        let name = self.name().to_owned();
        let stats = self.stats();

        let thread = std::thread::Builder::new()
            .name(format!("wan-{}", self.name()))
            .spawn(move || match self.run(router) {
                Ok(_) => tracing::trace!("wan thread exited successfully"),
                Err(error) => tracing::warn!(?error, "unable to run wan thread"),
            })?;

        Ok(WanHandle {
            name,
            ty,
            thread,
            tx,
            stats,
        })
    }
}

pub trait WanTx: Send + Sync {
    /// Writes a packet to the upstream device
    fn write(&self, pkt: Ipv4Packet) -> Result<(), NetworkError>;
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
    pub fn name(&self) -> &str {
        self.name.as_str()
    }

    pub fn ty(&self) -> &str {
        self.ty.as_str()
    }

    /// Returns true if this WAN is running, false if it has stopped
    pub fn is_running(&self) -> bool {
        !self.thread.is_finished()
    }

    pub fn write(&self, pkt: Ipv4Packet) -> Result<(), NetworkError> {
        if !self.thread.is_finished() {
            self.tx.write(pkt)?;
        }

        Ok(())
    }

    pub fn stats_tx(&self) -> u64 {
        self.stats.tx()
    }

    pub fn stats_rx(&self) -> u64 {
        self.stats.rx()
    }

    pub fn stats(&self) -> WanStats {
        self.stats.clone()
    }

    pub fn stop(&self) -> Result<(), NetworkError> {
        tracing::debug!("attempting to stop wan thread");
        let tid = self.thread.as_pthread_t();
        nix::sys::pthread::pthread_kill(tid, Signal::SIGTERM)?;
        Ok(())
    }
}
