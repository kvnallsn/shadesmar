//! Various WAN providers

mod pcap;
mod tap;
mod udp;
mod wireguard;

use std::{
    net::Ipv4Addr,
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

/// A `WanHandle` provides a method to communicate with a WAN device
pub struct WanHandle {
    /// Name of the WAN device
    name: String,

    /// Type of WAN device (i.e., WireGuard)
    ty: String,

    /// IPv4 Address of the WAN device
    ipv4: Option<Ipv4Addr>,

    /// Thread running the WAN device
    thread: JoinHandle<()>,

    /// Transmit/sender channel to queue packets for transmission
    tx: Box<dyn WanTx>,

    /// Send/Receive stats
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

/// Core trait to describe a WAN device
pub trait Wan: Send + Sync
where
    Self: 'static,
{
    /// Human-friendly name of the WAN device
    fn name(&self) -> &str;

    /// Returns the type of this WAN connection
    fn ty(&self) -> &str;

    /// Returns the IPv4 address assigned to this WAN device
    ///
    /// Note: in the case of VPNs (e.g., WireGuard) this is not the same
    /// as the exit/public IPv4 but rather the internal IPv4 of the adapter
    /// itself
    fn ipv4(&self) -> Option<Ipv4Addr>;

    /// Returns the number of bytes transmitted (tx) and received (tx)
    /// over this WAN connection.
    ///
    /// Return value: (tx, rx)
    fn stats(&self) -> WanStats;

    /// Returns a transmitter/sender channel to queue packets for transmission
    ///
    /// If the channel is closed, or cannot otherwise be used, returns an error
    fn tx(&self) -> Result<Box<dyn WanTx>, NetworkError>;

    /// Main receiver loop for a WAN device
    ///
    /// This function should receive traffic from the distant end and queue it for
    /// routing by sending it over router's TX channel
    ///
    /// ### Arguments
    /// * `router` - Trasmit/send channel to queue packets for routing
    fn run(self: Box<Self>, router: RouterTx) -> Result<(), NetworkError>;

    /// Convenience function to spawn a thread to run the WAN device
    ///
    /// Sets up the `WanHandle` that can be used to communicate with the WAN
    /// (i.e., queue packets for transmission and track stats)
    ///
    /// ### Arguments
    /// * `router` - Trasmit/send channel to queue packets for routing
    fn spawn(self: Box<Self>, router: RouterTx) -> Result<WanHandle, NetworkError> {
        let tx = self.tx()?;
        let ty = self.ty().to_owned();
        let name = self.name().to_owned();
        let stats = self.stats();
        let ipv4 = self.ipv4();

        let thread = std::thread::Builder::new()
            .name(format!("wan-{}", self.name()))
            .spawn(move || match self.run(router) {
                Ok(_) => tracing::trace!("wan thread exited successfully"),
                Err(error) => tracing::warn!(?error, "unable to run wan thread"),
            })?;

        Ok(WanHandle {
            name,
            ty,
            ipv4,
            thread,
            tx,
            stats,
        })
    }

    /// Converts a WAN device into a boxed WAN (aka type erasure)
    fn to_boxed(self) -> Box<dyn Wan>
    where
        Self: Sized,
    {
        Box::new(self)
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
    /// Returns the name of the WAN device
    pub fn name(&self) -> &str {
        self.name.as_str()
    }

    /// Returns the type of WAN attached to this WAN handle
    pub fn ty(&self) -> &str {
        self.ty.as_str()
    }

    /// Returns the IPv4 address of this WAN device
    pub fn ipv4(&self) -> Option<Ipv4Addr> {
        self.ipv4
    }

    /// Returns true if this WAN is running, false if it has stopped
    pub fn is_running(&self) -> bool {
        !self.thread.is_finished()
    }

    /// If the WAN is running, attempts to queue the packet for transmission
    ///
    /// ### Arguments
    /// * `pkt`- IPv4 packet to queue for transmission
    pub fn write(&self, pkt: Ipv4Packet) -> Result<(), NetworkError> {
        if !self.thread.is_finished() {
            self.tx.write(pkt)?;
        }

        Ok(())
    }

    /// Returns the number of bytes transmitted/sent over this WAN
    pub fn stats_tx(&self) -> u64 {
        self.stats.tx()
    }

    /// Returns the number of bytes received/read from this WAN
    pub fn stats_rx(&self) -> u64 {
        self.stats.rx()
    }

    /// Attempts to stop this WAN device
    pub fn stop(&self) -> Result<(), NetworkError> {
        tracing::debug!("attempting to stop wan thread");
        let tid = self.thread.as_pthread_t();
        nix::sys::pthread::pthread_kill(tid, Signal::SIGTERM)?;
        Ok(())
    }
}
