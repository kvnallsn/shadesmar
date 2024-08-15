//! Various WAN providers

mod pcap;
mod tap;
mod udp;
mod wireguard;

use std::{
    net::Ipv4Addr,
    os::unix::thread::JoinHandleExt,
    path::Path,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    thread::JoinHandle,
};

use nix::sys::signal::Signal;
use shadesmar_net::Ipv4Packet;

use crate::config::{WanConfig, WanDevice};

pub use self::{
    pcap::PcapDevice,
    tap::{TapConfig, TunTap},
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

    /// WAN device settings / parameters
    device: Box<dyn Wan>,

    /// Thread running the WAN device
    thread: Option<WanThreadHandle>,

    /// Send/Receive stats
    stats: WanStats,
}

pub struct WanThreadHandle {
    /// Thread running the WAN device
    thread: JoinHandle<()>,

    /// Transmit/sender channel to queue packets for transmission
    tx: Box<dyn WanTx>,
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
    /// Convenience function to spawn a thread to run the WAN device
    ///
    /// Sets up the `WanHandle` that can be used to communicate with the WAN
    /// (i.e., queue packets for transmission and track stats)
    ///
    /// ### Arguments
    /// * `router` - Trasmit/send channel to queue packets for routing
    fn spawn(&self, router: RouterTx, stats: WanStats) -> Result<WanThreadHandle, NetworkError>;

    /// Returns the IPv4 to use when masquerading packets through the NAT, or
    /// None if masquearding is not supported
    ///
    /// The default implementation returns None, disabling masquerading
    fn masquerade_ipv4(&self) -> Option<Ipv4Addr> {
        None
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
    /// Creates a new WAN device
    ///
    /// A WAN device represents a connection to the outside world and
    /// is used to forward packets to non-local destinations.
    ///
    /// ### Arguments
    /// * `name` - Name of this WAN device
    /// * `ty` - Type of WAN device
    /// * `wan` - WAN device settings
    pub fn new<P: AsRef<Path>>(cfg: WanConfig, data_dir: P) -> Result<Self, NetworkError> {
        let data_dir = data_dir.as_ref();

        let (ty, device) = match cfg.device {
            WanDevice::Pcap => {
                // generate a name for the pcap file
                let ts = jiff::Timestamp::now().as_second();
                let file = format!("capture_{}_{ts}", cfg.name);
                let file = data_dir.join(file).with_extension("pcap");
                let wan = PcapDevice::new(&file);
                ("blackhole", wan.to_boxed())
            }
            WanDevice::Tap(opts) => {
                let wan = TunTap::create_tap(opts)?;
                ("tap", wan.to_boxed())
            }
            WanDevice::Udp(opts) => {
                let wan = UdpDevice::connect(&cfg.name, opts.endpoint)?;
                ("udp", wan.to_boxed())
            }
            WanDevice::Wireguard(opts) => {
                let wan = WgDevice::create(&cfg.name, &opts)?;
                ("wireguard", wan.to_boxed())
            }
        };

        let stats = WanStats::new();

        Ok(Self {
            name: cfg.name,
            ty: ty.into(),
            device,
            stats,
            thread: None,
        })
    }

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
        self.device.masquerade_ipv4()
    }

    /// Returns true if this WAN is running, false if it has stopped
    pub fn is_running(&self) -> bool {
        self.thread
            .as_ref()
            .map(|t| !t.thread.is_finished())
            .unwrap_or(false)
    }

    /// If the WAN is running, attempts to queue the packet for transmission
    ///
    /// ### Arguments
    /// * `pkt`- IPv4 packet to queue for transmission
    pub fn write(&self, pkt: Ipv4Packet) -> Result<(), NetworkError> {
        if let Some(ref thread) = self.thread {
            thread.tx.write(pkt)?;
        } else {
            tracing::debug!(
                "attempted to write packet to non-running wan ({})",
                self.name
            );
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

    /// Starts the WAN device, if not already running
    ///
    /// Spawns a thread to handle the send/receive functions of the WAN device
    ///
    /// ### Arguments
    /// * `router` - Transmit/send channel to router
    pub fn start(&mut self, router: RouterTx) -> Result<(), NetworkError> {
        tracing::debug!("starting wan: {}", self.name);
        if self.is_running() {
            tracing::debug!("wan already running: {}", self.name);
            return Ok(());
        }

        let handle = self.device.spawn(router, self.stats.clone())?;
        self.thread = Some(handle);

        Ok(())
    }

    /// Attempts to stop this WAN device
    pub fn stop(&self) -> Result<(), NetworkError> {
        if let Some(ref t) = self.thread {
            tracing::debug!("attempting to stop wan thread");
            let tid = t.thread.as_pthread_t();
            nix::sys::pthread::pthread_kill(tid, Signal::SIGTERM)?;
        }
        Ok(())
    }
}

impl WanThreadHandle {
    /// Creates a new handle to the thread running the WAN device
    pub fn new<W: WanTx + 'static>(thread: JoinHandle<()>, tx: W) -> Self {
        let tx = Box::new(tx);
        Self { thread, tx }
    }
}
