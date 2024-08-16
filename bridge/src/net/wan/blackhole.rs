//! WAN adapter to capture traffic (and drop it)

use shadesmar_net::Ipv4Packet;
use uuid::Uuid;

use crate::net::{router::RouterTx, wan::WanThreadHandle, NetworkError};

use super::{Wan, WanStats, WanTx};

/// WAN device to capture and save traffic into a PCAP file
///
/// This device does not respond to any traffic, effectively
/// dropping all traffic it sees
pub struct Blackhole;

pub struct BlackholeHandle {
    stats: WanStats,
}

impl Blackhole {
    /// Creates a new WAN device that ignores all traffic
    pub fn new() -> Self {
        Blackhole
    }
}

impl Wan for Blackhole {
    fn spawn(
        &self,
        _id: Uuid,
        _router: RouterTx,
        stats: WanStats,
    ) -> Result<super::WanThreadHandle, NetworkError> {
        tracing::debug!("pcap wan thread exiting, nothing to do (pcap drops all packets)");

        let handle = BlackholeHandle { stats };
        let thread = std::thread::spawn(|| {});

        Ok(WanThreadHandle::new(thread, handle))
    }
}

impl WanTx for BlackholeHandle {
    fn write(&self, pkt: Ipv4Packet) -> Result<(), NetworkError> {
        // Blackhole drops all packets, ignore
        self.stats.tx_add(pkt.len());
        Ok(())
    }
}
