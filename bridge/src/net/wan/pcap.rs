//! WAN adapter to capture traffic (and drop it)

use std::{borrow::Cow, fs::File, path::PathBuf, time::UNIX_EPOCH};

use parking_lot::Mutex;
use pcap_file::{
    pcap::{PcapHeader, PcapPacket, PcapWriter},
    DataLink, Endianness, TsResolution,
};
use shadesmar_net::Ipv4Packet;

use crate::net::{router::RouterTx, NetworkError};

use super::{Wan, WanHandle, WanStats};

/// WAN device to capture and save traffic into a PCAP file
///
/// This device does not respond to any traffic, effectively
/// dropping all traffic it sees
pub struct PcapDevice {
    name: String,
    path: PathBuf,
    stats: WanStats,
}

pub struct PcapDeviceHandle(Mutex<PcapWriter<File>>, WanStats);

impl PcapDevice {
    /// Creates a new WAN device to capture traffic and save into a PCAP file
    ///
    /// ### Arguments
    /// * `name` - Name of WAN device
    /// * `path` - Path to pcap file on disk (aka where to save traffic)
    pub fn new<S, P>(name: S, path: P) -> Self
    where
        S: Into<String>,
        P: Into<PathBuf>,
    {
        let name = name.into();
        let path = path.into();
        let stats = WanStats::new("Pcap");
        Self { name, path, stats }
    }
}

impl Wan for PcapDevice {
    fn name(&self) -> &str {
        self.name.as_str()
    }

    fn stats(&self) -> super::WanStats {
        self.stats.clone()
    }

    fn as_wan_handle(&self) -> Result<Box<dyn WanHandle>, NetworkError> {
        let file = File::options()
            .create(true)
            .write(true)
            .append(true)
            .open(&self.path)?;

        let header = PcapHeader {
            version_major: 2,
            version_minor: 4,
            ts_correction: 0,
            ts_accuracy: 0,
            snaplen: 65535,
            datalink: DataLink::IPV4,
            ts_resolution: TsResolution::MicroSecond,
            endianness: Endianness::native(),
        };

        let writer = PcapWriter::with_header(file, header)?;
        Ok(Box::new(PcapDeviceHandle(
            Mutex::new(writer),
            self.stats.clone(),
        )))
    }

    fn run(self: Box<Self>, _router: RouterTx) -> Result<(), NetworkError> {
        tracing::debug!("pcap wan thread exiting, nothing to do (pcap drops all packets)");
        Ok(())
    }
}

impl WanHandle for PcapDeviceHandle {
    fn write(&self, pkt: Ipv4Packet) -> Result<(), NetworkError> {
        self.1.tx_add(pkt.len());
        let mut wr = self.0.lock();
        wr.write_packet(&PcapPacket {
            timestamp: UNIX_EPOCH.elapsed().unwrap(),
            orig_len: pkt.len() as u32,
            data: Cow::Borrowed(pkt.as_bytes()),
        })?;

        Ok(())
    }
}
