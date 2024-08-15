//! WAN adapter to capture traffic (and drop it)

use std::{borrow::Cow, fs::File, net::Ipv4Addr, path::PathBuf, time::UNIX_EPOCH};

use parking_lot::Mutex;
use pcap_file::{
    pcap::{PcapHeader, PcapPacket, PcapWriter},
    DataLink, Endianness, TsResolution,
};
use shadesmar_net::Ipv4Packet;

use crate::net::{router::RouterTx, wan::WanThreadHandle, NetworkError};

use super::{Wan, WanStats, WanTx};

/// WAN device to capture and save traffic into a PCAP file
///
/// This device does not respond to any traffic, effectively
/// dropping all traffic it sees
pub struct PcapDevice {
    path: PathBuf,
}

pub struct PcapDeviceHandle {
    writer: Mutex<PcapWriter<File>>,
}

impl PcapDevice {
    /// Creates a new WAN device to capture traffic and save into a PCAP file
    ///
    /// ### Arguments
    /// * `name` - Name of WAN device
    /// * `path` - Path to pcap file on disk (aka where to save traffic)
    pub fn new<P: Into<PathBuf>>(path: P) -> Self {
        let path = path.into();
        Self { path }
    }
}

impl Wan for PcapDevice {
    fn ipv4(&self) -> Option<Ipv4Addr> {
        None
    }

    fn spawn(
        &self,
        _router: RouterTx,
        _stats: WanStats,
    ) -> Result<super::WanThreadHandle, NetworkError> {
        tracing::debug!("pcap wan thread exiting, nothing to do (pcap drops all packets)");

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
        let handle = PcapDeviceHandle {
            writer: Mutex::new(writer),
        };

        let thread = std::thread::spawn(|| {});

        Ok(WanThreadHandle::new(thread, handle))
    }
}

impl WanTx for PcapDeviceHandle {
    fn write(&self, pkt: Ipv4Packet) -> Result<(), NetworkError> {
        //self.stats.tx_add(pkt.len());
        let mut wr = self.writer.lock();
        wr.write_packet(&PcapPacket {
            timestamp: UNIX_EPOCH.elapsed().unwrap(),
            orig_len: pkt.len() as u32,
            data: Cow::Borrowed(pkt.as_bytes()),
        })?;

        Ok(())
    }
}
