//! Reponsible for all pcap/netflow related functions

use std::{
    borrow::Cow,
    collections::{HashMap, HashSet},
    fs::File,
    os::unix::net::UnixDatagram,
    path::{Path, PathBuf},
    sync::Arc,
    time::UNIX_EPOCH,
};

use flume::Sender;
use parking_lot::Mutex;
use pcap_file::{
    pcap::{PcapHeader, PcapPacket, PcapWriter},
    DataLink, TsResolution,
};
use uuid::Uuid;

use crate::BridgeConfig;

use super::NetworkError;

/// A shared list of taps to send packets out
pub type TapList = Arc<Mutex<HashSet<PathBuf>>>;

#[derive(Debug)]
pub struct PcapLogger {
    tx: Sender<LogRequest>,

    /// List of paths to unix datagram sockets to send pcap/netflow
    taps: TapList,
}

pub enum LogRequest {
    Switch(Vec<u8>),
    Wan(Uuid, Vec<u8>),
}

impl PcapLogger {
    pub fn new(cfg: &BridgeConfig, data_dir: &Path) -> Result<Arc<Self>, NetworkError> {
        let now = jiff::Timestamp::now().as_second();

        let wan_files = cfg
            .wan
            .iter()
            .map(|wan| {
                let file = format!("capture-wan-{}-{now}.pcap", wan.name);
                let file = File::options()
                    .create_new(true)
                    .write(true)
                    .open(data_dir.join(file))
                    .and_then(|file| {
                        let header = PcapHeader {
                            version_major: 2,
                            version_minor: 4,
                            ts_correction: 0,
                            ts_accuracy: 0,
                            snaplen: 65535,
                            datalink: DataLink::IPV4,
                            ts_resolution: TsResolution::MicroSecond,
                            endianness: pcap_file::Endianness::Big,
                        };

                        tracing::debug!("[pcap] logging wan {}", wan.name);
                        PcapWriter::with_header(file, header)
                            .map_err(|err| std::io::Error::other(err))
                    })
                    .unwrap();

                (wan.id, file)
            })
            .collect::<HashMap<_, _>>();

        let taps = Arc::new(Mutex::new(HashSet::new()));
        let tx = Self::spawn(wan_files, Arc::clone(&taps))?;

        Ok(Arc::new(Self { tx, taps }))
    }

    fn spawn(
        mut wans: HashMap<Uuid, PcapWriter<File>>,
        taps: TapList,
    ) -> Result<Sender<LogRequest>, NetworkError> {
        let (tx, rx) = flume::unbounded::<_>();
        let sock = UnixDatagram::unbound()?;

        std::thread::Builder::new()
            .name(String::from("pcap-logger"))
            .spawn(move || {
                while let Ok(req) = rx.recv() {
                    let timestamp = UNIX_EPOCH.elapsed().unwrap();

                    match req {
                        LogRequest::Switch(pkt) => {
                            let mut errors = Vec::new();
                            let mut sockets = taps.lock();
                            for tap in &*sockets {
                                if let Err (error) = sock.send_to(&pkt, tap) {
                                    tracing::warn!(tap = %tap.display(), %error, "removing tap, socket error");
                                    errors.push(tap.to_owned());
                                }
                            }

                            for tap in errors {
                                sockets.remove(&tap);
                            }
                        },
                        LogRequest::Wan(id, pkt) => match wans.get_mut(&id) {
                            Some(writer) => match writer.write_packet(&PcapPacket {
                                timestamp,
                                orig_len: pkt.len() as u32,
                                data: Cow::Borrowed(&pkt)
                            }) {
                                Ok(_) => tracing::trace!("log packet for wan:{id} success"),
                                Err(error) => tracing::warn!(%error, "unable to log packet for wan:{id}"),
                            }
                            None => (),
                        }
                    }
                }
            })?;

        Ok(tx)
    }

    /// Associates a wan with a pcap device
    pub fn capture_wan(&self, id: Uuid) {
        tracing::debug!("enabling pcap on wan:{id}");
    }

    /// Logs a packet to a pcap file and the any connected taps
    ///
    /// ### Arguments
    /// * `pkt` - Packet to log
    pub fn log_switch(&self, pkt: &[u8]) {
        self.tx.send(LogRequest::Switch(pkt.to_vec())).ok();
    }

    /// Logs a packet to a WAN-specific pcap file
    pub fn log_wan(&self, id: Uuid, pkt: &[u8]) {
        self.tx.send(LogRequest::Wan(id, pkt.to_vec())).ok();
    }

    /// Adds a new tap socket to forward traffic towards
    ///
    /// ### Arguments
    /// * `path` - Path to client socket
    pub fn add_tap<P: Into<PathBuf>>(&self, path: P) {
        self.taps.lock().insert(path.into());
    }
}
