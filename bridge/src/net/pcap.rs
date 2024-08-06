//! Reponsible for all pcap/netflow related functions

use std::{
    borrow::Cow, collections::HashSet, fs::File, os::unix::net::UnixDatagram, path::PathBuf,
    sync::Arc, time::UNIX_EPOCH,
};

use flume::Sender;
use parking_lot::Mutex;
use pcap_file::pcap::{PcapPacket, PcapWriter};

use super::NetworkError;

/// A shared list of taps to send packets out
pub type TapList = Arc<Mutex<HashSet<PathBuf>>>;

#[derive(Debug)]
pub struct PcapLogger {
    tx: Sender<Vec<u8>>,

    /// List of paths to unix datagram sockets to send pcap/netflow
    taps: TapList,
}

impl PcapLogger {
    pub fn new(path: Option<PathBuf>) -> Result<Self, NetworkError> {
        let taps = Arc::new(Mutex::new(HashSet::new()));

        let tx = Self::spawn(path, Arc::clone(&taps))?;

        Ok(Self { tx, taps })
    }

    fn spawn(path: Option<PathBuf>, taps: TapList) -> Result<Sender<Vec<u8>>, NetworkError> {
        let mut writer = match path {
            None => None,
            Some(path) => {
                let file = File::options().create(true).write(true).open(path)?;
                let writer = PcapWriter::new(file)?;
                Some(writer)
            }
        };

        let (tx, rx) = flume::unbounded::<Vec<u8>>();
        let sock = UnixDatagram::unbound()?;

        std::thread::Builder::new()
            .name(String::from("pcap-logger"))
            .spawn(move || {
                while let Ok(pkt) = rx.recv() {
                    if let Some(writer) = writer.as_mut() {
                        writer
                            .write_packet(&PcapPacket{
                                timestamp: UNIX_EPOCH.elapsed().unwrap(),
                                orig_len: pkt.len() as u32,
                                data: Cow::Borrowed(&pkt),
                            })
                            .ok();
                    }

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
                }
            })?;

        Ok(tx)
    }

    /// Logs a packet to a pcap file and the any connected taps
    ///
    /// ### Arguments
    /// * `pkt` - Packet to log
    pub fn log_packet(&self, pkt: &[u8]) {
        self.tx.send(pkt.to_vec()).ok();
    }

    /// Adds a new tap socket to forward traffic towards
    ///
    /// ### Arguments
    /// * `path` - Path to client socket
    pub fn add_tap<P: Into<PathBuf>>(&self, path: P) {
        self.taps.lock().insert(path.into());
    }
}
