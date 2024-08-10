//! Shadesmar application

mod pcap;

use std::{
    collections::BinaryHeap,
    fs::File,
    io::{Read, Write},
    path::{Path, PathBuf},
};

use anyhow::Context;
use dialoguer::{theme::Theme, Confirm};
use pcap::handle_pcap;
use shadesmar_bridge::{
    ctrl::{CtrlClientStream, CtrlRequest, CtrlResponse},
    Bridge,
};
use shadesmar_net::types::Ipv4Network;

use crate::Command;

const SHADESMAR_CFG_PATH: &str = "/etc/shadesmar";
const SHADESMAR_RUN_PATH: &str = "/var/run/shadesmar";
const SHADESMAR_DAT_PATH: &str = "/var/lib/shadesmar";

/// Configuration constants
const SHADESMAR_CFG_EXT: &str = "yml";
const SHADESMAR_PID_FILE: &str = "app.pid";

const MAX_BYTES: u64 = 1024;
const MAX_KILOBYTES: u64 = MAX_BYTES * 1024;
const MAX_MEGABYTES: u64 = MAX_KILOBYTES * 1024;
const MAX_GIGABYTES: u64 = MAX_MEGABYTES * 1024;
const MAX_TERABYTES: u64 = MAX_GIGABYTES * 1024;

macro_rules! human_bytes {
    ($b:expr) => {{
        match $b {
            x if x < MAX_BYTES => format!("{} B", $b),
            x if x < MAX_KILOBYTES => format!("{} KB", $b / MAX_BYTES),
            x if x < MAX_MEGABYTES => format!("{} MB", $b / MAX_KILOBYTES),
            x if x < MAX_GIGABYTES => format!("{} GB", $b / MAX_MEGABYTES),
            x if x < MAX_TERABYTES => format!("{} GB", $b / MAX_GIGABYTES),
            _ => format!("a whole lot, more than a terabyte"),
        }
    }};
}

macro_rules! print_separator {
    () => {
        println!("{:-<80}", "-")
    };
}

/// Internal application state
pub struct App {
    /// Path to the configuration directory
    cfg_dir: PathBuf,

    /// Path to the run directory
    run_dir: PathBuf,

    /// Path to the network's data directory (pcap, etc.)
    data_dir: PathBuf,

    /// Theme to use for input prompts
    theme: Box<dyn Theme>,
}

/// Represents a network
#[derive(Debug)]
pub struct Network {
    /// Name of the network
    name: String,

    /// Path to the network's runtime directory (sockets, etc.)
    run_dir: PathBuf,

    /// Path to the network's configuration file
    cfg_file: PathBuf,

    /// Path to the network's data directory (pcap, etc.)
    data_dir: PathBuf,
}

impl App {
    /// Initializes the application
    ///
    /// Performs initialization steps the the shadesmar application:
    /// - creates all required directories
    pub fn initialize() -> anyhow::Result<Self> {
        let cfg_dir = PathBuf::from(SHADESMAR_CFG_PATH);
        let run_dir = PathBuf::from(SHADESMAR_RUN_PATH);
        let data_dir = PathBuf::from(SHADESMAR_DAT_PATH);

        if !cfg_dir.exists() {
            tracing::info!(path = %cfg_dir.display(), "configuration directory does not exist, attempting to create");
            std::fs::create_dir_all(&cfg_dir)?;
        } else if !cfg_dir.is_dir() {
            return Err(anyhow::anyhow!(
                "configuration path exists but is not a directory (path: {})",
                cfg_dir.display(),
            ));
        }

        if !run_dir.exists() {
            tracing::info!(path = %cfg_dir.display(), "runtime directory does not exist, attempting to create");
            std::fs::create_dir_all(&run_dir)?;
        } else if !run_dir.is_dir() {
            return Err(anyhow::anyhow!(
                "rutime path exists but is not a directory (path: {})",
                run_dir.display(),
            ));
        }

        let theme = Box::new(dialoguer::theme::ColorfulTheme::default());

        Ok(Self {
            cfg_dir,
            run_dir,
            data_dir,
            theme,
        })
    }

    /// Runs the application
    pub fn run(self, cmd: Command) -> anyhow::Result<()> {
        match cmd {
            Command::Install { config, name } => self.install(config, name)?,
            Command::Uninstall { network, purge } => self.uninstall(network, purge)?,
            Command::Start { network } => self.start(network)?,
            Command::Status { network } => self.status(network)?,
            Command::Netflow { network } => self.pcap(network)?,
            Command::Stop { network, force } => self.stop(network, force)?,
            Command::AddRoute {
                network,
                route,
                wan,
            } => self.add_route(network, route, wan)?,
            Command::DeleteRoute { network, route } => self.del_route(network, route)?,
        };
        Ok(())
    }

    /// Creates a new network
    ///
    /// ### Arguments
    /// * `network` - Name of the network
    pub fn open_network(&self, network: String) -> anyhow::Result<Network> {
        let run_dir = self.run_dir.join(&network);
        let data_dir = self.data_dir.join(&network);
        let cfg_file = self
            .cfg_dir
            .join(&network)
            .with_extension(SHADESMAR_CFG_EXT);

        Ok(Network {
            name: network,
            run_dir,
            cfg_file,
            data_dir,
        })
    }

    /// Shows a confirmation (yes / no) prompt using the app's theme
    ///
    /// Returns:
    /// - true if the user confirmed the prompt (aka yes)
    /// - false if the user denied the prompt (aka no)
    /// - error if anything else happens
    fn prompt_confirm<S: Into<String>>(&self, msg: S) -> anyhow::Result<bool> {
        let confirmation = Confirm::with_theme(&*self.theme)
            .with_prompt(msg)
            .interact()?;

        Ok(confirmation)
    }

    /// Installs a shadesmar network configuration file
    ///
    /// # Arguments
    /// * `config` - Path to configuration file
    /// * `name` - Name of this network, or None to use existing file name
    fn install(self, config: PathBuf, name: Option<String>) -> anyhow::Result<()> {
        let name = name
            .or_else(|| {
                config
                    .file_name()
                    .map(|f| f.to_str().map(|s| s.to_string()))
                    .flatten()
            })
            .ok_or_else(|| anyhow::anyhow!("unable to get destination file name"))?;

        let network = self.open_network(name)?;

        tracing::info!(
            src = %config.display(),
            dst = %network.cfg_file().display(),
            "installing network configuration as {}",
            network.name(),
        );

        if network.cfg_file().exists() {
            // Prompt to overwrite
            if !self.prompt_confirm("Overwrite existing network file?")? {
                println!("operation cancelled");
                return Ok(());
            }
        }

        let mut src = File::open(config).context("unable to open source configuration file")?;
        let mut dst = File::options()
            .create(true)
            .write(true)
            .truncate(true)
            .open(network.cfg_file())
            .context("unable to open destination configuration file")?;

        std::io::copy(&mut src, &mut dst)?;

        Ok(())
    }

    /// Uninstalls a network configuration file
    ///
    /// If the purge option is specificed, this will also remove any files
    /// located in the runtime directory (e.g. /var/run/shadesmar/<network>/)
    ///
    /// ### Arguments
    /// * `network` - Name of network to uninstall
    /// * `purge` - Delete any/all runtime generated files
    fn uninstall(self, network: String, purge: bool) -> anyhow::Result<()> {
        let network = self
            .open_network(network)
            .context("unable to open network")?;

        if network
            .ctrl_socket()
            .and_then(|mut sock| {
                sock.send(CtrlRequest::Ping)
                    .map_err(|e| anyhow::Error::from(e))
            })
            .is_ok()
        {
            eprintln!("network is running, please stop if first");
            return Ok(());
        }

        tracing::info!(file = %network.cfg_file().display(), "uninstalling network configuration file");
        std::fs::remove_file(network.cfg_file()).ok();
        if purge {
            tracing::info!(dir = %network.run_dir().display(), "purging runtime files");
            std::fs::remove_dir_all(network.run_dir()).ok();
        }

        Ok(())
    }

    /// Starts a shadesmar network
    ///
    /// ### Arguments
    /// * `network` - Name of network to start
    fn start(self, network: String) -> anyhow::Result<()> {
        use shadesmar_bridge::{Bridge, BridgeConfig};

        let network = self
            .open_network(network)
            .context("unable to open network")?;

        if !network.run_dir().exists() {
            tracing::debug!(path = %network.run_dir().display(), "attmepting to create runtime directory");

            std::fs::create_dir_all(network.run_dir())
                .context("unable to create runtime directory")?;
        }

        if !network.data_dir().exists() {
            tracing::debug!(path = %network.data_dir().display(), "attempting to create data directory");

            std::fs::create_dir_all(network.data_dir())
                .context("unable to create data directory")?;
        }

        tracing::debug!(path = %network.cfg_file().display(), "loading network configuration");
        let cfg = BridgeConfig::load(network.cfg_file())
            .context("unable to load network configuration")?;

        let bridge = Bridge::builder()
            .run_dir(network.run_dir())
            .data_dir(network.data_dir())
            .build(network.name(), cfg)?;

        network.write_pid()?;
        bridge.start()?;
        network.clear_pid()?;

        Ok(())
    }

    /// Prints the status of all installed shadesmar networks
    fn status(self, network: String) -> anyhow::Result<()> {
        let network = self.open_network(network)?;

        let mut sock = network.ctrl_socket()?;
        sock.send(CtrlRequest::Status)?;

        match sock.recv()? {
            Some(CtrlResponse::Status(switch, router)) => {
                println!("Router Status:");
                print_separator!();
                println!("MAC:      {}", router.mac);
                println!("Network:  {}", router.network);

                println!("");
                println!("WAN Interfaces:");
                print_separator!();
                println!(
                    "| {:^25} | {:^16} | {:^13} | {:^13} |",
                    "Name", "Type", "TX", "RX"
                );
                print_separator!();
                for (idx, (ty, tx, rx)) in router
                    .wan_stats
                    .into_iter()
                    .collect::<BinaryHeap<_>>()
                    .into_iter()
                    .rev()
                {
                    let tx = human_bytes!(tx);
                    let rx = human_bytes!(rx);
                    println!("| {idx:<25} | {ty:<16} | {tx:>13} | {rx:>13} |");
                }
                print_separator!();

                println!("");
                println!("Route Table:");
                print_separator!();
                println!(
                    "| {:^20} | {:^16} | {:^14} |",
                    "Destination", "Via", "Packet Count"
                );
                print_separator!();
                for (net, (idx, num_packets)) in router
                    .route_table
                    .into_iter()
                    .collect::<BinaryHeap<_>>()
                    .into_iter()
                    .rev()
                {
                    let net = net.to_string();
                    println!("| {net:<20} | {idx:<16} | {num_packets:<14} |");
                }
                print_separator!();

                println!("");
                println!("Switch Status:");
                print_separator!();
                println!("LAN:      {}", human_bytes!(switch.pkt_stats));
                print_separator!();
                println!("| {:^8} | {:^10} | MACs", "Port", "Type");
                print_separator!();
                for (idx, port) in switch.ports.iter().enumerate() {
                    let macs = port
                        .macs
                        .iter()
                        .map(|mac| mac.to_string())
                        .collect::<Vec<_>>();

                    let macs = match macs.is_empty() {
                        false => macs.join(","),
                        true => String::from("-"),
                    };

                    println!("| {idx:>8} | {:<10} | {macs}", port.desc);
                }
                print_separator!();
            }
            Some(_) => tracing::warn!("requested, status, received non-status response"),
            None => tracing::warn!("requested status, did not receive a response"),
        }

        Ok(())
    }

    /// Stops a shadesmar network
    ///
    /// ### Arguments
    /// * `network` - Network to stop
    /// * `force` - Force network to stop (via SIGKILL)
    fn stop(self, network: String, force: bool) -> anyhow::Result<()> {
        let network = self.open_network(network)?;

        if force {
            // attempt to read pidfile
            let pid = network.read_pid()?;

            tracing::debug!(pid, "stopping network");
            Bridge::stop(pid, false)?;
        } else {
            network.stop()?;
        }

        Ok(())
    }

    /// Prints network packets crossing the switch to stdout
    ///
    /// ### Arguments
    /// * `network` - Network for which to view packets
    fn pcap(self, network: String) -> anyhow::Result<()> {
        let network = self.open_network(network)?;

        let tap = network.tap_socket();

        let mut sock = network.ctrl_socket()?;
        sock.send(CtrlRequest::ConnectTap(tap.clone()))?;

        handle_pcap(tap)?;

        Ok(())
    }

    /// Adds a new route to the routing table
    ///
    /// ### Arguments
    /// * `network` - Network for which to add route
    /// * `route` - Destination network/subnet to add
    /// * `wan` - WAN device over which to route traffic
    fn add_route(self, network: String, route: Ipv4Network, wan: String) -> anyhow::Result<()> {
        let network = self.open_network(network)?;

        let mut sock = network.ctrl_socket()?;
        sock.send(CtrlRequest::AddRoute(route, wan))?;
        sock.recv()?;

        Ok(())
    }

    /// Remvoes a route to the routing table
    ///
    /// ### Arguments
    /// * `network` - Network for which to delete route
    /// * `route` - Destination network/subnet to delete
    fn del_route(self, network: String, route: Ipv4Network) -> anyhow::Result<()> {
        let network = self.open_network(network)?;

        let mut sock = network.ctrl_socket()?;
        sock.send(CtrlRequest::DelRoute(route))?;
        sock.recv()?;

        Ok(())
    }
}

impl Network {
    /// Returns a reference to the name of the network
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns a reference to the configuration file path
    pub fn cfg_file(&self) -> &Path {
        &self.cfg_file
    }

    /// Returns the path to the runtime directory
    pub fn run_dir(&self) -> &Path {
        &self.run_dir
    }

    /// Returns the path to the data directory
    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    /// Returns the path to the file containing the pid of the network (if running)
    pub fn pid_file(&self) -> PathBuf {
        self.run_dir.join(SHADESMAR_PID_FILE)
    }

    /// Opens a new connection to the control socket
    pub fn ctrl_socket(&self) -> anyhow::Result<CtrlClientStream> {
        let path = self.run_dir.join("ctrl.sock");
        let strm = CtrlClientStream::connect(path)?;
        Ok(strm)
    }

    /// Creates a new unix datagram socket to receive netflow/pcap
    pub fn tap_socket(&self) -> PathBuf {
        self.run_dir.join("tap.sock")
    }

    /// Writes the pid of the current process to the pidfile
    pub fn write_pid(&self) -> anyhow::Result<()> {
        // create pid file
        let mut pid_file = File::options()
            .create_new(true)
            .write(true)
            .open(self.pid_file())?;

        let pid = std::process::id();
        pid_file.write_all(&pid.to_le_bytes())?;

        Ok(())
    }

    /// Reads the pid from the pid file, if it exists
    pub fn read_pid(&self) -> anyhow::Result<u32> {
        let mut pid_file = File::open(self.pid_file()).context("unable to open pid file")?;

        let mut buf = [0u8; 4];
        pid_file.read_exact(&mut buf)?;

        let pid = u32::from_le_bytes(buf);

        Ok(pid)
    }

    /// Removes the pidfile
    pub fn clear_pid(&self) -> anyhow::Result<()> {
        std::fs::remove_file(self.pid_file())?;
        Ok(())
    }

    /// Attempts to stop the network
    pub fn stop(&self) -> anyhow::Result<()> {
        let mut sock = self.ctrl_socket()?;
        sock.send(CtrlRequest::Stop)?;
        Ok(())
    }
}
