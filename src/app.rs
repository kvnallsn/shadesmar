//! Shadesmar application

mod pcap;

use std::{
    fs::File,
    io::{Read, Write},
    path::{Path, PathBuf},
};

use anyhow::Context;
use console::Style;
use dialoguer::{theme::Theme, Confirm};
use pcap::handle_pcap;
use shadesmar_bridge::{
    config::{WanConfig, YamlConfig},
    ctrl::{CtrlClientStream, CtrlRequest},
    Bridge, BridgeStatus,
};
use shadesmar_core::{
    plugins::{WanPluginInitOptions, WanPlugins},
    types::Ipv4Network,
};

use crate::{Command, NetworkCommand, NetworkRouteCommand, NetworkWanCommand, ShadesmarConfig};

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

macro_rules! table {
    (top) => {
        println!("\u{250C}{:\u{2500}<78}\u{2510}", "\u{2500}")
    };
    (bottom) => {
        println!("\u{2514}{:\u{2500}<78}\u{2518}", "\u{2500}")
    };
    (header; $style:expr; $(($text:expr,$width:expr)),+) => {{
        $(print!("\u{2502} {:^width$} ", $style.apply_to($text), width = $width);)+
        println!("\u{2502}");
    }};
    (row; $(($text:expr,$width:expr,$align:literal)),+) => {
        $(match $align {
            ">" => print!("\u{2502} {:>width$} ", $text, width = $width),
            "<" => print!("\u{2502} {:<width$} ", $text, width = $width),
            "^" => print!("\u{2502} {:^width$} ", $text, width = $width),
            _ => print!("\u{2502} {:width$} ", $text, width = $width),
        };)+
        println!("\u{2502}");
    };
    (sep) => {
        println!("\u{251C}{:\u{2500}<78}\u{2524}", "\u{2500}")
    };
}

/// Internal application state
pub struct App {
    /// Actively loaded plugins
    plugins: WanPlugins,

    /// Path to the runtime/ephemeral file storage location
    run: PathBuf,

    /// Path to the data/persistent file storage location
    data: PathBuf,

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
    pub fn initialize(
        cfg: ShadesmarConfig,
        plugin_opts: WanPluginInitOptions,
    ) -> anyhow::Result<Self> {
        if !cfg.data.exists() {
            tracing::info!(path = %cfg.data.display(), "data directory does not exist, attempting to create");
            std::fs::create_dir_all(&cfg.data)?;
        } else if !cfg.data.is_dir() {
            return Err(anyhow::anyhow!(
                "data path exists but is not a directory (path: {})",
                cfg.data.display(),
            ));
        }

        if !cfg.run.exists() {
            tracing::info!(path = %cfg.run.display(), "runtime directory does not exist, attempting to create");
            std::fs::create_dir_all(&cfg.run)?;
        } else if !cfg.run.is_dir() {
            return Err(anyhow::anyhow!(
                "rutime path exists but is not a directory (path: {})",
                cfg.run.display(),
            ));
        }

        let plugins = WanPlugins::init(cfg.plugins, plugin_opts)?;

        let theme = Box::new(dialoguer::theme::ColorfulTheme::default());

        Ok(Self {
            plugins,
            run: cfg.run,
            data: cfg.data,
            theme,
        })
    }

    /// Runs the application
    pub fn run(self, cmd: Command) -> anyhow::Result<()> {
        match cmd {
            Command::Install { config, name } => self.install(config, name)?,
            Command::Uninstall { network, purge } => self.uninstall(network, purge)?,
            Command::Net { name: network, cmd } => match cmd {
                NetworkCommand::Start => self.start(network)?,
                NetworkCommand::Stop { force } => self.stop(network, force)?,
                NetworkCommand::Status => self.status(network)?,
                NetworkCommand::Netflow => self.pcap(network)?,
                NetworkCommand::Route { cmd } => match cmd {
                    NetworkRouteCommand::Add { route, wan } => {
                        self.add_route(network, route, wan)?
                    }
                    NetworkRouteCommand::Delete { route } => self.del_route(network, route)?,
                },
                NetworkCommand::Wan { cmd } => match cmd {
                    NetworkWanCommand::Add { cfg, name } => self.add_wan(network, cfg, name)?,
                    NetworkWanCommand::Delete { wan, cleanup } => {
                        self.stop_wan(network, wan, cleanup)?
                    }
                },
            },
        }

        Ok(())
    }

    /// Creates a new network
    ///
    /// ### Arguments
    /// * `network` - Name of the network
    pub fn open_network(&self, network: String) -> anyhow::Result<Network> {
        let run_dir = self.run.join(&network);
        let data_dir = self.data.join(&network);

        let cfg_file = data_dir.join(&network).with_extension(SHADESMAR_CFG_EXT);

        if !run_dir.exists() {
            std::fs::create_dir_all(&run_dir)?;
        }

        if !data_dir.exists() {
            std::fs::create_dir_all(&data_dir)?;
        }

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
                    .file_stem()
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

        // NOTE: we delay the handling of the error message to ensure we
        // cleanup the run directory in case of an error
        let res = bridge.start(&self.plugins);
        network.cleanup()?;
        res?;

        Ok(())
    }

    /// Prints the status of all installed shadesmar networks
    fn status(self, network: String) -> anyhow::Result<()> {
        let network = self.open_network(network)?;

        let bold = Style::new().bold();
        let green = Style::new().green();
        let red = Style::new().red();

        let mut sock = network.ctrl_socket()?;
        let bridge: BridgeStatus = sock.request(CtrlRequest::Status)?;

        println!("Router Status:");
        //table!();
        println!("MAC:      {}", bridge.router.mac);
        println!("Network:  {}", bridge.router.network);

        println!("");
        println!("WAN Interfaces:");
        table!(top);
        table!(header; bold; ("Name", 18), ("Status", 8), ("Type", 12), ("TX", 13), ("RX", 13));
        table!(sep);
        for (name, (running, ty, tx, rx)) in bridge.router.wan_stats.iter() {
            let tx = human_bytes!(*tx);
            let rx = human_bytes!(*rx);
            let status = match running {
                true => green.apply_to("running"),
                false => red.apply_to("dead"),
            };

            table!(row; (name,18,"<"), (status,8,"<"), (ty,12,"<"), (tx,13,">"), (rx,13,">"));
        }
        table!(bottom);

        println!("");
        println!("Route Table:");
        table!(top);
        table!(header; bold; ("Destination", 20), ("Via", 20), ("Packet Count", 30));
        table!(sep);
        for (net, (wan, num_packets)) in bridge.router.route_table.into_iter() {
            let net = match net.is_default() {
                true => String::from("default"),
                false => net.to_string(),
            };

            let wan = match bridge.router.wan_stats.get(&wan) {
                None => red.apply_to("wan missing".to_owned()),
                Some((true, _, _, _)) => green.apply_to(wan),
                Some((false, _, _, _)) => red.apply_to(format!("{wan} (dead)")),
            };

            table!(row; (net,20,"<"), (wan, 20, "<"), (num_packets, 30, "<"));
        }
        table!(bottom);

        println!("");
        println!("Switch Status:");
        //table!();
        //println!("LAN:      {}", human_bytes!(switch.pkt_stats));
        table!(top);
        table!(header; bold; ("Port", 8), ("Type", 10), ("MACs", 52));
        table!(sep);
        for (idx, port) in bridge.switch.ports.iter().enumerate() {
            let macs = port
                .macs
                .iter()
                .map(|mac| mac.to_string())
                .collect::<Vec<_>>();

            let macs = match macs.is_empty() {
                false => macs.join(","),
                true => String::from("-"),
            };

            table!(row; (idx,8,">"), (port.desc,10, "<"), (macs,52,"<"));
        }
        table!(bottom);

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
            let mut sock = network.ctrl_socket()?;
            sock.request(CtrlRequest::Stop)?;
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
        sock.request::<()>(CtrlRequest::ConnectTap(tap.clone()))?;

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
        sock.request::<()>(CtrlRequest::AddRoute(route, wan))?;

        Ok(())
    }

    /// Remvoes a route to the routing table
    ///
    /// ### Arguments
    /// * `network` - Network for which to delete route
    /// * `route` - Destination network/subnet to delete
    fn del_route(self, network: String, route: Ipv4Network) -> anyhow::Result<()> {
        let network = self.open_network(network)?;

        if route.is_default() {
            if !self
                .prompt_confirm("This is the default route, are you sure you want to remove it?")?
            {
                return Err(anyhow::anyhow!("user cancelled operation"));
            }
        }

        let mut sock = network.ctrl_socket()?;
        sock.request::<()>(CtrlRequest::DelRoute(route))?;

        Ok(())
    }

    /// Stops a WAN device
    ///
    /// Once a WAN device has been stopped, it cannot be started again
    ///
    /// ### Arguments
    /// * `network` - Network for which the WAN device is assigned
    /// * `wan` - Name of WAN device to stop
    /// * `cleanup` - Remove associated routes
    fn stop_wan(self, network: String, wan: String, cleanup: bool) -> anyhow::Result<()> {
        let network = self.open_network(network)?;

        let mut sock = network.ctrl_socket()?;
        sock.request::<()>(CtrlRequest::RemoveWan(wan, cleanup))?;

        Ok(())
    }

    /// Attempts to add a new wan connection to the network
    ///
    /// ### Arguments
    /// * `network` - Network to assign WAN device
    /// * `cfg` - Path to the WAN device's configuration
    /// * `name` - Name of the WAN connection (if renaming)
    fn add_wan(self, network: String, cfg: PathBuf, name: Option<String>) -> anyhow::Result<()> {
        let network = self.open_network(network)?;

        let mut cfg = WanConfig::read_yaml_from_file(&cfg)?;
        if let Some(name) = name {
            cfg.name = name;
        }

        let mut sock = network.ctrl_socket()?;
        sock.request::<()>(CtrlRequest::AddWan(cfg))?;

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

    /// Deletes the run directory associated with this network
    ///
    /// This will remove the pid file, sockets, and any other files stored
    /// in the ephemeral run directory.
    pub fn cleanup(&self) -> anyhow::Result<()> {
        std::fs::remove_dir_all(&self.run_dir).with_context(|| {
            format!(
                "unable to cleanup run directory ({})",
                self.run_dir.display()
            )
        })?;
        Ok(())
    }
}
