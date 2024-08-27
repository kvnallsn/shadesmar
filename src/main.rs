//! Shadesmar main binary

pub mod app;
pub mod os;

use std::{collections::HashMap, path::PathBuf};

use app::App;
use clap::{Parser, Subcommand};
use serde::Deserialize;
use shadesmar_bridge::config::YamlConfig;
use shadesmar_net::{plugins::WanPluginInitOptions, types::Ipv4Network};

/// Path to the default configuration file
const DEFAULT_CONFIG_FILE: &str = "/etc/shadesmar.yml";
const DEFAULT_SHADESMAR_RUN_PATH: &str = "/var/run/shadesmar";
const DEFAULT_SHADESMAR_DAT_PATH: &str = "/var/lib/shadesmar";

/// Command line options
#[derive(Debug, Parser)]
#[command(version, author, about)]
struct Opts {
    /// Controls the verboisty/logging level (-v, -vv, -vvv)
    #[clap(short, long, global=true, action = clap::ArgAction::Count)]
    verbose: u8,

    /// Path to configuration file
    #[clap(short, long, default_value = DEFAULT_CONFIG_FILE)]
    config: PathBuf,

    /// Command to execute
    #[clap(subcommand)]
    cmd: Command,
}

/// Shadesmar Configuration
#[derive(Debug, Deserialize)]
pub struct ShadesmarConfig {
    /// Path to the runtime (ephemeral) directory
    #[serde(default = "default_run_directory")]
    pub run: PathBuf,

    /// Path to the data (persistent) directory
    #[serde(default = "default_data_directory")]
    pub data: PathBuf,

    /// List of plugins
    #[serde(default)]
    pub plugins: HashMap<String, PathBuf>,
}

fn default_run_directory() -> PathBuf {
    PathBuf::from(DEFAULT_SHADESMAR_RUN_PATH)
}

fn default_data_directory() -> PathBuf {
    PathBuf::from(DEFAULT_SHADESMAR_DAT_PATH)
}

impl Default for ShadesmarConfig {
    fn default() -> Self {
        Self {
            run: default_run_directory(),
            data: default_data_directory(),
            plugins: HashMap::new(),
        }
    }
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Installs a network configuration file
    Install {
        /// Path to network configuration file
        config: PathBuf,

        /// Rename the network on installation (default network name is the name of the file)
        #[clap(short, long)]
        name: Option<String>,
    },

    /// Uninstalls (optionally purges) a network configuration
    Uninstall {
        /// Name of network to uninstall
        network: String,

        /// Delete runtime files (sockets, pcap, etc.)
        #[clap(long)]
        purge: bool,
    },

    /// Manage a shadesmar network
    Net {
        /// Name of network
        name: String,

        #[clap(subcommand)]
        cmd: NetworkCommand,
    },
}

#[derive(Debug, Subcommand)]
pub enum NetworkCommand {
    /// Starts an shadesmar network
    Start,

    /// Prints the status of installed networks
    Status,

    /// Prints packets crossing the switch to stdout
    Netflow,

    /// Stops a (daemonized) shadesmar network
    Stop {
        /// Force network to stop
        #[clap(long)]
        force: bool,
    },

    /// Manage a network's routing table
    Route {
        #[clap(subcommand)]
        cmd: NetworkRouteCommand,
    },

    /// Manage a network's WAN devices
    Wan {
        #[clap(subcommand)]
        cmd: NetworkWanCommand,
    },
}

#[derive(Debug, Subcommand)]
pub enum NetworkRouteCommand {
    /// Adds a new route to the routing table
    Add {
        /// Destination network / subnet to add
        route: Ipv4Network,

        /// Name of WAN device over which to route traffic to subnet
        wan: String,
    },

    /// Deletes a route from the routing table
    Delete {
        /// Destination network / subnet to add
        route: Ipv4Network,
    },
}

#[derive(Debug, Subcommand)]
pub enum NetworkWanCommand {
    /// Adds a new WAN device to a network
    Add {
        /// Path to the WAN configuration file
        cfg: PathBuf,

        /// Name of wan device (if different from file)
        #[clap(short, long)]
        name: Option<String>,
    },

    /// Stops a running WAN device on a network
    Delete {
        /// Name of wan device to stop
        wan: String,

        /// Removes all routes associated with this WAN device
        #[clap(short = 'a', long = "cleanup")]
        cleanup: bool,
    },
}

fn main() -> anyhow::Result<()> {
    let opts = Opts::parse();

    shadesmar_net::init_tracinig(opts.verbose);

    let mut cfg = match opts.config.exists() && opts.config.is_file() {
        true => ShadesmarConfig::read_yaml_from_file(&opts.config)?,
        false => ShadesmarConfig::default(),
    };

    // fixup plugin paths
    let plugin_dir = cfg.data.join("plugins");
    for (_name, path) in cfg.plugins.iter_mut() {
        if path.is_relative() {
            let full_path = plugin_dir.join(&path);
            path.push(full_path);
        }
    }

    tracing::debug!("loaded configuration:\n{cfg:#?}");

    let plugin_opts = WanPluginInitOptions::new(opts.verbose);
    let app = App::initialize(cfg, plugin_opts)?;
    app.run(opts.cmd)?;

    Ok(())
}
