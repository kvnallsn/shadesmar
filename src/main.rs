//! Shadesmar main binary

pub mod app;
pub mod os;

use std::path::PathBuf;

use app::App;
use clap::{Parser, Subcommand};
use shadesmar_net::types::Ipv4Network;

/// Command line options
#[derive(Debug, Parser)]
#[command(version, author, about)]
struct Opts {
    /// Controls the verboisty/logging level (-v, -vv, -vvv)
    #[clap(short, long, global=true, action = clap::ArgAction::Count)]
    verbose: u8,

    /// Command to execute
    #[clap(subcommand)]
    cmd: Command,
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

    let tracing_level = match opts.verbose {
        0 => tracing::Level::WARN,
        1 => tracing::Level::INFO,
        2 => tracing::Level::DEBUG,
        _ => tracing::Level::TRACE,
    };

    tracing_subscriber::FmtSubscriber::builder()
        .with_max_level(tracing_level)
        .init();

    let app = App::initialize()?;
    app.run(opts.cmd)?;

    Ok(())
}
