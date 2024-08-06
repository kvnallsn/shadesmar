//! Shadesmar main binary

pub mod app;
pub mod os;

use std::path::PathBuf;

use app::App;
use clap::{Parser, Subcommand};

/// Command line options
#[derive(Debug, Parser)]
#[command(version, author, about)]
struct Opts {
    /// Controls the verboisty/logging level (-v, -vv, -vvv)
    #[clap(short, long, action = clap::ArgAction::Count)]
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
    },

    /// Starts an shadesmar network
    Start {
        /// Name of network to start
        network: String,
    },

    /// Prints the status of installed networks
    Status { network: String },

    /// Prints packets crossing the switch to stdout
    Netflow {
        /// Name of network to pcap
        network: String,
    },

    /// Stops a (daemonized) shadesmar network
    Stop {
        /// Name of network to start
        network: String,

        /// Force network to stop
        #[clap(short, long)]
        force: bool,
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
