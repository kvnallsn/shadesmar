pub mod csum;
mod frame;
pub mod ipv4;
mod macros;
pub mod nat;
pub mod plugins;
pub mod protocols;
pub mod switch;
pub mod types;

pub use self::frame::{EthernetFrame, EthernetPacket};

/// Initializes the logging / tracing library
pub fn init_tracinig(level: u8) {
    let tracing_level = match level {
        0 => tracing::Level::WARN,
        1 => tracing::Level::INFO,
        2 => tracing::Level::DEBUG,
        _ => tracing::Level::TRACE,
    };

    tracing_subscriber::FmtSubscriber::builder()
        .with_max_level(tracing_level)
        .pretty()
        .init();
}

#[derive(thiserror::Error, Debug)]
pub enum ProtocolError {
    #[error("not enough data for payload, got = {0}, expected = {1}")]
    NotEnoughData(usize, usize),

    #[error("malformed packet: {0}")]
    MalformedPacket(String),

    #[error("packet fragmentation required. size = {0}")]
    FragmentationRequired(usize),

    #[error("{0}")]
    Other(String),
}
