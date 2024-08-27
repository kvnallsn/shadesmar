//! Network Error Encapsulation

use std::borrow::Cow;

use shadesmar_net::{plugins::PluginError, types::Ipv4Network, ProtocolError};

/// Collection of errors that may occur during routing/switching packets
#[derive(Debug, thiserror::Error)]
pub enum NetworkError {
    #[error("router: {0}")]
    Generic(Cow<'static, str>),

    #[error("nix: {0}")]
    Errno(#[from] nix::errno::Errno),

    #[error("i/o: {0}")]
    Io(#[from] std::io::Error),

    #[error("protocol failed: {0}")]
    Protocol(#[from] ProtocolError),

    #[error("pcap: {0}")]
    Pcap(#[from] pcap_file::PcapError),

    #[error("unable to decode base64: {0}")]
    DecodeSlice(#[from] base64::DecodeSliceError),

    #[error("route not found: {0}")]
    RouteNotFound(Ipv4Network),

    #[error("wan device not found")]
    WanDeviceNotFound(String),

    #[error("plugin: {0}")]
    PluginError(#[from] PluginError),

    #[error("sender channel closed")]
    ChannelClosed,
}

impl<T> From<flume::SendError<T>> for NetworkError {
    fn from(_: flume::SendError<T>) -> Self {
        Self::ChannelClosed
    }
}
