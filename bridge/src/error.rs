//! bridge error type

use std::borrow::Cow;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("vhost: {0}")]
    VHost(#[from] shadesmar_vhost::Error),

    #[error("net: {0}")]
    NetProtocol(#[from] shadesmar_net::ProtocolError),

    #[error("i/o: {0}")]
    IO(#[from] std::io::Error),

    #[error("network: {0}")]
    Network(#[from] crate::net::NetworkError),

    #[error("system: {0}")]
    System(#[from] nix::errno::Errno),

    #[error("infallible: {0}")]
    Infallible(#[from] std::convert::Infallible),

    #[error("bincode: {0}")]
    Bincode(#[from] bincode::Error),

    #[error("json: {0}")]
    Json(#[from] serde_json::Error),

    #[error("{0}")]
    Other(Cow<'static, str>),
}

impl From<String> for Error {
    fn from(msg: String) -> Self {
        Error::Other(Cow::Owned(msg))
    }
}

impl From<&'static str> for Error {
    fn from(msg: &'static str) -> Self {
        Error::Other(Cow::Borrowed(msg))
    }
}
