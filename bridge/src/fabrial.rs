//! Provides access to devices in the network via a bound network socket

use std::{io, net::SocketAddr};

use mio::net::TcpListener;

pub struct Fabrial {
    /// listens for connections
    listener: TcpListener,
}

impl Fabrial {
    /// Creates a new `Fabrial` to allow port-forwarding into the oathgate-bridge network
    ///
    /// ### Arguments
    /// * `addr` - Socket address to bind the (host) TCP socket
    pub fn new<A: Into<SocketAddr>>(addr: A) -> io::Result<Self> {
        let listener = TcpListener::bind(addr.into())?;
        Ok(Self { listener })
    }
}
