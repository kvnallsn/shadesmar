//! Collection of Protocol Handlers

mod icmp;
mod udp;

use shadesmar_core::{Ipv4Packet, ProtocolError};

pub use self::{icmp::IcmpHandler, udp::UdpHandler};

pub trait ProtocolHandler: Send + Sync {
    fn protocol(&self) -> u8;

    fn handle_protocol(&mut self, pkt: &Ipv4Packet, buf: &mut [u8])
        -> Result<usize, ProtocolError>;
}

pub trait PortHandler: Send + Sync {
    fn port(&self) -> u16;
    fn handle_port(&mut self, data: &[u8], buf: &mut [u8]) -> Result<usize, ProtocolError>;
}
