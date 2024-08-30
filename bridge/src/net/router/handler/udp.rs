//! ICMP Protocol Handler

use std::collections::HashMap;

use parking_lot::RwLock;
use shadesmar_core::{
    ipv4::{Ipv4Packet, Ipv4PacketOwned},
    protocols::{NET_PROTOCOL_UDP, UDP_HDR_SZ},
    ProtocolError,
};

use super::{PortHandler, ProtocolHandler};

#[derive(Default)]
pub struct UdpHandler {
    handlers: RwLock<HashMap<u16, Box<dyn PortHandler>>>,
}

impl UdpHandler {
    /// Registers a port handler for this udp handler
    ///
    /// ### Arguments
    /// * `handler` - Implementation of a `PortHandler`
    pub fn register_port_handler<P: PortHandler + 'static>(&self, handler: P) {
        self.handlers
            .write()
            .insert(handler.port(), Box::new(handler));
    }
}

impl ProtocolHandler for UdpHandler {
    fn protocol(&self) -> u8 {
        NET_PROTOCOL_UDP
    }

    fn handle_protocol(
        &self,
        pkt: &Ipv4PacketOwned,
        buf: &mut [u8],
    ) -> Result<usize, ProtocolError> {
        let payload = pkt.payload();

        if payload.len() < UDP_HDR_SZ {
            return Err(ProtocolError::NotEnoughData(payload.len(), UDP_HDR_SZ))?;
        }

        let src_port = u16::from_be_bytes([payload[0], payload[1]]);
        let dst_port = u16::from_be_bytes([payload[2], payload[3]]);

        if let Some(handler) = self.handlers.read().get(&dst_port) {
            let len = handler.handle_port(&payload[8..], &mut buf[8..])?;
            let len = len + 8;

            buf[0..2].copy_from_slice(&dst_port.to_be_bytes());
            buf[2..4].copy_from_slice(&src_port.to_be_bytes());
            buf[4..6].copy_from_slice(&len.to_be_bytes()[6..8]);
            buf[6..8].copy_from_slice(&[0x00, 0x00]);
            Ok(len)
        } else {
            Ok(0)
        }
    }
}
