//! ICMP Protocol Handler

use shadesmar_core::{
    checksum,
    protocols::{
        icmp::{ICMP_HDR_SZ, ICMP_TY_ECHO_REPLY, ICMP_TY_ECHO_REQUEST},
        NET_PROTOCOL_ICMP,
    },
    Ipv4Packet, Ipv4PacketOwned, ProtocolError,
};

use super::ProtocolHandler;

#[derive(Default)]
pub struct IcmpHandler;

impl ProtocolHandler for IcmpHandler {
    fn protocol(&self) -> u8 {
        NET_PROTOCOL_ICMP
    }

    fn handle_protocol(
        &self,
        pkt: &Ipv4PacketOwned,
        buf: &mut [u8],
    ) -> Result<usize, ProtocolError> {
        let payload = pkt.payload();

        if payload.len() < ICMP_HDR_SZ {
            return Err(ProtocolError::NotEnoughData(payload.len(), ICMP_HDR_SZ))?;
        }

        match payload[0] {
            ICMP_TY_ECHO_REQUEST => {
                tracing::trace!("handling icmp echo request");

                let len = payload.len();
                buf[ICMP_HDR_SZ..len].copy_from_slice(&payload[ICMP_HDR_SZ..]);

                let csum = checksum(&buf);
                buf[2..4].copy_from_slice(&csum.to_be_bytes());
                Ok(payload.len())
            }
            ICMP_TY_ECHO_REPLY => Ok(0),
            _ => Ok(0),
        }
    }
}
