//! ICMP related structures

use crate::{checksum, Ipv4Header, ProtocolError};

pub const ICMP_HDR_SZ: usize = 4;
pub const ICMP_TY_ECHO_REPLY: u8 = 0;
pub const ICMP_TY_DESTINATION_UNREACHABLE: u8 = 3;
pub const ICMP_TY_ECHO_REQUEST: u8 = 8;

#[derive(Debug)]
pub enum IcmpType {
    EchoReply { id: u16, seq: u16, data: Vec<u8> },
    DestinationUnreachable(DestinationUnreachableCode, [u8; 28]),
    Redirect,
    EchoRequest { id: u16, seq: u16, data: Vec<u8> },
}

#[derive(Debug)]
pub enum DestinationUnreachableCode {
    NetworkUnreachable,
    HostUnreachable,
    ProtocolUnreachable,
    PortUnreachable,
    FragmentationRequired,
    SourceRouteFailed,
    NetworkUnknown,
    HostUnknown,
    SourceHostIsolated,
    NetworkAdminProhibited,
    HostAdminProhibited,
    NetworkUnreachableToS,
    HostUnreachableToS,
    CommAdminProhibited,
    HostPrecedenceViolation,
    PrecedenceCutoff,
}

impl IcmpType {
    pub fn as_u8(&self) -> u16 {
        match self {
            Self::EchoReply { .. } => 0,
            Self::DestinationUnreachable(code, _) => {
                let ty: u16 = 3;
                let code: u16 = code.as_u8().into();
                (ty << 8) | code
            }
            Self::Redirect => 5,
            Self::EchoRequest { .. } => 8,
        }
    }
}

impl DestinationUnreachableCode {
    pub fn as_u8(&self) -> u8 {
        match self {
            DestinationUnreachableCode::NetworkUnreachable => 0,
            DestinationUnreachableCode::HostUnreachable => 1,
            DestinationUnreachableCode::ProtocolUnreachable => 2,
            DestinationUnreachableCode::PortUnreachable => 3,
            DestinationUnreachableCode::FragmentationRequired => 4,
            DestinationUnreachableCode::SourceRouteFailed => 5,
            DestinationUnreachableCode::NetworkUnknown => 6,
            DestinationUnreachableCode::HostUnknown => 7,
            DestinationUnreachableCode::SourceHostIsolated => 8,
            DestinationUnreachableCode::NetworkAdminProhibited => 9,
            DestinationUnreachableCode::HostAdminProhibited => 10,
            DestinationUnreachableCode::NetworkUnreachableToS => 11,
            DestinationUnreachableCode::HostUnreachableToS => 12,
            DestinationUnreachableCode::CommAdminProhibited => 13,
            DestinationUnreachableCode::HostPrecedenceViolation => 14,
            DestinationUnreachableCode::PrecedenceCutoff => 15,
        }
    }
}

pub struct IcmpPacket {
    ty: IcmpType,
}

impl IcmpPacket {
    pub fn echo_request() -> Self {
        todo!("implement this")
    }

    pub fn echo_reply() -> Self {
        todo!("implement this")
    }

    pub fn destination_unreachable(
        code: DestinationUnreachableCode,
        hdr: &Ipv4Header,
        payload: &[u8],
    ) -> Self {
        let mut buf = [0u8; 28];
        hdr.as_bytes(&mut buf);
        buf[20..28].copy_from_slice(&payload[0..8]);
        Self {
            ty: IcmpType::DestinationUnreachable(code, buf),
        }
    }

    pub fn parse(data: &[u8]) -> Result<Self, ProtocolError> {
        if data.len() < ICMP_HDR_SZ {
            return Err(ProtocolError::NotEnoughData(data.len(), ICMP_HDR_SZ))?;
        }

        match data[0] {
            ICMP_TY_ECHO_REPLY => {
                let id = u16::from_be_bytes([data[4], data[5]]);
                let seq = u16::from_be_bytes([data[6], data[7]]);
                let data = data[8..].to_vec();
                Ok(IcmpPacket {
                    ty: IcmpType::EchoReply { id, seq, data },
                })
            }
            ICMP_TY_ECHO_REQUEST => {
                let id = u16::from_be_bytes([data[4], data[5]]);
                let seq = u16::from_be_bytes([data[6], data[7]]);
                let data = data[8..].to_vec();
                Ok(IcmpPacket {
                    ty: IcmpType::EchoRequest { id, seq, data },
                })
            }
            _ => todo!(),
        }
    }

    pub fn as_bytes(&self, buf: &mut [u8]) -> usize {
        match &self.ty {
            IcmpType::EchoRequest { id, seq, data } => {
                let end = 8 + data.len();
                buf[0] = ICMP_TY_ECHO_REQUEST;
                buf[1] = 0; /* code is zero for all requests */
                buf[2..4].copy_from_slice(&[0, 0]);
                buf[4..6].copy_from_slice(&id.to_be_bytes());
                buf[6..8].copy_from_slice(&seq.to_be_bytes());
                buf[8..end].copy_from_slice(&data);

                let csum = checksum(&buf[0..end]);
                buf[2..4].copy_from_slice(&csum.to_be_bytes());
                end
            }
            IcmpType::EchoReply { id, seq, data } => {
                let end = 8 + data.len();
                buf[0] = ICMP_TY_ECHO_REPLY;
                buf[1] = 0; /* code is zero for all requests */
                buf[2..4].copy_from_slice(&[0, 0]);
                buf[4..6].copy_from_slice(&id.to_be_bytes());
                buf[6..8].copy_from_slice(&seq.to_be_bytes());
                buf[8..end].copy_from_slice(&data);

                let csum = checksum(&buf[0..end]);
                buf[2..4].copy_from_slice(&csum.to_be_bytes());
                end
            }
            IcmpType::Redirect => 0,
            IcmpType::DestinationUnreachable(code, data) => {
                buf[0] = ICMP_TY_DESTINATION_UNREACHABLE;
                buf[1] = code.as_u8();
                buf[2..8].copy_from_slice(&[0, 0, 0, 0, 0, 0]);
                buf[8..36].copy_from_slice(data.as_slice());

                let csum = checksum(&buf[0..36]);
                buf[2..4].copy_from_slice(&csum.to_be_bytes());
                36
            }
        }
    }
}
