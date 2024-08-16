//! UDP upstream.  Forwards traffic to a specific UDP port

use std::{
    io::{self, IoSlice},
    net::{SocketAddr, ToSocketAddrs, UdpSocket},
    os::fd::{AsRawFd, RawFd},
};

use nix::sys::socket::{sendmsg, MsgFlags, SockaddrIn, SockaddrIn6};
use shadesmar_net::Ipv4Packet;
use uuid::Uuid;

use crate::net::{router::RouterTx, wan::WanThreadHandle, NetworkError};

use super::{Wan, WanStats, WanTx};

pub struct UdpDevice {
    dests: Vec<SocketAddr>,
}

pub struct UdpDeviceHandle {
    sock: RawFd,
    dests: Vec<SocketAddr>,
}

impl UdpDevice {
    pub fn connect<S: Into<String>, A: ToSocketAddrs>(_name: S, addrs: A) -> io::Result<Self> {
        let dests = addrs.to_socket_addrs()?.collect::<Vec<_>>();
        Ok(Self { dests })
    }
}

impl Wan for UdpDevice
where
    Self: Sized,
{
    fn spawn(
        &self,
        id: Uuid,
        router: RouterTx,
        _stats: WanStats,
    ) -> Result<super::WanThreadHandle, NetworkError> {
        let sock = UdpSocket::bind("0.0.0.0:0")?;

        let handle = UdpDeviceHandle {
            sock: sock.as_raw_fd(),
            dests: self.dests.clone(),
        };

        let thread = std::thread::Builder::new()
            .name(format!("wan"))
            .spawn(move || {
                let mut buf = [0u8; 1600];
                loop {
                    let (sz, peer) = match sock.recv_from(&mut buf) {
                        Ok(s) => s,
                        Err(_) => break,
                    };

                    tracing::trace!(?peer, "read {sz} bytes from peer: {:02x?}", &buf[..20],);
                    let pkt = buf[0..sz].to_vec();
                    match pkt[0] >> 4 {
                        4 => match Ipv4Packet::parse(pkt) {
                            Ok(pkt) => router.route_ipv4(id.clone(), pkt),
                            Err(_) => (),
                        },
                        6 => router.route_ipv6(pkt),
                        version => tracing::warn!(version, "unknown ip version / malformed packet"),
                    }
                }
            })?;

        let handle = WanThreadHandle::new(thread, handle);

        Ok(handle)
    }
}

impl WanTx for UdpDeviceHandle {
    fn write(&self, pkt: Ipv4Packet) -> Result<(), NetworkError> {
        let iov = [IoSlice::new(&pkt.as_bytes())];

        for dest in &self.dests {
            match dest {
                SocketAddr::V4(addr) => {
                    let addr = SockaddrIn::from(*addr);
                    sendmsg(self.sock, &iov, &[], MsgFlags::empty(), Some(&addr))?;
                }
                SocketAddr::V6(addr) => {
                    let addr = SockaddrIn6::from(*addr);
                    sendmsg(self.sock, &iov, &[], MsgFlags::empty(), Some(&addr))?;
                }
            }
        }
        Ok(())
    }
}
