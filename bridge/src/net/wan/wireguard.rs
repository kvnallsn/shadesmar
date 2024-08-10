//! A wireguard upstream provider to encrypt all traffic

use std::{
    borrow::Cow,
    collections::HashMap,
    fmt::Debug,
    io::ErrorKind,
    net::{Ipv4Addr, SocketAddr},
    os::fd::{AsFd, AsRawFd},
    sync::Arc,
};

use base64::Engine;
use boringtun::{
    noise::{errors::WireGuardError, Tunn, TunnResult},
    x25519::{PublicKey, StaticSecret},
};
use flume::{Receiver, Sender};
use mio::{net::UdpSocket, unix::SourceFd, Events, Interest, Poll, Token, Waker};
use nix::sys::{
    time::TimeSpec,
    timerfd::{ClockId, Expiration, TimerFd, TimerFlags, TimerSetTimeFlags},
};
use serde::{Deserialize, Serialize};
use shadesmar_net::{nat::NatTable, Ipv4Header, Ipv4Packet};

use crate::net::{router::RouterTx, NetworkError};

use super::{Wan, WanHandle, WanStats};

const TOKEN_WAKER: Token = Token(0);
const TOKEN_UDP: Token = Token(1);
const TOKEN_TIMER: Token = Token(2);

const WG_BUF_SZ: usize = 1600;

pub struct WgDevice {
    /// Human-friendly name of this wan device
    name: String,

    /// WireGuard tunnel (encryptor/decryptor)
    tun: Tunn,

    /// Endpoint of peer (ipv4/6 and port combo)
    endpoint: SocketAddr,

    /// Ipv4 address of WireGuard device
    ipv4: Ipv4Addr,

    /// Receiver for an Ipv4 packet to encrypt / route
    rx: Option<Receiver<Ipv4Packet>>,

    /// Handle used to communicate with this device
    handle: WgHandle,

    /// Poller to watch for events
    poll: Poll,

    /// Maps & tracks outbound connections
    nat: NatTable,

    /// Cache used to store/rebuild fragmented packets
    cache: HashMap<u16, Ipv4Packet>,

    /// WAN statistics
    stats: WanStats,
}

/// A handle/reference for the controller thread to communicate
/// with a WireGuard WAN device.
#[derive(Clone)]
pub struct WgHandle {
    tx: Sender<Ipv4Packet>,
    waker: Arc<Waker>,
}

#[derive(Deserialize, Serialize)]
pub struct WgConfig {
    pub key: String,
    pub peer: String,
    pub endpoint: SocketAddr,
}

impl Debug for WgConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "WgConfig {{ key: \"--snipped--\", peer: {}, endpoint: {} }}",
            self.peer, self.endpoint
        )
    }
}

impl WgDevice {
    /// Creates a new WireGuard tunnel device from the supplied config
    ///
    /// ### Arguments
    /// * `cfg` - WireGuard configuration
    pub fn create<A: Into<Ipv4Addr>, S: Into<String>>(
        name: S,
        ipv4: A,
        cfg: &WgConfig,
    ) -> Result<Self, NetworkError> {
        use base64::prelude::BASE64_STANDARD;

        let mut key = [0u8; 32];
        let mut peer = [0u8; 32];
        BASE64_STANDARD.decode_slice(&cfg.key, &mut key)?;
        BASE64_STANDARD.decode_slice(&cfg.peer, &mut peer)?;

        let key = StaticSecret::from(key);
        let peer = PublicKey::from(peer);

        let tun = Tunn::new(key, peer, None, None, 1, None)
            .map_err(|e| NetworkError::Generic(Cow::Borrowed(e)))?;

        let poll = Poll::new()?;
        let waker = Waker::new(poll.registry(), TOKEN_WAKER)?;

        let stats = WanStats::new(format!("WireGuard"));
        let (tx, rx) = flume::unbounded();
        let handle = WgHandle {
            tx,
            waker: Arc::new(waker),
        };

        Ok(Self {
            name: name.into(),
            tun,
            endpoint: cfg.endpoint,
            ipv4: ipv4.into(),
            rx: Some(rx),
            handle,
            poll,
            nat: NatTable::new(),
            cache: HashMap::new(),
            stats,
        })
    }

    /// Process the outcome of an encapsulate/decapsulate action
    ///
    /// ### Arguments
    /// * `action` - Outcome of encapsulate/decapsulate/update_timers
    fn handle_tun_result(
        &mut self,
        action: TunnResult,
        router: &RouterTx,
        sock: &UdpSocket,
    ) -> Result<bool, NetworkError> {
        let mut to_network = false;

        match action {
            TunnResult::Err(error) => match error {
                WireGuardError::ConnectionExpired => (),
                error => tracing::error!(?error, "[wg] unable to handle action"),
            },
            TunnResult::Done => tracing::trace!("[wg] no action"),
            TunnResult::WriteToNetwork(pkt) => {
                tracing::trace!("[wg] write {} bytes to network", pkt.len());
                self.stats.tx_add(pkt.len() as u64);
                sock.send_to(pkt, self.endpoint)?;
                to_network = true;
            }
            TunnResult::WriteToTunnelV4(pkt, ip) => {
                self.stats.rx_add(pkt.len() as u64);
                let hdr = Ipv4Header::extract_from_slice(&pkt)?;
                tracing::trace!(src = ?ip, dst = ?hdr.dst, "[wg] write {} bytes to tunnel", pkt.len());
                let pkt = Ipv4Packet::parse(pkt.to_vec())?;

                // rebuild fragmented packets
                let pkt = match (pkt.has_fragments(), pkt.fragment_offset()) {
                    (false, 0) => Some(pkt),
                    (true, 0) => {
                        self.cache.insert(pkt.id(), pkt);
                        None
                    }
                    (true, offset) => {
                        self.cache
                            .get_mut(&pkt.id())
                            .map(|fpkt| fpkt.add_fragment_data(offset, pkt.payload()));
                        None
                    }
                    (false, offset) => match self.cache.remove(&pkt.id()) {
                        Some(mut fpkt) => {
                            fpkt.add_fragment_data(offset, pkt.payload());
                            fpkt.finalize();
                            Some(fpkt)
                        }
                        None => {
                            return Err(NetworkError::Generic("missing frag packet data".into()))?
                        }
                    },
                };

                // undo nat'd packets
                if let Some(mut pkt) = pkt {
                    if let Some(orig) = self.nat.get(&pkt) {
                        tracing::trace!(ip = ?orig, "[wg] setting original ipv4 address");
                        pkt.unmasquerade(orig);
                        router.route_ipv4(pkt);
                    } else {
                        tracing::warn!(
                            protocol = pkt.protocol(),
                            src = %pkt.src(),
                            dst = %pkt.dest(),
                            id = %pkt.id(),
                            flags = %pkt.flags(),
                            hdrlen = %pkt.header_length(),
                            length = %pkt.len(),
                            "[wg] no nat entry found",
                        );

                        tracing::trace!("packet bytes: {:02x?}", &pkt.as_bytes()[..28]);
                    }
                }
            }
            TunnResult::WriteToTunnelV6(pkt, ip) => {
                self.stats.rx_add(pkt.len() as u64);
                tracing::trace!(?ip, "[wg] write {} bytes to tunnel", pkt.len());
                router.route_ipv6(pkt.to_vec());
            }
        }

        Ok(to_network)
    }
}

impl Wan for WgDevice {
    fn name(&self) -> &str {
        self.name.as_str()
    }

    fn stats(&self) -> WanStats {
        self.stats.clone()
    }

    fn as_wan_handle(&self) -> Result<Box<dyn WanHandle>, NetworkError> {
        Ok(Box::new(self.handle.clone()))
    }

    fn run(mut self: Box<Self>, router: RouterTx) -> Result<(), NetworkError> {
        let sock = std::net::UdpSocket::bind("0.0.0.0:0")?;
        sock.set_nonblocking(true)?;
        let mut sock = UdpSocket::from_std(sock);

        // create a timerfd to use with mio that expires every 500 milliseconds
        let timer = TimerFd::new(ClockId::CLOCK_MONOTONIC, TimerFlags::TFD_NONBLOCK)?;
        timer.set(
            Expiration::Interval(TimeSpec::new(0, 500000000)),
            TimerSetTimeFlags::empty(),
        )?;

        self.poll
            .registry()
            .register(&mut sock, TOKEN_UDP, Interest::READABLE)?;

        self.poll.registry().register(
            &mut SourceFd(&timer.as_fd().as_raw_fd()),
            TOKEN_TIMER,
            Interest::READABLE,
        )?;

        let rx = self.rx.take().ok_or_else(|| {
            NetworkError::Generic(String::from("wireguard missing receiver").into())
        })?;

        // Handle packets / messages
        // from vm (aka write): rx -> tunn -> socket
        // from internet (aka read): socket -> tunn -> router
        //
        // mio uses non-blocking sockets / edge-triggered mode for epoll.
        // This requires looping / drain to ensure we've read all available messages
        // because the file descriptor will not be triggered again until more data
        // arrives.
        let mut udp_buf = [0u8; WG_BUF_SZ];
        let mut wg_buf = [0u8; WG_BUF_SZ];
        let mut events = Events::with_capacity(10);
        while let Ok(_) = self.poll.poll(&mut events, None) {
            for event in &events {
                match event.token() {
                    TOKEN_UDP => {
                        'udp: loop {
                            match sock.recv_from(&mut udp_buf) {
                                Ok((sz, peer)) => {
                                    tracing::trace!(?peer, "[wg] read {sz} bytes");

                                    let mut sz = sz;
                                    'wg: loop {
                                        let action = self.tun.decapsulate(
                                            Some(peer.ip()),
                                            &udp_buf[..sz],
                                            &mut wg_buf,
                                        );

                                        if !self.handle_tun_result(action, &router, &sock)? {
                                            tracing::trace!("[wg] no queued packets!");
                                            break 'wg;
                                        } else {
                                            sz = 0;
                                        }
                                    }
                                }
                                Err(error) if error.kind() == ErrorKind::WouldBlock => {
                                    // no more data, not an error
                                    tracing::trace!("[wg] would block!");
                                    break 'udp;
                                }
                                err => {
                                    err?;
                                }
                            }
                        }
                    }
                    TOKEN_WAKER => {
                        tracing::trace!("[wg] woke up!");
                        for mut pkt in rx.drain() {
                            self.nat.insert(&pkt);
                            pkt.masquerade(self.ipv4);
                            tracing::trace!(src = ?pkt.src(), dst = ?pkt.dest(), "[wg] encapsulating packet");
                            let action = self.tun.encapsulate(pkt.as_bytes(), &mut wg_buf);
                            self.handle_tun_result(action, &router, &sock)?;
                        }
                    }
                    TOKEN_TIMER => {
                        tracing::trace!("[wg] updating timers");
                        timer.wait()?;
                        let action = self.tun.update_timers(&mut wg_buf);
                        self.handle_tun_result(action, &router, &sock)?;
                    }
                    Token(token) => tracing::warn!(?token, "[wg] unhandled mio token"),
                }
            }
        }

        tracing::debug!("[wg] wan died");

        Ok(())
    }
}

impl WanHandle for WgHandle {
    fn write(&self, pkt: Ipv4Packet) -> Result<(), NetworkError> {
        self.tx.send(pkt)?;
        self.waker.wake()?;
        Ok(())
    }
}
