//! A wireguard upstream provider to encrypt all traffic

use std::{
    collections::HashMap,
    fmt::Debug,
    io::ErrorKind,
    net::{Ipv4Addr, SocketAddr},
    os::fd::{AsFd, AsRawFd},
    thread::JoinHandle,
};

use anyhow::{anyhow, Context, Result};
use base64::Engine;
use boringtun::{
    noise::{errors::WireGuardError, Tunn, TunnResult},
    x25519::{PublicKey, StaticSecret},
};
use mio::{net::UdpSocket, unix::SourceFd, Events, Interest, Poll, Token};
use nix::sys::{
    signal::{SigSet, Signal},
    signalfd::{SfdFlags, SignalFd},
    time::TimeSpec,
    timerfd::{ClockId, Expiration, TimerFd, TimerFlags, TimerSetTimeFlags},
};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use shadesmar_core::{
    ipv4::{ChecksumFlags, Ipv4Packet, Ipv4PacketMut, Ipv4PacketOwned, MutableIpv4Packet},
    nat::NatTable,
    plugins::{WanCallback, WanPluginConfig},
    types::{
        buffers::{PacketBuffer, PacketBufferPool},
        Ipv4Network,
    },
};
use uuid::Uuid;

const TOKEN_ROUTER: Token = Token(0);
const TOKEN_UDP: Token = Token(1);
const TOKEN_TIMER: Token = Token(2);
const TOKEN_SFD: Token = Token(3);

const WG_BUF_SZ: usize = 1600;

pub enum WgMessage {
    Quit,
    Packet(PacketBuffer),
}

pub struct WgHandle {
    channel: flume::Sender<WgMessage>,
    waker: mio::Waker,
    thread: JoinHandle<()>,
}

pub type PacketCache = HashMap<u16, Ipv4PacketOwned>;

#[derive(Clone, Deserialize, Serialize)]
pub struct WgConfig {
    pub key: String,
    pub peer: String,
    pub endpoint: SocketAddr,
    pub ipv4: Ipv4Network,
}

pub struct WgDevice {
    /// Human-friendly name of this wan device
    id: Uuid,

    /// Private / Secret Key for WireGuard tunnel
    key: StaticSecret,

    /// Public key of WireGuard peer endpoint
    peer: PublicKey,

    /// Endpoint of peer (ipv4/6 and port combo)
    endpoint: SocketAddr,

    /// IPv4 network / address assigned to the tunnel
    ipv4: Ipv4Network,
}

pub struct WgTunnel {
    /// Unique ID of the WAN device
    wan_id: Uuid,

    /// Actual WireGuard tunnel
    tun: Tunn,

    /// (IP:Port) combo of distant end
    endpoint: SocketAddr,

    /// non-blocking i/o poller (mio)
    poll: Poll,

    /// Ipv4 address to apply to this tunnel (for NAT / masquerade)
    ipv4: Ipv4Addr,

    /// Network Address Translate table to support masquerades
    nat: RwLock<NatTable>,

    /// Sends packets back to router
    callback: WanCallback,

    /// UDP socket to send/recv encapsulated
    udp: UdpSocket,
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
    pub fn new(cfg: WanPluginConfig<WgConfig>) -> Result<Self> {
        use base64::prelude::BASE64_STANDARD;

        let mut key = [0u8; 32];
        let mut peer = [0u8; 32];
        BASE64_STANDARD.decode_slice(&cfg.device.key, &mut key)?;
        BASE64_STANDARD.decode_slice(&cfg.device.peer, &mut peer)?;

        let key = StaticSecret::from(key);
        let peer = PublicKey::from(peer);

        Ok(Self {
            id: cfg.id,
            key,
            peer,
            endpoint: cfg.device.endpoint,
            ipv4: cfg.device.ipv4,
        })
    }

    /// Spawns a new thread to run this device, returining an (opaque?) handle to the device info block
    pub fn run(&self, callback: WanCallback) -> Result<WgHandle> {
        let poll = Poll::new()?;
        let (tx, rx) = flume::unbounded();
        let waker = mio::Waker::new(poll.registry(), TOKEN_ROUTER)?;

        let tun = WgTunnel::new(
            self.id,
            self.ipv4.ip(),
            self.key.clone(),
            self.peer,
            self.endpoint,
            poll,
            callback,
        )?;

        let thread = std::thread::Builder::new()
            .name(String::from("wan-wireguard"))
            .spawn(move || {
                if let Err(error) = tun.run(rx) {
                    tracing::error!("unable to run wireguard wan: {error:?}");
                }
            })?;

        Ok(WgHandle {
            channel: tx,
            waker,
            thread,
        })
    }
}

impl WgTunnel {
    /// Creates a new WireGuard tunnel
    ///
    /// ### Arguments
    /// * `wan_id` - Unique ID of WAN device
    /// * `ipv4` - Private IPv4 address of this WireGuard device
    /// * `key` - Secret / private key for WireGuard tunnel
    /// * `peer` - Public key of WireGuard endpoint
    /// * `endpoint` - Socket address (IP:Port) of WireGuard endpoint
    pub fn new(
        wan_id: Uuid,
        ipv4: Ipv4Addr,
        key: StaticSecret,
        peer: PublicKey,
        endpoint: SocketAddr,
        poll: Poll,
        callback: WanCallback,
    ) -> Result<Self> {
        let tun = Tunn::new(key, peer, None, None, 1, None).map_err(|e| anyhow!(e))?;
        let nat = RwLock::new(NatTable::new());

        let udp = std::net::UdpSocket::bind("0.0.0.0:0")
            .context("unable to bind wireguard udp socket")?;

        udp.set_nonblocking(true)
            .context("unable to set wireguard socket as non-blocking")?;

        let udp = UdpSocket::from_std(udp);

        Ok(Self {
            wan_id,
            tun,
            endpoint,
            poll,
            ipv4,
            nat,
            callback,
            udp,
        })
    }

    /// Runs the WireGuard tunnel
    ///
    /// Running the tunnel will listen for inbound traffic, decapsulate/decypt, and forward to
    /// the router for processing.  
    pub fn run(mut self, router_rx: flume::Receiver<WgMessage>) -> Result<()> {
        tracing::info_span!("running wireguard", wan_id = %self.wan_id);

        // create a timerfd to use with mio that expires every 500 milliseconds
        let timer = TimerFd::new(ClockId::CLOCK_MONOTONIC, TimerFlags::TFD_NONBLOCK)
            .context("unable to create timerfd")?;

        timer
            .set(
                Expiration::Interval(TimeSpec::new(0, 500000000)),
                TimerSetTimeFlags::empty(),
            )
            .context("unable to set timerfd interval to 500ms")?;

        let mut sigset = SigSet::empty();
        sigset.add(Signal::SIGTERM);
        sigset
            .thread_block()
            .context("unable to block SIGTERM on wireguard thread")?;

        let sfd = SignalFd::with_flags(&sigset, SfdFlags::SFD_NONBLOCK)
            .context("unable to create signalfd from sigset")?;

        self.poll
            .registry()
            .register(&mut self.udp, TOKEN_UDP, Interest::READABLE)?;

        self.poll.registry().register(
            &mut SourceFd(&timer.as_fd().as_raw_fd()),
            TOKEN_TIMER,
            Interest::READABLE,
        )?;

        self.poll.registry().register(
            &mut SourceFd(&sfd.as_raw_fd()),
            TOKEN_SFD,
            Interest::READABLE,
        )?;

        let mut cache = HashMap::new();

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
        'event: while let Ok(_) = self.poll.poll(&mut events, None) {
            for event in &events {
                match event.token() {
                    TOKEN_UDP => {
                        'udp: loop {
                            match self.udp.recv_from(&mut udp_buf) {
                                Ok((sz, peer)) => {
                                    tracing::trace!("[wg] read {sz} bytes from {peer}");

                                    let mut sz = sz;
                                    'wg: loop {
                                        let action = self.tun.decapsulate(
                                            Some(peer.ip()),
                                            &udp_buf[..sz],
                                            &mut wg_buf,
                                        );

                                        if !self
                                            .handle_tun_result(action, &mut cache)
                                            .context("handle_tun_result failed (queued packets)")?
                                        {
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
                                Err(err) => {
                                    return Err(anyhow::Error::new(err)
                                        .context("unable to read from udp socket"));
                                }
                            }
                        }
                    }
                    TOKEN_ROUTER => {
                        // read packets from router
                        for msg in router_rx.drain() {
                            match msg {
                                WgMessage::Quit => break 'event,
                                WgMessage::Packet(buffer) => {
                                    match self.handle_router_recv(buffer, &mut cache) {
                                        Ok(_) => (),
                                        Err(error) => tracing::warn!(
                                            "unable to handle router message: {error:?}"
                                        ),
                                    }
                                }
                            }
                        }
                    }
                    TOKEN_TIMER => {
                        tracing::trace!("[wg] updating timers");
                        timer.wait()?;
                        let action = self.tun.update_timers(&mut wg_buf);
                        self.handle_tun_result(action, &mut cache)
                            .context("unable to handle tun result from timer")?;
                    }
                    TOKEN_SFD => match sfd.read_signal() {
                        Err(error) => tracing::warn!(%error, "unable to read signal"),
                        Ok(sig) => match sig {
                            None => tracing::debug!("no signal found but sfd was triggered"),
                            Some(sig) => match Signal::try_from(sig.ssi_signo as i32) {
                                Err(error) => {
                                    tracing::warn!(%error, "received unknown signal ({})", sig.ssi_signo)
                                }
                                Ok(sig) => match sig {
                                    Signal::SIGTERM => {
                                        tracing::info!("[wg] caught sigterm, exiting");
                                        break 'event;
                                    }
                                    _ => { /* ignore other signals */ }
                                },
                            },
                        },
                    },
                    Token(token) => tracing::warn!(?token, "[wg] unhandled mio token"),
                }
            }
        }

        tracing::info!("[wg] wan died");

        Ok(())
    }

    /// Encapsulates (encrypts) a packet to send over the wire to the WireGuard endpoint
    ///
    /// ### Arguments
    /// * `router` - Address of the unix router socket
    /// * `sock` - UDP socket over which to transmit encapsulated packet
    fn handle_router_recv(
        &mut self,
        mut buffer: PacketBuffer,
        cache: &mut PacketCache,
    ) -> Result<()> {
        let _span = tracing::info_span!("received packet from router", len = buffer.len());
        let mut udp_buf = PacketBufferPool::with_size(1600);

        let mut pkt = Ipv4PacketMut::new(&mut buffer)?;
        self.nat.write().insert(&pkt);
        pkt.masquerade(self.ipv4, ChecksumFlags::Full);

        let action = self.tun.encapsulate(pkt.as_bytes(), &mut udp_buf);
        self.handle_tun_result(action, cache)?;

        Ok(())
    }

    /// Process the outcome of an encapsulate/decapsulate action
    ///
    /// ### Arguments
    /// * `action` - Outcome of encapsulate/decapsulate/update_timers
    fn handle_tun_result(&mut self, action: TunnResult, cache: &mut PacketCache) -> Result<bool> {
        let mut to_network = false;

        match action {
            TunnResult::Err(error) => match error {
                WireGuardError::ConnectionExpired => (),
                error => tracing::error!(?error, "[wg] unable to handle action"),
            },
            TunnResult::Done => tracing::trace!("[wg] no action"),
            TunnResult::WriteToNetwork(pkt) => {
                tracing::trace!("[wg] write {} bytes to network", pkt.len());
                self.udp
                    .send_to(pkt, self.endpoint)
                    .context("unable to write to wireguard udp socket")?;
                to_network = true;
            }
            TunnResult::WriteToTunnelV4(pkt, _ip) => {
                let pkt = Ipv4PacketMut::new(pkt).context("unable to parse ipv4 packet")?;

                // rebuild fragmented packets
                match (pkt.has_fragments(), pkt.fragment_offset()) {
                    (false, 0) => self
                        .queue_to_router(pkt)
                        .context("unable to send to router")?,

                    (true, 0) => {
                        cache.insert(pkt.id(), pkt.to_owned());
                    }
                    (true, offset) => {
                        cache
                            .get_mut(&pkt.id())
                            .map(|fpkt| fpkt.add_fragment_data(offset, pkt.payload()));
                    }
                    (false, offset) => match cache.remove(&pkt.id()) {
                        Some(mut fpkt) => {
                            fpkt.add_fragment_data(offset, pkt.payload());
                            fpkt.clear_flags();
                            fpkt.clear_frag_offset();
                            self.queue_to_router(fpkt)
                                .context("unable to send to router")?;
                        }
                        None => {
                            return Err(anyhow!("missing frag packet data"))?;
                        }
                    },
                }
            }
            TunnResult::WriteToTunnelV6(pkt, ip) => {
                tracing::trace!(?ip, "[wg] write {} bytes to tunnel", pkt.len());
                //router.route_ipv6(pkt.to_vec());
            }
        }

        Ok(to_network)
    }

    /// Queues a decapsulated packet to be sent to the network's router
    ///
    /// ### Arguments
    /// * `pkt` - Mutable IPv4 packet received from WireGuard decapsulate function
    /// * `dst` - Unix (datagram) socket address of the router
    fn queue_to_router<P: MutableIpv4Packet + Debug>(&self, mut pkt: P) -> Result<()> {
        let _span =
            tracing::info_span!("queue to router", id = pkt.id(), src = %pkt.src()).entered();

        if let Some(orig) = self.nat.read().get(&pkt) {
            pkt.unmasquerade(orig, ChecksumFlags::Full);
        } else {
            tracing::warn!("no nat entry for packet: (pkt: {pkt:?})");
        }

        tracing::trace!("queue received packet for router: {pkt:?}");
        self.callback.exec(self.wan_id, pkt.as_bytes());

        Ok(())
    }
}

impl WgHandle {
    pub fn write(&self, data: &[u8]) {
        let buffer = PacketBufferPool::copy(data);
        self.channel.send(WgMessage::Packet(buffer)).ok();
        self.waker.wake().ok();
    }

    pub fn stop(self) -> Result<()> {
        self.channel.send(WgMessage::Quit).ok();
        self.waker.wake().ok();
        self.thread.join().ok();
        Ok(())
    }
}
