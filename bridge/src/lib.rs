mod config;
pub mod ctrl;
mod error;
mod net;

use std::{collections::HashMap, fmt::Display, os::fd::AsRawFd, path::PathBuf};

use ctrl::CtrlResponse;
use mio::{unix::SourceFd, Events, Interest, Poll, Token};
use net::router::RouterHandle;
use nix::{
    errno::Errno,
    sys::{
        signal::{SigSet, Signal},
        signalfd::{SfdFlags, SignalFd},
    },
    unistd::Pid,
};
use shadesmar_vhost::{DeviceOpts, VHostSocket};

pub use self::config::Config as BridgeConfig;

use crate::{
    config::WanConfig,
    ctrl::{CtrlRequest, CtrlServerStream, CtrlSocket},
    error::Error,
    net::{
        dhcp::DhcpServer,
        router::{
            handler::{IcmpHandler, UdpHandler},
            Router,
        },
        switch::VirtioSwitch,
        wan::{TunTap, UdpDevice, Wan, WgDevice},
    },
};

type TokenMap = HashMap<Token, CtrlServerStream>;

pub enum ControlAction {
    Stop,
    Continue,
    Closed,
}

#[derive(Default)]
pub struct BridgeBuilder {
    /// Path to pcap file, or None to disable pcap
    pcap: Option<PathBuf>,

    /// Path to base directory for bridge-related files
    base: Option<PathBuf>,
}

pub struct Bridge {
    name: String,
    vhost_socket_path: PathBuf,
    ctrl_socket_path: PathBuf,
    pcap: Option<PathBuf>,
    cfg: BridgeConfig,
}

impl BridgeBuilder {
    /// Configures bridge to log all traffic transiting the switch
    ///
    /// ### Arguments
    /// * `pcap` - Path to location to save pcap file, or None to disable
    pub fn pcap(mut self, pcap: Option<PathBuf>) -> Self {
        self.pcap = pcap;
        self
    }

    /// Sets the base path to use for storing bridge-related files
    ///
    /// ### Arguments
    /// * `base` - Base path (directory)
    pub fn base<P: Into<PathBuf>>(mut self, base: P) -> Self {
        self.base = Some(base.into());
        self
    }

    pub fn build<S: Into<String>>(self, name: S, cfg: BridgeConfig) -> Result<Bridge, Error> {
        let base_dir = match self.base {
            Some(base) => base,
            None => std::env::current_dir()?,
        };

        if !base_dir.exists() {
            std::fs::create_dir_all(&base_dir)?;
        }

        let vhost_socket_path = base_dir.join("vhost").with_extension("sock");
        let ctrl_socket_path = base_dir.join("ctrl").with_extension("sock");

        Ok(Bridge {
            name: name.into(),
            vhost_socket_path,
            ctrl_socket_path,
            pcap: self.pcap,
            cfg,
        })
    }
}

fn parse_wan(cfg: &WanConfig) -> Result<Option<Box<dyn Wan>>, Error> {
    match cfg {
        WanConfig::Tap(opts) => {
            let wan = TunTap::create_tap(&opts.device)?;
            Ok(Some(Box::new(wan)))
        }
        WanConfig::Udp(opts) => {
            let wan = UdpDevice::connect(opts.endpoint)?;
            Ok(Some(Box::new(wan)))
        }
        WanConfig::Wireguard(opts) => {
            let wan = WgDevice::create(opts)?;
            Ok(Some(Box::new(wan)))
        }
    }
}

impl Bridge {
    /// Returns a new `BridgeBuilder` with default settings
    pub fn builder() -> BridgeBuilder {
        BridgeBuilder::default()
    }

    /// Signals a running bridge to stop
    ///
    /// ### Arguments
    /// * `pid` - Process id of the running bridge
    /// * `force` - True to force process to stop (with SIGKILL), false to request stop (SIGTERM)
    pub fn stop(pid: u32, force: bool) -> Result<(), Error> {
        use nix::sys::signal::kill;

        let signal = match force {
            true => Signal::SIGKILL,
            false => Signal::SIGTERM,
        };

        let pid = Pid::from_raw(pid as i32);
        kill(pid, signal)?;

        for attempt in 0..3 {
            std::thread::sleep(std::time::Duration::from_secs(1));

            match kill(pid, None) {
                Ok(_) => {
                    tracing::debug!(%pid, attempt, "network still running after attempted stop");
                }
                Err(errno) => match errno {
                    Errno::ESRCH => {
                        // process not found...must be stopped
                        return Ok(());
                    }
                    errno => {
                        return Err(errno)?;
                    }
                },
            }
        }

        Err(Error::Other(
            "unable to stop network after 3 attempts".into(),
        ))
    }

    /// Starts the bridge, binding a new signalfd as required
    pub fn start(self) -> Result<(), Error> {
        let mut mask = SigSet::empty();
        mask.add(Signal::SIGTERM);
        mask.add(Signal::SIGINT);
        mask.thread_block()?;

        let sfd = SignalFd::with_flags(&mask, SfdFlags::SFD_NONBLOCK)?;

        self.run(sfd)?;

        Ok(())
    }

    pub fn run(mut self, sfd: SignalFd) -> Result<(), Error> {
        const TOKEN_VHOST: Token = Token(0);
        const TOKEN_SIGNAL: Token = Token(1);
        const TOKEN_CTRL: Token = Token(2);

        tracing::debug!(bridge = %self, "bridge starting");

        let mut vhost_socket = VHostSocket::new(&self.vhost_socket_path)?;
        let mut ctrl_socket = CtrlSocket::bind(&self.ctrl_socket_path)?;

        let switch = VirtioSwitch::new(self.pcap.take())?;

        // spawn the default route / upstream
        let wan = parse_wan(&self.cfg.wan)?;

        let mut udp_handler = UdpHandler::default();
        udp_handler
            .register_port_handler(DhcpServer::new(self.cfg.router.ipv4, &self.cfg.router.dhcp));

        // spawn thread to receive messages/packets
        let router = Router::builder()
            .wan(wan)
            .register_l4_proto_handler(IcmpHandler::default())
            .register_l4_proto_handler(udp_handler)
            .spawn(self.cfg.router.ipv4, switch.clone())?;

        let mut poller = Poll::new()?;
        poller
            .registry()
            .register(&mut vhost_socket, TOKEN_VHOST, Interest::READABLE)?;

        poller.registry().register(
            &mut SourceFd(&sfd.as_raw_fd()),
            TOKEN_SIGNAL,
            Interest::READABLE,
        )?;

        poller
            .registry()
            .register(&mut ctrl_socket, TOKEN_CTRL, Interest::READABLE)?;

        let mut token_map = TokenMap::new();

        tracing::info!(bridge = %self, "bridge started");
        let mut events = Events::with_capacity(10);
        'poll: loop {
            poller.poll(&mut events, None)?;

            for event in &events {
                match event.token() {
                    TOKEN_VHOST => {
                        if let Err(error) =
                            vhost_socket.accept_and_spawn(DeviceOpts::default(), switch.clone())
                        {
                            tracing::error!(bridge = %self, %error, "unable to accept vhost-user connection");
                        }
                    }
                    TOKEN_SIGNAL => match sfd.read_signal() {
                        Ok(None) => { /* no nothing, no signal read */ }
                        Ok(Some(sig)) => match Signal::try_from(sig.ssi_signo as i32) {
                            Err(error) => {
                                tracing::warn!(bridge = %self, %error, "unknown signal number")
                            }
                            Ok(signal) => match signal {
                                Signal::SIGINT | Signal::SIGTERM => break 'poll,
                                signal => {
                                    tracing::debug!(bridge = %self, %signal, "unhandled masked signal")
                                }
                            },
                        },
                        Err(error) => {
                            tracing::error!(bridge = %self, %error, "unable to read signal");
                        }
                    },
                    TOKEN_CTRL => match ctrl_socket.accept() {
                        Ok(mut strm) => {
                            let token = strm.token();
                            match poller
                                .registry()
                                .register(&mut strm, token, Interest::READABLE)
                            {
                                Ok(_) => {
                                    token_map.insert(token, strm);
                                }
                                Err(error) => {
                                    tracing ::warn!(bridge = %self, %error, "unable to register ctrl stream with mio")
                                }
                            }
                        }
                        Err(error) => {
                            tracing::warn!(bridge = %self, %error, "unable to accept control socket connection")
                        }
                    },
                    token => {
                        let mut closed = false;
                        match token_map.get_mut(&token) {
                            Some(strm) => match Self::handle_ctrl(strm, &switch, &router) {
                                Ok(action) => match action {
                                    ControlAction::Stop => break 'poll,
                                    ControlAction::Closed => {
                                        closed = true;
                                        poller.registry().deregister(strm).ok();
                                    }
                                    ControlAction::Continue => (),
                                },
                                Err(error) => {
                                    tracing::warn!(bridge = %self, %error, "unable to process control message")
                                }
                            },
                            None => {
                                tracing::debug!(bridge = %self, token = token.0, "unregistered mio token")
                            }
                        }

                        if closed {
                            token_map.remove(&token);
                            tracing::debug!(bridge = %self, "client closed control stream");
                        }
                    }
                }
            }
        }

        std::fs::remove_file(&self.vhost_socket_path).ok();
        std::fs::remove_file(&self.ctrl_socket_path).ok();
        tracing::info!(bridge = %self, "bridge stopped");

        Ok(())
    }

    /// Handles a control message
    fn handle_ctrl(
        strm: &mut CtrlServerStream,
        switch: &VirtioSwitch,
        router: &RouterHandle,
    ) -> Result<ControlAction, Error> {
        let msgs = match strm.recv()? {
            Some(msgs) => msgs,
            None => return Ok(ControlAction::Closed),
        };

        for msg in msgs {
            tracing::debug!(message = ?msg, "received control message");
            match msg {
                CtrlRequest::Stop => return Ok(ControlAction::Stop),
                CtrlRequest::ConnectTap(socket) => switch.register_tap(socket),
                CtrlRequest::Status => {
                    let switch_status = switch.get_status()?;
                    let router_status = router.status();

                    strm.send(CtrlResponse::Status(switch_status, router_status))?;
                }
            }
        }

        Ok(ControlAction::Continue)
    }
}

impl Display for Bridge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name)
    }
}
