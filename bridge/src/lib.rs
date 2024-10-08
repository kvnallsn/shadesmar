pub mod config;
pub mod ctrl;
mod error;
pub mod net;

use std::{
    collections::HashMap,
    fmt::Display,
    os::fd::AsRawFd,
    path::PathBuf,
    sync::{Arc, OnceLock},
};

use ctrl::CtrlResponse;
use mio::{unix::SourceFd, Events, Interest, Poll, Token};
use net::{
    pcap::PcapLogger,
    router::{handle::RouterHandle, RouterStatus},
    switch::SwitchStatus,
};
use nix::{
    errno::Errno,
    sys::{
        signal::{SigSet, Signal},
        signalfd::{SfdFlags, SignalFd},
    },
    unistd::Pid,
};
use serde::{Deserialize, Serialize};
use shadesmar_core::{
    plugins::{PluginError, WanPlugins},
    types::buffers::PacketBufferPool,
};
use shadesmar_vhost::{DeviceOpts, VHostSocket};

pub use self::config::Config as BridgeConfig;

static WAN_PLUGINS: OnceLock<WanPlugins> = OnceLock::new();

pub fn get_wan_plugins() -> Result<&'static WanPlugins, PluginError> {
    WAN_PLUGINS
        .get()
        .ok_or_else(|| PluginError::new("plugins not loaded"))
}

use crate::{
    ctrl::{CtrlRequest, CtrlServerStream, CtrlSocket},
    error::Error,
    net::{
        dhcp::DhcpServer,
        router::{
            handler::{IcmpHandler, UdpHandler},
            Router,
        },
        switch::VirtioSwitch,
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
    /// Path to base directory for bridge-related files
    run_dir: Option<PathBuf>,

    /// Path to the data directory for network-related files
    data_dir: Option<PathBuf>,
}

pub struct Bridge {
    name: String,
    vhost_socket_path: PathBuf,
    ctrl_socket_path: PathBuf,
    cfg: BridgeConfig,
    data_dir: PathBuf,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct BridgeStatus {
    /// Status of the internal switch
    pub switch: SwitchStatus,

    /// Status of the router/wan
    pub router: RouterStatus,
}

impl BridgeBuilder {
    /// Sets the runtime directory to store ephemeral files (i.e., sockets) generated
    /// by this network/bridge
    ///
    /// ### Arguments
    /// * `base` - Base path (directory)
    pub fn run_dir<P: Into<PathBuf>>(mut self, base: P) -> Self {
        self.run_dir = Some(base.into());
        self
    }

    /// Sets the data directory to store persistent files (i.e., pcap) generated
    /// by this network/bridge
    ///
    /// ### Arguments
    /// * `dir` - Path to the data directory
    pub fn data_dir<P: Into<PathBuf>>(mut self, dir: P) -> Self {
        self.data_dir = Some(dir.into());
        self
    }

    pub fn build<S: Into<String>>(self, name: S, cfg: BridgeConfig) -> Result<Bridge, Error> {
        let name = name.into();
        let span = tracing::info_span!("create network", name = name);
        let _enter = span.enter();

        tracing::debug!("initializing packet buffers");
        PacketBufferPool::init(1600, 1024);

        tracing::info!("configuring {name} network");

        let run_dir = match self.run_dir {
            Some(base) => base,
            None => {
                let dir = std::env::temp_dir();
                tracing::info!("runtime directory not set, using {}", dir.display());
                dir
            }
        };

        tracing::debug!("network run directoy: {}", run_dir.display());

        if !run_dir.exists() {
            tracing::debug!("run directory does not exist, attempting to create");
            std::fs::create_dir_all(&run_dir)?;
        }

        let data_dir = match self.data_dir {
            Some(base) => base,
            None => {
                let dir = std::env::current_dir()?;
                tracing::debug!("data directory not set, using {}", dir.display());
                dir
            }
        };

        tracing::debug!("network data directoy: {}", data_dir.display());
        if !data_dir.exists() {
            tracing::info!("data directory does not exist, attempting to create");
            std::fs::create_dir_all(&data_dir)?;
        }

        let vhost_socket_path = run_dir.join("vhost").with_extension("sock");
        let ctrl_socket_path = run_dir.join("ctrl").with_extension("sock");

        Ok(Bridge {
            name: name.into(),
            vhost_socket_path,
            ctrl_socket_path,
            cfg,
            data_dir,
        })
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

        Err(Error::new("unable to stop network after 3 attempts"))
    }

    /// Helper function to run the bridge, binding a new signalfd to intercept SIGTERM and SIGINT
    ///
    /// After the signalfd is created, calls run()
    ///
    /// ### Arguments
    /// * `plugins` - Loaded WAN plugins
    pub fn start(self, plugins: WanPlugins) -> Result<(), Error> {
        let mut mask = SigSet::empty();
        mask.add(Signal::SIGTERM);
        mask.add(Signal::SIGINT);
        mask.thread_block()?;

        let sfd = SignalFd::with_flags(&mask, SfdFlags::SFD_NONBLOCK)?;

        self.run(sfd, plugins)?;

        Ok(())
    }

    /// Runs the bridge using the provided signalfd to watch for pre-configured signals
    ///
    /// ### Arguments
    /// * `sfd` - Signal File Descriptor
    /// * `plugins` - Loaded WAN plugins
    pub fn run(self, sfd: SignalFd, plugins: WanPlugins) -> Result<(), Error> {
        const TOKEN_VHOST: Token = Token(0);
        const TOKEN_SIGNAL: Token = Token(1);
        const TOKEN_CTRL: Token = Token(2);

        tracing::debug!(bridge = %self, "bridge starting");
        WAN_PLUGINS
            .set(plugins)
            .map_err(|_| Error::new("unable to set plugin global"))?;

        let mut vhost_socket = VHostSocket::new(&self.vhost_socket_path)?;
        let mut ctrl_socket = CtrlSocket::bind(&self.ctrl_socket_path)?;

        let pcap_logger = PcapLogger::new(&self.cfg, &self.data_dir)?;
        let switch = VirtioSwitch::new(Arc::clone(&pcap_logger))?;

        // spawn the default route / upstream
        //let wan = parse_wan(&self.cfg.wan)?;

        let udp_handler = UdpHandler::default();
        udp_handler
            .register_port_handler(DhcpServer::new(self.cfg.router.ipv4, &self.cfg.router.dhcp));

        // spawn thread to receive messages/packets
        tracing::debug!(bridge = %self, "spawning router");
        let mut router = Router::builder()
            .register_wans(&self.cfg.wan)
            .routing_table(&self.cfg.router.table)
            .register_l4_proto_handler(IcmpHandler::default())
            .register_l4_proto_handler(udp_handler)
            .spawn(
                self.cfg.router.ipv4,
                switch.clone(),
                Arc::clone(&pcap_logger),
            )?;

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
                            Some(strm) => match Self::handle_ctrl(strm, &switch, &mut router) {
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

        router.stop()?;
        pcap_logger.stop();
        tracing::info!(bridge = %self, "bridge stopped");
        tracing::debug!(
            "final packetbuffer pool count: {}",
            PacketBufferPool::available()
        );

        Ok(())
    }

    /// Handles a control message
    fn handle_ctrl(
        strm: &mut CtrlServerStream,
        switch: &VirtioSwitch,
        router: &mut RouterHandle,
    ) -> Result<ControlAction, Error> {
        let msgs = match strm.recv()? {
            Some(msgs) => msgs,
            None => return Ok(ControlAction::Closed),
        };

        for msg in msgs {
            tracing::trace!(message = ?msg, "received control message");
            match msg {
                CtrlRequest::Stop => {
                    strm.send(CtrlResponse::ok())?;
                    tracing::info!("got control stop message, terminating");
                    return Ok(ControlAction::Stop);
                }
                CtrlRequest::ConnectTap(socket) => {
                    switch.register_tap(socket);
                    strm.send(CtrlResponse::ok())?;
                }
                CtrlRequest::Status => {
                    let switch_status = switch.get_status()?;
                    let router_status = router.status();

                    let status = BridgeStatus {
                        switch: switch_status,
                        router: router_status,
                    };

                    strm.send(CtrlResponse::Success(&status))?;
                }
                CtrlRequest::Ping => {
                    strm.send(CtrlResponse::Success(()))?;
                }
                CtrlRequest::AddRoute(route, wan) => {
                    let resp = match router.add_route(route, wan) {
                        Ok(_) => CtrlResponse::ok(),
                        Err(error) => CtrlResponse::fail(error.to_string()),
                    };

                    strm.send(resp)?;
                }
                CtrlRequest::DelRoute(route) => {
                    let resp = match router.del_route(route) {
                        Ok(_) => CtrlResponse::ok(),
                        Err(error) => CtrlResponse::fail(error.to_string()),
                    };

                    strm.send(resp)?;
                }
                CtrlRequest::AddWan(cfg) => {
                    let resp = match router.add_wan(cfg) {
                        Ok(_) => CtrlResponse::ok(),
                        Err(error) => CtrlResponse::fail(error.to_string()),
                    };

                    strm.send(resp)?;
                }
                CtrlRequest::RemoveWan(name, cleanup) => {
                    let resp = match router.del_wan(name, cleanup) {
                        Ok(_) => CtrlResponse::ok(),
                        Err(error) => CtrlResponse::fail(error.to_string()),
                    };

                    strm.send(resp)?;
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
