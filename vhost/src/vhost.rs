//! File Descriptor Map

use std::{io, path::PathBuf};

use mio::{event::Source, net::UnixListener, Events, Interest, Poll, Token};
use shadesmar_net::Switch;

use crate::{
    device::{DeviceOpts, VirtioDevice},
    error::AppResult,
};

/// An `FdMap` is a map of unique tokens to file descriptors
pub struct VHostSocket {
    socket: UnixListener,
}

impl VHostSocket {
    /// Creates a new, empty FdMap
    pub fn new<P: Into<PathBuf>>(path: P) -> io::Result<Self> {
        let socket_path = path.into();
        if socket_path.exists() {
            std::fs::remove_file(&socket_path)?;
        }

        let socket = UnixListener::bind(&socket_path)?;

        Ok(Self { socket })
    }

    pub fn accept_and_spawn<S: Switch + 'static>(
        &mut self,
        device_opts: DeviceOpts,
        switch: S,
    ) -> AppResult<()> {
        let (strm, _peer) = self.socket.accept()?;
        tracing::info!("[vhost] accepted unix socket connection, spawning device");

        let dev = VirtioDevice::new(switch, device_opts)?;
        dev.spawn(strm)?;
        Ok(())
    }

    pub fn run<S: Switch + 'static>(
        &mut self,
        device_opts: DeviceOpts,
        switch: S,
    ) -> io::Result<()> {
        let listener_token = Token(0);

        let mut poll = Poll::new()?;

        poll.registry()
            .register(self, listener_token, Interest::READABLE)?;

        let mut events = Events::with_capacity(10);
        loop {
            if let Err(error) = poll.poll(&mut events, None) {
                tracing::error!(?error, "unable to poll");
                break;
            }

            for event in &events {
                let token = event.token();
                match token {
                    token if token == listener_token => {
                        if let Err(error) =
                            self.accept_and_spawn(device_opts.clone(), switch.clone())
                        {
                            tracing::error!(?error, "unable to spawn virtio device");
                        }
                    }
                    Token(token) => tracing::trace!(?token, "[poller] unknown mio token"),
                }
            }
        }
        Ok(())
    }
}

impl Source for VHostSocket {
    fn register(
        &mut self,
        registry: &mio::Registry,
        token: Token,
        interests: Interest,
    ) -> io::Result<()> {
        self.socket.register(registry, token, interests)
    }

    fn reregister(
        &mut self,
        registry: &mio::Registry,
        token: Token,
        interests: Interest,
    ) -> io::Result<()> {
        self.socket.reregister(registry, token, interests)
    }

    fn deregister(&mut self, registry: &mio::Registry) -> io::Result<()> {
        self.socket.deregister(registry)
    }
}
