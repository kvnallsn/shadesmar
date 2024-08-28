use std::{
    ffi::{c_char, c_void},
    io::ErrorKind,
    os::{fd::AsRawFd, unix::thread::JoinHandleExt},
    path::Path,
    thread::JoinHandle,
};

use mio::{event::Source, net::UnixDatagram, unix::SourceFd, Events, Interest, Poll, Token};
use nix::sys::{
    signal::{SigSet, Signal},
    signalfd::{SfdFlags, SignalFd},
};
use serde::{Deserialize, Serialize};
use shadesmar_core::plugins::{WanPluginConfig, WanPluginStartOpts};

#[derive(Debug, Deserialize, Serialize)]
pub struct BlackholeConfig {
    #[allow(dead_code)]
    #[serde(rename = "type")]
    ty: String,
}

pub struct BlackholeDevice {
    _marker: u32,
}

pub struct BlackholeInstance {
    poller: Poll,
    sock: UnixDatagram,
    sigfd: SignalFd,
    sigmask: SigSet,
}

pub struct BlackholeHandle(JoinHandle<()>);

shadesmar_core::define_wan_plugin!(
    "blackhole",
    BlackholeConfig,
    BlackholeDevice,
    BlackholeHandle
);

impl BlackholeDevice {
    pub fn new(_cfg: WanPluginConfig<BlackholeConfig>) -> anyhow::Result<Self> {
        Ok(BlackholeDevice { _marker: 67331 })
    }

    pub fn run(&self, opts: WanPluginStartOpts) -> anyhow::Result<BlackholeHandle> {
        let instance = BlackholeInstance::new(&opts.socket)?;

        let handle = std::thread::Builder::new()
            .name(String::from("wan-blackhole"))
            .spawn(move || match instance.run() {
                Ok(_) => (),
                Err(_error) => (),
            })?;

        Ok(BlackholeHandle(handle))
    }
}

impl BlackholeInstance {
    const TOKEN_UNIX_SOCK: Token = Token(0);
    const TOKEN_SIGNAL_FD: Token = Token(1);

    pub fn new(path: &Path) -> anyhow::Result<Self> {
        let poller = Poll::new()?;

        let mut sock = UnixDatagram::bind(path)?;
        sock.register(poller.registry(), Self::TOKEN_UNIX_SOCK, Interest::READABLE)?;

        let mut sigmask = SigSet::empty();
        sigmask.add(Signal::SIGTERM);

        let sigfd = SignalFd::with_flags(&sigmask, SfdFlags::SFD_NONBLOCK)?;
        poller.registry().register(
            &mut SourceFd(&sigfd.as_raw_fd()),
            Self::TOKEN_SIGNAL_FD,
            Interest::READABLE,
        )?;

        Ok(Self {
            poller,
            sock,
            sigfd,
            sigmask,
        })
    }

    pub fn run(mut self) -> anyhow::Result<()> {
        self.sigmask.thread_block()?;

        let mut buf = [0u8; 1600];
        let mut events = Events::with_capacity(10);
        'poll: loop {
            self.poller.poll(&mut events, None)?;

            for event in &events {
                match event.token() {
                    Self::TOKEN_SIGNAL_FD => match self.read_signal()? {
                        true => break 'poll,
                        false => (),
                    },
                    Self::TOKEN_UNIX_SOCK => self.read_unix_sock(&mut buf)?,
                    _ => (),
                }
            }
        }

        Ok(())
    }

    fn read_unix_sock(&self, buf: &mut [u8]) -> anyhow::Result<()> {
        'aio: loop {
            match self.sock.recv_from(buf) {
                Ok((sz, _peer)) => {
                    // blackhole, do nothing
                    tracing::debug!("[blackhole] dropping {sz} byte packet");
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => {
                    // no more data avaiable,
                    break 'aio;
                }
                Err(error) => Err(error)?,
            }
        }

        Ok(())
    }

    fn read_signal(&self) -> anyhow::Result<bool> {
        match self.sigfd.read_signal()? {
            None => (),
            Some(sig) => match Signal::try_from(sig.ssi_signo as i32)? {
                Signal::SIGTERM => return Ok(true),
                _ => (),
            },
        }

        Ok(false)
    }
}

impl BlackholeHandle {
    pub fn stop(self) -> anyhow::Result<()> {
        // send SIGTERM to thread to indicate it's time to quit
        let tid = self.0.as_pthread_t();
        nix::sys::pthread::pthread_kill(tid, Signal::SIGTERM)?;

        Ok(())
    }
}
