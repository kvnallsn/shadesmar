//! OS-specific configuration items

use std::os::fd::AsRawFd;

use mio::{
    event::{Event, Source},
    unix::SourceFd,
    Events, Interest, Poll, Token,
};
use nix::sys::{
    signal::{SigSet, Signal},
    signalfd::{SfdFlags, SignalFd},
};

pub struct Poller {
    poller: Poll,
    sfd: SignalFd,
    events: Events,
    next_token: usize,
}

/// Masks signals on the current thread and returns a `signalfd`
/// that can be polled/waited on (aka create with the `SFD_NONBLOCK` flag)
pub fn make_signalfd(signals: &[Signal]) -> anyhow::Result<SignalFd> {
    let mut mask = SigSet::empty();
    for signal in signals {
        mask.add(*signal);
    }
    mask.thread_block()?;

    let flags = SfdFlags::SFD_NONBLOCK;
    let sfd = SignalFd::with_flags(&mask, flags)?;
    Ok(sfd)
}

impl Poller {
    pub fn new(max_events: usize, signals: &[Signal]) -> anyhow::Result<Self> {
        let poller = Poll::new()?;
        let sfd = make_signalfd(signals)?;
        let events = Events::with_capacity(max_events);
        let next_token = 0;

        let mut poller = Poller {
            poller,
            sfd,
            events,
            next_token,
        };

        poller.register_read(&mut SourceFd(&poller.sfd.as_raw_fd()))?;
        Ok(poller)
    }

    pub fn register_read<S: Source>(&mut self, source: &mut S) -> anyhow::Result<Token> {
        let token = Token(self.next_token);
        self.next_token += 1;

        self.poller
            .registry()
            .register(source, token, Interest::READABLE)?;

        Ok(token)
    }

    pub fn poll<F1, F2>(
        &mut self,
        mut event_handler: F1,
        mut signal_handler: F2,
    ) -> anyhow::Result<()>
    where
        F1: FnMut(&Event) -> anyhow::Result<()>,
        F2: FnMut(Signal) -> anyhow::Result<()>,
    {
        self.poller.poll(&mut self.events, None)?;

        for event in &self.events {
            if event.token() == Token(0) {
                //  handle signal
                match self.sfd.read_signal() {
                    Err(error) => tracing::warn!(%error, "unable to read signal"),
                    Ok(sig) => match sig {
                        None => tracing::debug!("no signal read but signalfd was triggered"),
                        Some(sig) => match Signal::try_from(sig.ssi_signo as i32) {
                            Err(error) => tracing::warn!(?sig, %error, "unknown signal"),
                            Ok(signal) => signal_handler(signal)?,
                        },
                    },
                }
            } else {
                event_handler(event)?;
            }
        }
        Ok(())
    }
}
