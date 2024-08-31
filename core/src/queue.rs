//! A simple Unix Datagram Send Queue

use std::{
    collections::VecDeque,
    io::ErrorKind,
    os::unix::io::AsRawFd,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread::JoinHandle,
};

use mio::{net::UnixDatagram, unix::SourceFd, Interest, Registry, Token};
use nix::sys::socket::UnixAddr;
use parking_lot::{Condvar, Mutex, MutexGuard};

use crate::ipv4::Ipv4PacketOwned;

pub struct UnixSendQueue {
    queue: Mutex<VecDeque<(UnixAddr, Ipv4PacketOwned)>>,
    notify: Condvar,
    ready: AtomicBool,
    socket: UnixDatagram,
}

impl UnixSendQueue {
    pub fn new() -> std::io::Result<Arc<Self>> {
        let queue = Mutex::new(VecDeque::new());
        let notify = Condvar::new();
        let ready = AtomicBool::new(false);
        let socket = UnixDatagram::unbound()?;

        Ok(Arc::new(Self {
            queue,
            notify,
            ready,
            socket,
        }))
    }

    pub fn register(&self, registry: &Registry, token: Token) -> std::io::Result<()> {
        registry.register(
            &mut SourceFd(&self.socket.as_raw_fd()),
            token,
            Interest::WRITABLE,
        )?;
        Ok(())
    }

    pub fn enqueue(&self, dst: UnixAddr, pkt: Ipv4PacketOwned) {
        self.queue.lock().push_back((dst, pkt));
        self.notify.notify_one();
    }

    pub fn set_ready(&self) {
        self.ready.store(true, Ordering::Release);
        self.notify.notify_one();
    }

    pub fn set_unready(&self) {
        self.ready.store(false, Ordering::Release);
    }

    pub fn is_ready(&self) -> bool {
        self.ready.load(Ordering::Acquire)
    }

    pub fn wait(&self) -> MutexGuard<VecDeque<(UnixAddr, Ipv4PacketOwned)>> {
        let mut queue = self.queue.lock();
        self.notify.wait(&mut queue);
        queue
    }

    pub fn spawn<F>(self: Arc<Self>, name: String, send_fn: F) -> std::io::Result<JoinHandle<()>>
    where
        F: Fn(i32, UnixAddr, &Ipv4PacketOwned) -> std::io::Result<()> + Send + Sync + 'static,
    {
        let queue = Arc::clone(&self);

        let fd = self.socket.as_raw_fd();
        let thread = std::thread::Builder::new()
            .name(name.clone())
            .spawn(move || 'cond: loop {
                let _span = tracing::info_span!("unix send queue loop", %name).entered();

                let mut sq = queue.wait();
                if !queue.is_ready() {
                    tracing::debug!(
                        "socket is not ready, waiting again (queue size = {})",
                        sq.len()
                    );
                    continue 'cond;
                }

                'send: loop {
                    match sq.pop_front() {
                        Some((dst, pkt)) => {
                            match send_fn(fd, dst, &pkt) {
                                Ok(_) => { /* do nothing */ }
                                Err(error) if error.kind() == ErrorKind::WouldBlock => {
                                    tracing::warn!("re-queuing packet (EAGAIN)");
                                    queue.set_unready();
                                    sq.push_front((dst, pkt));
                                    break 'send;
                                }
                                Err(error) => {
                                    tracing::warn!("unable to send packet to router: {error}");
                                }
                            }
                        }
                        None => break 'send,
                    }
                }
            })?;

        Ok(thread)
    }
}
