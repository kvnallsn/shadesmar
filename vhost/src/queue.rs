//! VirtQueue implementation

use std::{
    fs::File,
    io::{Read, Write},
    ops::Deref,
    os::fd::{FromRawFd, RawFd},
};

use anyhow::Context;
use nix::unistd;
use shadesmar_core::{switch::Switch, types::buffers::PacketBufferPool};
use virtio_queue::{Queue, QueueOwnedT, QueueT};
use vm_memory::{GuestAddressSpace, GuestMemoryAtomic, GuestMemoryMmap};

use crate::{
    error::{AppResult, Error, MemoryError},
    types::{DeviceRxQueue, VirtioNetHeader},
};

pub struct VirtQueue<S> {
    enabled: bool,
    queue: Queue,
    mem: Option<GuestMemoryAtomic<GuestMemoryMmap<()>>>,
    desc_table: u64,
    avail_ring: u64,
    used_ring: u64,
    err_fd: Option<RawFd>,
    call_fd: Option<File>,
    kick_fd: Option<RawFd>,
    switch: S,
    pending: DeviceRxQueue,
}

impl<S: Switch> VirtQueue<S> {
    /// Creates a new VirtQueue with a the specified max virtqueue size
    ///
    /// ### Arguments
    /// * `max_size` - Maximum size of the virtqueue
    pub fn new(
        max_size: u16,
        switch: S,
        rx_queue: DeviceRxQueue,
    ) -> Result<Self, virtio_queue::Error> {
        Ok(Self {
            enabled: false,
            queue: Queue::new(max_size)?,
            mem: None,
            desc_table: 0,
            avail_ring: 0,
            used_ring: 0,
            err_fd: None,
            call_fd: None,
            kick_fd: None,
            switch,
            pending: rx_queue,
        })
    }

    /// Enable this virtqueue
    pub fn set_enabled(&mut self) {
        self.enabled = true;
    }

    /// Disable this virtqueue
    #[allow(dead_code)]
    pub fn set_disabled(&mut self) {
        self.enabled = false;
    }

    /// Set the size of the virtqueue
    ///
    /// ### Arguments
    /// * `size` - Size (in entries) of the queue
    pub fn set_queue_size(&mut self, size: u16) {
        self.queue.set_size(size);
    }

    /// Mark this virtqueue as not ready
    pub fn set_not_ready(&mut self) {
        self.queue.set_ready(false);
    }

    /// Set the addresses for the descriptor table, available ring, and used ring
    pub fn set_queue_addresses(&mut self, desc: u64, avail: u64, used: u64) {
        let high = ((desc >> 32) & 0xFFFF_FFFF) as u32;
        let low = (desc & 0xFFFF_FFFF) as u32;
        self.desc_table = desc;
        self.queue.set_desc_table_address(Some(low), Some(high));

        let high = ((avail >> 32) & 0xFFFF_FFFF) as u32;
        let low = (avail & 0xFFFF_FFFF) as u32;
        self.avail_ring = avail;
        self.queue.set_avail_ring_address(Some(low), Some(high));

        let high = ((used >> 32) & 0xFFFF_FFFF) as u32;
        let low = (used & 0xFFFF_FFFF) as u32;
        self.used_ring = used;
        self.queue.set_used_ring_address(Some(low), Some(high));
    }

    /// Sets the error file descriptor associated with this queue
    ///
    /// ### Arguments
    /// * `fd` - File Descriptor to set
    pub fn set_error_fd(&mut self, fd: RawFd) {
        self.err_fd = Some(fd);
    }

    /// Sets the call file descriptor associated with this queue
    ///
    /// ### Arguments
    /// * `fd` - File Descriptor to set
    pub fn set_call_fd(&mut self, fd: RawFd) {
        self.call_fd = Some(unsafe { File::from_raw_fd(fd) });
    }

    /// Sets the kick file descriptor associated with this queue
    ///
    /// ### Arguments
    /// * `fd` - File Descriptor to set
    pub fn set_kick_fd(&mut self, fd: RawFd) {
        self.kick_fd = Some(fd);
        self.queue.set_ready(true);
    }

    /// Sets the memory map associated with this vring
    ///
    /// ### Arguments
    /// * `mem` - Mapped memory in guest space
    pub fn set_memory(&mut self, mem: GuestMemoryAtomic<GuestMemoryMmap<()>>) {
        self.mem = Some(mem);
    }

    /// Sets the next available index for the vring
    ///
    /// ### Arguments
    /// * `idx` - Next index in the avail ring
    pub fn set_next_avail(&mut self, idx: u16) {
        self.queue.set_next_avail(idx);
    }

    /// Returns the next index in the avail ring
    pub fn get_next_avail(&self) -> u16 {
        self.queue.next_avail()
    }

    /// Clears the file descriptors set for this virtqueue and returns them
    ///
    /// ### Return Order
    /// 1. kick fd
    /// 2. call fd
    /// 3. error fd
    pub fn clear_fds(&mut self) -> (Option<RawFd>, Option<File>, Option<RawFd>) {
        (self.kick_fd.take(), self.call_fd.take(), self.err_fd.take())
    }

    /// Reads data from the driver and processes it
    ///
    /// ### Arguments
    /// * `pkt` - data from kick file descriptor
    /// * `switch_port` - Port device is connected to on the switch
    pub fn kick_tx(&mut self, pkt: &[u8], switch_port: usize) -> AppResult<()> {
        let enabled = crate::cast!(u64, pkt[0..8]);
        if enabled == 0 {
            tracing::warn!(fd = ?self.kick_fd, "virtqueue not enabled, ignore kick");
            return Err(Error::QueueDisabled);
        }

        let mem = match self.mem.as_ref().map(|m| m.memory()) {
            None => return Err(MemoryError::NoMappedMemory)?,
            Some(mem) => mem,
        };

        let chains = self.queue.iter(mem.deref())?.collect::<Vec<_>>();
        for (idx, chain) in chains.into_iter().enumerate() {
            let mut pkt = PacketBufferPool::get();
            let head_idx = chain.head_index();
            tracing::trace!("[queue] reading from descriptor chain: {}", head_idx);

            let mut reader = chain.reader(mem.deref())?;
            reader.read_to_end(&mut pkt)?;

            let hdr = VirtioNetHeader::extract(&mut pkt)?;
            let len = pkt.len();
            tracing::trace!(slot = %head_idx, %idx, "[kick-tx] read {} bytes (cap: {})", len, pkt.capacity());
            tracing::trace!(?idx, "[kick-tx] header: {hdr:02x?}");

            self.switch.process(switch_port, pkt).unwrap();

            self.queue.add_used(mem.deref(), head_idx, len as u32)?;
        }

        // notify client
        self.call(&[0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])?;

        Ok(())
    }

    /// Writes data into the receive queues
    pub fn kick_rx(&mut self, pkt: &[u8]) -> anyhow::Result<()> {
        let enabled = crate::cast!(u64, pkt[0..8]);
        if enabled == 0 {
            tracing::warn!(fd = ?self.kick_fd, "virtqueue not enabled, ignore kick");
            return Err(Error::QueueDisabled)?;
        }

        // check if we have waiting messages to send?
        self.handle_rx_queued()?;

        Ok(())
    }

    /// Writes data into the receive queues
    pub fn handle_rx_queued(&mut self) -> anyhow::Result<()> {
        let mut pending = self.pending.lock();
        if pending.is_empty() {
            return Ok(());
        }

        let mem = match self.mem.as_ref().map(|m| m.memory()) {
            None => return Err(MemoryError::NoMappedMemory)?,
            Some(mem) => mem,
        };

        loop {
            if pending.is_empty() {
                // no more packets...
                break;
            }

            let chain = match self.queue.pop_descriptor_chain(mem.deref()) {
                Some(chain) => chain,
                None => {
                    tracing::warn!("[handle-rx-queued] exhausted descriptor chains");
                    break;
                }
            };

            let pkt = match pending.pop_front() {
                Some(pkt) => pkt,
                None => {
                    tracing::warn!("[handle-rx-queued] no more packets...but a non-empty queue");
                    break;
                }
            };

            let head_idx = chain.head_index();
            tracing::trace!("[queue] writing to descriptor chain: {}", head_idx);
            let mut writer = chain
                .writer(mem.deref())
                .context("unable to get virtqueue chain writer")?;

            let vhdr = VirtioNetHeader::new().as_bytes();
            let frame = pkt.frame.to_bytes();

            // NOTE: write_vectored may be better, but I don't think it's implemented for
            // the GuestMemory writer.  When tried, it only write the first buffer, which
            // appears to be the default behavior for the Write trait
            let sz = vhdr.len() + frame.len() + pkt.payload.len();
            tracing::trace!(slot = %head_idx, "[kick-rx] write {sz} bytes");
            tracing::trace!("[queue] frame:  {:02x?}", frame);
            tracing::trace!("[queue] packet: {:02x?}", &pkt.payload);

            writer
                .write_all(&vhdr)
                .context("unable to write vhost header")?;
            writer
                .write_all(&frame)
                .context("unable to write ethernet (L2) frame")?;
            writer.write_all(&pkt.payload).with_context(|| {
                format!(
                    "unable to write packet payload ({} bytes)",
                    pkt.payload.len()
                )
            })?;

            self.queue
                .add_used(mem.deref(), head_idx, sz as u32)
                .context("queue add_used failed")?;
        }

        // notify client
        self.call(&[0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
            .context("failed to notify client")?;

        Ok(())
    }

    /// Reads data from the driver and processes it
    ///
    /// ### Arguments
    /// * `pkt` - data to write to call file descriptor
    /// * `mem` - Mapped memory to read from
    pub fn call(&self, pkt: &[u8]) -> AppResult<()> {
        if !self.enabled {
            tracing::warn!(fd = ?self.call_fd, "virtqueue not enabled, ignore call");
            return Err(Error::QueueDisabled);
        }

        if let Some(fd) = self.call_fd.as_ref() {
            let sz = unistd::write(fd, pkt)?;
            tracing::trace!("sent notification to driver ({} bytes)", sz);
        }

        Ok(())
    }

    #[allow(dead_code)]
    pub fn err(&self, pkt: &[u8]) {
        let enabled = crate::cast!(u64, pkt[0..8]);
        if enabled == 0 {
            tracing::warn!(fd = ?self.err_fd, "virtqueue not enabled, ignore error");
            return;
        }
    }
}
