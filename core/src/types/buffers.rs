//! Packet Buffers implementation (arena allocator?)

use std::{
    ops::{Deref, DerefMut},
    sync::OnceLock,
};

use parking_lot::Mutex;

/// A pool of pre-allocated buffers to store packet data
///
/// The intent of the pool is to avoid costly allocations when
/// dealing with packet data. This is done by pre-allocating a
/// set number of buffers of a given capacity right when the
/// application starts
pub struct PacketBufferPool {
    buffers: Mutex<Vec<Vec<u8>>>,
}

/// A wrapper around a vector used to hold packet data
///
/// The vector is wrapped in an option in order to properly return it
/// to the buffer store when the struct is dropped
#[derive(Debug)]
pub struct PacketBuffer {
    buffer: Option<Vec<u8>>,
}

impl PacketBufferPool {
    /// Returns a refererence to the packet buffer pool
    pub fn load() -> &'static PacketBufferPool {
        static PACKET_BUFFERS: OnceLock<PacketBufferPool> = OnceLock::new();
        PACKET_BUFFERS.get_or_init(|| PacketBufferPool::default())
    }

    /// Creates a PacketBuffer pool with default settings
    ///
    /// Capacity: 1600 bytes
    /// Pre-Allocated Buffers: 1024
    pub fn default() -> Self {
        Self::new(1600, 1024)
    }

    /// Creates a PacketBuffer pool with the provided values
    ///
    /// ### Arguments
    /// * `capacity` - Pre-allocated size of each buffer
    /// * `count` - Number of buffers to pre-allocate
    pub fn new(capacity: usize, count: usize) -> Self {
        let buffers = (0..count)
            .map(|_| Vec::with_capacity(capacity))
            .collect::<Vec<_>>();

        let buffers = Mutex::new(buffers);

        Self { buffers }
    }

    /// Returns the number of pre-allocated buffers currently available
    pub fn available() -> usize {
        Self::load().buffers.lock().len()
    }

    /// Returns a new PacketBuffer to use to store data
    ///
    /// This function will either return an unused buffer from it's internal store
    /// or will allocate a new buffer if none are available.
    ///
    /// **IMPORTANT**: The buffers will have a length of zero but a _capacity_ of 1600.
    /// If the buffer needs space available now (i.e., for a call to `read()`), use
    /// `PacketBuffers::with_size(sz)` instead!
    pub fn get() -> PacketBuffer {
        let pbs = PacketBufferPool::load();
        let vec = match pbs.buffers.lock().pop() {
            Some(vec) => vec,
            None => {
                tracing::warn!("no buffers left, allocating new buffer");
                Vec::with_capacity(1600)
            }
        };

        PacketBuffer { buffer: Some(vec) }
    }
    /// Returns a new PacketBuffer to use to store data
    ///
    /// This function will either return an unused buffer from it's internal store
    /// or will allocate a new buffer if none are available.  Additionally, it will
    /// fill the buffer with zeroes up to the specified size
    ///
    /// # Arguments
    /// * `sz` - Minimum size of buffer to allocate and fill
    pub fn with_size(sz: usize) -> PacketBuffer {
        let span = tracing::info_span!("get packet buffer with size", sz);
        let _enter = span.enter();

        let _enter = span.enter();
        let mut buf = PacketBufferPool::get();
        buf.resize(sz, 0);

        tracing::trace!(
            "resized buffer (len: {}, cap: {})",
            buf.len(),
            buf.capacity()
        );

        buf
    }
}

impl PacketBuffer {
    /// Returns a new Packet buffer that wraps an existing vector
    pub fn new(vec: Vec<u8>) -> Self {
        Self { buffer: Some(vec) }
    }

    /// Clones a `PacketBuffer`
    ///
    /// This is not derived (and not an instance method) to discourage the use of cloning
    /// PacketBuffers
    pub fn clone(other: &PacketBuffer) -> Self {
        let mut buffer = PacketBufferPool::get();
        buffer.extend_from_slice(&other);
        buffer
    }

    /// Returns the number of bytes stored in the PacketBuffer
    pub fn len(&self) -> usize {
        self.buffer.as_ref().unwrap().len()
    }

    /// Returns the number of bytes allocated for the PacketBuffer
    pub fn capacity(&self) -> usize {
        self.buffer.as_ref().unwrap().capacity()
    }

    /// Fills the buffer to capacity with the specified value
    ///
    /// ### Arguments
    /// * `val` - Value to fill entire buffer with
    pub fn fill(&mut self, val: u8) {
        let cap = self.capacity();
        self.buffer.as_mut().unwrap().resize(cap, val)
    }
}

impl Drop for PacketBuffer {
    fn drop(&mut self) {
        if let Some(mut v) = self.buffer.take() {
            tracing::trace!(
                "returning buffer to pool (len = {}, cap = {})",
                v.len(),
                v.capacity()
            );

            v.clear();

            let pbs = PacketBufferPool::load();
            pbs.buffers.lock().push(v);
        }
    }
}

impl Deref for PacketBuffer {
    type Target = Vec<u8>;
    fn deref(&self) -> &Self::Target {
        // NOTE: unwrap is safe, buffer is only None after it is dropped
        self.buffer.as_ref().unwrap()
    }
}

impl DerefMut for PacketBuffer {
    fn deref_mut(&mut self) -> &mut Self::Target {
        // NOTE: unwrap is safe, buffer is only None after it is dropped
        self.buffer.as_mut().unwrap()
    }
}

impl From<Vec<u8>> for PacketBuffer {
    fn from(value: Vec<u8>) -> Self {
        Self::new(value)
    }
}

impl From<&[u8]> for PacketBuffer {
    fn from(value: &[u8]) -> Self {
        Self::new(value.to_vec())
    }
}

impl From<&mut [u8]> for PacketBuffer {
    fn from(value: &mut [u8]) -> Self {
        Self::new(value.to_vec())
    }
}

/*
impl PacketBuffer {
    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    pub fn get(&self) -> &[u8] {
        let len = self.len();
        &(*self.buffer)[..len]
    }

    pub fn fill_from<R: Read>(&mut self, rdr: &mut R) -> Result<(), std::io::Error> {
        rdr.read_to_end(&mut self.buffer)?;
        Ok(())
    }

    /// Copies data from the slice into the packet buffer
    pub fn extend(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);
    }
}


impl Drop for PacketBuffer {
    fn drop(&mut self) {
        self.buffer.fill(0);
        self.used = 0;
        self.bitmap.lock().remove(&self.idx);
    }
}
 */
