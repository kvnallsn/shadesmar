//! Control message handler

use std::{
    io::{ErrorKind, IoSlice, Read, Write},
    os::{fd::AsRawFd, unix::net::UnixStream},
    path::{Path, PathBuf},
};

use mio::{event::Source, net::UnixListener, Token};
use serde::{Deserialize, Serialize};

use crate::{
    error::Error,
    net::{router::RouterStatus, switch::SwitchStatus},
};

const TOKEN_CTRL_STREAM: usize = 0x0000_0001_0000_0000;
const CTRL_MSG_HDR_SZ: usize = 5;

/// Represents a server for the control messages
pub struct CtrlSocket(UnixListener);

/// Wraps a (connected) unix stream
pub struct CtrlClientStream(UnixStream);

/// Wraps a control stream on the server
///
/// The server utilizes non-blocking sockets and mio/epoll.  This changes
/// how we need to handle send/recv rather than a (blocking) client stream
pub struct CtrlServerStream(mio::net::UnixStream);

#[derive(Debug, Deserialize, Serialize)]
pub enum CtrlRequest {
    Stop,
    ConnectTap(PathBuf),
    Status,
}

/// Represents a response from the server to a client
#[derive(Debug, Deserialize, Serialize)]
pub enum CtrlResponse {
    /// Returns the status of the switch
    Status(SwitchStatus, RouterStatus),
}

impl CtrlSocket {
    /// Binds a socket at the specified path
    ///
    /// ### Arguments
    /// * `path` - Path to the unix socket
    pub fn bind<P: AsRef<Path>>(path: P) -> Result<Self, Error> {
        let socket = UnixListener::bind(path)?;
        Ok(Self(socket))
    }

    /// Accepts a connection returns the new control stream
    pub fn accept(&self) -> Result<CtrlServerStream, Error> {
        let (strm, peer) = self.0.accept()?;
        tracing::debug!(?peer, "received new ctrl connection");
        Ok(CtrlServerStream::new(strm.into()))
    }
}

impl CtrlClientStream {
    /// Wraps a unix stream and returns a new ctrl stream
    pub fn new(strm: UnixStream) -> Self {
        Self(strm)
    }

    /// Connects to a control socket listener at the specified path
    pub fn connect<P: AsRef<Path>>(path: P) -> Result<Self, Error> {
        let strm = UnixStream::connect(path)?;
        Ok(Self::new(strm))
    }

    pub fn token(&self) -> Token {
        let fd = self.0.as_raw_fd() as usize;
        Token(TOKEN_CTRL_STREAM | fd)
    }

    /// Performs a blocking read while attempting to fill the whole buffer
    ///
    /// ### Arguments
    /// * `buf` - Buffer to read data into
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<()> {
        let mut nread = 0;
        loop {
            nread += self.0.read(&mut buf[nread..])?;
            if nread == buf.len() {
                return Ok(());
            }
        }
    }

    pub fn recv(&mut self) -> Result<Option<CtrlResponse>, Error> {
        // [0x01 | len | buf]
        let mut hdr = [0u8; 5];

        self.read(&mut hdr)?;
        let sz = u32::from_le_bytes([hdr[1], hdr[2], hdr[3], hdr[4]]);

        let mut data = vec![0u8; sz as usize];
        self.read(&mut data)?;

        let msg: CtrlResponse = bincode::deserialize(&data)?;

        Ok(Some(msg))
    }

    pub fn send(&mut self, msg: CtrlRequest) -> Result<(), Error> {
        // encode using bincode
        let data = bincode::serialize(&msg)?;

        let mut hdr = [0u8; 5];
        let sz_bytes = data.len().to_le_bytes();
        hdr[0] = 0x01; // version?
        hdr[1..5].copy_from_slice(&sz_bytes[0..4]);

        let sz = self
            .0
            .write_vectored(&[IoSlice::new(&hdr), IoSlice::new(&data)])?;

        tracing::trace!("wrote {sz} bytes to server");

        Ok(())
    }
}

impl CtrlServerStream {
    /// Wraps a unix stream and returns a new ctrl stream
    ///
    /// ### Arguments
    /// * `strm` - Newly accepted (non-blocking) unix stream
    pub fn new(strm: mio::net::UnixStream) -> Self {
        Self(strm)
    }

    pub fn token(&self) -> Token {
        let fd = self.0.as_raw_fd() as usize;
        Token(TOKEN_CTRL_STREAM | fd)
    }

    /// Performs an edge-triggered read on receive.
    ///
    /// This function will attempt to fill the entire buffer, reading in a
    /// loop until an EAGAIN or EWOULDBLOCK error is received. It returns the
    /// number of bytes successfully read before data is exhausted.
    ///
    /// ### Arguments
    /// * `buf` - Byte buffer to store data
    fn read(&mut self) -> std::io::Result<Option<Vec<u8>>> {
        let mut rbuf = [0u8; 1024];
        let mut buf = Vec::new();

        loop {
            match self.0.read(&mut rbuf) {
                Ok(0) => {
                    // client closed connection
                    return Ok(None);
                }
                Ok(sz) => buf.extend_from_slice(&rbuf[..sz]),
                Err(error) if error.kind() == ErrorKind::WouldBlock => {
                    return Ok(Some(buf));
                }
                Err(error) => {
                    // forward the error
                    return Err(error);
                }
            }
        }
    }

    /// Receives all available control messages on the stream
    ///
    /// Returns a vector of all messages, or None if the client has closed the connection
    pub fn recv(&mut self) -> Result<Option<Vec<CtrlRequest>>, Error> {
        let mut msgs = Vec::new();

        // read in all available data and parse into messages
        let mut data = match self.read()? {
            None => return Ok(None),
            Some(data) => data,
        };

        loop {
            let data_len = data.len();
            if data_len == 0 {
                break;
            }

            if data_len < CTRL_MSG_HDR_SZ {
                tracing::debug!(
                    "not enough data for control message header. want {CTRL_MSG_HDR_SZ} bytes, have {data_len} bytes"
                );
                break;
            }

            let _version = data[0];
            let msg_sz = u32::from_le_bytes([data[1], data[2], data[3], data[4]]);
            let total_sz = CTRL_MSG_HDR_SZ
                + usize::try_from(msg_sz).map_err(|e| Error::Other(e.to_string().into()))?;

            if data_len < total_sz {
                // TODO: save data for later?
                tracing::debug!(
                    "not enough data for control message payload. want {msg_sz} bytes, have {data_len} bytes"
                );
                break;
            }

            let msg: CtrlRequest = bincode::deserialize(&data[CTRL_MSG_HDR_SZ..total_sz])?;

            // drop the used elements
            data.drain(..total_sz);

            msgs.push(msg);
        }

        Ok(Some(msgs))
    }

    /// Sends a response message to the client
    ///
    /// Uses a vectored write to write the header and (serialized) message at the same time
    ///
    /// ### Arguments
    /// * `msg` -  Response to send to client
    pub fn send(&mut self, msg: CtrlResponse) -> Result<(), Error> {
        // encode using bincode
        let data = bincode::serialize(&msg)?;

        let mut hdr = [0u8; CTRL_MSG_HDR_SZ];
        let sz_bytes = data.len().to_le_bytes();
        hdr[0] = 0x01; // version?
        hdr[1..CTRL_MSG_HDR_SZ].copy_from_slice(&sz_bytes[0..4]);

        let sz = self
            .0
            .write_vectored(&[IoSlice::new(&hdr), IoSlice::new(&data)])?;

        tracing::trace!("wrote {sz} bytes to client");

        Ok(())
    }
}

impl Source for CtrlSocket {
    fn register(
        &mut self,
        registry: &mio::Registry,
        token: mio::Token,
        interests: mio::Interest,
    ) -> std::io::Result<()> {
        self.0.register(registry, token, interests)
    }

    fn reregister(
        &mut self,
        registry: &mio::Registry,
        token: mio::Token,
        interests: mio::Interest,
    ) -> std::io::Result<()> {
        self.0.register(registry, token, interests)
    }

    fn deregister(&mut self, registry: &mio::Registry) -> std::io::Result<()> {
        self.0.deregister(registry)
    }
}

impl Source for CtrlServerStream {
    fn register(
        &mut self,
        registry: &mio::Registry,
        token: mio::Token,
        interests: mio::Interest,
    ) -> std::io::Result<()> {
        self.0.register(registry, token, interests)
    }

    fn reregister(
        &mut self,
        registry: &mio::Registry,
        token: mio::Token,
        interests: mio::Interest,
    ) -> std::io::Result<()> {
        self.0.register(registry, token, interests)
    }

    fn deregister(&mut self, registry: &mio::Registry) -> std::io::Result<()> {
        self.0.deregister(registry)
    }
}
