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
use shadesmar_net::plugins::{
    PluginError, PluginMessage, WanConfiguration, WanPluginConfig, WanPluginInitOptions,
    WanPluginStartOpts,
};
use wan_core::error::WanError;

const NULPTR: *const c_void = std::ptr::null();
const NULPTR_MUT: *mut c_void = std::ptr::null_mut();

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

pub type BlackholeHandle = JoinHandle<()>;

pub fn from_raw<T>(device: *mut c_void) -> Result<Box<T>, WanError> {
    match device.is_null() {
        true => Err(WanError::with_message("null pointer")),
        false => {
            let device: Box<T> = unsafe { Box::from_raw(device as *mut T) };
            Ok(device)
        }
    }
}

/// Macro to extract variables from FFI arguments
///
/// Supports two different types of variables
/// * `ptr` - A raw/opaque (i.e., *const c_void) pointer to a data structure
/// * `json` - A c-style (i.e., nul terminated) string containing JSON data
///
/// Examples:
/// * Convert an opaque pointer back into a rust data structure:
/// ```
/// arg!(ptr: SomeDataType; data: var_containing_pointer; error: error_return_value)
/// ```
///
/// * Extract JSON parameters into a structured type:
/// ```
/// arg!(json: MySettingsType; data: var_container_nul_terminated_string; error: error_value)
/// ```
macro_rules! arg {
    (ptr: $ty:ty; data: $data:tt; error: $error:expr) => {
        match $data.is_null() {
            true => return $error,
            false => {
                // SAFETY: we check for null above. all other safety checks are the
                // responsiblity of the caller!
                unsafe { Box::from_raw($data as *mut $ty) }
            }
        }
    };
    (json: $ty:ty; data: $data:tt; error: $error:expr) => {
        match <$ty as shadesmar_net::plugins::PluginMessage>::from_plugin_message($data) {
            Ok($data) => $data,
            Err(error) => {
                eprintln!("unable to decode config: {error}");
                return $error;
            }
        }
    };
}

/// Initializes the plugin
///
/// This is called when the plugin is loaded by shadesmar on application start and
/// should perform and generic, global configuration necessary in order to be able to
/// spawn new WAN connections.
///
/// ### Returns
/// - `0` on success
/// - Non-zero on failure
#[no_mangle]
pub extern "C" fn init(data: *const WanPluginInitOptions) -> i32 {
    let cfg = unsafe {
        match data.as_ref() {
            None => return PluginError::NulPointer.as_i32(),
            Some(cfg) => cfg,
        }
    };

    shadesmar_net::init_tracinig(cfg.log_level);
    tracing::info!(
        "[blackhole] initialized plugin (log level: {})",
        cfg.log_level
    );

    0
}

/// Creates a new WAN adapter
///
/// Initializes a new WAN adapter for use with the provided name and configuration. The
/// configuration is passed as a serialized JSON object.
///
/// ### Return
/// * `*const c_void`
///
/// This function returns an opaque pointer to a handle structure.  This pointer
/// can be passed to futher wan fuctions to interact with that specific device.
/// For example, it can be passed to `wan_stop` to terminate the wan.
///
/// ### Arguments
/// * `cfg` - JSON string containaing WAN configuration
#[no_mangle]
pub extern "C" fn wan_create(cfg: *const c_char) -> *mut c_void {
    let _cfg = arg!(json: WanPluginConfig::<BlackholeConfig>; data: cfg; error: NULPTR_MUT);

    let device = BlackholeDevice::new();
    Box::into_raw(device) as *mut _
}

#[no_mangle]
pub extern "C" fn wan_start(device: *mut c_void, settings: *const c_char) -> *const c_void {
    let device = arg!(ptr: BlackholeDevice; data: device; error: NULPTR);
    let settings = arg!(json: WanPluginStartOpts; data: settings; error: NULPTR);

    let handle = match device.run(&settings.socket) {
        Ok(handle) => handle,
        Err(_error) => return std::ptr::null(),
    };

    Box::into_raw(Box::new(handle)) as *const c_void
}

/// Attempts to stop a running device
#[no_mangle]
pub extern "C" fn wan_stop(handle: *mut c_void) -> i32 {
    let handle = match from_raw::<BlackholeHandle>(handle) {
        Ok(handle) => handle,
        Err(_error) => return -1,
    };

    // send SIGTERM to thread to indicate it's time to quit
    let tid = handle.as_pthread_t();
    match nix::sys::pthread::pthread_kill(tid, Signal::SIGTERM) {
        Ok(_) => 0,
        Err(err) => err as i32,
    }
}

/// Attempts to release a WAN device
#[no_mangle]
pub extern "C" fn wan_destroy(device: *mut c_void) -> i32 {
    let device = match from_raw::<BlackholeDevice>(device) {
        Ok(device) => device,
        Err(_error) => return -1,
    };

    drop(device);

    0
}

/// Returns the configuration of this WAN device
#[no_mangle]
pub extern "C" fn wan_stats(_device: *mut c_void) -> i32 {
    let wan_cfg = WanConfiguration::new();
    let _wan_cfg = wan_cfg.as_plugin_message().unwrap();

    0
}

/// Returns the IPv4 address assigned to this one, if one exists
#[no_mangle]
pub extern "C" fn wan_ipv4(_device: *mut c_void) -> u32 {
    0
}

impl BlackholeDevice {
    pub fn new() -> Box<Self> {
        Box::new(BlackholeDevice { _marker: 67331 })
    }

    pub fn from_raw(device: *mut c_void) -> Result<Box<Self>, WanError> {
        match device.is_null() {
            true => Err(WanError::with_message("null pointer")),
            false => {
                let device: Box<BlackholeDevice> = unsafe { Box::from_raw(device as *mut Self) };
                Ok(device)
            }
        }
    }

    pub fn run(&self, socket: &Path) -> Result<Box<BlackholeHandle>, WanError> {
        let instance = BlackholeInstance::new(socket)?;

        let handle = std::thread::Builder::new()
            .name(String::from("wan-blackhole"))
            .spawn(move || match instance.run() {
                Ok(_) => (),
                Err(_error) => (),
            })?;

        Ok(Box::new(handle))
    }
}

impl BlackholeInstance {
    const TOKEN_UNIX_SOCK: Token = Token(0);
    const TOKEN_SIGNAL_FD: Token = Token(1);

    pub fn new(path: &Path) -> Result<Self, WanError> {
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

    pub fn run(mut self) -> Result<(), WanError> {
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

    fn read_unix_sock(&self, buf: &mut [u8]) -> Result<(), WanError> {
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

    fn read_signal(&self) -> Result<bool, WanError> {
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
