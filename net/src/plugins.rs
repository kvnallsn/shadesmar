//! Plugin Support

use std::{
    borrow::Cow,
    collections::HashMap,
    ffi::{c_char, c_void, CStr, CString},
    net::Ipv4Addr,
    path::{Path, PathBuf},
};

use libloading::{Library, Symbol};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use uuid::Uuid;

type FnInit = fn(*const WanPluginInitOptions) -> i32;
type FnWanCreate = fn(*const c_char) -> *mut c_void;
type FnWanStart = unsafe extern "C" fn(*const c_void, *const c_char) -> *const c_void;
type FnWanStop = unsafe extern "C" fn(*const c_void) -> i32;
type FnWanDestroy = unsafe extern "C" fn(*const c_void) -> i32;

/// Error type for any errors generated by a plugin
#[derive(Debug, thiserror::Error)]
pub enum PluginError {
    #[error("failed to load library: {0}")]
    Load(#[from] libloading::Error),

    #[error("plugin not loaded or missing: {0}")]
    PluginNotFound(String),

    #[error("symbol not found in library: {0}")]
    SymbolNotFound(&'static str),

    #[error("null pointer!")]
    NulPointer,

    #[error("ffi: {0}")]
    FFI(#[from] std::ffi::NulError),

    #[error("utf8: {0}")]
    UTF8(#[from] std::str::Utf8Error),

    #[error("json: {0}")]
    Json(#[from] serde_json::Error),

    #[error("plugin failed to spawn an instance")]
    SpawnFailed,

    #[error("{0}")]
    Other(String),
}

/// New Type to wrap an opaque pointer to a WAN device
pub struct WanDevice(*const c_void);

/// New Type to wrap an opaque pointer to a WAN instance
pub struct WanInstance(*const c_void);

/// Contains references to all loaded plugin libraries
pub struct WanPlugins {
    libs: HashMap<String, Library>,
}

/// Represents the virtual table (vtable) for a WAN plugin
pub struct WanPlugin<'a> {
    fn_create: Symbol<'a, FnWanCreate>,
    fn_start: Symbol<'a, FnWanStart>,
    fn_stop: Symbol<'a, FnWanStop>,
    fn_destroy: Symbol<'a, FnWanDestroy>,
}

pub trait PluginMessage: Sized {
    /// Serializes a struct to json and converts it to a CString to
    /// be passed over an FFI barrier / function call
    fn as_plugin_message(&self) -> Result<CString, PluginError>;

    /// Deserializes a message received over the ffi barrier
    fn from_plugin_message(data: *const c_char) -> Result<Self, PluginError>;
}

/// Options passed to the initialziation FFI function
#[derive(Debug, Deserialize, Serialize)]
#[repr(C)]
pub struct WanPluginInitOptions {
    /// Verbosity level to which to produce logs
    pub log_level: u8,
}

/// Configuration data for a WAN plugin
///
/// WAN plugin configuration is generic over T, where T is the specific type
/// of plugin being configured. This allows each plugin to specify its own
/// configuration type and not expose it to the larger application.
///
/// For example, the simple `blackhole` wan driver specifies a config type
/// of `BlackholeConfig` that takes no parameters (aka the unit type `()`).
/// The WireGuard wan driver specifies a config type of `WgConfig` that contains
/// information about the WireGuard endpoint
#[derive(Debug, Deserialize, Serialize)]
pub struct WanPluginConfig<T> {
    /// WAN unique identifier
    pub id: Uuid,

    /// Device-specific settings
    pub device: T,
}

/// Contains options passed to the plugin when an instance is started
///
/// These should be runtime settings and are not required to be persistent
/// over the lifetime of a device.
#[derive(Debug, Deserialize, Serialize)]
pub struct WanPluginStartOpts<'a> {
    /// Path to the router's socket
    pub router: Cow<'a, Path>,

    /// Path to wan plugin socket
    pub socket: Cow<'a, Path>,
}

/// Common set of configuration items that a WAN device will report back
/// to the bridge / network / router
#[derive(Debug, Deserialize, Serialize)]
pub struct WanConfiguration {
    /// Internal Ipv4 address, if any
    ipv4: Option<Ipv4Addr>,
}

impl PluginError {
    pub fn new<S: Into<String>>(msg: S) -> Self {
        PluginError::Other(msg.into())
    }
}

impl WanPlugins {
    /// Loads all plugins from a list
    ///
    /// ### Arguments
    /// * `plugins` - List of plugins to load
    /// * `opts` - Global plugin configuration object
    pub fn init(
        plugins: HashMap<String, PathBuf>,
        opts: WanPluginInitOptions,
    ) -> Result<Self, PluginError> {
        let mut libs = HashMap::new();
        for (name, plugin) in plugins {
            // SAFETY:
            // Ensure all so/dll init and termination routies are safe
            let lib = unsafe {
                let lib = Library::new(&plugin)?;

                let init: Symbol<FnInit> = lib.get(b"init")?;
                match init(&opts) {
                    0 => Ok(lib),
                    _ => Err(PluginError::SymbolNotFound("init")),
                }
            }?;

            tracing::trace!("registering plugin: {name}");
            libs.insert(name, lib);
        }

        Ok(Self { libs })
    }

    /// Returns the virtual table (vtable) for a plugin
    ///
    /// A vtable contains all the functions necessary to interact with a given wan plugin
    ///
    /// ### Arguments
    /// * `plugin` - Name of the plugin for which to retrieve the vtable
    pub fn get_vtable<'a, S: AsRef<str>>(
        &'a self,
        plugin: S,
    ) -> Result<WanPlugin<'a>, PluginError> {
        let plugin = plugin.as_ref();

        let lib = self
            .libs
            .get(plugin)
            .ok_or_else(|| PluginError::PluginNotFound(plugin.to_owned()))?;

        // SAFETY:
        // Ensure this library is loaded and the function exists before calling!
        let fn_create: Symbol<FnWanCreate> = unsafe { lib.get(b"wan_create") }?;
        let fn_start: Symbol<FnWanStart> = unsafe { lib.get(b"wan_start") }?;
        let fn_stop: Symbol<FnWanStop> = unsafe { lib.get(b"wan_stop") }?;
        let fn_destroy: Symbol<FnWanDestroy> = unsafe { lib.get(b"wan_destroy") }?;

        let vtable = WanPlugin {
            fn_create,
            fn_start,
            fn_stop,
            fn_destroy,
        };

        Ok(vtable)
    }
}

impl<'a> WanPlugin<'a> {
    /// Creates/spawns the WAN device
    pub fn create(
        &self,
        id: Uuid,
        device: &HashMap<String, String>,
    ) -> Result<WanDevice, PluginError> {
        let arg = WanPluginConfig::as_json(id, device)?;

        // SAFETY:
        // All pointers are guarenteed to be valid c-string
        let ptr = (self.fn_create)(arg.as_ptr());

        match ptr.is_null() {
            true => Err(PluginError::SpawnFailed),
            false => Ok(WanDevice(ptr)),
        }
    }

    /// Attempts to start a WAN plugin
    ///
    /// This will return a handle to a `WanInstance`, an opaque pointer to
    /// a running WAN device
    ///
    /// ### Arguments
    /// * `device` - WAN device to start
    pub fn start<P1: AsRef<Path>, P2: AsRef<Path>>(
        &self,
        device: &WanDevice,
        router: P1,
        socket: P2,
    ) -> Result<WanInstance, PluginError> {
        let router = router.as_ref();
        let socket = socket.as_ref();
        let msg = WanPluginStartOpts::new(router, socket);
        let args = msg.as_plugin_message()?;

        // SAFETY:
        // Pointer cannot be null/invalid.  Only way to create a `WanDevice` is through
        // a successful call to `WanPlugin::create()`
        let instance = unsafe { (self.fn_start)(device.0, args.as_ptr()) };

        match instance.is_null() {
            true => Err(PluginError::SpawnFailed),
            false => Ok(WanInstance(instance)),
        }
    }

    /// Attempts to stop a WAN instance
    ///
    /// ### Arguments
    /// * `instance` - WAN instance to stop
    pub fn stop(&self, instance: WanInstance) -> Result<(), PluginError> {
        // SAFETY:
        // Pointer cannot be null/invalid.  Only way to create a `WanInstance` is through
        // a successful call to `WanPlugin::start()`
        let err = unsafe { (self.fn_stop)(instance.0) };

        match err {
            0 => Ok(()),
            _ => Err(PluginError::SpawnFailed),
        }
    }

    /// Attempts to destroy a WAN device
    ///
    /// ### Arguments
    /// * `device` - WAN device to obliterate
    pub fn destroy(self, device: WanDevice) -> Result<(), PluginError> {
        // SAFETY:
        // Pointer cannot be null/invalid.  Only way to create a `WanInstance` is through
        // a successful call to `WanPlugin::create()`
        let err = unsafe { (self.fn_destroy)(device.0) };

        match err {
            0 => Ok(()),
            _ => Err(PluginError::SpawnFailed),
        }
    }
}

impl WanPluginConfig<()> {
    /// Serializes a plugin's configuration into a CString (null-terminated)
    ///
    /// ### Arguments
    /// * `id` - Unique id of WAN plugin
    /// * `router` - Path to router's socket
    /// * `device` - Device specific configuration
    pub fn as_json(id: Uuid, device: &HashMap<String, String>) -> Result<CString, PluginError> {
        let s = serde_json::json!({
            "id": id,
            "device": device
        })
        .to_string();

        let cs = CString::new(s)?;

        Ok(cs)
    }
}

impl WanConfiguration {
    pub fn new() -> Self {
        WanConfiguration { ipv4: None }
    }
}

impl<T> PluginMessage for T
where
    T: Serialize + DeserializeOwned,
{
    /// Serializes a struct to json and converts it to a CString to
    /// be passed over an FFI barrier / function call
    fn as_plugin_message(&self) -> Result<CString, PluginError> {
        let params = serde_json::to_string(self)?;
        let params = CString::new(params)?;

        Ok(params)
    }

    /// Deserializes a message received over the ffi barrier
    fn from_plugin_message(data: *const c_char) -> Result<Self, PluginError> {
        let data = unsafe { CStr::from_ptr(data) };
        let params = data.to_str()?;
        let params: Self = serde_json::from_str(params)?;
        Ok(params)
    }
}

impl WanPluginInitOptions {
    /// Creates a new plugin init options to initialize a plugin
    ///
    /// ### Arguments
    /// * `log_level` - Level at which to install tracing logger
    pub fn new(log_level: u8) -> Self {
        Self { log_level }
    }
}

impl<'a> WanPluginStartOpts<'a> {
    /// Creates a new plugin start options struct from borrowed params
    pub fn new(router: &'a Path, socket: &'a Path) -> Self {
        Self {
            router: Cow::Borrowed(router),
            socket: Cow::Borrowed(socket),
        }
    }
}

impl PluginError {
    pub fn as_i32(&self) -> i32 {
        match self {
            Self::Load(_error_) => -1,
            Self::PluginNotFound(_plugin) => -2,
            Self::SymbolNotFound(_symbol) => -3,
            Self::NulPointer => -4,
            Self::FFI(_ffi) => -5,
            Self::UTF8(_error) => -6,
            Self::Json(_error) => -7,
            Self::SpawnFailed => -8,
            Self::Other(_error) => -9,
        }
    }
}
