//! Plugin helper macros

/// Generates the required bindings (exported functions) for a WAN plugin.
///
/// This macro takes 4 arguments:
/// * The name/type of the macro (a string, used in tracing/logging)
/// * The plugins configuration type
/// * The plugins device type
/// * The plugins (thread) handle type
///
/// The types specified above are required to implement certain traits or functions.
///
/// ### Configuration Type
/// This needs to implement both Serialize and Deserialize, as the plugin config is passed as a JSON string
///
/// ### Device Type
/// * `pub fn new(cfg: WanPluginConfig<$dev>) -> Result<(), Error>`
/// ** Creates a new device from the provided config.
/// ** Error can be any type.
///
/// * `pub fn run(&self, opts: WanPluginStartOpts)` -> Result<(), Error>
/// ** Spawns a new thread (if required) to run an instance of the WAN device.
/// ** Error can be any type
///
/// ### Handle Type
/// * `pub fn stop(self) -> Result<(), Error>`
/// ** Stops the instance, cleaning up any required memory or other allocations
#[macro_export]
macro_rules! define_wan_plugin {
    ($name:expr, $cfg:ty, $dev:ty, $handle:ty) => {
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
        pub extern "C" fn init(data: *const shadesmar_core::plugins::WanPluginInitOptions) -> i32 {
            let cfg = unsafe {
                match data.as_ref() {
                    None => return shadesmar_core::plugins::PluginError::NulPointer.as_i32(),
                    Some(cfg) => cfg,
                }
            };

            shadesmar_core::init_tracinig(cfg.log_level);

            // initialize the packet buffer pool (if not already done)
            shadesmar_core::types::buffers::PacketBufferPool::load();

            tracing::info!(
                "[{}] initialized plugin (log level: {})",
                $name,
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
            let cfg = shadesmar_core::arg!(json: shadesmar_core::plugins::WanPluginConfig::<$cfg>; data: cfg; error: std::ptr::null_mut());

            match <$dev>::new(cfg) {
                Ok(device) => Box::into_raw(Box::new(device)) as *mut _,
                Err(_error) => std::ptr::null_mut(),
            }
        }


        #[no_mangle]
        pub extern "C" fn wan_start(device: *mut c_void, settings: *const c_char) -> *const c_void {
            let device = shadesmar_core::arg!(ptr: $dev; data: device; error: std::ptr::null());
            let settings = shadesmar_core::arg!(json: shadesmar_core::plugins::WanPluginStartOpts; data: settings; error: std::ptr::null());

            let handle = match device.run(settings) {
                Ok(handle) => handle,
                Err(_error) => return std::ptr::null(),
            };

            // drop the device again, but don't return it.  we don't intend to free it yet
            Box::into_raw(device);

            Box::into_raw(Box::new(handle)) as *const c_void
        }

        /// Attempts to stop a running device
        #[no_mangle]
        pub extern "C" fn wan_stop(handle: *mut c_void) -> i32 {
            let handle = shadesmar_core::arg!(ptr: $handle; data: handle; error: -1);

            // send SIGTERM to thread to indicate it's time to quit
            match handle.stop() {
                Ok(_) => 0,
                Err(_err) => {
                    tracing::warn!("unable to stop {} handle", $name);
                    -1
                }
            }
        }

        /// Attempts to release a WAN device
        #[no_mangle]
        pub extern "C" fn wan_destroy(device: *mut c_void) -> i32 {
            let device = shadesmar_core::arg!(ptr: $dev; data: device; error: -1);
            drop(device);
            0
        }
    };
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
#[macro_export]
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
        match <$ty as shadesmar_core::plugins::PluginMessage>::from_plugin_message($data) {
            Ok($data) => $data,
            Err(error) => {
                eprintln!("unable to decode config: {error}");
                return $error;
            }
        }
    };
}
