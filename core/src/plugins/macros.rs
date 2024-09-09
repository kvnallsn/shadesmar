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
    ($name:expr, $plugin_type:expr, $cfg:ty, $dev:ty, $handle:ty) => {
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

            tracing::info!(
                "[{}] initialized plugin (log level: {})",
                $name,
                cfg.log_level
            );

            0
        }

        /// Specifies the type of plugin
        #[no_mangle]
        pub extern "C" fn plugin_type() -> u8 {
            $plugin_type as u8
        }

        /// Creates a new WAN adapter
        ///
        /// Initializes a new WAN adapter for use with the provided name and configuration. The
        /// configuration is passed as a serialized JSON object.
        ///
        /// This function will store an opaque pointer in the `device` parameter. On succes, it
        /// can be passed to futher wan fuctions to interact with that specific device.
        /// For example, it can be passed to `wan_stop` to terminate the wan.
        ///
        /// ### Arguments
        /// * `cfg` - [in] JSON string containaing WAN configuration
        /// * `device` - [out] stores the pointer to the device when the function exits
        #[no_mangle]
        pub extern "C" fn wan_create(
            cfg: *const std::ffi::c_char,
            device: *mut *mut std::ffi::c_void
        ) -> i32 {
            let _span = tracing::error_span!("wan_start").entered();

            // initialize the packet buffer pool (if not already done)
            shadesmar_core::types::buffers::PacketBufferPool::init(1600, 1024);

            let cfg = shadesmar_core::arg!(json: shadesmar_core::plugins::WanPluginConfig::<$cfg>; data: cfg; error: -1);
            shadesmar_core::arg!(checknul; device);

            match <$dev>::new(cfg) {
                Ok(wan) => {
                    let ptr = Box::into_raw(Box::new(wan)) as *mut _;
                    unsafe { *device = ptr } ;
                    0
                }
                Err(error) => {
                    tracing::error!("unable to start wan: {error:?}");
                    -1
                }
            }
        }

        /// Starts a WAN device
        ///
        /// Generally, starting a new WAN device involves creating new one or more threads
        /// to handle the upstream send/receive functionality. This function will store a
        /// handle to the running instance in the out pointer `instance` on success that may
        /// be used to further interact with the newly start instance.
        ///
        /// ### Arguments
        /// * `device` - [in] WAN device for which to spawn an instance
        /// * `channel` - [in] Opaque pointer to a channel structure used to communicate with the router
        /// * `cb` - [in] Callback function that writes/queues data the router (uses `channel`)
        /// * `instance` - [out] Stores pointer to instance on success
        #[no_mangle]
        pub extern "C" fn wan_start(
            device: *mut std::ffi::c_void,
            channel: *mut std::ffi::c_void,
            callback_fn: shadesmar_core::plugins::FnCallback,
            instance: *mut *mut std::ffi::c_void,
        ) -> i32 {
            let _span = tracing::error_span!("wan_start").entered();

            let device = shadesmar_core::arg!(ptr: $dev; data: device);
            shadesmar_core::arg!(checknul; instance);

            let callback = shadesmar_core::plugins::WanCallback::new(channel, callback_fn);

            match device.run(callback) {
                Ok(handle) => {
                    let ptr = Box::into_raw(Box::new(handle));
                    unsafe { *instance = ptr as *mut _ };
                }
                Err(error) => {
                    tracing::error!("unable to start wan: {error:?}");
                    return -1;
                }
            }

            // drop the device again, but don't return it.  we don't intend to free it yet
            Box::into_raw(device);

            0
        }

        /// Writes data to a WAN device
        ///
        /// Attempts to write (or queue) data to a WAN device instance specified by the handle `handle`.
        /// No assumptions may be made about the lifetime of the `data`, it is only valid for the duration
        /// of this function. Any uses (sending to other threads/queues/etc.) MUST copy this data to ensure
        /// it remains accessible to the WAN device.
        ///
        /// ### Arguments
        /// * `handle` - [in] Opaque pointer to the WAN instance
        /// * `data` - [in] Data to write to WAN device
        /// * `len` - [in] Length of data buffer
        #[no_mangle]
        pub extern "C" fn wan_send(
            handle: *mut std::ffi::c_void,
            data: *const u8,
            len: usize
        ) -> i32 {
            let handle = shadesmar_core::arg!(ptr: $handle; data: handle);

            let ret = match (data.is_null(), len) {
                (true, _) => 0,
                (false, 0) => 0,
                (false, _) => {
                    let data = unsafe { std::slice::from_raw_parts(data, len) };
                    handle.write(data);
                    0
                }
           };

           // "leak" the handle so it doesn't get deallocated (yet)
           Box::into_raw(handle);
           ret
        }

        /// Attempts to stop a running device
        ///
        /// Calls the associated stop function on the instance's handle, requesting the instance to stop
        ///
        /// ### Arguments
        /// * `handle` - [in] Opaque pointer to the WAN instance
        #[no_mangle]
        pub extern "C" fn wan_stop(handle: *mut std::ffi::c_void) -> i32 {
            let handle = shadesmar_core::arg!(ptr: $handle; data: handle);

            match handle.stop() {
                Ok(_) => 0,
                Err(_err) => {
                    tracing::warn!("unable to stop {} handle", $name);
                    -1
                }
            }
        }

        /// Attempts to release/destroy a WAN device
        ///
        /// Will free memory associated with the WAN device and perform any cleanup actions
        #[no_mangle]
        pub extern "C" fn wan_destroy(device: *mut std::ffi::c_void) -> i32 {
            let device = shadesmar_core::arg!(ptr: $dev; data: device);
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
    (ptr: $ty:ty; data: $data:tt) => {
        match $data.is_null() {
            true => return -1,
            false => {
                // SAFETY: we check for null above. all other safety checks are the
                // responsiblity of the caller!
                unsafe { Box::from_raw($data as *mut $ty) }
            }
        }
    };
    (checknul; $data:tt) => {
        match $data.is_null() {
            true => return -1,
            false => (),
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
