//! Represents the plugin's "virtual table" of functions

use std::{
    collections::HashMap,
    ffi::{c_char, c_void},
    mem::MaybeUninit,
};

use libloading::{Library, Symbol};
use uuid::Uuid;

use super::{FnCallback, PluginError, WanDevice, WanInstance, WanPluginConfig};

type FnWanCreate = fn(*const c_char, *mut *mut c_void) -> i32;
type FnWanStart = fn(*const c_void, *const c_void, FnCallback, *mut *mut c_void) -> i32;
type FnWanSend = fn(*const c_void, *const u8, usize) -> i32;
type FnWanStop = fn(*const c_void) -> i32;
type FnWanDestroy = fn(*const c_void) -> i32;

/// Represents the virtual table (vtable) for a WAN plugin
pub struct WanPlugin<'a> {
    fn_create: Symbol<'a, FnWanCreate>,
    fn_start: Symbol<'a, FnWanStart>,
    fn_send: Symbol<'a, FnWanSend>,
    fn_stop: Symbol<'a, FnWanStop>,
    fn_destroy: Symbol<'a, FnWanDestroy>,
}

impl<'a> WanPlugin<'a> {
    pub fn new(lib: &'a Library) -> Result<Self, PluginError> {
        // SAFETY:
        // Ensure this library is loaded and the function exists before calling!
        let fn_create: Symbol<FnWanCreate> = unsafe { lib.get(b"wan_create") }?;
        let fn_start: Symbol<FnWanStart> = unsafe { lib.get(b"wan_start") }?;
        let fn_send: Symbol<FnWanSend> = unsafe { lib.get(b"wan_send") }?;
        let fn_stop: Symbol<FnWanStop> = unsafe { lib.get(b"wan_stop") }?;
        let fn_destroy: Symbol<FnWanDestroy> = unsafe { lib.get(b"wan_destroy") }?;

        let vtable = WanPlugin {
            fn_create,
            fn_start,
            fn_send,
            fn_stop,
            fn_destroy,
        };

        Ok(vtable)
    }

    /// Creates a new WAN plugin with the specified id and configuration
    ///
    /// This will serialize the id and configuration (which is a map of strings) to json
    /// and pass that to the device plugin (via ffi).  On sucecss, it returns an opaque pointer
    /// (`WanDevice`) that may be used with other `WanPlugin` functions to interact with the
    /// WAN device.  On failure, an error is return.
    ///
    /// ### Arguments
    /// * `id` - Unique ID used to identify device
    /// * `cfg` - Configuration of the device
    pub fn create(
        &self,
        id: Uuid,
        cfg: &HashMap<String, String>,
    ) -> Result<WanDevice, PluginError> {
        let arg = WanPluginConfig::as_json(id, cfg)?;
        let mut ptr = MaybeUninit::<*mut c_void>::uninit();

        match (self.fn_create)(arg.as_ptr(), ptr.as_mut_ptr()) {
            0 => {
                // SAFETY: a return code of zero indicates success
                let dev = unsafe { ptr.assume_init() };
                Ok(WanDevice { ptr: dev })
            }
            _ => Err(PluginError::SpawnFailed),
        }
    }

    /// Attempts to start a WAN plugin
    ///
    /// This will return a handle to a `WanInstance`, an opaque pointer to
    /// a running WAN device
    ///
    /// ### Arguments
    /// * `device` - WAN device to start
    pub fn start(
        &self,
        device: &WanDevice,
        channel: *mut c_void,
        cb: FnCallback,
    ) -> Result<WanInstance, PluginError> {
        let mut ptr = MaybeUninit::<*mut c_void>::uninit();
        match (self.fn_start)(device.ptr, channel, cb, ptr.as_mut_ptr()) {
            0 => {
                // SAFETY: zero indicates success and the pointer is valid
                let obj = unsafe { ptr.assume_init() };
                Ok(WanInstance { obj, channel })
            }
            _ => Err(PluginError::SpawnFailed),
        }
    }

    /// Passes a data buffer (by reference!) to the WAN device
    ///
    /// This WAN device will NOT take ownership of the buffer and once the call to the
    /// WAN device (via ffi) returns, it must be assumed the buffer is no longer exists or
    /// can be used in any meaningful way _by the plugin_.
    ///
    /// ### Arguments
    /// * `instance` - (Opaque) pointer to the running device instance
    /// * `data` - Byte slice/buffer to pass to the WAN device
    pub fn write(&self, instance: &WanInstance, data: &[u8]) -> Result<(), PluginError> {
        (self.fn_send)(instance.obj, data.as_ptr(), data.len());
        Ok(())
    }

    /// Attempts to stop a WAN instance
    ///
    /// On success, a pointer to the router channel will be returned.  The caller is
    /// responsible for freeing any memory associated with this pointer / channel.
    ///
    /// ### Arguments
    /// * `instance` - WAN instance to stop
    pub fn stop(&self, instance: WanInstance) -> Result<*mut c_void, PluginError> {
        let err = (self.fn_stop)(instance.obj);

        match err {
            0 => Ok(instance.channel),
            _ => Err(PluginError::SpawnFailed),
        }
    }

    /// Attempts to destroy a WAN device.
    ///
    /// ### Arguments
    /// * `device` - WAN device to obliterate
    pub fn destroy(&self, device: &WanDevice) -> Result<(), PluginError> {
        // SAFETY:
        // Pointer cannot be null/invalid.  Only way to create a `WanInstance` is through
        // a successful call to `WanPlugin::create()`
        let err = (self.fn_destroy)(device.ptr);

        match err {
            0 => Ok(()),
            _ => Err(PluginError::SpawnFailed),
        }
    }
}
