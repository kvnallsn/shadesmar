//! Plugin Support

use std::{
    collections::HashMap,
    ffi::{c_char, c_void},
    path::PathBuf,
};

use libloading::{Library, Symbol};

use crate::error::Error;

type FnInit = unsafe extern "C" fn() -> i32;
type FnWanCreate =
    unsafe extern "C" fn(*const c_char, *const c_char, *const c_char) -> *const c_void;

/// Contains references to all loaded plugin libraries
pub struct WanPlugins {
    libs: HashMap<String, Library>,
}

pub struct WanPlugin<'a> {
    create: Symbol<'a, FnWanCreate>,
}

impl WanPlugins {
    /// Loads all plugins from a list
    ///
    /// ### Arguments
    /// * `plugins` - List of plugins to load
    pub fn init(plugins: HashMap<String, PathBuf>) -> Result<Self, Error> {
        let mut libs = HashMap::new();
        for (name, plugin) in plugins {
            // SAFETY:
            // Ensure all so/dll init and termination routies are safe
            let lib = unsafe {
                let lib = Library::new(&plugin)?;

                let init: Symbol<FnInit> = lib.get(b"init")?;
                match init() {
                    0 => Ok(lib),
                    _ => Err(Error::new(format!("unable to load plugin '{name}'"))),
                }
            }?;

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
    pub fn get_vtable<'a, S: AsRef<str>>(&'a self, plugin: S) -> Result<WanPlugin<'a>, Error> {
        let plugin = plugin.as_ref();

        let lib = self
            .libs
            .get(plugin)
            .ok_or_else(|| Error::new("wan device type not found"))?;

        // SAFETY:
        // Ensure this library is loaded and the function exists before calling!
        let create: Symbol<FnWanCreate> = unsafe { lib.get(b"wan_create") }?;

        let vtable = WanPlugin { create };

        Ok(vtable)
    }
}
