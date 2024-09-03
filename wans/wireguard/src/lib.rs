use std::ffi::{c_char, c_void};

use wireguard::{WgConfig, WgDevice, WgHandle};

mod wireguard;

shadesmar_core::define_wan_plugin!("wireguard", WgConfig, WgDevice, WgHandle);