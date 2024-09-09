use shadesmar_core::plugins::PluginType;
use wireguard::{WgConfig, WgDevice, WgHandle};

mod wireguard;

shadesmar_core::define_wan_plugin!("wireguard", PluginType::Wan, WgConfig, WgDevice, WgHandle);
