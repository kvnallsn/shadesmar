mod tap;

use shadesmar_core::plugins::PluginType;

use self::tap::{TunTapConfig, TunTapDevice, TunTapHandle};

shadesmar_core::define_wan_plugin!(
    "tuntap",
    PluginType::Wan,
    TunTapConfig,
    TunTapDevice,
    TunTapHandle
);
