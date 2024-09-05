mod tap;

use self::tap::{TapConfig, TapDevice, TapHandle};

shadesmar_core::define_wan_plugin!("tap", TapConfig, TapDevice, TapHandle);
