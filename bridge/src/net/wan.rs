//! Various WAN providers

mod tap;
mod udp;
mod wireguard;

use shadesmar_net::Ipv4Packet;

pub use self::{
    tap::TunTap,
    udp::UdpDevice,
    wireguard::{WgConfig, WgDevice},
};

use super::{router::RouterHandle, NetworkError};

pub trait Wan: Send + Sync
where
    Self: 'static,
{
    /// Describes the type of WAN to which this handle is connected
    fn desc(&self) -> String;

    fn as_wan_handle(&self) -> Result<Box<dyn WanHandle>, NetworkError>;

    fn run(self: Box<Self>, router: RouterHandle) -> Result<(), NetworkError>;

    fn spawn(self: Box<Self>, router: RouterHandle) -> Result<Box<dyn WanHandle>, NetworkError> {
        let handle = self.as_wan_handle()?;

        std::thread::Builder::new()
            .name(String::from("wan-thread"))
            .spawn(move || match self.run(router) {
                Ok(_) => tracing::trace!("wan thread exited successfully"),
                Err(error) => tracing::warn!(?error, "unable to run wan thread"),
            })?;

        Ok(handle)
    }
}

pub trait WanHandle: Send + Sync {
    /// Writes a packet to the upstream device
    fn write(&self, pkt: Ipv4Packet) -> Result<(), NetworkError>;
}
