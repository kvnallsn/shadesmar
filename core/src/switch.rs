//! Switch Traits

use crate::{types::buffers::PacketBuffer, EthernetFrame, ProtocolError};

pub trait Switch: Clone + Send + Sync {
    /// Returns the port associated with the new switch device
    fn connect<P: SwitchPort + 'static>(&self, port: P) -> usize;

    /// Process a packet, sending it to the correct device
    fn process(&self, port: usize, pkt: PacketBuffer) -> Result<(), ProtocolError>;
}

/// A `SwitchPort` represents a device that can be connected to a switch
pub trait SwitchPort: Send + Sync {
    /// Human-friendly description (type) of switch port
    fn desc(&self) -> &'static str;

    /// Places a packet in the device's receive queue
    ///
    /// ### Arguments
    /// * `frame` - Ethernet frame header
    /// * `pkt` - Ethernet frame payload
    fn enqueue(&self, frame: EthernetFrame, pkt: PacketBuffer);
}

impl<T> SwitchPort for Box<T>
where
    T: SwitchPort,
{
    fn desc(&self) -> &'static str {
        T::desc(&self)
    }

    fn enqueue(&self, frame: EthernetFrame, pkt: PacketBuffer) {
        T::enqueue(&self, frame, pkt)
    }
}
