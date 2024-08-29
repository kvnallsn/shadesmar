//! NAT table implementation

use std::{collections::HashMap, net::Ipv4Addr};

use crate::{
    cast,
    protocols::{NET_PROTOCOL_ICMP, NET_PROTOCOL_TCP, NET_PROTOCOL_UDP},
    Ipv4Packet,
};

/// Network Address Translation (NAT) table
#[derive(Default)]
pub struct NatTable {
    table: HashMap<NatEntry, Ipv4Addr>,
}

/// An entry in the NAT table
#[derive(Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum NatEntry {
    Tcp(Ipv4Addr, u16),
    Udp(Ipv4Addr, u16),
    Icmp(Ipv4Addr, u16),
}

impl NatTable {
    /// Creates a new, empty NAT table
    pub fn new() -> Self {
        Self::default()
    }

    /// Inserts an entry into the NAT table based on the src ip, dst ip, and
    /// protocol specific information
    pub fn insert<P: Ipv4Packet>(&mut self, pkt: &P) {
        match pkt.protocol() {
            NET_PROTOCOL_ICMP => {
                let id = cast!(be16, &pkt.payload()[4..6]);
                self.put_icmp(pkt.dst(), id, pkt.src());
            }
            NET_PROTOCOL_TCP => {
                let port = cast!(be16, &pkt.payload()[0..2]);
                self.put_tcp(pkt.dst(), port, pkt.src());
            }
            NET_PROTOCOL_UDP => {
                let port = cast!(be16, &pkt.payload()[0..2]);
                self.put_udp(pkt.dst(), port, pkt.src());
            }
            _ => (),
        }
    }

    /// Associates a TCP port with a specific address
    ///
    /// ### Arguments
    /// * `dst` - Destination IP Address
    /// * `port` - Destination TCP Port
    /// * `src` - Source IPv4 Address
    pub fn put_tcp(&mut self, dst: Ipv4Addr, port: u16, src: Ipv4Addr) {
        tracing::trace!(?dst, ?src, port, "[nat], inserting tcp entry");
        self.table.insert(NatEntry::Tcp(dst, port), src);
    }

    /// Associates a UDP port with a specific address
    ///
    /// ### Arguments
    /// * `dst` - Destination IP Address
    /// * `port` - Destination TCP Port
    /// * `src` - Source IPv4 Address
    pub fn put_udp(&mut self, dst: Ipv4Addr, port: u16, src: Ipv4Addr) {
        tracing::trace!("[nat], inserting udp entry: {src} -> {dst}:{port}");
        self.table.insert(NatEntry::Udp(dst, port), src);
    }

    /// Associates a UDP port with a specific address
    ///
    /// ### Arguments
    /// * `dst` - Destination IP Address
    /// * `id` - Unique ICMP identification number
    /// * `src` - Source IPv4 Address
    pub fn put_icmp(&mut self, dst: Ipv4Addr, id: u16, src: Ipv4Addr) {
        tracing::trace!(?dst, ?src, id, "[nat], inserting icmp entry");
        self.table.insert(NatEntry::Icmp(dst, id), src);
    }

    /// Returns the NAT'd ipv4 address for a packet, if one exists
    pub fn get<P: Ipv4Packet>(&self, pkt: &P) -> Option<Ipv4Addr> {
        self.get_internal(pkt.protocol(), pkt.src(), pkt.payload())
    }

    fn get_internal(&self, protocol: u8, src: Ipv4Addr, payload: &[u8]) -> Option<Ipv4Addr> {
        match protocol {
            NET_PROTOCOL_ICMP => {
                let id = cast!(be16, &payload[4..6]);
                tracing::trace!(
                    proto = "icmp",
                    %src, %id,
                    "[nat] looking up entry"
                );
                self.table.get(&NatEntry::Icmp(src, id)).copied()
            }
            NET_PROTOCOL_TCP => {
                let port = cast!(be16, &payload[2..4]);
                tracing::trace!(
                    proto = "tcp",
                    %src, %port,
                    "[nat] looking up entry"
                );

                self.table.get(&NatEntry::Tcp(src, port)).copied()
            }
            NET_PROTOCOL_UDP => {
                let port = cast!(be16, &payload[2..4]);
                tracing::trace!(
                    proto = "icmp",
                    %src, %port,
                    "[nat] looking up entry"
                );
                self.table.get(&NatEntry::Udp(src, port)).copied()
            }
            _ => None,
        }
    }
}
