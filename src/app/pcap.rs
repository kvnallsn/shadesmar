//! handles pcap related tasks

use std::{io::ErrorKind, net::Ipv4Addr, path::Path};

use jiff::Timestamp;
use mio::net::UnixDatagram;
use nix::sys::signal::Signal;
use serde::{Deserialize, Serialize};
use shadesmar_core::{
    ipv4::{Ipv4Packet, Ipv4PacketRef},
    protocols::{
        tcp::TcpHeader, udp::UdpHeader, ArpPacket, NET_PROTOCOL_ICMP, NET_PROTOCOL_TCP,
        NET_PROTOCOL_UDP,
    },
    types::MacAddress,
};

use crate::os::Poller;

macro_rules! print_netflow {
    (header) => {
        println!(
            "| {:^30} | {:^10} | {:^11} | {:^60} |",
            "Date/Time", "Protocol", "Size", "Details"
        )
    };
    (separator) => {
        println!(
            "| {:-^30} | {:-^10} | {:-^11} | {:-^60} |",
            "--", "--", "--", "--"
        )
    };
    ($proto:expr, $len:expr, $msg:expr) => {{
        let now = jiff::Timestamp::now().to_string();
        println!(
            "| {now:<30} | {:<10} | {:>5} bytes | {:<60} |",
            $proto, $len, $msg
        )
    }};
}

#[allow(unused)]
macro_rules! build_netflow {
    (ipv4/tcp, $data:expr) => {{
        let l4 = NetflowL4Protocol::Tcp {
            src_port: u16::from_be_bytes([$data[20], $data[21]]),
            dst_port: u16::from_be_bytes([$data[22], $data[23]]),
            flags: $data[13],
        };

        build_netflow!(ipv4, l4, $data)
    }};

    (ipv4/udp, $data:expr) => {{
        let l4 = NetflowL4Protocol::Udp {
            src_port: u16::from_be_bytes([$data[20], $data[21]]),
            dst_port: u16::from_be_bytes([$data[22], $data[23]]),
        };

        build_netflow!(ipv4, l4, $data)
    }};

    (ipv4, $l4:expr, $data:expr) => {{
        let l3 = NetflowL3Protocol::Ipv4 {
            src_ip: Ipv4Addr::new($data[12], $data[13], $data[14], $data[15]),
            dst_ip: Ipv4Addr::new($data[16], $data[17], $data[18], $data[19]),
            proto: $l4,
        };

        NetflowRecord {
            ts: jiff::Timestamp::now(),
            size: $data.len(),
            protocol: l3,
        }
    }};
}

#[derive(Debug, Deserialize, Serialize)]
enum NetflowL4Protocol {
    Tcp {
        src_port: u16,
        dst_port: u16,
        flags: u8,
    },
    Udp {
        src_port: u16,
        dst_port: u16,
    },
}

#[derive(Debug, Deserialize, Serialize)]
enum NetflowL3Protocol {
    Ipv4 {
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        proto: NetflowL4Protocol,
    },
    Arp4 {
        sha: MacAddress,
        spa: Ipv4Addr,
        tha: MacAddress,
        tpa: Ipv4Addr,
    },
}

/// Represents a netflow record
#[derive(Debug, Deserialize, Serialize)]
struct NetflowRecord {
    ts: Timestamp,
    size: usize,
    protocol: NetflowL3Protocol,
}

pub fn handle_pcap<P: AsRef<Path>>(tap: P) -> anyhow::Result<()> {
    let tap_path = tap.as_ref();
    tracing::debug!(tap = %tap_path.display(), "binding tap socket");

    let mut poller = Poller::new(10, &[Signal::SIGINT, Signal::SIGTERM])?;
    let mut tap = UnixDatagram::bind(&tap_path)?;

    let tap_token = poller.register_read(&mut tap)?;

    print_netflow!(separator);
    print_netflow!(header);
    print_netflow!(separator);

    let mut buf = [0u8; 4096];
    'poll: loop {
        let mut should_quit = false;
        poller.poll(
            |event| {
                match event.token() {
                    token if token == tap_token => {
                        handle_pcap_read(&mut tap, &mut buf)?;
                    }
                    _ => (),
                }

                Ok(())
            },
            |signal| {
                match signal {
                    Signal::SIGINT | Signal::SIGTERM => should_quit = true,
                    _ => (),
                }
                Ok(())
            },
        )?;

        if should_quit {
            break 'poll;
        }
    }

    drop(tap);
    tracing::debug!(tap = %tap_path.display(), "unbinding tap socket");
    std::fs::remove_file(tap_path).ok();

    Ok(())
}

fn handle_pcap_read(tap: &mut UnixDatagram, buf: &mut [u8]) -> anyhow::Result<()> {
    // tap is a non-blocking socket, read until EWOULDBLOCK
    loop {
        let (sz, _peer) = match tap.recv_from(buf) {
            Ok((sz, peer)) => (sz, peer),
            Err(error) if error.kind() == ErrorKind::WouldBlock => {
                return Ok(());
            }
            Err(error) => Err(error)?,
        };
        tracing::trace!("[netflow] read {sz} bytes");

        if buf.len() < 14 {
            tracing::debug!(
                "[netflow] skipping packet, too small. got {} bytes, want 14 bytes",
                buf.len()
            );
            return Ok(()); // unknown ethernet frame
        }

        let ethertype = u16::from_be_bytes([buf[12], buf[13]]);
        match ethertype {
            0x0800 => handle_pcap_ipv4(&buf[14..sz])?,
            0x0806 => handle_pcap_arp(&buf[14..sz])?,
            _ => tracing::debug!("[netflow] unknown ethertype: 0x{ethertype:02x}"),
        }
    }
}

fn handle_pcap_ipv4(data: &[u8]) -> anyhow::Result<()> {
    let ipv4 = Ipv4PacketRef::new(data)?;

    // extract dst/src ip address
    let src_ip = ipv4.src();
    let dst_ip = ipv4.dst();
    let protocol = ipv4.protocol();
    let length = ipv4.len();
    let start = ipv4.header_length();

    match protocol {
        NET_PROTOCOL_TCP => {
            let tcp = TcpHeader::extract_from_slice(&data[start..])?;

            //let nf = build_netflow!(ipv4 / tcp, data);
            //tracing::debug!(?nf, "net flow");

            print_netflow!(
                "ipv4/tcp",
                length,
                format!(
                    "[{}] {src_ip}:{} --> {dst_ip}:{}",
                    tcp.flags, tcp.src_port, tcp.dst_port
                )
            );
        }
        NET_PROTOCOL_UDP => {
            let udp = UdpHeader::extract_from_slice(&data[start..])?;

            print_netflow!(
                "ipv4/udp",
                length,
                format!("{src_ip}:{} --> {dst_ip}:{}", udp.src_port, udp.dst_port)
            );
        }
        NET_PROTOCOL_ICMP => {
            let msg = match data[20] {
                0 => "echo reply",
                3 => match data[21] {
                    0 => "dst ntwk unreachable",
                    1 => "dst host unreachable",
                    2 => "dst proto unreachable",
                    3 => "dst port unreachable",
                    4 => "frag required",
                    5 => "src route failed",
                    6 => "dst ntwk unknown",
                    7 => "dst host unknown",
                    8 => "src host isolated",
                    9 => "ntwk admin prohib",
                    10 => "host admin prohib",
                    11 => "ntwk unreachable (ToS)",
                    12 => "host unreachable (ToS)",
                    13 => "comm admin prohib",
                    14 => "host precedence violation",
                    15 => "precedence cutoff",
                    _ => "?? unreachable",
                },
                4 => "source quench",
                5 => match data[22] {
                    0 => "ntwk redirect",
                    1 => "host redirect",
                    2 => "ntwk redirect (ToS)",
                    3 => "host redirect (ToS)",
                    _ => "?? redirect",
                },
                8 => "echo request",
                9 => "router advert",
                10 => "router solicit",
                _ => "reserved",
            };

            print_netflow!(
                "ipv4/icmp",
                length,
                format!("[{msg}] {src_ip} --> {dst_ip}")
            );
        }
        _ => {
            print_netflow!(
                "ipv4/????",
                length,
                format!("{src_ip} --> {dst_ip} [proto: 0x{protocol:02x}]")
            );
        }
    }

    Ok(())
}

fn handle_pcap_arp(data: &[u8]) -> anyhow::Result<()> {
    let arp = ArpPacket::parse(data)?;

    match arp.operation {
        1 /* REQUEST */ => print_netflow!("arp", data.len(), format!("who has {}? tell {}", arp.tpa, arp.spa)),
        2 /* RESPONSE */ => print_netflow!("arp", data.len(), format!("{} is at {}", arp.spa,arp.sha)),
        _ /* UNKNOWN*/ => print_netflow!("arp", data.len(), format!("unknown arp (op = 0x{:02x})", arp.operation)),
    }

    Ok(())
}
