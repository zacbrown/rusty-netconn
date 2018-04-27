extern crate pcap;
extern crate pnet;
extern crate prettytable;

use prettytable::Table;
use prettytable::row::Row;
use prettytable::cell::Cell;

use pnet::packet::Packet;
use pnet::packet::arp::ArpPacket;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::icmpv6::Icmpv6Packet;
use pnet::packet::icmp::{echo_reply, echo_request, IcmpPacket, IcmpTypes};
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;

use std::collections::HashMap;
use std::net::IpAddr;

macro_rules! debug_println {
    () => (if cfg!(debug_assertions) { print!("\n") });
    ($fmt:expr) => (if cfg!(debug_assertions) { print!(concat!($fmt, "\n")) });
    ($fmt:expr, $($arg:tt)*) => (if cfg!(debug_assertions) { print!(concat!($fmt, "\n"), $($arg)*) });
}

fn main() {
    let mut dest_stats: DestinationStatsMap = HashMap::new();
    let main_device = pcap::Device::lookup().unwrap();
    let mut cap = pcap::Capture::from_device(main_device).unwrap()
        .timeout(100)
        .open().unwrap();

    let mut count = 0;

    loop {
        match cap.next() {
            Ok(p) => handle_packet(&mut dest_stats, p),
            Err(e) => handle_error(e)
        }

        count += 1;

        if count % 100000 == 0 {
            let mut table = Table::new();
            table.add_row(Row::new(vec![Cell::new("dest ip"),
                                        Cell::new("tcp bytes"),
                                        Cell::new("udp bytes"),
                                        Cell::new("icmp reqs")]));

            for (ip, stat) in &dest_stats {
                table.add_row(Row::new(vec![Cell::new(&ip.to_string()),
                              Cell::new(&stat.tcp_total_bytes.to_string()),
                              Cell::new(&stat.udp_total_bytes.to_string()),
                              Cell::new(&stat.icmp_count_reqs.to_string())]));
            }
            table.printstd();
            println!();
            count = 0;
        }
    }
}

fn handle_packet(dest_stats: &mut DestinationStatsMap, packet: pcap::Packet) {
    let ethernet = EthernetPacket::new(&packet.data).unwrap();
    let interface_name = "sample0";

    match ethernet.get_ethertype() {
        EtherTypes::Ipv4 => handle_ipv4_packet(dest_stats, interface_name, &ethernet),
        EtherTypes::Ipv6 => handle_ipv6_packet(dest_stats, interface_name, &ethernet),
        EtherTypes::Arp => handle_arp_packet(interface_name, &ethernet),
        _ => {
            println!(
                "[{}]: Unknown packet: {} > {}; ethertype: {:?} length: {}",
                interface_name,
                ethernet.get_source(),
                ethernet.get_destination(),
                ethernet.get_ethertype(),
                ethernet.packet().len()
            )
        }
    }
}

fn handle_error(error: pcap::Error) {
    match error {
        pcap::Error::TimeoutExpired => {},
        _ => println!("ERROR: {:?}", error)
    }
}

#[derive(Debug, Clone)]
struct DestinationStats {
    udp_total_bytes: usize,
    tcp_total_bytes: usize,
    icmp_count_reqs: usize,
}

impl DestinationStats {
    fn add_udp(&mut self, bytes: usize) {
        self.udp_total_bytes += bytes;
    }

    fn add_tcp(&mut self, bytes: usize) {
        self.tcp_total_bytes += bytes;
    }

    fn add_icmp(&mut self, count: usize) {
        self.icmp_count_reqs += count;
    }
}

type DestinationStatsMap = HashMap<IpAddr, DestinationStats>;

fn handle_udp_packet(dest_stats: &mut DestinationStatsMap, interface_name: &str, source: IpAddr, destination: IpAddr, packet: &[u8]) {
    let udp = UdpPacket::new(packet);

    if let Some(udp) = udp {
        debug_println!("[{}]: UDP Packet: {}:{} > {}:{}; length: {}",
                 interface_name,
                 source,
                 udp.get_source(),
                 destination,
                 udp.get_destination(),
                 udp.get_length());

        let mut stats = {
            match dest_stats.get(&destination) {
                Some(stats) => {
                    let mut new_stats = stats.clone();
                    new_stats.add_udp(udp.get_length() as usize);
                    new_stats
                },
                None => {
                    DestinationStats {
                        udp_total_bytes: udp.get_length() as usize,
                        tcp_total_bytes: 0,
                        icmp_count_reqs: 0,
                    }
                }
            }
        };

        dest_stats.insert(destination, stats);
    } else {
        println!("[{}]: Malformed UDP Packet", interface_name);
    }
}

fn handle_icmp_packet(dest_stats: &mut DestinationStatsMap, interface_name: &str, source: IpAddr, destination: IpAddr, packet: &[u8]) {
    let icmp_packet = IcmpPacket::new(packet);
    if let Some(icmp_packet) = icmp_packet {
        match icmp_packet.get_icmp_type() {
            IcmpTypes::EchoReply => {
                let echo_reply_packet = echo_reply::EchoReplyPacket::new(packet).unwrap();
                debug_println!("[{}]: ICMP echo reply {} -> {} (seq={:?}, id={:?})",
                         interface_name,
                         source,
                         destination,
                         echo_reply_packet.get_sequence_number(),
                         echo_reply_packet.get_identifier());
            }
            IcmpTypes::EchoRequest => {
                let echo_request_packet = echo_request::EchoRequestPacket::new(packet).unwrap();
                debug_println!("[{}]: ICMP echo request {} -> {} (seq={:?}, id={:?})",
                         interface_name,
                         source,
                         destination,
                         echo_request_packet.get_sequence_number(),
                         echo_request_packet.get_identifier());
            }
            _ => {
                debug_println!("[{}]: ICMP packet {} -> {} (type={:?})",
                         interface_name,
                         source,
                         destination,
                         icmp_packet.get_icmp_type())
            }
        }

        let mut stats = {
            match dest_stats.get(&destination) {
                Some(stats) => {
                    let mut new_stats = stats.clone();
                    new_stats.add_icmp(1 as usize);
                    new_stats
                },
                None => {
                    DestinationStats {
                        udp_total_bytes: 0,
                        tcp_total_bytes: 0,
                        icmp_count_reqs: 1,
                    }
                }
            }
        };

        dest_stats.insert(destination, stats);
    } else {
        println!("[{}]: Malformed ICMP Packet", interface_name);
    }
}

fn handle_icmpv6_packet(dest_stats: &mut DestinationStatsMap, interface_name: &str, source: IpAddr, destination: IpAddr, packet: &[u8]) {
    let icmpv6_packet = Icmpv6Packet::new(packet);
    if let Some(icmpv6_packet) = icmpv6_packet {
        debug_println!(
            "[{}]: ICMPv6 packet {} -> {} (type={:?})",
            interface_name,
            source,
            destination,
            icmpv6_packet.get_icmpv6_type()
        );

        let mut stats = {
            match dest_stats.get(&destination) {
                Some(stats) => {
                    let mut new_stats = stats.clone();
                    new_stats.add_icmp(1 as usize);
                    new_stats
                },
                None => {
                    DestinationStats {
                        udp_total_bytes: 0,
                        tcp_total_bytes: 0,
                        icmp_count_reqs: 1,
                    }
                }
            }
        };

        dest_stats.insert(destination, stats);
    } else {
        println!("[{}]: Malformed ICMPv6 Packet", interface_name);
    }
}

fn handle_tcp_packet(dest_stats: &mut DestinationStatsMap, interface_name: &str, source: IpAddr, destination: IpAddr, packet: &[u8]) {
    let tcp = TcpPacket::new(packet);
    if let Some(tcp) = tcp {
        debug_println!("[{}]: TCP Packet: {}:{} > {}:{}; length: {}",
                 interface_name,
                 source,
                 tcp.get_source(),
                 destination,
                 tcp.get_destination(),
                 packet.len());

        let mut stats = {
            match dest_stats.get(&destination) {
                Some(stats) => {
                    let mut new_stats = stats.clone();
                    new_stats.add_tcp(packet.len() as usize);
                    new_stats
                },
                None => {
                    DestinationStats {
                        udp_total_bytes: 0,
                        tcp_total_bytes: packet.len(),
                        icmp_count_reqs: 0,
                    }
                }
            }
        };

        dest_stats.insert(destination, stats);
    } else {
        println!("[{}]: Malformed TCP Packet", interface_name);
    }
}

fn handle_transport_protocol(dest_stats: &mut DestinationStatsMap,
                             interface_name: &str,
                             source: IpAddr,
                             destination: IpAddr,
                             protocol: IpNextHeaderProtocol,
                             packet: &[u8]) {
    match protocol {
        IpNextHeaderProtocols::Udp => {
            handle_udp_packet(dest_stats, interface_name, source, destination, packet)
        }
        IpNextHeaderProtocols::Tcp => {
            handle_tcp_packet(dest_stats, interface_name, source, destination, packet)
        }
        IpNextHeaderProtocols::Icmp => {
            handle_icmp_packet(dest_stats, interface_name, source, destination, packet)
        }
        IpNextHeaderProtocols::Icmpv6 => {
            handle_icmpv6_packet(dest_stats, interface_name, source, destination, packet)
        }
        _ => {
            println!("[{}]: Unknown {} packet: {} > {}; protocol: {:?} length: {}",
                     interface_name,
                     match source {
                         IpAddr::V4(..) => "IPv4",
                         _ => "IPv6",
                     },
                     source,
                     destination,
                     protocol,
                     packet.len())
        }

    }
}

fn handle_ipv4_packet(dest_stats: &mut DestinationStatsMap, interface_name: &str, ethernet: &EthernetPacket) {
    let header = Ipv4Packet::new(ethernet.payload());
    if let Some(header) = header {
        handle_transport_protocol(dest_stats,
                                  interface_name,
                                  IpAddr::V4(header.get_source()),
                                  IpAddr::V4(header.get_destination()),
                                  header.get_next_level_protocol(),
                                  header.payload());
    } else {
        println!("[{}]: Malformed IPv4 Packet", interface_name);
    }
}

fn handle_ipv6_packet(dest_stats: &mut DestinationStatsMap, interface_name: &str, ethernet: &EthernetPacket) {
    let header = Ipv6Packet::new(ethernet.payload());
    if let Some(header) = header {
        handle_transport_protocol(dest_stats,
                                  interface_name,
                                  IpAddr::V6(header.get_source()),
                                  IpAddr::V6(header.get_destination()),
                                  header.get_next_header(),
                                  header.payload());
    } else {
        println!("[{}]: Malformed IPv6 Packet", interface_name);
    }
}

fn handle_arp_packet(interface_name: &str, ethernet: &EthernetPacket) {
    let header = ArpPacket::new(ethernet.payload());
    if let Some(header) = header {
        debug_println!("[{}]: ARP packet: {}({}) > {}({}); operation: {:?}",
                 interface_name,
                 ethernet.get_source(),
                 header.get_sender_proto_addr(),
                 ethernet.get_destination(),
                 header.get_target_proto_addr(),
                 header.get_operation());
    } else {
        println!("[{}]: Malformed ARP Packet", interface_name);
    }
}