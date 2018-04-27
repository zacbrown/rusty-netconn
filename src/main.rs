extern crate pcap;
extern crate pnet;

use pnet::datalink::{self, NetworkInterface};

use pnet::packet::Packet;
use pnet::packet::arp::ArpPacket;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::icmpv6::Icmpv6Packet;
use pnet::packet::icmp::{echo_reply, echo_request, IcmpPacket, IcmpTypes};
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::util::MacAddr;

use std::env;
use std::io::{self, Write};
use std::process;
use std::net::IpAddr;

fn main() {
    let main_device = pcap::Device::lookup().unwrap();
    let mut cap = pcap::Capture::from_device(main_device).unwrap()
        .timeout(100)
        .open().unwrap();

    loop {
        match cap.next() {
            Ok(p) => handle_packet(p),
            Err(e) => handle_error(e)
        }
    }
}

fn handle_packet(packet: pcap::Packet) {
    let ethernet = EthernetPacket::new(&packet.data).unwrap();
    let interface_name = "sample0";

    match ethernet.get_ethertype() {
        EtherTypes::Ipv4 => handle_ipv4_packet(interface_name, &ethernet),
        EtherTypes::Ipv6 => handle_ipv6_packet(interface_name, &ethernet),
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

fn handle_udp_packet(interface_name: &str, source: IpAddr, destination: IpAddr, packet: &[u8]) {
    let udp = UdpPacket::new(packet);

    if let Some(udp) = udp {
        println!("[{}]: UDP Packet: {}:{} > {}:{}; length: {}",
                 interface_name,
                 source,
                 udp.get_source(),
                 destination,
                 udp.get_destination(),
                 udp.get_length());
    } else {
        println!("[{}]: Malformed UDP Packet", interface_name);
    }
}

fn handle_icmp_packet(interface_name: &str, source: IpAddr, destination: IpAddr, packet: &[u8]) {
    let icmp_packet = IcmpPacket::new(packet);
    if let Some(icmp_packet) = icmp_packet {
        match icmp_packet.get_icmp_type() {
            IcmpTypes::EchoReply => {
                let echo_reply_packet = echo_reply::EchoReplyPacket::new(packet).unwrap();
                println!("[{}]: ICMP echo reply {} -> {} (seq={:?}, id={:?})",
                         interface_name,
                         source,
                         destination,
                         echo_reply_packet.get_sequence_number(),
                         echo_reply_packet.get_identifier());
            }
            IcmpTypes::EchoRequest => {
                let echo_request_packet = echo_request::EchoRequestPacket::new(packet).unwrap();
                println!("[{}]: ICMP echo request {} -> {} (seq={:?}, id={:?})",
                         interface_name,
                         source,
                         destination,
                         echo_request_packet.get_sequence_number(),
                         echo_request_packet.get_identifier());
            }
            _ => {
                println!("[{}]: ICMP packet {} -> {} (type={:?})",
                         interface_name,
                         source,
                         destination,
                         icmp_packet.get_icmp_type())
            }
        }
    } else {
        println!("[{}]: Malformed ICMP Packet", interface_name);
    }
}

fn handle_icmpv6_packet(interface_name: &str, source: IpAddr, destination: IpAddr, packet: &[u8]) {
    let icmpv6_packet = Icmpv6Packet::new(packet);
    if let Some(icmpv6_packet) = icmpv6_packet {
        println!(
            "[{}]: ICMPv6 packet {} -> {} (type={:?})",
            interface_name,
            source,
            destination,
            icmpv6_packet.get_icmpv6_type()
        )
    } else {
        println!("[{}]: Malformed ICMPv6 Packet", interface_name);
    }
}

fn handle_tcp_packet(interface_name: &str, source: IpAddr, destination: IpAddr, packet: &[u8]) {
    let tcp = TcpPacket::new(packet);
    if let Some(tcp) = tcp {
        println!("[{}]: TCP Packet: {}:{} > {}:{}; length: {}",
                 interface_name,
                 source,
                 tcp.get_source(),
                 destination,
                 tcp.get_destination(),
                 packet.len());
    } else {
        println!("[{}]: Malformed TCP Packet", interface_name);
    }
}

fn handle_transport_protocol(interface_name: &str,
                             source: IpAddr,
                             destination: IpAddr,
                             protocol: IpNextHeaderProtocol,
                             packet: &[u8]) {
    match protocol {
        IpNextHeaderProtocols::Udp => {
            handle_udp_packet(interface_name, source, destination, packet)
        }
        IpNextHeaderProtocols::Tcp => {
            handle_tcp_packet(interface_name, source, destination, packet)
        }
        IpNextHeaderProtocols::Icmp => {
            handle_icmp_packet(interface_name, source, destination, packet)
        }
        IpNextHeaderProtocols::Icmpv6 => {
            handle_icmpv6_packet(interface_name, source, destination, packet)
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

fn handle_ipv4_packet(interface_name: &str, ethernet: &EthernetPacket) {
    let header = Ipv4Packet::new(ethernet.payload());
    if let Some(header) = header {
        handle_transport_protocol(interface_name,
                                  IpAddr::V4(header.get_source()),
                                  IpAddr::V4(header.get_destination()),
                                  header.get_next_level_protocol(),
                                  header.payload());
    } else {
        println!("[{}]: Malformed IPv4 Packet", interface_name);
    }
}

fn handle_ipv6_packet(interface_name: &str, ethernet: &EthernetPacket) {
    let header = Ipv6Packet::new(ethernet.payload());
    if let Some(header) = header {
        handle_transport_protocol(interface_name,
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
        println!("[{}]: ARP packet: {}({}) > {}({}); operation: {:?}",
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