use pnet::packet::icmp::{echo_request::MutableEchoRequestPacket, IcmpTypes, IcmpCode};
use pnet::packet::icmp::{echo_reply::EchoReplyPacket, IcmpPacket};
use pnet::packet::Packet;
use pnet::transport::{icmp_packet_iter, transport_channel, TransportChannelType, TransportProtocol};
use pnet::packet::ip::IpNextHeaderProtocols;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Instant;

pub fn run_icmp_echo() {
    let protocol = TransportChannelType::Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Icmp));

    let (mut tx, mut rx) = transport_channel(1024, protocol).expect("Failed to create transport channel");

    let mut packet_buffer = [0u8; 64];

    let mut echo_packet = MutableEchoRequestPacket::new(&mut packet_buffer).expect("Failed to create echo request packet");

    echo_packet.set_icmp_type(IcmpTypes::EchoRequest);
    echo_packet.set_icmp_code(IcmpCode(0));

    let identifier: u16 = 0x1234;
    echo_packet.set_identifier(identifier);
    echo_packet.set_sequence_number(1);

    let payload_data = vec![0u8; 32];
    echo_packet.set_payload(&payload_data);

    let checksum = pnet::packet::icmp::checksum(&IcmpPacket::new(echo_packet.packet()).unwrap());
    echo_packet.set_checksum(checksum);

    let destination = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

    let start_time = Instant::now();

    tx.send_to(echo_packet, destination).expect("Failed to send echo request");

    let mut iter = icmp_packet_iter(&mut rx);

    loop {
        match iter.next() {
            Ok((packet, addr)) => {
                if let Some(echo_reply) = EchoReplyPacket::new(packet.packet()) {
                    if addr == destination && packet.get_icmp_type() == IcmpTypes::EchoReply {
                        if echo_reply.get_identifier() == identifier {
                            println!(
                                "Received ICMP echo reply from {} in {:?} ms",
                                addr,
                                start_time.elapsed().as_millis()
                            );
                            break;
                        }
                    }
                }
            }
            Err(e) => {
                eprintln!("An error occured while receiving packet: {:?}", e);
            }
        }
    }
}