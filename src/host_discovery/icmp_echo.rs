use pnet::packet::icmp::{
    echo_request::MutableEchoRequestPacket, echo_reply::EchoReplyPacket, IcmpCode, IcmpPacket,
    IcmpTypes,
};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::Packet;
use pnet::transport::{icmp_packet_iter, transport_channel, TransportChannelType, TransportProtocol};
use std::net::{IpAddr, Ipv4Addr};
use std::time::Instant;
use futures::stream::{FuturesUnordered, StreamExt};
use tokio::task;

pub async fn run_icmp_echo(ip_addresses: Result<Vec<Ipv4Addr>, String>) {
    let ips = match ip_addresses {
        Ok(addresses) => addresses,
        Err(error) => {
            eprintln!("Failed to process IP addresses: {}", error);
            return;
        }
    };

    let mut reachable_ips = Vec::new();
    let mut unreachable_count = 0;

    // Create a collection to hold our concurrent ping futures
    let mut futures = FuturesUnordered::new();
    for ip in ips {
        futures.push(async move {
            let reachable = icmp_ping_host(&ip).await;
            (ip, reachable)
        });
    }

    // Process results as each task completes
    while let Some((ip, is_reachable)) = futures.next().await {
        if is_reachable {
            println!("{} - REACHABLE", ip);
            reachable_ips.push(ip);
        } else {
            println!("{} - UNREACHABLE", ip);
            unreachable_count += 1;
        }
    }

    println!("\nPing scan completed.");
    println!(
        "Total: {} reachable, {} unreachable",
        reachable_ips.len(),
        unreachable_count
    );

    if !reachable_ips.is_empty() {
        println!("\nReachable IP addresses:");
        for ip in &reachable_ips {
            println!("  {}", ip);
        }
    } else {
        println!("\nNo reachable IP addresses found.");
    }
}

/// Asynchronously pings a host using ICMP echo requests.
/// This function wraps the blocking pnet operations with `tokio::task::spawn_blocking`.
async fn icmp_ping_host(ip: &Ipv4Addr) -> bool {
    // Clone the IP to move into the blocking task.
    let ip = *ip;
    let result = task::spawn_blocking(move || {
        // Set up transport channel for ICMP over IPv4.
        let protocol = TransportChannelType::Layer4(TransportProtocol::Ipv4(
            IpNextHeaderProtocols::Icmp,
        ));
        let (mut tx, mut rx) = match transport_channel(1024, protocol) {
            Ok(channels) => channels,
            Err(e) => {
                eprintln!("Failed to create transport channel: {}", e);
                return false;
            }
        };

        let mut packet_buffer = [0u8; 64];
        let mut echo_packet = match MutableEchoRequestPacket::new(&mut packet_buffer) {
            Some(packet) => packet,
            None => {
                eprintln!("Failed to create echo request packet");
                return false;
            }
        };

        // Configure the ICMP echo request fields.
        echo_packet.set_icmp_type(IcmpTypes::EchoRequest);
        echo_packet.set_icmp_code(IcmpCode(0));

        let identifier: u16 = 0x1234;
        echo_packet.set_identifier(identifier);
        echo_packet.set_sequence_number(1);
        let payload_data = vec![0u8; 32];
        echo_packet.set_payload(&payload_data);

        let checksum = pnet::packet::icmp::checksum(
            &IcmpPacket::new(echo_packet.packet()).expect("Invalid packet"),
        );
        echo_packet.set_checksum(checksum);

        let destination = IpAddr::V4(ip);
        let start_time = Instant::now();

        if let Err(e) = tx.send_to(echo_packet, destination) {
            eprintln!("Failed to send echo request: {}", e);
            return false;
        }

        // Listen for the reply.
        let mut iter = icmp_packet_iter(&mut rx);
        loop {
            match iter.next() {
                Ok((packet, addr)) => {
                    if addr == destination && packet.get_icmp_type() == IcmpTypes::EchoReply {
                        if let Some(echo_reply) = EchoReplyPacket::new(packet.packet()) {
                            if echo_reply.get_identifier() == identifier {
                                println!(
                                    "Received ICMP echo reply from {} in {:?} ms",
                                       addr,
                                    start_time.elapsed().as_millis()
                                );
                                return true;
                            }
                        }
                    }
                }
                Err(e) => {
                    eprintln!("An error occurred while receiving packet: {:?}", e);
                    return false;
                }
            }
        }
    })
    .await
    .unwrap_or(false);

    result
}