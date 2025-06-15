use pnet::packet::icmp::{
    echo_request::MutableEchoRequestPacket, echo_reply::EchoReplyPacket, IcmpPacket,
    IcmpTypes,
};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::Packet;
use pnet::transport::{icmp_packet_iter, transport_channel, TransportChannelType, TransportProtocol};
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant, SystemTime};
use tokio::task;
use tokio::time::timeout;
use futures::stream::{FuturesUnordered, StreamExt};

use crate::models::{HostDiscoverySingleResult, HostDiscoveryAllResult};
use crate::resolving::{resolve_hostname};

pub async fn run_icmp_echo(
    ip_addresses: Result<Vec<Ipv4Addr>, String>,
) -> (Vec<HostDiscoverySingleResult>, HostDiscoveryAllResult) {
    // Start timing the operation
    let start_time = SystemTime::now();
    
    let ips = match ip_addresses {
        Ok(addresses) => addresses,
        Err(error) => {
            println!("Failed to process IP addresses: {}", error);
            return (Vec::new(), HostDiscoveryAllResult {
                scanned_addresses: Vec::new(),
                ports_per_host: 0,
                hosts_up: 0,
                hosts_dns_resolution: 0,
                start_time,
                end_time: SystemTime::now(),
                packets_sent: 0
            });
        }
    };
   
    // Create a collection of futures
    let mut futures = FuturesUnordered::new();
   
    // Convert IPs to IpAddr type for results
    let all_ips: Vec<IpAddr> = ips.iter().map(|ip| IpAddr::V4(*ip)).collect();
    
    // Add ping tasks to our collection
    for ip in ips {
        futures.push(async move {
            let (is_reachable, latency, ttl) = icmp_ping_host_with_details(&ip).await;

            let mut dns_resolve = None;

            if is_reachable {
                // Try to resolve hostname
                dns_resolve = resolve_hostname(&ip).await;
            }
            
            let host_result = HostDiscoverySingleResult {
                ip_address: IpAddr::V4(ip),
                latency,
                dns_resolve,
                is_up: is_reachable,
                reply_type: if is_reachable { "ICMP echo reply".to_string() } else { "no response".to_string() },
                ttl: ttl.unwrap_or(0)
            };
            
            host_result
        });
    }
   
    // Collect all results
    let mut host_results = Vec::new();
    while let Some(result) = futures.next().await {
        host_results.push(result);
    }
   
    // Calculate stats for the summary
    let hosts_up = host_results.iter().filter(|r| r.is_up).count() as u64;
    let hosts_dns_resolution = host_results.iter().filter(|r| r.dns_resolve.is_some()).count() as u64;
    
    let end_time = SystemTime::now();
    
    // Create the summary result
    let summary = HostDiscoveryAllResult {
        scanned_addresses: all_ips,
        ports_per_host: 0,
        hosts_up,
        hosts_dns_resolution,
        start_time,
        end_time,
        packets_sent: host_results.len() as u64
    };
    
    (host_results, summary)
}

/// Asynchronously pings a host using ICMP echo requests.
/// Ping a host using raw ICMP echo request and return reachability, latency, and TTL.
async fn icmp_ping_host_with_details(ip: &Ipv4Addr) -> (bool, Option<Duration>, Option<u8>) {
    let ip = *ip;
    let task = task::spawn_blocking(move || {

        let protocol = TransportChannelType::Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Icmp));
        let (mut tx, mut rx) = match transport_channel(1024, protocol) {
            Ok(channels) => channels,
            Err(e) => {
                eprintln!("Failed to create transport channel: {}", e);
                return (false, None, None);
            }
        };

        let mut packet_buffer = [0u8; 64];
        let mut echo_packet = match MutableEchoRequestPacket::new(&mut packet_buffer) {
            Some(packet) => packet,
            None => {
                eprintln!("Failed to create echo request packet");
                return (false, None, None);
            }
        };

        echo_packet.set_icmp_type(IcmpTypes::EchoRequest);
        echo_packet.set_icmp_code(pnet::packet::icmp::IcmpCode(0));

        let identifier: u16 = 0x1234;
        echo_packet.set_identifier(identifier);
        echo_packet.set_sequence_number(1);
        let payload_data = vec![0u8; 32];
        echo_packet.set_payload(&payload_data);

        let checksum = pnet::packet::icmp::checksum(
            &IcmpPacket::new(echo_packet.packet()).unwrap(),
        );
        echo_packet.set_checksum(checksum);

        let destination = std::net::IpAddr::V4(ip);
        let start = Instant::now();

        if let Err(e) = tx.send_to(echo_packet, destination) {
            eprintln!("Failed to send echo request: {}", e);
            return (false, None, None);
        }

        let mut iter = icmp_packet_iter(&mut rx);
        let timeout_duration = Duration::from_secs(2);
        let deadline = Instant::now() + timeout_duration;

        while Instant::now() < deadline {
            match iter.next() {
                Ok((packet, addr)) => {
                    if addr == destination && packet.get_icmp_type() == IcmpTypes::EchoReply {
                        if let Some(reply) = EchoReplyPacket::new(packet.packet()) {
                            if reply.get_identifier() == identifier {
                                let latency = start.elapsed();
                                let ttl = crate::resolving::extract_ttl(&String::from_utf8_lossy(packet.packet()));
                                return (true, Some(latency), ttl);
                            }
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Error receiving packet: {:?}", e);
                    return (false, None, None);
                }
            }
        }

        (false, None, None)
    });

    match timeout(Duration::from_secs(3), task).await {
        Ok(Ok(result)) => result,
        Ok(Err(e)) => {
            eprintln!("Join error in ICMP task: {:?}", e);
            (false, None, None)
        }
        Err(_) => {
            eprintln!("ICMP echo request timed out (hard timeout)");
            (false, None, None)
        }
    }
}
