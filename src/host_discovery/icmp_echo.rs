use pnet::packet::icmp::{
    echo_request::MutableEchoRequestPacket, echo_reply::EchoReplyPacket, IcmpPacket,
    IcmpTypes,
};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet; // Added for TTL extraction
use pnet::packet::Packet;
use pnet::transport::{icmp_packet_iter, transport_channel, TransportChannelType, TransportProtocol};
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant, SystemTime};
use tokio::task;
use tokio::time::timeout;
use futures::stream::{FuturesUnordered, StreamExt};

use crate::models::{HostDiscoverySingleResult, HostDiscoveryAllResult};
use crate::resolving::{resolve_hostname};

/// Runs an ICMP echo (ping) scan against a list of target IP addresses.
///
/// This function takes a list of IPv4 addresses, sends a single ICMP echo request
/// to each one concurrently, and collects the results. It returns a tuple containing
/// a vector of detailed results for each host and a summary of the entire scan.
pub async fn run_icmp_echo(
    ip_addresses: Result<Vec<Ipv4Addr>, String>,
) -> (Vec<HostDiscoverySingleResult>, HostDiscoveryAllResult) {
    // Start timing the entire scan operation.
    let start_time = SystemTime::now();

    let ips = match ip_addresses {
        Ok(addresses) => addresses,
        Err(error) => {
            // If the initial IP address processing failed, return early.
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

    // Use FuturesUnordered to manage multiple concurrent ping tasks.
    let mut futures = FuturesUnordered::new();

    // Collect all IPs for the final summary report.
    let all_ips: Vec<IpAddr> = ips.iter().map(|ip| IpAddr::V4(*ip)).collect();

    // Create and spawn a ping task for each IP address.
    for ip in ips {
        futures.push(async move {
            let (is_reachable, latency, ttl) = icmp_ping_host_with_details(&ip).await;

            let mut dns_resolve = None;
            // Only attempt DNS resolution for hosts that responded.
            if is_reachable {
                dns_resolve = resolve_hostname(&ip).await;
            }

            HostDiscoverySingleResult {
                ip_address: IpAddr::V4(ip),
                latency,
                dns_resolve,
                is_up: is_reachable,
                reply_type: if is_reachable { "ICMP echo reply".to_string() } else { "no response".to_string() },
                ttl: ttl.unwrap_or(0),
            }
        });
    }

    // Wait for all the ping tasks to complete and collect their results.
    let mut host_results = Vec::new();
    while let Some(result) = futures.next().await {
        host_results.push(result);
    }

    // Calculate summary statistics from the collected results.
    let hosts_up = host_results.iter().filter(|r| r.is_up).count() as u64;
    let hosts_dns_resolution = host_results.iter().filter(|r| r.dns_resolve.is_some()).count() as u64;
    let end_time = SystemTime::now();

    let summary = HostDiscoveryAllResult {
        scanned_addresses: all_ips,
        ports_per_host: 0, // Not applicable for ICMP scan.
        hosts_up,
        hosts_dns_resolution,
        start_time,
        end_time,
        packets_sent: host_results.len() as u64
    };

    (host_results, summary)
}

/// Sends a single ICMP echo request to a host and waits for a reply.
///
/// This function performs the low-level work of creating a raw socket,
/// constructing an ICMP packet, sending it, and listening for a valid reply.
///
/// # Returns
/// A tuple: `(is_reachable, latency, ttl)`.
async fn icmp_ping_host_with_details(ip: &Ipv4Addr) -> (bool, Option<Duration>, Option<u8>) {
    let ip = *ip;
    // The pnet transport channel uses blocking I/O, so we run it in a blocking-safe thread
    // to avoid starving the async runtime.
    let task = task::spawn_blocking(move || {
        // Layer 4 protocol channel for ICMP.
        let protocol = TransportChannelType::Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Icmp));
        let (mut tx, mut rx) = match transport_channel(1024, protocol) {
            Ok(channels) => channels,
            Err(e) => {
                // Permissions errors (e.g., not running as root) are common here.
                eprintln!("Failed to create transport channel for {}: {}. Try running with sudo.", ip, e);
                return (false, None, None);
            }
        };

        // Allocate a buffer for our packet.
        let mut packet_buffer = [0u8; 64];
        let mut echo_packet = MutableEchoRequestPacket::new(&mut packet_buffer)
            .expect("Failed to create mutable echo request packet. The buffer might be too small.");

        // Manually construct the ICMP Echo Request packet.
        echo_packet.set_icmp_type(IcmpTypes::EchoRequest);
        echo_packet.set_icmp_code(pnet::packet::icmp::IcmpCode(0));
        // Use a fixed identifier to filter replies meant for us.
        let identifier: u16 = rand::random();
        echo_packet.set_identifier(identifier);
        echo_packet.set_sequence_number(1);
        // The payload can be anything; size matters more than content.
        let payload_data = vec![0u8; 32];
        echo_packet.set_payload(&payload_data);

        // The ICMP checksum is mandatory.
        let checksum = pnet::packet::icmp::checksum(&IcmpPacket::new(echo_packet.packet())
            .expect("Failed to create an immutable ICMP packet view for checksum calculation."));
        echo_packet.set_checksum(checksum);

        let destination = IpAddr::V4(ip);
        let start_time = Instant::now();

        if let Err(e) = tx.send_to(echo_packet, destination) {
            eprintln!("Failed to send echo request to {}: {}", ip, e);
            return (false, None, None);
        }

        // Create an iterator to process incoming ICMP packets.
        let mut iter = icmp_packet_iter(&mut rx);
        let timeout_duration = Duration::from_secs(2);

        // This loop waits for a reply, with an internal timeout.
        match iter.next_with_timeout(timeout_duration) {
            Ok(Some((packet, addr))) => {
                // Ensure the reply is from the correct IP.
                if addr == destination && packet.get_icmp_type() == IcmpTypes::EchoReply {
                    if let Some(reply) = EchoReplyPacket::new(packet.packet()) {
                        // Ensure it's a reply to our specific request.
                        if reply.get_identifier() == identifier {
                            let latency = start_time.elapsed();
                            // Correctly extract TTL from the encapsulating IPv4 packet header.
                            let ttl = Ipv4Packet::new(packet.packet()).map(|p| p.get_ttl());
                            return (true, Some(latency), ttl);
                        }
                    }
                }
            }
            Ok(None) => { /* Timeout occurred, host is considered down */ },
            Err(e) => {
                eprintln!("Error receiving packet from {}: {:?}", ip, e);
            }
        }

        (false, None, None)
    });

    // A secondary, hard timeout on the entire task.
    match timeout(Duration::from_secs(3), task).await {
        Ok(Ok(result)) => result,
        Ok(Err(e)) => {
            eprintln!("Join error in ICMP task for {}: {:?}", ip, e);
            (false, None, None)
        }
        Err(_) => {
            // This triggers if spawn_blocking itself times out.
            (false, None, None)
        }
    }
}