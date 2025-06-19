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
/// Should return Result
pub async fn run_icmp_echo(
    ip_addresses: Result<Vec<Ipv4Addr>, String>,
) -> Result<(Vec<HostDiscoverySingleResult>, HostDiscoveryAllResult), String> {
    // Start timing the entire scan operation.
    let start_time = SystemTime::now();

    let ips = ip_addresses?; // Propagate the error if initial IP address processing failed.

    // Use of FuturesUnordered to manage multiple concurrent ping tasks.
    let mut futures = FuturesUnordered::new();

    // Collect all IPs for the final summary report.
    let all_ips: Vec<IpAddr> = ips.iter().map(|ip| IpAddr::V4(*ip)).collect();

    // Create and spawn a ping task for each IP address.
    for ip in ips {
        futures.push(async move {
            let icmp_result = icmp_ping_host_with_details(&ip).await;

            let mut dns_resolve = None;
            let mut is_reachable = false;
            let mut latency = None;
            let mut ttl = 0;
            let mut reply_type = "no response".to_string();

            match icmp_result {
                Ok((reachable, lat, received_ttl)) => {
                    is_reachable = reachable;
                    latency = lat;
                    ttl = received_ttl.unwrap_or(0);
                    if is_reachable {
                        reply_type = "ICMP echo reply".to_string();
                        // Only attempt DNS resolution for hosts that responded.
                        dns_resolve = resolve_hostname(&ip).await;
                    }
                }
                Err(e) => {
                    // An error occurred during the ICMP ping (e.g., permission denied, socket error).
                    // This host is considered not up due to the error.
                    reply_type = format!("Error: {}", e);
                    // is_reachable remains false, latency and ttl remain None/0
                }
            }

            HostDiscoverySingleResult {
                ip_address: IpAddr::V4(ip),
                latency,
                dns_resolve,
                is_up: is_reachable,
                reply_type,
                ttl,
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
        packets_sent: host_results.len() as u64,
    };

    Ok((host_results, summary))
}

/// Sends a single ICMP echo request to a host and waits for a reply.
///
/// This function performs the low-level work of creating a raw socket,
/// constructing an ICMP packet, sending it, and listening for a valid reply.
///
/// # Returns (Should return result)
/// A tuple: `(is_reachable, latency, ttl)`.
async fn icmp_ping_host_with_details(ip: &Ipv4Addr) -> Result<(bool, Option<Duration>, Option<u8>), String> {
    let ip = *ip;

    let task = task::spawn_blocking(move || {
        // Layer 4 protocol channel for ICMP.
        let protocol = TransportChannelType::Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Icmp));
        let (mut tx, mut rx) = match transport_channel(1024, protocol) {
            Ok(channels) => channels,
            Err(e) => {
                // For Permissions errors.
                let error_msg = format!("Failed to create transport channel for {}: {}. Try running with sudo.", ip, e);
                eprintln!("{}", error_msg);
                return Err(error_msg);
            }
        };

        let mut packet_buffer = [0u8; 64];
        let mut echo_packet = MutableEchoRequestPacket::new(&mut packet_buffer)
            .ok_or_else(|| "Failed to create mutable echo request packet. The buffer might be too small.".to_string())?;

        // Manually construct the ICMP Echo Request packet.
        echo_packet.set_icmp_type(IcmpTypes::EchoRequest);
        echo_packet.set_icmp_code(pnet::packet::icmp::IcmpCode(0));
        let identifier: u16 = rand::random();
        echo_packet.set_identifier(identifier);
        echo_packet.set_sequence_number(1);
        let payload_data = vec![0u8; 32];
        echo_packet.set_payload(&payload_data);

        // ICMP checksum is mandatory.
        let checksum = pnet::packet::icmp::checksum(&IcmpPacket::new(echo_packet.packet())
            .ok_or_else(|| "Failed to create an immutable ICMP packet view for checksum calculation.".to_string())?);
        echo_packet.set_checksum(checksum);

        let destination = IpAddr::V4(ip);
        let start_time = Instant::now();

        if let Err(e) = tx.send_to(echo_packet, destination) {
            let error_msg = format!("Failed to send echo request to {}: {}", ip, e);
            eprintln!("{}", error_msg);
            return Err(error_msg);
        }

        // Create an iterator to process incoming ICMP packets.
        let mut iter = icmp_packet_iter(&mut rx);
        let timeout_duration = Duration::from_secs(2);

        match iter.next_with_timeout(timeout_duration) {
            Ok(Some((packet, addr))) => {
                if addr == destination && packet.get_icmp_type() == IcmpTypes::EchoReply {
                    if let Some(reply) = EchoReplyPacket::new(packet.packet()) {
                        if reply.get_identifier() == identifier {
                            let latency = start_time.elapsed();
                            let ttl = Ipv4Packet::new(packet.packet()).map(|p| p.get_ttl());
                            return Ok((true, Some(latency), ttl));
                        }
                    }
                }
                // If it's a reply but not matching destination/type/identifier
                Err(format!("Received unexpected ICMP reply from {}.", addr))
            }
            Ok(None) => {
                // Timeout occurred, host is considered down
                Ok((false, None, None))
            }
            Err(e) => {
                let error_msg = format!("Error receiving packet from {}: {:?}", ip, e);
                eprintln!("{}", error_msg);
                Err(error_msg)
            }
        }
    });

    // A secondary, hard timeout on the entire task.
    match timeout(Duration::from_secs(3), task).await {
        Ok(Ok(result)) => result, // This is the Result<(bool, Option<Duration>, Option<u8>), String> from the spawned_blocking task
        Ok(Err(e)) => {
            // Error originated from the spawned_blocking task itself
            let error_msg = format!("ICMP task failed for {}: {}", ip, e);
            eprintln!("{}", error_msg);
            Err(error_msg)
        }
        Err(_) => {
            // This triggers if spawn_blocking itself times out.
            let error_msg = format!("ICMP ping task timed out for {}", ip);
            eprintln!("{}", error_msg);
            Err(error_msg)
        }
    }
}