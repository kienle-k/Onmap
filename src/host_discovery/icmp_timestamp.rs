use futures::stream::{FuturesUnordered, StreamExt};
use pnet::packet::Packet;
use pnet::packet::icmp::{IcmpCode, IcmpPacket, IcmpTypes, MutableIcmpPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::transport::{
    TransportChannelType, TransportProtocol, icmp_packet_iter, transport_channel,
};
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::task;
use tokio::time::timeout;

use crate::models::{HostDiscoveryAllResult, HostDiscoverySingleResult};
use crate::resolving::resolve_hostname;

/// Runs an ICMP timestamp scan against a list of target IP addresses.
///
/// This function sends a single ICMP Timestamp Request (Type 13) to each target
/// concurrently and collects the results. It returns a tuple containing detailed
/// per-host results and a summary of the entire scan.
pub async fn run_icmp_timestamp(
    ip_addresses: Vec<Ipv4Addr>,
    timeout_override_ms: Option<u64>,
) -> Result<(Vec<HostDiscoverySingleResult>, HostDiscoveryAllResult), String> {
    let start_time = SystemTime::now();
    let ips = ip_addresses;

    let mut futures = FuturesUnordered::new();
    let all_ips: Vec<IpAddr> = ips.iter().map(|ip| IpAddr::V4(*ip)).collect();

    for ip in ips {
        futures.push(async move {
            let icmp_result = icmp_timestamp_host_with_details(&ip, timeout_override_ms).await;

            let dns_resolve = None;
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
                        reply_type = "ICMP timestamp reply".to_string();
                    }
                }
                Err(e) => {
                    reply_type = format!("Error: {}", e);
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

    let mut host_results = Vec::new();
    while let Some(result) = futures.next().await {
        host_results.push(result);
    }

    let dns_start = Instant::now();
    let dns_tasks: Vec<_> = host_results
        .iter()
        .enumerate()
        .filter_map(|(i, r)| match r.ip_address {
            IpAddr::V4(ipv4) if r.is_up => Some((i, ipv4)),
            _ => None,
        })
        .collect();
    let dns_resolved = futures::future::join_all(
        dns_tasks
            .into_iter()
            .map(|(i, ipv4)| async move { (i, resolve_hostname(&ipv4).await) }),
    )
    .await;
    for (idx, hostname) in dns_resolved {
        host_results[idx].dns_resolve = hostname;
    }
    let dns_elapsed_secs = dns_start.elapsed().as_secs_f64();

    let hosts_up = host_results.iter().filter(|r| r.is_up).count() as u64;
    let hosts_dns_resolution = host_results
        .iter()
        .filter(|r| r.dns_resolve.is_some())
        .count() as u64;
    let end_time = SystemTime::now();

    let summary = HostDiscoveryAllResult {
        scanned_addresses: all_ips,
        ports_per_host: 0,
        hosts_up,
        hosts_dns_resolution,
        start_time,
        end_time,
        packets_sent: host_results.len() as u64,
        dns_elapsed_secs,
    };

    Ok((host_results, summary))
}

fn icmp_timestamp_origin_ms() -> u32 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let millis = (now.as_secs() % 86_400) * 1_000 + u64::from(now.subsec_millis());
    millis as u32
}

/// Sends a single ICMP Timestamp Request and waits for a reply.
async fn icmp_timestamp_host_with_details(
    ip: &Ipv4Addr,
    timeout_override_ms: Option<u64>,
) -> Result<(bool, Option<Duration>, Option<u8>), String> {
    let ip = *ip;

    const DEFAULT_RECEIVE_TIMEOUT_MS: u64 = 2_000;
    const DEFAULT_OUTER_PADDING_MS: u64 = 1_000;
    let receive_timeout_ms = timeout_override_ms.unwrap_or(DEFAULT_RECEIVE_TIMEOUT_MS);
    let outer_timeout_ms = receive_timeout_ms + DEFAULT_OUTER_PADDING_MS;

    let task = task::spawn_blocking(move || {
        let protocol =
            TransportChannelType::Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Icmp));
        let (mut tx, mut rx) = match transport_channel(1024, protocol) {
            Ok(channels) => channels,
            Err(e) => {
                let error_msg = format!(
                    "Failed to create transport channel for {}: {}. Try running with sudo.",
                    ip, e
                );
                eprintln!("{}", error_msg);
                return Err(error_msg);
            }
        };

        let mut packet_buffer = [0u8; 20];
        let mut ts_packet = MutableIcmpPacket::new(&mut packet_buffer).ok_or_else(|| {
            "Failed to create mutable ICMP packet for timestamp request.".to_string()
        })?;

        ts_packet.set_icmp_type(IcmpTypes::Timestamp);
        ts_packet.set_icmp_code(IcmpCode(0));

        let identifier: u16 = rand::random();
        let sequence_number: u16 = 1;
        let originate_ts = icmp_timestamp_origin_ms();
        let mut payload: Vec<u8> = Vec::with_capacity(16);
        payload.extend_from_slice(&identifier.to_be_bytes());
        payload.extend_from_slice(&sequence_number.to_be_bytes());
        payload.extend_from_slice(&originate_ts.to_be_bytes());
        payload.extend_from_slice(&0u32.to_be_bytes());
        payload.extend_from_slice(&0u32.to_be_bytes());
        ts_packet.set_payload(&payload);

        let checksum =
            pnet::packet::icmp::checksum(&IcmpPacket::new(ts_packet.packet()).ok_or_else(
                || "Failed to create ICMP packet view for checksum calculation.".to_string(),
            )?);
        ts_packet.set_checksum(checksum);

        let destination = IpAddr::V4(ip);
        let start_time = Instant::now();

        if let Err(e) = tx.send_to(ts_packet, destination) {
            let error_msg = format!("Failed to send timestamp request to {}: {}", ip, e);
            eprintln!("{}", error_msg);
            return Err(error_msg);
        }

        let mut iter = icmp_packet_iter(&mut rx);
        let receive_start_time = Instant::now();
        let timeout_duration = Duration::from_millis(receive_timeout_ms);

        while receive_start_time.elapsed() < timeout_duration {
            let remaining_time = timeout_duration.saturating_sub(receive_start_time.elapsed());
            if remaining_time.is_zero() {
                break;
            }

            match iter.next_with_timeout(remaining_time) {
                Ok(Some((packet, addr))) => {
                    if addr == destination && packet.get_icmp_type() == IcmpTypes::TimestampReply {
                        let payload = packet.payload();
                        if payload.len() >= 4 {
                            let reply_identifier = u16::from_be_bytes([payload[0], payload[1]]);
                            let reply_sequence = u16::from_be_bytes([payload[2], payload[3]]);
                            if reply_identifier == identifier && reply_sequence == sequence_number {
                                let latency = start_time.elapsed();
                                let ttl = Ipv4Packet::new(packet.packet()).map(|p| p.get_ttl());
                                return Ok((true, Some(latency), ttl));
                            }
                        }
                    }
                }
                Ok(None) => {
                    continue;
                }
                Err(_) => {
                    continue;
                }
            }
        }

        Ok((false, None, None))
    });

    match timeout(Duration::from_millis(outer_timeout_ms), task).await {
        Ok(Ok(result)) => result,
        Ok(Err(e)) => {
            let error_msg = format!("ICMP timestamp task failed for {}: {}", ip, e);
            eprintln!("{}", error_msg);
            Err(error_msg)
        }
        Err(_) => {
            let error_msg = format!("ICMP timestamp task timed out for {}", ip);
            eprintln!("{}", error_msg);
            Err(error_msg)
        }
    }
}
