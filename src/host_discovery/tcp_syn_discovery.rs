use futures::stream::{FuturesUnordered, StreamExt};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use crate::models::{
    HostDiscoveryAllResult, HostDiscoveryReply, HostDiscoverySingleResult, PortStates,
};
use crate::port_scanning::syn_scan::port_syn_scan;
use crate::resolving::get_service_name::load_protocol_map;
use crate::resolving::resolve_hostname;

struct HostProbeState {
    is_up: bool,
    latency: Option<Duration>,
    ttl: u8,
    reply_type: HostDiscoveryReply,
}

/// Runs a TCP SYN discovery scan against `(target, source_ip)` pairs.
/// The source IP is used per target for packet construction and TCP checksum.
pub async fn run_tcp_syn_discovery(
    ip_addresses: Vec<(Ipv4Addr, Ipv4Addr)>,
    ports: Vec<u16>,
    timeout_override_ms: Option<u64>,
    no_dns: bool,
) -> Result<(Vec<HostDiscoverySingleResult>, HostDiscoveryAllResult), String> {
    let start_time = SystemTime::now();

    if ports.is_empty() {
        return Err("At least one port is required for TCP SYN discovery".to_string());
    }

    let protocols = Arc::new(
        load_protocol_map("src/resolving/port_service_mapping.json")
            .map_err(|e| format!("Failed to load protocol map: {}", e))?,
    );

    let all_ips: Vec<IpAddr> = ip_addresses.iter().map(|(ip, _)| IpAddr::V4(*ip)).collect();
    let mut host_states: HashMap<Ipv4Addr, HostProbeState> = ip_addresses
        .iter()
        .map(|(ip, _)| {
            (
                *ip,
                HostProbeState {
                    is_up: false,
                    latency: None,
                    ttl: 0,
                    reply_type: HostDiscoveryReply::NoResponse,
                },
            )
        })
        .collect();

    let semaphore = Arc::new(tokio::sync::Semaphore::new(100));
    let mut futures = FuturesUnordered::new();

    for (ip, source_ip) in &ip_addresses {
        let (ip, source_ip) = (*ip, *source_ip);
        for &port in &ports {
            let sem_clone = Arc::clone(&semaphore);
            let protocols_clone = Arc::clone(&protocols);

            futures.push(async move {
                let _permit = sem_clone
                    .acquire()
                    .await
                    .expect("Semaphore should not be closed");
                let start = Instant::now();
                let result = port_syn_scan(
                    IpAddr::V4(ip),
                    port,
                    source_ip,
                    protocols_clone,
                    timeout_override_ms,
                )
                .await;
                let latency = start.elapsed();
                (ip, port, latency, result)
            });
        }
    }

    while let Some((ip, port, latency, result)) = futures.next().await {
        let entry = host_states.get_mut(&ip).expect("Host state missing for IP");

        match result {
            Ok(port_result) => match port_result.port_state {
                PortStates::Open | PortStates::Closed => {
                    let should_update = match entry.latency {
                        None => true,
                        Some(existing) => latency < existing,
                    };

                    if should_update {
                        entry.is_up = true;
                        entry.latency = Some(latency);
                        entry.ttl = port_result.ttl;
                        entry.reply_type = HostDiscoveryReply::TcpSyn {
                            port,
                            reason: port_result.reason,
                        };
                    }
                }
                _ => {}
            },
            Err(e) => {
                if !entry.is_up && entry.reply_type == HostDiscoveryReply::NoResponse {
                    entry.reply_type = HostDiscoveryReply::Error(e);
                }
            }
        }
    }

    let mut host_results = Vec::new();
    for (ip, _) in ip_addresses {
        let state = host_states.remove(&ip).expect("Host state missing for IP");

        let dns_resolve = None;

        host_results.push(HostDiscoverySingleResult {
            ip_address: IpAddr::V4(ip),
            latency: state.latency,
            dns_resolve,
            is_up: state.is_up,
            reply_type: state.reply_type,
            ttl: state.ttl,
        });
    }

    let hosts_up = host_results.iter().filter(|r| r.is_up).count() as u64;
    let end_time = SystemTime::now();
    let mut dns_elapsed_secs = 0.0;
    if !no_dns {
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
        dns_elapsed_secs = dns_start.elapsed().as_secs_f64();
    }
    let hosts_dns_resolution = host_results
        .iter()
        .filter(|r| r.dns_resolve.is_some())
        .count() as u64;

    let summary = HostDiscoveryAllResult {
        scanned_addresses: all_ips,
        ports_per_host: ports.len() as u16,
        hosts_up,
        hosts_dns_resolution,
        start_time,
        end_time,
        packets_sent: (ports.len() * host_results.len()) as u64,
        dns_elapsed_secs,
    };

    Ok((host_results, summary))
}
