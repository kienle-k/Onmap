use futures::stream::{FuturesUnordered, StreamExt};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use crate::models::{
    HostDiscoveryAllResult, HostDiscoveryReply, HostDiscoverySingleResult, PortStates,
};
use crate::port_scanning::connect_scan::port_tcp_connect_scan;
use crate::resolving::get_service_name::load_service_map;
use crate::resolving::resolve_hostname;

const DEFAULT_TIMEOUT_MS: u64 = 300;

struct HostProbeState {
    is_up: bool,
    latency: Option<Duration>,
    ttl: u8,
    reply_type: HostDiscoveryReply,
}

/// Runs a TCP connect discovery scan against target IPs.
///
/// This uses the OS TCP stack to attempt a full connection and treats
/// open or closed ports as evidence the host is up.
pub async fn run_tcp_connect_discovery(
    ip_addresses: Vec<Ipv4Addr>,
    ports: Vec<u16>,
    timeout_override_ms: Option<u64>,
    no_dns: bool,
) -> Result<(Vec<HostDiscoverySingleResult>, HostDiscoveryAllResult), String> {
    let start_time = SystemTime::now();

    if ports.is_empty() {
        return Err("At least one port is required for TCP connect discovery".to_string());
    }

    let timeout = Duration::from_millis(timeout_override_ms.unwrap_or(DEFAULT_TIMEOUT_MS));
    let service_map = Arc::new(
        load_service_map("src/resolving/port_service_mapping.json")
            .map_err(|e| format!("Failed to load service map: {}", e))?,
    );

    let all_ips: Vec<IpAddr> = ip_addresses.iter().map(|ip| IpAddr::V4(*ip)).collect();
    let mut host_states: HashMap<Ipv4Addr, HostProbeState> = ip_addresses
        .iter()
        .map(|ip| {
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

    for ip in &ip_addresses {
        let ip = *ip;
        for &port in &ports {
            let sem_clone = Arc::clone(&semaphore);
            let service_map_clone = Arc::clone(&service_map);

            futures.push(async move {
                let _permit = sem_clone
                    .acquire()
                    .await
                    .expect("Semaphore should not be closed");
                let start = Instant::now();
                let result =
                    port_tcp_connect_scan(IpAddr::V4(ip), port, timeout, &service_map_clone).await;
                let latency = start.elapsed();
                (ip, port, latency, result)
            });
        }
    }

    let mut open_ports_found: u64 = 0;

    while let Some((ip, port, latency, result)) = futures.next().await {
        let entry = host_states.get_mut(&ip).expect("Host state missing for IP");

        match result {
            Ok(port_result) => match port_result.port_state {
                PortStates::Open | PortStates::Closed => {
                    if port_result.port_state == PortStates::Open {
                        open_ports_found = open_ports_found.saturating_add(1);
                    }

                    let should_update = match entry.latency {
                        None => true,
                        Some(existing) => latency < existing,
                    };

                    if should_update {
                        entry.is_up = true;
                        entry.latency = Some(latency);
                        entry.ttl = port_result.ttl;
                        entry.reply_type = HostDiscoveryReply::TcpConnect {
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
    for ip in ip_addresses {
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

    let attempts = (ports.len() * host_results.len()) as u64;
    let summary = HostDiscoveryAllResult {
        scanned_addresses: all_ips,
        ports_per_host: ports.len() as u16,
        hosts_up,
        hosts_dns_resolution,
        start_time,
        end_time,
        packets_sent: attempts.saturating_add(open_ports_found.saturating_mul(2)),
        dns_elapsed_secs,
    };

    Ok((host_results, summary))
}
