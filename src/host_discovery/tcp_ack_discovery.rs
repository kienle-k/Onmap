
use futures::stream::{FuturesUnordered, StreamExt};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use crate::models::{HostDiscoveryAllResult, HostDiscoverySingleResult};
use crate::port_scanning::ack_scan::port_ack_scan;
use crate::resolving::resolve_hostname;

struct HostProbeState {
    is_up: bool,
    latency: Option<Duration>,
    ttl: u8,
    reply_type: String,
}

/// Runs a TCP ACK discovery scan against a list of target IP addresses.
pub async fn run_tcp_ack_discovery(
    ip_addresses: Result<Vec<Ipv4Addr>, String>,
    ports: Vec<u16>,
    local_ip_address: Ipv4Addr,
    timeout_override_ms: Option<u64>,
) -> Result<(Vec<HostDiscoverySingleResult>, HostDiscoveryAllResult), String> {
    let start_time = SystemTime::now();
    let ips = ip_addresses?;

    if ports.is_empty() {
        return Err("At least one port is required for TCP ACK discovery".to_string());
    }

    let all_ips: Vec<IpAddr> = ips.iter().map(|ip| IpAddr::V4(*ip)).collect();
    let mut host_states: HashMap<Ipv4Addr, HostProbeState> = ips
        .iter()
        .map(|ip| (*ip, HostProbeState {
            is_up: false,
            latency: None,
            ttl: 0,
            reply_type: "no response".to_string(),
        }))
        .collect();

    let semaphore = Arc::new(tokio::sync::Semaphore::new(100));
    let mut futures = FuturesUnordered::new();

    for ip in &ips {
        for &port in &ports {
            let sem_clone = Arc::clone(&semaphore);
            let ip = *ip;
            let source_ip = if ip.is_loopback() {
                Ipv4Addr::new(127, 0, 0, 1)
            } else {
                local_ip_address
            };

            futures.push(async move {
                let _permit = sem_clone.acquire().await.expect("Semaphore should not be closed");
                let start = Instant::now();
                let (is_unfiltered, ttl) = port_ack_scan(ip, port, source_ip, timeout_override_ms).await;
                let latency = start.elapsed();
                (ip, port, latency, is_unfiltered, ttl)
            });
        }
    }

    while let Some((ip, port, latency, is_unfiltered, ttl)) = futures.next().await {
        let entry = host_states
            .get_mut(&ip)
            .expect("Host state missing for IP");

        if is_unfiltered {
            let should_update = match entry.latency {
                None => true,
                Some(existing) => latency < existing,
            };

            if should_update {
                entry.is_up = true;
                entry.latency = Some(latency);
                entry.ttl = ttl.unwrap_or(0);
                entry.reply_type = format!("RST port {}", port);
            }
        }
    }

    let mut host_results = Vec::new();
    for ip in ips {
        let state = host_states
            .remove(&ip)
            .expect("Host state missing for IP");

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
    let dns_start = Instant::now();
    let dns_tasks: Vec<_> = host_results.iter().enumerate()
        .filter_map(|(i, r)| match r.ip_address {
            IpAddr::V4(ipv4) if r.is_up => Some((i, ipv4)),
            _ => None,
        })
        .collect();
    let dns_resolved = futures::future::join_all(
        dns_tasks.into_iter().map(|(i, ipv4)| async move {
            (i, resolve_hostname(&ipv4).await)
        })
    ).await;
    for (idx, hostname) in dns_resolved {
        host_results[idx].dns_resolve = hostname;
    }
    let dns_elapsed_secs = dns_start.elapsed().as_secs_f64();
    let hosts_dns_resolution = host_results.iter().filter(|r| r.dns_resolve.is_some()).count() as u64;

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