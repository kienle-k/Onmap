use futures::stream::{FuturesUnordered, StreamExt};
use std::collections::HashMap;
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use tokio::task;
use tokio::time::timeout;

use crate::models::{HostDiscoveryAllResult, HostDiscoverySingleResult};
use crate::resolving::resolve_hostname;

enum UdpProbeStatus {
    UdpResponse,
    IcmpPortUnreachable,
    NoResponse,
}

struct HostProbeState {
    is_up: bool,
    latency: Option<Duration>,
    ttl: u8,
    reply_type: String,
}

/// Runs a UDP discovery scan against a list of target IP addresses.
pub async fn run_udp_discovery(
    ip_addresses: Result<Vec<Ipv4Addr>, String>,
    ports: Vec<u16>,
    local_ip_address: Ipv4Addr,
) -> Result<(Vec<HostDiscoverySingleResult>, HostDiscoveryAllResult), String> {
    let start_time = SystemTime::now();
    let ips = ip_addresses?;

    if ports.is_empty() {
        return Err("At least one port is required for UDP discovery".to_string());
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
                let result = udp_probe_with_details(ip, port, source_ip).await;
                (ip, port, result)
            });
        }
    }

    while let Some((ip, port, result)) = futures.next().await {
        let entry = host_states
            .get_mut(&ip)
            .expect("Host state missing for IP");

        match result {
            Ok((status, latency)) => {
                let reply_type = match status {
                    UdpProbeStatus::UdpResponse => Some(format!("UDP response port {}", port)),
                    UdpProbeStatus::IcmpPortUnreachable => {
                        Some(format!("ICMP port unreachable port {}", port))
                    }
                    UdpProbeStatus::NoResponse => None,
                };

                if let Some(reply_type) = reply_type {
                    let should_update = match entry.latency {
                        None => true,
                        Some(existing) => latency.map(|new| new < existing).unwrap_or(false),
                    };

                    if should_update {
                        entry.is_up = true;
                        entry.latency = latency;
                        entry.ttl = 0;
                        entry.reply_type = reply_type;
                    }
                }
            }
            Err(e) => {
                if !entry.is_up && entry.reply_type == "no response" {
                    entry.reply_type = format!("Error: {}", e);
                }
            }
        }
    }

    let mut host_results = Vec::new();
    for ip in ips {
        let state = host_states
            .remove(&ip)
            .expect("Host state missing for IP");

        let dns_resolve = if state.is_up {
            resolve_hostname(&ip).await
        } else {
            None
        };

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
    let hosts_dns_resolution = host_results.iter().filter(|r| r.dns_resolve.is_some()).count() as u64;
    let end_time = SystemTime::now();

    let summary = HostDiscoveryAllResult {
        scanned_addresses: all_ips,
        ports_per_host: ports.len() as u16,
        hosts_up,
        hosts_dns_resolution,
        start_time,
        end_time,
        packets_sent: (ports.len() * host_results.len()) as u64,
    };

    Ok((host_results, summary))
}

async fn udp_probe_with_details(
    target_ip: Ipv4Addr,
    port: u16,
    source_ip: Ipv4Addr,
) -> Result<(UdpProbeStatus, Option<Duration>), String> {
    const READ_TIMEOUT_MS: u64 = 800;
    const OUTER_TIMEOUT_MS: u64 = READ_TIMEOUT_MS + 200;

    let task = task::spawn_blocking(move || {
        let bind_addr = SocketAddr::new(IpAddr::V4(source_ip), 0);
        let socket = UdpSocket::bind(bind_addr)
            .map_err(|e| format!("Failed to bind UDP socket: {}", e))?;

        let dest_addr = SocketAddr::new(IpAddr::V4(target_ip), port);
        socket
            .connect(dest_addr)
            .map_err(|e| format!("Failed to connect UDP socket to {}:{}: {}", target_ip, port, e))?;

        socket
            .set_read_timeout(Some(Duration::from_millis(READ_TIMEOUT_MS)))
            .map_err(|e| format!("Failed to set UDP read timeout: {}", e))?;

        let payload = [0u8; 8];
        let start = Instant::now();
        match socket.send(&payload) {
            Ok(_) => {}
            Err(e) => {
                if e.kind() == ErrorKind::ConnectionRefused {
                    return Ok((UdpProbeStatus::IcmpPortUnreachable, Some(start.elapsed())));
                }
                return Err(format!("Failed to send UDP probe to {}:{}: {}", target_ip, port, e));
            }
        }

        let mut buffer = [0u8; 512];
        match socket.recv(&mut buffer) {
            Ok(_) => Ok((UdpProbeStatus::UdpResponse, Some(start.elapsed()))),
            Err(e) => match e.kind() {
                ErrorKind::ConnectionRefused => {
                    Ok((UdpProbeStatus::IcmpPortUnreachable, Some(start.elapsed())))
                }
                ErrorKind::WouldBlock | ErrorKind::TimedOut => Ok((UdpProbeStatus::NoResponse, None)),
                _ => Err(format!("UDP receive failed for {}:{}: {}", target_ip, port, e)),
            },
        }
    });

    match timeout(Duration::from_millis(OUTER_TIMEOUT_MS), task).await {
        Ok(Ok(result)) => result,
        Ok(Err(e)) => Err(format!("UDP probe task failed for {}:{}: {}", target_ip, port, e)),
        Err(_) => Err(format!("UDP probe task timed out for {}:{}", target_ip, port)),
    }
}