use futures::stream::{FuturesUnordered, StreamExt};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use crate::models::{
    HostDiscoveryAllResult, HostDiscoveryReply, HostDiscoverySingleResult, PortStates,
};
use crate::port_scanning::connect_scan::port_tcp_connect_scan;
use crate::resolving::resolve_hostname;

const DEFAULT_TIMEOUT_MS: u64 = 1000;

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

            futures.push(async move {
                let _permit = sem_clone
                    .acquire()
                    .await
                    .expect("Semaphore should not be closed");
                let start = Instant::now();
                let result = port_tcp_connect_scan(IpAddr::V4(ip), port, timeout).await;
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

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    // Binds a loopback listener that keeps accepting connections in the background
    // and returns the bound port.
    async fn spawn_open_listener() -> u16 {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind loopback listener");
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                drop(stream);
            }
        });
        port
    }

    // Binds to get an OS-assigned port then drops the listener: any connect
    // to the returned port will immediately receive a RST (Closed).
    async fn closed_port() -> u16 {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind to find a free port");
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        port
    }

    /// An empty port list must be rejected with an Err before touching the network.
    #[tokio::test]
    async fn empty_ports_returns_err() {
        let result = run_tcp_connect_discovery(vec![], vec![], None, true).await;
        assert!(result.is_err(), "expected Err for empty ports, got Ok");
    }

    /// The error message for an empty port list must mention "port" so callers
    /// understand why the call was rejected.
    #[tokio::test]
    async fn empty_ports_error_message_mentions_port() {
        let err = run_tcp_connect_discovery(vec![], vec![], None, true)
            .await
            .unwrap_err();
        assert!(
            err.to_lowercase().contains("port"),
            "error should mention 'port', got: {err}"
        );
    }

    /// An empty host list with a valid port must succeed and return no per-host
    /// results.
    #[tokio::test]
    async fn empty_hosts_returns_zero_results() {
        let (results, _) = run_tcp_connect_discovery(vec![], vec![80], None, true)
            .await
            .expect("empty host list must not fail");
        assert!(results.is_empty());
    }

    /// hosts_up must be zero when no hosts were scanned.
    #[tokio::test]
    async fn empty_hosts_summary_hosts_up_is_zero() {
        let (_, summary) = run_tcp_connect_discovery(vec![], vec![80], None, true)
            .await
            .expect("empty host list must not fail");
        assert_eq!(summary.hosts_up, 0);
    }

    /// packets_sent = attempts + 2×open_ports.  With no hosts, both terms are
    /// zero.
    #[tokio::test]
    async fn empty_hosts_summary_packets_sent_is_zero() {
        let (_, summary) = run_tcp_connect_discovery(vec![], vec![80, 443], None, true)
            .await
            .expect("empty host list must not fail");
        assert_eq!(summary.packets_sent, 0);
    }

    /// scanned_addresses must mirror the caller's input list.
    #[tokio::test]
    async fn empty_hosts_summary_scanned_addresses_is_empty() {
        let (_, summary) = run_tcp_connect_discovery(vec![], vec![80], None, true)
            .await
            .expect("empty host list must not fail");
        assert!(summary.scanned_addresses.is_empty());
    }

    /// ports_per_host must equal the number of ports provided regardless of
    /// how many hosts were in the list.
    #[tokio::test]
    async fn summary_ports_per_host_matches_port_count() {
        let (_, summary) = run_tcp_connect_discovery(vec![], vec![22, 80, 443], None, true)
            .await
            .expect("empty host list must not fail");
        assert_eq!(summary.ports_per_host, 3);
    }

    /// With no_dns = true the DNS timing field must stay at exactly 0.0.
    #[tokio::test]
    async fn no_dns_flag_keeps_dns_elapsed_secs_at_zero() {
        let (_, summary) = run_tcp_connect_discovery(vec![], vec![80], None, true)
            .await
            .expect("empty host list must not fail");
        assert_eq!(summary.dns_elapsed_secs, 0.0);
    }

    /// With no_dns = true no result may carry a resolved hostname.
    #[tokio::test]
    async fn no_dns_flag_leaves_all_dns_resolves_empty() {
        let (results, _) = run_tcp_connect_discovery(vec![], vec![80], None, true)
            .await
            .expect("empty host list must not fail");
        assert!(results.iter().all(|r| r.dns_resolve.is_none()));
    }

    /// end_time must not precede start_time.
    #[tokio::test]
    async fn summary_end_time_not_before_start_time() {
        let (_, summary) = run_tcp_connect_discovery(vec![], vec![80], None, true)
            .await
            .expect("empty host list must not fail");
        assert!(summary.end_time >= summary.start_time);
    }

    /// A host with a listening port must be reported as up.
    #[tokio::test]
    async fn open_port_on_localhost_marks_host_as_up() {
        let port = spawn_open_listener().await;

        let (results, _) =
            run_tcp_connect_discovery(vec![Ipv4Addr::LOCALHOST], vec![port], Some(300), true)
                .await
                .expect("scan must not fail");

        assert_eq!(results.len(), 1);
        assert!(results[0].is_up, "localhost with open port should be up");
    }

    /// A host that refuses a connection (RST) must also be reported as up,
    /// because a RST proves the host is reachable.
    #[tokio::test]
    async fn closed_port_on_localhost_marks_host_as_up() {
        let port = closed_port().await;

        let (results, _) =
            run_tcp_connect_discovery(vec![Ipv4Addr::LOCALHOST], vec![port], Some(300), true)
                .await
                .expect("scan must not fail");

        assert_eq!(results.len(), 1);
        assert!(
            results[0].is_up,
            "localhost with closed (RST) port should still be up"
        );
    }

    /// For an open port the packets_sent accounting must be:
    /// attempts (1) + handshake overhead (2) = 3.
    #[tokio::test]
    async fn packets_sent_includes_open_port_handshake_overhead() {
        let port = spawn_open_listener().await;

        let (_, summary) =
            run_tcp_connect_discovery(vec![Ipv4Addr::LOCALHOST], vec![port], Some(300), true)
                .await
                .expect("scan must not fail");

        // 1 attempt + 2 for the open-port handshake = 3
        assert_eq!(
            summary.packets_sent, 3,
            "packets_sent should be attempts(1) + 2×open_ports(1) = 3"
        );
    }

    /// The result for a scanned host must carry the correct IP address so
    /// callers can match results back to their input.
    #[tokio::test]
    async fn result_ip_address_matches_input() {
        let port = closed_port().await;

        let (results, _) =
            run_tcp_connect_discovery(vec![Ipv4Addr::LOCALHOST], vec![port], Some(300), true)
                .await
                .expect("scan must not fail");

        assert_eq!(results[0].ip_address, IpAddr::V4(Ipv4Addr::LOCALHOST));
    }
}
