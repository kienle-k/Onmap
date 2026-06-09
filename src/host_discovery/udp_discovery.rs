use futures::stream::{FuturesUnordered, StreamExt};
use std::collections::HashMap;
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use tokio::task;
use tokio::time::timeout;

use crate::models::{
    HostDiscoveryAllResult, HostDiscoveryReply, HostDiscoverySingleResult, PortStateReasons,
};
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
    reply_type: HostDiscoveryReply,
}

/// Runs a UDP discovery scan against `(target, source_ip)` pairs.
/// The source IP is used per target for the bind address of each UDP probe.
pub async fn run_udp_discovery(
    ip_addresses: Vec<(Ipv4Addr, Ipv4Addr)>,
    ports: Vec<u16>,
    timeout_override_ms: Option<u64>,
    no_dns: bool,
) -> Result<(Vec<HostDiscoverySingleResult>, HostDiscoveryAllResult), String> {
    let start_time = SystemTime::now();

    if ports.is_empty() {
        return Err("At least one port is required for UDP discovery".to_string());
    }

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

            futures.push(async move {
                let _permit = sem_clone
                    .acquire()
                    .await
                    .expect("Semaphore should not be closed");
                let result = udp_probe_with_details(ip, port, source_ip, timeout_override_ms).await;
                (ip, port, result)
            });
        }
    }

    while let Some((ip, port, result)) = futures.next().await {
        let entry = host_states.get_mut(&ip).expect("Host state missing for IP");

        match result {
            Ok((status, latency)) => {
                let reply_type = match status {
                    UdpProbeStatus::UdpResponse => Some(HostDiscoveryReply::Udp {
                        port,
                        reason: PortStateReasons::UdpResponse,
                    }),
                    UdpProbeStatus::IcmpPortUnreachable => Some(HostDiscoveryReply::Udp {
                        port,
                        reason: PortStateReasons::IcmpPortUnreachable,
                    }),
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

async fn udp_probe_with_details(
    target_ip: Ipv4Addr,
    port: u16,
    source_ip: Ipv4Addr,
    timeout_override_ms: Option<u64>,
) -> Result<(UdpProbeStatus, Option<Duration>), String> {
    const DEFAULT_READ_TIMEOUT_MS: u64 = 1000;
    const OUTER_PADDING_MS: u64 = 200;
    let read_timeout_ms = timeout_override_ms.unwrap_or(DEFAULT_READ_TIMEOUT_MS);
    let outer_timeout_ms = read_timeout_ms + OUTER_PADDING_MS;

    let task = task::spawn_blocking(move || {
        let bind_addr = SocketAddr::new(IpAddr::V4(source_ip), 0);
        let socket =
            UdpSocket::bind(bind_addr).map_err(|e| format!("Failed to bind UDP socket: {}", e))?;

        let dest_addr = SocketAddr::new(IpAddr::V4(target_ip), port);
        socket.connect(dest_addr).map_err(|e| {
            format!(
                "Failed to connect UDP socket to {}:{}: {}",
                target_ip, port, e
            )
        })?;

        socket
            .set_read_timeout(Some(Duration::from_millis(read_timeout_ms)))
            .map_err(|e| format!("Failed to set UDP read timeout: {}", e))?;

        let payload = [0u8; 8];
        let start = Instant::now();
        match socket.send(&payload) {
            Ok(_) => {}
            Err(e) => {
                if e.kind() == ErrorKind::ConnectionRefused {
                    return Ok((UdpProbeStatus::IcmpPortUnreachable, Some(start.elapsed())));
                }
                return Err(format!(
                    "Failed to send UDP probe to {}:{}: {}",
                    target_ip, port, e
                ));
            }
        }

        let mut buffer = [0u8; 512];
        match socket.recv(&mut buffer) {
            Ok(_) => Ok((UdpProbeStatus::UdpResponse, Some(start.elapsed()))),
            Err(e) => match e.kind() {
                ErrorKind::ConnectionRefused => {
                    Ok((UdpProbeStatus::IcmpPortUnreachable, Some(start.elapsed())))
                }
                ErrorKind::WouldBlock | ErrorKind::TimedOut => {
                    Ok((UdpProbeStatus::NoResponse, None))
                }
                _ => Err(format!(
                    "UDP receive failed for {}:{}: {}",
                    target_ip, port, e
                )),
            },
        }
    });

    match timeout(Duration::from_millis(outer_timeout_ms), task).await {
        Ok(Ok(result)) => result,
        Ok(Err(e)) => Err(format!(
            "UDP probe task failed for {}:{}: {}",
            target_ip, port, e
        )),
        Err(_) => Err(format!(
            "UDP probe task timed out for {}:{}",
            target_ip, port
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Convenience alias: (target=loopback, source=loopback)
    fn localhost_pair() -> (Ipv4Addr, Ipv4Addr) {
        (Ipv4Addr::LOCALHOST, Ipv4Addr::LOCALHOST)
    }

    // Binds a UDP socket on loopback, spawns a task that echoes every datagram
    // back to the sender, and returns the bound port.
    fn spawn_udp_echo_server() -> u16 {
        let socket =
            UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).unwrap();
        let port = socket.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let mut buf = [0u8; 512];
            // One echo is enough for a single test probe.
            if let Ok((len, peer)) = socket.recv_from(&mut buf) {
                let _ = socket.send_to(&buf[..len], peer);
            }
        });
        port
    }

    // Returns a loopback UDP port that nothing listens on, so a send will
    // receive ICMP port unreachable (ECONNREFUSED on Linux).
    fn closed_udp_port() -> u16 {
        let socket =
            UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).unwrap();
        let port = socket.local_addr().unwrap().port();
        drop(socket); // Release the port immediately.
        port
    }

    /// An empty port list must be rejected immediately with an Err.
    #[tokio::test]
    async fn empty_ports_returns_err() {
        let result = run_udp_discovery(vec![], vec![], None, true).await;
        assert!(result.is_err(), "expected Err for empty ports, got Ok");
    }

    /// The error message for an empty port list must mention "port".
    #[tokio::test]
    async fn empty_ports_error_message_mentions_port() {
        let err = run_udp_discovery(vec![], vec![], None, true)
            .await
            .unwrap_err();
        assert!(
            err.to_lowercase().contains("port"),
            "error should mention 'port', got: {err}"
        );
    }

    /// An empty host list with a valid port must succeed and return no results.
    #[tokio::test]
    async fn empty_hosts_returns_zero_results() {
        let (results, _) = run_udp_discovery(vec![], vec![53], None, true)
            .await
            .expect("empty host list must not fail");
        assert!(results.is_empty());
    }

    /// hosts_up must be zero when no hosts were scanned.
    #[tokio::test]
    async fn empty_hosts_summary_hosts_up_is_zero() {
        let (_, summary) = run_udp_discovery(vec![], vec![53], None, true)
            .await
            .expect("empty host list must not fail");
        assert_eq!(summary.hosts_up, 0);
    }

    /// packets_sent = ports × hosts.  With no hosts this is always zero.
    #[tokio::test]
    async fn empty_hosts_summary_packets_sent_is_zero() {
        let (_, summary) = run_udp_discovery(vec![], vec![53, 123], None, true)
            .await
            .expect("empty host list must not fail");
        assert_eq!(summary.packets_sent, 0);
    }

    /// scanned_addresses must mirror the caller's input list.
    #[tokio::test]
    async fn empty_hosts_summary_scanned_addresses_is_empty() {
        let (_, summary) = run_udp_discovery(vec![], vec![53], None, true)
            .await
            .expect("empty host list must not fail");
        assert!(summary.scanned_addresses.is_empty());
    }

    /// ports_per_host must equal the number of ports provided.
    #[tokio::test]
    async fn summary_ports_per_host_matches_port_count() {
        let (_, summary) = run_udp_discovery(vec![], vec![53, 123, 161], None, true)
            .await
            .expect("empty host list must not fail");
        assert_eq!(summary.ports_per_host, 3);
    }

    /// With no_dns = true the DNS timing field must stay at exactly 0.0.
    #[tokio::test]
    async fn no_dns_flag_keeps_dns_elapsed_secs_at_zero() {
        let (_, summary) = run_udp_discovery(vec![], vec![53], None, true)
            .await
            .expect("empty host list must not fail");
        assert_eq!(summary.dns_elapsed_secs, 0.0);
    }

    /// With no_dns = true no result may carry a resolved hostname.
    #[tokio::test]
    async fn no_dns_flag_leaves_all_dns_resolves_empty() {
        let (results, _) = run_udp_discovery(vec![], vec![53], None, true)
            .await
            .expect("empty host list must not fail");
        assert!(results.iter().all(|r| r.dns_resolve.is_none()));
    }

    /// end_time must not precede start_time.
    #[tokio::test]
    async fn summary_end_time_not_before_start_time() {
        let (_, summary) = run_udp_discovery(vec![], vec![53], None, true)
            .await
            .expect("empty host list must not fail");
        assert!(summary.end_time >= summary.start_time);
    }

    /// A host that responds to a UDP probe must be reported as up.
    #[tokio::test]
    async fn udp_response_marks_host_as_up() {
        let port = spawn_udp_echo_server();

        let (results, _) = run_udp_discovery(vec![localhost_pair()], vec![port], Some(300), true)
            .await
            .expect("scan must not fail");

        assert_eq!(results.len(), 1);
        assert!(
            results[0].is_up,
            "host that replied to UDP probe should be up"
        );
    }

    /// A host that returns ICMP port unreachable (closed UDP port, ECONNREFUSED
    /// on Linux) must also be reported as up — the ICMP proves reachability.
    #[tokio::test]
    async fn icmp_port_unreachable_marks_host_as_up() {
        let port = closed_udp_port();

        let (results, _) = run_udp_discovery(vec![localhost_pair()], vec![port], Some(300), true)
            .await
            .expect("scan must not fail");

        assert_eq!(results.len(), 1);
        assert!(
            results[0].is_up,
            "host that returned ICMP port unreachable should be up"
        );
    }

    /// The result for a scanned host must carry the correct IP address.
    #[tokio::test]
    async fn result_ip_address_matches_input() {
        let port = closed_udp_port();

        let (results, _) = run_udp_discovery(vec![localhost_pair()], vec![port], Some(300), true)
            .await
            .expect("scan must not fail");

        assert_eq!(results[0].ip_address, IpAddr::V4(Ipv4Addr::LOCALHOST));
    }
}
