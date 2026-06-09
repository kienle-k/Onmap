use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant, SystemTime};

use pnet::packet::tcp::TcpFlags;

use crate::models::{
    HostDiscoveryAllResult, HostDiscoveryReply, HostDiscoverySingleResult, PortStateReasons,
};
use crate::port_scanning::tcp_raw_scan::{ScanConfig, TcpProbeOutcome, scan_tcp_probes};
use crate::resolving::resolve_hostname;

const DEFAULT_READ_TIMEOUT_MS: u64 = 1000;
const MAX_IN_FLIGHT: usize = 100;

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

    let config = ScanConfig {
        timeout: Duration::from_millis(timeout_override_ms.unwrap_or(DEFAULT_READ_TIMEOUT_MS)),
        max_in_flight: MAX_IN_FLIGHT,
        min_send_interval: Duration::ZERO,
        max_attempts: 1,
    };

    // One shared socket for the whole scan: every (host, port) probe is in
    // flight together and demuxed by target IP. Fold the replies into per-host
    // state, grouped by IP, fastest reply wins. A SYN+ACK or a RST both prove
    // the host is alive.
    let raw = scan_tcp_probes(ip_addresses.clone(), ports.clone(), TcpFlags::SYN, config).await?;

    for probe in raw.results {
        let TcpProbeOutcome::Reply { flags } = probe.outcome else {
            continue;
        };
        let reason = if flags & TcpFlags::SYN != 0 && flags & TcpFlags::ACK != 0 {
            PortStateReasons::SynAck
        } else if flags & TcpFlags::RST != 0 {
            PortStateReasons::Reset
        } else {
            continue;
        };

        let Some(entry) = host_states.get_mut(&probe.ip_address) else {
            log::debug!(
                "Ignoring TCP SYN discovery reply for unexpected host {}",
                probe.ip_address
            );
            continue;
        };
        if entry
            .latency
            .is_none_or(|existing| probe.latency < existing)
        {
            entry.is_up = true;
            entry.latency = Some(probe.latency);
            entry.ttl = 0;
            entry.reply_type = HostDiscoveryReply::TcpSyn {
                port: probe.port,
                reason,
            };
        }
    }

    let mut host_results = Vec::new();
    for (ip, _) in ip_addresses {
        let state = host_states.remove(&ip).unwrap_or(HostProbeState {
            is_up: false,
            latency: None,
            ttl: 0,
            reply_type: HostDiscoveryReply::NoResponse,
        });

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

#[cfg(test)]
mod tests {
    use super::*;

    /// An empty port list must be rejected immediately with an Err.
    #[tokio::test]
    async fn empty_ports_returns_err() {
        let result = run_tcp_syn_discovery(vec![], vec![], None, true).await;
        assert!(result.is_err(), "expected Err for empty ports, got Ok");
    }

    /// The error message for an empty port list must mention "port".
    #[tokio::test]
    async fn empty_ports_error_message_mentions_port() {
        let err = run_tcp_syn_discovery(vec![], vec![], None, true)
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
        let (results, _) = run_tcp_syn_discovery(vec![], vec![80], None, true)
            .await
            .expect("empty host list must not fail");
        assert!(results.is_empty());
    }

    /// hosts_up must be zero when no hosts were scanned.
    #[tokio::test]
    async fn empty_hosts_summary_hosts_up_is_zero() {
        let (_, summary) = run_tcp_syn_discovery(vec![], vec![80], None, true)
            .await
            .expect("empty host list must not fail");
        assert_eq!(summary.hosts_up, 0);
    }

    /// packets_sent = ports × hosts.  With no hosts this is always zero.
    #[tokio::test]
    async fn empty_hosts_summary_packets_sent_is_zero() {
        let (_, summary) = run_tcp_syn_discovery(vec![], vec![80, 443], None, true)
            .await
            .expect("empty host list must not fail");
        assert_eq!(summary.packets_sent, 0);
    }

    /// scanned_addresses must mirror the caller's input list.
    #[tokio::test]
    async fn empty_hosts_summary_scanned_addresses_is_empty() {
        let (_, summary) = run_tcp_syn_discovery(vec![], vec![80], None, true)
            .await
            .expect("empty host list must not fail");
        assert!(summary.scanned_addresses.is_empty());
    }

    /// ports_per_host must equal the number of ports provided.
    #[tokio::test]
    async fn summary_ports_per_host_matches_port_count() {
        let (_, summary) = run_tcp_syn_discovery(vec![], vec![22, 80, 443], None, true)
            .await
            .expect("empty host list must not fail");
        assert_eq!(summary.ports_per_host, 3);
    }

    /// With no_dns = true the DNS timing field must stay at exactly 0.0.
    #[tokio::test]
    async fn no_dns_flag_keeps_dns_elapsed_secs_at_zero() {
        let (_, summary) = run_tcp_syn_discovery(vec![], vec![80], None, true)
            .await
            .expect("empty host list must not fail");
        assert_eq!(summary.dns_elapsed_secs, 0.0);
    }

    /// With no_dns = true no result may carry a resolved hostname.
    #[tokio::test]
    async fn no_dns_flag_leaves_all_dns_resolves_empty() {
        let (results, _) = run_tcp_syn_discovery(vec![], vec![80], None, true)
            .await
            .expect("empty host list must not fail");
        assert!(results.iter().all(|r| r.dns_resolve.is_none()));
    }

    /// end_time must not precede start_time.
    #[tokio::test]
    async fn summary_end_time_not_before_start_time() {
        let (_, summary) = run_tcp_syn_discovery(vec![], vec![80], None, true)
            .await
            .expect("empty host list must not fail");
        assert!(summary.end_time >= summary.start_time);
    }
}
