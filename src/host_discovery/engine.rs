//! Host-discovery execution engine.
//!
//! Consumes a `DiscoveryPlan` and runs the probes via the existing
//! per-method modules. Partitions targets into local-Ethernet vs routed
//! and dispatches ARP only to local ones.

use crate::host_discovery::{
    run_arp_discovery, run_icmp_echo_discovery, run_icmp_timestamp_discovery,
    run_tcp_ack_discovery, run_tcp_connect_discovery, run_tcp_syn_discovery,
    udp_discovery::run_udp_discovery,
};
use crate::models::{
    DiscoveryMode, DiscoveryPlan, DiscoveryProbe, HostDiscoverySingleResult,
};
use crate::resolving::source_ip::resolve_for_targets;
use futures::future::join_all;
use pnet::datalink;
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

/// Flat per-probe, per-host result. `hosts_up()` derives the up-set.
pub struct DiscoveryResult {
    pub per_probe: Vec<HostDiscoverySingleResult>,
    pub packets_sent: u64,
}

impl DiscoveryResult {
    pub fn hosts_up(&self) -> Vec<Ipv4Addr> {
        let mut seen = HashSet::new();
        self.per_probe
            .iter()
            .filter(|r| r.is_up)
            .filter_map(|r| match r.ip_address {
                IpAddr::V4(v) => Some(v),
                IpAddr::V6(_) => None,
            })
            .filter(|ip| seen.insert(*ip))
            .collect()
    }
}

pub async fn run_discovery(
    plan: &DiscoveryPlan,
    targets: &[Ipv4Addr],
    timeout_override_ms: Option<u64>,
) -> DiscoveryResult {
    if matches!(plan.mode, DiscoveryMode::SkipDiscoveryTreatAllUp) {
        return DiscoveryResult {
            per_probe: targets.iter().map(treat_as_up).collect(),
            packets_sent: 0,
        };
    }

    let (local, routed) = partition_targets(targets);
    let mut per_probe = Vec::new();
    let mut packets_sent: u64 = 0;

    // Nmap-style auto-ARP: local-Ethernet targets always get ARP, regardless
    // of plan. Cheap, reliable, and provides MAC info other probes can't.
    // Suppressed by --disable-arp-ping, falling back to IP-level probes.
    if !local.is_empty() && !plan.disable_arp_ping {
        match run_arp_discovery(resolve_for_targets(&local), timeout_override_ms).await {
            Ok((rows, summary)) => {
                per_probe.extend(rows);
                packets_sent = packets_sent.saturating_add(summary.packets_sent);
            }
            Err(e) => eprintln!("warning: ARP discovery failed: {e}"),
        }
    }

    // Plan probes run in parallel. Auto-ARP covers local hosts; IP probes only
    // fall back to all targets when --disable-arp-ping suppresses auto-ARP.
    if !plan.probes.is_empty() {
        let all_targets = Arc::new(targets.to_vec());
        let routed = Arc::new(routed);

        let probe_results = join_all(plan.probes.iter().map(|probe| {
            let probe = probe.clone();
            let all_targets = Arc::clone(&all_targets);
            let routed = Arc::clone(&routed);
            async move {
                let targets_for_probe: &[Ipv4Addr] = match &probe {
                    DiscoveryProbe::Arp => &routed,
                    _ if plan.disable_arp_ping => &all_targets,
                    _ => &routed,
                };
                let result = run_probe(&probe, targets_for_probe, timeout_override_ms).await;
                (probe, result)
            }
        }))
        .await;

        for (probe, result) in probe_results {
            match result {
                Ok((rows, sent)) => {
                    per_probe.extend(rows);
                    packets_sent = packets_sent.saturating_add(sent);
                }
                Err(e) => eprintln!("warning: {probe:?} discovery failed: {e}"),
            }
        }
    }

    DiscoveryResult {
        per_probe,
        packets_sent,
    }
}

fn treat_as_up(ip: &Ipv4Addr) -> HostDiscoverySingleResult {
    HostDiscoverySingleResult {
        ip_address: IpAddr::V4(*ip),
        dns_resolve: None,
        latency: None,
        is_up: true,
        reply_type: "user-set".to_string(),
        ttl: 0,
    }
}

async fn run_probe(
    probe: &DiscoveryProbe,
    targets: &[Ipv4Addr],
    timeout_override_ms: Option<u64>,
) -> Result<(Vec<HostDiscoverySingleResult>, u64), String> {
    let outcome = match probe {
        DiscoveryProbe::Arp => {
            run_arp_discovery(resolve_for_targets(targets), timeout_override_ms).await
        }
        DiscoveryProbe::IcmpEcho => {
            run_icmp_echo_discovery(targets.to_vec(), timeout_override_ms).await
        }
        DiscoveryProbe::IcmpTimestamp => {
            run_icmp_timestamp_discovery(targets.to_vec(), timeout_override_ms).await
        }
        DiscoveryProbe::TcpSyn { port } => run_tcp_syn_discovery(
            resolve_for_targets(targets),
            vec![*port],
            timeout_override_ms,
        )
        .await,
        DiscoveryProbe::TcpAck { port } => run_tcp_ack_discovery(
            resolve_for_targets(targets),
            vec![*port],
            timeout_override_ms,
        )
        .await,
        DiscoveryProbe::Udp { port } => run_udp_discovery(
            resolve_for_targets(targets),
            vec![*port],
            timeout_override_ms,
        )
        .await,
        DiscoveryProbe::TcpConnect { port } => {
            run_tcp_connect_discovery(targets.to_vec(), vec![*port], timeout_override_ms).await
        }
    };
    outcome.map(|(rows, summary)| (rows, summary.packets_sent))
}

/// Split targets into (local-Ethernet, routed) by IPv4 CIDR membership in
/// any non-loopback interface's network.
fn partition_targets(targets: &[Ipv4Addr]) -> (Vec<Ipv4Addr>, Vec<Ipv4Addr>) {
    let local_networks: Vec<_> = datalink::interfaces()
        .into_iter()
        .filter(|iface| !iface.is_loopback())
        .flat_map(|iface| iface.ips.into_iter())
        .filter(|n| n.is_ipv4())
        .collect();

    let mut local = Vec::new();
    let mut routed = Vec::new();
    for ip in targets {
        let addr = IpAddr::V4(*ip);
        if local_networks.iter().any(|net| net.contains(addr)) {
            local.push(*ip);
        } else {
            routed.push(*ip);
        }
    }
    (local, routed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::DiscoveryPlan;

    #[test]
    fn hosts_up_dedupes_and_filters() {
        let r = DiscoveryResult {
            per_probe: vec![
                row(Ipv4Addr::new(1, 1, 1, 1), true),
                row(Ipv4Addr::new(2, 2, 2, 2), false),
                row(Ipv4Addr::new(1, 1, 1, 1), true), // duplicate up
                row(Ipv4Addr::new(3, 3, 3, 3), true),
            ],
            packets_sent: 0,
        };
        assert_eq!(
            r.hosts_up(),
            vec![Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(3, 3, 3, 3)]
        );
    }

    #[tokio::test]
    async fn pn_mode_treats_all_targets_up() {
        let plan = DiscoveryPlan {
            mode: DiscoveryMode::SkipDiscoveryTreatAllUp,
            probes: Vec::new(),
            disable_arp_ping: false,
        };
        let targets = vec![Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(2, 2, 2, 2)];
        let result = run_discovery(&plan, &targets, Some(100)).await;
        assert_eq!(result.per_probe.len(), 2);
        assert!(result.per_probe.iter().all(|r| r.is_up));
        assert_eq!(result.hosts_up(), targets);
    }

    fn row(ip: Ipv4Addr, up: bool) -> HostDiscoverySingleResult {
        HostDiscoverySingleResult {
            ip_address: IpAddr::V4(ip),
            dns_resolve: None,
            latency: None,
            is_up: up,
            reply_type: String::new(),
            ttl: 0,
        }
    }
}
