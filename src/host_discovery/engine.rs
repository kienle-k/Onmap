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
    no_dns: bool,
    is_root: bool,
) -> DiscoveryResult {
    let (local, routed) = partition_targets(targets);

    if matches!(plan.mode, DiscoveryMode::SkipDiscoveryTreatAllUp) {
        // `-Pn` skips the IP-level ping phase, so routed (off-link) targets are
        // assumed up and scanned — nmap cannot ping across a router under -Pn
        // either. But on a directly-connected segment, sending any IP packet
        // first requires the target's MAC, which means ARP. nmap treats this
        // ARP as mandatory link-layer resolution (not host discovery): it runs
        // even under -Pn, and a host that never answers ARP has no MAC and
        // cannot be scanned, so it is reported down. We mirror that here.
        //
        // ARP needs raw sockets; when it cannot run (non-root) or is suppressed
        // (--disable-arp-ping), fall back to assume-up for local targets too so
        // we never silently drop them.
        let arp_local = is_root && !plan.disable_arp_ping && !local.is_empty();
        if !arp_local {
            return DiscoveryResult {
                per_probe: targets.iter().map(treat_as_up).collect(),
                packets_sent: 0,
            };
        }

        let mut per_probe: Vec<HostDiscoverySingleResult> =
            routed.iter().map(treat_as_up).collect();
        let mut packets_sent: u64 = 0;
        match run_arp_discovery(resolve_for_targets(&local), timeout_override_ms, no_dns).await {
            Ok((rows, summary)) => {
                per_probe.extend(rows);
                packets_sent = packets_sent.saturating_add(summary.packets_sent);
            }
            // If ARP itself errors, don't drop the local targets — assume them up.
            Err(e) => {
                eprintln!("warning: ARP resolution failed under -Pn: {e}");
                per_probe.extend(local.iter().map(treat_as_up));
            }
        }
        return DiscoveryResult {
            per_probe,
            packets_sent,
        };
    }

    let mut per_probe = Vec::new();
    let mut packets_sent: u64 = 0;

    // Nmap-style auto-ARP: local-Ethernet targets get ARP, regardless of plan —
    // but only when raw-packet privilege is actually available. ARP needs raw
    // sockets, so as non-root it cannot run; replacing the planned IP/TCP-connect
    // probes with a method that can't run would silently leave local-link targets
    // undiscovered. Suppressed by --disable-arp-ping.
    let auto_arp = is_root && !plan.disable_arp_ping && !local.is_empty();
    if auto_arp {
        match run_arp_discovery(resolve_for_targets(&local), timeout_override_ms, no_dns).await {
            Ok((rows, summary)) => {
                per_probe.extend(rows);
                packets_sent = packets_sent.saturating_add(summary.packets_sent);
            }
            Err(e) => eprintln!("warning: ARP discovery failed: {e}"),
        }
    }

    // Plan probes run in parallel. When auto-ARP ran, it covers local hosts so
    // IP probes only target routed hosts. When auto-ARP did not run (non-root,
    // --disable-arp-ping, or no local targets), IP/TCP-connect probes must cover
    // every target so local-link hosts still get their planned fallback probes.
    if !plan.probes.is_empty() {
        let all_targets = Arc::new(targets.to_vec());
        let routed = Arc::new(routed);

        let probe_results = join_all(plan.probes.iter().map(|probe| {
            let probe = probe.clone();
            let all_targets = Arc::clone(&all_targets);
            let routed = Arc::clone(&routed);
            async move {
                let targets_for_probe = probe_target_set(&probe, auto_arp, &all_targets, &routed);
                let result = run_probe(&probe, targets_for_probe, timeout_override_ms, no_dns).await;
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
    no_dns: bool,
) -> Result<(Vec<HostDiscoverySingleResult>, u64), String> {
    let outcome = match probe {
        DiscoveryProbe::Arp => {
            run_arp_discovery(resolve_for_targets(targets), timeout_override_ms, no_dns).await
        }
        DiscoveryProbe::IcmpEcho => {
            run_icmp_echo_discovery(targets.to_vec(), timeout_override_ms, no_dns).await
        }
        DiscoveryProbe::IcmpTimestamp => {
            run_icmp_timestamp_discovery(targets.to_vec(), timeout_override_ms, no_dns).await
        }
        DiscoveryProbe::TcpSyn { port } => run_tcp_syn_discovery(
            resolve_for_targets(targets),
            vec![*port],
            timeout_override_ms,
            no_dns,
        )
        .await,
        DiscoveryProbe::TcpAck { port } => run_tcp_ack_discovery(
            resolve_for_targets(targets),
            vec![*port],
            timeout_override_ms,
            no_dns,
        )
        .await,
        DiscoveryProbe::Udp { port } => run_udp_discovery(
            resolve_for_targets(targets),
            vec![*port],
            timeout_override_ms,
            no_dns,
        )
        .await,
        DiscoveryProbe::TcpConnect { port } => {
            run_tcp_connect_discovery(targets.to_vec(), vec![*port], timeout_override_ms, no_dns).await
        }
    };
    outcome.map(|(rows, summary)| (rows, summary.packets_sent))
}

/// Select which targets a single planned probe runs against.
///
/// When auto-ARP ran, it already covered the local hosts, so IP-level probes
/// target only `routed`. When auto-ARP did not run (non-root, `--disable-arp-ping`,
/// or no local targets), IP-level probes must target every host so local-link
/// targets still receive their planned (e.g. TCP-connect) probes. Explicit `-PR`
/// ARP probes always target `routed` here (local hosts are auto-ARP's job).
fn probe_target_set<'a>(
    probe: &DiscoveryProbe,
    auto_arp: bool,
    all_targets: &'a [Ipv4Addr],
    routed: &'a [Ipv4Addr],
) -> &'a [Ipv4Addr] {
    match probe {
        DiscoveryProbe::Arp => routed,
        _ if auto_arp => routed,
        _ => all_targets,
    }
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
    async fn pn_mode_non_root_treats_all_targets_up() {
        // Non-root: ARP can't run, so -Pn falls back to assume-up for every
        // target (routed and local alike) rather than dropping local hosts.
        let plan = DiscoveryPlan {
            mode: DiscoveryMode::SkipDiscoveryTreatAllUp,
            probes: Vec::new(),
            disable_arp_ping: false,
        };
        let targets = vec![Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(2, 2, 2, 2)];
        let result = run_discovery(&plan, &targets, Some(100), false, false).await;
        assert_eq!(result.per_probe.len(), 2);
        assert!(result.per_probe.iter().all(|r| r.is_up));
        assert!(result.per_probe.iter().all(|r| r.reply_type == "user-set"));
        assert_eq!(result.hosts_up(), targets);
    }

    #[tokio::test]
    async fn pn_mode_disable_arp_ping_treats_all_targets_up_even_as_root() {
        // --disable-arp-ping is the documented escape hatch: under -Pn it
        // restores assume-up for local targets too, so no ARP runs and no host
        // is dropped, regardless of privilege.
        let plan = DiscoveryPlan {
            mode: DiscoveryMode::SkipDiscoveryTreatAllUp,
            probes: Vec::new(),
            disable_arp_ping: true,
        };
        let targets = vec![Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(2, 2, 2, 2)];
        let result = run_discovery(&plan, &targets, Some(100), false, true).await;
        assert_eq!(result.per_probe.len(), 2);
        assert!(result.per_probe.iter().all(|r| r.is_up && r.reply_type == "user-set"));
        assert_eq!(result.packets_sent, 0);
    }

    #[test]
    fn tcp_connect_probe_targets_all_hosts_when_auto_arp_off() {
        // Non-root / --disable-arp-ping / no local hosts: auto_arp == false.
        // A local-link target would land only in `all_targets`, not `routed`,
        // so the planned TCP-connect probe must run against `all_targets` or it
        // would silently never probe local-link hosts (Issue 3).
        let local = Ipv4Addr::new(192, 168, 1, 5);
        let routed = Ipv4Addr::new(8, 8, 8, 8);
        let all = vec![local, routed];
        let routed_only = vec![routed];

        let probe = DiscoveryProbe::TcpConnect { port: 80 };
        let selected = probe_target_set(&probe, false, &all, &routed_only);
        assert_eq!(selected, all.as_slice());
        assert!(selected.contains(&local));
    }

    #[test]
    fn ip_probe_targets_routed_only_when_auto_arp_on() {
        // Root with auto-ARP active: local hosts handled by ARP, so IP probes
        // only cover routed targets (avoids redundant probing).
        let local = Ipv4Addr::new(192, 168, 1, 5);
        let routed = Ipv4Addr::new(8, 8, 8, 8);
        let all = vec![local, routed];
        let routed_only = vec![routed];

        let probe = DiscoveryProbe::TcpSyn { port: 443 };
        let selected = probe_target_set(&probe, true, &all, &routed_only);
        assert_eq!(selected, routed_only.as_slice());
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
