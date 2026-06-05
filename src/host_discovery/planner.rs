//! Central host-discovery planner.
//!
//! Maps CLI flags + privilege into a `DiscoveryPlan` the engine executes.
//! Mirrors Nmap: explicit `-P*` flags replace the default probe set; `-sn`
//! runs discovery only; `-Pn` skips discovery.

use crate::models::{Cli, DiscoveryMode, DiscoveryPlan, DiscoveryProbe};
use crate::parsing::ports::convert_ports;

pub fn plan_discovery(cli: &Cli, is_root: bool) -> Result<DiscoveryPlan, String> {
    if cli.pn && cli.ping_scan {
        return Err("-Pn cannot be combined with -sn".to_string());
    }
    let port_scan_selected = cli.syn_scan || cli.connect_scan || cli.ack_scan || cli.udp_scan;

    if cli.ping_scan && port_scan_selected {
        return Err(
            "-sn (skip port scan) cannot be combined with a port-scan flag (-sS, -sT, -sA, -sU)"
                .to_string(),
        );
    }
    let ports_provided = cli.scan_ports.is_some();

    if cli.ping_scan && ports_provided {
        return Err(
            "-sn (skip port scan) cannot be combined with a port-scan argument (-p)".to_string(),
        );
    }

    let explicit_discovery = cli.icmp_echo
        || cli.icmp_timestamp
        || cli.arp
        || cli.syn_discovery
        || cli.ack_discovery
        || cli.udp_discovery;

    let mode = match (cli.pn, cli.ping_scan) {
        (true, _) => DiscoveryMode::SkipDiscoveryTreatAllUp,
        (false, true) => DiscoveryMode::DiscoveryOnly,
        (false, false) => DiscoveryMode::BeforePortScan,
    };

    // -Pn skips discovery entirely, so the -P* probes never run and root is
    // not needed — let it through regardless of privilege.
    if !is_root && !cli.pn {
        if explicit_discovery || cli.ping_scan {
            eprintln!(
                "warning: Host discovery requires raw sockets; falling back to TCP connect probes."
            );
        }
    }

    let probes = match mode {
        DiscoveryMode::SkipDiscoveryTreatAllUp => Vec::new(),
        _ => select_probes(cli, is_root)?,
    };

    Ok(DiscoveryPlan {
        mode,
        probes,
        disable_arp_ping: cli.disable_arp_ping,
    })
}

fn select_probes(cli: &Cli, is_root: bool) -> Result<Vec<DiscoveryProbe>, String> {
    if !is_root {
        return select_unprivileged_probes(cli);
    }

    let explicit = cli.icmp_echo
        || cli.icmp_timestamp
        || cli.arp
        || cli.syn_discovery
        || cli.ack_discovery
        || cli.udp_discovery;

    if !explicit {
        return Ok(default_set(is_root));
    }

    let mut probes = Vec::new();
    if cli.icmp_echo {
        probes.push(DiscoveryProbe::IcmpEcho);
    }
    if cli.icmp_timestamp {
        probes.push(DiscoveryProbe::IcmpTimestamp);
    }
    if cli.arp {
        probes.push(DiscoveryProbe::Arp);
    }
    if cli.syn_discovery {
        for port in explicit_ports(&cli.syn_discovery_ports, 80)? {
            probes.push(DiscoveryProbe::TcpSyn { port });
        }
    }
    if cli.ack_discovery {
        for port in explicit_ports(&cli.ack_discovery_ports, 80)? {
            probes.push(DiscoveryProbe::TcpAck { port });
        }
    }
    if cli.udp_discovery {
        for port in explicit_ports(&cli.udp_discovery_ports, 40125)? {
            probes.push(DiscoveryProbe::Udp { port });
        }
    }
    Ok(probes)
}

fn select_unprivileged_probes(cli: &Cli) -> Result<Vec<DiscoveryProbe>, String> {
    let explicit = cli.icmp_echo
        || cli.icmp_timestamp
        || cli.arp
        || cli.syn_discovery
        || cli.ack_discovery
        || cli.udp_discovery;

    if !explicit {
        return Ok(default_set(false));
    }

    let mut ports = Vec::new();
    if cli.syn_discovery {
        ports.extend(explicit_ports(&cli.syn_discovery_ports, 80)?);
    }
    if cli.ack_discovery {
        ports.extend(explicit_ports(&cli.ack_discovery_ports, 80)?);
    }
    if cli.udp_discovery {
        ports.extend(explicit_ports(&cli.udp_discovery_ports, 40125)?);
    }

    if ports.is_empty() {
        return Ok(default_set(false));
    }

    Ok(ports
        .into_iter()
        .map(|port| DiscoveryProbe::TcpConnect { port })
        .collect())
}

/// Default probe set when no `-P*` flag is explicit.
/// Root: ICMP echo + TCP SYN 443 + TCP ACK 80 + ICMP timestamp.
/// Non-root: TCP connect 80, 443.
pub fn default_set(is_root: bool) -> Vec<DiscoveryProbe> {
    if is_root {
        vec![
            DiscoveryProbe::IcmpEcho,
            DiscoveryProbe::TcpSyn { port: 443 },
            DiscoveryProbe::TcpAck { port: 80 },
            DiscoveryProbe::IcmpTimestamp,
        ]
    } else {
        vec![
            DiscoveryProbe::TcpConnect { port: 80 },
            DiscoveryProbe::TcpConnect { port: 443 },
        ]
    }
}

fn explicit_ports(spec: &Option<String>, default: u16) -> Result<Vec<u16>, String> {
    match spec {
        Some(s) => convert_ports(s.clone()),
        None => Ok(vec![default]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::Cli;
    use clap::Parser;
    use std::ffi::OsString;

    fn cli_from(args: &[&str]) -> Cli {
        let mut full: Vec<OsString> = vec![OsString::from("onmap")];
        full.extend(args.iter().map(OsString::from));
        Cli::parse_from(Cli::normalize_args(full))
    }

    #[test]
    fn pn_skips_discovery() {
        let cli = cli_from(&["-sS", "-Pn", "1.2.3.4"]);
        let plan = plan_discovery(&cli, true).unwrap();
        assert_eq!(plan.mode, DiscoveryMode::SkipDiscoveryTreatAllUp);
        assert!(plan.probes.is_empty());
    }

    #[test]
    fn sn_root_uses_default_set() {
        let cli = cli_from(&["-sn", "1.2.3.4"]);
        let plan = plan_discovery(&cli, true).unwrap();
        assert_eq!(plan.mode, DiscoveryMode::DiscoveryOnly);
        assert_eq!(
            plan.probes,
            vec![
                DiscoveryProbe::IcmpEcho,
                DiscoveryProbe::TcpSyn { port: 443 },
                DiscoveryProbe::TcpAck { port: 80 },
                DiscoveryProbe::IcmpTimestamp,
            ]
        );
    }

    #[test]
    fn default_before_port_scan_root() {
        let cli = cli_from(&["-sS", "1.2.3.4"]);
        let plan = plan_discovery(&cli, true).unwrap();
        assert_eq!(plan.mode, DiscoveryMode::BeforePortScan);
        assert_eq!(plan.probes.len(), 4);
    }

    #[test]
    fn explicit_pe_replaces_default() {
        let cli = cli_from(&["-sS", "-PE", "1.2.3.4"]);
        let plan = plan_discovery(&cli, true).unwrap();
        assert_eq!(plan.probes, vec![DiscoveryProbe::IcmpEcho]);
    }

    #[test]
    fn explicit_ps_no_ports_defaults_80() {
        let cli = cli_from(&["-sS", "-PS", "1.2.3.4"]);
        let plan = plan_discovery(&cli, true).unwrap();
        assert_eq!(plan.probes, vec![DiscoveryProbe::TcpSyn { port: 80 }]);
    }

    #[test]
    fn explicit_ps_with_ports_emits_one_probe_per_port() {
        let cli = cli_from(&["-sS", "-PS80,443", "1.2.3.4"]);
        let plan = plan_discovery(&cli, true).unwrap();
        assert_eq!(
            plan.probes,
            vec![
                DiscoveryProbe::TcpSyn { port: 80 },
                DiscoveryProbe::TcpSyn { port: 443 },
            ]
        );
    }

    #[test]
    fn explicit_pr_emits_only_arp_probe() {
        let cli = cli_from(&["-sS", "-PR", "1.2.3.4"]);
        let plan = plan_discovery(&cli, true).unwrap();
        assert_eq!(plan.probes, vec![DiscoveryProbe::Arp]);
    }

    #[test]
    fn pn_combined_with_sn_errors() {
        let cli = cli_from(&["-Pn", "-sn", "1.2.3.4"]);
        let err = plan_discovery(&cli, true).expect_err("conflict must error");
        assert!(err.contains("-Pn"));
        assert!(err.contains("-sn"));
    }

    #[test]
    fn sn_combined_with_port_scan_flag_errors() {
        let cli = cli_from(&["-sn", "-sT", "-p", "80", "1.2.3.4"]);
        let err = plan_discovery(&cli, true).expect_err("conflict must error");
        assert!(err.contains("-sn"));
    }

    #[test]
    fn explicit_pe_and_pa_compose() {
        let cli = cli_from(&["-sS", "-PE", "-PA", "1.2.3.4"]);
        let plan = plan_discovery(&cli, true).unwrap();
        assert_eq!(
            plan.probes,
            vec![
                DiscoveryProbe::IcmpEcho,
                DiscoveryProbe::TcpAck { port: 80 }
            ]
        );
    }

    #[test]
    fn default_before_port_scan_non_root_uses_tcp_connect() {
        let cli = cli_from(&["-sT", "1.2.3.4"]);
        let plan = plan_discovery(&cli, false).unwrap();
        assert_eq!(plan.mode, DiscoveryMode::BeforePortScan);
        assert_eq!(
            plan.probes,
            vec![
                DiscoveryProbe::TcpConnect { port: 80 },
                DiscoveryProbe::TcpConnect { port: 443 },
            ]
        );
    }

    #[test]
    fn explicit_pa_ports_non_root_map_to_tcp_connect() {
        let cli = cli_from(&["-PA80,443", "1.2.3.4"]);
        let plan = plan_discovery(&cli, false).unwrap();
        assert_eq!(
            plan.probes,
            vec![
                DiscoveryProbe::TcpConnect { port: 80 },
                DiscoveryProbe::TcpConnect { port: 443 },
            ]
        );
    }

    #[test]
    fn explicit_icmp_only_non_root_falls_back_to_tcp_connect() {
        let cli = cli_from(&["-PE", "1.2.3.4"]);
        let plan = plan_discovery(&cli, false).unwrap();
        assert_eq!(
            plan.probes,
            vec![
                DiscoveryProbe::TcpConnect { port: 80 },
                DiscoveryProbe::TcpConnect { port: 443 },
            ]
        );
    }
}
