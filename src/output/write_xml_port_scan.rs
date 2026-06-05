use crate::models::{
    HostDiscoverySingleResult, PortScanAllResult, PortScanOption, PortScanSingleResult, Protocols,
};
use crate::output::{
    host_reply_nmap_reason,
    port_result_processing::{
        extraport_reason_name, format_port_ranges, port_state_name, protocol_name,
        state_reason_name, summarize_ports,
    },
};
use chrono::{DateTime, Local};
use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};

fn addrtype(ip: IpAddr) -> &'static str {
    match ip {
        IpAddr::V4(_) => "ipv4",
        IpAddr::V6(_) => "ipv6",
    }
}

/// Nmap `<scaninfo type>` value for the scan method.
fn scan_type_name(scan_type: Option<PortScanOption>) -> &'static str {
    match scan_type {
        Some(PortScanOption::SynScan) => "syn",
        Some(PortScanOption::ConnectScan) => "connect",
        Some(PortScanOption::AckScan) => "ack",
        Some(PortScanOption::UdpScan) => "udp",
        _ => "unknown",
    }
}

fn xml_attr(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('"', "&quot;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn epoch_secs(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

fn xml_time(t: SystemTime) -> String {
    let dt: DateTime<Local> = t.into();
    dt.format("%a %b %e %H:%M:%S %Y").to_string()
}

pub fn save_to_file_xml_port_scan(
    path: &str,
    results: (&Vec<PortScanSingleResult>, &PortScanAllResult),
    host_up: &[HostDiscoverySingleResult],
    verbosity: u8,
) -> std::io::Result<()> {
    let (single_results, summary) = results;
    let mut file = File::create(path)?;

    // Per-host liveness reason (+ttl) from the discovery phase, for <status>.
    let host_status: HashMap<IpAddr, (&'static str, u8)> = host_up
        .iter()
        .map(|host| {
            (
                host.ip_address,
                (host_reply_nmap_reason(&host.reply_type), host.ttl),
            )
        })
        .collect();

    // Union of every scanned port, for <scaninfo> numservices/services.
    let mut scanned_ports: Vec<u16> = single_results
        .iter()
        .map(|port_result| port_result.port)
        .collect();
    scanned_ports.sort_unstable();
    scanned_ports.dedup();
    let protocol = single_results
        .first()
        .map(|port_result| port_result.protocol)
        .unwrap_or(Protocols::TCP);

    let start_ts = epoch_secs(summary.start_time);
    let startstr = xml_time(summary.start_time);
    writeln!(file, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>")?;
    writeln!(file, "<!DOCTYPE nmaprun>")?;
    writeln!(
        file,
        "<nmaprun scanner=\"onmap\" start=\"{}\" startstr=\"{}\" version=\"{}\" xmloutputversion=\"1.05\">",
        start_ts,
        startstr,
        env!("CARGO_PKG_VERSION")
    )?;
    writeln!(
        file,
        "  <scaninfo type=\"{}\" protocol=\"{}\" numservices=\"{}\" services=\"{}\"/>",
        scan_type_name(summary.scan_type),
        protocol_name(protocol),
        scanned_ports.len(),
        format_port_ranges(&scanned_ports)
    )?;
    writeln!(file, "  <verbose level=\"{}\"/>", verbosity)?;
    writeln!(file, "  <debugging level=\"0\"/>")?;

    let mut host_map: HashMap<IpAddr, Vec<&PortScanSingleResult>> = HashMap::new();
    for res in single_results {
        host_map.entry(res.ip_address).or_default().push(res);
    }
    let hosts_up = host_map.len();
    let total_hosts = if host_up.is_empty() {
        hosts_up
    } else {
        host_up.len()
    };
    let hosts_down = total_hosts.saturating_sub(hosts_up);

    for (ip, host_results) in host_map {
        let (reason, reason_ttl) = host_status.get(&ip).copied().unwrap_or(("user-set", 0));

        writeln!(file, "  <host>")?;
        writeln!(
            file,
            "    <status state=\"up\" reason=\"{}\" reason_ttl=\"{}\"/>",
            xml_attr(reason),
            reason_ttl
        )?;
        writeln!(
            file,
            "    <address addr=\"{}\" addrtype=\"{}\"/>",
            ip,
            addrtype(ip)
        )?;
        writeln!(file, "    <ports>")?;

        let summary_ports = summarize_ports(&host_results, verbosity);

        // Nmap emits <extraports> before the individual <port> elements.
        for group in &summary_ports.extra {
            writeln!(
                file,
                "      <extraports state=\"{}\" count=\"{}\">",
                port_state_name(group.state),
                group.count
            )?;
            for (reason, ports) in &group.reasons {
                // Exact membership preserved so every scanned port is recoverable.
                writeln!(
                    file,
                    "        <extrareasons reason=\"{}\" count=\"{}\" ports=\"{}\"/>",
                    extraport_reason_name(*reason),
                    ports.len(),
                    format_port_ranges(ports)
                )?;
            }
            writeln!(file, "      </extraports>")?;
        }

        for result in &summary_ports.shown {
            writeln!(
                file,
                "      <port protocol=\"{}\" portid=\"{}\">",
                protocol_name(result.protocol),
                result.port
            )?;
            writeln!(
                file,
                "        <state state=\"{}\" reason=\"{}\" reason_ttl=\"{}\"/>",
                port_state_name(result.port_state),
                state_reason_name(result.reason),
                result.ttl
            )?;
            writeln!(
                file,
                "        <service name=\"{}\" method=\"table\" conf=\"3\"/>",
                xml_attr(&result.service)
            )?;
            writeln!(file, "      </port>")?;
        }

        writeln!(file, "    </ports>")?;
        writeln!(file, "  </host>")?;
    }

    let end_ts = epoch_secs(summary.end_time);
    let elapsed = summary
        .end_time
        .duration_since(summary.start_time)
        .unwrap_or_default()
        .as_secs_f64();
    let timestr = xml_time(summary.end_time);
    let ip_word = if total_hosts == 1 {
        "IP address"
    } else {
        "IP addresses"
    };
    let host_word = if hosts_up == 1 { "host" } else { "hosts" };
    let summary_line = format!(
        "Onmap done at {}; {} {} ({} {} up) scanned in {:.2} seconds",
        timestr, total_hosts, ip_word, hosts_up, host_word, elapsed
    );
    writeln!(file, "  <runstats>")?;
    writeln!(
        file,
        "    <finished time=\"{}\" timestr=\"{}\" elapsed=\"{:.3}\" summary=\"{}\" exit=\"success\"/>",
        end_ts,
        xml_attr(&timestr),
        elapsed,
        xml_attr(&summary_line)
    )?;
    writeln!(
        file,
        "    <hosts up=\"{}\" down=\"{}\" total=\"{}\"/>",
        hosts_up, hosts_down, total_hosts
    )?;
    writeln!(file, "  </runstats>")?;
    writeln!(file, "</nmaprun>")?;

    println!("Successfully saved port scan results to: {}", path);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{HostDiscoveryReply, PortStateReasons, PortStates};
    use std::fs;
    use std::net::Ipv4Addr;
    use std::time::SystemTime;

    fn port(
        ip: IpAddr,
        port: u16,
        state: PortStates,
        reason: PortStateReasons,
    ) -> PortScanSingleResult {
        PortScanSingleResult {
            ip_address: ip,
            port,
            protocol: Protocols::TCP,
            port_state: state,
            ttl: 0,
            reason,
            service: "svc".to_string(),
        }
    }

    #[test]
    fn collapses_states_over_threshold_and_shows_open_and_small_states() {
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let mut results = vec![
            port(ip, 22, PortStates::Open, PortStateReasons::SynAck),
            // 2 filtered ports stay individual (below the 25 threshold).
            port(ip, 81, PortStates::Filtered, PortStateReasons::Timeout),
            port(ip, 82, PortStates::Filtered, PortStateReasons::Timeout),
        ];
        // 26 closed ports collapse into <extraports>.
        for p in 1000..1026 {
            results.push(port(ip, p, PortStates::Closed, PortStateReasons::Reset));
        }
        let mut summary = PortScanAllResult::new();
        summary.scan_type = Some(PortScanOption::SynScan);
        summary.start_time = SystemTime::now();
        summary.end_time = SystemTime::now();

        let path = std::env::temp_dir().join(format!("onmap-xml-{}.xml", std::process::id()));
        save_to_file_xml_port_scan(path.to_str().unwrap(), (&results, &summary), &[], 0).unwrap();
        let xml = fs::read_to_string(&path).unwrap();
        let _ = fs::remove_file(&path);

        assert!(xml.contains("xmloutputversion=\"1.05\""));
        assert!(xml.contains("<!DOCTYPE nmaprun>"));
        assert!(xml.contains("startstr=\""));
        assert!(xml.contains("<verbose level=\"0\"/>"));
        assert!(xml.contains("<debugging level=\"0\"/>"));
        assert!(xml.contains("<scaninfo type=\"syn\" protocol=\"tcp\""));
        // open and the 2 filtered ports are individual.
        assert!(xml.contains("<port protocol=\"tcp\" portid=\"22\">"));
        assert!(xml.contains("<port protocol=\"tcp\" portid=\"81\">"));
        // 26 closed collapse, with exact membership.
        assert!(xml.contains("<extraports state=\"closed\" count=\"26\">"));
        assert!(xml.contains("<extrareasons reason=\"resets\" count=\"26\" ports=\"1000-1025\"/>"));
    }

    #[test]
    fn status_reason_comes_from_discovery_rows() {
        let ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        let results = vec![port(ip, 443, PortStates::Open, PortStateReasons::SynAck)];
        let host_up = vec![HostDiscoverySingleResult {
            ip_address: ip,
            dns_resolve: None,
            latency: None,
            is_up: true,
            reply_type: HostDiscoveryReply::TcpConnect {
                port: 443,
                reason: PortStateReasons::SynAck,
            },
            ttl: 0,
        }];
        let mut summary = PortScanAllResult::new();
        summary.scan_type = Some(PortScanOption::ConnectScan);

        let path = std::env::temp_dir().join(format!("onmap-xml-st-{}.xml", std::process::id()));
        save_to_file_xml_port_scan(path.to_str().unwrap(), (&results, &summary), &host_up, 0)
            .unwrap();
        let xml = fs::read_to_string(&path).unwrap();
        let _ = fs::remove_file(&path);

        assert!(xml.contains("<status state=\"up\" reason=\"syn-ack\" reason_ttl=\"0\"/>"));
        assert!(xml.contains("<scaninfo type=\"connect\""));
    }

    #[test]
    fn status_reason_normalizes_closed_discovery_replies() {
        let ip = IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4));
        let results = vec![port(ip, 443, PortStates::Open, PortStateReasons::SynAck)];
        let host_up = vec![HostDiscoverySingleResult {
            ip_address: ip,
            dns_resolve: None,
            latency: None,
            is_up: true,
            reply_type: HostDiscoveryReply::TcpConnect {
                port: 443,
                reason: PortStateReasons::Reset,
            },
            ttl: 0,
        }];
        let mut summary = PortScanAllResult::new();
        summary.scan_type = Some(PortScanOption::ConnectScan);

        let path = std::env::temp_dir().join(format!("onmap-xml-rst-{}.xml", std::process::id()));
        save_to_file_xml_port_scan(path.to_str().unwrap(), (&results, &summary), &host_up, 0)
            .unwrap();
        let xml = fs::read_to_string(&path).unwrap();
        let _ = fs::remove_file(&path);

        assert!(xml.contains("<status state=\"up\" reason=\"reset\" reason_ttl=\"0\"/>"));
    }

    #[test]
    fn runstats_count_discovery_down_hosts() {
        let up_ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        let down_ip = IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4));
        let results = vec![port(up_ip, 443, PortStates::Open, PortStateReasons::SynAck)];
        let host_up = vec![
            HostDiscoverySingleResult {
                ip_address: up_ip,
                dns_resolve: None,
                latency: None,
                is_up: true,
                reply_type: HostDiscoveryReply::TcpConnect {
                    port: 443,
                    reason: PortStateReasons::SynAck,
                },
                ttl: 0,
            },
            HostDiscoverySingleResult {
                ip_address: down_ip,
                dns_resolve: None,
                latency: None,
                is_up: false,
                reply_type: HostDiscoveryReply::NoResponse,
                ttl: 0,
            },
        ];
        let mut summary = PortScanAllResult::new();
        summary.scan_type = Some(PortScanOption::ConnectScan);

        let path =
            std::env::temp_dir().join(format!("onmap-xml-counts-{}.xml", std::process::id()));
        save_to_file_xml_port_scan(path.to_str().unwrap(), (&results, &summary), &host_up, 0)
            .unwrap();
        let xml = fs::read_to_string(&path).unwrap();
        let _ = fs::remove_file(&path);

        assert!(xml.contains("<hosts up=\"1\" down=\"1\" total=\"2\"/>"));
        assert!(xml.contains("2 IP addresses (1 host up)"));
    }

    #[test]
    fn escapes_xml_attributes_and_uses_unknown_scan_type_without_scan_method() {
        let ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        let results = vec![PortScanSingleResult {
            ip_address: ip,
            port: 443,
            protocol: Protocols::TCP,
            port_state: PortStates::Open,
            ttl: 0,
            reason: PortStateReasons::SynAck,
            service: "a&b\"<c>".to_string(),
        }];
        let summary = PortScanAllResult::new();
        let host_up = vec![HostDiscoverySingleResult {
            ip_address: ip,
            dns_resolve: None,
            latency: None,
            is_up: true,
            reply_type: HostDiscoveryReply::Custom("custom & \"bad\"".to_string()),
            ttl: 0,
        }];

        let path =
            std::env::temp_dir().join(format!("onmap-xml-escape-{}.xml", std::process::id()));
        save_to_file_xml_port_scan(path.to_str().unwrap(), (&results, &summary), &host_up, 0)
            .unwrap();
        let xml = fs::read_to_string(&path).unwrap();
        let _ = fs::remove_file(&path);

        assert!(xml.contains("<scaninfo type=\"unknown\""));
        assert!(xml.contains("reason=\"user-set\""));
        assert!(xml.contains("service name=\"a&amp;b&quot;&lt;c&gt;\""));
    }
}
