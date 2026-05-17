use crate::models::{PortScanAllResult, PortScanSingleResult, PortStateReasons, PortStates, Protocols};
use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use std::time::UNIX_EPOCH;

fn addrtype(ip: std::net::IpAddr) -> &'static str {
    match ip {
        std::net::IpAddr::V4(_) => "ipv4",
        std::net::IpAddr::V6(_) => "ipv6",
    }
}

fn protocol_name(protocol: Protocols) -> &'static str {
    match protocol {
        Protocols::TCP => "tcp",
        Protocols::UDP => "udp",
    }
}

fn port_state_name(state: PortStates) -> &'static str {
    match state {
        PortStates::Open => "open",
        PortStates::Closed => "closed",
        PortStates::Filtered => "filtered",
        PortStates::Unfiltered => "unfiltered",
        PortStates::OpenOrFiltered => "open|filtered",
        PortStates::ClosedOrFiltered => "closed|filtered",
    }
}

fn state_reason_name(reason: PortStateReasons) -> &'static str {
    match reason {
        PortStateReasons::SynAck => "syn-ack",
        PortStateReasons::Reset | PortStateReasons::Unfiltered => "reset",
        PortStateReasons::Timeout => "no-response",
        PortStateReasons::UdpResponse => "udp-response",
        PortStateReasons::IcmpPortUnreachable => "port-unreach",
    }
}

fn extraport_reason_name(reason: PortStateReasons) -> &'static str {
    match reason {
        PortStateReasons::SynAck => "syn-acks",
        PortStateReasons::Reset | PortStateReasons::Unfiltered => "resets",
        PortStateReasons::Timeout => "no-responses",
        PortStateReasons::UdpResponse => "udp-responses",
        PortStateReasons::IcmpPortUnreachable => "port-unreaches",
    }
}

fn format_port_ranges(ports: &[u16]) -> String {
    if ports.is_empty() {
        return String::new();
    }

    // Ports arrive pre-sorted, so we can compress them into Nmap-style ranges without cloning or re-sorting the grouped lists
    let mut ranges = Vec::new();
    let mut range_start = ports[0];
    let mut range_end = ports[0];

    for &port in ports.iter().skip(1) {
        if port == range_end + 1 {
            range_end = port;
            continue;
        }

        if range_start == range_end {
            ranges.push(range_start.to_string());
        } else {
            ranges.push(format!("{}-{}", range_start, range_end));
        }

        range_start = port;
        range_end = port;
    }

    if range_start == range_end {
        ranges.push(range_start.to_string());
    } else {
        ranges.push(format!("{}-{}", range_start, range_end));
    }

    ranges.join(",")
}

pub fn save_to_file_xml_port_scan(
    path: &str,
    results: (&Vec<PortScanSingleResult>, &PortScanAllResult),
) -> std::io::Result<()> {
    let (single_results, summary) = results;
    let mut file = File::create(path)?;

    let start_timestamp = summary
        .start_time
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    writeln!(file, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>")?;
    writeln!(
        file,
        "<nmaprun scanner=\"onmap\" start=\"{}\" version=\"1.0\">",
        start_timestamp
    )?;

    let mut host_map: HashMap<std::net::IpAddr, Vec<&PortScanSingleResult>> = HashMap::new();
    for res in single_results {
        host_map.entry(res.ip_address).or_default().push(res);
    }

    let total_hosts = host_map.len();

    for (ip, mut host_results) in host_map {
        host_results.sort_unstable_by_key(|result| result.port);

        writeln!(file, "  <host>")?;
        writeln!(file, "    <status state=\"up\" reason=\"user-set\"/>")?;
        writeln!(
            file,
            "    <address addr=\"{}\" addrtype=\"{}\"/>",
            ip,
            addrtype(ip)
        )?;
        writeln!(file, "    <ports>")?;

        // Keep open ports explicit and summarize the rest by state+reason while
        // still preserving exact port membership via the later ports field.
        let mut extraports: HashMap<PortStates, HashMap<PortStateReasons, Vec<u16>>> = HashMap::new();

        for result in host_results {
            if result.port_state != PortStates::Open {
                extraports
                    .entry(result.port_state)
                    .or_default()
                    .entry(result.reason)
                    .or_default()
                    .push(result.port);
                continue;
            }

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
                result.service
            )?;
            writeln!(file, "      </port>")?;
        }

        let extraport_order = [
            PortStates::Closed,
            PortStates::Filtered,
            PortStates::Unfiltered,
            PortStates::OpenOrFiltered,
            PortStates::ClosedOrFiltered,
        ];

        for state in extraport_order {
            let Some(reason_counts) = extraports.get(&state) else {
                continue;
            };

            let count: usize = reason_counts.values().map(Vec::len).sum();
            writeln!(
                file,
                "      <extraports state=\"{}\" count=\"{}\">",
                port_state_name(state),
                count
            )?;

            let mut reasons: Vec<_> = reason_counts.iter().collect();
            reasons.sort_unstable_by_key(|(reason, _)| extraport_reason_name(**reason));

            for (reason, ports) in reasons {
                // Each summary entry names the exact covered ports so downstream
                // parsers can recover every scanned port deterministically.
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

        writeln!(file, "    </ports>")?;
        writeln!(file, "  </host>")?;
    }

    let end_timestamp = summary
        .end_time
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let elapsed = summary
        .end_time
        .duration_since(summary.start_time)
        .unwrap_or_default()
        .as_secs_f64();
    writeln!(file, "  <runstats>")?;
    writeln!(
        file,
        "    <finished time=\"{}\" elapsed=\"{:.3}\" exit=\"success\"/>",
        end_timestamp,
        elapsed
    )?;
    writeln!(
        file,
        "    <hosts up=\"{}\" down=\"0\" total=\"{}\"/>",
        total_hosts,
        total_hosts
    )?;
    writeln!(file, "  </runstats>")?;
    writeln!(file, "</nmaprun>")?;

    println!("Successfully saved port scan results to: {}", path);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::SystemTime;

    #[test]
    fn writes_open_and_extraports_with_exact_port_membership() {
        let path = std::env::temp_dir().join(format!(
            "onmap-port-scan-xml-{}.xml",
            std::process::id()
        ));
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let results = vec![
            PortScanSingleResult {
                ip_address: ip,
                port: 22,
                protocol: Protocols::TCP,
                port_state: PortStates::Open,
                ttl: 64,
                reason: PortStateReasons::SynAck,
                service: "ssh".to_string(),
            },
            PortScanSingleResult {
                ip_address: ip,
                port: 79,
                protocol: Protocols::TCP,
                port_state: PortStates::Closed,
                ttl: 64,
                reason: PortStateReasons::Reset,
                service: "finger".to_string(),
            },
            PortScanSingleResult {
                ip_address: ip,
                port: 80,
                protocol: Protocols::TCP,
                port_state: PortStates::Closed,
                ttl: 64,
                reason: PortStateReasons::Reset,
                service: "http".to_string(),
            },
            PortScanSingleResult {
                ip_address: ip,
                port: 443,
                protocol: Protocols::TCP,
                port_state: PortStates::Filtered,
                ttl: 0,
                reason: PortStateReasons::Timeout,
                service: "https".to_string(),
            },
            PortScanSingleResult {
                ip_address: ip,
                port: 8080,
                protocol: Protocols::TCP,
                port_state: PortStates::Unfiltered,
                ttl: 0,
                reason: PortStateReasons::Unfiltered,
                service: "http-proxy".to_string(),
            },
        ];
        let summary = PortScanAllResult {
            ports_scanned: 5,
            packets_sent: 5,
            open_ports: vec![22],
            start_time: SystemTime::now(),
            end_time: SystemTime::now(),
        };

        save_to_file_xml_port_scan(path.to_str().unwrap(), (&results, &summary)).unwrap();

        let xml = fs::read_to_string(&path).unwrap();
        let _ = fs::remove_file(&path);

        assert!(xml.contains("<port protocol=\"tcp\" portid=\"22\">"));
        assert!(xml.contains("<state state=\"open\" reason=\"syn-ack\" reason_ttl=\"64\"/>"));
        assert!(xml.contains("<extraports state=\"closed\" count=\"2\">"));
        assert!(xml.contains("<extrareasons reason=\"resets\" count=\"2\" ports=\"79-80\"/>"));
        assert!(xml.contains("<extraports state=\"filtered\" count=\"1\">"));
        assert!(xml.contains("<extrareasons reason=\"no-responses\" count=\"1\" ports=\"443\"/>"));
        assert!(xml.contains("<extraports state=\"unfiltered\" count=\"1\">"));
        assert!(xml.contains("<extrareasons reason=\"resets\" count=\"1\" ports=\"8080\"/>"));
    }

    #[test]
    fn writes_udp_open_or_filtered_extraports_with_exact_port_membership() {
        let path = std::env::temp_dir().join(format!(
            "onmap-udp-port-scan-xml-{}.xml",
            std::process::id()
        ));
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let results = vec![
            PortScanSingleResult {
                ip_address: ip,
                port: 53,
                protocol: Protocols::UDP,
                port_state: PortStates::Open,
                ttl: 64,
                reason: PortStateReasons::SynAck,
                service: "domain".to_string(),
            },
            PortScanSingleResult {
                ip_address: ip,
                port: 54,
                protocol: Protocols::UDP,
                port_state: PortStates::OpenOrFiltered,
                ttl: 0,
                reason: PortStateReasons::Timeout,
                service: "unknown".to_string(),
            },
            PortScanSingleResult {
                ip_address: ip,
                port: 55,
                protocol: Protocols::UDP,
                port_state: PortStates::OpenOrFiltered,
                ttl: 0,
                reason: PortStateReasons::Timeout,
                service: "unknown".to_string(),
            },
            PortScanSingleResult {
                ip_address: ip,
                port: 56,
                protocol: Protocols::UDP,
                port_state: PortStates::ClosedOrFiltered,
                ttl: 0,
                reason: PortStateReasons::Timeout,
                service: "unknown".to_string(),
            },
        ];
        let summary = PortScanAllResult {
            ports_scanned: 4,
            packets_sent: 4,
            open_ports: vec![53],
            start_time: SystemTime::now(),
            end_time: SystemTime::now(),
        };

        save_to_file_xml_port_scan(path.to_str().unwrap(), (&results, &summary)).unwrap();

        let xml = fs::read_to_string(&path).unwrap();
        let _ = fs::remove_file(&path);

        assert!(xml.contains("<port protocol=\"udp\" portid=\"53\">"));
        assert!(xml.contains("<extraports state=\"open|filtered\" count=\"2\">"));
        assert!(xml.contains("<extrareasons reason=\"no-responses\" count=\"2\" ports=\"54-55\"/>"));
        assert!(xml.contains("<extraports state=\"closed|filtered\" count=\"1\">"));
        assert!(xml.contains("<extrareasons reason=\"no-responses\" count=\"1\" ports=\"56\"/>"));
    }
}