use crate::models::{PortScanAllResult, PortScanSingleResult};
use crate::output::{port_state_name, protocol_name, summarize_ports};
use crate::resolving::get_service_name::get_service_name;
use chrono::{DateTime, Local};
use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use std::net::IpAddr;

pub fn save_to_file_grepable_port_scan(
    path: &str,
    results: (&Vec<PortScanSingleResult>, &PortScanAllResult),
) -> std::io::Result<()> {
    let (single_results, summary) = results;
    let mut file = File::create(path)?;

    let start_dt: DateTime<Local> = summary.start_time.into();
    writeln!(
        file,
        "# Onmap {} scan initiated {}",
        env!("CARGO_PKG_VERSION"),
        start_dt.format("%a %b %e %H:%M:%S %Y")
    )?;

    // Group by IP, preserving insertion order
    let mut order: Vec<IpAddr> = Vec::new();
    let mut by_ip: HashMap<IpAddr, Vec<&PortScanSingleResult>> = HashMap::new();
    for port_result in single_results {
        by_ip
            .entry(port_result.ip_address)
            .or_insert_with(|| {
                order.push(port_result.ip_address);
                Vec::new()
            })
            .push(port_result);
    }

    for ip in &order {
        let ports = &by_ip[ip];

        // Status line
        writeln!(file, "Host: {} ()\tStatus: Up", ip)?;

        let summary = summarize_ports(ports, 0);

        // Ports line: list shown ports, then the largest collapsed state.
        let port_entries: Vec<String> = summary
            .shown
            .iter()
            .map(|port_result| {
                format!(
                    "{}/{}/{}//{}///",
                    port_result.port,
                    port_state_name(port_result.port_state),
                    protocol_name(port_result.protocol),
                    get_service_name(port_result.protocol, port_result.port)
                )
            })
            .collect();

        let ignored_group = summary.extra.first();

        if !port_entries.is_empty() || ignored_group.is_some() {
            let mut line = format!("Host: {} ()\tPorts: {}", ip, port_entries.join(", "));
            if let Some(group) = ignored_group {
                line.push_str(&format!(
                    "\tIgnored State: {} ({})",
                    port_state_name(group.state),
                    group.count
                ));
            }
            writeln!(file, "{}", line)?;
        }
    }

    let elapsed = summary
        .end_time
        .duration_since(summary.start_time)
        .unwrap_or_default()
        .as_secs_f64();
    let end_dt: DateTime<Local> = summary.end_time.into();
    let total = order.len();
    let up = total;
    writeln!(
        file,
        "# Onmap done at {} -- {} IP address{} ({} host{} up) scanned in {:.2} seconds",
        end_dt.format("%a %b %e %H:%M:%S %Y"),
        total,
        if total == 1 { "" } else { "es" },
        up,
        if up == 1 { "" } else { "s" },
        elapsed
    )?;

    println!("Successfully saved port scan results to: {}", path);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{
        PortScanAllResult, PortScanSingleResult, PortStateReasons, PortStates, Protocols,
    };
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::SystemTime;

    fn make_summary() -> PortScanAllResult {
        let now = SystemTime::now();
        PortScanAllResult {
            ports_scanned: 0,
            packets_sent: 0,
            open_ports: vec![],
            start_time: now,
            end_time: now,
            scan_type: None,
        }
    }

    fn make_port_result(
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
        }
    }

    // Writes to a temp file and returns its contents as a String.
    fn write_and_read(results: (&Vec<PortScanSingleResult>, &PortScanAllResult)) -> String {
        let path = std::env::temp_dir().join(format!(
            "onmap_test_grepable_ps_{}.gnmap",
            rand::random::<u64>()
        ));
        let path_str = path.to_str().unwrap();
        save_to_file_grepable_port_scan(path_str, results).expect("write must not fail");
        let content = std::fs::read_to_string(&path).expect("read must not fail");
        let _ = std::fs::remove_file(&path);
        content
    }

    /// The first line must start with '# Onmap' and contain the crate version.
    #[test]
    fn header_contains_version() {
        let summary = make_summary();
        let content = write_and_read((&vec![], &summary));
        let first = content.lines().next().unwrap_or("");
        assert!(
            first.starts_with("# Onmap"),
            "header should start with '# Onmap', got: {first}"
        );
        assert!(
            first.contains(env!("CARGO_PKG_VERSION")),
            "header should contain the crate version"
        );
    }

    /// Every scanned host must have a 'Status: Up' line.
    #[test]
    fn scanned_host_gets_status_up_line() {
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let results = vec![make_port_result(
            ip,
            80,
            PortStates::Open,
            PortStateReasons::SynAck,
        )];
        let summary = make_summary();
        let content = write_and_read((&results, &summary));
        assert!(
            content.contains("Status: Up"),
            "scanned host should have 'Status: Up' line"
        );
    }

    /// The status line must contain the host's IP address.
    #[test]
    fn status_line_contains_ip_address() {
        let ip = IpAddr::V4(Ipv4Addr::new(172, 16, 0, 5));
        let results = vec![make_port_result(
            ip,
            22,
            PortStates::Open,
            PortStateReasons::SynAck,
        )];
        let summary = make_summary();
        let content = write_and_read((&results, &summary));
        assert!(
            content.contains("172.16.0.5"),
            "status line should contain the IP address"
        );
    }

    /// The ports line must include the port number.
    #[test]
    fn ports_line_contains_port_number() {
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let results = vec![make_port_result(
            ip,
            443,
            PortStates::Open,
            PortStateReasons::SynAck,
        )];
        let summary = make_summary();
        let content = write_and_read((&results, &summary));
        assert!(
            content.contains("443/"),
            "ports line should include the port number '443/'"
        );
    }

    /// The ports line must include the protocol name ('tcp' or 'udp').
    #[test]
    fn ports_line_contains_protocol() {
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let results = vec![make_port_result(
            ip,
            80,
            PortStates::Open,
            PortStateReasons::SynAck,
        )];
        let summary = make_summary();
        let content = write_and_read((&results, &summary));
        assert!(
            content.contains("/tcp/") || content.contains("/udp/"),
            "ports line should contain '/tcp/' or '/udp/'"
        );
    }

    /// The ports line must be labelled 'Ports:'.
    #[test]
    fn ports_line_has_ports_label() {
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let results = vec![make_port_result(
            ip,
            80,
            PortStates::Open,
            PortStateReasons::SynAck,
        )];
        let summary = make_summary();
        let content = write_and_read((&results, &summary));
        assert!(
            content.contains("Ports:"),
            "output should contain a 'Ports:' label"
        );
    }

    /// The footer must start with '# Onmap done at'.
    #[test]
    fn footer_starts_with_onmap_done() {
        let summary = make_summary();
        let content = write_and_read((&vec![], &summary));
        let last = content.lines().last().unwrap_or("");
        assert!(
            last.starts_with("# Onmap done at"),
            "footer should start with '# Onmap done at', got: {last}"
        );
    }

    /// The footer must use the singular form for exactly one address.
    #[test]
    fn footer_uses_singular_for_one_host() {
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let results = vec![make_port_result(
            ip,
            80,
            PortStates::Open,
            PortStateReasons::SynAck,
        )];
        let summary = make_summary();
        let content = write_and_read((&results, &summary));
        assert!(
            content.contains("1 IP address ") || content.contains("1 IP address)"),
            "footer should use singular for 1 host, got: {content}"
        );
    }

    /// The footer must use the plural form for more than one address.
    #[test]
    fn footer_uses_plural_for_multiple_hosts() {
        let results: Vec<PortScanSingleResult> = (1u8..=3)
            .map(|i| {
                make_port_result(
                    IpAddr::V4(Ipv4Addr::new(10, 0, 0, i)),
                    80,
                    PortStates::Open,
                    PortStateReasons::SynAck,
                )
            })
            .collect();
        let summary = make_summary();
        let content = write_and_read((&results, &summary));
        assert!(
            content.contains("3 IP addresses"),
            "footer should report 3 IP addresses, got: {content}"
        );
    }
}
