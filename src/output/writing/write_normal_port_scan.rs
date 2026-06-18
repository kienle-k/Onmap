use crate::models::{PortScanAllResult, PortScanSingleResult, PortStates};
use crate::output::{port_state_name, protocol_name};
use crate::resolving::get_service_name::get_service_name;
use chrono::{DateTime, Local};
use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use std::net::IpAddr;

pub fn save_to_file_normal_port_scan(
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

    // Group by IP, preserving insertion order via a vec of keys
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
        writeln!(file)?;
        writeln!(file, "Nmap scan report for {}", ip)?;
        writeln!(file, "Host is up.")?;

        let not_open: usize = ports
            .iter()
            .filter(|port_result| {
                port_result.port_state != PortStates::Open
                    && port_result.port_state != PortStates::OpenOrFiltered
            })
            .count();
        if not_open > 0 {
            let closed_count = ports
                .iter()
                .filter(|port_result| port_result.port_state == PortStates::Closed)
                .count();
            let filtered_count = ports
                .iter()
                .filter(|port_result| port_result.port_state == PortStates::Filtered)
                .count();
            let ignored_state = if closed_count >= filtered_count {
                PortStates::Closed
            } else {
                PortStates::Filtered
            };
            writeln!(
                file,
                "Not shown: {} {} ports",
                not_open,
                port_state_name(ignored_state)
            )?;
        }

        let open_ports: Vec<&&PortScanSingleResult> = ports
            .iter()
            .filter(|port_result| {
                port_result.port_state == PortStates::Open
                    || port_result.port_state == PortStates::OpenOrFiltered
            })
            .collect();

        if !open_ports.is_empty() {
            writeln!(file, "{:<8} {:<6} {}", "PORT", "STATE", "SERVICE")?;
            for port_result in &open_ports {
                let port_proto = format!(
                    "{}/{}",
                    port_result.port,
                    protocol_name(port_result.protocol)
                );
                writeln!(
                    file,
                    "{:<8} {:<6} {}",
                    port_proto,
                    port_state_name(port_result.port_state),
                    get_service_name(port_result.protocol, port_result.port)
                )?;
            }
        }
    }

    writeln!(file)?;
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

    fn make_port_result(ip: IpAddr, port: u16, state: PortStates) -> PortScanSingleResult {
        PortScanSingleResult {
            ip_address: ip,
            port,
            protocol: Protocols::TCP,
            port_state: state,
            ttl: 0,
            reason: PortStateReasons::SynAck,
        }
    }

    fn write_and_read(results: (&Vec<PortScanSingleResult>, &PortScanAllResult)) -> String {
        let path = std::env::temp_dir().join(format!(
            "onmap_test_normal_ps_{}.nmap",
            rand::random::<u64>()
        ));
        let path_str = path.to_str().unwrap();
        save_to_file_normal_port_scan(path_str, results).expect("write must not fail");
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

    /// Every scanned host must have a 'Nmap scan report for' line.
    #[test]
    fn scanned_host_produces_scan_report_line() {
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let results = vec![make_port_result(ip, 80, PortStates::Open)];
        let summary = make_summary();
        let content = write_and_read((&results, &summary));
        assert!(
            content.contains("Nmap scan report for"),
            "scanned host should produce a 'Nmap scan report for' line"
        );
    }

    /// The scan report line must contain the host's IP address.
    #[test]
    fn scan_report_line_contains_ip_address() {
        let ip = IpAddr::V4(Ipv4Addr::new(172, 16, 0, 5));
        let results = vec![make_port_result(ip, 22, PortStates::Open)];
        let summary = make_summary();
        let content = write_and_read((&results, &summary));
        assert!(
            content.contains("172.16.0.5"),
            "scan report line should contain the IP address"
        );
    }

    /// Every scanned host must have a 'Host is up' line.
    #[test]
    fn scanned_host_has_host_is_up_line() {
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let results = vec![make_port_result(ip, 80, PortStates::Open)];
        let summary = make_summary();
        let content = write_and_read((&results, &summary));
        assert!(
            content.contains("Host is up."),
            "output should contain 'Host is up.'"
        );
    }

    /// An open port must appear in the PORT/STATE/SERVICE table.
    #[test]
    fn open_port_appears_in_port_table() {
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let results = vec![make_port_result(ip, 443, PortStates::Open)];
        let summary = make_summary();
        let content = write_and_read((&results, &summary));
        assert!(
            content.contains("443/"),
            "open port 443 should appear in the port table"
        );
    }

    /// A closed port must not appear in the open-ports table but must increment
    /// the 'Not shown' counter.
    #[test]
    fn closed_port_counted_in_not_shown_line() {
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let results = vec![make_port_result(ip, 22, PortStates::Closed)];
        let summary = make_summary();
        let content = write_and_read((&results, &summary));
        assert!(
            content.contains("Not shown:"),
            "closed port should appear in 'Not shown:' line"
        );
    }

    /// The port table header must list PORT, STATE and SERVICE columns.
    #[test]
    fn port_table_has_column_header() {
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let results = vec![make_port_result(ip, 80, PortStates::Open)];
        let summary = make_summary();
        let content = write_and_read((&results, &summary));
        assert!(
            content.contains("PORT") && content.contains("STATE") && content.contains("SERVICE"),
            "port table should have PORT, STATE, SERVICE columns"
        );
    }

    /// The last non-empty line must start with '# Onmap done at'.
    #[test]
    fn footer_starts_with_onmap_done() {
        let summary = make_summary();
        let content = write_and_read((&vec![], &summary));
        let last = content
            .lines()
            .filter(|l| !l.is_empty())
            .last()
            .unwrap_or("");
        assert!(
            last.starts_with("# Onmap done at"),
            "footer should start with '# Onmap done at', got: {last}"
        );
    }

    /// The footer must use the singular form for exactly one host.
    #[test]
    fn footer_uses_singular_for_one_host() {
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let results = vec![make_port_result(ip, 80, PortStates::Open)];
        let summary = make_summary();
        let content = write_and_read((&results, &summary));
        assert!(
            content.contains("1 IP address ") || content.contains("1 IP address)"),
            "footer should use singular for 1 host, got: {content}"
        );
    }

    /// The footer must use the plural form for more than one host.
    #[test]
    fn footer_uses_plural_for_multiple_hosts() {
        let results: Vec<PortScanSingleResult> = (1u8..=3)
            .map(|i| make_port_result(IpAddr::V4(Ipv4Addr::new(10, 0, 0, i)), 80, PortStates::Open))
            .collect();
        let summary = make_summary();
        let content = write_and_read((&results, &summary));
        assert!(
            content.contains("3 IP addresses"),
            "footer should report 3 IP addresses, got: {content}"
        );
    }
}
