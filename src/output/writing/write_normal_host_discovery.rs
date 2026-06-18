use crate::models::{HostDiscoveryAllResult, HostDiscoverySingleResult};
use chrono::{DateTime, Local};
use std::fs::File;
use std::io::Write;

pub fn save_to_file_normal_host_discovery(
    path: &str,
    results: (&Vec<HostDiscoverySingleResult>, &HostDiscoveryAllResult),
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

    for host in single_results {
        if !host.is_up {
            continue;
        }
        if let Some(dns) = &host.dns_resolve {
            writeln!(file, "Nmap scan report for {} ({})", dns, host.ip_address)?;
        } else {
            writeln!(file, "Nmap scan report for {}", host.ip_address)?;
        }
        if let Some(latency) = host.latency {
            let secs = latency.as_secs_f64();
            if secs >= 0.001 {
                writeln!(file, "Host is up ({:.4}s latency).", secs)?;
            } else {
                writeln!(file, "Host is up ({:.7}s latency).", secs)?;
            }
        } else {
            writeln!(file, "Host is up.")?;
        }
    }

    let elapsed = summary
        .end_time
        .duration_since(summary.start_time)
        .unwrap_or_default()
        .as_secs_f64();
    let end_dt: DateTime<Local> = summary.end_time.into();
    let total = summary.scanned_addresses.len();
    let up = summary.hosts_up;
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

    println!("Successfully saved host discovery results to: {}", path);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{HostDiscoveryAllResult, HostDiscoveryReply, HostDiscoverySingleResult};
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::SystemTime;

    fn make_summary(scanned: Vec<IpAddr>, hosts_up: u64) -> HostDiscoveryAllResult {
        let now = SystemTime::now();
        HostDiscoveryAllResult {
            scanned_addresses: scanned,
            ports_per_host: 0,
            hosts_up,
            hosts_dns_resolution: 0,
            start_time: now,
            end_time: now,
            packets_sent: 0,
            dns_elapsed_secs: 0.0,
        }
    }

    fn write_and_read(
        results: (&Vec<HostDiscoverySingleResult>, &HostDiscoveryAllResult),
    ) -> String {
        let path = std::env::temp_dir().join(format!(
            "onmap_test_normal_hd_{}.nmap",
            rand::random::<u64>()
        ));
        let path_str = path.to_str().unwrap();
        save_to_file_normal_host_discovery(path_str, results).expect("write must not fail");
        let content = std::fs::read_to_string(&path).expect("read must not fail");
        let _ = std::fs::remove_file(&path);
        content
    }

    fn up_host(ip: IpAddr) -> HostDiscoverySingleResult {
        HostDiscoverySingleResult {
            ip_address: ip,
            dns_resolve: None,
            latency: None,
            is_up: true,
            reply_type: HostDiscoveryReply::IcmpEchoReply,
            ttl: 64,
        }
    }

    /// The first line must start with '# Onmap' and contain the crate version.
    #[test]
    fn header_contains_version() {
        let summary = make_summary(vec![], 0);
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

    /// An up host must produce a 'Nmap scan report for' line.
    #[test]
    fn up_host_produces_scan_report_line() {
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let summary = make_summary(vec![ip], 1);
        let content = write_and_read((&vec![up_host(ip)], &summary));
        assert!(
            content.contains("Nmap scan report for"),
            "up host should produce a 'Nmap scan report for' line"
        );
    }

    /// A down host must not produce any 'Nmap scan report' line.
    #[test]
    fn down_host_produces_no_scan_report_line() {
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let host = HostDiscoverySingleResult {
            ip_address: ip,
            dns_resolve: None,
            latency: None,
            is_up: false,
            reply_type: HostDiscoveryReply::NoResponse,
            ttl: 0,
        };
        let summary = make_summary(vec![ip], 0);
        let content = write_and_read((&vec![host], &summary));
        assert!(
            !content.contains("Nmap scan report for"),
            "down host must not produce a scan report line"
        );
    }

    /// The scan report line must contain the host's IP address.
    #[test]
    fn scan_report_line_contains_ip_address() {
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 42));
        let summary = make_summary(vec![ip], 1);
        let content = write_and_read((&vec![up_host(ip)], &summary));
        assert!(
            content.contains("192.168.1.42"),
            "scan report should contain the IP address"
        );
    }

    /// When a hostname was resolved it must appear before the IP on the report line.
    #[test]
    fn scan_report_includes_hostname_when_resolved() {
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let host = HostDiscoverySingleResult {
            ip_address: ip,
            dns_resolve: Some("myhost.local".to_string()),
            latency: None,
            is_up: true,
            reply_type: HostDiscoveryReply::IcmpEchoReply,
            ttl: 64,
        };
        let summary = make_summary(vec![ip], 1);
        let content = write_and_read((&vec![host], &summary));
        assert!(
            content.contains("myhost.local"),
            "scan report should contain the resolved hostname"
        );
    }

    /// An up host must have a 'Host is up' line.
    #[test]
    fn up_host_has_host_is_up_line() {
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let summary = make_summary(vec![ip], 1);
        let content = write_and_read((&vec![up_host(ip)], &summary));
        assert!(
            content.contains("Host is up"),
            "output should contain 'Host is up'"
        );
    }

    /// When latency is available it must be shown in the 'Host is up' line.
    #[test]
    fn host_is_up_line_includes_latency_when_available() {
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let host = HostDiscoverySingleResult {
            ip_address: ip,
            dns_resolve: None,
            latency: Some(std::time::Duration::from_millis(5)),
            is_up: true,
            reply_type: HostDiscoveryReply::IcmpEchoReply,
            ttl: 64,
        };
        let summary = make_summary(vec![ip], 1);
        let content = write_and_read((&vec![host], &summary));
        assert!(
            content.contains("latency"),
            "'Host is up' line should include latency when available"
        );
    }

    /// The last line must start with '# Onmap done at'.
    #[test]
    fn footer_starts_with_onmap_done() {
        let summary = make_summary(vec![], 0);
        let content = write_and_read((&vec![], &summary));
        let last = content.lines().last().unwrap_or("");
        assert!(
            last.starts_with("# Onmap done at"),
            "footer should start with '# Onmap done at', got: {last}"
        );
    }

    /// The footer must report the correct number of scanned IP addresses.
    #[test]
    fn footer_reports_correct_ip_count() {
        let ips: Vec<IpAddr> = (1u8..=3)
            .map(|i| IpAddr::V4(Ipv4Addr::new(10, 0, 0, i)))
            .collect();
        let summary = make_summary(ips, 0);
        let content = write_and_read((&vec![], &summary));
        assert!(
            content.contains("3 IP addresses"),
            "footer should report 3 IP addresses, got: {content}"
        );
    }

    /// The footer must use the singular form for exactly one address.
    #[test]
    fn footer_uses_singular_for_one_address() {
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let summary = make_summary(vec![ip], 0);
        let content = write_and_read((&vec![], &summary));
        assert!(
            content.contains("1 IP address ") || content.contains("1 IP address)"),
            "footer should use singular for 1 address, got: {content}"
        );
    }

    /// The footer must report the correct hosts-up count.
    #[test]
    fn footer_reports_correct_hosts_up_count() {
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let summary = make_summary(vec![ip], 1);
        let content = write_and_read((&vec![up_host(ip)], &summary));
        assert!(
            content.contains("1 host up"),
            "footer should report '1 host up', got: {content}"
        );
    }
}
