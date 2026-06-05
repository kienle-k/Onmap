use crate::models::{HostDiscoveryAllResult, HostDiscoverySingleResult};
use chrono::{DateTime, Local};
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

fn epoch_secs(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

fn xml_time(t: SystemTime) -> String {
    let dt: DateTime<Local> = t.into();
    dt.format("%a %b %e %H:%M:%S %Y").to_string()
}

fn xml_attr(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('"', "&quot;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn host_reason_name(reason: &str) -> &str {
    if reason.starts_with("SYN-ACK") {
        "syn-ack"
    } else if reason.starts_with("RST")
        || reason.contains("ConnectionRefused")
        || reason.contains("connection refused")
    {
        "reset"
    } else if reason == "ARP reply" {
        "arp-response"
    } else if reason == "ICMP echo reply" {
        "echo-reply"
    } else if reason.contains("timestamp") {
        "timestamp-reply"
    } else if reason.contains("UDP") {
        "udp-response"
    } else if reason == "no response" || reason.starts_with("Error:") {
        "no-response"
    } else {
        reason
    }
}

pub fn save_to_file_xml_host_discovery(
    path: &str,
    results: (&Vec<HostDiscoverySingleResult>, &HostDiscoveryAllResult),
    verbosity: u8,
) -> std::io::Result<()> {
    let (single_results, summary) = results;
    let mut file = File::create(path)?;

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
    writeln!(file, "  <verbose level=\"{}\"/>", verbosity)?;
    writeln!(file, "  <debugging level=\"0\"/>")?;

    for host in single_results {
        if !host.is_up && verbosity == 0 {
            continue;
        }

        writeln!(file, "  <host>")?;
        writeln!(
            file,
            "    <status state=\"{}\" reason=\"{}\" reason_ttl=\"{}\"/>",
            if host.is_up { "up" } else { "down" },
            xml_attr(host_reason_name(&host.reply_type)),
            host.ttl
        )?;
        writeln!(
            file,
            "    <address addr=\"{}\" addrtype=\"{}\"/>",
            host.ip_address,
            addrtype(host.ip_address)
        )?;

        if let Some(dns) = &host.dns_resolve {
            writeln!(
                file,
                "    <hostnames><hostname name=\"{}\" type=\"PTR\"/></hostnames>",
                xml_attr(dns)
            )?;
        }
        writeln!(file, "  </host>")?;
    }

    let total_hosts = summary.scanned_addresses.len();
    let hosts_up = summary.hosts_up;
    let hosts_down = total_hosts as u64 - hosts_up;
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

    println!("Successfully saved host discovery results to: {}", path);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::net::Ipv4Addr;
    use std::time::{Duration, SystemTime};

    #[test]
    fn writes_nmaprun_header_and_hides_down_hosts_by_default() {
        let up_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let down_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2));
        let hosts = vec![
            HostDiscoverySingleResult {
                ip_address: up_ip,
                dns_resolve: Some("up.example".to_string()),
                latency: Some(Duration::from_millis(2)),
                is_up: true,
                reply_type: "SYN-ACK port 80".to_string(),
                ttl: 64,
            },
            HostDiscoverySingleResult {
                ip_address: down_ip,
                dns_resolve: None,
                latency: None,
                is_up: false,
                reply_type: "no response".to_string(),
                ttl: 0,
            },
        ];
        let summary = HostDiscoveryAllResult {
            scanned_addresses: vec![up_ip, down_ip],
            ports_per_host: 1,
            hosts_up: 1,
            hosts_dns_resolution: 1,
            start_time: SystemTime::now(),
            end_time: SystemTime::now(),
            packets_sent: 2,
            dns_elapsed_secs: 0.0,
        };

        let path = std::env::temp_dir().join(format!("onmap-host-xml-{}.xml", std::process::id()));
        save_to_file_xml_host_discovery(path.to_str().unwrap(), (&hosts, &summary), 0).unwrap();
        let xml = fs::read_to_string(&path).unwrap();
        let _ = fs::remove_file(&path);

        assert!(xml.contains("<!DOCTYPE nmaprun>"));
        assert!(xml.contains("<nmaprun scanner=\"onmap\""));
        assert!(xml.contains("startstr=\""));
        assert!(xml.contains("xmloutputversion=\"1.05\""));
        assert!(xml.contains("<verbose level=\"0\"/>"));
        assert!(xml.contains("<debugging level=\"0\"/>"));
        assert!(xml.contains("<status state=\"up\" reason=\"syn-ack\" reason_ttl=\"64\"/>"));
        assert!(!xml.contains("<status state=\"down\""));
        assert!(!xml.contains("192.0.2.2"));
        assert!(
            xml.contains("<hostnames><hostname name=\"up.example\" type=\"PTR\"/></hostnames>")
        );
        assert!(!xml.contains("<times "));
        assert!(!xml.contains("<downhosts "));
        assert!(xml.contains("<hosts up=\"1\" down=\"1\" total=\"2\"/>"));
        assert!(xml.contains("</nmaprun>"));
    }

    #[test]
    fn writes_down_hosts_when_verbose() {
        let down_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2));
        let hosts = vec![HostDiscoverySingleResult {
            ip_address: down_ip,
            dns_resolve: None,
            latency: None,
            is_up: false,
            reply_type: "no response".to_string(),
            ttl: 0,
        }];
        let summary = HostDiscoveryAllResult {
            scanned_addresses: vec![down_ip],
            ports_per_host: 1,
            hosts_up: 0,
            hosts_dns_resolution: 0,
            start_time: SystemTime::now(),
            end_time: SystemTime::now(),
            packets_sent: 1,
            dns_elapsed_secs: 0.0,
        };

        let path =
            std::env::temp_dir().join(format!("onmap-host-xml-v-{}.xml", std::process::id()));
        save_to_file_xml_host_discovery(path.to_str().unwrap(), (&hosts, &summary), 1).unwrap();
        let xml = fs::read_to_string(&path).unwrap();
        let _ = fs::remove_file(&path);

        assert!(xml.contains("<verbose level=\"1\"/>"));
        assert!(xml.contains("<status state=\"down\" reason=\"no-response\" reason_ttl=\"0\"/>"));
        assert!(xml.contains("<address addr=\"192.0.2.2\" addrtype=\"ipv4\"/>"));
        assert!(xml.contains("<hosts up=\"0\" down=\"1\" total=\"1\"/>"));
    }

    #[test]
    fn escapes_xml_attributes() {
        let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 3));
        let hosts = vec![HostDiscoverySingleResult {
            ip_address: ip,
            dns_resolve: Some("a&b\"<c>".to_string()),
            latency: None,
            is_up: true,
            reply_type: "custom & \"bad\"".to_string(),
            ttl: 0,
        }];
        let summary = HostDiscoveryAllResult {
            scanned_addresses: vec![ip],
            ports_per_host: 1,
            hosts_up: 1,
            hosts_dns_resolution: 1,
            start_time: SystemTime::now(),
            end_time: SystemTime::now(),
            packets_sent: 1,
            dns_elapsed_secs: 0.0,
        };

        let path =
            std::env::temp_dir().join(format!("onmap-host-xml-escape-{}.xml", std::process::id()));
        save_to_file_xml_host_discovery(path.to_str().unwrap(), (&hosts, &summary), 0).unwrap();
        let xml = fs::read_to_string(&path).unwrap();
        let _ = fs::remove_file(&path);

        assert!(xml.contains("reason=\"custom &amp; &quot;bad&quot;\""));
        assert!(xml.contains("hostname name=\"a&amp;b&quot;&lt;c&gt;\""));
    }
}
