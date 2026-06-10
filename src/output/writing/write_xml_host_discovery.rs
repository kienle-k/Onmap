use crate::models::{HostDiscoveryAllResult, HostDiscoverySingleResult};
use crate::output::host_reply_nmap_reason;
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
            xml_attr(host_reply_nmap_reason(&host.reply_type)),
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
    use crate::models::{HostDiscoveryReply, PortStateReasons};
    use std::fs;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::time::{Duration, SystemTime};

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
        verbosity: u8,
    ) -> String {
        let path = std::env::temp_dir()
            .join(format!("onmap_test_xml_hd_{}.xml", rand::random::<u64>()));
        save_to_file_xml_host_discovery(path.to_str().unwrap(), results, verbosity)
            .expect("write must not fail");
        let content = fs::read_to_string(&path).expect("read must not fail");
        let _ = fs::remove_file(&path);
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

    #[test]
    fn xml_attr_escapes_ampersand() {
        assert_eq!(xml_attr("a&b"), "a&amp;b");
    }

    #[test]
    fn xml_attr_escapes_double_quote() {
        assert_eq!(xml_attr("say \"hi\""), "say &quot;hi&quot;");
    }

    #[test]
    fn xml_attr_escapes_less_than() {
        assert_eq!(xml_attr("a<b"), "a&lt;b");
    }

    #[test]
    fn xml_attr_escapes_greater_than() {
        assert_eq!(xml_attr("a>b"), "a&gt;b");
    }

    #[test]
    fn xml_attr_leaves_plain_text_unchanged() {
        assert_eq!(xml_attr("hello world"), "hello world");
    }

    #[test]
    fn addrtype_returns_ipv4_for_v4_address() {
        assert_eq!(addrtype(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))), "ipv4");
    }

    #[test]
    fn addrtype_returns_ipv6_for_v6_address() {
        assert_eq!(addrtype(IpAddr::V6(Ipv6Addr::LOCALHOST)), "ipv6");
    }

    /// The output must begin with the XML declaration.
    #[test]
    fn output_starts_with_xml_declaration() {
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let summary = make_summary(vec![ip], 0);
        let content = write_and_read((&vec![], &summary), 0);
        assert!(
            content.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"),
            "output should start with XML declaration"
        );
    }

    /// The root element must be <nmaprun>.
    #[test]
    fn output_has_nmaprun_root_element() {
        let summary = make_summary(vec![], 0);
        let content = write_and_read((&vec![], &summary), 0);
        assert!(content.contains("<nmaprun "), "output should contain <nmaprun> root element");
        assert!(content.contains("</nmaprun>"), "output should close </nmaprun>");
    }

    /// The crate version must appear in the <nmaprun> opening tag.
    #[test]
    fn nmaprun_contains_crate_version() {
        let summary = make_summary(vec![], 0);
        let content = write_and_read((&vec![], &summary), 0);
        assert!(
            content.contains(env!("CARGO_PKG_VERSION")),
            "<nmaprun> should carry the crate version"
        );
    }

    /// An up host must produce a `<status state="up">` element.
    #[test]
    fn up_host_has_status_state_up() {
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let summary = make_summary(vec![ip], 1);
        let content = write_and_read((&vec![up_host(ip)], &summary), 0);
        assert!(
            content.contains("state=\"up\""),
            "up host should have state=\"up\""
        );
    }

    /// A down host must be omitted at verbosity 0.
    #[test]
    fn down_host_omitted_at_verbosity_zero() {
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
        let content = write_and_read((&vec![host], &summary), 0);
        assert!(
            !content.contains("<host>"),
            "down host should not appear at verbosity 0"
        );
    }

    /// The <address> element must carry the correct addrtype attribute.
    #[test]
    fn address_element_has_correct_addrtype() {
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let summary = make_summary(vec![ip], 1);
        let content = write_and_read((&vec![up_host(ip)], &summary), 0);
        assert!(
            content.contains("addrtype=\"ipv4\""),
            "IPv4 host should have addrtype=\"ipv4\""
        );
    }

    /// When no DNS name is available no <hostnames> element must be emitted.
    #[test]
    fn no_hostname_element_when_dns_not_resolved() {
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let summary = make_summary(vec![ip], 1);
        let content = write_and_read((&vec![up_host(ip)], &summary), 0);
        assert!(
            !content.contains("<hostnames>"),
            "no <hostnames> element should be emitted when DNS is absent"
        );
    }

    /// When DNS resolves the hostname must appear inside a <hostnames> element.
    #[test]
    fn hostname_element_present_when_dns_resolved() {
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
        let content = write_and_read((&vec![host], &summary), 0);
        assert!(
            content.contains("<hostnames>"),
            "<hostnames> element should be present when DNS was resolved"
        );
        assert!(
            content.contains("myhost.local"),
            "hostname should contain the resolved name"
        );
    }

    /// The <runstats> block must be present and carry the <hosts> element.
    #[test]
    fn runstats_contains_hosts_element() {
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let summary = make_summary(vec![ip], 1);
        let content = write_and_read((&vec![up_host(ip)], &summary), 0);
        assert!(
            content.contains("<runstats>"),
            "output should contain <runstats>"
        );
        assert!(
            content.contains("<hosts "),
            "runstats should contain a <hosts> element"
        );
    }

    /// The summary line must use the singular form for exactly one address.
    #[test]
    fn summary_line_uses_singular_for_one_address() {
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let summary = make_summary(vec![ip], 0);
        let content = write_and_read((&vec![], &summary), 0);
        assert!(
            content.contains("1 IP address"),
            "summary should use singular for 1 address, got: {content}"
        );
    }

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
                reply_type: HostDiscoveryReply::TcpSyn {
                    port: 80,
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
        assert!(xml.contains("<status state=\"up\" reason=\"syn-ack\" reason_ttl=\"0\"/>"));
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
            reply_type: HostDiscoveryReply::NoResponse,
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
            reply_type: HostDiscoveryReply::Custom("custom & \"bad\"".to_string()),
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

        assert!(xml.contains("reason=\"user-set\""));
        assert!(xml.contains("hostname name=\"a&amp;b&quot;&lt;c&gt;\""));
    }
}
