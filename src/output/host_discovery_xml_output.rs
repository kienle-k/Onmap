use std::fs::File;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr};
use std::time::UNIX_EPOCH;
use crate::models::{HostDiscoverySingleResult, HostDiscoveryAllResult};

fn format_ipv4_ranges(addresses: &mut Vec<Ipv4Addr>) -> Vec<String> {
    if addresses.is_empty() {
        return Vec::new();
    }

    addresses.sort_unstable();
    addresses.dedup();

    let mut ranges: Vec<String> = Vec::new();
    let mut range_start = u32::from(addresses[0]);
    let mut range_end = range_start;

    for addr in addresses.iter().skip(1) {
        let value = u32::from(*addr);
        if value == range_end + 1 {
            range_end = value;
            continue;
        }

        if range_start == range_end {
            ranges.push(Ipv4Addr::from(range_start).to_string());
        } else {
            ranges.push(format!("{}-{}", Ipv4Addr::from(range_start), Ipv4Addr::from(range_end)));
        }

        range_start = value;
        range_end = value;
    }

    if range_start == range_end {
        ranges.push(Ipv4Addr::from(range_start).to_string());
    } else {
        ranges.push(format!("{}-{}", Ipv4Addr::from(range_start), Ipv4Addr::from(range_end)));
    }

    ranges
}

pub fn save_to_file_xml_host_discovery(
    path: &str, 
    results: (&Vec<HostDiscoverySingleResult>, &HostDiscoveryAllResult)
) -> std::io::Result<()> {
    let (single_results, summary) = results;
    let mut file = File::create(path)?;

    // Start header
    let start_timestamp = summary.start_time.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    writeln!(file, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>")?;
    writeln!(file, "<!DOCTYPE onmap>")?;
    writeln!(file, "<onmap start=\"{}\" version=\"1.0\">", start_timestamp)?;

    let mut down_ipv4: Vec<Ipv4Addr> = Vec::new();
    let mut down_other: Vec<IpAddr> = Vec::new();

    for host in single_results {
        if !host.is_up {
            match host.ip_address {
                IpAddr::V4(addr) => down_ipv4.push(addr),
                other => down_other.push(other),
            }
            continue;
        }

        writeln!(file, "  <host>")?;
        writeln!(file, "    <status state=\"up\" reason=\"{}\" reason_ttl=\"{}\"/>", host.reply_type, host.ttl)?;
        writeln!(file, "    <address addr=\"{}\" addrtype=\"ipv4\"/>", host.ip_address)?;

        if let Some(dns) = &host.dns_resolve {
            writeln!(file, "    <hostnames><hostname name=\"{}\" type=\"PTR\"/></hostnames>", dns)?;
        }

        if let Some(latency) = host.latency {
            writeln!(file, "    <times srtt=\"{}\" rttvar=\"0\" to=\"100000\"/>", latency.as_micros())?;
        }
        writeln!(file, "  </host>")?;
    }

    let down_hosts_count = summary.scanned_addresses.len() as u64 - summary.hosts_up;
    let mut down_ranges = format_ipv4_ranges(&mut down_ipv4);
    for addr in down_other {
        down_ranges.push(addr.to_string());
    }

    if !down_ranges.is_empty() {
        writeln!(
            file,
            "  <downhosts count=\"{}\" ranges=\"{}\"/>",
            down_hosts_count,
            down_ranges.join(",")
        )?;
    }

    // Footer stats
    let end_timestamp = summary.end_time.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let elapsed = summary
        .end_time
        .duration_since(summary.start_time)
        .unwrap_or_default()
        .as_secs_f64();
    writeln!(file, "  <runstats>")?;
    writeln!(
        file,
        "    <finished time=\"{}\" elapsed=\"{:.3}\" summary=\"Onmap done; {} hosts up\"/>",
        end_timestamp,
        elapsed,
        summary.hosts_up
    )?;
    writeln!(file, "    <hosts up=\"{}\" down=\"{}\" total=\"{}\"/>", summary.hosts_up, summary.scanned_addresses.len() as u64 - summary.hosts_up, summary.scanned_addresses.len())?;
    writeln!(file, "  </runstats>")?;
    writeln!(file, "</onmap>")?;

    println!("Successfully saved host discovery results to: {}", path);
    Ok(())
}