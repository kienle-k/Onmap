use std::fs::File;
use std::io::Write;
use std::time::UNIX_EPOCH;
use crate::models::{HostDiscoverySingleResult, HostDiscoveryAllResult};

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

    for host in single_results {
        let state = if host.is_up { "up" } else { "down" };
        writeln!(file, "  <host>")?;
        writeln!(file, "    <status state=\"{}\" reason=\"{}\" reason_ttl=\"{}\"/>", state, host.reply_type, host.ttl)?;
        writeln!(file, "    <address addr=\"{}\" addrtype=\"ipv4\"/>", host.ip_address)?;
        
        if let Some(dns) = &host.dns_resolve {
            writeln!(file, "    <hostnames><hostname name=\"{}\" type=\"PTR\"/></hostnames>", dns)?;
        }
        
        if let Some(latency) = host.latency {
            writeln!(file, "    <times srtt=\"{}\" rttvar=\"0\" to=\"100000\"/>", latency.as_micros())?;
        }
        writeln!(file, "  </host>")?;
    }

    // Footer stats
    let end_timestamp = summary.end_time.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    writeln!(file, "  <runstats>")?;
    writeln!(file, "    <finished time=\"{}\" summary=\"Onmap done; {} hosts up\"/>", end_timestamp, summary.hosts_up)?;
    writeln!(file, "    <hosts up=\"{}\" down=\"{}\" total=\"{}\"/>", summary.hosts_up, summary.scanned_addresses.len() as u64 - summary.hosts_up, summary.scanned_addresses.len())?;
    writeln!(file, "  </runstats>")?;
    writeln!(file, "</onmap>")?;

    println!("Successfully saved host discovery results to: {}", path);
    Ok(())
}