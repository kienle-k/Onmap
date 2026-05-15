use std::fs::File;
use std::io::Write;
use std::time::UNIX_EPOCH;
use crate::models::{PortScanSingleResult, PortScanAllResult, PortStates, Protocols};
use std::collections::HashMap;

fn format_port_ranges(ports: &mut Vec<u16>) -> String {
    if ports.is_empty() {
        return String::new();
    }

    ports.sort_unstable();
    ports.dedup();

    let mut ranges: Vec<String> = Vec::new();
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
    results: (&Vec<PortScanSingleResult>, &PortScanAllResult)
) -> std::io::Result<()> {
    let (single_results, summary) = results;
    let mut file = File::create(path)?;

    let start_timestamp = summary.start_time.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    writeln!(file, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>")?;
    writeln!(file, "<nmaprun scanner=\"onmap\" start=\"{}\" version=\"1.0\">", start_timestamp)?;

    // Group single results by IP Address
    let mut host_map: HashMap<std::net::IpAddr, Vec<&PortScanSingleResult>> = HashMap::new();
    for res in single_results {
        host_map.entry(res.ip_address).or_default().push(res);
    }

    for (ip, ports) in host_map {
        writeln!(file, "  <host>")?;
        writeln!(file, "    <status state=\"up\" reason=\"user-set\"/>")?;
        writeln!(file, "    <address addr=\"{}\" addrtype=\"ipv4\"/>", ip)?;
        writeln!(file, "    <ports>")?;

        let mut closed_ports: Vec<u16> = Vec::new();

        for p in &ports {
            if p.port_state == PortStates::Closed {
                closed_ports.push(p.port);
                continue;
            }

            let state_str = match p.port_state {
                PortStates::Open => "open",
                PortStates::Filtered => "filtered",
                PortStates::Unfiltered => "unfiltered",
                PortStates::Closed => "closed",
                PortStates::OpenOrFiltered => "open|filtered",
            };
            let protocol_str = match p.protocol {
                Protocols::TCP => "tcp",
                Protocols::UDP => "udp",
            };
            writeln!(file, "      <port protocol=\"{}\" portid=\"{}\">", protocol_str, p.port)?;
            writeln!(file, "        <state state=\"{}\" reason=\"{:?}\" reason_ttl=\"{}\"/>", state_str, p.reason, p.ttl)?;
            writeln!(file, "        <service name=\"{}\" method=\"table\"/>", p.service)?;
            writeln!(file, "      </port>")?;
        }

        if !closed_ports.is_empty() {
            let closed_ports_list = format_port_ranges(&mut closed_ports);
            writeln!(
                file,
                "      <closed-ports count=\"{}\" ports=\"{}\"/>",
                closed_ports.len(),
                closed_ports_list
            )?;
        }
        
        writeln!(file, "    </ports>")?;
        writeln!(file, "  </host>")?;
    }

    let end_timestamp = summary.end_time.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let elapsed = summary
        .end_time
        .duration_since(summary.start_time)
        .unwrap_or_default()
        .as_secs_f64();
    writeln!(
        file,
        "  <runstats><finished time=\"{}\" elapsed=\"{:.3}\" exit=\"success\"/></runstats>",
        end_timestamp,
        elapsed
    )?;
    writeln!(file, "</nmaprun>")?;

    println!("Successfully saved port scan results to: {}", path);
    Ok(())
}