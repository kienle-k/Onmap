use crate::models::{PortScanAllResult, PortScanSingleResult, PortStates, Protocols};
use chrono::{DateTime, Local};
use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use std::net::IpAddr;

fn state_str(state: PortStates) -> &'static str {
    match state {
        PortStates::Open => "open",
        PortStates::Closed => "closed",
        PortStates::Filtered => "filtered",
        PortStates::Unfiltered => "unfiltered",
        PortStates::OpenOrFiltered => "open|filtered",
        PortStates::ClosedOrFiltered => "closed|filtered",
    }
}

fn proto_str(proto: Protocols) -> &'static str {
    match proto {
        Protocols::TCP => "tcp",
        Protocols::UDP => "udp",
    }
}

pub fn save_to_file_grepable_port_scan(
    path: &str,
    results: (&Vec<PortScanSingleResult>, &PortScanAllResult),
) -> std::io::Result<()> {
    let (single_results, summary) = results;
    let mut file = File::create(path)?;

    let start_dt: DateTime<Local> = summary.start_time.into();
    writeln!(
        file,
        "# Onmap 1.0 scan initiated {}",
        start_dt.format("%a %b %e %H:%M:%S %Y")
    )?;

    // Group by IP, preserving insertion order
    let mut order: Vec<IpAddr> = Vec::new();
    let mut by_ip: HashMap<IpAddr, Vec<&PortScanSingleResult>> = HashMap::new();
    for r in single_results {
        by_ip
            .entry(r.ip_address)
            .or_insert_with(|| {
                order.push(r.ip_address);
                Vec::new()
            })
            .push(r);
    }

    for ip in &order {
        let ports = &by_ip[ip];

        // Status line
        writeln!(file, "Host: {} ()\tStatus: Up", ip)?;

        // Ports line: list all ports, then ignored state for closed/filtered
        let port_entries: Vec<String> = ports
            .iter()
            .filter(|r| r.port_state != PortStates::Closed && r.port_state != PortStates::Filtered)
            .map(|r| {
                format!(
                    "{}/{}/{}//{}///",
                    r.port,
                    state_str(r.port_state),
                    proto_str(r.protocol),
                    r.service
                )
            })
            .collect();

        let ignored_count = ports
            .iter()
            .filter(|r| r.port_state == PortStates::Closed || r.port_state == PortStates::Filtered)
            .count();

        if !port_entries.is_empty() || ignored_count > 0 {
            let mut line = format!("Host: {} ()\tPorts: {}", ip, port_entries.join(", "));
            if ignored_count > 0 {
                let ignored_state = if ports.iter().any(|r| r.port_state == PortStates::Closed) {
                    "closed"
                } else {
                    "filtered"
                };
                line.push_str(&format!(
                    "\tIgnored State: {} ({})",
                    ignored_state, ignored_count
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
