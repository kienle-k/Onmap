use crate::models::{PortScanAllResult, PortScanSingleResult};
use crate::output::{port_state_name, protocol_name, summarize_ports};
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
                    port_result.service
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
