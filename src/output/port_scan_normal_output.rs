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
        writeln!(file)?;
        writeln!(file, "Nmap scan report for {}", ip)?;
        writeln!(file, "Host is up.")?;

        let not_open: usize = ports
            .iter()
            .filter(|r| {
                r.port_state != PortStates::Open && r.port_state != PortStates::OpenOrFiltered
            })
            .count();
        if not_open > 0 {
            let closed_count = ports
                .iter()
                .filter(|r| r.port_state == PortStates::Closed)
                .count();
            let filtered_count = ports
                .iter()
                .filter(|r| r.port_state == PortStates::Filtered)
                .count();
            let label = if closed_count >= filtered_count {
                "closed"
            } else {
                "filtered"
            };
            writeln!(file, "Not shown: {} {} ports", not_open, label)?;
        }

        let open_ports: Vec<&&PortScanSingleResult> = ports
            .iter()
            .filter(|r| {
                r.port_state == PortStates::Open || r.port_state == PortStates::OpenOrFiltered
            })
            .collect();

        if !open_ports.is_empty() {
            writeln!(file, "{:<8} {:<6} {}", "PORT", "STATE", "SERVICE")?;
            for r in &open_ports {
                let port_proto = format!("{}/{}", r.port, proto_str(r.protocol));
                writeln!(
                    file,
                    "{:<8} {:<6} {}",
                    port_proto,
                    state_str(r.port_state),
                    r.service
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
