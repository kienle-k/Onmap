use prettytable::{Table, Row, Cell, format};
use std::collections::HashMap;
use std::net::IpAddr;
use crate::models::{PortScanSingleResult, PortScanAllResult, PortStates, Protocols, PortStateReasons};
use super::format_duration;

/// Formats and prints the results of a port scan to the console.
///
/// This function organizes the raw scan data into a human-readable report.
/// The report is split into two main sections:
///
/// 1.  **Global Summary**: A brief table showing aggregate statistics for the
///     entire scan, such as total ports scanned, packets sent, and total duration.
/// 2.  **Per-Host Details**: For each unique IP address scanned, a separate section
///     is printed. This includes a detailed table listing all **open ports**,
///     along with their protocol, determined service, TTL, and the reason they
///     were marked as open.
///
/// If a host has no open ports, a message indicating this is displayed for that host.
///
/// # Arguments
///
/// * `results` - A tuple containing:
///   * A `Vec<PortScanSingleResult>`: A detailed list of results for every single port that was scanned.
///   * A `PortScanAllResult`: The summary statistics for the entire scan operation.
pub fn print_port_scan_results(results: (Vec<PortScanSingleResult>, PortScanAllResult)) {
    println!();
    let (single_results, all_results) = results;

    // Print summary information
    println!("=== Port Scan Summary ===");
    println!();

    let mut summary_table = Table::new();
    summary_table.set_format(*format::consts::FORMAT_NO_BORDER_LINE_SEPARATOR);

    // Print different rows for every field in the PortScanAllResult struct
    summary_table.add_row(Row::new(vec![
        Cell::new("Ports scanned per host"),
        Cell::new(&all_results.ports_scanned.to_string())
    ]));
    summary_table.add_row(Row::new(vec![
        Cell::new("Total packets sent"),
        Cell::new(&all_results.packets_sent.to_string())
    ]));
    summary_table.add_row(Row::new(vec![
        Cell::new("Open ports discovered"),
        Cell::new(&all_results.open_ports.len().to_string())
    ]));

    // Calculate and add scan duration
    let duration_str = match all_results.end_time.duration_since(all_results.start_time) {
        Ok(duration) => format_duration(&duration),
        Err(_) => String::from("Invalid time calculation"),
    };
    summary_table.add_row(Row::new(vec![
        Cell::new("Scan duration"),
        Cell::new(&duration_str)
    ]));

    summary_table.printstd();

    // Group scan results by IP address for per-host reporting
    let mut results_by_ip: HashMap<IpAddr, Vec<&PortScanSingleResult>> = HashMap::new();
    for result in single_results.iter() {
        results_by_ip
            .entry(result.ip_address)
            .or_default()
            .push(result);
    }

    // Print detailed port scan information for each host
    for (ip_address, host_results) in results_by_ip.iter() {
        println!("\n=== Host: {} ===", ip_address);

        // Filter for only open ports to display them
        let open_ports: Vec<&PortScanSingleResult> = host_results.iter()
            .filter(|r| r.port_state == PortStates::Open)
            .copied()
            .collect();

        if open_ports.is_empty() {
            println!("No open ports discovered.");
        } else {
            println!("\nOpen Ports:");

            let mut open_port_table = Table::new();
            open_port_table.set_format(*format::consts::FORMAT_BOX_CHARS);

            // Add header row
            open_port_table.set_titles(Row::new(vec![
                Cell::new("Port"),
                Cell::new("Protocol"),
                Cell::new("Service"),
                Cell::new("TTL"),
                Cell::new("Reason")
            ]));

            // Add each open port as a row, sorted by port number for consistency
            let mut sorted_open_ports = open_ports;
            sorted_open_ports.sort_by_key(|r| r.port);

            for port_result in sorted_open_ports {
                // Convert enum values to strings for display
                let protocol_str = match port_result.protocol {
                    Protocols::TCP => "TCP",
                };

                let reason_str = match port_result.reason {
                    PortStateReasons::SynAck => "SYN-ACK",
                    PortStateReasons::Reset => "RST",
                    PortStateReasons::Timeout => "Timeout",
                };

                // Add a single result as a row
                open_port_table.add_row(Row::new(vec![
                    Cell::new(&port_result.port.to_string()),
                    Cell::new(protocol_str),
                    Cell::new(&port_result.service),
                    Cell::new(&port_result.ttl.to_string()),
                    Cell::new(reason_str)
                ]));
            }

            open_port_table.printstd();
        }
    }

    println!();
}