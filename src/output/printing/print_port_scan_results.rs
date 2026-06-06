use crate::models::{PortScanAllResult, PortScanSingleResult};
use crate::output::{
    format_duration, port_state_name, protocol_display_name, state_reason_display_name,
    summarize_ports, ttl_display_value,
};
use crate::resolving::get_service_name::get_service_name;
use prettytable::{Cell, Row, Table, format};
use std::collections::HashMap;
use std::net::IpAddr;

/// Formats and prints the results of a port scan to the console.
///
/// This function organizes the raw scan data into a human-readable report.
/// The report is split into two main sections:
///
/// 1.  **Global Summary**: A brief table showing aggregate statistics for the
///     entire scan, such as total ports scanned, packets sent, and total duration.
/// 2.  **Per-Host Details**: For each unique IP address scanned, a separate section
///     is printed. This includes a detailed table listing the ports selected by
///     the shared port summary, along with their protocol, service, TTL, and
///     reason.
///
/// If a host has no open ports, a message indicating this is displayed for that host.
///
/// # Arguments
///
/// * `results` - A tuple containing:
///   * A `Vec<PortScanSingleResult>`: A detailed list of results for every single port that was scanned.
///   * A `PortScanAllResult`: The summary statistics for the entire scan operation.
pub fn print_port_scan_results(results: &(Vec<PortScanSingleResult>, PortScanAllResult)) {
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
        Cell::new(&all_results.ports_scanned.to_string()),
    ]));
    summary_table.add_row(Row::new(vec![
        Cell::new("Total packets sent"),
        Cell::new(&all_results.packets_sent.to_string()),
    ]));
    summary_table.add_row(Row::new(vec![
        Cell::new("Open ports discovered"),
        Cell::new(&all_results.open_ports.len().to_string()),
    ]));

    // Calculate and add scan duration
    let duration_str = match all_results.end_time.duration_since(all_results.start_time) {
        Ok(duration) => format_duration(&duration),
        Err(_) => String::from("Invalid time calculation"),
    };
    summary_table.add_row(Row::new(vec![
        Cell::new("Scan duration"),
        Cell::new(&duration_str),
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

        let summary = summarize_ports(host_results, 0);

        if !summary.extra.is_empty() {
            let hidden_count: usize = summary.extra.iter().map(|group| group.count).sum();
            println!("Not shown: {} ports in ignored states.", hidden_count);
        }

        if summary.shown.is_empty() {
            println!("No open ports discovered.");
        } else {
            println!("\nPorts:");

            let mut open_port_table = Table::new();
            open_port_table.set_format(*format::consts::FORMAT_BOX_CHARS);

            // Add header row
            open_port_table.set_titles(Row::new(vec![
                Cell::new("Port"),
                Cell::new("State"),
                Cell::new("Protocol"),
                Cell::new("Service"),
                Cell::new("TTL"),
                Cell::new("Reason"),
            ]));

            for port_result in summary.shown {
                // Add a single result as a row
                open_port_table.add_row(Row::new(vec![
                    Cell::new(&port_result.port.to_string()),
                    Cell::new(port_state_name(port_result.port_state)),
                    Cell::new(protocol_display_name(port_result.protocol)),
                    Cell::new(get_service_name(port_result.protocol, port_result.port)),
                    Cell::new(&ttl_display_value(port_result.ttl)),
                    Cell::new(state_reason_display_name(port_result.reason)),
                ]));
            }

            open_port_table.printstd();
        }
    }

    println!();
}
