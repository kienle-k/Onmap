use super::format_duration;
use crate::models::{HostDiscoveryAllResult, HostDiscoverySingleResult};
use prettytable::{Cell, Row, Table, format};

/// Formats and prints the results of a host discovery scan to the console.
///
/// This function takes the detailed and summary results from a host discovery operation
/// and presents them in two human-readable tables:
///
/// 1.  **Summary Table**: Displays aggregate data like the number of hosts scanned,
///     hosts found to be up, total packets sent, and the total scan duration.
/// 2.  **Host Details Table**: Lists each reachable host, showing its IP address,
///     status, latency, resolved hostname (if available), the type of reply received,
///     and the packet's TTL.
///
/// If no hosts are discovered, a simple message is printed instead of the details table.
///
/// # Arguments
///
/// * `results` - A tuple containing:
///   * A `Vec<HostDiscoverySingleResult>`: The detailed results for each host probed.
///   * A `HostDiscoveryAllResult`: The summary statistics for the entire scan.
pub fn print_host_discovery_results(
    results: &(Vec<HostDiscoverySingleResult>, HostDiscoveryAllResult),
) {
    println!();
    let (single_results, all_results) = results;

    // Print summary information
    println!("=== Host Discovery Summary ===");
    println!();

    let mut summary_table = Table::new();
    summary_table.set_format(*format::consts::FORMAT_NO_BORDER_LINE_SEPARATOR);

    // Print different rows for every field in the HostDiscoveryAllResult struct
    summary_table.add_row(Row::new(vec![
        Cell::new("Hosts scanned"),
        Cell::new(&all_results.scanned_addresses.len().to_string()),
    ]));
    summary_table.add_row(Row::new(vec![
        Cell::new("Hosts up"),
        Cell::new(&all_results.hosts_up.to_string()),
    ]));
    summary_table.add_row(Row::new(vec![
        Cell::new("Hosts with DNS resolution"),
        Cell::new(&all_results.hosts_dns_resolution.to_string()),
    ]));
    summary_table.add_row(Row::new(vec![
        Cell::new("Port probes per host"),
        Cell::new(&all_results.ports_per_host.to_string()),
    ]));
    summary_table.add_row(Row::new(vec![
        Cell::new("Total packets sent"),
        Cell::new(&all_results.packets_sent.to_string()),
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

    // Print detailed host information
    println!("\n=== Host Details ===");

    // Filter for hosts that are reachable to display in the details table
    let reachable_hosts: Vec<&HostDiscoverySingleResult> =
        single_results.iter().filter(|host| host.is_up).collect();

    if reachable_hosts.is_empty() {
        println!("No hosts discovered.");
    } else {
        let mut host_table = Table::new();
        host_table.set_format(*format::consts::FORMAT_BOX_CHARS);

        // Add header row
        host_table.set_titles(Row::new(vec![
            Cell::new("IP Address"),
            Cell::new("Status"),
            Cell::new("Latency"),
            Cell::new("Hostname"),
            Cell::new("Reply Type"),
            Cell::new("TTL"),
        ]));

        // Add each host as a row
        for host in reachable_hosts {
            let status = if host.is_up { "up" } else { "down" };
            let latency = match host.latency {
                Some(duration) => format_duration(&duration),
                None => String::from("-"),
            };
            let hostname = host.dns_resolve.as_deref().unwrap_or("-");

            // Add a single host as a row
            host_table.add_row(Row::new(vec![
                Cell::new(&host.ip_address.to_string()),
                Cell::new(status),
                Cell::new(&latency),
                Cell::new(hostname),
                Cell::new(&host.reply_type),
                Cell::new(&host.ttl.to_string()),
            ]));
        }

        host_table.printstd();
        println!();
    }
}
