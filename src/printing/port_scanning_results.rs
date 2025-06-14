use std::time::Duration;
use prettytable::{Table, Row, Cell, format};
use std::collections::HashMap;
use std::net::IpAddr;
use crate::models::{PortScanSingleResult, PortScanAllResult, PortStates, Protocols, PortStateReasons};

// Helper function to format Duration in a readable way
fn format_duration(duration: &Duration) -> String {
    let total_millis = duration.as_millis();
    if total_millis < 1 {
        format!("<1ms")
    } else if total_millis < 1000 {
        format!("{}ms", total_millis)
    } else {
        let seconds = total_millis / 1000;
        let millis = total_millis % 1000;
        format!("{}s {}ms", seconds, millis)
    }
}

pub fn print_port_scan_results(results: (Vec<PortScanSingleResult>, PortScanAllResult)) {
    println!();
    let (single_results, all_results) = results;
    
    // Print summary information
    println!("=== Port Scan Summary ===");
    println!();
    
    let mut summary_table = Table::new();
    summary_table.set_format(*format::consts::FORMAT_NO_BORDER_LINE_SEPARATOR);
    
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
    
    // Group scan results by IP address
    let mut results_by_ip: HashMap<IpAddr, Vec<&PortScanSingleResult>> = HashMap::new();
    for result in single_results.iter() {
        results_by_ip
            .entry(result.ip_address)
            .or_insert_with(Vec::new)
            .push(result);
    }
    
    // Print detailed port scan information for each host
    for (ip_address, host_results) in results_by_ip.iter() {
        println!("\n=== Host: {} ===", ip_address);
        
        // Filter for only open ports first
        let open_ports: Vec<&PortScanSingleResult> = host_results.iter()
            .filter(|r| r.port_state == PortStates::Open)
            .cloned()
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
            
            // Add each open port as a row, sorted by port number
            let mut sorted_open_ports = open_ports.clone();
            sorted_open_ports.sort_by_key(|r| r.port);
            
            for port_result in sorted_open_ports {
                // Convert enum values to strings for display
                let protocol_str = match port_result.protocol {
                    Protocols::TCP => "TCP"
                    // Other protocols not needed yet
                };
                
                let reason_str = match port_result.reason {
                    PortStateReasons::SynAck => "SYN-ACK",
                    PortStateReasons::Reset => "RST",
                    PortStateReasons::Timeout => "Timeout"
                    // Other reasons not needed yet
                };
                
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

        /*

        println!("");

        // Filter for only open ports first
        let filtered_ports: Vec<&PortScanSingleResult> = host_results.iter()
            .filter(|r| r.port_state == PortStates::Filtered)
            .cloned()
            .collect();

        if filtered_ports.is_empty() {
            println!("No filtered ports discovered.");
        } else {
            println!("\nFiltered Ports:");
            
            let mut filtered_ports_table = Table::new();
            filtered_ports_table.set_format(*format::consts::FORMAT_BOX_CHARS);
            
            // Add header row
            filtered_ports_table.set_titles(Row::new(vec![
                Cell::new("Port"),
                Cell::new("Protocol"),
                Cell::new("Service"),
                Cell::new("TTL"),
                Cell::new("Reason")
            ]));
            
            // Add each open port as a row, sorted by port number
            let mut sorted_filtered_ports = filtered_ports.clone();
            sorted_filtered_ports.sort_by_key(|r| r.port);
            
            for port_result in sorted_filtered_ports {
                // Convert enum values to strings for display
                let protocol_str = match port_result.protocol {
                    Protocols::TCP => "TCP",
                    Protocols::UDP => "UDP",
                    Protocols::ICMP => "ICMP",
                    // Handle other protocols as needed
                };
                
                let reason_str = match port_result.reason {
                    PortStateReasons::SynAck => "SYN-ACK",
                    PortStateReasons::Reset => "RST",
                    PortStateReasons::Timeout => "Timeout",
                    PortStateReasons::NoResponse => "No Response"
                    // Handle other reasons as needed
                };
                
                filtered_ports_table.add_row(Row::new(vec![
                    Cell::new(&port_result.port.to_string()),
                    Cell::new(protocol_str),
                    Cell::new(&port_result.service),
                    Cell::new(&port_result.ttl.to_string()),
                    Cell::new(reason_str)
                ]));
            }
            filtered_ports_table.printstd();
        }
        */
        
    }
    
    println!();
}

// Example usage:
// fn main() {
//     let single_results = vec![
//         PortScanSingleResult {
//             ip_address: "192.168.1.1".parse().unwrap(),
//             port: 80,
//             protocol: Protocols::TCP,
//             port_state: PortStates::Open,
//             ttl: 64,
//             reason: PortStateReasons::SynAck,
//             service: "HTTP".to_string()
//         },
//         // Add more results as needed
//     ];
//
//     let all_results = PortScanAllResult {
//         ports_scanned: 100,
//         packets_sent: 100,
//         open_ports: vec![80],
//         start_time: SystemTime::now(),
//         end_time: SystemTime::now()
//     };
//
//     print_port_scan_results((single_results, all_results));
// }