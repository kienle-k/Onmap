use std::time::Duration;
use std::collections::HashMap;
use std::net::IpAddr;
use crate::models::{PortScanSingleResult, PortScanAllResult, PortStates, Protocols};


// Hauptfunktion zum Ausführen des Connect-Scans
pub fn print_port_scan_results_original(results: (Vec<PortScanSingleResult>, PortScanAllResult)) {
    let (single_results, all_results) = results;

    let mut results_by_ip: HashMap<IpAddr, Vec<&PortScanSingleResult>> = HashMap::new();
    for result in single_results.iter() {
        results_by_ip
            .entry(result.ip_address)
            .or_insert_with(Vec::new)
            .push(result);
    }

    for (ip_address, host_results) in results_by_ip.iter() {
        println!("Onmap scan report for {}", ip_address);
        
        // Filter for only open ports first
        let open_ports: Vec<&PortScanSingleResult> = host_results.iter()
            .filter(|r| r.port_state == PortStates::Open)
            .cloned()
            .collect(); 

        let closed_ports: Vec<&PortScanSingleResult> = host_results.iter()
            .filter(|r| r.port_state == PortStates::Closed)
            .cloned()
            .collect();
        
        let closed_port_num = closed_ports.len();
        
        if closed_port_num > 0 {
            println!("Not shown: {} closed ports", closed_port_num);
        }
        
        if open_ports.is_empty() {
            //println!("No open ports discovered.");
        } else {


            let mut sorted_open_ports = open_ports.clone();
            sorted_open_ports.sort_by_key(|r| r.port);
            
            println!("{:<7}      STATE    SERVICE", "PORT");

            for port_result in sorted_open_ports {
                // Convert enum values to strings for display
                let protocol_str = match port_result.protocol {
                    Protocols::TCP => "tcp",
                    Protocols::UDP => "udp",
                    Protocols::ICMP => "icmp",
                };
                println!("{:<7}/{}  open     {}", &port_result.port.to_string(), protocol_str, &port_result.service);  
            }
        }
        println!("");
    }

    let elapsed_time = match all_results.end_time.duration_since(all_results.start_time) {
        Ok(duration) => format!("{:.2}", duration.as_secs_f32()),
        Err(_) => String::from("Invalid time calculation"),
    };

    let num_hosts_scanned = results_by_ip.len();

    if num_hosts_scanned == 0{
        println!(
            "Onmap done: 0 IP addresses (0 hosts up) scanned in {} seconds",
            elapsed_time
        );        
    }else if num_hosts_scanned == 1{
        println!(
            "Onmap done: 1 IP address (1 host up) scanned in {} seconds",
            elapsed_time
        );
    }else {
        println!(
            "Onmap done: {} IP addresses ({} hosts up) scanned in {} seconds",
            num_hosts_scanned, num_hosts_scanned, elapsed_time
        );
    }
    
}