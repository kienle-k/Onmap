use std::collections::HashMap;
use std::net::IpAddr;
use crate::models::{PortScanSingleResult, PortScanAllResult, PortStates};
use crate::resolving::{resolve_hostname};

// Hauptfunktion zum Ausführen des Connect-Scans
pub async fn print_port_scan_results_original(results: &(Vec<PortScanSingleResult>, PortScanAllResult)) {

    println!("");

    let (single_results, all_results) = results;

    let mut results_by_ip: HashMap<IpAddr, Vec<&PortScanSingleResult>> = HashMap::new();
    for result in single_results.iter() {
        results_by_ip
            .entry(result.ip_address)
            .or_insert_with(Vec::new)
            .push(result);
    }

    for (ip_address, host_results) in results_by_ip.iter() {
        
        let mut hostname = String::from("-");
        if let IpAddr::V4(ipv4_addr) = ip_address {
            if let Some(resolved_hostname) = resolve_hostname(&ipv4_addr).await {
                hostname = resolved_hostname;
            }
        }
        
        println!("Onmap scan report for {} ({})", &hostname, &ip_address);
        
        // Filter for only open or open|filtered ports first
        let open_ports: Vec<&PortScanSingleResult> = host_results.iter()
            .filter(|r| r.port_state == PortStates::Open || r.port_state == PortStates::OpenOrFiltered)
            .cloned()
            .collect(); 

        // let closed_ports: Vec<&PortScanSingleResult> = host_results.iter()
        //     .filter(|r| r.port_state == PortStates::Closed)
        //     .cloned()
        //     .collect();
        // let closed_port_num = closed_ports.len();
        

        // Count closed and filtered ports
        let closed_port_num = host_results
            .iter()
            .filter(|r| r.port_state == PortStates::Closed)
            .count();

        let filtered_port_num = host_results
            .iter()
            .filter(|r| r.port_state == PortStates::Filtered)
            .count();

        let unfiltered_ports: Vec<&PortScanSingleResult> = host_results.iter()
            .filter(|r| r.port_state == PortStates::Unfiltered)
            .copied()
            .collect();


        // Debug to show filtered ports
        // let filtered_ports: Vec<&PortScanSingleResult> = host_results.iter()
        //     .filter(|r| r.port_state == PortStates::Filtered)
        //     .copied()
        //     .collect();
        // 
        // for port in filtered_ports {
        //     let protocol_str = match port_result.protocol {
        //         Protocols::TCP => "tcp"
        //     };
        //     println!("{:<7}/{}  open     {}", &port_result.port.to_string(), protocol_str, &port_result.service);  
        // }
        
        // Show either closed port num, filtered port num or both
        if closed_port_num > 0 || filtered_port_num > 0 {
            print!("Not shown: ");
            if closed_port_num > 0 {
                print!("{} closed ports", closed_port_num);
            }
            if filtered_port_num > 0 {
                if closed_port_num > 0 {
                    print!(" and ");
                }
                print!("{} filtered ports", filtered_port_num);
            }
            println!();
        }
        
        if !open_ports.is_empty() {

            let mut sorted_open_ports = open_ports.clone();
            sorted_open_ports.sort_by_key(|r| r.port);
            
            println!("{:<7}  {:<14} {}", "PORT", "STATE", "SERVICE");

            for port_result in sorted_open_ports {
                let state_str = match port_result.port_state {
                    PortStates::Open => "open",
                    PortStates::OpenOrFiltered => "open|filtered",
                    _ => "unknown",
                };
                println!(
                    "{:<7}  {:<14} {}",
                    &port_result.port.to_string(),
                    state_str,
                    &port_result.service
                );
            }
        } else if !unfiltered_ports.is_empty() {

            let mut sorted_unfiltered_ports = unfiltered_ports.clone();
            sorted_unfiltered_ports.sort_by_key(|r| r.port);

            println!("{:<7}  {:<14} {}", "PORT", "STATE", "SERVICE");

            for port_result in sorted_unfiltered_ports {
                println!(
                    "{:<7}  {:<14} {}",
                    &port_result.port.to_string(),
                    "unfiltered",
                    &port_result.service
                );
            }
        } else {
            if !host_results.is_empty() {
                println!("Host is up, but all {} scanned ports are in a 'closed' or 'filtered' state.", host_results.len());
            }
        }
        println!("");
    }

    let elapsed_time = match all_results.end_time.duration_since(all_results.start_time) {
        Ok(duration) => format!("{:.2}", duration.as_secs_f32()),
        Err(_) => String::from("Invalid time calculation"),
    };

    let num_hosts_scanned = results_by_ip.len();

    match num_hosts_scanned {
        0 => println!("Onmap done: 0 IP addresses (0 hosts up) scanned in {} seconds", elapsed_time),    
        1 => println!("Onmap done: 1 IP address (1 host up) scanned in {} seconds", elapsed_time),
        _ => println!("Onmap done: {} IP addresses ({} hosts up) scanned in {} seconds", num_hosts_scanned, num_hosts_scanned, elapsed_time)
    }
    println!(); 
}