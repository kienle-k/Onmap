use crate::models::{HostDiscoverySingleResult, HostDiscoveryAllResult};



pub fn print_host_discovery_results_original(results: (Vec<HostDiscoverySingleResult>, HostDiscoveryAllResult)) {

    println!("");

    let (single_results, all_results) = results;


    // Sort results by IP address for consistent output
    let reachable_hosts: Vec<&HostDiscoverySingleResult> = single_results.iter()
        .filter(|host| host.is_up)
        .collect();
    
    if reachable_hosts.is_empty() {
        println!("No hosts discovered.");
    }else {}
        // Add each host as a row
        for host in reachable_hosts {
            let hostname = match &host.dns_resolve {
                Some(name) => name,
                None => &String::from("-"),
            };

            println!("Onmap scan report for {} ({})", &hostname, &host.ip_address.to_string());

            let status = if host.is_up { "up" } else { "down" };
            
            let latency = match host.latency {
                Some(duration) => duration.as_secs_f32() / 10.0,
                None => -1.0,
            };  
            println!("Host is {} ({:.7}s latency)", status, latency);
            println!("");
    }

    let elapsed_time = match all_results.end_time.duration_since(all_results.start_time) {
        Ok(duration) => format!("{:.2}", duration.as_secs_f32()),
        Err(_) => String::from("Invalid time calculation"),
    };

    let num_hosts_scanned = all_results.scanned_addresses.len();
    let num_hosts_up = all_results.hosts_up;

    if num_hosts_scanned == 0 && num_hosts_up == 0{
        println!(
            "Onmap done: {} IP addresses (0 hosts up) scanned in {} seconds",
            num_hosts_scanned, elapsed_time
        );        
    }if num_hosts_scanned == 1 && num_hosts_up == 0{
        println!(
            "Onmap done: 1 IP address (0 hosts up) scanned in {} seconds",
            elapsed_time
        );        
    }else if num_hosts_scanned == 1 && num_hosts_up == 1{
        println!(
            "Onmap done: 1 IP address (1 host up) scanned in {} seconds",
            elapsed_time
        );
    }else {
        println!(
            "Onmap done: {} IP addresses ({} hosts up) scanned in {} seconds",
            num_hosts_scanned, num_hosts_up, elapsed_time
        );
    }
    println!("");


}

