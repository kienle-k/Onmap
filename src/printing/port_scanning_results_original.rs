use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Instant;
use chrono::Local;
use crate::models::{PortScanSingleResult, PortScanAllResult, PortStateReasons, PortStates};
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

    // --- DNS resolution phase (batch, for verbosity messages) ---
    let host_count = results_by_ip.len();
    log::info!(
        "Initiating Parallel DNS resolution of {} host(s). at {}",
        host_count,
        Local::now().format("%H:%M")
    );
    let dns_start = Instant::now();

    let mut hostname_map: HashMap<IpAddr, String> = HashMap::new();
    let mut dns_ok = 0usize;
    let mut dns_nx = 0usize;
    for ip_address in results_by_ip.keys() {
        let hostname = if let IpAddr::V4(ipv4_addr) = ip_address {
            match resolve_hostname(ipv4_addr).await {
                Some(h) => { dns_ok += 1; h }
                None    => { dns_nx += 1; "-".to_string() }
            }
        } else {
            dns_nx += 1;
            "-".to_string()
        };
        hostname_map.insert(*ip_address, hostname);
    }

    let dns_elapsed = dns_start.elapsed().as_secs_f64();
    log::info!(
        "Completed Parallel DNS resolution of {} host(s). at {}, {:.2}s elapsed",
        host_count,
        Local::now().format("%H:%M"),
        dns_elapsed
    );
    log::trace!(
        "DNS resolution of {} IPs took {:.2}s. Mode: Async [#: {}, OK: {}, NX: {}, DR: 0, SF: 0, TR: {}, CN: 0]",
        host_count, dns_elapsed, host_count, dns_ok, dns_nx, host_count
    );

    // --- Per-host printing ---
    let show_reason = log::max_level() >= log::LevelFilter::Debug;

    for (ip_address, host_results) in results_by_ip.iter() {

        let hostname = hostname_map.get(ip_address).map(String::as_str).unwrap_or("-");
        println!("Onmap scan report for {} ({})", hostname, ip_address);

        // verbosity 2: "Host is up, received user-set"
        if show_reason {
            println!("Host is up, received user-set");
        }

        // Filter for only open or open|filtered ports first
        let open_ports: Vec<&PortScanSingleResult> = host_results.iter()
            .filter(|r| r.port_state == PortStates::Open || r.port_state == PortStates::OpenOrFiltered)
            .cloned()
            .collect();

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

            // verbosity 2: reason breakdown for hidden ports
            if show_reason {
                let mut reason_counts: HashMap<&str, usize> = HashMap::new();
                for r in host_results.iter() {
                    if r.port_state == PortStates::Closed || r.port_state == PortStates::Filtered {
                        let name = match r.reason {
                            PortStateReasons::Reset | PortStateReasons::Unfiltered => "resets",
                            PortStateReasons::Timeout                              => "no-responses",
                            PortStateReasons::SynAck                               => "syn-acks",
                            PortStateReasons::UdpResponse                          => "udp-responses",
                            PortStateReasons::IcmpPortUnreachable                  => "port-unreaches",
                        };
                        *reason_counts.entry(name).or_insert(0) += 1;
                    }
                }
                let mut parts: Vec<String> = reason_counts
                    .iter()
                    .map(|(k, v)| format!("{} {}", v, k))
                    .collect();
                parts.sort();
                println!("Reason: {}", parts.join(", "));
            }
        }

        if !open_ports.is_empty() {

            let mut sorted_open_ports = open_ports.clone();
            sorted_open_ports.sort_by_key(|r| r.port);

            if show_reason {
                println!("{:<10} {:<14} {:<20} {}", "PORT", "STATE", "SERVICE", "REASON");
            } else {
                println!("{:<7}  {:<14} {}", "PORT", "STATE", "SERVICE");
            }

            for port_result in sorted_open_ports {
                let state_str = match port_result.port_state {
                    PortStates::Open          => "open",
                    PortStates::OpenOrFiltered => "open|filtered",
                    _                          => "unknown",
                };
                if show_reason {
                    let reason_str = match port_result.reason {
                        PortStateReasons::SynAck                               => format!("syn-ack ttl {}", port_result.ttl),
                        PortStateReasons::Reset | PortStateReasons::Unfiltered => format!("reset ttl {}", port_result.ttl),
                        PortStateReasons::Timeout                              => "no-response".to_string(),
                        PortStateReasons::UdpResponse                          => format!("udp-response ttl {}", port_result.ttl),
                        PortStateReasons::IcmpPortUnreachable                  => "port-unreach".to_string(),
                    };
                    println!("{:<10} {:<14} {:<20} {}", port_result.port, state_str, port_result.service, reason_str);
                } else {
                    println!(
                        "{:<7}  {:<14} {}",
                        &port_result.port.to_string(),
                        state_str,
                        &port_result.service
                    );
                }
            }
        } else if !unfiltered_ports.is_empty() {

            let mut sorted_unfiltered_ports = unfiltered_ports.clone();
            sorted_unfiltered_ports.sort_by_key(|r| r.port);

            if show_reason {
                println!("{:<10} {:<14} {:<20} {}", "PORT", "STATE", "SERVICE", "REASON");
            } else {
                println!("{:<7}  {:<14} {}", "PORT", "STATE", "SERVICE");
            }

            for port_result in sorted_unfiltered_ports {
                if show_reason {
                    let reason_str = format!("reset ttl {}", port_result.ttl);
                    println!("{:<10} {:<14} {:<20} {}", port_result.port, "unfiltered", port_result.service, reason_str);
                } else {
                    println!(
                        "{:<7}  {:<14} {}",
                        &port_result.port.to_string(),
                        "unfiltered",
                        &port_result.service
                    );
                }
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