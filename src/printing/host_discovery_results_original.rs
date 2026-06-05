use crate::models::{HostDiscoveryAllResult, HostDiscoveryReply, HostDiscoverySingleResult};
use std::net::IpAddr;

fn reply_type_to_nmap(reply_type: &HostDiscoveryReply) -> &str {
    reply_type.to_nmap_reason()
}

pub fn print_host_discovery_results_original(
    results: &(Vec<HostDiscoverySingleResult>, HostDiscoveryAllResult),
) {
    println!("");

    let (single_results, all_results) = results;

    let show_down = log::max_level() >= log::LevelFilter::Info;
    let show_reason = log::max_level() >= log::LevelFilter::Debug;

    // Sort by IP for consistent output
    let mut sorted: Vec<&HostDiscoverySingleResult> = single_results.iter().collect();
    sorted.sort_by_key(|h| match h.ip_address {
        IpAddr::V4(a) => u32::from(a),
        IpAddr::V6(_) => u32::MAX,
    });

    let up_hosts: Vec<_> = sorted.iter().filter(|h| h.is_up).copied().collect();

    if !show_down && up_hosts.is_empty() {
        println!("No hosts discovered.");
    }

    for host in &sorted {
        if !host.is_up {
            if !show_down {
                continue;
            }
            if show_reason {
                println!(
                    "Onmap scan report for {}  [host down, received no-response]",
                    host.ip_address
                );
            } else {
                println!("Onmap scan report for {}  [host down]", host.ip_address);
            }
        } else {
            if let Some(hostname) = &host.dns_resolve {
                println!("Onmap scan report for {} ({})", hostname, host.ip_address);
            } else {
                println!("Onmap scan report for {}", host.ip_address);
            }

            let latency = host.latency.map(|d| d.as_secs_f32() / 10.0).unwrap_or(-1.0);

            if show_reason {
                let reply = reply_type_to_nmap(&host.reply_type);
                println!("Host is up, received {} ({:.7}s latency).", reply, latency);
            } else {
                println!("Host is up ({:.7}s latency).", latency);
            }
            println!("");
        }
    }

    let elapsed_time = match all_results.end_time.duration_since(all_results.start_time) {
        Ok(duration) => format!("{:.2}", duration.as_secs_f32()),
        Err(_) => String::from("0.00"),
    };

    let num_hosts_scanned = all_results.scanned_addresses.len();
    let num_hosts_up = all_results.hosts_up;

    let hosts_up_str = if num_hosts_up == 1 {
        format!("1 host up")
    } else {
        format!("{} hosts up", num_hosts_up)
    };
    if num_hosts_scanned == 1 {
        println!(
            "Onmap done: 1 IP address ({}) scanned in {} seconds",
            hosts_up_str, elapsed_time
        );
    } else {
        println!(
            "Onmap done: {} IP addresses ({}) scanned in {} seconds",
            num_hosts_scanned, hosts_up_str, elapsed_time
        );
    }
    println!("");
}
