use crate::models::{PortScanAllResult, PortScanSingleResult, PortStateReasons};
use crate::port_summary::{port_state_name, protocol_name, state_reason_name, summarize_ports};
use crate::resolving::resolve_hostname;
use chrono::Local;
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Instant;

// Hauptfunktion zum Ausführen des Connect-Scans
pub async fn print_port_scan_results_original(
    results: &(Vec<PortScanSingleResult>, PortScanAllResult),
    total_targets: usize,
    verbosity: u8,
) {
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
                Some(h) => {
                    dns_ok += 1;
                    h
                }
                None => {
                    dns_nx += 1;
                    "-".to_string()
                }
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
        host_count,
        dns_elapsed,
        host_count,
        dns_ok,
        dns_nx,
        host_count
    );

    // --- Per-host printing ---
    let show_reason = verbosity >= 2;

    for (ip_address, host_results) in results_by_ip.iter() {
        let hostname = hostname_map
            .get(ip_address)
            .map(String::as_str)
            .unwrap_or("-");
        if hostname == "-" {
            println!("Onmap scan report for {}", ip_address);
        } else {
            println!("Onmap scan report for {} ({})", hostname, ip_address);
        }

        // verbosity 2: "Host is up, received user-set"
        if show_reason {
            println!("Host is up, received user-set");
        }

        // Shared collapse decision (open never collapsed; non-open collapses
        // past the verbosity threshold) — same logic the XML writer uses.
        let summary = summarize_ports(host_results, verbosity);

        // Collapsed states → one "Not shown:" line, largest groups first.
        if !summary.extra.is_empty() {
            let parts: Vec<String> = summary
                .extra
                .iter()
                .map(|g| {
                    let base = format!(
                        "{} {} {} ports",
                        g.count,
                        port_state_name(g.state),
                        protocol_name(g.proto)
                    );
                    if show_reason {
                        let reason = g
                            .reasons
                            .iter()
                            .max_by_key(|(_, ports)| ports.len())
                            .map(|(r, _)| state_reason_name(*r))
                            .unwrap_or("");
                        format!("{} ({})", base, reason)
                    } else {
                        base
                    }
                })
                .collect();
            println!("Not shown: {}", parts.join(", "));
        }

        if summary.shown.is_empty() {
            if !host_results.is_empty() {
                println!(
                    "All {} scanned ports on {} ({}) are in ignored states.",
                    host_results.len(),
                    hostname,
                    ip_address
                );
            }
        } else {
            if show_reason {
                println!("{:<10} {:<14} {:<20} {}", "PORT", "STATE", "SERVICE", "REASON");
            } else {
                println!("{:<7}  {:<14} {}", "PORT", "STATE", "SERVICE");
            }
            for r in &summary.shown {
                let state = port_state_name(r.port_state);
                if show_reason {
                    let reason = match r.reason {
                        PortStateReasons::Timeout | PortStateReasons::IcmpPortUnreachable => {
                            state_reason_name(r.reason).to_string()
                        }
                        _ => format!("{} ttl {}", state_reason_name(r.reason), r.ttl),
                    };
                    println!("{:<10} {:<14} {:<20} {}", r.port, state, r.service, reason);
                } else {
                    println!("{:<7}  {:<14} {}", &r.port.to_string(), state, &r.service);
                }
            }
        }
        println!("");
    }

    let elapsed_time = match all_results.end_time.duration_since(all_results.start_time) {
        Ok(duration) => format!("{:.2}", duration.as_secs_f32()),
        Err(_) => String::from("Invalid time calculation"),
    };

    // "IP addresses" counts every target given (incl. hosts dropped as down);
    // "hosts up" counts only those that survived discovery and were scanned.
    let hosts_up = results_by_ip.len();
    let ip_word = if total_targets == 1 { "IP address" } else { "IP addresses" };
    let host_word = if hosts_up == 1 { "host" } else { "hosts" };

    println!(
        "Onmap done: {} {} ({} {} up) scanned in {} seconds",
        total_targets, ip_word, hosts_up, host_word, elapsed_time
    );
    println!();
}
