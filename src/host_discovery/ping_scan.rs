use std::net::{Ipv4Addr, IpAddr};
use std::process::Command;
use std::time::{Duration, SystemTime, Instant};
use tokio::task;
use futures::stream::{FuturesUnordered, StreamExt};

use crate::models::{HostDiscoverySingleResult, HostDiscoveryAllResult};
use crate::resolving::{resolve_hostname, extract_ttl};


/// Performs ICMP ping scans on the provided IP addresses asynchronously.
/// Returns a vector of individual host results and an aggregate summary.
pub async fn run_ping_scan(
    ip_addresses: Result<Vec<Ipv4Addr>, String>,
    ports: Vec<u16>
) -> (Vec<HostDiscoverySingleResult>, HostDiscoveryAllResult) {
    // Start timing the operation
    let start_time = SystemTime::now();
    let mut packets_sent = 0;
    
    let ips = match ip_addresses {
        Ok(addresses) => addresses,
        Err(error) => {
            println!("Failed to process IP addresses: {}", error);
            return (Vec::new(), HostDiscoveryAllResult {
                scanned_addresses: Vec::new(),
                ports_per_host: 0,
                hosts_up: 0,
                hosts_dns_resolution: 0,
                start_time,
                end_time: SystemTime::now(),
                packets_sent: 0
            });
        }
    };

    if !ports.is_empty() {
        println!("Note: Ports specified but not used for ICMP ping scan: {:?}", ports);
    }
   
    // Create a collection of futures
    let mut futures = FuturesUnordered::new();
   
    // Convert IPs to IpAddr type for results
    let all_ips: Vec<IpAddr> = ips.iter().map(|ip| IpAddr::V4(*ip)).collect();
    
    // Add ping tasks to our collection
    for ip in ips {
        futures.push(async move {
            packets_sent += 1;
            let (is_reachable, latency, ttl) = ping_host_with_details(&ip).await;

            let mut dns_resolve = None;

            if is_reachable {
                // Try to resolve hostname
                dns_resolve = resolve_hostname(&ip).await;
            }
            
            let host_result = HostDiscoverySingleResult {
                ip_address: IpAddr::V4(ip),
                latency,
                dns_resolve,
                is_up: is_reachable,
                reply_type: if is_reachable { "ICMP echo reply".to_string() } else { "no response".to_string() },
                ttl: ttl.unwrap_or(0)
            };
            
            host_result
        });
    }
   
    // Collect all results
    let mut host_results = Vec::new();
    while let Some(result) = futures.next().await {
        host_results.push(result);
    }
   
    // Calculate stats for the summary
    let hosts_up = host_results.iter().filter(|r| r.is_up).count() as u64;
    let hosts_dns_resolution = host_results.iter().filter(|r| r.dns_resolve.is_some()).count() as u64;
    
    let end_time = SystemTime::now();
    
    // Create the summary result
    let summary = HostDiscoveryAllResult {
        scanned_addresses: all_ips,
        ports_per_host: if ports.is_empty() { 0 } else { ports.len() as u16 },
        hosts_up,
        hosts_dns_resolution,
        start_time,
        end_time,
        packets_sent: host_results.len() as u64
    };
    
    (host_results, summary)
}



/// Ping a host and return whether it's reachable, the latency, and TTL
async fn ping_host_with_details(ip: &Ipv4Addr) -> (bool, Option<Duration>, Option<u8>) {
    let ip_string = ip.to_string();
    
    // Tokio's spawn_blocking returns a JoinHandle<T>
    let result = task::spawn_blocking(move || {
        let start = Instant::now();
        
        let output = if cfg!(target_os = "windows") {
            Command::new("ping")
                .args(["-n", "1", "-w", "1000", &ip_string])
                .output()
        } else {
            Command::new("ping")
                .args(["-c", "1", "-W", "1", &ip_string])
                .output()
        };
        
        let elapsed = start.elapsed();
        
        match output {
            Ok(output) => {
                if output.status.success() {
                    // Try to extract TTL from the output
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    let ttl = extract_ttl(&stdout);
                    
                    (true, Some(elapsed), ttl)
                } else {
                    (false, None, None)
                }
            },
            Err(_) => (false, None, None)
        }
    });
   
    // Unwrap the result from the JoinHandle or return false if the task failed
    match result.await {
        Ok(ping_result) => ping_result,
        Err(_) => (false, None, None)
    }
}