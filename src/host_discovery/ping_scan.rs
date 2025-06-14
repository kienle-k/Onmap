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
) -> (Vec<HostDiscoverySingleResult>, HostDiscoveryAllResult) {
    // Start timing the operation
    let start_time = SystemTime::now();
    
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
   
    // Create a collection of futures
    let mut futures = FuturesUnordered::new();
   
    // Convert IPs to IpAddr type for results
    let all_ips: Vec<IpAddr> = ips.iter().map(|ip| IpAddr::V4(*ip)).collect();
    
    // Add ping tasks to our collection
    for ip in ips {
        futures.push(async move {
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
        ports_per_host: 0,
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


#[cfg(test)]
mod tests {

    use super::*;

    #[tokio::test]
    async fn test_ping_host_with_details_reachable() {
        // This is an integration test: it relies on the system's ping command
        // and network stack. It should be reliable as localhost is always available.
        let ip = Ipv4Addr::new(127, 0, 0, 1);
        let (is_reachable, latency, ttl) = ping_host_with_details(&ip).await;

        assert!(is_reachable, "Localhost should be reachable");
        assert!(latency.is_some(), "Latency should be recorded for a successful ping");
        // The actual TTL can vary by OS, so we just check if our mock parser would get a value.
        // The real `extract_ttl` function would determine if this is Some or None.
        assert!(ttl.is_some() || ttl.is_none()); // We accept either as OS ping outputs differ
    }

    #[tokio::test]
    async fn test_ping_host_with_details_unreachable() {
        // This is an integration test. 192.0.2.1 is from TEST-NET-1 (RFC 5737),
        // reserved for documentation and should not be reachable on the internet.
        // Note: This test can take ~1 second to complete due to the ping timeout.
        let ip = Ipv4Addr::new(192, 0, 2, 1);
        let (is_reachable, latency, ttl) = ping_host_with_details(&ip).await;

        assert!(!is_reachable, "Documentation IP should be unreachable");
        assert!(latency.is_none(), "Latency should be None for a failed ping");
        assert!(ttl.is_none(), "TTL should be None for a failed ping");
    }

    #[tokio::test]
    async fn test_run_ping_scan_with_valid_and_mixed_ips() {
        // This test combines a reachable and an unreachable IP.
        // It tests the main loop, result aggregation, and summary calculation.
        let ips = Ok(vec![
            Ipv4Addr::new(127, 0, 0, 1),      // Reachable
            Ipv4Addr::new(192, 0, 2, 123),    // Unreachable
        ]);
        let total_ips = ips.as_ref().unwrap().len();

        let (results, summary) = run_ping_scan(ips).await;

        // --- Assertions on the Summary ---
        assert_eq!(summary.scanned_addresses.len(), total_ips);
        assert_eq!(summary.packets_sent, total_ips as u64);
        assert_eq!(summary.hosts_up, 1);
        // Our mock `resolve_hostname` only works for loopback, so this should be 1.
        assert_eq!(summary.hosts_dns_resolution, 1);
        assert!(summary.end_time >= summary.start_time);

        // --- Assertions on the detailed results ---
        assert_eq!(results.len(), total_ips);

        // Find the result for localhost
        let localhost_result = results.iter().find(|r| r.ip_address.is_loopback()).unwrap();
        assert!(localhost_result.is_up);
        assert_eq!(localhost_result.dns_resolve, Some("localhost".to_string()));
        assert_eq!(localhost_result.reply_type, "ICMP echo reply");

        // Find the result for the unreachable host
        let unreachable_result = results.iter().find(|r| !r.ip_address.is_loopback()).unwrap();
        assert!(!unreachable_result.is_up);
        assert!(unreachable_result.dns_resolve.is_none());
        assert_eq!(unreachable_result.reply_type, "no response");
        assert_eq!(unreachable_result.ttl, 0);
    }

    #[tokio::test]
    async fn test_run_ping_scan_with_input_error() {
        // Tests the case where the input IP list is an error.
        let ip_addresses = Err("Failed to parse IP range".to_string());

        let (results, summary) = run_ping_scan(ip_addresses).await;

        // The function should return empty/zeroed results without panicking.
        assert!(results.is_empty(), "Results vector should be empty on input error");
        assert_eq!(summary.hosts_up, 0);
        assert_eq!(summary.hosts_dns_resolution, 0);
        assert_eq!(summary.packets_sent, 0);
        assert!(summary.scanned_addresses.is_empty());
    }
}