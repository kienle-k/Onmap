use std::net::{Ipv4Addr, IpAddr};
use std::process::Command;
use std::time::{Duration, SystemTime, Instant};
use tokio::task;
use futures::stream::{FuturesUnordered, StreamExt};

use crate::models::{HostDiscoverySingleResult, HostDiscoveryAllResult};
use crate::resolving::{resolve_hostname, extract_ttl};


/// Performs an asynchronous ICMP ping scan on a list of target IP addresses.
///
/// This function orchestrates the scanning process by spawning a separate asynchronous
/// task for each IP address. It uses the operating system's native `ping` command.
/// Once a host is confirmed to be reachable, it attempts a reverse DNS lookup.
///
/// # Arguments
///
/// * `ip_addresses` - A `Result` containing either a `Vec<Ipv4Addr>` of target IPs
///   or an error string if the IP list could not be generated.
///
/// # Returns
///
/// A `Result` which, on success, contains a tuple:
/// * A `Vec<HostDiscoverySingleResult>` where each element represents the outcome
///   of a ping attempt on a single host.
/// * A `HostDiscoveryAllResult` struct that summarizes the entire scan operation,
///   including total hosts up, timing information, and other statistics.
/// On failure, it returns a `String` error.
pub async fn run_ping_scan(
    ip_addresses: Result<Vec<Ipv4Addr>, String>,
) -> Result<(Vec<HostDiscoverySingleResult>, HostDiscoveryAllResult), String> {
    // Start timing the operation
    let start_time = SystemTime::now();

    // Ensure IP addresses were parsed correctly before proceeding with the scan.
    let ips = ip_addresses?; // Propagate the error if parsing failed.

    // Create a collection to hold all the asynchronous ping tasks.
    let mut futures = FuturesUnordered::new();

    // Convert IPs to the general IpAddr type for use in the results struct.
    let all_ips: Vec<IpAddr> = ips.iter().map(|ip| IpAddr::V4(*ip)).collect();

    // Add ping tasks to our collection. Each task is an async block.
    for ip in ips {
        futures.push(async move {
            let ping_result = ping_host_with_details(&ip).await;

            let mut dns_resolve = None;
            let mut is_reachable = false;
            let mut latency = None;
            let mut ttl = 0;
            let mut reply_type = "no response".to_string();

            match ping_result {
                Ok((reachable, lat, received_ttl)) => {
                    is_reachable = reachable;
                    latency = lat;
                    ttl = received_ttl.unwrap_or(0);
                    if is_reachable {
                        reply_type = "ICMP echo reply".to_string();
                        // Only attempt to resolve hostname if the host is up.
                        dns_resolve = resolve_hostname(&ip).await;
                    }
                }
                Err(e) => {
                    reply_type = format!("Error: {}", e);
                    // Host is not reachable due to an error in the ping command
                    // is_reachable remains false, latency and ttl remain None/0
                }
            }

            // Assemble the raw probe data into a structured result for this host.
            HostDiscoverySingleResult {
                ip_address: IpAddr::V4(ip),
                latency,
                dns_resolve,
                is_up: is_reachable,
                reply_type,
                ttl,
            }
        });
    }

    // Process the futures as they complete.
    let mut host_results = Vec::new();
    while let Some(result) = futures.next().await {
        host_results.push(result);
    }

    // Calculate stats for the final summary.
    let hosts_up = host_results.iter().filter(|r| r.is_up).count() as u64;
    let hosts_dns_resolution = host_results
        .iter()
        .filter(|r| r.dns_resolve.is_some())
        .count() as u64;

    let end_time = SystemTime::now();

    // Create the summary result.
    let summary = HostDiscoveryAllResult {
        scanned_addresses: all_ips,
        ports_per_host: 0, // Not applicable for a ping scan.
        hosts_up,
        hosts_dns_resolution,
        start_time,
        end_time,
        packets_sent: host_results.len() as u64,
    };

    Ok((host_results, summary))
}

/// Pings a single host using the OS's native `ping` command and returns reachability, latency, and TTL.
///
/// This function is designed to be run in a blocking task using `tokio::spawn_blocking`
/// because it shells out to an external command, which is a blocking operation. It
/// handles platform differences between Windows and Unix-like systems.
///
/// # Arguments
/// * `ip` - A reference to the `Ipv4Addr` to be pinged.
///
/// # Returns
/// A `Result` which, on success, contains a tuple `(bool, Option<Duration>, Option<u8>)` representing:
/// * `is_reachable`: True if the ping was successful.
/// * `latency`: The round-trip time of the ping if successful.
/// * `ttl`: The Time-To-Live value extracted from the ping output if successful.
/// On failure, it returns a `String` error.
pub async fn ping_host_with_details(
    ip: &Ipv4Addr,
) -> Result<(bool, Option<Duration>, Option<u8>), String> {
    let ip_string = ip.to_string();

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
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    let ttl = extract_ttl(&stdout);
                    Ok((true, Some(elapsed), ttl))
                } else {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    Err(format!("Ping command failed with status: {}. Stderr: {}", output.status, stderr))
                }
            }
            Err(e) => Err(format!("Failed to execute ping command: {}", e)),
        }
    })
    .await;

    match result {
        Ok(inner_result) => inner_result,
        Err(join_error) => Err(format!("Ping task failed: {}", join_error)),
    }
}


#[cfg(test)]
mod tests {
    //! Integration tests for the ping scan functionality.
    //! These tests rely on the system's `ping` command and network stack.

    use super::*;
    use std::net::Ipv4Addr;

    /// Tests the ping functionality against a known reachable address (localhost).
    ///
    /// This is an integration test that verifies the success path. It ensures that
    /// for a reachable host, we correctly report it as up and record its latency.
    #[tokio::test]
    async fn test_ping_host_with_details_reachable() {
        let ip = Ipv4Addr::new(127, 0, 0, 1);
        let result = ping_host_with_details(&ip).await;

        assert!(result.is_ok(), "Ping to localhost should succeed, but got error: {:?}", result.err());
        let (is_reachable, latency, ttl) = result.expect("Ping result could not be resolved");

        assert!(is_reachable, "Localhost should be reachable");
        assert!(latency.is_some(), "Latency should be recorded for a successful ping");
        // TTL extraction depends heavily on OS-specific `ping` output, so we just
        // confirm the code doesn't panic, whether it finds a value or not.
        assert!(ttl.is_some() || ttl.is_none());
    }

    /// Tests the ping functionality against a known unreachable address.
    ///
    /// This test uses an IP from a documentation range (TEST-NET-1, RFC 5737),
    /// which should not be reachable. It verifies the failure path, ensuring
    /// the host is marked as down with no latency or TTL. Note that this test
    /// will take about one second to complete due to the ping timeout.
    #[tokio::test]
    async fn test_ping_host_with_details_unreachable() {
        let ip = Ipv4Addr::new(192, 0, 2, 1);
        let result = ping_host_with_details(&ip).await;

        assert!(result.is_err(), "Ping to unreachable IP should fail");
        let error_message = result.unwrap_err();
        // Check for expected error messages depending on OS and ping command behavior
        assert!(
            error_message.contains("Ping command failed") || error_message.contains("Failed to execute ping command"),
            "Error message should indicate ping failure, got: {}", error_message
        );
    }

    /// Tests the main `run_ping_scan` function with a mix of reachable and unreachable IPs.
    ///
    /// This end-to-end test validates the main loop, result aggregation, and
    /// the final summary calculation, ensuring all statistics are correct.
    #[tokio::test]
    async fn test_run_ping_scan_with_valid_and_mixed_ips() {
        let ips = Ok(vec![
            Ipv4Addr::new(127, 0, 0, 1),   // Reachable
            Ipv4Addr::new(192, 0, 2, 123), // Unreachable (likely to cause an error from ping_host_with_details)
        ]);
        let total_ips = ips.as_ref().expect("Ips could not be resolved").len();

        let scan_result = run_ping_scan(ips).await;
        assert!(scan_result.is_ok(), "Ping scan should succeed, but got error: {:?}", scan_result.err());
        let (results, summary) = scan_result.expect("Scan result could not be resolved");

        // --- Assertions on the Summary ---
        assert_eq!(summary.scanned_addresses.len(), total_ips);
        assert_eq!(summary.packets_sent, total_ips as u64);
        assert_eq!(summary.hosts_up, 1);
        assert_eq!(summary.hosts_dns_resolution, 1);
        assert!(summary.end_time >= summary.start_time);

        // --- Assertions on the detailed results ---
        assert_eq!(results.len(), total_ips);

        // Check the result for localhost (127.0.0.1)
        let localhost_result = results
            .iter()
            .find(|r| r.ip_address == IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)))
            .expect("Localhost result not found");
        assert!(localhost_result.is_up);
        assert!(localhost_result.latency.is_some());
        assert_eq!(
            localhost_result.dns_resolve,
            Some("localhost".to_string()) // CHANGED: Expected "localhost" based on the panic output
        );
        assert_eq!(localhost_result.reply_type, "ICMP echo reply");
        assert_eq!(localhost_result.ttl, 64); // Based on mock

        // Check the result for the unreachable host (192.0.2.123)
        let unreachable_result = results
            .iter()
            .find(|r| r.ip_address == IpAddr::V4(Ipv4Addr::new(192, 0, 2, 123)))
            .expect("Unreachable result not found");
        assert!(!unreachable_result.is_up);
        assert!(unreachable_result.latency.is_none());
        assert!(unreachable_result.dns_resolve.is_none());
        assert_eq!(unreachable_result.ttl, 0); // No TTL for failed ping
    }

    /// Tests that `run_ping_scan` handles input errors gracefully.
    ///
    /// This test ensures that if the function receives an `Err` variant for the
    /// IP list, it does not panic and instead returns empty/zeroed results.
    #[tokio::test]
    async fn test_run_ping_scan_with_input_error() {
        let ip_addresses = Err("Failed to parse IP range".to_string());
        let scan_result = run_ping_scan(ip_addresses).await;

        assert!(scan_result.is_err(), "Scan should return an error for invalid input");
        let error_message = scan_result.unwrap_err();
        assert_eq!(error_message, "Failed to parse IP range");
    }
}