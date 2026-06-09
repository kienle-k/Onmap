use std::collections::HashMap;
use std::time::{Duration, SystemTime};
use tokio::net::TcpStream;
use tokio::time::timeout;

use std::io::ErrorKind;
use std::net::SocketAddr;

use std::net::{IpAddr, Ipv4Addr};
use std::result::Result;
use std::sync::Arc;

use crate::models::{
    PortScanAllResult, PortScanSingleResult, PortStateReasons, PortStates, Protocols,
};

const MAX_IN_FLIGHT: usize = 100;
const MAX_TIMEOUT_RETRY_RATIO: usize = 4;

/// Performs a TCP connect scan on a single IP address and port.
///
/// This scan uses the operating system's TCP stack to attempt a full connection,
/// which will complete if the port is open. If the connection is refused, it is considered closed.
/// If a timeout occurs, the port is assumed to be filtered (e.g., dropped by a firewall).
///
/// # Arguments
/// * `ip_address` - The target IP address.
/// * `port` - The target port to scan.
/// * `timeout_duration` - The maximum duration to wait for a connection attempt.
///
/// # Returns
/// * `Ok(PortScanSingleResult)` if the scan completes successfully.
/// * `Err(String)` in case of unexpected I/O errors or issues.
///
/// # Port States
/// * `Open` - Connection succeeded (SYN-ACK).
/// * `Closed` - Connection refused (RST).
/// * `Filtered` - Timed out or dropped by a firewall.
pub async fn port_tcp_connect_scan(
    ip_address: IpAddr,
    port: u16,
    timeout_duration: Duration,
) -> Result<PortScanSingleResult, String> {
    // Function to automatically create the struct
    let make_result = |state, reason| PortScanSingleResult {
        ip_address,
        port,
        protocol: Protocols::TCP,
        port_state: state,
        ttl: 0, // TTL only meaningful for raw scans like SYN or ACK (here, the OS handles the packets -> no ttl insight)
        reason,
    };

    let socket_addr = SocketAddr::new(ip_address, port);

    // Map each connect outcome to a port state, mirroring Nmap's connect scan.
    match timeout(timeout_duration, TcpStream::connect(socket_addr)).await {
        Ok(Ok(stream)) => {
            if is_loopback_self_connect(&stream) {
                return Ok(make_result(
                    PortStates::Closed,
                    PortStateReasons::ConnRefused,
                ));
            }
            Ok(make_result(PortStates::Open, PortStateReasons::SynAck))
        }
        Ok(Err(e)) => {
            let (state, reason) = match e.kind() {
                ErrorKind::ConnectionRefused => (PortStates::Closed, PortStateReasons::ConnRefused),
                ErrorKind::TimedOut => (PortStates::Filtered, PortStateReasons::Timeout),
                ErrorKind::HostUnreachable => {
                    (PortStates::Filtered, PortStateReasons::HostUnreachable)
                }
                ErrorKind::NetworkUnreachable => {
                    (PortStates::Filtered, PortStateReasons::NetworkUnreachable)
                }
                ErrorKind::PermissionDenied => {
                    (PortStates::Filtered, PortStateReasons::AdminProhibited)
                }
                // nmap maps EADDRNOTAVAIL to no-response.
                ErrorKind::AddrNotAvailable => (PortStates::Filtered, PortStateReasons::Timeout),
                // Unmapped errors are still a valid (filtered) result; log for visibility.
                other => {
                    log::debug!(
                        "Unmapped connect error for {}:{}: {:?}",
                        ip_address,
                        port,
                        other
                    );
                    (PortStates::Filtered, PortStateReasons::Timeout)
                }
            };
            Ok(make_result(state, reason))
        }
        Err(_) => Ok(make_result(PortStates::Filtered, PortStateReasons::Timeout)),
    }
}

fn is_loopback_self_connect(stream: &TcpStream) -> bool {
    let (Ok(local), Ok(peer)) = (stream.local_addr(), stream.peer_addr()) else {
        return false;
    };

    local == peer && local.ip().is_loopback()
}

/// Runs a full TCP connect scan on multiple IP addresses and ports concurrently.
///
/// This function performs concurrent scanning with a semaphore to limit active tasks.
/// It collects results for each IP/port combination and aggregates them into summary statistics.
///
/// # Arguments
/// * `ip_address_arr` - A `Result` wrapping a list of IPv4 addresses to scan.
/// * `ports_arr` - A list of TCP ports to scan on each IP.
/// * `timeout_override_ms` - Optional timeout per scan attempt, in milliseconds.
///
/// # Returns
/// * `Ok((Vec<PortScanSingleResult>, PortScanAllResult))` if all scans complete without critical error.
/// * `Err(String)` if IP resolution fails.
///
/// # Notes
/// * Limits active connect attempts with a semaphore.
/// * Spawns every probe task up front; this intentionally preserves the older
///   scheduler behavior because it benchmarked faster and more consistently.
/// * Accurately counts packets sent (connect + response for open ports).
pub async fn run_connect_scan(
    ip_addresses: Vec<Ipv4Addr>,
    ports_arr: Vec<u16>,
    timeout_override_ms: Option<u64>,
) -> Result<(Vec<PortScanSingleResult>, PortScanAllResult), String> {
    const DEFAULT_TIMEOUT_MS: u64 = 300;
    let timeout = Duration::from_millis(timeout_override_ms.unwrap_or(DEFAULT_TIMEOUT_MS));

    let start_time = SystemTime::now();
    let targets: Vec<(IpAddr, u16)> = ip_addresses
        .into_iter()
        .flat_map(|ip| {
            let ip_addr = IpAddr::V4(ip);
            ports_arr.iter().map(move |&port| (ip_addr, port))
        })
        .collect();

    let total_targets = targets.len();
    let (mut single_results, mut packets_sent) = scan_connect_targets(targets, timeout).await?;

    let retry_targets = sparse_timeout_retry_targets(&single_results, total_targets);
    if !retry_targets.is_empty() {
        log::debug!(
            "Retrying {} sparse TCP connect timeout result(s)",
            retry_targets.len()
        );
        let (retry_results, retry_packets) = scan_connect_targets(retry_targets, timeout).await?;
        packets_sent += retry_packets;

        let mut retry_by_target: HashMap<(IpAddr, u16), PortScanSingleResult> = retry_results
            .into_iter()
            .map(|result| ((result.ip_address, result.port), result))
            .collect();

        for result in &mut single_results {
            if let Some(retry_result) = retry_by_target.remove(&(result.ip_address, result.port)) {
                *result = retry_result;
            }
        }
    }

    let open_ports: Vec<u16> = single_results
        .iter()
        .filter(|result| result.port_state == PortStates::Open)
        .map(|result| {
            log::info!(
                "Discovered open port {}/tcp on {}",
                result.port,
                result.ip_address
            );
            result.port
        })
        .collect();
    packets_sent += (open_ports.len() as u32) * 2;

    let all_result = PortScanAllResult {
        ports_scanned: ports_arr.len() as u32,
        packets_sent,
        open_ports,
        start_time,
        end_time: SystemTime::now(),
        scan_type: None,
    };

    Ok((single_results, all_result))
}

async fn scan_connect_targets(
    targets: Vec<(IpAddr, u16)>,
    timeout: Duration,
) -> Result<(Vec<PortScanSingleResult>, u32), String> {
    let packets_sent = targets.len() as u32;
    let semaphore = Arc::new(tokio::sync::Semaphore::new(MAX_IN_FLIGHT));
    let mut tasks = Vec::with_capacity(targets.len());

    for (ip_addr, port) in targets {
        let semaphore = Arc::clone(&semaphore);
        tasks.push(tokio::spawn(async move {
            let _permit = semaphore
                .acquire_owned()
                .await
                .map_err(|e| format!("Semaphore acquire error: {}", e))?;

            port_tcp_connect_scan(ip_addr, port, timeout).await
        }));
    }

    let mut results = Vec::with_capacity(tasks.len());
    for task in tasks {
        let result = task
            .await
            .map_err(|e| format!("Connect scan task failed: {}", e))??;
        results.push(result);
    }

    Ok((results, packets_sent))
}

fn sparse_timeout_retry_targets(
    results: &[PortScanSingleResult],
    total_targets: usize,
) -> Vec<(IpAddr, u16)> {
    let retry_targets: Vec<(IpAddr, u16)> = results
        .iter()
        .filter(|result| {
            result.port_state == PortStates::Filtered && result.reason == PortStateReasons::Timeout
        })
        .map(|result| (result.ip_address, result.port))
        .collect();

    if retry_targets.len() * MAX_TIMEOUT_RETRY_RATIO <= total_targets {
        retry_targets
    } else {
        Vec::new()
    }
}
