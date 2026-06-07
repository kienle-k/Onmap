use std::time::{Duration, SystemTime};
use tokio::net::TcpStream;
use tokio::time::timeout;

use futures::stream::{self, StreamExt};
use std::io::ErrorKind;
use std::net::SocketAddr;

use std::net::{IpAddr, Ipv4Addr};
use std::result::Result;

use crate::models::{
    PortScanAllResult, PortScanSingleResult, PortStateReasons, PortStates, Protocols,
};

/// Maximum connect attempts in flight at once. The stream window is the only
/// concurrency limit (no semaphore) and bounds live futures, so memory stays
/// flat regardless of the port count.
const MAX_IN_FLIGHT: usize = 100;

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
        Ok(Ok(_)) => Ok(make_result(PortStates::Open, PortStateReasons::SynAck)),
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
        Err(_) => Ok(make_result(PortStates::Filtered, PortStateReasons::Timeout)), // tokio timeout
    }
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
/// * Bounds concurrency with a stream window (`MAX_IN_FLIGHT`); only that many
///   probe futures exist at once, so memory does not scale with the port count.
/// * Accurately counts packets sent (connect + response for open ports).
pub async fn run_connect_scan(
    ip_addresses: Vec<Ipv4Addr>,
    ports_arr: Vec<u16>,
    timeout_override_ms: Option<u64>,
) -> Result<(Vec<PortScanSingleResult>, PortScanAllResult), String> {
    const DEFAULT_TIMEOUT_MS: u64 = 300;
    let timeout = Duration::from_millis(timeout_override_ms.unwrap_or(DEFAULT_TIMEOUT_MS));

    let start_time = SystemTime::now();

    // Lazily generate (ip, port) probes and keep at most MAX_IN_FLIGHT running.
    let probes = ip_addresses.iter().flat_map(|&ip| {
        let ip_addr = IpAddr::V4(ip);
        ports_arr.iter().map(move |&port| (ip_addr, port))
    });
    let mut stream = stream::iter(probes)
        .map(|(ip_addr, port)| async move {
            (ip_addr, port, port_tcp_connect_scan(ip_addr, port, timeout).await)
        })
        .buffer_unordered(MAX_IN_FLIGHT);

    // Single consumer: no shared state, no locks.
    let mut single_results = Vec::new();
    let mut open_ports = Vec::new();
    let mut packets_sent: u32 = 0;

    while let Some((ip_addr, port, outcome)) = stream.next().await {
        // Every probe sends a SYN.
        packets_sent += 1;
        match outcome {
            Ok(result) => {
                if result.port_state == PortStates::Open {
                    log::info!("Discovered open port {}/tcp on {}", port, ip_addr);
                    open_ports.push(port);
                    // Open ports also see the ACK and RST.
                    packets_sent += 2;
                }
                single_results.push(result);
            }
            // A per-port error means a result is missing; fail the whole run
            // rather than returning Ok with a port silently dropped.
            Err(e) => {
                log::error!("Connect scan failed for {}:{}: {}", ip_addr, port, e);
                return Err(e);
            }
        }
    }

    let all_result = PortScanAllResult {
        ports_scanned: ports_arr.len() as u16,
        packets_sent,
        open_ports,
        start_time,
        end_time: SystemTime::now(),
        scan_type: None,
    };

    Ok((single_results, all_result))
}
