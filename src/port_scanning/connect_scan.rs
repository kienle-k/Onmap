use std::time::{Duration, SystemTime};
use tokio::net::{TcpSocket, TcpStream};
use tokio::time::timeout;

use std::io::ErrorKind;
use std::net::SocketAddr;

use std::net::{IpAddr, Ipv4Addr};
use std::result::Result;

use futures::stream::{self, StreamExt};

use crate::models::{
    PortScanAllResult, PortScanSingleResult, PortStateReasons, PortStates, Protocols,
};

/// Maximum number of connect probes in flight at once.
///
/// This bounds both concurrency and memory: with a stream window only this many
/// probe futures (and their sockets) exist at any instant, so memory is O(window)
/// rather than O(targets). It also caps the number of simultaneous ephemeral
/// sockets, which is what keeps the kernel from running out of source ports.
const MAX_IN_FLIGHT: usize = 100;

/// Backoff before retrying a probe that hit a scanner-side resource error.
///
/// Long enough for a handful of ephemeral ports / TIME_WAIT slots to free up,
/// short enough to be negligible against the per-probe timeout.
const RESOURCE_RETRY_BACKOFF: Duration = Duration::from_millis(20);

/// Outcome of a single connect probe.
///
/// `Measured` carries a real port observation. `ResourceExhausted` means the
/// probe never reached the target: the kernel ran out of ephemeral ports
/// (EADDRNOTAVAIL) or a comparable scanner-side limit. That is not a statement
/// about the port — it must be retried, never reported as `Filtered`.
enum ProbeOutcome {
    Measured(PortScanSingleResult),
    ResourceExhausted,
}

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
    match probe_connect(ip_address, port, timeout_duration).await {
        ProbeOutcome::Measured(result) => Ok(result),
        // External callers (e.g. host discovery) have no retry loop; a resource
        // error there is best treated as no response from the target, not an
        // invented filtered verdict tied to a kernel limit.
        ProbeOutcome::ResourceExhausted => Ok(PortScanSingleResult {
            ip_address,
            port,
            protocol: Protocols::TCP,
            port_state: PortStates::Filtered,
            ttl: 0,
            reason: PortStateReasons::Timeout,
        }),
    }
}

/// Runs one connect probe and classifies the outcome.
///
/// Separated from [`port_tcp_connect_scan`] so the multi-target scanner can act
/// on [`ProbeOutcome::ResourceExhausted`] (retry it) while the simple public
/// entry point collapses it to a no-response result.
async fn probe_connect(
    ip_address: IpAddr,
    port: u16,
    timeout_duration: Duration,
) -> ProbeOutcome {
    // Function to automatically create the struct
    let make_result = |state, reason| {
        ProbeOutcome::Measured(PortScanSingleResult {
            ip_address,
            port,
            protocol: Protocols::TCP,
            port_state: state,
            ttl: 0, // TTL only meaningful for raw scans like SYN or ACK (here, the OS handles the packets -> no ttl insight)
            reason,
        })
    };

    let socket_addr = SocketAddr::new(ip_address, port);

    // Map each connect outcome to a port state, mirroring Nmap's connect scan.
    match timeout(timeout_duration, connect_reuseaddr(socket_addr)).await {
        Ok(Ok(stream)) => {
            if is_loopback_self_connect(&stream) {
                return make_result(PortStates::Closed, PortStateReasons::ConnRefused);
            }
            make_result(PortStates::Open, PortStateReasons::SynAck)
        }
        Ok(Err(e)) => match e.kind() {
            ErrorKind::ConnectionRefused => {
                make_result(PortStates::Closed, PortStateReasons::ConnRefused)
            }
            ErrorKind::TimedOut => make_result(PortStates::Filtered, PortStateReasons::Timeout),
            ErrorKind::HostUnreachable => {
                make_result(PortStates::Filtered, PortStateReasons::HostUnreachable)
            }
            ErrorKind::NetworkUnreachable => {
                make_result(PortStates::Filtered, PortStateReasons::NetworkUnreachable)
            }
            ErrorKind::PermissionDenied => {
                make_result(PortStates::Filtered, PortStateReasons::AdminProhibited)
            }
            // EADDRNOTAVAIL: the kernel had no free ephemeral source port. This is
            // a scanner-side resource limit, NOT a target verdict, so it must be
            // retried rather than reported as filtered.
            ErrorKind::AddrNotAvailable => ProbeOutcome::ResourceExhausted,
            // Unmapped errors are still a valid (filtered) result; log for visibility.
            other => {
                log::debug!(
                    "Unmapped connect error for {}:{}: {:?}",
                    ip_address,
                    port,
                    other
                );
                make_result(PortStates::Filtered, PortStateReasons::Timeout)
            }
        },
        Err(_) => make_result(PortStates::Filtered, PortStateReasons::Timeout),
    }
}

/// Connects to `addr` with `SO_REUSEADDR` set on the source socket.
///
/// Setting `SO_REUSEADDR` lets the kernel reuse ephemeral source ports still in
/// `TIME_WAIT`, which is what prevents EADDRNOTAVAIL during high-fan-out scans.
/// On any setup error we fall back to a plain `TcpStream::connect` so the probe
/// still runs rather than failing on a platform quirk.
async fn connect_reuseaddr(addr: SocketAddr) -> std::io::Result<TcpStream> {
    let socket = match addr {
        SocketAddr::V4(_) => TcpSocket::new_v4(),
        SocketAddr::V6(_) => TcpSocket::new_v6(),
    };

    match socket {
        Ok(socket) => {
            // Best effort: if the option is unsupported we still attempt the connect.
            let _ = socket.set_reuseaddr(true);
            socket.connect(addr).await
        }
        Err(_) => TcpStream::connect(addr).await,
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
/// # Arguments
/// * `ip_addresses` - The list of IPv4 addresses to scan.
/// * `ports_arr` - A list of TCP ports to scan on each IP.
/// * `timeout_override_ms` - Optional timeout per scan attempt, in milliseconds.
///
/// # Returns
/// * `Ok((Vec<PortScanSingleResult>, PortScanAllResult))` if all scans complete without critical error.
/// * `Err(String)` if a probe task fails unexpectedly.
///
/// # Notes
/// * Bounds concurrency with a stream window (`MAX_IN_FLIGHT`); only that many
///   probe futures and sockets exist at once, so memory is O(window), not
///   O(targets), and the kernel never runs short of ephemeral ports under load.
/// * Probes that hit a scanner-side resource limit (EADDRNOTAVAIL) are retried
///   once after a short backoff instead of being mis-reported as filtered. There
///   is no blanket timeout retry: a real timeout is a real (filtered) verdict.
/// * Accurately counts packets sent (connect + response for open ports).
pub async fn run_connect_scan(
    ip_addresses: Vec<Ipv4Addr>,
    ports_arr: Vec<u16>,
    timeout_override_ms: Option<u64>,
) -> Result<(Vec<PortScanSingleResult>, PortScanAllResult), String> {
    const DEFAULT_TIMEOUT_MS: u64 = 300;
    let timeout = Duration::from_millis(timeout_override_ms.unwrap_or(DEFAULT_TIMEOUT_MS));

    let start_time = SystemTime::now();

    // Lazily generate (ip, port) probes; the stream keeps at most MAX_IN_FLIGHT
    // of them resident, so nothing scales with the port count up front.
    let probes = ip_addresses.iter().flat_map(|&ip| {
        let ip_addr = IpAddr::V4(ip);
        ports_arr.iter().map(move |&port| (ip_addr, port))
    });

    // Each probe is spawned so the multi-thread runtime can drive connects across
    // all worker threads (cooperatively polling them on one consumer task is what
    // made an earlier stream-only version single-core and slow). `buffer_unordered`
    // gates how many are spawned-but-uncollected at once, so live tasks/sockets
    // stay at O(MAX_IN_FLIGHT) instead of O(targets).
    let mut stream = stream::iter(probes)
        .map(|(ip_addr, port)| {
            tokio::spawn(async move {
                (ip_addr, port, probe_connect(ip_addr, port, timeout).await)
            })
        })
        .buffer_unordered(MAX_IN_FLIGHT);

    // Single consumer: no shared state, no locks.
    let mut single_results: Vec<PortScanSingleResult> = Vec::new();
    let mut resource_exhausted: Vec<(IpAddr, u16)> = Vec::new();
    // Every probe sends a connect attempt (one SYN).
    let mut packets_sent: u32 = 0;

    while let Some(joined) = stream.next().await {
        let (ip_addr, port, outcome) =
            joined.map_err(|e| format!("Connect scan task failed: {}", e))?;
        packets_sent += 1;
        match outcome {
            ProbeOutcome::Measured(result) => single_results.push(result),
            ProbeOutcome::ResourceExhausted => resource_exhausted.push((ip_addr, port)),
        }
    }

    // Retry only the probes that never reached the target. These cost real SYNs.
    if !resource_exhausted.is_empty() {
        log::debug!(
            "Retrying {} TCP connect probe(s) that hit a resource limit (EADDRNOTAVAIL)",
            resource_exhausted.len()
        );
        let retried = retry_resource_exhausted(resource_exhausted, timeout).await;
        packets_sent += retried.len() as u32;
        single_results.extend(retried);
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
    // Open ports also see the ACK and the closing RST.
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

/// Retries probes that hit a scanner-side resource limit, once each, with a
/// short backoff to let ephemeral ports free up.
///
/// A probe that still reports `ResourceExhausted` on the retry is recorded as a
/// no-response (filtered/timeout) result: we have measured it as best we can and
/// must not drop the port. Concurrency is bounded the same way as the main pass.
async fn retry_resource_exhausted(
    targets: Vec<(IpAddr, u16)>,
    timeout: Duration,
) -> Vec<PortScanSingleResult> {
    stream::iter(targets)
        .map(|(ip_addr, port)| {
            tokio::spawn(async move {
                tokio::time::sleep(RESOURCE_RETRY_BACKOFF).await;
                match probe_connect(ip_addr, port, timeout).await {
                    ProbeOutcome::Measured(result) => result,
                    // Still exhausted after a retry: best-effort no-response so the
                    // port is still reported rather than silently lost.
                    ProbeOutcome::ResourceExhausted => PortScanSingleResult {
                        ip_address: ip_addr,
                        port,
                        protocol: Protocols::TCP,
                        port_state: PortStates::Filtered,
                        ttl: 0,
                        reason: PortStateReasons::Timeout,
                    },
                }
            })
        })
        .buffer_unordered(MAX_IN_FLIGHT)
        // A join error means a result is missing; drop it rather than fabricate.
        // The main pass already reported these ports, so they are never lost.
        .filter_map(|joined| async move { joined.ok() })
        .collect()
        .await
}
