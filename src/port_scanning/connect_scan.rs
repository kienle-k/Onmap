use std::time::{Duration, SystemTime};
use tokio::net::{TcpSocket, TcpStream};
use tokio::time::timeout;

use std::io::ErrorKind;
use std::net::SocketAddr;
use std::net::{IpAddr, Ipv4Addr};
use std::result::Result;

use futures::stream::{StreamExt, FuturesUnordered};

use crate::models::{
    PortScanAllResult, PortScanSingleResult, PortStateReasons, PortStates, Protocols,
};

/// Maximum concurrent connects. Bounds memory and limits ephemeral port usage.
const MAX_IN_FLIGHT: usize = 100;

const DEFAULT_TIMEOUT_MS: u64 = 300;

/// Performs a TCP connect scan on a single IP address and port.
pub async fn port_tcp_connect_scan(
    ip_address: IpAddr,
    port: u16,
    timeout_duration: Duration,
) -> Result<PortScanSingleResult, String> {
    let make_result = |state, reason| {
        PortScanSingleResult {
            ip_address,
            port,
            protocol: Protocols::TCP,
            port_state: state,
            ttl: 0,
            reason,
        }
    };

    let socket_addr = SocketAddr::new(ip_address, port);

    let result = match timeout(timeout_duration, connect_reuseaddr(socket_addr)).await {
        Ok(Ok(stream)) => {
            if is_loopback_self_connect(&stream) {
                make_result(PortStates::Closed, PortStateReasons::ConnRefused)
            } else {
                make_result(PortStates::Open, PortStateReasons::SynAck)
            }
        }
        Ok(Err(e)) => match e.kind() {
            ErrorKind::ConnectionRefused => make_result(PortStates::Closed, PortStateReasons::ConnRefused),
            ErrorKind::TimedOut => make_result(PortStates::Filtered, PortStateReasons::Timeout),
            ErrorKind::HostUnreachable => make_result(PortStates::Filtered, PortStateReasons::HostUnreachable),
            ErrorKind::NetworkUnreachable => make_result(PortStates::Filtered, PortStateReasons::NetworkUnreachable),
            ErrorKind::PermissionDenied => make_result(PortStates::Filtered, PortStateReasons::AdminProhibited),
            ErrorKind::AddrNotAvailable => {
                log::warn!(
                    "Resource exhaustion: Out of local ephemeral ports connecting to {}:{}. Consider lowering MAX_IN_FLIGHT.",
                    ip_address, port
                );
                make_result(PortStates::Filtered, PortStateReasons::Timeout)
            }
            other => {
                log::debug!("Unmapped connect error for {}:{}: {:?}", ip_address, port, other);
                make_result(PortStates::Filtered, PortStateReasons::Timeout)
            }
        },
        Err(_) => make_result(PortStates::Filtered, PortStateReasons::Timeout),
    };

    Ok(result)
}

/// Connects with `SO_REUSEADDR` to recycle `TIME_WAIT` sockets and prevent exhaustion.
async fn connect_reuseaddr(addr: SocketAddr) -> std::io::Result<TcpStream> {
    let socket = match addr {
        SocketAddr::V4(_) => TcpSocket::new_v4(),
        SocketAddr::V6(_) => TcpSocket::new_v6(),
    };

    match socket {
        Ok(socket) => {
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
/// # Notes
/// * Concurrency is bounded by `MAX_IN_FLIGHT` to keep memory at O(window) and prevent source port exhaustion.
/// * Local resource exhaustion (`EADDRNOTAVAIL`) is logged as a warning and reported as `Filtered`.
/// * Counts all packets sent, including the handshake overhead for open ports.
pub async fn run_connect_scan(
    ip_addresses: Vec<Ipv4Addr>,
    ports_arr: Vec<u16>,
    timeout_override_ms: Option<u64>,
) -> Result<(Vec<PortScanSingleResult>, PortScanAllResult), String> {
    let timeout = Duration::from_millis(timeout_override_ms.unwrap_or(DEFAULT_TIMEOUT_MS));
    let start_time = SystemTime::now();

    // Lazily generate pairs so memory doesn't scale with total target size.
    let probes = ip_addresses.iter().flat_map(|&ip| {
        let ip_addr = IpAddr::V4(ip);
        ports_arr.iter().map(move |&port| (ip_addr, port))
    });

    let mut stream = FuturesUnordered::new();
    let mut single_results: Vec<PortScanSingleResult> = Vec::new();
    let mut packets_sent: u32 = 0;

    // Drains one finished task into `single_results`, logging either failure mode.
    // Every probe sends a SYN regardless of outcome, so the count happens at spawn
    // time below rather than here.
    let drain = |joined: Result<Result<PortScanSingleResult, String>, tokio::task::JoinError>,
                 results: &mut Vec<PortScanSingleResult>| {
        match joined {
            Ok(Ok(result)) => results.push(result),
            Ok(Err(e)) => log::error!("Scan probe error: {}", e),
            Err(e) => log::error!("Tokio task panicked or was cancelled: {}", e),
        }
    };

    for (ip_addr, port) in probes {
        // Enforce the concurrency limit by waiting for the next completed task.
        if stream.len() >= MAX_IN_FLIGHT
            && let Some(joined) = stream.next().await
        {
            drain(joined, &mut single_results);
        }

        // One SYN goes out per probe, independent of how the connect resolves.
        packets_sent += 1;
        // Parallelize connection attempts across all runtime threads.
        stream.push(tokio::spawn(async move {
            port_tcp_connect_scan(ip_addr, port, timeout).await
        }));
    }

    // Collect remaining in-flight tasks to ensure no results are dropped.
    while let Some(joined) = stream.next().await {
        drain(joined, &mut single_results);
    }

    let open_ports: Vec<u16> = single_results
        .iter()
        .filter(|result| result.port_state == PortStates::Open)
        .map(|result| {
            log::info!("Discovered open port {}/tcp on {}", result.port, result.ip_address);
            result.port
        })
        .collect();

    // Account for the handshake-completing ACK and the closing FIN/RST on opened connections.
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