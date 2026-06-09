use std::time::{Duration, SystemTime};
use tokio::net::{TcpSocket, TcpStream};
use tokio::time::timeout;

use std::io::ErrorKind;
use std::net::SocketAddr;
use std::net::{IpAddr, Ipv4Addr};
use std::os::unix::io::AsRawFd;
use std::result::Result;

use futures::stream::{FuturesUnordered, StreamExt};

use crate::models::{
    PortScanAllResult, PortScanSingleResult, PortStateReasons, PortStates, Protocols,
};

// Max concurrent connects. Bounds memory and ephemeral-port use.
const MAX_IN_FLIGHT: usize = 100;

const DEFAULT_TIMEOUT_MS: u64 = 1000;

// Close probe sockets with SO_LINGER 0 (RST instead of FIN) to skip TIME_WAIT
// and relieve ephemeral-port exhaustion, like nmap's connect scan. Ruder to
// targets: may trip IDS or rate-limiters.
const ABORT_WITH_RST: bool = true;

// Connect-scans a single IP and port, mapping the connect outcome to a state.
pub async fn port_tcp_connect_scan(
    ip_address: IpAddr,
    port: u16,
    timeout_duration: Duration,
) -> Result<PortScanSingleResult, String> {
    let make_result = |state, reason| PortScanSingleResult {
        ip_address,
        port,
        protocol: Protocols::TCP,
        port_state: state,
        ttl: 0,
        reason,
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
            ErrorKind::AddrNotAvailable => {
                log::warn!(
                    "Resource exhaustion: Out of local ephemeral ports connecting to {}:{}. Consider lowering MAX_IN_FLIGHT.",
                    ip_address,
                    port
                );
                make_result(PortStates::Filtered, PortStateReasons::Timeout)
            }
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
    };

    Ok(result)
}

// Connects with SO_REUSEADDR so the kernel can recycle TIME_WAIT source ports.
async fn connect_reuseaddr(addr: SocketAddr) -> std::io::Result<TcpStream> {
    let socket = match addr {
        SocketAddr::V4(_) => TcpSocket::new_v4(),
        SocketAddr::V6(_) => TcpSocket::new_v6(),
    };

    match socket {
        Ok(socket) => {
            let _ = socket.set_reuseaddr(true);
            if ABORT_WITH_RST {
                // RST instead of FIN on close: skip TIME_WAIT, relieve port pressure.
                set_linger_zero(socket.as_raw_fd());
            }
            socket.connect(addr).await
        }
        Err(_) => TcpStream::connect(addr).await,
    }
}

// Sets SO_LINGER 0 on the raw fd so close sends a RST and skips TIME_WAIT.
// Uses libc directly, not the deprecated TcpSocket::set_linger; with a zero
// timeout Linux close returns at once and does not block on drop. Best effort:
// on failure the socket just closes gracefully with a FIN.
fn set_linger_zero(fd: std::os::unix::io::RawFd) {
    let linger = libc::linger {
        l_onoff: 1,
        l_linger: 0,
    };
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_LINGER,
            &linger as *const _ as *const libc::c_void,
            std::mem::size_of_val(&linger) as libc::socklen_t,
        );
    }
}

fn is_loopback_self_connect(stream: &TcpStream) -> bool {
    let (Ok(local), Ok(peer)) = (stream.local_addr(), stream.peer_addr()) else {
        return false;
    };

    local == peer && local.ip().is_loopback()
}

// Runs a TCP connect scan over many IP addresses and ports concurrently.
// Concurrency is bounded by MAX_IN_FLIGHT, so memory stays flat and the kernel
// keeps free source ports. Local resource exhaustion (EADDRNOTAVAIL) is logged
// and reported as filtered. Counts every probe plus the handshake overhead of
// open ports.
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

    for (ip_addr, port) in probes {
        // Enforce the concurrency limit by waiting for the next completed task.
        if stream.len() >= MAX_IN_FLIGHT
            && let Some(joined) = stream.next().await
        {
            match joined {
                Ok(Ok(result)) => single_results.push(result),
                Ok(Err(e)) => log::error!("Scan probe error: {:?}", e),
                Err(e) => log::error!("Tokio task panicked or was cancelled: {:?}", e),
            }
        }

        // One SYN per probe, counted once here so the drain loops can't drift.
        packets_sent += 1;
        // Parallelize connection attempts across all runtime threads.
        stream.push(tokio::spawn(async move {
            port_tcp_connect_scan(ip_addr, port, timeout).await
        }));
    }

    // Collect remaining in-flight tasks to ensure no results are dropped.
    while let Some(joined) = stream.next().await {
        match joined {
            Ok(Ok(result)) => single_results.push(result),
            Ok(Err(e)) => log::error!("Scan probe error: {:?}", e),
            Err(e) => log::error!("Tokio task panicked or was cancelled: {:?}", e),
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

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    const LOCALHOST: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

    // Binds a loopback listener that accepts and drops connections in the
    // background, returning the bound port.
    async fn spawn_open_listener() -> u16 {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind loopback listener");
        let port = listener.local_addr().expect("listener addr").port();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                drop(stream);
            }
        });
        port
    }

    // Returns a loopback port that nothing listens on, so a connect is refused.
    async fn closed_port() -> u16 {
        // Bind to get a real OS-assigned port, then drop: a connect to it now
        // gets a RST (refused) rather than hanging until timeout.
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind to find closed port");
        let port = listener.local_addr().expect("addr").port();
        drop(listener);
        port
    }

    #[tokio::test]
    async fn open_port_reports_open_synack() {
        let port = spawn_open_listener().await;

        let result = port_tcp_connect_scan(LOCALHOST, port, Duration::from_millis(300))
            .await
            .expect("scan should not error");

        assert_eq!(result.port_state, PortStates::Open);
        assert_eq!(result.reason, PortStateReasons::SynAck);
        assert_eq!(result.port, port);
    }

    #[tokio::test]
    async fn closed_port_reports_closed_refused() {
        let port = closed_port().await;

        let result = port_tcp_connect_scan(LOCALHOST, port, Duration::from_millis(300))
            .await
            .expect("scan should not error");

        assert_eq!(result.port_state, PortStates::Closed);
        assert_eq!(result.reason, PortStateReasons::ConnRefused);
    }

    #[tokio::test]
    async fn unroutable_address_times_out_filtered() {
        // 192.0.2.0/24 (TEST-NET-1) is reserved and unrouted: the connect never
        // completes, so a short timeout yields Filtered/Timeout.
        let unroutable = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));

        let result = port_tcp_connect_scan(unroutable, 80, Duration::from_millis(150))
            .await
            .expect("scan should not error");

        assert_eq!(result.port_state, PortStates::Filtered);
        assert_eq!(result.reason, PortStateReasons::Timeout);
    }

    #[tokio::test]
    async fn connect_reuseaddr_succeeds_to_listener_and_fails_to_closed() {
        let open = spawn_open_listener().await;
        let shut = closed_port().await;

        let ok = connect_reuseaddr(SocketAddr::new(LOCALHOST, open)).await;
        assert!(ok.is_ok(), "connect to live listener should succeed");

        let err = connect_reuseaddr(SocketAddr::new(LOCALHOST, shut)).await;
        assert!(err.is_err(), "connect to closed port should fail");
    }

    #[tokio::test]
    async fn is_loopback_self_connect_false_for_distinct_peers() {
        let port = spawn_open_listener().await;

        let stream = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
            .await
            .expect("connect to listener");

        // Client and server use different ports, so this is not a self-connect.
        assert!(!is_loopback_self_connect(&stream));
    }

    #[tokio::test]
    async fn set_linger_zero_does_not_break_connect() {
        // Confirms applying SO_LINGER=0 (as connect_reuseaddr does when
        // ABORT_WITH_RST is on) does not prevent a normal successful connect.
        let port = spawn_open_listener().await;

        let socket = TcpSocket::new_v4().unwrap();
        set_linger_zero(socket.as_raw_fd());
        let stream = socket
            .connect(SocketAddr::new(LOCALHOST, port))
            .await
            .expect("connect with linger-0 should still succeed");

        assert!(stream.peer_addr().is_ok());
    }

    #[tokio::test]
    async fn run_connect_scan_empty_ips() {
        let (single_results, all_result) = run_connect_scan(Vec::new(), vec![80], None)
            .await
            .expect("empty scan should succeed");

        assert!(single_results.is_empty());
        assert_eq!(all_result.packets_sent, 0);
        assert!(all_result.open_ports.is_empty());
    }

    #[tokio::test]
    async fn run_connect_scan_mixed_open_and_closed() {
        let open = spawn_open_listener().await;
        let shut = closed_port().await;

        let (results, summary) =
            run_connect_scan(vec![Ipv4Addr::LOCALHOST], vec![open, shut], Some(300))
                .await
                .expect("scan should succeed");

        assert_eq!(results.len(), 2);

        let open_res = results
            .iter()
            .find(|r| r.port == open)
            .expect("open result");
        assert_eq!(open_res.port_state, PortStates::Open);

        let shut_res = results
            .iter()
            .find(|r| r.port == shut)
            .expect("closed result");
        assert_eq!(shut_res.port_state, PortStates::Closed);

        assert_eq!(summary.open_ports, vec![open]);
        // Two probes (one SYN each) + 2 extra packets for the single open port.
        assert_eq!(summary.packets_sent, 2 + 2);
    }
}
