use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use futures::stream::{FuturesUnordered, StreamExt};
use tokio::sync::Semaphore;
use tokio::task;
use tokio::time::timeout;

use crate::models::{
    PortScanAllResult, PortScanSingleResult, PortStateReasons, PortStates, Protocols,
};

async fn udp_probe_with_details(
    target_ip: Ipv4Addr,
    port: u16,
    source_ip: Ipv4Addr,
    timeout_override_ms: Option<u64>,
) -> (PortStates, PortStateReasons) {
    const ATTEMPTS: usize = 2;
    const MIN_SUCCESS: usize = 2;
    const DEFAULT_READ_TIMEOUT_MS: u64 = 800;
    const RETRY_DELAY_MS: u64 = 50;
    const OUTER_PADDING_MS: u64 = 200;
    let read_timeout_ms = timeout_override_ms.unwrap_or(DEFAULT_READ_TIMEOUT_MS);
    let outer_timeout_ms =
        (ATTEMPTS as u64 * (read_timeout_ms + RETRY_DELAY_MS)) + OUTER_PADDING_MS;

    let task = task::spawn_blocking(move || {
        let mut success_count = 0usize;

        for attempt in 0..ATTEMPTS {
            let bind_addr = SocketAddr::new(IpAddr::V4(source_ip), 0);
            let socket = UdpSocket::bind(bind_addr)
                .map_err(|e| format!("Failed to bind UDP socket: {}", e))?;

            let dest_addr = SocketAddr::new(IpAddr::V4(target_ip), port);
            socket.connect(dest_addr).map_err(|e| {
                format!(
                    "Failed to connect UDP socket to {}:{}: {}",
                    target_ip, port, e
                )
            })?;

            socket
                .set_read_timeout(Some(Duration::from_millis(read_timeout_ms)))
                .map_err(|e| format!("Failed to set UDP read timeout: {}", e))?;

            let payload = [0u8; 8];
            match socket.send(&payload) {
                Ok(_) => {}
                Err(e) => {
                    if e.kind() == ErrorKind::ConnectionRefused {
                        return Ok((PortStates::Closed, PortStateReasons::IcmpPortUnreachable));
                    }
                    return Err(format!(
                        "Failed to send UDP probe to {}:{}: {}",
                        target_ip, port, e
                    ));
                }
            }

            let mut buffer = [0u8; 512];
            match socket.recv(&mut buffer) {
                Ok(_) => {
                    success_count += 1;
                    if success_count >= MIN_SUCCESS {
                        return Ok((PortStates::Open, PortStateReasons::UdpResponse));
                    }
                }
                Err(e) => match e.kind() {
                    ErrorKind::ConnectionRefused => {
                        return Ok((PortStates::Closed, PortStateReasons::IcmpPortUnreachable));
                    }
                    ErrorKind::WouldBlock | ErrorKind::TimedOut => {}
                    _ => {
                        return Err(format!(
                            "UDP receive failed for {}:{}: {}",
                            target_ip, port, e
                        ));
                    }
                },
            }

            if attempt + 1 < ATTEMPTS {
                std::thread::sleep(Duration::from_millis(RETRY_DELAY_MS));
            }
        }

        Ok((PortStates::OpenOrFiltered, PortStateReasons::Timeout))
    });

    match timeout(Duration::from_millis(outer_timeout_ms), task).await {
        Ok(Ok(Ok(result))) => result,
        Ok(Ok(Err(e))) => {
            log::warn!("UDP probe failed for {}:{}: {}", target_ip, port, e);
            (PortStates::Filtered, PortStateReasons::Timeout)
        }
        Ok(Err(e)) => {
            log::warn!("UDP probe task failed for {}:{}: {}", target_ip, port, e);
            (PortStates::Filtered, PortStateReasons::Timeout)
        }
        Err(_) => (PortStates::OpenOrFiltered, PortStateReasons::Timeout),
    }
}

/// Runs a concurrent UDP scan against `(target, source_ip)` pairs and ports.
pub async fn run_udp_scan(
    ip_addresses: Vec<(Ipv4Addr, Ipv4Addr)>,
    ports: Vec<u16>,
    timeout_override_ms: Option<u64>,
) -> Result<(Vec<PortScanSingleResult>, PortScanAllResult), String> {
    let start_time = SystemTime::now();
    let semaphore = Arc::new(Semaphore::new(200));
    let mut futs = FuturesUnordered::new();

    for &(ip, source_ip) in &ip_addresses {
        for &port in &ports {
            let sem_clone = semaphore.clone();

            futs.push(async move {
                let _permit = sem_clone
                    .acquire()
                    .await
                    .expect("Semaphore should not be closed");
                let (state, reason) =
                    udp_probe_with_details(ip, port, source_ip, timeout_override_ms).await;

                if state == PortStates::Open {
                    log::info!("Discovered open port {}/udp on {}", port, ip);
                }

                PortScanSingleResult {
                    ip_address: IpAddr::V4(ip),
                    port,
                    protocol: Protocols::UDP,
                    port_state: state,
                    ttl: 0,
                    reason,
                }
            });
        }
    }

    let mut single_results: Vec<PortScanSingleResult> = Vec::new();
    while let Some(result) = futs.next().await {
        single_results.push(result);
    }

    let open_ports = single_results
        .iter()
        .filter(|r| r.port_state == PortStates::Open)
        .map(|r| r.port)
        .collect();

    let all_results = PortScanAllResult {
        ports_scanned: ports.len() as u32,
        packets_sent: (ip_addresses.len() * ports.len()) as u32,
        open_ports,
        start_time,
        end_time: SystemTime::now(),
        scan_type: None,
    };

    Ok((single_results, all_results))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::UdpSocket;

    // Binds a UDP loopback socket and spawns a thread that echoes every
    // datagram back.  Returns the bound port.  The echo loop runs indefinitely
    // so multiple probes (ATTEMPTS = 2) are all answered.
    fn spawn_udp_echo_server() -> u16 {
        let socket =
            UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).unwrap();
        let port = socket.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let mut buf = [0u8; 512];
            loop {
                if let Ok((len, peer)) = socket.recv_from(&mut buf) {
                    let _ = socket.send_to(&buf[..len], peer);
                }
            }
        });
        port
    }

    // Binds to get an OS-assigned port, then drops the socket.  Any connect
    // to the returned port receives ICMP port unreachable (ECONNREFUSED).
    fn closed_udp_port() -> u16 {
        let socket =
            UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).unwrap();
        let port = socket.local_addr().unwrap().port();
        drop(socket);
        port
    }

    // Pair of (target=loopback, source=loopback) for run_udp_scan.
    fn localhost_pair() -> (Ipv4Addr, Ipv4Addr) {
        (Ipv4Addr::LOCALHOST, Ipv4Addr::LOCALHOST)
    }

    // -------------------------------------------------------------------------
    // Empty-input tests — no network I/O
    // -------------------------------------------------------------------------

    /// An empty host list must succeed and return no per-port results.
    #[tokio::test]
    async fn empty_hosts_returns_zero_results() {
        let (results, _) = run_udp_scan(vec![], vec![53], None)
            .await
            .expect("empty host list must not fail");
        assert!(results.is_empty());
    }

    /// packets_sent = hosts × ports.  With no hosts this is always zero.
    #[tokio::test]
    async fn empty_hosts_summary_packets_sent_is_zero() {
        let (_, summary) = run_udp_scan(vec![], vec![53, 123], None)
            .await
            .expect("empty host list must not fail");
        assert_eq!(summary.packets_sent, 0);
    }

    /// open_ports must be empty when no hosts were scanned.
    #[tokio::test]
    async fn empty_hosts_summary_open_ports_is_empty() {
        let (_, summary) = run_udp_scan(vec![], vec![53], None)
            .await
            .expect("empty host list must not fail");
        assert!(summary.open_ports.is_empty());
    }

    /// ports_scanned must equal the number of ports provided regardless of
    /// how many hosts were in the list.
    #[tokio::test]
    async fn summary_ports_scanned_matches_port_count() {
        let (_, summary) = run_udp_scan(vec![], vec![53, 123, 161], None)
            .await
            .expect("empty host list must not fail");
        assert_eq!(summary.ports_scanned, 3);
    }

    /// end_time must not precede start_time.
    #[tokio::test]
    async fn summary_end_time_not_before_start_time() {
        let (_, summary) = run_udp_scan(vec![], vec![53], None)
            .await
            .expect("empty host list must not fail");
        assert!(summary.end_time >= summary.start_time);
    }

    // -------------------------------------------------------------------------
    // Loopback tests — real UDP sockets, no root required
    // -------------------------------------------------------------------------

    /// A port that echoes UDP datagrams back must be reported as Open.
    #[tokio::test]
    async fn echo_server_port_reported_as_open() {
        let port = spawn_udp_echo_server();

        let (results, _) = run_udp_scan(vec![localhost_pair()], vec![port], Some(300))
            .await
            .expect("scan must not fail");

        assert_eq!(results.len(), 1);
        assert_eq!(
            results[0].port_state,
            PortStates::Open,
            "echoing port should be Open"
        );
    }

    /// An Open result must carry the UdpResponse reason.
    #[tokio::test]
    async fn echo_server_port_reason_is_udp_response() {
        let port = spawn_udp_echo_server();

        let (results, _) = run_udp_scan(vec![localhost_pair()], vec![port], Some(300))
            .await
            .expect("scan must not fail");

        assert_eq!(results[0].reason, PortStateReasons::UdpResponse);
    }

    /// A port that returns ICMP port unreachable must be reported as Closed.
    #[tokio::test]
    async fn closed_port_reported_as_closed() {
        let port = closed_udp_port();

        let (results, _) = run_udp_scan(vec![localhost_pair()], vec![port], Some(300))
            .await
            .expect("scan must not fail");

        assert_eq!(results.len(), 1);
        assert_eq!(
            results[0].port_state,
            PortStates::Closed,
            "refused port should be Closed"
        );
    }

    /// A Closed result must carry the IcmpPortUnreachable reason.
    #[tokio::test]
    async fn closed_port_reason_is_icmp_port_unreachable() {
        let port = closed_udp_port();

        let (results, _) = run_udp_scan(vec![localhost_pair()], vec![port], Some(300))
            .await
            .expect("scan must not fail");

        assert_eq!(results[0].reason, PortStateReasons::IcmpPortUnreachable);
    }

    /// An Open port must appear in the summary's open_ports list.
    #[tokio::test]
    async fn open_port_appears_in_summary_open_ports() {
        let port = spawn_udp_echo_server();

        let (_, summary) = run_udp_scan(vec![localhost_pair()], vec![port], Some(300))
            .await
            .expect("scan must not fail");

        assert!(
            summary.open_ports.contains(&port),
            "open port {port} should be in summary open_ports"
        );
    }

    /// A Closed port must not appear in the summary's open_ports list.
    #[tokio::test]
    async fn closed_port_absent_from_summary_open_ports() {
        let port = closed_udp_port();

        let (_, summary) = run_udp_scan(vec![localhost_pair()], vec![port], Some(300))
            .await
            .expect("scan must not fail");

        assert!(
            !summary.open_ports.contains(&port),
            "closed port {port} must not appear in open_ports"
        );
    }

    /// The result must carry the correct IP address so callers can match
    /// results back to their input.
    #[tokio::test]
    async fn result_ip_address_matches_input() {
        let port = closed_udp_port();

        let (results, _) = run_udp_scan(vec![localhost_pair()], vec![port], Some(300))
            .await
            .expect("scan must not fail");

        assert_eq!(results[0].ip_address, IpAddr::V4(Ipv4Addr::LOCALHOST));
    }
}
