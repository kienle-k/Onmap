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
use crate::resolving::get_service_name::{get_service_name, load_service_map};

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
        Ok(Ok(result)) => result.expect("UDP probe task should return a result"),
        Ok(Err(e)) => {
            log::warn!("UDP probe failed for {}:{}: {}", target_ip, port, e);
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
    let service_map = Arc::new(
        load_service_map("src/resolving/port_service_mapping.json")
            .map_err(|e| format!("Failed to load service names: {}", e))?,
    );

    let start_time = SystemTime::now();
    let semaphore = Arc::new(Semaphore::new(200));
    let mut futs = FuturesUnordered::new();

    for &(ip, source_ip) in &ip_addresses {
        for &port in &ports {
            let sem_clone = semaphore.clone();
            let service_map_clone = Arc::clone(&service_map);

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
                    service: get_service_name(&service_map_clone, "udp", port),
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
        ports_scanned: ports.len() as u16,
        packets_sent: (ip_addresses.len() * ports.len()) as u32,
        open_ports,
        start_time,
        end_time: SystemTime::now(),
        scan_type: None,
    };

    Ok((single_results, all_results))
}
