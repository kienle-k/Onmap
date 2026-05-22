use crate::resolving::get_service_name::{ProtocolMap, get_service_name, load_protocol_map};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::tcp::{MutableTcpPacket, TcpFlags};
use pnet::transport::tcp_packet_iter;
use pnet::transport::{TransportChannelType, TransportProtocol, transport_channel};
use rand::Rng;
use std::net::{IpAddr, Ipv4Addr, UdpSocket};
use std::result::Result;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use crate::models::{
    PortScanAllResult, PortScanSingleResult, PortStateReasons, PortStates, Protocols,
};

fn source_ip_for_target(target: Ipv4Addr) -> Result<Ipv4Addr, String> {
    if target.is_loopback() {
        return Ok(Ipv4Addr::new(127, 0, 0, 1));
    }

    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
        .map_err(|e| format!("Failed to bind route probe socket: {}", e))?;

    socket
        .connect((target, 9))
        .map_err(|e| format!("Failed to determine route to {}: {}", target, e))?;

    match socket
        .local_addr()
        .map_err(|e| format!("Failed to read local route address: {}", e))?
        .ip()
    {
        IpAddr::V4(ip) => Ok(ip),
        IpAddr::V6(ip) => Err(format!("Expected IPv4 source address, got IPv6 {}", ip)),
    }
}

/// Performs a TCP SYN scan on a single port for a given IP address.
///
/// This function crafts and sends a raw TCP packet with the SYN flag set. It then listens
/// for a response to determine the port's state:
/// - **Open**: A SYN/ACK response is received.
/// - **Closed**: A RST response is received.
/// - **Filtered**: No response is received within the timeout period.
///
/// # Arguments
///
/// * `ip_address` - The target `IpAddr` to scan.
/// * `port` - The target port number to scan.
/// * `local_ip_address` - The source `Ipv4Addr` to use for the packet.
/// * `protocols` - A map of protocols and services for service name resolution.
/// * `timeout_override_ms` - Optional receive timeout in milliseconds.
///
/// # Returns
///
/// A `Result` containing either a `PortScanSingleResult` with the scan details
/// or a `String` describing an error.
///
/// # Errors
///
/// This function will return an `Err` if it fails to create the transport channel,
/// which typically requires administrator/root privileges. It also returns an error for IPv6 addresses.
pub async fn port_syn_scan(
    ip_address: IpAddr,
    port: u16,
    _local_ip_address: Ipv4Addr,
    protocols: Arc<ProtocolMap>,
    timeout_override_ms: Option<u64>,
) -> Result<PortScanSingleResult, String> {
    // Only IPv4 is supported for this implementation
    let ipv4 = match ip_address {
        IpAddr::V4(ipv4) => ipv4,
        IpAddr::V6(_) => return Err("IPv6 is not supported for SYN scanning".to_string()),
    };

    // Create a raw transport channel for sending and receiving TCP packets
    let protocol = TransportProtocol::Ipv4(IpNextHeaderProtocols::Tcp);
    let (mut tx, rx) = match transport_channel(4096, TransportChannelType::Layer4(protocol)) {
        Ok((tx, rx)) => (tx, rx),
        Err(e) => {
            return Err(format!(
                "Error creating transport channel: {}. Try running with sudo.",
                e
            ));
        }
    };

    // Create an Arc<Mutex<...>> for the receiver so it can be moved into the blocking task
    let rx = Arc::new(Mutex::new(rx));

    // Generate a random source port from the ephemeral range
    let source_port = rand::thread_rng().gen_range(49152..65535);

    // Create a SYN packet (header only, no options)
    let mut tcp_buffer = [0u8; 20];
    let mut tcp_packet =
        MutableTcpPacket::new(&mut tcp_buffer).expect("Failed to create TCP packet buffer");

    // Configure TCP header
    tcp_packet.set_source(source_port);
    tcp_packet.set_destination(port);
    tcp_packet.set_sequence(rand::thread_rng().r#gen::<u32>());
    tcp_packet.set_acknowledgement(0);
    tcp_packet.set_data_offset(5); // Standard TCP header length
    tcp_packet.set_flags(TcpFlags::SYN);
    tcp_packet.set_window(64240);
    tcp_packet.set_urgent_ptr(0);

    // Ask the kernel which IPv4 source address it would use for this target.
    let route_source_ip = source_ip_for_target(ipv4)?;

    // The TCP pseudo-header must match the route-specific source IP.
    let checksum =
        pnet::packet::tcp::ipv4_checksum(&tcp_packet.to_immutable(), &route_source_ip, &ipv4);
    tcp_packet.set_checksum(checksum);

    // eprintln!(
    //     "SYN DEBUG send: target={} configured_local_ip={} route_source_ip={} source_port={} target_port={} checksum=0x{:04x}",
    //     ip_address,
    //     local_ip_address,
    //     route_source_ip,
    //     source_port,
    //     port,
    //     checksum
    // );

    // Send the packet
    if let Err(e) = tx.send_to(tcp_packet, ip_address) {
        return Err(format!("Failed to send packet: {}", e));
    };

    let protocols_clone_for_response = Arc::clone(&protocols);
    let rx_clone = Arc::clone(&rx);

    const DEFAULT_READ_TIMEOUT_MS: u64 = 800;
    let read_timeout_ms = timeout_override_ms.unwrap_or(DEFAULT_READ_TIMEOUT_MS);

    let response_task = tokio::task::spawn_blocking(move || {
        let mut rx_guard = rx_clone.lock().expect("Mutex was poisoned");
        let mut iter = tcp_packet_iter(&mut *rx_guard);
        let timeout_duration = Duration::from_millis(read_timeout_ms);
        let start_time = Instant::now();

        loop {
            let remaining_time = timeout_duration.saturating_sub(start_time.elapsed());
            if remaining_time.is_zero() {
                break;
            }

            match iter.next_with_timeout(remaining_time) {
                Ok(Some((packet, addr))) => {
                    if packet.get_destination() == source_port
                        && addr == ip_address
                        && packet.get_source() == port
                    {
                        let flags = packet.get_flags();
                        if (flags & TcpFlags::SYN != 0) && (flags & TcpFlags::ACK != 0) {
                            let ttl = 63; // Placeholder, real TTL extraction is not implemented yet
                            return Ok(PortScanSingleResult {
                                ip_address,
                                port,
                                protocol: Protocols::TCP,
                                port_state: PortStates::Open,
                                ttl,
                                reason: PortStateReasons::SynAck,
                                service: get_service_name(
                                    &protocols_clone_for_response,
                                    "tcp",
                                    port,
                                ),
                            });
                        }
                        if flags & TcpFlags::RST != 0 {
                            let ttl = 63; // Placeholder, real TTL extractions is not implemented yet
                            return Ok(PortScanSingleResult {
                                ip_address,
                                port,
                                protocol: Protocols::TCP,
                                port_state: PortStates::Closed,
                                ttl,
                                reason: PortStateReasons::Reset,
                                service: get_service_name(
                                    &protocols_clone_for_response,
                                    "tcp",
                                    port,
                                ),
                            });
                        }
                    }
                }
                Ok(None) => {
                    continue;
                }
                Err(e) => {
                    eprintln!("Error receiving packet: {}", e);
                    std::thread::sleep(Duration::from_millis(20));
                }
            }
        }

        Ok(PortScanSingleResult {
            ip_address,
            port,
            protocol: Protocols::TCP,
            port_state: PortStates::Filtered,
            ttl: 0,
            reason: PortStateReasons::Timeout,
            service: get_service_name(&protocols_clone_for_response, "tcp", port),
        })
    });

    match response_task.await {
        Ok(result) => result,
        Err(e) => Err(format!("Blocking task panicked: {}", e)),
    }
}

/// Orchestrates an asynchronous TCP SYN scan across multiple IPs and ports.
///
/// This function serves as the main entry point for conducting a SYN scan. It spawns
/// concurrent tasks for each target IP and port, managing concurrency with a semaphore
/// to avoid overwhelming the network or the host system.
///
/// # Arguments
///
/// * `ip_address_arr` - A `Result` containing either a `Vec<Ipv4Addr>` of targets or an error string.
/// * `ports_arr` - A vector of `u16` port numbers to scan on each target.
/// * `local_ip_address` - The source `Ipv4Addr` to be used for sending packets.
///
/// # Returns
///
/// A `Result` which, on success, contains a tuple of:
/// * `Vec<PortScanSingleResult>`: A detailed list of results for each port scanned.
/// * `PortScanAllResult`: An aggregate summary of the entire scan operation.
///
/// # Errors
///
/// This function requires administrator/root privileges to create raw sockets for packet crafting.
/// It will return an `Err` if the underlying `port_syn_scan` calls fail due to permission issues.
pub async fn run_syn_scan(
    ip_addresses: Vec<Ipv4Addr>,
    ports_arr: Vec<u16>,
    local_ip_address: Ipv4Addr,
    timeout_override_ms: Option<u64>,
) -> Result<(Vec<PortScanSingleResult>, PortScanAllResult), String> {
    // Load the protocol/service data from the json file
    let protocols = Arc::new(
        load_protocol_map("src/resolving/port_service_mapping.json")
            .expect("Failed to load protocol map"),
    );

    // Record the start time to calculate total scan duration later.
    let start_time = SystemTime::now();

    // Create a vector to hold the handles for all the asynchronous tasks we're about to spawn.
    let mut tasks = Vec::new();

    // Create thread-safe, shared containers for the results.
    let single_results = Arc::new(Mutex::new(Vec::<PortScanSingleResult>::new()));
    let open_ports = Arc::new(Mutex::new(Vec::<u16>::new()));
    let packets_sent = Arc::new(Mutex::new(0u32));

    // Use a semaphore to limit concurrent scans to 100 at a time.
    let semaphore = Arc::new(tokio::sync::Semaphore::new(100));

    // Create a task for each IP/port combination
    for ip in ip_addresses {
        for &port in &ports_arr {
            let single_results_clone = Arc::clone(&single_results);
            let open_ports_clone = Arc::clone(&open_ports);
            let packets_sent_clone = Arc::clone(&packets_sent);
            let sem_clone = Arc::clone(&semaphore);
            let protocols_clone = Arc::clone(&protocols);

            // Spawn a Tokio task for each scan
            let task = tokio::spawn(async move {
                // Acquire a permit from the semaphore before scanning
                let _permit = sem_clone
                    .acquire()
                    .await
                    .expect("Semaphore should not be closed");

                // Increment packets sent counter safely
                *packets_sent_clone.lock().expect("Mutex was poisoned") += 1;

                match port_syn_scan(
                    IpAddr::V4(ip),
                    port,
                    local_ip_address,
                    protocols_clone,
                    timeout_override_ms,
                )
                .await
                {
                    Ok(result) => {
                        // If port is open, add it to the shared list of open ports
                        if result.port_state == PortStates::Open {
                            open_ports_clone
                                .lock()
                                .expect("Mutex was poisoned")
                                .push(port);
                            log::info!("Discovered open port {}/tcp on {}", port, ip);
                        }
                        // Add the detailed result to the shared list of all results
                        single_results_clone
                            .lock()
                            .expect("Mutex was poisoned")
                            .push(result);
                    }
                    Err(e) => {
                        log::warn!("Error scanning {}:{}: {}", ip, port, e);
                    }
                }
            });
            tasks.push(task);
        }
    }

    // Wait for all scan tasks to complete
    for task in tasks {
        let _ = task.await;
    }

    let end_time = SystemTime::now();

    // Unwrap the results from their thread-safe containers
    let single_results = Arc::try_unwrap(single_results)
        .expect("Mutex still has references")
        .into_inner()
        .expect("Mutex was poisoned");
    let open_ports = Arc::try_unwrap(open_ports)
        .expect("Mutex still has references")
        .into_inner()
        .expect("Mutex was poisoned");
    let packets_sent = Arc::try_unwrap(packets_sent)
        .expect("Mutex still has references")
        .into_inner()
        .expect("Mutex was poisoned");

    // Create the final summary result
    let all_result = PortScanAllResult {
        ports_scanned: ports_arr.len() as u16,
        packets_sent,
        open_ports,
        start_time,
        end_time,
    };

    Ok((single_results, all_result))
}

#[cfg(test)]
mod tests {
    //! Unit tests for the SYN scan module.
    use super::*;

    /// Tests that `run_syn_scan` handles empty IP input without failing.
    #[tokio::test]
    async fn test_run_syn_scan_empty_ips() {
        let ips = Vec::new();
        let ports = vec![80];
        let local_ip = Ipv4Addr::new(127, 0, 0, 1);

        let result = run_syn_scan(ips, ports, local_ip, None).await;

        assert!(result.is_ok());
        let (single_results, all_result) = result.expect("Expected empty scan to succeed");
        assert!(single_results.is_empty());
        assert_eq!(all_result.packets_sent, 0);
        assert!(all_result.open_ports.is_empty());
    }
}
