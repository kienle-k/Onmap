use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::tcp::{MutableTcpPacket, TcpFlags};
use pnet::transport::{transport_channel, TransportChannelType, TransportProtocol};
use rand::Rng;
use pnet::transport::tcp_packet_iter;
use std::result::Result;
use crate::resolving::get_service_name::{ProtocolMap, load_protocol_map, get_service_name};

use crate::models::{Protocols, PortStates, PortStateReasons, PortScanSingleResult, PortScanAllResult};

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
pub async fn port_syn_scan(ip_address: IpAddr, port: u16, local_ip_address: Ipv4Addr, protocols: Arc<ProtocolMap>) -> Result<PortScanSingleResult, String> {
    // Only IPv4 is supported for this implementation
    let ipv4 = match ip_address {
        IpAddr::V4(ipv4) => ipv4,
        IpAddr::V6(_) => return Err("IPv6 is not supported for SYN scanning".to_string()),
    };

    // Create a raw transport channel for sending and receiving TCP packets
    let protocol = TransportProtocol::Ipv4(IpNextHeaderProtocols::Tcp);
    let (mut tx, rx) = match transport_channel(4096, TransportChannelType::Layer4(protocol)) {
        Ok((tx, rx)) => (tx, rx),
        Err(e) => return Err(format!("Error creating transport channel: {}. Try running with sudo.", e)),
    };

    // Create an Arc<Mutex<...>> for the receiver so it can be moved into the blocking task
    let rx = Arc::new(Mutex::new(rx));

    // Generate a random source port from the ephemeral range
    let source_port = rand::thread_rng().gen_range(49152..65535);

    // Create a SYN packet
    let mut tcp_buffer = [0u8; 66]; // TCP header size + options
    let mut tcp_packet = MutableTcpPacket::new(&mut tcp_buffer).expect("Failed to create TCP packet buffer");

    // Configure TCP header
    tcp_packet.set_source(source_port);
    tcp_packet.set_destination(port);
    tcp_packet.set_sequence(rand::thread_rng().r#gen::<u32>());
    tcp_packet.set_acknowledgement(0);
    tcp_packet.set_data_offset(5); // Standard TCP header length
    tcp_packet.set_flags(TcpFlags::SYN);
    tcp_packet.set_window(64240);
    tcp_packet.set_urgent_ptr(0);

    // Calculate checksum using the source and destination IPs
    let checksum = pnet::packet::tcp::ipv4_checksum(&tcp_packet.to_immutable(), &local_ip_address, &ipv4);
    tcp_packet.set_checksum(checksum);

    // Send the packet
    if let Err(e) = tx.send_to(tcp_packet, ip_address) {
        return Err(format!("Failed to send packet: {}", e));
    };

    // Clone protocols here to move into the async block
    let protocols_clone_for_response = Arc::clone(&protocols);

    // Asynchronously wait for a matching response, offloading blocking `iter.next()` to a blocking task
    let response_future = async move { // Add `move` here to take ownership of protocols_clone_for_response
        let rx_clone = Arc::clone(&rx);
        tokio::task::spawn_blocking(move || { // Add `move` here to take ownership of protocol_clone_for_response
            let mut rx_guard = rx_clone.lock().expect("Mutex was poisoned");
            let mut iter = tcp_packet_iter(&mut *rx_guard); // Dereference the MutexGuard to get the TransportReceiver

            loop {
                match iter.next() {
                    Ok((packet, addr)) => {
                        // Check if the response is from the target host and for our source port
                        if packet.get_destination() == source_port && addr == ip_address && packet.get_source() == port {
                            let flags = packet.get_flags();
                            if (flags & TcpFlags::SYN != 0) && (flags & TcpFlags::ACK != 0) {
                                let ttl = 63; // Placeholder, real TTL extraction is not implemented yet
                                return Ok(PortScanSingleResult {
                                    ip_address, port, protocol: Protocols::TCP,
                                    port_state: PortStates::Open, ttl,
                                    reason: PortStateReasons::SynAck, service: get_service_name(&protocols_clone_for_response, "tcp", port),
                                });
                            }
                            if flags & TcpFlags::RST != 0 {
                                let ttl = 63; // Placeholder, real TTL extractions is not implemented yet
                                return Ok(PortScanSingleResult {
                                    ip_address, port, protocol: Protocols::TCP,
                                    port_state: PortStates::Closed, ttl,
                                    reason: PortStateReasons::Reset, service: get_service_name(&protocols_clone_for_response, "tcp", port),
                                });
                            }
                        }
                    }
                    Err(e) => {
                        // Log or handle the error from iter.next()
                        eprintln!("Error receiving packet: {}", e);
                        // A short delay to prevent fast spinning on I/O errors (still good practice)
                        std::thread::sleep(Duration::from_millis(20));
                    }
                }
            }
        }).await.expect("Blocking task panicked") // Await the result of the blocking task
    };

    // Wait for the response with an 800ms timeout
    match tokio::time::timeout(Duration::from_millis(800), response_future).await {
        Ok(Ok(result)) => Ok(result), // Response received and processed successfully
        Ok(Err(e)) => Err(e),         // Internal error from the response logic (e.g., blocking task failed)
        Err(_) => { // Timeout occurred, port is considered filtered
            Ok(PortScanSingleResult {
                ip_address, port, protocol: Protocols::TCP,
                port_state: PortStates::Filtered, ttl: 0,
                reason: PortStateReasons::Timeout,
                service: get_service_name(&protocols, "tcp", port), // Use the original protocols here if needed
            })
        }
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
    ip_address_arr: Result<Vec<Ipv4Addr>, String>,
    ports_arr: Vec<u16>,
    local_ip_address: Ipv4Addr
) -> Result<(Vec<PortScanSingleResult>, PortScanAllResult), String> {
    let ip_addresses = match ip_address_arr {
        Ok(ips) => ips,
        Err(e) => return Err(format!("Failed to get IP addresses: {}", e)),
    };

    // Load the protocol/service data from the json file
    let protocols = Arc::new(load_protocol_map("src/resolving/port_service_mapping.json").expect("Failed to load protocol map"));

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
                let _permit = sem_clone.acquire().await.expect("Semaphore should not be closed");
                
                // Increment packets sent counter safely
                *packets_sent_clone.lock().expect("Mutex was poisoned") += 1;
                
                match port_syn_scan(IpAddr::V4(ip), port, local_ip_address, protocols_clone).await {
                    Ok(result) => {
                        // If port is open, add it to the shared list of open ports
                        if result.port_state == PortStates::Open {
                            open_ports_clone.lock().expect("Mutex was poisoned").push(port);
                        }
                        // Add the detailed result to the shared list of all results
                        single_results_clone.lock().expect("Mutex was poisoned").push(result);
                    }
                    Err(e) => {
                        eprintln!("Error scanning {}:{}: {}", ip, port, e);
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
    let single_results = Arc::try_unwrap(single_results).expect("Mutex still has references").into_inner().expect("Mutex was poisoned");
    let open_ports = Arc::try_unwrap(open_ports).expect("Mutex still has references").into_inner().expect("Mutex was poisoned");
    let packets_sent = Arc::try_unwrap(packets_sent).expect("Mutex still has references").into_inner().expect("Mutex was poisoned");

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

    /// Tests the error handling path of `run_syn_scan` when provided with an `Err`
    /// containing the IP addresses. This is a unit test as it does not perform
    /// any network operations.
    #[tokio::test]
    async fn test_run_syn_scan_ip_error_handling() {
        let ips = Err("Failed to resolve hostname".to_string());
        let ports = vec![80];
        let local_ip = Ipv4Addr::new(127, 0, 0, 1);

        let result = run_syn_scan(ips, ports, local_ip).await;

        assert!(result.is_err());
        let err_msg = result.expect_err("Expected run_syn_scan to fail");

        assert_eq!(err_msg, "Failed to get IP addresses: Failed to resolve hostname");
    }
}