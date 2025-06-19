use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use futures::stream::{FuturesUnordered, StreamExt};
use pnet::packet::tcp::{MutableTcpPacket, TcpFlags};
use pnet::transport::{transport_channel, TransportChannelType, TransportProtocol};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::transport::tcp_packet_iter;
use rand::Rng;
use tokio::sync::Semaphore;
use tokio::time::timeout;
use tokio::task;

use crate::resolving::get_service_name::{load_protocol_map, get_service_name};
use crate::models::{PortScanSingleResult, PortScanAllResult, PortStates, Protocols, PortStateReasons};

/// Sends a single TCP ACK packet using a Layer 4 channel and returns its status.
///
/// NOTE: This implementation uses a Layer 4 channel.
/// As a result, it cannot extract the real TTL from the reply packet's IP header.
/// A placeholder TTL of 0 will be used for unfiltered ports.
///
/// # Arguments
///
/// * `ip_address` - The target IPv4 address to scan.
/// * `port` - The target port number.
/// * `local_ip` - The source IPv4 address to use for the packet.
///
/// # Returns
///
/// A tuple `(is_unfiltered, optional_ttl)` indicating the scan result.
pub async fn port_ack_scan(ip_address: Ipv4Addr, port: u16, local_ip: Ipv4Addr) -> (bool, Option<u8>) {
    let target_ip = IpAddr::V4(ip_address);

     // Entire pnet operation is synchronous and blocking.
     // -> Spawn a blocking task, to move off the main thread.
     // -> Prevents from stalling other concurrent tasks.
    let send_and_recv = task::spawn_blocking(move || {

        let protocol = TransportProtocol::Ipv4(IpNextHeaderProtocols::Tcp);
        let (mut tx, mut rx) = match transport_channel(4096, TransportChannelType::Layer4(protocol)) {
            Ok((tx, rx)) => (tx, rx),
            Err(_) => return (false, None),
        };

        let mut tcp_buffer = [0u8; 66];
        let mut tcp_packet = MutableTcpPacket::new(&mut tcp_buffer).unwrap();
        
        // Generate a random source port to check against the reply.
        let source_port = rand::thread_rng().gen_range(49152..65535);

        tcp_packet.set_source(source_port);
        tcp_packet.set_destination(port);
        tcp_packet.set_sequence(rand::thread_rng().r#gen::<u32>());
        tcp_packet.set_data_offset(5);

        tcp_packet.set_flags(TcpFlags::ACK);
        tcp_packet.set_window(64240);
        tcp_packet.set_urgent_ptr(0);

        let checksum = pnet::packet::tcp::ipv4_checksum(&tcp_packet.to_immutable(), &local_ip, &ip_address);
        tcp_packet.set_checksum(checksum);

        if tx.send_to(tcp_packet, target_ip).is_err() {
            return (false, None);
        };
        
        let mut iter = tcp_packet_iter(&mut rx);
        let start_time = Instant::now();
        let timeout_duration = Duration::from_millis(800);

        while start_time.elapsed() < timeout_duration {
            let remaining_time = timeout_duration.saturating_sub(start_time.elapsed());
            
            match iter.next_with_timeout(remaining_time) {
                Ok(Some((packet, addr))) => {
                    if packet.get_destination() == source_port && addr == target_ip {
                        if packet.get_flags() & TcpFlags::RST != 0 {
                            // RST received, port is unfiltered. Return placeholder TTL.
                            return (true, Some(0));
                        }
                    }
                }
                // A timeout or error on a single receive attempt is fine -> loop and try again.
                Ok(None) => {},
                Err(_) => {}
            }
        }

        // If loop completes without valid reply, the port is considered filtered.
        (false, None)
    });

    // A hard outer timeout to ensure the blocking task never hangs.
    match timeout(Duration::from_millis(900), send_and_recv).await {
        Ok(Ok(result)) => result,
        _ => (false, None),
    }
}

/// Runs a concurrent TCP ACK scan against a list of hosts and ports.
///
/// This function orchestrates the scan by spawning asynchronous tasks for each target port.
/// Concurrency is managed by a semaphore to avoid overwhelming the network.
///
/// # Arguments
///
/// * `ip_addresses` - A `Result` containing a vector of target IPv4 addresses.
/// * `ports` - A slice of port numbers to scan on each target.
/// * `local_ip` - The primary source `Ipv4Addr` to be used for sending packets.
///
/// # Returns
///
/// A `Result` containing a tuple of `(Vec<PortScanSingleResult>, PortScanAllResult)` on success.
pub async fn run_ack_scan(
    ip_addresses: Result<Vec<Ipv4Addr>, String>,
    ports: &[u16],
    local_ip: Ipv4Addr,
) -> Result<(Vec<PortScanSingleResult>, PortScanAllResult), String> {
    let ips = match ip_addresses {
        Ok(ips) => ips,
        Err(e) => return Err(format!("Failed to get IP addresses: {}", e)),
    };

    // Load service name data once, share cheaply across all tasks then.
    let protocols = Arc::new(load_protocol_map("src/resolving/port_service_mapping.json")
        .map_err(|e| format!("Failed to load service names: {}", e))?);


    let start_time = SystemTime::now();
    // Semaphore limits the number of concurrent in-flight scans.
    let semaphore = Arc::new(Semaphore::new(200));
    let mut futs = FuturesUnordered::new();



    for &ip in &ips {
        for &port in ports {
            let sem_clone = semaphore.clone();
            let protocols_clone = Arc::clone(&protocols);


            // CRITICAL: If scanning a loopback address, the source IP *must* also be a
            // loopback address for the OS to correctly route and receive the reply.
            let source_ip = if ip.is_loopback() {
                Ipv4Addr::new(127, 0, 0, 1)
            } else {
                local_ip
            };
   
            futs.push(async move {
                // Wait for a permit from the semaphore before starting the scan.
                let _permit = sem_clone.acquire().await.unwrap();
                let (is_unfiltered, ttl_option) = port_ack_scan(ip, port, source_ip).await;
                
                PortScanSingleResult {
                    ip_address: IpAddr::V4(ip),
                    port,
                    protocol: Protocols::TCP,
                    port_state: if is_unfiltered { PortStates::Unfiltered } else { PortStates::Filtered },
                    ttl: ttl_option.unwrap_or(0),
                    reason: if is_unfiltered { PortStateReasons::Unfiltered } else { PortStateReasons::Timeout },
                    service: get_service_name(&protocols_clone, "tcp", port),
                }
            });
        }
    }

    let mut single_results: Vec<PortScanSingleResult> = Vec::new();
    while let Some(result) = futs.next().await {
        single_results.push(result);
    }
    
    let all_results = PortScanAllResult {
        ports_scanned: ports.len() as u16,
        packets_sent: (ips.len() * ports.len()) as u32,
        //An ACK scan finds UNFILTERED ports, so this list is left empty.
        open_ports: Vec::new(),
        start_time,
        end_time: SystemTime::now(),
    };

    Ok((single_results, all_results))
}