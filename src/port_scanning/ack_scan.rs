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
/// Returns a tuple: `(is_unfiltered, optional_ttl)`.
pub async fn port_ack_scan(ip_address: Ipv4Addr, port: u16, local_ip: Ipv4Addr) -> (bool, Option<u8>) {
    let target_ip = IpAddr::V4(ip_address);

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
            match iter.next() {
                Ok((packet, addr)) => {
                    
                    if packet.get_destination() == source_port && addr == target_ip {
                        if packet.get_flags() & TcpFlags::RST != 0 {
                            
                            return (true, Some(0));
                        }
                    }
                }
                Err(_) => {
                    // Ignore errors and keep trying until the timeout
                }
            }
        }

        (false, None)
    });

    match timeout(Duration::from_millis(900), send_and_recv).await {
        Ok(Ok(result)) => result,
        _ => (false, None),
    }
}

/// Runs a concurrent ACK scan across all given IPs and ports.
pub async fn run_ack_scan(
    ip_addresses: Result<Vec<Ipv4Addr>, String>,
    ports: &[u16],
    local_ip: Ipv4Addr,
) -> Result<(Vec<PortScanSingleResult>, PortScanAllResult), String> {
    let ips = match ip_addresses {
        Ok(ips) => ips,
        Err(e) => return Err(format!("Failed to get IP addresses: {}", e)),
    };

    let protocols = Arc::new(load_protocol_map("src/resolving/port_service_mapping.json")
        .map_err(|e| format!("Failed to load service names: {}", e))?);


    let start_time = SystemTime::now();
    let semaphore = Arc::new(Semaphore::new(200));
    let mut futs = FuturesUnordered::new();



    for &ip in &ips {
        for &port in ports {
            let sem_clone = semaphore.clone();
            let protocols_clone = Arc::clone(&protocols);


            let source_ip = if ip.is_loopback() {
                Ipv4Addr::new(127, 0, 0, 1)
            } else {
                local_ip
            };
   
            futs.push(async move {
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
        open_ports: Vec::new(),
        start_time,
        end_time: SystemTime::now(),
    };

    Ok((single_results, all_results))
}