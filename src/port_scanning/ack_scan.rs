use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use futures::stream::{FuturesUnordered, StreamExt};
use pnet::packet::ipv4::{MutableIpv4Packet};
use pnet::packet::tcp::{MutableTcpPacket, TcpFlags, TcpPacket};
use pnet::packet::Packet;
use pnet::transport::{transport_channel, TransportChannelType};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::tcp;
use tokio::sync::Semaphore;
use tokio::time::timeout;
use tokio::task;

use crate::models::{PortScanSingleResult, PortScanAllResult, PortStates, Protocols, PortStateReasons};


/// Sends a single TCP ACK packet and returns its status and the reply TTL.
///
/// Returns a tuple: `(is_unfiltered, optional_ttl)`.
/// `is_unfiltered` is true if an RST is received.
/// `optional_ttl` contains the TTL from the RST packet's IP header.
/// Sends a single TCP ACK packet and returns its status and the reply TTL.
pub async fn port_ack_scan(ip_address: Ipv4Addr, port: u16, local_ip: Ipv4Addr) -> (bool, Option<u8>) {
    let send_and_recv = task::spawn_blocking(move || {
        let (mut tx, mut rx) = match transport_channel(4096, TransportChannelType::Layer3(IpNextHeaderProtocols::Tcp)) {
            Ok(ch) => ch,
            Err(_) => return (false, None),
        };

        const IP_HDR_LEN: usize = 20;
        const TCP_HDR_LEN: usize = 20;
        let mut packet_buf = [0u8; IP_HDR_LEN + TCP_HDR_LEN];

        let (ip_slice, tcp_slice) = packet_buf.split_at_mut(IP_HDR_LEN);

        // Build the IPv4 header from its dedicated slice.
        let mut ip_header = MutableIpv4Packet::new(ip_slice).unwrap();
        ip_header.set_version(4);
        ip_header.set_header_length(5);
        ip_header.set_total_length((IP_HDR_LEN + TCP_HDR_LEN) as u16);
        ip_header.set_ttl(64);
        ip_header.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
        ip_header.set_source(local_ip);
        ip_header.set_destination(ip_address);
        
        let ip_checksum = pnet::packet::ipv4::checksum(&ip_header.to_immutable());
        ip_header.set_checksum(ip_checksum);

        // Build the TCP header from its dedicated slice.
        let mut tcp_header = MutableTcpPacket::new(tcp_slice).unwrap();
        let src_port = 16384 + (rand::random::<u16>() % 49151);
        tcp_header.set_source(src_port);
        tcp_header.set_destination(port);
        tcp_header.set_sequence(0);
        tcp_header.set_data_offset(5);
        tcp_header.set_flags(TcpFlags::ACK);
        tcp_header.set_window(64240);
        
        let tcp_checksum = tcp::ipv4_checksum(&tcp_header.to_immutable(), &local_ip, &ip_address);
        tcp_header.set_checksum(tcp_checksum);
        
        if tx.send_to(ip_header, IpAddr::V4(ip_address)).is_err() {
            return (false, None);
        }

        let mut iter = pnet::transport::ipv4_packet_iter(&mut rx);
        let timeout_duration = Duration::from_millis(800);

        if let Ok(Some((packet, addr))) = iter.next_with_timeout(timeout_duration) {
            if addr == ip_address {
                let ip_header_len = packet.get_header_length() as usize * 4;
                if let Some(tcp_packet) = TcpPacket::new(&packet.payload()[ip_header_len..]) {
                    if tcp_packet.get_flags() & TcpFlags::RST != 0 {
                        let ttl = Some(packet.get_ttl());
                        return (true, ttl);
                    }
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
) -> (Vec<PortScanSingleResult>, PortScanAllResult) {
    let ips = match ip_addresses {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Failed to parse IP list: {}", e);
            // Return empty, valid results
            return (Vec::new(), PortScanAllResult::new());
        }
    };

    let start_time = SystemTime::now();
    let semaphore = Arc::new(Semaphore::new(200));
    let mut futs = FuturesUnordered::new();

    for &ip in &ips {
        for &port in ports {
            let sem_clone = semaphore.clone();
            futs.push(async move {
                let _permit = sem_clone.acquire().await.unwrap();
                let (is_unfiltered, ttl_option) = port_ack_scan(ip, port, local_ip).await;
                
                // Construct a PortScanSingleResult for every port scanned using your struct definition.
                PortScanSingleResult {
                    ip_address: IpAddr::V4(ip),
                    port,
                    protocol: Protocols::TCP,
                    // Map the boolean result to the correct PortStates enum variant.
                    port_state: if is_unfiltered { PortStates::Unfiltered } else { PortStates::Filtered },
                    // Use unwrap_or to provide a default TTL if none was received.
                    ttl: ttl_option.unwrap_or(0),
                    // Map the result to the correct reason using your new enum variant.
                    reason: if is_unfiltered { PortStateReasons::Unfiltered } else { PortStateReasons::Timeout },
                    // ACK scan cannot determine the service.
                    service: "unknown".to_string(),
                }
            });
        }
    }

    // Collect all results into a single vector.
    let mut single_results: Vec<PortScanSingleResult> = Vec::new();
    while let Some(result) = futs.next().await {
        single_results.push(result);
    }
    
    // Construct the summary result.
    let all_results = PortScanAllResult {
        ports_scanned: ports.len() as u16,
        packets_sent: (ips.len() * ports.len()) as u32,
        // The `open_ports` field is for OPEN ports. ACK scan finds UNFILTERED ports.
        // For now, we leave this empty to be semantically correct.
        open_ports: Vec::new(),
        start_time,
        end_time: SystemTime::now(),
    };

    (single_results, all_results)
}