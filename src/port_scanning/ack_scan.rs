use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use futures::stream::{FuturesUnordered, StreamExt};
use pnet::packet::ipv4::MutableIpv4Packet;
use pnet::packet::tcp::{MutableTcpPacket, TcpFlags, TcpPacket};
use pnet::packet::Packet;
use pnet::transport::{tcp_packet_iter, transport_channel, TransportChannelType};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::tcp;
use tokio::sync::Semaphore;
use tokio::time::timeout;
use tokio::task;

/// Send a single ACK scan to `ip_address:port`, binding the IP headers to `local_ip`.
/// Returns `true` if the port is unfiltered (RST received), `false` otherwise.
pub async fn port_ack_scan(ip_address: IpAddr, port: u16, local_ip: Ipv4Addr) -> bool {
    let target_ip = if let IpAddr::V4(v4) = ip_address { v4 } else { return false };

    // Run the raw‐socket work off the async reactor
    let send_and_recv = task::spawn_blocking(move || {
        // Create a Layer3 TCP channel
        let (mut tx, mut rx) = match transport_channel(
            4096,
            TransportChannelType::Layer3(IpNextHeaderProtocols::Tcp),
        ) {
            Ok(ch) => ch,
            Err(_)    => return false,
        };

        const IP_HDR_LEN: usize  = 20;
        const TCP_HDR_LEN: usize = 20;
        let mut buf = [0u8; IP_HDR_LEN + TCP_HDR_LEN];

        // Build the IPv4 header in place
        let mut ip_hdr = MutableIpv4Packet::new(&mut buf[..IP_HDR_LEN]).unwrap();
        ip_hdr.set_version(4);
        ip_hdr.set_header_length(5);
        ip_hdr.set_total_length((IP_HDR_LEN + TCP_HDR_LEN) as u16);
        ip_hdr.set_ttl(64);
        ip_hdr.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
        ip_hdr.set_source(local_ip);
        ip_hdr.set_destination(target_ip);
        // Optionally compute IP checksum here if your OS doesn't auto‐fill it.

        // Build the TCP header immediately after the IP header
        let mut tcp_hdr = MutableTcpPacket::new(&mut buf[IP_HDR_LEN..]).unwrap();
        // pick some source port
        let src_port = 10_000 + (rand::random::<u16>() % 50);
        tcp_hdr.set_source(src_port);
        tcp_hdr.set_destination(port);
        tcp_hdr.set_sequence(0);
        tcp_hdr.set_data_offset(5);
        tcp_hdr.set_flags(TcpFlags::ACK);
        tcp_hdr.set_window(64240);

        // Compute the TCP checksum (includes pseudo‐header)
        let checksum = tcp::ipv4_checksum(&tcp_hdr.to_immutable(), &local_ip, &target_ip);
        tcp_hdr.set_checksum(checksum);

        // Send the entire packet buffer
        if let Some(packet) = pnet::packet::ipv4::Ipv4Packet::new(&buf) {
            if tx.send_to(packet, IpAddr::V4(target_ip)).is_err() {
                return false;
            }
        } else {
            return false;
        }

        // Listen for up to 800 ms for a RST from the target
        let start = Instant::now();
        let mut iter  = tcp_packet_iter(&mut rx);
        while start.elapsed() < Duration::from_millis(800) {
            if let Ok((packet, addr)) = iter.next() {
                if addr == IpAddr::V4(target_ip) {
                    // parse the TCP portion using immutable parser
                    if let Some(resp) = TcpPacket::new(&packet.packet()[IP_HDR_LEN..]) {
                        if resp.get_flags() & TcpFlags::RST != 0 {
                            return true; // unfiltered
                        }
                    }
                }
            }
        }
        false  // no RST => filtered
    });

    // Hard timeout so the blocking task never hangs forever
    match timeout(Duration::from_millis(900), send_and_recv).await {
        Ok(Ok(r)) => r,
        _         => false,
    }
}

/// Runs an ACK scan across all given IPs and ports, then prints per-host summaries.
pub async fn run_ack_scan(
    ip_addresses: Result<Vec<Ipv4Addr>, String>,
    ports: &[u16],
    local_ip: Ipv4Addr,
) {
    let ips = match ip_addresses {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Failed to parse IP list: {}", e);
            return;
        }
    };

    let start_time = SystemTime::now();
    let semaphore = Arc::new(Semaphore::new(100));

    for ip in ips {
        let mut futs = FuturesUnordered::new();
        for &port in ports {
            let sem = semaphore.clone();
            let addr = IpAddr::V4(ip);
            let lip = local_ip;
            futs.push(async move {
                // rate‑limit concurrency
                let _permit = sem.acquire().await.unwrap();
                let ok = port_ack_scan(addr, port, lip).await;
                (port, ok)
            });
        }

        // Collect results
        let mut unfiltered_ports = Vec::new();
        let mut filtered_count = 0u32;
        while let Some((port, unfiltered)) = futs.next().await {
            if unfiltered {
                unfiltered_ports.push(port);
            } else {
                filtered_count += 1;
            }
        }

        let unfiltered_count = unfiltered_ports.len() as u32;
        let is_up = unfiltered_count > 0;

        // Print summary for this host
        println!("Host: {}", ip);
        println!("  Status          : {}", if is_up { "UP" } else { "DOWN" });
        println!("  Filtered Ports  : {}", filtered_count);
        println!("  Unfiltered Ports: {}{}", 
            unfiltered_count,
            if unfiltered_count > 0 {
                format!(": {:?}", unfiltered_ports)
            } else {
                "".to_string()
            }
        );
        println!();
    }

    let end_time = SystemTime::now();
    let elapsed = end_time.duration_since(start_time)
        .map(|d| format!("{:.2?}", d))
        .unwrap_or_else(|_| "unknown".into());
    println!("ACK scan complete in {}", elapsed);
}
