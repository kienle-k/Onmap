use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::time::timeout;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::tcp::{MutableTcpPacket, TcpFlags};
use pnet::transport::{transport_channel, TransportChannelType, TransportProtocol};
use rand::Rng;
use pnet::transport::tcp_packet_iter;
use std::result::Result;

use crate::models::{PortScanResult, ScanResult};


// Function to run SYN scan on multiple IP addresses and ports
pub async fn run_syn_scan(ip_address_arr: Result<Vec<Ipv4Addr>, String>, ports_arr: Vec<u16>) -> Result<Vec<PortScanResult>, String> {
    // First, handle the Result to extract the IP addresses or propagate the error
    let ip_addresses = match ip_address_arr {
        Ok(ips) => ips,
        Err(e) => return Err(format!("Failed to get IP addresses: {}", e)),
    };

    let mut tasks = Vec::new();
    let results = Arc::new(Mutex::new(Vec::<(IpAddr, u16)>::new()));

    // Create a task for each IP/port combination
    for ip in ip_addresses {
        let ip_addr = IpAddr::V4(ip); // Convert Ipv4Addr to IpAddr
        for port in &ports_arr {
            let port = *port;
            let results_clone = Arc::clone(&results);
            
            // Spawn a task for each scan
            let task = tokio::spawn(async move {
                match port_syn_scan(ip_addr, port).await {
                    Ok(result) => {
                        if result.is_open {
                            let mut results = results_clone.lock().unwrap();
                            results.push((result.ip, port));
                        }
                    }
                    Err(e) => {
                        eprintln!("Error scanning {}:{}: {}", ip_addr, port, e);
                    }
                }
            });
            
            tasks.push(task);
        }
    }

    // Wait for all scans to complete
    for task in tasks {
        let _ = task.await;
    }

    // Get the raw results
    let raw_results = Arc::try_unwrap(results)
        .expect("References still exist to results")
        .into_inner()
        .expect("Mutex is poisoned");

    // Process the raw results into the final format
    // Group by IP address
    let mut ip_results = Vec::new();
    
    // Group open ports by IP
    for (ip, port) in raw_results {
        // Check if we already have this IP in our results
        let ip_result = ip_results.iter_mut().find(|r: &&mut PortScanResult| r.ip == ip);
        
        if let Some(existing) = ip_result {
            // Add the port to existing IP entry
            existing.open_ports.push(port);
        } else {
            // Create a new entry for this IP
            ip_results.push(PortScanResult {
                ip,
                open_ports: vec![port],
            });
        }
    }
    
    // Sort ports within each IP result
    for result in &mut ip_results {
        result.open_ports.sort_unstable();
    }

    Ok(ip_results)
}

// Function to scan a single port on a single IP address
pub async fn port_syn_scan(ip_address: IpAddr, port: u16) -> Result<ScanResult, String> {
    // Only IPv4 is supported for simplicity
    let ipv4 = match ip_address {
        IpAddr::V4(ipv4) => ipv4,
        IpAddr::V6(_) => return Err("IPv6 is not supported for SYN scanning".to_string()),
    };

    // Create a raw transport channel for sending and receiving TCP packets
    let protocol = TransportProtocol::Ipv4(IpNextHeaderProtocols::Tcp);
    let config = TransportChannelType::Layer4(protocol);
    
    let (mut tx, mut rx) = match transport_channel(4096, config) {
        Ok((tx, rx)) => (tx, rx),
        Err(e) => return Err(format!("Error creating transport channel: {}", e)),
    };
    
    // Create a packet iterator to receive packets
    let mut iter = tcp_packet_iter(&mut rx);

    // Generate a random source port
    let source_port = rand::thread_rng().r#gen_range(49152..65535);
    
    // Create a SYN packet
    let mut tcp_buffer = [0u8; 66]; // TCP header size + options
    let mut tcp_packet = MutableTcpPacket::new(&mut tcp_buffer).unwrap();
    
    // Configure TCP header
    tcp_packet.set_source(source_port);
    tcp_packet.set_destination(port);
    tcp_packet.set_sequence(rand::thread_rng().r#gen::<u32>());
    tcp_packet.set_acknowledgement(0);
    tcp_packet.set_data_offset(5); // Standard header length (5 × 32 bits = 20 bytes)
    tcp_packet.set_flags(TcpFlags::SYN);
    tcp_packet.set_window(64240);
    tcp_packet.set_urgent_ptr(0);
    
    // Simplified TCP options to avoid offset issues
    // No options for simplicity
    
    // Calculate checksum (need source and destination IPs for this)
    let checksum = pnet::packet::tcp::ipv4_checksum(
        &tcp_packet.to_immutable(),
        &Ipv4Addr::new(127, 0, 0, 1), // Source IP (doesn't matter for checksum calculation)
        &ipv4,
    );
    tcp_packet.set_checksum(checksum);

    // Send the packet
    match tx.send_to(tcp_packet, ip_address) {
        Ok(_) => (),
        Err(e) => return Err(format!("Failed to send packet: {}", e)),
    };

    // Wait for response with timeout
    let response_future = async {
        loop {
            match iter.next() {
                Ok((packet, addr)) => {
                    if addr == ip_address {
                        // Check if this is a response to our SYN packet
                        if packet.get_destination() == source_port && packet.get_source() == port {
                            // Check if SYN+ACK flags are set (port is open)
                            if (packet.get_flags() & TcpFlags::SYN) != 0 && (packet.get_flags() & TcpFlags::ACK) != 0 {
                                return Ok(ScanResult {
                                    ip: ip_address,
                                    port,
                                    is_open: true,
                                });
                            }
                            // RST+ACK means port is closed
                            else if (packet.get_flags() & TcpFlags::RST) != 0 {
                                return Ok(ScanResult {
                                    ip: ip_address,
                                    port,
                                    is_open: false,
                                });
                            }
                        }
                    }
                }
                Err(e) => return Err(format!("Error receiving packet: {}", e)),
            }
        }
    };

    // Wait for response with a timeout
    match timeout(Duration::from_millis(50), response_future).await {
        Ok(result) => result,
        Err(_) => Ok(ScanResult {
            ip: ip_address,
            port,
            is_open: false, // Assume filtered/closed on timeout
        }),
    }
}