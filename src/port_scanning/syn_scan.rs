use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::tcp::{MutableTcpPacket, TcpFlags};
use pnet::transport::{transport_channel, TransportChannelType, TransportProtocol};
use rand::Rng;
use pnet::transport::tcp_packet_iter;
use std::result::Result;

use crate::models::{Protocols, PortStates, PortStateReasons, PortScanSingleResult, PortScanAllResult};
use crate::resolving::get_service_name;

// Function to scan a single port on a single IP address
pub async fn port_syn_scan(ip_address: IpAddr, port: u16, local_ip_address: Ipv4Addr) -> Result<PortScanSingleResult, String> {
    //println!("Scanning {}:{}", ip_address, port);
    
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
    let source_port = rand::thread_rng().gen_range(49152..65535);
    //println!("Using source port: {}", source_port);
    
    // Create a SYN packet
    let mut tcp_buffer = [0u8; 66]; // TCP header size + options
    let mut tcp_packet = MutableTcpPacket::new(&mut tcp_buffer).unwrap();
    
    // Configure TCP header
    tcp_packet.set_source(source_port);
    tcp_packet.set_destination(port);
    tcp_packet.set_sequence(rand::thread_rng().r#gen::<u32>());
    tcp_packet.set_acknowledgement(0);
    tcp_packet.set_data_offset(5); // Standard header length
    tcp_packet.set_flags(TcpFlags::SYN);
    tcp_packet.set_window(64240);
    tcp_packet.set_urgent_ptr(0);
    
    
    // Calculate checksum with the proper source IP
    let checksum = pnet::packet::tcp::ipv4_checksum(
        &tcp_packet.to_immutable(),
        &local_ip_address,
        &ipv4,
    );
    
    tcp_packet.set_checksum(checksum);
    //println!("Packet checksum: {}", checksum);

    // Send the packet
    match tx.send_to(tcp_packet, ip_address) {
        Ok(_) => {} //println!("Packet sent successfully"),
        Err(e) => return Err(format!("Failed to send packet: {}", e)),
    };

    // Wait for response with timeout
    let response_future = async {

        loop {
            match iter.next() {

                Ok((packet, addr)) => {
                    if packet.get_destination() == source_port && addr == ip_address && packet.get_source() == port {
                        let flags = packet.get_flags();
                        if (flags & TcpFlags::SYN != 0) && (flags & TcpFlags::ACK != 0) {
                            let ttl = 63; // Placeholder
                            return Ok(PortScanSingleResult {
                                ip_address, port, protocol: Protocols::TCP,
                                port_state: PortStates::Open, ttl,
                                reason: PortStateReasons::SynAck, service: get_service_name(port),
                            });
                        }
                        if flags & TcpFlags::RST != 0 {
                            let ttl = 63; // Placeholder
                            return Ok(PortScanSingleResult {
                                ip_address, port, protocol: Protocols::TCP,
                                port_state: PortStates::Closed, ttl,
                                reason: PortStateReasons::Reset, service: get_service_name(port),
                            });
                        }
                    }
                }
                Err(_e) => { // I/O error from iter.next()
                    // eprintln!("Error receiving packet for {}:{}: {}", ip_address, port, e);
                    // Short delay before retrying to prevent fast spinning on persistent errors
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            }
            
            tokio::task::yield_now().await;
        }
    };

    // Wait for response with a single overall timeout
    match tokio::time::timeout(Duration::from_millis(800), response_future).await {
        Ok(Ok(result)) => Ok(result), // Double Ok: timeout succeeded, response_future succeeded
        Ok(Err(e)) => Err(e), // Error from within response_future's logic (if it could return its own errors)
        Err(_) => { // This is the timeout from tokio::time::timeout
            //println!("Timeout occurred while waiting for response for {}:{}", ip_address, port);
            Ok(PortScanSingleResult {
                ip_address,
                port,
                protocol: Protocols::TCP,
                port_state: PortStates::Filtered,
                ttl: 0,
                reason: PortStateReasons::Timeout,
                service: get_service_name(port),
            })
        }
    }
}



// Function to run SYN scan on multiple IP addresses and ports
pub async fn run_syn_scan(
    ip_address_arr: Result<Vec<Ipv4Addr>, String>, 
    ports_arr: Vec<u16>,
    local_ip_address: Ipv4Addr
) -> Result<(Vec<PortScanSingleResult>, PortScanAllResult), String> {
    // First, handle the Result to extract the IP addresses or propagate the error
    let ip_addresses = match ip_address_arr {
        Ok(ips) => ips,
        Err(e) => return Err(format!("Failed to get IP addresses: {}", e)),
    };

    //println!("Starting scan of {} IPs across {} ports", ip_addresses.len(), ports_arr.len());
    
    let start_time = SystemTime::now();
    let mut tasks = Vec::new();
    let single_results = Arc::new(Mutex::new(Vec::<PortScanSingleResult>::new()));
    let open_ports = Arc::new(Mutex::new(Vec::<u16>::new()));
    let packets_sent = Arc::new(Mutex::new(0u32));

    // Limit concurrent scans to avoid overwhelming the network
    let semaphore = Arc::new(tokio::sync::Semaphore::new(100));

    // Create a task for each IP/port combination
    for ip in ip_addresses {
        let ip_addr = IpAddr::V4(ip); // Convert Ipv4Addr to IpAddr
        for port in &ports_arr {
            let port = *port;
            let single_results_clone = Arc::clone(&single_results);
            let open_ports_clone = Arc::clone(&open_ports);
            let packets_sent_clone = Arc::clone(&packets_sent);
            let sem_clone = Arc::clone(&semaphore);
            
            // Spawn a task for each scan
            let task = tokio::spawn(async move {
                // Acquire a permit from the semaphore before scanning
                let _permit = sem_clone.acquire().await.unwrap();
                
                // Increment packets sent counter
                {
                    let mut counter = packets_sent_clone.lock().unwrap();
                    *counter += 1;
                }
                
                match port_syn_scan(ip_addr, port, local_ip_address).await {
                    Ok(result) => {
                        let mut results = single_results_clone.lock().unwrap();
                        results.push(result.clone());
                        
                        // If port is open, add it to the open ports list
                        if result.port_state == PortStates::Open {
                            //println!("Found open port: {}:{}", ip_addr, port);
                            let mut open = open_ports_clone.lock().unwrap();
                            open.push(port);
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

    //println!("Waiting for all scan tasks to complete...");
    // Wait for all scans to complete
    for task in tasks {
        let _ = task.await;
    }
    
    let end_time = SystemTime::now();
    
    // Prepare the final results
    let single_results = Arc::try_unwrap(single_results)
        .expect("References still exist to single_results")
        .into_inner()
        .expect("Mutex is poisoned");
        
    let open_ports = Arc::try_unwrap(open_ports)
        .expect("References still exist to open_ports")
        .into_inner()
        .expect("Mutex is poisoned");
        
    let packets_sent = Arc::try_unwrap(packets_sent)
        .expect("References still exist to packets_sent")
        .into_inner()
        .expect("Mutex is poisoned");
    
    // Create the PortScanAllResult
    let all_result = PortScanAllResult {
        ports_scanned: ports_arr.len() as u16,
        packets_sent,
        open_ports,
        start_time,
        end_time,
    };
    
    //println!("Scan completed. Found {} results with {} open ports", 
             //single_results.len(), all_result.open_ports.len());
    
    // Return both result types
    Ok((single_results, all_result))
}