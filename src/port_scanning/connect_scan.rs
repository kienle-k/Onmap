use tokio::net::TcpStream;
use tokio::time::timeout;
use std::time::{Duration, SystemTime};

use std::net::ToSocketAddrs;
use std::io::ErrorKind;

use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};
use std::result::Result;

use crate::resolving::get_service_name::{ProtocolMap, load_protocol_map, get_service_name};
use crate::models::{Protocols, PortStates, PortStateReasons, PortScanSingleResult, PortScanAllResult};



pub async fn port_tcp_connect_scan(
    ip_address: IpAddr, 
    port: u16, 
    timeout_duration: Duration,
    protocols: &ProtocolMap
) -> Result<PortScanSingleResult, String> {
    let addr = format!("{}:{}", ip_address, port);

    // Hostname -> SocketAddr auflösen
    let socket_addr = match addr.to_socket_addrs() {
        Ok(mut addrs) => match addrs.next() {
            Some(sa) => sa,
            None => return Ok(PortScanSingleResult {
                ip_address,
                port,
                protocol: Protocols::TCP,
                port_state: PortStates::Filtered,
                ttl: 63,
                reason: PortStateReasons::SynAck,
                service: get_service_name(protocols, "tcp", port),
            }),
        },
        Err(_) => return Ok(PortScanSingleResult {
            ip_address,
            port,
            protocol: Protocols::TCP,
            port_state: PortStates::Filtered,
            ttl: 63,
            reason: PortStateReasons::SynAck,
            service: get_service_name(protocols, "tcp", port),
        }),
    };

    // Tokio async TCP connect mit timeout
    match timeout(timeout_duration, TcpStream::connect(socket_addr)).await {
        Ok(Ok(_)) => Ok(PortScanSingleResult {
            ip_address,
            port,
            protocol: Protocols::TCP,
            port_state: PortStates::Open,
            ttl: 63,
            reason: PortStateReasons::SynAck,
            service: get_service_name(protocols, "tcp", port),
        }),
        Ok(Err(e)) => match e.kind() {
            ErrorKind::ConnectionRefused => Ok(PortScanSingleResult {
                ip_address,
                port,
                protocol: Protocols::TCP,
                port_state: PortStates::Closed,
                ttl: 63,
                reason: PortStateReasons::SynAck,
                service: get_service_name(protocols, "tcp", port),
            }),
            _ => Err(format!("Error connecting to {}:{}: {:?}", ip_address, port, e.kind())),
        },
        Err(_) => Ok(PortScanSingleResult {
            ip_address,
            port,
            protocol: Protocols::TCP,
            port_state: PortStates::Filtered,
            ttl: 63,
            reason: PortStateReasons::SynAck,
            service: get_service_name(protocols, "tcp", port),
        }), // Timeout ausgelöst
    }
}


// Hauptfunktion zum Ausführen des Connect-Scans
pub async fn run_connect_scan(
    ip_address_arr: Result<Vec<Ipv4Addr>, String>, 
    ports_arr: Vec<u16>,
    timeout_ms: u64
) -> Result<(Vec<PortScanSingleResult>, PortScanAllResult), String> {

    let timeout = Duration::from_millis(timeout_ms);

    let ip_addresses = match ip_address_arr {
        Ok(ips) => ips,
        Err(e) => return Err(format!("Failed to get IP addresses: {}", e)),
    };

    let protocols = Arc::new(load_protocol_map("src/resolving/port_service_mapping.json").expect("Failed to load service names"));

    //println!("Starting scan of {} IPs across {} ports", ip_addresses.len(), ports_arr.len());
    
    let start_time = SystemTime::now();
    let mut tasks = Vec::new();
    let single_results = Arc::new(Mutex::new(Vec::<PortScanSingleResult>::new()));
    let open_ports = Arc::new(Mutex::new(Vec::<u16>::new()));
    let packets_sent = Arc::new(Mutex::new(0u32));

    // Avoid overwhelming the network --> limit concurrent scans
    let semaphore = Arc::new(tokio::sync::Semaphore::new(10));

    // Create a task for each IP/port combination
    for ip in ip_addresses {
        let ip_addr = IpAddr::V4(ip); // Convert Ipv4Addr to IpAddr
        for port in &ports_arr {
            let port = *port;
            let single_results_clone = Arc::clone(&single_results);
            let open_ports_clone = Arc::clone(&open_ports);
            let packets_sent_clone = Arc::clone(&packets_sent);
            let sem_clone = Arc::clone(&semaphore);
            let protocols_clone = Arc::clone(&protocols);
            
            // Spawn a task for each scan
            let task = tokio::spawn(async move {
                // Acquire a permit from the semaphore before scanning
                let _permit = sem_clone.acquire().await.unwrap();
                
                // Increment packets sent counter (Cause every check sends a SYN packet)
                {
                    let mut counter = packets_sent_clone.lock().unwrap();
                    *counter += 1;
                }
                
                match port_tcp_connect_scan(ip_addr, port, timeout, &protocols_clone).await {
                    Ok(result) => {
                        let mut results = single_results_clone.lock().unwrap();
                        results.push(result.clone());
                        
                        // If port is open, add it to the open ports list
                        if result.port_state == PortStates::Open {
                            //println!("Found open port: {}:{}", ip_addr, port);
                            let mut open = open_ports_clone.lock().unwrap();
                            open.push(port);
                            {
                                // Increment packets sent counter by 2 (cause of ACK and RST)
                                let mut counter = packets_sent_clone.lock().unwrap();
                                *counter += 2;
                            }
                        }
                    }
                    Err(_e) => {
                    }
                }
            });
            
            tasks.push(task);
        }
    }

    // Wait for scans to complete
    for task in tasks {
        let _ = task.await;
    }
    
    let end_time = SystemTime::now();
    
    // Final results
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
    
    // Return both result types
    Ok((single_results, all_result))
}
