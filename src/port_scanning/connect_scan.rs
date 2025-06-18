use tokio::net::TcpStream;
use tokio::time::timeout;
use std::time::{Duration, SystemTime};

use std::net::SocketAddr;
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
    


// Function to automatically create the struct
    let make_result = |state, reason| PortScanSingleResult {
        ip_address,
        port,
        protocol: Protocols::TCP,
        port_state: state,
        ttl: 0, // TTL only meaningful for raw scans like SYN or ACK (here, the OS handles the packets -> no ttl insight)
        reason,
        service: get_service_name(protocols, "tcp", port),
    };

    let socket_addr = SocketAddr::new(ip_address, port);

    // Optimized to remove redundancy (using the function above)
    match timeout(timeout_duration, TcpStream::connect(socket_addr)).await {
        Ok(Ok(_)) => Ok(make_result(PortStates::Open, PortStateReasons::SynAck)),
        Ok(Err(e)) => match e.kind() {
            ErrorKind::ConnectionRefused => Ok(make_result(PortStates::Closed, PortStateReasons::Reset)),
            _ => Err(format!("Error connecting to {}:{}: {:?}", ip_address, port, e.kind())),
        },
        Err(_) => Ok(make_result(PortStates::Filtered, PortStateReasons::Timeout)), // timeout
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

    // let protocols = Arc::new(load_protocol_map("src/resolving/port_service_mapping.json").expect("Failed to load service names"));
    let protocols = Arc::new(load_protocol_map("src/resolving/port_service_mapping.json")
        .map_err(|e| format!("Failed to load service names: {}", e))?);
    
    let start_time = SystemTime::now();
    let mut tasks = Vec::new();
    let single_results = Arc::new(Mutex::new(Vec::<PortScanSingleResult>::new()));
    let open_ports = Arc::new(Mutex::new(Vec::<u16>::new()));
    let packets_sent = Arc::new(Mutex::new(0u32));

    // Avoid overwhelming the network --> limit concurrent scans
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
            let protocols_clone = Arc::clone(&protocols);
            
            // Spawn a task for each scan
            let task = tokio::spawn(async move {
                // Acquire a permit from the semaphore before scanning
                let _permit = match sem_clone.acquire().await {
                    Ok(permit) => permit,
                    Err(e) => {
                        eprintln!("Semaphore acquire error: {}", e);
                        return; // exit this task
                    }
                };
                
                // Increment packets sent counter (Cause every check sends a SYN packet)
                {
                    let mut counter = match packets_sent_clone.lock() {
                        Ok(guard) => guard,
                        Err(poisoned) => {
                            eprintln!("Mutex poisoned: packets_sent");
                            poisoned.into_inner()
                        }
                    };
                    *counter += 1;
                }
                
                match port_tcp_connect_scan(ip_addr, port, timeout, &protocols_clone).await {
                    Ok(result) => {
                        let mut results = match single_results_clone.lock() {
                            Ok(guard) => guard,
                            Err(poisoned) => {
                                eprintln!("Mutex poisoned: single_results");
                                poisoned.into_inner()
                            }
                        };
                        
                        // If port is open, add it to the open ports list
                        if result.port_state == PortStates::Open {
                            //println!("Found open port: {}:{}", ip_addr, port);
                            let mut open = match open_ports_clone.lock() {
                                Ok(guard) => guard,
                                Err(poisoned) => {
                                    eprintln!("Mutex poisoned: open_ports");
                                    poisoned.into_inner()
                                }
                            };
                            open.push(port);
                            {
                                // Increment packets sent counter by 2 (cause of ACK and RST)
                                let mut counter = match packets_sent_clone.lock() {
                                    Ok(guard) => guard,
                                    Err(poisoned) => {
                                        eprintln!("Mutex poisoned: packets_sent");
                                        poisoned.into_inner()
                                    }
                                };
                                *counter += 2;
                            }
                        }
                        results.push(result);

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
        .map_err(|_| "References still exist to single_results")?
        .into_inner()
        .map_err(|_| "Mutex is poisoned: single_results")?;
        
    let open_ports = Arc::try_unwrap(open_ports)
        .map_err(|_| "References still exist to open_ports")?
        .into_inner()
        .map_err(|_| "Mutex is poisoned: open_ports")?;

    let packets_sent = Arc::try_unwrap(packets_sent)
        .map_err(|_| "References still exist to packets_sent")?
        .into_inner()
        .map_err(|_| "Mutex is poisoned: packets_sent")?;
    
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
