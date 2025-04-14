use async_std::task;
use futures::stream::{FuturesUnordered, StreamExt};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};
use chrono::Local;
use std::process::Command;

use crate::utils::json_loader::{load_protocols, get_port_info}; // Verweise auf utils korrekt



async fn ping_host(ip: &str) -> Result<(bool, f64), Box<dyn std::error::Error>> {
    let ip = ip.to_string();

    let output_result = task::spawn_blocking(move || {
        Command::new("ping")
        .args(&["-c", "1", "-W", "1", "-q", &ip])
        .output()
    }).await;

    match output_result {
        Ok(output) => {
            if output.status.success() {
                // You could parse actual latency from output.stdout here if needed
                Ok((true, 1.0))
            } else {
                Ok((false, 0.0))
            }
        }
        Err(e) => Err(Box::new(e)),
    }
}



// Async function to scan a single port
async fn scan_port(ip: &str, port: u16, timeout: Duration) -> (u16, String) {
    let addr = format!("{}:{}", ip, port);
    if let Ok(mut addrs) = addr.to_socket_addrs() {
        if let Some(socket_addr) = addrs.next() {
            match task::spawn_blocking(move || TcpStream::connect_timeout(&socket_addr, timeout)).await {
                Ok(_) => return (port, String::from("open")),
                Err(_e) => return (port, String::from("closed")),
            }
        }
    }
    (port, String::from("filtered"))
}

// Main function to run the connect scan
pub async fn run_connect_scan(ip: &str, ports: Vec<u16>, timeout_ms: u64) {


    let now = Local::now();
    let formatted_time = now.format("%Y-%m-%d %H:%M %Z");

    println!("Starting Onmap 1.0 (https://oxy-nmap.com) at {}", formatted_time);


    println!("Nmap scan report for {}\n", ip);

    // Record the start time
    let start_time = Instant::now();
    let mut host_num: i32 = 0;
    match ping_host(ip).await {
        Ok((is_up, latency)) => {
            if is_up {
                host_num = 1;
                println!("Host is up ({} s latency)", latency / 1000.0);
            } else {
                println!("Host is down.");
                return;
            }
        },
        Err(e) => println!("Error: {}", e),
    }


    // Load protocols from JSON
    let protocols = match load_protocols("src/utils/port_service_mapping.json") {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Error loading protocols: {}", e);
            return;
        }
    };

    let timeout = Duration::from_millis(timeout_ms);
    let mut tasks = FuturesUnordered::new();


    // Add tasks for all ports
    for port in ports {
        tasks.push(scan_port(ip, port, timeout));
    }

    let mut closed_port_num = 0;
    let mut open_ports = vec![];

    // Process scan results
    while let Some((port, status)) = tasks.next().await {
        match status.as_str() {
            "open" => {
                let service_name = if let Some(info) = get_port_info(&protocols, "tcp", &port.to_string()) {
                    info.service.clone()
                } else {
                    String::from("unknown")
                };
                open_ports.push((port, service_name));
            },
            _ => {
                closed_port_num += 1;
            }
        }
    }

    // Display closed ports info first
    if closed_port_num > 0 {
        println!("Not shown: {} closed ports", closed_port_num);
    }

    println!("\n{:<7}      STATE    SERVICE", "PORT");


    // Now display open ports
    for (port, service_name) in open_ports {
        println!("{:<7}/tcp  open     {}", port, service_name);
    }

    // Calculate elapsed time
    let elapsed_time = start_time.elapsed();

    // Add "x hosts up" message
    println!(
        "\nNmap done: 1 IP address ({} hosts up) scanned in {:.2} seconds",
        host_num,
        elapsed_time.as_secs_f32()
    );
}

