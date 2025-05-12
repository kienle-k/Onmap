use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};

use futures::stream::{FuturesUnordered, StreamExt};

use std::net::ToSocketAddrs;
use std::time::Instant;
use std::io::ErrorKind;

use chrono::prelude::*;
use chrono_tz::Tz;
use iana_time_zone::get_timezone;

use crate::utils::json_loader::{load_protocols, get_port_info};


// Tokio-native scan_port-Funktion
async fn scan_port(ip: &str, port: u16, timeout_duration: Duration) -> (u16, String) {
    let addr = format!("{}:{}", ip, port);

    // Hostname -> SocketAddr auflösen
    let socket_addr = match addr.to_socket_addrs() {
        Ok(mut addrs) => match addrs.next() {
            Some(sa) => sa,
            None => return (port, "filtered".to_string()),
        },
        Err(_) => return (port, "filtered".to_string()),
    };

    // Tokio async TCP connect mit timeout
    match timeout(timeout_duration, TcpStream::connect(socket_addr)).await {
        Ok(Ok(_)) => (port, "open".to_string()),
        Ok(Err(e)) => match e.kind() {
            ErrorKind::ConnectionRefused => (port, "closed".to_string()),
            _ => (port, format!("error: {:?}", e.kind())),
        },
        Err(_) => (port, "filtered".to_string()), // Timeout ausgelöst
    }
}


// Hauptfunktion zum Ausführen des Connect-Scans
pub async fn run_connect_scan(ip: &str, ports: Vec<u16>, timeout_ms: u64) {
    let tz_str = get_timezone().expect("Failed to get system timezone");
    let tz: Tz = tz_str.parse().expect("Invalid timezone string");

    let now = Utc::now().with_timezone(&tz);
    let formatted_time = now.format("%Y-%m-%d %H:%M %Z").to_string();

    println!("Starting Onmap 1.0 (https://oxy-nmap.com) at {}", formatted_time);
    println!("Nmap scan report for {}\n", ip);

    let protocols = match load_protocols("src/utils/port_service_mapping.json") {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Error loading protocols: {}", e);
            return;
        }
    };

    let timeout = Duration::from_millis(timeout_ms);
    let mut tasks = FuturesUnordered::new();

    let start_time = Instant::now();

    for port in ports {
        tasks.push(scan_port(ip, port, timeout));
    }

    let mut closed_port_num = 0;
    let mut open_ports = vec![];

    while let Some((port, status)) = tasks.next().await {
        match status.as_str() {
            "open" | "filtered" => {
                let service_name = if let Some(info) = get_port_info(&protocols, "tcp", &port.to_string()) {
                    info.service.clone()
                } else {
                    "unknown".to_string()
                };
                open_ports.push((port, service_name));
            },
            _ => {
                closed_port_num += 1;
            }
        }
    }

    if closed_port_num > 0 {
        println!("Not shown: {} closed ports", closed_port_num);
    }

    // Sort Ports ASC
    open_ports.sort_by_key(|(port, _)| *port);

    println!("\n{:<7}      STATE    SERVICE", "PORT");

    for (port, service_name) in open_ports {
        println!("{:<7}/tcp  open     {}", port, service_name);
    }

    let elapsed_time = start_time.elapsed();

    println!(
        "\nNmap done: 1 IP address (1 host up) scanned in {:.2} seconds",
        elapsed_time.as_secs_f32()
    );
}
