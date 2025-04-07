use async_std::task;
use futures::stream::{FuturesUnordered, StreamExt};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;



// Use PNET for scans, not TCP-Stream


async fn scan_port(ip: &str, port: u16, timeout: Duration) -> (u16, String) {
    let addr = format!("{}:{}", ip, port);
    if let Ok(mut addrs) = addr.to_socket_addrs() {
        if let Some(socket_addr) = addrs.next() {
            match task::spawn_blocking(move || TcpStream::connect_timeout(&socket_addr, timeout)).await {
                Ok(_) => {
                    // If we successfully connect, the port is open.
                    return (port, String::from("open"));
                }
                Err(_) => {
                    // If we can't connect, check if it's a timeout (filtered) or closed
                    return (port, String::from("closed"));
                }
            }
        }
    }

    // Return filtered status if no connection is possible
    (port, String::from("filtered"))
}

pub async fn run_connect_scan(ip: &str, ports: Vec<u16>, _timeout: u64) {
    let timeout = Duration::from_millis(_timeout);
    let mut tasks = FuturesUnordered::new();

    // Start all port scan tasks in parallel
    for port in ports {
        tasks.push(scan_port(ip, port, timeout));
    }

    // Process all results and print the output like nmap
    while let Some((port, status)) = tasks.next().await {
        match status.as_str() {
            "open" => println!("{:<6}/tcp  open", port),
            "closed" => println!("{:<6}/tcp  closed", port),
            "filtered" => println!("{:<6}/tcp  filtered", port),
            _ => {}
        }
    }
}

