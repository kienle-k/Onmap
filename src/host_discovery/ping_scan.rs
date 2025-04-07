use std::net::Ipv4Addr;
use std::process::Command;
use async_std::task;
use async_std::stream::StreamExt;
use futures::stream::FuturesUnordered;

/// Performs ICMP ping scans on the provided IP addresses asynchronously.
/// Prints the results with a summary of reachable addresses.
pub async fn run_ping_scan(ip_addresses: Result<Vec<Ipv4Addr>, String>, ports: Vec<u16>) {
    let ips = match ip_addresses {
        Ok(addresses) => addresses,
        Err(error) => {
            println!("Failed to process IP addresses: {}", error);
            return;
        }
    };
    
    println!("Starting ping scan of {} IP addresses", ips.len());
    if !ports.is_empty() {
        println!("Note: Ports specified but not used for ICMP ping scan: {:?}", ports);
    }
    
    let mut reachable_ips = Vec::new();
    let mut unreachable_count = 0;
    
    // Create a collection of futures
    let mut futures = FuturesUnordered::new();
    
    // Add ping tasks to our collection
    for ip in ips {
        futures.push(async move {
            let is_reachable = ping_host(&ip).await;
            (ip, is_reachable)
        });
    }
    
    // Process results as they complete
    while let Some((ip, is_reachable)) = futures.next().await {
        if is_reachable { 
            println!("{} - REACHABLE", ip);
            reachable_ips.push(ip);
        } else { 
            println!("{} - UNREACHABLE", ip);
            unreachable_count += 1;
        }
    }
    
    println!("\nPing scan completed.");
    println!("Total: {} reachable, {} unreachable", reachable_ips.len(), unreachable_count);
    
    if !reachable_ips.is_empty() {
        println!("\nReachable IP addresses:");
        for ip in &reachable_ips {
            println!("  {}", ip);
        }
    } else {
        println!("\nNo reachable IP addresses found.");
    }
    println!()
}

async fn ping_host(ip: &Ipv4Addr) -> bool {
    let ip_string = ip.to_string();
    
    // async-std's spawn_blocking returns a JoinHandle<T>, not Result<T, JoinError>
    let result = task::spawn_blocking(move || {
        let output = if cfg!(target_os = "windows") {
            Command::new("ping")
                .args(["-n", "1", "-w", "1000", &ip_string])
                .output()
        } else {
            Command::new("ping")
                .args(["-c", "1", "-W", "1", &ip_string])
                .output()
        };
        
        match output {
            Ok(output) => output.status.success(),
            Err(_) => false
        }
    });
    
    result.await
}
