use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::fs::File;
use std::io::{BufRead, BufReader};
use trust_dns_resolver::config::{NameServerConfig, Protocol};



pub fn get_resolv_conf_nameservers() -> Vec<NameServerConfig> {
    let mut nameservers = Vec::new();
    
    // Open resolv.conf file
    if let Ok(file) = File::open("/etc/resolv.conf") {
        let reader = BufReader::new(file);
        
        // Read line by line
        for line in reader.lines() {
            if let Ok(line) = line {
                let line = line.trim();
                
                // Skip comments and empty lines
                if line.starts_with('#') || line.is_empty() {
                    continue;
                }
                
                // Parse nameserver entries
                if line.starts_with("nameserver ") {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 2 {
                        let ip_str = parts[1];
                        
                        // Try to parse as IPv4 or IPv6
                        if let Ok(ipv4) = ip_str.parse::<Ipv4Addr>() {
                            nameservers.push(NameServerConfig {
                                socket_addr: SocketAddr::new(IpAddr::V4(ipv4), 53),
                                protocol: Protocol::Udp,
                                tls_dns_name: None,
                                trust_negative_responses: true,
                                bind_addr: None
                            });
                        } else if let Ok(ipv6) = ip_str.parse::<Ipv6Addr>() {
                            nameservers.push(NameServerConfig {
                                socket_addr: SocketAddr::new(IpAddr::V6(ipv6), 53),
                                protocol: Protocol::Udp,
                                tls_dns_name: None,
                                trust_negative_responses: true,
                                bind_addr: None
                            });
                        }
                    }
                }
            }
        }
    } else {
        println!("Could not open /etc/resolv.conf");
    }
    
    // If no nameservers found, add a fallback
    if nameservers.is_empty() {
        println!("No nameservers found in resolv.conf, using fallback (Google DNS)");
        nameservers.push(NameServerConfig {
            socket_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53),
            protocol: Protocol::Udp,
            tls_dns_name: None,
            trust_negative_responses: true,
            bind_addr: None
        });
    }
    
    nameservers
}



