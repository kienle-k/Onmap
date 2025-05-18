use std::net::{IpAddr, Ipv4Addr};
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use trust_dns_resolver::TokioAsyncResolver;

use super::get_resolv_conf_nameservers;

pub async fn resolve_hostname(ip: &Ipv4Addr) -> Option<String> {
    let ip_addr = IpAddr::V4(*ip);
    
    // Create a custom resolver config with nameservers from resolv.conf
    let mut config = ResolverConfig::new();
    for ns in get_resolv_conf_nameservers() {
        config.add_name_server(ns);
    }
    
    let resolver = TokioAsyncResolver::tokio(
        config,
        ResolverOpts::default()
    );
   
    // Perform the reverse lookup
    match resolver.reverse_lookup(ip_addr).await {
        Ok(lookup) => {
            
            // Get the first hostname if available
            lookup.iter().next().and_then(|name| {
                // Convert to string and take the first part before the dot
                let hostname_str = name.to_string();
                let hostname = hostname_str.trim_end_matches(".").trim().to_string();
                
                // Check if empty after processing
                if hostname.is_empty() {
                    None
                } else {
                    Some(hostname.to_string())
                }
            })
        },
        Err(e) => {
            println!("Error performing reverse lookup: {:?}", e);
            None
        },
    }
}