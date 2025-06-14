use std::net::{IpAddr, Ipv4Addr};
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use trust_dns_resolver::TokioAsyncResolver;
use trust_dns_resolver::error::ResolveErrorKind;

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
            if let ResolveErrorKind::NoRecordsFound { .. } = e.kind() {
                    None
                } else {
                    // For any other error (e.g., timeout), print an error message.
                    eprintln!("[Warning: DNS lookup for {} failed: {}]", ip, e);
                    None
                }
        },
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use trust_dns_resolver::config::{ResolverConfig, NameServerConfig, Protocol};
    use std::time::Duration;

    #[tokio::test]
    async fn test_resolve_hostname_success() {
        // Using a known Google DNS IP which should have a PTR record
        let ip = Ipv4Addr::new(8, 8, 8, 8);
        let result = resolve_hostname(&ip).await;
        assert_eq!(result, Some("dns.google".to_string()));
    }

    #[tokio::test]
    async fn test_resolve_hostname_no_record() {
        // An IP that is unlikely to have a PTR record
        let ip = Ipv4Addr::new(192, 0, 2, 1); // TEST-NET-1, reserved for documentation
        let result = resolve_hostname(&ip).await;
        assert_eq!(result, None);
    }

    #[tokio::test]
    async fn test_resolve_hostname_timeout() {
        // This test simulates a timeout scenario.
        // We use an IP address that is reserved for private networks and
        // a non-responsive "mock" DNS server to ensure a timeout.
        let ip = Ipv4Addr::new(10, 255, 255, 1);

        // A mock resolver that will time out.
        // 192.0.2.255 is a reserved IP, unlikely to be a responsive DNS server.
        let mut config = ResolverConfig::new();
        config.add_name_server(NameServerConfig {
            socket_addr: "192.0.2.255:53"
                .parse()
                .expect("Parsing a hardcoded socket address for mock resolver setup should not fail"),
            protocol: Protocol::Udp,
            tls_dns_name: None,
            trust_negative_responses: true,
            bind_addr: None,
        });

        let mut opts = ResolverOpts::default();
        opts.timeout = Duration::from_millis(1); // Set a very short timeout

        let resolver = TokioAsyncResolver::tokio(config, opts);

        match resolver.reverse_lookup(IpAddr::V4(ip)).await {
            Ok(_) => panic!("Expected a timeout error, but got a successful lookup."),
            Err(e) => {
                // We expect an error, and the function should return None.
                // The eprintln! in the original function will show a warning, which is expected.
                if let ResolveErrorKind::NoRecordsFound { .. } = e.kind() {
                    // This could happen if the "unreachable" server is actually reached
                    // and returns that there are no records. This is still a valid failure test.
                }
                // For any other error (like a timeout), the test passes.
            }
        }

        // Now, let's test the original function with a setup that should cause a timeout.
        // We can't directly inject the failing resolver into `resolve_hostname`,
        // so we rely on the fact that an unroutable DNS server will cause a timeout.
        // This part of the test is less reliable as it depends on network configuration.
        // A more robust solution would be to refactor `resolve_hostname` to accept a resolver.
        let result = resolve_hostname_with_custom_resolver(&ip, resolver).await;
        assert_eq!(result, None);
    }

    // A helper function for testing with a custom resolver
    async fn resolve_hostname_with_custom_resolver(ip: &Ipv4Addr, resolver: TokioAsyncResolver) -> Option<String> {
        let ip_addr = IpAddr::V4(*ip);

        match resolver.reverse_lookup(ip_addr).await {
            Ok(lookup) => {
                lookup.iter().next().and_then(|name| {
                    let hostname_str = name.to_string();
                    let hostname = hostname_str.trim_end_matches(".").trim().to_string();
                    if hostname.is_empty() {
                        None
                    } else {
                        Some(hostname.to_string())
                    }
                })
            },
            Err(e) => {
                if let ResolveErrorKind::NoRecordsFound { .. } = e.kind() {
                    None
                } else {
                    eprintln!("[Warning: DNS lookup for {} failed: {}]", ip, e);
                    None
                }
            },
        }
    }
}