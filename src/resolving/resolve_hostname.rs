use std::net::{IpAddr, Ipv4Addr};
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use trust_dns_resolver::TokioAsyncResolver;
use trust_dns_resolver::error::ResolveErrorKind;

use super::get_resolv_conf_nameservers;

/// Performs an asynchronous reverse DNS lookup to find the hostname for a given IPv4 address.
///
/// This function configures a DNS resolver using the system's nameservers (from `/etc/resolv.conf`)
/// and attempts to find the PTR record associated with the provided IP address.
///
/// # Arguments
///
/// * `ip` - A reference to the `Ipv4Addr` for which to find the hostname.
///
/// # Returns
///
/// An `Option<String>` which is:
/// * `Some(hostname)` if a PTR record is successfully found.
/// * `None` if no record is found, or if a DNS lookup error (like a timeout) occurs.
///
/// # Panics
///
/// This function does not panic, but it will print a warning to `stderr` if a DNS
/// lookup fails for reasons other than `NoRecordsFound`.
///
/// # Examples
///
/// ```
/// # use std::net::Ipv4Addr;
/// # use tokio::runtime::Runtime;
/// # use onmap::resolving::resolve_hostname;
///
/// # fn main() {
/// #     let rt = Runtime::new().unwrap();
/// #     rt.block_on(async {
/// // Resolve a well-known public IP address.
/// let ip = Ipv4Addr::new(8, 8, 8, 8);
/// if let Some(hostname) = resolve_hostname(&ip).await {
///     assert_eq!(hostname, "dns.google");
/// }
/// #     });
/// # }
/// ```
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
                // Convert to string and trim the trailing dot
                let hostname_str = name.to_string();
                let hostname = hostname_str.trim_end_matches('.').to_string();

                if hostname.is_empty() {
                    None
                } else {
                    Some(hostname)
                }
            })
        },
        Err(e) => {
            // If no record was found, that's a valid (empty) result.
            // For other errors, print a warning and return None.
            if let ResolveErrorKind::NoRecordsFound { .. } = e.kind() {
                None
            } else {
                eprintln!("[Warning: DNS lookup for {} failed: {}]", ip, e);
                None
            }
        },
    }
}


#[cfg(test)]
mod tests {
    //! Integration tests for the hostname resolution functionality.
    //! These tests perform real network requests to DNS servers.
    use super::*;
    use std::net::Ipv4Addr;
    use trust_dns_resolver::config::{ResolverConfig, NameServerConfig, Protocol};
    use std::time::Duration;

    /// Verifies that a successful reverse lookup on a known IP returns the correct hostname.
    #[tokio::test]
    async fn test_resolve_hostname_success() {
        // Using a known Google DNS IP which should have a PTR record
        let ip = Ipv4Addr::new(8, 8, 8, 8);
        let result = resolve_hostname(&ip).await;
        assert_eq!(result, Some("dns.google".to_string()));
    }

    /// Tests the case where an IP address is valid but has no associated PTR record.
    #[tokio::test]
    async fn test_resolve_hostname_no_record() {
        // An IP from TEST-NET-1 (RFC 5737), reserved for documentation, should not have a PTR record.
        let ip = Ipv4Addr::new(192, 0, 2, 1);
        let result = resolve_hostname(&ip).await;
        assert_eq!(result, None);
    }

    /// Verifies that the internal logic handles DNS errors (like timeouts) by returning None.
    /// This test uses a helper function to inject a resolver that is configured to time out quickly.
    #[tokio::test]
    async fn test_resolve_hostname_timeout() {
        let ip = Ipv4Addr::new(10, 255, 255, 1); // An unroutable IP

        // Configure a mock resolver that uses a non-responsive IP and a very short timeout.
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
        opts.timeout = Duration::from_millis(1);

        let resolver = TokioAsyncResolver::tokio(config, opts);

        // Use the test helper to inject the failing resolver.
        // We expect the function to handle the resulting error and return None.
        let result = resolve_hostname_with_custom_resolver(&ip, resolver).await;
        assert_eq!(result, None);
    }

    /// A test helper that mirrors `resolve_hostname` but accepts a custom resolver.
    /// This allows for injecting a mock or specially configured resolver for testing
    /// specific scenarios, like timeouts.
    async fn resolve_hostname_with_custom_resolver(ip: &Ipv4Addr, resolver: TokioAsyncResolver) -> Option<String> {
        let ip_addr = IpAddr::V4(*ip);

        match resolver.reverse_lookup(ip_addr).await {
            Ok(lookup) => {
                lookup.iter().next().and_then(|name| {
                    let hostname_str = name.to_string();
                    let hostname = hostname_str.trim_end_matches('.').to_string();
                    if hostname.is_empty() {
                        None
                    } else {
                        Some(hostname)
                    }
                })
            },
            Err(e) => {
                if let ResolveErrorKind::NoRecordsFound { .. } = e.kind() {
                    None
                } else {
                    // In a real test, we might log this, but for this helper,
                    // simply returning None is sufficient to test the failure path.
                    eprintln!("[Warning: DNS lookup for {} failed: {}]", ip, e);
                    None
                }
            },
        }
    }
}