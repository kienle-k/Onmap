use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::fs::File;
use std::io::{BufRead, BufReader};
use trust_dns_resolver::config::{NameServerConfig, Protocol};

// The new, testable function that contains all the parsing logic.
// It takes a generic `BufRead` so you can pass a file or a string slice for testing.
pub fn parse_resolv_conf<R: BufRead>(reader: R) -> Vec<NameServerConfig> {
    let mut nameservers = Vec::new();
    
    for line in reader.lines() {
        if let Ok(line) = line {
            let line = line.trim();
            
            // Skip comments and empty lines
            if line.starts_with('#') || line.is_empty() {
                continue;
            }
            
            // Parse nameserver entries
            if line.starts_with("nameserver ") {
                if let Some(ip_str) = line.split_whitespace().nth(1) {
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
    
    // If no nameservers found, add a fallback
    if nameservers.is_empty() {
        println!("No nameservers found, using fallback (Google DNS)");
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

// Your original function now handles the file opening and calls the parsing logic.
pub fn get_resolv_conf_nameservers() -> Vec<NameServerConfig> {
    if let Ok(file) = File::open("/etc/resolv.conf") {
        let reader = BufReader::new(file);
        parse_resolv_conf(reader)
    } else {
        println!("Could not open /etc/resolv.conf");
        // Fallback logic is handled inside parse_resolv_conf
        parse_resolv_conf(BufReader::new("".as_bytes()))
    }
}



#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ipv4_and_comments() {
        let mock_data = "
                                # This is a comment
                                nameserver 8.8.8.8
                                nameserver 1.1.1.1
                              ";
        let reader = BufReader::new(mock_data.as_bytes());
        let nameservers = parse_resolv_conf(reader);

        assert_eq!(nameservers.len(), 2);
        assert_eq!(
            nameservers[0].socket_addr,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53)
        );
        assert_eq!(
            nameservers[1].socket_addr,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 53)
        );
    }

    #[test]
    fn test_parse_ipv6() {
        let mock_data = "nameserver 2001:4860:4860::8888";
        let reader = BufReader::new(mock_data.as_bytes());
        let nameservers = parse_resolv_conf(reader);

        assert_eq!(nameservers.len(), 1);
        assert_eq!(
            nameservers[0].socket_addr,
            SocketAddr::new(
                IpAddr::V6(
                    "2001:4860:4860::8888"
                        .parse::<Ipv6Addr>()
                        .expect("Parsing a hardcoded IPv6 literal for a test should always succeed")
                ),
                53
            )
        );
    }

    #[test]
    fn test_parse_mixed_ips_and_empty_lines() {
        let mock_data = "
                                nameserver 8.8.4.4

                                nameserver 2606:4700:4700::1111
                              ";
        let reader = BufReader::new(mock_data.as_bytes());
        let nameservers = parse_resolv_conf(reader);

        assert_eq!(nameservers.len(), 2);
        assert_eq!(
            nameservers[0].socket_addr,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4)), 53)
        );
        assert_eq!(
            nameservers[1].socket_addr,
            SocketAddr::new(
                IpAddr::V6(
                    "2606:4700:4700::1111"
                        .parse::<Ipv6Addr>()
                        .expect("Parsing a hardcoded IPv6 literal for a test should always succeed")
                ),
                53
            )
        );
    }

    #[test]
    fn test_malformed_and_irrelevant_lines() {
        let mock_data = "
                                domain example.com
                                search example.com
                                nameserver 9.9.9.9
                                nameserver
                                nameserver malformed-ip
                              ";
        let reader = BufReader::new(mock_data.as_bytes());
        let nameservers = parse_resolv_conf(reader);

        // Only the valid IP should be parsed.
        assert_eq!(nameservers.len(), 1);
        assert_eq!(
            nameservers[0].socket_addr,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)), 53)
        );
    }

    #[test]
    fn test_fallback_on_empty_input() {
        let mock_data = ""; // Simulates a missing or empty file
        let reader = BufReader::new(mock_data.as_bytes());
        let nameservers = parse_resolv_conf(reader);

        // Should return the Google DNS fallback
        assert_eq!(nameservers.len(), 1);
        assert_eq!(
            nameservers[0].socket_addr,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53)
        );
    }

    #[test]
    fn test_fallback_on_no_nameserver_entries() {
        let mock_data = "
                                # No nameservers here
                                domain example.com
                              ";
        let reader = BufReader::new(mock_data.as_bytes());
        let nameservers = parse_resolv_conf(reader);

        // Should also return the Google DNS fallback
        assert_eq!(nameservers.len(), 1);
        assert_eq!(
            nameservers[0].socket_addr,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53)
        );
    }
}