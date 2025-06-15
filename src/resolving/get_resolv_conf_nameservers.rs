use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::fs::File;
use std::io::{BufRead, BufReader};
use trust_dns_resolver::config::{NameServerConfig, Protocol};

/// Parses DNS nameserver configurations from any readable source.
///
/// This function reads line by line, looking for `nameserver` entries. It correctly
/// parses both IPv4 and IPv6 addresses. Lines that are empty or start with '#' are
/// ignored. If no nameservers are found after parsing, it provides a default
/// fallback configuration to Google's public DNS (8.8.8.8).
///
/// This function is generic over any type that implements `BufRead`, making it
/// easy to test with in-memory strings as well as actual files.
///
/// # Arguments
///
/// * `reader` - A type that implements `BufRead`, such as a `BufReader<File>` or a `BufReader` for a byte slice.
///
/// # Returns
///
/// A `Vec<NameServerConfig>` containing the configurations for all valid nameservers found.
///
/// # Examples
///
/// ```
/// # use std::io::BufReader;
/// # use onmap::resolving::get_resolv_conf_nameservers::parse_resolv_conf;
/// let mock_conf = "
/// # System DNS servers
/// nameserver 8.8.8.8
/// nameserver 2001:4860:4860::8888
/// ";
/// let reader = BufReader::new(mock_conf.as_bytes());
/// let nameservers = parse_resolv_conf(reader);
/// assert_eq!(nameservers.len(), 2);
/// ```
pub fn parse_resolv_conf<R: BufRead>(reader: R) -> Vec<NameServerConfig> {
    // This vector will store the successfully parsed nameserver configurations.
    let mut nameservers = Vec::new();

    // Process the input one line at a time.
    for line in reader.lines() {
        // `reader.lines()` returns a Result for each line to handle potential I/O errors.
        // We use `if let Ok(line)` to gracefully skip any line that couldn't be read.
        if let Ok(line) = line {
            // Remove leading/trailing whitespace from the line.
            let line = line.trim();

            // Ignore lines that are designated as comments or are empty.
            if line.starts_with('#') || line.is_empty() {
                continue; // Skip to the next line.
            }

            // `strip_prefix` is an efficient way to check if the line starts with "nameserver "
            // and get the remainder of the line (the IP address part) in one step.
            if let Some(ip_str) = line.strip_prefix("nameserver ") {
                // Trim whitespace from the IP string itself, e.g., " nameserver   8.8.8.8  ".
                let ip_str = ip_str.trim();
                
                // First, try to parse the string as an IPv4 address.
                if let Ok(ipv4) = ip_str.parse::<Ipv4Addr>() {
                    // If successful, create a standard UDP nameserver configuration on port 53.
                    nameservers.push(NameServerConfig {
                        socket_addr: SocketAddr::new(IpAddr::V4(ipv4), 53),
                        protocol: Protocol::Udp,
                        tls_dns_name: None,
                        trust_negative_responses: true,
                        bind_addr: None
                    });
                // If it's not IPv4, try parsing it as an IPv6 address.
                } else if let Ok(ipv6) = ip_str.parse::<Ipv6Addr>() {
                    // If successful, create a standard UDP nameserver configuration for IPv6.
                    nameservers.push(NameServerConfig {
                        socket_addr: SocketAddr::new(IpAddr::V6(ipv6), 53),
                        protocol: Protocol::Udp,
                        tls_dns_name: None,
                        trust_negative_responses: true,
                        bind_addr: None
                    });
                }
                // If the string after "nameserver " is not a valid IPv4 or IPv6, it's ignored.
            }
        }
    }

    // If, after checking all lines, no valid nameservers were found, a fallback
    // is necessary for the DNS resolver to have a server to query.
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

    // Return the final list of nameservers.
    nameservers
}

/// Retrieves DNS nameservers from the system's `/etc/resolv.conf` file.
///
/// This is a convenience wrapper around `parse_resolv_conf` for Unix-like systems.
/// It attempts to open and read `/etc/resolv.conf`. If the file cannot be opened,
/// it triggers the fallback mechanism in `parse_resolv_conf`.
///
/// # Returns
///
/// A `Vec<NameServerConfig>` containing the system's configured nameservers,
/// or a fallback if the file is inaccessible or empty.
pub fn get_resolv_conf_nameservers() -> Vec<NameServerConfig> {
    if let Ok(file) = File::open("/etc/resolv.conf") {
        let reader = BufReader::new(file);
        parse_resolv_conf(reader)
    } else {
        println!("Could not open /etc/resolv.conf");
        // Fallback logic is handled inside parse_resolv_conf when given an empty source.
        parse_resolv_conf(BufReader::new("".as_bytes()))
    }
}


#[cfg(test)]
mod tests {
    //! Unit tests for the resolv.conf parsing logic.
    use super::*;

    /// Verifies that IPv4 addresses are parsed correctly while ignoring comments.
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

    /// Verifies that a single IPv6 address is parsed correctly.
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

    /// Checks that a mix of IPv4, IPv6, and empty lines is handled correctly.
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

    /// Ensures that malformed and irrelevant lines are ignored, and valid lines are still parsed.
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

    /// Verifies that the fallback logic is triggered for empty input.
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

    /// Verifies that the fallback is triggered if the file contains no 'nameserver' entries.
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