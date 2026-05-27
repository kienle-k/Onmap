use dns_lookup::lookup_host;
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr; // For DNS resolution

/// Parses a string representation of one or more IPv4 addresses into a vector of `Ipv4Addr`.
///
/// This function supports multiple flexible formats, including comma-separated combinations
/// of single IPs, CIDR blocks, and IP ranges. It detects the format of each segment
/// automatically based on the presence of `'/'` (CIDR) or `'-'` (range).
///
/// ## Supported formats:
/// - Single IP: `"192.168.1.1"`
/// - CIDR notation: `"192.168.1.0/24"`
/// - IP range (inclusive): `"192.168.1.10 - 192.168.1.20"` or `"192.168.1.10-20"`
/// - Comma-separated combinations:  
///   `"192.168.1.1, 192.168.1.5-8, 192.168.1.0/30"`
///
/// # Arguments
///
/// * `ip_str` - A string slice containing one or more IP definitions, separated by commas.
///
/// # Returns
///
/// * `Ok(Vec<Ipv4Addr>)` - A vector of all parsed IP addresses.
/// * `Err(String)` - An error message if any segment is malformed or invalid.
///
/// # Examples
///
/// ```
/// use std::net::{Ipv4Addr, ToSocketAddrs};
/// use onmap::parsing::ip_addresses::parse_ip_addresses;
///
/// // Single IP
/// let ips = parse_ip_addresses("127.0.0.1").expect("Could not parse localhost");
/// assert_eq!(ips, vec![Ipv4Addr::new(127, 0, 0, 1)]);
///
/// // IP Range
/// let ips = parse_ip_addresses("10.0.0.1 - 10.0.0.3").expect("Could not parse ip addresses");
/// assert_eq!(ips.len(), 3);
///
/// // CIDR Notation
/// let ips = parse_ip_addresses("192.168.1.0/30").expect("Could not parse ip addresses with CIDR notation");
/// assert_eq!(ips.len(), 4);
///
/// // Mixed comma-separated list
/// let ips = parse_ip_addresses("10.0.0.1,10.0.0.3-4,10.0.0.10/31").expect("Could not parse ip addresses with mixed notation");
/// assert_eq!(ips.len(), 5);
/// ```
// --- parse_ip_addresses (main function) ---
pub fn parse_ip_addresses(input: &str) -> Result<Vec<Ipv4Addr>, String> {
    let mut result = Vec::new();

    for part in input.split(',') {
        let trimmed = part.trim();

        // Check if it's potentially a hostname (not containing '/' or '-')
        // and doesn't look like a direct IP address.
        let parsed_ips = if trimmed.contains('/') {
            parse_cidr(trimmed)
        } else if trimmed.contains('-') {
            parse_ip_range(trimmed)
        } else if let Ok(ip) = Ipv4Addr::from_str(trimmed) {
            // It's a direct IP address
            Ok(vec![ip])
        } else {
            match Ipv4Addr::from_str(trimmed) {
                Ok(ip) => Ok(vec![ip]),
                Err(_) => {
                    if is_potential_hostname(trimmed) {
                        resolve_hostname_to_ipv4(trimmed)
                    } else {
                        Err(format!("Invalid IP address or hostname: {}", trimmed))
                    }
                }
            }
        }?;

        result.extend(parsed_ips); // Use extend instead of append for Vec<T>
    }

    Ok(result)
}

fn is_potential_hostname(s: &str) -> bool {
    let re = regex::Regex::new(r"^[a-zA-Z0-9.-]+$").unwrap();
    re.is_match(s)
}

/// Resolves a hostname to a list of IPv4 addresses.
///
/// This function performs a DNS lookup for the given hostname and
/// filters the results to return only IPv4 addresses.
/// It returns an error if no IPv4 addresses are found or if the DNS resolution fails.
fn resolve_hostname_to_ipv4(hostname: &str) -> Result<Vec<Ipv4Addr>, String> {
    match lookup_host(hostname) {
        Ok(ips) => {
            let ipv4_ips: Vec<Ipv4Addr> = ips
                .into_iter()
                .filter_map(|ip| {
                    match ip {
                        IpAddr::V4(ipv4) => Some(ipv4), // Correctly extract Ipv4Addr
                        _ => None,                      // Discard IPv6 or other variants
                    }
                })
                .collect();
            if ipv4_ips.is_empty() {
                Err(format!(
                    "No IPv4 addresses found for hostname: {}",
                    hostname
                ))
            } else {
                Ok(ipv4_ips)
            }
        }
        Err(e) => Err(format!("DNS resolution failed for {}: {}", hostname, e)),
    }
}

/// Parses an IP address range from a string in the format "start_ip - end_ip".
///
/// This is a helper function that takes a string representing an inclusive range of IP addresses,
/// validates the format and the IPs, and generates a vector containing every IP address in that range.
fn parse_ip_range(range_str: &str) -> Result<Vec<Ipv4Addr>, String> {
    // Split the input string by the hyphen and trim whitespace from each part.
    let parts: Vec<&str> = range_str.split('-').map(|s| s.trim()).collect();

    // Ensure the input is in the format "start - end" by checking for exactly two parts.
    if parts.len() != 2 {
        return Err(format!("Invalid IP range format: {}", range_str));
    }

    // Parse the first part as the starting IP address, returning an error if it's invalid.
    let start_ip = match Ipv4Addr::from_str(parts[0]) {
        Ok(ip) => ip,
        Err(_) => return Err(format!("Invalid starting IP address: {}", parts[0])),
    };

    // Parse the second part as the ending IP address (either full address or last octet), returning an error if it's invalid.
    let end_ip;

    if parts[1].contains('.') {
        end_ip = match Ipv4Addr::from_str(parts[1]) {
            Ok(ip) => ip,
            Err(_) => return Err(format!("Invalid ending IP address: {}", parts[1])),
        };
    } else {
        let end_octet: u8 = match parts[1].parse() {
            Ok(o) => o,
            Err(_) => return Err(format!("Invalid ending octet: {}", parts[1])),
        };
        let start_ip = match Ipv4Addr::from_str(parts[0]) {
            Ok(ip) => ip,
            Err(_) => return Err(format!("Invalid starting IP address: {}", parts[0])),
        };
        let octets = start_ip.octets();
        end_ip = Ipv4Addr::new(octets[0], octets[1], octets[2], end_octet);
    }

    // Convert IP addresses to their u32 integer representations to allow for easy iteration.
    let start_u32: u32 = u32::from(start_ip);
    let end_u32: u32 = u32::from(end_ip);

    // Check that the start of the range is not after the end.
    if start_u32 > end_u32 {
        return Err(
            "Starting IP address must be less than or equal to ending IP address".to_string(),
        );
    }

    // Create a vector to hold the generated IP addresses.
    let mut result = Vec::new();
    // Iterate from the start number to the end number (inclusive).
    for i in start_u32..=end_u32 {
        // Convert each number back to an Ipv4Addr and add it to our list.
        result.push(Ipv4Addr::from(i));
    }

    // Return the complete list of IP addresses.
    Ok(result)
}

/// Parses a CIDR notation string (e.g., "192.168.1.0/24") into a list of IP addresses.
///
/// This helper function calculates the network address and the broadcast address for the
/// given CIDR block and generates a complete list of all host IP addresses within that block.
fn parse_cidr(cidr_str: &str) -> Result<Vec<Ipv4Addr>, String> {
    // Split the string into the IP part and the prefix length part.
    let parts: Vec<&str> = cidr_str.split('/').collect();

    // A valid CIDR string must have exactly two parts separated by a '/'.
    if parts.len() != 2 {
        return Err(format!("Invalid CIDR format: {}", cidr_str));
    }

    // Parse the IP address part of the CIDR string.
    let base_ip = match Ipv4Addr::from_str(parts[0]) {
        Ok(ip) => ip,
        Err(_) => return Err(format!("Invalid IP address in CIDR: {}", parts[0])),
    };

    // Parse the prefix length, ensuring it's a valid number between 0 and 32.
    let prefix_len = match parts[1].parse::<u8>() {
        Ok(len) if len <= 32 => len,
        _ => return Err(format!("Invalid prefix length in CIDR: {}", parts[1])),
    };

    // --- Perform bitwise calculations to determine the exact IP range ---

    // Create a subnet mask from the prefix length. For a /24, this would be
    // `u32::MAX << (32 - 24)`, resulting in `0xFFFFFF00`.
    let mask = u32::MAX << (32 - prefix_len);
    // Apply the mask to the base IP's integer value to find the true network
    // address (the first IP in the subnet).
    let network_addr = u32::from(base_ip) & mask;

    // Calculate the total number of IP addresses in the subnet (2^(32-prefix)).
    // The `1 << n` is an efficient way to calculate 2^n.
    let num_hosts = 1u32 << (32 - prefix_len);

    // Create a vector to hold the generated IP addresses.
    let mut result = Vec::new();
    // Iterate through all possible addresses in the subnet.
    for i in 0..num_hosts {
        // Add the offset `i` to the network address to get each sequential IP.
        result.push(Ipv4Addr::from(network_addr + i));
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    //! Unit tests for the IP address parsing functions.
    //!
    //! The tests are divided into three sections:
    //! 1.  Tests for the main `parse_ip_addresses` dispatcher function.
    //! 2.  Tests specifically for the CIDR parsing logic.
    //! 3.  Tests specifically for the IP range parsing logic.
    use super::*;
    use std::net::Ipv4Addr;

    // --- Tests for the main dispatcher function: parse_ip_addresses ---

    /// Verifies that a single, valid IP address string is parsed correctly.
    #[test]
    fn test_parse_single_valid_ip() {
        let result = parse_ip_addresses("192.168.1.1")
            .expect("Parsing a single valid IP address should succeed");
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], Ipv4Addr::new(192, 168, 1, 1));
    }

    /// Verifies that leading/trailing whitespace is correctly handled.
    #[test]
    fn test_parse_single_valid_ip_with_whitespace() {
        let result = parse_ip_addresses("   127.0.0.1  ")
            .expect("Parsing a valid IP with whitespace should succeed");
        assert_eq!(result, vec![Ipv4Addr::new(127, 0, 0, 1)]);
    }

    /// Verifies that an IP address with an invalid octet returns an error.
    #[test]
    fn test_parse_single_invalid_ip() {
        let input = "192.168.1.256"; // Invalid octet value
        let result = parse_ip_addresses(input);
        assert!(result.is_err());
        // Updated assertion to expect DNS resolution failure for the "invalid IP" string
        let err_msg = result.unwrap_err();
        assert!(
            err_msg.contains("DNS resolution failed for 192.168.1.256")
                || err_msg.contains("Invalid IP address: 192.168.1.256"),
            "Expected DNS failure or Invalid IP error, got: {}",
            err_msg
        );
    }

    /// Verifies that a non-IP string returns an error.
    #[test]
    fn test_parse_single_gibberish_input() {
        let input = "not an ip";
        let result = parse_ip_addresses(input);
        assert!(result.is_err());
        // Updated assertion to expect DNS resolution failure
        let err_msg = result.unwrap_err();
        assert!(
            err_msg.contains("DNS resolution failed for not an ip")
                || err_msg.contains("Invalid IP address: not an ip")
                || err_msg.contains("Invalid IP address or hostname: not an ip"),
            "Expected DNS failure or Invalid IP error, got: {}",
            err_msg
        );
    }

    // --- Tests for CIDR parsing functionality ---

    /// Verifies that a standard /24 CIDR block is parsed correctly.
    #[test]
    fn test_parse_cidr_valid_24() {
        let result =
            parse_ip_addresses("192.168.1.0/24").expect("Parsing a valid /24 CIDR should succeed");
        assert_eq!(result.len(), 256);
        assert_eq!(result.first(), Some(&Ipv4Addr::new(192, 168, 1, 0)));
        assert_eq!(result.last(), Some(&Ipv4Addr::new(192, 168, 1, 255)));
    }

    /// Verifies that the parser correctly finds the network address for a given IP in a subnet.
    #[test]
    fn test_parse_cidr_correctly_finds_network_address() {
        let result = parse_ip_addresses("10.10.10.130/27")
            .expect("Parsing a valid CIDR with a non-network IP should succeed");
        assert_eq!(result.len(), 32);
        assert_eq!(result.first(), Some(&Ipv4Addr::new(10, 10, 10, 128)));
        assert_eq!(result.last(), Some(&Ipv4Addr::new(10, 10, 10, 159)));
    }

    /// Verifies that a /32 CIDR block (a single host) is parsed correctly.
    #[test]
    fn test_parse_cidr_valid_32() {
        let result =
            parse_ip_addresses("203.0.113.42/32").expect("Parsing a valid /32 CIDR should succeed");
        assert_eq!(result, vec![Ipv4Addr::new(203, 0, 113, 42)]);
    }

    /// Verifies that a /31 CIDR block (two hosts, as per RFC 3021) is parsed correctly.
    #[test]
    fn test_parse_cidr_valid_31() {
        let result =
            parse_ip_addresses("192.0.2.0/31").expect("Parsing a valid /31 CIDR should succeed");
        assert_eq!(result.len(), 2);
        assert_eq!(result[0], Ipv4Addr::new(192, 0, 2, 0));
        assert_eq!(result[1], Ipv4Addr::new(192, 0, 2, 1));
    }

    /// Verifies that a CIDR block with a prefix length > 32 returns an error.
    #[test]
    fn test_parse_cidr_invalid_prefix_length() {
        let err_message = parse_ip_addresses("192.168.1.1/33")
            .expect_err("A prefix length greater than 32 should result in an error");
        assert_eq!(err_message, "Invalid prefix length in CIDR: 33");
    }

    /// Verifies that a CIDR block with an invalid IP part returns an error.
    #[test]
    fn test_parse_cidr_invalid_ip_part() {
        let err_message = parse_ip_addresses("192.168.abc.1/24")
            .expect_err("A CIDR with an invalid IP part should result in an error");
        assert_eq!(err_message, "Invalid IP address in CIDR: 192.168.abc.1");
    }

    /// Verifies that a malformed CIDR string returns an error.
    #[test]
    fn test_parse_cidr_invalid_format() {
        let err_message = parse_ip_addresses("192.168.1.1/24/extra")
            .expect_err("A CIDR with an invalid format should result in an error");
        assert_eq!(err_message, "Invalid CIDR format: 192.168.1.1/24/extra");
    }

    // --- Tests for IP Range parsing functionality ---

    /// Verifies that a simple, valid IP range is parsed correctly.
    #[test]
    fn test_parse_range_valid() {
        let result = parse_ip_addresses("10.0.0.1 - 10.0.0.4")
            .expect("Parsing a valid IP range should succeed");
        assert_eq!(
            result,
            vec![
                Ipv4Addr::new(10, 0, 0, 1),
                Ipv4Addr::new(10, 0, 0, 2),
                Ipv4Addr::new(10, 0, 0, 3),
                Ipv4Addr::new(10, 0, 0, 4),
            ]
        );
    }

    /// Verifies that a range that spans across an octet boundary is parsed correctly.
    #[test]
    fn test_parse_range_crossing_octet() {
        let result = parse_ip_addresses("192.168.1.254 - 192.168.2.2")
            .expect("Parsing a valid IP range crossing an octet should succeed");
        assert_eq!(result.len(), 5);
        assert_eq!(result.first(), Some(&Ipv4Addr::new(192, 168, 1, 254)));
        assert_eq!(result.last(), Some(&Ipv4Addr::new(192, 168, 2, 2)));
    }

    /// Verifies that a range with extra whitespace is handled correctly.
    #[test]
    fn test_parse_range_with_whitespace() {
        let result = parse_ip_addresses("  10.0.0.1  -  10.0.0.2  ")
            .expect("Parsing a valid IP range with extra whitespace should succeed");
        assert_eq!(
            result,
            vec![Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2),]
        );
    }

    /// Verifies that a range with the same start and end IP produces a single IP.
    #[test]
    fn test_parse_range_single_ip() {
        let result = parse_ip_addresses("192.168.1.1 - 192.168.1.1")
            .expect("Parsing a range with identical start and end IPs should succeed");
        assert_eq!(result, vec![Ipv4Addr::new(192, 168, 1, 1)]);
    }

    /// Verifies that a range where the start IP is greater than the end IP returns an error.
    #[test]
    fn test_parse_range_start_ip_greater() {
        let err_message = parse_ip_addresses("192.168.1.10 - 192.168.1.5")
            .expect_err("A range where the start IP is greater than the end IP should fail");
        assert_eq!(
            err_message,
            "Starting IP address must be less than or equal to ending IP address"
        );
    }

    /// Verifies that a range with an invalid start IP returns an error.
    #[test]
    fn test_parse_range_invalid_start_ip() {
        let err_message = parse_ip_addresses("192.168.300.1 - 192.168.1.10")
            .expect_err("A range with an invalid start IP should fail");
        assert_eq!(err_message, "Invalid starting IP address: 192.168.300.1");
    }

    /// Verifies that a range with an invalid end IP returns an error.
    #[test]
    fn test_parse_range_invalid_end_ip() {
        let err_message = parse_ip_addresses("192.168.1.1 - 192.168.1.xyz")
            .expect_err("A range with an invalid end IP should fail");
        assert_eq!(err_message, "Invalid ending IP address: 192.168.1.xyz");
    }

    /// Verifies that a malformed range string returns an error.
    #[test]
    fn test_parse_range_invalid_format() {
        let err_message = parse_ip_addresses("192.168.1.1 - 192.168.1.2 - 192.168.1.3")
            .expect_err("A range with an invalid format should fail");
        assert_eq!(
            err_message,
            "Invalid IP range format: 192.168.1.1 - 192.168.1.2 - 192.168.1.3"
        );
    }
}
