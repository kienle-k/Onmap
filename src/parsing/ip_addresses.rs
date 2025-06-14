use std::net::Ipv4Addr;
use std::str::FromStr;

pub fn parse_ip_addresses(ip_str: &str) -> Result<Vec<Ipv4Addr>, String> {
    let ip_str = ip_str.trim();
    
    // Case 1: Check if it's a CIDR notation
    if ip_str.contains('/') {
        return parse_cidr(ip_str);
    } 
    // Case 2: Check if it's an IP range
    else if ip_str.contains('-') {
        return parse_ip_range(ip_str);
    } 
    // Case 3: Single IP address
    else {
        match Ipv4Addr::from_str(ip_str) {
            Ok(ip) => Ok(vec![ip]),
            Err(_) => Err(format!("Invalid IP address: {}", ip_str)),
        }
    }
}

/// Parse IP address range in format "192.168.1.0 - 192.168.1.20"
fn parse_ip_range(range_str: &str) -> Result<Vec<Ipv4Addr>, String> {
    let parts: Vec<&str> = range_str.split('-').map(|s| s.trim()).collect();
    
    if parts.len() != 2 {
        return Err(format!("Invalid IP range format: {}", range_str));
    }
    
    let start_ip = match Ipv4Addr::from_str(parts[0]) {
        Ok(ip) => ip,
        Err(_) => return Err(format!("Invalid starting IP address: {}", parts[0])),
    };
    
    let end_ip = match Ipv4Addr::from_str(parts[1]) {
        Ok(ip) => ip,
        Err(_) => return Err(format!("Invalid ending IP address: {}", parts[1])),
    };
    
    let start_u32: u32 = u32::from(start_ip);
    let end_u32: u32 = u32::from(end_ip);
    
    if start_u32 > end_u32 {
        return Err("Starting IP address must be less than or equal to ending IP address".to_string());
    }
    
    let mut result = Vec::new();
    for i in start_u32..=end_u32 {
        result.push(Ipv4Addr::from(i));
    }
    
    Ok(result)
}

/// Parse CIDR notation in format "192.168.1.0/24"
fn parse_cidr(cidr_str: &str) -> Result<Vec<Ipv4Addr>, String> {
    let parts: Vec<&str> = cidr_str.split('/').collect();
    
    if parts.len() != 2 {
        return Err(format!("Invalid CIDR format: {}", cidr_str));
    }
    
    let base_ip = match Ipv4Addr::from_str(parts[0]) {
        Ok(ip) => ip,
        Err(_) => return Err(format!("Invalid IP address in CIDR: {}", parts[0])),
    };
    
    let prefix_len = match parts[1].parse::<u8>() {
        Ok(len) if len <= 32 => len,
        _ => return Err(format!("Invalid prefix length in CIDR: {}", parts[1])),
    };
    
    // Calculate number of IPs in this subnet
    let hosts = 2u32.pow((32 - prefix_len) as u32);
    
    // Calculate the network address (first IP in the range)
    let base_u32 = u32::from(base_ip) & (u32::MAX << (32 - prefix_len));
    
    let mut result = Vec::new();
    for i in 0..hosts {
        result.push(Ipv4Addr::from(base_u32 + i));
    }
    
    Ok(result)
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    // Tests for the main dispatcher function: parse_ip_addresses

    #[test]
    fn test_parse_single_valid_ip() {
        let result = parse_ip_addresses("192.168.1.1").unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], Ipv4Addr::new(192, 168, 1, 1));
    }

    #[test]
    fn test_parse_single_valid_ip_with_whitespace() {
        let result = parse_ip_addresses("  127.0.0.1  ").unwrap();
        assert_eq!(result, vec![Ipv4Addr::new(127, 0, 0, 1)]);
    }

    #[test]
    fn test_parse_single_invalid_ip() {
        let result = parse_ip_addresses("192.168.1.256");
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            "Invalid IP address: 192.168.1.256"
        );
    }

    #[test]
    fn test_parse_single_gibberish_input() {
        let result = parse_ip_addresses("not an ip");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Invalid IP address: not an ip");
    }

    // Tests for CIDR parsing functionality

    #[test]
    fn test_parse_cidr_valid_24() {
        // A /24 should result in 256 addresses.
        let result = parse_ip_addresses("192.168.1.0/24").unwrap();
        assert_eq!(result.len(), 256);
        assert_eq!(result.first(), Some(&Ipv4Addr::new(192, 168, 1, 0)));
        assert_eq!(result.last(), Some(&Ipv4Addr::new(192, 168, 1, 255)));
    }

    #[test]
    fn test_parse_cidr_correctly_finds_network_address() {
        // Input IP is not the network address; the function should find it.
        // 10.10.10.130/27 -> network address is 10.10.10.128
        let result = parse_ip_addresses("10.10.10.130/27").unwrap();
        // 2^(32-27) = 2^5 = 32 addresses
        assert_eq!(result.len(), 32);
        assert_eq!(result.first(), Some(&Ipv4Addr::new(10, 10, 10, 128)));
        assert_eq!(result.last(), Some(&Ipv4Addr::new(10, 10, 10, 159)));
    }

    #[test]
    fn test_parse_cidr_valid_32() {
        // A /32 is a single host.
        let result = parse_ip_addresses("203.0.113.42/32").unwrap();
        assert_eq!(result, vec![Ipv4Addr::new(203, 0, 113, 42)]);
    }

    #[test]
    fn test_parse_cidr_valid_31() {
        // A /31 is a special case with 2 addresses.
        let result = parse_ip_addresses("192.0.2.0/31").unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result[0], Ipv4Addr::new(192, 0, 2, 0));
        assert_eq!(result[1], Ipv4Addr::new(192, 0, 2, 1));
    }

    #[test]
    fn test_parse_cidr_invalid_prefix_length() {
        let result = parse_ip_addresses("192.168.1.1/33");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Invalid prefix length in CIDR: 33");
    }

    #[test]
    fn test_parse_cidr_invalid_ip_part() {
        let result = parse_ip_addresses("192.168.abc.1/24");
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            "Invalid IP address in CIDR: 192.168.abc.1"
        );
    }
    
    #[test]
    fn test_parse_cidr_invalid_format() {
        let result = parse_ip_addresses("192.168.1.1/24/extra");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Invalid CIDR format: 192.168.1.1/24/extra");
    }

    // Tests for IP Range parsing functionality

    #[test]
    fn test_parse_range_valid() {
        let result = parse_ip_addresses("10.0.0.1 - 10.0.0.4").unwrap();
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
    
    #[test]
    fn test_parse_range_crossing_octet() {
        let result = parse_ip_addresses("192.168.1.254 - 192.168.2.2").unwrap();
        assert_eq!(result.len(), 5);
        assert_eq!(result.first(), Some(&Ipv4Addr::new(192, 168, 1, 254)));
        assert_eq!(result.last(), Some(&Ipv4Addr::new(192, 168, 2, 2)));
    }

    #[test]
    fn test_parse_range_with_whitespace() {
        let result = parse_ip_addresses("  10.0.0.1  -  10.0.0.2  ").unwrap();
        assert_eq!(
            result,
            vec![
                Ipv4Addr::new(10, 0, 0, 1),
                Ipv4Addr::new(10, 0, 0, 2),
            ]
        );
    }

    #[test]
    fn test_parse_range_single_ip() {
        let result = parse_ip_addresses("192.168.1.1 - 192.168.1.1").unwrap();
        assert_eq!(result, vec![Ipv4Addr::new(192, 168, 1, 1)]);
    }

    #[test]
    fn test_parse_range_start_ip_greater() {
        let result = parse_ip_addresses("192.168.1.10 - 192.168.1.5");
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            "Starting IP address must be less than or equal to ending IP address"
        );
    }
    
    #[test]
    fn test_parse_range_invalid_start_ip() {
        let result = parse_ip_addresses("192.168.300.1 - 192.168.1.10");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Invalid starting IP address: 192.168.300.1");
    }

    #[test]
    fn test_parse_range_invalid_end_ip() {
        let result = parse_ip_addresses("192.168.1.1 - 192.168.1.xyz");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Invalid ending IP address: 192.168.1.xyz");
    }
    
    #[test]
    fn test_parse_range_invalid_format() {
        let result = parse_ip_addresses("192.168.1.1 - 192.168.1.2 - 192.168.1.3");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Invalid IP range format: 192.168.1.1 - 192.168.1.2 - 192.168.1.3");
    }
}