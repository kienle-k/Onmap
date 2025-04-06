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