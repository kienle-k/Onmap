use std::collections::HashMap;
use std::fs;
use std::path::Path;

use serde::Deserialize;



/// Represents a network service mapped to a port.
#[derive(Deserialize)]
pub struct PortService {
    /// Name of the service (e.g., "http", "ssh").
    service: String,
    // pservice: String, // Optional protocol service name (but not used 
    //-> can be added in the future, as it is present a a parameter in the file)
}

/// Holds protocol-to-service mappings for TCP and UDP ports.
#[derive(Deserialize)]
pub struct ProtocolMap {
    /// TCP port to service mapping.
    tcp: HashMap<String, PortService>,
    /// UDP port to service mapping.
    udp: HashMap<String, PortService>,
}


/// Loads the protocol map from a JSON file at the given path.
///
/// Returns the parsed `ProtocolMap` or an error with context.
pub fn load_protocol_map(path: &str) -> Result<ProtocolMap, Box<dyn std::error::Error>> {
    // Check if file exists first (optional but better for clearer error messages)
    if !Path::new(path).exists() {
        return Err(format!("Protocol map file not found: {}", path).into());
    }

    // Read file content
    let json_str = fs::read_to_string(path)
        .map_err(|e| format!("Failed to read protocol map file '{}': {}", path, e))?;

    // Parse JSON
    let protocols: ProtocolMap = serde_json::from_str(&json_str)
        .map_err(|e| format!("Failed to parse protocol map JSON from '{}': {}", path, e))?;

    Ok(protocols)
}

// Old version of the json loader
// pub fn load_protocol_map(path: &str) -> Result<ProtocolMap, Box<dyn std::error::Error>> {
//     let json_str = std::fs::read_to_string(path)?;
//     let protocols: ProtocolMap = serde_json::from_str(&json_str)?;
//     Ok(protocols)
// }


/// Returns the service name for a given protocol and port.
/// If not found or unsupported protocol, returns "unknown".
pub fn get_service_name(protocols: &ProtocolMap, proto: &str, port: u16) -> String {
    let port_str = port.to_string(); // Convert port number to string key

    // Lookup service in the correct protocol map
    let service = match proto {
        "tcp" => protocols.tcp.get(&port_str),
        "udp" => protocols.udp.get(&port_str),
        _ => None, // Unsupported protocol
    };

    // Return found service name or "unknown" if not found
    service
        .map(|p| p.service.as_str())
        .unwrap_or("unknown")
        .to_string()
}