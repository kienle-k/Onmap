use std::collections::HashMap;
use std::sync::OnceLock;

use serde::Deserialize;

/// Represents a network service mapped to a port.
#[derive(Clone, Deserialize)]
pub struct PortService {
    /// Name of the service (e.g., "http", "ssh").
    service: String,
    // pservice: String, // Optional protocol service name (but not used
    //-> can be added in the future, as it is present a a parameter in the file)
}

/// Holds port-to-service mappings for TCP and UDP.
#[derive(Clone, Deserialize)]
pub struct ServiceMap {
    /// TCP port to service mapping.
    tcp: HashMap<String, PortService>,
    /// UDP port to service mapping.
    udp: HashMap<String, PortService>,
}

/// Loads the service map from a JSON file at the given path.
///
/// Returns the parsed `ServiceMap` or an error with context.
pub fn load_service_map(_path: &str) -> Result<ServiceMap, Box<dyn std::error::Error>> {
    static SERVICE_MAP: OnceLock<Result<ServiceMap, String>> = OnceLock::new();

    let service_map = SERVICE_MAP.get_or_init(|| {
        serde_json::from_str(include_str!("port_service_mapping.json"))
            .map_err(|e| format!("Failed to parse embedded service map JSON: {}", e))
    });

    match service_map {
        Ok(service_map) => Ok(service_map.clone()),
        Err(e) => Err(e.clone().into()),
    }
}

// Old version of the json loader
// pub fn load_service_map(path: &str) -> Result<ServiceMap, Box<dyn std::error::Error>> {
//     let json_str = std::fs::read_to_string(path)?;
//     let service_map: ServiceMap = serde_json::from_str(&json_str)?;
//     Ok(service_map)
// }

/// Returns the service name for a given protocol and port.
/// If not found or unsupported protocol, returns "unknown".
pub fn get_service_name(service_map: &ServiceMap, proto: &str, port: u16) -> String {
    let port_str = port.to_string(); // Convert port number to string key

    // Lookup service in the correct service map
    let service = match proto {
        "tcp" => service_map.tcp.get(&port_str),
        "udp" => service_map.udp.get(&port_str),
        _ => None, // Unsupported protocol
    };

    // Return found service name or "unknown" if not found
    service
        .map(|p| p.service.as_str())
        .unwrap_or("unknown")
        .to_string()
}
