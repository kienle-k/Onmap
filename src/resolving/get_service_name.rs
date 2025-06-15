use std::collections::HashMap;
use serde::Deserialize;

// #[derive(Deserialize)]
// pub struct ProtocolMap {
//     tcp: HashMap<String, String>,
//     udp: HashMap<String, String>,
// }

// pub fn get_service_name(protocols: &ProtocolMap, proto: &str, port: u16) -> String {
//     let port_str = port.to_string();
//     match proto {
//         "tcp" => protocols.tcp.get(&port_str).map(|s| s.to_string()).unwrap_or_else(|| "unknown".to_string()),
//         "udp" => protocols.udp.get(&port_str).map(|s| s.to_string()).unwrap_or_else(|| "unknown".to_string()),
//         _ => "unknown".to_string(),
//     }
// }

#[derive(Deserialize)]
pub struct PortService {
    service: String,
    //pservice: String,
}

#[derive(Deserialize)]
pub struct ProtocolMap {
    tcp: HashMap<String, PortService>,
    udp: HashMap<String, PortService>,
}


pub fn load_protocol_map(path: &str) -> Result<ProtocolMap, Box<dyn std::error::Error>> {
    let json_str = std::fs::read_to_string(path)?;
    let protocols: ProtocolMap = serde_json::from_str(&json_str)?;
    Ok(protocols)
}

pub fn get_service_name(protocols: &ProtocolMap, proto: &str, port: u16) -> String {
    let port_str = port.to_string();
    match proto {
        "tcp" => protocols.tcp.get(&port_str)
                     .map(|p| p.service.clone())  // or p.pservice.clone()
                     .unwrap_or_else(|| "unknown".to_string()),
        "udp" => protocols.udp.get(&port_str)
                     .map(|p| p.service.clone())
                     .unwrap_or_else(|| "unknown".to_string()),
        _ => "unknown".to_string(),
    }
}