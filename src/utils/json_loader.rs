use std::collections::HashMap;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct PortInfo {
    pub service: String,
}

#[derive(Debug, Deserialize)]
pub struct Protocols {
    pub tcp: HashMap<String, PortInfo>,
    pub udp: HashMap<String, PortInfo>,
}

pub fn load_protocols(path: &str) -> Result<Protocols, Box<dyn std::error::Error>> {
    let file_content = std::fs::read_to_string(path)?;
    let protocols: Protocols = serde_json::from_str(&file_content)?;
    Ok(protocols)
}

pub fn get_port_info<'a>(
    protocols: &'a Protocols,
    proto: &str,
    port: &str,
) -> Option<&'a PortInfo> {
    match proto {
        "tcp" => protocols.tcp.get(port),
        "udp" => protocols.udp.get(port),
        _ => None,
    }
}
