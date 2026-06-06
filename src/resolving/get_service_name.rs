use crate::models::Protocols;

include!(concat!(env!("OUT_DIR"), "/services_generated.rs"));

/// Returns the service name for a given protocol and port.
pub fn get_service_name(protocol: Protocols, port: u16) -> &'static str {
    let service_id = match protocol {
        Protocols::TCP => TCP_SERVICE_IDS[port as usize],
        Protocols::UDP => UDP_SERVICE_IDS[port as usize],
    };

    SERVICE_NAMES[service_id as usize]
}
