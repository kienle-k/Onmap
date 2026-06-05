//! Shared host-discovery output names.

use crate::models::{HostDiscoveryReply, PortStateReasons};

/// Returns the human-readable reply text for terminal output.
pub fn host_reply_display_name(reply: &HostDiscoveryReply) -> String {
    match reply {
        HostDiscoveryReply::NoResponse => "no response".to_string(),
        HostDiscoveryReply::Error(message) => format!("Error: {}", message),
        HostDiscoveryReply::UserSet => "user-set".to_string(),
        HostDiscoveryReply::Custom(value) => value.to_string(),
        HostDiscoveryReply::ArpReply => "ARP reply".to_string(),
        HostDiscoveryReply::IcmpEchoReply => "ICMP echo reply".to_string(),
        HostDiscoveryReply::IcmpTimestampReply => "ICMP timestamp reply".to_string(),
        HostDiscoveryReply::TcpSyn { port, reason }
        | HostDiscoveryReply::TcpConnect { port, reason } => match reason {
            PortStateReasons::SynAck => format!("SYN-ACK port {}", port),
            PortStateReasons::Reset | PortStateReasons::ConnRefused => {
                format!("RST port {}", port)
            }
            _ => format!("response port {}", port),
        },
        HostDiscoveryReply::TcpAck { port, reason } => match reason {
            PortStateReasons::Reset | PortStateReasons::Unfiltered => {
                format!("RST port {}", port)
            }
            _ => format!("response port {}", port),
        },
        HostDiscoveryReply::Udp { port, reason } => match reason {
            PortStateReasons::UdpResponse => format!("UDP response port {}", port),
            PortStateReasons::IcmpPortUnreachable => {
                format!("ICMP port unreachable port {}", port)
            }
            _ => format!("response port {}", port),
        },
    }
}

/// Returns the Nmap-compatible host status reason name.
pub fn host_reply_nmap_reason(reply: &HostDiscoveryReply) -> &'static str {
    match reply {
        HostDiscoveryReply::NoResponse | HostDiscoveryReply::Error(_) => "no-response",
        HostDiscoveryReply::UserSet => "user-set",
        HostDiscoveryReply::Custom(_) => "user-set",
        HostDiscoveryReply::ArpReply => "arp-response",
        HostDiscoveryReply::IcmpEchoReply => "echo-reply",
        HostDiscoveryReply::IcmpTimestampReply => "timestamp-reply",
        HostDiscoveryReply::TcpSyn { reason, .. }
        | HostDiscoveryReply::TcpConnect { reason, .. } => match reason {
            PortStateReasons::SynAck => "syn-ack",
            PortStateReasons::Reset => "reset",
            PortStateReasons::ConnRefused => "conn-refused",
            _ => "user-set",
        },
        HostDiscoveryReply::TcpAck { .. } => "reset",
        HostDiscoveryReply::Udp { .. } => "udp-response",
    }
}
