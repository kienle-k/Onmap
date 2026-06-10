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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_no_response() {
        assert_eq!(host_reply_display_name(&HostDiscoveryReply::NoResponse), "no response");
    }

    #[test]
    fn display_error_includes_message() {
        let reply = HostDiscoveryReply::Error("timeout".to_string());
        assert_eq!(host_reply_display_name(&reply), "Error: timeout");
    }

    #[test]
    fn display_user_set() {
        assert_eq!(host_reply_display_name(&HostDiscoveryReply::UserSet), "user-set");
    }

    #[test]
    fn display_custom_returns_value() {
        let reply = HostDiscoveryReply::Custom("my-probe".to_string());
        assert_eq!(host_reply_display_name(&reply), "my-probe");
    }

    #[test]
    fn display_arp_reply() {
        assert_eq!(host_reply_display_name(&HostDiscoveryReply::ArpReply), "ARP reply");
    }

    #[test]
    fn display_icmp_echo_reply() {
        assert_eq!(host_reply_display_name(&HostDiscoveryReply::IcmpEchoReply), "ICMP echo reply");
    }

    #[test]
    fn display_icmp_timestamp_reply() {
        assert_eq!(
            host_reply_display_name(&HostDiscoveryReply::IcmpTimestampReply),
            "ICMP timestamp reply"
        );
    }

    #[test]
    fn display_tcp_syn_synack_includes_port() {
        let reply = HostDiscoveryReply::TcpSyn { port: 80, reason: PortStateReasons::SynAck };
        assert_eq!(host_reply_display_name(&reply), "SYN-ACK port 80");
    }

    #[test]
    fn display_tcp_syn_reset_includes_port() {
        let reply = HostDiscoveryReply::TcpSyn { port: 443, reason: PortStateReasons::Reset };
        assert_eq!(host_reply_display_name(&reply), "RST port 443");
    }

    #[test]
    fn display_tcp_syn_conn_refused_shown_as_rst() {
        let reply = HostDiscoveryReply::TcpSyn { port: 22, reason: PortStateReasons::ConnRefused };
        assert_eq!(host_reply_display_name(&reply), "RST port 22");
    }

    #[test]
    fn display_tcp_connect_synack_includes_port() {
        let reply = HostDiscoveryReply::TcpConnect { port: 80, reason: PortStateReasons::SynAck };
        assert_eq!(host_reply_display_name(&reply), "SYN-ACK port 80");
    }

    #[test]
    fn display_tcp_ack_reset_includes_port() {
        let reply = HostDiscoveryReply::TcpAck { port: 80, reason: PortStateReasons::Reset };
        assert_eq!(host_reply_display_name(&reply), "RST port 80");
    }

    #[test]
    fn display_tcp_ack_unfiltered_shown_as_rst() {
        let reply = HostDiscoveryReply::TcpAck { port: 80, reason: PortStateReasons::Unfiltered };
        assert_eq!(host_reply_display_name(&reply), "RST port 80");
    }

    #[test]
    fn display_udp_response_includes_port() {
        let reply = HostDiscoveryReply::Udp { port: 53, reason: PortStateReasons::UdpResponse };
        assert_eq!(host_reply_display_name(&reply), "UDP response port 53");
    }

    #[test]
    fn display_udp_icmp_port_unreachable_includes_port() {
        let reply = HostDiscoveryReply::Udp { port: 53, reason: PortStateReasons::IcmpPortUnreachable };
        assert_eq!(host_reply_display_name(&reply), "ICMP port unreachable port 53");
    }

    #[test]
    fn nmap_reason_no_response() {
        assert_eq!(host_reply_nmap_reason(&HostDiscoveryReply::NoResponse), "no-response");
    }

    #[test]
    fn nmap_reason_error_is_no_response() {
        assert_eq!(
            host_reply_nmap_reason(&HostDiscoveryReply::Error("x".to_string())),
            "no-response"
        );
    }

    #[test]
    fn nmap_reason_user_set() {
        assert_eq!(host_reply_nmap_reason(&HostDiscoveryReply::UserSet), "user-set");
    }

    #[test]
    fn nmap_reason_custom_is_user_set() {
        assert_eq!(
            host_reply_nmap_reason(&HostDiscoveryReply::Custom("x".to_string())),
            "user-set"
        );
    }

    #[test]
    fn nmap_reason_arp_reply() {
        assert_eq!(host_reply_nmap_reason(&HostDiscoveryReply::ArpReply), "arp-response");
    }

    #[test]
    fn nmap_reason_icmp_echo_reply() {
        assert_eq!(host_reply_nmap_reason(&HostDiscoveryReply::IcmpEchoReply), "echo-reply");
    }

    #[test]
    fn nmap_reason_icmp_timestamp_reply() {
        assert_eq!(
            host_reply_nmap_reason(&HostDiscoveryReply::IcmpTimestampReply),
            "timestamp-reply"
        );
    }

    #[test]
    fn nmap_reason_tcp_syn_synack() {
        let reply = HostDiscoveryReply::TcpSyn { port: 80, reason: PortStateReasons::SynAck };
        assert_eq!(host_reply_nmap_reason(&reply), "syn-ack");
    }

    #[test]
    fn nmap_reason_tcp_syn_reset() {
        let reply = HostDiscoveryReply::TcpSyn { port: 80, reason: PortStateReasons::Reset };
        assert_eq!(host_reply_nmap_reason(&reply), "reset");
    }

    #[test]
    fn nmap_reason_tcp_syn_conn_refused() {
        let reply = HostDiscoveryReply::TcpSyn { port: 80, reason: PortStateReasons::ConnRefused };
        assert_eq!(host_reply_nmap_reason(&reply), "conn-refused");
    }

    #[test]
    fn nmap_reason_tcp_connect_synack() {
        let reply = HostDiscoveryReply::TcpConnect { port: 80, reason: PortStateReasons::SynAck };
        assert_eq!(host_reply_nmap_reason(&reply), "syn-ack");
    }

    #[test]
    fn nmap_reason_tcp_ack_always_reset() {
        let reply = HostDiscoveryReply::TcpAck { port: 80, reason: PortStateReasons::Unfiltered };
        assert_eq!(host_reply_nmap_reason(&reply), "reset");
    }

    #[test]
    fn nmap_reason_udp_always_udp_response() {
        let reply = HostDiscoveryReply::Udp { port: 53, reason: PortStateReasons::UdpResponse };
        assert_eq!(host_reply_nmap_reason(&reply), "udp-response");
    }
}
