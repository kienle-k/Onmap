//! Shared port-result processing for terminal and file output.
//!
//! Keeps port grouping and output names in one place so output styles do not
//! duplicate state, protocol, and reason mappings.

use std::collections::HashMap;

use crate::models::{PortScanSingleResult, PortStateReasons, PortStates, Protocols};

/// Collapsed non-open ports for one state/protocol group.
pub struct ExtraPortsGroup {
    pub state: PortStates,
    pub proto: Protocols,
    pub count: usize,
    /// Reason -> exact ports, sorted so membership is recoverable.
    pub reasons: Vec<(PortStateReasons, Vec<u16>)>,
}

/// Port rows split into shown rows and collapsed groups.
pub struct PortSummary<'a> {
    /// Ports listed individually, sorted by port.
    pub shown: Vec<&'a PortScanSingleResult>,
    /// Collapsed groups, sorted by count descending.
    pub extra: Vec<ExtraPortsGroup>,
}

/// Returns the collapse threshold for non-open ports at a verbosity level.
pub fn collapse_threshold(verbosity: u8) -> usize {
    match verbosity {
        0 => 25,
        1 => 100,
        2 => 1000,
        _ => usize::MAX,
    }
}

/// Groups host port results into individually shown rows and collapsed groups.
pub fn summarize_ports<'a>(results: &[&'a PortScanSingleResult], verbosity: u8) -> PortSummary<'a> {
    let threshold = collapse_threshold(verbosity);

    let mut by_state: HashMap<PortStates, Vec<&'a PortScanSingleResult>> = HashMap::new();
    for port_result in results {
        by_state
            .entry(port_result.port_state)
            .or_default()
            .push(port_result);
    }

    let mut shown = Vec::new();
    let mut extra = Vec::new();

    for (state, ports) in by_state {
        // Nmap keeps open ports visible and collapses large non-open groups.
        if state == PortStates::Open || ports.len() <= threshold {
            shown.extend(ports);
            continue;
        }

        let proto = ports[0].protocol;
        let mut reason_ports: HashMap<PortStateReasons, Vec<u16>> = HashMap::new();
        for port_result in &ports {
            reason_ports
                .entry(port_result.reason)
                .or_default()
                .push(port_result.port);
        }
        let mut reasons: Vec<(PortStateReasons, Vec<u16>)> = reason_ports
            .into_iter()
            .map(|(reason, mut ports)| {
                ports.sort_unstable();
                (reason, ports)
            })
            .collect();
        reasons.sort_unstable_by_key(|(reason, _)| extraport_reason_name(*reason));

        extra.push(ExtraPortsGroup {
            state,
            proto,
            count: ports.len(),
            reasons,
        });
    }

    shown.sort_unstable_by_key(|port_result| port_result.port);
    // Largest groups first, with state name as a stable tiebreaker.
    extra.sort_unstable_by(|left, right| {
        right
            .count
            .cmp(&left.count)
            .then_with(|| port_state_name(left.state).cmp(port_state_name(right.state)))
    });

    PortSummary { shown, extra }
}

/// Formats sorted port numbers as Nmap-style ranges.
pub fn format_port_ranges(ports: &[u16]) -> String {
    if ports.is_empty() {
        return String::new();
    }

    let mut ranges = Vec::new();
    let mut start = ports[0];
    let mut end = ports[0];

    for &port in ports.iter().skip(1) {
        if port == end + 1 {
            end = port;
            continue;
        }
        ranges.push(range_str(start, end));
        start = port;
        end = port;
    }
    ranges.push(range_str(start, end));
    ranges.join(",")
}

fn range_str(start: u16, end: u16) -> String {
    if start == end {
        start.to_string()
    } else {
        format!("{}-{}", start, end)
    }
}

/// Returns the protocol name used in file output.
pub fn protocol_name(protocol: Protocols) -> &'static str {
    match protocol {
        Protocols::TCP => "tcp",
        Protocols::UDP => "udp",
    }
}

/// Returns the protocol name used in terminal tables.
pub fn protocol_display_name(protocol: Protocols) -> &'static str {
    match protocol {
        Protocols::TCP => "TCP",
        Protocols::UDP => "UDP",
    }
}

/// Returns the canonical lowercase port state name.
pub fn port_state_name(state: PortStates) -> &'static str {
    match state {
        PortStates::Open => "open",
        PortStates::Closed => "closed",
        PortStates::Filtered => "filtered",
        PortStates::Unfiltered => "unfiltered",
        PortStates::OpenOrFiltered => "open|filtered",
        PortStates::ClosedOrFiltered => "closed|filtered",
    }
}

/// Returns the canonical singular reason name.
pub fn state_reason_name(reason: PortStateReasons) -> &'static str {
    match reason {
        PortStateReasons::SynAck => "syn-ack",
        PortStateReasons::Reset | PortStateReasons::Unfiltered => "reset",
        PortStateReasons::Timeout => "no-response",
        PortStateReasons::UdpResponse => "udp-response",
        PortStateReasons::IcmpPortUnreachable => "port-unreach",
        PortStateReasons::ConnRefused => "conn-refused",
        PortStateReasons::HostUnreachable => "host-unreach",
        PortStateReasons::NetworkUnreachable => "net-unreach",
        PortStateReasons::AdminProhibited => "admin-prohibited",
    }
}

/// Returns the human-readable reason name for terminal tables.
pub fn state_reason_display_name(reason: PortStateReasons) -> &'static str {
    match reason {
        PortStateReasons::SynAck => "SYN-ACK",
        PortStateReasons::Reset => "RST",
        PortStateReasons::UdpResponse => "UDP Response",
        PortStateReasons::IcmpPortUnreachable => "ICMP Port Unreachable",
        PortStateReasons::Unfiltered => "Unfiltered",
        PortStateReasons::Timeout => "Timeout",
        PortStateReasons::ConnRefused => "Connection Refused",
        PortStateReasons::HostUnreachable => "Host Unreachable",
        PortStateReasons::NetworkUnreachable => "Network Unreachable",
        PortStateReasons::AdminProhibited => "Admin Prohibited",
    }
}

/// Formats a reason with TTL when that mirrors Nmap's reason output.
pub fn state_reason_with_ttl(reason: PortStateReasons, ttl: u8) -> String {
    match reason {
        PortStateReasons::Timeout | PortStateReasons::IcmpPortUnreachable => {
            state_reason_name(reason).to_string()
        }
        _ => format!("{} ttl {}", state_reason_name(reason), ttl),
    }
}

/// Formats TTL for outputs where zero means not applicable.
pub fn ttl_display_value(ttl: u8) -> String {
    if ttl == 0 {
        "-".to_string()
    } else {
        ttl.to_string()
    }
}

/// Returns the plural reason name used by collapsed port groups.
pub fn extraport_reason_name(reason: PortStateReasons) -> &'static str {
    match reason {
        PortStateReasons::SynAck => "syn-acks",
        PortStateReasons::Reset | PortStateReasons::Unfiltered => "resets",
        PortStateReasons::Timeout => "no-responses",
        PortStateReasons::UdpResponse => "udp-responses",
        PortStateReasons::IcmpPortUnreachable => "port-unreaches",
        PortStateReasons::ConnRefused => "conn-refused",
        PortStateReasons::HostUnreachable => "host-unreaches",
        PortStateReasons::NetworkUnreachable => "net-unreaches",
        PortStateReasons::AdminProhibited => "admin-prohibiteds",
    }
}
