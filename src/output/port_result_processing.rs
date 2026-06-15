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

/// Returns the collapse threshold for non-open ports at a verbosity level; values here are nmap-behavior observations
pub fn collapse_threshold(verbosity: u8) -> usize {
    match verbosity {
        0 => 25,
        1 => 50,
        2 => 76,
        3 => 103,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{PortScanSingleResult, Protocols};
    use std::net::{IpAddr, Ipv4Addr};

    fn make_result(port: u16, state: PortStates, reason: PortStateReasons) -> PortScanSingleResult {
        PortScanSingleResult {
            ip_address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            port,
            protocol: Protocols::TCP,
            port_state: state,
            ttl: 64,
            reason,
        }
    }

    #[test]
    fn collapse_threshold_verbosity_0_is_25() {
        assert_eq!(collapse_threshold(0), 25);
    }

    #[test]
    fn collapse_threshold_verbosity_1_is_100() {
        assert_eq!(collapse_threshold(1), 100);
    }

    #[test]
    fn collapse_threshold_verbosity_2_is_1000() {
        assert_eq!(collapse_threshold(2), 1000);
    }

    #[test]
    fn collapse_threshold_verbosity_3_is_max() {
        assert_eq!(collapse_threshold(3), usize::MAX);
    }

    #[test]
    fn format_port_ranges_empty_input_returns_empty_string() {
        assert_eq!(format_port_ranges(&[]), "");
    }

    #[test]
    fn format_port_ranges_single_port() {
        assert_eq!(format_port_ranges(&[80]), "80");
    }

    #[test]
    fn format_port_ranges_consecutive_ports_collapsed_to_range() {
        assert_eq!(format_port_ranges(&[80, 81, 82]), "80-82");
    }

    #[test]
    fn format_port_ranges_non_consecutive_ports_separated_by_comma() {
        assert_eq!(format_port_ranges(&[80, 443]), "80,443");
    }

    #[test]
    fn format_port_ranges_mixed_consecutive_and_gap() {
        assert_eq!(format_port_ranges(&[80, 81, 443]), "80-81,443");
    }

    #[test]
    fn format_port_ranges_two_separate_ranges() {
        assert_eq!(format_port_ranges(&[22, 23, 80, 81]), "22-23,80-81");
    }

    #[test]
    fn protocol_name_tcp() {
        assert_eq!(protocol_name(Protocols::TCP), "tcp");
    }

    #[test]
    fn protocol_name_udp() {
        assert_eq!(protocol_name(Protocols::UDP), "udp");
    }

    #[test]
    fn protocol_display_name_tcp_uppercase() {
        assert_eq!(protocol_display_name(Protocols::TCP), "TCP");
    }

    #[test]
    fn protocol_display_name_udp_uppercase() {
        assert_eq!(protocol_display_name(Protocols::UDP), "UDP");
    }

    #[test]
    fn port_state_name_open() {
        assert_eq!(port_state_name(PortStates::Open), "open");
    }

    #[test]
    fn port_state_name_closed() {
        assert_eq!(port_state_name(PortStates::Closed), "closed");
    }

    #[test]
    fn port_state_name_filtered() {
        assert_eq!(port_state_name(PortStates::Filtered), "filtered");
    }

    #[test]
    fn port_state_name_unfiltered() {
        assert_eq!(port_state_name(PortStates::Unfiltered), "unfiltered");
    }

    #[test]
    fn port_state_name_open_or_filtered() {
        assert_eq!(port_state_name(PortStates::OpenOrFiltered), "open|filtered");
    }

    #[test]
    fn port_state_name_closed_or_filtered() {
        assert_eq!(port_state_name(PortStates::ClosedOrFiltered), "closed|filtered");
    }

    #[test]
    fn state_reason_name_syn_ack() {
        assert_eq!(state_reason_name(PortStateReasons::SynAck), "syn-ack");
    }

    #[test]
    fn state_reason_name_reset() {
        assert_eq!(state_reason_name(PortStateReasons::Reset), "reset");
    }

    #[test]
    fn state_reason_name_timeout_is_no_response() {
        assert_eq!(state_reason_name(PortStateReasons::Timeout), "no-response");
    }

    #[test]
    fn state_reason_name_conn_refused() {
        assert_eq!(state_reason_name(PortStateReasons::ConnRefused), "conn-refused");
    }

    #[test]
    fn state_reason_name_icmp_port_unreachable() {
        assert_eq!(state_reason_name(PortStateReasons::IcmpPortUnreachable), "port-unreach");
    }

    #[test]
    fn state_reason_with_ttl_appends_ttl_for_syn_ack() {
        assert_eq!(state_reason_with_ttl(PortStateReasons::SynAck, 64), "syn-ack ttl 64");
    }

    #[test]
    fn state_reason_with_ttl_omits_ttl_for_timeout() {
        assert_eq!(state_reason_with_ttl(PortStateReasons::Timeout, 64), "no-response");
    }

    #[test]
    fn state_reason_with_ttl_omits_ttl_for_icmp_port_unreachable() {
        assert_eq!(
            state_reason_with_ttl(PortStateReasons::IcmpPortUnreachable, 64),
            "port-unreach"
        );
    }

    #[test]
    fn ttl_display_value_zero_returns_dash() {
        assert_eq!(ttl_display_value(0), "-");
    }

    #[test]
    fn ttl_display_value_nonzero_returns_number() {
        assert_eq!(ttl_display_value(64), "64");
    }

    #[test]
    fn extraport_reason_name_syn_ack_is_plural() {
        assert_eq!(extraport_reason_name(PortStateReasons::SynAck), "syn-acks");
    }

    #[test]
    fn extraport_reason_name_reset_is_plural() {
        assert_eq!(extraport_reason_name(PortStateReasons::Reset), "resets");
    }

    #[test]
    fn extraport_reason_name_timeout_is_plural() {
        assert_eq!(extraport_reason_name(PortStateReasons::Timeout), "no-responses");
    }

    #[test]
    fn extraport_reason_name_icmp_port_unreachable_is_plural() {
        assert_eq!(
            extraport_reason_name(PortStateReasons::IcmpPortUnreachable),
            "port-unreaches"
        );
    }

    /// Open ports are always individually shown, never collapsed.
    #[test]
    fn summarize_ports_open_ports_always_shown() {
        let results: Vec<PortScanSingleResult> =
            (0u16..50).map(|i| make_result(i, PortStates::Open, PortStateReasons::SynAck)).collect();
        let refs: Vec<&PortScanSingleResult> = results.iter().collect();
        let summary = summarize_ports(&refs, 0);
        assert_eq!(summary.shown.len(), 50);
        assert!(summary.extra.is_empty());
    }

    /// Non-open ports below the threshold are shown individually.
    #[test]
    fn summarize_ports_few_closed_ports_are_shown() {
        let results: Vec<PortScanSingleResult> =
            (0u16..10).map(|i| make_result(i, PortStates::Closed, PortStateReasons::Reset)).collect();
        let refs: Vec<&PortScanSingleResult> = results.iter().collect();
        let summary = summarize_ports(&refs, 0);
        // 10 < threshold(25), so all are shown individually
        assert_eq!(summary.shown.len(), 10);
        assert!(summary.extra.is_empty());
    }

    /// Non-open ports exceeding the threshold are collapsed into an extra group.
    #[test]
    fn summarize_ports_many_closed_ports_are_collapsed() {
        let results: Vec<PortScanSingleResult> =
            (0u16..30).map(|i| make_result(i, PortStates::Closed, PortStateReasons::Reset)).collect();
        let refs: Vec<&PortScanSingleResult> = results.iter().collect();
        let summary = summarize_ports(&refs, 0);
        // 30 > threshold(25), so they collapse
        assert!(summary.shown.is_empty());
        assert_eq!(summary.extra.len(), 1);
        assert_eq!(summary.extra[0].count, 30);
    }

    /// Collapsed group state must match the collapsed port state.
    #[test]
    fn summarize_ports_extra_group_has_correct_state() {
        let results: Vec<PortScanSingleResult> =
            (0u16..30).map(|i| make_result(i, PortStates::Filtered, PortStateReasons::Timeout)).collect();
        let refs: Vec<&PortScanSingleResult> = results.iter().collect();
        let summary = summarize_ports(&refs, 0);
        assert_eq!(summary.extra[0].state, PortStates::Filtered);
    }

    /// Shown ports must be sorted ascending by port number.
    #[test]
    fn summarize_ports_shown_sorted_by_port_number() {
        let r1 = make_result(443, PortStates::Open, PortStateReasons::SynAck);
        let r2 = make_result(80, PortStates::Open, PortStateReasons::SynAck);
        let r3 = make_result(22, PortStates::Open, PortStateReasons::SynAck);
        let refs = vec![&r1, &r2, &r3];
        let summary = summarize_ports(&refs, 0);
        let ports: Vec<u16> = summary.shown.iter().map(|r| r.port).collect();
        assert_eq!(ports, vec![22, 80, 443]);
    }

    /// Higher verbosity raises the collapse threshold so more ports stay visible.
    #[test]
    fn summarize_ports_higher_verbosity_raises_threshold() {
        // 30 closed: collapsed at verbosity 0, shown at verbosity 1 (threshold=100)
        let results: Vec<PortScanSingleResult> =
            (0u16..30).map(|i| make_result(i, PortStates::Closed, PortStateReasons::Reset)).collect();
        let refs: Vec<&PortScanSingleResult> = results.iter().collect();
        let summary = summarize_ports(&refs, 1);
        assert_eq!(summary.shown.len(), 30);
        assert!(summary.extra.is_empty());
    }
}
