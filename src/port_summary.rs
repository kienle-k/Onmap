//! Shared port-summary logic for both terminal and XML output.
//!
//! Implements Nmap's "ignored state" rule once, so the console printer and the
//! XML writer differ only in rendering, never in *which* ports get collapsed:
//! `open` is never collapsed; any other state is collapsed into an extraports
//! group when it has more ports than the verbosity-dependent threshold.

use std::collections::HashMap;

use crate::models::{PortScanSingleResult, PortStateReasons, PortStates, Protocols};

/// One collapsed (`<extraports>` / "Not shown") state group.
pub struct ExtraPortsGroup {
    pub state: PortStates,
    pub proto: Protocols,
    pub count: usize,
    /// Reason → exact ports (sorted), so membership is fully recoverable.
    pub reasons: Vec<(PortStateReasons, Vec<u16>)>,
}

/// Result of splitting a host's ports into individually-shown vs collapsed.
pub struct PortSummary<'a> {
    /// Ports listed individually (sorted by port), always including `open`.
    pub shown: Vec<&'a PortScanSingleResult>,
    /// Collapsed state groups, sorted by count descending.
    pub extra: Vec<ExtraPortsGroup>,
}

/// Minimum port count above which a non-open state is collapsed. Mirrors Nmap:
/// 25 by default, raised by `-v`, and effectively disabled at `-vvv` and above.
pub fn collapse_threshold(verbosity: u8) -> usize {
    match verbosity {
        0 => 25,
        1 => 100,
        2 => 1000,
        _ => usize::MAX,
    }
}

/// Split a host's port results into shown vs collapsed per the threshold rule.
pub fn summarize_ports<'a>(results: &[&'a PortScanSingleResult], verbosity: u8) -> PortSummary<'a> {
    let threshold = collapse_threshold(verbosity);

    let mut by_state: HashMap<PortStates, Vec<&'a PortScanSingleResult>> = HashMap::new();
    for r in results {
        by_state.entry(r.port_state).or_default().push(r);
    }

    let mut shown = Vec::new();
    let mut extra = Vec::new();

    for (state, ports) in by_state {
        // `open` is never collapsed; everything else collapses once it exceeds
        // the threshold.
        if state == PortStates::Open || ports.len() <= threshold {
            shown.extend(ports);
            continue;
        }

        let proto = ports[0].protocol;
        let mut reason_ports: HashMap<PortStateReasons, Vec<u16>> = HashMap::new();
        for r in &ports {
            reason_ports.entry(r.reason).or_default().push(r.port);
        }
        let mut reasons: Vec<(PortStateReasons, Vec<u16>)> = reason_ports
            .into_iter()
            .map(|(reason, mut ps)| {
                ps.sort_unstable();
                (reason, ps)
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

    shown.sort_unstable_by_key(|r| r.port);
    // Largest groups first, with state name as a stable tiebreaker.
    extra.sort_unstable_by(|a, b| {
        b.count
            .cmp(&a.count)
            .then_with(|| port_state_name(a.state).cmp(port_state_name(b.state)))
    });

    PortSummary { shown, extra }
}

/// Compress a sorted port list into Nmap-style ranges, e.g. `22,79-81,443`.
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

pub fn protocol_name(protocol: Protocols) -> &'static str {
    match protocol {
        Protocols::TCP => "tcp",
        Protocols::UDP => "udp",
    }
}

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

/// Singular reason name, used by `<state reason>` and the CLI "Not shown" line.
pub fn state_reason_name(reason: PortStateReasons) -> &'static str {
    match reason {
        PortStateReasons::SynAck => "syn-ack",
        PortStateReasons::Reset | PortStateReasons::Unfiltered => "reset",
        PortStateReasons::Timeout => "no-response",
        PortStateReasons::UdpResponse => "udp-response",
        PortStateReasons::IcmpPortUnreachable => "port-unreach",
    }
}

/// Plural reason name, used by `<extrareasons reason>`.
pub fn extraport_reason_name(reason: PortStateReasons) -> &'static str {
    match reason {
        PortStateReasons::SynAck => "syn-acks",
        PortStateReasons::Reset | PortStateReasons::Unfiltered => "resets",
        PortStateReasons::Timeout => "no-responses",
        PortStateReasons::UdpResponse => "udp-responses",
        PortStateReasons::IcmpPortUnreachable => "port-unreaches",
    }
}
