use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use pnet::packet::tcp::TcpFlags;

use super::tcp_raw_scan::{
    ScanConfig, TcpProbeBatchResult, TcpProbeOutcome, TcpProbeResult, scan_tcp_probes,
};
use crate::models::{
    PortScanAllResult, PortScanSingleResult, PortStateReasons, PortStates, Protocols,
};

/// ACK scan defaults.
const DEFAULT_READ_TIMEOUT_MS: u64 = 800;
const MAX_ACK_IN_FLIGHT: usize = 200;
/// Window-only throttle (no per-send delay); pacing is available but unused.
const MIN_SEND_INTERVAL: Duration = Duration::ZERO;
/// Retransmit a timed-out probe once before declaring `filtered`. The target
/// rate-limits RST emission, so some RSTs are never sent under our burst and a
/// single pass mislabels those ports; re-asking after the rate-limit window
/// recovers them. Verified consistent (20/20 runs all-unfiltered) on
/// scanme.nmap.org with the full 800 ms retry window.
const MAX_ACK_ATTEMPTS: u8 = 2;

/// Maps one raw probe outcome to an ACK-scan port state: an RST means the port
/// is unfiltered; anything else (or no reply) means filtered.
fn ack_result_from_probe(probe: TcpProbeResult) -> PortScanSingleResult {
    let (port_state, reason) = match probe.outcome {
        TcpProbeOutcome::Reply { flags } if flags & TcpFlags::RST != 0 => {
            (PortStates::Unfiltered, PortStateReasons::Unfiltered)
        }
        TcpProbeOutcome::Reply { .. } | TcpProbeOutcome::Timeout => {
            (PortStates::Filtered, PortStateReasons::Timeout)
        }
    };

    PortScanSingleResult {
        ip_address: IpAddr::V4(probe.ip_address),
        port: probe.port,
        protocol: Protocols::TCP,
        port_state,
        ttl: 0,
        reason,
    }
}

/// Orchestrates a TCP ACK scan across multiple IPs and ports.
///
/// Probes are sent through the shared, paced raw-socket engine in
/// [`super::tcp_raw_scan`]; this function only chooses the ACK flag and maps the
/// engine's raw outcomes to port states. An ACK scan finds *unfiltered* ports,
/// so the summary's `open_ports` list is always empty.
///
/// # Arguments
///
/// * `ip_addresses` - `(target, source)` IPv4 pairs to scan.
/// * `ports` - port numbers to scan on each target.
/// * `timeout_override_ms` - optional per-probe receive timeout in milliseconds.
///
/// # Returns
///
/// On success, the per-port results and an aggregate [`PortScanAllResult`].
///
/// # Errors
///
/// Requires root to open a raw socket; returns `Err` if the channel cannot be created.
pub async fn run_ack_scan(
    ip_addresses: Vec<(Ipv4Addr, Ipv4Addr)>,
    ports: &[u16],
    timeout_override_ms: Option<u64>,
) -> Result<(Vec<PortScanSingleResult>, PortScanAllResult), String> {
    let config = ScanConfig {
        timeout: Duration::from_millis(timeout_override_ms.unwrap_or(DEFAULT_READ_TIMEOUT_MS)),
        max_in_flight: MAX_ACK_IN_FLIGHT,
        min_send_interval: MIN_SEND_INTERVAL,
        max_attempts: MAX_ACK_ATTEMPTS,
    };
    let raw = scan_tcp_probes(ip_addresses, ports.to_vec(), TcpFlags::ACK, config).await?;

    let single_results: Vec<PortScanSingleResult> =
        raw.results.iter().copied().map(ack_result_from_probe).collect();
    for r in single_results.iter().filter(|r| r.port_state == PortStates::Unfiltered) {
        log::info!("Discovered unfiltered port {}/tcp on {}", r.port, r.ip_address);
    }

    Ok((single_results, ack_scan_summary(&raw)))
}

fn ack_scan_summary(raw: &TcpProbeBatchResult) -> PortScanAllResult {
    PortScanAllResult {
        ports_scanned: raw.ports_scanned as u16,
        packets_sent: raw.packets_sent,
        open_ports: Vec::new(),
        start_time: raw.start_time,
        end_time: raw.end_time,
        scan_type: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_run_ack_scan_empty_ips() {
        let (single_results, all_result) = run_ack_scan(Vec::new(), &[80], None)
            .await
            .expect("empty scan should succeed");
        assert!(single_results.is_empty());
        assert_eq!(all_result.packets_sent, 0);
        assert!(all_result.open_ports.is_empty());
    }
}
