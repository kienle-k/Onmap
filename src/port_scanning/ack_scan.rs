use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use pnet::packet::tcp::TcpFlags;

use super::tcp_raw_scan::{
    ScanConfig, TcpProbeBatchResult, TcpProbeOutcome, TcpProbeResult, scan_tcp_probes,
};
use crate::models::{
    PortScanAllResult, PortScanSingleResult, PortStateReasons, PortStates, Protocols,
};

const DEFAULT_READ_TIMEOUT_MS: u64 = 800;
const MAX_ACK_IN_FLIGHT: usize = 200;
const MIN_SEND_INTERVAL: Duration = Duration::ZERO;
const MAX_ACK_ATTEMPTS: u8 = 2;

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

    let single_results: Vec<PortScanSingleResult> = raw
        .results
        .iter()
        .copied()
        .map(ack_result_from_probe)
        .collect();
    for r in single_results
        .iter()
        .filter(|r| r.port_state == PortStates::Unfiltered)
    {
        log::info!(
            "Discovered unfiltered port {}/tcp on {}",
            r.port,
            r.ip_address
        );
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
