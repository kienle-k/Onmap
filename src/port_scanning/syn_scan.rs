use pnet::packet::tcp::TcpFlags;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use super::tcp_raw_scan::{
    ScanConfig, TcpProbeBatchResult, TcpProbeOutcome, TcpProbeResult, scan_tcp_probes,
};
use crate::models::{
    PortScanAllResult, PortScanSingleResult, PortStateReasons, PortStates, Protocols,
};

const DEFAULT_READ_TIMEOUT_MS: u64 = 1000;
const MAX_SYN_IN_FLIGHT: usize = 100;
const MIN_SEND_INTERVAL: Duration = Duration::from_micros(2); //Duration::ZERO;
const MAX_SYN_ATTEMPTS: u8 = 1;

fn syn_result_from_probe(probe: TcpProbeResult) -> PortScanSingleResult {
    let (port_state, reason) = match probe.outcome {
        TcpProbeOutcome::Reply { flags }
            if flags & TcpFlags::SYN != 0 && flags & TcpFlags::ACK != 0 =>
        {
            (PortStates::Open, PortStateReasons::SynAck)
        }
        TcpProbeOutcome::Reply { flags } if flags & TcpFlags::RST != 0 => {
            (PortStates::Closed, PortStateReasons::Reset)
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

pub async fn run_syn_scan(
    ip_addresses: Vec<(Ipv4Addr, Ipv4Addr)>,
    ports_arr: Vec<u16>,
    timeout_override_ms: Option<u64>,
) -> Result<(Vec<PortScanSingleResult>, PortScanAllResult), String> {
    let config = ScanConfig {
        timeout: Duration::from_millis(timeout_override_ms.unwrap_or(DEFAULT_READ_TIMEOUT_MS)),
        max_in_flight: MAX_SYN_IN_FLIGHT,
        min_send_interval: MIN_SEND_INTERVAL,
        max_attempts: MAX_SYN_ATTEMPTS,
    };
    let raw = scan_tcp_probes(ip_addresses, ports_arr, TcpFlags::SYN, config).await?;

    let single_results: Vec<PortScanSingleResult> = raw
        .results
        .iter()
        .copied()
        .map(syn_result_from_probe)
        .collect();
    let open_ports = single_results
        .iter()
        .filter(|r| r.port_state == PortStates::Open)
        .map(|r| {
            log::info!("Discovered open port {}/tcp on {}", r.port, r.ip_address);
            r.port
        })
        .collect();

    Ok((single_results, syn_scan_summary(&raw, open_ports)))
}

fn syn_scan_summary(raw: &TcpProbeBatchResult, open_ports: Vec<u16>) -> PortScanAllResult {
    PortScanAllResult {
        ports_scanned: raw.ports_scanned as u32,
        packets_sent: raw.packets_sent,
        open_ports,
        start_time: raw.start_time,
        end_time: raw.end_time,
        scan_type: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_run_syn_scan_empty_ips() {
        let ips: Vec<(Ipv4Addr, Ipv4Addr)> = Vec::new();
        let ports = vec![80];

        let result = run_syn_scan(ips, ports, None).await;

        assert!(result.is_ok());
        let (single_results, all_result) = result.expect("Expected empty scan to succeed");
        assert!(single_results.is_empty());
        assert_eq!(all_result.packets_sent, 0);
        assert!(all_result.open_ports.is_empty());
    }

    fn probe(outcome: TcpProbeOutcome) -> TcpProbeResult {
        TcpProbeResult {
            ip_address: Ipv4Addr::new(10, 0, 0, 1),
            port: 80,
            outcome,
            latency: Duration::ZERO,
        }
    }

    #[test]
    fn syn_ack_reply_is_open() {
        let r = syn_result_from_probe(probe(TcpProbeOutcome::Reply {
            flags: TcpFlags::SYN | TcpFlags::ACK,
        }));
        assert_eq!(r.port_state, PortStates::Open);
        assert_eq!(r.reason, PortStateReasons::SynAck);
    }

    #[test]
    fn rst_reply_is_closed() {
        let r = syn_result_from_probe(probe(TcpProbeOutcome::Reply {
            flags: TcpFlags::RST,
        }));
        assert_eq!(r.port_state, PortStates::Closed);
        assert_eq!(r.reason, PortStateReasons::Reset);
    }

    #[test]
    fn timeout_is_filtered() {
        let r = syn_result_from_probe(probe(TcpProbeOutcome::Timeout));
        assert_eq!(r.port_state, PortStates::Filtered);
        assert_eq!(r.reason, PortStateReasons::Timeout);
    }
}
