//! # Shared TCP Raw Scan Engine
//!
//! One paced send/receive loop shared by every TCP raw scan (SYN, ACK). It
//! opens a single raw transport channel for the whole run, sends probes at a
//! bounded rate, and demultiplexes replies back to the probe that asked for
//! them. The previous design opened one channel and one receive loop *per
//! port*, which both scaled badly and lost fast replies under concurrency.
//!
//! ## Responsibilities
//!
//! This module is pure mechanism. It does not know SYN from ACK: callers pass
//! the TCP flags to send and receive raw [`TcpProbeOutcome`]s back, then map
//! those to port states themselves. SYN/ACK policy stays in their own modules.
//!
//! ## Why pacing
//!
//! "No reply" is ambiguous: it can mean filtered, or it can mean we sent faster
//! than the target (or the local kernel, on loopback) would answer. The Linux
//! stack rate-limits some replies (e.g. `net.ipv4.tcp_invalid_ratelimit` for
//! RSTs), so a tight burst drops replies that then look like timeouts. Pacing
//! sends to a sustained rate keeps loss rare, which fixes both throughput and
//! the false-`filtered` results in one mechanism.

use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::tcp::MutableTcpPacket;
use pnet::transport::{
    TransportChannelType, TransportProtocol, TransportSender, tcp_packet_iter, transport_channel,
};
use rand::Rng;
use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant, SystemTime};

/// pnet maps the receive timeout onto the socket's `SO_RCVTIMEO`, and a zero
/// `timeval` means "block forever" on Linux. We must never pass zero, or the
/// loop stalls until an unrelated packet arrives. Floor the wait here.
const MIN_RECEIVE_TIMEOUT: Duration = Duration::from_millis(1);

/// Tuning knobs supplied once by the calling scan, so adding a knob never
/// changes a function signature. Values are fixed for now; `min_send_interval`
/// is the pacing lever and `max_attempts` the (currently inert) retransmit cap.
#[derive(Clone, Copy)]
pub(crate) struct ScanConfig {
    /// How long to wait for a reply before a probe is considered timed out.
    pub(crate) timeout: Duration,
    /// Upper bound on probes awaiting a reply at once.
    pub(crate) max_in_flight: usize,
    /// Minimum spacing between two sends. The pacing lever: larger spacing
    /// stays under the kernel's reply rate-limit and avoids buffer overflow.
    pub(crate) min_send_interval: Duration,
    /// Total times a port may be probed before it is recorded as timed out.
    /// `1` disables retransmission (a timed-out probe is final).
    pub(crate) max_attempts: u8,
}

/// Demux key: a reply is matched to its probe by target IP, the target port
/// (the reply's TCP *source* port), and the random source port we chose (the
/// reply's TCP *destination* port).
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
struct ProbeKey {
    target_ip: Ipv4Addr,
    target_port: u16,
    source_port: u16,
}

/// A probe queued to send. `attempts` distinguishes a retransmit from a fresh
/// probe; `source_port` is assigned on the first send (`None` before) and then
/// reused on every retransmit so the demux key is stable across attempts — a
/// *late* reply to an earlier send still matches and completes the probe,
/// instead of being discarded because the original used a different port.
struct Probe {
    target_ip: Ipv4Addr,
    source_ip: Ipv4Addr,
    target_port: u16,
    result_index: usize,
    attempts: u8,
    source_port: Option<u16>,
}

/// A probe that has been sent and is awaiting a reply. `sent_at` lets us report
/// the reply latency, which host discovery uses to pick the fastest port.
struct InFlight {
    probe: Probe,
    sent_at: Instant,
    deadline: Instant,
}

#[derive(Clone, Copy)]
pub(crate) enum TcpProbeOutcome {
    Reply { flags: u16 },
    Timeout,
}

#[derive(Clone, Copy)]
pub(crate) struct TcpProbeResult {
    pub(crate) ip_address: Ipv4Addr,
    pub(crate) port: u16,
    pub(crate) outcome: TcpProbeOutcome,
    /// Time from sending to the matching reply. For a timeout this is the full
    /// configured timeout (i.e. how long we actually waited).
    pub(crate) latency: Duration,
}

pub(crate) struct TcpProbeBatchResult {
    pub(crate) results: Vec<TcpProbeResult>,
    pub(crate) ports_scanned: usize,
    pub(crate) packets_sent: u32,
    pub(crate) start_time: SystemTime,
    pub(crate) end_time: SystemTime,
}

/// Scans every `(target, port)` pair with one shared raw socket, returning one
/// outcome per pair (in input order). `packet_flags` are the TCP flags to send;
/// the caller interprets the returned flags.
pub(crate) async fn scan_tcp_probes(
    ip_addresses: Vec<(Ipv4Addr, Ipv4Addr)>,
    ports: Vec<u16>,
    packet_flags: u16,
    config: ScanConfig,
) -> Result<TcpProbeBatchResult, String> {
    // The pnet transport API is blocking; isolate it on a blocking thread so it
    // never stalls the async runtime.
    tokio::task::spawn_blocking(move || scan_blocking(ip_addresses, ports, packet_flags, config))
        .await
        .map_err(|e| format!("TCP raw scan task panicked: {}", e))?
}

fn scan_blocking(
    ip_addresses: Vec<(Ipv4Addr, Ipv4Addr)>,
    ports: Vec<u16>,
    packet_flags: u16,
    config: ScanConfig,
) -> Result<TcpProbeBatchResult, String> {
    let start_time = SystemTime::now();
    let ports_scanned = ports.len();
    let total_probes = ip_addresses.len().saturating_mul(ports.len());

    let mut to_send = queue_probes(&ip_addresses, &ports);
    let mut results: Vec<Option<TcpProbeResult>> = vec![None; total_probes];
    let mut in_flight: HashMap<ProbeKey, InFlight> = HashMap::new();
    let mut completed = 0usize;
    let mut packets_sent = 0u32;

    if total_probes == 0 {
        return Ok(batch_result(
            Vec::new(),
            ports_scanned,
            0,
            start_time,
        ));
    }

    let (mut tx, mut rx) = open_channel()?;
    let mut iter = tcp_packet_iter(&mut rx);
    let mut next_send_at = Instant::now();

    while completed < total_probes {
        // SEND: fill the in-flight window. The window size is the throttle; the
        // optional per-send interval only applies when configured non-zero.
        while in_flight.len() < config.max_in_flight && Instant::now() >= next_send_at {
            let Some(mut probe) = to_send.pop_front() else {
                break;
            };
            let key = send_probe(&mut tx, packet_flags, &mut probe)?;
            packets_sent = packets_sent.saturating_add(1);
            if !config.min_send_interval.is_zero() {
                next_send_at = Instant::now() + config.min_send_interval;
            }
            let now = Instant::now();
            in_flight.insert(
                key,
                InFlight {
                    sent_at: now,
                    deadline: now + config.timeout,
                    probe,
                },
            );
        }

        // EXPIRE before receiving: a due probe must be settled now, else the
        // receive wait below collapses toward zero and stalls the socket.
        expire_due(&mut in_flight, &mut to_send, &mut results, &mut completed, config.max_attempts);

        if in_flight.is_empty() && to_send.is_empty() {
            break;
        }

        // RECV: block until a reply arrives or the next thing we must act on.
        // When the window has room and probes are queued, that is the next send
        // slot (paced runs only); otherwise it is the nearest deadline.
        let waiting_to_send =
            in_flight.len() < config.max_in_flight && !to_send.is_empty();
        let wake_at = if waiting_to_send {
            Some(next_send_at)
        } else {
            None
        };
        match iter.next_with_timeout(receive_wait(&in_flight, wake_at)) {
            Ok(Some((packet, addr))) => {
                // The receiver also sees our own outbound probes (loopback / any
                // shared link). A genuine reply never carries the exact flag set
                // we sent (SYN -> SYN+ACK or RST; ACK -> RST), so drop echoes
                // before they can alias an in-flight key and be misclassified.
                let flags = packet.get_flags();
                if flags != packet_flags
                    && let IpAddr::V4(target_ip) = addr
                {
                    let key = ProbeKey {
                        target_ip,
                        target_port: packet.get_source(),
                        source_port: packet.get_destination(),
                    };
                    if let Some(entry) = in_flight.remove(&key) {
                        results[entry.probe.result_index] = Some(TcpProbeResult {
                            ip_address: target_ip,
                            port: key.target_port,
                            outcome: TcpProbeOutcome::Reply { flags },
                            latency: entry.sent_at.elapsed(),
                        });
                        completed += 1;
                    }
                }
            }
            Ok(None) => {}
            Err(e) => log::debug!("TCP raw scan receive error: {}", e),
        }
    }

    // Anything still in flight when the loop exits is a final timeout.
    for (key, entry) in &in_flight {
        results[entry.probe.result_index] = Some(timeout_result(*key, entry));
    }

    let results = results
        .into_iter()
        .map(|slot| slot.expect("every probe must produce exactly one result"))
        .collect();

    Ok(batch_result(results, ports_scanned, packets_sent, start_time))
}

/// Builds the send queue, one probe per `(target, port)`.
///
/// Ordered **port-major** (round-robin across hosts): port P for every host,
/// then port P+1 for every host, and so on. This interleaves hosts in the send
/// stream, so the bounded in-flight window holds probes spread across *all*
/// hosts at once and their reply waits overlap. A host-major order would fill
/// the window with one host's probes and effectively scan hosts serially —
/// total time scaling with host count instead of overlapping (the cause of poor
/// multi-host scaling). `result_index` still pins each probe to a stable slot,
/// so send order does not affect where results land.
fn queue_probes(ip_addresses: &[(Ipv4Addr, Ipv4Addr)], ports: &[u16]) -> VecDeque<Probe> {
    let mut queue = VecDeque::with_capacity(ip_addresses.len() * ports.len());
    for (port_index, &target_port) in ports.iter().enumerate() {
        for (host_index, &(target_ip, source_ip)) in ip_addresses.iter().enumerate() {
            // Stable slot per (host, port), independent of send order.
            let result_index = host_index * ports.len() + port_index;
            queue.push_back(Probe {
                target_ip,
                source_ip,
                target_port,
                result_index,
                attempts: 0,
                source_port: None,
            });
        }
    }
    queue
}

fn open_channel() -> Result<(TransportSender, pnet::transport::TransportReceiver), String> {
    let protocol = TransportProtocol::Ipv4(IpNextHeaderProtocols::Tcp);
    transport_channel(65_535, TransportChannelType::Layer4(protocol))
        .map_err(|e| format!("Error creating transport channel: {}. Try running with sudo.", e))
}

/// Sends one probe and returns its demux key. The source port is assigned once
/// (random, ephemeral range) on the first send and reused on retransmits, so a
/// late reply to an earlier send still matches this probe's key.
fn send_probe(
    tx: &mut TransportSender,
    packet_flags: u16,
    probe: &mut Probe,
) -> Result<ProbeKey, String> {
    let source_port = *probe
        .source_port
        .get_or_insert_with(|| rand::thread_rng().gen_range(49152..65535));

    // 20 bytes = exactly one TCP header with data_offset=5 (no options). A
    // larger buffer would send uninitialised bytes past the header.
    let mut buffer = [0u8; 20];
    let mut packet = MutableTcpPacket::new(&mut buffer).expect("20 bytes fits a TCP header");
    packet.set_source(source_port);
    packet.set_destination(probe.target_port);
    packet.set_sequence(rand::thread_rng().r#gen::<u32>());
    packet.set_acknowledgement(0);
    packet.set_data_offset(5);
    packet.set_flags(packet_flags);
    packet.set_window(64240);
    packet.set_urgent_ptr(0);
    let checksum =
        pnet::packet::tcp::ipv4_checksum(&packet.to_immutable(), &probe.source_ip, &probe.target_ip);
    packet.set_checksum(checksum);

    tx.send_to(packet, IpAddr::V4(probe.target_ip)).map_err(|e| {
        format!("Failed to send TCP packet to {}:{}: {}", probe.target_ip, probe.target_port, e)
    })?;

    Ok(ProbeKey {
        target_ip: probe.target_ip,
        target_port: probe.target_port,
        source_port,
    })
}

/// Settles probes whose deadline has passed: re-queue if retransmits remain
/// (the reply may have been dropped/rate-limited), otherwise record a timeout.
fn expire_due(
    in_flight: &mut HashMap<ProbeKey, InFlight>,
    to_send: &mut VecDeque<Probe>,
    results: &mut [Option<TcpProbeResult>],
    completed: &mut usize,
    max_attempts: u8,
) {
    let now = Instant::now();
    let due: Vec<ProbeKey> = in_flight
        .iter()
        .filter_map(|(key, entry)| (entry.deadline <= now).then_some(*key))
        .collect();

    for key in due {
        let Some(entry) = in_flight.remove(&key) else {
            continue;
        };
        if entry.probe.attempts + 1 < max_attempts {
            to_send.push_back(Probe {
                attempts: entry.probe.attempts + 1,
                ..entry.probe
            });
        } else {
            results[entry.probe.result_index] = Some(timeout_result(key, &entry));
            *completed += 1;
        }
    }
}

/// How long the next receive may block: until the nearest deadline, brought
/// forward to `wake_at` if we are pacing and owe a send sooner. Floored above
/// zero so we never pass 0 to the socket (see [`MIN_RECEIVE_TIMEOUT`]). A reply
/// arriving interrupts the wait early regardless.
fn receive_wait(in_flight: &HashMap<ProbeKey, InFlight>, wake_at: Option<Instant>) -> Duration {
    let now = Instant::now();
    let nearest_deadline = in_flight.values().map(|e| e.deadline).min();
    let next_event = [nearest_deadline, wake_at].into_iter().flatten().min();
    match next_event {
        Some(at) => at.saturating_duration_since(now).max(MIN_RECEIVE_TIMEOUT),
        None => MIN_RECEIVE_TIMEOUT,
    }
}

fn timeout_result(key: ProbeKey, entry: &InFlight) -> TcpProbeResult {
    TcpProbeResult {
        ip_address: entry.probe.target_ip,
        port: key.target_port,
        outcome: TcpProbeOutcome::Timeout,
        latency: entry.sent_at.elapsed(),
    }
}

fn batch_result(
    results: Vec<TcpProbeResult>,
    ports_scanned: usize,
    packets_sent: u32,
    start_time: SystemTime,
) -> TcpProbeBatchResult {
    TcpProbeBatchResult {
        results,
        ports_scanned,
        packets_sent,
        start_time,
        end_time: SystemTime::now(),
    }
}
