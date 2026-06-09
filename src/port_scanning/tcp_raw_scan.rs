use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::tcp::MutableTcpPacket;
use pnet::transport::{
    TransportChannelType, TransportProtocol, TransportSender, tcp_packet_iter, transport_channel,
};
use rand::Rng;
use std::collections::{HashMap, VecDeque};
use std::io::{self, ErrorKind};
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant, SystemTime};

const MAX_SENDS_PER_TICK: usize = 128;
const SEND_BACKPRESSURE_WAIT: Duration = Duration::from_millis(1);
const RAW_SOCKET_RECV_BUFFER_BYTES: libc::c_int = 8 * 1024 * 1024;

#[derive(Clone, Copy)]
pub(crate) struct ScanConfig {
    pub(crate) timeout: Duration,
    // Max probes per host awaiting a reply.
    pub(crate) max_in_flight: usize,
    // Optional send pacing; SYN/ACK leave it at zero.
    pub(crate) min_send_interval: Duration,
    pub(crate) max_attempts: u8,
}

// Matches a reply to its probe. Unique per in-flight probe: a host scans each
// port once at a time, so two in-flight probes to one host differ in target_port
// even if their random source_port collides.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct ProbeKey {
    target_ip: Ipv4Addr,
    target_port: u16,
    source_port: u16,
}

struct Probe {
    host_index: usize,
    target_ip: Ipv4Addr,
    source_ip: Ipv4Addr,
    target_port: u16,
    result_index: usize,
    attempts: u8,
    source_port: Option<u16>,
}

struct HostState {
    target_ip: Ipv4Addr,
    source_ip: Ipv4Addr,
    in_flight: usize,
    next_port_index: usize,
    retry_queue: VecDeque<Probe>,
}

struct InFlight {
    probe: Probe,
    sent_at: Instant,
    deadline: Instant,
}

enum SendProbeError {
    Backpressure(Probe),
    Fatal(String),
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
    pub(crate) latency: Duration,
}

pub(crate) struct TcpProbeBatchResult {
    pub(crate) results: Vec<TcpProbeResult>,
    pub(crate) ports_scanned: usize,
    pub(crate) packets_sent: u32,
    pub(crate) start_time: SystemTime,
    pub(crate) end_time: SystemTime,
}

pub(crate) async fn scan_tcp_probes(
    ip_addresses: Vec<(Ipv4Addr, Ipv4Addr)>,
    ports: Vec<u16>,
    packet_flags: u16,
    config: ScanConfig,
) -> Result<TcpProbeBatchResult, String> {
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

    if total_probes == 0 {
        return Ok(batch_result(Vec::new(), ports_scanned, 0, start_time));
    }

    let mut hosts = queue_probes(&ip_addresses);
    let mut results: Vec<Option<TcpProbeResult>> = vec![None; total_probes];
    let mut in_flight: HashMap<ProbeKey, InFlight> = HashMap::new();
    let mut completed = 0usize;
    let mut packets_sent = 0u32;
    let per_host_limit = config.max_in_flight.max(1);
    let global_limit = per_host_limit.saturating_mul(hosts.len()).max(1);
    let mut next_host_index = 0usize;
    let mut next_send_at = Instant::now();
    let mut rng = rand::thread_rng();

    let (mut tx, mut rx) = open_channel()?;
    let rx_fd = rx.socket.fd;
    set_receive_buffer(rx_fd)?;
    set_nonblocking(rx_fd)?;
    let mut iter = tcp_packet_iter(&mut rx);

    while completed < total_probes {
        let mut sends_this_tick = 0usize;
        while in_flight.len() < global_limit && Instant::now() >= next_send_at {
            if sends_this_tick >= MAX_SENDS_PER_TICK {
                break;
            }
            let Some(mut probe) =
                next_probe(&mut hosts, &ports, per_host_limit, &mut next_host_index)
            else {
                break;
            };
            let host_index = probe.host_index;
            let key = match send_probe(&mut tx, packet_flags, &mut probe, &mut rng) {
                Ok(key) => key,
                Err(SendProbeError::Backpressure(probe)) => {
                    hosts[host_index].in_flight = hosts[host_index].in_flight.saturating_sub(1);
                    hosts[host_index].retry_queue.push_front(probe);
                    next_send_at = Instant::now() + SEND_BACKPRESSURE_WAIT;
                    break;
                }
                Err(SendProbeError::Fatal(e)) => {
                    hosts[host_index].in_flight = hosts[host_index].in_flight.saturating_sub(1);
                    return Err(e);
                }
            };
            let now = Instant::now();
            in_flight.insert(
                key,
                InFlight {
                    probe,
                    sent_at: now,
                    deadline: now + config.timeout,
                },
            );
            packets_sent = packets_sent.saturating_add(1);
            sends_this_tick += 1;
            if !config.min_send_interval.is_zero() {
                next_send_at = Instant::now() + config.min_send_interval;
            }
        }

        drain_ready_packets(
            &mut iter,
            packet_flags,
            &mut in_flight,
            &mut hosts,
            &mut results,
            &mut completed,
        );

        expire_due(
            &mut in_flight,
            &mut hosts,
            &mut results,
            &mut completed,
            config.max_attempts,
        );

        if in_flight.is_empty() && hosts_done(&hosts, ports.len()) {
            break;
        }

        let waiting_to_send = in_flight.len() < global_limit
            && has_send_capacity(&hosts, ports.len(), per_host_limit);
        if waiting_to_send && Instant::now() >= next_send_at {
            continue;
        }
        let wake_at = waiting_to_send.then_some(next_send_at);
        if wait_for_readable(rx_fd, receive_wait(&in_flight, wake_at))? {
            drain_ready_packets(
                &mut iter,
                packet_flags,
                &mut in_flight,
                &mut hosts,
                &mut results,
                &mut completed,
            );
        }
    }

    for (key, entry) in &in_flight {
        results[entry.probe.result_index] = Some(timeout_result(*key, entry));
    }

    let results = results
        .into_iter()
        .map(|slot| slot.expect("every probe must produce exactly one result"))
        .collect();

    Ok(batch_result(
        results,
        ports_scanned,
        packets_sent,
        start_time,
    ))
}

fn queue_probes(ip_addresses: &[(Ipv4Addr, Ipv4Addr)]) -> Vec<HostState> {
    ip_addresses
        .iter()
        .map(|&(target_ip, source_ip)| HostState {
            target_ip,
            source_ip,
            in_flight: 0,
            next_port_index: 0,
            retry_queue: VecDeque::new(),
        })
        .collect()
}

fn next_probe(
    hosts: &mut [HostState],
    ports: &[u16],
    per_host_limit: usize,
    next_host_index: &mut usize,
) -> Option<Probe> {
    if hosts.is_empty() {
        return None;
    }

    for _ in 0..hosts.len() {
        let host_index = *next_host_index % hosts.len();
        *next_host_index = (*next_host_index + 1) % hosts.len();
        let host = &mut hosts[host_index];
        if host.in_flight >= per_host_limit {
            continue;
        }

        let probe = if let Some(probe) = host.retry_queue.pop_front() {
            probe
        } else {
            let Some(&target_port) = ports.get(host.next_port_index) else {
                continue;
            };
            let port_index = host.next_port_index;
            host.next_port_index += 1;
            // Every host scans the same ports slice, so its result slot is
            // host_index * ports.len() + port_index. Per-host port lists would
            // need this mapping and total_probes changed together.
            Probe {
                host_index,
                target_ip: host.target_ip,
                source_ip: host.source_ip,
                target_port,
                result_index: host_index * ports.len() + port_index,
                attempts: 0,
                source_port: None,
            }
        };
        host.in_flight += 1;
        return Some(probe);
    }

    None
}

fn hosts_done(hosts: &[HostState], ports_len: usize) -> bool {
    hosts.iter().all(|host| {
        host.in_flight == 0 && host.retry_queue.is_empty() && host.next_port_index >= ports_len
    })
}

fn has_send_capacity(hosts: &[HostState], ports_len: usize, per_host_limit: usize) -> bool {
    hosts.iter().any(|host| {
        host.in_flight < per_host_limit
            && (!host.retry_queue.is_empty() || host.next_port_index < ports_len)
    })
}

fn open_channel() -> Result<(TransportSender, pnet::transport::TransportReceiver), String> {
    let protocol = TransportProtocol::Ipv4(IpNextHeaderProtocols::Tcp);
    transport_channel(65_535, TransportChannelType::Layer4(protocol)).map_err(|e| {
        format!(
            "Error creating transport channel: {}. Try running with sudo.",
            e
        )
    })
}

fn set_receive_buffer(fd: libc::c_int) -> Result<(), String> {
    let size = RAW_SOCKET_RECV_BUFFER_BYTES;
    let result = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            &size as *const _ as *const libc::c_void,
            std::mem::size_of_val(&size) as libc::socklen_t,
        )
    };
    if result < 0 {
        return Err(format!(
            "Failed to set raw socket receive buffer: {}",
            io::Error::last_os_error()
        ));
    }
    Ok(())
}

fn set_nonblocking(fd: libc::c_int) -> Result<(), String> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(format!(
            "Failed to read raw socket flags: {}",
            io::Error::last_os_error()
        ));
    }
    let result = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
    if result < 0 {
        return Err(format!(
            "Failed to set raw socket nonblocking: {}",
            io::Error::last_os_error()
        ));
    }
    Ok(())
}

fn wait_for_readable(fd: libc::c_int, timeout: Duration) -> Result<bool, String> {
    let timeout_ms = timeout.as_millis().min(libc::c_int::MAX as u128) as libc::c_int;
    let mut poll_fd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    let result = unsafe { libc::poll(&mut poll_fd, 1, timeout_ms) };
    if result < 0 {
        return Err(format!(
            "Failed to poll raw socket: {}",
            io::Error::last_os_error()
        ));
    }
    Ok(result > 0 && (poll_fd.revents & libc::POLLIN) != 0)
}

fn send_probe(
    tx: &mut TransportSender,
    packet_flags: u16,
    probe: &mut Probe,
    rng: &mut impl Rng,
) -> Result<ProbeKey, SendProbeError> {
    let source_port = *probe
        .source_port
        .get_or_insert_with(|| rng.gen_range(49152..65535));

    let mut buffer = [0u8; 20];
    let mut packet = MutableTcpPacket::new(&mut buffer).expect("20 bytes fits a TCP header");
    packet.set_source(source_port);
    packet.set_destination(probe.target_port);
    packet.set_sequence(rng.r#gen::<u32>());
    packet.set_acknowledgement(0);
    packet.set_data_offset(5);
    packet.set_flags(packet_flags);
    packet.set_window(64240);
    packet.set_urgent_ptr(0);
    let checksum = pnet::packet::tcp::ipv4_checksum(
        &packet.to_immutable(),
        &probe.source_ip,
        &probe.target_ip,
    );
    packet.set_checksum(checksum);

    if let Err(e) = tx.send_to(packet, IpAddr::V4(probe.target_ip)) {
        let message = format!(
            "Failed to send TCP packet to {}:{}: {}",
            probe.target_ip, probe.target_port, e
        );
        if is_send_backpressure(&e) {
            log::debug!("{}", message);
            return Err(SendProbeError::Backpressure(Probe {
                host_index: probe.host_index,
                target_ip: probe.target_ip,
                source_ip: probe.source_ip,
                target_port: probe.target_port,
                result_index: probe.result_index,
                attempts: probe.attempts,
                source_port: probe.source_port,
            }));
        }
        return Err(SendProbeError::Fatal(message));
    }

    Ok(ProbeKey {
        target_ip: probe.target_ip,
        target_port: probe.target_port,
        source_port,
    })
}

fn is_send_backpressure(error: &io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(libc::ENOBUFS) | Some(libc::EAGAIN)
    ) || error.kind() == ErrorKind::WouldBlock
}

fn drain_ready_packets(
    iter: &mut pnet::transport::TcpTransportChannelIterator<'_>,
    packet_flags: u16,
    in_flight: &mut HashMap<ProbeKey, InFlight>,
    hosts: &mut [HostState],
    results: &mut [Option<TcpProbeResult>],
    completed: &mut usize,
) {
    loop {
        match iter.next() {
            Ok((packet, addr)) => settle_packet(
                packet.get_flags(),
                addr,
                packet.get_source(),
                packet.get_destination(),
                packet_flags,
                in_flight,
                hosts,
                results,
                completed,
            ),
            Err(e) => {
                if e.kind() == ErrorKind::WouldBlock {
                    break;
                }
                log::debug!("TCP raw scan receive error: {}", e);
                break;
            }
        }
    }
}

fn settle_packet(
    flags: u16,
    addr: IpAddr,
    source_port: u16,
    destination_port: u16,
    packet_flags: u16,
    in_flight: &mut HashMap<ProbeKey, InFlight>,
    hosts: &mut [HostState],
    results: &mut [Option<TcpProbeResult>],
    completed: &mut usize,
) {
    if flags == packet_flags {
        return;
    }
    let IpAddr::V4(target_ip) = addr else {
        return;
    };
    let key = ProbeKey {
        target_ip,
        target_port: source_port,
        source_port: destination_port,
    };
    let Some(entry) = in_flight.remove(&key) else {
        return;
    };

    finish_reply(key, entry, flags, hosts, results, completed);
}

fn finish_reply(
    key: ProbeKey,
    entry: InFlight,
    flags: u16,
    hosts: &mut [HostState],
    results: &mut [Option<TcpProbeResult>],
    completed: &mut usize,
) {
    hosts[entry.probe.host_index].in_flight =
        hosts[entry.probe.host_index].in_flight.saturating_sub(1);
    results[entry.probe.result_index] = Some(TcpProbeResult {
        ip_address: entry.probe.target_ip,
        port: key.target_port,
        outcome: TcpProbeOutcome::Reply { flags },
        latency: entry.sent_at.elapsed(),
    });
    *completed += 1;
}

fn expire_due(
    in_flight: &mut HashMap<ProbeKey, InFlight>,
    hosts: &mut [HostState],
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
        let host_index = entry.probe.host_index;
        hosts[host_index].in_flight = hosts[host_index].in_flight.saturating_sub(1);
        if entry.probe.attempts + 1 < max_attempts {
            hosts[host_index].retry_queue.push_back(Probe {
                attempts: entry.probe.attempts + 1,
                ..entry.probe
            });
        } else {
            results[entry.probe.result_index] = Some(timeout_result(key, &entry));
            *completed += 1;
        }
    }
}

fn receive_wait(in_flight: &HashMap<ProbeKey, InFlight>, wake_at: Option<Instant>) -> Duration {
    let now = Instant::now();
    let nearest_deadline = in_flight.values().map(|e| e.deadline).min();
    let next_event = [nearest_deadline, wake_at].into_iter().flatten().min();
    match next_event {
        Some(at) => at.saturating_duration_since(now),
        None => Duration::from_millis(1),
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

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(d: u8) -> Ipv4Addr {
        Ipv4Addr::new(10, 0, 0, d)
    }

    fn config(timeout_ms: u64, max_attempts: u8) -> ScanConfig {
        ScanConfig {
            timeout: Duration::from_millis(timeout_ms),
            max_in_flight: 1,
            min_send_interval: Duration::ZERO,
            max_attempts,
        }
    }

    fn in_flight_entry() -> (ProbeKey, InFlight) {
        let key = ProbeKey {
            target_ip: ip(1),
            target_port: 80,
            source_port: 50000,
        };
        let entry = InFlight {
            probe: Probe {
                host_index: 0,
                target_ip: ip(1),
                source_ip: ip(254),
                target_port: 80,
                result_index: 0,
                attempts: 0,
                source_port: Some(50000),
            },
            sent_at: Instant::now(),
            deadline: Instant::now() - Duration::from_millis(1),
        };
        (key, entry)
    }

    #[tokio::test]
    async fn empty_input_returns_no_probes_without_socket() {
        // No targets: scan_blocking returns before opening a raw socket, so this
        // runs unprivileged.
        let result = scan_tcp_probes(Vec::new(), vec![80], 0, config(100, 1))
            .await
            .expect("empty scan should succeed");
        assert!(result.results.is_empty());
        assert_eq!(result.packets_sent, 0);
        assert_eq!(result.ports_scanned, 1);
    }

    #[test]
    fn next_probe_round_robins_and_maps_result_index() {
        let mut hosts = queue_probes(&[(ip(1), ip(254)), (ip(2), ip(254))]);
        let ports = vec![80, 443];
        let mut next = 0;

        let p0 = next_probe(&mut hosts, &ports, 1, &mut next).unwrap();
        let p1 = next_probe(&mut hosts, &ports, 1, &mut next).unwrap();
        assert_eq!((p0.host_index, p0.target_port), (0, 80));
        assert_eq!((p1.host_index, p1.target_port), (1, 80));
        // result_index == host_index * ports.len() + port_index
        assert_eq!(p0.result_index, 0);
        assert_eq!(p1.result_index, 2);
    }

    #[test]
    fn next_probe_respects_per_host_limit() {
        let mut hosts = queue_probes(&[(ip(1), ip(254))]);
        let ports = vec![80, 443];
        let mut next = 0;

        assert!(next_probe(&mut hosts, &ports, 1, &mut next).is_some());
        assert!(next_probe(&mut hosts, &ports, 1, &mut next).is_none());
    }

    #[test]
    fn next_probe_prefers_retry_queue() {
        let mut hosts = queue_probes(&[(ip(1), ip(254))]);
        let ports = vec![80];
        hosts[0].retry_queue.push_back(Probe {
            host_index: 0,
            target_ip: ip(1),
            source_ip: ip(254),
            target_port: 9999,
            result_index: 0,
            attempts: 1,
            source_port: Some(50000),
        });

        let mut next = 0;
        let p = next_probe(&mut hosts, &ports, 2, &mut next).unwrap();
        assert_eq!(p.target_port, 9999);
        assert_eq!(p.attempts, 1);
    }

    #[test]
    fn hosts_done_only_when_fully_drained() {
        let mut hosts = queue_probes(&[(ip(1), ip(254))]);
        assert!(!hosts_done(&hosts, 1));
        hosts[0].next_port_index = 1;
        assert!(hosts_done(&hosts, 1));
        hosts[0].in_flight = 1;
        assert!(!hosts_done(&hosts, 1));
    }

    #[test]
    fn expire_due_retries_until_attempts_exhausted() {
        let mut hosts = queue_probes(&[(ip(1), ip(254))]);
        hosts[0].in_flight = 1;
        let mut results = vec![None];
        let mut completed = 0;
        let (key, entry) = in_flight_entry();
        let mut in_flight = HashMap::from([(key, entry)]);

        // max_attempts 2: first expiry re-queues rather than finalizing.
        expire_due(&mut in_flight, &mut hosts, &mut results, &mut completed, 2);
        assert_eq!(completed, 0);
        assert_eq!(hosts[0].retry_queue.len(), 1);
        assert!(results[0].is_none());
    }

    #[test]
    fn expire_due_times_out_on_last_attempt() {
        let mut hosts = queue_probes(&[(ip(1), ip(254))]);
        hosts[0].in_flight = 1;
        let mut results = vec![None];
        let mut completed = 0;
        let (key, entry) = in_flight_entry();
        let mut in_flight = HashMap::from([(key, entry)]);

        // max_attempts 1: the only attempt is final, so it becomes a Timeout.
        expire_due(&mut in_flight, &mut hosts, &mut results, &mut completed, 1);
        assert_eq!(completed, 1);
        assert!(hosts[0].retry_queue.is_empty());
        assert!(matches!(
            results[0].unwrap().outcome,
            TcpProbeOutcome::Timeout
        ));
    }

    #[test]
    fn backpressure_errors_are_classified() {
        assert!(is_send_backpressure(&io::Error::from_raw_os_error(
            libc::ENOBUFS
        )));
        assert!(is_send_backpressure(&io::Error::from(
            ErrorKind::WouldBlock
        )));
        assert!(!is_send_backpressure(&io::Error::from(
            ErrorKind::PermissionDenied
        )));
    }
}
