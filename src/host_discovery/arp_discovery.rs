use futures::stream::{FuturesUnordered, StreamExt};
use local_ip_address::local_ip;
use pnet::datalink::{self, Channel, NetworkInterface};
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::{MutablePacket, Packet};
use pnet::util::MacAddr;
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant, SystemTime};
use tokio::task;
use tokio::time::timeout;

use crate::models::{HostDiscoveryAllResult, HostDiscoverySingleResult};
use crate::resolving::resolve_hostname;

/// Runs an ARP scan against a list of target IP addresses on the local network.
pub async fn run_arp_discovery(
    ip_addresses: Vec<Ipv4Addr>,
    timeout_override_ms: Option<u64>,
) -> Result<(Vec<HostDiscoverySingleResult>, HostDiscoveryAllResult), String> {
    let start_time = SystemTime::now();

    let local_ip = match local_ip() {
        Ok(IpAddr::V4(ip)) => ip,
        Ok(IpAddr::V6(_)) => return Err("ARP scan requires an IPv4 local address".to_string()),
        Err(e) => return Err(format!("Failed to determine local IP: {}", e)),
    };

    let interface = select_interface_for_ip(local_ip)?;
    let source_mac = interface
        .mac
        .ok_or_else(|| format!("No MAC address found for interface {}", interface.name))?;

    let mut futures = FuturesUnordered::new();
    let all_ips: Vec<IpAddr> = ip_addresses.iter().map(|ip| IpAddr::V4(*ip)).collect();

    for ip in ip_addresses {
        let interface = interface.clone();
        futures.push(async move {
            let arp_result = arp_ping_host_with_details(
                interface,
                source_mac,
                local_ip,
                ip,
                timeout_override_ms,
            )
            .await;

            let dns_resolve = None;
            let mut is_reachable = false;
            let mut latency = None;
            let ttl = 0;
            let mut reply_type = "no response".to_string();

            match arp_result {
                Ok((reachable, lat, _)) => {
                    is_reachable = reachable;
                    latency = lat;
                    if is_reachable {
                        reply_type = "ARP reply".to_string();
                    }
                }
                Err(e) => {
                    reply_type = format!("Error: {}", e);
                }
            }

            HostDiscoverySingleResult {
                ip_address: IpAddr::V4(ip),
                latency,
                dns_resolve,
                is_up: is_reachable,
                reply_type,
                ttl,
            }
        });
    }

    let mut host_results = Vec::new();
    while let Some(result) = futures.next().await {
        host_results.push(result);
    }

    let dns_start = Instant::now();
    let dns_tasks: Vec<_> = host_results
        .iter()
        .enumerate()
        .filter_map(|(i, r)| match r.ip_address {
            IpAddr::V4(ipv4) if r.is_up => Some((i, ipv4)),
            _ => None,
        })
        .collect();
    let dns_resolved = futures::future::join_all(
        dns_tasks
            .into_iter()
            .map(|(i, ipv4)| async move { (i, resolve_hostname(&ipv4).await) }),
    )
    .await;
    for (idx, hostname) in dns_resolved {
        host_results[idx].dns_resolve = hostname;
    }
    let dns_elapsed_secs = dns_start.elapsed().as_secs_f64();

    let hosts_up = host_results.iter().filter(|r| r.is_up).count() as u64;
    let hosts_dns_resolution = host_results
        .iter()
        .filter(|r| r.dns_resolve.is_some())
        .count() as u64;
    let end_time = SystemTime::now();

    let summary = HostDiscoveryAllResult {
        scanned_addresses: all_ips,
        ports_per_host: 0,
        hosts_up,
        hosts_dns_resolution,
        start_time,
        end_time,
        packets_sent: host_results.len() as u64,
        dns_elapsed_secs,
    };

    Ok((host_results, summary))
}

fn select_interface_for_ip(local_ip: Ipv4Addr) -> Result<NetworkInterface, String> {
    let interfaces = datalink::interfaces();
    interfaces
        .into_iter()
        .find(|iface| iface.ips.iter().any(|ip| ip.ip() == IpAddr::V4(local_ip)))
        .ok_or_else(|| format!("No network interface found for local IP {}", local_ip))
}

async fn arp_ping_host_with_details(
    interface: NetworkInterface,
    source_mac: MacAddr,
    source_ip: Ipv4Addr,
    target_ip: Ipv4Addr,
    timeout_override_ms: Option<u64>,
) -> Result<(bool, Option<Duration>, Option<u8>), String> {
    const DEFAULT_READ_TIMEOUT_MS: u64 = 200;
    const DEFAULT_SCAN_WINDOW_MS: u64 = 2_000;
    const DEFAULT_OUTER_PADDING_MS: u64 = 1_000;
    let read_timeout_ms = timeout_override_ms.unwrap_or(DEFAULT_READ_TIMEOUT_MS);
    let scan_window_ms = timeout_override_ms.unwrap_or(DEFAULT_SCAN_WINDOW_MS);
    let outer_timeout_ms = scan_window_ms + DEFAULT_OUTER_PADDING_MS;

    let task = task::spawn_blocking(move || {
        let mut config = datalink::Config::default();
        config.read_timeout = Some(Duration::from_millis(read_timeout_ms));

        let (mut tx, mut rx) = match datalink::channel(&interface, config) {
            Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => return Err("Unhandled datalink channel type".to_string()),
            Err(e) => return Err(format!("Failed to open datalink channel: {}", e)),
        };

        let mut buffer = [0u8; 42];
        let mut ethernet_packet = MutableEthernetPacket::new(&mut buffer)
            .ok_or_else(|| "Failed to create Ethernet packet".to_string())?;
        ethernet_packet.set_destination(MacAddr::broadcast());
        ethernet_packet.set_source(source_mac);
        ethernet_packet.set_ethertype(EtherTypes::Arp);

        let mut arp_packet = MutableArpPacket::new(ethernet_packet.payload_mut())
            .ok_or_else(|| "Failed to create ARP packet".to_string())?;
        arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
        arp_packet.set_protocol_type(EtherTypes::Ipv4);
        arp_packet.set_hw_addr_len(6);
        arp_packet.set_proto_addr_len(4);
        arp_packet.set_operation(ArpOperations::Request);
        arp_packet.set_sender_hw_addr(source_mac);
        arp_packet.set_sender_proto_addr(source_ip);
        arp_packet.set_target_hw_addr(MacAddr::zero());
        arp_packet.set_target_proto_addr(target_ip);

        let start_time = Instant::now();
        let _ = tx
            .send_to(ethernet_packet.packet(), None)
            .expect("Failed to send ARP request");

        let timeout_duration = Duration::from_millis(scan_window_ms);
        while start_time.elapsed() < timeout_duration {
            match rx.next() {
                Ok(raw_frame) => {
                    if let Some(ethernet_frame) = EthernetPacket::new(raw_frame) {
                        if ethernet_frame.get_ethertype() != EtherTypes::Arp {
                            continue;
                        }

                        if let Some(arp_packet) = ArpPacket::new(ethernet_frame.payload()) {
                            if arp_packet.get_operation() == ArpOperations::Reply
                                && arp_packet.get_sender_proto_addr() == target_ip
                                && arp_packet.get_target_proto_addr() == source_ip
                            {
                                let latency = start_time.elapsed();
                                return Ok((true, Some(latency), None));
                            }
                        }
                    }
                }
                Err(_) => {
                    continue;
                }
            }
        }

        Ok((false, None, None))
    });

    match timeout(Duration::from_millis(outer_timeout_ms), task).await {
        Ok(Ok(result)) => result,
        Ok(Err(e)) => {
            let error_msg = format!("ARP task failed for {}: {}", target_ip, e);
            eprintln!("{}", error_msg);
            Err(error_msg)
        }
        Err(_) => {
            let error_msg = format!("ARP task timed out for {}", target_ip);
            eprintln!("{}", error_msg);
            Err(error_msg)
        }
    }
}
