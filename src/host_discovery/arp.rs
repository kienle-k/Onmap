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
pub async fn run_arp(
    ip_addresses: Result<Vec<Ipv4Addr>, String>,
) -> Result<(Vec<HostDiscoverySingleResult>, HostDiscoveryAllResult), String> {
    let start_time = SystemTime::now();
    let ips = ip_addresses?;

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
    let all_ips: Vec<IpAddr> = ips.iter().map(|ip| IpAddr::V4(*ip)).collect();

    for ip in ips {
        let interface = interface.clone();
        futures.push(async move {
            let arp_result = arp_ping_host_with_details(interface, source_mac, local_ip, ip).await;

            let mut dns_resolve = None;
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
                        dns_resolve = resolve_hostname(&ip).await;
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

    let hosts_up = host_results.iter().filter(|r| r.is_up).count() as u64;
    let hosts_dns_resolution = host_results.iter().filter(|r| r.dns_resolve.is_some()).count() as u64;
    let end_time = SystemTime::now();

    let summary = HostDiscoveryAllResult {
        scanned_addresses: all_ips,
        ports_per_host: 0,
        hosts_up,
        hosts_dns_resolution,
        start_time,
        end_time,
        packets_sent: host_results.len() as u64,
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
) -> Result<(bool, Option<Duration>, Option<u8>), String> {
    let task = task::spawn_blocking(move || {
        let mut config = datalink::Config::default();
        config.read_timeout = Some(Duration::from_millis(200));

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
        let _ = tx.send_to(ethernet_packet.packet(), None).expect("Failed to send ARP request");

        let timeout_duration = Duration::from_secs(2);
        while start_time.elapsed() < timeout_duration {
            match rx.next() {
                Ok(packet) => {
                    if let Some(ethernet) = EthernetPacket::new(packet) {
                        if ethernet.get_ethertype() != EtherTypes::Arp {
                            continue;
                        }

                        if let Some(arp) = ArpPacket::new(ethernet.payload()) {
                            if arp.get_operation() == ArpOperations::Reply
                                && arp.get_sender_proto_addr() == target_ip
                                && arp.get_target_proto_addr() == source_ip
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

    match timeout(Duration::from_secs(3), task).await {
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