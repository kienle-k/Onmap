use std::net::IpAddr;
use std::time::{Duration, SystemTime};

#[derive(Clone, Copy)]
pub enum AppState {
    MainMenu,
    SubMenuHostDiscovery,
    SubMenuPortScan,
    IpAddressInput,
    PortOptions,
    PortRangeInput
}

#[derive(Clone, Copy)]
pub enum MainMenuItem {
    SubMenuHostDiscovery,
    SubMenuPortScan,
    SubMenuServiceDetection,
    SubMenuOperatingSystemDetection,
}

/*
#[derive(Clone, Copy)]
pub enum AllMenuItem {
    SubMenuHostDiscovery,
    SubMenuPortScan,
    SubMenuServiceDetection,
    SubMenuOperatingSystemDetection,

    ListScan,
    PingScan,
    TcpSynDiscovery,
    TcpAckDiscovery,
    UdpDiscovery,
    ArpDiscovery,
    IcmpEcho,
    IcmpTimestamp,
    IcmpNetmask,

    SynScan,
    ConnectScan,
    AckScan,
    WindowScan,
    MaimonScan,
    NullScan,
    FinScan,
    XmasScan,
    UdpScan,
}
*/

#[derive(Clone, Copy)]
pub enum HostDiscoveryOption {
    ListScan,
    PingScan,
    TcpSynDiscovery,
    TcpAckDiscovery,
    UdpDiscovery,
    ArpDiscovery,
    IcmpEcho,
    IcmpTimestamp,
    IcmpNetmask,
}

#[derive(Clone, Copy)]
pub enum PortScanOption {
    SynScan,
    ConnectScan,
    AckScan,
    WindowScan,
    MaimonScan,
    NullScan,
    FinScan,
    XmasScan,
    UdpScan,
}

#[derive(Clone, Copy)]
pub enum PortOptions {
    NormalMode,
    PortRangeInput,
    FastMode,
    SequentialMode
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum PortStates {
    Open,
    Closed,
    Filtered
}

#[derive(Clone, Copy, Debug)]
pub enum PortStateReasons {
    SynAck,
    Reset,
    Timeout
}

#[derive(Clone, Copy, Debug)]
pub enum Protocols {
    TCP
}

#[derive(Debug, Clone)]
pub struct PortScanSingleResult {
    pub ip_address: IpAddr,
    pub port: u16,
    pub protocol: Protocols,
    pub port_state: PortStates,
    pub ttl: u8,
    pub reason: PortStateReasons,
    pub service: String
}

#[derive(Debug, Clone)]
pub struct PortScanAllResult {
    pub ports_scanned: u16,
    pub packets_sent: u32,
    pub open_ports: Vec<u16>,
    pub start_time: SystemTime,
    pub end_time: SystemTime
}

impl PortScanAllResult {
    pub fn new() -> Self {

        PortScanAllResult {
            ports_scanned:0,
            packets_sent: 0,
            open_ports: Vec::new(),
            start_time: SystemTime::now(),
            end_time: SystemTime::now()

        }
    }
}

#[derive(Debug, Clone)]
pub struct HostDiscoverySingleResult {
    pub ip_address: IpAddr,
    pub dns_resolve: Option<String>,
    pub latency: Option<Duration>,
    pub is_up: bool,
    pub reply_type: String,
    pub ttl: u8
}

#[derive(Debug, Clone)]
pub struct HostDiscoveryAllResult {
    pub scanned_addresses: Vec<IpAddr>,
    pub ports_per_host: u16,
    pub hosts_up: u64,
    pub hosts_dns_resolution: u64,
    pub start_time: SystemTime,
    pub end_time: SystemTime,
    pub packets_sent: u64
}

impl HostDiscoveryAllResult {
    pub fn new() -> Self {

        HostDiscoveryAllResult {
            scanned_addresses: Vec::new(),
            ports_per_host: 0,
            hosts_up: 0,
            hosts_dns_resolution: 0,
            start_time: SystemTime::now(),
            end_time: SystemTime::now(),
            packets_sent: 0
        }
    }
}