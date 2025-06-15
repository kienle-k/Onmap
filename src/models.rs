use std::net::IpAddr;
use std::time::{Duration, SystemTime};
use clap::{Parser, Subcommand, ArgAction};
use crate::parsing;

pub fn parse_ports_arg(s: &str) -> Result<Vec<u16>, String> {
    parsing::convert_ports(s.to_string())
        .map_err(|e| format!("Ungültiges Port-Format: {}", e))
}

#[derive(Parser, Debug)]
#[command(author, version, about = "Onmap 1.0 - Network Mapper (nmap clone)", long_about = None)]
pub struct Cli {
    /// Run in Text User Interface (TUI) mode
    #[arg(long)]
    pub tui: bool,

    #[command(subcommand)]
    pub command: Option<ScanCommand>,

    /// Disable original printing style, use modernized printing
    #[arg(long = "pp",global = true, help = "Activate pretty printing", action = ArgAction::SetTrue)]
    pub modern_printing: bool,
}

#[derive(Subcommand, Debug)]
pub enum ScanCommand {
    /// SYN stealth scan
    #[command(name = "sS")]
    SynScan {
        /// Port specification (e.g., -p22,80, -p1-1024)
        #[arg(short = 'p')]
        ports: Option<String>,
        /// Target IP addresses or CIDR (e.g., 192.168.1.1, 192.168.1.0/24)
        ips: String,
    },
    /// TCP connect scan
    #[command(name = "sT")]
    ConnectScan {
        /// Port specification (e.g., -p22,80, -p1-1024)
        #[arg(short = 'p')]
        ports: Option<String>,
        /// Target IP addresses or CIDR (e.g., 192.168.1.1, 192.168.1.0/24)
        ips: String,
    },
    /// ACK scan (for firewall rule discovery)
    #[command(name = "sA")]
    AckScan {
        /// Port specification (e.g., -p22,80, -p1-1024)
        #[arg(short = 'p')]
        ports: Option<String>,
        /// Target IP addresses or CIDR (e.g., 192.168.1.1, 192.168.1.0/24)
        ips: String,
    },
    /// Ping scan (Host Discovery)
    #[command(name = "sn")]
    PingScan {
        /// Target IP addresses or CIDR (e.g., 192.168.1.1, 192.168.1.0/24)
        ips: String,
    },
    /// ICMP Echo scan (Host Discovery)
    #[command(name = "PE")]
    IcmpEcho {
        /// Target IP addresses or CIDR (e.g., 192.168.1.1, 192.168.1.0/24)
        ips: String,
    },
}





#[derive(PartialEq, Debug, Clone, Copy)]
pub enum AppState {
    MainMenu,
    SubMenuHostDiscovery,
    SubMenuPortScan,
    IpAddressInput,
    PortOptions,
    PortRangeInput
}

#[derive(PartialEq, Debug, Clone, Copy)]
pub enum MainMenuItem {
    SubMenuHostDiscovery,
    SubMenuPortScan,
    SubMenuServiceDetection,
    SubMenuOperatingSystemDetection,
}


#[derive(PartialEq, Debug, Clone, Copy)]
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

#[derive(PartialEq, Debug, Clone, Copy)]
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

#[derive(PartialEq, Debug, Clone, Copy)]
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