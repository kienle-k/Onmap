use std::net::IpAddr;
use std::time::{Duration, SystemTime};
use clap::{Parser, Subcommand, ArgAction};



#[derive(Parser, Debug)]
#[command(author, version, about = "Onmap - A fast and memory-safe network scanning tool built in Rust.", long_about = None)]
pub struct Cli {
    /// Run in Text User Interface (TUI) mode
    #[arg(long)]
    pub tui: bool,

    /// Specify the scan type and its arguments
    #[command(subcommand)]
    pub command: Option<ScanCommand>,

    /// Disable original printing style, use modernized printing
    #[arg(short = 'm', long = "modern-print", global = true, help = "Use modern result printing", action = ArgAction::SetTrue)]
    pub modern_printing: bool,

    #[arg(
        name = "output_normal",
        short = 'o',        // The primary short flag is 'o'
        short_alias = 'N',  // This allows the 'N' to be attached directly
        id = "oN",          // Internal ID
        global = true, 
        value_name = "file",
        help = "Output scan in normal format (-oN <file>)"
    )]
    pub output_normal: Option<String>,

    #[arg(
        name = "output_xml",
        short = 'X', 
        global = true, 
        value_name = "file",
        help = "Output scan in XML format (-oX <file>)"
    )]
    pub output_xml: Option<String>,
}

#[derive(Subcommand, Debug)]
pub enum ScanCommand {
    /// SYN stealth scan
    #[command(name = "-sS", aliases = ["sS"])]
    SynScan {
        /// Port specification (e.g -pF, -p-, -p 80, -p1-1000)
        #[arg(short = 'p', long="ports")]
        ports: Option<String>,
        /// Target IP address, IP address list, IP range or CIDR
        #[arg(value_name = "Targets")]
        ips: String,
    },
    /// TCP connect scan
    #[command(name = "-sT", aliases = ["sT"])]
    ConnectScan {
        /// Port specification (e.g -pF, -p-, -p 80, -p1-1000)
        #[arg(short = 'p', long="ports")]
        ports: Option<String>,
        /// Target IP address, IP address list, IP range or CIDR
        #[arg(value_name = "TARGETS")]
        ips: String,
    },
    /// ACK scan (firewall rule discovery)
    #[command(name = "-sA", aliases = ["sA"])]
    AckScan {
        /// Port specification (e.g -pF, -p-, -p 80, -p1-1000)
        #[arg(short = 'p', long="ports")]
        ports: Option<String>,
        /// Target IP address, IP address list, IP range or CIDR
        #[arg(value_name = "TARGETS")]
        ips: String,
    },
    /// Ping scan (Host Discovery)
    #[command(name = "-sn", aliases = ["sn"])]
    PingScan {
        /// Target IP address, IP address list, IP range or CIDR
        #[arg(value_name = "TARGETS")]
        ips: String,
    },
    /// ICMP Echo scan (Host Discovery)
    #[command(name = "-PE", aliases = ["PE"])]
    IcmpEcho {
        /// Target IP address, IP address list, IP range or CIDR
        #[arg(value_name = "TARGETS")]
        ips: String,
    },
    /// ICMP Timestamp scan (Host Discovery)
    #[command(name = "-PP", aliases = ["PP"])]
    IcmpTimestamp {
        /// Target IP address, IP address list, IP range or CIDR
        #[arg(value_name = "TARGETS")]
        ips: String,
    },
    /// ARP scan (Host Discovery)
    #[command(name = "-PR", aliases = ["PR"])]
    Arp {
        /// Target IP address, IP address list, IP range or CIDR
        #[arg(value_name = "TARGETS")]
        ips: String,
    },

    /// TCP SYN discovery scan (Host Discovery)
    #[command(name = "-PS", aliases = ["PS"])]
    SynDiscovery {
        /// Port specification (e.g -pF, -p-, -p 80, -p1-1000)
        #[arg(short = 'p', long="ports")]
        ports: Option<String>,
        /// Target IP address, IP address list, IP range or CIDR
        #[arg(value_name = "TARGETS")]
        ips: String,
    },
}

/// Internal execution plan used to unify CLI and TUI flows.
#[derive(Debug, Clone)]
pub enum ExecutionCommand {
    HostDiscovery {
        method: HostDiscoveryOption,
        targets: Vec<IpAddr>,
        ports: Option<Vec<u16>>,
    },
    PortScan {
        method: PortScanOption,
        targets: Vec<IpAddr>,
        ports: Vec<u16>,
    },
    ServiceDetection {
        targets: Vec<IpAddr>,
    },
    OsDetection {
        targets: Vec<IpAddr>,
    },
}

/// Represents the current state or view of the application's user interface.
#[derive(PartialEq, Debug, Clone, Copy)]
pub enum AppState {
    /// The main menu screen where major scan types are selected.
    MainMenu,
    /// The sub-menu for choosing a specific host discovery method.
    SubMenuHostDiscovery,
    /// The sub-menu for choosing a specific port scanning method.
    SubMenuPortScan,
    /// The view for entering target IP addresses or networks.
    IpAddressInput,
    /// The view for selecting high-level port options (e.g., fast mode).
    PortOptions,
    /// The view for entering a specific range of ports to scan.
    PortRangeInput
}

/// Represents a selectable option within the main menu.
#[derive(PartialEq, Debug, Clone, Copy)]
pub enum MainMenuItem {
    /// Option to perform a host discovery scan.
    SubMenuHostDiscovery,
    /// Option to perform a port scan.
    SubMenuPortScan,
    /// Option to perform service and version detection (not yet implemented).
    SubMenuServiceDetection,
    /// Option to perform operating system detection (not yet implemented).
    SubMenuOperatingSystemDetection,
}

/// Defines the different techniques available for host discovery.
#[derive(PartialEq, Debug, Clone, Copy)]
pub enum HostDiscoveryOption {
    /// A no-scan scan; simply lists the targets without sending packets.
    ListScan,
    /// A standard ICMP echo request (ping) scan to see if hosts are up.
    PingScan,
    /// A discovery scan using TCP SYN packets.
    TcpSynDiscovery,
    /// A discovery scan using TCP ACK packets.
    TcpAckDiscovery,
    /// A discovery scan using UDP packets.
    UdpDiscovery,
    /// A discovery scan using ARP requests on the local network.
    ArpDiscovery,
    /// A discovery scan using ICMP Echo packets.
    IcmpEcho,
    /// A discovery scan using ICMP Timestamp requests.
    IcmpTimestamp,
    /// A discovery scan using ICMP Netmask requests.
    IcmpNetmask,
}

/// Defines the different techniques available for port scanning.
#[derive(PartialEq, Debug, Clone, Copy)]
pub enum PortScanOption {
    /// A stealthy "half-open" scan that sends a SYN packet and analyzes the response.
    SynScan,
    /// A full TCP handshake scan that uses the OS's `connect()` syscall.
    ConnectScan,
    /// An ACK scan used to map out firewall rulesets.
    AckScan,
    /// A scan that analyzes TCP Window sizes to infer port states.
    WindowScan,
    /// A subtle FIN/ACK scan variant.
    MaimonScan,
    /// A scan that sends a TCP packet with no flags set.
    NullScan,
    /// A scan that sends a TCP packet with only the FIN flag set.
    FinScan,
    /// A scan that sends a packet with FIN, PSH, and URG flags set.
    XmasScan,
    /// A scan for open UDP ports.
    UdpScan,
}

/// High-level options to configure a port scan.
#[derive(PartialEq, Debug, Clone, Copy)]
pub enum PortOptions {
    /// Scan the top 1,000 most common ports.
    NormalMode,
    /// Allow the user to input a custom port range.
    PortRangeInput,
    /// Scan the top 100 most common ports for a faster scan.
    FastMode,
    /// Scan all ports from 1 to 65535 sequentially.
    SequentialMode
}

/// Represents the determined state of a scanned network port.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum PortStates {
    /// The port is open and accepting connections.
    Open,
    /// The port is closed and actively refusing connections.
    Closed,
    /// The port's state cannot be determined, likely due to a firewall.
    Filtered,
    /// The port is not blocked by a stateful firewall (RST received).
    Unfiltered
}

/// The reason for a port's determined state, based on the network response.
#[derive(Clone, Copy, Debug)]
pub enum PortStateReasons {
    /// A SYN-ACK packet was received, indicating an open port.
    SynAck,
    /// A RST (reset) packet was received, indicating a closed port.
    Reset,
    /// A RST-ACK packet was received from an ACK scan, indicating an unfiltered port.
    Unfiltered,
    /// No response was received, indicating a filtered port or dropped packet.
    Timeout
}



/// The network protocol used for a scan.
#[derive(Clone, Copy, Debug)]
pub enum Protocols {
    /// Transmission Control Protocol.
    TCP
}

/// Holds the detailed result of a scan on a single port of a single host.
#[derive(Debug, Clone)]
pub struct PortScanSingleResult {
    /// The IP address of the host that was scanned.
    pub ip_address: IpAddr,
    /// The port number that was scanned.
    pub port: u16,
    /// The protocol used for the scan.
    pub protocol: Protocols,
    /// The determined state of the port (e.g., Open, Closed).
    pub port_state: PortStates,
    /// The Time-To-Live value from the response packet.
    pub ttl: u8,
    /// The network reason for the determined port state (e.g., SynAck).
    pub reason: PortStateReasons,
    /// The potential service running on the port (e.g., "http").
    pub service: String
}

/// Holds the summary and aggregate results of a port scan operation across multiple ports.
#[derive(Debug, Clone)]
pub struct PortScanAllResult {
    /// The total number of ports that were scanned.
    pub ports_scanned: u16,
    /// The total number of packets sent during the scan.
    pub packets_sent: u32,
    /// A vector of port numbers that were found to be open.
    pub open_ports: Vec<u16>,
    /// The timestamp when the scan began.
    pub start_time: SystemTime,
    /// The timestamp when the scan completed.
    pub end_time: SystemTime
}

impl PortScanAllResult {
    /// Creates a new, empty `PortScanAllResult` with default values and timers set to now.
    pub fn new() -> Self {
        PortScanAllResult {
            ports_scanned: 0,
            packets_sent: 0,
            open_ports: Vec::new(),
            start_time: SystemTime::now(),
            end_time: SystemTime::now()
        }
    }
}

/// Holds the detailed result of a discovery probe against a single host.
#[derive(Debug, Clone)]
pub struct HostDiscoverySingleResult {
    /// The IP address of the host that was probed.
    pub ip_address: IpAddr,
    /// The resolved DNS name of the host, if available.
    pub dns_resolve: Option<String>,
    /// The round-trip time for the probe, if successful.
    pub latency: Option<Duration>,
    /// A boolean indicating whether the host is considered online.
    pub is_up: bool,
    /// A string describing the type of reply received (e.g., "echo-reply").
    pub reply_type: String,
    /// The Time-To-Live value from the response packet.
    pub ttl: u8
}

/// Holds the summary and aggregate results of a host discovery scan across multiple targets.
#[derive(Debug, Clone)]
pub struct HostDiscoveryAllResult {
    /// A list of all IP addresses that were targeted by the scan.
    pub scanned_addresses: Vec<IpAddr>,
    /// The number of ports that were probed on each host.
    pub ports_per_host: u16,
    /// The total count of hosts determined to be online.
    pub hosts_up: u64,
    /// The total count of hosts for which a DNS name was successfully resolved.
    pub hosts_dns_resolution: u64,
    /// The timestamp when the scan began.
    pub start_time: SystemTime,
    /// The timestamp when the scan completed.
    pub end_time: SystemTime,
    /// The total number of packets sent during the scan.
    pub packets_sent: u64
}

impl HostDiscoveryAllResult {
    /// Creates a new, empty `HostDiscoveryAllResult` with default values and timers set to now.
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