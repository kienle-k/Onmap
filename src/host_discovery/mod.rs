//! # Host Discovery
//!
//! This module provides various methods for "host discovery," which is the process
//! of identifying live hosts on a network. These techniques can determine if a host
//! is online and responsive.
//!
//! Each submodule implements a different discovery technique, such as a standard
//! ICMP ping, a TCP SYN ping, or an ICMP netmask request. The primary functions
//! from these modules are re-exported here for convenient access.

// --- Standard Ping Scans ---

/// Implements host discovery using the operating system's native ICMP Echo (ping) command.
pub mod ping_scan;
pub use ping_scan::run_ping_scan;

// --- ICMP-based Discovery Methods ---

/// Implements host discovery using ICMP Echo Request packets (Type 8).
pub mod icmp_echo;
pub use icmp_echo::run_icmp_echo;

/// Implements host discovery using ICMP Netmask Request packets (Type 17).
pub mod icmp_netmask;
pub use icmp_netmask::run_icmp_netmask;

/// Implements host discovery using ICMP Timestamp Request packets (Type 13).
pub mod icmp_timestamp;
pub use icmp_timestamp::run_icmp_timestamp;

// --- TCP-based Discovery Methods ---

/// Implements host discovery by sending TCP SYN packets to specific ports.
pub mod tcp_syn_discovery;
pub use tcp_syn_discovery::run_tcp_syn_discovery;

/// Implements host discovery by sending TCP ACK packets to specific ports.
pub mod tcp_ack_discovery;
pub use tcp_ack_discovery::run_tcp_ack_discovery;

// --- ARP-based Discovery Methods ---

/// Implements host discovery using ARP requests.
pub mod arp;
pub use arp::run_arp;