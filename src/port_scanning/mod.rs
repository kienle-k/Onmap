//! # Port Scanning
//!
//! This module provides various methods for "port scanning," the process of
//! sending packets to specific ports on a host to determine their state
//! (e.g., open, closed, or filtered).
//!
//! Each submodule implements a different scanning technique. The primary `run_*`
//! function from each module is re-exported here for convenient access.

// --- TCP Scans ---

pub(crate) mod tcp_raw_scan;

/// Implements a TCP SYN scan, also known as a "half-open" or "stealth" scan.
pub mod syn_scan;
pub use syn_scan::run_syn_scan;

/// Implements a TCP Connect scan, which completes a full three-way handshake.
pub mod connect_scan;
pub use connect_scan::run_connect_scan;

/// Implements a TCP ACK scan, often used to map firewall rulesets.
pub mod ack_scan;
pub use ack_scan::run_ack_scan;

// --- UDP Scans ---

/// Implements a UDP scan to find open UDP ports.
pub mod upd_scan;
pub use upd_scan::run_udp_scan;
