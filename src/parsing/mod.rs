//! # Parsing
//!
//! This module provides utility functions for parsing user input related to network
//! scanning targets, such as IP addresses and port numbers. It centralizes the logic
//! for handling different formats, like CIDR notation for IPs and port ranges.

/// Contains functions for parsing IP address strings into usable `Ipv4Addr` objects.
pub mod ip_addresses;
/// Re-exports the primary function for parsing strings into a vector of IP addresses.
pub use ip_addresses::parse_ip_addresses;

/// Contains functions for handling port numbers and port ranges.
pub mod ports;
/// Re-exports a function to convert a string range (e.g., "80-100") into a vector of ports.
pub use ports::convert_port_range_to_arr;
pub use ports::convert_ports;
/// Re-exports a function to set a port array based on a predefined mode (e.g., fast, normal).
pub use ports::set_ports_arr;