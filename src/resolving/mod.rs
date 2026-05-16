//! # Resolving and Data Extraction Utilities
//!
//! This module provides functions related to network name resolution and
//! data parsing. It includes utilities for resolving hostnames to IP addresses,
//! finding system nameservers, and extracting specific information like TTL
//! values or service names from network protocols.

/// Finds system DNS nameservers by parsing the `/etc/resolv.conf` file.
pub mod get_resolv_conf_nameservers;
pub use get_resolv_conf_nameservers::get_resolv_conf_nameservers;

/// Resolves a given hostname to its corresponding IP address.
pub mod resolve_hostname;
pub use resolve_hostname::resolve_hostname;

/// Extracts the Time-To-Live (TTL) value from the output of a ping command.
pub mod extract_ttl;
pub use extract_ttl::extract_ttl;

/// Contains logic for mapping port numbers and protocols to service names.
pub mod get_service_name;