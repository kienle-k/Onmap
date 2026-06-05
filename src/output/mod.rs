//! # Output and Formatting Utilities
//!
//! This module contains all user-facing output code: terminal printing, file
//! writers, and shared formatting/result-processing helpers.

/// Shared utility to format `Duration` values for terminal output.
pub mod format_duration;

/// Shared port-result grouping and output-name processing.
pub mod port_result_processing;
/// Terminal output for host discovery results.
pub mod print_host_discovery_results;
/// Original terminal output for host discovery results.
pub mod print_host_discovery_results_original;
/// Terminal output for port scan results.
pub mod print_port_scan_results;
/// Original terminal output for port scan results.
pub mod print_port_scan_results_original;
/// File output for host discovery in grepable format.
pub mod write_grepable_host_discovery;
/// File output for port scans in grepable format.
pub mod write_grepable_port_scan;
/// File output for host discovery in normal text format.
pub mod write_normal_host_discovery;
/// File output for port scans in normal text format.
pub mod write_normal_port_scan;
/// File output for host discovery in XML format.
pub mod write_xml_host_discovery;
/// File output for port scans in XML format.
pub mod write_xml_port_scan;

pub use format_duration::format_duration;
pub use port_result_processing::{
    collapse_threshold, extraport_reason_name, format_port_ranges, port_state_name,
    protocol_display_name, protocol_name, state_reason_display_name, state_reason_name,
    state_reason_with_ttl, summarize_ports, ttl_display_value,
};
pub use print_host_discovery_results::print_host_discovery_results;
pub use print_host_discovery_results_original::print_host_discovery_results_original;
pub use print_port_scan_results::print_port_scan_results;
pub use print_port_scan_results_original::print_port_scan_results_original;
pub use write_grepable_host_discovery::save_to_file_grepable_host_discovery;
pub use write_grepable_port_scan::save_to_file_grepable_port_scan;
pub use write_normal_host_discovery::save_to_file_normal_host_discovery;
pub use write_normal_port_scan::save_to_file_normal_port_scan;
pub use write_xml_host_discovery::save_to_file_xml_host_discovery;
pub use write_xml_port_scan::save_to_file_xml_port_scan;
