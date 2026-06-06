//! # Output and Formatting Utilities
//!
//! This module contains all user-facing output code: terminal printing, file
//! writers, and shared formatting/result-processing helpers.

/// Shared utility to format `Duration` values for terminal output.
pub mod format_duration;

/// Shared host-discovery output-name processing.
pub mod host_result_processing;
/// Shared port-result grouping and output-name processing.
pub mod port_result_processing;
/// Terminal output modules.
pub mod printing;
/// File output modules.
pub mod writing;

pub use format_duration::format_duration;
pub use host_result_processing::{host_reply_display_name, host_reply_nmap_reason};
pub use port_result_processing::{
    collapse_threshold, extraport_reason_name, format_port_ranges, port_state_name,
    protocol_display_name, protocol_name, state_reason_display_name, state_reason_name,
    state_reason_with_ttl, summarize_ports, ttl_display_value,
};
pub use printing::{
    print_host_discovery_results::print_host_discovery_results,
    print_host_discovery_results_original::print_host_discovery_results_original,
    print_port_scan_results::print_port_scan_results,
    print_port_scan_results_original::print_port_scan_results_original,
};
pub use writing::{
    write_grepable_host_discovery::save_to_file_grepable_host_discovery,
    write_grepable_port_scan::save_to_file_grepable_port_scan,
    write_normal_host_discovery::save_to_file_normal_host_discovery,
    write_normal_port_scan::save_to_file_normal_port_scan,
    write_xml_host_discovery::save_to_file_xml_host_discovery,
    write_xml_port_scan::save_to_file_xml_port_scan,
};
