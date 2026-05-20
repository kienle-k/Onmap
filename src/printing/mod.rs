//! # Printing and Formatting Utilities
//!
//! This module provides functions dedicated to formatting and printing the results
//! of various network scans to the console. It separates the presentation logic
//! from the core scanning and data-handling logic.

/// Contains functions for printing the results of a host discovery scan.
pub mod host_discovery_results;
pub use host_discovery_results::print_host_discovery_results;

/// Contains functions for printing the results of a port scan.
pub mod port_scanning_results;
pub use port_scanning_results::print_port_scan_results;

/// An alternative or original implementation for printing port scan results.
pub mod port_scanning_results_original;
pub use port_scanning_results_original::print_port_scan_results_original;

/// An alternative or original implementation for printing host discovery results.
pub mod host_discovery_results_original;
pub use host_discovery_results_original::print_host_discovery_results_original;

/// A utility function to format `Duration` objects into a human-readable string.
pub mod format_duration;
pub use format_duration::format_duration;
