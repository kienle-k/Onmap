//! File output writers for scan results.

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
