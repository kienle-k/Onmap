use crate::models::{HostDiscoveryAllResult, HostDiscoverySingleResult};
use chrono::{DateTime, Local};
use std::fs::File;
use std::io::Write;

pub fn save_to_file_normal_host_discovery(
    path: &str,
    results: (&Vec<HostDiscoverySingleResult>, &HostDiscoveryAllResult),
) -> std::io::Result<()> {
    let (single_results, summary) = results;
    let mut file = File::create(path)?;

    let start_dt: DateTime<Local> = summary.start_time.into();
    writeln!(
        file,
        "# Onmap {} scan initiated {}",
        env!("CARGO_PKG_VERSION"),
        start_dt.format("%a %b %e %H:%M:%S %Y")
    )?;

    for host in single_results {
        if !host.is_up {
            continue;
        }
        if let Some(dns) = &host.dns_resolve {
            writeln!(file, "Nmap scan report for {} ({})", dns, host.ip_address)?;
        } else {
            writeln!(file, "Nmap scan report for {}", host.ip_address)?;
        }
        if let Some(latency) = host.latency {
            let secs = latency.as_secs_f64();
            if secs >= 0.001 {
                writeln!(file, "Host is up ({:.4}s latency).", secs)?;
            } else {
                writeln!(file, "Host is up ({:.7}s latency).", secs)?;
            }
        } else {
            writeln!(file, "Host is up.")?;
        }
    }

    let elapsed = summary
        .end_time
        .duration_since(summary.start_time)
        .unwrap_or_default()
        .as_secs_f64();
    let end_dt: DateTime<Local> = summary.end_time.into();
    let total = summary.scanned_addresses.len();
    let up = summary.hosts_up;
    writeln!(
        file,
        "# Onmap done at {} -- {} IP address{} ({} host{} up) scanned in {:.2} seconds",
        end_dt.format("%a %b %e %H:%M:%S %Y"),
        total,
        if total == 1 { "" } else { "es" },
        up,
        if up == 1 { "" } else { "s" },
        elapsed
    )?;

    println!("Successfully saved host discovery results to: {}", path);
    Ok(())
}
