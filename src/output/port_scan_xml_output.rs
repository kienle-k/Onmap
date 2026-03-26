use std::fs::File;
use std::io::Write;
use std::time::UNIX_EPOCH;
use crate::models::{PortScanSingleResult, PortScanAllResult, PortStates};
use std::collections::HashMap;

pub fn save_to_file_xml_port_scan(
    path: &str, 
    results: (&Vec<PortScanSingleResult>, &PortScanAllResult)
) -> std::io::Result<()> {
    let (single_results, summary) = results;
    let mut file = File::create(path)?;

    let start_timestamp = summary.start_time.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    writeln!(file, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>")?;
    writeln!(file, "<nmaprun scanner=\"onmap\" start=\"{}\" version=\"1.0\">", start_timestamp)?;

    // Group single results by IP Address
    let mut host_map: HashMap<std::net::IpAddr, Vec<&PortScanSingleResult>> = HashMap::new();
    for res in single_results {
        host_map.entry(res.ip_address).or_default().push(res);
    }

    for (ip, ports) in host_map {
        writeln!(file, "  <host>")?;
        writeln!(file, "    <status state=\"up\" reason=\"user-set\"/>")?;
        writeln!(file, "    <address addr=\"{}\" addrtype=\"ipv4\"/>", ip)?;
        writeln!(file, "    <ports>")?;
        
        for p in ports {
            let state_str = match p.port_state {
                PortStates::Open => "open",
                PortStates::Closed => "closed",
                PortStates::Filtered => "filtered",
                PortStates::Unfiltered => "unfiltered",
            };
            writeln!(file, "      <port protocol=\"tcp\" portid=\"{}\">", p.port)?;
            writeln!(file, "        <state state=\"{}\" reason=\"{:?}\" reason_ttl=\"{}\"/>", state_str, p.reason, p.ttl)?;
            writeln!(file, "        <service name=\"{}\" method=\"table\"/>", p.service)?;
            writeln!(file, "      </port>")?;
        }
        
        writeln!(file, "    </ports>")?;
        writeln!(file, "  </host>")?;
    }

    let end_timestamp = summary.end_time.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    writeln!(file, "  <runstats><finished time=\"{}\" exit=\"success\"/></runstats>", end_timestamp)?;
    writeln!(file, "</nmaprun>")?;

    println!("Successfully saved port scan results to: {}", path);
    Ok(())
}