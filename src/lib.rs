// --- Module declarations ---
mod host_discovery;
mod port_scanning;
mod service_detection;
mod os_detection;
mod tui;

// --- Public API modules ---
pub mod models;
pub mod parsing;
pub mod printing;
pub mod resolving;
mod output;

// --- Standard library imports ---
use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::io::Write;

// --- External crate imports ---
use chrono::prelude::*;
use chrono_tz::Tz;
use crossterm::{
    event::{DisableMouseCapture, EnableMouseCapture},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use iana_time_zone::get_timezone;
use local_ip_address::local_ip;
use ratatui::backend::CrosstermBackend;
use ratatui::terminal::Terminal;

// --- Internal imports (from this crate) ---
use models::{Cli, ExecutionCommand, ScanCommand, HostDiscoveryAllResult, HostDiscoverySingleResult, PortOptions, MainMenuItem, HostDiscoveryOption, PortScanOption, PortScanAllResult, PortScanSingleResult};
use printing::{print_port_scan_results, print_host_discovery_results, print_port_scan_results_original, print_host_discovery_results_original};
use crate::host_discovery::{run_icmp_netmask};
use crate::os_detection::run_os_detection;
use crate::service_detection::run_service_detection;
use crate::tui::{run_app, App};
use crate::output::{save_to_file_xml_host_discovery, save_to_file_xml_port_scan};


// --- Main public entry point ---
/// Runs the Onmap application with the given CLI arguments.
/// Handles both TUI and CLI modes.

#[tokio::main]
pub async fn run_onmap(cli : Cli) -> Result<(), io::Error> {    
    // Flush to enable TUI in docker (test environment)
    // This is a quick fix for an issue where the TUI doesn't display inside the container
    io::stdout().flush()?;


    // for tcp connect scan
    let connect_timeout: u64 = 300;

    // Get the local source IP for proper checksum calculation
    let local_ip_address: Ipv4Addr = match local_ip() {
        Ok(ip) => match ip {
            IpAddr::V4(ipv4) => ipv4,
            IpAddr::V6(_) => {
                println!("Got an IPv6 address, but need IPv4 for some operations. Defaulting to localhost.");
                // Default to localhost the result is IPv6
                Ipv4Addr::new(127, 0, 0, 1)
            }
        },
        Err(e) => {
            eprintln!("Error getting local IP: {}. Defaulting to localhost.", e);
            // Default to localhost on error
            Ipv4Addr::new(127, 0, 0, 1)
        }
    };

    // Initialize results variables
    // --> They are populated with data by the user-specified function that performs the scan
    let mut port_scan_result: (Vec<PortScanSingleResult>, PortScanAllResult) = (Vec::new(), PortScanAllResult::new());
    let mut host_discovery_result: (Vec<HostDiscoverySingleResult>, HostDiscoveryAllResult) = (Vec::new(), HostDiscoveryAllResult::new());


    // Extract the `modern_printing` flag from the parsed `cli` struct --> use different print styles based on user spec
    let use_original_printing = !cli.modern_printing;

    // Extract tui argument --> decide whether to use CLI args or open TUI
    let use_tui = cli.tui;

    // MODE selection: Either TUI (Text-User-Interface) if specified, else use CLI-Arguments (Command-Line-Interface)
    let command_result = if use_tui {
        // Setup terminal
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
        let backend = CrosstermBackend::new(stdout);
        let mut terminal = Terminal::new(backend)?;

        // Create app state
        let mut app = App::new();

        // Main TUI loop
        let res = run_app(&mut terminal, &mut app);

        // Restore terminal
        disable_raw_mode()?;
        execute!(
            terminal.backend_mut(),
            LeaveAlternateScreen,
            DisableMouseCapture
        )?;
        terminal.show_cursor()?;

        match res {
            Ok((
                main_selected,
                host_discovery_selected,
                port_scan_selected,
                ip_input,
                port_needed,
                port_mode,
                port_input,
            )) => build_command_from_tui(
                main_selected,
                host_discovery_selected,
                port_scan_selected,
                &ip_input,
                port_needed,
                port_mode,
                &port_input,
            ),
            Err(e) => Err(format!("TUI Application Error: {:?}", e)),
        }
    } else {
        build_command_from_cli(&cli)
    };

    let command = match command_result {
        Ok(Some(cmd)) => cmd,
        Ok(None) => {
            if use_tui {
                println!("No main menu item was selected, or TUI was exited prematurely.");
            } else {
                println!("No scan method specified. Use `onmap --help` for usage information.");
            }
            return Ok(());
        }
        Err(e) => {
            eprintln!("{}", e);
            std::process::exit(1);
        }
    };

    print_startup_message();

    let (host_result_opt, port_result_opt) = match execute_command(
        command,
        local_ip_address,
        connect_timeout,
        use_original_printing,
    ).await {
        Ok(result) => result,
        Err(e) => {
            eprintln!("{}", e);
            std::process::exit(1);
        }
    };

    if let Some(result) = host_result_opt {
        host_discovery_result = result;
    }

    if let Some(result) = port_result_opt {
        port_scan_result = result;
    }

    if let Some(path) = &cli.output_xml {
        let mut saved = false;

        if !host_discovery_result.0.is_empty() {
            save_to_file_xml_host_discovery(path, (&host_discovery_result.0, &host_discovery_result.1))?;
            saved = true;
        }

        if !port_scan_result.0.is_empty() {
            save_to_file_xml_port_scan(path, (&port_scan_result.0, &port_scan_result.1))?;
            saved = true;
        }

        if !saved {
            println!("No results available to save to XML.");
        }
    }

    Ok(())
}

type HostDiscoveryResult = (Vec<HostDiscoverySingleResult>, HostDiscoveryAllResult);
type PortScanResult = (Vec<PortScanSingleResult>, PortScanAllResult);

fn build_command_from_tui(
    main_selected: Option<MainMenuItem>,
    host_discovery_selected: Option<HostDiscoveryOption>,
    port_scan_selected: Option<PortScanOption>,
    ip_input: &str,
    port_needed: bool,
    port_mode: Option<PortOptions>,
    port_input: &str,
) -> Result<Option<ExecutionCommand>, String> {
    let main_selected = match main_selected {
        Some(selected) => selected,
        None => return Ok(None),
    };

    let targets = parse_targets(ip_input)?;

    let ports = if port_needed {
        let port_mode = port_mode.ok_or_else(|| "Ports array could not be set".to_string())?;
        let ports = match port_mode {
            PortOptions::NormalMode => parsing::set_ports_arr(PortOptions::NormalMode),
            PortOptions::PortRangeInput => parsing::convert_ports(port_input.to_string()),
            PortOptions::FastMode => parsing::set_ports_arr(PortOptions::FastMode),
            PortOptions::SequentialMode => parsing::set_ports_arr(PortOptions::SequentialMode),
        }?;
        Some(ports)
    } else {
        None
    };

    let command = match main_selected {
        MainMenuItem::SubMenuHostDiscovery => {
            let method = host_discovery_selected.ok_or_else(|| "No host discovery option selected".to_string())?;
            ExecutionCommand::HostDiscovery {
                method,
                targets,
                ports,
            }
        }
        MainMenuItem::SubMenuPortScan => {
            let method = port_scan_selected.ok_or_else(|| "No port scan option selected".to_string())?;
            let ports = ports.ok_or_else(|| "Ports array could not be set".to_string())?;
            ExecutionCommand::PortScan {
                method,
                targets,
                ports,
            }
        }
        MainMenuItem::SubMenuServiceDetection => ExecutionCommand::ServiceDetection { targets },
        MainMenuItem::SubMenuOperatingSystemDetection => ExecutionCommand::OsDetection { targets },
    };

    Ok(Some(command))
}

fn build_command_from_cli(cli: &Cli) -> Result<Option<ExecutionCommand>, String> {
    let command = match &cli.command {
        None => return Ok(None),
        Some(ScanCommand::SynScan { ports, ips }) => ExecutionCommand::PortScan {
            method: PortScanOption::SynScan,
            targets: parse_targets(ips)?,
            ports: parse_ports_spec(ports.as_ref())?,
        },
        Some(ScanCommand::ConnectScan { ports, ips }) => ExecutionCommand::PortScan {
            method: PortScanOption::ConnectScan,
            targets: parse_targets(ips)?,
            ports: parse_ports_spec(ports.as_ref())?,
        },
        Some(ScanCommand::AckScan { ports, ips }) => ExecutionCommand::PortScan {
            method: PortScanOption::AckScan,
            targets: parse_targets(ips)?,
            ports: parse_ports_spec(ports.as_ref())?,
        },
        Some(ScanCommand::UdpScan { ports, ips }) => ExecutionCommand::PortScan {
            method: PortScanOption::UdpScan,
            targets: parse_targets(ips)?,
            ports: parse_ports_spec(ports.as_ref())?,
        },
        Some(ScanCommand::PingScan { ips }) => ExecutionCommand::HostDiscovery {
            method: HostDiscoveryOption::PingScan,
            targets: parse_targets(ips)?,
            ports: None,
        },
        Some(ScanCommand::IcmpEcho { ips }) => ExecutionCommand::HostDiscovery {
            method: HostDiscoveryOption::IcmpEcho,
            targets: parse_targets(ips)?,
            ports: None,
        },
        Some(ScanCommand::IcmpTimestamp { ips }) => ExecutionCommand::HostDiscovery {
            method: HostDiscoveryOption::IcmpTimestamp,
            targets: parse_targets(ips)?,
            ports: None,
        },
        Some(ScanCommand::Arp { ips }) => ExecutionCommand::HostDiscovery {
            method: HostDiscoveryOption::ArpDiscovery,
            targets: parse_targets(ips)?,
            ports: None,
        },
        Some(ScanCommand::SynDiscovery { ports, ips }) => ExecutionCommand::HostDiscovery {
            method: HostDiscoveryOption::TcpSynDiscovery,
            targets: parse_targets(ips)?,
            ports: Some(parse_ports_spec(ports.as_ref())?),
        },
        Some(ScanCommand::AckDiscovery { ports, ips }) => ExecutionCommand::HostDiscovery {
            method: HostDiscoveryOption::TcpAckDiscovery,
            targets: parse_targets(ips)?,
            ports: Some(parse_ports_spec(ports.as_ref())?),
        },
    };

    Ok(Some(command))
}

fn parse_ports_spec(ports: Option<&String>) -> Result<Vec<u16>, String> {
    let ports_str = ports.ok_or_else(|| "Ports must be provided".to_string())?;
    parsing::convert_ports(ports_str.to_string())
        .map_err(|e| format!("Invalid port specification: {}", e))
}

fn parse_targets(ips: &str) -> Result<Vec<IpAddr>, String> {
    parsing::parse_ip_addresses(ips)
        .map(|targets| targets.into_iter().map(IpAddr::V4).collect())
}

fn to_ipv4_vec(targets: &[IpAddr]) -> Result<Vec<Ipv4Addr>, String> {
    let mut ipv4_targets = Vec::with_capacity(targets.len());
    for target in targets {
        match target {
            IpAddr::V4(ip) => ipv4_targets.push(*ip),
            IpAddr::V6(_) => return Err("IPv6 is not supported for this scan".to_string()),
        }
    }
    Ok(ipv4_targets)
}

fn requires_root(cmd: &ExecutionCommand) -> bool {
    match cmd {
        ExecutionCommand::PortScan { method, .. } => matches!(
            method,
            PortScanOption::SynScan | PortScanOption::AckScan | PortScanOption::UdpScan
        ),
        ExecutionCommand::HostDiscovery { method, .. } => matches!(
            method,
            HostDiscoveryOption::IcmpEcho
                | HostDiscoveryOption::IcmpTimestamp
                | HostDiscoveryOption::IcmpNetmask
                | HostDiscoveryOption::ArpDiscovery
                | HostDiscoveryOption::TcpSynDiscovery
                | HostDiscoveryOption::TcpAckDiscovery
        ),
        ExecutionCommand::ServiceDetection { .. } | ExecutionCommand::OsDetection { .. } => false,
    }
}

async fn execute_command(
    command: ExecutionCommand,
    local_ip_address: Ipv4Addr,
    connect_timeout: u64,
    use_original_printing: bool,
) -> Result<(Option<HostDiscoveryResult>, Option<PortScanResult>), String> {

    let is_root = nix::unistd::Uid::effective().is_root();

    if requires_root(&command) && !is_root {
        return Err("This scan requires root privileges.".to_string());
    }
    
    match command {
        ExecutionCommand::HostDiscovery { method, targets, ports } => {
            let ipv4_targets = to_ipv4_vec(&targets)?;

            let result = match method {
                HostDiscoveryOption::ListScan => {
                    println!("Doing ListScan (Implementation coming soon)");
                    return Ok((None, None));
                }
                HostDiscoveryOption::PingScan => host_discovery::run_ping_scan(Ok(ipv4_targets)).await?,
                HostDiscoveryOption::TcpSynDiscovery => {
                    let ports = ports.ok_or_else(|| "Ports array could not be set".to_string())?;
                    host_discovery::run_tcp_syn_discovery(Ok(ipv4_targets), ports, local_ip_address).await?
                }
                HostDiscoveryOption::TcpAckDiscovery => {
                    let ports = ports.ok_or_else(|| "Ports array could not be set".to_string())?;
                    host_discovery::run_tcp_ack_discovery(Ok(ipv4_targets), ports, local_ip_address).await?
                }
                HostDiscoveryOption::UdpDiscovery => {
                    println!("Doing UdpDiscovery (Implementation coming soon)");
                    return Ok((None, None));
                }
                HostDiscoveryOption::ArpDiscovery => host_discovery::run_arp(Ok(ipv4_targets)).await?,
                HostDiscoveryOption::IcmpEcho => host_discovery::run_icmp_echo(Ok(ipv4_targets)).await?,
                HostDiscoveryOption::IcmpTimestamp => host_discovery::run_icmp_timestamp(Ok(ipv4_targets)).await?,
                HostDiscoveryOption::IcmpNetmask => {
                    run_icmp_netmask();
                    return Ok((None, None));
                }
            };

            if use_original_printing {
                print_host_discovery_results_original(&result);
            } else {
                print_host_discovery_results(&result);
            }

            Ok((Some(result), None))
        }
        ExecutionCommand::PortScan { method, targets, ports } => {
            let ipv4_targets = to_ipv4_vec(&targets)?;

            let result = match method {
                PortScanOption::SynScan => port_scanning::run_syn_scan(Ok(ipv4_targets), ports, local_ip_address).await?,
                PortScanOption::ConnectScan => port_scanning::run_connect_scan(Ok(ipv4_targets), ports, connect_timeout).await?,
                PortScanOption::AckScan => port_scanning::run_ack_scan(Ok(ipv4_targets), &ports, local_ip_address).await?,
                PortScanOption::WindowScan => {
                    println!("Doing WindowScan (Implementation coming soon)");
                    return Ok((None, None));
                }
                PortScanOption::MaimonScan => {
                    println!("Doing MaimonScan (Implementation coming soon)");
                    return Ok((None, None));
                }
                PortScanOption::NullScan => {
                    println!("Doing NullScan (Implementation coming soon)");
                    return Ok((None, None));
                }
                PortScanOption::FinScan => {
                    println!("Doing FinScan (Implementation coming soon)");
                    return Ok((None, None));
                }
                PortScanOption::XmasScan => {
                    println!("Doing XmasScan (Implementation coming soon)");
                    return Ok((None, None));
                }
                PortScanOption::UdpScan => port_scanning::run_udp_scan(Ok(ipv4_targets), ports, local_ip_address).await?
            };

            if use_original_printing {
                print_port_scan_results_original(&result).await;
            } else {
                print_port_scan_results(&result);
            }

            Ok((None, Some(result)))
        }
        ExecutionCommand::ServiceDetection { .. } => {
            run_service_detection();
            Ok((None, None))
        }
        ExecutionCommand::OsDetection { .. } => {
            run_os_detection();
            Ok((None, None))
        }
    }
}



/// Print startup message
fn print_startup_message(){
    // Use cargo env to gather version and package name
    // Format time to fit the user settings
    let tz_str = get_timezone().expect("Failed to get system timezone");
    let tz: Tz = tz_str.parse().expect("Invalid timezone string");
    let now = Utc::now().with_timezone(&tz);
    let formatted_time = now.format("%Y-%m-%d %H:%M %Z").to_string();
    let version = env!("CARGO_PKG_VERSION");
    let name = env!("CARGO_PKG_NAME");
    println!("\nStarting {} {} (https://github.com/kienle-k/Onmap) at {}", name, version, formatted_time);
}




