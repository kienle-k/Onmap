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
use models::{Cli, ScanCommand, HostDiscoveryAllResult, HostDiscoverySingleResult, PortOptions, MainMenuItem, HostDiscoveryOption, PortScanOption, PortScanAllResult, PortScanSingleResult};
use printing::{print_port_scan_results, print_host_discovery_results, print_port_scan_results_original, print_host_discovery_results_original};
use crate::host_discovery::{run_icmp_netmask, run_icmp_timestamp, run_tcp_syn_discovery};
use crate::os_detection::run_os_detection;
use crate::port_scanning::run_udp_scan;
use crate::service_detection::run_service_detection;
use crate::tui::{run_app, App};


// --- Main public entry point ---
/// Runs the Onmap application with the given CLI arguments.
/// Handles both TUI and CLI modes.

#[tokio::main]
pub async fn run_onmap(cli : Cli) -> Result<(), io::Error> {    
    // Flush to enable TUI in docker (test environment)
    // This is a quick fix for an issue where the TUI doesn't display inside the container
    io::stdout().flush()?;


    // for tcp connect scan
    let connect_timeout = 300;

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

    // TUI
    if use_tui {
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
        
        // Handle application result from TUI
        if let Ok((
            main_selected,
            host_discovery_selected,
            port_scan_selected,
            ip_input,
            port_needed,
            port_mode,
            port_input)) = res {
            
            print_startup_message();

            if let Some(main_selected) = main_selected {
                
                // Parsing of ip addresses
                let ip_addresses_arr = match parsing::parse_ip_addresses(&ip_input) {
                    Ok(addresses) => addresses,
                    Err(e) => {
                        eprintln!("Error parsing IP addresses: {}", e);
                        std::process::exit(1);
                    }
                };

                // Parsing of ports
                let ports_arr: Result<Vec<u16>, String> = if port_needed {
                    if let Some(port_mode) = port_mode {
                        match port_mode {
                            PortOptions::NormalMode => parsing::set_ports_arr(PortOptions::NormalMode),
                            PortOptions::PortRangeInput => parsing::convert_ports(port_input),
                            PortOptions::FastMode => parsing::set_ports_arr(PortOptions::FastMode),
                            PortOptions::SequentialMode => parsing::set_ports_arr(PortOptions::SequentialMode)
                        }
                    } else {
                        Err("Ports array could not be set".to_string())
                    }
                } else {
                    Err("Ports array could not be set".to_string())
                };

                // Depending on what options are selected in the TUI the fitting scan will be executed
                match main_selected {

                    // When host discovery is selected in the tui
                    MainMenuItem::SubMenuHostDiscovery => {
                        if let Some(host_discovery_selected) = host_discovery_selected {

                            // Depending on what host discovery method is selected in the TUI
                            match host_discovery_selected {
                                HostDiscoveryOption::ListScan => println!("Doing ListScan (Implementation coming soon)"),
                                HostDiscoveryOption::PingScan => host_discovery_result = host_discovery::run_ping_scan(Ok(ip_addresses_arr)).await,
                                HostDiscoveryOption::TcpSynDiscovery => {
                                    run_tcp_syn_discovery();
                                    // Not implemented yet
                                },
                                HostDiscoveryOption::TcpAckDiscovery => println!("Doing TcpAckDiscovery (Implementation coming soon)"),
                                HostDiscoveryOption::UdpDiscovery => println!("Doing UdpDiscovery (Implementation coming soon)"),
                                HostDiscoveryOption::ArpDiscovery => println!("Doing ArpDiscovery (Implementation coming soon)"),
                                HostDiscoveryOption::IcmpEcho => host_discovery_result = host_discovery::run_icmp_echo(Ok(ip_addresses_arr)).await,
                                HostDiscoveryOption::IcmpTimestamp => {
                                    run_icmp_timestamp();
                                    // Not implemented yet
                                },
                                HostDiscoveryOption::IcmpNetmask => {
                                    run_icmp_netmask();
                                    // Not implemented yet
                                }
                            }
                            
                            // Use modern printing
                            if cli.modern_printing == true {
                                print_host_discovery_results(host_discovery_result);
                            } else {
                                print_host_discovery_results_original(host_discovery_result);
                            }
                        } else {
                            println!("No host discovery option selected or an error occurred.");
                        }
                    }
                    // When port scan is selected as an option in the TUI
                    MainMenuItem::SubMenuPortScan => {
                        if let Some(port_scan_selected) = port_scan_selected {

                            // Depending on what port scan is selected in the TUI
                            match port_scan_selected {
                                PortScanOption::SynScan => {
                                    match port_scanning::run_syn_scan(Ok(ip_addresses_arr), ports_arr.expect("Ports array not be set"), local_ip_address).await {
                                        Ok(result) => port_scan_result = result,
                                        Err(e) => eprintln!("SYN scan failed: {}", e),
                                    }
                                },
                                PortScanOption::ConnectScan => {
                                    match port_scanning::run_connect_scan(Ok(ip_addresses_arr), ports_arr.expect("Ports array could not be set"), connect_timeout).await { // Assuming 300ms timeout
                                        Ok(result) => port_scan_result = result,
                                        Err(e) => eprintln!("TCP-Connect scan failed: {}", e),
                                    }
                                },
                                PortScanOption::AckScan => {
                                    match port_scanning::run_ack_scan(Ok(ip_addresses_arr), &ports_arr.expect("Ports array could not be set"), local_ip_address).await { // Assuming 300ms timeout
                                        Ok(result) => port_scan_result = result,
                                        Err(e) => eprintln!("ACK scan failed: {}", e),
                                    }
                                    // port_scan_result = port_scanning::run_ack_scan(Ok(ip_addresses_arr), &ports_arr.expect("Ports array could not be set"), local_ip_address).await;
                                },
                                PortScanOption::WindowScan => println!("Doing WindowScan (Implementation coming soon)"),
                                PortScanOption::MaimonScan => println!("Doing MaimonScan (Implementation coming soon)"),
                                PortScanOption::NullScan => println!("Doing NullScan (Implementation coming soon)"),
                                PortScanOption::FinScan => println!("Doing FinScan (Implementation coming soon)"),
                                PortScanOption::XmasScan => println!("Doing XmasScan (Implementation coming soon)"),
                                PortScanOption::UdpScan => {
                                    run_udp_scan();
                                    // Not implemented yet
                                }
                            }
                            // Use modern printing
                            if cli.modern_printing == true {
                                print_port_scan_results(port_scan_result);
                            } else {
                                print_port_scan_results_original(port_scan_result).await;
                            }
                        } else {
                            println!("No port scan option selected or an error occurred.");
                        }
                    }
                    // When service detection is selected as an option in the TUI
                    MainMenuItem::SubMenuServiceDetection => {
                        run_service_detection();
                        // Not implemented yet
                    },
                    // When os detection is selected as an option in the TUI
                    MainMenuItem::SubMenuOperatingSystemDetection => {
                        run_os_detection();
                        // Not implemented yet
                    },
                }
            } else {
                 println!("No main menu item was selected, or TUI was exited prematurely.");
            }
        } else if let Err(e) = res {
             // This case handles if run_app itself returns an error, not if the user exits without selection.
            eprintln!("TUI Application Error: {:?}", e);
        }
        // else: TUI finished without error but didn't yield the expected tuple.
        // This could happen if run_app returns Ok(()) without selections,
        // or if the user quits in a way that doesn't populate the selections.

    // CLI Arguments
    } else {
        // Extract CLI specs --> build ip and port range arrays

        // Extract IP addresses array only once (if applicable)
        let ip_addresses_arr = match &cli.command {
            Some(ScanCommand::PingScan { ips })
            | Some(ScanCommand::IcmpEcho { ips })
            | Some(ScanCommand::SynScan { ips, .. })
            | Some(ScanCommand::ConnectScan { ips, .. })
            | Some(ScanCommand::AckScan { ips, .. }) => parsing::parse_ip_addresses(ips),
            None => Ok(Vec::new()),
        };

        // Extract ports only once (if applicable, some scans dont need ports specificed)
        let ports_vec = match &cli.command {
            Some(ScanCommand::SynScan { ports, .. })
            | Some(ScanCommand::ConnectScan { ports, .. })
            | Some(ScanCommand::AckScan { ports, .. }) => {
                let ports_str = ports.as_ref().unwrap_or_else(|| {
                    eprintln!("Ports must be provided");
                    std::process::exit(1);
                });
                parsing::convert_ports(ports_str.to_string()).unwrap_or_else(|e| {
                    eprintln!("Invalid port specification: {}", e);
                    std::process::exit(1);
                })
            }
            _ => Vec::new(),
        };



        print_startup_message();


        // Execute specific scan & print results
        match cli.command {
            Some(ScanCommand::SynScan { ports: _, ips: _ }) => {   
                let scan_result = port_scanning::run_syn_scan(ip_addresses_arr, ports_vec, local_ip_address).await;
                match scan_result {
                    Ok(result) => port_scan_result = result,
                    Err(e) => eprintln!("SYN scan failed: {}", e),
                }
                if use_original_printing {
                    print_port_scan_results_original(port_scan_result).await;
                } else {
                    print_port_scan_results(port_scan_result);
                }
            },
            Some(ScanCommand::ConnectScan { ports: _, ips: _ }) => {
                let scan_result = port_scanning::run_connect_scan(ip_addresses_arr, ports_vec, connect_timeout).await;
                match scan_result {
                    Ok(result) => port_scan_result = result,
                    Err(e) => eprintln!("Connect scan failed: {}", e),
                }
                if use_original_printing {
                    print_port_scan_results_original(port_scan_result).await;
                } else {
                    print_port_scan_results(port_scan_result);
                }
            },
            Some(ScanCommand::AckScan { ports: _, ips: _ }) => {
                let scan_result = port_scanning::run_ack_scan(ip_addresses_arr, &ports_vec, local_ip_address).await;
                match scan_result {
                    Ok(result) => port_scan_result = result,
                    Err(e) => eprintln!("ACK scan failed: {}", e),
                }

                if use_original_printing {
                    print_port_scan_results_original(port_scan_result).await;
                } else {
                    print_port_scan_results(port_scan_result);
                }
            },
            Some(ScanCommand::PingScan { ips: _ }) => {
                
                let host_discovery_result = host_discovery::run_ping_scan(ip_addresses_arr).await;
                if use_original_printing {
                    print_host_discovery_results_original(host_discovery_result);
                } else {
                    print_host_discovery_results(host_discovery_result);
                }
            },
            Some(ScanCommand::IcmpEcho { ips: _ }) => {
                let host_discovery_result = host_discovery::run_icmp_echo(ip_addresses_arr).await;
                if use_original_printing {
                    print_host_discovery_results_original(host_discovery_result);
                } else {
                    print_host_discovery_results(host_discovery_result);
                }
            },
            None => {
                println!("No scan method specified. Use `onmap --help` for usage information.");
            }
        }
    }
    Ok(())
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




