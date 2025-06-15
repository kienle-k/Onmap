mod host_discovery;
mod port_scanning;
mod service_detection;
mod os_detection;
mod parsing;
mod printing;
mod resolving;

mod tui;
mod models;



use std::env; // Added to read command-line arguments
use std::io;
use std::io::{Write};
use std::net::{IpAddr, Ipv4Addr};
use models::{HostDiscoveryAllResult, HostDiscoverySingleResult, PortOptions, MainMenuItem, HostDiscoveryOption, PortScanOption, PortScanAllResult, PortScanSingleResult};
use printing::{print_port_scan_results, print_host_discovery_results, print_port_scan_results_original, print_host_discovery_results_original};
use ratatui::backend::CrosstermBackend;
use ratatui::terminal::Terminal;
use crossterm::{
    event::DisableMouseCapture,
    event::EnableMouseCapture,
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use chrono::prelude::*; // For Utc::now(), .with_timezone() und .format()
use chrono_tz::Tz;      // For Tz
use iana_time_zone::get_timezone;

use crate::host_discovery::run_icmp_netmask;
use crate::host_discovery::run_icmp_timestamp;
use crate::host_discovery::run_tcp_syn_discovery;
use crate::os_detection::run_os_detection;
use crate::port_scanning::run_udp_scan;
use crate::service_detection::run_service_detection;
use crate::tui::{run_app, App};
use local_ip_address::local_ip;

// use utils::json_loader::{load_protocols, get_port_info};


#[tokio::main]
pub async fn run_onmap() -> Result<(), io::Error> {
    // Flush to enable TUI in docker
    // This is a workaround for the issue where the TUI doesn't show up in Docker
    io::stdout().flush()?;

    let mut use_original_printing = false;

    // Get command-line arguments
    let args: Vec<String> = env::args().collect();
    let run_tui_mode = args.contains(&String::from("-tui"));

    // Get the local source IP for proper checksum calculation
    // This might be needed for both TUI and non-TUI modes if you implement CLI scanning
    let local_ip_address: Ipv4Addr = match local_ip() {
        Ok(ip) => match ip {
            IpAddr::V4(ipv4) => ipv4,
            IpAddr::V6(_) => {
                println!("Got an IPv6 address, but need IPv4 for some operations. Defaulting to localhost.");
                // Default to localhost when we get an IPv6
                Ipv4Addr::new(127, 0, 0, 1)
            }
        },
        Err(e) => {
            eprintln!("Error getting local IP: {}. Defaulting to localhost.", e);
            // Default to localhost on error
            Ipv4Addr::new(127, 0, 0, 1)
        }
    };

    // Initialize results variables specifically for TUI mode,
    // as they are populated based on TUI interaction.
    let mut port_scan_result: (Vec<PortScanSingleResult>, PortScanAllResult) = (Vec::new(), PortScanAllResult::new());
    let mut host_discovery_result: (Vec<HostDiscoverySingleResult>, HostDiscoveryAllResult) = (Vec::new(), HostDiscoveryAllResult::new());

    if run_tui_mode {
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
            
            // Original startup message from nmap
            let tz_str = get_timezone().expect("Failed to get system timezone");
            let tz: Tz = tz_str.parse().expect("Invalid timezone string");
            let now = Utc::now().with_timezone(&tz);
            let formatted_time = now.format("%Y-%m-%d %H:%M %Z").to_string();
            println!("\nStarting Onmap 1.0 (https://github.com/kienle-k/Onmap) at {}", formatted_time);

            if let Some(main_selected) = main_selected {
                // This parsing is specific to how the TUI collects input
                let ip_addresses_arr = parsing::parse_ip_addresses(&ip_input).expect("Failed to parse Ip addresses");

                let ports_arr: Result<Vec<u16>, String> = if port_needed {
                    if let Some(port_mode) = port_mode {
                        match port_mode {
                            PortOptions::NormalMode => parsing::set_ports_arr(PortOptions::NormalMode),
                            PortOptions::PortRangeInput => parsing::convert_port_range_to_arr(port_input),
                            PortOptions::FastMode => parsing::set_ports_arr(PortOptions::FastMode),
                            PortOptions::SequentialMode => parsing::set_ports_arr(PortOptions::SequentialMode)
                        }
                    } else {
                        Err("Ports array could not be set".to_string())
                    }
                } else {
                    Err("Ports array could not be set".to_string())
                };

                match main_selected {
                    MainMenuItem::SubMenuHostDiscovery => {
                        if let Some(host_discovery_selected) = host_discovery_selected {
                            match host_discovery_selected {
                                HostDiscoveryOption::ListScan => println!("Doing ListScan (Output results or integrate further)"), // Placeholder
                                HostDiscoveryOption::PingScan => host_discovery_result = host_discovery::run_ping_scan(Ok(ip_addresses_arr)).await,
                                HostDiscoveryOption::TcpSynDiscovery => {
                                    run_tcp_syn_discovery();
                                    // Not implemented yet
                                },
                                HostDiscoveryOption::TcpAckDiscovery => println!("Doing TcpAckDiscovery (Placeholder)"),
                                HostDiscoveryOption::UdpDiscovery => println!("Doing UdpDiscovery (Placeholder)"),
                                HostDiscoveryOption::ArpDiscovery => println!("Doing ArpDiscovery (Placeholder)"),
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
                            print_host_discovery_results(host_discovery_result);
                        } else {
                            println!("No host discovery option selected or an error occurred.");
                        }
                    }
                    MainMenuItem::SubMenuPortScan => {
                        if let Some(port_scan_selected) = port_scan_selected {
                            match port_scan_selected {
                                PortScanOption::SynScan => {
                                    match port_scanning::run_syn_scan(Ok(ip_addresses_arr), ports_arr.expect("Ports array not be set"), local_ip_address).await {
                                        Ok(result) => port_scan_result = result,
                                        Err(e) => eprintln!("SYN scan failed: {}", e),
                                    }
                                },
                                PortScanOption::ConnectScan => {
                                    match port_scanning::run_connect_scan(Ok(ip_addresses_arr), ports_arr.expect("Ports array could not be set"), 300).await { // Assuming 300ms timeout
                                        Ok(result) => port_scan_result = result,
                                        Err(e) => eprintln!("TCP-Connect scan failed: {}", e),
                                    }
                                },
                                PortScanOption::AckScan => {
                                    port_scanning::run_ack_scan(Ok(ip_addresses_arr), &ports_arr.expect("Ports array could not be set"), local_ip_address).await;
                                },
                                PortScanOption::WindowScan => println!("Doing WindowScan (Placeholder)"),
                                PortScanOption::MaimonScan => println!("Doing MaimonScan (Placeholder)"),
                                PortScanOption::NullScan => println!("Doing NullScan (Placeholder)"),
                                PortScanOption::FinScan => println!("Doing FinScan (Placeholder)"),
                                PortScanOption::XmasScan => println!("Doing XmasScan (Placeholder)"),
                                PortScanOption::UdpScan => {
                                    run_udp_scan();
                                }
                            }
                            if use_original_printing == false{
                                print_port_scan_results(port_scan_result);
                            } else {
                                print_port_scan_results_original(port_scan_result).await;
                            }
                        } else {
                            println!("No port scan option selected or an error occurred.");
                        }
                    }
                    MainMenuItem::SubMenuServiceDetection => {
                        run_service_detection();
                        // Not implemented yet
                    },
                    MainMenuItem::SubMenuOperatingSystemDetection => {
                        run_os_detection();
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

    } else {

        let mut arg_len = args.len();
        if !args.is_empty() { 
            if args[args.len() - 1] == "-pp" {
                arg_len = arg_len - 1; // Remove the last arguments visibility for the parser
                use_original_printing = false;
            } else {
                use_original_printing = true;
            }
        }

        // Original startup message from nmap
        let tz_str = get_timezone().expect("Failed to get system timezone");
        let tz: Tz = tz_str.parse().expect("Invalid timezone string");
        let now = Utc::now().with_timezone(&tz);
        let formatted_time = now.format("%Y-%m-%d %H:%M %Z").to_string();
        println!("\nStarting Onmap 1.0 (https://github.com/kienle-k/Onmap) at {}", formatted_time);
        
        
        match arg_len {
            4 => {
                let scan_method_arg = &args[1];
                let port_arg = &args[2];
                let ip_addresses_arg = &args[3];

                let port_prefix = "-p";

                // Attempt to remove the prefix
                if let Some(result_port_string) = port_arg.strip_prefix(port_prefix)  {
                    let ip_addresses_arr = parsing::parse_ip_addresses(&ip_addresses_arg);
                    let ports_arr = parsing::convert_port_range_to_arr(result_port_string.to_string());
                    match scan_method_arg.as_ref() {
                        "-sS" => {
                                let scan_result = port_scanning::run_syn_scan(ip_addresses_arr, ports_arr.expect("Ports array could not be set"), local_ip_address).await;
                                match scan_result {
                                    Ok(result) => port_scan_result = result,
                                    Err(e) => eprintln!("SYN scan failed: {}", e),
                                }
                                if use_original_printing == false{
                                    print_port_scan_results(port_scan_result);
                                } else {
                                    print_port_scan_results_original(port_scan_result).await;
                                }
                            },
                        "-sT" => {
                                let scan_result = port_scanning::run_connect_scan(ip_addresses_arr, ports_arr.expect("Ports array could not be set"), 300).await;
                                match scan_result {
                                    Ok(result) => port_scan_result = result,
                                    Err(e) => eprintln!("SYN scan failed: {}", e),
                                }
                                if use_original_printing == false{
                                    print_port_scan_results(port_scan_result);
                                } else {
                                    print_port_scan_results_original(port_scan_result).await;
                                }
                            },
                        "-sA" => {
                                // Call the new ACK scan function
                                port_scanning::run_ack_scan(ip_addresses_arr, &ports_arr.expect("Ports array could not be set"), local_ip_address).await;
                            },
                        
                        _ => println!("Scan method not implemented yet")
                    }
                } else {
                    println!("Prefix '{}' not found in '{}'.", port_prefix, port_arg);
                }

            },

        3 => {
            let scan_method_arg = &args[1];
            let ip_addresses_arg = &args[2];

            let ip_addresses_arr = parsing::parse_ip_addresses(&ip_addresses_arg);

            match scan_method_arg.as_ref() {
                "-sn" => {
                        let host_discovery_result = host_discovery::run_ping_scan(ip_addresses_arr).await;
                        if use_original_printing == true {
                            print_host_discovery_results_original(host_discovery_result);
                        }else {
                            print_host_discovery_results(host_discovery_result);
                        }
                    },
                "-PE" => {
                        let host_discovery_result = host_discovery::run_icmp_echo(ip_addresses_arr).await;
                        if use_original_printing == true {
                            print_host_discovery_results_original(host_discovery_result);
                        }else {
                            print_host_discovery_results(host_discovery_result);
                        }                }
                
                _ => println!("Scan method not implemented yet")
            }

        }

        _ => println!("Please select a valid amount of arguments")

        }

    }

    Ok(())
}