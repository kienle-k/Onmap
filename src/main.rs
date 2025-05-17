use std::io;
use std::net::{IpAddr, Ipv4Addr};
use models::{HostDiscoveryAllResult, HostDiscoverySingleResult, PortOptions, MainMenuItem, HostDiscoveryOption, PortScanOption, PortScanAllResult, PortScanSingleResult};
use printing::{print_port_scan_results, print_host_discovery_results};
use ratatui::backend::CrosstermBackend;
use ratatui::terminal::Terminal;
use crossterm::{
    event::DisableMouseCapture,
    event::EnableMouseCapture,
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use crate::tui::{run_app, App};
use local_ip_address::local_ip;

mod host_discovery;
mod port_scanning;
mod service_detection;
mod os_detection;
mod parsing;
mod printing;
mod resolving;

mod tui;
mod models;


#[tokio::main]
async fn main() -> Result<(), io::Error> {
    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    
    // Create app state
    let mut app = App::new();

    // Get the local source IP for proper checksum calculation
    let local_ip_address: Ipv4Addr = match local_ip() {
        Ok(ip) => match ip {
            IpAddr::V4(ipv4) => ipv4,
            IpAddr::V6(_) => {
                println!("Got an IPv6 address, but need IPv4");
                // Default to localhost when we get an IPv6
                Ipv4Addr::new(127, 0, 0, 1)
            }
        },
        Err(e) => {
            eprintln!("Error getting IP: {}", e);
            // Default to localhost on error
            Ipv4Addr::new(127, 0, 0, 1)
        }
    };
    
    // Main loop
    let res = run_app(&mut terminal, &mut app);
    
    // Restore terminal
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    let mut port_scan_result: (Vec<PortScanSingleResult>, PortScanAllResult) = (Vec::new(), PortScanAllResult::new());
    let mut host_discovery_result: (Vec<HostDiscoverySingleResult>, HostDiscoveryAllResult) = (Vec::new(), HostDiscoveryAllResult::new());
    
    // Handle application result
    if let Ok((
        main_selected,
        host_discovery_selected,
        port_scan_selected,
        ip_input,
        port_needed,
        port_mode,
        port_input)) = res {

        if let Some(main_selected) = main_selected {

            let ip_addresses_arr = parsing::parse_ip_addresses(&ip_input);

            let ports_arr: Vec<u16> = if port_needed {
                if let Some(port_mode) = port_mode {
                    match port_mode {
                        PortOptions::NormalMode => parsing::set_ports_arr(PortOptions::NormalMode),
                        PortOptions::PortRangeInput => parsing::convert_port_range_to_arr(port_input),
                        PortOptions::FastMode => parsing::set_ports_arr(PortOptions::FastMode),
                        PortOptions::SequentialMode => parsing::set_ports_arr(PortOptions::SequentialMode)
                    }
                } else {
                    Vec::new()
                }
            } else {
                Vec::new()
            };

            /* Output ip address and ports for debugging

            if let Ok(addresses) = &ip_addresses_arr {
                for ip_address in addresses {
                    println!("{:?}", ip_address);
                }
            }

            for port in &ports_arr {
                println!("{}", port);
            }
            */

            match main_selected {
                MainMenuItem::SubMenuHostDiscovery => {
                    if let Some(host_discovery_selected) = host_discovery_selected {
                        match host_discovery_selected {
                            HostDiscoveryOption::ListScan => println!("Doing ListScan"),
                            HostDiscoveryOption::PingScan => host_discovery_result = host_discovery::run_ping_scan(ip_addresses_arr, ports_arr).await,
                            HostDiscoveryOption::TcpSynDiscovery => host_discovery::run_tcp_syn_discovery(),
                            HostDiscoveryOption::TcpAckDiscovery => println!("Doing TcpAckDiscovery"),
                            HostDiscoveryOption::UdpDiscovery => println!("Doing UdpDiscovery"),
                            HostDiscoveryOption::ArpDiscovery => println!("Doing ArpDiscovery"),
                            HostDiscoveryOption::IcmpEcho => host_discovery::run_icmp_echo(ip_addresses_arr).await,
                            HostDiscoveryOption::IcmpTimestamp => host_discovery::run_icmp_timestamp(),
                            HostDiscoveryOption::IcmpNetmask => host_discovery::run_icmp_netmask()
                        }
                        print_host_discovery_results(host_discovery_result);
                    } else {
                        println!("Something went wrong");
                    }
                }
                MainMenuItem::SubMenuPortScan => {
                    if let Some(port_scan_selected) = port_scan_selected {
                        match port_scan_selected {
                            PortScanOption::SynScan => port_scan_result = port_scanning::run_syn_scan(ip_addresses_arr, ports_arr, local_ip_address).await.expect("SYN scan failed"),
                            PortScanOption::ConnectScan => port_scanning::run_connect_scan(),
                            PortScanOption::AckScan => port_scanning::run_ack_scan(),
                            PortScanOption::WindowScan => println!("Doing WindowScan"),
                            PortScanOption::MaimonScan => println!("Doing MaimonScan"),
                            PortScanOption::NullScan => println!("Doing NullScan"),
                            PortScanOption::FinScan => println!("Doing FinScan"),
                            PortScanOption::XmasScan => println!("Doing XmasScan"),
                            PortScanOption::UdpScan => port_scanning::run_udp_scan(),
                        }
                        print_port_scan_results(port_scan_result);
                    }
                    else {
                        println!("Something went wrong")
                    }
                }
                MainMenuItem::SubMenuServiceDetection => service_detection::run_service_detection(),
                MainMenuItem::SubMenuOperatingSystemDetection => os_detection::run_os_detection(),
            }

        }

    }
    Ok(())
}