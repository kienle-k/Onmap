use std::io;
use ratatui::backend::CrosstermBackend;
use ratatui::terminal::Terminal;
use crossterm::{
    event::DisableMouseCapture,
    event::EnableMouseCapture,
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use crate::tui::{run_app, App};
use crate::models::{MainMenuItem, HostDiscoveryOption, PortScanOption};

mod host_discovery;
mod port_scanning;
mod service_detection;
mod os_detection;

mod tui;
mod models;

fn main() -> Result<(), io::Error> {
    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    
    // Create app state
    let mut app = App::new();
    
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
    
    // Handle application result
    if let Ok((
        main_selected,
        host_discovery_selected,
        port_scan_selected,
        ip_input,
        port_needed,
        _port_mode,
        port_input)) = res {
        if let Some(main_selected) = main_selected {
            match main_selected {
                MainMenuItem::SubMenuHostDiscovery => {
                    if let Some(host_discovery_selected) = host_discovery_selected {
                        match host_discovery_selected {
                            HostDiscoveryOption::ListScan => println!("Doing ListScan"),
                            HostDiscoveryOption::PingScan => host_discovery::run_ping_scan(),
                            HostDiscoveryOption::TcpSynDiscovery => host_discovery::run_tcp_syn_discovery(),
                            HostDiscoveryOption::TcpAckDiscovery => println!("Doing TcpAckDiscovery"),
                            HostDiscoveryOption::UdpDiscovery => println!("Doing UdpDiscovery"),
                            HostDiscoveryOption::ArpDiscovery => println!("Doing ArpDiscovery"),
                            HostDiscoveryOption::IcmpEcho => host_discovery::run_icmp_echo(),
                            HostDiscoveryOption::IcmpTimestamp => host_discovery::run_icmp_timestamp(),
                            HostDiscoveryOption::IcmpNetmask => host_discovery::run_icmp_netmask()
                        }
                    } else {
                        println!("Something went wrong");
                    }
                }
                MainMenuItem::SubMenuPortScan => {
                    if let Some(port_scan_selected) = port_scan_selected {
                        match port_scan_selected {
                            PortScanOption::SynScan => port_scanning::run_syn_scan(),
                            PortScanOption::ConnectScan => port_scanning::run_connect_scan(),
                            PortScanOption::AckScan => port_scanning::run_ack_scan(),
                            PortScanOption::WindowScan => println!("Doing WindowScan"),
                            PortScanOption::MaimonScan => println!("Doing MaimonScan"),
                            PortScanOption::NullScan => println!("Doing NullScan"),
                            PortScanOption::FinScan => println!("Doing FinScan"),
                            PortScanOption::XmasScan => println!("Doing XmasScan"),
                            PortScanOption::UdpScan => port_scanning::run_udp_scan(),
                        }
                    }
                    else {
                        println!("Something went wrong")
                    }
                }
                MainMenuItem::SubMenuServiceDetection => service_detection::run_service_detection(),
                MainMenuItem::SubMenuOperatingSystemDetection => os_detection::run_os_detection(),
            }
        }

    println!("ip_input: {}", ip_input);
    println!("port_needed: {}", port_needed);
    println!("port_mode: ... cant be printed (also has _ please remove later on)");
    println!("port_input: {}", port_input);
    }
    Ok(())
}