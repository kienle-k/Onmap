use std::io;
use models::PortOptions;
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

fn convert_port_range_to_arr(port_input: String) -> Vec<u16> {
    // Split the input string by the '-' character
    let parts: Vec<&str> = port_input.split('-').collect();
    
    // Return empty vector if format is incorrect
    if parts.len() != 2 {
        return Vec::new();
    }
    
    // Parse the start and end ports
    let start = match parts[0].trim().parse::<u16>() {
        Ok(num) => num,
        Err(_) => return Vec::new(), // Return empty vector if parsing fails
    };
    
    let end = match parts[1].trim().parse::<u16>() {
        Ok(num) => num,
        Err(_) => return Vec::new(), // Return empty vector if parsing fails
    };
    
    // Create a vector with all ports in the range (inclusive)
    if start <= end {
        (start..=end).collect()
    } else {
        Vec::new() // Return empty vector if start > end
    }
}

fn set_ports_arr(port_option: PortOptions) -> Vec<u16> {
    match port_option {
        PortOptions::FastMode => {
            // Return the 100 most common ports
            vec![
                20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 
                88, 110, 115, 123, 135, 137, 138, 139, 143, 161, 
                162, 179, 194, 389, 443, 445, 465, 514, 587, 636, 
                993, 995, 1080, 1194, 1433, 1434, 1521, 1723, 1900, 2049, 
                2082, 2083, 2086, 2087, 2375, 2376, 3128, 3306, 3389, 3690, 
                4443, 5060, 5061, 5222, 5432, 5500, 5601, 5672, 5900, 5901, 
                6379, 6443, 6660, 6661, 6662, 6663, 6664, 6665, 6666, 6667, 
                6668, 6669, 7001, 7002, 7080, 8000, 8008, 8009, 8080, 8081, 
                8085, 8086, 8087, 8088, 8443, 8686, 8888, 9000, 9090, 9100, 
                9200, 9300, 9999, 10000, 11211, 27017, 27018, 27019, 28017, 32400
            ]
        },
        PortOptions::SequentialMode => {
            // Return all ports from 1 to 65535 in order
            (1..=65535).collect()
        },
        PortOptions::NormalMode => {
            // Create a randomized array of all ports
            let mut ports: Vec<u16> = (1..=65535).collect();
            
            // Fisher-Yates shuffle algorithm to randomize the array
            use rand::Rng;
            let mut rng = rand::thread_rng();
            
            for i in (1..ports.len()).rev() {
                let j = rng.gen_range(0..=i);
                ports.swap(i, j);
            }
            
            ports
        },
        _ => Vec::new(), // Handle any other variants that might exist
    }
}

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
        port_mode,
        port_input)) = res {

        if let Some(main_selected) = main_selected {

            let ports: Vec<u16> = if port_needed {
                if let Some(port_mode) = port_mode {
                    match port_mode {
                        PortOptions::NormalMode => set_ports_arr(PortOptions::NormalMode),
                        PortOptions::PortRangeInput => convert_port_range_to_arr(port_input),
                        PortOptions::FastMode => set_ports_arr(PortOptions::FastMode),
                        PortOptions::SequentialMode => set_ports_arr(PortOptions::SequentialMode)
                    }
                } else {
                    Vec::new()
                }
            } else {
                Vec::new()
            };

            for port in &ports {
                println!("{}", port);
            }

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
    }
    Ok(())
}