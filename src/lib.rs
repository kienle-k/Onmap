// --- Module declarations ---
mod host_discovery;
mod port_scanning;
mod tui;

// --- Public API modules ---
pub mod models;
mod output;
pub mod parsing;
pub mod printing;
pub mod resolving;
pub mod version;

// --- Standard library imports ---
use std::collections::HashMap;
use std::io;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr};
use std::time::SystemTime;

// --- External crate imports ---
use chrono::prelude::*;
use chrono_tz::Tz;
use crossterm::{
    event::{DisableMouseCapture, EnableMouseCapture},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use futures::future::try_join_all;
use iana_time_zone::get_timezone;
use local_ip_address::local_ip;
use ratatui::backend::CrosstermBackend;
use ratatui::terminal::Terminal;

// --- Internal imports (from this crate) ---
use crate::output::{
    save_to_file_grepable_host_discovery, save_to_file_grepable_port_scan,
    save_to_file_normal_host_discovery, save_to_file_normal_port_scan,
    save_to_file_xml_host_discovery, save_to_file_xml_port_scan,
};
use crate::tui::{App, run_app};
use models::{
    Cli, ExecutionCommand, HostDiscoveryAllResult, HostDiscoveryOption, HostDiscoverySingleResult,
    HostDiscoverySpec, MainMenuItem, PortOptions, PortScanAllResult, PortScanOption,
    PortScanSingleResult, VersionFormat,
};
use printing::{
    print_host_discovery_results, print_host_discovery_results_original, print_port_scan_results,
    print_port_scan_results_original,
};
use version::{version_json, version_text};

// --- Main public entry point ---
/// Runs the Onmap application with the given CLI arguments.
/// Handles both TUI and CLI modes.

#[tokio::main]
pub async fn run_onmap(cli: Cli) -> Result<(), io::Error> {
    if let Some(format) = &cli.version {
        match format {
            Some(VersionFormat::Json) => println!("{}", version_json()),
            None => println!("{}", version_text()),
        }

        return Ok(());
    }

    // Flush to enable TUI in docker (test environment)
    // This is a quick fix for an issue where the TUI doesn't display inside the container
    io::stdout().flush()?;

    env_logger::Builder::new()
        .target(env_logger::Target::Stdout)
        .format(|buf, record| writeln!(buf, "{}", record.args()))
        .filter_level(log::LevelFilter::Warn) // all other crates: Warn only
        .filter_module(
            "onmap",
            match cli.verbosity {
                // only onmap follows -v flags
                0 => log::LevelFilter::Warn,
                1 => log::LevelFilter::Info,
                2 => log::LevelFilter::Debug,
                _ => log::LevelFilter::Trace,
            },
        )
        .init();

    // Get the local source IP for proper checksum calculation
    let local_ip_address: Ipv4Addr = match local_ip() {
        Ok(ip) => match ip {
            IpAddr::V4(ipv4) => ipv4,
            IpAddr::V6(_) => {
                println!(
                    "Got an IPv6 address, but need IPv4 for some operations. Defaulting to localhost."
                );
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
    let mut port_scan_result: (Vec<PortScanSingleResult>, PortScanAllResult) =
        (Vec::new(), PortScanAllResult::new());
    let mut host_discovery_result: (Vec<HostDiscoverySingleResult>, HostDiscoveryAllResult) =
        (Vec::new(), HostDiscoveryAllResult::new());

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

    let (host_result_opt, port_result_opt) =
        match execute_command(command, local_ip_address, use_original_printing).await {
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
            save_to_file_xml_host_discovery(
                path,
                (&host_discovery_result.0, &host_discovery_result.1),
            )?;
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

    if let Some(path) = &cli.output_normal {
        let mut saved = false;
        if !host_discovery_result.0.is_empty() {
            save_to_file_normal_host_discovery(
                path,
                (&host_discovery_result.0, &host_discovery_result.1),
            )?;
            saved = true;
        }
        if !port_scan_result.0.is_empty() {
            save_to_file_normal_port_scan(path, (&port_scan_result.0, &port_scan_result.1))?;
            saved = true;
        }
        if !saved {
            println!("No results available to save to normal output.");
        }
    }

    if let Some(path) = &cli.output_grepable {
        let mut saved = false;
        if !host_discovery_result.0.is_empty() {
            save_to_file_grepable_host_discovery(
                path,
                (&host_discovery_result.0, &host_discovery_result.1),
            )?;
            saved = true;
        }
        if !port_scan_result.0.is_empty() {
            save_to_file_grepable_port_scan(path, (&port_scan_result.0, &port_scan_result.1))?;
            saved = true;
        }
        if !saved {
            println!("No results available to save to grepable output.");
        }
    }

    if let Some(basename) = &cli.output_all {
        let xml_path = format!("{}.xml", basename);
        let normal_path = format!("{}.nmap", basename);
        let grepable_path = format!("{}.gnmap", basename);
        let mut saved = false;
        if !host_discovery_result.0.is_empty() {
            save_to_file_xml_host_discovery(
                &xml_path,
                (&host_discovery_result.0, &host_discovery_result.1),
            )?;
            save_to_file_normal_host_discovery(
                &normal_path,
                (&host_discovery_result.0, &host_discovery_result.1),
            )?;
            save_to_file_grepable_host_discovery(
                &grepable_path,
                (&host_discovery_result.0, &host_discovery_result.1),
            )?;
            saved = true;
        }
        if !port_scan_result.0.is_empty() {
            save_to_file_xml_port_scan(&xml_path, (&port_scan_result.0, &port_scan_result.1))?;
            save_to_file_normal_port_scan(
                &normal_path,
                (&port_scan_result.0, &port_scan_result.1),
            )?;
            save_to_file_grepable_port_scan(
                &grepable_path,
                (&port_scan_result.0, &port_scan_result.1),
            )?;
            saved = true;
        }
        if !saved {
            println!("No results available to save.");
        }
    }

    Ok(())
}

type HostDiscoveryResult = (Vec<HostDiscoverySingleResult>, HostDiscoveryAllResult);
type PortScanResult = (Vec<PortScanSingleResult>, PortScanAllResult);

struct HostMergeState {
    best_up: Option<HostDiscoverySingleResult>,
    best_down: Option<HostDiscoverySingleResult>,
}

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
            let method = host_discovery_selected
                .ok_or_else(|| "No host discovery option selected".to_string())?;
            ExecutionCommand::HostDiscovery {
                methods: vec![HostDiscoverySpec { method, ports }],
                targets,
                timeout_override_ms: None,
            }
        }
        MainMenuItem::SubMenuPortScan => {
            let method =
                port_scan_selected.ok_or_else(|| "No port scan option selected".to_string())?;
            let ports = ports.ok_or_else(|| "Ports array could not be set".to_string())?;
            ExecutionCommand::PortScan {
                method,
                targets,
                ports,
                timeout_override_ms: None,
                service_version: false,
                os_detection: false,
                script: None,
            }
        }
    };

    Ok(Some(command))
}

fn build_command_from_cli(cli: &Cli) -> Result<Option<ExecutionCommand>, String> {
    let host_discovery_methods = cli.host_discovery_methods();
    let port_scan_method = selected_port_scan_method(cli)?;
    let has_host_discovery_config = !host_discovery_methods.is_empty()
        || cli.syn_discovery_ports.is_some()
        || cli.ack_discovery_ports.is_some()
        || cli.udp_discovery_ports.is_some();

    if port_scan_method.is_some() && has_host_discovery_config {
        return Err("Host discovery flags cannot be combined with port scan modes".to_string());
    }

    let command = match port_scan_method {
        Some(method) => ExecutionCommand::PortScan {
            method,
            targets: parse_targets(
                cli.host_discovery_targets
                    .as_deref()
                    .ok_or_else(|| "Targets must be provided".to_string())?,
            )?,
            ports: parse_ports_spec(cli.host_discovery_ports.as_ref())?,
            timeout_override_ms: cli.host_discovery_timeout_ms,
            service_version: cli.service_version,
            os_detection: cli.os_detection,
            script: cli.script.clone(),
        },
        None => {
            if !has_host_discovery_config {
                return Ok(None);
            }

            build_host_discovery_command(cli, host_discovery_methods)?
        }
    };

    Ok(Some(command))
}

fn selected_port_scan_method(cli: &Cli) -> Result<Option<PortScanOption>, String> {
    let mut selected = Vec::new();

    if cli.syn_scan {
        selected.push(PortScanOption::SynScan);
    }
    if cli.connect_scan {
        selected.push(PortScanOption::ConnectScan);
    }
    if cli.ack_scan {
        selected.push(PortScanOption::AckScan);
    }
    if cli.udp_scan {
        selected.push(PortScanOption::UdpScan);
    }

    if selected.len() > 1 {
        return Err("Only one port scan mode can be selected at a time".to_string());
    }

    Ok(selected.into_iter().next())
}

fn build_host_discovery_command(
    cli: &Cli,
    methods: Vec<HostDiscoveryOption>,
) -> Result<ExecutionCommand, String> {
    let targets = cli
        .host_discovery_targets
        .as_deref()
        .ok_or_else(|| "Host discovery targets must be provided".to_string())?;

    let has_syn = methods.contains(&HostDiscoveryOption::TcpSynDiscovery);
    let has_ack = methods.contains(&HostDiscoveryOption::TcpAckDiscovery);
    let has_udp = methods.contains(&HostDiscoveryOption::UdpDiscovery);
    let has_port_based_method = has_syn || has_ack || has_udp;

    if cli.syn_discovery_ports.is_some() && !has_syn {
        return Err("TCP SYN discovery ports were provided but -PS was not selected".to_string());
    }
    if cli.ack_discovery_ports.is_some() && !has_ack {
        return Err("TCP ACK discovery ports were provided but -PA was not selected".to_string());
    }
    if cli.udp_discovery_ports.is_some() && !has_udp {
        return Err("UDP discovery ports were provided but -PU was not selected".to_string());
    }

    if methods.is_empty() {
        return Err("No host discovery method specified".to_string());
    }

    let shared_ports = match cli.host_discovery_ports.as_ref() {
        Some(ports) => Some(
            parsing::convert_ports(ports.clone())
                .map_err(|e| format!("Invalid port specification: {}", e))?,
        ),
        None => None,
    };

    if shared_ports.is_some() && !has_port_based_method {
        return Err("Ports can only be used with TCP/UDP host discovery probes".to_string());
    }

    let syn_ports = match cli.syn_discovery_ports.as_ref() {
        Some(ports) => Some(
            parsing::convert_ports(ports.clone())
                .map_err(|e| format!("Invalid TCP SYN discovery ports: {}", e))?,
        ),
        None => None,
    };
    let ack_ports = match cli.ack_discovery_ports.as_ref() {
        Some(ports) => Some(
            parsing::convert_ports(ports.clone())
                .map_err(|e| format!("Invalid TCP ACK discovery ports: {}", e))?,
        ),
        None => None,
    };
    let udp_ports = match cli.udp_discovery_ports.as_ref() {
        Some(ports) => Some(
            parsing::convert_ports(ports.clone())
                .map_err(|e| format!("Invalid UDP discovery ports: {}", e))?,
        ),
        None => None,
    };

    let methods = methods
        .into_iter()
        .map(|method| {
            let ports = match method {
                HostDiscoveryOption::TcpSynDiscovery => {
                    syn_ports.clone().or_else(|| shared_ports.clone())
                }
                HostDiscoveryOption::TcpAckDiscovery => {
                    ack_ports.clone().or_else(|| shared_ports.clone())
                }
                HostDiscoveryOption::UdpDiscovery => {
                    udp_ports.clone().or_else(|| shared_ports.clone())
                }
                _ => None,
            };

            if method_requires_ports(method) && ports.is_none() {
                return Err(format!(
                    "Ports must be provided for {}",
                    host_discovery_method_name(method)
                ));
            }

            Ok(HostDiscoverySpec { method, ports })
        })
        .collect::<Result<Vec<_>, String>>()?;

    Ok(ExecutionCommand::HostDiscovery {
        methods,
        targets: parse_targets(targets)?,
        timeout_override_ms: cli.host_discovery_timeout_ms,
    })
}

fn host_discovery_method_name(method: HostDiscoveryOption) -> &'static str {
    match method {
        HostDiscoveryOption::TcpSynDiscovery => "TCP SYN discovery probes",
        HostDiscoveryOption::TcpAckDiscovery => "TCP ACK discovery probes",
        HostDiscoveryOption::UdpDiscovery => "UDP discovery probes",
        HostDiscoveryOption::ListScan => "list scan",
        HostDiscoveryOption::PingScan => "ping scan",
        HostDiscoveryOption::ArpDiscovery => "ARP discovery",
        HostDiscoveryOption::IcmpEcho => "ICMP echo discovery",
        HostDiscoveryOption::IcmpTimestamp => "ICMP timestamp discovery",
    }
}

fn method_requires_ports(method: HostDiscoveryOption) -> bool {
    matches!(
        method,
        HostDiscoveryOption::TcpSynDiscovery
            | HostDiscoveryOption::TcpAckDiscovery
            | HostDiscoveryOption::UdpDiscovery
    )
}

fn parse_ports_spec(ports: Option<&String>) -> Result<Vec<u16>, String> {
    let ports_str = ports.ok_or_else(|| "Ports must be provided".to_string())?;
    parsing::convert_ports(ports_str.to_string())
        .map_err(|e| format!("Invalid port specification: {}", e))
}

fn parse_targets(ips: &str) -> Result<Vec<IpAddr>, String> {
    parsing::parse_ip_addresses(ips).map(|targets| targets.into_iter().map(IpAddr::V4).collect())
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
        ExecutionCommand::HostDiscovery { methods, .. } => methods.iter().any(|spec| {
            matches!(
                spec.method,
                HostDiscoveryOption::IcmpEcho
                    | HostDiscoveryOption::IcmpTimestamp
                    | HostDiscoveryOption::ArpDiscovery
                    | HostDiscoveryOption::TcpSynDiscovery
                    | HostDiscoveryOption::TcpAckDiscovery
                    | HostDiscoveryOption::UdpDiscovery
            )
        }),
    }
}

async fn run_nmap_post_scan(
    targets: &[Ipv4Addr],
    open_ports: &[u16],
    is_udp: bool,
    service_version: bool,
    os_detection: bool,
    script: Option<&str>,
) -> Result<(), String> {
    if open_ports.is_empty() {
        println!("\nNo open ports found — skipping nmap post-scan detection.");
        return Ok(());
    }

    let port_list: String = if is_udp {
        open_ports
            .iter()
            .map(|p| format!("U:{}", p))
            .collect::<Vec<_>>()
            .join(",")
    } else {
        open_ports
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(",")
    };

    let mut args: Vec<String> = Vec::new();

    if is_udp {
        args.push("-sU".to_string());
    }
    if service_version {
        args.push("-sV".to_string());
    }
    if os_detection {
        args.push("-O".to_string());
    }
    if let Some(s) = script {
        args.push(format!("--script={}", s));
    }

    args.push("-p".to_string());
    args.push(port_list);

    for ip in targets {
        args.push(ip.to_string());
    }

    println!("---------- Nmap Post-Scan ----------");
    println!("Running: nmap {}", args.join(" "));
    println!();

    let status = tokio::process::Command::new("nmap")
        .args(&args)
        .status()
        .await
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                "nmap not found — please install nmap to use post-scan detection.".to_string()
            } else {
                format!("Failed to launch nmap: {}", e)
            }
        })?;

    if !status.success() {
        eprintln!("nmap exited with status: {}", status);
    }

    Ok(())
}

async fn execute_command(
    command: ExecutionCommand,
    local_ip_address: Ipv4Addr,
    use_original_printing: bool,
) -> Result<(Option<HostDiscoveryResult>, Option<PortScanResult>), String> {
    let is_root = nix::unistd::Uid::effective().is_root();

    if requires_root(&command) && !is_root {
        return Err("This scan requires root privileges.".to_string());
    }

    match command {
        ExecutionCommand::HostDiscovery {
            methods,
            targets,
            timeout_override_ms,
        } => {
            let ipv4_targets = to_ipv4_vec(&targets)?;
            let num_targets = ipv4_targets.len();

            let scan_type_names: Vec<&str> = methods
                .iter()
                .map(|s| match s.method {
                    HostDiscoveryOption::PingScan => "Ping Scan",
                    HostDiscoveryOption::IcmpEcho => "ICMP Echo Ping Scan",
                    HostDiscoveryOption::IcmpTimestamp => "ICMP Timestamp Ping Scan",
                    HostDiscoveryOption::ArpDiscovery => "ARP Ping Scan",
                    HostDiscoveryOption::TcpSynDiscovery => "SYN Ping Scan",
                    HostDiscoveryOption::TcpAckDiscovery => "ACK Ping Scan",
                    HostDiscoveryOption::UdpDiscovery => "UDP Ping Scan",
                    HostDiscoveryOption::ListScan => "List Scan",
                })
                .collect();
            let ports_per_host: usize = methods
                .iter()
                .map(|s| s.ports.as_ref().map(|p| p.len()).unwrap_or(1))
                .max()
                .unwrap_or(1);

            for name in &scan_type_names {
                log::info!("Initiating {} at {}", name, Local::now().format("%H:%M"));
            }
            log::info!(
                "Scanning {} hosts [{} port/host]",
                num_targets,
                ports_per_host
            );

            let result = if methods.len() == 1 {
                match run_host_discovery_spec(
                    methods
                        .into_iter()
                        .next()
                        .expect("single method is present"),
                    ipv4_targets,
                    local_ip_address,
                    timeout_override_ms,
                )
                .await?
                {
                    Some(result) => result,
                    None => return Ok((None, None)),
                }
            } else {
                run_multi_host_discovery(
                    methods,
                    ipv4_targets,
                    local_ip_address,
                    timeout_override_ms,
                )
                .await?
            };

            let elapsed = result
                .1
                .end_time
                .duration_since(result.1.start_time)
                .unwrap_or_default()
                .as_secs_f64();
            for name in &scan_type_names {
                log::info!(
                    "Completed {} at {}, {:.2}s elapsed ({} total hosts)",
                    name,
                    Local::now().format("%H:%M"),
                    elapsed,
                    num_targets
                );
            }

            let dns_count = result.1.scanned_addresses.len();
            let dns_ok = result.1.hosts_dns_resolution as usize;
            let dns_nx = dns_count.saturating_sub(dns_ok);
            let dns_elapsed = result.1.dns_elapsed_secs;
            log::info!(
                "Initiating Parallel DNS resolution of {} host(s). at {}",
                dns_count,
                Local::now().format("%H:%M")
            );
            log::info!(
                "Completed Parallel DNS resolution of {} host(s). at {}, {:.2}s elapsed",
                dns_count,
                Local::now().format("%H:%M"),
                dns_elapsed
            );
            log::trace!(
                "DNS resolution of {} IPs took {:.2}s. Mode: Async [#: {}, OK: {}, NX: {}, DR: 0, SF: 0, TR: {}, CN: 0]",
                dns_count,
                dns_elapsed,
                dns_count,
                dns_ok,
                dns_nx,
                dns_count
            );

            if use_original_printing {
                print_host_discovery_results_original(&result);
            } else {
                print_host_discovery_results(&result);
            }

            log::info!("Loaded embedded port service mapping");
            log::info!("Raw packets sent: {}", result.1.packets_sent);

            Ok((Some(result), None))
        }
        ExecutionCommand::PortScan {
            method,
            targets,
            ports,
            timeout_override_ms,
            service_version,
            os_detection,
            script,
        } => {
            let ipv4_targets = to_ipv4_vec(&targets)?;
            let nmap_targets = ipv4_targets.clone();

            let num_ports = ports.len();
            let target_display = if ipv4_targets.len() == 1 {
                ipv4_targets[0].to_string()
            } else {
                format!("{} hosts", ipv4_targets.len())
            };
            let scan_type_name = match method {
                PortScanOption::SynScan => "SYN Stealth Scan",
                PortScanOption::ConnectScan => "TCP Connect Scan",
                PortScanOption::AckScan => "ACK Scan",
                PortScanOption::UdpScan => "UDP Scan",
                _ => "Port Scan",
            };

            log::info!(
                "Initiating {} at {}",
                scan_type_name,
                Local::now().format("%H:%M")
            );
            log::info!("Scanning {} [{} ports]", target_display, num_ports);

            let result = match method {
                PortScanOption::SynScan => {
                    port_scanning::run_syn_scan(
                        ipv4_targets,
                        ports,
                        local_ip_address,
                        timeout_override_ms,
                    )
                    .await?
                }
                PortScanOption::ConnectScan => {
                    port_scanning::run_connect_scan(ipv4_targets, ports, timeout_override_ms)
                        .await?
                }
                PortScanOption::AckScan => {
                    port_scanning::run_ack_scan(
                        ipv4_targets,
                        &ports,
                        local_ip_address,
                        timeout_override_ms,
                    )
                    .await?
                }
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
                PortScanOption::UdpScan => {
                    port_scanning::run_udp_scan(
                        ipv4_targets,
                        ports,
                        local_ip_address,
                        timeout_override_ms,
                    )
                    .await?
                }
            };

            let elapsed = result
                .1
                .end_time
                .duration_since(result.1.start_time)
                .unwrap_or_default()
                .as_secs_f64();
            log::info!(
                "Completed {} at {}, {:.2}s elapsed ({} total ports)",
                scan_type_name,
                Local::now().format("%H:%M"),
                elapsed,
                result.1.ports_scanned
            );

            if use_original_printing {
                print_port_scan_results_original(&result).await;
            } else {
                print_port_scan_results(&result);
            }

            log::info!("Loaded embedded port service mapping");
            log::info!("Raw packets sent: {}", result.1.packets_sent);

            if service_version || os_detection || script.is_some() {
                let is_udp = method == PortScanOption::UdpScan;
                run_nmap_post_scan(
                    &nmap_targets,
                    &result.1.open_ports,
                    is_udp,
                    service_version,
                    os_detection,
                    script.as_deref(),
                )
                .await?;
            }

            Ok((None, Some(result)))
        }
    }
}

async fn run_host_discovery_spec(
    spec: HostDiscoverySpec,
    ipv4_targets: Vec<Ipv4Addr>,
    local_ip_address: Ipv4Addr,
    timeout_override_ms: Option<u64>,
) -> Result<Option<HostDiscoveryResult>, String> {
    let result = match spec.method {
        HostDiscoveryOption::ListScan => {
            println!("Doing ListScan (Implementation coming soon)");
            return Ok(None);
        }
        HostDiscoveryOption::PingScan => {
            host_discovery::run_ping_discovery(ipv4_targets, timeout_override_ms).await?
        }
        HostDiscoveryOption::TcpSynDiscovery => {
            let ports = spec
                .ports
                .ok_or_else(|| "Ports array could not be set".to_string())?;
            host_discovery::run_tcp_syn_discovery(
                ipv4_targets,
                ports,
                local_ip_address,
                timeout_override_ms,
            )
            .await?
        }
        HostDiscoveryOption::TcpAckDiscovery => {
            let ports = spec
                .ports
                .ok_or_else(|| "Ports array could not be set".to_string())?;
            host_discovery::run_tcp_ack_discovery(
                ipv4_targets,
                ports,
                local_ip_address,
                timeout_override_ms,
            )
            .await?
        }
        HostDiscoveryOption::UdpDiscovery => {
            let ports = spec
                .ports
                .ok_or_else(|| "Ports array could not be set".to_string())?;
            host_discovery::run_udp_discovery(
                ipv4_targets,
                ports,
                local_ip_address,
                timeout_override_ms,
            )
            .await?
        }
        HostDiscoveryOption::ArpDiscovery => {
            host_discovery::run_arp_discovery(ipv4_targets, timeout_override_ms).await?
        }
        HostDiscoveryOption::IcmpEcho => {
            host_discovery::run_icmp_echo_discovery(ipv4_targets, timeout_override_ms).await?
        }
        HostDiscoveryOption::IcmpTimestamp => {
            host_discovery::run_icmp_timestamp_discovery(ipv4_targets, timeout_override_ms).await?
        }
    };

    Ok(Some(result))
}

async fn run_multi_host_discovery(
    methods: Vec<HostDiscoverySpec>,
    ipv4_targets: Vec<Ipv4Addr>,
    local_ip_address: Ipv4Addr,
    timeout_override_ms: Option<u64>,
) -> Result<HostDiscoveryResult, String> {
    if methods.iter().any(|spec| {
        matches!(
            spec.method,
            HostDiscoveryOption::ListScan
        )
    }) {
        return Err("List scan cannot be combined with other host discovery methods".to_string());
    }

    let futures = methods.into_iter().map(|spec| {
        let targets = ipv4_targets.clone();
        async move {
            run_host_discovery_spec(spec, targets, local_ip_address, timeout_override_ms)
                .await?
                .ok_or_else(|| "Host discovery method did not produce a result".to_string())
        }
    });

    let results = try_join_all(futures).await?;
    Ok(merge_host_discovery_results(results))
}

fn merge_host_discovery_results(results: Vec<HostDiscoveryResult>) -> HostDiscoveryResult {
    let mut merged_hosts: HashMap<IpAddr, HostMergeState> = HashMap::new();
    let mut scanned_addresses = Vec::new();
    let mut ports_per_host = 0_u16;
    let mut packets_sent = 0_u64;
    let mut start_time: Option<SystemTime> = None;
    let mut end_time: Option<SystemTime> = None;

    for (hosts, summary) in results {
        if scanned_addresses.is_empty() {
            scanned_addresses = summary.scanned_addresses.clone();
        }

        ports_per_host = ports_per_host.saturating_add(summary.ports_per_host);
        packets_sent = packets_sent.saturating_add(summary.packets_sent);
        start_time = Some(match start_time {
            Some(existing) => existing.min(summary.start_time),
            None => summary.start_time,
        });
        end_time = Some(match end_time {
            Some(existing) => existing.max(summary.end_time),
            None => summary.end_time,
        });

        for host in hosts {
            let entry = merged_hosts
                .entry(host.ip_address)
                .or_insert_with(|| HostMergeState {
                    best_up: None,
                    best_down: None,
                });

            if host.is_up {
                let should_replace = match &entry.best_up {
                    Some(current) => compare_host_priority(&host, current),
                    None => true,
                };

                if should_replace {
                    entry.best_up = Some(host);
                }
            } else if entry.best_down.is_none() {
                entry.best_down = Some(host);
            }
        }
    }

    let mut merged_results = Vec::new();
    for address in &scanned_addresses {
        if let Some(state) = merged_hosts.remove(address) {
            if let Some(host) = state.best_up.or(state.best_down) {
                merged_results.push(host);
            }
        }
    }

    for state in merged_hosts.into_values() {
        if let Some(host) = state.best_up.or(state.best_down) {
            merged_results.push(host);
        }
    }

    let hosts_up = merged_results.iter().filter(|host| host.is_up).count() as u64;
    let hosts_dns_resolution = merged_results
        .iter()
        .filter(|host| host.dns_resolve.is_some())
        .count() as u64;

    (
        merged_results,
        HostDiscoveryAllResult {
            scanned_addresses,
            ports_per_host,
            hosts_up,
            hosts_dns_resolution,
            start_time: start_time.unwrap_or_else(SystemTime::now),
            end_time: end_time.unwrap_or_else(SystemTime::now),
            packets_sent,
            dns_elapsed_secs: 0.0,
        },
    )
}

fn compare_host_priority(
    candidate: &HostDiscoverySingleResult,
    current: &HostDiscoverySingleResult,
) -> bool {
    match (candidate.latency, current.latency) {
        (Some(candidate_latency), Some(current_latency)) => candidate_latency < current_latency,
        (Some(_), None) => true,
        (None, Some(_)) => false,
        (None, None) => false,
    }
}

/// Print startup message
fn print_startup_message() {
    // Use cargo env to gather version and package name
    // Format time to fit the user settings
    let tz_str = get_timezone().expect("Failed to get system timezone");
    let tz: Tz = tz_str.parse().expect("Invalid timezone string");
    let now = Utc::now().with_timezone(&tz);
    let formatted_time = now.format("%Y-%m-%d %H:%M %Z").to_string();
    let version = env!("CARGO_PKG_VERSION");
    let name = env!("CARGO_PKG_NAME");
    println!(
        "\nStarting {} {} (https://github.com/kienle-k/Onmap) at {}",
        name, version, formatted_time
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use std::time::Duration;

    fn parse_cli(args: &[&str]) -> Cli {
        Cli::try_parse_from(Cli::normalize_args(args.iter().copied()))
            .expect("CLI arguments should parse")
    }

    #[test]
    fn cli_accepts_plain_version_flag() {
        let cli = parse_cli(&["onmap", "-V"]);

        assert_eq!(cli.version, Some(None));
    }

    #[test]
    fn cli_accepts_json_version_format() {
        let cli = parse_cli(&["onmap", "--version", "json"]);

        assert_eq!(cli.version, Some(Some(VersionFormat::Json)));
    }

    #[test]
    fn cli_rejects_invalid_version_format() {
        let err = Cli::try_parse_from(Cli::normalize_args(["onmap", "-V", "text"]))
            .expect_err("invalid version format should fail");

        assert!(err.to_string().contains("json"));
    }

    #[test]
    fn build_command_from_cli_supports_combined_host_discovery_probes() {
        let cli = parse_cli(&["onmap", "-PE", "-PP", "-PS22", "127.0.0.1"]);

        let command = build_command_from_cli(&cli)
            .expect("combined host discovery command should build")
            .expect("combined host discovery command should be present");

        match command {
            ExecutionCommand::HostDiscovery {
                methods,
                targets,
                timeout_override_ms,
            } => {
                assert_eq!(methods.len(), 3);
                assert_eq!(timeout_override_ms, None);
                assert_eq!(targets, vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))]);

                assert!(methods.iter().any(
                    |spec| spec.method == HostDiscoveryOption::IcmpEcho && spec.ports.is_none()
                ));
                assert!(
                    methods
                        .iter()
                        .any(|spec| spec.method == HostDiscoveryOption::IcmpTimestamp
                            && spec.ports.is_none())
                );
                assert!(
                    methods
                        .iter()
                        .any(|spec| spec.method == HostDiscoveryOption::TcpSynDiscovery
                            && spec.ports == Some(vec![22]))
                );
            }
            other => panic!("expected host discovery command, got {:?}", other),
        }
    }

    #[test]
    fn build_command_from_cli_supports_different_ports_per_method() {
        let cli = parse_cli(&["onmap", "-PE", "-PS22", "-PA80", "-PU53", "127.0.0.1"]);

        let command = build_command_from_cli(&cli)
            .expect("host discovery command should build")
            .expect("host discovery command should be present");

        match command {
            ExecutionCommand::HostDiscovery {
                methods, targets, ..
            } => {
                assert_eq!(targets, vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))]);
                assert!(methods.iter().any(
                    |spec| spec.method == HostDiscoveryOption::IcmpEcho && spec.ports.is_none()
                ));
                assert!(
                    methods
                        .iter()
                        .any(|spec| spec.method == HostDiscoveryOption::TcpSynDiscovery
                            && spec.ports == Some(vec![22]))
                );
                assert!(
                    methods
                        .iter()
                        .any(|spec| spec.method == HostDiscoveryOption::TcpAckDiscovery
                            && spec.ports == Some(vec![80]))
                );
                assert!(
                    methods
                        .iter()
                        .any(|spec| spec.method == HostDiscoveryOption::UdpDiscovery
                            && spec.ports == Some(vec![53]))
                );
            }
            other => panic!("expected host discovery command, got {:?}", other),
        }
    }

    #[test]
    fn build_command_from_cli_uses_shared_fallback_ports_for_unspecified_methods() {
        let cli = parse_cli(&["onmap", "-PS22", "-PA", "-PU", "-p", "53", "127.0.0.1"]);

        let command = build_command_from_cli(&cli)
            .expect("host discovery command should build")
            .expect("host discovery command should be present");

        match command {
            ExecutionCommand::HostDiscovery { methods, .. } => {
                assert!(
                    methods
                        .iter()
                        .any(|spec| spec.method == HostDiscoveryOption::TcpSynDiscovery
                            && spec.ports == Some(vec![22]))
                );
                assert!(
                    methods
                        .iter()
                        .any(|spec| spec.method == HostDiscoveryOption::TcpAckDiscovery
                            && spec.ports == Some(vec![53]))
                );
                assert!(
                    methods
                        .iter()
                        .any(|spec| spec.method == HostDiscoveryOption::UdpDiscovery
                            && spec.ports == Some(vec![53]))
                );
            }
            other => panic!("expected host discovery command, got {:?}", other),
        }
    }

    #[test]
    fn build_command_from_cli_errors_when_selected_port_method_has_no_ports() {
        let cli = parse_cli(&["onmap", "-PS", "-PA80", "127.0.0.1"]);

        let err = build_command_from_cli(&cli)
            .expect_err("missing ports for selected port-based method should error");

        assert!(err.contains("TCP SYN discovery probes"));
    }

    #[test]
    fn build_command_from_cli_errors_when_method_specific_ports_are_unused() {
        let cli = parse_cli(&["onmap", "--PA-ports", "80", "127.0.0.1"]);

        let err = build_command_from_cli(&cli)
            .expect_err("method-specific ports without selecting the method should error");

        assert!(err.contains("-PA"));
    }

    #[test]
    fn build_command_from_cli_supports_flat_port_scan_syntax() {
        let cli = parse_cli(&["onmap", "-sT", "-p", "22", "127.0.0.1"]);

        let command = build_command_from_cli(&cli)
            .expect("port scan command should build")
            .expect("port scan command should be present");

        match command {
            ExecutionCommand::PortScan {
                method,
                ports,
                targets,
                timeout_override_ms,
                ..
            } => {
                assert_eq!(method, PortScanOption::ConnectScan);
                assert_eq!(ports, vec![22]);
                assert_eq!(targets, vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))]);
                assert_eq!(timeout_override_ms, None);
            }
            other => panic!("expected port scan command, got {:?}", other),
        }
    }

    #[test]
    fn build_command_from_cli_supports_port_scan_after_output_flag() {
        let cli = parse_cli(&["onmap", "-X", "test", "-sS", "-p1", "127.0.0.1"]);

        let command = build_command_from_cli(&cli)
            .expect("port scan command should build")
            .expect("port scan command should be present");

        match command {
            ExecutionCommand::PortScan {
                method,
                ports,
                targets,
                ..
            } => {
                assert_eq!(method, PortScanOption::SynScan);
                assert_eq!(ports, vec![1]);
                assert_eq!(targets, vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))]);
            }
            other => panic!("expected port scan command, got {:?}", other),
        }
    }

    #[test]
    fn merge_host_discovery_results_uses_any_up_and_best_latency() {
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let start_one = SystemTime::UNIX_EPOCH + Duration::from_secs(10);
        let end_one = SystemTime::UNIX_EPOCH + Duration::from_secs(12);
        let start_two = SystemTime::UNIX_EPOCH + Duration::from_secs(9);
        let end_two = SystemTime::UNIX_EPOCH + Duration::from_secs(13);

        let merged = merge_host_discovery_results(vec![
            (
                vec![HostDiscoverySingleResult {
                    ip_address: ip,
                    dns_resolve: Some("slow.example".to_string()),
                    latency: Some(Duration::from_millis(25)),
                    is_up: true,
                    reply_type: "ICMP echo reply".to_string(),
                    ttl: 42,
                }],
                HostDiscoveryAllResult {
                    scanned_addresses: vec![ip],
                    ports_per_host: 0,
                    hosts_up: 1,
                    hosts_dns_resolution: 1,
                    start_time: start_one,
                    end_time: end_one,
                    packets_sent: 1,
                    dns_elapsed_secs: 0.0,
                },
            ),
            (
                vec![HostDiscoverySingleResult {
                    ip_address: ip,
                    dns_resolve: Some("fast.example".to_string()),
                    latency: Some(Duration::from_millis(5)),
                    is_up: true,
                    reply_type: "RST port 22".to_string(),
                    ttl: 55,
                }],
                HostDiscoveryAllResult {
                    scanned_addresses: vec![ip],
                    ports_per_host: 1,
                    hosts_up: 1,
                    hosts_dns_resolution: 1,
                    start_time: start_two,
                    end_time: end_two,
                    packets_sent: 1,
                    dns_elapsed_secs: 0.0,
                },
            ),
        ]);

        assert_eq!(merged.0.len(), 1);
        assert!(merged.0[0].is_up);
        assert_eq!(merged.0[0].reply_type, "RST port 22");
        assert_eq!(merged.0[0].dns_resolve.as_deref(), Some("fast.example"));
        assert_eq!(merged.0[0].ttl, 55);

        assert_eq!(merged.1.scanned_addresses, vec![ip]);
        assert_eq!(merged.1.hosts_up, 1);
        assert_eq!(merged.1.hosts_dns_resolution, 1);
        assert_eq!(merged.1.ports_per_host, 1);
        assert_eq!(merged.1.packets_sent, 2);
        assert_eq!(merged.1.start_time, start_two);
        assert_eq!(merged.1.end_time, end_two);
    }
}
