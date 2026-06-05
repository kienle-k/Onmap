// --- Module declarations ---
mod host_discovery;
mod port_scanning;
mod port_summary;
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
use iana_time_zone::get_timezone;
use ratatui::backend::CrosstermBackend;
use ratatui::terminal::Terminal;

// --- Internal imports (from this crate) ---
use crate::output::{
    save_to_file_grepable_host_discovery, save_to_file_grepable_port_scan,
    save_to_file_normal_host_discovery, save_to_file_normal_port_scan,
    save_to_file_xml_host_discovery, save_to_file_xml_port_scan,
};
use crate::tui::{App, run_tui};
use models::{
    Cli, DiscoveryMode, DiscoveryPlan, DiscoveryProbe, ExecutionCommand, HostDiscoveryAllResult,
    HostDiscoveryOption, HostDiscoveryResult, HostDiscoverySingleResult, HostMergeState,
    MainMenuItem, PortOptions, PortScanAllResult, PortScanOption, PortScanResult,
    PortScanSingleResult, VersionFormat,
};

use crate::host_discovery::engine::{DiscoveryResult, run_discovery};
use crate::host_discovery::planner::{default_set, plan_discovery};
use crate::resolving::source_ip::resolve_for_targets;
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
        let res = run_tui(&mut terminal, &mut app);

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
                println!();
            } else {
                println!("No scan method specified. Use `onmap --help` for usage information.");
                println!();
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
        match execute_command(command, use_original_printing, cli.verbosity).await {
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
        if !host_discovery_result.0.is_empty() && port_scan_result.0.is_empty() {
            save_to_file_xml_host_discovery(
                path,
                (&host_discovery_result.0, &host_discovery_result.1),
                cli.verbosity,
            )?;
            saved = true;
        }
        if !port_scan_result.0.is_empty() {
            save_to_file_xml_port_scan(
                path,
                (&port_scan_result.0, &port_scan_result.1),
                &host_discovery_result.0,
                cli.verbosity,
            )?;
            saved = true;
        }
        if !saved {
            println!("No results available to save to XML.");
        }
    }

    if let Some(path) = &cli.output_normal {
        let mut saved = false;
        if !host_discovery_result.0.is_empty() && port_scan_result.0.is_empty() {
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
        if !host_discovery_result.0.is_empty() && port_scan_result.0.is_empty() {
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
        if !host_discovery_result.0.is_empty() && port_scan_result.0.is_empty() {
            save_to_file_xml_host_discovery(
                &xml_path,
                (&host_discovery_result.0, &host_discovery_result.1),
                cli.verbosity,
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
            save_to_file_xml_port_scan(
                &xml_path,
                (&port_scan_result.0, &port_scan_result.1),
                &host_discovery_result.0,
                cli.verbosity,
            )?;
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
            let plan = DiscoveryPlan {
                mode: DiscoveryMode::DiscoveryOnly,
                probes: tui_option_to_probes(method, ports)?,
                disable_arp_ping: false,
            };
            ExecutionCommand::HostDiscovery {
                plan,
                targets,
                timeout_override_ms: None,
                no_dns: false,
            }
        }
        MainMenuItem::SubMenuPortScan => {
            let method =
                port_scan_selected.ok_or_else(|| "No port scan option selected".to_string())?;
            let ports = ports.ok_or_else(|| "Ports array could not be set".to_string())?;
            let is_root = nix::unistd::Uid::effective().is_root();
            // TUI does not surface -Pn or -sn yet; use the default planner output.
            let plan = DiscoveryPlan {
                mode: DiscoveryMode::BeforePortScan,
                probes: default_set(is_root),
                disable_arp_ping: false,
            };
            ExecutionCommand::PortScan {
                method,
                plan,
                targets,
                ports,
                timeout_override_ms: None,
                no_dns: false,
                service_version: false,
                os_detection: false,
                script: None,
            }
        }
    };

    Ok(Some(command))
}

fn tui_option_to_probes(
    option: HostDiscoveryOption,
    ports: Option<Vec<u16>>,
) -> Result<Vec<DiscoveryProbe>, String> {
    match option {
        HostDiscoveryOption::ListScan => Err("List scan is not implemented".to_string()),
        HostDiscoveryOption::PingScan => Ok(vec![DiscoveryProbe::IcmpEcho]),
        HostDiscoveryOption::ArpDiscovery => Ok(vec![DiscoveryProbe::Arp]),
        HostDiscoveryOption::IcmpEcho => Ok(vec![DiscoveryProbe::IcmpEcho]),
        HostDiscoveryOption::IcmpTimestamp => Ok(vec![DiscoveryProbe::IcmpTimestamp]),
        HostDiscoveryOption::TcpSynDiscovery => {
            let ports = ports.unwrap_or_else(|| vec![80]);
            Ok(ports
                .into_iter()
                .map(|port| DiscoveryProbe::TcpSyn { port })
                .collect())
        }
        HostDiscoveryOption::TcpAckDiscovery => {
            let ports = ports.unwrap_or_else(|| vec![80]);
            Ok(ports
                .into_iter()
                .map(|port| DiscoveryProbe::TcpAck { port })
                .collect())
        }
        HostDiscoveryOption::UdpDiscovery => {
            let ports = ports.unwrap_or_else(|| vec![40125]);
            Ok(ports
                .into_iter()
                .map(|port| DiscoveryProbe::Udp { port })
                .collect())
        }
    }
}

fn build_command_from_cli(cli: &Cli) -> Result<Option<ExecutionCommand>, String> {
    validate_discovery_port_flags(cli)?;

    let port_scan_method = selected_port_scan_method(cli)?;
    let is_root = nix::unistd::Uid::effective().is_root();
    let mut plan = plan_discovery(cli, is_root)?;

    // TCP connect scan never does ARP: connect() goes through the OS stack,
    // which resolves the MAC transparently, so onmap performs no link-layer ARP
    // for this scan type regardless of privilege or local-link membership
    // (matches nmap). Suppressing auto-ARP makes -sT -Pn on a local target
    // report it `user-set` up rather than `arp-response`. For other scan types
    // ARP behavior is unchanged.
    if port_scan_method == Some(PortScanOption::ConnectScan) {
        plan.disable_arp_ping = true;
    }
    let any_discovery_flag = cli.ping_scan
        || cli.pn
        || cli.icmp_echo
        || cli.icmp_timestamp
        || cli.arp
        || cli.syn_discovery
        || cli.ack_discovery
        || cli.udp_discovery;

    let command = match port_scan_method {
        Some(method) => ExecutionCommand::PortScan {
            method,
            plan,
            targets: parse_targets(
                cli.host_discovery_targets
                    .as_deref()
                    .ok_or_else(|| "Targets must be provided".to_string())?,
            )?,
            ports: parse_ports_spec(cli.scan_ports.as_ref())?,
            timeout_override_ms: cli.host_discovery_timeout_ms,
            no_dns: cli.no_dns,
            service_version: cli.service_version,
            os_detection: cli.os_detection,
            script: cli.script.clone(),
        },
        None => {
            if !any_discovery_flag {
                return Ok(None);
            }
            // No port scan requested; force discovery-only mode regardless of -sn.
            let plan = DiscoveryPlan {
                mode: DiscoveryMode::DiscoveryOnly,
                probes: plan.probes,
                disable_arp_ping: plan.disable_arp_ping,
            };
            ExecutionCommand::HostDiscovery {
                plan,
                targets: parse_targets(
                    cli.host_discovery_targets
                        .as_deref()
                        .ok_or_else(|| "Host discovery targets must be provided".to_string())?,
                )?,
                timeout_override_ms: cli.host_discovery_timeout_ms,
                no_dns: cli.no_dns,
            }
        }
    };

    Ok(Some(command))
}

fn validate_discovery_port_flags(cli: &Cli) -> Result<(), String> {
    if cli.syn_discovery_ports.is_some() && !cli.syn_discovery {
        return Err("TCP SYN discovery ports were provided but -PS was not selected".to_string());
    }
    if cli.ack_discovery_ports.is_some() && !cli.ack_discovery {
        return Err("TCP ACK discovery ports were provided but -PA was not selected".to_string());
    }
    if cli.udp_discovery_ports.is_some() && !cli.udp_discovery {
        return Err("UDP discovery ports were provided but -PU was not selected".to_string());
    }
    Ok(())
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
        // Discovery privilege is handled by the planner (raw probes when root,
        // TCP-connect when not), so no global root gate here.
        ExecutionCommand::HostDiscovery { .. } => false,
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
    use_original_printing: bool,
    verbosity: u8,
) -> Result<(Option<HostDiscoveryResult>, Option<PortScanResult>), String> {
    let is_root = nix::unistd::Uid::effective().is_root();

    if requires_root(&command) && !is_root {
        return Err("This scan requires root privileges.".to_string());
    }

    match command {
        ExecutionCommand::HostDiscovery {
            plan,
            targets,
            timeout_override_ms,
            no_dns,
        } => {
            let ipv4_targets = to_ipv4_vec(&targets)?;
            let num_targets = ipv4_targets.len();

            log::info!(
                "Initiating Host Discovery at {} [{} probe(s)/host, {} target(s)]",
                Local::now().format("%H:%M"),
                plan.probes.len(),
                num_targets
            );

            let start_time = SystemTime::now();
            let engine_result =
                run_discovery(&plan, &ipv4_targets, timeout_override_ms, no_dns, is_root).await;
            let end_time = SystemTime::now();
            let result =
                discovery_to_legacy(engine_result, &ipv4_targets, &plan, start_time, end_time);

            let elapsed = result
                .1
                .end_time
                .duration_since(result.1.start_time)
                .unwrap_or_default()
                .as_secs_f64();
            log::info!(
                "Completed Host Discovery at {}, {:.2}s elapsed ({} total hosts)",
                Local::now().format("%H:%M"),
                elapsed,
                num_targets
            );

            if use_original_printing {
                print_host_discovery_results_original(&result);
            } else {
                print_host_discovery_results(&result);
            }

            log::info!("Raw packets sent: {}", result.1.packets_sent);

            Ok((Some(result), None))
        }
        ExecutionCommand::PortScan {
            method,
            plan,
            targets,
            ports,
            timeout_override_ms,
            no_dns,
            service_version,
            os_detection,
            script,
        } => {
            let original_targets = to_ipv4_vec(&targets)?;
            let nmap_targets = original_targets.clone();

            let run_discovery_phase = !matches!(plan.mode, DiscoveryMode::SkipDiscoveryTreatAllUp);
            if run_discovery_phase {
                log::info!(
                    "Initiating Host Discovery at {} [{} probe(s)/host, {} target(s)]",
                    Local::now().format("%H:%M"),
                    plan.probes.len(),
                    original_targets.len()
                );
            }
            let discovery_start = SystemTime::now();
            let host_disc = run_pre_scan_discovery(
                &plan,
                &original_targets,
                timeout_override_ms,
                discovery_start,
                no_dns,
                is_root,
            )
            .await;
            let ipv4_targets: Vec<Ipv4Addr> = host_disc
                .0
                .iter()
                .filter(|r| r.is_up)
                .filter_map(|r| match r.ip_address {
                    IpAddr::V4(v) => Some(v),
                    IpAddr::V6(_) => None,
                })
                .collect();
            if run_discovery_phase {
                let elapsed = SystemTime::now()
                    .duration_since(discovery_start)
                    .unwrap_or_default()
                    .as_secs_f64();
                log::info!(
                    "Completed Host Discovery at {}, {:.2}s elapsed ({} of {} hosts up)",
                    Local::now().format("%H:%M"),
                    elapsed,
                    ipv4_targets.len(),
                    original_targets.len()
                );
            }
            if ipv4_targets.is_empty() {
                let elapsed = SystemTime::now()
                    .duration_since(discovery_start)
                    .unwrap_or_default()
                    .as_secs_f64();
                let total = original_targets.len();
                println!();
                if total == 1 {
                    println!(
                        "Note: Host seems down. If it is really up, but blocking our ping probes, try -Pn"
                    );
                } else {
                    println!(
                        "Note: Hosts seem down. If they are really up, but blocking our ping probes, try -Pn"
                    );
                }
                let ip_word = if total == 1 {
                    "IP address"
                } else {
                    "IP addresses"
                };
                println!(
                    "Onmap done: {} {} (0 hosts up) scanned in {:.2} seconds",
                    total, ip_word, elapsed
                );
                println!();
                // Return the discovery result (down hosts) rather than nothing so a
                // requested XML/normal/grepable path still produces a parseable
                // artifact with explicit zero-host runstats. No port-scan result.
                return Ok((Some(host_disc), None));
            }

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

            let mut result = match method {
                PortScanOption::SynScan => {
                    let pairs = resolve_for_targets(&ipv4_targets);
                    port_scanning::run_syn_scan(pairs, ports, timeout_override_ms).await?
                }
                PortScanOption::ConnectScan => {
                    port_scanning::run_connect_scan(ipv4_targets, ports, timeout_override_ms)
                        .await?
                }
                PortScanOption::AckScan => {
                    let pairs = resolve_for_targets(&ipv4_targets);
                    port_scanning::run_ack_scan(pairs, &ports, timeout_override_ms).await?
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
                    let pairs = resolve_for_targets(&ipv4_targets);
                    port_scanning::run_udp_scan(pairs, ports, timeout_override_ms).await?
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

            // Report the full scan-run window (discovery + port scan), not
            // scan-only. Done after the phase log above so that stays scan-only.
            result.1.start_time = discovery_start;
            // Label the result with the scan method for `<scaninfo>`.
            result.1.scan_type = Some(method);

            if use_original_printing {
                print_port_scan_results_original(
                    &result,
                    original_targets.len(),
                    verbosity,
                    no_dns,
                )
                .await;
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

            Ok((Some(host_disc), Some(result)))
        }
    }
}

/// Run the discovery engine and return the up-set (or the original targets
/// when the plan says skip discovery).
/// Runs the pre-scan host discovery and returns the full per-host result
/// (up reason/ttl included). `-Pn` (`SkipDiscoveryTreatAllUp`) is handled inside
/// `run_discovery`, which marks every target up without probing.
async fn run_pre_scan_discovery(
    plan: &DiscoveryPlan,
    targets: &[Ipv4Addr],
    timeout_override_ms: Option<u64>,
    start_time: SystemTime,
    no_dns: bool,
    is_root: bool,
) -> HostDiscoveryResult {
    let engine = run_discovery(plan, targets, timeout_override_ms, no_dns, is_root).await;
    discovery_to_legacy(engine, targets, plan, start_time, SystemTime::now())
}

/// Adapt the engine's `DiscoveryResult` to the legacy `HostDiscoveryResult` tuple
/// the existing printers consume.
fn discovery_to_legacy(
    engine: DiscoveryResult,
    ipv4_targets: &[Ipv4Addr],
    plan: &DiscoveryPlan,
    start_time: SystemTime,
    end_time: SystemTime,
) -> HostDiscoveryResult {
    let scanned_addresses: Vec<IpAddr> = ipv4_targets.iter().map(|ip| IpAddr::V4(*ip)).collect();
    let hosts_up = engine.hosts_up().len() as u64;
    let hosts_dns_resolution = engine
        .per_probe
        .iter()
        .filter(|r| r.dns_resolve.is_some())
        .count() as u64;
    let summary = HostDiscoveryAllResult {
        scanned_addresses,
        ports_per_host: plan.probes.len() as u16,
        hosts_up,
        hosts_dns_resolution,
        start_time,
        end_time,
        packets_sent: engine.packets_sent,
        dns_elapsed_secs: 0.0,
    };
    // Collapse the flat per-probe rows into one row per host via the original
    // merge. A single element keeps the summary above untouched (its min/max/sum
    // are identities) while the merge recomputes the deduplicated host counts.
    merge_host_discovery_results(vec![(engine.per_probe, summary)])
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

        let is_root = nix::unistd::Uid::effective().is_root();
        let command = build_command_from_cli(&cli)
            .expect("combined host discovery command should build")
            .expect("combined host discovery command should be present");

        match command {
            ExecutionCommand::HostDiscovery {
                plan,
                targets,
                timeout_override_ms,
                no_dns,
            } => {
                assert_eq!(timeout_override_ms, None);
                assert!(!no_dns);
                assert_eq!(targets, vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))]);
                assert_eq!(plan.mode, DiscoveryMode::DiscoveryOnly);

                if is_root {
                    assert_eq!(
                        plan.probes,
                        vec![
                            DiscoveryProbe::IcmpEcho,
                            DiscoveryProbe::IcmpTimestamp,
                            DiscoveryProbe::TcpSyn { port: 22 },
                        ]
                    );
                } else {
                    assert_eq!(plan.probes, vec![DiscoveryProbe::TcpConnect { port: 22 }]);
                }
            }
            other => panic!("expected host discovery command, got {:?}", other),
        }
    }

    #[test]
    fn build_command_from_cli_threads_no_dns() {
        let cli = parse_cli(&["onmap", "-n", "-sn", "127.0.0.1"]);

        let command = build_command_from_cli(&cli)
            .expect("no-dns host discovery command should build")
            .expect("no-dns host discovery command should be present");

        match command {
            ExecutionCommand::HostDiscovery { no_dns, .. } => assert!(no_dns),
            other => panic!("expected host discovery command, got {:?}", other),
        }
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
    fn connect_scan_disables_arp_ping() {
        // -sT never does ARP (connect() resolves the MAC via the OS stack), so
        // the plan must suppress auto-ARP regardless of -Pn / privilege.
        let cli = parse_cli(&["onmap", "-sT", "-Pn", "-p", "80", "10.10.0.1"]);
        let command = build_command_from_cli(&cli)
            .expect("connect scan command should build")
            .expect("connect scan command should be present");

        match command {
            ExecutionCommand::PortScan { method, plan, .. } => {
                assert_eq!(method, PortScanOption::ConnectScan);
                assert!(plan.disable_arp_ping, "connect scan must disable ARP ping");
            }
            other => panic!("expected port scan command, got {:?}", other),
        }
    }

    #[test]
    fn syn_scan_does_not_disable_arp_ping() {
        // Other scan types keep their normal ARP behavior.
        let cli = parse_cli(&["onmap", "-sS", "-p", "80", "10.10.0.1"]);
        let command = build_command_from_cli(&cli)
            .expect("syn scan command should build")
            .expect("syn scan command should be present");

        match command {
            ExecutionCommand::PortScan { method, plan, .. } => {
                assert_eq!(method, PortScanOption::SynScan);
                assert!(!plan.disable_arp_ping, "syn scan must not disable ARP ping");
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
