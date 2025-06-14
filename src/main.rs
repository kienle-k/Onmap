use std::io;
use clap::Parser;
use std::env;
use onmap::run_onmap;

/// A simple and fast network scanner built in Rust.
#[derive(Parser, Debug)]
#[command(name = "onmap", version, about, long_about = None)]
pub struct Cli {
    /// Target host(s) to scan.
    #[arg(required = true)]
    pub target: String,

    /// Specify port range, a list of ports, or a single port.
    #[arg(short, long)]
    pub port: Option<String>,

    // These are the simple, unambiguous flags our code will use.
    // They are hidden from the user's --help menu because we will trigger them manually.

    #[arg(long, hide = true, group = "scan_type")]
    pub ping_scan: bool,

    #[arg(long, hide = true, group = "scan_type")]
    pub syn_scan: bool,
    
    #[arg(long, hide = true, group = "scan_type")]
    pub connect_scan: bool,
}


fn main() -> Result<(), io::Error> {

    // 1. Collect all command-line arguments into a vector of strings.
    let args: Vec<String> = env::args().collect();
    let mut modified_args: Vec<String> = Vec::new();

    // 2. Iterate and transform the arguments.
    for arg in args {
        match arg.as_str() {
            "-sn" => modified_args.push("--ping-scan".to_string()),
            "-sS" => modified_args.push("--syn-scan".to_string()),
            "-sT" => modified_args.push("--connect-scan".to_string()),
            // You can add more transformations here, e.g., for -sA, -sU, etc.
            _ => modified_args.push(arg), // Keep all other arguments as they are.
        }
    }

    // 3. Ask clap to parse from our MODIFIED argument list.
    let cli = Cli::parse_from(modified_args);

    // 4. Now the logic is clean, using the unambiguous flags.
    if cli.ping_scan {
        println!("Action: Performing Ping Scan on target '{}'", cli.target);
        // ... call ping scan logic
    } else if cli.syn_scan {
        println!("Action: Performing SYN Scan on target '{}'", cli.target);
        // ... call syn scan logic
    } else if cli.connect_scan {
        println!("Action: Performing Connect Scan on target '{}'", cli.target);
        // ... call connect scan logic
    } else {
        println!("No scan type specified or scan type not recognized.");
    }
   
    if let Err(e) = run_onmap() {
        eprintln!("Application failed to run: {}", e);
    }

    Ok(())
}