use std::io;
use onmap::run_onmap;
use onmap::models::Cli;
use clap::Parser;



fn main() -> Result<(), io::Error> {

    let cli = Cli::parse_from(Cli::normalize_args(std::env::args_os()));
   
    if let Err(e) = run_onmap(cli) {
        eprintln!("Application failed to run: {}", e);
    }

    Ok(())
}