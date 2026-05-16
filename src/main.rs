use std::io;
use onmap::run_onmap;
use onmap::models::Cli;
use clap::Parser;



fn main() -> Result<(), io::Error> {

    let cli = Cli::parse();
   
    if let Err(e) = run_onmap(cli) {
        eprintln!("Application failed to run: {}", e);
    }

    Ok(())
}