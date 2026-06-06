use clap::Parser;
use onmap::models::Cli;
use onmap::run_onmap;
use std::io;

fn main() -> Result<(), io::Error> {
    let cli = Cli::parse_from(Cli::normalize_args(std::env::args_os()));

    let runtime = tokio::runtime::Runtime::new()?;
    let result = runtime.block_on(run_onmap(cli));
    // Don't wait on orphaned spawn_blocking probes (losers of a host's first-up
    // race) at exit, or the process lingers after output is printed.
    runtime.shutdown_background();

    if let Err(e) = result {
        eprintln!("Application failed to run: {}", e);
    }

    Ok(())
}
