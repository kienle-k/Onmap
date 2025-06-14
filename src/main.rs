use std::io;
//use clap::Parser;
use onmap::run_onmap;




fn main() -> Result<(), io::Error> {
   
    if let Err(e) = run_onmap() {
        eprintln!("Application failed to run: {}", e);
    }

    Ok(())
}