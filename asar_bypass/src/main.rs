use std::path::PathBuf;

use clap::Parser;
use log::info;

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    /// The file to patch
    input: PathBuf,

    /// Where to output the patched file
    output: PathBuf,
}

fn main() -> asar_bypass::Result<()> {
    env_logger::init();
    let cli = Cli::parse();
    asar_bypass::patch_file(cli.input, Some(cli.output))?;
    info!("Successfully patched.");
    Ok(())
}
