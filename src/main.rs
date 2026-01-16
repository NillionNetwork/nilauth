//! The main binary entrypoint for the nilauth service.

use clap::Parser;
use nilauth::args::Cli;
use nilauth::config::Config;
use nilauth::observability;
use nilauth::run::run;
use std::process::exit;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let config = match Config::load(cli.config_file.as_deref()) {
        Ok(config) => config,
        Err(e) => {
            eprintln!("Invalid config: {e}");
            exit(1);
        }
    };

    // Initialize observability (metrics or otel).
    // This must happen before any logging calls.
    let observability_guard = match observability::init(&config) {
        Ok(guard) => guard,
        Err(e) => {
            eprintln!("Failed to initialize observability: {e}");
            exit(1);
        }
    };

    let result = run(config).await;

    // Explicitly shutdown observability to flush pending traces/logs.
    // Necessary because exit() doesn't run destructors.
    observability_guard.shutdown();

    if let Err(e) = result {
        eprintln!("Failed to run server: {e:#}");
        exit(1);
    } else {
        Ok(())
    }
}
