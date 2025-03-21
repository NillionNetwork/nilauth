use authority_service::args::Cli;
use authority_service::config::Config;
use authority_service::run::run;
use clap::Parser;
use std::process::exit;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().init();

    let cli = Cli::parse();
    let config = match Config::load(cli.config_file.as_deref()) {
        Ok(config) => config,
        Err(e) => {
            eprintln!("Invalid config: {e}");
            exit(1);
        }
    };
    if let Err(e) = run(config).await {
        eprintln!("Failed to run server: {e:#}");
        exit(1);
    } else {
        Ok(())
    }
}
