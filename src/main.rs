use anyhow::Context;
use args::Cli;
use clap::Parser;
use config::Config;
use state::AppState;
use std::{process::exit, time::Duration};
use tokio::net::TcpListener;
use tracing::info;

mod args;
mod config;
mod routes;
mod state;

async fn run(cli: Cli) -> anyhow::Result<()> {
    let config = Config::load(cli.config_file.as_deref())?;
    let secret_key = config.private_key.load_key()?;
    let state = AppState {
        secret_key,
        token_expiration: Duration::from_secs(config.tokens.expiration_seconds),
    };
    let router = routes::build_router(state);
    info!("Starting server on {}", config.server.bind_endpoint);
    let listener = TcpListener::bind(config.server.bind_endpoint)
        .await
        .context("failed to bind to endpoint")?;
    axum::serve(listener, router)
        .await
        .context("failed to run application")?;
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().init();

    let cli = Cli::parse();
    if let Err(e) = run(cli).await {
        eprintln!("Failed to run server: {e}");
        exit(1);
    } else {
        Ok(())
    }
}
