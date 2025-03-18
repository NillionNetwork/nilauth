use anyhow::Context;
use args::Cli;
use axum::{routing::get, Router};
use axum_prometheus::{
    metrics_exporter_prometheus::PrometheusBuilder, EndpointLabel, PrometheusMetricLayerBuilder,
};
use clap::Parser;
use config::Config;
use nillion_chain_client::tx::DefaultPaymentTransactionRetriever;
use state::{AppState, Services};
use std::{net::SocketAddr, process::exit, time::Duration};
use time::DefaultTimeService;
use tokio::{join, net::TcpListener};
use tracing::info;

mod args;
mod config;
mod routes;
mod state;
mod time;

#[cfg(test)]
mod tests;

async fn serve(
    endpoint: SocketAddr,
    router: Router,
    server_type: &'static str,
) -> anyhow::Result<()> {
    info!("Starting {server_type} server on {endpoint}");
    let listener = TcpListener::bind(endpoint)
        .await
        .context("failed to bind to endpoint")?;
    axum::serve(listener, router)
        .await
        .context("failed to serve")
}

async fn run(cli: Cli) -> anyhow::Result<()> {
    let config = Config::load(cli.config_file.as_deref())?;
    let secret_key = config.private_key.load_key()?;
    let services = Services {
        tx: Box::new(DefaultPaymentTransactionRetriever::new(
            &config.payments.nilchain_url,
        )?),
        time: Box::new(DefaultTimeService),
    };
    let state = AppState {
        secret_key,
        token_expiration: Duration::from_secs(config.tokens.expiration_seconds),
        services,
    };
    // Create a custom prometheus layer that ignores unknown paths and returns `/unknown` instead so
    // crawlers/malicious actors can't create high cardinality metrics by hitting unknown routes.
    let (prometheus_layer, metrics_handle) = PrometheusMetricLayerBuilder::new()
        .with_prefix("app")
        .with_endpoint_label_type(EndpointLabel::MatchedPathWithFallbackFn(|_| {
            "/unknown".into()
        }))
        .with_metrics_from_fn(|| {
            PrometheusBuilder::new()
                .install_recorder()
                .expect("failed to install metrics recorder")
        })
        .build_pair();
    let router = routes::build_router(state).layer(prometheus_layer);
    let metrics_router =
        Router::new().route("/metrics", get(|| async move { metrics_handle.render() }));

    let app = serve(config.server.bind_endpoint, router, "main");
    let metrics = serve(config.metrics.bind_endpoint, metrics_router, "metrics");
    let (app, metrics) = join!(app, metrics);
    app.context("running main server")?;
    metrics.context("running metrics server")?;
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
