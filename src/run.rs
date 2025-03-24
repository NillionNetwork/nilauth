use crate::config::Config;
use crate::db::{account::PostgresAccountDb, PostgresPool};
use crate::state::{AppState, Databases, Services};
use crate::time::DefaultTimeService;
use anyhow::Context;
use axum::{routing::get, Router};
use axum_prometheus::{
    metrics_exporter_prometheus::PrometheusBuilder, EndpointLabel, PrometheusMetricLayerBuilder,
};
use chrono::Utc;
use nillion_chain_client::tx::DefaultPaymentTransactionRetriever;
use std::net::SocketAddr;
use tokio::{join, net::TcpListener};
use tracing::info;

pub async fn run(config: Config) -> anyhow::Result<()> {
    let secret_key = config.private_key.load_key()?;
    let services = Services {
        tx: Box::new(DefaultPaymentTransactionRetriever::new(
            &config.payments.nilchain_url,
        )?),
        time: Box::new(DefaultTimeService),
    };
    let pool = PostgresPool::new(&config.postgres.url)
        .await
        .context("failed to create database connection")?;
    let databases = Databases {
        accounts: Box::new(PostgresAccountDb::new(pool, config.payments.subscriptions)),
    };
    let state = AppState {
        secret_key,
        services,
        databases,
        started_at: Utc::now(),
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
    let router = crate::routes::build_router(state).layer(prometheus_layer);
    let metrics_router =
        Router::new().route("/metrics", get(|| async move { metrics_handle.render() }));

    let app = serve(config.server.bind_endpoint, router, "main");
    let metrics = serve(config.metrics.bind_endpoint, metrics_router, "metrics");
    let (app, metrics) = join!(app, metrics);
    app.context("running main server")?;
    metrics.context("running metrics server")?;
    Ok(())
}

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
