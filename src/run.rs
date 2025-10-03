use crate::cleanup::RevokedTokenCleaner;
use crate::config::Config;
use crate::db::revocations::PostgresRevocationDb;
use crate::db::{PostgresPool, subscriptions::PostgresSubscriptionDb};
use crate::metrics::ProcessMetricsCollector;
use crate::services::subscription_cost::DefaultSubscriptionCostService;
use crate::services::token_price::CoinGeckoTokenPriceService;
use crate::state::{AppState, Databases, Parameters, Services};
use crate::time::DefaultTimeService;
use anyhow::Context;
use axum::http;
use axum::{Router, routing::get};
use axum_prometheus::{EndpointLabel, PrometheusMetricLayerBuilder, metrics_exporter_prometheus::PrometheusBuilder};
use chrono::Utc;
use nilauth_client::nilchain_client::tx::DefaultPaymentTransactionRetriever;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::signal;
use tokio::{join, net::TcpListener};
use tower_http::cors::CorsLayer;
use tracing::info;

pub async fn run(config: Config) -> anyhow::Result<()> {
    let keypair = config.private_key.load_key()?;
    let token_price_service = Arc::new(CoinGeckoTokenPriceService::new(config.payments.token_price)?);
    let services = Services {
        tx: Box::new(DefaultPaymentTransactionRetriever::new(&config.payments.nilchain_url)?),
        time: Box::new(DefaultTimeService),
        subscription_cost: Box::new(DefaultSubscriptionCostService::new(
            token_price_service,
            config.payments.subscriptions.dollar_cost.clone(),
        )),
    };
    let pool = PostgresPool::new(&config.postgres.url).await.context("failed to create database connection")?;
    let databases = Databases {
        subscriptions: Box::new(PostgresSubscriptionDb::new(pool.clone(), config.payments.subscriptions.clone())),
        revocations: Arc::new(PostgresRevocationDb::new(pool)),
    };
    let state = AppState {
        parameters: Parameters {
            keypair,
            started_at: Utc::now(),
            subscription_cost_slippage: config.payments.subscriptions.payment_slippage,
            subscription_renewal_threshold: config.payments.subscriptions.renewal_threshold,
        },
        services,
        databases,
    };
    // Spawn a helper to clean up expired tokens
    RevokedTokenCleaner::spawn(state.databases.revocations.clone(), Box::new(DefaultTimeService));

    // Create a custom prometheus layer that ignores unknown paths and returns `/unknown` instead so
    // crawlers/malicious actors can't create high cardinality metrics by hitting unknown routes.
    let (prometheus_layer, metrics_handle) = PrometheusMetricLayerBuilder::new()
        .with_prefix("app")
        .with_endpoint_label_type(EndpointLabel::MatchedPathWithFallbackFn(|_| "/unknown".into()))
        .with_metrics_from_fn(|| {
            PrometheusBuilder::new().install_recorder().expect("failed to install metrics recorder")
        })
        .build_pair();
    let cors = CorsLayer::new()
        .allow_methods([http::Method::GET, http::Method::POST])
        .allow_headers([http::header::CONTENT_TYPE])
        .allow_origin(tower_http::cors::Any);
    let router = crate::routes::build_router(state).layer(prometheus_layer).layer(cors);
    let metrics_router = Router::new().route("/metrics", get(|| async move { metrics_handle.render() }));

    ProcessMetricsCollector::spawn();

    let app = serve(config.server.bind_endpoint, router, "main");
    let metrics = serve(config.metrics.bind_endpoint, metrics_router, "metrics");
    let (app, metrics) = join!(app, metrics);
    app.context("running main server")?;
    metrics.context("running metrics server")?;
    Ok(())
}

async fn serve(endpoint: SocketAddr, router: Router, server_type: &'static str) -> anyhow::Result<()> {
    info!("Starting {server_type} server on {endpoint}");
    let listener = TcpListener::bind(endpoint).await.context("failed to bind to endpoint")?;
    axum::serve(listener, router).with_graceful_shutdown(shutdown_signal()).await.context("failed to serve")
}

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c().await.expect("failed to install Ctrl+C handler");
    };

    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    info!("Received shutdown signal");
}
