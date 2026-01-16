//! Observability initialization for the nilauth service.
//!
//! This module provides OpenTelemetry integration for exporting logs and traces via OTLP gRPC.
//! When OTEL is enabled, telemetry is exported to a configured endpoint.

use std::env;

use crate::config::{Config, OtelConfig};
use opentelemetry::{KeyValue, trace::TracerProvider};
use opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge;
use opentelemetry_otlp::{LogExporter, SpanExporter, WithExportConfig};
use opentelemetry_resource_detectors::ProcessResourceDetector;
use opentelemetry_sdk::{Resource, logs::SdkLoggerProvider, trace::SdkTracerProvider};
use tracing::info;
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

/// A guard that manages the lifecycle of observability resources.
///
/// When dropped, this guard ensures proper shutdown of any OTEL providers.
pub struct ObservabilityGuard {
    logger_provider: Option<SdkLoggerProvider>,
    tracer_provider: Option<SdkTracerProvider>,
}

impl ObservabilityGuard {
    /// Shuts down the observability providers, flushing any pending data.
    pub fn shutdown(mut self) {
        if let Some(provider) = self.tracer_provider.take()
            && let Err(e) = provider.shutdown()
        {
            eprintln!("Error shutting down tracer provider: {e}");
        }
        if let Some(provider) = self.logger_provider.take()
            && let Err(e) = provider.shutdown()
        {
            eprintln!("Error shutting down logger provider: {e}");
        }
    }
}

impl Drop for ObservabilityGuard {
    fn drop(&mut self) {
        if let Some(provider) = self.tracer_provider.take()
            && let Err(e) = provider.shutdown()
        {
            eprintln!("Error shutting down tracer provider: {e}");
        }
        if let Some(provider) = self.logger_provider.take()
            && let Err(e) = provider.shutdown()
        {
            eprintln!("Error shutting down logger provider: {e}");
        }
    }
}

/// Initializes observability based on the provided configuration.
///
/// When `otel.enabled` is true, OTLP export is configured for enabled signals (logs, metrics, traces).
/// Standard fmt logging is always enabled alongside OTEL.
///
/// Environment variables take precedence over YAML configuration:
/// - `OTEL_SDK_DISABLED`: Set to "true" to disable OTEL and use only fmt logging
/// - `OTEL_ENDPOINT`: OTLP endpoint URL
/// - `OTEL_SERVICE_NAME`: Service name (also read by SDK's EnvResourceDetector)
/// - `OTEL_TEAM_NAME`: Team responsible for the service
/// - `OTEL_DEPLOYMENT_ENV`: Deployment environment
/// - `OTEL_RESOURCE_ATTRIBUTES`: Additional resource attributes (read by SDK's EnvResourceDetector)
pub fn init(config: &Config) -> anyhow::Result<ObservabilityGuard> {
    let otel_enabled = config.otel.enabled && !is_otel_sdk_disabled();

    // Check if OTEL is disabled via environment variable
    if config.otel.enabled && is_otel_sdk_disabled() {
        let guard = init_fmt_logging()?;
        info!("OpenTelemetry SDK disabled via OTEL_SDK_DISABLED environment variable");
        return Ok(guard);
    }

    if otel_enabled {
        let otel_config = apply_otel_env_overrides(&config.otel);
        init_otel(&otel_config)
    } else {
        init_fmt_logging()
    }
}

/// Checks if the OTEL SDK is disabled via the `OTEL_SDK_DISABLED` environment variable.
fn is_otel_sdk_disabled() -> bool {
    env::var("OTEL_SDK_DISABLED").map(|v| v.eq_ignore_ascii_case("true") || v == "1").unwrap_or(false)
}

/// Applies OTEL environment variable overrides to the configuration.
///
/// Environment variables take precedence over YAML configuration values.
fn apply_otel_env_overrides(config: &OtelConfig) -> OtelConfig {
    let mut config = config.clone();

    if let Ok(endpoint) = env::var("OTEL_ENDPOINT") {
        config.endpoint = endpoint;
    }

    if let Ok(service_name) = env::var("OTEL_SERVICE_NAME") {
        config.service_name = service_name;
    }

    if let Ok(team_name) = env::var("OTEL_TEAM_NAME") {
        config.team_name = team_name;
    }

    if let Ok(deployment_env) = env::var("OTEL_DEPLOYMENT_ENV") {
        config.deployment_env = deployment_env;
    }

    config
}

/// Initializes standard fmt logging.
fn init_fmt_logging() -> anyhow::Result<ObservabilityGuard> {
    tracing_subscriber::fmt().init();
    Ok(ObservabilityGuard { logger_provider: None, tracer_provider: None })
}

/// Initializes OpenTelemetry with OTLP export for logs and traces.
fn init_otel(config: &OtelConfig) -> anyhow::Result<ObservabilityGuard> {
    let resource = create_resource(config);

    // Initialize tracer provider if traces are enabled
    let tracer_provider =
        if config.traces.enabled { Some(init_tracer_provider(config, resource.clone())?) } else { None };

    // Initialize logger provider if logs are enabled
    let logger_provider = if config.logs.enabled { Some(init_logger_provider(config, resource)?) } else { None };

    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    // Build optional layers
    let tracing_layer =
        tracer_provider.as_ref().map(|tp| tracing_opentelemetry::layer().with_tracer(tp.tracer("nilauth")));
    let logs_layer = logger_provider.as_ref().map(OpenTelemetryTracingBridge::new);

    tracing_subscriber::registry()
        .with(env_filter)
        .with(tracing_layer)
        .with(logs_layer)
        .with(tracing_subscriber::fmt::layer())
        .try_init()
        .map_err(|e| anyhow::anyhow!("failed to initialize tracing subscriber: {e}"))?;

    // Determine effective endpoints for logging
    let logs_endpoint = config.logs.endpoint.as_ref().unwrap_or(&config.endpoint);
    let traces_endpoint = config.traces.endpoint.as_ref().unwrap_or(&config.endpoint);

    info!(
        logs_endpoint = %logs_endpoint,
        traces_endpoint = %traces_endpoint,
        service_name = %config.service_name,
        team_name = %config.team_name,
        deployment_env = %config.deployment_env,
        logs_enabled = config.logs.enabled,
        traces_enabled = config.traces.enabled,
        "OpenTelemetry initialized"
    );

    Ok(ObservabilityGuard { logger_provider, tracer_provider })
}

/// Creates an OTEL resource with service attributes.
fn create_resource(config: &OtelConfig) -> Resource {
    // Build the base attributes
    let mut attributes = vec![
        KeyValue::new("service.version", env!("CARGO_PKG_VERSION")),
        KeyValue::new("team.name", config.team_name.clone()),
        KeyValue::new("deployment.environment.name", config.deployment_env.clone()),
    ];

    // Add any custom resource attributes
    for (key, value) in &config.resource_attributes {
        attributes.push(KeyValue::new(key.clone(), value.clone()));
    }

    Resource::builder()
        .with_service_name(config.service_name.clone())
        .with_attributes(attributes)
        .with_detector(Box::new(ProcessResourceDetector))
        .build()
}

/// Initializes the OTEL tracer provider with OTLP export.
fn init_tracer_provider(config: &OtelConfig, resource: Resource) -> anyhow::Result<SdkTracerProvider> {
    let exporter = build_span_exporter(config)?;
    let provider = SdkTracerProvider::builder().with_resource(resource).with_batch_exporter(exporter).build();

    Ok(provider)
}

/// Builds the OTLP span exporter using gRPC transport.
fn build_span_exporter(config: &OtelConfig) -> anyhow::Result<SpanExporter> {
    // Use traces.endpoint if set, otherwise fall back to global endpoint
    let endpoint = config.traces.endpoint.as_ref().unwrap_or(&config.endpoint);

    let exporter = SpanExporter::builder()
        .with_tonic()
        .with_endpoint(endpoint)
        .with_timeout(config.export_timeout)
        .build()
        .map_err(|e| anyhow::anyhow!("failed to build gRPC span exporter: {e}"))?;

    Ok(exporter)
}

/// Initializes the OTEL logger provider with OTLP export.
fn init_logger_provider(config: &OtelConfig, resource: Resource) -> anyhow::Result<SdkLoggerProvider> {
    let exporter = build_log_exporter(config)?;
    let provider = SdkLoggerProvider::builder().with_resource(resource).with_batch_exporter(exporter).build();

    Ok(provider)
}

/// Builds the OTLP log exporter using gRPC transport.
fn build_log_exporter(config: &OtelConfig) -> anyhow::Result<LogExporter> {
    // Use logs.endpoint if set, otherwise fall back to global endpoint
    let endpoint = config.logs.endpoint.as_ref().unwrap_or(&config.endpoint);

    let exporter = LogExporter::builder()
        .with_tonic()
        .with_endpoint(endpoint)
        .with_timeout(config.export_timeout)
        .build()
        .map_err(|e| anyhow::anyhow!("failed to build gRPC log exporter: {e}"))?;

    Ok(exporter)
}
