//! Observability initialization for the nilauth service.
//!
//! This module provides OpenTelemetry integration for exporting logs and traces via OTLP gRPC.
//! When OTEL is enabled, telemetry is exported to a configured endpoint.

use std::env;

use crate::config::{Config, OtelConfig};
use opentelemetry::{KeyValue, global, trace::TracerProvider};
use opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge;
use opentelemetry_otlp::{LogExporter, MetricExporter, SpanExporter, WithExportConfig};
use opentelemetry_resource_detectors::ProcessResourceDetector;
use opentelemetry_sdk::{
    Resource,
    logs::SdkLoggerProvider,
    metrics::{PeriodicReader, SdkMeterProvider},
    trace::SdkTracerProvider,
};
use tracing::{error, info};
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

/// A guard that manages the lifecycle of observability resources.
///
/// When dropped, this guard ensures proper shutdown of any OTEL providers.
pub struct ObservabilityGuard {
    logger_provider: Option<SdkLoggerProvider>,
    tracer_provider: Option<SdkTracerProvider>,
    meter_provider: Option<SdkMeterProvider>,
}

impl ObservabilityGuard {
    /// Returns whether OTEL metrics are enabled.
    pub fn otel_metrics_enabled(&self) -> bool {
        self.meter_provider.is_some()
    }

    /// Shuts down the observability providers, flushing any pending data.
    pub fn shutdown(mut self) {
        self.shutdown_providers();
    }

    /// Internal helper to shut down all providers.
    ///
    /// Flushes pending data before shutdown to ensure nothing is lost.
    /// Uses tracing::error! for consistency. The fmt layer remains active even
    /// after OTEL providers are shut down, so errors will still be logged.
    fn shutdown_providers(&mut self) {
        if let Some(provider) = self.meter_provider.take() {
            if let Err(e) = provider.force_flush() {
                error!("Error flushing meter provider: {e}");
            }
            if let Err(e) = provider.shutdown() {
                error!("Error shutting down meter provider: {e}");
            }
        }
        if let Some(provider) = self.tracer_provider.take() {
            if let Err(e) = provider.force_flush() {
                error!("Error flushing tracer provider: {e}");
            }
            if let Err(e) = provider.shutdown() {
                error!("Error shutting down tracer provider: {e}");
            }
        }
        if let Some(provider) = self.logger_provider.take() {
            if let Err(e) = provider.force_flush() {
                error!("Error flushing logger provider: {e}");
            }
            if let Err(e) = provider.shutdown() {
                error!("Error shutting down logger provider: {e}");
            }
        }
    }
}

impl Drop for ObservabilityGuard {
    fn drop(&mut self) {
        self.shutdown_providers();
    }
}

/// Initializes observability based on the provided configuration.
///
/// When `otel.enabled` is true, OTLP export is configured for enabled signals (logs, metrics, traces).
/// Standard fmt logging is always enabled alongside OTEL.
///
/// Standard OTEL environment variables are supported:
/// - `OTEL_SDK_DISABLED`: Set to "true" to disable OTEL and use only fmt logging
/// - `OTEL_EXPORTER_OTLP_ENDPOINT`: OTLP endpoint URL (overrides config)
/// - `OTEL_SERVICE_NAME`: Service name (overrides config)
/// - `OTEL_RESOURCE_ATTRIBUTES`: Additional resource attributes (e.g., "team.name=myteam,deployment.environment.name=prod")
pub fn init(config: &Config) -> anyhow::Result<ObservabilityGuard> {
    // Check if OTEL is disabled via environment variable
    if config.otel.enabled && is_otel_sdk_disabled() {
        let guard = init_fmt_logging()?;
        info!("OpenTelemetry SDK disabled via OTEL_SDK_DISABLED environment variable");
        return Ok(guard);
    }

    if config.otel.enabled {
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

/// Applies standard OTEL environment variable overrides to the configuration.
///
/// Environment variables take precedence over YAML configuration values.
fn apply_otel_env_overrides(config: &OtelConfig) -> OtelConfig {
    let mut config = config.clone();

    if let Ok(endpoint) = env::var("OTEL_EXPORTER_OTLP_ENDPOINT") {
        config.endpoint = endpoint;
    }

    if let Ok(service_name) = env::var("OTEL_SERVICE_NAME") {
        config.service_name = service_name;
    }

    config
}

/// Initializes standard fmt logging.
///
/// Uses `try_init()` to gracefully handle the case where a subscriber is already set
/// (e.g., in integration tests that initialize tracing before calling this function).
fn init_fmt_logging() -> anyhow::Result<ObservabilityGuard> {
    // Ignore SetGlobalDefaultError. If a subscriber is already set, that's fine
    let _ = tracing_subscriber::fmt().try_init();
    Ok(ObservabilityGuard { logger_provider: None, tracer_provider: None, meter_provider: None })
}

/// Initializes OpenTelemetry with OTLP export for logs, traces, and metrics.
///
/// Gracefully degrades on exporter errors: if a provider fails to initialize,
/// logs a warning and continues with partial observability rather than failing completely.
fn init_otel(config: &OtelConfig) -> anyhow::Result<ObservabilityGuard> {
    let resource = create_resource(config);

    // Initialize tracer provider if traces are enabled (graceful degradation on error)
    let tracer_provider = if config.traces.enabled {
        match init_tracer_provider(config, resource.clone()) {
            Ok(provider) => Some(provider),
            Err(e) => {
                eprintln!("Warning: Failed to initialize tracer provider: {e}");
                None
            }
        }
    } else {
        None
    };

    // Initialize logger provider if logs are enabled (graceful degradation on error)
    let logger_provider = if config.logs.enabled {
        match init_logger_provider(config, resource.clone()) {
            Ok(provider) => Some(provider),
            Err(e) => {
                eprintln!("Warning: Failed to initialize logger provider: {e}");
                None
            }
        }
    } else {
        None
    };

    // Initialize meter provider if metrics are enabled (graceful degradation on error)
    let meter_provider = if config.metrics.enabled {
        match init_meter_provider(config, resource) {
            Ok(provider) => {
                // Set the global meter provider so metrics can be recorded from anywhere
                global::set_meter_provider(provider.clone());
                Some(provider)
            }
            Err(e) => {
                eprintln!("Warning: Failed to initialize meter provider: {e}");
                None
            }
        }
    } else {
        None
    };

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
    let metrics_endpoint = config.metrics.endpoint.as_ref().unwrap_or(&config.endpoint);

    info!(
        logs_endpoint = %logs_endpoint,
        traces_endpoint = %traces_endpoint,
        metrics_endpoint = %metrics_endpoint,
        service_name = %config.service_name,
        logs_enabled = config.logs.enabled,
        traces_enabled = config.traces.enabled,
        metrics_enabled = config.metrics.enabled,
        "OpenTelemetry initialized"
    );

    Ok(ObservabilityGuard { logger_provider, tracer_provider, meter_provider })
}

/// Creates an OTEL resource with service attributes.
///
/// Additional attributes like `team.name` and `deployment.environment.name`
/// can be set via the `OTEL_RESOURCE_ATTRIBUTES` environment variable.
fn create_resource(config: &OtelConfig) -> Resource {
    // Build the base attributes
    let mut attributes = vec![KeyValue::new("service.version", env!("CARGO_PKG_VERSION"))];

    // Add any custom resource attributes from config
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

/// Initializes the OTEL meter provider with OTLP export.
///
/// NOTE: The export timeout is configured on the `MetricExporter` itself (in `build_metric_exporter`),
/// not on the `PeriodicReader`. The reader's interval controls how often metrics are collected and
/// exported, while the exporter's timeout controls the network operation timeout.
fn init_meter_provider(config: &OtelConfig, resource: Resource) -> anyhow::Result<SdkMeterProvider> {
    let exporter = build_metric_exporter(config)?;
    let reader = PeriodicReader::builder(exporter).with_interval(config.metrics.export_interval).build();
    let provider = SdkMeterProvider::builder().with_resource(resource).with_reader(reader).build();

    Ok(provider)
}

/// Builds the OTLP metric exporter using gRPC transport.
fn build_metric_exporter(config: &OtelConfig) -> anyhow::Result<MetricExporter> {
    // Use metrics.endpoint if set, otherwise fall back to global endpoint
    let endpoint = config.metrics.endpoint.as_ref().unwrap_or(&config.endpoint);

    let exporter = MetricExporter::builder()
        .with_tonic()
        .with_endpoint(endpoint)
        .with_timeout(config.export_timeout)
        .build()
        .map_err(|e| anyhow::anyhow!("failed to build gRPC metric exporter: {e}"))?;

    Ok(exporter)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    #[test]
    #[serial]
    fn otel_sdk_disabled_env_var() {
        // SAFETY: Test-only, running serially
        unsafe { env::remove_var("OTEL_SDK_DISABLED") };
        assert!(!is_otel_sdk_disabled(), "should be enabled when unset");

        unsafe { env::set_var("OTEL_SDK_DISABLED", "true") };
        assert!(is_otel_sdk_disabled(), "should be disabled for 'true'");

        unsafe { env::set_var("OTEL_SDK_DISABLED", "1") };
        assert!(is_otel_sdk_disabled(), "should be disabled for '1'");

        unsafe { env::set_var("OTEL_SDK_DISABLED", "false") };
        assert!(!is_otel_sdk_disabled(), "should be enabled for 'false'");

        unsafe { env::remove_var("OTEL_SDK_DISABLED") };
    }

    #[test]
    fn create_resource_with_attributes() {
        let mut config = OtelConfig::default();
        config.service_name = "test-service".to_string();
        config.resource_attributes.insert("team.name".to_string(), "platform".to_string());

        let resource = create_resource(&config);

        let get_attr = |name: &str| resource.iter().find(|(k, _)| k.as_str() == name).map(|(_, v)| v.to_string());

        assert_eq!(get_attr("service.name"), Some("test-service".to_string()));
        assert_eq!(get_attr("service.version"), Some(env!("CARGO_PKG_VERSION").to_string()));
        assert_eq!(get_attr("team.name"), Some("platform".to_string()));
    }

    #[test]
    fn observability_guard_safe_with_no_providers() {
        let guard = ObservabilityGuard { logger_provider: None, tracer_provider: None, meter_provider: None };

        assert!(!guard.otel_metrics_enabled());
        guard.shutdown(); // Should not panic
    }
}
