//! Unified metrics.
//!
//! This module defines metrics once and records to both backends:
//! - **Prometheus**: Underscore naming (`nucs_minted_total`)
//! - **OTEL**: Dot-notation semantic conventions (`nilauth.nucs.minted`)
//!
//! The active backend depends on configuration:
//! - OTEL metrics enabled → OTEL records to collector, Prometheus is no-op
//! - OTEL metrics disabled → Prometheus records via installed recorder, OTEL uses no-op
//!
//! ## Usage
//!
//! ```ignore
//! use crate::metrics;
//! metrics::record_nuc_minted("NilDb");
//! metrics::record_invalid_payment("underpaid");
//! ```

// Use explicit `::metrics` to reference the external crate, avoiding ambiguity
// with this module's name.
use ::metrics::{counter, gauge, histogram};
use opentelemetry::metrics::{Counter, Gauge, Histogram, Meter};
use opentelemetry::{KeyValue, global};
use std::sync::LazyLock;

/// Returns the nilauth meter from the global meter provider.
fn meter() -> Meter {
    global::meter("nilauth")
}

// =============================================================================
// OTEL Instrument Definitions
// =============================================================================

/// Counter for invalid payment attempts.
static OTEL_PAYMENT_INVALID: LazyLock<Counter<u64>> = LazyLock::new(|| {
    meter()
        .u64_counter("nilauth.payment.invalid")
        .with_description("Total number of invalid payment attempts")
        .with_unit("{payment}")
        .build()
});

/// Counter for valid payments processed.
static OTEL_PAYMENT_VALID: LazyLock<Counter<u64>> = LazyLock::new(|| {
    meter()
        .u64_counter("nilauth.payment.valid")
        .with_description("Total number of valid payments processed")
        .with_unit("{payment}")
        .build()
});

/// Counter for nucs (tokens) minted.
static OTEL_NUC_MINTED: LazyLock<Counter<u64>> = LazyLock::new(|| {
    meter().u64_counter("nilauth.nuc.minted").with_description("Total number of nucs minted").with_unit("{nuc}").build()
});

/// Counter for revoked tokens.
static OTEL_TOKEN_REVOKED: LazyLock<Counter<u64>> = LazyLock::new(|| {
    meter()
        .u64_counter("nilauth.token.revoked")
        .with_description("Total number of tokens revoked")
        .with_unit("{token}")
        .build()
});

/// Counter for expired revoked tokens removed from the database.
static OTEL_TOKEN_EXPIRED_REMOVED: LazyLock<Counter<u64>> = LazyLock::new(|| {
    meter()
        .u64_counter("nilauth.token.expired.removed")
        .with_description("Total number of expired revoked tokens removed")
        .with_unit("{token}")
        .build()
});

/// Counter for token price fetch errors.
static OTEL_TOKEN_PRICE_FETCH_ERROR: LazyLock<Counter<u64>> = LazyLock::new(|| {
    meter()
        .u64_counter("nilauth.token.price.fetch.error")
        .with_description("Total number of token price fetch errors")
        .with_unit("{error}")
        .build()
});

/// Counter for token price cache hits.
static OTEL_TOKEN_PRICE_CACHE_HIT: LazyLock<Counter<u64>> = LazyLock::new(|| {
    meter()
        .u64_counter("nilauth.token.price.cache.hit")
        .with_description("Total number of token price cache hits")
        .with_unit("{hit}")
        .build()
});

/// Gauge for current NIL token price in USD.
static OTEL_TOKEN_PRICE_USD: LazyLock<Gauge<f64>> = LazyLock::new(|| {
    meter()
        .f64_gauge("nilauth.token.price.usd")
        .with_description("Current NIL token price in USD")
        .with_unit("{USD}")
        .build()
});

/// Histogram for token price fetch duration.
static OTEL_TOKEN_PRICE_FETCH_DURATION: LazyLock<Histogram<f64>> = LazyLock::new(|| {
    meter()
        .f64_histogram("nilauth.token.price.fetch.duration")
        .with_description("Duration of token price fetch requests")
        .with_unit("s")
        .build()
});

// =============================================================================
// Process Metrics OTEL Instruments
// =============================================================================

/// Counter for process CPU time in seconds.
static OTEL_PROCESS_CPU_TIME: LazyLock<Counter<f64>> = LazyLock::new(|| {
    meter()
        .f64_counter("process.cpu.time")
        .with_description("Total CPU time consumed by the process")
        .with_unit("s")
        .build()
});

/// Gauge for process resident memory usage in bytes.
static OTEL_PROCESS_MEMORY_USAGE: LazyLock<Gauge<f64>> = LazyLock::new(|| {
    meter()
        .f64_gauge("process.memory.usage")
        .with_description("Current resident memory usage of the process")
        .with_unit("By")
        .build()
});

/// Gauge for open file descriptor count.
static OTEL_PROCESS_OPEN_FD_COUNT: LazyLock<Gauge<i64>> = LazyLock::new(|| {
    meter()
        .i64_gauge("process.unix.file_descriptor.count")
        .with_description("Number of open file descriptors")
        .with_unit("{file_descriptor}")
        .build()
});

/// Gauge for process thread count.
static OTEL_PROCESS_THREAD_COUNT: LazyLock<Gauge<i64>> = LazyLock::new(|| {
    meter()
        .i64_gauge("process.thread.count")
        .with_description("Number of threads in the process")
        .with_unit("{thread}")
        .build()
});

/// Counter for disk I/O bytes.
static OTEL_PROCESS_DISK_IO: LazyLock<Counter<u64>> = LazyLock::new(|| {
    meter().u64_counter("process.disk.io").with_description("Total bytes read/written to disk").with_unit("By").build()
});

/// Counter for disk I/O syscalls.
static OTEL_PROCESS_DISK_SYSCALLS: LazyLock<Counter<u64>> = LazyLock::new(|| {
    meter()
        .u64_counter("process.disk.syscalls")
        .with_description("Total number of disk read/write syscalls")
        .with_unit("{syscall}")
        .build()
});

/// Gauge for established TCP connections for this process.
static OTEL_PROCESS_NETWORK_CONNECTIONS: LazyLock<Gauge<i64>> = LazyLock::new(|| {
    meter()
        .i64_gauge("process.network.connection.count")
        .with_description("Number of established TCP connections for this process")
        .with_unit("{connection}")
        .build()
});

// =============================================================================
// Unified Recording Functions - Application Metrics
//
// Each function records to BOTH backends. The active backend depends on config:
// - OTEL metrics enabled: OTEL records, Prometheus is no-op
// - OTEL metrics disabled: Prometheus records, OTEL uses no-op provider
// =============================================================================

/// Records an invalid payment attempt.
///
/// - Prometheus: `invalid_payments_total{reason="..."}`
/// - OTEL: `nilauth.payment.invalid{reason="..."}`
pub fn record_invalid_payment(reason: &str) {
    // Prometheus
    counter!("invalid_payments_total", "reason" => reason.to_string()).increment(1);
    // OTEL
    OTEL_PAYMENT_INVALID.add(1, &[KeyValue::new("reason", reason.to_string())]);
}

/// Records a valid payment.
///
/// - Prometheus: `payments_valid_total{module="..."}`
/// - OTEL: `nilauth.payment.valid{module="..."}`
pub fn record_valid_payment(module: &str) {
    // Prometheus
    counter!("payments_valid_total", "module" => module.to_string()).increment(1);
    // OTEL
    OTEL_PAYMENT_VALID.add(1, &[KeyValue::new("module", module.to_string())]);
}

/// Records a nuc minted.
///
/// - Prometheus: `nucs_minted_total{module="..."}`
/// - OTEL: `nilauth.nuc.minted{module="..."}`
pub fn record_nuc_minted(module: &str) {
    // Prometheus
    counter!("nucs_minted_total", "module" => module.to_string()).increment(1);
    // OTEL
    OTEL_NUC_MINTED.add(1, &[KeyValue::new("module", module.to_string())]);
}

/// Records a token revocation.
///
/// - Prometheus: `revoked_tokens_total`
/// - OTEL: `nilauth.token.revoked`
pub fn record_token_revoked() {
    // Prometheus
    counter!("revoked_tokens_total").increment(1);
    // OTEL
    OTEL_TOKEN_REVOKED.add(1, &[]);
}

/// Records expired revoked tokens removed.
///
/// - Prometheus: `expired_revoked_tokens_removed_total`
/// - OTEL: `nilauth.token.expired.removed`
pub fn record_expired_tokens_removed(count: u64) {
    // Prometheus
    counter!("expired_revoked_tokens_removed_total").increment(count);
    // OTEL
    OTEL_TOKEN_EXPIRED_REMOVED.add(count, &[]);
}

/// Records a token price fetch error.
///
/// - Prometheus: `nil_token_price_fetch_errors_total`
/// - OTEL: `nilauth.token.price.fetch.error`
pub fn record_token_price_fetch_error() {
    // Prometheus
    counter!("nil_token_price_fetch_errors_total").increment(1);
    // OTEL
    OTEL_TOKEN_PRICE_FETCH_ERROR.add(1, &[]);
}

/// Records a token price cache hit.
///
/// - Prometheus: `nil_token_cache_hits_total`
/// - OTEL: `nilauth.token.price.cache.hit`
pub fn record_token_price_cache_hit() {
    // Prometheus
    counter!("nil_token_cache_hits_total").increment(1);
    // OTEL
    OTEL_TOKEN_PRICE_CACHE_HIT.add(1, &[]);
}

/// Records the current token price in USD.
///
/// - Prometheus: `nil_token_price`
/// - OTEL: `nilauth.token.price.usd`
pub fn record_token_price(price: f64) {
    // Prometheus
    gauge!("nil_token_price").set(price);
    // OTEL
    OTEL_TOKEN_PRICE_USD.record(price, &[]);
}

/// Records a token price fetch duration in seconds.
///
/// - Prometheus: `nil_token_price_fetch_seconds`
/// - OTEL: `nilauth.token.price.fetch.duration`
pub fn record_token_price_fetch_duration(seconds: f64) {
    // Prometheus
    histogram!("nil_token_price_fetch_seconds").record(seconds);
    // OTEL
    OTEL_TOKEN_PRICE_FETCH_DURATION.record(seconds, &[]);
}

// =============================================================================
// Unified Recording Functions - Process Metrics
// =============================================================================

/// Records process CPU time in seconds.
pub fn record_process_cpu_time(seconds: f64) {
    OTEL_PROCESS_CPU_TIME.add(seconds, &[]);
}

/// Records process resident memory usage in bytes.
pub fn record_process_memory_usage(bytes: f64) {
    OTEL_PROCESS_MEMORY_USAGE.record(bytes, &[]);
}

/// Records open file descriptor count.
pub fn record_process_open_fd_count(count: i64) {
    OTEL_PROCESS_OPEN_FD_COUNT.record(count, &[]);
}

/// Records process thread count.
pub fn record_process_thread_count(count: i64) {
    OTEL_PROCESS_THREAD_COUNT.record(count, &[]);
}

/// Records disk I/O bytes with direction attribute.
pub fn record_process_disk_io(bytes: u64, direction: &str) {
    OTEL_PROCESS_DISK_IO.add(bytes, &[KeyValue::new("direction", direction.to_string())]);
}

/// Records disk I/O syscalls with direction attribute.
pub fn record_process_disk_syscalls(count: u64, direction: &str) {
    OTEL_PROCESS_DISK_SYSCALLS.add(count, &[KeyValue::new("direction", direction.to_string())]);
}

/// Records established TCP connection count for this process.
pub fn record_network_connections(count: i64) {
    OTEL_PROCESS_NETWORK_CONNECTIONS.record(count, &[]);
}
