pub use collector::ProcessMetricsCollector;
pub use otel_collector::OtelProcessMetricsCollector;

#[cfg(not(target_os = "linux"))]
mod collector {
    use tracing::warn;

    /// A stub collector for non-Linux systems.
    pub struct ProcessMetricsCollector;

    impl ProcessMetricsCollector {
        /// On non-Linux systems, warns that process metrics collection is disabled.
        pub fn spawn() {
            warn!("Metrics collection is only supported on Linux.");
        }
    }
}

#[cfg(not(target_os = "linux"))]
mod otel_collector {
    use tracing::warn;

    /// A stub OTEL collector for non-Linux systems.
    pub struct OtelProcessMetricsCollector;

    impl OtelProcessMetricsCollector {
        /// On non-Linux systems, warns that process metrics collection is disabled.
        pub fn spawn() {
            warn!("OTEL metrics collection is only supported on Linux.");
        }
    }
}

#[cfg(target_os = "linux")]
pub(crate) mod collector {
    use metrics::{counter, gauge};
    use procfs::{WithCurrentSystemInfo, net::TcpState, process::Process};
    use std::{sync::LazyLock, time::Duration};
    use tokio::time::sleep;
    use tracing::warn;

    pub(crate) static TICKS_PER_SECOND: LazyLock<f64> = LazyLock::new(|| procfs::ticks_per_second() as f64);
    pub(crate) const COLLECT_INTERVAL: Duration = Duration::from_secs(30);

    /// Metrics about the node process.
    pub struct ProcessMetricsCollector;

    impl ProcessMetricsCollector {
        /// Spawns a background task to periodically collect and report process metrics.
        pub fn spawn() {
            tokio::spawn(async move {
                loop {
                    Self::collect_metrics();
                    sleep(COLLECT_INTERVAL).await;
                }
            });
        }

        fn collect_metrics() {
            let metrics = match Process::myself() {
                Ok(metrics) => metrics,
                Err(e) => {
                    warn!("Failed to load procfs entry: {e}");
                    return;
                }
            };
            let stat = match metrics.stat() {
                Ok(stat) => stat,
                Err(e) => {
                    warn!("Failed to load procfs stat: {e}");
                    return;
                }
            };
            let tick_rate = *TICKS_PER_SECOND;
            match stat.utime.checked_add(stat.stime) {
                Some(total_ticks) => {
                    let total_milliseconds = (total_ticks as f64 / tick_rate) * 1000.0;
                    counter!("process_cpu_milliseconds_total").absolute(total_milliseconds as u64);
                }
                None => warn!("CPU time calculation overflowed"),
            };
            let rss = stat.rss_bytes().get() as f64;
            gauge!("process_resident_memory_bytes").set(rss);

            if let Some(count) = metrics.fd_count().ok().and_then(|c| i32::try_from(c).ok()) {
                gauge!("open_file_descriptors").set(count);
            }
            gauge!("process_threads").set(stat.num_threads as f64);

            if let Ok(io) = metrics.io() {
                let operation_values = [("read", io.read_bytes, io.syscr), ("write", io.write_bytes, io.syscw)];
                for (operation, bytes, syscalls) in operation_values {
                    // See notes on gauge vs counter semantics needed for CPU time.
                    counter!("storage_io_bytes_total", "operation" => operation).absolute(bytes);
                    counter!("storage_io_syscalls_total", "operation" => operation).absolute(syscalls);
                }
            }

            if let Ok(net) = metrics.tcp() {
                let established_count =
                    net.iter().filter(|connection| connection.state == TcpState::Established).count() as f64;
                gauge!("established_tcp_connections").set(established_count);
            }
        }
    }
}

#[cfg(target_os = "linux")]
pub(crate) mod otel_collector {
    use crate::metrics;
    use procfs::{WithCurrentSystemInfo, net::TcpState, process::Process};
    use std::{sync::LazyLock, time::Duration};
    use tokio::{sync::Mutex, time::sleep};
    use tracing::warn;

    static TICKS_PER_SECOND: LazyLock<f64> = LazyLock::new(|| procfs::ticks_per_second() as f64);
    pub(crate) const COLLECT_INTERVAL: Duration = Duration::from_secs(30);

    /// Tracks previous values for cumulative metrics to compute deltas.
    /// OTEL counters use `add()` which increments, so we must track deltas ourselves.
    #[derive(Default)]
    pub(crate) struct PreviousValues {
        pub(crate) cpu_ticks: u64,
        pub(crate) disk_read_bytes: u64,
        pub(crate) disk_write_bytes: u64,
        pub(crate) disk_read_syscalls: u64,
        pub(crate) disk_write_syscalls: u64,
    }

    static PREVIOUS: LazyLock<Mutex<PreviousValues>> = LazyLock::new(|| Mutex::new(PreviousValues::default()));

    /// OTEL process metrics collector using OpenTelemetry semantic conventions.
    pub struct OtelProcessMetricsCollector;

    impl OtelProcessMetricsCollector {
        /// Spawns a background task to periodically collect and report process metrics via OTEL.
        pub fn spawn() {
            tokio::spawn(async move {
                loop {
                    Self::collect_metrics().await;
                    sleep(COLLECT_INTERVAL).await;
                }
            });
        }

        async fn collect_metrics() {
            let process = match Process::myself() {
                Ok(p) => p,
                Err(e) => {
                    warn!("Failed to load procfs entry: {e}");
                    return;
                }
            };
            let stat = match process.stat() {
                Ok(stat) => stat,
                Err(e) => {
                    warn!("Failed to load procfs stat: {e}");
                    return;
                }
            };

            let mut prev = PREVIOUS.lock().await;
            let tick_rate = *TICKS_PER_SECOND;

            // CPU time - compute delta from previous reading
            match stat.utime.checked_add(stat.stime) {
                Some(total_ticks) => {
                    let delta_ticks = total_ticks.saturating_sub(prev.cpu_ticks);
                    prev.cpu_ticks = total_ticks;
                    let delta_seconds = delta_ticks as f64 / tick_rate;
                    metrics::record_process_cpu_time(delta_seconds);
                }
                None => warn!("CPU time calculation overflowed"),
            };

            // Gauges - these are point-in-time values, no delta needed
            let rss = stat.rss_bytes().get() as f64;
            metrics::record_process_memory_usage(rss);

            if let Some(count) = process.fd_count().ok().and_then(|c| i64::try_from(c).ok()) {
                metrics::record_process_open_fd_count(count);
            }
            metrics::record_process_thread_count(stat.num_threads as i64);

            // Disk I/O - compute deltas from previous reading
            if let Ok(io) = process.io() {
                let delta_read_bytes = io.read_bytes.saturating_sub(prev.disk_read_bytes);
                let delta_write_bytes = io.write_bytes.saturating_sub(prev.disk_write_bytes);
                let delta_read_syscalls = io.syscr.saturating_sub(prev.disk_read_syscalls);
                let delta_write_syscalls = io.syscw.saturating_sub(prev.disk_write_syscalls);

                prev.disk_read_bytes = io.read_bytes;
                prev.disk_write_bytes = io.write_bytes;
                prev.disk_read_syscalls = io.syscr;
                prev.disk_write_syscalls = io.syscw;

                metrics::record_process_disk_io(delta_read_bytes, "read");
                metrics::record_process_disk_io(delta_write_bytes, "write");
                metrics::record_process_disk_syscalls(delta_read_syscalls, "read");
                metrics::record_process_disk_syscalls(delta_write_syscalls, "write");
            }

            // TCP connections - gauge, no delta needed
            if let Ok(net) = process.tcp() {
                let established_count =
                    net.iter().filter(|connection| connection.state == TcpState::Established).count() as i64;
                metrics::record_network_connections(established_count);
            }
        }
    }
}
