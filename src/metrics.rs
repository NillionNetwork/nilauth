//! Collector for process metrics.

use metrics::{counter, gauge};
use procfs::{net::TcpState, process::Process, WithCurrentSystemInfo};
use std::{sync::LazyLock, time::Duration};
use tokio::time::sleep;
use tracing::warn;

static TICKS_PER_SECOND: LazyLock<f64> = LazyLock::new(|| procfs::ticks_per_second() as f64);
const COLLECT_INTERVAL: Duration = Duration::from_secs(30);

/// Metrics about the node process.
pub struct ProcessMetricsCollector;

impl ProcessMetricsCollector {
    /// Run the process metrics collector.
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
            let operation_values = [
                ("read", io.read_bytes, io.syscr),
                ("write", io.write_bytes, io.syscw),
            ];
            for (operation, bytes, syscalls) in operation_values {
                // See notes on gauge vs counter semantics needed for CPU time.
                counter!("storage_io_bytes_total", "operation" => operation).absolute(bytes);
                counter!("storage_io_syscalls_total", "operation" => operation).absolute(syscalls);
            }
        }

        if let Ok(net) = metrics.tcp() {
            let established_count = net
                .iter()
                .filter(|connection| connection.state == TcpState::Established)
                .count() as f64;
            gauge!("established_tcp_connections").set(established_count);
        }
    }
}
