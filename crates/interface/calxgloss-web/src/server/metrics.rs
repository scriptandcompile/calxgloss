//! Cross-platform process metrics for the server status endpoint.
//!
//! Gathers memory, CPU, and open-file-handle counts for the server process
//! through `sysinfo`'s per-OS backends (procfs on Linux, sysctl/libproc on
//! macOS, API calls on Windows) — never `/proc`-only reads, since the project
//! targets Windows/macOS/Linux.

use std::sync::Mutex;

/// One reading of the server process's resource usage.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct ProcessSample {
    /// Resident set size in megabytes (rounded to one decimal).
    pub memory_mb: f64,
    /// CPU usage as a percentage of one core (can exceed 100 on multicore).
    pub cpu_percent: f64,
    /// Number of open file handles; 0 when the platform cannot report it.
    pub open_file_handles: u64,
}

/// Gathers process metrics for the current process.
///
/// Keeps a persistent [`sysinfo::System`] so CPU usage is computed as a diff
/// between successive samples — the first sample reports 0.0, and each status
/// poll refreshes the reading for the next one (sysinfo requires two
/// refreshes before CPU usage is meaningful).
pub(crate) struct ProcessMetrics {
    pid: sysinfo::Pid,
    system: Mutex<sysinfo::System>,
}

impl ProcessMetrics {
    /// Start tracking the current process.
    pub(crate) fn for_current_process() -> Self {
        Self {
            // Falls back to PID 0 only if the OS refuses to name our own
            // process; samples then degrade to zeros instead of failing.
            pid: sysinfo::get_current_pid().unwrap_or_else(|_| sysinfo::Pid::from(0usize)),
            system: Mutex::new(sysinfo::System::new()),
        }
    }

    /// Refresh and return the current resource reading for this process.
    pub(crate) fn sample(&self) -> ProcessSample {
        let mut system = self
            .system
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        system.refresh_processes_specifics(
            sysinfo::ProcessesToUpdate::Some(&[self.pid]),
            true,
            sysinfo::ProcessRefreshKind::nothing()
                .with_memory()
                .with_cpu(),
        );
        let Some(process) = system.process(self.pid) else {
            return ProcessSample::default();
        };
        ProcessSample {
            memory_mb: (process.memory() as f64 / (1024.0 * 1024.0) * 10.0).round() / 10.0,
            cpu_percent: (f64::from(process.cpu_usage()) * 10.0).round() / 10.0,
            open_file_handles: process.open_files().map(|count| count as u64).unwrap_or(0),
        }
    }
}

/// Host name of the machine running the server, resolved once at startup.
/// Falls back to "unknown" when the OS does not expose one.
pub(crate) fn host_name() -> String {
    sysinfo::System::host_name().unwrap_or_else(|| "unknown".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Sampling the current process must yield plausible cross-platform
    /// readings: positive memory and at least the stdio file handles open.
    #[test]
    fn sample_reports_current_process_metrics() {
        let metrics = ProcessMetrics::for_current_process();
        let sample = metrics.sample();
        assert!(
            sample.memory_mb > 0.0,
            "memory should be non-zero for this process"
        );
        assert!(sample.cpu_percent >= 0.0, "cpu usage is never negative");
        assert!(
            sample.open_file_handles > 0,
            "at least stdin/stdout/stderr are open"
        );
    }

    /// The host name must be a non-empty string on every supported OS.
    #[test]
    fn host_name_is_non_empty() {
        assert!(!host_name().is_empty());
    }
}
