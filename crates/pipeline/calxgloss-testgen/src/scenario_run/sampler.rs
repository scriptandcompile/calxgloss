//! The scenario run's process-tree sampling seam (P24.4, issue #405):
//! the process samples for a standing run. On Linux hosts each sweep
//! reads the host's process table. Every Wine guest process is
//! recognizable by its `exe` being Wine's preloader — Wine's own loader,
//! not the guest image — which says guest, not host noise. The prefix
//! stamps itself into every guest's inherited environment (`observe_run`
//! always exports the runner's prefix), and that stamp scopes the
//! samples to the run's own prefix even though unix orphan re-parenting
//! scrambles any ancestry a walk could follow; the launch-time birth
//! anchor then keeps prefix services and earlier runs' guests out of
//! this run's samples. Sampling a moving tree is inherently racy: a
//! sample records the processes visible when the sweep reached them,
//! and a pid that dies between the table read and its stat line is
//! simply absent.
//!
//! When the birth anchor itself is unavailable — `/proc/uptime`
//! unreadable — every sweep is skipped: a run that cannot anchor must
//! not claim the whole machine's uptime as its own tree, so the launch
//! sample stands alone and the dimension states only what it really
//! saw.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::Duration;

use calxgloss_types::ProcessSample;

/// The sampling cadence: often enough to catch a child that lives across
/// a scenario window's beat, cheap enough to ride the output-polling
/// loop.
const SAMPLE_CADENCE: Duration = Duration::from_millis(250);

/// One run's sampling state: what prefix to scope to, when processes
/// count as born to this run, which pids already have a sample, and when
/// the next sweep is due.
pub(super) struct Sampler {
    prefix: PathBuf,
    /// The uptime in clock ticks at construction — the same
    /// ticks-since-boot unit every process's stat line stamps its birth
    /// in. `None` when `/proc/uptime` could not be read, which keeps
    /// every sweep silent.
    anchor: Option<u64>,
    seen: BTreeSet<u32>,
    next_at: Duration,
}

impl Sampler {
    pub(super) fn new(prefix: &Path) -> Self {
        Self {
            prefix: prefix.to_path_buf(),
            anchor: uptime_ticks(),
            seen: BTreeSet::new(),
            next_at: Duration::ZERO,
        }
    }

    /// Sweep when the cadence has come round; the only work the run's
    /// event loop does for the process dimension.
    pub(super) fn sweep(&mut self, elapsed: Duration, samples: &mut Vec<ProcessSample>) {
        if elapsed < self.next_at {
            return;
        }
        self.next_at = elapsed + SAMPLE_CADENCE;
        self.collect(samples);
    }

    /// The sweep after the close, past the cadence: a child born while
    /// the windows ruled is sampled even if the beat had not come round.
    pub(super) fn final_sweep(&mut self, samples: &mut Vec<ProcessSample>) {
        self.collect(samples);
    }

    fn collect(&mut self, samples: &mut Vec<ProcessSample>) {
        let Some(anchor) = self.anchor else {
            return;
        };
        let wanted = format!("WINEPREFIX={}", self.prefix.display());
        let Ok(procs) = std::fs::read_dir("/proc") else {
            return;
        };
        let mut found = Vec::new();
        for entry in procs.flatten() {
            let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
                continue;
            };
            if self.seen.contains(&pid) {
                continue;
            }
            let Some(started) = process_start_ticks(pid) else {
                continue;
            };
            if started < anchor {
                continue;
            }
            let Ok(exe) = std::fs::read_link(format!("/proc/{pid}/exe")) else {
                continue;
            };
            let exe_name = exe
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_default();
            if exe_name != "wine-preloader" && exe_name != "wine64-preloader" {
                continue;
            }
            let Ok(environ) = std::fs::read(format!("/proc/{pid}/environ")) else {
                continue;
            };
            if !environ
                .split(|byte| *byte == 0)
                .any(|pair| pair == wanted.as_bytes())
            {
                continue;
            }
            self.seen.insert(pid);
            found.push(ProcessSample {
                pid,
                name: guest_image_name(pid),
            });
        }
        // New samples land in pid order: deterministic, diff-friendly
        // output the compare lane can pair across captures.
        found.sort_by_key(|sample| sample.pid);
        samples.extend(found);
    }
}

/// The uptime in clock ticks at reading.
fn uptime_ticks() -> Option<u64> {
    let uptime = std::fs::read_to_string("/proc/uptime").ok()?;
    let seconds = uptime.split_whitespace().next()?.parse::<f64>().ok()?;
    Some((seconds * 100.0) as u64)
}

/// The process's birth in ticks-since-boot: field 22 of
/// `/proc/<pid>/stat`. The comm field can hold spaces and parentheses,
/// so the parse starts after its closing bracket, where field 22 is the
/// 20th token.
fn process_start_ticks(pid: u32) -> Option<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let after_comm = stat.rsplit(')').next()?;
    after_comm
        .split_whitespace()
        .nth(19)
        .and_then(|ticks| ticks.parse().ok())
}

/// The guest image a process runs. Wine's argv[0] carries it — a guest
/// path like `Z:\...\x.exe` or a bare name — while `comm` truncates at
/// 15 characters, so the name comes from the command line, with `comm`
/// the fallback for the process whose command line reads empty.
fn guest_image_name(pid: u32) -> String {
    if let Ok(cmdline) = std::fs::read(format!("/proc/{pid}/cmdline")) {
        let argv0 = cmdline.split(|byte| *byte == 0).next().unwrap_or(&[]);
        let argv0 = String::from_utf8_lossy(argv0);
        let image = argv0.rsplit(['/', '\\']).next().unwrap_or(&argv0);
        if !image.is_empty() {
            return image.to_string();
        }
    }
    std::fs::read_to_string(format!("/proc/{pid}/comm"))
        .map(|name| name.trim_end().to_string())
        .unwrap_or_default()
}
