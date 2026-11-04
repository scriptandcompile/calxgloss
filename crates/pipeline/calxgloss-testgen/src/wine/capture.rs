//! The capture run: scaffold an instrumented run dir, launch the
//! operator's reference application under Wine against the recording
//! proxy, and stop it under **capture budgets** (P23.6, issue #400).
//!
//! The whole mining step is one command at the CLI; the machinery here is
//! the run half of it. The run dir is the instrumented layout the
//! reference application resolves the target through: the real module
//! parked under [`px_real_name`], the proxy wearing the target's binary
//! identity in front of it, and — once the run ends — the capture event
//! log beside them.
//!
//! Capture budgets — max events, duration, event-log size — stop a runaway
//! run, and each one states its truncation in the log and the report, the
//! same never-silent rule the *capture event log* already speaks. Stopping
//! the run goes through owned-process discipline ([`OwnedProcess`]): the
//! launched process's identity is bound at launch to an ownership token
//! and rechecked before every signal.
//!
//! The run dir's final state never leaves the application tree running
//! through a recorder: whatever the run did — finished, budget-stopped,
//! or lost to an error — [`finalize_run_dir`] takes the proxy out and
//! puts the real module back under its own identity.

use std::io::BufRead as _;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use serde_json::Value;
use tracing::warn;

use super::ScalarKind;
use super::WineRunner;
use super::owned::{OwnedProcess, Stopped};
use super::parse_entry_event_line;
use super::proxy::{ProxySlot, generate_recording_proxy, px_real_name, px_stderr_notes};
use crate::ffi::{decompiler_type_to_rust, parse_signature};
use crate::pe::{Machine, PeImage};

/// Lay the instrumented run dir: copy the real target into it under its
/// real module name, the name the proxy will resolve through.
///
/// The source is never touched — the run dir holds a copy, and until the
/// proxy is built beside it nothing records: the dir is merely ready to
/// be armed.
pub fn scaffold_run_dir(run_dir: &Path, binary: &str, dll_path: &Path) -> Result<()> {
    std::fs::create_dir_all(run_dir)
        .with_context(|| format!("Failed to create the run directory {}", run_dir.display()))?;
    let real = run_dir.join(px_real_name(binary));
    std::fs::copy(dll_path, &real).with_context(|| {
        format!(
            "Failed to copy the real target {} into the run dir as {}",
            dll_path.display(),
            real.display()
        )
    })?;
    Ok(())
}

/// Take the recording proxy out of the run dir and put the real module
/// back under the target's binary identity.
///
/// This is the AC-4 rule made mechanical: after a finished **or
/// interrupted** capture, the run dir's final state cannot leave the
/// application tree running through a recorder. The call is idempotent —
/// a run dir already standing clean finalizes clean.
pub fn finalize_run_dir(run_dir: &Path, binary: &str) -> Result<()> {
    let proxy = run_dir.join(binary);
    let real = run_dir.join(px_real_name(binary));
    // Only the armed state — proxy at the identity, real copy beside it —
    // gets the identity file removed. Once the identity holds the real
    // module, it is the operator's tree again, not a recorder: a repeat
    // finalize must leave it standing.
    if real.is_file() {
        if proxy.is_file() {
            std::fs::remove_file(&proxy).with_context(|| {
                format!(
                    "Failed to remove the recording proxy at {}",
                    proxy.display()
                )
            })?;
        }
        std::fs::rename(&real, &proxy).with_context(|| {
            format!(
                "Failed to restore the real module {} to {}",
                real.display(),
                proxy.display()
            )
        })?;
    }
    Ok(())
}

/// The event log a capture run leaves in its run dir.
pub const CAPTURE_LOG_NAME: &str = "capture-log.json";

/// Read the Kuna listing's export signatures into the proxy's slot table:
/// an export whose whole parameter vector the recorder can carry — every
/// parameter a register marshallable scalar (floats excluded), at most
/// four of them — gets a recording slot; every other export still gets a
/// forwarding slot, so the proxy exports the target's full name set and
/// every arriving call reaches a real entry either way.
pub fn derive_proxy_slots(exports: &[calxgloss_types::Export], machine: Machine) -> Vec<ProxySlot> {
    exports
        .iter()
        .map(|export| match recorded_kinds(&export.signature, machine) {
            Some(kinds) => ProxySlot::recorded(&export.name, kinds),
            None => ProxySlot::forwarding(&export.name),
        })
        .collect()
}

/// The argument vector a slot could record, or `None` when the signature
/// is missing, unparseable, or carries a parameter outside the vector.
fn recorded_kinds(signature: &str, machine: Machine) -> Option<Vec<super::ScalarKind>> {
    if signature.trim().is_empty() {
        return None;
    }
    let parsed = parse_signature(signature).ok()?;
    let mut kinds = Vec::new();
    for param in &parsed.parameters {
        let rust_type = decompiler_type_to_rust(&param.r#type, &parsed.type_map);
        let kind = ScalarKind::from_rust_type(&rust_type, machine)?;
        if matches!(kind, ScalarKind::F32 | ScalarKind::F64 | ScalarKind::Unit) {
            return None;
        }
        kinds.push(kind);
    }
    if kinds.len() > 4 {
        return None;
    }
    Some(kinds)
}

/// The **capture budgets** that stop a reference-app run: max events,
/// duration, and event-log size. Each is optional; a run without a
/// budget runs until the reference application exits. Whichever budget
/// fires, the run states its truncation in the log — never silently.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CaptureBudgets {
    /// Stop once this many events have been recorded.
    pub max_events: Option<u64>,
    /// Stop once this many seconds have elapsed.
    pub max_duration_secs: Option<u64>,
    /// Stop once the recorded events pass this many bytes, and keep the
    /// written log at or under the budget.
    pub max_log_bytes: Option<u64>,
}

impl CaptureBudgets {
    /// No budgets: the run is bounded only by the application.
    pub fn new() -> Self {
        Self::default()
    }

    /// Cap the run at `count` recorded events.
    pub fn with_max_events(mut self, count: u64) -> Self {
        self.max_events = Some(count);
        self
    }

    /// Cap the run at `secs` of wall time.
    pub fn with_max_duration_secs(mut self, secs: u64) -> Self {
        self.max_duration_secs = Some(secs);
        self
    }

    /// Cap the event log at `bytes`.
    pub fn with_max_log_bytes(mut self, bytes: u64) -> Self {
        self.max_log_bytes = Some(bytes);
        self
    }
}

/// The budget that stopped a run — `None` when the application ended on
/// its own. Each variant states its truncation in the report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BudgetStop {
    /// The event budget cut the run off.
    MaxEvents,
    /// The duration budget cut the run off.
    Duration,
    /// The event-log size budget cut the run off.
    LogSize,
}

impl std::fmt::Display for BudgetStop {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BudgetStop::MaxEvents => f.write_str("event budget"),
            BudgetStop::Duration => f.write_str("duration budget"),
            BudgetStop::LogSize => f.write_str("event-log size budget"),
        }
    }
}

/// What a launched reference-app run left behind: every event the
/// recorder's wire produced, the truncation the budgets state, and the
/// run's own account of its limits.
#[derive(Debug)]
pub struct LaunchedCapture {
    /// Recorded events, in arrival order, already trimmed to any budget.
    pub events: Vec<Value>,
    /// Events the run observed on the wire, kept or dropped alike.
    pub events_seen: usize,
    /// Events that arrived past a budget and were not recorded.
    pub events_dropped: u64,
    /// The budget that stopped the run, when a budget stopped it.
    pub stop: Option<BudgetStop>,
    /// Honest notes the proxy stated on stderr.
    pub proxy_notes: Vec<String>,
    /// A stated note when the application exited on its own with a
    /// failure status — capture still stands, the run names the status.
    pub exit_note: Option<String>,
    /// True when the event stream never closed after the stop: the
    /// dropped count then covers only what the runner managed to read.
    pub stream_unclosed: bool,
}

impl WineRunner {
    /// Run the whole reference-app capture: scaffold the instrumented run
    /// dir, build the recording proxy over the real target, launch the
    /// application under Wine with the run dir on the DLL search path,
    /// stop at the budgets, and leave the run dir holding the real module
    /// under its own identity beside the finished event log.
    ///
    /// The binary's identity is the target's own file name and its machine
    /// is what the PE header states: both are read from the target, so the
    /// proxy can never stand at an identity the application would not
    /// resolve. A generation cannot instrument (not x86-64) fails the run
    /// with its coverage note before the run dir is ever touched — no
    /// proxy exists to leave behind, and no faked event is.
    pub fn capture_reference_app_run(
        &self,
        slots: &[ProxySlot],
        dll_path: &Path,
        app_path: &Path,
        run_dir: &Path,
        budgets: &CaptureBudgets,
    ) -> Result<CaptureRun> {
        self.preflight_wine()?;
        let binary = dll_path
            .file_name()
            .and_then(|name| name.to_str())
            .with_context(|| {
                format!(
                    "the target path {} has no usable file name",
                    dll_path.display()
                )
            })?;
        let machine = PeImage::parse(dll_path)?.machine();
        // Generate before the run dir exists: an admit-defeat target
        // leaves no scaffolding to clean up.
        let generation = generate_recording_proxy(binary, slots, Some(machine))?;
        scaffold_run_dir(run_dir, binary, dll_path)?;
        // Whatever happens from here on, the run dir must not end with a
        // recorder standing over the target.
        let guard = RunDirGuard::new(run_dir, binary);
        self.build_recording_proxy(binary, &generation, machine, run_dir)?;
        let launch = self.launch_reference_app(binary, run_dir, app_path, budgets)?;
        let (log, events_dropped) = self.assemble_capture_log_value(binary, &launch, budgets);
        let log_path = run_dir.join(CAPTURE_LOG_NAME);
        std::fs::write(&log_path, serde_json::to_string_pretty(&log)?.into_bytes())
            .with_context(|| format!("Failed to write the capture log {}", log_path.display()))?;
        guard.finish()?;
        let notes = log
            .get("notes")
            .and_then(Value::as_array)
            .map(|rows| {
                rows.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default();
        Ok(CaptureRun {
            log,
            log_path,
            events_seen: launch.events_seen,
            events_dropped,
            stop: launch.stop,
            notes,
        })
    }

    /// Launch the reference application against an armed run dir under
    /// Wine, harvest the recorder's entry events, and stop the run at
    /// the first budget to fire.
    ///
    /// The launched process is owned from spawn ([`OwnedProcess`]): its
    /// identity is bound to an ownership token at launch and rechecked
    /// before the stop signal. When this returns — success or error — the
    /// run dir holds no proxy: [`finalize_run_dir`] runs on every exit
    /// path, so the application tree can never keep resolving through a
    /// recorder.
    pub fn launch_reference_app(
        &self,
        binary: &str,
        run_dir: &Path,
        app_path: &Path,
        budgets: &CaptureBudgets,
    ) -> Result<LaunchedCapture> {
        // The guard rides the whole launch: a spawn failure or a panicked
        // harvest still ends with the real module restored.
        let guard = RunDirGuard::new(run_dir, binary);
        let app_wine = self.to_wine_path(app_path)?;
        let run_wine = self.to_wine_path(run_dir)?;
        let mut cmd = std::process::Command::new(&self.wine_bin);
        cmd.arg(&app_wine)
            // Wine's own diagnostics would hide the recorder's event lines.
            .env("WINEDEBUG", "-all")
            // The run dir on the DLL search path is what lets the
            // application resolve the target through the proxy's identity.
            .env("WINEPATH", &run_wine)
            .current_dir(app_path.parent().unwrap_or(app_path))
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = cmd
            .spawn()
            .with_context(|| format!("Failed to launch '{}' under Wine", app_path.display()))?;
        let stdout = child
            .stdout
            .take()
            .context("the launched process has no stdout pipe")?;
        let stderr = child
            .stderr
            .take()
            .context("the launched process has no stderr pipe")?;
        let mut owned = OwnedProcess::own(child);

        // Reader threads so the pump can enforce budgets while the
        // application streams: stdout lines carry events, stderr lines
        // carry the proxy's honest refusals.
        enum Pump {
            Out(String),
            Err(String),
        }
        let (tx, rx) = mpsc::channel::<Pump>();
        std::thread::spawn({
            let tx = tx.clone();
            move || {
                for line in std::io::BufReader::new(stdout).lines() {
                    let Ok(line) = line else { break };
                    if tx.send(Pump::Out(line)).is_err() {
                        break;
                    }
                }
            }
        });
        std::thread::spawn({
            let tx = tx.clone();
            move || {
                for line in std::io::BufReader::new(stderr).lines() {
                    let Ok(line) = line else { break };
                    if tx.send(Pump::Err(line)).is_err() {
                        break;
                    }
                }
            }
        });
        drop(tx);

        let started = Instant::now();
        let deadline = budgets
            .max_duration_secs
            .map(|secs| started + Duration::from_secs(secs));
        // After a stop, drain what the pipes still carry for this long,
        // so events that had already been written are counted as dropped
        // rather than vanishing uncounted.
        let mut drain_deadline: Option<Instant> = None;
        let mut events: Vec<Value> = Vec::new();
        let mut stderr_lines: Vec<String> = Vec::new();
        let mut events_seen: usize = 0;
        let mut events_dropped: u64 = 0;
        let mut live_bytes: u64 = 0;
        let mut stop: Option<BudgetStop> = None;
        let mut stream_unclosed = false;

        loop {
            match rx.recv_timeout(Duration::from_millis(50)) {
                Ok(Pump::Out(line)) => {
                    if let Some(event) = parse_entry_event_line(&line) {
                        events_seen += 1;
                        let payload = line.len() as u64;
                        let over_events = budgets
                            .max_events
                            .is_some_and(|max| events.len() as u64 >= max);
                        let over_size = budgets
                            .max_log_bytes
                            .is_some_and(|max| live_bytes + payload > max);
                        if stop.is_some() || over_events || over_size {
                            events_dropped += 1;
                            if stop.is_none() {
                                let reason = if over_events {
                                    BudgetStop::MaxEvents
                                } else {
                                    BudgetStop::LogSize
                                };
                                stop_run(&mut owned, reason);
                                stop = Some(reason);
                                drain_deadline = Some(Instant::now() + Duration::from_secs(2));
                            }
                        } else {
                            events.push(event);
                            live_bytes += payload;
                            if budgets
                                .max_events
                                .is_some_and(|max| events.len() as u64 >= max)
                            {
                                // The budget is spent: stop the run now.
                                // A later natural exit would change
                                // nothing the log records.
                                stop_run(&mut owned, BudgetStop::MaxEvents);
                                stop = Some(BudgetStop::MaxEvents);
                                drain_deadline = Some(Instant::now() + Duration::from_secs(2));
                            }
                        }
                    }
                }
                Ok(Pump::Err(line)) => stderr_lines.push(line),
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    if stop.is_none() && deadline.is_some_and(|deadline| Instant::now() >= deadline)
                    {
                        stop_run(&mut owned, BudgetStop::Duration);
                        stop = Some(BudgetStop::Duration);
                        drain_deadline = Some(Instant::now() + Duration::from_secs(2));
                    }
                }
            }
            if drain_deadline.is_some_and(|drain| Instant::now() >= drain) {
                // The pipes are still open past the grace: a Wine process
                // tree the stop could not close. The count states what
                // was read; the note says the rest is uncounted.
                stream_unclosed = true;
                break;
            }
        }

        // Reap the owned process. If the run ended on its own the wait
        // is instant; a run the budgets stopped already holds a signaled
        // (or token-refused) child. The token recheck inside `stop`
        // stands between this point and any further signal.
        if owned.try_wait().is_ok_and(|waited| waited.is_none())
            && owned.stop() == Stopped::StaleIdentityUntouched
        {
            warn!(
                binary,
                "the launched process stopped answering to its ownership token; \
                 nothing more was signaled"
            );
        }
        let exited = owned
            .wait()
            .context("the launched process never came back from its wait")?;
        let stderr = stderr_lines.join("\n");
        let proxy_notes = px_stderr_notes(&stderr);
        let exit_note = if stop.is_none() && !exited.success() {
            Some(format!(
                "the reference application exited on its own with status {exited}"
            ))
        } else {
            None
        };
        guard.finish()?;
        Ok(LaunchedCapture {
            events,
            events_seen,
            events_dropped,
            stop,
            proxy_notes,
            exit_note,
            stream_unclosed,
        })
    }

    /// Assemble the run's `capture-log-v1` document: proxy refusals and
    /// budget truncations ride as notes, the stated dropped-event count
    /// rides beside the entries, and an event-log size budget trims
    /// trailing entries until the document fits the budget — counting
    /// every trim as a drop, never silently.
    pub fn assemble_capture_log_value(
        &self,
        binary: &str,
        run: &LaunchedCapture,
        budgets: &CaptureBudgets,
    ) -> (Value, u64) {
        let mut notes: Vec<String> = run.proxy_notes.clone();
        if let Some(reason) = run.stop {
            notes.push(match reason {
                BudgetStop::MaxEvents => format!(
                    "capture stopped at its event budget of {} events; {} event(s) dropped",
                    budgets.max_events.unwrap_or(run.events.len() as u64),
                    run.events_dropped
                ),
                BudgetStop::Duration => format!(
                    "capture stopped at its duration budget of {} seconds; {} event(s) dropped",
                    budgets.max_duration_secs.unwrap_or(0),
                    run.events_dropped
                ),
                BudgetStop::LogSize => format!(
                    "capture stopped at its event-log size budget of {} bytes; {} event(s) dropped",
                    budgets.max_log_bytes.unwrap_or(0),
                    run.events_dropped
                ),
            });
        }
        if run.stream_unclosed {
            notes.push(
                "the event stream had not closed when the runner gave up; the dropped count \
                 covers only what the runner read"
                    .to_string(),
            );
        }
        let mut log = self.px_capture_log(binary, &run.events, &notes);
        let mut dropped = run.events_dropped;
        if dropped > 0 {
            log["events_dropped"] = serde_json::json!(dropped);
        }
        // The size budget holds the written document, notes and stated
        // drops included — not just the entries: annotate, measure, trim
        // trailing entries, repeat. Every trim counts as a drop, stated
        // in the very annotation the loop is sizing.
        if let Some(max_bytes) = budgets.max_log_bytes {
            let mut trimmed: u64 = 0;
            loop {
                if trimmed > 0 {
                    let mut annotated = notes.clone();
                    annotated.push(format!(
                        "the event-log size budget of {max_bytes} bytes trimmed {trimmed} \
                         trailing event(s) from the log"
                    ));
                    log["notes"] = Value::Array(annotated.into_iter().map(Value::String).collect());
                    log["events_dropped"] = serde_json::json!(dropped + trimmed);
                }
                let fits =
                    serde_json::to_string(&log).is_ok_and(|text| text.len() as u64 <= max_bytes);
                if fits || !trim_last_entry(&mut log) {
                    break;
                }
                trimmed += 1;
            }
            dropped += trimmed;
        }
        (log, dropped)
    }
}

/// Pop the newest entry off an assembled log, reporting whether any entry
/// was actually removed.
fn trim_last_entry(log: &mut Value) -> bool {
    log.get_mut("entries")
        .and_then(Value::as_array_mut)
        .and_then(|rows| rows.pop().map(|_| ()))
        .is_some()
}

/// What one finished reference-app capture run leaves behind.
#[derive(Debug)]
pub struct CaptureRun {
    /// The assembled `capture-log-v1` document.
    pub log: Value,
    /// Where the log was written inside the run dir.
    pub log_path: PathBuf,
    /// Events the run observed on the wire, kept or dropped alike.
    pub events_seen: usize,
    /// Events left out of the log — budget cuts and size trims, stated.
    pub events_dropped: u64,
    /// The budget that stopped the run, when a budget stopped it.
    pub stop: Option<BudgetStop>,
    /// The notes the log carries: proxy refusals and truncations named.
    pub notes: Vec<String>,
}

/// Stop the owned process once, through the token path: the identity is
/// rechecked inside [`OwnedProcess::stop`] before the signal.
fn stop_run(owned: &mut OwnedProcess, reason: BudgetStop) {
    match owned.stop() {
        Stopped::Signaled => info_stop(owned.token().pid, reason),
        Stopped::AlreadyExited => {
            // The application exited at the very moment the budget fired;
            // the stop still stands and the truncation still states.
        }
        Stopped::StaleIdentityUntouched => warn!(
            pid = owned.token().pid,
            "the budget fired but the PID no longer answers to its ownership \
             token: nothing was signaled"
        ),
    }
}

fn info_stop(pid: u32, reason: BudgetStop) {
    tracing::info!(pid, budget = %reason, "capture run stopped at its budget");
}

/// Finalizes the run dir on every path out of a capture — including an
/// early `?` or a panic — so the run dir can never end with the proxy
/// standing over the target. [`finish`](Self::finish) marks the ordered
/// finalize done; the Drop side is the insurance, and finalize is
/// idempotent, so double-finalizing is honest.
struct RunDirGuard<'a> {
    run_dir: &'a Path,
    binary: &'a str,
    done: bool,
}

impl<'a> RunDirGuard<'a> {
    fn new(run_dir: &'a Path, binary: &'a str) -> Self {
        Self {
            run_dir,
            binary,
            done: false,
        }
    }

    fn finish(mut self) -> Result<()> {
        self.done = true;
        finalize_run_dir(self.run_dir, self.binary)
    }
}

impl Drop for RunDirGuard<'_> {
    fn drop(&mut self) {
        if !self.done
            && let Err(e) = finalize_run_dir(self.run_dir, self.binary)
        {
            warn!(
                run_dir = %self.run_dir.display(),
                error = %e,
                "the interrupted capture could not fully restore its run dir"
            );
        }
    }
}

#[cfg(test)]
mod tests;
