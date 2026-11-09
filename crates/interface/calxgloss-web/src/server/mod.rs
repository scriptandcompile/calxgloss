//! Axum API server for the review dashboard.
//!
//! This module is only compiled when the `server` feature is enabled.

mod actions;
mod events;
mod handlers;
mod lifecycle;
mod llm_io_log;
mod metrics;
mod routes;
mod types;
mod unknown_actions;

pub use self::actions::*;
pub use self::handlers::*;
pub use self::lifecycle::{LifecycleError, LogLevel, LogLevelControl};
pub use self::llm_io_log::{LlmIoEntry, LlmIoEntryType, LlmIoLog, MAX_LLM_IO_ENTRIES};
pub use self::routes::*;
pub use self::types::*;
pub use self::unknown_actions::*;
pub use events::{EventsBridge, SessionManager, UnitPhaseMessage, WebSocketHandler, WsMessage};

use axum::{Router, extract::FromRef};
use calxgloss_reports::dashboard::DashboardBuilder;
use calxgloss_types::{
    BinaryActivity, BinaryIdentity, ClassificationOverrideControl, OverrideControl, PhaseRecord,
    PipelineControl, ProgressEvent, ReviewDashboard, RunRequestSignal, ScopeControl, StopSignal,
    TranslationPhase, UnitCancellation, UnitKey,
};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::info;

/// Shared state for the API server.
#[derive(Clone)]
pub struct ServerState {
    repo_path: PathBuf,
    /// When the server state was created — the reference point for uptime.
    started_at: std::time::Instant,
    /// Active tracing log level, reported by `/api/server/status` and
    /// updated by `PATCH /api/server/log-level` (process-lifetime only).
    log_level: Arc<std::sync::RwLock<String>>,
    /// Reload handle for the process's tracing `EnvFilter` — `None` when
    /// the server was built without the CLI's logging init (e.g. tests),
    /// in which case a level change only updates the reported value.
    log_filter: Option<LogLevelControl>,
    /// Host name of the machine, resolved once at startup.
    host: String,
    /// Cross-platform process metrics (memory/CPU/open file handles).
    metrics: Arc<metrics::ProcessMetrics>,
    /// Shared stop signal — the live pipeline observes it at unit
    /// boundaries when the shutdown/restart endpoints fire.
    stop_signal: StopSignal,
    /// The live run's [`PipelineControl`] state machine — `None` on plain
    /// `serve` routers, which have no pipeline to control. The lifecycle
    /// control endpoints (issue #90) drive pause/resume/stop through it,
    /// and `/api/server/status` derives the reported pipeline status from
    /// it when attached.
    pipeline_control: Option<PipelineControl>,
    /// The live run's [`UnitCancellation`] handle (issue #91, W2.2) —
    /// `None` on plain `serve` routers, which have no unit in flight to
    /// cancel. The cancel-current endpoint cancels whatever unit the
    /// pipeline registered on it.
    unit_cancellation: Option<UnitCancellation>,
    /// The start/restart request channel (issue #92, W2.3) — `None` on
    /// plain `serve` routers, which have no live loop to receive a run
    /// request. The start/restart endpoints store the request here for
    /// the `calxgloss live` loop to pick up and re-run the pipeline.
    run_requests: Option<RunRequestSignal>,
    /// The live run's [`ScopeControl`] handle (issue #93, W2.5) — `None`
    /// on plain `serve` routers, which have no pipeline to steer. The
    /// scope endpoints read and mutate the operator's translation scope
    /// and constraints through it.
    scope_control: Option<ScopeControl>,
    /// The live run's [`OverrideControl`] handle (issue #96, W2.7) — `None`
    /// on plain `serve` routers, which have no pipeline to steer. The unit
    /// override endpoints read and mutate per-unit reviewer overrides
    /// through it.
    override_control: Option<OverrideControl>,
    /// The live run's [`ClassificationOverrideControl`] handle (issue #97,
    /// W2.8) — `None` on plain `serve` routers, which have no run whose
    /// classifications to correct. The binary classification endpoints read
    /// and mutate the operator's classification overrides through it, and
    /// the analyzer consults the same handle before strategy dispatch.
    classification_override_control: Option<ClassificationOverrideControl>,
    /// Graceful-shutdown trigger watched by `serve`/`serve_with_listener`.
    shutdown_tx: Arc<tokio::sync::watch::Sender<bool>>,
}

impl ServerState {
    pub fn new(repo_path: PathBuf) -> Self {
        Self {
            repo_path,
            started_at: std::time::Instant::now(),
            // Default matches what the CLI's `init_logging` installs with no
            // verbosity flags; the CLI always overrides via `with_log_level`
            // so this reports the level that is actually active.
            log_level: Arc::new(std::sync::RwLock::new("warn".to_string())),
            log_filter: None,
            host: metrics::host_name(),
            metrics: Arc::new(metrics::ProcessMetrics::for_current_process()),
            stop_signal: StopSignal::new(),
            pipeline_control: None,
            unit_cancellation: None,
            run_requests: None,
            scope_control: None,
            override_control: None,
            classification_override_control: None,
            shutdown_tx: Arc::new(tokio::sync::watch::channel(false).0),
        }
    }
    pub fn repo_path(&self) -> &Path {
        &self.repo_path
    }

    /// Override the log level reported by `/api/server/status` so it matches
    /// the level the CLI's logging init actually installed.
    pub fn with_log_level(mut self, level: impl Into<String>) -> Self {
        self.log_level = Arc::new(std::sync::RwLock::new(level.into()));
        self
    }

    /// Share the reloadable tracing filter installed by the CLI's logging
    /// init, so `PATCH /api/server/log-level` can change the verbosity of
    /// the running process.
    pub fn with_log_filter(mut self, filter: LogLevelControl) -> Self {
        self.log_filter = Some(filter);
        self
    }

    /// Attach the [`StopSignal`] the live pipeline shares with this server,
    /// so the shutdown/restart endpoints can pause the run at a unit
    /// boundary.
    pub fn with_stop_signal(mut self, stop: StopSignal) -> Self {
        self.stop_signal = stop;
        self
    }

    /// Attach the [`PipelineControl`] state machine the live pipeline shares
    /// with this server, so the pause/resume/stop endpoints (issue #90) can
    /// drive the run and `/api/server/status` can report its true state.
    pub fn with_pipeline_control(mut self, control: PipelineControl) -> Self {
        self.pipeline_control = Some(control);
        self
    }

    /// Attach the [`UnitCancellation`] handle the live pipeline shares with
    /// this server, so the cancel-current endpoint (issue #91) can abort
    /// whatever unit is in flight.
    pub fn with_unit_cancellation(mut self, cancellation: UnitCancellation) -> Self {
        self.unit_cancellation = Some(cancellation);
        self
    }

    /// Attach the [`RunRequestSignal`] channel the live pipeline shares with
    /// this server, so the start/restart endpoints (issue #92) can queue the
    /// next run's scope for the `calxgloss live` loop to pick up.
    pub fn with_run_requests(mut self, run_requests: RunRequestSignal) -> Self {
        self.run_requests = Some(run_requests);
        self
    }

    /// Attach the [`ScopeControl`] handle the live pipeline shares with this
    /// server, so the scope endpoints (issue #93) can read and steer the
    /// operator's translation scope and constraints.
    pub fn with_scope_control(mut self, scope: ScopeControl) -> Self {
        self.scope_control = Some(scope);
        self
    }

    /// Attach the [`OverrideControl`] handle the live pipeline shares with
    /// this server, so the unit override endpoints (issue #96) can read and
    /// steer per-unit reviewer overrides.
    pub fn with_override_control(mut self, overrides: OverrideControl) -> Self {
        self.override_control = Some(overrides);
        self
    }

    /// Time elapsed since this state (and therefore the server) was created.
    pub fn uptime(&self) -> std::time::Duration {
        self.started_at.elapsed()
    }

    /// Calxgloss version the server binary was built with.
    pub fn version() -> &'static str {
        env!("CARGO_PKG_VERSION")
    }

    /// Host name of the machine running the server.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// Active tracing log level.
    pub fn log_level(&self) -> String {
        self.log_level
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Validate a level name and apply it to the running process.
    ///
    /// Requires the reloadable filter handle shared in via
    /// [`ServerState::with_log_filter`]; without one the process's verbosity
    /// cannot change, and the endpoint reports 503 rather than pretending.
    /// Nothing persists — the next process start re-reads the CLI verbosity
    /// flags.
    ///
    /// Returns the normalized level name now active.
    pub fn set_log_level(&self, level: &str) -> Result<String, ServerError> {
        let normalized = LogLevel::parse(level).ok_or_else(|| {
            ServerError::bad_request(&format!(
                "invalid log level '{level}'; valid levels: {}",
                LogLevel::names().join(", ")
            ))
        })?;
        let filter = self.log_filter.as_ref().ok_or_else(|| {
            ServerError::unavailable("this server has no reloadable log filter attached")
        })?;
        filter.apply(normalized)?;
        let name = normalized.as_str().to_string();
        *self.log_level.write().unwrap_or_else(|e| e.into_inner()) = name.clone();
        Ok(name)
    }

    /// Clone of the stop signal shared with the live pipeline.
    pub fn stop_signal(&self) -> StopSignal {
        self.stop_signal.clone()
    }

    /// Clone of the pipeline control handle attached via
    /// [`ServerState::with_pipeline_control`] — `None` when this server has
    /// no live pipeline to control.
    pub fn pipeline_control(&self) -> Option<PipelineControl> {
        self.pipeline_control.clone()
    }

    /// Clone of the unit-cancellation handle attached via
    /// [`ServerState::with_unit_cancellation`] — `None` when this server
    /// has no live pipeline whose unit could be cancelled.
    pub fn unit_cancellation(&self) -> Option<UnitCancellation> {
        self.unit_cancellation.clone()
    }

    /// Clone of the run-request channel attached via
    /// [`ServerState::with_run_requests`] — `None` when this server has no
    /// live loop that a start/restart request could wake.
    pub fn run_requests(&self) -> Option<RunRequestSignal> {
        self.run_requests.clone()
    }

    /// Clone of the scope-control handle attached via
    /// [`with_scope_control`](Self::with_scope_control), or `None` when this
    /// router has no scope control (plain `serve`).
    pub fn scope_control(&self) -> Option<ScopeControl> {
        self.scope_control.clone()
    }

    /// Clone of the override-control handle attached via
    /// [`with_override_control`](Self::with_override_control), or `None`
    /// when this router has no override control (plain `serve`).
    pub fn override_control(&self) -> Option<OverrideControl> {
        self.override_control.clone()
    }

    /// Attach the [`ClassificationOverrideControl`] handle the live
    /// analyzer shares with this server, so the binary classification
    /// endpoints (issue #97) can read and correct target classifications.
    pub fn with_classification_override_control(
        mut self,
        overrides: ClassificationOverrideControl,
    ) -> Self {
        self.classification_override_control = Some(overrides);
        self
    }

    /// The classification-override handle attached to this server, if any.
    pub fn classification_override_control(&self) -> Option<ClassificationOverrideControl> {
        self.classification_override_control.clone()
    }

    /// Request graceful shutdown: stop accepting new requests and let
    /// in-flight ones finish.
    pub fn request_shutdown(&self) {
        // The receiver may already be gone (server not started yet) —
        // nothing to do in that case.
        self.shutdown_tx.send_replace(true);
    }

    /// Future that resolves once graceful shutdown has been requested —
    /// pass it to `axum::serve(...).with_graceful_shutdown(...)`.
    pub fn shutdown_signal(&self) -> impl std::future::Future<Output = ()> + Send + 'static {
        let mut rx = self.shutdown_tx.subscribe();
        async move {
            // Resolve when the flag flips to true; if the sender is dropped
            // the server state is gone, so resolve rather than hang.
            while !*rx.borrow_and_update() {
                if rx.changed().await.is_err() {
                    break;
                }
            }
        }
    }
}

/// Combined state for WebSocket support and review actions.
#[derive(Clone)]
pub struct CombinedState {
    pub server: ServerState,
    pub manager: Option<SessionManager>,
    pub bridge: Option<EventsBridge>,
    /// Review action backend — runs accept, send-back, and patch against
    /// Git and the Translator.
    pub actions: Option<ActionsState>,
    /// Live translation progress — tracks units currently being translated.
    pub progress: Option<Arc<RwLock<ProgressState>>>,
}

impl FromRef<CombinedState> for ServerState {
    fn from_ref(c: &CombinedState) -> Self {
        c.server.clone()
    }
}

impl FromRef<CombinedState> for SessionManager {
    fn from_ref(c: &CombinedState) -> Self {
        c.manager.clone().expect("SessionManager not configured")
    }
}

impl FromRef<CombinedState> for EventsBridge {
    fn from_ref(c: &CombinedState) -> Self {
        c.bridge.clone().expect("EventsBridge not configured")
    }
}

impl FromRef<CombinedState> for ActionsState {
    fn from_ref(c: &CombinedState) -> Self {
        c.actions.clone().expect("ActionsState not configured")
    }
}

// ============================================================
// Live Progress State
// ============================================================

/// A single DLL classification result, tracked during live translation.
#[derive(Debug)]
struct ClassificationResult {
    binary: BinaryIdentity,
    category: String,
    classification_strategy: String,
    crate_replacement: Option<String>,
    exported_symbols: usize,
    imported_symbols: usize,
}

/// Batch summary for a DLL after all functions are translated.
#[derive(Debug)]
struct BatchResult {
    binary: BinaryIdentity,
    total_functions: usize,
    success_count: usize,
    failure_count: usize,
    total_attempts: usize,
    total_tokens: usize,
}

/// Tracks translation units currently in progress.
///
/// Created when `handle_live` starts the server with an event channel,
/// updated by processing `ProgressEvent` messages, and served by the
/// `/api/progress` endpoint so the dashboard can merge live status
/// with the git-backed state.
#[derive(Debug, Clone, Default)]
pub struct ProgressState {
    /// Map of unit key (`{binary}/{function}`) → current progress info for a
    /// live translation.
    entries: Arc<RwLock<std::collections::HashMap<String, ProgressEntry>>>,
    /// Classification results keyed by binary identity.
    classifications: Arc<RwLock<std::collections::HashMap<BinaryIdentity, ClassificationResult>>>,
    /// Batch summary results keyed by binary identity.
    batch_summaries: Arc<RwLock<std::collections::HashMap<BinaryIdentity, BatchResult>>>,
    /// The DLL whose batch pass is currently in flight — set by
    /// `BatchStarted`, cleared by that DLL's `BatchSummary`. The live loop
    /// works one binary at a time, so one slot is enough; a new
    /// `BatchStarted` replaces the old value if a pass ended without a
    /// summary (an error path).
    processing: Arc<RwLock<Option<BinaryIdentity>>>,
    /// The run's ordered plan — `QueuePlanned` records the binaries the
    /// live loop will process, in that order. Empty until a plan lands;
    /// a later plan replaces the earlier one.
    queue: Arc<RwLock<Vec<String>>>,
    /// The working pass's latest heartbeat — `(binary, activity)`. Set by
    /// `BatchProgress`, cleared when a new `BatchStarted` replaces the
    /// pass or that DLL's `BatchSummary` lands.
    activity: Arc<RwLock<Option<(BinaryIdentity, BinaryActivity)>>>,
    /// Startup ingestion state (issue #124). The Ghidra preflight events
    /// that used to set it were retired along with the Ghidra analysis
    /// engine (issue #214), so this stays empty and the pipeline view
    /// derives `project_ingestion` from classification counts alone.
    ingestion: Arc<RwLock<IngestionState>>,
    /// The pre-batch evidence scans of the binary whose pass is in flight,
    /// keyed by scan name so the latest event for a name wins
    /// (issue #428). The map holds one binary at a time: the first scan
    /// event for a different binary, or a `BatchStarted` naming one,
    /// clears the previous binary's rows — they no longer describe the
    /// live pass.
    scans: Arc<RwLock<std::collections::BTreeMap<String, ScanRecord>>>,
}

/// One registered evidence scan as the live store currently holds it
/// (issue #428). A running record has `elapsed_secs: None`, and the
/// payload measures its elapsed time from `started_at` at serve time. A
/// finished record keeps the run's wall-clock seconds, and keeps the
/// row's finding count only when the evidence engine reported a single
/// one.
///
/// `error` carries the failure's own words from the completed event: a
/// failed scan is finished with its error set and its finding count left
/// unknown, so a failure never reads as a completed scan with zero
/// findings (issue #429).
#[derive(Debug, Clone)]
pub struct ScanRecord {
    /// The registry row's name.
    pub scan: String,
    /// The binary whose scan pass this record belongs to.
    pub binary: BinaryIdentity,
    /// When the started event landed — the running clock's anchor.
    pub started_at: std::time::Instant,
    /// Whether the completed event has landed.
    pub finished: bool,
    /// The completed event's wall-clock seconds; `None` while running.
    pub elapsed_secs: Option<f64>,
    /// The count the evidence engine reported; `None` means the row
    /// files no single count, never a zero.
    pub findings: Option<usize>,
    /// The completed event's error words; `None` when the scan did not
    /// fail.
    pub error: Option<String>,
}

/// Startup ingestion state (issue #124): whether startup ingestion has
/// begun and which binaries' analysis has landed. Its producers were
/// retired (issue #214), so it stays empty; the pipeline view still
/// derives this phase from classification counts.
#[derive(Debug, Default, Clone)]
pub struct IngestionState {
    pub started: bool,
    pub analyzed: Vec<BinaryIdentity>,
}

#[derive(Debug, Clone)]
pub struct ProgressEntry {
    pub binary: BinaryIdentity,
    pub function: String,
    pub attempt: u32,
    /// Retry strategy the current LLM-call attempt used — Pipeline's word,
    /// never a batch outcome (issue #363). See [`outcome`](Self::outcome).
    pub retry_strategy: String,
    /// The outcome the batch recorded for this finished unit — `"batch_ok"`,
    /// `"batch_failed"` or `"cancelled"`. It is a separate field from the
    /// retry strategy, so the two names never take on each other's meaning.
    pub outcome: Option<String>,
    pub started_at: std::time::Instant,
    /// The pipeline step this unit is currently in, derived from the latest
    /// phase-bearing `ProgressEvent`.
    pub phase: TranslationPhase,
    /// Phases entered, in event order (the first entry is the starting phase).
    /// Re-entering a phase (e.g. `ContextTier` on tier escalation) appends a
    /// new entry, so the retry history stays visible.
    pub phase_history: Vec<PhaseRecord>,
    /// Set once a terminal event (completed / failed / function-completed)
    /// has been observed for this unit.
    pub finished: bool,
    /// Whether the unit's translation ultimately succeeded — `None` until a
    /// terminal event (`TranslationCompleted` / `TranslationFailed` /
    /// `FunctionCompleted`) says so, so an unfinished unit never looks failed.
    pub succeeded: Option<bool>,
    /// Context tier the current attempt runs at — `None` until a
    /// `ContextTierSelected` event records one (re-emitted on tier escalation).
    pub context_tier: Option<String>,
    /// Human-readable tier label from the same event.
    pub tier_label: Option<String>,
    /// Baseline tests that passed in the latest verified attempt — `None` until
    /// a `TranslationAttemptCompleted` reports a run.
    pub baseline_tests_passed: Option<usize>,
    /// Baseline tests for the unit — from `TestsGenerated`, then from the
    /// verified attempt's own count, whichever landed last.
    pub baseline_tests_total: Option<usize>,
    /// Edge-case (verification) tests that passed — `None` until the
    /// behavior-divergence detector runs them.
    pub verification_tests_passed: Option<usize>,
    /// Edge-case (verification) tests the detector ran.
    pub verification_tests_total: Option<usize>,
    /// Whether the latest verified attempt compiled — `None` until an attempt
    /// has been verified.
    pub compiled: Option<bool>,
    pub last_event_at: std::time::Instant,
}

impl ProgressState {
    pub fn new() -> Self {
        Self {
            entries: Arc::new(RwLock::new(std::collections::HashMap::new())),
            classifications: Arc::new(RwLock::new(std::collections::HashMap::new())),
            batch_summaries: Arc::new(RwLock::new(std::collections::HashMap::new())),
            processing: Arc::new(RwLock::new(None)),
            queue: Arc::new(RwLock::new(Vec::new())),
            activity: Arc::new(RwLock::new(None)),
            ingestion: Arc::new(RwLock::new(IngestionState::default())),
            scans: Arc::new(RwLock::new(std::collections::BTreeMap::new())),
        }
    }

    /// Update progress state from a translation progress event.
    pub async fn on_event(&self, event: &ProgressEvent) {
        match event {
            ProgressEvent::TranslationStarted { .. }
            | ProgressEvent::ScanFetchComplete { .. }
            | ProgressEvent::ApiTaggingComplete { .. }
            | ProgressEvent::TestsGenerated { .. }
            | ProgressEvent::ContextTierSelected { .. }
            | ProgressEvent::LlmCallStart { .. }
            | ProgressEvent::LlmCallComplete { .. }
            | ProgressEvent::LlmCallFailed { .. }
            | ProgressEvent::LlmCallInProgress { .. }
            | ProgressEvent::LlmRequest { .. }
            | ProgressEvent::LlmResponse { .. }
            | ProgressEvent::TranslationAttemptCompleted { .. }
            | ProgressEvent::TranslationCompleted { .. }
            | ProgressEvent::TranslationFailed { .. }
            | ProgressEvent::FunctionCompleted { .. }
            | ProgressEvent::HallucinationDetected { .. }
            | ProgressEvent::InfiniteLoopDetected { .. }
            | ProgressEvent::BehaviorDivergenceDetected { .. }
            | ProgressEvent::ResourceExhaustionDetected { .. }
            | ProgressEvent::UnitCancelled { .. } => {
                self.on_translation_event(event).await;
            }
            ProgressEvent::ClassificationComplete {
                binary,
                category,
                classification_strategy,
                crate_replacement,
                exported_symbols,
                imported_symbols,
            } => {
                let mut classifications = self.classifications.write().await;
                classifications.insert(
                    binary.clone(),
                    ClassificationResult {
                        binary: binary.clone(),
                        category: category.clone(),
                        classification_strategy: classification_strategy.clone(),
                        crate_replacement: crate_replacement.clone(),
                        exported_symbols: *exported_symbols,
                        imported_symbols: *imported_symbols,
                    },
                );
            }
            ProgressEvent::BatchStarted { binary } => {
                // The live loop works one binary at a time; the newest
                // started pass is the one in flight. Any heartbeat from the
                // previous pass is stale the moment a new one begins.
                *self.processing.write().await = Some(binary.clone());
                *self.activity.write().await = None;
                // The same rule for the scan panel (issue #428): records
                // belong to the binary whose pass they witnessed. Another
                // pass over the same binary keeps them until that row's
                // next started event replaces the record. A pass for a
                // different binary retires the previous binary's rows.
                let mut scans = self.scans.write().await;
                if scans.values().any(|record| record.binary != *binary) {
                    scans.clear();
                }
            }
            ProgressEvent::QueuePlanned { binaries } => {
                // The plan is the run's intent, replaced wholesale if a
                // later run plans differently.
                *self.queue.write().await = binaries.clone();
            }
            ProgressEvent::BatchProgress {
                binary,
                pass,
                function,
                index,
                total,
            } => {
                // The latest heartbeat wins: it records the live position,
                // not a history log. Position fields that are not known
                // stay `None`.
                let activity = BinaryActivity {
                    pass: pass.clone(),
                    function: (!function.is_empty()).then(|| function.clone()),
                    index: (*index > 0).then_some(*index),
                    total: (*total > 0).then_some(*total),
                };
                *self.activity.write().await = Some((binary.clone(), activity));
            }
            ProgressEvent::BatchSummary {
                binary,
                total_functions,
                success_count,
                failure_count,
                total_attempts,
                total_tokens,
            } => {
                let mut batch_summaries = self.batch_summaries.write().await;
                batch_summaries.insert(
                    binary.clone(),
                    BatchResult {
                        binary: binary.clone(),
                        total_functions: *total_functions,
                        success_count: *success_count,
                        failure_count: *failure_count,
                        total_attempts: *total_attempts,
                        total_tokens: *total_tokens,
                    },
                );
                // The pass in flight is done — no binary is being worked on.
                let mut processing = self.processing.write().await;
                if processing.as_deref() == Some(binary.as_str()) {
                    *processing = None;
                }
                let mut activity = self.activity.write().await;
                if activity.as_ref().is_some_and(|(d, _)| d == binary) {
                    *activity = None;
                }
            }
            ProgressEvent::EvidenceScanStarted { binary, scan } => {
                // The scan traffic itself also marks the pass boundary:
                // the live pipeline emits no `BatchStarted`, so the first
                // scan event naming a new binary retires the previous
                // binary's rows (issue #428).
                let mut scans = self.scans.write().await;
                if scans.values().any(|record| record.binary != *binary) {
                    scans.clear();
                }
                // A re-run pass over the same binary replaces the row's
                // old record the moment its new pass starts.
                scans.insert(
                    scan.clone(),
                    ScanRecord {
                        scan: scan.clone(),
                        binary: binary.clone(),
                        started_at: std::time::Instant::now(),
                        finished: false,
                        elapsed_secs: None,
                        findings: None,
                        error: None,
                    },
                );
            }
            ProgressEvent::EvidenceScanCompleted {
                binary,
                scan,
                elapsed_secs,
                findings,
                error,
            } => {
                let mut scans = self.scans.write().await;
                if scans.values().any(|record| record.binary != *binary) {
                    scans.clear();
                }
                // The phase emits the started event before this one, so a
                // running record is normally already here. A completed
                // with no running record for the current binary is a
                // dropped event, and an incomplete story stays out of the
                // panel rather than inventing one row.
                if let Some(record) = scans.get_mut(scan)
                    && record.binary == *binary
                {
                    record.finished = true;
                    record.elapsed_secs = Some(*elapsed_secs);
                    record.findings = *findings;
                    // The completed event's error words mark the row
                    // failed, its finding count left unknown — the panel
                    // must never read the missing count as zero
                    // (issue #429).
                    record.error = error.clone();
                }
            }
            ProgressEvent::PipelineStateChanged { .. } => {
                // Run-level lifecycle change (issue #90). ProgressState
                // tracks per-unit and per-binary state, not the run's own
                // state — the control handle is the source of truth, read
                // by `/api/server/status` and echoed to WS clients by the
                // broadcast. There is nothing to add to the per-unit view.
            }
            ProgressEvent::BinaryPauseChanged { .. } => {
                // Per-binary pause (issue #221). ProgressState does not
                // mirror the paused set — the scope handle is the source of
                // truth, and `GET /api/pipeline` fills each row's `paused`
                // flag from it. WS clients get the raw event from the
                // broadcast and re-render the row. There is nothing to add
                // here.
            }
        }
    }

    /// Handle translation-specific events (updates entries HashMap).
    async fn on_translation_event(&self, event: &ProgressEvent) {
        let mut entries = self.entries.write().await;

        // Unit-scoped events include the binary/function pair that identifies
        // the unit; batch-level events (ClassificationComplete, BatchSummary)
        // are handled in `on_event` and never reach here.
        let Some(unit) = event.unit_key() else {
            return;
        };
        let key = unit.to_string();

        // The unit's record begins with the first event that identifies it.
        // That is normally `TranslationStarted`, but the event callback
        // spawns one task per event and they race for the write lock, so any
        // unit-scoped event may legitimately arrive first. Dropping that
        // first event (as `get_mut` did) loses real evidence, so create the
        // record instead. `TranslationStarted` then finds the record already
        // there and never overwrites it.
        let entry = entries.entry(key).or_insert_with(|| {
            // A started unit begins in the phase its first event derives.
            // `TranslationStarted` always derives ScanFetch (unit-tested);
            // fall back to it rather than panic if that ever changes.
            let phase = TranslationPhase::from_event(event).unwrap_or(TranslationPhase::ScanFetch);
            ProgressEntry {
                binary: unit.binary().clone(),
                function: unit.function().to_string(),
                attempt: 1,
                retry_strategy: String::new(),
                outcome: None,
                started_at: std::time::Instant::now(),
                phase,
                phase_history: vec![PhaseRecord {
                    phase,
                    elapsed_secs: 0.0,
                }],
                finished: false,
                succeeded: None,
                context_tier: None,
                tier_label: None,
                baseline_tests_passed: None,
                baseline_tests_total: None,
                verification_tests_passed: None,
                verification_tests_total: None,
                compiled: None,
                last_event_at: std::time::Instant::now(),
            }
        });

        {
            entry.last_event_at = std::time::Instant::now();

            // Record the phase the event moves the unit into; re-entering the
            // same phase (e.g. a second LLM call without tier escalation) is
            // not a transition, but a re-derived *different* phase (e.g.
            // ContextTier on tier escalation) appends to the history.
            if let Some(phase) = TranslationPhase::from_event(event) {
                if phase != entry.phase {
                    entry.phase_history.push(PhaseRecord {
                        phase,
                        elapsed_secs: entry.started_at.elapsed().as_secs_f64(),
                    });
                }
                entry.phase = phase;
            }

            match event {
                ProgressEvent::LlmCallStart {
                    attempt,
                    retry_strategy,
                    ..
                } => {
                    entry.attempt = *attempt;
                    entry.retry_strategy = retry_strategy.clone();
                }
                // The tier the current attempt runs at; re-emitted on tier
                // escalation, so the latest one wins.
                ProgressEvent::ContextTierSelected {
                    tier, tier_label, ..
                } => {
                    entry.context_tier = Some(tier.clone());
                    entry.tier_label = Some(tier_label.clone());
                }
                // Baseline tests exist once they are generated; the verified
                // attempt then reports how many of them passed.
                ProgressEvent::TestsGenerated { test_count, .. } => {
                    entry.baseline_tests_total = Some(*test_count);
                }
                ProgressEvent::TranslationAttemptCompleted {
                    compiled,
                    tests_passed,
                    tests_total,
                    ..
                } => {
                    entry.compiled = Some(*compiled);
                    entry.baseline_tests_passed = Some(*tests_passed);
                    entry.baseline_tests_total = Some(*tests_total);
                }
                // The behavior-divergence detector re-runs the baseline plus
                // generated edge-case tests; its counts are the only live
                // source for the verification class.
                ProgressEvent::BehaviorDivergenceDetected {
                    baseline_passed,
                    baseline_total,
                    edge_tests_passed,
                    edge_tests_total,
                    ..
                } => {
                    entry.baseline_tests_passed = Some(*baseline_passed);
                    entry.baseline_tests_total = Some(*baseline_total);
                    entry.verification_tests_passed = Some(*edge_tests_passed);
                    entry.verification_tests_total = Some(*edge_tests_total);
                }
                ProgressEvent::TranslationCompleted { .. } => {
                    entry.finished = true;
                    entry.succeeded = Some(true);
                }
                ProgressEvent::TranslationFailed { .. } => {
                    entry.finished = true;
                    entry.succeeded = Some(false);
                }
                ProgressEvent::FunctionCompleted { success, .. } => {
                    // Batch-level completion marks the unit as done. The
                    // outcome field records the result for the dashboard,
                    // while retry_strategy still records the last attempt
                    // that ran (issue #363).
                    entry.finished = true;
                    entry.succeeded = Some(*success);
                    entry.outcome = Some(if *success {
                        "batch_ok".to_string()
                    } else {
                        "batch_failed".to_string()
                    });
                }
                ProgressEvent::UnitCancelled { .. } => {
                    // The operator cancelled the in-flight unit (issue #91):
                    // terminal and failed like any other unfinished attempt,
                    // but the outcome field records why — the dashboard can
                    // tell a cancelled unit from one that simply failed.
                    entry.finished = true;
                    entry.succeeded = Some(false);
                    entry.outcome = Some("cancelled".to_string());
                }
                _ => {}
            }
        }
    }

    /// Returns a snapshot of all progress entries.
    pub async fn snapshot(&self) -> std::collections::HashMap<String, ProgressEntry> {
        self.entries.read().await.clone()
    }

    /// The current record for one unit, keyed by binary and function name.
    pub async fn entry(&self, binary: &str, function: &str) -> Option<ProgressEntry> {
        let key = UnitKey::new(&BinaryIdentity::from(binary), function).to_string();
        self.entries.read().await.get(&key).cloned()
    }

    /// The scan records of the binary whose pass is in flight, in scan-name
    /// order — the live view's stable row order (issue #428).
    pub async fn scan_snapshot(&self) -> Vec<ScanRecord> {
        self.scans.read().await.values().cloned().collect()
    }

    /// Returns a snapshot of classification results as serializable info.
    pub async fn classifications(&self) -> Vec<super::ClassificationInfo> {
        let map = self.classifications.read().await;
        map.values()
            .map(|v| super::ClassificationInfo {
                binary: v.binary.clone(),
                category: v.category.clone(),
                classification_strategy: v.classification_strategy.clone(),
                crate_replacement: v.crate_replacement.clone(),
                exported_symbols: v.exported_symbols,
                imported_symbols: v.imported_symbols,
            })
            .collect()
    }

    /// Returns a snapshot of batch summary results as serializable info.
    pub async fn batch_summaries(&self) -> Vec<super::BatchInfo> {
        let map = self.batch_summaries.read().await;
        map.values()
            .map(|v| super::BatchInfo {
                binary: v.binary.clone(),
                total_functions: v.total_functions,
                success_count: v.success_count,
                failure_count: v.failure_count,
                total_attempts: v.total_attempts,
                total_tokens: v.total_tokens,
            })
            .collect()
    }

    /// The binary whose batch pass is currently in flight, if any —
    /// `BatchStarted` records it, and that binary's `BatchSummary` clears it.
    pub async fn processing_binary(&self) -> Option<BinaryIdentity> {
        self.processing.read().await.clone()
    }

    /// The run's ordered queue plan — the binaries the live loop will
    /// process, in that order. Empty when no plan has been announced.
    pub async fn queue(&self) -> Vec<String> {
        self.queue.read().await.clone()
    }

    /// The working pass's latest heartbeat — `(binary, activity)`, `None`
    /// while no pass is running to report one.
    pub async fn activity(&self) -> Option<(BinaryIdentity, BinaryActivity)> {
        self.activity.read().await.clone()
    }

    /// Startup ingestion state (issue #124) — whether the startup preflight
    /// scan has begun, and which binaries' auto-analysis has landed.
    pub async fn ingestion(&self) -> IngestionState {
        self.ingestion.read().await.clone()
    }

    /// Returns the number of currently in-flight units.
    pub async fn len(&self) -> usize {
        self.entries.read().await.len()
    }

    /// Returns the number of units still in flight (not yet finished).
    ///
    /// Finished units stay in the map for the dashboard's benefit, so the
    /// server status endpoint counts only the unfinished ones.
    pub async fn in_flight_count(&self) -> usize {
        self.entries
            .read()
            .await
            .values()
            .filter(|entry| !entry.finished)
            .count()
    }

    /// Returns whether there are any currently in-flight units.
    pub async fn is_empty(&self) -> bool {
        self.entries.read().await.is_empty()
    }
}

/// Builds a [`ReviewDashboard`] from the state of a Git repository.
pub fn build_dashboard(repo_path: &Path) -> Result<ReviewDashboard, anyhow::Error> {
    let git = calxgloss_git::GitManager::open(repo_path)?;
    let builder = DashboardBuilder::new(&git);
    let dashboard = builder.build()?;
    Ok(dashboard)
}

/// Start the review UI API server on the given address, with the
/// settings-backed review-actions backend built into the router (issue
/// #327): accept, send-back, and patch all run for real. Each patch retry
/// is assembled per request from the backend's pass description.
///
/// If `ready` is provided, its sender is notified (with the local address)
/// immediately after the TCP listener is bound, before any requests are
/// accepted.  Callers can use this to wait until the server is reachable
/// before proceeding.
///
/// **Note:** `ready_tx` is consumed even on bind failure so that the caller
/// never has to handle a `RecvError`.  The error is sent through the channel
/// instead.
pub async fn serve(
    state: ServerState,
    actions: ActionsState,
    port: u16,
    ready: Option<
        tokio::sync::oneshot::Sender<std::result::Result<std::net::SocketAddr, anyhow::Error>>,
    >,
) -> Result<(), anyhow::Error> {
    let listener = match tokio::net::TcpListener::bind(format!("0.0.0.0:{port}")).await {
        Ok(l) => l,
        Err(e) => {
            let io_err = std::io::Error::new(e.kind(), e.to_string());
            let err: anyhow::Error = io_err.into();
            if let Some(tx) = ready {
                let _ = tx.send(Err(e.into()));
            }
            return Err(err);
        }
    };
    let local_addr = listener.local_addr()?;
    info!("API server listening on {local_addr}");

    // Signal readiness **after** the socket is bound and listening.
    if let Some(tx) = ready {
        let _ = tx.send(Ok(local_addr));
    }

    // `POST /api/server/shutdown` (and `/restart`) flip the state's shutdown
    // flag; axum then stops accepting new connections and lets in-flight
    // requests finish before `serve` returns.
    let shutdown = state.shutdown_signal();
    axum::serve(listener, build_router_with_actions(state, actions))
        .with_graceful_shutdown(shutdown)
        .await?;
    Ok(())
}

/// Start the API server using a pre-bound TCP listener and a pre-built
/// router.
///
/// Used internally by `handle_live` to bind outside of `serve()` so that
/// bind failures can be reported through the ready channel. The caller
/// builds the router (with or without WebSocket support) before passing it in.
///
/// `shutdown` resolves when a graceful shutdown should begin — pass
/// [`ServerState::shutdown_signal`] so the shutdown/restart endpoints work.
pub async fn serve_with_listener(
    listener: tokio::net::TcpListener,
    router: Router,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> Result<(), anyhow::Error> {
    axum::serve(listener, router)
        .with_graceful_shutdown(shutdown)
        .await?;
    Ok(())
}
