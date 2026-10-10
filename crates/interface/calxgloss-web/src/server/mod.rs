//! Axum API server for the review dashboard.
//!
//! This module is only compiled when the `server` feature is enabled.

mod actions;
mod events;
mod handlers;
mod lifecycle;
mod llm_io_log;
mod metrics;
mod types;

pub use self::actions::*;
pub use self::handlers::*;
pub use self::lifecycle::{LifecycleError, LogLevel, LogLevelControl};
pub use self::llm_io_log::{LlmIoEntry, LlmIoEntryType, LlmIoLog, MAX_LLM_IO_ENTRIES};
pub use self::types::*;
pub use events::{EventsBridge, SessionManager, UnitPhaseMessage, WebSocketHandler, WsMessage};

use axum::{
    Router,
    extract::FromRef,
    extract::{DefaultBodyLimit, WebSocketUpgrade},
    middleware,
    routing::{get, patch, post},
};
use calxgloss_reports::dashboard::DashboardBuilder;
use calxgloss_types::{
    BinaryActivity, BinaryIdentity, PhaseRecord, ProgressEvent, ReviewDashboard, StopSignal,
    TranslationPhase, UnitKey,
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
    /// Review action backend — wires accept/send-back/patch into Git + Translator.
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
    strategy: String,
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
    /// The run's ordered plan — `QueuePlanned` names the binaries the
    /// live loop will process, in that order. Empty until a plan lands;
    /// a later plan replaces the earlier one.
    queue: Arc<RwLock<Vec<String>>>,
    /// The working pass's latest heartbeat — `(binary, activity)`. Set by
    /// `BatchProgress`, cleared when a new `BatchStarted` replaces the
    /// pass or that DLL's `BatchSummary` lands.
    activity: Arc<RwLock<Option<(BinaryIdentity, BinaryActivity)>>>,
}

#[derive(Debug, Clone)]
pub struct ProgressEntry {
    pub binary: BinaryIdentity,
    pub function: String,
    pub attempt: u32,
    pub strategy: String,
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
    /// `ContextTierSelected` event names one (re-emitted on tier escalation).
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
        }
    }

    /// Update progress state from a translation progress event.
    pub async fn on_event(&self, event: &ProgressEvent) {
        match event {
            ProgressEvent::TranslationStarted { .. }
            | ProgressEvent::GhidraFetchComplete { .. }
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
            | ProgressEvent::ResourceExhaustionDetected { .. } => {
                self.on_translation_event(event).await;
            }
            ProgressEvent::ClassificationComplete {
                binary,
                category,
                strategy,
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
                        strategy: strategy.clone(),
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
                // Latest beat wins — the heartbeat is a live position,
                // not a log. Unknown position fields stay `None`.
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
        }
    }

    /// Handle translation-specific events (updates entries HashMap).
    async fn on_translation_event(&self, event: &ProgressEvent) {
        let mut entries = self.entries.write().await;

        // Unit-scoped events carry the binary/function pair identifying the unit;
        // batch-level events (ClassificationComplete, BatchSummary) are handled
        // in `on_event` and never reach here.
        let Some(unit) = event.unit_key() else {
            return;
        };
        let key = unit.to_string();

        // The unit's record begins with the first event that names it. That is
        // normally `TranslationStarted`, but the event callback spawns one task
        // per event and they race for the write lock, so any unit-scoped event
        // may legitimately arrive first — dropping it (as `get_mut` did) loses
        // real evidence, so create the record instead. `TranslationStarted`
        // then finds the record already there and never clobbers it.
        let entry = entries.entry(key).or_insert_with(|| {
            // A started unit begins in the phase its first event derives.
            // `TranslationStarted` always derives GhidraFetch (unit-tested);
            // fall back to it rather than panic if that ever changes.
            let phase =
                TranslationPhase::from_event(event).unwrap_or(TranslationPhase::GhidraFetch);
            ProgressEntry {
                binary: unit.binary().clone(),
                function: unit.function().to_string(),
                attempt: 1,
                strategy: String::new(),
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
                    attempt, strategy, ..
                } => {
                    entry.attempt = *attempt;
                    entry.strategy = strategy.clone();
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
                    // Batch-level completion marks the unit as done; the
                    // strategy field records the outcome for the dashboard.
                    entry.finished = true;
                    entry.succeeded = Some(*success);
                    entry.strategy = if *success {
                        "batch_ok".to_string()
                    } else {
                        "batch_failed".to_string()
                    };
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

    /// Returns a snapshot of classification results as serializable info.
    pub async fn classifications(&self) -> Vec<super::ClassificationInfo> {
        let map = self.classifications.read().await;
        map.values()
            .map(|v| super::ClassificationInfo {
                binary: v.binary.clone(),
                category: v.category.clone(),
                strategy: v.strategy.clone(),
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
    /// `BatchStarted` names it, that binary's `BatchSummary` clears it.
    pub async fn processing_binary(&self) -> Option<BinaryIdentity> {
        self.processing.read().await.clone()
    }

    /// The run's ordered queue plan — the binaries the live loop will
    /// process, in that order. Empty when no plan has been announced.
    pub async fn queue(&self) -> Vec<String> {
        self.queue.read().await.clone()
    }

    /// The working pass's latest heartbeat — `(binary, activity)`, `None`
    /// while no pass is beating.
    pub async fn activity(&self) -> Option<(BinaryIdentity, BinaryActivity)> {
        self.activity.read().await.clone()
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

// ============================================================
// Route table
// ============================================================

/// Routes shared by **every** router — plain `serve`, `serve` with review
/// actions, and `live`. An endpoint that reads live translation state must
/// not be added here unless it degrades to an honest empty payload when no
/// live state is attached; `/api/pipeline` is the one such case (issue #61 —
/// the dashboard phase bar renders in every mode). Endpoints that cannot
/// answer honestly without live state belong in [`live_only_routes`]. Server
/// management (`/api/server/*`) is registered here so it is available in
/// every mode.
fn shared_routes() -> Router<CombinedState> {
    Router::new()
        .route("/", get(handlers::serve_index))
        .route("/api/dashboard", get(handlers::api_get_dashboard))
        .route("/api/pipeline", get(handlers::api_get_pipeline))
        .route("/api/units/{id}", get(handlers::api_get_unit))
        .route("/api/units/{id}/diff", get(handlers::api_get_unit_diff))
        .route("/api/units/{id}/ghidra", get(handlers::api_get_unit_ghidra))
        .route("/api/units/{id}/accept", post(handlers::api_accept_unit))
        .route(
            "/api/units/{id}/send-back",
            post(handlers::api_send_back_unit),
        )
        .route("/api/units/{id}/patch", post(handlers::api_request_patch))
        // Skip state (issue #75): persisted in every mode — it reads/writes
        // `re/review/skips.json`, never live pipeline state.
        .route("/api/units/{id}/skip", post(handlers::api_skip_unit))
        .route("/api/units/{id}/unskip", post(handlers::api_unskip_unit))
        .route("/api/queue", get(handlers::api_get_queue))
        .route("/api/queue/next", get(handlers::api_get_next_unit))
        // Queue overlay (issue #74): persisted manual order + priority,
        // available in every mode — it reads/writes
        // `re/review/queue_overlay.json`, never live pipeline state. The PUT
        // body carries the full manual order, which grows with the queue, so
        // this route lifts the global 16 KB body limit.
        .route(
            "/api/queue/overlay",
            get(handlers::api_get_queue_overlay)
                .put(handlers::api_update_queue_overlay)
                .layer(DefaultBodyLimit::max(256 * 1024)),
        )
        // LLM I/O log (issue #77): persisted in every mode — it reads
        // `re/analysis/llm_io/log.jsonl`, written by the live server as
        // requests/responses happen, never live pipeline state. A workspace
        // that has never run live honestly answers with an empty payload.
        .route("/api/llm-io", get(handlers::api_get_llm_io_log))
        .route("/api/graph", get(handlers::api_get_dependency_graph))
        .route("/api/gc/candidates", get(handlers::api_get_gc_candidates))
        .route("/api/gc/archive", post(handlers::api_archive_gc))
        .route("/health", get(handlers::api_health))
        .route("/api/server/status", get(handlers::api_server_status))
        .route("/api/server/shutdown", post(handlers::api_server_shutdown))
        .route("/api/server/restart", post(handlers::api_server_restart))
        .route(
            "/api/server/log-level",
            patch(handlers::api_server_log_level),
        )
        .fallback_service(axum::routing::get(handlers::static_fallback))
}

/// Routes registered **only** in the live (`calxgloss live`) router — these
/// read live translation state that plain `serve` does not own and cannot
/// report honestly without it, so on the other routers they must fall
/// through to the static 404 rather than answer with fabricated empty data.
/// Every W0–W4 endpoint reporting in-flight status belongs here;
/// `/api/pipeline` moved to [`shared_routes`] because it degrades to an
/// honest empty payload instead.
fn live_only_routes() -> Router<CombinedState> {
    Router::new()
        .route("/api/progress", get(handlers::api_get_progress))
        .route(
            "/api/progress/enhanced",
            get(handlers::api_get_progress_enhanced),
        )
        .route("/api/events/upgrade", get(api_events_upgrade_ws))
}

/// Apply the middleware layers every router shares.
fn with_common_layers(router: Router) -> Router {
    router
        .layer(middleware::from_fn(handlers::trace_middleware))
        .layer(DefaultBodyLimit::max(16 * 1024))
}

/// Assemble a router from the shared route table, wired to the given
/// combined state. The live-only table is registered exactly when the state
/// carries a [`SessionManager`] — the same dependency the live handlers
/// read — so a live route can never be registered on a router that lacks
/// the live state it needs.
fn assemble(state: CombinedState) -> Router {
    let mut routes = shared_routes();
    if state.manager.is_some() {
        routes = routes.merge(live_only_routes());
    }
    with_common_layers(routes.with_state(state))
}

/// Build the axum router for plain `calxgloss serve` — the shared review
/// surface, without the live-pipeline endpoints.
pub fn build_router(state: ServerState) -> Router {
    assemble(CombinedState {
        server: state,
        manager: None,
        bridge: None,
        actions: None,
        progress: None,
    })
}

/// Build the router for `calxgloss serve` with the review-actions backend
/// wired in — still no live-pipeline endpoints.
pub fn build_router_with_actions(state: ServerState, actions: ActionsState) -> Router {
    assemble(CombinedState {
        server: state,
        manager: None,
        bridge: None,
        actions: Some(actions),
        progress: None,
    })
}

/// Build the router for `calxgloss live`: the shared surface plus the
/// live-only pipeline-progress and WebSocket endpoints.
pub fn build_router_with_ws(
    state: ServerState,
    manager: SessionManager,
    progress: ProgressState,
) -> Router {
    // Wire the session manager's callback so that every translation
    // progress event also updates the in-memory ProgressState.
    //
    // Events are handed to one consumer task over a channel rather than
    // spawning a task per event: per-event tasks raced for the state lock
    // and applied events out of order, so a unit's final state depended on
    // task scheduling instead of event order.
    let progress_clone = progress.clone();
    let manager_clone = manager.clone();
    // Server-side LLM I/O log (issue #77): every request/response/error the
    // run emits is appended to `re/analysis/llm_io/log.jsonl` as it happens,
    // so `GET /api/llm-io` can serve the history a page reload would
    // otherwise lose.
    let llm_io_log = LlmIoLog::new(state.repo_path());
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<calxgloss_types::ProgressEvent>();
    tokio::spawn(async move {
        while let Some(event) = rx.recv().await {
            llm_io_log.record(&event);
            progress_clone.on_event(&event).await;
            // WS phase events (issue #55): once a unit-scoped event is
            // applied, push that unit's full live record — current phase,
            // phase history, tier, evidence — so the live view updates the
            // row in place instead of refetching the enhanced endpoint.
            if let Some(unit) = event.unit_key()
                && let Some(entry) = progress_clone
                    .entry(unit.binary().as_str(), unit.function())
                    .await
            {
                let record = handlers::live_unit_progress(&entry);
                manager_clone
                    .push(WsMessage::UnitPhase(UnitPhaseMessage::new(record)))
                    .await;
            }
        }
    });
    manager.set_event_callback(move |event| {
        let _ = tx.send(event.clone());
    });

    assemble(CombinedState {
        server: state,
        manager: Some(manager),
        bridge: None,
        actions: None,
        progress: Some(Arc::new(RwLock::new(progress))),
    })
}

/// WebSocket upgrade handler for live progress events.
async fn api_events_upgrade_ws(
    ws: WebSocketUpgrade,
    axum::extract::State(combined): axum::extract::State<CombinedState>,
) -> axum::response::Response {
    let manager = combined.manager.expect("SessionManager not configured");
    ws.on_upgrade(move |ws| async move {
        let handler = manager.register_client().await;
        handler.process(ws).await;
    })
}

/// Start the API server on the given address.
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
    axum::serve(listener, build_router(state))
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
