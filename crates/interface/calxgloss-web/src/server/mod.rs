//! Axum API server for the review dashboard.
//!
//! This module is only compiled when the `server` feature is enabled.

mod actions;
mod events;
mod handlers;
mod metrics;
mod types;

pub use self::actions::*;
pub use self::handlers::*;
pub use self::types::*;
pub use events::{EventsBridge, SessionManager, WebSocketHandler};

use axum::{
    Router,
    extract::FromRef,
    extract::{DefaultBodyLimit, WebSocketUpgrade},
    middleware,
    routing::{get, post},
};
use calxgloss_reports::dashboard::DashboardBuilder;
use calxgloss_types::{PhaseRecord, ProgressEvent, ReviewDashboard, TranslationPhase};
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
    /// Active tracing log level, reported by `/api/server/status`.
    log_level: String,
    /// Host name of the machine, resolved once at startup.
    host: String,
    /// Cross-platform process metrics (memory/CPU/open file handles).
    metrics: Arc<metrics::ProcessMetrics>,
}

impl ServerState {
    pub fn new(repo_path: PathBuf) -> Self {
        Self {
            repo_path,
            started_at: std::time::Instant::now(),
            // Default matches what the CLI's `init_logging` installs with no
            // verbosity flags; the CLI always overrides via `with_log_level`
            // so this reports the level that is actually active.
            log_level: "warn".to_string(),
            host: metrics::host_name(),
            metrics: Arc::new(metrics::ProcessMetrics::for_current_process()),
        }
    }
    pub fn repo_path(&self) -> &Path {
        &self.repo_path
    }

    /// Override the log level reported by `/api/server/status` so it matches
    /// the level the CLI's logging init actually installed.
    pub fn with_log_level(mut self, level: impl Into<String>) -> Self {
        self.log_level = level.into();
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
    pub fn log_level(&self) -> &str {
        &self.log_level
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
    dll: String,
    category: String,
    strategy: String,
    crate_replacement: Option<String>,
    exported_symbols: usize,
    imported_symbols: usize,
}

/// Batch summary for a DLL after all functions are translated.
#[derive(Debug)]
struct BatchResult {
    dll: String,
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
    /// Map of "dll/function" → current progress info for a live translation.
    entries: Arc<RwLock<std::collections::HashMap<String, ProgressEntry>>>,
    /// Classification results keyed by DLL name.
    classifications: Arc<RwLock<std::collections::HashMap<String, ClassificationResult>>>,
    /// Batch summary results keyed by DLL name.
    batch_summaries: Arc<RwLock<std::collections::HashMap<String, BatchResult>>>,
}

#[derive(Debug, Clone)]
pub struct ProgressEntry {
    pub dll: String,
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
    pub last_event_at: std::time::Instant,
}

impl ProgressState {
    pub fn new() -> Self {
        Self {
            entries: Arc::new(RwLock::new(std::collections::HashMap::new())),
            classifications: Arc::new(RwLock::new(std::collections::HashMap::new())),
            batch_summaries: Arc::new(RwLock::new(std::collections::HashMap::new())),
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
                dll,
                category,
                strategy,
                crate_replacement,
                exported_symbols,
                imported_symbols,
            } => {
                let mut classifications = self.classifications.write().await;
                classifications.insert(
                    dll.clone(),
                    ClassificationResult {
                        dll: dll.clone(),
                        category: category.clone(),
                        strategy: strategy.clone(),
                        crate_replacement: crate_replacement.clone(),
                        exported_symbols: *exported_symbols,
                        imported_symbols: *imported_symbols,
                    },
                );
            }
            ProgressEvent::BatchSummary {
                dll,
                total_functions,
                success_count,
                failure_count,
                total_attempts,
                total_tokens,
            } => {
                let mut batch_summaries = self.batch_summaries.write().await;
                batch_summaries.insert(
                    dll.clone(),
                    BatchResult {
                        dll: dll.clone(),
                        total_functions: *total_functions,
                        success_count: *success_count,
                        failure_count: *failure_count,
                        total_attempts: *total_attempts,
                        total_tokens: *total_tokens,
                    },
                );
            }
        }
    }

    /// Handle translation-specific events (updates entries HashMap).
    async fn on_translation_event(&self, event: &ProgressEvent) {
        let mut entries = self.entries.write().await;

        // Unit-scoped events carry the dll/function pair identifying the unit;
        // batch-level events (ClassificationComplete, BatchSummary) are handled
        // in `on_event` and never reach here.
        let Some((dll, function)) = event.unit_key() else {
            return;
        };
        let key = format!("{dll}/{function}");

        // A started unit begins in the phase its first event derives.
        if let ProgressEvent::TranslationStarted { dll, function } = event {
            // TranslationStarted always derives GhidraFetch (unit-tested);
            // fall back to it rather than panic if that ever changes.
            let phase =
                TranslationPhase::from_event(event).unwrap_or(TranslationPhase::GhidraFetch);
            entries.insert(
                key,
                ProgressEntry {
                    dll: dll.clone(),
                    function: function.clone(),
                    attempt: 1,
                    strategy: String::new(),
                    started_at: std::time::Instant::now(),
                    phase,
                    phase_history: vec![PhaseRecord {
                        phase,
                        elapsed_secs: 0.0,
                    }],
                    finished: false,
                    last_event_at: std::time::Instant::now(),
                },
            );
            return;
        }

        if let Some(entry) = entries.get_mut(&key) {
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
                ProgressEvent::TranslationCompleted { .. }
                | ProgressEvent::TranslationFailed { .. } => {
                    entry.finished = true;
                }
                ProgressEvent::FunctionCompleted { success, .. } => {
                    // Batch-level completion marks the unit as done; the
                    // strategy field records the outcome for the dashboard.
                    entry.finished = true;
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

    /// Returns a snapshot of classification results as serializable info.
    pub async fn classifications(&self) -> Vec<super::ClassificationInfo> {
        let map = self.classifications.read().await;
        map.values()
            .map(|v| super::ClassificationInfo {
                dll: v.dll.clone(),
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
                dll: v.dll.clone(),
                total_functions: v.total_functions,
                success_count: v.success_count,
                failure_count: v.failure_count,
                total_attempts: v.total_attempts,
                total_tokens: v.total_tokens,
            })
            .collect()
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
/// not be added here; it belongs in [`live_only_routes`].
fn shared_routes() -> Router<CombinedState> {
    Router::new()
        .route("/", get(handlers::serve_index))
        .route("/api/dashboard", get(handlers::api_get_dashboard))
        .route("/api/units/{id}", get(handlers::api_get_unit))
        .route("/api/units/{id}/diff", get(handlers::api_get_unit_diff))
        .route("/api/units/{id}/ghidra", get(handlers::api_get_unit_ghidra))
        .route("/api/units/{id}/accept", post(handlers::api_accept_unit))
        .route(
            "/api/units/{id}/send-back",
            post(handlers::api_send_back_unit),
        )
        .route("/api/units/{id}/patch", post(handlers::api_request_patch))
        .route("/api/queue", get(handlers::api_get_queue))
        .route("/api/queue/next", get(handlers::api_get_next_unit))
        .route("/api/graph", get(handlers::api_get_dependency_graph))
        .route("/api/gc/candidates", get(handlers::api_get_gc_candidates))
        .route("/api/gc/archive", post(handlers::api_archive_gc))
        .route("/health", get(handlers::api_health))
        .route("/api/server/status", get(handlers::api_server_status))
        .fallback_service(axum::routing::get(handlers::static_fallback))
}

/// Routes registered **only** in the live (`calxgloss live`) router — these
/// read live translation state that plain `serve` does not own, so on the
/// other routers they must fall through to the static 404 rather than answer
/// with fabricated empty data. Every W0–W4 endpoint reporting pipeline
/// progress or in-flight status belongs here.
fn live_only_routes() -> Router<CombinedState> {
    Router::new()
        .route("/api/pipeline", get(handlers::api_get_pipeline))
        .route("/api/progress", get(handlers::api_get_progress))
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
    let progress_clone = progress.clone();
    manager.set_event_callback(move |event| {
        // Run the async update on a blocking thread since on_event
        // uses tokio::sync::RwLock (non-blocking).
        let p = progress_clone.clone();
        let evt = event.clone();
        tokio::spawn(async move {
            p.on_event(&evt).await;
        });
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
        let (handler, _sender) = manager.register_client().await;
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

    axum::serve(listener, build_router(state)).await?;
    Ok(())
}

/// Start the API server using a pre-bound TCP listener and a pre-built
/// router.
///
/// Used internally by `handle_live` to bind outside of `serve()` so that
/// bind failures can be reported through the ready channel. The caller
/// builds the router (with or without WebSocket support) before passing it in.
pub async fn serve_with_listener(
    listener: tokio::net::TcpListener,
    router: Router,
) -> Result<(), anyhow::Error> {
    axum::serve(listener, router).await?;
    Ok(())
}
