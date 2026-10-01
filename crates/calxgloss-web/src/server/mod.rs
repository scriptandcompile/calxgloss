//! Axum API server for the review dashboard.
//!
//! This module is only compiled when the `server` feature is enabled.

mod actions;
mod events;
mod handlers;
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
use calxgloss_types::{ProgressEvent, ReviewDashboard};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::info;

/// Shared state for the API server.
#[derive(Clone)]
pub struct ServerState {
    repo_path: PathBuf,
}

impl ServerState {
    pub fn new(repo_path: PathBuf) -> Self {
        Self { repo_path }
    }
    pub fn repo_path(&self) -> &Path {
        &self.repo_path
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
    pub status: ProgressUnitStatus,
    pub last_event_at: std::time::Instant,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProgressUnitStatus {
    Translating,
    LlmCall,
    Compiling,
    Testing,
    Complete,
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
        use ProgressUnitStatus::*;
        let mut entries = self.entries.write().await;

        match event {
            ProgressEvent::TranslationStarted { dll, function } => {
                let key = format!("{dll}/{function}");
                entries.insert(
                    key,
                    ProgressEntry {
                        dll: dll.clone(),
                        function: function.clone(),
                        attempt: 1,
                        strategy: String::new(),
                        started_at: std::time::Instant::now(),
                        status: Translating,
                        last_event_at: std::time::Instant::now(),
                    },
                );
            }
            ProgressEvent::GhidraFetchComplete { dll, function, .. } => {
                if let Some(entry) = entries.get_mut(&format!("{dll}/{function}")) {
                    entry.status = Translating;
                    entry.last_event_at = std::time::Instant::now();
                }
            }
            ProgressEvent::ApiTaggingComplete { dll, function, .. } => {
                if let Some(entry) = entries.get_mut(&format!("{dll}/{function}")) {
                    entry.status = Translating;
                    entry.last_event_at = std::time::Instant::now();
                }
            }
            ProgressEvent::TestsGenerated { dll, function, .. } => {
                if let Some(entry) = entries.get_mut(&format!("{dll}/{function}")) {
                    entry.status = Translating;
                    entry.last_event_at = std::time::Instant::now();
                }
            }
            ProgressEvent::LlmCallStart {
                dll,
                function,
                attempt,
                strategy,
                ..
            } => {
                let key = format!("{dll}/{function}");
                if let Some(entry) = entries.get_mut(&key) {
                    entry.attempt = *attempt;
                    entry.strategy = strategy.clone();
                    entry.status = LlmCall;
                    entry.last_event_at = std::time::Instant::now();
                }
            }
            ProgressEvent::LlmCallComplete { dll, function, .. } => {
                if let Some(entry) = entries.get_mut(&format!("{dll}/{function}")) {
                    entry.status = Compiling;
                    entry.last_event_at = std::time::Instant::now();
                }
            }
            ProgressEvent::LlmRequest { dll, function, .. }
            | ProgressEvent::LlmResponse { dll, function, .. }
            | ProgressEvent::LlmCallInProgress { dll, function, .. } => {
                // Informational — status stays as LlmCall; update heartbeat
                if let Some(entry) = entries.get_mut(&format!("{dll}/{function}")) {
                    entry.last_event_at = std::time::Instant::now();
                }
            }
            ProgressEvent::TranslationAttemptCompleted { dll, function, .. } => {
                if let Some(entry) = entries.get_mut(&format!("{dll}/{function}")) {
                    entry.status = Testing;
                    entry.last_event_at = std::time::Instant::now();
                }
            }
            ProgressEvent::TranslationCompleted { dll, function, .. } => {
                if let Some(entry) = entries.get_mut(&format!("{dll}/{function}")) {
                    entry.status = Complete;
                    entry.last_event_at = std::time::Instant::now();
                }
            }
            ProgressEvent::TranslationFailed { dll, function, .. } => {
                if let Some(entry) = entries.get_mut(&format!("{dll}/{function}")) {
                    entry.status = Complete;
                    entry.last_event_at = std::time::Instant::now();
                }
            }
            ProgressEvent::FunctionCompleted {
                dll,
                function,
                success,
                ..
            } => {
                if let Some(entry) = entries.get_mut(&format!("{dll}/{function}")) {
                    // Batch-level completion marks the unit as done.
                    entry.status = Complete;
                    entry.last_event_at = std::time::Instant::now();
                    // Optionally differentiate success/failure in the stored data
                    // by updating the strategy field to reflect the outcome.
                    entry.strategy = if *success {
                        "batch_ok".to_string()
                    } else {
                        "batch_failed".to_string()
                    };
                }
            }
            // ClassificationComplete and BatchSummary are handled in on_event
            // directly; they should never reach here, but we need exhaustiveness.
            _ => {}
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

/// Build the axum router with all API endpoints.
pub fn build_router(state: ServerState) -> Router {
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
        .route("/health", get(handlers::api_health))
        .fallback_service(axum::routing::get(handlers::static_fallback))
        .layer(middleware::from_fn(handlers::trace_middleware))
        .layer(DefaultBodyLimit::max(16 * 1024))
        .with_state(CombinedState {
            server: state,
            manager: None,
            bridge: None,
            actions: None,
            progress: None,
        })
}

/// Build a router with WebSocket support and review-actions backend.
pub fn build_router_with_actions(state: ServerState, actions: ActionsState) -> Router {
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
        .route("/health", get(handlers::api_health))
        .fallback_service(axum::routing::get(handlers::static_fallback))
        .layer(middleware::from_fn(handlers::trace_middleware))
        .layer(DefaultBodyLimit::max(16 * 1024))
        .with_state(CombinedState {
            server: state,
            manager: None,
            bridge: None,
            actions: Some(actions),
            progress: None,
        })
}

/// Build a router with WebSocket support.
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

    Router::new()
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
        .route("/api/queue", get(handlers::api_get_queue))
        .route("/api/queue/next", get(handlers::api_get_next_unit))
        .route("/api/graph", get(handlers::api_get_dependency_graph))
        .route("/api/progress", get(handlers::api_get_progress))
        .route("/health", get(handlers::api_health))
        .route("/", get(handlers::serve_index))
        .fallback_service(axum::routing::get(handlers::static_fallback))
        .route("/api/events/upgrade", get(api_events_upgrade_ws))
        .layer(middleware::from_fn(handlers::trace_middleware))
        .layer(DefaultBodyLimit::max(16 * 1024))
        .with_state(CombinedState {
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
