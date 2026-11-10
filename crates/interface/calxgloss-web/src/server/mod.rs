//! Axum API server for the review dashboard.
//!
//! This module is only compiled when the `server` feature is enabled.

mod actions;
mod events;
mod handlers;
mod lifecycle;
mod live_store;
mod llm_io_log;
mod metrics;
mod review_reader;
mod routes;
mod types;
mod unknown_actions;

pub use self::actions::*;
pub use self::handlers::*;
pub use self::lifecycle::{LifecycleError, LogLevel, LogLevelControl};
pub use self::live_store::*;
pub use self::llm_io_log::{LlmIoEntry, LlmIoEntryType, LlmIoLog, MAX_LLM_IO_ENTRIES};
pub use self::review_reader::*;
pub use self::routes::*;
pub use self::types::*;
pub use self::unknown_actions::*;
pub use events::{EventsBridge, SessionManager, UnitPhaseMessage, WebSocketHandler, WsMessage};

use axum::{Router, extract::FromRef};
use calxgloss_reports::dashboard::DashboardBuilder;
use calxgloss_types::{
    ClassificationOverrideControl, OverrideControl, PipelineControl, ReviewDashboard,
    RunRequestSignal, ScopeControl, StopSignal, UnitCancellation,
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
    /// The review-surface reader (issue #460). It reads the record tree
    /// and the live store for every review payload, and owns the single
    /// live-merge fold.
    pub reader: ReviewSurfaceReader,
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
