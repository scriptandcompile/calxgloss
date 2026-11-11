//! Test adapter for the review surface (issues #466, #468, #469, #471).
//!
//! All three web test targets wire this one module: the e2e family
//! (`tests/e2e.rs`), the accept-conflict test (`tests/accept_conflict.rs`),
//! and the Kuna-scan e2e (`tests/kuna_scan_e2e.rs`). Because every target
//! rides it, the boot rules, the fixture writers, and the wait rules exist
//! once (issue #478). Besides the booted worlds below, it holds the shared
//! sample-data fixture (`TestFixture`), the record writers that file every
//! document a test names, and the helpers the scenario submodules call.
//!
//! One call boots everything a review-surface e2e test needs and hands
//! back a typed HTTP client, a typed event emitter, event-applied waits,
//! and — on a live (websocket) world — a connected websocket handle with
//! wire reads and the applied-then-push wait, so wire-protocol assertions
//! are the body of the test instead of the handshake plumbing. The call
//! creates the temporary git repository with the shared sample data, the
//! server state, the translation event bus, the session manager
//! subscribed to the bus, the live-view store, and the router. Boot entry
//! points name the router shapes `calxgloss_web` exports: plain serve
//! (`boot_plain`), actions-wired serve (`boot_with_actions`), and live
//! actions-plus-websocket (`boot`). [`ReviewWorld::boot_ws_wired`] is
//! the live shape with every control handle `calxgloss live` attaches —
//! the pipeline machine, unit cancellation, run-request channel, scope
//! and the two override handles — each reachable through the world's
//! accessors (issue #472). The `_on` variants boot over a
//! caller-supplied fixture — a second server over the same repository,
//! which is what a server-restart pin needs — and the `_with_log_filter`
//! variants attach the reloadable tracing filter the log-verbosity pins
//! drive. The routers come from the same builders the production serve
//! and live commands use (`calxgloss-cli`'s `handle_serve` and
//! `handle_live`), and the server runs on a freshly bound port. Dropping
//! the returned world takes the server down with it, so no port leaks
//! between tests. The browser seam (issue #471) rides that same world:
//! `open_dashboard_tab` launches headless Chrome over it and hands back
//! a tab with the evaluate helpers and bounded DOM waits. Where no
//! Chrome/Chromium exists it hands back `None`, so a browser test
//! self-skips instead of failing.

use calxgloss_callgraph::{
    CallGraph, CallGraphEdge, CallGraphPersistor, CallType, FunctionCallGraph, NodeCategory,
};
use calxgloss_git::{GitManager, InitConfig};
use calxgloss_translator::assembly::PipelineSpec;
use calxgloss_types::{
    ApiCategory, BinaryClassificationOverride, ClassificationOverrides, ClassificationRecord,
    ComplexityScore, DllCategory, FaultCategory, FaultEvent, FaultLog, FaultSeverity, GitBranch,
    ProgressEvent, PromptStrategyEntry, PromptStrategyLog, SHIM_MAPPINGS_FILE,
    SHIM_VERIFICATION_FILE, ShimApiMapping, ShimLayer, ShimVerificationResult, TestCase,
    TestResult, TokenUsageEntry, TokenUsageLog, TranslationEvents, WindowsApiCall,
    shim_artifacts_dir,
};
use calxgloss_web::{
    ActionsState, CombinedState, ProgressState, ReviewSurfaceReader, ServerState, SessionManager,
    build_router, build_router_with_actions, build_router_with_ws, serve_with_listener,
};
use futures_util::StreamExt;
use std::path::PathBuf;
use std::time::Duration;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, connect_async};

/// A booted review world: the fixture repo, the live review server, and
/// the typed client pointed at it.
pub struct ReviewWorld {
    fixture: TestFixture,
    /// Typed handle on the progress-event bus. Kept alive on purpose:
    /// the session manager's broadcast subscription closes once the
    /// bus's only sender is dropped.
    emitter: EventEmitter,
    client: Client,
    /// The live-view store the router's own event consumer applies
    /// events to — present only on a websocket (live) boot.
    progress: Option<ProgressState>,
    /// The router's websocket session manager — present only on a
    /// websocket (live) boot.
    manager: Option<SessionManager>,
    /// The state the router was built from, so the shutdown pins can
    /// read the stop signal the shutdown/restart endpoints flip.
    state: ServerState,
    /// The live control handles `calxgloss live` attaches — present only
    /// on a `boot_ws_wired()` world (issue #472).
    controls: Option<LiveControls>,
    port: u16,
    server: Option<tokio::task::JoinHandle<()>>,
}

/// The live-world-only pieces a router can be served with: the live-view
/// store and session manager a websocket router runs on, and the live
/// control handles a wired boot attaches.
#[derive(Default)]
struct LiveParts {
    progress: Option<ProgressState>,
    manager: Option<SessionManager>,
    controls: Option<LiveControls>,
}

/// The live control handles a `boot_ws_wired()` world attaches to its
/// server state, mirroring what `calxgloss-cli`'s `handle_live` wires
/// (issue #472): the pipeline machine, the unit-cancellation handle, the
/// run-request channel, and the scope and override handles opened over
/// the fixture's workspace. A test reads some handles through the world's
/// accessors and the rest through the server state. The world holds them
/// for as long as it serves.
struct LiveControls {
    control: calxgloss_types::PipelineControl,
    cancellation: calxgloss_types::UnitCancellation,
    run_requests: calxgloss_types::RunRequestSignal,
    scope: calxgloss_types::ScopeControl,
    overrides: calxgloss_types::OverrideControl,
    classification_overrides: calxgloss_types::ClassificationOverrideControl,
}

impl LiveControls {
    fn new(fixture: &TestFixture, events: &TranslationEvents) -> Self {
        let repo = fixture.repo_path();
        let scope = calxgloss_types::ScopeControl::try_open(&repo)
            .expect("scope handle opens over a clean fixture workspace")
            .with_events(events.clone());
        let overrides = calxgloss_types::OverrideControl::try_open(&repo)
            .expect("override handle opens over a clean fixture workspace");
        let classification_overrides =
            calxgloss_types::ClassificationOverrideControl::try_open(&repo)
                .expect("classification override handle opens over a clean fixture workspace");
        Self {
            control: calxgloss_types::PipelineControl::new().with_events(events.clone()),
            cancellation: calxgloss_types::UnitCancellation::new().with_events(events.clone()),
            run_requests: calxgloss_types::RunRequestSignal::new(),
            scope,
            overrides,
            classification_overrides,
        }
    }
}

impl ReviewWorld {
    /// The way a test gets a running review server.
    ///
    /// The router matches the production live command's: a live (WS)
    /// router over the event bus's broadcast subscription, the
    /// live-view store, and the settings-backed actions backend. The
    /// accept loop ignores the state's shutdown signal, like the test
    /// harnesses that served these routers before issue #469 — a
    /// lifecycle POST does not take the server down under a test that
    /// only probes route registration.
    pub async fn boot() -> Self {
        Self::boot_live(&TestFixture::new(), None, false, false).await
    }

    /// A live (websocket) world whose accept loop **does** watch the
    /// state's shutdown signal — the shape `calxgloss live` runs with,
    /// so `POST /api/server/shutdown` stops it. The graceful-shutdown
    /// pins (issue #469) boot through here.
    pub async fn boot_graceful() -> Self {
        Self::boot_live(&TestFixture::new(), None, true, false).await
    }

    /// Boot a live (websocket) world whose state carries a reloadable
    /// tracing filter — the shape `calxgloss live` installs, so a
    /// `PATCH /api/server/log-level` changes the running process's
    /// verbosity rather than only the reported string.
    pub async fn boot_with_log_filter(
        fixture: &TestFixture,
        filter: calxgloss_web::LogLevelControl,
    ) -> Self {
        Self::boot_live(fixture, Some(filter), false, false).await
    }

    /// Boot through the actions-wired serve router — `calxgloss serve`
    /// with the review-actions backend attached, still without the
    /// live-pipeline endpoints (issue #468).
    pub async fn boot_with_actions() -> Self {
        Self::boot_actions(&TestFixture::new(), None, false, None).await
    }

    /// The actions-wired serve router over a caller-supplied fixture.
    pub async fn boot_with_actions_on(fixture: &TestFixture) -> Self {
        Self::boot_actions(fixture, None, false, None).await
    }

    /// The actions-wired serve router with a reloadable tracing filter
    /// attached (issue #469 — the lifecycle-registration pin exercises
    /// all three router shapes with the log-level endpoint).
    pub async fn boot_with_actions_and_log_filter(
        fixture: &TestFixture,
        filter: calxgloss_web::LogLevelControl,
    ) -> Self {
        Self::boot_actions(fixture, Some(filter), false, None).await
    }

    /// The actions-wired serve router over a fixture, served with a
    /// caller-supplied actions backend. The default backend names no LLM
    /// selection and no target directory; a test whose request drives a real
    /// assembled pass needs both, so it builds its own backend and boots here.
    pub async fn boot_with_actions_backend(fixture: &TestFixture, actions: ActionsState) -> Self {
        Self::boot_actions(fixture, None, false, Some(actions)).await
    }

    /// Boot through the plain-serve router — the shared review surface
    /// with no actions backend and no live-pipeline endpoints, the
    /// router shape [`build_router`] assembles (issue #468). Tests
    /// pinning that a router without an actions backend refuses rather
    /// than fabricates run against this world.
    pub async fn boot_plain() -> Self {
        Self::boot_plain_router(&TestFixture::new(), None, None, false).await
    }

    /// A plain-serve world whose accept loop **does** watch the state's
    /// shutdown signal — the graceful-shutdown pins' shape (issue #469),
    /// where `POST /api/server/restart` must take the server down.
    pub async fn boot_plain_graceful() -> Self {
        Self::boot_plain_router(&TestFixture::new(), None, None, true).await
    }

    /// The plain-serve router over a caller-supplied fixture — a
    /// second server over the same repository (a server restart).
    pub async fn boot_plain_on(fixture: &TestFixture) -> Self {
        Self::boot_plain_router(fixture, None, None, false).await
    }

    /// A live (websocket) world over a caller-supplied fixture. Tests
    /// that pin both router shapes seed one fixture and boot each shape
    /// over it (issue #470).
    pub async fn boot_ws_on(fixture: &TestFixture) -> Self {
        Self::boot_live(fixture, None, false, false).await
    }

    /// A live (websocket) world with every control handle `calxgloss
    /// live` attaches to the server state (issue #472): the pipeline
    /// machine, the unit-cancellation handle, the run-request channel,
    /// and the scope and override handles opened over the fixture's
    /// workspace. `handle_live` builds the same shape, so the control-
    /// endpoint pins drive the same wiring production serves. The world
    /// hands the pipeline machine, unit-cancellation handle, and run-request
    /// channel back through accessors, and serves the other three handles
    /// through its state. The honest-503 pins keep the bare
    /// [`ReviewWorld::boot`] world, which attaches none of them.
    pub async fn boot_ws_wired() -> Self {
        Self::boot_live(&TestFixture::new(), None, false, true).await
    }

    /// [`ReviewWorld::boot_ws_wired`] over a caller-supplied fixture. Use
    /// it when a test files records — scope, override, classification-
    /// override — into the fixture before the boot, so the world's own
    /// handles open over them (issue #475).
    pub async fn boot_ws_wired_on(fixture: &TestFixture) -> Self {
        Self::boot_live(fixture, None, false, true).await
    }

    /// The plain-serve router with a reloadable tracing filter attached.
    pub async fn boot_plain_with_log_filter(
        fixture: &TestFixture,
        filter: calxgloss_web::LogLevelControl,
    ) -> Self {
        Self::boot_plain_router(fixture, Some(filter), None, false).await
    }

    /// The plain-serve router whose state starts at the given log level,
    /// so `/api/server/status` reports it (issue #472).
    pub async fn boot_plain_with_log_level(level: &str) -> Self {
        Self::boot_plain_router(&TestFixture::new(), None, Some(level), false).await
    }

    /// Assemble the live actions-plus-websocket router over `fixture`
    /// and serve it, keeping the live-view store and session manager
    /// reachable through the world's accessors. The state carries its
    /// shared stop signal **before** the router is built, so the signal
    /// the shutdown endpoints flip is the one the world hands back.
    async fn boot_live(
        fixture: &TestFixture,
        filter: Option<calxgloss_web::LogLevelControl>,
        graceful: bool,
        wired: bool,
    ) -> Self {
        let mut state = ServerState::new(fixture.repo_path())
            .with_stop_signal(calxgloss_types::StopSignal::new());
        if let Some(filter) = filter {
            state = state.with_log_level("warn").with_log_filter(filter);
        }
        // The bus is deeper than the live command's 256 so the
        // stalled-client pin (issue #469's raw-protocol case, 400
        // events) can emit without a lagged drop.
        let events = TranslationEvents::new(1024);
        let controls = wired.then(|| LiveControls::new(fixture, &events));
        if let Some(controls) = &controls {
            state = state
                .with_pipeline_control(controls.control.clone())
                .with_unit_cancellation(controls.cancellation.clone())
                .with_run_requests(controls.run_requests.clone())
                .with_scope_control(controls.scope.clone())
                .with_override_control(controls.overrides.clone())
                .with_classification_override_control(controls.classification_overrides.clone());
        }
        let manager = SessionManager::new_with_broadcast(events.subscribe());
        let progress = ProgressState::new();
        let router = build_router_with_ws(
            state.clone(),
            manager.clone(),
            progress.clone(),
            build_actions_state(fixture),
        );
        Self::spawn(
            fixture.clone(),
            state,
            EventEmitter { events },
            router,
            LiveParts {
                progress: Some(progress),
                manager: Some(manager),
                controls,
            },
            graceful,
        )
        .await
    }

    /// Assemble the actions-wired serve router over `fixture` and serve
    /// it, with the default settings-backed backend unless the caller
    /// hands in its own.
    async fn boot_actions(
        fixture: &TestFixture,
        filter: Option<calxgloss_web::LogLevelControl>,
        graceful: bool,
        actions: Option<ActionsState>,
    ) -> Self {
        let mut state = ServerState::new(fixture.repo_path())
            .with_stop_signal(calxgloss_types::StopSignal::new());
        if let Some(filter) = filter {
            state = state.with_log_level("warn").with_log_filter(filter);
        }
        let events = TranslationEvents::new(256);
        let actions = actions.unwrap_or_else(|| build_actions_state(fixture));
        let router = build_router_with_actions(state.clone(), actions);
        Self::spawn(
            fixture.clone(),
            state,
            EventEmitter { events },
            router,
            LiveParts::default(),
            graceful,
        )
        .await
    }

    /// Assemble the plain-serve router over `fixture` and serve it.
    async fn boot_plain_router(
        fixture: &TestFixture,
        filter: Option<calxgloss_web::LogLevelControl>,
        level: Option<&str>,
        graceful: bool,
    ) -> Self {
        let mut state = ServerState::new(fixture.repo_path())
            .with_stop_signal(calxgloss_types::StopSignal::new());
        if let Some(filter) = filter {
            state = state.with_log_level("warn").with_log_filter(filter);
        }
        if let Some(level) = level {
            state = state.with_log_level(level);
        }
        let events = TranslationEvents::new(256);
        let router = build_router(state.clone());
        Self::spawn(
            fixture.clone(),
            state,
            EventEmitter { events },
            router,
            LiveParts::default(),
            graceful,
        )
        .await
    }

    /// Bind a free port, serve `router` over it, and hand back the world
    /// that owns the server task.
    ///
    /// Bind port 0 and read the port back. The socket is already
    /// listening when the serve task is spawned, so the first request
    /// needs no settle sleep — the kernel queues it for `accept`. The
    /// state's shared stop signal was attached at boot **before** the
    /// router was built, so the signal the shutdown and restart
    /// endpoints flip is the one the world hands back (issue #469).
    /// With `graceful`, the accept loop watches the state's shutdown
    /// signal — the shape `calxgloss live` runs with, where a lifecycle
    /// POST takes the server down; without it, the server ignores the
    /// signal, like the pre-#469 test harnesses, so route-registration
    /// probes keep answering after a lifecycle POST.
    async fn spawn(
        fixture: TestFixture,
        state: ServerState,
        emitter: EventEmitter,
        router: axum::Router,
        parts: LiveParts,
        graceful: bool,
    ) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind free port");
        let port = listener.local_addr().expect("listener address").port();
        let server = if graceful {
            let shutdown = state.shutdown_signal();
            tokio::spawn(async move {
                let _ = serve_with_listener(listener, router, shutdown).await;
            })
        } else {
            tokio::spawn(async move {
                let _ = axum::serve(listener, router).await;
            })
        };
        Self {
            fixture,
            emitter,
            client: Client {
                http: reqwest::Client::new(),
                port,
            },
            progress: parts.progress,
            manager: parts.manager,
            state,
            controls: parts.controls,
            port,
            server: Some(server),
        }
    }

    /// The fixture repository, for tests filing record fixtures into it.
    pub fn repo_path(&self) -> PathBuf {
        self.fixture.repo_path()
    }

    /// The typed client pointed at this world's server.
    pub fn client(&self) -> &Client {
        &self.client
    }

    /// The typed emitter over this world's progress-event bus.
    pub fn emitter(&self) -> &EventEmitter {
        &self.emitter
    }

    /// The stop signal this world's server shares — the shutdown and
    /// restart endpoints flip it, and the graceful-shutdown pins assert
    /// what the endpoint promised the pipeline (issue #469).
    pub fn stop_signal(&self) -> calxgloss_types::StopSignal {
        self.state.stop_signal()
    }

    /// The pipeline machine attached by `boot_ws_wired`, so a test can
    /// read the run's lifecycle state directly (issue #472).
    pub fn pipeline_control(&self) -> calxgloss_types::PipelineControl {
        self.expect_wired().control.clone()
    }

    /// The unit-cancellation handle attached by `boot_ws_wired`.
    pub fn unit_cancellation(&self) -> calxgloss_types::UnitCancellation {
        self.expect_wired().cancellation.clone()
    }

    /// The scope-steering handle attached by `boot_ws_wired`, so a test
    /// can read and drive the run's scope record directly — and record
    /// token spend, which lives on this live handle rather than in the
    /// persisted record (issue #475).
    pub fn scope_control(&self) -> calxgloss_types::ScopeControl {
        self.expect_wired().scope.clone()
    }

    /// The run-request channel attached by `boot_ws_wired`; subscribing
    /// to it is how a test watches what the start endpoint stored
    /// without a sleep (issue #472).
    pub fn run_requests(&self) -> calxgloss_types::RunRequestSignal {
        self.expect_wired().run_requests.clone()
    }

    /// The handles attached by `boot_ws_wired`. A bare `boot()` world
    /// attaches none, so asking it for these handles fails the test.
    fn expect_wired(&self) -> &LiveControls {
        self.controls
            .as_ref()
            .expect("these handles stand only on a wired (boot_ws_wired) world")
    }

    /// The live-view store this world's router applies events to —
    /// only on a `boot()` world.
    pub fn progress_state(&self) -> &ProgressState {
        self.progress
            .as_ref()
            .expect("the live-view store stands only on a websocket (live) boot")
    }

    /// Wait for an emitted event to reach the applied state (issue
    /// #468): a bounded poll of `GET /api/pipeline` until the caller's
    /// predicate holds, returning as soon as it does. That endpoint is
    /// the live view the router's own event consumer applies events to,
    /// so it answers only on a `boot()` world. On deadline the wait
    /// fails naming the pending event and showing the last live view,
    /// so a timeout points at the stuck event rather than at a guessed
    /// sleep length.
    pub async fn wait_until_applied(
        &self,
        pending: &ProgressEvent,
        applied: impl Fn(&serde_json::Value) -> bool,
    ) {
        let deadline = tokio::time::Instant::now() + APPLIED_WAIT_DEADLINE;
        loop {
            let (status, view) = self.client.get_json("/api/pipeline").await;
            assert_eq!(status, 200, "the live view endpoint answers during a wait");
            if applied(&view) {
                return;
            }
            if tokio::time::Instant::now() >= deadline {
                panic!(
                    "event `{pending}` never reached the applied state within \
                     {APPLIED_WAIT_DEADLINE:?}; last live view: {view}"
                );
            }
            tokio::time::sleep(APPLIED_WAIT_POLL).await;
        }
    }

    /// Poll `GET /api/progress/enhanced` until `applied` accepts its payload,
    /// proving the router's own event consumer has finished applying
    /// `pending`. The enhanced view carries what `/api/pipeline` does not:
    /// the scan records and the working pass's heartbeat (issues #428, #430).
    pub async fn wait_until_enhanced_progress_applied(
        &self,
        pending: &ProgressEvent,
        applied: impl Fn(&serde_json::Value) -> bool,
    ) {
        let deadline = tokio::time::Instant::now() + APPLIED_WAIT_DEADLINE;
        loop {
            let (status, view) = self.client.get_json("/api/progress/enhanced").await;
            assert_eq!(
                status, 200,
                "the enhanced live view endpoint answers during a wait"
            );
            if applied(&view) {
                return;
            }
            if tokio::time::Instant::now() >= deadline {
                panic!(
                    "event `{pending}` never reached the applied state in the live \
                     view within {APPLIED_WAIT_DEADLINE:?}; last live view: {view}"
                );
            }
            tokio::time::sleep(APPLIED_WAIT_POLL).await;
        }
    }

    /// The same applied wait read straight from the live-view store's
    /// unit record (issue #469), for the pin whose server has already
    /// stopped answering HTTP — the graceful-shutdown contract. Returns
    /// the record once `applied` holds it, and fails naming the pending
    /// event on deadline.
    pub async fn wait_until_unit_applied(
        &self,
        pending: &ProgressEvent,
        binary: &str,
        function: &str,
        applied: impl Fn(&calxgloss_types::LiveUnitProgress) -> bool,
    ) -> calxgloss_types::LiveUnitProgress {
        let store = self.progress_state().clone();
        let deadline = tokio::time::Instant::now() + APPLIED_WAIT_DEADLINE;
        loop {
            if let Some(record) = store.entry(binary, function).await
                && applied(&record)
            {
                return record;
            }
            if tokio::time::Instant::now() >= deadline {
                panic!(
                    "event `{pending}` never reached the applied state in the \
                     live-view store within {APPLIED_WAIT_DEADLINE:?}"
                );
            }
            tokio::time::sleep(APPLIED_WAIT_POLL).await;
        }
    }

    /// The websocket URL of this world's upgrade route, for a test that
    /// deliberately exercises the raw protocol.
    pub fn websocket_url(&self) -> String {
        format!("ws://127.0.0.1:{}/api/events/upgrade", self.port)
    }

    /// Connect a websocket client to this world's upgrade route and hand
    /// back a registered handle (issue #469): the upgrade has completed
    /// and the session manager has taken the new session, so an event
    /// emitted after this returns is guaranteed to reach the client.
    pub async fn websocket(&self) -> WebSocket {
        self.connect_ws(None)
            .await
            .expect("websocket client connects and registers")
    }

    /// [`ReviewWorld::websocket`] for a handle named in the test's
    /// failure messages — the stalled-client pin labels its peers.
    pub async fn websocket_named(&self, label: &str) -> WebSocket {
        self.connect_ws(Some(label))
            .await
            .unwrap_or_else(|e| panic!("websocket client `{label}` connects and registers: {e}"))
    }

    /// The websocket plumbing the test body must not repeat: the
    /// upgrade, and a bounded wait until the session manager's client
    /// list holds this session. Fails with the reason instead of
    /// panicking — the plain-router pin asserts the refusal.
    async fn connect_ws(&self, label: Option<&str>) -> Result<WebSocket, String> {
        let manager = self.manager.as_ref().ok_or_else(|| {
            "this world booted without a live router — `boot()` assembles the \
             router that routes /api/events/upgrade"
                .to_string()
        })?;
        let registered_before = manager.connection_count().await;
        let socket = match connect_async(self.websocket_url()).await {
            Ok((socket, _)) => socket,
            Err(e) => {
                return Err(format!(
                    "websocket upgrade to /api/events/upgrade failed: {e}"
                ));
            }
        };
        // The upgrade response answers before the server's session is
        // registered; a test emitting an event into that gap would lose
        // it. Poll the session manager's own client list until this
        // connection appears in it.
        let deadline = tokio::time::Instant::now() + APPLIED_WAIT_DEADLINE;
        while manager.connection_count().await <= registered_before {
            if tokio::time::Instant::now() >= deadline {
                return Err(format!(
                    "the session manager never registered the new client \
                     ({} live sessions so far)",
                    manager.connection_count().await
                ));
            }
            tokio::time::sleep(APPLIED_WAIT_POLL).await;
        }
        Ok(WebSocket {
            socket,
            raw_events: Vec::new(),
            unit_phase_pushes: 0,
            label: label.map(str::to_string),
        })
    }

    /// Wait for this world's accept loop to exit on its own — the
    /// graceful-shutdown path the shutdown/restart endpoints drive
    /// (issue #469). Takes the server task: a second call, or a drop
    /// after it, has no task left to wait on or abort.
    pub async fn wait_for_server_shutdown(&mut self) {
        let server = self
            .server
            .take()
            .expect("the server task is still owned by this world");
        server
            .await
            .expect("server task exits after graceful shutdown");
    }

    /// Launch a browser and open a dashboard tab on this world's server
    /// (issue #471), so a browser test's body is the DOM behaviour it
    /// pins — no fixture, router, port, or settle sleep. `None` is the
    /// runtime capability skip: with no Chrome/Chromium installed the
    /// calling test returns early instead of failing.
    pub fn open_dashboard_tab(&self) -> Option<DashboardTab> {
        let browser = launch_headless_browser()?;
        let tab = open_dashboard_tab(&browser, self.port);
        Some(DashboardTab { browser, tab })
    }
}

/// Dropping the world aborts its serve task, and the listener dies with
/// the task — no port leaks into the next test.
impl Drop for ReviewWorld {
    fn drop(&mut self) {
        if let Some(server) = self.server.take() {
            server.abort();
        }
    }
}

/// How often an applied wait re-reads the live view, and how long it
/// keeps trying before it fails naming the pending event (issue #468).
/// The websocket reads and the registration wait share these bounds, and
/// so do the endpoint-poll waits in the scenario submodules (issue #475).
pub const APPLIED_WAIT_POLL: Duration = Duration::from_millis(10);
pub const APPLIED_WAIT_DEADLINE: Duration = Duration::from_secs(5);

// ─────────────────────────────────────────────────────────────
// The browser seam (issue #471): browser pins ride the booted world
// ─────────────────────────────────────────────────────────────

/// How often a DOM wait re-reads the page, and how long it keeps trying
/// before it gives up (issue #471). The DOM waits replace the browser
/// pins' `25 × 200 ms` settle loops: they return as soon as the page
/// shows the state, inside the same five-second budget.
const DOM_WAIT_POLL: Duration = Duration::from_millis(50);
const DOM_WAIT_DEADLINE: Duration = Duration::from_secs(5);

/// Launch headless Chrome with the flags that work inside containers and CI,
/// or return `None` — printing a skip note — when no browser is installed.
/// `default_executable` looks at `$CHROME`, then `google-chrome-stable`,
/// `chromium`, and the other standard names on PATH, so the browser tests run
/// wherever a browser exists and are skipped with a printed note where none is.
///
/// Chrome's CDP calls are **blocking**, so every browser test must run on a
/// multi-thread runtime (`#[tokio::test(flavor = "multi_thread")]`). On the
/// default current-thread runtime the blocking calls starve the axum server
/// task that the same test spawns, so the page is never served and navigation
/// times out with "The event waited for never came".
pub fn launch_headless_browser() -> Option<headless_chrome::Browser> {
    use headless_chrome::{Browser, LaunchOptionsBuilder};

    if headless_chrome::browser::default_executable().is_err() {
        eprintln!("skipping browser test: no Chrome/Chromium found (set $CHROME to name one)");
        return None;
    }
    Some(
        Browser::new(
            LaunchOptionsBuilder::default()
                .headless(true)
                .args(vec![
                    std::ffi::OsStr::new("--no-sandbox"),
                    std::ffi::OsStr::new("--disable-gpu"),
                    std::ffi::OsStr::new("--disable-dev-shm-usage"),
                    // Wide viewport: a narrow window pins the pipeline row's
                    // head track to its minimum size and hides column-alignment
                    // bugs that only show up once the tracks grow with content.
                    std::ffi::OsStr::new("--window-size=1400,900"),
                ])
                .build()
                .expect("build chrome launch options"),
        )
        .expect("launch headless chrome"),
    )
}

/// Open a tab on the server at `port` and wait for the page to load.
///
/// `navigate_to` waits for Chrome's `networkAlmostIdle` lifecycle event, which
/// only arrives after the dashboard's own fetches finish. That is generous on
/// purpose, so a slow machine still passes.
pub fn open_dashboard_tab(
    browser: &headless_chrome::Browser,
    port: u16,
) -> std::sync::Arc<headless_chrome::Tab> {
    let tab = browser.new_tab().expect("open new tab");
    tab.navigate_to(&format!("http://127.0.0.1:{port}"))
        .expect("navigate to server root");
    tab.wait_until_navigated().expect("wait for navigation");
    tab.enable_runtime().expect("enable runtime");
    tab
}

/// Evaluate a JS expression on a dashboard tab and read the result as a
/// boolean. Every headless test uses this, so none repeats the conversion.
///
/// An evaluation error or a non-boolean result reads as `false`. That keeps
/// the render-polling loops honest until the dashboard really shows the thing.
pub fn eval_bool(tab: &headless_chrome::Tab, expr: &str) -> bool {
    tab.evaluate(expr, false)
        .ok()
        .and_then(|r| r.value)
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
}

/// Like [`eval_bool`], but reads the result as text; errors and non-string
/// results read as the empty string.
pub fn eval_text(tab: &headless_chrome::Tab, expr: &str) -> String {
    tab.evaluate(expr, false)
        .ok()
        .and_then(|r| r.value)
        .and_then(|v| v.as_str().map(String::from))
        .unwrap_or_default()
}

/// Like [`eval_bool`], but reads the result as a whole number. Errors and
/// non-number results read as `-1`, a number no real element count can be.
pub fn eval_count(tab: &headless_chrome::Tab, expr: &str) -> i64 {
    tab.evaluate(expr, false)
        .ok()
        .and_then(|r| r.value)
        .and_then(|v| v.as_i64())
        .unwrap_or(-1)
}

/// [`DashboardTab::wait_for_bool`]'s bounded DOM wait over a bare tab —
/// the fresh tab a shared URL opens (issue #476). Same bounds.
pub async fn wait_for_bool_on(tab: &headless_chrome::Tab, expr: &str) -> bool {
    let deadline = tokio::time::Instant::now() + DOM_WAIT_DEADLINE;
    loop {
        if eval_bool(tab, expr) {
            return true;
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(DOM_WAIT_POLL).await;
    }
}

/// A dashboard tab riding a booted world (issue #471). It opens on the
/// world's own port with Chrome's runtime enabled, and it holds the
/// browser for the tab's lifetime. The evaluate helpers and the bounded
/// DOM waits sit on the tab, so the test body states only DOM behaviour.
pub struct DashboardTab {
    /// Never read by code — held so Chrome stays up for the tab's
    /// lifetime and dies with the tab (the compiler's drop glue reads it).
    #[allow(dead_code)]
    browser: headless_chrome::Browser,
    tab: std::sync::Arc<headless_chrome::Tab>,
}

impl DashboardTab {
    /// Click the first element matching `selector`, through the page's
    /// own handler. Fails naming the selector when the CDP call does.
    pub fn click(&self, selector: &str) {
        self.tab
            .evaluate(
                &format!("document.querySelector('{selector}')?.click() === undefined"),
                false,
            )
            .unwrap_or_else(|e| panic!("click `{selector}`: {e}"));
    }

    /// Reload the page and wait for Chrome's navigation to settle —
    /// the reload a pin does after filing a record behind the server.
    pub fn reload(&self) {
        self.tab.reload(false, None).expect("reload the tab");
        self.tab.wait_until_navigated().expect("wait for reload");
    }

    /// Run a side-effecting script on the page — a reviewer's input that a
    /// click cannot express, like setting a filter select and firing its
    /// `change` event. Panics, naming `label`, if the DevTools call fails.
    pub fn run(&self, script: &str, label: &str) {
        self.tab
            .evaluate(script, false)
            .unwrap_or_else(|e| panic!("run `{label}`: {e}"));
    }

    /// Open a second tab on this tab's browser, navigated to `url` and
    /// settled, for a pin whose page opens a URL another tab produced —
    /// the graph's shareable URL (issue #476). The caller closes it. The
    /// browser dies with this tab.
    pub fn open_tab_at(&self, url: &str) -> std::sync::Arc<headless_chrome::Tab> {
        let tab = self.browser.new_tab().expect("open new tab");
        tab.navigate_to(url).expect("navigate to shared URL");
        tab.wait_until_navigated().expect("wait for navigation");
        tab.enable_runtime().expect("enable runtime");
        tab
    }

    /// Evaluate `expr` with `awaitPromise` and read the resolved value as a
    /// boolean. An evaluation error or non-boolean result reads as `false`
    /// (issue #476 — the PNG export's rasterize step).
    pub fn eval_promise_bool(&self, expr: &str) -> bool {
        self.tab
            .evaluate(expr, true)
            .ok()
            .and_then(|r| r.value)
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
    }

    /// Evaluate `expr` and read the result as a boolean; an evaluation
    /// error or non-boolean result reads as `false`.
    pub fn eval_bool(&self, expr: &str) -> bool {
        eval_bool(&self.tab, expr)
    }

    /// [`DashboardTab::eval_bool`] reading the result as text; errors
    /// and non-string results read as the empty string.
    pub fn eval_text(&self, expr: &str) -> String {
        eval_text(&self.tab, expr)
    }

    /// [`DashboardTab::eval_bool`] reading the result as a whole number;
    /// errors and non-number results read as `-1`.
    pub fn eval_count(&self, expr: &str) -> i64 {
        eval_count(&self.tab, expr)
    }

    /// Poll `expr` as a boolean until it holds, bounded by
    /// [`DOM_WAIT_DEADLINE`]. Reads `false` at the deadline — the
    /// caller's own assertion then names what the page never showed.
    pub async fn wait_for_bool(&self, expr: &str) -> bool {
        wait_for_bool_on(&self.tab, expr).await
    }

    /// Poll `expr` as text until `seen` accepts what it reads, bounded
    /// by [`DOM_WAIT_DEADLINE`]. Returns whether `seen` ever agreed.
    pub async fn wait_for_text(&self, expr: &str, seen: impl Fn(&str) -> bool) -> bool {
        let deadline = tokio::time::Instant::now() + DOM_WAIT_DEADLINE;
        loop {
            if seen(&self.eval_text(expr)) {
                return true;
            }
            if tokio::time::Instant::now() >= deadline {
                return false;
            }
            tokio::time::sleep(DOM_WAIT_POLL).await;
        }
    }
}

/// Closing the tab on the way out; dropping the world took the server
/// down, and dropping the browser field takes Chrome down with it —
/// the same teardown the hand-rolled browser pins spelled by hand.
impl Drop for DashboardTab {
    fn drop(&mut self) {
        self.tab.close_target().ok();
    }
}

/// A typed handle on the booted world's progress-event bus (issue #468).
/// Tests emit the progress-event vocabulary's own variants, so renaming
/// a variant surfaces in the compiler instead of as a wrong tag string
/// on the wire. On a `boot()` world the emitter holds the bus's only
/// sender, which keeps the session manager's broadcast subscription
/// open for the world's lifetime.
pub struct EventEmitter {
    events: TranslationEvents,
}

impl EventEmitter {
    /// Emit one progress event onto the bus the server consumes.
    pub fn emit(&self, event: ProgressEvent) {
        self.events.emit(event);
    }

    /// A second subscriber to the same progress-event bus (issue #472),
    /// for pins that assert an endpoint's action *emitted* an event by
    /// watching the bus instead of sleeping. Subscribe before the action
    /// that emits.
    pub fn subscribe(&self) -> tokio::sync::broadcast::Receiver<ProgressEvent> {
        self.events.subscribe()
    }
}

/// A connected websocket session on a booted world, with wire reads a
/// test can assert on (issue #469). The handshake — the upgrade and the
/// session-manager registration — has settled before the handle exists.
/// The applied-then-push wait leans on the router's own ordering: the
/// event consumer applies each event to the live-view store before
/// pushing that unit's live record, so a client that receives the push
/// has proof the event was applied. Tests that deliberately exercise
/// the raw protocol (the stalled-client eviction, an oversized payload)
/// drive the socket through [`WebSocket::raw_mut`].
#[derive(Debug)]
pub struct WebSocket {
    socket: WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>,
    /// Raw pipeline-event tags seen while reading, in arrival order.
    raw_events: Vec<String>,
    /// `unit_phase` records consumed so far.
    unit_phase_pushes: usize,
    label: Option<String>,
}

/// One outcome of reading a wire frame.
enum Frame {
    Json(serde_json::Value),
    /// A frame a JSON read skips over (ping, pong, binary).
    Skipped,
    Closed,
    Silent,
}

impl WebSocket {
    fn suffix(&self) -> String {
        self.label
            .as_deref()
            .map(|label| format!(" `{label}`"))
            .unwrap_or_default()
    }

    /// The next wire frame, bounded so a stuck read names itself in a
    /// panic message instead of hanging the test.
    async fn read_frame(&mut self) -> Frame {
        match tokio::time::timeout(APPLIED_WAIT_DEADLINE, self.socket.next()).await {
            Ok(Some(Ok(Message::Text(text)))) => {
                Frame::Json(serde_json::from_str(text.as_str()).expect("wire message is JSON"))
            }
            Ok(Some(Ok(Message::Close(_)))) => Frame::Closed,
            Ok(Some(Ok(_))) => Frame::Skipped,
            Ok(Some(Err(_))) | Ok(None) => Frame::Closed,
            Err(_) => Frame::Silent,
        }
    }

    /// The applied-then-push wait for websocket tests (issue #469):
    /// read wire frames until a `unit_phase` record satisfies
    /// `applied`, and return that record. The router pushes the record
    /// only after applying the event, so the returned record is proof
    /// the event reached the applied state. Raw pipeline events seen on
    /// the way are kept for [`WebSocket::raw_events`]. On deadline the
    /// wait fails naming the pending event.
    pub async fn wait_for_unit_phase_push(
        &mut self,
        pending: &ProgressEvent,
        applied: impl Fn(&serde_json::Value) -> bool,
    ) -> serde_json::Value {
        let deadline = tokio::time::Instant::now() + APPLIED_WAIT_DEADLINE;
        loop {
            match self.read_frame().await {
                Frame::Json(value) => match value["event"].as_str() {
                    Some("unit_phase") => {
                        self.unit_phase_pushes += 1;
                        let unit = value["unit"].clone();
                        if applied(&unit) {
                            return unit;
                        }
                    }
                    Some(name) => self.raw_events.push(name.to_string()),
                    None => {}
                },
                Frame::Skipped => {}
                Frame::Closed => panic!(
                    "websocket{} connection closed while waiting for the applied \
                     `unit_phase` push of event `{pending}` (seen so far: {} raw \
                     events, {} unit_phase pushes)",
                    self.suffix(),
                    self.raw_events.len(),
                    self.unit_phase_pushes,
                ),
                Frame::Silent => panic!(
                    "websocket{} went silent while waiting for the applied \
                     `unit_phase` push of event `{pending}` (seen so far: {} raw \
                     events, {} unit_phase pushes)",
                    self.suffix(),
                    self.raw_events.len(),
                    self.unit_phase_pushes,
                ),
            }
            if tokio::time::Instant::now() >= deadline {
                panic!(
                    "event `{pending}` never produced an applied `unit_phase` push \
                     within {APPLIED_WAIT_DEADLINE:?} (seen so far: {} raw events, \
                     {} unit_phase pushes)",
                    self.raw_events.len(),
                    self.unit_phase_pushes,
                );
            }
        }
    }

    /// The stalled client's side of the eviction pins (issue #469):
    /// read and discard whatever the kernel still holds until the
    /// server closes the connection. Panics naming the client if the
    /// socket is still live past the read bound.
    pub async fn drain_until_closed(&mut self) {
        loop {
            match tokio::time::timeout(APPLIED_WAIT_DEADLINE, self.socket.next()).await {
                Ok(Some(Ok(Message::Close(_)))) | Ok(Some(Err(_))) | Ok(None) => return,
                Ok(Some(Ok(_))) => {}
                Err(_) => panic!(
                    "websocket{} was never disconnected — no frame arrived and \
                     the connection stayed live past {APPLIED_WAIT_DEADLINE:?}",
                    self.suffix()
                ),
            }
        }
    }

    /// The raw pipeline-event tags seen while reading, in arrival order.
    pub fn raw_events(&self) -> &[String] {
        &self.raw_events
    }

    /// The connected socket itself, for tests that deliberately drive
    /// the raw protocol (the stalled-client eviction, an oversized
    /// payload) instead of the wire reads.
    pub fn raw_mut(&mut self) -> &mut WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>> {
        &mut self.socket
    }
}

/// A typed HTTP client over one booted world: it owns the port, builds
/// the URLs, and decodes JSON bodies. A test that deliberately exercises
/// the raw protocol reads [`Client::url`] and drives reqwest itself.
pub struct Client {
    http: reqwest::Client,
    port: u16,
}

impl Client {
    /// The full URL for a server path, for a test that drives reqwest
    /// directly.
    pub fn url(&self, path: &str) -> String {
        format!("http://127.0.0.1:{}{}", self.port, path)
    }

    /// A plain GET expecting a JSON body: the status plus the decoded value.
    pub async fn get_json(&self, path: &str) -> (reqwest::StatusCode, serde_json::Value) {
        let resp = self
            .http
            .get(self.url(path))
            .send()
            .await
            .expect("request reaches server");
        let status = resp.status();
        let body: serde_json::Value = resp.json().await.expect("body is JSON");
        (status, body)
    }

    /// `GET /api/units/{id}` with the unit id (`binary/function/vN`)
    /// URL-encoded, as the route's path parameter expects.
    pub async fn unit_detail(&self, unit_id: &str) -> (reqwest::StatusCode, serde_json::Value) {
        self.get_json(&format!("/api/units/{}", urlencoding::encode(unit_id)))
            .await
    }

    /// `GET /api/units/{id}/diff` with the unit id URL-encoded, as the
    /// route's path parameter expects.
    pub async fn unit_diff(&self, unit_id: &str) -> (reqwest::StatusCode, serde_json::Value) {
        self.get_json(&format!("/api/units/{}/diff", urlencoding::encode(unit_id)))
            .await
    }

    /// `GET /api/units/{id}/decomp` with the unit id URL-encoded, as the
    /// route's path parameter expects.
    pub async fn unit_decomp(&self, unit_id: &str) -> (reqwest::StatusCode, serde_json::Value) {
        self.get_json(&format!(
            "/api/units/{}/decomp",
            urlencoding::encode(unit_id)
        ))
        .await
    }

    /// POST to an endpoint that takes no body (the lifecycle and review
    /// actions) and decode the JSON reply.
    pub async fn post_lifecycle(&self, path: &str) -> (reqwest::StatusCode, serde_json::Value) {
        let resp = self
            .http
            .post(self.url(path))
            .send()
            .await
            .expect("lifecycle request reaches server");
        let status = resp.status();
        let body: serde_json::Value = resp.json().await.expect("lifecycle body is JSON");
        (status, body)
    }

    /// POST a JSON body and decode the JSON reply (the batch actions).
    pub async fn post_json(
        &self,
        path: &str,
        payload: serde_json::Value,
    ) -> (reqwest::StatusCode, serde_json::Value) {
        let resp = self
            .http
            .post(self.url(path))
            .json(&payload)
            .send()
            .await
            .expect("request reaches server");
        let status = resp.status();
        let body: serde_json::Value = resp.json().await.expect("body is JSON");
        (status, body)
    }

    /// PUT a JSON body and decode the JSON reply (the queue overlay).
    pub async fn put_json(
        &self,
        path: &str,
        payload: serde_json::Value,
    ) -> (reqwest::StatusCode, serde_json::Value) {
        let resp = self
            .http
            .put(self.url(path))
            .json(&payload)
            .send()
            .await
            .expect("request reaches server");
        let status = resp.status();
        let body: serde_json::Value = resp.json().await.expect("body is JSON");
        (status, body)
    }

    /// PUT a JSON body and report only the status (issue #469). An axum
    /// body-descriptor rejection answers with a plain-text 422, so a pin
    /// on a rejected payload must not try to decode the body.
    pub async fn put_for_status(
        &self,
        path: &str,
        payload: serde_json::Value,
    ) -> reqwest::StatusCode {
        self.http
            .put(self.url(path))
            .json(&payload)
            .send()
            .await
            .expect("request reaches server")
            .status()
    }

    /// POST a JSON body and report only the status (issue #472). An axum
    /// body-descriptor rejection answers with a plain-text 422, so a pin
    /// on a rejected payload must not try to decode the body.
    pub async fn post_for_status(
        &self,
        path: &str,
        payload: serde_json::Value,
    ) -> reqwest::StatusCode {
        self.http
            .post(self.url(path))
            .json(&payload)
            .send()
            .await
            .expect("request reaches server")
            .status()
    }

    /// DELETE with no body and decode the JSON reply (the override
    /// removal endpoint).
    pub async fn delete_json(&self, path: &str) -> (reqwest::StatusCode, serde_json::Value) {
        let resp = self
            .http
            .delete(self.url(path))
            .send()
            .await
            .expect("request reaches server");
        let status = resp.status();
        let body: serde_json::Value = resp.json().await.expect("body is JSON");
        (status, body)
    }

    /// PATCH a JSON body and decode the JSON reply (the log-level control).
    pub async fn patch_json(
        &self,
        path: &str,
        payload: serde_json::Value,
    ) -> (reqwest::StatusCode, serde_json::Value) {
        let resp = self
            .http
            .patch(self.url(path))
            .json(&payload)
            .send()
            .await
            .expect("request reaches server");
        let status = resp.status();
        let body: serde_json::Value = resp.json().await.expect("body is JSON");
        (status, body)
    }
}

/// Files deliberately unreadable bytes at a record's path — the one way
/// a fixture asks the review surface to report a record as unreadable
/// (issue #470). The bytes parse as no record shape, so every reader
/// reports a JSON parse error naming that path instead of an empty
/// record. The helper creates the parent directory, so the call site
/// states only which record it wants unreadable.
pub fn file_unreadable_record_bytes(path: &std::path::Path) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("parent dir for unreadable record bytes");
    }
    std::fs::write(path, "{ not json").expect("unreadable record bytes filed");
}

/// The pipeline-view row for one binary, from a live `/api/pipeline` body.
/// Applied-wait predicates use it to name the row whose event they await.
pub fn row_named<'a>(view: &'a serde_json::Value, binary: &str) -> Option<&'a serde_json::Value> {
    view["binaries"]
        .as_array()
        .expect("binaries is an array")
        .iter()
        .find(|b| b["binary"] == binary)
}

/// The conformance row for `binary` in a `/api/dashboard` payload.
pub fn conformance_row(body: &serde_json::Value, binary: &str) -> serde_json::Value {
    body["dashboard"]["conformance"]
        .as_array()
        .expect("conformance is an array")
        .iter()
        .find(|row| row["binary"] == binary)
        .unwrap_or_else(|| panic!("the conformance row for {binary} rides the model"))
        .clone()
}

// ─────────────────────────────────────────────────────────────
// Test fixture setup
// ─────────────────────────────────────────────────────────────

/// A fixture that creates a temporary git repository with sample
/// translation data (branches, patches, baselines, classifications)
/// so the web server has real data to serve.
#[derive(Clone)]
pub struct TestFixture {
    /// Shared so an `_on` boot variant can serve the same repository
    /// from a second world (a server restart); the directory is removed
    /// when the last holder drops.
    dir: std::sync::Arc<tempfile::TempDir>,
}

impl TestFixture {
    pub fn new() -> Self {
        let dir = tempfile::tempdir().expect("create temp dir");

        // Initialise a bare-bones git repo with a README on `main`.
        let config = InitConfig {
            author_name: "Calxgloss Test".into(),
            author_email: "test@calxgloss.test".into(),
            committer_name: None,
            committer_email: None,
        };
        let git = GitManager::init_repo(dir.path(), Some(config)).expect("init git repo");

        // We need the working tree checked out to `main` so that
        // branches can be created with files on them.
        Self::create_sample_data(&git);

        Self {
            dir: std::sync::Arc::new(dir),
        }
    }

    /// The fixture's repository path, for tests filing record fixtures
    /// into it.
    pub fn repo_path(&self) -> PathBuf {
        self.dir.path().to_path_buf()
    }

    /// A fixture repo where `re/game_logic.dll/DrawSpritev1` is merged
    /// into main and `re/game_logic.dll/DrawSpritev2` edits the same
    /// file from the same base — so accepting v2 hits a merge conflict
    /// (issue #83; the accept-conflict target boots its world over this
    /// fixture, issue #478).
    // Dead inside the e2e test binary, which builds no conflicting repo:
    // the accept-conflict target is the one that calls this writer.
    #[allow(dead_code)]
    pub fn with_conflicting_attempts() -> Self {
        let dir = tempfile::tempdir().expect("temp dir");
        let git = GitManager::init_repo(dir.path(), None).expect("init git repo");

        let branch_v1 = GitBranch::new("game_logic.dll", "DrawSprite", 1).expect("v1 branch name");
        git.create_branch("game_logic.dll", "DrawSprite", 1, None)
            .expect("create v1 branch");
        std::fs::write(dir.path().join("shared.rs"), "// version 1").expect("write v1 file");
        git.commit(&branch_v1, "attempt 1 edits shared", &["shared.rs"])
            .expect("commit v1");

        // v2 branches off the same base (create_branch always starts from
        // main, which v1 has not merged into yet).
        let branch_v2 = GitBranch::new("game_logic.dll", "DrawSprite", 2).expect("v2 branch name");
        git.create_branch("game_logic.dll", "DrawSprite", 2, None)
            .expect("create v2 branch");
        std::fs::write(dir.path().join("shared.rs"), "// version 2").expect("write v2 file");
        git.commit(&branch_v2, "attempt 2 edits shared", &["shared.rs"])
            .expect("commit v2");

        // v1 lands on main first, making v2 unmergeable.
        git.merge_to_main(&branch_v1).expect("merge v1");

        Self {
            dir: std::sync::Arc::new(dir),
        }
    }

    /// Creates sample data the DashboardBuilder can read:
    /// - A translation branch with a small file committed on it
    /// - A patch record (so the unit has attempt history)
    /// - A baseline file (so the unit has test data)
    /// - A classification JSON
    /// - A shim branch that's merged into main
    fn create_sample_data(git: &GitManager) {
        // 1. A classification record for `game_logic.dll`
        let classify_dir = git.repo_path().join("re").join("classify");
        std::fs::create_dir_all(&classify_dir).unwrap();
        std::fs::write(
            classify_dir.join("game_logic.dll.json"),
            serde_json::json!({
                "category": "ProjectSpecific",
                "strategy": "reverse_engineer",
                "exported_symbols": 24,
                "imported_symbols": 12
            })
            .to_string(),
        )
        .unwrap();

        // Also classify `d3d9.dll` as a crate-replacement target
        std::fs::write(
            classify_dir.join("d3d9.dll.json"),
            serde_json::json!({
                "category": "MicrosoftSdk",
                "strategy": "crate_replacement",
                "crate": "wgpu",
                "exported_symbols": 100,
                "imported_symbols": 5
            })
            .to_string(),
        )
        .unwrap();

        // 2. Create a shim branch `re/shim/wgpu` with a file and merge it into main.
        {
            let shim_branch = GitBranch::new("d3d9.dll", "wgpu", 1).unwrap();
            git.create_branch("d3d9.dll", "wgpu", 1, None).unwrap();

            let shim_file = "src/d3d9_shim.rs";
            std::fs::create_dir_all(git.repo_path().join("src")).unwrap();
            std::fs::write(
                git.repo_path().join(shim_file),
                "// wgpu shim layer for d3d9",
            )
            .unwrap();
            git.commit(&shim_branch, "Add d3d9 shim layer", &[shim_file])
                .unwrap();
            git.merge_to_main(&shim_branch).unwrap();
        }

        // 3. Create a PAL trait branch `re/pal/GraphicsDevice` and merge it.
        {
            let pal_branch = GitBranch::new("pal", "GraphicsDevice", 1).unwrap();
            git.create_branch("pal", "GraphicsDevice", 1, None).unwrap();

            let pal_file = "src/pal/graphics.rs";
            std::fs::create_dir_all(git.repo_path().join("src").join("pal")).unwrap();
            std::fs::write(
                git.repo_path().join(pal_file),
                "// GraphicsDevice PAL trait",
            )
            .unwrap();
            git.commit(&pal_branch, "Add GraphicsDevice PAL trait", &[pal_file])
                .unwrap();
            git.merge_to_main(&pal_branch).unwrap();
        }

        // 4. Create a translation branch `re/game_logic.dll/DrawPrimitivev1`
        //    with a Rust source file.
        {
            let branch = GitBranch::new("game_logic.dll", "DrawPrimitive", 1).unwrap();
            git.create_branch("game_logic.dll", "DrawPrimitive", 1, None)
                .unwrap();

            let src_file = "src/draw_primitive.rs";
            std::fs::create_dir_all(git.repo_path().join("src")).unwrap();
            std::fs::write(
                git.repo_path().join(src_file),
                r#"/// Translated DrawPrimitive function.
/// Maps DirectX9 DrawPrimitive to wgpu encoder.draw().
pub fn draw_primitive(encoder: &mut wgpu::CommandEncoder, _args: &[u8]) {
    // 47 assembly instructions → 12 lines of Rust
    let _ = encoder;
}
"#,
            )
            .unwrap();
            git.commit(&branch, "Translate DrawPrimitive to wgpu", &[src_file])
                .unwrap();
            git.merge_to_main(&branch).unwrap();

            // Create a v2 branch that failed (for attempt history)
            let branch_v2 = GitBranch::new("game_logic.dll", "DrawPrimitive", 2).unwrap();
            git.create_branch("game_logic.dll", "DrawPrimitive", 2, None)
                .unwrap();

            let src_file_v2 = "src/draw_primitive_v2.rs";
            std::fs::create_dir_all(git.repo_path().join("src")).ok();
            std::fs::write(
                git.repo_path().join(src_file_v2),
                r#"/// Attempt 2 — wrong shader constant mapping
pub fn draw_primitive_v2(_encoder: &mut wgpu::CommandEncoder) {
    // buggy implementation
}
"#,
            )
            .unwrap();
            git.commit(
                &branch_v2,
                "Retry DrawPrimitive — fix shader constants",
                &[src_file_v2],
            )
            .unwrap();
        }

        // 5. A second translation: `re/game_logic.dll/UpdateScenev1` (accepted/merged).
        {
            let branch = GitBranch::new("game_logic.dll", "UpdateScene", 1).unwrap();
            git.create_branch("game_logic.dll", "UpdateScene", 1, None)
                .unwrap();

            let src_file = "src/update_scene.rs";
            std::fs::write(
                git.repo_path().join(src_file),
                r#"/// UpdateScene — full translation
pub fn update_scene(world: &mut World) {
    world.update_physics();
    world.update_ai();
}
"#,
            )
            .unwrap();
            git.commit(&branch, "Translate UpdateScene", &[src_file])
                .unwrap();
            // Merge this one so it appears as "accepted"
            git.merge_to_main(&branch).unwrap();
        }

        // 6. Create a patch record for game_logic.dll/DrawPrimitive v1.
        let patch_dir = git
            .repo_path()
            .join("re")
            .join("patches")
            .join("game_logic.dll")
            .join("DrawPrimitive");
        std::fs::create_dir_all(&patch_dir).unwrap();
        let patch_record = serde_json::json!({
            "binary": "game_logic.dll",
            "function": "DrawPrimitive",
            "attempt": 1,
            "branch_name": "re/game_logic.dll/DrawPrimitivev1",
            "committed_at": "2025-09-28T10:00:00Z",
            "error_message": "",
            "compilation_errors": [],
            "test_failures": [],
            "commit_hash": "abc123"
        });
        std::fs::write(
            patch_dir.join("v1.json"),
            serde_json::to_string_pretty(&patch_record).unwrap(),
        )
        .unwrap();

        // Patch record for v2 (this one had compile errors).
        let patch_record_v2 = serde_json::json!({
            "binary": "game_logic.dll",
            "function": "DrawPrimitive",
            "attempt": 2,
            "branch_name": "re/game_logic.dll/DrawPrimitivev2",
            "committed_at": "2025-09-28T11:30:00Z",
            "error_message": "type mismatch in shader constant",
            "compilation_errors": ["mismatched types"],
            "test_failures": ["shader_constant_map_wrong"],
            "commit_hash": "def456"
        });
        std::fs::write(
            patch_dir.join("v2.json"),
            serde_json::to_string_pretty(&patch_record_v2).unwrap(),
        )
        .unwrap();

        // 7. Create baseline test data for DrawPrimitive — in the exact
        //    `Vec<TestResult>` shape `calxgloss-testgen` persists, so the
        //    dashboard's baseline readers parse it (issue #67).
        let baseline_dir = git
            .repo_path()
            .join("re")
            .join("baseline")
            .join("game_logic.dll")
            .join("DrawPrimitive");
        std::fs::create_dir_all(&baseline_dir).unwrap();
        let baseline: Vec<TestResult> = [
            (
                serde_json::json!({"vertices": [1,2,3], "index": 0}),
                serde_json::json!(0),
            ),
            (
                serde_json::json!({"vertices": [], "index": 0}),
                serde_json::json!(0),
            ),
            (
                serde_json::json!({"vertices": [99], "index": -1}),
                serde_json::json!(-1),
            ),
        ]
        .into_iter()
        .map(|(inputs, expected)| baseline_result(inputs, expected, true))
        .collect();
        std::fs::write(
            baseline_dir.join("baseline.json"),
            serde_json::to_string_pretty(&baseline).unwrap(),
        )
        .unwrap();

        // 8. Baseline for UpdateScene
        let baseline_us = git
            .repo_path()
            .join("re")
            .join("baseline")
            .join("game_logic.dll")
            .join("UpdateScene");
        std::fs::create_dir_all(&baseline_us).unwrap();
        let baseline_us_data = vec![baseline_result(
            serde_json::json!({"delta_time": 0.016}),
            serde_json::json!(0),
            true,
        )];
        std::fs::write(
            baseline_us.join("baseline.json"),
            serde_json::to_string_pretty(&baseline_us_data).unwrap(),
        )
        .unwrap();

        // Switch HEAD back to main so the server process works correctly.
        let main_ref = git
            .repo()
            .find_branch("main", git2::BranchType::Local)
            .expect("main branch exists");
        let main_commit = main_ref.get().peel_to_commit().expect("main commit");
        let mut checkout_opts = git2::build::CheckoutBuilder::new();
        checkout_opts.force();
        git.repo()
            .set_head("refs/heads/main")
            .expect("set head to main");
        git.repo()
            .reset(
                main_commit.as_object(),
                git2::ResetType::Hard,
                Some(&mut checkout_opts),
            )
            .expect("reset to main");
    }
}

// ─────────────────────────────────────────────────────────────
// Server helpers
// ─────────────────────────────────────────────────────────────

/// One baseline `TestResult` in the exact shape `calxgloss-testgen`
/// persists to `re/baseline/{file}/{func}/baseline.json` — the observed
/// return equals the expected one when the test passed — so every reader
/// of the artifact parses it (issue #67).
fn baseline_result(
    inputs: serde_json::Value,
    expected: serde_json::Value,
    passed: bool,
) -> TestResult {
    TestResult {
        test_case: TestCase {
            inputs,
            expected_return: expected.clone(),
            expected_side_effects: Vec::new(),
            expected_api_calls: Vec::new(),
            origin: calxgloss_types::CaseOrigin::Generated,
            case_kind: None,
        },
        actual_return: expected,
        actual_side_effects: Vec::new(),
        actual_api_calls: Vec::new(),
        passed,
        error: None,
    }
}

/// The actions backend every booted world and the accept-conflict target
/// builds: a settings-backed backend over the fixture repository (issue
/// #327). The web review surface under test never posts a patch, so the
/// default LLM-less pass description is enough here. A patch request
/// against these routers would fail assembly, exactly what issue #327
/// specifies for a server started without LLM settings.
pub fn build_actions_state(fixture: &TestFixture) -> ActionsState {
    ActionsState::new(fixture.repo_path(), PipelineSpec::default())
}

/// The plain-serve world assembled the way [`build_router`] assembles it —
/// server state and review-surface reader, no actions backend, no
/// session manager, no live store. A test that drives a router handler
/// directly (the accept-conflict target's legacy `api_accept_unit` pin,
/// issue #478) boots this shape instead of spelling the wiring by hand.
// Dead inside the e2e test binary, whose tests always serve through a
// router: the accept-conflict target is the one that drives handlers here.
#[allow(dead_code)]
pub fn build_plain_combined_state(fixture: &TestFixture) -> CombinedState {
    let server = ServerState::new(fixture.repo_path());
    CombinedState {
        reader: ReviewSurfaceReader::new(fixture.repo_path(), None),
        server,
        manager: None,
        bridge: None,
        actions: None,
        progress: None,
    }
}

// ─────────────────────────────────────────────────────────────
// Binary classification overrides (issue #97, W2.8)
// ─────────────────────────────────────────────────────────────

/// File a classification record for one binary through the record
/// writer — the same `ClassificationRecord` shape the `classify`
/// command files, reasoning included — so the endpoints have a
/// recorded classification to report.
pub fn write_canned_classification_record(
    repo: &std::path::Path,
    binary: &str,
    category: DllCategory,
) {
    let record = ClassificationRecord {
        binary: binary.to_string(),
        category: Some(category),
        strategy: Some(serde_json::json!("ReverseEngineer")),
        exports_count: Some(10),
        imports_count: Some(4),
        crate_replacement: None,
        known_runtime: false,
        reason: Some(
            "import table matched no known library — treated as unknown third-party".to_string(),
        ),
    };
    calxgloss_types::save_classification_record(repo, &record)
        .expect("classification record filed");
}

// ─────────────────────────────────────────────────────────────
// Pipeline start & restart (issue #92, W2.3)
// ─────────────────────────────────────────────────────────────

// ─────────────────────────────────────────────────────────────
// Server lifecycle endpoint tests (issue #60)
// ─────────────────────────────────────────────────────────────

/// Counts global-subscriber events whose message is the test's probe
/// marker, to prove a `PATCH /api/server/log-level` change actually alters
/// the running process's verbosity — not just the reported string.
pub struct ProbeCountingLayer(pub std::sync::Arc<std::sync::atomic::AtomicUsize>);

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for ProbeCountingLayer {
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        struct MessageVisitor {
            message: String,
        }
        impl tracing::field::Visit for MessageVisitor {
            fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
                if field.name() == "message" {
                    self.message = value.to_string();
                }
            }
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                if field.name() == "message" {
                    self.message = format!("{value:?}");
                }
            }
        }

        let mut visitor = MessageVisitor {
            message: String::new(),
        };
        event.record(&mut visitor);
        if visitor.message == "log-level-probe" {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }
}

// ─── Queue overlay: manual order & priority (issue #74) ──────────────

/// Adds a second unmerged translation branch (`game_logic.dll/{function}`)
/// so the queue holds two active units at the same dependency depth — a
/// tie the overlay can break.
pub fn add_pending_translation(fixture: &TestFixture, function: &str) {
    let git = GitManager::open(&fixture.repo_path()).expect("open fixture repo");
    let branch = GitBranch::new("game_logic.dll", function, 1).expect("branch name");
    git.create_branch("game_logic.dll", function, 1, None)
        .expect("create branch");

    let src_file = format!("src/{}.rs", function.to_lowercase());
    std::fs::create_dir_all(fixture.repo_path().join("src")).expect("create src dir");
    std::fs::write(
        fixture.repo_path().join(&src_file),
        format!(
            "/// {function} — pending translation\npub fn {}() {{}}\n",
            function.to_lowercase()
        ),
    )
    .expect("write translation file");
    git.commit(
        &branch,
        &format!("Translate {function}"),
        &[src_file.as_str()],
    )
    .expect("commit branch");
}

/// The `binaries` row for one binary, by name.
pub fn binary_row<'a>(rows: &'a [serde_json::Value], name: &str) -> &'a serde_json::Value {
    rows.iter()
        .find(|r| r["binary"] == name)
        .unwrap_or_else(|| panic!("{name} row present in {rows:?}"))
}

// ─────────────────────────────────────────────────────────────
// Pipeline PAL-readiness summary (issue #243, part of #223)
// ─────────────────────────────────────────────────────────────

/// Seed the artifacts the pipeline PAL-readiness tests pin: disk
/// classification records routing d3d9.dll to PalMapping and game_logic.dll
/// to ReverseEngineer, per-function analysis artifacts under
/// `re/analysis/d3d9.dll/` recording DirectX and Win32Core API-call
/// categories, and a generated shared PAL crate under `scratch/pal/src/`
/// defining GraphicsDevice but not PlatformCore — the partially defined
/// trait set the summary must report honestly.
pub fn write_pipeline_pal_readiness_fixtures(fixture: &TestFixture) {
    for (binary, category, strategy) in [
        ("d3d9.dll", DllCategory::WindowsOs, "PalMapping"),
        (
            "game_logic.dll",
            DllCategory::ProjectSpecific,
            "ReverseEngineer",
        ),
    ] {
        calxgloss_types::save_classification_record(
            fixture.repo_path(),
            &ClassificationRecord {
                binary: binary.to_string(),
                category: Some(category),
                strategy: Some(serde_json::json!(strategy)),
                exports_count: Some(0),
                imports_count: Some(1),
                ..ClassificationRecord::default()
            },
        )
        .expect("classification record filed");
    }

    write_windows_api_artifact(
        fixture.repo_path().as_path(),
        "d3d9.dll",
        "CreateDevice",
        &[
            windows_api("Direct3DCreate9", ApiCategory::DirectX),
            windows_api("CreateFileA", ApiCategory::Win32Core),
        ],
    );
    write_windows_api_artifact(
        fixture.repo_path().as_path(),
        "d3d9.dll",
        "Present",
        &[windows_api(
            "IDXGISwapChain::Present",
            ApiCategory::DirectX11,
        )],
    );

    let pal_src = fixture.repo_path().join("scratch").join("pal").join("src");
    std::fs::create_dir_all(&pal_src).expect("scratch pal src dir");
    std::fs::write(
        pal_src.join("stub_content.rs"),
        "pub trait GraphicsDevice {\n    fn create_device(width: u32, height: u32) -> Self;\n}\n",
    )
    .expect("pal stub content written");
}

/// One Windows API call as a fixture record — no PAL mapping yet.
fn windows_api(name: &str, category: ApiCategory) -> WindowsApiCall {
    WindowsApiCall {
        name: name.to_string(),
        category,
        pal_mapping: String::new(),
    }
}

/// The per-function analysis artifact shape the pipeline's
/// `file_analysis_artifact` files under `re/analysis/{binary}/{function}.json`.
pub fn write_windows_api_artifact(
    repo_path: &std::path::Path,
    binary: &str,
    function: &str,
    apis: &[WindowsApiCall],
) {
    #[derive(serde::Serialize)]
    struct ApiArtifact<'a> {
        function_name: &'a str,
        windows_apis: &'a [WindowsApiCall],
    }
    calxgloss_types::save_json(
        &calxgloss_types::analysis_artifact_path(repo_path, binary, function),
        &ApiArtifact {
            function_name: function,
            windows_apis: apis,
        },
    )
    .expect("analysis artifact filed");
}

// ─────────────────────────────────────────────────────────────
// Pipeline time estimate + queue effort (issue #64)
// ─────────────────────────────────────────────────────────────

/// File a token-usage log through the record writer. When
/// `with_durations` is false the entries omit `duration_secs`, exactly
/// like logs written before issue #64, so the average stays unknown.
pub fn write_token_usage_log(fixture: &TestFixture, with_durations: bool) {
    let mut entries = Vec::new();
    for (attempt, tokens) in [(1usize, 4096usize), (2, 3072)] {
        let mut entry = token_usage_entry(
            "game_logic.dll",
            "DrawPrimitive",
            attempt as u32,
            if attempt == 1 {
                "initial"
            } else {
                "compile_fix"
            },
            tokens,
            attempt == 2,
            "",
            1767225600 + attempt as u64 * 300,
        );
        if with_durations {
            entry.duration_secs = Some(100 * attempt as u64);
        }
        entries.push(entry);
    }
    write_token_usage_fixture(fixture.repo_path().as_path(), &entries);
}

/// Like `write_canned_run_telemetry` but the token-usage entries include
/// durations (100s and 200s for DrawPrimitive's two attempts).
pub fn write_canned_run_telemetry_with_durations(fixture: &TestFixture) {
    let entries = [
        ("initial", "disassembly", 4096, false, 1),
        ("compile_fix", "with_tests", 3072, true, 2),
    ]
    .map(|(strategy, tier, tokens_used, success, attempt)| {
        let mut entry = token_usage_entry(
            "game_logic.dll",
            "DrawPrimitive",
            attempt,
            strategy,
            tokens_used,
            success,
            tier,
            1767225600 + (attempt - 1) as u64 * 300,
        );
        entry.duration_secs = Some(100 * attempt as u64);
        entry
    });
    write_token_usage_fixture(fixture.repo_path().as_path(), &entries);
}

// ─────────────────────────────────────────────────────────────
// Fault analytics (issue #125, W3.1)
// ─────────────────────────────────────────────────────────────

/// UTC day boundaries the fault fixtures bucket against: 2026-10-01 through
/// 2026-10-04, midnight. The trend endpoint buckets on these exact days.
pub const FAULT_DAY_1: u64 = 1_790_812_800; // 2026-10-01T00:00:00Z
pub const FAULT_DAY_4: u64 = 1_791_072_000; // 2026-10-04T00:00:00Z

/// One fault-log entry with every field spelled out — the fixture's exact
/// values are what the endpoint assertions pin.
pub fn fault_entry(
    binary: &str,
    function: &str,
    attempt: u32,
    strategy: &str,
    category: FaultCategory,
    severity: FaultSeverity,
    timestamp: u64,
) -> FaultEvent {
    // The category's Display label is its serde name (pinned in
    // calxgloss-types), so the description reads exactly as the old
    // canned body did.
    let kind = category.to_string();
    FaultEvent {
        binary: binary.into(),
        function: function.to_string(),
        attempt,
        strategy: strategy.to_string(),
        category,
        severity,
        description: format!("{kind} detected in {function}"),
        recovery: format!("recovery guidance for {function}"),
        timestamp,
        metadata: None,
    }
}

/// File a deterministic fault log through the record writer — the file
/// the analytics endpoints read on demand.
pub fn write_fault_log_fixture(repo_path: &std::path::Path, entries: &[FaultEvent]) {
    calxgloss_types::save_fault_log(
        repo_path,
        &FaultLog {
            entries: entries.to_vec(),
            trimmed: calxgloss_types::FaultTrim::default(),
        },
    )
    .expect("fault log filed");
}

/// The six-entry fixture both analytics tests share: three faults for
/// `game_logic.dll/DrawSprite` on 2026-10-01 and three for
/// `d3d9.dll/UpdateScene` on 2026-10-04 — leaving 10-02 and 10-03 as gap
/// days the trend must fill with honest zeros.
pub fn sample_fault_entries() -> Vec<FaultEvent> {
    vec![
        fault_entry(
            "game_logic.dll",
            "DrawSprite",
            1,
            "initial",
            FaultCategory::ContextWindowExceeded,
            FaultSeverity::Error,
            FAULT_DAY_1 + 60,
        ),
        fault_entry(
            "game_logic.dll",
            "DrawSprite",
            2,
            "compile_fix",
            FaultCategory::Hallucination,
            FaultSeverity::Error,
            FAULT_DAY_1 + 120,
        ),
        fault_entry(
            "game_logic.dll",
            "DrawSprite",
            3,
            "retry",
            FaultCategory::ResourceExhaustion,
            FaultSeverity::Warning,
            FAULT_DAY_1 + 180,
        ),
        fault_entry(
            "d3d9.dll",
            "UpdateScene",
            1,
            "initial",
            FaultCategory::InfiniteLoop,
            FaultSeverity::Critical,
            FAULT_DAY_4 + 60,
        ),
        fault_entry(
            "d3d9.dll",
            "UpdateScene",
            2,
            "compile_fix",
            FaultCategory::Hallucination,
            FaultSeverity::Error,
            FAULT_DAY_4 + 120,
        ),
        fault_entry(
            "d3d9.dll",
            "UpdateScene",
            3,
            "retry",
            FaultCategory::SlowResponse,
            FaultSeverity::Warning,
            FAULT_DAY_4 + 180,
        ),
    ]
}

// ─────────────────────────────────────────────────────────────
// Token usage analytics (issue #126, W3.2)
// ─────────────────────────────────────────────────────────────

/// One token-usage entry with every field spelled out — the fixture's
/// exact values are what the endpoint assertions pin. An empty tier omits
/// `context_tier` entirely, the shape entries written before tier tracking
/// (and by older versions) have on disk.
// One parameter per fixture field — the whole point is spelling every
// field out, so grouping them into a struct would only hide the values.
#[allow(clippy::too_many_arguments)]
pub fn token_usage_entry(
    binary: &str,
    function: &str,
    attempt: u32,
    strategy: &str,
    tokens: usize,
    success: bool,
    tier: &str,
    timestamp: u64,
) -> TokenUsageEntry {
    TokenUsageEntry {
        binary: binary.into(),
        function: function.to_string(),
        attempt,
        strategy: strategy.to_string(),
        tokens_used: tokens,
        success,
        timestamp,
        context_tier: tier.to_string(),
        duration_secs: None,
    }
}

/// File a deterministic token usage log through the record writer — the
/// file the analytics endpoints read on demand.
pub fn write_token_usage_fixture(repo_path: &std::path::Path, entries: &[TokenUsageEntry]) {
    calxgloss_types::save_token_usage_log(
        repo_path,
        &TokenUsageLog {
            entries: entries.to_vec(),
            trimmed: calxgloss_types::TokenUsageTrim::default(),
        },
    )
    .expect("token log filed");
}

/// The five-entry fixture the exact-JSON tests share: three attempts on
/// `game_logic.dll/DrawSprite` on 2026-10-01 and two on
/// `d3d9.dll/UpdateScene` on 2026-10-04. Token totals divide exactly
/// (15000/5000 of 20000) so percentage shares pin as clean floats, and the
/// 3000-token ties in the tier and strategy breakdowns pin the alphabetical
/// tie rule.
pub fn sample_token_usage_entries() -> Vec<TokenUsageEntry> {
    vec![
        token_usage_entry(
            "game_logic.dll",
            "DrawSprite",
            1,
            "initial",
            4000,
            false,
            "stub",
            FAULT_DAY_1 + 60,
        ),
        token_usage_entry(
            "game_logic.dll",
            "DrawSprite",
            2,
            "compile_fix",
            3000,
            true,
            "disassembly",
            FAULT_DAY_1 + 120,
        ),
        token_usage_entry(
            "game_logic.dll",
            "DrawSprite",
            3,
            "escalate",
            8000,
            false,
            "module_context",
            FAULT_DAY_1 + 180,
        ),
        token_usage_entry(
            "d3d9.dll",
            "UpdateScene",
            1,
            "initial",
            2000,
            true,
            "stub",
            FAULT_DAY_4 + 60,
        ),
        token_usage_entry(
            "d3d9.dll",
            "UpdateScene",
            2,
            "retry",
            3000,
            false,
            "",
            FAULT_DAY_4 + 120,
        ),
    ]
}

// ─────────────────────────────────────────────────────────────
// Strategy analytics (issue #127, W3.3)
// ─────────────────────────────────────────────────────────────

/// One prompt-strategy entry with every field spelled out — the fixture's
/// exact values are what the endpoint assertions pin.
pub fn strategy_entry(
    binary: &str,
    dll_category: DllCategory,
    strategy: &str,
    success: bool,
    attempt: u32,
    timestamp: u64,
) -> PromptStrategyEntry {
    PromptStrategyEntry {
        binary: binary.into(),
        dll_category,
        retry_strategy: strategy.to_string(),
        success,
        attempt,
        timestamp,
    }
}

/// File a deterministic prompt-strategy log through the record writer —
/// the file the analytics endpoints read on demand.
pub fn write_strategy_fixture(repo_path: &std::path::Path, entries: &[PromptStrategyEntry]) {
    calxgloss_types::save_prompt_strategy_log(
        repo_path,
        &PromptStrategyLog {
            entries: entries.to_vec(),
            trimmed: calxgloss_types::PromptStrategyTrim::default(),
        },
    )
    .expect("prompt-strategy log filed");
}

/// The six-entry fixture the exact-JSON tests share: four attempts on
/// `game_logic.dll/DrawSprite` (ProjectSpecific) on 2026-10-01 and two on
/// `d3d9.dll/UpdateScene` (KnownThirdParty) on 2026-10-04. Success counts
/// divide exactly (2/4 and 1/2) so pass rates pin as clean floats, and
/// `initial`/`retry` tie at two attempts to pin the alphabetical tie rule.
pub fn sample_strategy_entries() -> Vec<PromptStrategyEntry> {
    vec![
        strategy_entry(
            "game_logic.dll",
            DllCategory::ProjectSpecific,
            "initial",
            false,
            1,
            FAULT_DAY_1 + 60,
        ),
        strategy_entry(
            "game_logic.dll",
            DllCategory::ProjectSpecific,
            "compile_fix",
            true,
            2,
            FAULT_DAY_1 + 120,
        ),
        strategy_entry(
            "game_logic.dll",
            DllCategory::ProjectSpecific,
            "escalate",
            false,
            3,
            FAULT_DAY_1 + 180,
        ),
        strategy_entry(
            "game_logic.dll",
            DllCategory::ProjectSpecific,
            "retry",
            true,
            4,
            FAULT_DAY_1 + 240,
        ),
        strategy_entry(
            "d3d9.dll",
            DllCategory::KnownThirdParty,
            "initial",
            true,
            1,
            FAULT_DAY_4 + 60,
        ),
        strategy_entry(
            "d3d9.dll",
            DllCategory::KnownThirdParty,
            "retry",
            false,
            2,
            FAULT_DAY_4 + 120,
        ),
    ]
}

// ─────────────────────────────────────────────────────────────
// LLM performance metrics (issue #128, W3.4)
// ─────────────────────────────────────────────────────────────

/// One token-usage entry with a recorded attempt duration — the same
/// shape as `token_usage_entry` plus `duration_secs`. `duration: None`
/// writes the pre-duration-tracking shape (the field omitted entirely),
/// which the percentile math must exclude rather than count as zero.
// One parameter per fixture field — the whole point is spelling every
// field out, so grouping them into a struct would only hide the values.
#[allow(clippy::too_many_arguments)]
pub fn llm_metrics_token_entry(
    binary: &str,
    function: &str,
    attempt: u32,
    strategy: &str,
    tokens: usize,
    success: bool,
    tier: &str,
    timestamp: u64,
    duration: Option<u64>,
) -> TokenUsageEntry {
    let mut entry = token_usage_entry(
        binary, function, attempt, strategy, tokens, success, tier, timestamp,
    );
    entry.duration_secs = duration;
    entry
}

/// One resource-exhaustion fault with the `metadata.reason` the
/// pipeline's `ResourceExhaustionFault` writes — the timeout kind is what
/// the metrics endpoints count, and the overloaded kind is what they must
/// leave out.
pub fn resource_exhaustion_fault_entry(
    binary: &str,
    function: &str,
    attempt: u32,
    strategy: &str,
    reason: &str,
    timestamp: u64,
) -> FaultEvent {
    FaultEvent {
        binary: binary.into(),
        function: function.to_string(),
        attempt,
        strategy: strategy.to_string(),
        category: FaultCategory::ResourceExhaustion,
        severity: FaultSeverity::Warning,
        description: format!("{reason} — resource exhaustion in {function}"),
        recovery: "switch to a smaller/faster model for this translation".to_string(),
        timestamp,
        metadata: Some(serde_json::json!({ "reason": reason, "elapsed_secs": 300 })),
    }
}

/// Writes the deterministic fixture pair the metrics tests share: nine
/// token-usage attempts (four on `game_logic.dll/DrawSprite` starting
/// 2026-10-01, five on 2026-10-04) and four faults. Seven attempts
/// recorded durations — 10/20/30/40/50/60/70 seconds, so nearest-rank
/// P50/P95/P99 pin as 40/70/70 — and two predate duration tracking,
/// excluded from the percentiles, never counted as zero. The faults hold exactly
/// two timeout-kind resource-exhaustion events (one per fixture day),
/// one overloaded resource-exhaustion event that must not count as a
/// timeout, and one slow-response fault that must not count either.
pub fn write_llm_metrics_fixtures(repo_path: &std::path::Path) {
    write_token_usage_fixture(
        repo_path,
        &[
            llm_metrics_token_entry(
                "game_logic.dll",
                "DrawSprite",
                1,
                "initial",
                4000,
                false,
                "stub",
                FAULT_DAY_1 + 60,
                Some(10),
            ),
            llm_metrics_token_entry(
                "game_logic.dll",
                "DrawSprite",
                2,
                "compile_fix",
                3000,
                true,
                "stub",
                FAULT_DAY_1 + 120,
                Some(30),
            ),
            llm_metrics_token_entry(
                "game_logic.dll",
                "DrawSprite",
                3,
                "escalate",
                8000,
                false,
                "stub",
                FAULT_DAY_1 + 180,
                None,
            ),
            llm_metrics_token_entry(
                "game_logic.dll",
                "DrawSprite",
                4,
                "retry",
                3000,
                true,
                "disassembly",
                FAULT_DAY_1 + 240,
                Some(50),
            ),
            llm_metrics_token_entry(
                "game_logic.dll",
                "DrawSprite",
                5,
                "initial",
                2000,
                true,
                "disassembly",
                FAULT_DAY_4 + 300,
                None,
            ),
            llm_metrics_token_entry(
                "d3d9.dll",
                "UpdateScene",
                1,
                "initial",
                2000,
                true,
                "",
                FAULT_DAY_4 + 60,
                Some(20),
            ),
            llm_metrics_token_entry(
                "d3d9.dll",
                "UpdateScene",
                2,
                "retry",
                3000,
                false,
                "",
                FAULT_DAY_4 + 120,
                Some(40),
            ),
            llm_metrics_token_entry(
                "d3d9.dll",
                "UpdateScene",
                3,
                "initial",
                5000,
                true,
                "module_context",
                FAULT_DAY_4 + 180,
                Some(60),
            ),
            llm_metrics_token_entry(
                "d3d9.dll",
                "UpdateScene",
                4,
                "compile_fix",
                6000,
                true,
                "module_context",
                FAULT_DAY_4 + 240,
                Some(70),
            ),
        ],
    );
    write_fault_log_fixture(
        repo_path,
        &[
            resource_exhaustion_fault_entry(
                "game_logic.dll",
                "DrawSprite",
                3,
                "escalate",
                "timeout",
                FAULT_DAY_1 + 200,
            ),
            resource_exhaustion_fault_entry(
                "game_logic.dll",
                "DrawSprite",
                4,
                "retry",
                "overloaded",
                FAULT_DAY_1 + 260,
            ),
            fault_entry(
                "d3d9.dll",
                "UpdateScene",
                2,
                "retry",
                FaultCategory::SlowResponse,
                FaultSeverity::Warning,
                FAULT_DAY_4 + 150,
            ),
            resource_exhaustion_fault_entry(
                "d3d9.dll",
                "UpdateScene",
                3,
                "initial",
                "timeout",
                FAULT_DAY_4 + 210,
            ),
        ],
    );
}

/// Seed the full-shape persisted history the exact-JSON test pins:
/// classification records carrying the `binary` field the artifact reader
/// requires (overwriting the fixture's minimal ones), a corrupt record
/// that must be skipped, a classification override on `d3d9.dll`, and a
/// token-usage log with a differently-spelled binary to pin the
/// case-insensitive join.
pub fn write_binaries_list_fixtures(fixture: &TestFixture) {
    calxgloss_types::save_classification_record(
        fixture.repo_path(),
        &ClassificationRecord {
            binary: "game_logic.dll".to_string(),
            category: Some(DllCategory::ProjectSpecific),
            strategy: Some(serde_json::json!("ReverseEngineer")),
            exports_count: Some(24),
            imports_count: Some(12),
            crate_replacement: None,
            known_runtime: false,
            reason: Some("project-built binary — reverse engineer from disassembly".to_string()),
        },
    )
    .expect("game_logic classification filed");
    calxgloss_types::save_classification_record(
        fixture.repo_path(),
        &ClassificationRecord {
            binary: "d3d9.dll".to_string(),
            category: Some(DllCategory::MicrosoftSdk),
            strategy: Some(serde_json::json!("CrateReplacement")),
            exports_count: Some(100),
            imports_count: Some(5),
            crate_replacement: Some("wgpu".to_string()),
            known_runtime: false,
            reason: Some("Direct3D 9 — replaced with wgpu behind a shim layer".to_string()),
        },
    )
    .expect("d3d9 classification filed");
    // A corrupt record is no record at all — it must not become a row.
    file_unreadable_record_bytes(&calxgloss_types::classification_record_path(
        fixture.repo_path(),
        &"broken.dll".into(),
    ));

    // The persisted override layer: it sets d3d9.dll to KnownThirdParty
    // with a different target crate — exact-key match on the filename.
    calxgloss_types::save_classification_overrides(
        fixture.repo_path(),
        &ClassificationOverrides {
            overrides: [(
                "d3d9.dll".to_string(),
                BinaryClassificationOverride {
                    category: DllCategory::KnownThirdParty,
                    crate_replacement: Some("wgpu-rs".to_string()),
                    known_runtime: false,
                },
            )]
            .into(),
        },
    )
    .expect("override record filed");

    // Token totals: game_logic.dll 100 + 50, plus a 25-token entry under
    // a different spelling that must join into the same row; d3d9.dll 75;
    // other.dll 999 belongs to no row — no classification record names it.
    write_token_usage_fixture(
        &fixture.repo_path(),
        &[
            token_usage_entry(
                "game_logic.dll",
                "DrawPrimitive",
                1,
                "initial",
                100,
                false,
                "",
                1,
            ),
            token_usage_entry(
                "game_logic.dll",
                "UpdateScene",
                1,
                "initial",
                50,
                true,
                "",
                2,
            ),
            token_usage_entry(
                "GAME_LOGIC.DLL",
                "DrawPrimitive",
                2,
                "escalate",
                25,
                true,
                "",
                3,
            ),
            token_usage_entry("d3d9.dll", "CreateDevice", 1, "initial", 75, true, "", 4),
            token_usage_entry("other.dll", "Whatever", 1, "initial", 999, true, "", 5),
        ],
    );
}

// ── Binaries shim tracker API (issue #133, W4.3) ───────────────────────

/// Seed the shim artifacts and shim branches the shim-tracker tests
/// pin, on top of `write_binaries_list_fixtures`: readable mappings and
/// a verification result for `d3d9.dll` (whose in-force override names
/// `wgpu-rs`) with the `re/shim/wgpu-rs` branch merged into main, and a
/// crate-replacement `fmod.dll` whose shim was generated but whose
/// `re/shim/fmod-rs` branch a reviewer sent back.
pub fn write_shim_tracker_fixtures(fixture: &TestFixture) {
    calxgloss_types::save_classification_record(
        fixture.repo_path(),
        &ClassificationRecord {
            binary: "fmod.dll".to_string(),
            category: Some(DllCategory::KnownThirdParty),
            strategy: Some(serde_json::json!("CrateReplacement")),
            exports_count: Some(40),
            imports_count: Some(3),
            crate_replacement: Some("fmod-rs".to_string()),
            known_runtime: false,
            reason: Some(
                "audio middleware — replaced with fmod-rs behind a shim layer".to_string(),
            ),
        },
    )
    .expect("fmod classification filed");

    // The shim pipeline's persisted artifacts for d3d9.dll, filed where
    // the record module says they live: a `ShimLayer` mappings document
    // and a `ShimVerificationResult` under `re/shims/d3d9.dll/`.
    let mut d3d9_shim = ShimLayer::new("d3d9.dll".to_string(), "wgpu-rs".to_string());
    d3d9_shim.add_mapping(ShimApiMapping::new(
        "Present".to_string(),
        "wgpu::Queue::submit".to_string(),
        ComplexityScore::Low,
    ));
    d3d9_shim.add_mapping(ShimApiMapping::new(
        "Clear".to_string(),
        "wgpu::RenderPass::clear_color".to_string(),
        ComplexityScore::Low,
    ));
    let d3d9_shim_dir = shim_artifacts_dir(fixture.repo_path()).join("d3d9.dll");
    calxgloss_types::save_json(&d3d9_shim_dir.join(SHIM_MAPPINGS_FILE), &d3d9_shim)
        .expect("shim mappings filed");
    calxgloss_types::save_json(
        &d3d9_shim_dir.join(SHIM_VERIFICATION_FILE),
        &ShimVerificationResult {
            compiled: true,
            compilation_errors: Vec::new(),
            compilation_warnings: Vec::new(),
            tests_passed: 7,
            tests_total: 8,
            edge_tests_passed: 2,
            edge_tests_total: 2,
            failed_tests: Vec::new(),
            mapping_results: Vec::new(),
        },
    )
    .expect("shim verification filed");

    // The dashboard's branch model: `re/shim/wgpu-rs` merged into main
    // (the crate the d3d9.dll override in force names), and
    // `re/shim/fmod-rs` unmerged with a reviewer's send-back record —
    // fmod.dll's generated artifacts still on disk (generated, then sent back).
    let mut fmod_shim = ShimLayer::new("fmod.dll".to_string(), "fmod-rs".to_string());
    fmod_shim.add_mapping(ShimApiMapping::new(
        "FSOUND_Init".to_string(),
        "fmod_rs::init".to_string(),
        ComplexityScore::Low,
    ));
    fmod_shim.add_mapping(ShimApiMapping::new(
        "FSOUND_Close".to_string(),
        "fmod_rs::close".to_string(),
        ComplexityScore::Low,
    ));
    calxgloss_types::save_json(
        &shim_artifacts_dir(fixture.repo_path())
            .join("fmod.dll")
            .join(SHIM_MAPPINGS_FILE),
        &fmod_shim,
    )
    .expect("fmod shim mappings filed");
    let git = GitManager::open(&fixture.repo_path()).expect("open fixture repo");
    {
        let branch = GitBranch::new("shim", "wgpu-rs", 1).expect("wgpu-rs shim branch name");
        git.create_branch("shim", "wgpu-rs", 1, None)
            .expect("wgpu-rs branch created");
        let shim_file = "src/wgpu_rs_shim.rs";
        std::fs::create_dir_all(git.repo_path().join("src")).expect("src dir");
        std::fs::write(git.repo_path().join(shim_file), "// wgpu-rs shim layer")
            .expect("wgpu-rs shim written");
        git.commit(&branch, "Add wgpu-rs shim layer", &[shim_file])
            .expect("wgpu-rs shim committed");
        git.merge_to_main(&branch).expect("wgpu-rs branch merged");
    }
    {
        let branch = GitBranch::new("shim", "fmod-rs", 1).expect("fmod-rs shim branch name");
        git.create_branch("shim", "fmod-rs", 1, None)
            .expect("fmod-rs branch created");
        let shim_file = "src/fmod_rs_shim.rs";
        std::fs::write(git.repo_path().join(shim_file), "// fmod-rs shim layer")
            .expect("fmod-rs shim written");
        git.commit(&branch, "Add fmod-rs shim layer", &[shim_file])
            .expect("fmod-rs shim committed");
        // The reviewer's send-back verdict, filed through the git
        // manager's own rejection record, as `reject_branch` persists it.
        git.reject_branch(&branch, "mapping table incomplete — send back")
            .expect("send-back record filed");
    }
}

// ── Binaries PAL tracker API (issue #134, W4.4) ────────────────────────

/// Seed the artifacts the PAL-tracker tests pin, on top of
/// `write_binaries_list_fixtures`: per-function analysis artifacts under
/// `re/analysis/d3d9.dll/` whose `windows_apis` carry categories
/// (DirectX, DirectX11, Win32Core — one corrupt artifact contributing
/// nothing), the generated shared PAL crate under `scratch/pal/src/`
/// defining `GraphicsDevice` but not `PlatformCore`, and the binary's
/// generated shim source under `re/shims/d3d9.dll/shim.rs` defining no
/// trait at all.
pub fn write_pal_tracker_fixtures(fixture: &TestFixture) {
    write_windows_api_artifact(
        fixture.repo_path().as_path(),
        "d3d9.dll",
        "CreateDevice",
        &[
            windows_api_with_mapping("Direct3DCreate9", ApiCategory::DirectX, "wgpu::Instance"),
            windows_api_with_mapping("CreateFileA", ApiCategory::Win32Core, "std::fs::File::open"),
        ],
    );
    write_windows_api_artifact(
        fixture.repo_path().as_path(),
        "d3d9.dll",
        "Present",
        &[windows_api_with_mapping(
            "IDXGISwapChain::Present",
            ApiCategory::DirectX11,
            "wgpu::Surface::present",
        )],
    );
    // A corrupt function artifact is no artifact: it gives no category.
    file_unreadable_record_bytes(&calxgloss_types::analysis_artifact_path(
        fixture.repo_path(),
        "d3d9.dll",
        "broken",
    ));

    // The generated shared PAL crate that the verifier writes under
    // `scratch/pal/`: it defines GraphicsDevice (and AudioDevice) but not
    // PlatformCore.
    let pal_src = fixture.repo_path().join("scratch").join("pal").join("src");
    std::fs::create_dir_all(&pal_src).expect("scratch pal src dir");
    std::fs::write(
        pal_src.join("stub_content.rs"),
        "pub trait GraphicsDevice {\n    fn create_device(width: u32, height: u32) -> Self;\n}\n\npub trait AudioDevice {\n    fn play(&mut self, samples: &[f32]);\n}\n",
    )
    .expect("pal stub content written");

    // The binary's generated shim source: functions, no trait definitions.
    let shim_dir = fixture
        .repo_path()
        .join("re")
        .join("shims")
        .join("d3d9.dll");
    std::fs::create_dir_all(&shim_dir).expect("d3d9 shim dir");
    std::fs::write(
        shim_dir.join("shim.rs"),
        "// generated shim layer\nunsafe fn present() {}\n",
    )
    .expect("shim source written");
}

/// Wait until a binaries-detail tracker's own text contains `needle`. The
/// panel draws the tracker before its read lands (issue #471), so the test
/// waits for the settled text instead of sleeping. `kind` is the tracker
/// family: "shim" or "pal".
pub async fn wait_for_tracker(tab: &DashboardTab, kind: &str, needle: &str) -> bool {
    let expr = format!(
        "document.querySelector('#binaries-table-body .binaries-detail-{kind} .binaries-{kind}-tracker')?.textContent.includes({needle:?}) === true"
    );
    tab.wait_for_bool(&expr).await
}
// ─────────────────────────────────────────────────────────────
// Unit process detail tests (issue #62)
// ─────────────────────────────────────────────────────────────

/// Writes canned run-telemetry artifacts for game_logic.dll/DrawPrimitive:
/// a token-usage log (2 attempts, escalated tiers), a fault log (2 faults),
/// and an analysis artifact (its tier rationale is read from there).
pub fn write_canned_run_telemetry(fixture: &TestFixture) {
    let token_log = [
        token_usage_entry(
            "game_logic.dll",
            "DrawPrimitive",
            1,
            "initial",
            4096,
            false,
            "disassembly",
            1767225600,
        ),
        token_usage_entry(
            "game_logic.dll",
            "DrawPrimitive",
            2,
            "compile_fix",
            3072,
            true,
            "with_tests",
            1767225900,
        ),
        token_usage_entry(
            "audio.dll",
            "PlaySample",
            1,
            "initial",
            150,
            true,
            "signature",
            1767226200,
        ),
    ];
    write_token_usage_fixture(fixture.repo_path().as_path(), &token_log);

    let fault_log = [
        FaultEvent {
            binary: "game_logic.dll".into(),
            function: "DrawPrimitive".into(),
            attempt: 1,
            strategy: "initial".into(),
            category: FaultCategory::ContextWindowExceeded,
            severity: FaultSeverity::Warning,
            description: "Prompt exceeded context window".into(),
            recovery: "escalate_context".into(),
            timestamp: 1767225660,
            metadata: None,
        },
        FaultEvent {
            binary: "game_logic.dll".into(),
            function: "DrawPrimitive".into(),
            attempt: 2,
            strategy: "compile_fix".into(),
            category: FaultCategory::Hallucination,
            severity: FaultSeverity::Error,
            description: "Output referenced unknown symbol".into(),
            recovery: "retry".into(),
            timestamp: 1767225960,
            metadata: None,
        },
        FaultEvent {
            binary: "audio.dll".into(),
            function: "PlaySample".into(),
            attempt: 1,
            strategy: "initial".into(),
            category: FaultCategory::SlowResponse,
            severity: FaultSeverity::Warning,
            description: "Response latency exceeded threshold".into(),
            recovery: "retry".into(),
            timestamp: 1767226260,
            metadata: None,
        },
    ];
    write_fault_log_fixture(fixture.repo_path().as_path(), &fault_log);

    let windows_apis = [
        windows_api_with_mapping("DirectXDraw", ApiCategory::DirectX, "wgpu::Queue::submit"),
        windows_api_with_mapping("Present", ApiCategory::DirectX, "wgpu::Surface::present"),
    ];
    let artifact = FunctionArtifact {
        name: "DrawPrimitive",
        address: 4198400,
        binary: "game_logic.dll",
        disassembly: "push rbp\nmov rbp, rsp\nmov rax, [rdi]\ncall DirectXDraw\ncall Present\nret\npop rbp\nret\nnop\nnop",
        decompiler_output: "void DrawPrimitive() { DirectXDraw(); Present(); }",
        windows_apis: &windows_apis,
        call_graph: &[],
    };
    calxgloss_types::save_json(
        &calxgloss_types::analysis_artifact_path(
            fixture.repo_path(),
            "game_logic.dll",
            "DrawPrimitive",
        ),
        &artifact,
    )
    .expect("function artifact filed");
}

/// One Windows API call with its PAL mapping, as a fixture record.
pub fn windows_api_with_mapping(
    name: &str,
    category: ApiCategory,
    pal_mapping: &str,
) -> WindowsApiCall {
    WindowsApiCall {
        name: name.to_string(),
        category,
        pal_mapping: pal_mapping.to_string(),
    }
}

/// The function-analysis artifact shape the web's tier rationale reads.
#[derive(serde::Serialize)]
struct FunctionArtifact<'a> {
    name: &'a str,
    address: u64,
    binary: &'a str,
    disassembly: &'a str,
    decompiler_output: &'a str,
    windows_apis: &'a [WindowsApiCall],
    call_graph: &'a [serde_json::Value],
}

// ─────────────────────────────────────────────────────────────
// Unit analysis context tests (issue #73)
// ─────────────────────────────────────────────────────────────

/// Writes canned analysis artifacts for game_logic.dll/DrawPrimitive: a
/// function analysis artifact naming two Windows APIs, and a per-binary
/// call-graph record. In that record DrawPrimitive is called by GameLoop
/// (the caller is stored as an address) and calls BlitSurface (an edge with
/// a name) and InternalFlush (an edge with no name, matched by address).
pub fn write_canned_analysis_context(fixture: &TestFixture) {
    let windows_apis = [
        windows_api_with_mapping("Present", ApiCategory::DirectX, "wgpu::Surface::present"),
        windows_api_with_mapping("CreateFileA", ApiCategory::Win32Core, "std::fs::File::open"),
    ];
    calxgloss_types::save_json(
        &calxgloss_types::analysis_artifact_path(
            fixture.repo_path(),
            "game_logic.dll",
            "DrawPrimitive",
        ),
        &FunctionArtifact {
            name: "DrawPrimitive",
            address: 4198400,
            binary: "game_logic.dll",
            disassembly: "push rbp\ncall Present\nret",
            decompiler_output: "void DrawPrimitive() { Present(); }",
            windows_apis: &windows_apis,
            call_graph: &[],
        },
    )
    .expect("function artifact filed");

    // The call-graph record rides its own module's persistor, so the
    // fixture can never drift from the shape the analysis scan writes
    // (issue #475). DrawPrimitive is called by GameLoop (the caller is
    // stored as an address) and calls BlitSurface (an edge with a name)
    // and InternalFlush (an edge with no name, matched by address).
    CallGraphPersistor::new(fixture.repo_path())
        .save(&CallGraph {
            binary: "game_logic.dll".to_string(),
            functions: vec![
                FunctionCallGraph {
                    name: "DrawPrimitive".to_string(),
                    address: 4198400,
                    callers: vec![4198656],
                    callees: vec![
                        CallGraphEdge {
                            source: 4198400,
                            target: 4198912,
                            call_site: 4198410,
                            call_type: CallType::Direct,
                            callee_name: "BlitSurface".to_string(),
                        },
                        CallGraphEdge {
                            source: 4198400,
                            target: 4199168,
                            call_site: 4198420,
                            call_type: CallType::Direct,
                            callee_name: String::new(),
                        },
                    ],
                    node_category: NodeCategory::Middle,
                },
                FunctionCallGraph {
                    name: "GameLoop".to_string(),
                    address: 4198656,
                    callers: vec![],
                    callees: vec![],
                    node_category: NodeCategory::Root,
                },
                FunctionCallGraph {
                    name: "BlitSurface".to_string(),
                    address: 4198912,
                    callers: vec![],
                    callees: vec![],
                    node_category: NodeCategory::Leaf,
                },
                FunctionCallGraph {
                    name: "InternalFlush".to_string(),
                    address: 4199168,
                    callers: vec![],
                    callees: vec![],
                    node_category: NodeCategory::Leaf,
                },
            ],
        })
        .expect("call graph artifact filed");
}

/// Adds a DrawPrimitive attempt branch with its own commit, so the
/// fixture unit gains another comparable attempt whose tree differs —
/// a pair the side-by-side diff can visibly switch between.
pub fn add_attempt_branch_with_commit(fixture: &TestFixture, attempt: u32, file_stem: &str) {
    let git = GitManager::open(&fixture.repo_path()).expect("open fixture repo");
    let branch = GitBranch::new("game_logic.dll", "DrawPrimitive", attempt).expect("branch name");
    git.create_branch("game_logic.dll", "DrawPrimitive", attempt, None)
        .expect("create branch");

    let src_file = format!("src/{file_stem}.rs");
    std::fs::create_dir_all(fixture.repo_path().join("src")).expect("create src dir");
    std::fs::write(
        fixture.repo_path().join(&src_file),
        format!(
            "/// {file_stem} — retry translation\npub fn {file_stem}(_encoder: &mut wgpu::CommandEncoder) {{}}\n"
        ),
    )
    .expect("write translation file");
    git.commit(
        &branch,
        &format!("Retry DrawPrimitive — attempt {attempt}"),
        &[src_file.as_str()],
    )
    .expect("commit branch");
}

/// Pin (issue #466): one boot gives a reachable server — `/health`
/// answers with zero sleeps in the test body.
#[tokio::test]
async fn booted_world_answers_health_without_sleeping() {
    let world = ReviewWorld::boot().await;
    let (status, body) = world.client().get_json("/health").await;
    assert_eq!(status, 200);
    assert_eq!(body["status"], "ok");
}

/// Pin (issue #468): the plain-serve router variant — no actions
/// backend — boots through the adapter, so tests can keep pinning that
/// such a router refuses an actions request instead of fabricating one.
#[tokio::test]
async fn plain_serve_variant_answers_health() {
    let world = ReviewWorld::boot_plain().await;
    let (status, body) = world.client().get_json("/health").await;
    assert_eq!(status, 200);
    assert_eq!(body["status"], "ok");
}

/// Pin (issue #468): the actions-wired serve variant — `calxgloss serve`
/// with the review-actions backend attached, still no live-pipeline
/// endpoints — boots through the adapter too.
#[tokio::test]
async fn actions_wired_variant_answers_health() {
    let world = ReviewWorld::boot_with_actions().await;
    let (status, body) = world.client().get_json("/health").await;
    assert_eq!(status, 200);
    assert_eq!(body["status"], "ok");
}

/// Pin (issue #468): an event emitted through the typed emitter reaches the
/// live view through the router's own event consumer, and
/// `wait_until_applied` returns as soon as `/api/pipeline` reflects it —
/// zero sleeps in the test body.
#[tokio::test]
async fn the_applied_wait_returns_once_the_live_view_shows_the_emitted_event() {
    let world = ReviewWorld::boot().await;
    let event = ProgressEvent::TranslationStarted {
        binary: "game_logic.dll".into(),
        function: "DrawPrimitive".into(),
    };
    world.emitter().emit(event.clone());
    world
        .wait_until_applied(&event, |view| {
            view["binaries"]
                .as_array()
                .expect("binaries is an array")
                .iter()
                .any(|row| {
                    row["binary"] == "game_logic.dll"
                        && row["functions_in_progress"]
                            .as_u64()
                            .is_some_and(|n| n >= 1)
                })
        })
        .await;
}

/// Pin (issue #468): a wait that runs past its deadline fails by naming
/// the pending event in the panic message, instead of hanging forever or
/// failing silently.
#[tokio::test]
#[should_panic(expected = "Starting translation of DrawPrimitive (game_logic.dll)")]
async fn a_wait_past_its_deadline_names_the_pending_event() {
    let world = ReviewWorld::boot().await;
    let never_emitted = ProgressEvent::TranslationStarted {
        binary: "game_logic.dll".into(),
        function: "DrawPrimitive".into(),
    };
    world.wait_until_applied(&never_emitted, |_| false).await;
}

/// Pin (issue #469): a `boot()` world hands back a connected websocket
/// handle — no upgrade URL, no `connect_async`, no register-drain sleep
/// in the test body — and its applied-then-push wait returns the live
/// record the router pushed after applying the emitted event, with the
/// raw pipeline event seen along the way.
#[tokio::test]
async fn the_websocket_handle_reads_the_applied_push_without_handshake_plumbing() {
    let world = ReviewWorld::boot().await;
    let event = ProgressEvent::TranslationStarted {
        binary: "game_logic.dll".into(),
        function: "DrawPrimitive".into(),
    };
    let mut ws = world.websocket().await;
    world.emitter().emit(event.clone());
    let record = ws
        .wait_for_unit_phase_push(&event, |unit| {
            unit["binary"] == "game_logic.dll" && unit["function"] == "DrawPrimitive"
        })
        .await;
    assert_eq!(
        record["phase"], "scan_fetch",
        "the pushed record is the unit's applied live state"
    );
    assert_eq!(
        ws.raw_events(),
        ["translation_started"],
        "the raw event rode the wire before the applied push"
    );
}

/// Pin (issue #469): a websocket wait that runs past its deadline fails
/// naming the pending event, instead of hanging forever.
#[tokio::test]
#[should_panic(expected = "Starting translation of DrawPrimitive (game_logic.dll)")]
async fn a_websocket_wait_past_its_deadline_names_the_pending_event() {
    let world = ReviewWorld::boot().await;
    let mut ws = world.websocket().await;
    let never_emitted = ProgressEvent::TranslationStarted {
        binary: "game_logic.dll".into(),
        function: "DrawPrimitive".into(),
    };
    ws.wait_for_unit_phase_push(&never_emitted, |_| false).await;
}

/// Pin (issue #469): the handle reports the refusal instead of
/// pretending — a plain-serve world has no upgrade route to connect to.
#[tokio::test]
async fn a_plain_serve_world_refuses_the_websocket_handle() {
    let world = ReviewWorld::boot_plain().await;
    let refusal = world
        .connect_ws(None)
        .await
        .expect_err("the plain-serve router must not hand back a websocket");
    assert!(
        refusal.contains("/api/events/upgrade"),
        "the refusal names the upgrade the world does not route: {refusal}"
    );
}

/// Pin (issue #471): a booted world launches the browser and opens a
/// dashboard tab on its own port — no fixture, router, port, or settle
/// sleep in the test body. The tab's evaluate helpers read the rendered
/// DOM as a boolean, a string, and a count, and its DOM waits return
/// the moment the page shows the state they poll for. A wait reads
/// `false` at its deadline when it never does, so the caller's own
/// assertion names what the page never showed instead of a hang or a
/// guessed sleep length. Self-skips where no Chrome/Chromium is
/// installed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_booted_world_hands_a_dashboard_tab_that_reads_the_rendered_dom() {
    let world = ReviewWorld::boot_plain().await;
    let Some(tab) = world.open_dashboard_tab() else {
        return;
    };
    assert!(
        tab.eval_text("document.title").contains("Calxgloss"),
        "the tab rides the booted world's server and loads the dashboard"
    );
    assert!(
        tab.eval_count("document.querySelectorAll('.nav-tab').length") > 0,
        "the dashboard's nav tabs stand in the DOM"
    );
    assert!(
        tab.eval_bool("!!document.querySelector('.nav-tab[data-view=\"queue\"]')"),
        "the tab reads a boolean the same way the count reads a number"
    );
    assert!(
        tab.wait_for_bool("!!document.querySelector('.nav-tab')")
            .await,
        "a state the page already shows needs no sleep"
    );
    assert!(
        tab.wait_for_text("document.title", |title| title.contains("Calxgloss"))
            .await,
        "a text wait reads the rendered title through its predicate"
    );
    assert!(
        !tab.wait_for_bool("false").await,
        "a wait past its deadline reads false, bounded by the deadline"
    );
}
