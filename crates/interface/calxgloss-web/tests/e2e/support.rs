//! Test adapter for the review surface (issues #466, #468, #469).
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

use super::*;
use futures_util::StreamExt;
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
            ws_actions(fixture),
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
        let actions = actions.unwrap_or_else(|| ws_actions(fixture));
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
