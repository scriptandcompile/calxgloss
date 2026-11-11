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
//! actions-plus-websocket (`boot`). The `_on` variants boot over a
//! caller-supplied fixture — a second server over the same repository,
//! which is what a server-restart pin needs — and the `_with_log_filter`
//! variants attach the reloadable tracing filter the log-verbosity pins
//! drive. The routers come from the same builders the production serve
//! and live commands use (`calxgloss-cli`'s `handle_serve` and
//! `handle_live`), and the server runs on a freshly bound port. Dropping
//! the returned world takes the server down with it, so no port leaks
//! between tests.

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
    port: u16,
    server: Option<tokio::task::JoinHandle<()>>,
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
        Self::boot_live(&TestFixture::new(), None, false).await
    }

    /// A live (websocket) world whose accept loop **does** watch the
    /// state's shutdown signal — the shape `calxgloss live` runs with,
    /// so `POST /api/server/shutdown` stops it. The graceful-shutdown
    /// pins (issue #469) boot through here.
    pub async fn boot_graceful() -> Self {
        Self::boot_live(&TestFixture::new(), None, true).await
    }

    /// Boot a live (websocket) world whose state carries a reloadable
    /// tracing filter — the shape `calxgloss live` installs, so a
    /// `PATCH /api/server/log-level` changes the running process's
    /// verbosity rather than only the reported string.
    pub async fn boot_with_log_filter(
        fixture: &TestFixture,
        filter: calxgloss_web::LogLevelControl,
    ) -> Self {
        Self::boot_live(fixture, Some(filter), false).await
    }

    /// Boot through the actions-wired serve router — `calxgloss serve`
    /// with the review-actions backend attached, still without the
    /// live-pipeline endpoints (issue #468).
    pub async fn boot_with_actions() -> Self {
        Self::boot_actions(&TestFixture::new(), None, false).await
    }

    /// The actions-wired serve router over a caller-supplied fixture.
    pub async fn boot_with_actions_on(fixture: &TestFixture) -> Self {
        Self::boot_actions(fixture, None, false).await
    }

    /// The actions-wired serve router with a reloadable tracing filter
    /// attached (issue #469 — the lifecycle-registration pin exercises
    /// all three router shapes with the log-level endpoint).
    pub async fn boot_with_actions_and_log_filter(
        fixture: &TestFixture,
        filter: calxgloss_web::LogLevelControl,
    ) -> Self {
        Self::boot_actions(fixture, Some(filter), false).await
    }

    /// Boot through the plain-serve router — the shared review surface
    /// with no actions backend and no live-pipeline endpoints, the
    /// router shape [`build_router`] assembles (issue #468). Tests
    /// pinning that a router without an actions backend refuses rather
    /// than fabricates run against this world.
    pub async fn boot_plain() -> Self {
        Self::boot_plain_router(&TestFixture::new(), None, false).await
    }

    /// A plain-serve world whose accept loop **does** watch the state's
    /// shutdown signal — the graceful-shutdown pins' shape (issue #469),
    /// where `POST /api/server/restart` must take the server down.
    pub async fn boot_plain_graceful() -> Self {
        Self::boot_plain_router(&TestFixture::new(), None, true).await
    }

    /// The plain-serve router over a caller-supplied fixture — a
    /// second server over the same repository (a server restart).
    pub async fn boot_plain_on(fixture: &TestFixture) -> Self {
        Self::boot_plain_router(fixture, None, false).await
    }

    /// The plain-serve router with a reloadable tracing filter attached.
    pub async fn boot_plain_with_log_filter(
        fixture: &TestFixture,
        filter: calxgloss_web::LogLevelControl,
    ) -> Self {
        Self::boot_plain_router(fixture, Some(filter), false).await
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
            Some(progress),
            Some(manager),
            graceful,
        )
        .await
    }

    /// Assemble the actions-wired serve router over `fixture` and serve it.
    async fn boot_actions(
        fixture: &TestFixture,
        filter: Option<calxgloss_web::LogLevelControl>,
        graceful: bool,
    ) -> Self {
        let mut state = ServerState::new(fixture.repo_path())
            .with_stop_signal(calxgloss_types::StopSignal::new());
        if let Some(filter) = filter {
            state = state.with_log_level("warn").with_log_filter(filter);
        }
        let events = TranslationEvents::new(256);
        let router = build_router_with_actions(state.clone(), ws_actions(fixture));
        Self::spawn(
            fixture.clone(),
            state,
            EventEmitter { events },
            router,
            None,
            None,
            graceful,
        )
        .await
    }

    /// Assemble the plain-serve router over `fixture` and serve it.
    async fn boot_plain_router(
        fixture: &TestFixture,
        filter: Option<calxgloss_web::LogLevelControl>,
        graceful: bool,
    ) -> Self {
        let mut state = ServerState::new(fixture.repo_path())
            .with_stop_signal(calxgloss_types::StopSignal::new());
        if let Some(filter) = filter {
            state = state.with_log_level("warn").with_log_filter(filter);
        }
        let events = TranslationEvents::new(256);
        let router = build_router(state.clone());
        Self::spawn(
            fixture.clone(),
            state,
            EventEmitter { events },
            router,
            None,
            None,
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
        progress: Option<ProgressState>,
        manager: Option<SessionManager>,
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
            progress,
            manager,
            state,
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
/// The websocket reads and the registration wait share these bounds.
const APPLIED_WAIT_POLL: Duration = Duration::from_millis(10);
const APPLIED_WAIT_DEADLINE: Duration = Duration::from_secs(5);

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
