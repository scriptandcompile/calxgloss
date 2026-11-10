//! Test adapter for the review surface (issues #466, #468).
//!
//! One call boots everything a review-surface e2e test needs and hands
//! back a typed HTTP client, a typed event emitter, and event-applied
//! waits. The call creates the temporary git repository with the shared
//! sample data, the server state, the translation event bus, the session
//! manager subscribed to the bus, the live-view store, and the router.
//! Three boot entry points name the three router shapes `calxgloss_web`
//! exports: plain serve (`boot_plain`), actions-wired serve
//! (`boot_with_actions`), and live actions-plus-websocket (`boot`). The routers come from the same builders the production
//! serve and live commands use (`calxgloss-cli`'s `handle_serve` and
//! `handle_live`), and the server runs on a freshly bound port.
//! Dropping the returned world takes the server down with it, so no
//! port leaks between tests.

use super::*;

/// A booted review world: the fixture repo, the live review server, and
/// the typed client pointed at it.
pub struct ReviewWorld {
    fixture: TestFixture,
    /// Typed handle on the progress-event bus. Kept alive on purpose:
    /// the session manager's broadcast subscription closes once the
    /// bus's only sender is dropped.
    emitter: EventEmitter,
    client: Client,
    server: tokio::task::JoinHandle<()>,
}

impl ReviewWorld {
    /// The way a test gets a running review server.
    ///
    /// The router matches the production live command's: a live (WS)
    /// router over the event bus's broadcast subscription, the
    /// live-view store, and the settings-backed actions backend. It is
    /// served through `serve_with_listener`, which watches the state's
    /// shutdown signal for graceful shutdown.
    pub async fn boot() -> Self {
        let fixture = TestFixture::new();
        let state = ServerState::new(fixture.repo_path());
        let events = TranslationEvents::new(256);
        let manager = SessionManager::new_with_broadcast(events.subscribe());
        let router = build_router_with_ws(
            state.clone(),
            manager,
            ProgressState::new(),
            ws_actions(&fixture),
        );
        Self::spawn(fixture, &state, EventEmitter { events }, router).await
    }

    /// Boot through the plain-serve router — the shared review surface
    /// with no actions backend and no live-pipeline endpoints, the
    /// router shape [`build_router`] assembles (issue #468). Tests
    /// pinning that a router without an actions backend refuses rather
    /// than fabricates run against this world.
    pub async fn boot_plain() -> Self {
        let fixture = TestFixture::new();
        let state = ServerState::new(fixture.repo_path());
        let events = TranslationEvents::new(256);
        let router = build_router(state.clone());
        Self::spawn(fixture, &state, EventEmitter { events }, router).await
    }

    /// Boot through the actions-wired serve router — `calxgloss serve`
    /// with the review-actions backend attached, still without the
    /// live-pipeline endpoints (issue #468).
    pub async fn boot_with_actions() -> Self {
        let fixture = TestFixture::new();
        let state = ServerState::new(fixture.repo_path());
        let events = TranslationEvents::new(256);
        let router = build_router_with_actions(state.clone(), ws_actions(&fixture));
        Self::spawn(fixture, &state, EventEmitter { events }, router).await
    }

    /// Bind a free port, serve `router` over it, and hand back the world
    /// that owns the server task.
    ///
    /// Bind port 0 and read the port back. The socket is already
    /// listening when the serve task is spawned, so the first request
    /// needs no settle sleep — the kernel queues it for `accept`.
    async fn spawn(
        fixture: TestFixture,
        state: &ServerState,
        emitter: EventEmitter,
        router: axum::Router,
    ) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind free port");
        let port = listener.local_addr().expect("listener address").port();
        let shutdown = state.shutdown_signal();
        let server = tokio::spawn(async move {
            let _ = serve_with_listener(listener, router, shutdown).await;
        });
        Self {
            fixture,
            emitter,
            client: Client {
                http: reqwest::Client::new(),
                port,
            },
            server,
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
}

/// Dropping the world aborts its serve task, and the listener dies with
/// the task — no port leaks into the next test.
impl Drop for ReviewWorld {
    fn drop(&mut self) {
        self.server.abort();
    }
}

/// How often an applied wait re-reads the live view, and how long it
/// keeps trying before it fails naming the pending event (issue #468).
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

    /// POST to a lifecycle endpoint (they take no body) and decode the
    /// JSON reply.
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
