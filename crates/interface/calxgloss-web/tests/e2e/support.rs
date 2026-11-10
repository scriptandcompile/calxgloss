//! Test adapter for the review surface (issue #466).
//!
//! One call boots everything a review-surface e2e test needs and hands
//! back a typed HTTP client. The call creates the temporary git
//! repository with the shared sample data, the server state, the
//! translation event bus, the session manager subscribed to the bus,
//! the live-view store, and the router. The router comes from the same
//! builders the production live command uses (`calxgloss-cli`'s
//! `handle_live`), and the server runs on a freshly bound port.
//! Dropping the returned world takes the server down with it, so no
//! port leaks between tests.

use super::*;

/// A booted review world: the fixture repo, the live review server, and
/// the typed client pointed at it.
pub struct ReviewWorld {
    fixture: TestFixture,
    /// Kept alive on purpose: the session manager's broadcast
    /// subscription closes once the bus's only sender is dropped.
    #[allow(dead_code)] // held so the subscription stays open
    events: TranslationEvents,
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
        // Bind port 0 and read the port back. The socket is already
        // listening when the serve task is spawned, so the first request
        // needs no settle sleep — the kernel queues it for `accept`.
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
            events,
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
}

/// Dropping the world aborts its serve task, and the listener dies with
/// the task — no port leaks into the next test.
impl Drop for ReviewWorld {
    fn drop(&mut self) {
        self.server.abort();
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
