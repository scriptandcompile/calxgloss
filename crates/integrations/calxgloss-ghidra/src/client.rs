//! The [`GhidraConfig`] and [`GhidraClient`] — connection settings and HTTP API client.

use crate::error;
use crate::error::Classification;
use crate::model::{
    AnalysisOutcome, AnalysisStatus, DataItem, DataTypeEntry, DecompiledFunction, EnumDefinition,
    FunctionBody, FunctionReport, FunctionSummary, LoadedProgram, OpenProgram, ProjectInfo,
    Segment, ServerInfo, ServerKind, StringLiteral, StructLayout, Symbol, Xref,
};
use crate::parse;
use crate::type_write_source::NewStructField;
use calxgloss_types::{BinaryIdentity, ProgressEvent, TranslationEvents};
use reqwest::Client;
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tracing::{debug, info, instrument, trace, warn};
use url::Url;

/// Result of a GhidraMCP operation.
pub type Result<T> = std::result::Result<T, GhidraError>;

/// Page size used when the client collects a paged endpoint in full.
///
/// The server defaults to 100 per page, which means hundreds of round trips
/// for a large binary's listings; a larger page trades one bigger response
/// for far fewer requests.
const DATA_PAGE: usize = 1000;

/// Oldest GhidraMCP plugin version the client will work against.
///
/// ADR-0001 pins the bethington bridge at v6.0.0: the endpoint names and
/// response shapes this client speaks are that bridge's, so an older plugin
/// is a configuration fault to name, not a shape to adapt to.
pub const MIN_PLUGIN_VERSION: &str = "6.0.0";

/// Timeout for a `/run_analysis` request.
///
/// The endpoint blocks inside Ghidra until the whole auto-analysis finishes,
/// which for a large DLL runs to several minutes — far past the ordinary
/// request timeout — so this call gets its own, much longer budget.
pub const ANALYSIS_TIMEOUT: Duration = Duration::from_secs(600);

// ============================================================
// Error types
// ============================================================

/// Errors from talking to GhidraMCP.
#[derive(Debug, thiserror::Error)]
pub enum GhidraError {
    /// The request could not be delivered, or its body could not be read.
    ///
    /// The hint matters because the GhidraMCP bridge only serves requests while
    /// a CodeBrowser is open, so a refused connection usually means a closed
    /// window rather than a broken server.
    #[error(
        "Could not reach GhidraMCP at {url}: {source}\nGhidra must be running with the \
            GhidraMCP extension loaded and a program open in a CodeBrowser"
    )]
    Transport { url: String, source: reqwest::Error },

    /// The server answered, and its answer was an explanation rather than a
    /// result.
    ///
    /// `status` is the HTTP status. Most failures arrive as `200` with the
    /// explanation in the body, so this is `Some(200)` far more often than a
    /// real transport-level status.
    #[error("Ghidra reported an error: {message}")]
    Reported {
        status: Option<u16>,
        message: String,
    },

    /// Nothing in the open program matched the request.
    #[error("Ghidra has no {kind} matching '{query}'")]
    NotFound { kind: &'static str, query: String },

    /// A response was a result but did not have the shape the endpoint promises.
    #[error("Could not read {kind} from Ghidra's response: {detail}")]
    Malformed { kind: &'static str, detail: String },

    /// The configured base URL could not be parsed.
    #[error("Server URL is invalid: {0}")]
    InvalidUrl(#[from] url::ParseError),

    /// The port answered HTTP, but not as GhidraMCP.
    ///
    /// The usual cause is a configured URL pointing at some other local server
    /// — 8080 is the bridge's default port and a popular one for local AI
    /// assistants — so the hint points at the URL rather than at Ghidra.
    #[error(
        "The port at {url} answers, but it is not GhidraMCP.\n{hint}\nCheck the configured \
            Ghidra URL (`--ghidra-url`, `CALXGLOSS_GHIDRA_URL`, or `ghidra.url`)"
    )]
    NotGhidraMcp { url: String, hint: String },

    /// Nothing answered the connection probe at all.
    ///
    /// Distinct from [`Transport`](Self::Transport) because the probe is the
    /// one request whose failure means "no server here" rather than "this call
    /// did not land" — the usual cause is Ghidra not running.
    #[error(
        "No server answered at {url}: {source}\nStart Ghidra with the GhidraMCP extension \
            loaded, or point the configured URL at a running server"
    )]
    ServerUnreachable { url: String, source: reqwest::Error },

    /// The server identified itself but named a plugin older than the bridge
    /// calxgloss is built against (ADR-0001 pins the bethington bridge).
    #[error(
        "GhidraMCP plugin v{found} is too old: calxgloss needs v{required} or newer.\nInstall \
            the matching GhidraMCP release into this Ghidra (ADR-0001)"
    )]
    VersionMismatch { found: String, required: String },

    /// The server is up, but it is not serving the program the run targets.
    ///
    /// The 2026-10-08 incident: with several CodeBrowser windows open, the
    /// bridge answered listings and searches from *different* programs, and a
    /// scan nearly persisted a phantom-clean record. The wrong-program guard
    /// fails before any scan runs, naming the programs that *are* open so the
    /// operator can fix the right window or point the URL at the right
    /// instance.
    #[error(
        "The Ghidra server is not serving '{target}'.\nPrograms open in this instance: {}\nOpen \
            '{target}' in this Ghidra instance, or point the configured URL at the instance \
            that has it",
        if open.is_empty() { "none".to_string() } else { open.join(", ") }
    )]
    WrongProgram { target: String, open: Vec<String> },

    /// A local filesystem step the bootstrap needs — creating the
    /// directory beside the run's `.gpr` — failed.
    ///
    /// Distinct from [`Reported`](Self::Reported): nothing on the server
    /// answered this; the workspace itself refused the write.
    #[error("Could not create the Ghidra project directory {path}: {source}")]
    LocalIo {
        path: String,
        source: std::io::Error,
    },

    /// Neither the configured port nor the fallback default is free, so a
    /// headless spawn cannot bind either.
    ///
    /// calxgloss never binds a busy port (design risk 4): the usual holder
    /// is a foreign local server (8080 is also the popular local-AI port).
    /// A merely *stale* configured port no longer lands here — UDS
    /// discovery reconciles it against the live servers the bridge
    /// registers before a spawn is considered — so this failure means both
    /// candidate ports are held.
    #[error(
        "Cannot start a headless Ghidra server: the configured port at {url} and the bridge \
            default are both in use by something that is not GhidraMCP.\nFree one of them or \
            point the configured Ghidra URL (`--ghidra-url`, `CALXGLOSS_GHIDRA_URL`, or \
            `ghidra.url`) at a free one"
    )]
    PortBusy { url: String },

    /// A spawned headless server died before it ever answered the probe.
    ///
    /// The usual causes are a missing `java` on PATH or a JVM that refused
    /// the launch arguments; the log file beside the project carries the
    /// child's own explanation.
    #[error(
        "The headless Ghidra server calxgloss started died before it answered: {detail}\nIts \
            log: {log}"
    )]
    SpawnFailed { detail: String, log: String },

    /// A spawned headless server stayed silent through the whole boot poll.
    ///
    /// JVM + Ghidra boot is slow (the design budget is ~90 s), but a server
    /// that never answers usually means it is wedged inside Ghidra startup —
    /// the log file beside the project says where.
    #[error(
        "The headless Ghidra server calxgloss started never answered at {url} within {secs}s.\n\
            Its log: {log}"
    )]
    BootTimeout { url: String, secs: u64, log: String },

    /// The stack checks passed the *server* half but failed the pieces a
    /// spawn needs: no valid Ghidra install, or no extension paired to it.
    ///
    /// Attaching to a running server needs neither, so this failure only
    /// arises when preflight decides to start one — the message names what
    /// is missing and points at `calxgloss doctor` for the full report.
    #[error(
        "Cannot start a headless Ghidra server: {reason}\nRun `calxgloss doctor` for the full stack report"
    )]
    CannotSpawn { reason: String },

    /// The JDK-21 prerequisite for `doctor --fix` did not hold.
    ///
    /// Ghidra 12.x will not run without a Java 21 LTS runtime, and a
    /// bootstrap that downloaded 570 MB only to fail at first launch is the
    /// outcome this gate exists to prevent. calxgloss never installs a JDK
    /// itself — the remediation is always the user's to run.
    #[error(
        "Java 21 is required before calxgloss can install Ghidra: {detail}\nInstall a JDK 21 \
            or newer (on Debian/Ubuntu: `sudo apt install openjdk-21-jdk`), or point \
            `ghidra.java_home` at an existing one. calxgloss never installs a JDK itself."
    )]
    JdkGate { detail: String },

    /// The bootstrap stopped before a download because consent was not given.
    ///
    /// The Ghidra release is a ~570 MB download, so `ghidra.auto_install`
    /// defaults to false and `--install-ghidra` opts in per run; this failure
    /// is the consent request itself, not a malfunction.
    #[error(
        "{detail}\ncalxgloss will not download it without consent: re-run with \
            `--install-ghidra`, or set `ghidra.auto_install = true` to consent on every run"
    )]
    ConsentRequired { detail: String },

    /// The bootstrap would replace an existing install, which needs an
    /// explicit old → new confirmation first.
    ///
    /// A working stack is never broken by a routine `doctor --fix`: the
    /// confirmation names exactly what changes, and the CLI re-runs the
    /// bootstrap with consent once the human has agreed.
    #[error(
        "calxgloss would replace the {what}: {from} → {to}.\nRe-run `calxgloss doctor --fix` \
            and confirm the upgrade, or leave the existing install alone"
    )]
    UpgradeConfirmation {
        what: String,
        from: String,
        to: String,
    },

    /// The GitHub releases API — the source of both artifacts and their
    /// digests — answered with something unusable.
    #[error("The GitHub releases API call for {url} failed: {detail}")]
    ReleasesApi { url: String, detail: String },

    /// The GitHub releases API refused the request because the caller's
    /// rate limit is exhausted — the anonymous bucket, or a token's own.
    ///
    /// Named apart from a plain API failure because the remediation is
    /// different: a token raises the limit immediately, and the clock
    /// clears it on its own; anything already downloaded stays cached
    /// either way, so a retry does not refetch.
    #[error(
        "The GitHub releases API rate limit is exhausted ({url}: {detail}).\nSet \
            GHIDRA_MCP_GITHUB_TOKEN to a GitHub token to raise the limit, or wait for the \
            window to reset and retry — downloaded artifacts stay cached"
    )]
    RateLimited { url: String, detail: String },

    /// A downloaded artifact's sha256 did not match the releases API digest,
    /// so it was never unzipped.
    ///
    /// Verification happens before unzipping by design (design §3.5): a
    /// corrupted or tampered download must never execute.
    #[error(
        "The download of {asset} failed sha256 verification: expected {expected}, got \
            {found}.\nNothing was unzipped; delete the cached copy and retry, or check the \
            connection"
    )]
    DigestMismatch {
        asset: String,
        expected: String,
        found: String,
    },

    /// A release artifact did not have the layout its repository promises.
    #[error("The Ghidra bootstrap artifact is not what it claims to be: {detail}")]
    ArtifactInvalid { detail: String },

    /// A bootstrap step stopped on a machine state the user must resolve.
    ///
    /// The prefix is not writable, a named install path does not validate,
    /// or `$HOME` is unknown — never something calxgloss may work around by
    /// escalating privileges or writing elsewhere.
    #[error("The Ghidra bootstrap stopped: {reason}")]
    BootstrapBlocked { reason: String },
}

/// Fold a Kuna engine failure into the seam's error vocabulary (ADR-0039).
///
/// A missing function is the same fact Ghidra reports, in the same shape —
/// consumers already branch on [`NotFound`](Self::NotFound) for a bad name.
/// Every other Kuna failure is already a named, self-explaining message
/// (each names the `--engine ghidra` fallback where it matters), so it rides
/// the seam as a [`Reported`](Self::Reported) explanation with no HTTP
/// status behind it.
impl From<calxgloss_kuna::error::KunaError> for GhidraError {
    fn from(error: calxgloss_kuna::error::KunaError) -> Self {
        match error {
            calxgloss_kuna::error::KunaError::FunctionNotFound { name } => GhidraError::NotFound {
                kind: "function",
                query: name,
            },
            other => GhidraError::Reported {
                status: None,
                message: other.to_string(),
            },
        }
    }
}

// ============================================================
// Configuration
// ============================================================

/// Connection settings for a GhidraMCP server.
#[derive(Debug, Clone)]
pub struct GhidraConfig {
    /// Base URL of the GhidraMCP bridge, e.g. `http://127.0.0.1:8080`.
    pub base_url: Url,

    /// How long to wait for a response.
    ///
    /// Decompiling a large function is slow inside Ghidra, so this is generous
    /// relative to a normal HTTP call.
    pub timeout: Duration,

    /// Optional bearer token, for a server behind a proxy.
    pub api_key: Option<String>,
}

impl GhidraConfig {
    /// Default configuration for a base URL.
    ///
    /// # Errors
    ///
    /// Returns [`GhidraError::InvalidUrl`] if `base_url` is not a valid URL.
    pub fn new(base_url: &str) -> std::result::Result<Self, GhidraError> {
        Ok(Self {
            base_url: Url::parse(base_url)?,
            timeout: Duration::from_secs(120),
            api_key: None,
        })
    }

    /// Override the request timeout.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Send a bearer token with every request.
    pub fn with_api_key(mut self, api_key: impl Into<String>) -> Self {
        self.api_key = Some(api_key.into());
        self
    }
}

// ============================================================
// Client
// ============================================================

/// A client for the GhidraMCP API.
///
/// Every query runs against the program currently open in Ghidra, so a client
/// is valid for as long as that program is. The 6.x bridge can hold several
/// programs at once; [`switch_program`](Self::switch_program) moves which one
/// queries run against, and opening a different program by hand changes what
/// these methods return without the client noticing.
#[derive(Debug, Clone)]
pub struct GhidraClient {
    config: GhidraConfig,
    http: Client,
    /// Same server, longer leash: `/run_analysis` blocks until a full
    /// auto-analysis finishes, which outlasts the ordinary timeout.
    slow_http: Client,
    /// Armed by `begin_pass` while an analysis pass walks the program;
    /// clones share it so every handle to one client beats as one.
    heartbeat: Arc<Mutex<Option<Arc<Heartbeat>>>>,
}

/// Minimum gap between heartbeat beats for one pass — a 20k-function scan
/// must not flood the event channel.
const HEARTBEAT_INTERVAL: Duration = Duration::from_millis(500);

/// Shared state for one analysis pass's progress heartbeat.
///
/// A pass (`begin_pass`) arms the client: while armed, every completed
/// decompile counts as one work item and beats a `BatchProgress` event,
/// throttled to [`HEARTBEAT_INTERVAL`]. `list_functions` during the pass
/// records the work list — its size is the total, and its names resolve
/// address-based decompiles to function names.
#[derive(Debug)]
struct Heartbeat {
    binary: BinaryIdentity,
    pass: String,
    events: TranslationEvents,
    total: AtomicUsize,
    index: AtomicUsize,
    last_beat: Mutex<Option<std::time::Instant>>,
    names: Mutex<HashMap<u64, String>>,
}

impl GhidraClient {
    // =========================================================
    // Construction
    // =========================================================

    /// Create a client with default settings.
    pub fn new(base_url: &str) -> std::result::Result<Self, GhidraError> {
        Self::from_config(GhidraConfig::new(base_url)?)
    }

    /// Create a client from explicit settings.
    pub fn from_config(config: GhidraConfig) -> std::result::Result<Self, GhidraError> {
        let build = |timeout: Duration| {
            Client::builder()
                .timeout(timeout)
                .build()
                .map_err(|source| GhidraError::Transport {
                    url: config.base_url.to_string(),
                    source,
                })
        };
        let http = build(config.timeout)?;
        let slow_http = build(config.timeout.max(ANALYSIS_TIMEOUT))?;
        info!(base_url = %config.base_url, "Created GhidraClient");
        Ok(Self {
            config,
            http,
            slow_http,
            heartbeat: Arc::new(Mutex::new(None)),
        })
    }

    /// The base URL of the server.
    pub fn base_url(&self) -> &Url {
        &self.config.base_url
    }

    // =========================================================
    // Analysis-pass heartbeat
    // =========================================================

    /// Arm the heartbeat for one analysis pass over the open program.
    ///
    /// While armed, every completed decompile beats a
    /// [`ProgressEvent::BatchProgress`] naming the pass and the function it
    /// just pulled, so the dashboard can show per-function progress through
    /// the pre-translation passes (call-graph extraction, the evidence
    /// scans) that run before any unit event exists. One pass at a time —
    /// a new `begin_pass` replaces any pass left armed by an error path
    /// that skipped [`end_pass`](Self::end_pass).
    pub fn begin_pass(&self, binary: &str, pass: &str, events: &TranslationEvents) {
        *self.heartbeat.lock().expect("heartbeat lock") = Some(Arc::new(Heartbeat {
            binary: binary.into(),
            pass: pass.to_string(),
            events: events.clone(),
            total: AtomicUsize::new(0),
            index: AtomicUsize::new(0),
            last_beat: Mutex::new(None),
            names: Mutex::new(HashMap::new()),
        }));
    }

    /// Disarm the heartbeat — the pass is done, later queries are ordinary.
    pub fn end_pass(&self) {
        *self.heartbeat.lock().expect("heartbeat lock") = None;
    }

    /// Record the pass's work list: its size is the total, and its names
    /// resolve address-based decompiles to function names.
    pub(crate) fn note_worklist(&self, functions: &[FunctionSummary]) {
        if let Some(hb) = self.active_heartbeat() {
            *hb.names.lock().expect("names lock") = functions
                .iter()
                .map(|f| (f.address, f.name.clone()))
                .collect();
            hb.total.store(functions.len(), Ordering::Relaxed);
        }
    }

    /// Count one completed decompile and beat if due: always for the first
    /// and last item, otherwise at most once per [`HEARTBEAT_INTERVAL`].
    fn tick(&self, address: u64) {
        let Some(hb) = self.active_heartbeat() else {
            return;
        };
        self.beat(&hb, || {
            hb.names
                .lock()
                .expect("names lock")
                .get(&address)
                .cloned()
                .unwrap_or_default()
        });
    }

    /// Count one completed decompile the caller knows by name — the read
    /// cache's shape: a cached body never reaches the address-based path,
    /// but the pipeline still consumed the work item, so the pass's
    /// progress must move (issue #121).
    pub(crate) fn tick_name(&self, name: &str) {
        let Some(hb) = self.active_heartbeat() else {
            return;
        };
        self.beat(&hb, || name.to_string());
    }

    /// Advance the pass counter for one consumed work item and emit the
    /// throttled `BatchProgress` beat. The function name is resolved only
    /// when a beat is actually due.
    fn beat(&self, hb: &Heartbeat, function: impl FnOnce() -> String) {
        let index = hb.index.fetch_add(1, Ordering::Relaxed) + 1;
        let total = hb.total.load(Ordering::Relaxed);
        let now = std::time::Instant::now();
        let due = index == 1
            || (total > 0 && index == total)
            || hb
                .last_beat
                .lock()
                .expect("last_beat lock")
                .map(|t| now.duration_since(t) >= HEARTBEAT_INTERVAL)
                .unwrap_or(true);
        if !due {
            return;
        }
        *hb.last_beat.lock().expect("last_beat lock") = Some(now);
        hb.events.emit(ProgressEvent::BatchProgress {
            binary: hb.binary.clone(),
            pass: hb.pass.clone(),
            function: function(),
            index,
            total,
        });
    }

    fn active_heartbeat(&self) -> Option<Arc<Heartbeat>> {
        self.heartbeat.lock().expect("heartbeat lock").clone()
    }

    // =========================================================
    // Transport
    // =========================================================

    /// Issue a GET and return the body, having established that it is a result.
    ///
    /// This is the single point where server errors become client errors, so
    /// every other method can assume it received content.
    async fn get_text(&self, endpoint: &str, params: &[(&str, String)]) -> Result<String> {
        self.get_text_on(&self.http, endpoint, params).await
    }

    /// [`get_text`](Self::get_text) on a chosen HTTP client — the slow one
    /// for calls like `/run_analysis` that block inside Ghidra.
    async fn get_text_on(
        &self,
        http: &Client,
        endpoint: &str,
        params: &[(&str, String)],
    ) -> Result<String> {
        let mut url = self.config.base_url.join(endpoint)?;
        // The query string is only touched when there is one to add. Merely
        // calling `query_pairs_mut` appends a bare `?`, and Ghidra rejects a
        // request path carrying one as an unknown context.
        if !params.is_empty() {
            let mut pairs = url.query_pairs_mut();
            for (k, v) in params {
                pairs.append_pair(k, v);
            }
        }

        trace!(%url, endpoint, "GET");
        let mut request = http.get(url.clone());
        if let Some(ref key) = self.config.api_key {
            request = request.bearer_auth(key);
        }
        self.deliver(request, &url).await
    }

    /// Issue a POST with a JSON body and return the body, having established
    /// that it is a result.
    ///
    /// The write endpoints answer `{"status":"success",...}` on success and
    /// `{"error":"..."}` on failure; the failure shape goes through
    /// [`error::classify`] like every other response.
    async fn post_json(&self, endpoint: &str, payload: &serde_json::Value) -> Result<String> {
        self.post_json_on(&self.http, endpoint, &[], payload).await
    }

    /// [`post_json`](Self::post_json) with query parameters and a chosen
    /// HTTP client — the bridge reads `program`-style parameters from the
    /// query string even for POST-declared endpoints.
    async fn post_json_on(
        &self,
        http: &Client,
        endpoint: &str,
        params: &[(&str, String)],
        payload: &serde_json::Value,
    ) -> Result<String> {
        let mut url = self.config.base_url.join(endpoint)?;
        if !params.is_empty() {
            let mut pairs = url.query_pairs_mut();
            for (k, v) in params {
                pairs.append_pair(k, v);
            }
        }
        trace!(%url, endpoint, "POST");
        let mut request = http.post(url.clone()).json(payload);
        if let Some(ref key) = self.config.api_key {
            request = request.bearer_auth(key);
        }
        self.deliver(request, &url).await
    }

    /// Send a built request and establish that its body is a result.
    async fn deliver(&self, request: reqwest::RequestBuilder, url: &Url) -> Result<String> {
        let send = |source: reqwest::Error| GhidraError::Transport {
            url: url.to_string(),
            source,
        };
        let response = request.send().await.map_err(send)?;
        let status = response.status();
        let body = response.text().await.map_err(send)?;
        trace!(%status, bytes = body.len(), "GOT");

        // The 6.x bridge answers an unknown endpoint with a real 404 and an
        // HTML body, which no content parser would recognise.
        if !status.is_success() {
            return Err(GhidraError::Reported {
                status: Some(status.as_u16()),
                message: Self::describe_error_body(&body),
            });
        }

        match error::classify(&body) {
            Classification::Content => Ok(body),
            Classification::Failure(message) => Err(GhidraError::Reported {
                status: Some(status.as_u16()),
                message: message.to_string(),
            }),
            Classification::FailureWithStatus(code, message) => Err(GhidraError::Reported {
                status: Some(code),
                message: message.to_string(),
            }),
            Classification::Unrecognised(body) => Err(GhidraError::Reported {
                status: Some(status.as_u16()),
                message: if body.is_empty() {
                    "the server returned an empty response".to_string()
                } else {
                    format!("the server returned an unrecognised response: {body}")
                },
            }),
        }
    }

    /// Render an address the way the server's endpoints expect: bare hex.
    fn addr(address: u64) -> String {
        format!("{address:x}")
    }

    /// The bridge's shared sentinel for a structure the Type Manager does
    /// not have, answered by both the read and the write structure
    /// endpoints — recognised here rather than by [`classify`](crate::error::classify)
    /// so it lands as [`NotFound`](GhidraError::NotFound).
    fn structure_not_found(body: &str) -> Option<GhidraError> {
        body.trim()
            .strip_prefix("Structure not found: ")
            .map(|missing| GhidraError::NotFound {
                kind: "structure",
                query: missing.trim().to_string(),
            })
    }

    /// Make an error-status body readable, stripping the HTML the PicoServer
    /// wraps its 404 pages in.
    fn describe_error_body(body: &str) -> String {
        let stripped = body
            .replace("<h1>", "")
            .replace("</h1>", " ")
            .trim()
            .to_string();
        if stripped.is_empty() {
            "the server returned an empty response".to_string()
        } else {
            stripped
        }
    }

    // =========================================================
    // Program state
    // =========================================================

    /// Every function Ghidra knows about in the open program.
    ///
    /// This is the whole program at once — a large binary returns several
    /// thousand entries — so prefer [`search_functions`](Self::search_functions)
    /// when a name is known.
    #[instrument(skip(self))]
    pub async fn list_functions(&self) -> Result<Vec<FunctionSummary>> {
        let body = self.get_text("list_functions", &[]).await?;
        let functions = parse::parse_function_listing(&body);
        self.note_worklist(&functions);
        debug!(count = functions.len(), "Listed functions");
        Ok(functions)
    }

    /// Functions whose name contains `query`.
    ///
    /// An empty result is reported as [`GhidraError::NotFound`] rather than an
    /// empty vector, because "no such function" and "the query found nothing
    /// yet" are different situations and only the first is an error.
    #[instrument(skip(self), fields(query))]
    pub async fn search_functions(
        &self,
        query: &str,
        limit: Option<usize>,
    ) -> Result<Vec<FunctionSummary>> {
        let mut params: Vec<(&str, String)> = vec![("name_pattern", query.to_string())];
        if let Some(n) = limit {
            params.push(("limit", n.to_string()));
        }
        let body = self.get_text("search_functions", &params).await?;
        let found = parse::parse_function_listing(&body);
        if found.is_empty() {
            return Err(GhidraError::NotFound {
                kind: "function",
                query: query.to_string(),
            });
        }
        debug!(count = found.len(), query, "Searched functions");
        Ok(found)
    }

    /// The address Ghidra's cursor is at.
    #[instrument(skip(self))]
    pub async fn current_address(&self) -> Result<u64> {
        let body = self.get_text("get_current_address", &[]).await?;
        parse::parse_current_address(&body).ok_or_else(|| GhidraError::Malformed {
            kind: "the current address",
            detail: body.trim().to_string(),
        })
    }

    /// The function under Ghidra's cursor.
    #[instrument(skip(self))]
    pub async fn current_function(&self) -> Result<FunctionBody> {
        let body = self.get_text("get_current_function", &[]).await?;
        parse::parse_current_function(&body).ok_or_else(|| GhidraError::Malformed {
            kind: "the current function",
            detail: body.trim().to_string(),
        })
    }

    /// The program's memory layout.
    ///
    /// The lowest segment start is the image base, which is what turns a Ghidra
    /// virtual address into a file-relative one.
    #[instrument(skip(self))]
    pub async fn segments(&self) -> Result<Vec<Segment>> {
        let body = self.get_text("list_segments", &[]).await?;
        Ok(parse::parse_segments(&body))
    }

    /// The base address the open program is loaded at.
    #[instrument(skip(self))]
    pub async fn image_base(&self) -> Result<u64> {
        self.segments()
            .await?
            .iter()
            .map(|s| s.start)
            .min()
            .ok_or_else(|| GhidraError::Malformed {
                kind: "the program layout",
                detail: "the server listed no segments".to_string(),
            })
    }

    // =========================================================
    // Function queries
    // =========================================================

    /// The pseudo-C for the function at `address`.
    ///
    /// `address` may be any address inside the function, not just its entry.
    #[instrument(skip(self), fields(address = format_args!("{address:#x}")))]
    pub async fn decompile_function(&self, address: u64) -> Result<DecompiledFunction> {
        let body = self
            .get_text("decompile_function", &[("address", Self::addr(address))])
            .await?;
        // The round trip completed — one work item of any armed pass done,
        // whether or not the body parses.
        self.tick(address);
        parse::parse_decompiled(&body).ok_or_else(|| GhidraError::Malformed {
            kind: "decompiled output",
            detail: body.trim().to_string(),
        })
    }

    /// The pseudo-C for a function named by Ghidra.
    ///
    /// The 6.x bridge dropped the old POST-by-name endpoint, so the name is
    /// resolved through [`search_functions`](Self::search_functions) and the
    /// body is pulled by address. An exact name match wins over the substring
    /// matches the search also returns.
    #[instrument(skip(self), fields(function))]
    pub async fn decompile_function_by_name(&self, function: &str) -> Result<DecompiledFunction> {
        let matches = self.search_functions(function, Some(10)).await?;
        let found = matches
            .iter()
            .find(|f| f.name == function)
            .or(matches.first())
            .ok_or_else(|| GhidraError::NotFound {
                kind: "function",
                query: function.to_string(),
            })?;
        self.decompile_function(found.address).await
    }

    /// The disassembly listing for the function at `address`.
    ///
    /// The server answers with a 200 and an empty body for functions that
    /// own no instructions — thunks and external (imported) functions have
    /// empty bodies, though the decompiler still follows them — which is a
    /// valid "no disassembly" answer, the same shape the cross-reference
    /// endpoints use for "no references", not a server failure.
    #[instrument(skip(self), fields(address = format_args!("{address:#x}")))]
    pub async fn disassemble_function(&self, address: u64) -> Result<String> {
        match self
            .get_text("disassemble_function", &[("address", Self::addr(address))])
            .await
        {
            Ok(body) => Ok(body),
            Err(GhidraError::Reported { message: ref m, .. })
                if m == "the server returned an empty response" =>
            {
                Ok(String::new())
            }
            Err(e) => Err(e),
        }
    }

    /// Entry point and body range of the function at `address`.
    #[instrument(skip(self), fields(address = format_args!("{address:#x}")))]
    pub async fn function_body(&self, address: u64) -> Result<FunctionBody> {
        let body = self
            .get_text(
                "get_function_by_address",
                &[("address", Self::addr(address))],
            )
            .await?;
        parse::parse_function_body(&body).ok_or_else(|| GhidraError::Malformed {
            kind: "function metadata",
            detail: body.trim().to_string(),
        })
    }

    /// Everything worth knowing about the function at `address`.
    ///
    /// This is the convenience the pipeline wants, assembled from four
    /// endpoints: the decompiled body, the disassembly, the body range, and the
    /// cross-references to the entry point.
    ///
    /// Callees are read out of the decompiled text rather than from a call-graph
    /// endpoint, because the server has no such endpoint and building a faithful
    /// list would cost a request per call site. A call through a function
    /// pointer therefore does not appear in `callees`.
    #[instrument(skip(self), fields(address = format_args!("{address:#x}")))]
    pub async fn function_report(&self, address: u64) -> Result<FunctionReport> {
        let decompiled = self.decompile_function(address).await?;

        // The remaining three enrich the decompilation rather than define it, so
        // a function that decompiles is still reported when they fail — a
        // missing call site is not a reason to lose the body.
        let disassembly = self
            .disassemble_function(address)
            .await
            .unwrap_or_else(|e| {
                warn!(error = %e, "Could not read disassembly; reporting without it");
                String::new()
            });
        let body = self.function_body(address).await.ok();
        let callers = self.callers(address).await.unwrap_or_else(|e| {
            warn!(error = %e, "Could not read cross-references; reporting without callers");
            Vec::new()
        });

        let callees = parse::callees_from_decompiled(&decompiled.body);
        let name = body
            .as_ref()
            .map(|b| b.name.clone())
            .unwrap_or_else(|| decompiled.name.clone());

        info!(%name, address = format_args!("{address:#x}"), callees = callees.len(), "Read function report");
        Ok(FunctionReport {
            name,
            address,
            decompiled,
            disassembly,
            body,
            callers,
            callees,
        })
    }

    // =========================================================
    // Cross-references
    // =========================================================

    /// References to `address` — who points at it.
    ///
    /// The server returns a 200 with an empty body when there are no
    /// cross-references, which is a valid "no results" response rather than
    /// an error.
    #[instrument(skip(self), fields(address = format_args!("{address:#x}")))]
    pub async fn xrefs_to(&self, address: u64, limit: Option<usize>) -> Result<Vec<Xref>> {
        let mut params: Vec<(&str, String)> = vec![("address", Self::addr(address))];
        if let Some(n) = limit {
            params.push(("limit", n.to_string()));
        }
        let body = self.get_text("get_xrefs_to", &params).await;
        match body {
            Ok(body) => Ok(parse::parse_xrefs(&body)),
            Err(GhidraError::Reported { message: ref m, .. })
                if m == "the server returned an empty response" =>
            {
                Ok(Vec::new())
            }
            Err(e) => Err(e),
        }
    }

    /// References from `address` — what it points at.
    ///
    /// A function's *entry* has no outgoing references, because nothing inside
    /// it is the source. Pass the address of a call instruction to learn its
    /// target.
    ///
    /// The server returns a 200 with an empty body when there are no
    /// cross-references, which is a valid "no results" response rather than
    /// an error.
    #[instrument(skip(self), fields(address = format_args!("{address:#x}")))]
    pub async fn xrefs_from(&self, address: u64, limit: Option<usize>) -> Result<Vec<Xref>> {
        let mut params: Vec<(&str, String)> = vec![("address", Self::addr(address))];
        if let Some(n) = limit {
            params.push(("limit", n.to_string()));
        }
        let body = self.get_text("get_xrefs_from", &params).await;
        match body {
            Ok(body) => Ok(parse::parse_xrefs(&body)),
            Err(GhidraError::Reported { message: ref m, .. })
                if m == "the server returned an empty response" =>
            {
                Ok(Vec::new())
            }
            Err(e) => Err(e),
        }
    }

    /// References to a function, found by name.
    ///
    /// The server returns a 200 with an empty body when there are no
    /// cross-references, which is a valid "no results" response rather than
    /// an error.
    #[instrument(skip(self), fields(function))]
    pub async fn function_xrefs(&self, function: &str, limit: Option<usize>) -> Result<Vec<Xref>> {
        let mut params: Vec<(&str, String)> = vec![("name", function.to_string())];
        if let Some(n) = limit {
            params.push(("limit", n.to_string()));
        }
        let body = self.get_text("get_function_xrefs", &params).await;
        match body {
            Ok(body) => Ok(parse::parse_xrefs(&body)),
            Err(GhidraError::Reported { message: ref m, .. })
                if m == "the server returned an empty response" =>
            {
                Ok(Vec::new())
            }
            Err(e) => Err(e),
        }
    }

    /// Names of the functions that call the function at `address`.
    ///
    /// Cross-references that name no enclosing function are dropped, so this
    /// answers "which functions call this" and not "how many references exist".
    #[instrument(skip(self), fields(address = format_args!("{address:#x}")))]
    pub async fn callers(&self, address: u64) -> Result<Vec<String>> {
        let xrefs = self.xrefs_to(address, None).await?;
        let mut names: Vec<String> = Vec::new();
        for x in xrefs {
            if let Some(f) = x.function
                && !names.contains(&f)
            {
                names.push(f);
            }
        }
        Ok(names)
    }

    // =========================================================
    // Symbols and data
    // =========================================================

    /// Symbols the program exports.
    #[instrument(skip(self))]
    pub async fn exports(&self, limit: Option<usize>) -> Result<Vec<Symbol>> {
        let params = limit
            .map(|n| vec![("limit", n.to_string())])
            .unwrap_or_default();
        let body = self.get_text("list_exports", &params).await?;
        Ok(parse::parse_symbols(&body, false))
    }

    /// Symbols the program imports.
    ///
    /// Imports that resolve to an external module arrive with an `EXTERNAL:`
    /// address, which is a slot the loader fills rather than a location in the
    /// program. The 6.x bridge answers JSON; older builds answered the same
    /// `name -> address` text as exports, and both shapes are accepted.
    #[instrument(skip(self))]
    pub async fn imports(&self, limit: Option<usize>) -> Result<Vec<Symbol>> {
        let params = limit
            .map(|n| vec![("limit", n.to_string())])
            .unwrap_or_default();
        let body = self.get_text("list_imports", &params).await?;
        Ok(parse::parse_symbols_json(&body, true)
            .unwrap_or_else(|| parse::parse_symbols(&body, true)))
    }

    /// String literals defined in the program.
    #[instrument(skip(self), fields(filter))]
    pub async fn strings(
        &self,
        limit: Option<usize>,
        filter: Option<&str>,
    ) -> Result<Vec<StringLiteral>> {
        self.strings_page(0, limit.unwrap_or(DATA_PAGE), filter)
            .await
    }

    /// Every defined string in the program, collected across pages.
    ///
    /// A scan that reasons over the program's literals — grouping the ones a
    /// function shares into candidate structs, say — needs the whole listing
    /// rather than a window of it, so this pages through to the end.
    #[instrument(skip(self), fields(filter))]
    pub async fn list_strings(&self, filter: Option<&str>) -> Result<Vec<StringLiteral>> {
        let mut all = Vec::new();
        let mut offset = 0;
        loop {
            let page = self.strings_page(offset, DATA_PAGE, filter).await?;
            let got = page.len();
            all.extend(page);
            if got < DATA_PAGE {
                return Ok(all);
            }
            offset += got;
        }
    }

    /// One page of the string listing, with the server's own `offset`/`limit`
    /// windowing.
    #[instrument(skip(self), fields(offset, limit, filter))]
    pub async fn strings_page(
        &self,
        offset: usize,
        limit: usize,
        filter: Option<&str>,
    ) -> Result<Vec<StringLiteral>> {
        let mut params: Vec<(&str, String)> =
            vec![("offset", offset.to_string()), ("limit", limit.to_string())];
        if let Some(f) = filter {
            params.push(("filter", f.to_string()));
        }
        let body = self.get_text("list_strings", &params).await?;
        Ok(parse::records(&body)
            .into_iter()
            .filter_map(parse::parse_string_literal)
            .collect())
    }

    /// Namespaces defined in the program.
    #[instrument(skip(self))]
    pub async fn namespaces(&self, limit: Option<usize>) -> Result<Vec<String>> {
        let params = limit
            .map(|n| vec![("limit", n.to_string())])
            .unwrap_or_default();
        let body = self.get_text("list_namespaces", &params).await?;
        Ok(parse::records(&body)
            .into_iter()
            .map(str::to_string)
            .collect())
    }

    /// Classes defined in the program.
    #[instrument(skip(self))]
    pub async fn classes(&self, limit: Option<usize>) -> Result<Vec<String>> {
        let params = limit
            .map(|n| vec![("limit", n.to_string())])
            .unwrap_or_default();
        let body = self.get_text("list_classes", &params).await?;
        Ok(parse::records(&body)
            .into_iter()
            .map(str::to_string)
            .collect())
    }

    /// Methods defined in the program.
    #[instrument(skip(self))]
    pub async fn methods(&self, limit: Option<usize>) -> Result<Vec<String>> {
        let params = limit
            .map(|n| vec![("limit", n.to_string())])
            .unwrap_or_default();
        let body = self.get_text("list_methods", &params).await?;
        Ok(parse::records(&body)
            .into_iter()
            .map(str::to_string)
            .collect())
    }

    // =========================================================
    // Type Manager and defined data
    // =========================================================

    /// Every named type in Ghidra's Type Manager, optionally filtered by
    /// category or name fragment.
    ///
    /// The Type Manager holds types that were never applied to a symbol, so
    /// this sees more than the symbol table. Pages are collected until the
    /// server runs out.
    #[instrument(skip(self), fields(category))]
    pub async fn list_data_types(&self, category: Option<&str>) -> Result<Vec<DataTypeEntry>> {
        let mut all = Vec::new();
        let mut offset = 0;
        loop {
            let page = self.data_types_page(category, offset, DATA_PAGE).await?;
            let got = page.len();
            all.extend(page);
            if got < DATA_PAGE {
                return Ok(all);
            }
            offset += got;
        }
    }

    /// One page of the Type Manager listing, with the server's own
    /// `offset`/`limit` windowing.
    #[instrument(skip(self), fields(category, offset, limit))]
    pub async fn data_types_page(
        &self,
        category: Option<&str>,
        offset: usize,
        limit: usize,
    ) -> Result<Vec<DataTypeEntry>> {
        let mut params: Vec<(&str, String)> =
            vec![("offset", offset.to_string()), ("limit", limit.to_string())];
        if let Some(c) = category {
            params.push(("category", c.to_string()));
        }
        let body = self.get_text("list_data_types", &params).await?;
        Ok(parse::parse_data_types(&body))
    }

    /// Field layout of a structure from the Type Manager.
    ///
    /// A name the Type Manager does not know becomes [`GhidraError::NotFound`];
    /// a name that resolves to a non-structure becomes [`GhidraError::Malformed`]
    /// carrying the server's explanation.
    #[instrument(skip(self), fields(name))]
    pub async fn get_struct_layout(&self, name: &str) -> Result<StructLayout> {
        let body = self
            .get_text("get_struct_layout", &[("struct_name", name.to_string())])
            .await?;
        if let Some(missing) = Self::structure_not_found(&body) {
            return Err(missing);
        }
        parse::parse_struct_layout(&body).ok_or_else(|| GhidraError::Malformed {
            kind: "structure layout",
            detail: body.trim().to_string(),
        })
    }

    /// Members and values of an enumeration from the Type Manager.
    ///
    /// Error mapping follows [`get_struct_layout`](Self::get_struct_layout).
    #[instrument(skip(self), fields(name))]
    pub async fn get_enum_values(&self, name: &str) -> Result<EnumDefinition> {
        let body = self
            .get_text("get_enum_values", &[("enum_name", name.to_string())])
            .await?;
        if let Some(missing) = body.trim().strip_prefix("Enumeration not found: ") {
            return Err(GhidraError::NotFound {
                kind: "enumeration",
                query: missing.trim().to_string(),
            });
        }
        parse::parse_enum_values(&body).ok_or_else(|| GhidraError::Malformed {
            kind: "enumeration values",
            detail: body.trim().to_string(),
        })
    }

    /// Every defined data object in the listing, collected across pages.
    ///
    /// Large binaries hold tens of thousands of defined items, so this pages
    /// through the whole listing; use [`data_items_page`](Self::data_items_page)
    /// to work a window at a time.
    #[instrument(skip(self))]
    pub async fn list_data_items(&self) -> Result<Vec<DataItem>> {
        let mut all = Vec::new();
        let mut offset = 0;
        loop {
            let page = self.data_items_page(offset, DATA_PAGE).await?;
            let got = page.len();
            all.extend(page);
            if got < DATA_PAGE {
                return Ok(all);
            }
            offset += got;
        }
    }

    /// One page of defined data items, with the server's own `offset`/`limit`
    /// windowing.
    #[instrument(skip(self), fields(offset, limit))]
    pub async fn data_items_page(&self, offset: usize, limit: usize) -> Result<Vec<DataItem>> {
        let params = [("offset", offset.to_string()), ("limit", limit.to_string())];
        let body = self.get_text("list_data_items", &params).await?;
        Ok(parse::parse_data_items(&body))
    }

    /// The raw bytes at `address`.
    ///
    /// This is how the contents of a defined data object are read — a vtable's
    /// method pointers, an RTTI locator — which no listing endpoint reports.
    #[instrument(skip(self), fields(address = format_args!("{address:#x}"), length))]
    pub async fn read_memory(&self, address: u64, length: usize) -> Result<Vec<u8>> {
        let params = [
            ("address", Self::addr(address)),
            ("length", length.to_string()),
        ];
        let body = self.get_text("read_memory", &params).await?;
        parse::parse_memory_bytes(&body).ok_or_else(|| GhidraError::Malformed {
            kind: "memory bytes",
            detail: body.trim().to_string(),
        })
    }

    // =========================================================
    // Write-back
    // =========================================================

    /// Attach `tag` to a function, naming it by address or by name.
    ///
    /// The tag is created if it does not exist. Only functions take tags: a
    /// data address is refused with `No function found for ...`.
    #[instrument(skip(self), fields(function, tag))]
    pub async fn add_function_tag(&self, function: &str, tag: &str) -> Result<()> {
        let payload = serde_json::json!({ "function": function, "tags": tag });
        self.post_json("add_function_tag", &payload).await?;
        Ok(())
    }

    /// Set the full prototype — return type and parameter types — of the
    /// function at `function_address`.
    ///
    /// The name inside the prototype text does not rename the function: the
    /// bridge parses the signature and applies it at the address. A calling
    /// convention spelled inside the text is honoured; the function's plate
    /// comment survives the change. The bridge answers a failure as prose
    /// (`Failed to set function prototype: …`), which the error prefixes in
    /// [`error`](crate::error) turn into a [`Reported`](GhidraError::Reported).
    #[instrument(skip(self), fields(function_address, prototype))]
    pub async fn set_function_prototype(
        &self,
        function_address: u64,
        prototype: &str,
    ) -> Result<()> {
        let payload = serde_json::json!({
            "function_address": Self::addr(function_address),
            "prototype": prototype,
        });
        self.post_json("set_function_prototype", &payload).await?;
        Ok(())
    }

    /// Set the type of the variable (local or parameter) named `variable`
    /// in the function at `function_address`.
    ///
    /// The bridge decompiles the function, finds the symbol by its
    /// high-level name, and refuses an `undefined*` target; a miss on
    /// `variable` answers with the variable names it does know, which the
    /// error message carries.
    #[instrument(skip(self), fields(function_address, variable, type_name))]
    pub async fn set_local_variable_type(
        &self,
        function_address: u64,
        variable: &str,
        type_name: &str,
    ) -> Result<()> {
        let payload = serde_json::json!({
            "function_address": Self::addr(function_address),
            "variable_name": variable,
            "new_type": type_name,
        });
        self.post_json("set_local_variable_type", &payload).await?;
        Ok(())
    }

    /// Create a new structure named `name` with `fields`.
    ///
    /// Every field type must already resolve in the Type Manager — create
    /// the named types a layout refers to before the layout that uses them
    /// — and a same-named type already in the manager is an error, not a
    /// silent replace.
    #[instrument(skip(self, fields), fields(name, field_count = fields.len()))]
    pub async fn create_struct(&self, name: &str, fields: &[NewStructField<'_>]) -> Result<()> {
        let fields: Vec<serde_json::Value> = fields
            .iter()
            .map(|field| {
                let mut entry = serde_json::json!({ "name": field.name, "type": field.type_name });
                if let Some(offset) = field.offset {
                    entry["offset"] = serde_json::json!(offset);
                }
                entry
            })
            .collect();
        let payload = serde_json::json!({ "name": name, "fields": fields });
        self.post_json("create_struct", &payload).await?;
        Ok(())
    }

    /// Create a new enumeration named `name`, `size` bytes wide (1, 2, 4,
    /// or 8), whose members are `values` (member name → value).
    #[instrument(skip(self, values), fields(name, member_count = values.len(), size))]
    pub async fn create_enum(&self, name: &str, values: &[(&str, i64)], size: u32) -> Result<()> {
        // The bridge takes the members as a JSON object, name to value.
        let mut members = serde_json::Map::new();
        for (member, value) in values {
            members.insert((*member).to_string(), serde_json::json!(value));
        }
        let payload = serde_json::json!({ "name": name, "values": members, "size": size });
        self.post_json("create_enum", &payload).await?;
        Ok(())
    }

    /// Create a typedef `name` as an alias for `base_type` — any type
    /// Ghidra can resolve, pointer spellings (`char *`) included.
    #[instrument(skip(self), fields(name, base_type))]
    pub async fn create_typedef(&self, name: &str, base_type: &str) -> Result<()> {
        let payload = serde_json::json!({ "name": name, "base_type": base_type });
        self.post_json("create_typedef", &payload).await?;
        Ok(())
    }

    /// Add one field to the existing structure `struct_name`.
    ///
    /// `offset` of `Some` places the field at that byte offset (growing the
    /// structure to fit); `None` appends it at the end. A missing structure
    /// answers the same prose sentinel the read side refuses
    /// (`Structure not found: X`), so it becomes a named
    /// [`NotFound`](GhidraError::NotFound) here too.
    #[instrument(skip(self), fields(struct_name, field_name, field_type, offset))]
    pub async fn add_struct_field(
        &self,
        struct_name: &str,
        field_name: &str,
        field_type: &str,
        offset: Option<u32>,
    ) -> Result<()> {
        let mut payload = serde_json::json!({
            "struct_name": struct_name,
            "field_name": field_name,
            "field_type": field_type,
        });
        if let Some(offset) = offset {
            payload["offset"] = serde_json::json!(offset);
        }
        let body = self.post_json("add_struct_field", &payload).await?;
        if let Some(missing) = Self::structure_not_found(&body) {
            return Err(missing);
        }
        Ok(())
    }

    // =========================================================
    // Availability and program selection
    // =========================================================

    /// Ask the server *who are you*: which kind of GhidraMCP answers, and
    /// which plugin version and program its answer names.
    ///
    /// This is the canonical identity check. Its failure modes are named by
    /// cause: nothing answering at all is [`ServerUnreachable`](GhidraError::ServerUnreachable),
    /// a port that answers HTTP but not as GhidraMCP (the local AI on 8080)
    /// is [`NotGhidraMcp`](GhidraError::NotGhidraMcp) rather than a
    /// malformed-response puzzle, and a plugin older than ADR-0001's bridge
    /// is [`VersionMismatch`](GhidraError::VersionMismatch).
    pub async fn check_connection(&self) -> Result<ServerInfo> {
        let body = self
            .get_text("check_connection", &[])
            .await
            .map_err(|err| match err {
                GhidraError::Transport { url, source } => {
                    GhidraError::ServerUnreachable { url, source }
                }
                GhidraError::InvalidUrl(source) => GhidraError::InvalidUrl(source),
                other => GhidraError::NotGhidraMcp {
                    url: self.config.base_url.to_string(),
                    hint: format!("its answer was not GhidraMCP's: {other}"),
                },
            })?;
        let info = parse::parse_connection(&body).ok_or_else(|| GhidraError::NotGhidraMcp {
            url: self.config.base_url.to_string(),
            hint: format!("it answered `{}` instead of naming GhidraMCP", body.trim()),
        })?;
        if let Some(version) = &info.version
            && !plugin_version_at_least(version, MIN_PLUGIN_VERSION)
        {
            return Err(GhidraError::VersionMismatch {
                found: version.clone(),
                required: MIN_PLUGIN_VERSION.to_string(),
            });
        }
        info!(
            kind = %info.kind,
            version = info.version.as_deref().unwrap_or("unnamed"),
            program = info.program.as_deref().unwrap_or("none"),
            "Identified the GhidraMCP server"
        );
        Ok(info)
    }

    /// Whether the server is up and a program is open.
    ///
    /// The check branches on the server kind the identity probe reports: a
    /// GUI instance is verified through its cursor endpoints, while a
    /// headless server — which has no cursor at all — is verified through
    /// `get_metadata`'s current-program block instead. This is the check to
    /// run before a long pipeline to fail early with a clear reason.
    pub async fn probe(&self) -> Result<ProgramInfo> {
        let server = self.check_connection().await?;
        match server.kind {
            ServerKind::Gui => {
                let body = self.get_text("get_current_address", &[]).await?;
                let address =
                    parse::parse_current_address(&body).ok_or_else(|| GhidraError::Malformed {
                        kind: "the current address",
                        detail: body.trim().to_string(),
                    })?;
                let program = parse::json_string(&body, "program")
                    .or(server.program)
                    .unwrap_or_default();
                let function = self.current_function().await?;
                info!(
                    program = %program,
                    function = %function.name,
                    address = format_args!("{address:#x}"),
                    "GhidraMCP is serving"
                );
                Ok(ProgramInfo {
                    program,
                    function: Some(function.name),
                    address: Some(address),
                })
            }
            ServerKind::Headless => {
                let body = self.get_text("get_metadata", &[]).await?;
                let program = parse::parse_metadata_program(&body)
                    .or(server.program)
                    .unwrap_or_default();
                info!(program = %program, "GhidraMCP headless server is serving");
                Ok(ProgramInfo {
                    program,
                    function: None,
                    address: None,
                })
            }
        }
    }

    /// The programs currently open in the Ghidra instance.
    ///
    /// The 6.x bridge can hold several at once; queries answer against the
    /// current one, which [`switch_program`](Self::switch_program) changes.
    #[instrument(skip(self))]
    pub async fn open_programs(&self) -> Result<Vec<OpenProgram>> {
        let body = self.get_text("list_open_programs", &[]).await?;
        let programs = parse::parse_open_programs(&body);
        debug!(count = programs.len(), "Listed open programs");
        Ok(programs)
    }

    /// Make `program` the one queries run against.
    ///
    /// `program` is the name or project path shown by
    /// [`open_programs`](Self::open_programs). Every other method on this
    /// client follows the switch, so a pipeline that assumed the previous
    /// program's addresses must re-resolve them.
    #[instrument(skip(self), fields(program))]
    pub async fn switch_program(&self, program: &str) -> Result<()> {
        let body = self
            .get_text("switch_program", &[("program", program.to_string())])
            .await?;
        let switched_to = parse::json_string(&body, "switched_to").unwrap_or_default();
        info!(program = %switched_to, "Switched GhidraMCP's current program");
        Ok(())
    }

    /// Close the project the headless server currently holds open.
    ///
    /// A headless server owns its project for the life of the process; an
    /// owned server gets this call before its process is killed so Ghidra
    /// releases the project's lock cleanly rather than by signal. A GUI
    /// server's project belongs to the human at the window — this is only
    /// ever called on a server calxgloss started.
    #[instrument(skip(self))]
    pub async fn close_project(&self) -> Result<()> {
        self.get_text("close_project", &[]).await?;
        info!("Closed the GhidraMCP server's project");
        Ok(())
    }

    // =========================================================
    // Project bootstrap and program loading (issue #116, G1-T6)
    // =========================================================

    /// What project the server currently holds open, if any.
    #[instrument(skip(self))]
    pub async fn project_info(&self) -> Result<ProjectInfo> {
        let body = self.get_text("get_project_info", &[]).await?;
        parse::parse_project_info(&body).ok_or_else(|| GhidraError::Malformed {
            kind: "project info",
            detail: body.trim().to_string(),
        })
    }

    /// Open the existing project whose `.gpr` file (or project directory) is
    /// at `path`.
    #[instrument(skip(self), fields(path))]
    pub async fn open_project(&self, path: &str) -> Result<()> {
        let payload = serde_json::json!({ "path": path });
        self.post_json("open_project", &payload).await?;
        info!(path, "Opened the GhidraMCP server's project");
        Ok(())
    }

    /// Create a new project named `name` under `parent_dir` and open it.
    #[instrument(skip(self), fields(parent_dir, name))]
    pub async fn create_project(&self, parent_dir: &str, name: &str) -> Result<()> {
        let payload = serde_json::json!({ "parentDir": parent_dir, "name": name });
        self.post_json("create_project", &payload).await?;
        info!(parent_dir, name, "Created the GhidraMCP server's project");
        Ok(())
    }

    /// Import the binary at `file` into the server's project and make it the
    /// current program.
    ///
    /// The bridge imports into the project root and, when a program of that
    /// name is already in the project, reopens it instead of re-importing —
    /// so this is safe to call for a binary the project already holds. It
    /// does *not* run analysis; that is [`run_analysis`](Self::run_analysis).
    #[instrument(skip(self), fields(file))]
    pub async fn load_program(&self, file: &str) -> Result<LoadedProgram> {
        let payload = serde_json::json!({ "file": file });
        let body = self.post_json("load_program", &payload).await?;
        let loaded = parse::parse_loaded_program(&body).ok_or_else(|| GhidraError::Malformed {
            kind: "a loaded-program result",
            detail: body.trim().to_string(),
        })?;
        info!(program = %loaded.name, "Loaded a program into the GhidraMCP server");
        Ok(loaded)
    }

    /// Open the program stored at project path `path` in the open project.
    ///
    /// Answers `Ok(None)` when the project holds no program at that path:
    /// the bridge reports a miss as HTTP 200 with `{"success":false,...}`,
    /// which the transport's error classification never sees, so the client
    /// reads the miss out of the body. A hard failure — no project open, a
    /// malformed answer — is still an `Err`.
    #[instrument(skip(self), fields(path))]
    pub async fn load_program_from_project(&self, path: &str) -> Result<Option<LoadedProgram>> {
        let payload = serde_json::json!({ "path": path });
        let body = self
            .post_json("load_program_from_project", &payload)
            .await?;
        if let Some(loaded) = parse::parse_loaded_program(&body) {
            info!(program = %loaded.name, "Opened a program from the Ghidra project");
            return Ok(Some(loaded));
        }
        match parse::parse_load_failure(&body) {
            Some(reason) => {
                debug!(path, reason, "Program is not in the Ghidra project");
                Ok(None)
            }
            None => Err(GhidraError::Malformed {
                kind: "a from-project load result",
                detail: body.trim().to_string(),
            }),
        }
    }

    /// Run Ghidra's full auto-analysis on `program` (the current program when
    /// `None`), blocking until it finishes.
    ///
    /// The endpoint holds the request open for as long as the analysis takes
    /// — minutes for a large DLL — so this request runs on the client's slow
    /// transport with [`ANALYSIS_TIMEOUT`]. Poll [`analysis_status`] from a
    /// concurrent task to watch progress while this call is in flight.
    #[instrument(skip(self), fields(program))]
    pub async fn run_analysis(&self, program: Option<&str>) -> Result<AnalysisOutcome> {
        let params = program
            .map(|p| vec![("program", p.to_string())])
            .unwrap_or_default();
        let body = self
            .post_json_on(
                &self.slow_http,
                "run_analysis",
                &params,
                &serde_json::json!({}),
            )
            .await?;
        let outcome =
            parse::parse_analysis_outcome(&body).ok_or_else(|| GhidraError::Malformed {
                kind: "an analysis result",
                detail: body.trim().to_string(),
            })?;
        info!(
            program = %outcome.program,
            secs = outcome.duration_ms / 1000,
            functions = outcome.total_functions,
            "Ghidra auto-analysis finished"
        );
        Ok(outcome)
    }

    /// Auto-analysis state for `program` (every open program when `None`).
    #[instrument(skip(self), fields(program))]
    pub async fn analysis_status(&self, program: Option<&str>) -> Result<Vec<AnalysisStatus>> {
        let params = program
            .map(|p| vec![("program", p.to_string())])
            .unwrap_or_default();
        let body = self.get_text("analysis_status", &params).await?;
        Ok(parse::parse_analysis_status(&body))
    }
}

/// A summary of what the server is currently serving.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProgramInfo {
    /// Name of the open program, as the server reports it.
    pub program: String,
    /// Name of the function under Ghidra's cursor — a GUI concept, so a
    /// headless server reports `None`.
    pub function: Option<String>,
    /// Address of Ghidra's cursor — `None` for the same reason.
    pub address: Option<u64>,
}

/// Whether a plugin version the server named is at least `minimum`.
///
/// Versions are dot-separated numbers (`6.0.0`); a pre-release or build
/// suffix (`6.0.0-rc1`) is compared on its numeric core, missing trailing
/// components count as zero, and a version that will not parse at all is
/// not treated as too old — the probe logs the raw string, and refusing a
/// server over an unrecognised version spelling would be guessing in the
/// wrong direction.
pub fn plugin_version_at_least(found: &str, minimum: &str) -> bool {
    let numbers = |version: &str| -> Option<Vec<u64>> {
        let core = version.split(['-', '+']).next().unwrap_or(version);
        core.split('.')
            .map(|part| part.parse::<u64>().ok())
            .collect()
    };
    match (numbers(found), numbers(minimum)) {
        (Some(found), Some(minimum)) => {
            let width = found.len().max(minimum.len());
            for i in 0..width {
                let (f, m) = (*found.get(i).unwrap_or(&0), *minimum.get(i).unwrap_or(&0));
                if f != m {
                    return f > m;
                }
            }
            true
        }
        _ => true,
    }
}

/// Convert a Ghidra virtual address into a file-relative one.
///
/// The program's image base is the lowest mapped address, and subtracting it
/// yields the RVA the PE headers index exports and imports by.
pub fn rva_from_va(image_base: u64, va: u64) -> Option<u32> {
    let rva = va.checked_sub(image_base)?;
    u32::try_from(rva).ok()
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_defaults() {
        let config = GhidraConfig::new("http://127.0.0.1:8080").unwrap();
        assert_eq!(config.base_url.as_str(), "http://127.0.0.1:8080/");
        assert_eq!(config.timeout, Duration::from_secs(120));
        assert!(config.api_key.is_none());
    }

    #[test]
    fn test_config_rejects_a_non_url() {
        assert!(GhidraConfig::new("not-a-url").is_err());
    }

    #[test]
    fn test_client_exposes_its_base_url() {
        let client = GhidraClient::new("http://127.0.0.1:8080").unwrap();
        assert_eq!(client.base_url().as_str(), "http://127.0.0.1:8080/");
    }

    #[test]
    fn test_addresses_are_sent_as_bare_hex() {
        // Ghidra writes addresses without a prefix and does not parse one, so
        // the client must not add it.
        assert_eq!(GhidraClient::addr(0x18008ed50), "18008ed50");
    }

    #[test]
    fn test_rva_from_va() {
        assert_eq!(rva_from_va(0x180000000, 0x18008ed50), Some(0x8ed50));
        // A VA below the image base is not addressable, and silently wrapping
        // would produce a plausible-looking but wrong RVA.
        assert_eq!(rva_from_va(0x180000000, 0x17ffffff), None);
    }

    #[test]
    fn heartbeat_beats_per_decompile_only_while_a_pass_is_active() {
        let client = GhidraClient::new("http://127.0.0.1:9").unwrap();
        let events = calxgloss_types::TranslationEvents::new(64);
        let mut rx = events.subscribe();

        client.begin_pass("eqgame.exe", "type inference", &events);
        client.note_worklist(&[
            FunctionSummary {
                name: "FUN_10".into(),
                address: 0x10,
            },
            FunctionSummary {
                name: "FUN_20".into(),
                address: 0x20,
            },
        ]);
        client.tick(0x10);
        client.tick(0x20);
        client.end_pass();
        client.tick(0x30); // outside any pass — must not beat

        let beats: Vec<calxgloss_types::ProgressEvent> =
            std::iter::from_fn(|| rx.try_recv().ok()).collect();
        assert_eq!(beats.len(), 2, "one beat per decompile inside the pass");
        match &beats[0] {
            calxgloss_types::ProgressEvent::BatchProgress {
                binary,
                pass,
                function,
                index,
                total,
            } => {
                assert_eq!(binary, "eqgame.exe");
                assert_eq!(pass, "type inference");
                assert_eq!(function, "FUN_10", "address resolved through the worklist");
                assert_eq!(*index, 1);
                assert_eq!(*total, 2);
            }
            other => panic!("expected BatchProgress, got {other:?}"),
        }
        match &beats[1] {
            calxgloss_types::ProgressEvent::BatchProgress {
                function,
                index,
                total,
                ..
            } => {
                assert_eq!(function, "FUN_20");
                assert_eq!(*index, 2);
                assert_eq!(*total, 2);
            }
            other => panic!("expected BatchProgress, got {other:?}"),
        }
    }

    #[test]
    fn test_reported_error_mentions_the_message() {
        let err = GhidraError::Reported {
            status: Some(200),
            message: "Function not found".to_string(),
        };
        assert!(err.to_string().contains("Function not found"));
    }

    #[test]
    fn test_plugin_version_comparison() {
        assert!(plugin_version_at_least("6.0.0", MIN_PLUGIN_VERSION));
        assert!(plugin_version_at_least("6.1.2", MIN_PLUGIN_VERSION));
        assert!(plugin_version_at_least("7.0.0", MIN_PLUGIN_VERSION));
        assert!(!plugin_version_at_least("5.4.0", MIN_PLUGIN_VERSION));
        assert!(!plugin_version_at_least("5.9.9", MIN_PLUGIN_VERSION));
        assert!(!plugin_version_at_least("5.9", MIN_PLUGIN_VERSION));
        // Missing trailing components count as zero, so `6.0` is `6.0.0`.
        assert!(plugin_version_at_least("6.0", MIN_PLUGIN_VERSION));
        assert!(plugin_version_at_least("6", MIN_PLUGIN_VERSION));
        // A pre-release suffix compares on its numeric core.
        assert!(plugin_version_at_least("6.0.0-rc1", MIN_PLUGIN_VERSION));
        assert!(!plugin_version_at_least("5.4.0-rc1", MIN_PLUGIN_VERSION));
        // An unrecognised spelling is not a reason to refuse the server.
        assert!(plugin_version_at_least("nightly", MIN_PLUGIN_VERSION));
    }
}
