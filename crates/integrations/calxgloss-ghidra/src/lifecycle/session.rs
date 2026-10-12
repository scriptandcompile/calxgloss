//! The preflight every Ghidra-dependent command starts from: attach to a
//! running server or spawn a headless one, with ownership tracked explicitly.
//!
//! [`GhidraSession::ensure`] replaces the bare client construction + probe
//! each command used to do by hand. It runs the same checks `calxgloss
//! doctor` reports (install, extension pairing, server identity), then:
//!
//! * a server that answers the identity probe is **attached** — a running
//!   GUI instance is never closed, never killed (design risk 5);
//! * a port that answers as something else, or an under-versioned plugin,
//!   fails fast with the probe's own named error — spawning over a foreign
//!   port is never attempted;
//! * nothing answering first consults the bridge's runtime-socket directory
//!   ([`discovery`]): a live server registered there means the configured
//!   port is merely stale, and the session attaches to the discovered one
//!   with the correction logged (design risk 4);
//! * only when nothing is discovered does a supervised headless server
//!   spawn ([`server`]), but only after the install and extension checks
//!   pass — a spawn with no valid stack fails with what is missing — and
//!   on a free port: the configured one if free, else the bridge default
//!   (design risk 4: never bind a busy port).
//!
//! Spawned servers run with `GHIDRA_MCP_REQUIRE_PROGRAM_SELECTORS=1` and
//! are **owned**: [`shutdown`](GhidraSession::shutdown) closes their project
//! and kills the process, and the wrong-program guard
//! ([`ensure_current_program`](GhidraSession::ensure_current_program)) rides
//! on the session so every scan verifies its target first (the 2026-10-08
//! incident fix).

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use calxgloss_types::{ProgressEvent, TranslationEvents};
use tracing::{info, warn};

use super::StackRequest;
use super::discovery::{self, DiscoveredServer};
use super::extension::{self, ExtensionDiscovery, ExtensionVerdict, GhidraExtension};
use super::install::{self, GhidraInstall, InstallDiscovery};
use super::program::{self, ProgramMatch};
use super::project::{self, ProjectSetup};
use super::server::{self, OwnedServer};
use crate::client::{
    GhidraClient, GhidraConfig, GhidraError, MIN_PLUGIN_VERSION, Result, plugin_version_at_least,
};
use crate::model::{ServerInfo, ServerKind};

/// The boot budget for a spawned headless server — JVM plus Ghidra startup
/// is slow, and the design doc's proven budget is ~90 s.
pub const DEFAULT_START_TIMEOUT: Duration = Duration::from_secs(90);

/// Who owns the server the session is talking to (design risk 5): killing
/// or closing anything follows from this, never from the server's kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ownership {
    /// calxgloss started this server — it closes the project and kills the
    /// process when the session shuts down.
    Owned,
    /// Someone else's server — normally a GUI instance with a human at the
    /// window. calxgloss never closes its project or kills its process.
    Attached,
}

/// The `ghidra.headless` preference (G1-T7): who serves a run when more
/// than one shape of server is possible.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HeadlessMode {
    /// Attach to a running server when one answers, spawn a headless one
    /// when nothing does — today's behavior, and the default.
    #[default]
    Auto,
    /// Prefer a headless instance: spawn one even when a GUI is open and
    /// answering. A headless server that is already running is still
    /// attached to — it already is what `always` asks for.
    Always,
    /// GUI-only: attach to a running server, never spawn.
    Never,
}

impl std::str::FromStr for HeadlessMode {
    type Err = ();

    fn from_str(s: &str) -> std::result::Result<Self, ()> {
        match s.trim().to_ascii_lowercase().as_str() {
            "auto" => Ok(Self::Auto),
            "always" => Ok(Self::Always),
            "never" => Ok(Self::Never),
            _ => Err(()),
        }
    }
}

impl std::fmt::Display for HeadlessMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Auto => write!(f, "auto"),
            Self::Always => write!(f, "always"),
            Self::Never => write!(f, "never"),
        }
    }
}

/// The resolved inputs of a preflight, injectable so tests point every
/// lookup at fixtures instead of the real machine — the same shape
/// [`StackRequest`] established for `doctor`.
#[derive(Debug, Clone)]
pub struct SessionRequest<'a> {
    /// The configured GhidraMCP URL (`--ghidra-url` / env / config).
    pub url: &'a str,
    /// Optional bearer token for the client.
    pub api_key: Option<&'a str>,
    /// The run's project path (`<workspace>/ghidra/<target>.gpr`, or the
    /// `ghidra.project` override): the log and pid files live beside it,
    /// and an existing project is reopened by the spawned server.
    pub project: &'a Path,
    /// The bridge's runtime-socket directory (`$XDG_RUNTIME_DIR/ghidra-mcp`),
    /// when known: a configured port that nothing answers is reconciled
    /// against the live servers registered there before a spawn is considered.
    pub socket_dir: Option<&'a Path>,
    /// The port to spawn on when the configured one is busy — the bridge
    /// default 8080 in production. calxgloss never binds a busy port, so a
    /// spawn needs whichever of the two is free.
    pub fallback_port: u16,
    /// The filesystem discovery inputs for the install and extension checks.
    pub stack: StackRequest<'a>,
    /// How long a spawned server may take to answer the probe
    /// (`ghidra.start_timeout_secs`).
    pub start_timeout: Duration,
    /// Whether a spawn is allowed at all (`ghidra.auto_start` /
    /// `--no-ghidra-autostart`): false makes the preflight check-only,
    /// failing fast with what a spawn would need.
    pub auto_start: bool,
    /// The GUI-vs-headless preference (`ghidra.headless`).
    pub headless: HeadlessMode,
    /// The `ghidra.min_version` floor for the install check, when set.
    pub min_version: Option<&'a str>,
}

/// A GhidraMCP client plus the ownership the preflight established for it.
///
/// Commands pull the client through [`client`](Self::client) and run every
/// scan behind [`ensure_current_program`](Self::ensure_current_program);
/// [`shutdown`](Self::shutdown) releases an owned server at the end of the
/// command. Dropping the session without shutting down still kills a spawned
/// child (`kill_on_drop`) and removes its pid file — only the graceful
/// project close is lost.
#[derive(Debug)]
pub struct GhidraSession {
    client: GhidraClient,
    info: ServerInfo,
    ownership: Ownership,
    /// The run's project path (`<workspace>/ghidra/<target>.gpr`), kept so
    /// [`ensure_project`](Self::ensure_project) bootstraps the one the
    /// preflight was asked for.
    project: PathBuf,
    /// The supervised child, present exactly when `ownership` is `Owned`.
    server: Option<OwnedServer>,
}

impl GhidraSession {
    /// Run the preflight: probe, then attach to what answered — or, when
    /// nothing did, to what the bridge's runtime-socket directory reports —
    /// or spawn a headless server under the checks the doctor reports.
    ///
    /// The `ghidra.headless` preference (G1-T7) steers the attach-vs-spawn
    /// decision: `always` spawns a headless server even when a GUI answers
    /// (a headless server already running is still attached to), and
    /// `never` — like `auto_start = false` — turns the preflight check-only,
    /// failing with what is missing instead of spawning.
    ///
    /// `events`, when given, receives a [`ProgressEvent::GhidraServerStarted`]
    /// the moment a spawned server answers its first probe.
    ///
    /// # Errors
    ///
    /// - [`GhidraError::NotGhidraMcp`] / [`GhidraError::VersionMismatch`] —
    ///   the configured port answered, but not as a usable GhidraMCP server;
    ///   nothing is spawned over it.
    /// - [`GhidraError::CannotSpawn`] — a spawn was needed but autostart is
    ///   off, or the install or extension checks failed; the reason names
    ///   what is missing.
    /// - [`GhidraError::PortBusy`] — a spawn was needed and nothing was
    ///   discovered, but neither the configured port nor the fallback is
    ///   free to bind.
    /// - [`GhidraError::SpawnFailed`] / [`GhidraError::BootTimeout`] — the
    ///   spawn itself failed; the message names the server's log.
    pub async fn ensure(
        request: &SessionRequest<'_>,
        events: Option<&TranslationEvents>,
    ) -> Result<Self> {
        let client = client_at(request.url, request.api_key)?;

        match client.check_connection().await {
            Ok(info) => {
                // `headless = always` wants a headless instance even with a
                // GUI open — but a headless server that already answers *is*
                // one, so it is attached to like any other.
                if request.headless == HeadlessMode::Always && info.kind == ServerKind::Gui {
                    info!(
                        url = %client.base_url(),
                        "ghidra.headless = always: spawning a headless server instead of attaching to the GUI"
                    );
                    return Self::start_headless(client, request, events).await;
                }
                info!(
                    kind = %info.kind,
                    url = %client.base_url(),
                    "Attached to a running GhidraMCP server"
                );
                Ok(Self {
                    client,
                    info,
                    ownership: Ownership::Attached,
                    project: request.project.to_path_buf(),
                    server: None,
                })
            }
            // Nothing answered: reconcile against the bridge's registrations
            // before a spawn is even considered.
            Err(GhidraError::ServerUnreachable { .. }) => {
                match Self::attach_discovered(&client, request).await {
                    // A discovered GUI does not satisfy `headless = always`;
                    // anything else attachable is taken as-is.
                    Some(session)
                        if !(request.headless == HeadlessMode::Always
                            && session.info.kind == ServerKind::Gui) =>
                    {
                        Ok(session)
                    }
                    _ => Self::start_headless(client, request, events).await,
                }
            }
            // A foreign port or an old plugin is a named failure to fix by
            // configuration — never something to spawn over.
            Err(other) => Err(other),
        }
    }

    /// The reconciliation half (G1-T5): a configured port that nothing
    /// answers may merely be *stale* — a reboot, or the bridge's own
    /// port-range fallback, moved the server elsewhere — and every live
    /// server registers its real TCP port in the bridge's runtime-socket
    /// directory. The first discovered server that answers the identity
    /// probe wins, the correction is logged, and the session is **attached**:
    /// a discovered server is someone else's process, never owned.
    async fn attach_discovered(
        configured: &GhidraClient,
        request: &SessionRequest<'_>,
    ) -> Option<Self> {
        let servers = discovery::discover(request.socket_dir?);
        for server in servers {
            let session =
                Self::attach_one(configured, &server, request.api_key, request.project).await;
            if session.is_some() {
                return session;
            }
        }
        None
    }

    /// Probe one discovered server on its own port; attach when it answers
    /// as a usable GhidraMCP server, and let the caller move on when it does
    /// not — a registration can always be mid-death between scan and probe.
    async fn attach_one(
        configured: &GhidraClient,
        server: &DiscoveredServer,
        api_key: Option<&str>,
        project: &Path,
    ) -> Option<Self> {
        let port = server.port?;
        let url = format!("http://127.0.0.1:{port}");
        let client = match client_at(&url, api_key) {
            Ok(client) => client,
            Err(err) => {
                warn!(%url, pid = server.pid, error = %err, "A discovered GhidraMCP port could not be probed");
                return None;
            }
        };
        match client.check_connection().await {
            Ok(info) => {
                info!(
                    configured = %configured.base_url(),
                    discovered = %client.base_url(),
                    pid = server.pid,
                    project = server.project.as_deref().unwrap_or("unknown"),
                    "Corrected a stale configured Ghidra URL to a discovered server"
                );
                Some(Self {
                    client,
                    info,
                    ownership: Ownership::Attached,
                    project: project.to_path_buf(),
                    server: None,
                })
            }
            Err(err) => {
                warn!(%url, pid = server.pid, error = %err, "A discovered GhidraMCP server did not answer the identity probe");
                None
            }
        }
    }

    /// The spawn half: the autostart controls, then doctor's checks as
    /// preconditions, a free port, then the supervised launch and boot poll.
    async fn start_headless(
        client: GhidraClient,
        request: &SessionRequest<'_>,
        events: Option<&TranslationEvents>,
    ) -> Result<Self> {
        // The autostart controls (G1-T7): `auto_start = false` /
        // `--no-ghidra-autostart` and `headless = never` both make the
        // preflight check-only — it reports what a spawn would need and
        // fails, spawning nothing.
        let off_knob = if !request.auto_start {
            Some("`ghidra.auto_start = false` (or `--no-ghidra-autostart`)")
        } else if request.headless == HeadlessMode::Never {
            Some("`ghidra.headless = never`")
        } else {
            None
        };
        if let Some(knob) = off_knob {
            let state = match spawn_prerequisites(request) {
                Ok(_) => "the install and extension checks pass — start a \
                          GhidraMCP server yourself, or turn autostart back on"
                    .to_string(),
                Err(missing) => format!("what a spawn would need: {missing}"),
            };
            return Err(GhidraError::CannotSpawn {
                reason: format!(
                    "no GhidraMCP server answered at {}, and calxgloss will not start one \
                     because of {knob}; {state}",
                    client.base_url()
                ),
            });
        }

        let (install, extension) =
            spawn_prerequisites(request).map_err(|reason| GhidraError::CannotSpawn { reason })?;

        // The port the configured URL names, and a bind address: loopback
        // unless the URL itself names a literal address — the bridge's
        // posture is localhost-only, and calxgloss never exposes Ghidra.
        let url = client.base_url().clone();
        let configured = url
            .port_or_known_default()
            .ok_or_else(|| GhidraError::CannotSpawn {
                reason: format!("the configured URL {url} names no port to spawn on"),
            })?;
        let host = url.host_str().unwrap_or("127.0.0.1");
        let bind = if host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback()) {
            host.to_string()
        } else if host == "localhost" {
            "127.0.0.1".to_string()
        } else {
            return Err(GhidraError::CannotSpawn {
                reason: format!(
                    "the configured URL {url} points at a remote host; calxgloss only spawns \
                     headless servers locally"
                ),
            });
        };
        // Log and pid beside the project, per the design.
        let beside = request.project.parent().unwrap_or(request.project);
        let log = beside.join("headless.log");
        let pid_file = beside.join("headless.pid");

        // Pid-file reuse across runs (G1-T7): a crashed run leaves its pid
        // file beside the project. Deal with the orphan — or the stale file
        // — *before* choosing a port, so a live orphan holding the
        // configured or fallback port is reaped first and the fresh spawn
        // neither collides with it nor trusts a file whose process is gone.
        server::reap_stale_pid_file(&pid_file).await;

        // Never bind a busy port (design risk 4): the configured port when
        // it is free, else the bridge default — and when neither is free,
        // a named failure instead of a bind attempt. The one exception is
        // `headless = always`: a GUI holding the configured port is exactly
        // the case that preference exists for, so it takes any free port
        // and the client follows.
        let port = match server::spawn_port(&bind, configured, request.fallback_port) {
            Some(port) => port,
            None if request.headless == HeadlessMode::Always => match server::free_port(&bind) {
                Some(port) => {
                    info!(
                        configured,
                        spawn = port,
                        "ghidra.headless = always: taking a free port past the busy ones"
                    );
                    port
                }
                None => {
                    return Err(GhidraError::PortBusy {
                        url: url.to_string(),
                    });
                }
            },
            None => {
                return Err(GhidraError::PortBusy {
                    url: url.to_string(),
                });
            }
        };
        // The client must talk to the port the server actually takes, so a
        // spawn that fell back off the configured port repoints the client.
        let client = if port == configured {
            client
        } else {
            info!(
                configured,
                spawn = port,
                "Configured Ghidra port is busy; spawning on the fallback"
            );
            let mut spawn_url = url.clone();
            spawn_url
                .set_port(Some(port))
                .map_err(|_| GhidraError::CannotSpawn {
                    reason: format!("the configured URL {url} cannot be pointed at port {port}"),
                })?;
            client_at(spawn_url.as_str(), request.api_key)?
        };

        let plan =
            server::LaunchPlan::build(&install, &extension, port, &bind, Some(request.project))
                .ok_or_else(|| GhidraError::CannotSpawn {
                    reason: format!(
                        "the GhidraMCP extension at {} names no GhidraMCP-*.jar in its lib/",
                        extension.dir.display()
                    ),
                })?;

        let mut server = server::spawn_server(&plan, &log, &pid_file)?;
        let info = match server::wait_for_boot(&mut server, &client, request.start_timeout).await {
            Ok(info) => info,
            Err(err) => {
                // Whatever half-booted is ours: take it down before the
                // error propagates, so a failed preflight leaks no JVM.
                server.shutdown(&client).await;
                return Err(err);
            }
        };

        if let Some(events) = events {
            events.emit(ProgressEvent::GhidraServerStarted {
                url: client.base_url().to_string(),
                pid: server.pid,
            });
        }
        Ok(Self {
            client,
            info,
            ownership: Ownership::Owned,
            project: request.project.to_path_buf(),
            server: Some(server),
        })
    }

    /// The client to run queries through.
    pub fn client(&self) -> &GhidraClient {
        &self.client
    }

    /// What the identity probe learned — kind, version, current program.
    pub fn server_info(&self) -> &ServerInfo {
        &self.info
    }

    /// Whether this session owns (and will shut down) its server.
    pub fn ownership(&self) -> Ownership {
        self.ownership
    }

    /// Run the wrong-program guard for `target` before any scan against it
    /// (the 2026-10-08 incident fix): verify the server is serving the scan
    /// target, switch to it when it is open but not current, and fail fast
    /// naming the programs that *are* open when it is not.
    pub async fn ensure_current_program(&self, target: &str) -> Result<ProgramMatch> {
        program::ensure_current_program(&self.client, target).await
    }

    /// Bootstrap the run's Ghidra project (issue #116, G1-T6): create or
    /// open the session's project on the server, then load every binary in
    /// `binaries` and analyze what the analysis cache has not already
    /// covered. See [`project`]'s module docs for the cascade and the
    /// cache; `workspace` roots the cache and the `.gitignore` rule.
    pub async fn ensure_project(
        &self,
        workspace: &Path,
        binaries: &[PathBuf],
        events: Option<&TranslationEvents>,
    ) -> Result<ProjectSetup> {
        project::ensure_project(&self.client, &self.project, workspace, binaries, events).await
    }

    /// The project path this session bootstraps.
    pub fn project_path(&self) -> &Path {
        &self.project
    }

    /// Release the session: an owned server gets its project closed and its
    /// process killed; an attached server gets nothing at all — its owner is
    /// a human, or the next command's preflight.
    pub async fn shutdown(self) {
        match self.server {
            Some(server) => server.shutdown(&self.client).await,
            None => info!(
                url = %self.client.base_url(),
                "Leaving the GhidraMCP server calxgloss only attached to running untouched"
            ),
        }
    }
}

/// Build a client for `url` with the request's bearer token, when it has
/// one — the one place the preflight constructs a [`GhidraClient`], so the
/// configured URL, a discovered URL, and a fallback-port URL all carry the
/// same connection settings.
fn client_at(url: &str, api_key: Option<&str>) -> Result<GhidraClient> {
    let mut config = GhidraConfig::new(url)?;
    if let Some(key) = api_key {
        config = config.with_api_key(key);
    }
    GhidraClient::from_config(config)
}

/// The doctor checks a spawn cannot run without — a valid install meeting the
/// `ghidra.min_version` floor, paired with a loadable extension built for it
/// (G1-T7). `Ok` hands back both so the launch plan can be built without
/// rediscovering them; `Err` names what is missing in the same words the
/// preflight has always used, so the check-only failure path and the spawn
/// path report the same problem.
fn spawn_prerequisites(
    request: &SessionRequest<'_>,
) -> std::result::Result<(GhidraInstall, GhidraExtension), String> {
    let install = match install::discover(
        request.stack.env_install_dir,
        request.stack.config_install_dir,
        request.stack.home,
        request.stack.managed_prefix,
    ) {
        InstallDiscovery::Found { install, source } => {
            info!(path = %install.path.display(), version = %install.version, %source, "Spawning against the discovered Ghidra install");
            install
        }
        InstallDiscovery::Invalid { path, source } => {
            return Err(format!(
                "the Ghidra install named by {source} is not a valid install: {}",
                path.display()
            ));
        }
        InstallDiscovery::NotFound => {
            return Err(
                "no Ghidra install was found ($GHIDRA_INSTALL_DIR, ghidra.install_dir, or a \
                 *ghidra_*_PUBLIC directory in the home directory)"
                    .to_string(),
            );
        }
    };

    // The `ghidra.min_version` floor (G1-T7): a too-old install fails the
    // spawn preflight by name — doctor stays a pure report of what *is*.
    // An unparseable floor fails the gate too: a typo must not silently
    // disable the check the user asked for.
    if let Some(min) = request.min_version {
        if !version_parses(min) {
            return Err(format!(
                "ghidra.min_version = {min:?} is not a version; expected dotted numbers \
                 like 12.1"
            ));
        }
        if !plugin_version_at_least(&install.version, min) {
            return Err(format!(
                "the Ghidra install at {} is version {}, but ghidra.min_version requires at \
                 least {min}",
                install.path.display(),
                install.version
            ));
        }
    }

    let extension = match request.stack.home {
        Some(home) => {
            let root = home.join(".config").join("ghidra");
            let discovery = extension::discover(&root, &install.version);
            let verdict = extension::verdict(&discovery, &install.version);
            match (discovery, verdict) {
                (ExtensionDiscovery::Found(ext), ExtensionVerdict::Ok { .. }) => ext,
                (_, ExtensionVerdict::Missing { extensions_dir }) => {
                    return Err(format!(
                        "the GhidraMCP extension is not installed for Ghidra {}; \
                         install the v{} zip into {}",
                        install.version,
                        MIN_PLUGIN_VERSION,
                        extensions_dir.display()
                    ));
                }
                (
                    _,
                    ExtensionVerdict::WrongBuild {
                        built_for,
                        ghidra,
                        extensions_dir,
                    },
                ) => {
                    return Err(format!(
                        "the GhidraMCP extension was built for Ghidra {built_for} but \
                         {ghidra} is installed; reinstall the matching zip into {}",
                        extensions_dir.display()
                    ));
                }
                (
                    _,
                    ExtensionVerdict::TooOld {
                        plugin_version,
                        required,
                    },
                ) => {
                    return Err(format!(
                        "the GhidraMCP extension is v{plugin_version} but v{required} \
                         is required (ADR-0001)"
                    ));
                }
                (_, ExtensionVerdict::Broken { dir }) => {
                    return Err(format!(
                        "the GhidraMCP extension at {} is not loadable (no readable \
                         manifest or jar)",
                        dir.display()
                    ));
                }
                (discovery, verdict) => {
                    return Err(format!(
                        "the extension check failed: {verdict:?} ({discovery:?})"
                    ));
                }
            }
        }
        None => {
            return Err(
                "no home directory is known, so the GhidraMCP extension for the discovered \
                 Ghidra install cannot be found"
                    .to_string(),
            );
        }
    };

    Ok((install, extension))
}

/// Whether a version string is the dotted-numeric form the comparison
/// speaks (`12.1`, `12.1.2-rc1`); anything else is a typo, not a floor.
fn version_parses(version: &str) -> bool {
    version.split(['-', '+']).next().is_some_and(|core| {
        !core.is_empty()
            && core
                .split('.')
                .all(|part| !part.is_empty() && part.parse::<u64>().is_ok())
    })
}

/// The project path a run defaults to: `<workspace>/ghidra/<binary>.gpr`,
/// matching the existing output layout (`crates/`, `re/`, `scratch/`).
pub fn default_project(workspace: &Path, binary: &str) -> PathBuf {
    let stem = binary
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(binary)
        .rsplit_once('.')
        .map(|(stem, _)| stem)
        .unwrap_or(binary);
    workspace.join("ghidra").join(format!("{stem}.gpr"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_headless_mode_parses_and_prints_its_three_values() {
        // The config layer carries the mode as a string; the CLI parses it
        // once and bails naming the valid values on anything else.
        for (text, mode) in [
            ("auto", HeadlessMode::Auto),
            ("  Always ", HeadlessMode::Always),
            ("NEVER", HeadlessMode::Never),
        ] {
            assert_eq!(text.parse::<HeadlessMode>().expect("valid mode"), mode);
        }
        assert_eq!(HeadlessMode::default(), HeadlessMode::Auto);
        assert!("sometimes".parse::<HeadlessMode>().is_err());
        assert_eq!(HeadlessMode::Always.to_string(), "always");
    }

    #[test]
    fn the_default_project_sits_under_the_workspace() {
        let project = default_project(Path::new("/run/eq"), "eqmain.dll");
        assert_eq!(project, Path::new("/run/eq/ghidra/eqmain.gpr"));
        // A full path still names its file, and a nameless extension keeps
        // the name whole.
        assert_eq!(
            default_project(Path::new("/run/eq"), r"C:\eq\shell32.dll"),
            Path::new("/run/eq/ghidra/shell32.gpr")
        );
        assert_eq!(
            default_project(Path::new("/run/eq"), "eqmain"),
            Path::new("/run/eq/ghidra/eqmain.gpr")
        );
    }
}
