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
//! * nothing answering at all spawns a supervised headless server
//!   ([`server`]), but only after the install and extension checks pass —
//!   a spawn with no valid stack fails with what is missing — and only if
//!   the configured port is free (design risk 4: never bind a busy port).
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
use tracing::info;

use super::StackRequest;
use super::extension::{self, ExtensionDiscovery, ExtensionVerdict};
use super::install::{self, InstallDiscovery};
use super::program::{self, ProgramMatch};
use super::server::{self, OwnedServer};
use crate::client::{GhidraClient, GhidraConfig, GhidraError, MIN_PLUGIN_VERSION, Result};
use crate::model::ServerInfo;

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

/// The resolved inputs of a preflight, injectable so tests point every
/// lookup at fixtures instead of the real machine — the same shape
/// [`StackRequest`] established for `doctor`.
#[derive(Debug, Clone)]
pub struct SessionRequest<'a> {
    /// The configured GhidraMCP URL (`--ghidra-url` / env / config).
    pub url: &'a str,
    /// Optional bearer token for the client.
    pub api_key: Option<&'a str>,
    /// The run's project path (`<workspace>/ghidra/<target>.gpr`): the log
    /// and pid files live beside it, and an existing project is reopened by
    /// the spawned server.
    pub project: &'a Path,
    /// The filesystem discovery inputs for the install and extension checks.
    pub stack: StackRequest<'a>,
    /// How long a spawned server may take to answer the probe.
    pub start_timeout: Duration,
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
    /// The supervised child, present exactly when `ownership` is `Owned`.
    server: Option<OwnedServer>,
}

impl GhidraSession {
    /// Run the preflight: probe, then attach to what answered or spawn a
    /// headless server under the checks the doctor reports.
    ///
    /// `events`, when given, receives a [`ProgressEvent::GhidraServerStarted`]
    /// the moment a spawned server answers its first probe.
    ///
    /// # Errors
    ///
    /// - [`GhidraError::NotGhidraMcp`] / [`GhidraError::VersionMismatch`] —
    ///   the configured port answered, but not as a usable GhidraMCP server;
    ///   nothing is spawned over it.
    /// - [`GhidraError::CannotSpawn`] — a spawn was needed but the install
    ///   or extension checks failed; the reason names what is missing.
    /// - [`GhidraError::PortBusy`] — a spawn was needed but the configured
    ///   port is held by something else.
    /// - [`GhidraError::SpawnFailed`] / [`GhidraError::BootTimeout`] — the
    ///   spawn itself failed; the message names the server's log.
    pub async fn ensure(
        request: &SessionRequest<'_>,
        events: Option<&TranslationEvents>,
    ) -> Result<Self> {
        let mut config = GhidraConfig::new(request.url)?;
        if let Some(key) = request.api_key {
            config = config.with_api_key(key);
        }
        let client = GhidraClient::from_config(config)?;

        match client.check_connection().await {
            Ok(info) => {
                info!(
                    kind = %info.kind,
                    url = %client.base_url(),
                    "Attached to a running GhidraMCP server"
                );
                Ok(Self {
                    client,
                    info,
                    ownership: Ownership::Attached,
                    server: None,
                })
            }
            // Nothing answered: the only case a spawn is even considered.
            Err(GhidraError::ServerUnreachable { .. }) => {
                Self::start_headless(client, request, events).await
            }
            // A foreign port or an old plugin is a named failure to fix by
            // configuration — never something to spawn over.
            Err(other) => Err(other),
        }
    }

    /// The spawn half: doctor's checks as preconditions, a free port, then
    /// the supervised launch and boot poll.
    async fn start_headless(
        client: GhidraClient,
        request: &SessionRequest<'_>,
        events: Option<&TranslationEvents>,
    ) -> Result<Self> {
        let install = install::discover(
            request.stack.env_install_dir,
            request.stack.config_install_dir,
            request.stack.home,
        );
        let install = match &install {
            InstallDiscovery::Found { install, source } => {
                info!(path = %install.path.display(), version = %install.version, %source, "Spawning against the discovered Ghidra install");
                install.clone()
            }
            InstallDiscovery::Invalid { path, source } => {
                return Err(GhidraError::CannotSpawn {
                    reason: format!(
                        "the Ghidra install named by {source} is not a valid install: {}",
                        path.display()
                    ),
                });
            }
            InstallDiscovery::NotFound => {
                return Err(GhidraError::CannotSpawn {
                    reason: "no Ghidra install was found ($GHIDRA_INSTALL_DIR, \
                             ghidra.install_dir, or a *ghidra_*_PUBLIC directory in the home \
                             directory)"
                        .to_string(),
                });
            }
        };

        let extension = match request.stack.home {
            Some(home) => {
                let root = home.join(".config").join("ghidra");
                let discovery = extension::discover(&root, &install.version);
                let verdict = extension::verdict(&discovery, &install.version);
                match (discovery, verdict) {
                    (ExtensionDiscovery::Found(ext), ExtensionVerdict::Ok { .. }) => ext,
                    (_, ExtensionVerdict::Missing { extensions_dir }) => {
                        return Err(GhidraError::CannotSpawn {
                            reason: format!(
                                "the GhidraMCP extension is not installed for Ghidra {}; \
                                 install the v{} zip into {}",
                                install.version,
                                MIN_PLUGIN_VERSION,
                                extensions_dir.display()
                            ),
                        });
                    }
                    (
                        _,
                        ExtensionVerdict::WrongBuild {
                            built_for,
                            ghidra,
                            extensions_dir,
                        },
                    ) => {
                        return Err(GhidraError::CannotSpawn {
                            reason: format!(
                                "the GhidraMCP extension was built for Ghidra {built_for} but \
                                 {ghidra} is installed; reinstall the matching zip into {}",
                                extensions_dir.display()
                            ),
                        });
                    }
                    (
                        _,
                        ExtensionVerdict::TooOld {
                            plugin_version,
                            required,
                        },
                    ) => {
                        return Err(GhidraError::CannotSpawn {
                            reason: format!(
                                "the GhidraMCP extension is v{plugin_version} but v{required} \
                                 is required (ADR-0001)"
                            ),
                        });
                    }
                    (_, ExtensionVerdict::Broken { dir }) => {
                        return Err(GhidraError::CannotSpawn {
                            reason: format!(
                                "the GhidraMCP extension at {} is not loadable (no readable \
                                 manifest or jar)",
                                dir.display()
                            ),
                        });
                    }
                    (discovery, verdict) => {
                        return Err(GhidraError::CannotSpawn {
                            reason: format!(
                                "the extension check failed: {verdict:?} ({discovery:?})"
                            ),
                        });
                    }
                }
            }
            None => {
                return Err(GhidraError::CannotSpawn {
                    reason: "no home directory is known, so the GhidraMCP extension for the \
                             discovered Ghidra install cannot be found"
                        .to_string(),
                });
            }
        };

        // The port the configured URL names, and a bind address: loopback
        // unless the URL itself names a literal address — the bridge's
        // posture is localhost-only, and calxgloss never exposes Ghidra.
        let url = client.base_url();
        let port = url
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
        if !server::port_free(&bind, port) {
            return Err(GhidraError::PortBusy {
                url: url.to_string(),
            });
        }

        let plan =
            server::LaunchPlan::build(&install, &extension, port, &bind, Some(request.project))
                .ok_or_else(|| GhidraError::CannotSpawn {
                    reason: format!(
                        "the GhidraMCP extension at {} names no GhidraMCP-*.jar in its lib/",
                        extension.dir.display()
                    ),
                })?;

        // Log and pid beside the project, per the design: a crashed run
        // leaves the pid file for the next run to clean up (G1-T7).
        let beside = request.project.parent().unwrap_or(request.project);
        let log = beside.join("headless.log");
        let pid_file = beside.join("headless.pid");

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
