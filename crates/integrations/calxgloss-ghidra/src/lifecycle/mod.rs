//! Read-only discovery of the whole Ghidra stack — install, extension,
//! running servers, server on the configured port — plus the wrong-program
//! guard a preflight runs before any scan.
//!
//! This is the checking half of the lifecycle design (`docs/ghidra_integration.md`
//! §3.2) — what `calxgloss doctor` reports in one pass (install, extension,
//! server on the configured port) plus the [`discovery`] scan of the bridge's
//! runtime-socket registrations, and the same checks [`session`]'s preflight
//! runs before spawning anything. The checks
//! themselves spawn nothing and modify no process: [`discovery`] reads the
//! filesystem and queries the bridge's runtime-socket registrations, and the
//! server check is one `check_connection` probe. The one exception is
//! [`program`]'s guard, which may switch the server's *current program* — the
//! incident fix (risk 7) — but never opens, closes, or kills anything.
//!
//! The acting half is G1-T4: [`session::GhidraSession::ensure`] attaches to a
//! running server or spawns a headless one ([`server`]) under these same
//! checks, tracking ownership so owned servers get closed and killed on exit
//! while attached ones are never touched. G1-T6 adds [`project`]'s bootstrap:
//! create or open the run's `.gpr` and bring every needed binary to loaded
//! and analyzed, with an on-disk analysis cache so later runs skip the
//! minutes-long re-analysis.
//!
//! Version coupling is the load-bearing constraint throughout (ADR-0001): the
//! extension jar is compiled against exactly one Ghidra build, so the install
//! and extension checks are judged *as a pair*, not independently.

mod discovery;
mod extension;
mod install;
mod program;
mod project;
mod server;
mod session;

pub use discovery::{BRIDGE_DEFAULT_PORT, DiscoveredServer, discover, socket_dir};
pub use extension::{ExtensionDiscovery, ExtensionVerdict, GhidraExtension};
pub use install::{GhidraInstall, InstallDiscovery, InstallSource};
pub use program::{ProgramMatch, ensure_current_program};
pub use project::{
    ANALYSIS_POLL_INTERVAL, ProgramLoad, ProjectSetup, analysis_cache_path, ensure_project,
};
pub use server::LaunchPlan;
pub use session::{
    DEFAULT_START_TIMEOUT, GhidraSession, HeadlessMode, Ownership, SessionRequest, default_project,
};

use tracing::warn;

use crate::client::{GhidraClient, GhidraError};
use crate::model::ServerInfo;

/// Read one `key=value` line out of a Java-style properties body — shared by
/// the install's `application.properties` and the extension's manifest.
pub(crate) fn properties_value(body: &str, key: &str) -> Option<String> {
    let prefix = format!("{key}=");
    body.lines()
        .find_map(|line| line.trim().strip_prefix(&prefix))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

/// Everything the read-only pass learned about the Ghidra stack.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StackReport {
    /// The discovered Ghidra install (path + version), or why there is none.
    pub install: InstallDiscovery,
    /// The extension judged against the discovered install — `None` when no
    /// install validated, since there is no Ghidra build to pair against.
    pub extension: Option<ExtensionVerdict>,
    /// What the identity probe found on the configured port.
    pub server: ServerDiscovery,
}

impl StackReport {
    /// Whether every check passed — what `doctor`'s exit code turns on.
    pub fn all_ok(&self) -> bool {
        matches!(self.install, InstallDiscovery::Found { .. })
            && matches!(self.extension, Some(ExtensionVerdict::Ok { .. }))
            && matches!(self.server, ServerDiscovery::Up { .. })
    }
}

/// What the `check_connection` probe found on the configured port.
///
/// An unreachable port is a reported state, not a crash: `doctor` must answer
/// "none" and move on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerDiscovery {
    /// A GhidraMCP server answered and identified itself.
    Up {
        /// Where it answered.
        url: String,
        /// Which kind of server, which version, and which program it named.
        info: ServerInfo,
    },
    /// Nothing answered at all.
    Unreachable {
        /// The URL that was probed.
        url: String,
    },
    /// The port answered HTTP, but not as GhidraMCP — the wrong-port class of
    /// error (8080 is also a popular local-AI port).
    NotGhidraMcp {
        /// The URL that was probed.
        url: String,
        /// Why the answer was rejected, as the probe saw it.
        hint: String,
    },
    /// The server identified itself but named a plugin older than ADR-0001's
    /// pinned bridge.
    TooOld {
        /// The URL that was probed.
        url: String,
        /// The plugin version found.
        found: String,
        /// The minimum required.
        required: String,
    },
}

/// The injectable inputs of a stack check, so tests can point every lookup at
/// tempdir fixtures instead of the real machine.
#[derive(Debug, Clone, Copy)]
pub struct StackRequest<'a> {
    /// The value of `$GHIDRA_INSTALL_DIR`, when set.
    pub env_install_dir: Option<&'a std::path::Path>,
    /// The resolved `ghidra.install_dir` config value, when set.
    pub config_install_dir: Option<&'a std::path::Path>,
    /// The user's home directory, when known: the install glob and Ghidra's
    /// `~/.config/ghidra` state root both hang off it.
    pub home: Option<&'a std::path::Path>,
}

/// Run every read-only check in one pass: install discovery, the extension
/// pairing against it, and the server identity probe through `client`.
pub async fn check_stack(client: &GhidraClient, request: &StackRequest<'_>) -> StackReport {
    let install = install::discover(
        request.env_install_dir,
        request.config_install_dir,
        request.home,
    );

    // The extension lives per Ghidra build, so it can only be judged against
    // a discovered install's version.
    let extension = match (&install, request.home) {
        (InstallDiscovery::Found { install, .. }, Some(home)) => {
            let root = home.join(".config").join("ghidra");
            let discovery = extension::discover(&root, &install.version);
            Some(extension::verdict(&discovery, &install.version))
        }
        _ => None,
    };

    let server = match client.check_connection().await {
        Ok(info) => ServerDiscovery::Up {
            url: client.base_url().to_string(),
            info,
        },
        Err(GhidraError::ServerUnreachable { url, source }) => {
            warn!(%url, error = %source, "No GhidraMCP server answered the probe");
            ServerDiscovery::Unreachable { url }
        }
        Err(GhidraError::NotGhidraMcp { url, hint }) => {
            warn!(%url, %hint, "The probed port is not GhidraMCP");
            ServerDiscovery::NotGhidraMcp { url, hint }
        }
        Err(GhidraError::VersionMismatch { found, required }) => {
            warn!(%found, %required, "The running plugin predates the pinned bridge");
            ServerDiscovery::TooOld {
                url: client.base_url().to_string(),
                found,
                required,
            }
        }
        // The probe maps every transport failure to `ServerUnreachable` and
        // every wrong-shape answer to `NotGhidraMcp`, so anything left here is
        // a URL that never became a request in the first place.
        Err(other) => {
            warn!(error = %other, "The identity probe could not run");
            ServerDiscovery::Unreachable {
                url: client.base_url().to_string(),
            }
        }
    };

    StackReport {
        install,
        extension,
        server,
    }
}
