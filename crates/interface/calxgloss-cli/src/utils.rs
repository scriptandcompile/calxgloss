//! Utility functions for the CLI.

use anyhow::{Context, Result, anyhow};
use calxgloss::TranslationEvents;
use calxgloss_ghidra::lifecycle::{
    BRIDGE_DEFAULT_PORT, GhidraSession, HeadlessMode, SessionRequest, StackRequest,
    default_project, socket_dir,
};
pub use calxgloss_reports::{
    print_batch_summary, print_classification_report, print_failure, print_git_status,
    print_verification_results,
};
pub use calxgloss_translator::RetryStrategy;
pub use calxgloss_verify::Verifier;
use std::path::{Path, PathBuf};
use std::time::Duration;
pub use tracing::{debug, warn};

/// The user's local state directory: `$XDG_STATE_HOME`, falling back to
/// `~/.local/share` — the XDG base directory for data that survives between
/// sessions but is not configuration.
pub(super) fn state_dir(home: &Path) -> PathBuf {
    std::env::var_os("XDG_STATE_HOME")
        .filter(|value| !value.as_os_str().is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| home.join(".local/share"))
}

/// The install prefix `doctor --fix` installs into — and every discovery
/// pass names, so a bootstrap's installs are found without env or config:
/// `<state>/calxgloss/ghidra/`.
pub(super) fn managed_install_prefix(home: &Path) -> PathBuf {
    state_dir(home).join("calxgloss/ghidra")
}

/// Open the session preflight (G1-T4) every Ghidra command starts from:
/// attach to a running GhidraMCP server — reconciling a stale configured
/// port against the servers registered in the bridge's runtime-socket
/// directory (G1-T5) — or spawn a supervised headless one under the
/// doctor's install and extension checks.
///
/// The discovery inputs — `$GHIDRA_INSTALL_DIR`, the layered
/// `ghidra.install_dir` setting, `$HOME`, and `$XDG_RUNTIME_DIR` — are read
/// here so the lifecycle checks stay pure and testable; the project path
/// defaults to `<workspace>/ghidra/<binary>.gpr`, beside which a spawned
/// server's log and pid files land. The returned session tracks ownership:
/// an owned server is shut down by [`GhidraSession::shutdown`] (or killed on
/// drop), an attached one is left untouched.
///
/// The project bootstrap (G1-T6, issue #116) then runs on the same session:
/// the `.gpr` is created on the first run and reused after, and every path
/// in `binaries` — the binaries this command will actually read — is loaded
/// into the project and analyzed, skipping what a live server already
/// holds open or the analysis cache says is done. A command whose binaries
/// are only known later (auto-shim's classified DLL list) passes an empty
/// slice here and calls [`GhidraSession::ensure_project`] itself once they
/// are; the bootstrap is idempotent, so a second pass costs two probes.
pub(super) async fn open_ghidra_session(
    settings: &crate::Settings,
    workspace: &Path,
    binary: &str,
    binaries: &[PathBuf],
    events: Option<&TranslationEvents>,
) -> Result<GhidraSession> {
    let env_install = std::env::var_os("GHIDRA_INSTALL_DIR").map(PathBuf::from);
    let home = std::env::var_os("HOME").map(PathBuf::from);
    let xdg_runtime = std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from);
    let uid = std::fs::metadata("/proc/self")
        .ok()
        .map(|meta| std::os::unix::fs::MetadataExt::uid(&meta));
    let sockets = socket_dir(xdg_runtime.as_deref(), uid);
    let config_install = settings
        .ghidra_install_dir
        .as_ref()
        .map(|r| PathBuf::from(&r.value));
    let managed_prefix = home.as_deref().map(managed_install_prefix);
    // The `ghidra.headless` mode is a config string, so a typo is named with
    // the layer it came from — the same attribution `config` shows.
    let headless: HeadlessMode = settings.ghidra_headless.value.parse().map_err(|_| {
        anyhow!(
            "ghidra.headless = {:?} (from {}) is not a valid mode; expected auto, always, \
             or never",
            settings.ghidra_headless.value,
            settings.ghidra_headless.source,
        )
    })?;
    // `ghidra.project` overrides the default `<workspace>/ghidra/<target>.gpr`.
    let project = settings
        .ghidra_project
        .as_ref()
        .map(|r| PathBuf::from(&r.value))
        .unwrap_or_else(|| default_project(workspace, binary));
    let request = SessionRequest {
        url: &settings.ghidra_url.value,
        api_key: settings.ghidra_api_key.as_ref().map(|r| r.value.as_str()),
        project: &project,
        socket_dir: sockets.as_deref(),
        fallback_port: BRIDGE_DEFAULT_PORT,
        stack: StackRequest {
            env_install_dir: env_install.as_deref(),
            config_install_dir: config_install.as_deref(),
            home: home.as_deref(),
            managed_prefix: managed_prefix.as_deref(),
        },
        start_timeout: Duration::from_secs(settings.ghidra_start_timeout_secs.value),
        auto_start: settings.ghidra_auto_start.value,
        headless,
        min_version: settings
            .ghidra_min_version
            .as_ref()
            .map(|r| r.value.as_str()),
    };
    let session = GhidraSession::ensure(&request, events)
        .await
        .with_context(|| {
            format!(
                "Failed to attach to or start a GhidraMCP server at {}",
                settings.ghidra_url.value
            )
        })?;
    // Bootstrap only the binaries that exist on disk: commands like
    // `translate` take a `--target` path that is decorative once a live
    // server already holds the program (Ghidra identifies programs
    // itself), and the wrong-program guard still verifies the name.
    let present: Vec<PathBuf> = binaries.iter().filter(|p| p.exists()).cloned().collect();
    if present.len() < binaries.len() {
        warn!(
            missing = binaries.len() - present.len(),
            "Some target binaries are not on disk; the project bootstrap skips them"
        );
    }
    session
        .ensure_project(workspace, &present, events)
        .await
        .with_context(|| "Failed to load the run's binaries into the Ghidra project")?;
    Ok(session)
}

/// Resolve the workspace: `--workspace` flag > settings > CWD.
///
/// This is the single point of resolution for commands that use the
/// config-file / env-var layer (`auto`, `translate`, `batch-translate`).
pub(super) fn resolve_workspace(
    cli_workspace: Option<&PathBuf>,
    settings: &crate::Settings,
) -> PathBuf {
    cli_workspace
        .cloned()
        .or_else(|| settings.workspace.as_ref().map(|r| PathBuf::from(&r.value)))
        .unwrap_or_else(|| std::env::current_dir().expect("Failed to read current directory"))
}

/// Resolve the workspace for `live` and `serve`: `--workspace` flag > CWD.
///
/// These commands always operate on the workspace in the current directory
/// (where `.git`, `src/`, `scratch/` live).  Config file and env-var
/// overrides are ignored — only an explicit `--workspace` flag can change this.
pub(super) fn resolve_live_workspace(cli_workspace: Option<&PathBuf>) -> PathBuf {
    cli_workspace
        .cloned()
        .unwrap_or_else(|| std::env::current_dir().expect("Failed to read current directory"))
}

/// Parse a retry strategy string into a [`RetryStrategy`].
pub(super) fn parse_retry_strategy(s: &str) -> Result<RetryStrategy> {
    Ok(match s {
        "compile_fix" => RetryStrategy::CompileFix,
        "test_fix" => RetryStrategy::TestFix,
        "escalate" => RetryStrategy::Escalate,
        "edge_case_fix" => RetryStrategy::EdgeCaseFix,
        "auto" => {
            // Auto mode starts with compile_fix and cycles through all strategies.
            // The cycling happens in the retry loop itself.
            RetryStrategy::CompileFix
        }
        other => anyhow::bail!(
            "Unknown retry strategy '{}'. Valid strategies: compile_fix, test_fix, \
             escalate, edge_case_fix, auto",
            other
        ),
    })
}

/// Map the CLI verbosity flag to the effective tracing level string.
/// Shared by `init_logging` and the serve/live commands so the server
/// status endpoint reports the level that is actually active.
pub(super) fn log_level_for_verbosity(verbosity: u8) -> &'static str {
    match verbosity {
        0 => "warn",
        1 => "info",
        2 => "debug",
        _ => "trace",
    }
}

/// Initialize tracing with the given verbosity level and format.
///
/// The `EnvFilter` is installed inside a `reload` layer so the web server's
/// `PATCH /api/server/log-level` endpoint can change verbosity while the
/// process runs; the returned handle is the control side of that layer and
/// is shared into server state by `serve`/`live`.
pub(super) fn init_logging(
    verbosity: u8,
    format: &str,
) -> tracing_subscriber::reload::Handle<tracing_subscriber::EnvFilter, tracing_subscriber::Registry>
{
    let level = log_level_for_verbosity(verbosity);
    let (filter, handle) =
        tracing_subscriber::reload::Layer::new(tracing_subscriber::EnvFilter::new(level));

    use tracing_subscriber::layer::SubscriberExt as _;
    use tracing_subscriber::util::SubscriberInitExt as _;
    match format {
        "json" => {
            tracing_subscriber::registry()
                .with(filter)
                .with(tracing_subscriber::fmt::layer().json())
                .init();
        }
        // Text (and anything unrecognized) gets the human-readable layer.
        _ => {
            tracing_subscriber::registry()
                .with(filter)
                .with(tracing_subscriber::fmt::layer().with_target(false))
                .init();
        }
    };

    debug!("Logging initialized: level={}, format={}", level, format);
    handle
}

// ============================================================
// Translation output helpers
// ============================================================

/// Derive a crate name from a DLL or EXE filename by stripping the extension.
pub fn derive_crate_name(binary: &str) -> String {
    binary.rsplit('.').next().unwrap_or(binary).to_string()
}

/// Set up the output crate directory structure for a translated DLL/EXE.
///
/// Creates `crates/<crate_name>/src/` and writes a `Cargo.toml` (only if it
/// doesn't already exist, so repeated calls are safe).
///
/// Returns `(crate_dir, src_dir)` for further file creation.
pub fn setup_translation_crate(workspace: &Path, binary: &str) -> Result<(PathBuf, PathBuf)> {
    let crate_name = derive_crate_name(binary);
    let crate_dir = workspace.join("crates").join(&crate_name);
    let crate_src_dir = crate_dir.join("src");

    std::fs::create_dir_all(&crate_src_dir).context("Failed to create crate src directory")?;

    let cargo_toml_path = crate_dir.join("Cargo.toml");
    if !cargo_toml_path.exists() {
        let cargo_toml = format!(
            "[package]\nname = \"{crate_name}\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            crate_name = crate_name,
        );
        std::fs::write(&cargo_toml_path, cargo_toml).context("Failed to write Cargo.toml")?;
        debug!(path = %cargo_toml_path.display(), "Created Cargo.toml");
    }

    Ok((crate_dir, crate_src_dir))
}

/// Write a single translated function to the crate's `src/` directory and
/// register it as a module in `mod.rs`.
///
/// The file is written as `src/<function>.rs`.  If `mod.rs` exists it is
/// updated with `pub mod <function>;` (duplicates are avoided).
pub fn write_translation_function(
    crate_src_dir: &Path,
    function: &str,
    rust_code: &str,
) -> Result<PathBuf> {
    let output_path = crate_src_dir.join(format!("{function}.rs"));
    std::fs::create_dir_all(output_path.parent().unwrap())
        .context("Failed to create output directory")?;
    std::fs::write(&output_path, rust_code).context("Failed to write translated function")?;
    debug!(path = %output_path.display(), "Wrote translated function");

    // Register the function as a module in mod.rs
    let mod_rs_path = crate_src_dir.join("mod.rs");
    let mod_contents = if mod_rs_path.exists() {
        std::fs::read_to_string(&mod_rs_path).unwrap_or_default()
    } else {
        String::new()
    };
    let module_decl = format!("pub mod {function};\n");
    if !mod_contents.contains(&module_decl) {
        let mut updated = mod_contents;
        updated.push_str(&module_decl);
        std::fs::write(&mod_rs_path, updated).ok();
    }

    Ok(output_path)
}

// ============================================================
// Terminal formatting helpers (mirrors calxgloss-reports internals)
// ============================================================

const ANSI_RESET: &str = "\x1b[0m";
const ANSI_BOLD: &str = "\x1b[1m";
const ANSI_GREEN: &str = "\x1b[32m";
const ANSI_RED: &str = "\x1b[31m";
const ANSI_YELLOW: &str = "\x1b[33m";
const ANSI_CYAN: &str = "\x1b[36m";

pub(super) fn bold(text: &str) -> String {
    format!("{}{}{}", ANSI_BOLD, text, ANSI_RESET)
}

pub(super) fn bold_color(text: &str, code: &str) -> String {
    format!("{}{}{}{}", ANSI_BOLD, code, text, ANSI_RESET)
}

pub(super) fn green_bold(text: &str) -> String {
    bold_color(text, ANSI_GREEN)
}

pub(super) fn red_bold(text: &str) -> String {
    bold_color(text, ANSI_RED)
}

pub(super) fn yellow_bold(text: &str) -> String {
    bold_color(text, ANSI_YELLOW)
}

pub(super) fn cyan_bold(text: &str) -> String {
    bold_color(text, ANSI_CYAN)
}

pub(super) fn white_bold(text: &str) -> String {
    bold(text)
}

pub(super) fn dim(text: &str) -> String {
    format!("{}{}{}", "\x1b[2m", text, ANSI_RESET)
}

pub(super) fn format_dim(text: &str) -> String {
    dim(text)
}

/// Width of horizontal dividers (no vertical borders, no corners).
const SEP_WIDTH: usize = 78;

/// A single horizontal divider.
pub(super) fn hsep() {
    println!("  {}", "─".repeat(SEP_WIDTH));
}

/// A bold horizontal divider.
pub(super) fn hsep_bold() {
    println!("  {}", "═".repeat(SEP_WIDTH));
}

/// Prints a line of content, padded to SEP_WIDTH with spaces.
/// Safe for ANSI codes and multi-byte UTF-8.
pub(super) fn println_content(content: impl AsRef<str>) {
    let s = content.as_ref();
    // Count visible *characters*, not bytes: a multi-byte character like
    // the ● bullet would otherwise push a short line into the truncation
    // branch, where the character-counting cut below never reaches the
    // byte-based limit and the whole line prints empty.
    let visible_chars = s.chars().filter(|c| !c.is_control()).count();
    let padded = if visible_chars < SEP_WIDTH {
        format!("{:<SEP_WIDTH$}", s)
    } else {
        let end = SEP_WIDTH.min(visible_chars);
        let mut vcount = 0usize;
        let mut bend = 0usize;
        for (bi, ch) in s.chars().enumerate() {
            if !ch.is_control() {
                vcount += 1;
            }
            if vcount >= end {
                bend = bi + ch.len_utf8();
                break;
            }
        }
        s[..bend].to_string()
    };
    println!("  {}", padded);
}

// ============================================================
// Dashboard accept/reject helpers
// ============================================================

/// Walk up from CWD to find the Git repository root.
pub(super) fn find_repo_path() -> Result<PathBuf> {
    let path = std::env::current_dir()?;
    let mut search = path.clone();
    for _ in 0..10 {
        if search.join(".git").exists() || search.join(".git").is_dir() {
            return Ok(search.clone());
        }
        if !search.pop() {
            break;
        }
    }
    Ok(path)
}

/// Resolve a ViewTarget to the actual git branch name.
///
/// Searches all translation branches (`re/*`) and returns the first one
/// whose DLL and function match the target, optionally checking the
/// attempt number.
pub(super) fn resolve_branch(
    git: &calxgloss_git::GitManager,
    target: &calxgloss_reports::dashboard::ViewTarget,
) -> Result<String> {
    let candidates = git.list_translation_branches()?;
    let target_binary = target.binary.clone();
    let target_func = target.function.clone();
    let target_attempt = target.specific_attempt;

    for branch in &candidates {
        // Must start with re/
        if !branch.starts_with("re/") {
            continue;
        }

        // Use the public matching function from reports
        if !calxgloss_reports::dashboard::branch_matches(
            branch,
            target_binary.as_str(),
            &target_func,
            target_attempt,
        ) {
            continue;
        }

        return Ok(branch.clone());
    }

    // Collect available branches for a helpful error message
    let available: Vec<String> = candidates
        .iter()
        .filter(|b| {
            b.starts_with("re/") && b.contains(target_binary.as_str()) && b.contains(&target_func)
        })
        .cloned()
        .collect();

    if available.is_empty() {
        let all_branches: String = candidates
            .iter()
            .take(10)
            .cloned()
            .collect::<Vec<_>>()
            .join(", ");
        anyhow::bail!(
            "No translation branch found for '{}/{}'.\n\
             Available branches: {}",
            target_binary,
            target_func,
            all_branches
        )
    } else {
        anyhow::bail!(
            "No translation branch found for '{}/{}'.\n\
             Possible matches (check attempt number): {}",
            target_binary,
            target_func,
            available.join(", ")
        )
    }
}

/// Parse a git branch name back into (binary, function, attempt) components.
///
/// Delegates to [`calxgloss_types::parse_branch_name`], the one owner of the
/// `re/{file}/{function}v{N}` grammar (issue #69). A name the grammar cannot
/// read yields empty components, which [`calxgloss_types::GitBranch::new`]
/// then rejects as an invalid branch name.
pub(super) fn parse_branch_for_accept(branch: &str) -> (String, String, u32) {
    match calxgloss_types::parse_branch_name(branch) {
        Some(parts) => (
            parts.binary.to_string(),
            parts.function.unwrap_or_default(),
            parts.attempt.unwrap_or(1),
        ),
        None => (String::new(), String::new(), 1),
    }
}
