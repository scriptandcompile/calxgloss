//! Project bootstrap — the G1-T6 half of the lifecycle design
//! (`docs/ghidra_integration.md` §3.2): make sure the server holds the
//! run's Ghidra project, and that every binary the run needs is loaded
//! into it and analyzed.
//!
//! [`ensure_project`] runs after the session preflight has a server
//! answering. The project at `<workspace>/ghidra/<target>.gpr` is:
//!
//! * **reused** when the server already has it open — a later run against
//!   a live server pays nothing;
//! * **opened** when it exists on disk but the server has none (or
//!   another) open;
//! * **created** when it does not exist at all — the first run — after
//!   which `ghidra/` is ensured in the workspace `.gitignore` on every
//!   route, since Ghidra project files are binary and large.
//!
//! Then each needed binary is brought to *loaded and current* through the
//! cheapest stage that works: already open (switch if not current) →
//! open from the project (a later run's fast path, since the first run's
//! import and analysis persist in the `.gpr`) → raw import plus full
//! auto-analysis. The bridge has no project-file listing over HTTP
//! (`list_project_files` is GUI-only in v6.0.0), so "is it in the project"
//! is answered by trying `load_program_from_project` and reading its
//! structured miss — HTTP 200 with `success: false` — as a fall-through.
//!
//! **Analysis is the expensive part** (minutes for a large DLL, design
//! risk 1), so it is tracked in `re/ghidra/analysis_cache.json`, keyed by
//! the binary's path and SHA-256: a program opened from the project whose
//! bytes match a cached record skips re-analysis, while a raw import is
//! always analyzed. While `run_analysis` blocks, `analysis_status` is
//! polled concurrently so the log and any watcher see progress rather than
//! one long silence, and each finished analysis emits
//! [`ProgressEvent::GhidraProgramAnalyzed`]. Creating or opening the
//! project emits [`ProgressEvent::GhidraProjectCreated`].
//!
//! Like the read cache, the analysis cache **degrades, never fails**: an
//! unreadable or corrupt cache document reads as cold, and a failed cache
//! write is logged without failing the run — the cost of losing it is one
//! re-analysis, not a broken command.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use calxgloss_types::persist::{load_json, save_json};
use calxgloss_types::{ProgressEvent, TranslationEvents};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use crate::cache::sha256_of_file;
use crate::client::{GhidraClient, Result};

/// How often `analysis_status` is polled while a `run_analysis` request is
/// in flight — frequent enough to show function discovery climbing, rare
/// enough to stay out of the server's way.
pub const ANALYSIS_POLL_INTERVAL: Duration = Duration::from_millis(2000);

/// Analysis-cache format version. Bump when the record shape changes: an
/// old document then reads as cold instead of serving records the new
/// readers cannot interpret.
const ANALYSIS_CACHE_VERSION: u32 = 1;

/// What the bootstrap established.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectSetup {
    /// The project file the server now holds open.
    pub project: PathBuf,
    /// Whether this run created the project (first run) rather than
    /// opening or reusing an existing one.
    pub created: bool,
    /// How each binary was brought to current, in request order.
    pub programs: Vec<ProgramLoad>,
}

/// How one binary reached the *loaded and current* state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProgramLoad {
    /// It was already open in the server; switched to when it was not
    /// current. No analysis was run.
    AlreadyOpen {
        /// Whether a switch was needed to make it current.
        switched: bool,
    },
    /// It was opened from the project. `analysis_ran` is false when the
    /// analysis cache showed the bytes were analyzed in an earlier run.
    FromProject { analysis_ran: bool },
    /// It was imported raw from disk and analyzed — a first analysis of
    /// these bytes, always run.
    Imported {
        /// Wall-clock seconds the analysis took.
        secs: u64,
    },
}

/// Ensure the server holds `project` open and every `binaries` path is
/// loaded and current in it, analyzing what needs it.
///
/// `workspace` roots the analysis cache
/// (`<workspace>/re/ghidra/analysis_cache.json`) and the `.gitignore` the
/// bootstrap keeps `ghidra/` in. `events`, when given, receives
/// [`ProgressEvent::GhidraProjectCreated`] when the project is created or
/// opened, and one [`ProgressEvent::GhidraProgramAnalyzed`] per analysis
/// run.
///
/// # Errors
///
/// Any transport or reported error from the project or program endpoints.
/// A binary that cannot be loaded fails the bootstrap — the run cannot
/// translate what Ghidra does not hold — but cache trouble never does.
pub async fn ensure_project(
    client: &GhidraClient,
    project: &Path,
    workspace: &Path,
    binaries: &[PathBuf],
    events: Option<&TranslationEvents>,
) -> Result<ProjectSetup> {
    let created = ensure_project_open(client, project, events).await?;
    // Ghidra project files are binary and large, and the project may have
    // arrived by any route — created here, opened from disk, or already
    // open from an older run — so the ignore rule is ensured every run.
    ensure_gitignore(workspace);
    let cache_path = analysis_cache_path(workspace);
    let mut cache = load_analysis_cache(&cache_path);

    let mut programs = Vec::with_capacity(binaries.len());
    for binary in binaries {
        programs.push(ensure_program(client, binary, &cache_path, &mut cache, events).await?);
    }

    Ok(ProjectSetup {
        project: project.to_path_buf(),
        created,
        programs,
    })
}

/// Make sure the server's open project is `project`: reuse it when it is
/// already current, open it when it exists on disk, create it otherwise.
/// Returns whether this run created it.
async fn ensure_project_open(
    client: &GhidraClient,
    project: &Path,
    events: Option<&TranslationEvents>,
) -> Result<bool> {
    let stem = project
        .file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_default();
    let info = client.project_info().await?;
    if info.has_project && info.name.as_deref() == Some(&stem) {
        debug!(project = %project.display(), "The GhidraMCP server already holds this run's project open");
        return Ok(false);
    }
    if info.has_project {
        debug!(
            open = info.name.as_deref().unwrap_or("unnamed"),
            wanted = %stem,
            "The GhidraMCP server has another project open; opening this run's"
        );
    }

    let created = if project.exists() {
        client.open_project(&project.display().to_string()).await?;
        false
    } else {
        let parent = project.parent().unwrap_or(project);
        std::fs::create_dir_all(parent).map_err(|source| crate::client::GhidraError::LocalIo {
            path: parent.display().to_string(),
            source,
        })?;
        // The bridge's createProject closes whatever is open and opens the
        // new one, so creation needs no follow-up open.
        client
            .create_project(&parent.display().to_string(), &stem)
            .await?;
        true
    };

    info!(project = %project.display(), created, "The GhidraMCP server now holds this run's project");
    if let Some(events) = events {
        events.emit(ProgressEvent::GhidraProjectCreated {
            path: project.display().to_string(),
        });
    }
    Ok(created)
}

/// Bring one binary to *loaded and current*, through the cascade: already
/// open → open from the project → raw import plus analysis.
async fn ensure_program(
    client: &GhidraClient,
    binary: &Path,
    cache_path: &Path,
    cache: &mut AnalysisCache,
    events: Option<&TranslationEvents>,
) -> Result<ProgramLoad> {
    let name = binary
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| binary.display().to_string());

    let open = client.open_programs().await?;
    if let Some(program) = open.iter().find(|p| p.name.eq_ignore_ascii_case(&name)) {
        if program.is_current {
            debug!(program = %name, "The GhidraMCP server already has this program current");
            return Ok(ProgramLoad::AlreadyOpen { switched: false });
        }
        client.switch_program(&program.name).await?;
        info!(program = %name, "Switched the GhidraMCP server to a program it already had open");
        return Ok(ProgramLoad::AlreadyOpen { switched: true });
    }

    // Not open: try the project first — the first run's import (and its
    // analysis) persisted in the `.gpr`, so a later run reopens it without
    // re-importing. A miss is the bridge's structured `success: false`
    // answer, which the client reports as `Ok(None)`.
    match client.load_program_from_project(&format!("/{name}")).await {
        Ok(Some(_)) => {
            let analysis_ran = if analysis_is_cached(cache, binary) {
                info!(program = %name, "Skipping analysis: the analysis cache says these bytes are already analyzed in the project");
                false
            } else {
                analyze(client, &name, binary, cache, cache_path, events).await?;
                true
            };
            Ok(ProgramLoad::FromProject { analysis_ran })
        }
        Ok(None) => {
            debug!(program = %name, "The Ghidra project holds no copy of this binary; importing it");
            import_and_analyze(client, binary, cache, cache_path, events).await
        }
        Err(err) => {
            // "No project open" and kin are hard-sounding but recoverable
            // the same way: import raw. The project was just ensured, so
            // this is the bridge refusing a path, not a broken stack.
            debug!(program = %name, error = %err, "Could not open the program from the project; importing it raw");
            import_and_analyze(client, binary, cache, cache_path, events).await
        }
    }
}

/// Import `binary` raw into the project and analyze it — the first run's
/// path, and the fallback whenever the project has no copy.
async fn import_and_analyze(
    client: &GhidraClient,
    binary: &Path,
    cache: &mut AnalysisCache,
    cache_path: &Path,
    events: Option<&TranslationEvents>,
) -> Result<ProgramLoad> {
    let loaded = client.load_program(&binary.display().to_string()).await?;
    let secs = analyze(client, &loaded.name, binary, cache, cache_path, events).await?;
    Ok(ProgramLoad::Imported { secs })
}

/// Run full auto-analysis on `program`, polling `analysis_status` while
/// the request blocks, then record the result in the analysis cache and
/// emit `GhidraProgramAnalyzed`. Returns the wall-clock seconds taken.
async fn analyze(
    client: &GhidraClient,
    program: &str,
    binary: &Path,
    cache: &mut AnalysisCache,
    cache_path: &Path,
    events: Option<&TranslationEvents>,
) -> Result<u64> {
    // The analysis request holds the connection for minutes; poll its
    // status concurrently so progress is visible while it runs. The poller
    // is aborted the moment the blocking call returns.
    let poller = {
        let client = client.clone();
        let program = program.to_string();
        tokio::spawn(async move {
            loop {
                match client.analysis_status(Some(&program)).await {
                    Ok(statuses) => {
                        for status in statuses {
                            debug!(
                                program = %status.name,
                                analyzing = status.analyzing,
                                functions = status.function_count,
                                "Ghidra analysis in progress"
                            );
                        }
                    }
                    Err(err) => {
                        debug!(program = %program, error = %err, "Analysis status poll did not land");
                    }
                }
                tokio::time::sleep(ANALYSIS_POLL_INTERVAL).await;
            }
        })
    };

    let started = Instant::now();
    let outcome = client.run_analysis(Some(program)).await;
    poller.abort();
    let outcome = outcome?;

    let secs = started.elapsed().as_secs();
    info!(
        program = %outcome.program,
        secs,
        functions = outcome.total_functions,
        new_functions = outcome.new_functions,
        "Ghidra auto-analysis finished"
    );
    record_analysis(cache, binary, secs, cache_path);
    if let Some(events) = events {
        events.emit(ProgressEvent::GhidraProgramAnalyzed {
            dll: program.to_string(),
            secs,
        });
    }
    Ok(secs)
}

// ============================================================
// Analysis cache: re/ghidra/analysis_cache.json
// ============================================================

/// One analyzed file: the bytes it was analyzed as, and how long it took.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct AnalysisRecord {
    /// SHA-256 (hex) of the binary's file bytes at analysis time.
    sha256: String,
    /// Wall-clock seconds the analysis took.
    secs: u64,
}

/// The whole cache document: versioned, keyed by the file's path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct AnalysisCache {
    /// The [`ANALYSIS_CACHE_VERSION`] this document was written under.
    version: u32,
    /// Analyzed files, keyed by their path (canonical when it resolved).
    analyzed: BTreeMap<String, AnalysisRecord>,
}

impl Default for AnalysisCache {
    fn default() -> Self {
        Self {
            version: ANALYSIS_CACHE_VERSION,
            analyzed: BTreeMap::new(),
        }
    }
}

/// The cache document's location for a workspace.
pub fn analysis_cache_path(workspace: &Path) -> PathBuf {
    workspace
        .join("re")
        .join("ghidra")
        .join("analysis_cache.json")
}

/// Read the cache; anything unreadable, corrupt, or of another version
/// reads as cold — the degradation the module docs promise.
fn load_analysis_cache(path: &Path) -> AnalysisCache {
    match load_json::<AnalysisCache>(path) {
        Ok(cache) if cache.version == ANALYSIS_CACHE_VERSION => cache,
        Ok(_) => {
            info!(path = %path.display(), "Analysis cache is an older format; starting cold");
            AnalysisCache::default()
        }
        Err(calxgloss_types::persist::PersistError::NotFound { .. }) => AnalysisCache::default(),
        Err(err) => {
            warn!(path = %path.display(), error = %err, "Analysis cache could not be read; starting cold");
            AnalysisCache::default()
        }
    }
}

/// The cache key for a binary: its canonical path when that resolves, so
/// the same file reached by different spellings shares one record.
fn cache_key(binary: &Path) -> String {
    binary
        .canonicalize()
        .unwrap_or_else(|_| binary.to_path_buf())
        .display()
        .to_string()
}

/// Whether `binary`'s current bytes match an analyzed record.
fn analysis_is_cached(cache: &AnalysisCache, binary: &Path) -> bool {
    let Some(sha) = hash_of(binary) else {
        return false;
    };
    cache
        .analyzed
        .get(&cache_key(binary))
        .is_some_and(|record| record.sha256 == sha)
}

/// Record a finished analysis and save the document. A failed save is
/// logged, not raised: the cost is one re-analysis next run.
fn record_analysis(cache: &mut AnalysisCache, binary: &Path, secs: u64, cache_path: &Path) {
    if let Some(sha) = hash_of(binary) {
        cache
            .analyzed
            .insert(cache_key(binary), AnalysisRecord { sha256: sha, secs });
    }
    if let Err(err) = save_json(cache_path, cache) {
        warn!(path = %cache_path.display(), error = %err, "Analysis cache could not be saved; the next run may re-analyze");
    }
}

/// SHA-256 of the binary's bytes, `None` when it cannot be read — an
/// unhashable file is never treated as cached.
fn hash_of(binary: &Path) -> Option<String> {
    match sha256_of_file(binary) {
        Ok(sha) => sha,
        Err(err) => {
            warn!(path = %binary.display(), error = %err, "Binary could not be hashed for the analysis cache");
            None
        }
    }
}

// ============================================================
// .gitignore: Ghidra project files are binary and large
// ============================================================

/// Ensure the workspace `.gitignore` carries `ghidra/`, creating or
/// appending as needed. Failure is logged, not raised — a missing ignore
/// rule is an inconvenience, not a broken run.
fn ensure_gitignore(workspace: &Path) {
    let path = workspace.join(".gitignore");
    let existing = match std::fs::read_to_string(&path) {
        Ok(body) => body,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(err) => {
            warn!(path = %path.display(), error = %err, "Could not read the workspace .gitignore");
            return;
        }
    };
    if existing.lines().any(|line| line.trim() == "ghidra/") {
        return;
    }
    let mut updated = existing;
    if !updated.is_empty() && !updated.ends_with('\n') {
        updated.push('\n');
    }
    updated.push_str("ghidra/\n");
    if let Err(err) = std::fs::write(&path, updated) {
        warn!(path = %path.display(), error = %err, "Could not add ghidra/ to the workspace .gitignore");
    }
}
