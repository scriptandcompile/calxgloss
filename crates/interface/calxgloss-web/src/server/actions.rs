//! Human review actions, backed by real Git and Translator operations.
//!
//! This module turns a reviewer's accept / send-back / patch action in
//! the web UI into real Git operations and, for patch requests, queued
//! retry translations.
//!
//! # Actions
//!
//! | Action | Git operation | Translator operation |
//! |--------|--------------|---------------------|
//! | Accept | `accept_branch` — merge to main, write `re/accepts/` record | none |
//! | Send-back | `reject_branch` — write `re/rejections/` record | none (the LLM learns it from the rejection file) |
//! | Patch | `next_attempt_branch` — create v{N+1} branch, write `re/patches/` record | enqueue retry translation for the new branch |
//!
//! Patch requests are idempotent while a retry is in flight: a second request
//! for a unit whose next attempt already has a patch request returns the
//! existing one instead of starting a second retry (issue #84).
//!
//! Actions on the same unit never silently disagree with git. Each action
//! captures the unit's persisted action state at start and re-checks it
//! before writing its own record: a racing action fails with a conflict
//! error instead of overwriting a newer record. Send-back and patch are
//! refused on an already-accepted unit (issue #86).
//!
//! The patch-retry pass is assembled per request through the translator's
//! assembly seam (issue #327). `serve`/`live` fold their resolved settings
//! into a [`calxgloss_translator::assembly::PipelineSpec`]; the request adds
//! this unit's binary and patch mode; `assemble_patch` then builds the whole
//! pass — its LLM client from the description's LLM selection (no
//! environment reads, no inline fallback chain), its analysis engine load
//! under the configured Kuna budgets, its retry config from the
//! description's policy. A server started without LLM settings fails a
//! patch request with the seam's assembly error, before any branch or
//! record exists.

use calxgloss_git::{GitManager, ShimDependencyMap};
use calxgloss_translator::assembly::{AssembledPass, BinaryTarget, PipelineSpec, assemble_patch};
use calxgloss_types::{GitBranch, ReviewStatus, TypesError};
use chrono::Utc;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use tracing::{info, warn};

// ============================================================
// State — shared across all handlers
// ============================================================

/// Shared state that the API handlers use to act on a unit of work.
#[derive(Clone)]
pub struct ActionsState {
    /// Path to the Git repository.
    repo_path: PathBuf,
    /// Serializes review actions within this process (issue #86). Action
    /// records are written only by the web server, so an in-process lock —
    /// not cross-process file locking — makes each action's conflict
    /// re-check and record write atomic against racing actions on a unit
    /// (e.g. a fast Accept-then-Send-Back double-click).
    action_lock: Arc<tokio::sync::Mutex<()>>,
    /// Where the target binaries live (issue #214): a patch retry loads
    /// the Kuna engine from `target_dir/<binary>`. `None` means retries
    /// refuse by name rather than guessing a path.
    target_dir: Option<PathBuf>,
    /// The server's pass description (issue #327). `serve`/`live` folded
    /// it once from the resolved settings they started with. Each patch
    /// request adds the run-scoped fields (patch mode, this unit's binary
    /// under the target dir, the repo as workspace) before `assemble_patch`
    /// builds the retry pass. The LLM selection, Kuna budgets, retry policy
    /// and everything else the fold composes arrive through this
    /// description — the description is the source, so the handler reads no
    /// environment variables and fills in no default `RetryConfig` by hand.
    /// A server started without LLM settings holds a description with no
    /// LLM selection, and its patch requests fail with the seam's assembly
    /// error at request time.
    pass_spec: PipelineSpec,
}

impl ActionsState {
    /// Build the actions backend for `repo_path`, with the pass description
    /// folded from the server's resolved settings (issue #327) — the same
    /// `pipeline_spec` fold the CLI commands run their passes through.
    pub fn new(repo_path: PathBuf, pass_spec: PipelineSpec) -> Self {
        Self {
            repo_path,
            action_lock: Arc::new(tokio::sync::Mutex::new(())),
            target_dir: None,
            pass_spec,
        }
    }

    /// Set the directory the target binaries live in, so patch retries
    /// can load the Kuna engine from `target_dir/<binary>`.
    pub fn with_target_dir(mut self, target_dir: impl Into<PathBuf>) -> Self {
        self.target_dir = Some(target_dir.into());
        self
    }

    /// Returns the path to the repository.
    pub fn repo_path(&self) -> &Path {
        &self.repo_path
    }

    /// Where the target binaries live, for analysis engine loads in
    /// patch retries.
    pub fn target_dir(&self) -> Option<&Path> {
        self.target_dir.as_deref()
    }

    /// The description one patch request runs (issue #327): the server's
    /// folded description plus the run-scoped fields — patch mode, this
    /// unit's binary resolved under the server's target dir, and the repo
    /// as the workspace. A patch retry writes into the server's repo,
    /// whatever workspace the settings record names. The result is pure
    /// data; each request does the assembly that turns it into a pass.
    fn patch_pass_spec(&self, binary: &str) -> Result<PipelineSpec, anyhow::Error> {
        // Kuna is the only analysis engine (issue #214): the scan source is
        // loaded in-process from the target file, so a retry needs the target
        // directory the binary lives in — refuse by name when the server was
        // started without one rather than guessing a path.
        let target_dir = self.target_dir.as_ref().ok_or_else(|| {
            anyhow::anyhow!(
                "no target directory is configured for this server, so {binary} cannot be loaded for the patch retry"
            )
        })?;
        let mut spec = self.pass_spec.clone();
        spec.workspace = self.repo_path.clone();
        spec.patch_mode = true;
        spec.target_binary = Some(BinaryTarget {
            name: binary.to_string(),
            path: target_dir.join(binary),
        });
        Ok(spec)
    }

    /// Begins one review action on a unit: captures the unit's persisted
    /// action state at start, then acquires the action lock so the action's
    /// conflict re-check and record write are atomic against racing actions
    /// on the unit (issue #86). The capture deliberately happens *before*
    /// the lock — a state that lands in between is exactly what the
    /// action's write-time re-check must catch.
    async fn begin_action(
        &self,
        unit_id: &str,
    ) -> (Option<ReviewStatus>, tokio::sync::MutexGuard<'_, ()>) {
        let captured = read_action_state(&self.repo_path, unit_id).map(|r| r.action);
        let guard = self.action_lock.lock().await;
        (captured, guard)
    }
}

// ============================================================
// Persisted review state
// ============================================================

/// Represents the last review action taken on a unit, persisted to disk
/// so the dashboard can display accurate status counts.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct ReviewActionRecord {
    pub unit_id: String,
    pub action: ReviewStatus,
    pub comments: Option<String>,
    pub performed_at: String,
    pub branch_name: Option<String>,
}

/// Path of the persisted action record for a unit.
///
/// `unit_id` includes slashes (`{binary}/{function}/v{attempt}`), so the
/// joined path nests under the actions dir rather than being one flat file.
fn action_record_path(repo_path: &Path, unit_id: &str) -> PathBuf {
    repo_path
        .join("re")
        .join("actions")
        .join(format!("{unit_id}.json"))
}

/// Writes a review action record to disk so the dashboard stays in sync.
fn persist_action_state(
    repo_path: &Path,
    record: &ReviewActionRecord,
) -> Result<PathBuf, TypesError> {
    let actions_dir = repo_path.join("re").join("actions");
    std::fs::create_dir_all(&actions_dir)
        .map_err(|e| TypesError::InvalidBranchName(format!("Failed to create actions dir: {e}")))?;

    let action_file = action_record_path(repo_path, &record.unit_id);
    if let Some(parent) = action_file.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            TypesError::InvalidBranchName(format!("Failed to create action dir: {e}"))
        })?;
    }
    let json = serde_json::to_string_pretty(record).map_err(TypesError::Serialization)?;
    std::fs::write(&action_file, json).map_err(|e| {
        TypesError::InvalidBranchName(format!("Failed to write action record: {e}"))
    })?;

    Ok(action_file)
}

/// Reads the persisted action record for a unit, if one exists.
///
/// A missing or unreadable record yields `None` — the caller treats it as
/// "no action recorded" rather than failing the request.
fn read_action_state(repo_path: &Path, unit_id: &str) -> Option<ReviewActionRecord> {
    std::fs::read_to_string(action_record_path(repo_path, unit_id))
        .ok()
        .and_then(|json| serde_json::from_str(&json).ok())
}

// ============================================================
// Conflict checking (issue #86)
// ============================================================

/// A review action was refused because of the unit's persisted action state
/// (issue #86). The message names the state that is actually persisted, so
/// the reviewer learns the unit changed underneath them instead of watching
/// a later action silently overwrite an earlier one.
#[derive(Debug, thiserror::Error)]
pub enum ActionConflictError {
    /// A different action landed between this action's start and its record
    /// write — the persisted state no longer matches what was captured.
    #[error(
        "Unit {unit_id} changed underneath you: its review state is now {current} — \
         not overwriting that action record"
    )]
    ChangedUnderneath {
        /// The unit the refused action targeted.
        unit_id: String,
        /// The persisted state found at check time, named for display.
        current: String,
    },
    /// The unit is already accepted: its code is merged to main and there is
    /// no un-merge path, so send-back and patch are refused outright.
    #[error(
        "Unit {unit_id} is already accepted (merged to main) — send-back and patch \
         are refused; there is no un-merge path"
    )]
    AlreadyAccepted {
        /// The unit the refused action targeted.
        unit_id: String,
    },
}

/// Names a persisted action state for conflict messages; a missing record
/// reads as "no recorded action" rather than an empty string.
fn state_name(state: Option<&ReviewStatus>) -> String {
    state
        .map(|s| s.to_string())
        .unwrap_or_else(|| "no recorded action".to_string())
}

/// Re-checks the unit's persisted action state just before an action writes
/// its own record. Fails with [`ActionConflictError::ChangedUnderneath`]
/// naming the current state when a different action landed since the action
/// captured the state at start (issue #86).
///
/// Returns the current persisted state so callers can apply further rules
/// (e.g. refusing send-back/patch on an accepted unit).
fn check_action_conflict(
    repo_path: &Path,
    unit_id: &str,
    captured: Option<ReviewStatus>,
) -> Result<Option<ReviewStatus>, ActionConflictError> {
    let current = read_action_state(repo_path, unit_id).map(|r| r.action);
    if current != captured {
        return Err(ActionConflictError::ChangedUnderneath {
            unit_id: unit_id.to_string(),
            current: state_name(current.as_ref()),
        });
    }
    Ok(current)
}

/// Refuses send-back and patch on an already-accepted unit: the code is
/// merged to main and there is no un-merge path (issue #86).
fn ensure_not_accepted(
    unit_id: &str,
    current: Option<ReviewStatus>,
) -> Result<(), ActionConflictError> {
    if current == Some(ReviewStatus::Accepted) {
        return Err(ActionConflictError::AlreadyAccepted {
            unit_id: unit_id.to_string(),
        });
    }
    Ok(())
}

// ============================================================
// Action implementations
// ============================================================

/// Accept a unit of work: merge the branch to main and persist the action.
///
/// When the branch cannot merge cleanly, the merge conflicts are reported as
/// an error naming the conflicted files and no `Accepted` action state is
/// persisted — the unit keeps its pre-accept status (issue #83).
///
/// The unit's persisted action state is captured at start and re-checked
/// before touching git: if another review action landed in the meantime, the
/// accept fails with a conflict error instead of racing the other action's
/// record write (issue #86).
pub async fn accept_unit(
    state: &ActionsState,
    unit_id: &str,
) -> Result<ActionResult, anyhow::Error> {
    let (captured, _action_guard) = state.begin_action(unit_id).await;

    let unit = lookup_unit(state, unit_id)?;
    let branch = GitBranch::new(
        &unit.binary,
        unit.function.as_deref().unwrap_or(""),
        unit.attempt,
    )?;
    let git = GitManager::open(state.repo_path())?;

    // Re-check before merging: the lock guarantees nothing lands between here
    // and the persist below, so a stale capture means the unit changed
    // underneath us — fail without merging or overwriting (issue #86).
    check_action_conflict(state.repo_path(), unit_id, captured)?;

    // Merge the branch (write acceptance record)
    let merge_result = git.accept_branch(&branch)?;
    let merge_hash = match &merge_result {
        calxgloss_git::MergeResult::Merged { merge_hash } => Some(merge_hash.clone()),
        calxgloss_git::MergeResult::AlreadyUpToDate => None,
        // A conflicted merge landed nothing on main — fail before persisting
        // any action state so the unit keeps its pre-accept status (issue #83).
        calxgloss_git::MergeResult::Conflicts {
            conflicted_files,
            error,
        } => {
            return Err(anyhow::anyhow!(
                "Cannot accept unit {unit_id}: {error} — conflicted files: {}",
                conflicted_files.join(", ")
            ));
        }
    };

    // Persist action state
    let record = ReviewActionRecord {
        unit_id: unit_id.to_string(),
        action: ReviewStatus::Accepted,
        comments: None,
        performed_at: Utc::now().to_rfc3339(),
        branch_name: Some(branch.name.clone()),
    };
    persist_action_state(state.repo_path(), &record)?;

    info!("Unit {unit_id} accepted — branch {} merged", branch.name);

    Ok(ActionResult {
        unit_id: unit_id.to_string(),
        action: "accept".to_string(),
        merge_hash,
        branch_name: Some(branch.name.clone()),
        message: "Unit accepted and merged to main".to_string(),
        rejection_path: None,
        translated_code: None,
    })
}

/// Send back a unit of work: write rejection record and persist the action.
///
/// Refused when the unit is already accepted: its code is merged to main
/// and there is no un-merge path (issue #86). A different action landing
/// between this action's start and its record write also fails it with a
/// conflict error naming the current state, instead of letting the last
/// write silently win.
pub async fn send_back_unit(
    state: &ActionsState,
    unit_id: &str,
    reason: &str,
) -> Result<ActionResult, anyhow::Error> {
    let (captured, _action_guard) = state.begin_action(unit_id).await;

    let unit = lookup_unit(state, unit_id)?;
    let branch = GitBranch::new(
        &unit.binary,
        unit.function.as_deref().unwrap_or(""),
        unit.attempt,
    )?;
    let git = GitManager::open(state.repo_path())?;

    // Re-check before writing anything (issue #86).
    let current = check_action_conflict(state.repo_path(), unit_id, captured)?;
    ensure_not_accepted(unit_id, current)?;

    // Write rejection record
    let rejection_path = git.reject_branch(&branch, reason)?;

    // Persist action state
    let record = ReviewActionRecord {
        unit_id: unit_id.to_string(),
        action: ReviewStatus::SendBack,
        comments: Some(reason.to_string()),
        performed_at: Utc::now().to_rfc3339(),
        branch_name: Some(branch.name.clone()),
    };
    persist_action_state(state.repo_path(), &record)?;

    info!("Unit {unit_id} sent back — reason: {reason:?}");

    Ok(ActionResult {
        unit_id: unit_id.to_string(),
        action: "send_back".to_string(),
        merge_hash: None,
        branch_name: Some(branch.name.clone()),
        message: format!("Unit sent back: {reason}"),
        rejection_path: Some(rejection_path.to_string_lossy().to_string()),
        translated_code: None,
    })
}

/// Request a patch: create the next-attempt branch, persist the action,
/// and start an async retry translation through the translator pipeline.
///
/// Idempotent while a retry is in flight (issue #84): if the unit's persisted
/// action record already records a patch request for the next attempt, the
/// existing request is returned (`action: "patch_already_in_progress"`) —
/// no second branch, record, or racing retry task is created.
///
/// Refused when the unit is already accepted: the code is merged to main
/// and there is no un-merge path (issue #86). As with the other actions, a
/// different action landing between this request's start and its record
/// write fails it with a conflict error instead of overwriting the record.
pub async fn request_patch(
    state: &ActionsState,
    unit_id: &str,
    issue: &str,
) -> Result<ActionResult, anyhow::Error> {
    request_patch_spawning(state, unit_id, issue, |task| {
        tokio::spawn(task);
    })
    .await
}

/// The detached background retry task a patch request hands to the spawner.
type PatchRetryTask = Pin<Box<dyn Future<Output = ()> + Send>>;

/// `request_patch` with the background retry spawn behind a seam, so tests
/// can count how many retry tasks a request starts without running the real
/// translation pipeline.
async fn request_patch_spawning(
    state: &ActionsState,
    unit_id: &str,
    issue: &str,
    spawn_retry: impl FnOnce(PatchRetryTask),
) -> Result<ActionResult, anyhow::Error> {
    let (captured, _action_guard) = state.begin_action(unit_id).await;

    let unit = lookup_unit(state, unit_id)?;
    let git = GitManager::open(state.repo_path())?;

    // Re-check before creating anything (issue #86).
    let current = check_action_conflict(state.repo_path(), unit_id, captured)?;
    ensure_not_accepted(unit_id, current)?;

    // Create the next-attempt branch
    let next_branch = git.next_attempt_branch(
        &unit.binary,
        unit.function.as_deref().unwrap_or(""),
        unit.attempt,
    )?;

    // Idempotency guard (issue #84): while a retry is in flight, the unit's
    // action record already names this next-attempt branch. Return the
    // existing request instead of creating the branch, record, and a second
    // retry task racing on the same branch. A finished patch moves the unit
    // to the new attempt's id, so its record never matches here and a fresh
    // request still starts a fresh attempt.
    if let Some(existing) = read_action_state(state.repo_path(), unit_id)
        && existing.action == ReviewStatus::PatchRequested
        && existing.branch_name.as_deref() == Some(next_branch.name.as_str())
    {
        info!(
            "Patch already in progress for {unit_id} on {} — ignoring duplicate request",
            next_branch.name
        );
        return Ok(ActionResult {
            unit_id: unit_id.to_string(),
            action: "patch_already_in_progress".to_string(),
            merge_hash: None,
            message: format!(
                "Patch already in progress for attempt {} on branch {}",
                next_branch.attempt, next_branch.name
            ),
            branch_name: Some(next_branch.name),
            rejection_path: None,
            translated_code: None,
        });
    }

    // Assemble the retry pass before anything is created (issue #327): the
    // server's folded description plus this unit's binary, then the seam
    // builds the whole pass — its LLM client from the description's LLM
    // selection (no environment reads, no inline fallback chain), its
    // analysis engine load under the description's Kuna budgets, its retry
    // config from the description's policy. An unbuildable pass — a server
    // started without LLM settings, or an unreadable binary — fails the
    // request HERE, at patch-request time, so the reviewer sees the
    // assembly error and no half-configured retry exists: no branch, no
    // record, no racing task.
    let spec = state.patch_pass_spec(&unit.binary)?;
    let pass = assemble_patch(&spec).await.map_err(|e| {
        anyhow::anyhow!("patch retry for {unit_id} could not assemble its pass: {e}")
    })?;

    // Create the branch in git (from main)
    let policy = match unit.kind.clone() {
        calxgloss_types::WorkKind::FunctionTranslation => {
            // For function translations, check shim dependencies
            let shim_map = ShimDependencyMap::new();
            let shim_crate = shim_map.get(&unit.binary).map(|s| s.to_string());
            Some(calxgloss_git::BranchCreationPolicy::Warn(
                calxgloss_git::DependencyPolicy {
                    category: calxgloss_types::DllCategory::ProjectSpecific,
                    crate_replacement: shim_crate,
                },
            ))
        }
        _ => None,
    };

    let _branch_result = git.create_branch(
        &unit.binary,
        unit.function.as_deref().unwrap_or(""),
        next_branch.attempt,
        policy.as_ref(),
    )?;

    // Write the patch request record (so the dashboard knows what to fix)
    let patch_dir = state
        .repo_path()
        .join("re")
        .join("patches")
        .join(&next_branch.binary)
        .join(&next_branch.function);
    std::fs::create_dir_all(&patch_dir)
        .map_err(|e| TypesError::InvalidBranchName(format!("Failed to create patch dir: {e}")))?;

    let patch_record_path = patch_dir.join(format!("v{}.json", next_branch.attempt));
    let patch_record = serde_json::json!({
        "binary": next_branch.binary,
        "function": next_branch.function,
        "attempt": next_branch.attempt,
        "branch_name": next_branch.name,
        "committed_at": Utc::now().to_rfc3339(),
        "error_message": issue.to_string(),
        "compilation_errors": Vec::<String>::new(),
        "test_failures": Vec::<String>::new(),
        "commit_hash": "",
        "patch_request": issue.to_string(),
    });
    std::fs::write(
        &patch_record_path,
        serde_json::to_string_pretty(&patch_record).map_err(TypesError::Serialization)?,
    )
    .map_err(|e| TypesError::InvalidBranchName(format!("Failed to write patch record: {e}")))?;

    // Persist action state
    let record = ReviewActionRecord {
        unit_id: unit_id.to_string(),
        action: ReviewStatus::PatchRequested,
        comments: Some(issue.to_string()),
        performed_at: Utc::now().to_rfc3339(),
        branch_name: Some(next_branch.name.clone()),
    };
    persist_action_state(state.repo_path(), &record)?;

    // Start the async retry translation in the background.
    // We can't hold git2 objects across await points (they're not Send),
    // so we pass only the data the closure needs and let it open its own GitManager.
    // The assembled pass (issue #327) is handed to the task: everything the
    // retry translates with was already built from the description above.
    let repo_path = state.repo_path().to_path_buf();
    let issue_str = issue.to_string();
    let binary = unit.binary.clone();
    let function = unit.function.clone().unwrap_or_default();
    let attempt = next_branch.attempt;
    let branch_name = next_branch.name.clone();
    let branch_name_for_log = branch_name.clone();

    spawn_retry(Box::pin(async move {
        if let Err(e) =
            run_patch_retry(pass, &repo_path, &issue_str, &binary, &function, attempt).await
        {
            warn!("Patch retry failed for {branch_name_for_log}: {e}");
        }
    }));

    info!("Unit {unit_id} patch requested for attempt {attempt} — issue: {issue:?}");

    Ok(ActionResult {
        unit_id: unit_id.to_string(),
        action: "patch_requested".to_string(),
        merge_hash: None,
        branch_name: Some(branch_name),
        message: format!("Patch requested: {issue}"),
        rejection_path: None,
        translated_code: None,
    })
}

/// Run a full retry translation for a patch request.
///
/// The request assembled this retry's pass itself, from the server's pass
/// description (issue #327): pipeline, verifier, and retry config all
/// arrive on [`AssembledPass`]. This function only handles the git branch
/// switching around the retry loop and records the outcome.
async fn run_patch_retry(
    pass: AssembledPass,
    repo_path: &Path,
    _issue: &str,
    binary: &str,
    function: &str,
    attempt: u32,
) -> Result<(), anyhow::Error> {
    // Build the branch name for the retry
    let branch = GitBranch::new(binary, function, attempt)?;

    // Switch to the branch — we must drop all git2 objects before awaiting.
    // We use a helper closure that does all the git setup and returns the
    // minimal info needed after the pipeline await.
    let git = GitManager::open(repo_path)?;
    let setup_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(
        || -> Result<(git2::Oid, std::path::PathBuf), anyhow::Error> {
            // Get main's OID
            let main_ref = git
                .repo()
                .find_branch("main", git2::BranchType::Local)
                .map_err(|_| TypesError::InvalidBranchName("main branch not found".to_string()))?;
            let main_commit = main_ref.get().peel_to_commit().map_err(|e| {
                TypesError::InvalidBranchName(format!("Failed to resolve main: {e}"))
            })?;
            let main_oid = main_commit.id();

            // Create the branch reference pointing to main's commit
            let branch_ref_name = format!("refs/heads/{}", branch.name);
            git.repo()
                .reference(&branch_ref_name, main_oid, true, &branch.name)
                .map_err(|e| anyhow::anyhow!("Branch creation failed: {e}"))?;

            let mut checkout_opts = git2::build::CheckoutBuilder::new();
            checkout_opts.force();

            git.repo()
                .set_head(&branch_ref_name)
                .map_err(|e| anyhow::anyhow!("Failed to set HEAD: {e}"))?;

            let main_commit = main_ref
                .get()
                .peel_to_commit()
                .map_err(|e| TypesError::InvalidBranchName(format!("Failed to peel main: {e}")))?;
            let main_obj = main_commit.as_object();

            git.repo()
                .reset(main_obj, git2::ResetType::Hard, Some(&mut checkout_opts))
                .map_err(|e| anyhow::anyhow!("Failed to reset: {e}"))?;

            Ok((main_oid, repo_path.to_path_buf()))
        },
    ));

    if setup_result.is_err() {
        return Err(anyhow::anyhow!("Failed to set up branch for patch retry"));
    }
    let Ok((_, _)) = setup_result.unwrap() else {
        return Err(anyhow::anyhow!("Failed to set up branch for patch retry"));
    };

    // Now drop all git2 objects — the `git` variable goes out of scope
    // (it was moved into the closure). Run the pipeline.
    info!("Starting patch retry for {binary}/{function} v{attempt}");

    let result = pass
        .pipeline
        .try_translate_with_retry(binary, function, &pass.retry, &pass.verifier)
        .await?;

    if result.success {
        // Commit the successful translation to the branch
        // Write the generated Rust code to the appropriate module file
        let rust_code = result
            .rust_code
            .as_ref()
            .expect("success implies code present");
        let modules_dir = repo_path.join("src").join("modules");
        std::fs::create_dir_all(&modules_dir).ok();

        // Determine the source file name (e.g., game_logic.rs for game_logic.dll).
        // Stem derivation is naming, not identity (issue #68): strip whatever
        // extension the binary has (.binary, .exe, …).
        let src_file_name = std::path::Path::new(binary)
            .file_stem()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| binary.to_string())
            + ".rs";
        let dest_path = modules_dir.join(&src_file_name);

        // Append the function to the existing module file
        let mut existing = std::fs::read_to_string(&dest_path).unwrap_or_default();
        if !existing.is_empty() && !existing.ends_with('\n') {
            existing.push('\n');
        }
        existing.push_str(rust_code);
        existing.push('\n');
        std::fs::write(&dest_path, &existing)?;

        // Re-open git and commit (avoid holding git2 objects across await)
        let git = GitManager::open(repo_path)?;
        // Switch to branch again
        let branch_ref = git
            .repo()
            .find_branch(&branch.name, git2::BranchType::Local)
            .map_err(|_| {
                TypesError::InvalidBranchName(format!("Branch {} not found", branch.name))
            })?;
        git.repo()
            .set_head(&format!("refs/heads/{}", branch.name))
            .map_err(|e| anyhow::anyhow!("Failed to set HEAD: {e}"))?;
        let branch_commit = branch_ref
            .get()
            .peel_to_commit()
            .map_err(|e| anyhow::anyhow!("Failed to resolve branch: {e}"))?;
        let branch_obj = branch_commit.as_object();
        let mut co = git2::build::CheckoutBuilder::new();
        co.force();
        git.repo()
            .reset(branch_obj, git2::ResetType::Hard, Some(&mut co))
            .map_err(|e| anyhow::anyhow!("Failed to reset: {e}"))?;

        // Commit
        let commit_msg = format!(
            "re/{binary}/{function}v{attempt}: translate {function} to Rust (patch retry)",
        );
        let _commit = git.commit(
            &branch,
            &commit_msg,
            &[&format!("src/modules/{src_file_name}")],
        )?;

        // Write the successful patch record
        let patch_dir = repo_path
            .join("re")
            .join("patches")
            .join(binary)
            .join(function);
        std::fs::create_dir_all(&patch_dir).map_err(|e| {
            TypesError::InvalidBranchName(format!("Failed to create patch dir: {e}"))
        })?;
        let patch_record_path = patch_dir.join(format!("v{}.json", attempt));
        let mut patch_record = serde_json::json!({
            "binary": binary,
            "function": function,
            "attempt": attempt,
            "branch_name": branch.name,
            "committed_at": Utc::now().to_rfc3339(),
            "error_message": "",
            "compilation_errors": Vec::<String>::new(),
            "test_failures": Vec::<String>::new(),
            "commit_hash": "",
        });
        if let Ok(commit) = git.commit(&branch, "", &[]) {
            patch_record["commit_hash"] = serde_json::Value::String(commit.hash);
        }
        let json = serde_json::to_string_pretty(&patch_record)?;
        std::fs::write(&patch_record_path, json)?;

        info!("Patch retry succeeded for {binary}/{function} v{attempt} — committed");
    } else {
        warn!("Patch retry exhausted all attempts for {binary}/{function} v{attempt}");
    }

    Ok(())
}

// ============================================================
// Support types
// ============================================================

/// The result of a review action.
#[derive(Debug, Clone)]
pub struct ActionResult {
    /// The unit of work this action was applied to.
    pub unit_id: String,

    /// The action performed (e.g., "accept", "send_back", "patch_requested").
    pub action: String,

    /// Merge hash if the unit was accepted and merged.
    pub merge_hash: Option<String>,

    /// Branch name that was operated on.
    pub branch_name: Option<String>,

    /// Human-readable message describing the result.
    pub message: String,

    /// Path to the rejection record (for send-back actions).
    pub rejection_path: Option<String>,

    /// The translated Rust code (for successful patch actions).
    pub translated_code: Option<String>,
}

/// Look up a unit of work from the dashboard data on disk.
fn lookup_unit(
    state: &ActionsState,
    unit_id: &str,
) -> Result<calxgloss_types::UnitOfWork, anyhow::Error> {
    let dashboard = super::build_dashboard(state.repo_path())?;
    dashboard
        .review_queue
        .iter()
        .chain(dashboard.recent_activity.iter())
        .find(|u| u.id == unit_id)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("Unit not found: {unit_id}"))
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use calxgloss_translator::assembly::{LlmDescription, LlmSelection};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// The description a server folds when it was started without LLM
    /// settings (issue #327): no LLM selection, so every patch request must
    /// fail at assembly with the seam's `MissingLlm` error.
    fn spec_without_llm() -> PipelineSpec {
        PipelineSpec::default()
    }

    /// A description with an LLM selection pointed at a port where
    /// nothing listens: `assemble_patch` builds the client fine, and the
    /// counting spawners below never let the retry run far enough to call it.
    fn spec_with_dead_llm() -> PipelineSpec {
        PipelineSpec {
            llm: Some(LlmSelection::Description(LlmDescription {
                endpoint: "http://127.0.0.1:1/v1/chat/completions".to_string(),
                model: "fixture-model".to_string(),
                api_key: None,
                context_window: Some(128_000),
                temperature: None,
                timeout_secs: Some(2),
            })),
            ..PipelineSpec::default()
        }
    }

    /// A fresh target dir holding the Kuna-loadable fixture binary renamed
    /// to `binary`: `assemble_patch` loads the retry's analysis engine from
    /// `target_dir/<binary>`, and the units in the tests below are named
    /// `game_logic.dll`.
    fn target_dir_with(binary: &str) -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("target dir");
        let fixture = calxgloss_testfixtures::fixture_target_path().expect("fixture target path");
        std::fs::copy(fixture, dir.path().join(binary)).expect("copy fixture binary");
        dir
    }

    /// A repo with one review unit: branch `re/game_logic.dll/DrawSpritev1`
    /// with one translated commit, so accepting the unit really merges code
    /// to main (the issue #86 tests check the persisted status against the
    /// actual git outcome).
    fn make_repo_with_unit() -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("temp dir");
        let git = GitManager::init_repo(dir.path(), None).expect("init git repo");
        git.create_branch("game_logic.dll", "DrawSprite", 1, None)
            .expect("create v1 branch");

        let branch = GitBranch::new("game_logic.dll", "DrawSprite", 1).expect("branch name");
        std::fs::create_dir_all(dir.path().join("src").join("modules")).expect("src dir");
        std::fs::write(
            dir.path().join("src").join("modules").join("game_logic.rs"),
            "pub fn draw_sprite() {}\n",
        )
        .expect("write translation");
        git.commit(
            &branch,
            "Translate DrawSprite",
            &["src/modules/game_logic.rs"],
        )
        .expect("commit translation");
        dir
    }

    /// A spawner that counts retry tasks instead of running them, dropping
    /// the task future so the translation pipeline never executes.
    fn counting_spawner(counts: &Arc<AtomicUsize>) -> impl FnOnce(PatchRetryTask) {
        let counts = counts.clone();
        move |_task: PatchRetryTask| {
            counts.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn patch_record_path(root: &Path, attempt: u32) -> PathBuf {
        root.join("re")
            .join("patches")
            .join("game_logic.dll")
            .join("DrawSprite")
            .join(format!("v{attempt}.json"))
    }

    #[tokio::test]
    async fn double_click_starts_one_branch_and_one_retry() {
        let dir = make_repo_with_unit();
        // Issue #327: the request assembles a real pass before recording
        // anything, so this test's state uses a description-backed
        // backend: a description with an LLM selection and a target dir
        // holding the unit's binary. The counting spawner still drops the
        // retry task, so the dead endpoint is never called.
        let target = target_dir_with("game_logic.dll");
        let state = ActionsState::new(dir.path().to_path_buf(), spec_with_dead_llm())
            .with_target_dir(target.path().to_path_buf());
        let spawns = Arc::new(AtomicUsize::new(0));

        let first = request_patch_spawning(
            &state,
            "game_logic.dll/DrawSprite/v1",
            "off-by-one in loop bound",
            counting_spawner(&spawns),
        )
        .await
        .expect("first patch request succeeds");
        assert_eq!(first.action, "patch_requested");
        assert_eq!(
            first.branch_name.as_deref(),
            Some("re/game_logic.dll/DrawSpritev2")
        );
        assert_eq!(
            spawns.load(Ordering::SeqCst),
            1,
            "first click starts one retry"
        );

        let second = request_patch_spawning(
            &state,
            "game_logic.dll/DrawSprite/v1",
            "off-by-one in loop bound",
            counting_spawner(&spawns),
        )
        .await
        .expect("second patch request succeeds");

        // The response distinguishes the duplicate from a fresh start.
        assert_eq!(second.action, "patch_already_in_progress");
        assert_eq!(second.branch_name.as_deref(), first.branch_name.as_deref());

        // No second retry task was spawned.
        assert_eq!(
            spawns.load(Ordering::SeqCst),
            1,
            "second click must not start another retry"
        );

        // Exactly one next-attempt branch exists.
        let git = GitManager::open(dir.path()).expect("open git");
        let v2_branches: Vec<_> = git
            .list_translation_branches()
            .expect("list branches")
            .into_iter()
            .filter(|b| b.ends_with("v2"))
            .collect();
        assert_eq!(v2_branches, ["re/game_logic.dll/DrawSpritev2"]);

        // Exactly one patch record was written.
        let patch_dir = dir.path().join("re").join("patches").join("game_logic.dll");
        let record_count = std::fs::read_dir(patch_dir.join("DrawSprite"))
            .expect("patch dir")
            .count();
        assert_eq!(record_count, 1, "second click must not write a record");
    }

    #[tokio::test]
    async fn patch_after_previous_attempt_finished_starts_fresh() {
        let dir = make_repo_with_unit();
        // Issue #327: description-backed actions backend (see the double-click
        // test) — each fresh attempt assembles its own pass at request time.
        let target = target_dir_with("game_logic.dll");
        let state = ActionsState::new(dir.path().to_path_buf(), spec_with_dead_llm())
            .with_target_dir(target.path().to_path_buf());
        let spawns = Arc::new(AtomicUsize::new(0));

        request_patch_spawning(
            &state,
            "game_logic.dll/DrawSprite/v1",
            "off-by-one in loop bound",
            counting_spawner(&spawns),
        )
        .await
        .expect("first patch request succeeds");

        // The retry finishes: the success path rewrites the v2 patch record
        // without a `patch_request`, which puts v2 back in review.
        let v2_record = patch_record_path(dir.path(), 2);
        let mut record: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&v2_record).expect("v2 record"))
                .expect("v2 record json");
        record["patch_request"] = serde_json::Value::Null;
        std::fs::write(
            &v2_record,
            serde_json::to_string(&record).expect("serialize"),
        )
        .expect("write");

        // A patch request on the unit now in review (v2) starts a fresh attempt.
        let fresh = request_patch_spawning(
            &state,
            "game_logic.dll/DrawSprite/v2",
            "still wrong",
            counting_spawner(&spawns),
        )
        .await
        .expect("fresh patch request succeeds");
        assert_eq!(fresh.action, "patch_requested");
        assert_eq!(
            fresh.branch_name.as_deref(),
            Some("re/game_logic.dll/DrawSpritev3")
        );
        assert_eq!(
            spawns.load(Ordering::SeqCst),
            2,
            "fresh attempt starts a retry"
        );
    }

    /// Issue #86: a fast Accept-then-Send-Back double-click must not leave
    /// the persisted status silently disagreeing with git. Both actions
    /// capture the unit's state while the other is still in flight, and
    /// exactly one wins. The loser fails with a changed-underneath
    /// conflict, and the final persisted status matches the git outcome
    /// (merged ⇒ Accepted).
    #[tokio::test]
    async fn accept_and_send_back_race_exactly_one_wins() {
        let dir = make_repo_with_unit();
        let state = ActionsState::new(dir.path().to_path_buf(), spec_without_llm());

        // Hold the action lock while both actions start, so each captures the
        // persisted state ("nothing recorded yet") before either can proceed
        // — the double-click scenario from the issue. Releasing it lets the
        // first-spawned action (accept) win the lock; send-back's write-time
        // re-check must then catch that the unit changed underneath it.
        let guard = state.action_lock.lock().await;
        let accept_state = state.clone();
        let send_back_state = state.clone();
        let accept = tokio::spawn(async move {
            accept_unit(&accept_state, "game_logic.dll/DrawSprite/v1").await
        });
        let send_back = tokio::spawn(async move {
            send_back_unit(
                &send_back_state,
                "game_logic.dll/DrawSprite/v1",
                "changed my mind",
            )
            .await
        });
        tokio::task::yield_now().await; // both tasks capture and queue on the lock
        drop(guard);

        let accept = accept
            .await
            .expect("accept task")
            .expect("the first action (accept) wins the race");
        assert_eq!(accept.action, "accept");
        let send_back_err = send_back
            .await
            .expect("send-back task")
            .expect_err("the losing action must fail, not overwrite the record");
        let conflict = send_back_err
            .downcast_ref::<ActionConflictError>()
            .expect("send-back fails with an action conflict");
        assert!(
            matches!(conflict, ActionConflictError::ChangedUnderneath { .. }),
            "the loser's stale capture must surface as a changed-underneath conflict: {conflict}"
        );
        assert!(
            conflict.to_string().contains("accepted"),
            "conflict error names the landed state: {conflict}"
        );

        // Git outcome: the branch really is merged into main…
        let git = GitManager::open(dir.path()).expect("open git");
        assert!(
            git.is_branch_merged_into_main("re/game_logic.dll/DrawSpritev1")
                .expect("merged check"),
            "accept merged the branch to main"
        );
        // …and the persisted status matches it.
        let record = read_action_state(dir.path(), "game_logic.dll/DrawSprite/v1")
            .expect("action record exists");
        assert_eq!(record.action, ReviewStatus::Accepted);
    }

    /// Issue #86: send-back on an already-accepted unit is refused — the code
    /// is merged to main and there is no un-merge path.
    #[tokio::test]
    async fn send_back_on_accepted_unit_is_rejected() {
        let dir = make_repo_with_unit();
        let state = ActionsState::new(dir.path().to_path_buf(), spec_without_llm());

        accept_unit(&state, "game_logic.dll/DrawSprite/v1")
            .await
            .expect("accept succeeds");

        let err = send_back_unit(&state, "game_logic.dll/DrawSprite/v1", "too late")
            .await
            .expect_err("send-back on an accepted unit must be rejected");
        let conflict = err
            .downcast_ref::<ActionConflictError>()
            .expect("rejection is an action conflict");
        assert!(
            matches!(conflict, ActionConflictError::AlreadyAccepted { .. }),
            "rejection explains the unit is already accepted: {conflict}"
        );

        // The Accepted record survives untouched.
        let record = read_action_state(dir.path(), "game_logic.dll/DrawSprite/v1")
            .expect("action record exists");
        assert_eq!(record.action, ReviewStatus::Accepted);
    }

    /// Issue #86: patch on an already-accepted unit is refused too — no new
    /// attempt branch and no retry task.
    #[tokio::test]
    async fn patch_on_accepted_unit_is_rejected() {
        let dir = make_repo_with_unit();
        // No LLM in the description: the accepted-unit refusal must fire
        // before assembly (issue #327), so this state could never assemble a
        // pass anyway — reaching the conflict proves the refusal's order.
        let state = ActionsState::new(dir.path().to_path_buf(), spec_without_llm());
        let spawns = Arc::new(AtomicUsize::new(0));

        accept_unit(&state, "game_logic.dll/DrawSprite/v1")
            .await
            .expect("accept succeeds");

        let err = request_patch_spawning(
            &state,
            "game_logic.dll/DrawSprite/v1",
            "still wrong",
            counting_spawner(&spawns),
        )
        .await
        .expect_err("patch on an accepted unit must be rejected");
        let conflict = err
            .downcast_ref::<ActionConflictError>()
            .expect("rejection is an action conflict");
        assert!(
            matches!(conflict, ActionConflictError::AlreadyAccepted { .. }),
            "rejection explains the unit is already accepted: {conflict}"
        );
        assert_eq!(spawns.load(Ordering::SeqCst), 0, "no retry is started");

        let git = GitManager::open(dir.path()).expect("open git");
        let v2_branches: Vec<_> = git
            .list_translation_branches()
            .expect("list branches")
            .into_iter()
            .filter(|b| b.ends_with("v2"))
            .collect();
        assert!(v2_branches.is_empty(), "no next-attempt branch is created");
    }

    /// Issue #327 AC6: a server started with no LLM settings fails a patch
    /// request with the assembly seam's clear error — not a canned success,
    /// not a half-configured retry — and the failed request leaves nothing
    /// behind: no branch, no record, no retry task.
    #[tokio::test]
    async fn patch_without_llm_settings_fails_assembly_and_creates_nothing() {
        let dir = make_repo_with_unit();
        // The target dir is configured, so the failure is specifically the
        // missing LLM selection, not the missing target dir.
        let target = target_dir_with("game_logic.dll");
        let state = ActionsState::new(dir.path().to_path_buf(), spec_without_llm())
            .with_target_dir(target.path().to_path_buf());
        let spawns = Arc::new(AtomicUsize::new(0));

        let err = request_patch_spawning(
            &state,
            "game_logic.dll/DrawSprite/v1",
            "off-by-one in loop bound",
            counting_spawner(&spawns),
        )
        .await
        .expect_err("a server without LLM settings cannot assemble a patch retry");
        let msg = err.to_string();
        assert!(
            msg.contains("cannot assemble a pass without an LLM"),
            "the request surfaces the seam's assembly error: {msg}"
        );
        assert_eq!(spawns.load(Ordering::SeqCst), 0, "no retry task is started");

        let git = GitManager::open(dir.path()).expect("open git");
        let v2_branches: Vec<_> = git
            .list_translation_branches()
            .expect("list branches")
            .into_iter()
            .filter(|b| b.ends_with("v2"))
            .collect();
        assert!(
            v2_branches.is_empty(),
            "a failed assembly must not leave a next-attempt branch: {v2_branches:?}"
        );
        assert!(
            read_action_state(dir.path(), "game_logic.dll/DrawSprite/v1").is_none(),
            "a failed assembly must not persist an action record"
        );
        assert!(
            !dir.path().join("re").join("patches").exists(),
            "a failed assembly must not write a patch record"
        );
    }

    /// Issue #327: the request assembles before creating anything, so a
    /// server that cannot resolve the unit's binary refuses by name too —
    /// no branch, no record — even when the rest of the description is fine.
    #[tokio::test]
    async fn patch_without_target_dir_refuses_by_name() {
        let dir = make_repo_with_unit();
        let state = ActionsState::new(dir.path().to_path_buf(), spec_with_dead_llm());
        let spawns = Arc::new(AtomicUsize::new(0));

        let err = request_patch_spawning(
            &state,
            "game_logic.dll/DrawSprite/v1",
            "off-by-one in loop bound",
            counting_spawner(&spawns),
        )
        .await
        .expect_err("a server without a target dir cannot load the binary for a retry");
        let msg = err.to_string();
        assert!(
            msg.contains("no target directory is configured") && msg.contains("game_logic.dll"),
            "the refusal names the missing wiring and the binary: {msg}"
        );
        assert_eq!(spawns.load(Ordering::SeqCst), 0, "no retry task is started");

        let git = GitManager::open(dir.path()).expect("open git");
        let v2_branches: Vec<_> = git
            .list_translation_branches()
            .expect("list branches")
            .into_iter()
            .filter(|b| b.ends_with("v2"))
            .collect();
        assert!(
            v2_branches.is_empty(),
            "the refusal must not leave a next-attempt branch: {v2_branches:?}"
        );
    }

    /// Issue #327: the request adds only the run-scoped fields to the
    /// server's description — workspace, patch mode, the unit's binary under
    /// the target dir. Every settings value the fold composes (LLM
    /// selection, retry policy, call-graph flags, Kuna budget) reaches the
    /// spec the assembly consumes unchanged.
    #[test]
    fn patch_request_layers_only_run_scoped_fields_onto_the_description() {
        let dir = make_repo_with_unit();
        let target = target_dir_with("game_logic.dll");
        let mut spec = spec_with_dead_llm();
        spec.retry_max_attempts = Some(7);
        spec.no_callgraph = true;
        spec.refresh_cache = true;
        spec.callgraph_cache_dir = Some(dir.path().join("cg-cache"));
        let state = ActionsState::new(dir.path().to_path_buf(), spec.clone())
            .with_target_dir(target.path().to_path_buf());

        let layered = state
            .patch_pass_spec("game_logic.dll")
            .expect("the request layers its run-scoped fields");

        // Run-scoped fields the request owns:
        assert_eq!(layered.workspace, dir.path(), "the repo is the workspace");
        assert!(layered.patch_mode, "the pass is a patch-retry pass");
        let binary = layered.target_binary.expect("the unit's binary is named");
        assert_eq!(binary.name, "game_logic.dll");
        assert_eq!(binary.path, target.path().join("game_logic.dll"));

        // Everything the fold composed arrives unchanged:
        assert!(
            layered.llm.is_some(),
            "the description's LLM selection rides along"
        );
        assert_eq!(
            layered.retry_max_attempts,
            Some(7),
            "the description's retry policy drives the retry"
        );
        assert!(
            layered.no_callgraph && layered.refresh_cache,
            "the call-graph/cache flags ride along"
        );
        assert_eq!(
            layered.callgraph_cache_dir.as_deref(),
            Some(dir.path().join("cg-cache").as_path())
        );
        assert_eq!(
            layered.kuna_budget, spec.kuna_budget,
            "the configured Kuna budgets reach the engine load"
        );

        // The server's own description is untouched by the layering.
        assert!(
            !state.pass_spec.patch_mode,
            "layering clones, it does not mutate"
        );
        assert!(state.pass_spec.target_binary.is_none());
    }

    /// Issue #327 AC2/AC4: the description drives the retry that runs. Its
    /// LLM selection (endpoint and model) is what the translation actually
    /// calls — there is no environment fallback behind it. A capture server
    /// listens at the address the description's endpoint names; the retry
    /// reaches it, and the captured request includes the description's model
    /// name. The retry runs to completion: the description's assembled pass
    /// — LLM, analysis engine under its Kuna budgets, retry config,
    /// verifier — drives a successful translation end to end.
    #[tokio::test]
    async fn patch_retry_runs_the_pass_the_description_describes() {
        let repo = tempfile::tempdir().expect("repo dir");
        let git = GitManager::init_repo(repo.path(), None).expect("init git repo");
        git.create_branch("fixture_target.dll", "fixture_tick", 1, None)
            .expect("create v1 branch");
        let branch = GitBranch::new("fixture_target.dll", "fixture_tick", 1).expect("branch name");
        std::fs::create_dir_all(repo.path().join("src").join("modules")).expect("src dir");
        std::fs::write(
            repo.path()
                .join("src")
                .join("modules")
                .join("fixture_target.rs"),
            "pub fn fixture_tick(code: u32) -> u32 { code }\n",
        )
        .expect("write translation");
        git.commit(
            &branch,
            "Translate fixture_tick",
            &["src/modules/fixture_target.rs"],
        )
        .expect("commit translation");

        // Start a capture server, point the description's endpoint at it,
        // and give it a model name no default chain could ever produce.
        let base = fake_llm_server().await;
        let spec = PipelineSpec {
            llm: Some(LlmSelection::Description(LlmDescription {
                endpoint: format!("{base}/v1/chat/completions"),
                model: "description-owned-model".to_string(),
                api_key: None,
                context_window: Some(128_000),
                temperature: None,
                timeout_secs: Some(30),
            })),
            ..PipelineSpec::default()
        };

        let target = target_dir_with("fixture_target.dll");
        let state = ActionsState::new(repo.path().to_path_buf(), spec)
            .with_target_dir(target.path().to_path_buf());

        // Run the same two steps a patch request performs — set the
        // run-scoped fields, then assemble the pass — and drive the same
        // retry the spawned task would run, all visible here for the
        // completion assertions.
        let spec = state
            .patch_pass_spec("fixture_target.dll")
            .expect("the request layers its description");
        let pass = assemble_patch(&spec)
            .await
            .expect("the description assembles a complete pass");
        let outcome = tokio::time::timeout(
            std::time::Duration::from_secs(120),
            run_patch_retry(
                pass,
                repo.path(),
                "off-by-one in loop bound",
                "fixture_target.dll",
                "fixture_tick",
                2,
            ),
        )
        .await
        .expect("the description-driven retry finishes");
        outcome.expect("the retry succeeds on the description's pass");

        assert!(
            capture_hits() > 0,
            "the retry reached an LLM — with the environment read gone, the only one it can reach is the description's"
        );
        assert!(
            captured_bodies()
                .iter()
                .any(|body| body.contains("description-owned-model")),
            "the description's model drove the call"
        );
    }

    /// A capture LLM server on an ephemeral port; `CAPTURE_HITS`/`CAPTURED`
    /// record how many chat requests arrived and their bodies.
    static CAPTURE_HITS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    static CAPTURED: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());

    fn capture_hits() -> usize {
        CAPTURE_HITS.load(Ordering::SeqCst)
    }

    fn captured_bodies() -> Vec<String> {
        CAPTURED.lock().expect("capture lock").clone()
    }

    async fn fake_llm_server() -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("capture server binds");
        let addr = listener.local_addr().expect("capture address");
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    CAPTURE_HITS.fetch_add(1, Ordering::SeqCst);
                    let mut request: Vec<u8> = Vec::new();
                    let mut buf = [0u8; 8192];
                    loop {
                        match stream.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                request.extend_from_slice(&buf[..n]);
                                let Some(header_end) =
                                    request.windows(4).position(|w| w == b"\r\n\r\n")
                                else {
                                    continue;
                                };
                                let headers = String::from_utf8_lossy(&request[..header_end]);
                                let need = headers
                                    .lines()
                                    .find_map(|line| {
                                        let (name, value) = line.split_once(':')?;
                                        name.trim()
                                            .eq_ignore_ascii_case("content-length")
                                            .then(|| value.trim().to_string())
                                    })
                                    .and_then(|value| value.parse::<usize>().ok())
                                    .unwrap_or(0);
                                if request.len() >= header_end + 4 + need {
                                    break;
                                }
                            }
                        }
                    }
                    let body_str = String::from_utf8_lossy(&request).into_owned();
                    CAPTURED.lock().expect("capture lock").push(body_str);
                    let body = r#"{"choices":[{"message":{"role":"assistant","content":"fn fixture_tick(code: u32) -> u32 { code }"}}],"usage":{"completion_tokens":10,"prompt_tokens":20,"total_tokens":30}}"#;
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                });
            }
        });
        format!("http://{addr}")
    }

    /// Issue #86: the write-time re-check fails with an error naming the state
    /// that landed between the action's start and its record write.
    #[test]
    fn conflict_check_names_the_landed_state() {
        let dir = make_repo_with_unit();
        let record = ReviewActionRecord {
            unit_id: "game_logic.dll/DrawSprite/v1".to_string(),
            action: ReviewStatus::Accepted,
            comments: None,
            performed_at: Utc::now().to_rfc3339(),
            branch_name: Some("re/game_logic.dll/DrawSpritev1".to_string()),
        };
        persist_action_state(dir.path(), &record).expect("persist record");

        // The action started before the accept landed (captured: no record).
        let err = check_action_conflict(dir.path(), "game_logic.dll/DrawSprite/v1", None)
            .expect_err("a landed accept conflicts with a stale capture");
        assert!(
            matches!(err, ActionConflictError::ChangedUnderneath { .. }),
            "a stale capture surfaces as changed-underneath: {err}"
        );
        assert!(
            err.to_string().contains("accepted"),
            "conflict names the current state: {err}"
        );
    }
}
