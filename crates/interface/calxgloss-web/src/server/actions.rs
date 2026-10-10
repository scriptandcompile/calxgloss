//! Human review actions wired into Git and Translator operations.
//!
//! This module provides the backend machinery that turns a reviewer's
//! accept / send-back / patch action in the web UI into real Git
//! operations and (for patches) queued retry translations.
//!
//! # Actions
//!
//! | Action | Git operation | Translator operation |
//! |--------|--------------|---------------------|
//! | Accept | `accept_branch` — merge to main, write `re/accepts/` record | none |
//! | Send-back | `reject_branch` — write `re/rejections/` record | none (LLM is told via rejection file) |
//! | Patch | `next_attempt_branch` — create v{N+1} branch, write `re/patches/` record | enqueue retry translation for the new branch |
//!
//! Patch requests are idempotent while a retry is in flight: a second request
//! for a unit whose next attempt already has a patch request returns the
//! existing one instead of starting a second retry (issue #84).

use calxgloss_git::{GitManager, ShimDependencyMap};
use calxgloss_translator::{RetryConfig, TranslationPipeline};
use calxgloss_types::{GitBranch, ReviewStatus, TypesError};
use chrono::Utc;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use tracing::{info, warn};

// ============================================================
// State — shared across all handlers
// ============================================================

/// Shared state that the API handlers use to act on a unit of work.
#[derive(Clone)]
pub struct ActionsState {
    /// Path to the Git repository.
    repo_path: PathBuf,
}

impl ActionsState {
    pub fn new(repo_path: PathBuf) -> Self {
        Self { repo_path }
    }

    /// Returns the path to the repository.
    pub fn repo_path(&self) -> &Path {
        &self.repo_path
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
/// `unit_id` carries slashes (`{binary}/{function}/v{attempt}`), so the
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
// Action implementations
// ============================================================

/// Accept a unit of work: merge the branch to main and persist the action.
///
/// When the branch cannot merge cleanly, the merge conflicts are reported as
/// an error naming the conflicted files and no `Accepted` action state is
/// persisted — the unit keeps its pre-accept status (issue #83).
pub async fn accept_unit(
    state: &ActionsState,
    unit_id: &str,
) -> Result<ActionResult, anyhow::Error> {
    let unit = lookup_unit(state, unit_id)?;
    let branch = GitBranch::new(
        &unit.binary,
        unit.function.as_deref().unwrap_or(""),
        unit.attempt,
    )?;
    let git = GitManager::open(state.repo_path())?;

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
pub async fn send_back_unit(
    state: &ActionsState,
    unit_id: &str,
    reason: &str,
) -> Result<ActionResult, anyhow::Error> {
    let unit = lookup_unit(state, unit_id)?;
    let branch = GitBranch::new(
        &unit.binary,
        unit.function.as_deref().unwrap_or(""),
        unit.attempt,
    )?;
    let git = GitManager::open(state.repo_path())?;

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

/// Request a patch: create the next-attempt branch, persist action, and
/// kick off an async retry translation via the translator pipeline.
///
/// Idempotent while a retry is in flight (issue #84): if the unit's persisted
/// action record already records a patch request for the next attempt, the
/// existing request is returned (`action: "patch_already_in_progress"`) —
/// no second branch, record, or racing retry task is created.
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
    let unit = lookup_unit(state, unit_id)?;
    let git = GitManager::open(state.repo_path())?;

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

    // Kick off async retry translation in the background.
    // We can't hold git2 objects across await points (they're not Send),
    // so we pass only the data the closure needs and let it open its own GitManager.
    let repo_path = state.repo_path().to_path_buf();
    let issue_str = issue.to_string();
    let binary = unit.binary.clone();
    let function = unit.function.clone().unwrap_or_default();
    let attempt = next_branch.attempt;
    let branch_name = next_branch.name.clone();
    let branch_name_for_log = branch_name.clone();

    spawn_retry(Box::pin(async move {
        if let Err(e) = run_patch_retry(&repo_path, &issue_str, &binary, &function, attempt).await {
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
/// This runs the translation pipeline with retry logic.  On success it
/// commits the result to the next-attempt branch.
async fn run_patch_retry(
    repo_path: &Path,
    _issue: &str,
    binary: &str,
    function: &str,
    attempt: u32,
) -> Result<(), anyhow::Error> {
    // Build Ghidra client
    let ghidra = calxgloss_ghidra::GhidraClient::new(
        &std::env::var("GHIDRA_URL").unwrap_or_else(|_| "http://localhost:8080".to_string()),
    )
    .map_err(|e| anyhow::anyhow!("Ghidra client: {e}"))?;

    let llm_url =
        std::env::var("LLM_URL").unwrap_or_else(|_| "http://localhost:11434/v1".to_string());
    let llm_model = std::env::var("LLM_MODEL").unwrap_or_else(|_| "qwen3".to_string());

    let llm = calxgloss_llm::LlmClient::from_url(&llm_url, &llm_model)
        .map_err(|e| anyhow::anyhow!("LLM client: {e}"))?;

    // Build the hallucination detector from Ghidra symbols and PAL APIs
    // before creating the pipeline (which consumes the Ghidra client).
    let api_mappings = calxgloss_pal::ApiMappings::default();
    let detector = calxgloss_translator::build_hallucination_detector(&ghidra, &api_mappings).await;
    let pipeline = TranslationPipeline::new(ghidra, llm, api_mappings)
        .with_workspace(repo_path.to_path_buf())
        .with_hallucination_detector(detector);

    let verifier =
        calxgloss_verify::Verifier::new(repo_path).map_err(|e| anyhow::anyhow!("Verifier: {e}"))?;

    let config = RetryConfig::default();

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

    let result = pipeline
        .try_translate_with_retry(binary, function, &config, &verifier)
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
        // extension the binary carries (.binary, .exe, …).
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
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A repo with one review unit: branch `re/game_logic.dll/DrawSpritev1`.
    fn make_repo_with_unit() -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("temp dir");
        let git = GitManager::init_repo(dir.path(), None).expect("init git repo");
        git.create_branch("game_logic.dll", "DrawSprite", 1, None)
            .expect("create v1 branch");
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
        let state = ActionsState::new(dir.path().to_path_buf());
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
        let state = ActionsState::new(dir.path().to_path_buf());
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
        // without a `patch_request`, landing v2 back in review.
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
}
