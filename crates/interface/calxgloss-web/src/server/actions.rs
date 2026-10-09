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

use calxgloss_git::{GitManager, ShimDependencyMap};
use calxgloss_translator::{RetryConfig, TranslationPipeline};
use calxgloss_types::{GitBranch, ReviewStatus, TypesError};
use chrono::Utc;
use std::path::{Path, PathBuf};
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

/// Writes a review action record to disk so the dashboard stays in sync.
fn persist_action_state(
    repo_path: &Path,
    record: &ReviewActionRecord,
) -> Result<PathBuf, TypesError> {
    let actions_dir = repo_path.join("re").join("actions");
    std::fs::create_dir_all(&actions_dir)
        .map_err(|e| TypesError::InvalidBranchName(format!("Failed to create actions dir: {e}")))?;

    let action_file = actions_dir.join(format!("{}.json", record.unit_id));
    // unit_id carries slashes (`{binary}/{function}/v{attempt}`), so the joined
    // path nests under actions_dir — create those parents before writing.
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

// ============================================================
// Action implementations
// ============================================================

/// Accept a unit of work: merge the branch to main and persist the action.
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
        calxgloss_git::MergeResult::Conflicts { .. } => None,
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
pub async fn request_patch(
    state: &ActionsState,
    unit_id: &str,
    issue: &str,
) -> Result<ActionResult, anyhow::Error> {
    let unit = lookup_unit(state, unit_id)?;
    let git = GitManager::open(state.repo_path())?;

    // Create the next-attempt branch
    let next_branch = git.next_attempt_branch(
        &unit.binary,
        unit.function.as_deref().unwrap_or(""),
        unit.attempt,
    )?;

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

    tokio::task::spawn(async move {
        if let Err(e) = run_patch_retry(&repo_path, &issue_str, &binary, &function, attempt).await {
            warn!("Patch retry failed for {branch_name_for_log}: {e}");
        }
    });

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
