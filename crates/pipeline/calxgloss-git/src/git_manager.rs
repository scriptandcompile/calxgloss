//! GitManager — branch, commit, merge, and acceptance operations.
//!
//! This module provides the [`GitManager`] struct, the central orchestrator
//! for all Git operations performed during the translation pipeline.
//! Every translation attempt gets its own branch following the naming
//! convention `re/{binary}/{function}v{N}`.

use std::path::{Path, PathBuf};

use calxgloss_types::{BinaryIdentity, GitBranch, GitCommit, TypesError};
use chrono::Utc;
use git2::build::CheckoutBuilder;
use git2::{DiffOptions, Oid, Repository, ResetType};
use tracing::{debug, info, warn};

use super::helpers::{format_flags, make_signature};
use crate::BranchCreationPolicy;

/// Result of a branch creation attempt.
#[derive(Debug)]
pub struct BranchResult {
    pub branch: GitBranch,
    pub created: bool,
}

/// Result of a merge operation.
#[derive(Debug)]
pub enum MergeResult {
    /// The branch landed on main; `merge_hash` is the commit main now points at.
    Merged { merge_hash: String },
    /// Main already contains the branch's commits — nothing to do.
    AlreadyUpToDate,
    /// The branch cannot merge cleanly; `conflicted_files` names every file
    /// with a content conflict and main is left untouched.
    Conflicts {
        conflicted_files: Vec<String>,
        error: String,
    },
}

/// Collects the paths of every conflicted entry in a merge index, sorted and
/// deduplicated — libgit2 records one index entry per stage (ancestor, ours,
/// theirs) for the same path, so a single conflicting file appears up to
/// three times.
fn conflicted_paths(index: &git2::Index) -> Result<Vec<String>, TypesError> {
    let conflicts = index
        .conflicts()
        .map_err(|e| TypesError::InvalidBranchName(format!("Conflict scan failed: {}", e)))?;
    let mut paths: Vec<String> = conflicts
        .filter_map(|conflict| {
            let conflict = conflict.ok()?;
            // A path conflict always has at least one side; the ancestor
            // covers the both-deleted case.
            let entry = conflict
                .our
                .as_ref()
                .or(conflict.their.as_ref())
                .or(conflict.ancestor.as_ref())?;
            Some(String::from_utf8_lossy(&entry.path).into_owned())
        })
        .collect();
    paths.sort();
    paths.dedup();
    Ok(paths)
}

/// Stores failure details for a translation attempt.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct PatchRecord {
    pub binary: BinaryIdentity,
    pub function: String,
    pub attempt: u32,
    pub branch_name: String,
    pub committed_at: String,
    pub error_message: String,
    pub compilation_errors: Vec<String>,
    pub test_failures: Vec<String>,
    pub commit_hash: String,
    /// The reviewer's stated issue, set only on patch *request* records —
    /// written by the review UI's request-patch action to say what to fix.
    /// Pipeline failure records ([`GitManager::store_failure`]) and
    /// successful retry records leave this `None`, which is how the
    /// dashboard builder tells a requested patch (`PatchRequested`) from an
    /// attempt that merely failed (`PendingReview`).
    #[serde(default)]
    pub patch_request: Option<String>,
}

/// Manages all Git operations for the translation pipeline.
pub struct GitManager {
    repo: Repository,
    init_config: crate::InitConfig,
    repo_path: PathBuf,
}

impl GitManager {
    /// Initializes a new Git repository in the given directory.
    pub fn init_repo(
        repo_path: &Path,
        config: Option<crate::InitConfig>,
    ) -> Result<Self, TypesError> {
        let config = config.unwrap_or_default();

        info!("Initializing Git repository at {}", repo_path.display());
        std::fs::create_dir_all(repo_path).map_err(|e| {
            TypesError::InvalidBranchName(format!("Cannot create directory: {}", e))
        })?;

        let repo = Repository::init(repo_path)
            .map_err(|e| TypesError::InvalidBranchName(format!("Git init failed: {}", e)))?;

        let readme_path = repo_path.join("README.md");
        std::fs::write(
            &readme_path,
            "# Translation Target\n\nThis directory contains the reverse-engineered Rust translations.\n",
        )
        .map_err(|e| TypesError::InvalidBranchName(format!("Failed to write README: {}", e)))?;

        let mut index = repo
            .index()
            .map_err(|e| TypesError::InvalidBranchName(format!("Failed to get index: {}", e)))?;
        index
            .add_path(Path::new("README.md"))
            .map_err(|e| TypesError::InvalidBranchName(format!("Failed to add README: {}", e)))?;
        index
            .write()
            .map_err(|e| TypesError::InvalidBranchName(format!("Failed to write index: {}", e)))?;

        let sig = make_signature(&repo, &config)?;
        let tree_id = index
            .write_tree()
            .map_err(|e| TypesError::InvalidBranchName(format!("Failed to write tree: {}", e)))?;

        let tree = repo
            .find_tree(tree_id)
            .map_err(|e| TypesError::InvalidBranchName(format!("Failed to find tree: {}", e)))?;
        let main_oid = repo
            .commit(
                Some("refs/heads/main"),
                &sig,
                &sig,
                "Initial commit: setup translation target",
                &tree,
                &[],
            )
            .ok();
        drop(tree);

        // Set HEAD to point to main
        if let Some(oid) = main_oid {
            let _ = repo.set_head("refs/heads/main");
            let mut checkout_opts = CheckoutBuilder::new();
            checkout_opts.force();
            if let Ok(obj) = repo.find_object(oid, None)
                && let Ok(tree) = obj.peel_to_tree()
            {
                let _ = repo.reset(tree.as_object(), ResetType::Hard, Some(&mut checkout_opts));
            }
        }

        Ok(Self {
            repo,
            init_config: config,
            repo_path: repo_path.to_path_buf(),
        })
    }

    /// Opens an existing Git repository.
    pub fn open(repo_path: &Path) -> Result<Self, TypesError> {
        let repo = Repository::open(repo_path)
            .map_err(|e| TypesError::InvalidBranchName(format!("Not a Git repository: {}", e)))?;

        Ok(Self {
            repo,
            init_config: crate::InitConfig::default(),
            repo_path: repo_path.to_path_buf(),
        })
    }

    /// Returns the path to the Git repository.
    pub fn repo_path(&self) -> &Path {
        &self.repo_path
    }

    /// Returns the underlying [`Repository`] reference.
    pub fn repo(&self) -> &Repository {
        &self.repo
    }

    /// Returns the author configuration used for commits.
    pub fn config(&self) -> &crate::InitConfig {
        &self.init_config
    }

    /// Creates a new branch for a translation attempt.
    ///
    /// # Dependency Enforcement
    ///
    /// If `policy` is `Some`, the method checks that all required shim layers
    /// and PAL traits for the given `binary` are already merged into `main` before
    /// creating the branch. The policy controls the behavior when dependencies
    /// are unmet:
    ///
    /// - `Some(Policy::Skip)` — no checking (same as `None`, the default).
    /// - `Some(Policy::Warn)` — logs a warning but still creates the branch.
    /// - `Some(Policy::Enforce)` — returns an error if any dependency is unmet.
    ///
    /// # Arguments
    ///
    /// * `binary` — The DLL filename (e.g. `d3d9.dll`).
    /// * `function` — The function name being translated.
    /// * `attempt` — The attempt number (1-based).
    /// * `policy` — Optional dependency enforcement policy with classification data.
    ///
    /// # Example
    ///
    /// ```
    /// use std::path::Path;
    /// use calxgloss_git::{GitManager, BranchCreationPolicy, DependencyPolicy};
    /// use calxgloss_types::DllCategory;
    ///
    /// let git = GitManager::init_repo(Path::new("/tmp/test_repo"), None).unwrap();
    ///
    /// // Create with dependency enforcement
    /// let policy = BranchCreationPolicy::Warn(DependencyPolicy {
    ///     category: DllCategory::MicrosoftSdk,
    ///     crate_replacement: Some("wgpu".to_string()),
    /// });
    /// let result = git.create_branch("d3d9.dll", "Present", 1, Some(&policy));
    /// ```
    pub fn create_branch(
        &self,
        binary: &str,
        function: &str,
        attempt: u32,
        policy: Option<&BranchCreationPolicy>,
    ) -> Result<BranchResult, TypesError> {
        let branch = GitBranch::new(binary, function, attempt)?;
        let git_branch_name = format!("refs/heads/{}", branch.name);

        if self
            .repo
            .find_branch(&branch.name, git2::BranchType::Local)
            .is_ok()
        {
            info!("Branch '{}' already exists, reusing", branch.name);
            return Ok(BranchResult {
                branch,
                created: false,
            });
        }

        // ── Dependency check ──────────────────────────────────────

        if let Some(policy) = policy {
            let check_result = match policy {
                BranchCreationPolicy::Skip => crate::DependencyCheckResult::default(),
                BranchCreationPolicy::Warn(dp) | BranchCreationPolicy::Enforce(dp) => {
                    self.check_dependencies(binary, &dp.category, dp.crate_replacement.as_deref())
                }
            };

            match policy {
                BranchCreationPolicy::Skip => {}
                BranchCreationPolicy::Warn(_) => {
                    if check_result.has_unmet() {
                        warn!(
                            binary = %binary,
                            unmet = ?check_result.unmet,
                            "Dependencies unmet — continuing anyway (Warn policy)"
                        );
                    }
                }
                BranchCreationPolicy::Enforce(_) => {
                    if check_result.has_unmet() {
                        return Err(TypesError::InvalidBranchName(format!(
                            "Cannot create branch '{}': unmet dependencies: {}. \
                             Merge these branches into main first.",
                            branch.name,
                            check_result.unmet.join(", ")
                        )));
                    }
                }
            }
        }

        let main_ref = self
            .repo
            .find_branch("main", git2::BranchType::Local)
            .map_err(|_| TypesError::InvalidBranchName("main branch not found".to_string()))?;
        let main_commit = main_ref
            .get()
            .peel_to_commit()
            .map_err(|e| TypesError::InvalidBranchName(format!("Failed to resolve main: {}", e)))?;
        let main_oid = main_commit.id();

        debug!("Creating branch '{}' from commit {}", branch.name, main_oid);

        self.repo
            .reference(&git_branch_name, main_oid, false, &branch.name)
            .map_err(|e| TypesError::InvalidBranchName(format!("Branch creation failed: {}", e)))?;

        let mut checkout_opts = CheckoutBuilder::new();
        checkout_opts.force();

        self.repo
            .set_head(&git_branch_name)
            .map_err(|e| TypesError::InvalidBranchName(format!("Failed to set HEAD: {}", e)))?;

        let main_commit = main_ref
            .get()
            .peel_to_commit()
            .map_err(|e| TypesError::InvalidBranchName(format!("Failed to peel main: {}", e)))?;
        let main_obj = main_commit.as_object();

        self.repo
            .reset(main_obj, ResetType::Hard, Some(&mut checkout_opts))
            .map_err(|e| TypesError::InvalidBranchName(format!("Failed to reset: {}", e)))?;

        info!("Created branch '{}'", branch.name);
        Ok(BranchResult {
            branch,
            created: true,
        })
    }

    /// Commits files to the current branch.
    pub fn commit(
        &self,
        branch: &GitBranch,
        message: &str,
        files: &[&str],
    ) -> Result<GitCommit, TypesError> {
        let mut index = self
            .repo
            .index()
            .map_err(|e| TypesError::InvalidBranchName(format!("Failed to get index: {}", e)))?;

        let mut added_files = Vec::new();

        if files.is_empty() {
            let mut diff_options = DiffOptions::new();
            let diff = self
                .repo
                .diff_index_to_workdir(Some(&index), Some(&mut diff_options))
                .map_err(|e| TypesError::InvalidBranchName(format!("Diff failed: {}", e)))?;

            diff.deltas().for_each(|delta| {
                if let Some(path) = delta.new_file().path() {
                    let path_str = path.to_string_lossy().to_string();
                    if let Err(e) = index.add_path(Path::new(&path_str)) {
                        warn!("Failed to stage '{}': {}", path_str, e);
                    } else {
                        added_files.push(path_str);
                    }
                }
            });
        } else {
            for file_path in files {
                let path = Path::new(file_path);
                if let Err(e) = index.add_path(path) {
                    warn!("Failed to stage '{}': {}", file_path, e);
                } else {
                    added_files.push(file_path.to_string());
                }
            }
        }

        let tree_id = index
            .write_tree()
            .map_err(|e| TypesError::InvalidBranchName(format!("Failed to write tree: {}", e)))?;
        let tree = self
            .repo
            .find_tree(tree_id)
            .map_err(|e| TypesError::InvalidBranchName(format!("Failed to find tree: {}", e)))?;

        let head = self
            .repo
            .head()
            .map_err(|e| TypesError::InvalidBranchName(format!("Failed to get HEAD: {}", e)))?;
        let parent_oid = head.target().ok_or_else(|| {
            TypesError::InvalidBranchName("HEAD does not point to a commit".to_string())
        })?;
        let parent = self
            .repo
            .find_commit(parent_oid)
            .map_err(|e| TypesError::InvalidBranchName(format!("Failed to find parent: {}", e)))?;

        let sig = make_signature(&self.repo, &self.init_config)?;

        let commit_oid = self
            .repo
            .commit(
                Some(head.name().unwrap()),
                &sig,
                &sig,
                message,
                &tree,
                &[&parent],
            )
            .map_err(|e| TypesError::InvalidBranchName(format!("Commit creation failed: {}", e)))?;

        Ok(GitCommit {
            branch: branch.name.clone(),
            message: message.to_string(),
            hash: commit_oid.to_string(),
            files: added_files,
        })
    }

    /// Commits files directly to the `main` branch.
    ///
    /// This is used for metadata records (classification, patch notes, etc.)
    /// that do not belong on per-function translation branches.
    pub fn commit_to_main(&self, message: &str, files: &[String]) -> Result<GitCommit, TypesError> {
        let mut index = self
            .repo
            .index()
            .map_err(|e| TypesError::InvalidBranchName(format!("Failed to get index: {}", e)))?;

        let mut added_files = Vec::new();
        for file_path in files {
            let path = Path::new(file_path);
            if let Err(e) = index.add_path(path) {
                warn!("Failed to stage '{}': {}", file_path, e);
            } else {
                added_files.push(file_path.to_string());
            }
        }

        if added_files.is_empty() {
            return Err(TypesError::InvalidBranchName(
                "No files were staged".to_string(),
            ));
        }

        let tree_id = index
            .write_tree()
            .map_err(|e| TypesError::InvalidBranchName(format!("Failed to write tree: {}", e)))?;
        let tree = self
            .repo
            .find_tree(tree_id)
            .map_err(|e| TypesError::InvalidBranchName(format!("Failed to find tree: {}", e)))?;

        let main_ref = self
            .repo
            .find_branch("main", git2::BranchType::Local)
            .map_err(|_| TypesError::InvalidBranchName("'main' branch not found".to_string()))?;
        let main_commit = main_ref
            .get()
            .peel_to_commit()
            .map_err(|e| TypesError::InvalidBranchName(format!("Failed to resolve main: {}", e)))?;
        let _main_oid = main_commit.id();

        let sig = make_signature(&self.repo, &self.init_config)?;

        let commit_oid = self
            .repo
            .commit(
                Some("refs/heads/main"),
                &sig,
                &sig,
                message,
                &tree,
                &[&main_commit],
            )
            .map_err(|e| TypesError::InvalidBranchName(format!("Commit creation failed: {}", e)))?;

        Ok(GitCommit {
            branch: "main".to_string(),
            message: message.to_string(),
            hash: commit_oid.to_string(),
            files: added_files,
        })
    }

    /// Merges a branch into `main`.
    pub fn merge_to_main(&self, branch: &GitBranch) -> Result<MergeResult, TypesError> {
        info!("Merging branch '{}' into main", branch.name);

        let branch_ref = self
            .repo
            .find_branch(&branch.name, git2::BranchType::Local)
            .map_err(|_| {
                TypesError::InvalidBranchName(format!("Branch '{}' not found", branch.name))
            })?;
        let branch_commit = branch_ref.get().peel_to_commit().map_err(|e| {
            TypesError::InvalidBranchName(format!("Failed to resolve branch: {}", e))
        })?;
        let branch_oid = branch_commit.id();

        let main_ref = self
            .repo
            .find_branch("main", git2::BranchType::Local)
            .map_err(|_| TypesError::InvalidBranchName("'main' branch not found".to_string()))?;
        let main_commit = main_ref
            .get()
            .peel_to_commit()
            .map_err(|e| TypesError::InvalidBranchName(format!("Failed to resolve main: {}", e)))?;
        let main_oid = main_commit.id();

        // Check if branch is already up to date with main
        let (branch_ahead, _) = self.repo.graph_ahead_behind(branch_oid, main_oid).unwrap();
        let (main_ahead, main_behind) = self.repo.graph_ahead_behind(main_oid, branch_oid).unwrap();

        if main_oid == branch_oid || branch_ahead == 0 {
            info!("Branch '{}' is already up to date with main", branch.name);
            return Ok(MergeResult::AlreadyUpToDate);
        }

        // Check if branch is an ancestor of main (main already has branch's commits)
        if main_ahead == 0 && main_behind == 0 {
            info!("Branch '{}' is already an ancestor of main", branch.name);
            return Ok(MergeResult::AlreadyUpToDate);
        }

        // Check if we can fast-forward (branch is a direct descendant of main)
        if main_ahead == 0 && branch_ahead > 0 {
            debug!("Fast-forward merge {}", branch.name);
            debug!("Fast-forward merge {}", branch.name);
            self.repo
                .reference(
                    "refs/heads/main",
                    branch_oid,
                    true,
                    &format!("FF to {}", branch.name),
                )
                .map_err(|e| TypesError::InvalidBranchName(format!("FF failed: {}", e)))?;

            let mut checkout_opts = CheckoutBuilder::new();
            checkout_opts.force();
            // Get the updated main reference directly from the repo (main_ref is stale
            // after reference() updates the ref on disk)
            let main_commit = self
                .repo
                .find_reference("refs/heads/main")
                .map_err(|e| {
                    TypesError::InvalidBranchName(format!("Failed to find main after FF: {}", e))
                })?
                .peel_to_commit()
                .map_err(|e| TypesError::InvalidBranchName(format!("Peel main failed: {}", e)))?;
            let main_obj = main_commit.as_object();

            self.repo
                .set_head("refs/heads/main")
                .map_err(|e| TypesError::InvalidBranchName(format!("Set HEAD failed: {}", e)))?;
            self.repo
                .reset(main_obj, ResetType::Hard, Some(&mut checkout_opts))
                .map_err(|e| TypesError::InvalidBranchName(format!("Reset failed: {}", e)))?;

            return Ok(MergeResult::Merged {
                merge_hash: branch_oid.to_string(),
            });
        }

        debug!("3-way merge {} + {} → main", main_oid, branch_oid);

        let mut merge_index = self
            .repo
            .merge_commits(&main_commit, &branch_commit, None)
            .map_err(|e| TypesError::InvalidBranchName(format!("Merge failed: {}", e)))?;

        // Detect conflicts before committing: a conflicted merge index cannot
        // produce a tree, and letting the tree-write fail surfaces as an
        // opaque error while the reviewer believes the unit was accepted
        // (issue #83).
        if merge_index.has_conflicts() {
            let conflicted_files = conflicted_paths(&merge_index)?;
            warn!(
                "Merge of '{}' into main conflicts in: {}",
                branch.name,
                conflicted_files.join(", ")
            );
            return Ok(MergeResult::Conflicts {
                conflicted_files,
                error: format!("branch '{}' does not merge cleanly into main", branch.name),
            });
        }

        // The merge index from `merge_commits` is in-memory, so the tree must
        // be written against the repo explicitly — `write_tree()` on an
        // unbacked index always fails (issue #83).
        let merge_tree_id = merge_index.write_tree_to(&self.repo).map_err(|e| {
            TypesError::InvalidBranchName(format!("Write merge tree failed: {}", e))
        })?;
        let merge_tree = self
            .repo
            .find_tree(merge_tree_id)
            .map_err(|e| TypesError::InvalidBranchName(format!("Get merge tree failed: {}", e)))?;

        let sig = make_signature(&self.repo, &self.init_config)?;
        let merge_oid = self
            .repo
            .commit(
                Some("refs/heads/main"),
                &sig,
                &sig,
                &format!("Merge branch '{}' into main", branch.name),
                &merge_tree,
                &[&main_commit, &branch_commit],
            )
            .map_err(|e| TypesError::InvalidBranchName(format!("Merge commit failed: {}", e)))?;

        let mut checkout_opts = CheckoutBuilder::new();
        checkout_opts.force();
        // Use the merge commit we just created (main_ref is stale after commit())
        let main_commit = self
            .repo
            .find_reference("refs/heads/main")
            .map_err(|e| {
                TypesError::InvalidBranchName(format!("Failed to find main after merge: {}", e))
            })?
            .peel_to_commit()
            .map_err(|e| TypesError::InvalidBranchName(format!("Peel main failed: {}", e)))?;
        let main_obj = main_commit.as_object();

        self.repo
            .set_head("refs/heads/main")
            .map_err(|e| TypesError::InvalidBranchName(format!("Set HEAD failed: {}", e)))?;
        self.repo
            .reset(main_obj, ResetType::Hard, Some(&mut checkout_opts))
            .map_err(|e| TypesError::InvalidBranchName(format!("Reset failed: {}", e)))?;

        info!("Merged '{}' into main", branch.name);
        Ok(MergeResult::Merged {
            merge_hash: merge_oid.to_string(),
        })
    }

    /// Accepts a branch by merging it into `main` and records the acceptance.
    ///
    /// Returns the merge result and writes a timestamp to
    /// `re/accepts/{binary}/{function}/v{N}.json` for dashboard visibility.
    /// When the merge conflicts, the record's `merge_result` says
    /// `conflicts:{files}:{error}` instead of claiming a merge — callers must
    /// still refuse to mark the unit accepted (issue #83).
    pub fn accept_branch(&self, branch: &GitBranch) -> Result<MergeResult, TypesError> {
        info!("Accepting branch '{}'", branch.name);

        let result = self.merge_to_main(branch)?;

        // Record acceptance for dashboard visibility
        let accepts_dir = self
            .repo_path
            .join("re")
            .join("accepts")
            .join(&branch.binary)
            .join(&branch.function);
        std::fs::create_dir_all(&accepts_dir).map_err(|e| {
            TypesError::InvalidBranchName(format!("Failed to create accepts dir: {}", e))
        })?;

        let accept_file = accepts_dir.join(format!("v{}.json", branch.attempt));
        let accept_record = serde_json::json!({
            "branch": branch.name,
            "binary": branch.binary,
            "function": branch.function,
            "attempt": branch.attempt,
            "merged_at": Utc::now().to_rfc3339(),
            "merge_result": match &result {
                MergeResult::Merged { merge_hash } => format!("merged:{}", merge_hash),
                MergeResult::AlreadyUpToDate => "already_up_to_date".to_string(),
                MergeResult::Conflicts { conflicted_files, error } => {
                    format!("conflicts:{}:{}", conflicted_files.join(","), error)
                }
            },
        });
        std::fs::write(
            &accept_file,
            serde_json::to_string_pretty(&accept_record).map_err(TypesError::Serialization)?,
        )
        .map_err(|e| {
            TypesError::InvalidBranchName(format!("Failed to write accept record: {}", e))
        })?;

        info!(
            "Accepted branch '{}' — record written to {}",
            branch.name,
            accept_file.display()
        );
        Ok(result)
    }

    /// Rejects a branch and stores a rejection record.
    ///
    /// The rejection reason is saved to
    /// `re/rejections/{binary}/{function}/v{N}.json` so the dashboard can
    /// display send-back history.
    pub fn reject_branch(&self, branch: &GitBranch, reason: &str) -> Result<PathBuf, TypesError> {
        info!("Rejecting branch '{}' — reason: {}", branch.name, reason);

        let rejection_dir = self
            .repo_path
            .join("re")
            .join("rejections")
            .join(&branch.binary)
            .join(&branch.function);
        std::fs::create_dir_all(&rejection_dir).map_err(|e| {
            TypesError::InvalidBranchName(format!("Failed to create rejection dir: {}", e))
        })?;

        let rejection_path = rejection_dir.join(format!("v{}.json", branch.attempt));
        let rejection_record = serde_json::json!({
            "branch": branch.name,
            "binary": branch.binary,
            "function": branch.function,
            "attempt": branch.attempt,
            "reason": reason,
            "rejected_at": Utc::now().to_rfc3339(),
        });
        std::fs::write(
            &rejection_path,
            serde_json::to_string_pretty(&rejection_record).map_err(TypesError::Serialization)?,
        )
        .map_err(|e| {
            TypesError::InvalidBranchName(format!("Failed to write rejection record: {}", e))
        })?;

        info!(
            "Rejected branch '{}' — record written to {}",
            branch.name,
            rejection_path.display()
        );
        Ok(rejection_path)
    }

    /// Increments the attempt number for a unit of work and creates the
    /// next-attempt branch so the review UI can queue a retry translation.
    ///
    /// Returns the new `GitBranch` ready to be used for the retry attempt.
    pub fn next_attempt_branch(
        &self,
        binary: &str,
        function: &str,
        current_attempt: u32,
    ) -> Result<GitBranch, TypesError> {
        let next_attempt = current_attempt
            .checked_add(1)
            .ok_or_else(|| TypesError::InvalidBranchName("Attempt number overflow".to_string()))?;

        GitBranch::new(binary, function, next_attempt)
    }

    /// Stores failure details for a translation attempt.
    pub fn store_failure(
        &self,
        branch: &GitBranch,
        error_message: &str,
        compilation_errors: &[String],
        test_failures: &[String],
        commit_hash: &str,
    ) -> Result<PathBuf, TypesError> {
        let patch_dir = self
            .repo_path
            .join("re")
            .join("patches")
            .join(&branch.binary);
        let function_dir = patch_dir.join(&branch.function);
        std::fs::create_dir_all(&function_dir).map_err(|e| {
            TypesError::InvalidBranchName(format!("Failed to create patch dir: {}", e))
        })?;

        let patch_path = function_dir.join(format!("v{}.json", branch.attempt));
        let record = PatchRecord {
            binary: branch.binary.clone(),
            function: branch.function.clone(),
            attempt: branch.attempt,
            branch_name: branch.name.clone(),
            committed_at: Utc::now().to_rfc3339(),
            error_message: error_message.to_string(),
            compilation_errors: compilation_errors.to_vec(),
            test_failures: test_failures.to_vec(),
            commit_hash: commit_hash.to_string(),
            patch_request: None,
        };

        let json = serde_json::to_string_pretty(&record).map_err(TypesError::Serialization)?;
        std::fs::write(&patch_path, json)
            .map_err(|e| TypesError::InvalidBranchName(format!("Failed to write patch: {}", e)))?;

        info!("Stored failure record at {}", patch_path.display());
        Ok(patch_path)
    }

    /// Checks shim-layer dependencies for a DLL and returns a result
    /// describing which required branches are merged and which are not.
    ///
    /// This is a convenience wrapper around [`crate::DependencyChecker::resolve`]
    /// that uses the checker's default shim mapping.
    fn check_dependencies(
        &self,
        binary: &str,
        category: &calxgloss_types::DllCategory,
        crate_replacement: Option<&str>,
    ) -> crate::DependencyCheckResult {
        let checker = crate::DependencyChecker::default();
        checker.resolve(&self.repo, binary, category, crate_replacement)
    }

    /// Returns the name of the current branch.
    pub fn current_branch(&self) -> Result<String, TypesError> {
        let head = self
            .repo
            .head()
            .map_err(|e| TypesError::InvalidBranchName(format!("Failed to get HEAD: {}", e)))?;

        match head.shorthand() {
            Ok(name) => Ok(name.to_string()),
            Err(e) => {
                if e.message().contains("detached") {
                    Ok("(detached HEAD)".to_string())
                } else {
                    Err(TypesError::InvalidBranchName(format!(
                        "Branch name error: {}",
                        e
                    )))
                }
            }
        }
    }

    /// Lists all local branches.
    pub fn list_branches(&self) -> Result<Vec<String>, TypesError> {
        let mut branches = Vec::new();
        let iter = self.repo.branches(None).map_err(|e| {
            TypesError::InvalidBranchName(format!("Failed to get branch iterator: {}", e))
        })?;
        for branch_result in iter {
            let (branch, _type) = branch_result.map_err(|e| {
                TypesError::InvalidBranchName(format!("Failed to list branch: {}", e))
            })?;
            let name = branch
                .name()
                .map_err(|e| TypesError::InvalidBranchName(format!("Invalid branch name: {}", e)))?
                .unwrap_or("unknown")
                .to_string();
            branches.push(name);
        }
        branches.sort();
        Ok(branches)
    }

    /// Returns the commit hash of the current HEAD.
    pub fn current_commit(&self) -> Result<String, TypesError> {
        let head = self
            .repo
            .head()
            .map_err(|e| TypesError::InvalidBranchName(format!("Failed to get HEAD: {}", e)))?;
        Ok(head
            .target()
            .ok_or_else(|| {
                TypesError::InvalidBranchName("HEAD does not point to a commit".to_string())
            })?
            .to_string())
    }

    /// Returns the list of translation branches (branches under `re/`).
    pub fn list_translation_branches(&self) -> Result<Vec<String>, TypesError> {
        let all_branches = self.list_branches()?;
        Ok(all_branches
            .into_iter()
            .filter(|b| b.starts_with("re/"))
            .collect())
    }

    /// The UTC timestamp of a branch's tip commit.
    ///
    /// Dashboards use this to date a unit's work by when it was committed
    /// rather than when the dashboard was built.
    pub fn branch_commit_time(
        &self,
        branch_name: &str,
    ) -> Result<chrono::DateTime<Utc>, TypesError> {
        let commit = self
            .repo
            .find_branch(branch_name, git2::BranchType::Local)
            .ok()
            .and_then(|b| b.get().peel_to_commit().ok())
            .ok_or_else(|| {
                TypesError::InvalidBranchName(format!("No local branch '{branch_name}'"))
            })?;
        chrono::DateTime::from_timestamp(commit.time().seconds(), 0).ok_or_else(|| {
            TypesError::InvalidBranchName(format!("Invalid commit timestamp on '{branch_name}'"))
        })
    }

    /// Checks if a specific branch is an ancestor of `main`.
    pub fn is_branch_merged_into_main(&self, branch_name: &str) -> Result<bool, TypesError> {
        let main_ref = self
            .repo
            .find_branch("main", git2::BranchType::Local)
            .ok()
            .and_then(|b| b.get().peel_to_commit().ok());

        let branch_ref = self
            .repo
            .find_branch(branch_name, git2::BranchType::Local)
            .ok()
            .and_then(|b| b.get().peel_to_commit().ok());

        match (main_ref, branch_ref) {
            (Some(main_commit), Some(branch_commit)) => {
                let is_ancestor = self
                    .repo
                    .graph_ahead_behind(branch_commit.id(), main_commit.id())
                    .map(|(ahead, _)| ahead == 0)
                    .unwrap_or(false);
                Ok(is_ancestor)
            }
            _ => Ok(false),
        }
    }

    /// Deletes a branch.
    pub fn delete_branch(&self, branch_name: &str) -> Result<(), TypesError> {
        debug!("Deleting branch '{}'", branch_name);

        if branch_name == "main" {
            return Err(TypesError::InvalidBranchName(
                "Cannot delete 'main'".to_string(),
            ));
        }

        let mut branch = self
            .repo
            .find_branch(branch_name, git2::BranchType::Local)
            .map_err(|_| {
                TypesError::InvalidBranchName(format!("Branch '{}' not found", branch_name))
            })?;

        branch
            .delete()
            .map_err(|e| TypesError::InvalidBranchName(format!("Delete failed: {}", e)))?;

        info!("Deleted branch '{}'", branch_name);
        Ok(())
    }

    /// Archives a branch by renaming it to an `refs/archive/` reference.
    ///
    /// The branch is not deleted; instead it is renamed to
    /// `refs/archive/re/{binary}/{function}/v{N}` so it remains reachable for
    /// reference.  This is the archival half of the garbage-collection
    /// workflow — branches are archived rather than discarded.
    ///
    /// # Arguments
    ///
    /// * `branch_name` — The existing local branch name (e.g.
    ///   `re/game_logic.dll/DrawSpritev3`).
    /// * `archive_ref` — The full reference to rename to (e.g.
    ///   `refs/archive/re/game_logic.dll/DrawSpritev3`).
    pub fn archive_branch(&self, branch_name: &str, archive_ref: &str) -> Result<(), TypesError> {
        debug!("Archiving branch '{}' → '{}'", branch_name, archive_ref);

        if branch_name == "main" {
            return Err(TypesError::InvalidBranchName(
                "Cannot archive 'main'".to_string(),
            ));
        }

        // Find the current branch reference and get its target OID
        let branch = self
            .repo
            .find_branch(branch_name, git2::BranchType::Local)
            .map_err(|_| {
                TypesError::InvalidBranchName(format!("Branch '{}' not found", branch_name))
            })?;

        let target_oid = branch.get().target().ok_or_else(|| {
            TypesError::InvalidBranchName(format!(
                "Branch '{}' does not point to a commit",
                branch_name
            ))
        })?;

        // Delete the old local branch
        let mut local_branch = self
            .repo
            .find_branch(branch_name, git2::BranchType::Local)
            .map_err(|_| {
                TypesError::InvalidBranchName(format!("Branch '{}' not found", branch_name))
            })?;
        local_branch
            .delete()
            .map_err(|e| TypesError::InvalidBranchName(format!("Delete failed: {}", e)))?;

        // Create the archive reference pointing to the same commit
        self.repo
            .reference(
                archive_ref,
                target_oid,
                false,
                &format!("Archive of '{}'", branch_name),
            )
            .map_err(|e| {
                TypesError::InvalidBranchName(format!("Archive reference creation failed: {}", e))
            })?;

        info!("Archived branch '{}' → '{}'", branch_name, archive_ref);
        Ok(())
    }

    /// Creates a revert commit for the given commit hash.
    pub fn revert_commit(&self, commit_hash: &str) -> Result<String, TypesError> {
        let oid = Oid::from_str(commit_hash).map_err(|_| {
            TypesError::InvalidBranchName(format!("Invalid commit hash: {}", commit_hash))
        })?;

        let commit = self
            .repo
            .find_commit(oid)
            .map_err(|e| TypesError::InvalidBranchName(format!("Commit not found: {}", e)))?;

        let merge_opts = git2::MergeOptions::new();
        let mut revert_index = self
            .repo
            .revert_commit(&commit, &commit, 0, Some(&merge_opts))
            .map_err(|e| TypesError::InvalidBranchName(format!("Revert failed: {}", e)))?;

        let revert_tree_id = revert_index.write_tree().map_err(|e| {
            TypesError::InvalidBranchName(format!("Write revert tree failed: {}", e))
        })?;
        let revert_tree = self
            .repo
            .find_tree(revert_tree_id)
            .map_err(|e| TypesError::InvalidBranchName(format!("Get revert tree failed: {}", e)))?;

        let head = self
            .repo
            .head()
            .map_err(|e| TypesError::InvalidBranchName(format!("Get HEAD failed: {}", e)))?;

        let sig = make_signature(&self.repo, &self.init_config)?;
        let revert_oid = self
            .repo
            .commit(
                Some(head.name().unwrap()),
                &sig,
                &sig,
                &format!("Revert \"{}\"", commit.message().unwrap_or("unknown")),
                &revert_tree,
                &[&commit],
            )
            .map_err(|e| TypesError::InvalidBranchName(format!("Revert commit failed: {}", e)))?;

        info!("Created revert commit: {}", revert_oid);
        Ok(revert_oid.to_string())
    }

    /// Gets the status of the working directory.
    pub fn working_dir_status(&self) -> Result<Vec<(String, String)>, TypesError> {
        let mut statuses = Vec::new();
        let mut opts = git2::StatusOptions::new();
        opts.include_untracked(true);

        let status_list = self
            .repo
            .statuses(Some(&mut opts))
            .map_err(|e| TypesError::InvalidBranchName(format!("Get status failed: {}", e)))?;

        for entry in status_list.iter() {
            if let Ok(path) = entry.path() {
                let status_str = format_flags(entry.status());
                statuses.push((path.to_string(), status_str));
            }
        }

        Ok(statuses)
    }
}
