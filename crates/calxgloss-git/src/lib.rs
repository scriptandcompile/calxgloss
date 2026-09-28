//! Git branch, commit, and merge automation for translation units of work.
//!
//! This crate provides [`GitManager`], the central orchestrator for all Git operations
//! performed during the translation pipeline. Every translation attempt gets its own
//! branch following the naming convention `re/{dll}/{function}v{N}`.
//!
//! # Branching Strategy
//!
//! - **Success**: Branch created → files committed → merged to `main`
//! - **Failure**: Branch created → files committed → branch retained (never deleted)
//! - **Retries**: New attempt gets a new branch with incremented version number
//!
//! # Commit Message Convention
//!
//! Every commit follows a structured format for traceability:
//!
//! ```text
//! re/translation/<function>: translate <function> to Rust
//!
//! Attempt: <N> of <total-attempts> (or "last" if not known)
//! Dependencies: <list of merged branches this depends on>
//! Tests: <count> baseline tests, <count> verification tests
//! Passing: <yes/no>
//! LLM model: <model name>
//! Context size: <N> tokens
//! ```

use std::path::{Path, PathBuf};

use calxgloss_types::{GitBranch, GitCommit, TypesError};
use chrono::Utc;
use git2::build::CheckoutBuilder;
use git2::{DiffOptions, Oid, Repository, ResetType, Signature};
use tracing::{debug, info, warn};

/// Configuration for Git repository initialization.
#[derive(Debug, Clone)]
pub struct InitConfig {
    pub author_name: String,
    pub author_email: String,
    pub committer_name: Option<String>,
    pub committer_email: Option<String>,
}

impl Default for InitConfig {
    fn default() -> Self {
        Self {
            author_name: "Calxgloss".to_string(),
            author_email: "calxgloss@system".to_string(),
            committer_name: None,
            committer_email: None,
        }
    }
}

/// Manages all Git operations for the translation pipeline.
pub struct GitManager {
    repo: Repository,
    init_config: InitConfig,
    repo_path: PathBuf,
}

/// Result of a branch creation attempt.
#[derive(Debug)]
pub struct BranchResult {
    pub branch: GitBranch,
    pub created: bool,
}

/// Result of a merge operation.
#[derive(Debug)]
pub enum MergeResult {
    Merged {
        merge_hash: String,
    },
    AlreadyUpToDate,
    Conflicts {
        conflicted_files: Vec<String>,
        error: String,
    },
}

/// Stores failure details for a translation attempt.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct PatchRecord {
    pub dll: String,
    pub function: String,
    pub attempt: u32,
    pub branch_name: String,
    pub committed_at: String,
    pub error_message: String,
    pub compilation_errors: Vec<String>,
    pub test_failures: Vec<String>,
    pub commit_hash: String,
}

fn make_signature(
    repo: &Repository,
    config: &InitConfig,
) -> Result<Signature<'static>, TypesError> {
    repo.signature()
        .or_else(|_| Signature::now(&config.author_name, &config.author_email))
        .map_err(|e| TypesError::InvalidBranchName(format!("Failed to create signature: {}", e)))
}

impl GitManager {
    /// Initializes a new Git repository in the given directory.
    pub fn init_repo(repo_path: &Path, config: Option<InitConfig>) -> Result<Self, TypesError> {
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
            init_config: InitConfig::default(),
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
    pub fn config(&self) -> &InitConfig {
        &self.init_config
    }

    /// Creates a new branch for a translation attempt.
    pub fn create_branch(
        &self,
        dll: &str,
        function: &str,
        attempt: u32,
    ) -> Result<BranchResult, TypesError> {
        let branch = GitBranch::new(dll, function, attempt)?;
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
            let main_commit = main_ref
                .get()
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

        let merge_tree_id = merge_index.write_tree().map_err(|e| {
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
        let main_commit = main_ref
            .get()
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

    /// Stores failure details for a translation attempt.
    pub fn store_failure(
        &self,
        branch: &GitBranch,
        error_message: &str,
        compilation_errors: &[String],
        test_failures: &[String],
        commit_hash: &str,
    ) -> Result<PathBuf, TypesError> {
        let patch_dir = self.repo_path.join("re").join("patches").join(&branch.dll);
        let function_dir = patch_dir.join(&branch.function);
        std::fs::create_dir_all(&function_dir).map_err(|e| {
            TypesError::InvalidBranchName(format!("Failed to create patch dir: {}", e))
        })?;

        let patch_path = function_dir.join(format!("v{}.json", branch.attempt));
        let record = PatchRecord {
            dll: branch.dll.clone(),
            function: branch.function.clone(),
            attempt: branch.attempt,
            branch_name: branch.name.clone(),
            committed_at: Utc::now().to_rfc3339(),
            error_message: error_message.to_string(),
            compilation_errors: compilation_errors.to_vec(),
            test_failures: test_failures.to_vec(),
            commit_hash: commit_hash.to_string(),
        };

        let json = serde_json::to_string_pretty(&record).map_err(TypesError::Serialization)?;
        std::fs::write(&patch_path, json)
            .map_err(|e| TypesError::InvalidBranchName(format!("Failed to write patch: {}", e)))?;

        info!("Stored failure record at {}", patch_path.display());
        Ok(patch_path)
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

fn format_flags(status: git2::Status) -> String {
    let mut flags = Vec::new();
    if status.is_index_new() {
        flags.push("added");
    }
    if status.is_index_modified() {
        flags.push("modified in index");
    }
    if status.is_index_deleted() {
        flags.push("deleted in index");
    }
    if status.is_wt_new() {
        flags.push("untracked");
    }
    if status.is_wt_modified() {
        flags.push("modified in working dir");
    }
    if status.is_wt_deleted() {
        flags.push("deleted in working dir");
    }
    if status.is_wt_renamed() {
        flags.push("renamed");
    }
    if status.is_conflicted() {
        flags.push("conflicted");
    }
    if flags.is_empty() {
        "unmodified".to_string()
    } else {
        flags.join(", ")
    }
}

#[cfg(test)]
mod tests;
