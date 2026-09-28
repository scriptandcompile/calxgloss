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

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use calxgloss_types::{DllCategory, GitBranch, GitCommit, TypesError};
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

/// Result of a dependency check before branch creation.
#[derive(Debug, Clone, Default)]
pub struct DependencyCheckResult {
    /// All required dependency branch names.
    pub required: Vec<String>,
    /// Dependencies that are already merged into main.
    pub satisfied: Vec<String>,
    /// Dependencies that are NOT yet merged (unblocked predecessors).
    pub unmet: Vec<String>,
}

impl DependencyCheckResult {
    /// Returns `true` if all dependencies are satisfied.
    pub fn is_complete(&self) -> bool {
        self.unmet.is_empty()
    }

    /// Returns `true` if there are unmet dependencies.
    pub fn has_unmet(&self) -> bool {
        !self.unmet.is_empty()
    }
}

/// Controls how branch creation handles dependency checking.
///
/// - `Skip` — no dependency checking (default, backwards-compatible).
/// - `Warn` — check dependencies but only log a warning if unmet. The branch
///   is still created.
/// - `Enforce` — block branch creation when dependencies are unmet. The caller
///   must resolve dependencies first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BranchCreationPolicy {
    /// No dependency checking.
    Skip,
    /// Check dependencies, warn on unmet, but allow branch creation.
    Warn(DependencyPolicy),
    /// Block branch creation when dependencies are unmet.
    Enforce(DependencyPolicy),
}

/// Dependency information passed to `create_branch` for enforcement.
///
/// Contains the DLL's classification and any crate-replacement info needed
/// to determine which shim layers and PAL traits are required before a
/// function translation can proceed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DependencyPolicy {
    /// The DLL's classification category.
    pub category: DllCategory,
    /// The recommended Rust crate name (for `CrateReplacement` DLLs).
    pub crate_replacement: Option<String>,
}

/// Encodes the mapping from DLL names to their required shim layer crates.
///
/// This is the canonical lookup used by [`DependencyChecker`] to determine
/// what shim branches must be merged before a function branch for a given DLL
/// can be safely created.
///
/// The mapping covers all Microsoft SDK and known third-party DLLs that have
/// Rust crate equivalents but need a shim layer for API compatibility.
///
/// # Examples
///
/// | DLL | Shim crate |
/// |-----|-----------|
/// | `d3d9.dll` | `wgpu` |
/// | `d3d11.dll` | `wgpu` |
/// | `fmod.dll` | `fmod-rs` |
/// | `openal32.dll` | `cpal` |
#[derive(Debug, Clone, Default)]
pub struct ShimDependencyMap(HashMap<String, String>);

impl ShimDependencyMap {
    /// Creates a new shim dependency map populated with all known mappings.
    pub fn new() -> Self {
        let mut map = HashMap::new();
        // DirectX → wgpu
        map.insert("d3d9.dll".to_string(), "wgpu".to_string());
        map.insert("d3d10.dll".to_string(), "wgpu".to_string());
        map.insert("d3d10_1.dll".to_string(), "wgpu".to_string());
        map.insert("d3d11.dll".to_string(), "wgpu".to_string());
        map.insert("d3d12.dll".to_string(), "wgpu".to_string());
        map.insert("dxgi.dll".to_string(), "wgpu".to_string());
        // Audio → cpal / fmod-rs
        map.insert("fmod.dll".to_string(), "fmod-rs".to_string());
        map.insert("fmodL.dll".to_string(), "fmod-rs".to_string());
        map.insert("openal32.dll".to_string(), "cpal".to_string());
        // 2D graphics → tiny-skia
        map.insert("d2d1.dll".to_string(), "tiny-skia".to_string());
        map.insert("dwrite.dll".to_string(), "skrifa".to_string());
        // UI frameworks
        map.insert("qt5_core.dll".to_string(), "iced".to_string());
        map.insert("qt5_gui.dll".to_string(), "iced".to_string());
        map.insert("qt5_widgets.dll".to_string(), "iced".to_string());
        // Math / geometry
        map.insert("gdi32.dll".to_string(), "tiny-skia".to_string());
        map.insert("gdiplus.dll".to_string(), "tiny-skia".to_string());
        Self(map)
    }

    /// Returns the shim crate name for a DLL, if known.
    pub fn get(&self, dll: &str) -> Option<&str> {
        self.0.get(dll).map(|s| s.as_str())
    }
}

/// Builds and validates dependency graphs for translation units of work.
///
/// Given a DLL name and classification, the checker determines which
/// shim layer and PAL trait branches must be merged into `main` before
/// a function translation branch can be safely created.
///
/// # Dependency Rules
///
/// | DLL Category | Required Dependencies |
/// |-------------|----------------------|
/// | `MicrosoftSdk` | Shim layer branch (e.g. `re/shim/wgpu`) |
/// | `KnownThirdParty` | Shim layer branch (e.g. `re/shim/fmod-rs`) |
/// | `WindowsOs` | No shim deps — PAL uses std lib directly |
/// | `ProjectSpecific` | No shim deps — pure RE target |
/// | `UnknownThirdParty` | No shim deps — treat as opaque |
///
/// # Example
///
/// ```
/// use calxgloss_git::DependencyChecker;
/// use calxgloss_types::DllCategory;
///
/// let checker = DependencyChecker::new();
/// let deps = checker.check("d3d9.dll", &DllCategory::MicrosoftSdk, Some("wgpu"));
/// assert_eq!(deps.required.len(), 1);
/// assert!(deps.required.iter().any(|s| s.contains("wgpu")));
/// ```
pub struct DependencyChecker {
    shim_map: ShimDependencyMap,
}

impl DependencyChecker {
    /// Creates a new dependency checker with the default shim mapping.
    pub fn new() -> Self {
        Self {
            shim_map: ShimDependencyMap::new(),
        }
    }

    /// Creates a new dependency checker with a custom shim mapping.
    pub fn with_shim_map(shim_map: ShimDependencyMap) -> Self {
        Self { shim_map }
    }

    /// Returns the expected shim branch name for a DLL.
    ///
    /// Returns `None` if the DLL has no known shim layer.
    pub fn shim_branch_name(&self, dll: &str) -> Option<String> {
        self.shim_map
            .get(dll)
            .map(|crate_name| format!("re/shim/{}", crate_name))
    }

    /// Checks all dependencies for a DLL's functions.
    ///
    /// Given the DLL name, category, and optional crate replacement, returns
    /// which dependencies must be merged before branch creation.
    ///
    /// For `MicrosoftSdk` and `KnownThirdParty` DLLs, this checks for a
    /// corresponding shim layer branch that has been merged into `main`.
    /// For all other categories, the required list is empty (no shim deps).
    ///
    /// # Arguments
    ///
    /// * `dll` — The DLL filename (e.g. `d3d9.dll`).
    /// * `category` — The DLL's classification category.
    /// * `crate_replacement` — The recommended Rust crate name, if any.
    pub fn check(
        &self,
        dll: &str,
        category: &DllCategory,
        crate_replacement: Option<&str>,
    ) -> DependencyCheckResult {
        let mut required = Vec::new();
        let satisfied = Vec::new();
        let mut unmet = Vec::new();

        // Only shim-layer categories require dependency checking
        match category {
            DllCategory::MicrosoftSdk | DllCategory::KnownThirdParty => {
                // Check the shim branch from the DLL-name lookup first
                if let Some(shim) = self.shim_branch_name(dll) {
                    required.push(shim.clone());
                    unmet.push(shim);
                } else if let Some(crate_name) = crate_replacement {
                    // Fallback: use the crate replacement name if no known mapping
                    let shim = format!("re/shim/{}", crate_name);
                    required.push(shim.clone());
                    unmet.push(shim);
                }
                // If both shim_branch_name and crate_replacement are available,
                // prefer the DLL-name lookup (it's more authoritative).
            }
            // WindowsOs, ProjectSpecific, UnknownThirdParty — no shim deps
            DllCategory::WindowsOs
            | DllCategory::ProjectSpecific
            | DllCategory::UnknownThirdParty => {}
        }

        DependencyCheckResult {
            required,
            satisfied,
            unmet,
        }
    }

    /// Resolves unmet dependencies by checking which ones are already merged.
    ///
    /// This is the full check-and-resolve loop: it populates `satisfied` and
    /// `unmet` by querying the repository to see which branches are already
    /// ancestors of `main`.
    ///
    /// # Arguments
    ///
    /// * `repo` — The Git repository to query.
    /// * `dll` — The DLL being translated.
    /// * `category` — The DLL's classification.
    /// * `crate_replacement` — Optional crate replacement name.
    pub fn resolve(
        &self,
        repo: &Repository,
        dll: &str,
        category: &DllCategory,
        crate_replacement: Option<&str>,
    ) -> DependencyCheckResult {
        let mut result = self.check(dll, category, crate_replacement);

        // Clear the placeholder unmet list and repopulate based on actual
        // merge status. The `check` method pre-fills `unmet` with the
        // required names; we replace them with accurate resolved values.
        result.unmet.clear();

        // Check each required dependency against main
        for dep in &result.required {
            if Self::is_branch_merged(repo, dep) {
                result.satisfied.push(dep.clone());
            } else {
                result.unmet.push(dep.clone());
            }
        }

        result
    }

    /// Checks whether a dependency branch is merged into `main`.
    fn is_branch_merged(repo: &Repository, branch_name: &str) -> bool {
        let main_ref = repo
            .find_branch("main", git2::BranchType::Local)
            .ok()
            .and_then(|b| b.get().peel_to_commit().ok());

        let branch_ref = repo
            .find_branch(branch_name, git2::BranchType::Local)
            .ok()
            .and_then(|b| b.get().peel_to_commit().ok());

        match (main_ref, branch_ref) {
            (Some(main_commit), Some(branch_commit)) => repo
                .graph_ahead_behind(branch_commit.id(), main_commit.id())
                .map(|(ahead, _)| ahead == 0)
                .unwrap_or(false),
            _ => false,
        }
    }
}

impl Default for DependencyChecker {
    fn default() -> Self {
        Self::new()
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
    ///
    /// # Dependency Enforcement
    ///
    /// If `policy` is `Some`, the method checks that all required shim layers
    /// and PAL traits for the given `dll` are already merged into `main` before
    /// creating the branch. The policy controls the behavior when dependencies
    /// are unmet:
    ///
    /// - `Some(Policy::Skip)` — no checking (same as `None`, the default).
    /// - `Some(Policy::Warn)` — logs a warning but still creates the branch.
    /// - `Some(Policy::Enforce)` — returns an error if any dependency is unmet.
    ///
    /// # Arguments
    ///
    /// * `dll` — The DLL filename (e.g. `d3d9.dll`).
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
        dll: &str,
        function: &str,
        attempt: u32,
        policy: Option<&BranchCreationPolicy>,
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

        // ── Dependency check ──────────────────────────────────────

        if let Some(policy) = policy {
            let check_result = match policy {
                BranchCreationPolicy::Skip => DependencyCheckResult::default(),
                BranchCreationPolicy::Warn(dp) | BranchCreationPolicy::Enforce(dp) => {
                    self.check_dependencies(dll, &dp.category, dp.crate_replacement.as_deref())
                }
            };

            match policy {
                BranchCreationPolicy::Skip => {}
                BranchCreationPolicy::Warn(_) => {
                    if check_result.has_unmet() {
                        warn!(
                            dll = %dll,
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

    /// Accepts a branch by merging it into `main` and records the acceptance.
    ///
    /// Returns the merge result and writes a timestamp to
    /// `re/accepts/{dll}/{function}/v{N}.json` for dashboard visibility.
    pub fn accept_branch(&self, branch: &GitBranch) -> Result<MergeResult, TypesError> {
        info!("Accepting branch '{}'", branch.name);

        let result = self.merge_to_main(branch)?;

        // Record acceptance for dashboard visibility
        let accepts_dir = self
            .repo_path
            .join("re")
            .join("accepts")
            .join(&branch.dll)
            .join(&branch.function);
        std::fs::create_dir_all(&accepts_dir).map_err(|e| {
            TypesError::InvalidBranchName(format!("Failed to create accepts dir: {}", e))
        })?;

        let accept_file = accepts_dir.join(format!("v{}.json", branch.attempt));
        let accept_record = serde_json::json!({
            "branch": branch.name,
            "dll": branch.dll,
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
            serde_json::to_string_pretty(&accept_record)
                .map_err(|e| TypesError::Serialization(e))?,
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
    /// `re/rejections/{dll}/{function}/v{N}.json` so the dashboard can
    /// display send-back history.
    pub fn reject_branch(&self, branch: &GitBranch, reason: &str) -> Result<PathBuf, TypesError> {
        info!("Rejecting branch '{}' — reason: {}", branch.name, reason);

        let rejection_dir = self
            .repo_path
            .join("re")
            .join("rejections")
            .join(&branch.dll)
            .join(&branch.function);
        std::fs::create_dir_all(&rejection_dir).map_err(|e| {
            TypesError::InvalidBranchName(format!("Failed to create rejection dir: {}", e))
        })?;

        let rejection_path = rejection_dir.join(format!("v{}.json", branch.attempt));
        let rejection_record = serde_json::json!({
            "branch": branch.name,
            "dll": branch.dll,
            "function": branch.function,
            "attempt": branch.attempt,
            "reason": reason,
            "rejected_at": Utc::now().to_rfc3339(),
        });
        std::fs::write(
            &rejection_path,
            serde_json::to_string_pretty(&rejection_record)
                .map_err(|e| TypesError::Serialization(e))?,
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

    /// Checks shim-layer dependencies for a DLL and returns a result
    /// describing which required branches are merged and which are not.
    ///
    /// This is a convenience wrapper around [`DependencyChecker::resolve`]
    /// that uses the checker's default shim mapping.
    ///
    /// # Arguments
    ///
    /// * `dll` — The DLL filename (e.g. `d3d9.dll`).
    /// * `category` — The DLL's classification category.
    /// * `crate_replacement` — Optional crate replacement name.
    fn check_dependencies(
        &self,
        dll: &str,
        category: &DllCategory,
        crate_replacement: Option<&str>,
    ) -> DependencyCheckResult {
        let checker = DependencyChecker::default();
        checker.resolve(&self.repo, dll, category, crate_replacement)
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
