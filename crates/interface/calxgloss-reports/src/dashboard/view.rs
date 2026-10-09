//! Dashboard view data types for the review dashboard.
//!
//! This module defines the data structures used for rendering the review
//! dashboard in the terminal, including view targets, unit views, and diff summaries.

use std::path::{Path, PathBuf};

use calxgloss_git::GitManager;
use calxgloss_types::BinaryIdentity;
use calxgloss_types::dashboard::UnitOfWork;

// ============================================================
// Unit view data types
// ============================================================

/// Parsed representation of a `dashboard view <target>` argument.
#[derive(Debug, Clone)]
pub struct ViewTarget {
    pub binary: BinaryIdentity,
    pub function: String,
    pub specific_attempt: Option<u32>,
}

/// Collected data for rendering a single unit view.
#[derive(Debug)]
pub struct UnitViewData {
    /// Parsed target identifier.
    pub target: ViewTarget,
    /// Unit of work info from the dashboard.
    pub unit: Option<UnitOfWork>,
    /// Git branch name that this unit lives on.
    pub branch_name: Option<String>,
    /// Whether the branch is merged into main.
    pub merged: bool,
    /// Diff summary: line changes between branch and main.
    pub diff_summary: Option<DiffSummary>,
    /// Patch/attempt history.
    pub attempt_history: Vec<AttemptInfo>,
    /// Baseline test results.
    pub baseline_tests_passed: Option<usize>,
    pub baseline_tests_total: Option<usize>,
    /// Classification data for the DLL.
    pub dll_category: Option<String>,
    pub dll_strategy: Option<String>,
}

/// Summary of a git diff between branch and main.
#[derive(Debug)]
pub struct DiffSummary {
    pub files_changed: usize,
    pub insertions: usize,
    pub deletions: usize,
}

/// Information about a single translation attempt.
#[derive(Debug)]
pub struct AttemptInfo {
    pub attempt: u32,
    pub strategy: String,
    pub compiled: bool,
    pub compilation_errors: Vec<String>,
    pub tests_passed: usize,
    pub tests_total: usize,
    pub failed_tests: Vec<String>,
    pub commit_hash: String,
    pub committed_at: String,
    pub is_latest: bool,
}

impl ViewTarget {
    /// Parse a target string like `game_logic.dll/DrawPrimitive/v3` or
    /// `game_logic.dll/DrawPrimitive`. Delegates to
    /// [`calxgloss_types::parse_branch_name`], the one owner of the
    /// branch-name grammar (issue #69); a target must name both a binary
    /// and a function.
    pub fn parse(s: &str) -> Option<Self> {
        let parts = calxgloss_types::parse_branch_name(s)?;
        Some(Self {
            binary: parts.binary,
            function: parts.function?,
            specific_attempt: parts.attempt,
        })
    }
}

impl UnitViewData {
    /// Load all data needed to render the unit view.
    pub fn load(
        git: &GitManager,
        target: &ViewTarget,
        repo_path: &Path,
    ) -> Result<Self, anyhow::Error> {
        // 1. Build dashboard to get the unit info and find the branch
        let builder = super::builder::DashboardBuilder::new(git);
        let dashboard = builder.build()?;

        // Find the unit matching our target
        let unit = dashboard
            .review_queue
            .iter()
            .chain(dashboard.recent_activity.iter())
            .find(|u| {
                u.binary == target.binary
                    && u.function.as_deref() == Some(&target.function)
                    && (target.specific_attempt.is_none()
                        || Some(u.attempt) == target.specific_attempt)
            })
            .cloned();

        // 2. Find the branch name
        let default_attempt = unit.as_ref().map(|u| u.attempt).unwrap_or(0);
        let branch_name = git.list_translation_branches()?.into_iter().find(|b| {
            b.starts_with("re/")
                && b.contains(target.binary.as_str())
                && b.contains(&target.function)
                && (target.specific_attempt.is_none()
                    || b.ends_with(&format!(
                        "v{}",
                        target.specific_attempt.unwrap_or(default_attempt)
                    )))
        });

        // 3. Check if the branch is merged
        let merged = if let Some(ref bname) = branch_name {
            Self::is_merged(git, bname)
        } else {
            false
        };

        // 4. Get diff summary
        let diff_summary = branch_name
            .as_deref()
            .and_then(|bname| Self::compute_diff(git, bname).ok())
            .or(Some(DiffSummary {
                files_changed: 0,
                insertions: 0,
                deletions: 0,
            }));

        // 5. Get patch records (attempt history)
        let patch_dir = repo_path
            .join("re")
            .join("patches")
            .join(&target.binary)
            .join(&target.function);
        let attempt_history =
            Self::load_attempt_history(&patch_dir, &target.function, &branch_name);

        // 6. Get baseline test data (baseline dirs carry the filename verbatim)
        let baseline_path = repo_path
            .join("re")
            .join("baseline")
            .join(&target.binary)
            .join(&target.function)
            .join("baseline.json");

        let (baseline_passed, baseline_total) = if baseline_path.exists() {
            let content = std::fs::read_to_string(&baseline_path).map_err(|e| {
                anyhow::anyhow!(
                    "Failed to read baseline from {}: {e}",
                    baseline_path.display()
                )
            })?;
            let tests: Vec<calxgloss_types::TestResult> =
                serde_json::from_str(&content).map_err(|e| {
                    anyhow::anyhow!(
                        "Failed to parse baseline from {}: {e}",
                        baseline_path.display()
                    )
                })?;
            let total = tests.len();
            let passed = tests.iter().filter(|t| t.passed).count();
            (Some(passed), Some(total))
        } else {
            (None, None)
        };

        // 7. Get DLL classification data
        let (dll_category, dll_strategy) = Self::load_classification(repo_path, &target.binary);

        Ok(Self {
            target: target.clone(),
            unit,
            branch_name,
            merged,
            diff_summary,
            attempt_history,
            baseline_tests_passed: baseline_passed,
            baseline_tests_total: baseline_total,
            dll_category,
            dll_strategy,
        })
    }

    /// Check if a branch is merged into main.
    fn is_merged(git: &GitManager, branch_name: &str) -> bool {
        git.is_branch_merged_into_main(branch_name).unwrap_or(false)
    }

    /// Compute diff summary between a branch and main.
    fn compute_diff(git: &GitManager, branch_name: &str) -> Result<DiffSummary, anyhow::Error> {
        use git2::{DiffFindOptions, DiffOptions};

        let main_ref = git
            .repo()
            .find_branch("main", git2::BranchType::Local)
            .ok()
            .and_then(|b| b.get().peel_to_commit().ok());

        let branch_ref = git
            .repo()
            .find_branch(branch_name, git2::BranchType::Local)
            .ok()
            .and_then(|b| b.get().peel_to_commit().ok());

        let (main_commit, branch_commit) = match (main_ref, branch_ref) {
            (Some(m), Some(b)) => (m, b),
            _ => return Err(anyhow::anyhow!("Could not resolve main or branch")),
        };

        let mut diff_opts = DiffOptions::new();
        let mut diff = git.repo().diff_tree_to_tree(
            Some(&main_commit.tree()?),
            Some(&branch_commit.tree()?),
            Some(&mut diff_opts),
        )?;

        let mut find_opts = DiffFindOptions::new();
        find_opts.renames(true);
        find_opts.rewrites(true);
        diff.find_similar(Some(&mut find_opts))?;

        let stats = diff.stats()?;
        Ok(DiffSummary {
            files_changed: stats.files_changed(),
            insertions: stats.insertions(),
            deletions: stats.deletions(),
        })
    }

    /// Load attempt history from patch records.
    fn load_attempt_history(
        patch_dir: &PathBuf,
        _function: &str,
        branch_name: &Option<String>,
    ) -> Vec<AttemptInfo> {
        if !patch_dir.exists() {
            return Vec::new();
        }

        let mut attempts = Vec::new();

        if let Ok(entries) = std::fs::read_dir(patch_dir) {
            for entry in entries.flatten() {
                let file_name = entry.file_name().to_string_lossy().to_string();
                if !file_name.ends_with(".json") {
                    continue;
                }

                let attempt = file_name
                    .strip_prefix('v')
                    .and_then(|s| s.trim_end_matches(".json").parse().ok())
                    .unwrap_or(0);

                let content = match std::fs::read_to_string(entry.path()) {
                    Ok(c) => c,
                    Err(_) => continue,
                };

                let record: calxgloss_git::PatchRecord = match serde_json::from_str(&content) {
                    Ok(r) => r,
                    Err(_) => continue,
                };

                let is_latest = branch_name
                    .as_deref()
                    .map(|b| {
                        let parts: Vec<&str> = b.split('v').collect();
                        if let Some(last) = parts.last() {
                            last.parse::<u32>().ok() == Some(attempt)
                        } else {
                            false
                        }
                    })
                    .unwrap_or(false);

                attempts.push(AttemptInfo {
                    attempt,
                    strategy: "unknown".to_string(),
                    compiled: !record.compilation_errors.is_empty(),
                    compilation_errors: record.compilation_errors,
                    tests_passed: 0,
                    tests_total: record.test_failures.len(),
                    failed_tests: record.test_failures,
                    commit_hash: record.commit_hash,
                    committed_at: record.committed_at,
                    is_latest,
                });
            }
        }

        attempts.sort_by_key(|a| a.attempt);
        attempts
    }

    /// Load DLL classification data. `binary` is the binary filename verbatim;
    /// the record file is `{binary}.json` (issue #68).
    fn load_classification(repo_path: &Path, binary: &str) -> (Option<String>, Option<String>) {
        let classify_dir = repo_path.join("re").join("classify");
        let file_name = format!("{}.json", binary);
        let path = classify_dir.join(&file_name);

        if !path.exists() {
            return (None, None);
        }

        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => return (None, None),
        };

        #[derive(serde::Deserialize)]
        struct ClassificationRecord {
            #[serde(rename = "category")]
            category: Option<String>,
            // `Strategy` serializes as an enum: unit variants as bare
            // strings, crate replacement as a tagged object. Reading it
            // as a plain string would fail the whole record parse.
            #[serde(rename = "strategy")]
            strategy: Option<serde_json::Value>,
        }

        let record: ClassificationRecord = match serde_json::from_str(&content) {
            Ok(r) => r,
            Err(_) => return (None, None),
        };
        let strategy = record.strategy.and_then(|s| match s {
            serde_json::Value::String(s) => Some(s),
            serde_json::Value::Object(obj) => obj.keys().next().cloned(),
            _ => None,
        });

        (record.category, strategy)
    }
}
