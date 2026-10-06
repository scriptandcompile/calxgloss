//! Dashboard builder — assembles [`ReviewDashboard`] from git + file artifacts.
//!
//! This module contains the [`DashboardBuilder`] which walks a Git repository's
//! branches, patch records, and baseline files to construct a complete review
//! dashboard.

use std::collections::HashMap;
use std::path::PathBuf;

use calxgloss_git::GitManager;
use calxgloss_types::dashboard::{
    ReviewDashboard, ReviewStatus, Staleness, UnitOfWork, WorkKind,
};
use chrono::Utc;

/// Parses a git branch name like `re/game_logic/DrawSpritev1` or
/// `re/classify/game_logic.dllv1` into its components.
pub fn parse_branch_name(name: &str) -> Option<BranchParts> {
    let rest = name.strip_prefix("re/")?;

    let (rest, attempt) = if let Some(vpos) = rest.rfind('v') {
        let after_v = &rest[vpos + 1..];
        if after_v.chars().all(|c| c.is_ascii_digit()) && !after_v.is_empty() {
            let attempt: u32 = after_v.parse().ok()?;
            (&rest[..vpos], attempt)
        } else {
            (rest, 1)
        }
    } else {
        (rest, 1)
    };

    let parts: Vec<&str> = rest.splitn(2, '/').collect();
    let kind = parts[0];

    let (dll, function) = if parts.len() > 1 {
        (parts[0].to_string(), Some(parts[1].to_string()))
    } else {
        (parts[0].to_string(), None)
    };

    let kind = match kind {
        "classify" => WorkKind::DllClassification,
        "shim" => WorkKind::ShimLayer,
        "pal" => WorkKind::PalTrait,
        "test" => WorkKind::TestCaseAddition,
        "integration" => WorkKind::IntegrationStep,
        "fix" => WorkKind::BugFix,
        _ => WorkKind::FunctionTranslation,
    };

    Some(BranchParts {
        kind,
        dll,
        function,
        attempt,
    })
}

/// Returns true if a git branch name matches the given DLL, function,
/// and optional attempt number.
pub fn branch_matches(branch: &str, dll: &str, function: &str, attempt: Option<u32>) -> bool {
    let Some(parts) = parse_branch_name(branch) else {
        return false;
    };

    let branch_dll = parts.dll.strip_suffix(".dll").unwrap_or(&parts.dll);
    let branch_func = parts.function.as_deref().unwrap_or("");

    if branch_dll != dll || branch_func != function {
        return false;
    }

    if let Some(req) = attempt {
        req == parts.attempt
    } else {
        true
    }
}

#[derive(Debug)]
pub struct BranchParts {
    kind: WorkKind,
    dll: String,
    function: Option<String>,
    attempt: u32,
}

/// Holds parsed data from a single patch record.
#[derive(Debug, Default)]
#[allow(dead_code)]
struct PatchData {
    llm_model: Option<String>,
    baseline_tests_passed: Option<usize>,
    baseline_tests_total: Option<usize>,
    verification_tests_passed: Option<usize>,
    verification_tests_total: Option<usize>,
    confidence: Option<f32>,
    context_tier: Option<usize>,
}

/// Assembles a [`ReviewDashboard`] from the state of a Git repository.
pub struct DashboardBuilder<'a> {
    git: &'a GitManager,
    repo_path: PathBuf,
}

impl<'a> DashboardBuilder<'a> {
    /// Creates a new builder for the given git repository.
    pub fn new(git: &'a GitManager) -> Self {
        Self {
            git,
            repo_path: git.repo_path().to_path_buf(),
        }
    }

    /// Builds the full dashboard, returning a [`ReviewDashboard`].
    pub fn build(&self) -> Result<ReviewDashboard, anyhow::Error> {
        let mut units_by_key: HashMap<String, Vec<UnitOfWork>> = HashMap::new();

        // 1. Discover translation branches
        let branches = self.git.list_translation_branches()?;
        let mut seen_keys: HashMap<String, u32> = HashMap::new();

        for branch in &branches {
            let parts = match parse_branch_name(branch) {
                Some(p) => p,
                None => continue,
            };

            let key = unit_key(&parts);
            let existing_attempt = seen_keys.entry(key.clone()).or_insert(0);

            if parts.attempt > *existing_attempt {
                *existing_attempt = parts.attempt;
            }

            let _ = parts;
        }

        // 2. Scan patch records for per-attempt data
        let patch_records = self.read_all_patch_records()?;

        // 3. Read baseline data
        let baselines = self.read_all_baselines()?;

        // 4. Determine the *latest* attempt for each key and build units
        for (key, latest_attempt) in &seen_keys {
            let mut unit = self.build_unit(&branches, key, *latest_attempt, &patch_records);

            let baseline_key = key.rsplit_once('/').map_or(key.as_str(), |(base, _)| base);
            if let Some(baseline) = baselines.get(baseline_key) {
                unit.baseline_tests_total = Some(baseline.test_count);
                unit.baseline_tests_passed = Some(baseline.pass_count);
            }

            let has_patch = patch_records
                .iter()
                .any(|pr| pr.key == *key && pr.attempt <= *latest_attempt);

            let merged = self.is_branch_merged(key);

            unit.status = if merged {
                ReviewStatus::Accepted
            } else if has_patch {
                ReviewStatus::PendingReview
            } else {
                ReviewStatus::Queued
            };

            units_by_key.entry(unit.id.clone()).or_default().push(unit);
        }

        // 5. Also check for classified DLLs not covered by translation branches
        let classified = self.read_classification_records();
        for cls in classified {
            let key = format!("classify/{}", cls.dll);
            if !seen_keys.contains_key(&key) {
                let unit = UnitOfWork {
                    id: key.clone(),
                    name: format!("Classify {}", cls.dll),
                    kind: WorkKind::DllClassification,
                    dll: cls.dll.clone(),
                    function: None,
                    attempt: 1,
                    status: ReviewStatus::Accepted,
                    accepted: true,
                    confidence: Some(0.95),
                    baseline_tests_passed: None,
                    baseline_tests_total: None,
                    verification_tests_passed: None,
                    verification_tests_total: None,
                    llm_model: Some("classificator".to_string()),
                    context_tier: Some(0),
                    dependencies: vec![],
                    created_at: Utc::now(),
                    updated_at: Utc::now(),
                    known_gaps: vec![],
                    stale: Staleness::Fresh,
                };
                units_by_key.entry(key).or_default().push(unit);
            }
        }

        // 6. Flatten and de-duplicate units
        let mut units: Vec<UnitOfWork> = units_by_key
            .into_values()
            .map(|mut v| {
                v.sort_by_key(|u| u.attempt);
                v.pop().unwrap()
            })
            .collect();

        // Add dependency edges
        let class_keys: Vec<String> = units
            .iter()
            .filter(|u| u.kind == WorkKind::DllClassification)
            .map(|u| u.id.clone())
            .collect();

        for unit in &mut units {
            if unit.kind == WorkKind::FunctionTranslation
                && let Some(class_key) = class_keys.iter().find(|k| {
                    k.starts_with("classify/")
                        && unit
                            .dll
                            .ends_with(k.strip_prefix("classify/").unwrap_or(""))
                })
            {
                unit.dependencies.push(class_key.clone());
            }
        }

        let mut dashboard = ReviewDashboard::new(units);

        let blocked = dashboard.auto_block_units();
        if blocked > 0 {
            eprintln!(
                "  [auto-block] Marked {} units as blocked due to unmet dependencies",
                blocked
            );
        }

        Ok(dashboard)
    }

    fn read_all_patch_records(&self) -> Result<Vec<PatchRecordEntry>, anyhow::Error> {
        let mut records = Vec::new();
        let patches_dir = self.repo_path.join("re").join("patches");
        if !patches_dir.exists() {
            return Ok(records);
        }

        for dll_dir in std::fs::read_dir(&patches_dir)? {
            let dll_dir = dll_dir?;
            let dll = dll_dir
                .file_name()
                .to_string_lossy()
                .trim_end_matches(".dll")
                .to_string();

            let func_dir = dll_dir.path();
            if !func_dir.is_dir() {
                continue;
            }

            for entry in std::fs::read_dir(&func_dir)? {
                let entry = entry?;
                let file_name = entry.file_name().to_string_lossy().to_string();
                if !file_name.ends_with(".json") {
                    continue;
                }

                let attempt = file_name
                    .strip_prefix("v")
                    .and_then(|s| s.trim_end_matches(".json").parse().ok())
                    .unwrap_or(0);

                let content = std::fs::read_to_string(entry.path())?;
                let patch: calxgloss_git::PatchRecord = match serde_json::from_str(&content) {
                    Ok(p) => p,
                    Err(_) => continue,
                };

                records.push(PatchRecordEntry {
                    key: format!("{}/{}/v{}", dll, patch.function, attempt),
                    dll: patch.dll.clone(),
                    function: patch.function.clone(),
                    attempt,
                    compilation_errors: patch.compilation_errors.len(),
                    test_failures: patch.test_failures.len(),
                    committed_at: patch.committed_at.clone(),
                });
            }
        }

        Ok(records)
    }

    fn read_all_baselines(&self) -> Result<HashMap<String, BaselineData>, anyhow::Error> {
        let mut baselines = HashMap::new();
        let baseline_dir = self.repo_path.join("re").join("baseline");
        if !baseline_dir.exists() {
            return Ok(baselines);
        }

        for dll_dir in std::fs::read_dir(&baseline_dir)? {
            let dll_dir = dll_dir?;
            let dll = dll_dir
                .file_name()
                .to_string_lossy()
                .trim_end_matches(".dll")
                .to_string();

            let func_dir = dll_dir.path();
            if !func_dir.is_dir() {
                continue;
            }

            let func_name = func_dir
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default();

            let baseline_path = func_dir.join("baseline.json");
            if !baseline_path.exists() {
                continue;
            }

            let content = std::fs::read_to_string(&baseline_path)?;
            let tests: Vec<calxgloss_types::TestResult> = match serde_json::from_str(&content) {
                Ok(t) => t,
                Err(_) => continue,
            };

            let test_count = tests.len();
            let pass_count = tests.iter().filter(|t| t.passed).count();

            baselines.insert(
                format!("{}/{}", dll, func_name),
                BaselineData {
                    test_count,
                    pass_count,
                },
            );
        }

        Ok(baselines)
    }

    fn read_classification_records(&self) -> Vec<ClassifiedDll> {
        let classify_dir = self.repo_path.join("re").join("classify");
        if !classify_dir.exists() {
            return Vec::new();
        }

        let entries = match std::fs::read_dir(&classify_dir) {
            Ok(e) => e,
            Err(_) => return Vec::new(),
        };

        let mut dlls = Vec::new();
        for entry in entries {
            let entry = match entry {
                Ok(e) => e,
                Err(_) => continue,
            };
            let file_name = entry.file_name().to_string_lossy().to_string();
            if file_name.ends_with(".json") {
                let dll_name = file_name.trim_end_matches(".json").to_string();
                dlls.push(ClassifiedDll {
                    dll: dll_name,
                    _category: String::new(),
                });
            }
        }
        dlls
    }

    fn is_branch_merged(&self, key: &str) -> bool {
        let all_branches = match self.git.list_branches() {
            Ok(b) => b,
            Err(_) => return false,
        };

        for branch in all_branches {
            if !branch.starts_with("re/") {
                continue;
            }
            let branch_parts = parse_branch_name(&branch);
            if let Some(bp) = branch_parts {
                let branch_key = unit_key(&bp);
                if branch_key == key
                    && let Ok(merged) = self.is_branch_merged_into_main(&branch)
                    && merged
                {
                    return true;
                }
            }
        }
        false
    }

    fn is_branch_merged_into_main(&self, branch_name: &str) -> Result<bool, anyhow::Error> {
        let main_ref = self
            .git
            .repo()
            .find_branch("main", git2::BranchType::Local)
            .ok()
            .and_then(|b| b.get().peel_to_commit().ok());

        let branch_ref = self
            .git
            .repo()
            .find_branch(branch_name, git2::BranchType::Local)
            .ok()
            .and_then(|b| b.get().peel_to_commit().ok());

        match (main_ref, branch_ref) {
            (Some(main_commit), Some(branch_commit)) => {
                let is_ancestor = self
                    .git
                    .repo()
                    .graph_ahead_behind(branch_commit.id(), main_commit.id())
                    .map(|(ahead, _)| ahead == 0)
                    .unwrap_or(false);
                Ok(is_ancestor)
            }
            _ => Ok(false),
        }
    }

    fn build_unit(
        &self,
        _branches: &[String],
        key: &str,
        latest_attempt: u32,
        patch_records: &[PatchRecordEntry],
    ) -> UnitOfWork {
        let parts = parse_branch_name_for_key(key, latest_attempt);
        let display_name = match &parts.function {
            Some(func) => format!("Translate {}", func),
            None => format!("Classify {}", parts.dll),
        };

        let id = if let Some(ref func) = parts.function {
            format!("{}/{}/v{}", parts.dll, func, latest_attempt)
        } else {
            format!("classify/{}", parts.dll)
        };

        let patch_data = patch_records
            .iter()
            .filter(|pr| {
                pr.key.contains(&parts.dll)
                    && pr.key.contains(parts.function.as_deref().unwrap_or(""))
            })
            .max_by_key(|pr| pr.attempt);

        let patch_info = patch_data.map(|pr| {
            let err_count = pr.compilation_errors + pr.test_failures;
            if err_count > 0 {
                0.3 + (0.1 * err_count as f32).min(0.6)
            } else {
                0.8
            }
        });

        let now = Utc::now();
        let (updated_at, stale) = patch_data
            .map(|pr| {
                let dt = chrono::DateTime::parse_from_rfc3339(&pr.committed_at)
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or(now);
                let staleness = Staleness::from_elapsed(now, dt);
                (dt, staleness)
            })
            .unwrap_or_else(|| (now, Staleness::Fresh));

        UnitOfWork {
            id,
            name: display_name,
            kind: parts.kind,
            dll: parts.dll,
            function: parts.function,
            attempt: latest_attempt,
            status: ReviewStatus::Queued,
            accepted: false,
            confidence: patch_data.map(|_| patch_info.unwrap_or(0.5)),
            baseline_tests_passed: None,
            baseline_tests_total: None,
            verification_tests_passed: None,
            verification_tests_total: None,
            llm_model: None,
            context_tier: None,
            dependencies: vec![],
            created_at: now,
            updated_at,
            known_gaps: vec![],
            stale,
        }
    }
}

fn unit_key(parts: &BranchParts) -> String {
    match &parts.function {
        Some(func) => format!("{}/{}/v{}", parts.dll, func, parts.attempt),
        None => format!("classify/{}", parts.dll),
    }
}

fn parse_branch_name_for_key(key: &str, default_attempt: u32) -> BranchParts {
    if key.starts_with("classify/") {
        let dll = key.strip_prefix("classify/").unwrap_or(key);
        return BranchParts {
            kind: WorkKind::DllClassification,
            dll: dll.to_string(),
            function: None,
            attempt: default_attempt,
        };
    }

    let (base, _) = key.rsplit_once('/').unwrap_or((key, ""));
    let parts: Vec<&str> = base.splitn(2, '/').collect();

    BranchParts {
        kind: WorkKind::FunctionTranslation,
        dll: parts.first().map(|s| s.to_string()).unwrap_or_default(),
        function: parts.get(1).map(|s| s.to_string()),
        attempt: default_attempt,
    }
}

#[derive(Debug)]
#[allow(dead_code)]
struct PatchRecordEntry {
    key: String,
    dll: String,
    function: String,
    attempt: u32,
    compilation_errors: usize,
    test_failures: usize,
    committed_at: String,
}

#[derive(Debug)]
struct BaselineData {
    test_count: usize,
    pass_count: usize,
}

#[derive(Debug)]
struct ClassifiedDll {
    dll: String,
    _category: String,
}
