//! Dashboard builder — assembles [`ReviewDashboard`] from git + file artifacts.
//!
//! This module contains the [`DashboardBuilder`] which walks a Git repository's
//! branches, patch records, send-back records, and baseline files to construct
//! a complete review dashboard. Branch state is authoritative for acceptance
//! (a branch merged into `main` is `Accepted`); the failing verdicts are
//! durable through their records — a send-back record makes a unit `SendBack`
//! and a patch-request record makes it `PatchRequested`, both surviving a
//! rebuild so `auto_block_units` has failing roots to cascade `Blocked` from.
//!
//! The builder also wires the dependency edges that cascade follows: a
//! function unit depends on its DLL's classification unit and on the
//! shim-layer unit its classification requires — the same dependency the
//! branch-creation policy (`DependencyChecker`) gates `create_branch` on —
//! so a sent-back shim or classification blocks whatever translates on top
//! of it.

use std::collections::HashMap;
use std::path::PathBuf;

use calxgloss_git::{DependencyChecker, GitManager};
use calxgloss_types::DllCategory;
use calxgloss_types::dashboard::{ReviewDashboard, ReviewStatus, Staleness, UnitOfWork, WorkKind};
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

    let kind = work_kind_for_prefix(kind).unwrap_or(WorkKind::FunctionTranslation);

    Some(BranchParts {
        kind,
        dll,
        function,
        attempt,
    })
}

/// Maps a branch name's first path segment to its supporting work kind
/// (`shim`, `pal`, …); any other segment is a DLL name, making the branch a
/// function translation.
fn work_kind_for_prefix(prefix: &str) -> Option<WorkKind> {
    match prefix {
        "classify" => Some(WorkKind::DllClassification),
        "shim" => Some(WorkKind::ShimLayer),
        "pal" => Some(WorkKind::PalTrait),
        "test" => Some(WorkKind::TestCaseAddition),
        "integration" => Some(WorkKind::IntegrationStep),
        "fix" => Some(WorkKind::BugFix),
        _ => None,
    }
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
    unit_confidence: Option<f32>,
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

        // 2b. Scan send-back records for sent-back verdicts
        let sent_back_keys = self.read_all_send_back_records()?;

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
            let patch_requested = patch_records
                .iter()
                .any(|pr| pr.key == *key && pr.patch_request.is_some());
            let sent_back = sent_back_keys.contains(key.as_str());

            let merged = self.is_branch_merged(key);

            // Branch state is authoritative for acceptance; failing verdicts
            // come from the durable records — a send-back at this attempt
            // outranks a patch request (send-back then re-patched lands the
            // request on the *next* attempt's key, never this one).
            unit.status = if merged {
                ReviewStatus::Accepted
            } else if sent_back {
                ReviewStatus::SendBack
            } else if patch_requested {
                ReviewStatus::PatchRequested
            } else if has_patch {
                ReviewStatus::PendingReview
            } else {
                ReviewStatus::Queued
            };

            units_by_key.entry(unit.id.clone()).or_default().push(unit);
        }

        // 5. Also check for classified DLLs not covered by translation branches
        let classified = self.read_classification_records();
        for cls in &classified {
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
                    unit_confidence: Some(0.95),
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

        // 6. Wire dependency edges from the branch model so the failing
        //    verdicts above cascade `Blocked` down the graph. A function
        //    unit depends on:
        //    - its DLL's classification unit (`classify/{dll}`), and
        //    - the shim-layer unit its classification requires — the same
        //      `DependencyChecker` result `GitManager::create_branch` gates
        //      branch creation on, so the dashboard graph reflects which
        //      work the branch model says must merge first.
        let classify_ids: HashMap<String, String> = units
            .iter()
            .filter(|u| u.kind == WorkKind::DllClassification)
            .map(|u| {
                let dll = u.id.strip_prefix("classify/").unwrap_or(&u.id);
                (classify_dll_key(dll).to_string(), u.id.clone())
            })
            .collect();

        let shim_ids: HashMap<String, String> = units
            .iter()
            .filter(|u| u.kind == WorkKind::ShimLayer)
            .filter_map(|u| u.function.clone().map(|krate| (krate, u.id.clone())))
            .collect();

        let classified_by_dll: HashMap<String, &ClassifiedDll> = classified
            .iter()
            .map(|c| (trim_dll_suffix(&c.dll).to_string(), c))
            .collect();

        let checker = DependencyChecker::new();
        for unit in &mut units {
            if unit.kind != WorkKind::FunctionTranslation {
                continue;
            }
            let dll_key = trim_dll_suffix(&unit.dll);

            if let Some(class_id) = classify_ids.get(dll_key)
                && !unit.dependencies.contains(class_id)
            {
                unit.dependencies.push(class_id.clone());
            }

            if let Some(cls) = classified_by_dll.get(dll_key)
                && let Some(category) = &cls.category
            {
                let required = checker.check(&cls.dll, category, cls.crate_replacement.as_deref());
                for branch in &required.required {
                    // Required deps are branch names (`re/shim/{crate}`); the
                    // dashboard unit lives under the same parts as a shim unit.
                    if let Some(shim_parts) = parse_branch_name(branch)
                        && let Some(krate) = &shim_parts.function
                        && let Some(shim_id) = shim_ids.get(krate)
                        && !unit.dependencies.contains(shim_id)
                    {
                        unit.dependencies.push(shim_id.clone());
                    }
                }
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

    /// Reads every patch record under `re/patches/{dll}/{function}/v{N}.json`
    /// (written by `GitManager::store_failure` for failures and by the review
    /// UI's request-patch action for patch requests).
    fn read_all_patch_records(&self) -> Result<Vec<PatchRecordEntry>, anyhow::Error> {
        let mut records = Vec::new();
        for file in read_record_tree::<calxgloss_git::PatchRecord>(
            &self.repo_path.join("re").join("patches"),
        )? {
            let patch = file.record;
            records.push(PatchRecordEntry {
                key: format!("{}/{}/v{}", file.dll, patch.function, file.attempt),
                attempt: file.attempt,
                compilation_errors: patch.compilation_errors.len(),
                test_failures: patch.test_failures.len(),
                committed_at: patch.committed_at,
                patch_request: patch.patch_request,
            });
        }
        Ok(records)
    }

    /// Reads every send-back record under
    /// `re/rejections/{dll}/{function}/v{N}.json` (written by
    /// `GitManager::reject_branch`), returning the unit keys
    /// (`{dll}/{function}/v{attempt}`) whose attempt a reviewer sent back.
    ///
    /// Without this read the `SendBack` verdict is invisible after a rebuild
    /// — branch state alone cannot tell a sent-back branch from a queued one,
    /// and `auto_block_units` would have no failing roots to cascade from.
    fn read_all_send_back_records(
        &self,
    ) -> Result<std::collections::HashSet<String>, anyhow::Error> {
        let mut keys = std::collections::HashSet::new();
        for file in
            read_record_tree::<SendBackRecord>(&self.repo_path.join("re").join("rejections"))?
        {
            keys.insert(format!(
                "{}/{}/v{}",
                file.dll, file.record.function, file.attempt
            ));
        }
        Ok(keys)
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

    /// Reads every classification record under `re/classify/{dll}.json`
    /// (written by the `classify` command). The category and crate
    /// replacement are parsed leniently — a record that fails to parse
    /// still counts as classified, it just declares no shim dependency.
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
                let parsed = std::fs::read_to_string(entry.path())
                    .ok()
                    .and_then(|content| serde_json::from_str::<ClassificationFile>(&content).ok());
                dlls.push(match parsed {
                    Some(p) => ClassifiedDll {
                        dll: dll_name,
                        category: p.category,
                        crate_replacement: p.crate_replacement,
                    },
                    None => ClassifiedDll {
                        dll: dll_name,
                        category: None,
                        crate_replacement: None,
                    },
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
            unit_confidence: patch_data.map(|_| patch_info.unwrap_or(0.5)),
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
        kind: parts
            .first()
            .and_then(|s| work_kind_for_prefix(s))
            .unwrap_or(WorkKind::FunctionTranslation),
        dll: parts.first().map(|s| s.to_string()).unwrap_or_default(),
        function: parts.get(1).map(|s| s.to_string()),
        attempt: default_attempt,
    }
}

/// Trims a single trailing `.dll` from a DLL name for cross-artifact
/// matching: branch names drop the extension, classification records keep it.
fn trim_dll_suffix(name: &str) -> &str {
    name.strip_suffix(".dll").unwrap_or(name)
}

/// Normalizes a classification unit's dll segment to the extension-free dll
/// name a function unit's `dll` matches: record-derived ids are
/// `classify/{dll}` and branch-derived ids carry an attempt
/// (`classify/{dll}/vN`, the shape `parse_branch_name` documents).
fn classify_dll_key(dll: &str) -> &str {
    trim_dll_suffix(strip_attempt_suffix(dll))
}

/// Strips a trailing `/v{N}` attempt suffix from a unit id segment.
fn strip_attempt_suffix(name: &str) -> &str {
    match name.rsplit_once("/v") {
        Some((base, n)) if !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()) => base,
        _ => name,
    }
}

#[derive(Debug)]
struct PatchRecordEntry {
    key: String,
    attempt: u32,
    compilation_errors: usize,
    test_failures: usize,
    committed_at: String,
    /// The reviewer's stated issue when this record is a patch *request*
    /// (written by the review UI's request-patch action); `None` on plain
    /// pipeline failure records and successful retry records.
    patch_request: Option<String>,
}

/// The fields the builder needs from a send-back record
/// (`re/rejections/{dll}/{function}/v{N}.json`, written by
/// `GitManager::reject_branch`); the attempt comes from the file name.
#[derive(Debug, serde::Deserialize)]
struct SendBackRecord {
    function: String,
}

/// One record file from the shared review-record tree: the DLL directory
/// name (`.dll` suffix trimmed), the attempt number from the file name,
/// and the deserialized record.
struct RecordFile<T> {
    dll: String,
    attempt: u32,
    record: T,
}

/// Walks the `{root}/{dll}/{function}/v{N}.json` layout shared by patch and
/// send-back records, deserializing every `*.json` file into `T`. A missing
/// root yields nothing; unreadable or malformed files are skipped.
fn read_record_tree<T: serde::de::DeserializeOwned>(
    root: &std::path::Path,
) -> Result<Vec<RecordFile<T>>, anyhow::Error> {
    let mut files = Vec::new();
    if !root.exists() {
        return Ok(files);
    }

    for dll_dir in std::fs::read_dir(root)? {
        let dll_dir = dll_dir?;
        let dll = dll_dir
            .file_name()
            .to_string_lossy()
            .trim_end_matches(".dll")
            .to_string();

        if !dll_dir.path().is_dir() {
            continue;
        }

        for func_dir in std::fs::read_dir(dll_dir.path())? {
            let func_dir = func_dir?;
            if !func_dir.path().is_dir() {
                continue;
            }

            for entry in std::fs::read_dir(func_dir.path())? {
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
                let record: T = match serde_json::from_str(&content) {
                    Ok(r) => r,
                    Err(_) => continue,
                };

                files.push(RecordFile {
                    dll: dll.clone(),
                    attempt,
                    record,
                });
            }
        }
    }

    Ok(files)
}

#[derive(Debug)]
struct BaselineData {
    test_count: usize,
    pass_count: usize,
}

/// The fields the builder needs from a classification record
/// (`re/classify/{dll}.json`, written by the `classify` command); everything
/// else in the record is ignored, and both fields are optional so older or
/// partial records still read.
#[derive(Debug, Default, serde::Deserialize)]
struct ClassificationFile {
    #[serde(default)]
    category: Option<DllCategory>,
    #[serde(default)]
    crate_replacement: Option<String>,
}

/// A DLL with a classification record on disk. `dll` is the record file name
/// minus `.json` (the `classify` command keeps the `.dll` extension in it);
/// the category and crate replacement drive the shim dependency edge.
#[derive(Debug)]
struct ClassifiedDll {
    dll: String,
    category: Option<DllCategory>,
    crate_replacement: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_branch_name_reads_shim_branch() {
        let parts = parse_branch_name("re/shim/wgpu").expect("shim branch parses");
        assert_eq!(parts.kind, WorkKind::ShimLayer);
        assert_eq!(parts.dll, "shim");
        assert_eq!(parts.function.as_deref(), Some("wgpu"));
        assert_eq!(unit_key(&parts), "shim/wgpu/v1");
    }

    #[test]
    fn parse_branch_name_for_key_keeps_supporting_work_kind() {
        // A shim unit rebuilt from its key must stay at the shim level in
        // the dependency graph, not collapse to a function translation.
        let parts = parse_branch_name_for_key("shim/wgpu/v2", 2);
        assert_eq!(parts.kind, WorkKind::ShimLayer);
        assert_eq!(parts.dll, "shim");
        assert_eq!(parts.function.as_deref(), Some("wgpu"));

        let parts = parse_branch_name_for_key("game_logic/DrawSprite/v1", 1);
        assert_eq!(parts.kind, WorkKind::FunctionTranslation);
        assert_eq!(parts.dll, "game_logic");
        assert_eq!(parts.function.as_deref(), Some("DrawSprite"));
    }

    #[test]
    fn trim_dll_suffix_matches_branch_and_record_spellings() {
        assert_eq!(trim_dll_suffix("d3d9.dll"), "d3d9");
        assert_eq!(trim_dll_suffix("d3d9"), "d3d9");
    }

    #[test]
    fn classify_dll_key_normalizes_record_and_branch_id_shapes() {
        // Record-derived ids carry the extension, branch-derived ids an
        // attempt; both must key to the same extension-free dll name.
        assert_eq!(classify_dll_key("d3d9.dll"), "d3d9");
        assert_eq!(classify_dll_key("game_logic"), "game_logic");
        assert_eq!(classify_dll_key("game_logic.dll/v1"), "game_logic");
    }
}
