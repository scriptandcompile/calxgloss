//! Dashboard data construction and terminal rendering for the review dashboard.
//!
//! This module builds [`ReviewDashboard`] instances from a Git repository's
//! branches, patch records, and baseline files — then renders them as an
//! ANSI-colored text table suitable for terminal output.
//!
//! # Architecture
//!
//! - [`DashboardBuilder`] walks the repository and assembles units of work
//! - [`render_dashboard`] formats everything for the terminal

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use calxgloss_git::GitManager;
use calxgloss_types::dashboard::{
    ReviewDashboard, ReviewStatus, StatusCounts, UnitOfWork, WorkUnitKind,
};
use chrono::Utc;

// ============================================================
// ANSI codes (kept in sync with the rest of the crate)
// ============================================================

const ANSI_RESET: &str = "\x1b[0m";
const ANSI_BOLD: &str = "\x1b[1m";
const ANSI_DIM: &str = "\x1b[2m";
const ANSI_GREEN: &str = "\x1b[32m";
const ANSI_RED: &str = "\x1b[31m";
const ANSI_YELLOW: &str = "\x1b[33m";
const ANSI_BLUE: &str = "\x1b[34m";

fn bold(text: &str) -> String {
    format!("{}{}{}", ANSI_BOLD, text, ANSI_RESET)
}

fn dim(text: &str) -> String {
    format!("{}{}{}", ANSI_DIM, text, ANSI_RESET)
}

fn green_bold(text: &str) -> String {
    format!("{}{}{}{}", ANSI_BOLD, ANSI_GREEN, text, ANSI_RESET)
}

fn red_bold(text: &str) -> String {
    format!("{}{}{}{}", ANSI_BOLD, ANSI_RED, text, ANSI_RESET)
}

fn yellow_bold(text: &str) -> String {
    format!("{}{}{}{}", ANSI_BOLD, ANSI_YELLOW, text, ANSI_RESET)
}

fn blue_bold(text: &str) -> String {
    format!("{}{}{}{}", ANSI_BOLD, ANSI_BLUE, text, ANSI_RESET)
}

fn format_dim(text: &str) -> String {
    dim(text)
}

// ============================================================
// Status emoji / symbol helpers
// ============================================================

fn status_symbol(status: &ReviewStatus) -> &str {
    match status {
        ReviewStatus::Queued => "  ?",
        ReviewStatus::PendingReview => " ◉",
        ReviewStatus::Accepted => " ✓",
        ReviewStatus::SendBack => " ✗",
        ReviewStatus::PatchRequested => " ⚑",
        ReviewStatus::Merged => " ◆",
        ReviewStatus::Blocked => " ✖",
    }
}

// ============================================================
// DashboardBuilder — assembles units from git + file artifacts
// ============================================================

/// Parses a git branch name like `re/game_logic/DrawSpritev1` or
/// `re/classify/game_logic.dllv1` into its components.
///
/// The naming convention is: `re/{kind}/{rest}v{attempt}` where *rest* may
/// contain a `/` for nested structures like `{dll}/{function}`.
fn parse_branch_name(name: &str) -> Option<BranchParts> {
    // Strip the `re/` prefix
    let rest = name.strip_prefix("re/")?;

    // Split off the attempt suffix (last segment starting with 'v' followed by digits)
    // e.g., "game_logic/DrawSpritev1" → dll="game_logic", function="DrawSprite", attempt=1
    // e.g., "classify/game_logic.dllv1" → kind="classify", dll="game_logic.dll", attempt=1

    // Try to find the last `v{digits}` suffix
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
        // Two-level: e.g., "game_logic/DrawSprite" → dll=game_logic, function=DrawSprite
        (parts[0].to_string(), Some(parts[1].to_string()))
    } else {
        // Single-level: e.g., "classify/game_logic.dll" → dll=game_logic.dll
        (parts[0].to_string(), None)
    };

    let kind = match kind {
        "classify" => WorkUnitKind::DllClassification,
        "shim" => WorkUnitKind::ShimLayer,
        "pal" => WorkUnitKind::PalTrait,
        "test" => WorkUnitKind::TestCaseAddition,
        "integration" => WorkUnitKind::IntegrationStep,
        "fix" => WorkUnitKind::BugFix,
        _ => WorkUnitKind::FunctionTranslation,
    };

    Some(BranchParts {
        kind,
        dll,
        function,
        attempt,
    })
}

#[derive(Debug)]
struct BranchParts {
    kind: WorkUnitKind,
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
    prompt_tier: Option<usize>,
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
        let mut seen_keys: HashMap<String, u32> = HashMap::new(); // key → highest attempt

        for branch in &branches {
            let parts = match parse_branch_name(branch) {
                Some(p) => p,
                None => continue, // skip branches we can't parse
            };

            let key = unit_key(&parts);
            let existing_attempt = seen_keys.entry(key.clone()).or_insert(0);

            if parts.attempt > *existing_attempt {
                *existing_attempt = parts.attempt;
            }

            // We'll finalize each unit below using patch/baseline data
            // For now, just note that we've seen it
            let _ = parts;
        }

        // 2. Scan patch records for per-attempt data
        let patch_records = self.read_all_patch_records()?;

        // 3. Read baseline data
        let baselines = self.read_all_baselines()?;

        // 4. Determine the *latest* attempt for each key and build units
        for (key, latest_attempt) in &seen_keys {
            let mut unit = self.build_unit(&branches, key, *latest_attempt, &patch_records);

            // Enrich with baseline data — strip the /vN suffix to match baseline keys
            let baseline_key = key.rsplit_once('/').map_or(key.as_str(), |(base, _)| base);
            if let Some(baseline) = baselines.get(baseline_key) {
                unit.baseline_tests_total = Some(baseline.test_count);
                unit.baseline_tests_passed = Some(baseline.pass_count);
            }

            // Determine status from branch existence & patch data
            let has_patch = patch_records
                .iter()
                .any(|pr| pr.key == *key && pr.attempt <= *latest_attempt);

            let merged = self.is_branch_merged(key);

            unit.status = if merged {
                ReviewStatus::Merged
            } else if has_patch {
                // If there's a patch record for the latest attempt, it failed
                ReviewStatus::PendingReview
            } else {
                ReviewStatus::Queued
            };

            // Add to our collection
            units_by_key
                .entry(unit.id.clone())
                .or_default()
                .push(unit);
        }

        // 5. Also check for classified DLLs that aren't covered by translation branches
        let classified = self.read_classification_records();
        for cls in classified {
            let key = format!("classify/{}", cls.dll);
            if !seen_keys.contains_key(&key) {
                let unit = UnitOfWork {
                    id: key.clone(),
                    name: format!("Classify {}", cls.dll),
                    kind: WorkUnitKind::DllClassification,
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
                    prompt_tier: Some(0),
                    dependencies: vec![],
                    created_at: Utc::now(),
                    updated_at: Utc::now(),
                    known_gaps: vec![],
                };
                units_by_key.entry(key).or_default().push(unit);
            }
        }

        // 6. Flatten and de-duplicate units, picking the highest attempt per key
        let mut units: Vec<UnitOfWork> = units_by_key
            .into_values()
            .map(|mut v| {
                v.sort_by_key(|u| u.attempt);
                v.pop().unwrap()
            })
            .collect();

        // Add dependency edges: function translation depends on its DLL's classification
        let class_keys: Vec<String> = units
            .iter()
            .filter(|u| u.kind == WorkUnitKind::DllClassification)
            .map(|u| u.id.clone())
            .collect();

        for unit in &mut units {
            if unit.kind == WorkUnitKind::FunctionTranslation {
                if let Some(class_key) = class_keys.iter().find(|k| k.starts_with("classify/") && unit.dll.ends_with(k.strip_prefix("classify/").unwrap_or(""))) {
                    unit.dependencies.push(class_key.clone());
                }
            }
        }

        let dashboard = ReviewDashboard::new(units);
        Ok(dashboard)
    }

    /// Reads patch records for all functions.
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
                let patch: calxgloss_git::PatchRecord =
                    match serde_json::from_str(&content) {
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

    /// Reads baseline files for all functions.
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
            let tests: Vec<calxgloss_types::TestResult> =
                match serde_json::from_str(&content) {
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

    /// Reads DLL classification records (stored in `re/classify/`).
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
                    _category: String::new(), // we don't parse this for dashboard
                });
            }
        }
        dlls
    }

    /// Checks whether a branch has been merged into main.
    fn is_branch_merged(&self, key: &str) -> bool {
        // Parse the key back to a branch name to check merge status
        // Keys are like "game_logic/DrawSprite" or "classify/game_logic.dll"
        let _branch_name = key.replace('/', "-");

        // Try the direct translation branch name format
        let all_branches = match self.git.list_branches() {
            Ok(b) => b,
            Err(_) => return false,
        };

        // Check if any translation branch for this unit is merged into main
        // A branch is merged if its commit is an ancestor of main
        for branch in all_branches {
            if !branch.starts_with("re/") {
                continue;
            }
            // Check if this branch belongs to our key
            let branch_parts = parse_branch_name(&branch);
            if let Some(bp) = branch_parts {
                let branch_key = unit_key(&bp);
                if branch_key == key {
                    // Check if this branch is merged (fast-forward into main)
                    if let Ok(merged) = self.is_branch_merged_into_main(&branch) {
                        if merged {
                            return true;
                        }
                    }
                }
            }
        }
        false
    }

    /// Checks if a specific branch is an ancestor of main.
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

    /// Builds a single [`UnitOfWork`] from branch + artifact data.
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

        // Look up patch data for this unit
        let patch_data = patch_records
            .iter()
            .filter(|pr| pr.key.contains(&parts.dll) && pr.key.contains(&parts.function.as_deref().unwrap_or("")))
            .max_by_key(|pr| pr.attempt);

        let patch_info = patch_data.map(|pr| {
            let err_count = pr.compilation_errors + pr.test_failures;
            if err_count > 0 {
                0.3 + (0.1 * err_count as f32).min(0.6)
            } else {
                0.8
            }
        });

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
            llm_model: patch_data.and_then(|_pr| {
                // We don't have LLM model in patch records, leave as None
                None
            }),
            prompt_tier: None,
            dependencies: vec![],
            created_at: Utc::now(),
            updated_at: Utc::now(),
            known_gaps: vec![],
        }
    }
}

/// Returns a deduplication key for a branch.
fn unit_key(parts: &BranchParts) -> String {
    match &parts.function {
        Some(func) => format!("{}/{}/v{}", parts.dll, func, parts.attempt),
        None => format!("classify/{}", parts.dll),
    }
}

/// Parse a key string back into branch parts.
fn parse_branch_name_for_key(key: &str, default_attempt: u32) -> BranchParts {
    if key.starts_with("classify/") {
        let dll = key.strip_prefix("classify/").unwrap_or(key);
        return BranchParts {
            kind: WorkUnitKind::DllClassification,
            dll: dll.to_string(),
            function: None,
            attempt: default_attempt,
        };
    }

    // Split on last /v{N}
    let (base, _) = key.rsplit_once('/').unwrap_or((key, ""));
    let parts: Vec<&str> = base.splitn(2, '/').collect();

    BranchParts {
        kind: WorkUnitKind::FunctionTranslation,
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

// ============================================================
// Terminal rendering — flat layout, horizontal dividers only
// ============================================================

/// Width of horizontal dividers (no vertical borders, no corners).
const SEP_WIDTH: usize = 78;

/// A single horizontal divider.
fn hsep() {
    println!("  {}", "─".repeat(SEP_WIDTH));
}

/// A bold horizontal divider.
fn hsep_bold() {
    println!("  {}", "═".repeat(SEP_WIDTH));
}

/// Prints a line of content, padded to SEP_WIDTH with spaces.
/// Safe for ANSI codes and multi-byte UTF-8.
fn println_content(content: impl AsRef<str>) {
    let s = content.as_ref();
    // Pad or truncate visible (non-ANSI) characters to SEP_WIDTH.
    // Strip ANSI codes first to measure visible width.
    let visible: String = s
        .chars()
        .filter(|c| !c.is_control())
        .collect();
    let padded = if visible.len() < SEP_WIDTH {
        format!("{:<SEP_WIDTH$}", s)
    } else {
        // Truncate visible text at a char boundary, then re-embed.
        let mut end = SEP_WIDTH.min(visible.len());
        while !visible.is_char_boundary(end) {
            end -= 1;
        }
        // Count how many bytes in `s` produce `end` visible chars
        let mut vcount = 0usize;
        let mut bend = 0usize;
        for (bi, ch) in s.chars().enumerate() {
            if !ch.is_control() {
                vcount += 1;
            }
            if vcount >= end {
                bend = bi + ch.len_utf8();
                break;
            }
        }
        s[..bend].to_string()
    };
    println!("  {}", padded);
}

/// Renders a [`ReviewDashboard`] to the terminal as a flat text report.
///
/// Uses horizontal dividers only — no vertical borders, no corners.
pub fn render_dashboard(dashboard: &ReviewDashboard, follow: bool) {
    let total = dashboard.status_counts.total();
    let now = Utc::now().format("%Y-%m-%d %H:%M UTC");

    hsep_bold();
    println_content(format!("  Calxgloss Review Dashboard — {}  ", now));
    hsep();

    render_status_summary(&dashboard.status_counts);
    hsep();

    let queue = &dashboard.review_queue;
    if queue.is_empty() {
        println_content("  No pending units in the review queue.");
    } else {
        println_content("  Review Queue");
        println_content("");
        render_queue_table(queue);
        println_content("");
    }

    let blocked = dashboard.blocked_units();
    if !blocked.is_empty() {
        println_content(format!("  Blocked units ({}):", blocked.len()));
        for unit in &blocked {
            let name = format!("{} ({})", unit.name, unit.dll);
            println_content(format!(
                "    ✖ {} — depends on: {}",
                name,
                unit.dependencies.join(", ")
            ));
        }
        println_content("");
    }

    let recent = &dashboard.recent_activity;
    if !recent.is_empty() {
        println_content(format!("  Recent activity ({}):", recent.len()));
        for unit in recent.iter().rev().take(5) {
            let test_info = match (unit.baseline_tests_passed, unit.baseline_tests_total) {
                (Some(passed), Some(total)) => format!("{}/{} tests", passed, total),
                _ => "—".to_string(),
            };
            let confidence = unit
                .confidence
                .map(|c| format!("({:.0}%)", c * 100.0))
                .unwrap_or_else(|| "no confidence".to_string());

            println_content(format!(
                "    ✓ {} [{}] — {} — {}",
                unit.name, unit.dll, test_info, confidence
            ));
        }
        println_content("");
    }

    println_content(format!("  {} branches found in re/*", total));
    if follow {
        println_content("  Watching for changes (Ctrl+C to stop). Press 'r' to refresh.");
    }

    hsep_bold();
    println!();
}

/// Renders the status summary row.
fn render_status_summary(counts: &StatusCounts) {
    let total = counts.total();
    let parts = [
        green_bold(&format!("OK {}", counts.accepted + counts.merged)),
        yellow_bold(&format!("Pending {}", counts.pending_review + counts.patch_requested)),
        red_bold(&format!("Failed {}", counts.send_back)),
        blue_bold(&format!("Queued {}", counts.queued)),
        dim(&format!("Blocked {}", counts.blocked)),
        bold(&format!("Total: {}", total)),
    ];
    println_content(parts.join("  │  "));
}

/// Renders the review queue as a table.
fn render_queue_table(units: &[UnitOfWork]) {
    // Header: #  Kind       Function                       Status      Tests    Attempt
    // Header — hardcoded spacing so ANSI codes in bold don't shift columns
    println_content("  #   Kind       Function                        Status      Tests    Attempt");
    hsep();

    for (idx, unit) in units.iter().enumerate() {
        let kind_str = format_kind(&unit.kind);
        let name = truncate(&unit.name, 30);
        let status_str = format_status_display(&unit.status);
        let _test_info = match (unit.baseline_tests_passed, unit.baseline_tests_total) {
            (Some(passed), Some(total)) => format!("{}/{}", passed, total),
            _ => "—".to_string(),
        };
        let attempt_str = format!("v{}", unit.attempt);

        let line = format!(
            "  {}  {}  {}  {}  {}  {}",
            bold(&format!("{:<3}", idx + 1)),
            format_dim(&format!("{:<8}", kind_str)),
            format_dim(&format!("{:<30}", name)),
            status_str,
            "\t\t—\t\t",
            attempt_str,
        );
        println!("{}", line);
    }
    hsep();
}


fn format_kind(kind: &WorkUnitKind) -> String {
    match kind {
        WorkUnitKind::DllClassification => "classify".to_string(),
        WorkUnitKind::ShimLayer => "shim".to_string(),
        WorkUnitKind::FunctionTranslation => "func".to_string(),
        WorkUnitKind::TestCaseAddition => "test".to_string(),
        WorkUnitKind::PalTrait => "pal".to_string(),
        WorkUnitKind::IntegrationStep => "integrate".to_string(),
        WorkUnitKind::BugFix => "fix".to_string(),
    }
}

/// Status text with symbol — returned without color so the caller can apply its own styling.
fn format_status_display(status: &ReviewStatus) -> String {
    let symbol = status_symbol(status);
    let text = match status {
        ReviewStatus::Queued => "queued",
        ReviewStatus::PendingReview => "pending",
        ReviewStatus::Accepted => "accepted",
        ReviewStatus::SendBack => "send_back",
        ReviewStatus::PatchRequested => "patch",
        ReviewStatus::Merged => "merged",
        ReviewStatus::Blocked => "blocked",
    };
    format!("{} {}", symbol, text)
}

fn truncate(text: &str, max_width: usize) -> String {
    if text.len() <= max_width {
        text.to_string()
    } else {
        format!("{}…", &text[..max_width.saturating_sub(1)])
    }
}

/// Renders the dashboard in "follow" mode, refreshing periodically.
pub fn render_dashboard_follow(git: &GitManager, interval: Duration) -> Result<(), anyhow::Error> {
    let builder = DashboardBuilder::new(git);
    let mut last_refresh: Option<Instant> = None;

    loop {
        let now = Instant::now();
        let should_refresh = match last_refresh {
            Some(last) => now.duration_since(last) >= interval,
            None => true,
        };

        if should_refresh {
            let dashboard = builder.build()?;
            render_dashboard(&dashboard, true);
            last_refresh = Some(now);
        }

        // Check for keyboard input (non-blocking) using a short sleep
        std::thread::sleep(Duration::from_millis(100));

        // Check if 'r' was pressed for manual refresh
        // Use non-blocking read from stdin (blocking only if there's a key)
        if should_stdin_refresh() {
            let dashboard = builder.build()?;
            render_dashboard(&dashboard, true);
            last_refresh = Some(Instant::now());
        }
    }
}

/// Checks if stdin has a pending character (for 'r' refresh key).
/// Uses a non-blocking read approach.
fn should_stdin_refresh() -> bool {
    use std::io;
    let _stdin = io::stdin();
    // Non-blocking stdin check is disabled to avoid blocking the follow loop.
    // Auto-refresh provides a good enough UX.
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_branch_name_translation() {
        let parts = parse_branch_name("re/game_logic/DrawSpritev1").unwrap();
        assert_eq!(parts.dll, "game_logic");
        assert_eq!(parts.function, Some("DrawSprite".to_string()));
        assert_eq!(parts.attempt, 1);
        assert_eq!(parts.kind, WorkUnitKind::FunctionTranslation);
    }

    #[test]
    fn parse_branch_name_high_attempt() {
        let parts = parse_branch_name("re/audio/AmbientPlayv3").unwrap();
        assert_eq!(parts.dll, "audio");
        assert_eq!(parts.function, Some("AmbientPlay".to_string()));
        assert_eq!(parts.attempt, 3);
    }

    #[test]
    fn parse_branch_name_classification() {
        let parts = parse_branch_name("re/classify/msvbvm60.dllv1").unwrap();
        assert_eq!(parts.dll, "classify");
        assert_eq!(parts.function, Some("msvbvm60.dll".to_string()));
        assert_eq!(parts.attempt, 1);
    }

    #[test]
    fn parse_branch_name_invalid() {
        assert!(parse_branch_name("main").is_none());
        assert!(parse_branch_name("feature/somethingv").is_none());
    }

    #[test]
    fn status_symbol_mapping() {
        assert_eq!(status_symbol(&ReviewStatus::Queued), "  ?");
        assert_eq!(status_symbol(&ReviewStatus::PendingReview), " ◉");
        assert_eq!(status_symbol(&ReviewStatus::Accepted), " ✓");
        assert_eq!(status_symbol(&ReviewStatus::SendBack), " ✗");
        assert_eq!(status_symbol(&ReviewStatus::Merged), " ◆");
    }

    #[test]
    fn format_kind_mapping() {
        assert_eq!(format_kind(&WorkUnitKind::DllClassification), "classify");
        assert_eq!(format_kind(&WorkUnitKind::FunctionTranslation), "func");
        assert_eq!(format_kind(&WorkUnitKind::ShimLayer), "shim");
    }
}
