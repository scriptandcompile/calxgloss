//! Unit attempt comparison reads — the attempt list with per-attempt
//! metadata (issue #131, W4.5) and the side-by-side diff between any two
//! attempt branches (issue #135, W4.6) that a function unit accumulated.
//!
//! Registered in the shared routes: every read is persisted history, never
//! live pipeline state, so plain `serve` and `live` answer identically.
//! The diff endpoint reuses this module's own join —
//! [`collect_unit_attempts`] resolves both requested attempts to the
//! branches they were recorded on, so `/api/units/{id}/attempts/diff`
//! compares the very same attempt set the list shows.
//!
//! The attempt set is exactly what the workspace persisted — the union of
//! translation branches named for this unit (read through
//! `GitManager::list_translation_branches` and parsed with
//! `parse_branch_name`) and patch-record files under
//! `re/patches/{binary}/{function}/` — nothing invented, nothing dropped.
//! Branch and patch sources are joined on the (binary, function, attempt)
//! triple with the same case-insensitive binary comparison every other
//! server comparison makes ([`binary_matches`]).
//!
//! Metadata comes only from persisted logs, and a missing or corrupt log
//! leaves its fields absent on the wire — never zeroed or guessed. The
//! token-usage log (`re/analysis/token_usage.json`) carries the full
//! triple and answers strategy, tier, tokens, and success; the fault log
//! (`re/analysis/fault_log.json`) is a strategy fallback for attempts the
//! token log never recorded. Patch records answer the compile/test outcome
//! and the commit identity — except that a patch *request* record, written
//! before the attempt it names has run, answers the attempt's identity only
//! and no outcome at all. The prompt-strategy log is deliberately NOT
//! joined for function units: its entries carry no function field, so
//! joining them on a function-scoped triple would invent identity.
//! `tests_passed` is likewise absent from the contract — no per-attempt
//! pass count is persisted anywhere, so the honest outcome fields
//! (`success`, `compilation_errors`, `test_failures`) stand in instead.

use std::collections::{BTreeMap, HashMap};

use axum::{Json, extract::Path, extract::Query, extract::State};

use calxgloss_git::{GitManager, PatchRecord};
use calxgloss_types::{
    FaultEvent, FaultLog, TokenUsageEntry, TokenUsageLog, UnitOfWork, parse_branch_name,
};

use super::super::types::{AttemptDiffResponse, AttemptMetadata, UnitAttemptsResponse};
use super::super::{ServerError, ServerState};
use super::process::{binary_matches, fault_log_path, load_json_or_default, token_usage_log_path};

/// What one attempt's persisted sources said about it, folded together
/// before it becomes wire types. Kept private so the follow-up diff
/// ticket consumes the finished [`UnitAttemptsResponse`] rather than
/// raw fragments.
struct AttemptFacts {
    attempt: u32,
    branch: Option<String>,
    patch: Option<PatchRecord>,
}

/// `GET /api/units/{id}/attempts` — the unit's attempt list with
/// per-attempt metadata, joined from persisted history only.
pub async fn api_get_unit_attempts(
    state: State<ServerState>,
    Path(unit_id): Path<String>,
) -> Result<Json<UnitAttemptsResponse>, ServerError> {
    let unit = super::queue::find_unit(&state, &unit_id)?;
    let response = collect_unit_attempts(state.repo_path(), &unit)?;
    Ok(Json(response))
}

/// The full attempt join for one unit: discover the attempt set, fold in
/// patch-record and log metadata, and answer ascending by attempt number.
/// `comparable` is true exactly when at least two attempts exist — the
/// honest precondition the detail panel uses to offer (or withhold) a diff.
pub(crate) fn collect_unit_attempts(
    repo_path: &std::path::Path,
    unit: &UnitOfWork,
) -> Result<UnitAttemptsResponse, ServerError> {
    let mut facts: BTreeMap<u32, AttemptFacts> = BTreeMap::new();

    // Source 1: translation branches named for this unit.
    let git = GitManager::open(repo_path)
        .map_err(|e| ServerError::internal(&format!("Failed to open repo: {e}")))?;
    let branches = git
        .list_translation_branches()
        .map_err(|e| ServerError::internal(&format!("Failed to list branches: {e}")))?;
    for branch in branches {
        let Some(parts) = parse_branch_name(&branch) else {
            continue;
        };
        if parts.kind != unit.kind
            || !binary_matches(parts.binary.as_str(), unit.binary.as_str())
            || parts.function.as_deref() != unit.function.as_deref()
        {
            continue;
        }
        let attempt = parts.attempt.unwrap_or(1);
        facts
            .entry(attempt)
            .or_insert_with(|| AttemptFacts {
                attempt,
                branch: None,
                patch: None,
            })
            .branch = Some(branch);
    }

    // Source 2: patch-record files under re/patches/{binary}/{function}/.
    for record in scan_patch_records(repo_path, unit) {
        let entry = facts.entry(record.attempt).or_insert_with(|| AttemptFacts {
            attempt: record.attempt,
            branch: None,
            patch: None,
        });
        if entry.branch.is_none() {
            entry.branch = Some(record.branch_name.clone());
        }
        entry.patch = Some(record);
    }

    // The logs, loaded once for the whole join; a missing or corrupt log
    // is no log at all — its fields simply stay absent.
    let token_log = load_json_or_default::<TokenUsageLog>(&token_usage_log_path(repo_path));
    let fault_log = load_json_or_default::<FaultLog>(&fault_log_path(repo_path));

    let attempts = facts
        .values()
        .map(|fact| attempt_metadata(unit, fact, &token_log.entries, &fault_log.entries))
        .collect::<Vec<_>>();
    let comparable = attempts.len() >= 2;

    Ok(UnitAttemptsResponse {
        unit_id: unit.id.clone(),
        attempts,
        comparable,
    })
}

/// `GET /api/units/{id}/attempts/diff?from={n}&to={m}` — the unified diff
/// between two attempt branches, git2 tree-to-tree (issue #135, W4.6).
/// Both attempts resolve through the same join the list uses; an attempt
/// with no recorded branch answers an honest 404 naming it, never an
/// empty fabricated diff.
pub async fn api_get_unit_attempts_diff(
    state: State<ServerState>,
    Path(unit_id): Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<AttemptDiffResponse>, ServerError> {
    let unit = super::queue::find_unit(&state, &unit_id)?;
    let from = parse_attempt_param(&params, "from")?;
    let to = parse_attempt_param(&params, "to")?;

    let attempts = collect_unit_attempts(state.repo_path(), &unit)?;
    let from_branch = attempt_branch(&attempts, from)?;
    let to_branch = attempt_branch(&attempts, to)?;

    let git = GitManager::open(state.repo_path())
        .map_err(|e| ServerError::internal(&format!("Failed to open repo: {e}")))?;
    let from_commit = attempt_commit(&git, from, &from_branch)?;
    let to_commit = attempt_commit(&git, to, &to_branch)?;
    let (diff, files_changed, insertions, deletions) =
        compute_attempt_diff(&git, &from_commit, &to_commit)
            .map_err(|e| ServerError::internal(&format!("Failed to compute diff: {e}")))?;

    Ok(Json(AttemptDiffResponse {
        unit_id: unit.id.clone(),
        from,
        to,
        from_branch,
        to_branch,
        files_changed,
        insertions,
        deletions,
        diff,
    }))
}

/// Parse one `from`/`to` query value; a missing or non-numeric value is a
/// 400 naming the accepted shape, like the analytics date filters do.
fn parse_attempt_param(params: &HashMap<String, String>, key: &str) -> Result<u32, ServerError> {
    params
        .get(key)
        .and_then(|value| value.parse::<u32>().ok())
        .ok_or_else(|| {
            ServerError::bad_request(
                "Query parameters 'from' and 'to' must be attempt numbers (e.g. ?from=1&to=2)",
            )
        })
}

/// The branch the attempt join recorded for one attempt number. A missing
/// attempt or a branchless one is a 404 naming the attempt — the honest
/// error the ticket demands in place of a fabricated empty diff.
fn attempt_branch(attempts: &UnitAttemptsResponse, attempt: u32) -> Result<String, ServerError> {
    attempts
        .attempts
        .iter()
        .find(|entry| entry.attempt == attempt)
        .and_then(|entry| entry.branch.clone())
        .ok_or_else(|| {
            ServerError::not_found(&format!(
                "Attempt {attempt} has no recorded branch for unit {} — nothing to diff",
                attempts.unit_id
            ))
        })
}

/// Resolve one attempt's branch to a commit. A branch the join named —
/// e.g. a patch record's `branch_name` whose git branch was since deleted
/// — is just as honestly a 404 naming the attempt as an attempt the join
/// never found: the diff is never fabricated from a half-present pair.
fn attempt_commit<'a>(
    git: &'a GitManager,
    attempt: u32,
    branch: &str,
) -> Result<git2::Commit<'a>, ServerError> {
    git.repo()
        .find_branch(branch, git2::BranchType::Local)
        .map_err(|_| {
            ServerError::not_found(&format!(
                "Attempt {attempt} branch {branch} is not in the repository — nothing to diff"
            ))
        })?
        .get()
        .peel_to_commit()
        .map_err(|e| ServerError::internal(&format!("Failed to resolve branch {branch}: {e}")))
}

/// The git2 tree-to-tree diff between two attempt commits: the unified
/// patch text plus its (files, insertions, deletions) stats.
fn compute_attempt_diff(
    git: &GitManager,
    from_commit: &git2::Commit,
    to_commit: &git2::Commit,
) -> Result<(String, usize, usize, usize), anyhow::Error> {
    let mut diff_opts = git2::DiffOptions::new();
    let diff = git.repo().diff_tree_to_tree(
        Some(&from_commit.tree()?),
        Some(&to_commit.tree()?),
        Some(&mut diff_opts),
    )?;
    let stats = diff.stats()?;

    let mut text = String::new();
    diff.print(git2::DiffFormat::Patch, |_delta, _hunk, line| {
        // git2 hands out the line content without its unified-diff origin
        // character; `f` (file header) and `h` (hunk header) lines are
        // already complete text, everything else needs its prefix back so
        // the payload is genuine `git diff` text.
        let origin = line.origin();
        if !matches!(origin, 'F' | 'H') {
            text.push(origin);
        }
        text.push_str(&String::from_utf8_lossy(line.content()));
        true
    })?;

    Ok((
        text,
        stats.files_changed(),
        stats.insertions(),
        stats.deletions(),
    ))
}

/// Every patch-record file this unit owns, read from
/// `re/patches/{binary_dir}/{function_dir}/`. The binary directory is
/// matched with the same case-insensitive rule as the logs; a corrupt or
/// unreadable record is no record at all.
fn scan_patch_records(repo_path: &std::path::Path, unit: &UnitOfWork) -> Vec<PatchRecord> {
    let patches = repo_path.join("re").join("patches");
    let Some(binary_dirs) = std::fs::read_dir(&patches).ok() else {
        return Vec::new();
    };
    let Some(function) = unit.function.as_deref() else {
        return Vec::new();
    };
    let mut records = Vec::new();
    for dir in binary_dirs.flatten() {
        let dir_name = dir.file_name().to_string_lossy().into_owned();
        if !binary_matches(&dir_name, unit.binary.as_str()) {
            continue;
        }
        let Some(files) = std::fs::read_dir(dir.path().join(function)).ok() else {
            continue;
        };
        for file in files.flatten() {
            let name = file.file_name().to_string_lossy().into_owned();
            if !name.ends_with(".json") {
                continue;
            }
            let Ok(text) = std::fs::read_to_string(file.path()) else {
                continue;
            };
            if let Ok(record) = serde_json::from_str::<PatchRecord>(&text) {
                records.push(record);
            }
        }
    }
    records
}

/// Fold one attempt's facts and log entries into its wire metadata.
/// Absent sources leave their fields absent — the honest degradation the
/// ticket demands.
fn attempt_metadata(
    unit: &UnitOfWork,
    fact: &AttemptFacts,
    token_entries: &[TokenUsageEntry],
    fault_entries: &[FaultEvent],
) -> AttemptMetadata {
    let token = token_entries.iter().find(|entry| {
        names_attempt(
            entry.binary.as_str(),
            &entry.function,
            entry.attempt,
            unit,
            fact.attempt,
        )
    });
    // A patch *request* record is a reviewer's note-to-self written before
    // the attempt it names has run — its outcome fields are placeholders.
    // It proves the attempt exists (its branch name still joins above),
    // but reporting its empty errors as "compiled" would invent an
    // outcome the disk never recorded, so it answers no metadata at all.
    let patch = fact
        .patch
        .as_ref()
        .filter(|record| record.patch_request.is_none());

    let strategy = token.map(|entry| entry.strategy.clone()).or_else(|| {
        fault_entries
            .iter()
            .find(|event| {
                names_attempt(
                    event.binary.as_str(),
                    &event.function,
                    event.attempt,
                    unit,
                    fact.attempt,
                )
            })
            .map(|event| event.strategy.clone())
    });

    // The patch record's own timestamp wins; the token log's is the
    // fallback, formatted as RFC 3339 UTC like the records store it.
    let committed_at = patch
        .filter(|record| !record.committed_at.is_empty())
        .map(|record| record.committed_at.clone())
        .or_else(|| {
            token.and_then(|entry| {
                chrono::DateTime::<chrono::Utc>::from_timestamp(entry.timestamp as i64, 0)
                    .map(|when| when.to_rfc3339())
            })
        });

    AttemptMetadata {
        attempt: fact.attempt,
        branch: fact.branch.clone(),
        strategy,
        context_tier: token
            .map(|entry| entry.context_tier.clone())
            .filter(|tier| !tier.is_empty()),
        tokens_used: token.map(|entry| entry.tokens_used),
        success: token.map(|entry| entry.success),
        compiled: patch.map(|record| record.compilation_errors.is_empty()),
        compilation_errors: patch.map(|record| record.compilation_errors.clone()),
        tests_failed: patch
            .map(|record| record.test_failures.len())
            .filter(|count| *count > 0),
        test_failures: patch
            .map(|record| record.test_failures.clone())
            .filter(|failures| !failures.is_empty()),
        commit_hash: patch
            .map(|record| record.commit_hash.clone())
            .filter(|hash| !hash.is_empty()),
        committed_at,
    }
}

/// The (binary, function, attempt) triple join, shared by the token and
/// fault logs: case-insensitive on the binary, verbatim on the function,
/// exact on the attempt.
fn names_attempt(
    entry_binary: &str,
    entry_function: &str,
    entry_attempt: u32,
    unit: &UnitOfWork,
    attempt: u32,
) -> bool {
    entry_attempt == attempt
        && binary_matches(entry_binary, unit.binary.as_str())
        && Some(entry_function) == unit.function.as_deref()
}

#[cfg(test)]
mod tests {
    use super::*;
    use calxgloss_types::{BinaryIdentity, WorkKind};

    fn make_unit(binary: &str, function: &str) -> UnitOfWork {
        UnitOfWork {
            id: format!("{binary}/{function}/v2"),
            name: format!("{binary}!{function}"),
            kind: WorkKind::FunctionTranslation,
            binary: BinaryIdentity::new(binary),
            function: Some(function.to_string()),
            attempt: 2,
            status: calxgloss_types::ReviewStatus::PendingReview,
            accepted: false,
            unit_confidence: None,
            baseline_tests_passed: None,
            baseline_tests_total: None,
            verification_tests_passed: None,
            verification_tests_total: None,
            llm_model: None,
            context_tier: None,
            dependencies: Vec::new(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            known_gaps: Vec::new(),
            stale: calxgloss_types::dashboard::Staleness::Fresh,
        }
    }

    /// A git workspace with the fixture unit's two branches plus patch
    /// records for v1 and v2, and a v3 record with no branch — the union
    /// shape the join must reproduce.
    fn seeded_workspace() -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().expect("tempdir");
        let repo_path = dir.path().to_path_buf();
        let git = GitManager::init_repo(&repo_path, None).expect("init repo");
        for attempt in [1, 2] {
            git.create_branch("game_logic.dll", "DrawPrimitive", attempt, None)
                .expect("branch");
        }
        let patch_dir = repo_path
            .join("re")
            .join("patches")
            .join("game_logic.dll")
            .join("DrawPrimitive");
        std::fs::create_dir_all(&patch_dir).expect("patch dir");
        write_patch_record(&patch_dir, 1, "abc123", "2025-09-28T10:00:00Z", &[], &[]);
        write_patch_record(
            &patch_dir,
            2,
            "def456",
            "2025-09-28T11:30:00Z",
            &["mismatched types"],
            &["shader_constant_map_wrong"],
        );
        write_patch_record(&patch_dir, 3, "ghi789", "2025-09-28T12:00:00Z", &[], &[]);
        (dir, repo_path)
    }

    fn write_patch_record(
        patch_dir: &std::path::Path,
        attempt: u32,
        commit_hash: &str,
        committed_at: &str,
        compilation_errors: &[&str],
        test_failures: &[&str],
    ) {
        let record = serde_json::json!({
            "binary": "game_logic.dll",
            "function": "DrawPrimitive",
            "attempt": attempt,
            "branch_name": format!("re/game_logic.dll/DrawPrimitivev{attempt}"),
            "committed_at": committed_at,
            "error_message": "",
            "compilation_errors": compilation_errors,
            "test_failures": test_failures,
            "commit_hash": commit_hash,
        });
        std::fs::write(
            patch_dir.join(format!("v{attempt}.json")),
            serde_json::to_string(&record).expect("record serializes"),
        )
        .expect("record written");
    }

    fn write_json_file(path: &std::path::Path, value: &serde_json::Value) {
        std::fs::create_dir_all(path.parent().expect("parent dir")).expect("analysis dir");
        std::fs::write(path, serde_json::to_string(value).expect("serializes")).expect("written");
    }

    #[test]
    fn attempt_set_is_the_union_of_branches_and_patch_records() {
        let (_dir, repo_path) = seeded_workspace();
        let response =
            collect_unit_attempts(&repo_path, &make_unit("game_logic.dll", "DrawPrimitive"))
                .expect("join succeeds");
        let attempts: Vec<u32> = response.attempts.iter().map(|a| a.attempt).collect();
        assert_eq!(
            attempts,
            [1, 2, 3],
            "branches 1–2 plus the branch-less v3 record"
        );
        assert!(
            response.comparable,
            "two or more attempts make a diff possible"
        );

        let v1 = response
            .attempts
            .iter()
            .find(|a| a.attempt == 1)
            .expect("v1");
        assert_eq!(
            v1.branch.as_deref(),
            Some("re/game_logic.dll/DrawPrimitivev1")
        );
        assert_eq!(v1.commit_hash.as_deref(), Some("abc123"));
        assert_eq!(v1.committed_at.as_deref(), Some("2025-09-28T10:00:00Z"));
        assert_eq!(v1.compiled, Some(true));
        assert_eq!(
            v1.tests_failed, None,
            "zero failures stays absent, not zeroed"
        );
        assert_eq!(v1.test_failures, None);
        assert_eq!(
            v1.strategy, None,
            "no log names a strategy — absent, not guessed"
        );

        let v2 = response
            .attempts
            .iter()
            .find(|a| a.attempt == 2)
            .expect("v2");
        assert_eq!(v2.compiled, Some(false));
        assert_eq!(
            v2.compilation_errors.as_deref(),
            Some(&["mismatched types".to_string()][..])
        );
        assert_eq!(v2.tests_failed, Some(1));
        assert_eq!(
            v2.test_failures.as_deref(),
            Some(&["shader_constant_map_wrong".to_string()][..])
        );

        let v3 = response
            .attempts
            .iter()
            .find(|a| a.attempt == 3)
            .expect("v3");
        assert_eq!(
            v3.branch.as_deref(),
            Some("re/game_logic.dll/DrawPrimitivev3"),
            "the record's own branch_name names the branch even though it is gone"
        );
    }

    #[test]
    fn other_units_branches_and_records_never_join() {
        let (_dir, repo_path) = seeded_workspace();
        let git = GitManager::open(&repo_path).expect("open");
        git.create_branch("game_logic.dll", "UpdateScene", 1, None)
            .expect("other function branch");
        git.create_branch("other.dll", "DrawPrimitive", 1, None)
            .expect("other binary branch");

        let response =
            collect_unit_attempts(&repo_path, &make_unit("game_logic.dll", "DrawPrimitive"))
                .expect("join succeeds");
        let attempts: Vec<u32> = response.attempts.iter().map(|a| a.attempt).collect();
        assert_eq!(attempts, [1, 2, 3], "only this unit's attempts join");
    }

    #[test]
    fn token_log_joins_on_the_case_insensitive_triple() {
        let (_dir, repo_path) = seeded_workspace();
        write_json_file(
            &token_usage_log_path(&repo_path),
            &serde_json::json!({
                "entries": [
                    {
                        "binary": "GAME_LOGIC.DLL",
                        "function": "DrawPrimitive",
                        "attempt": 2,
                        "strategy": "escalate",
                        "tokens_used": 2500,
                        "success": true,
                        "timestamp": 1759059000,
                        "context_tier": "with_tests"
                    },
                    {
                        "binary": "game_logic.dll",
                        "function": "UpdateScene",
                        "attempt": 2,
                        "strategy": "initial",
                        "tokens_used": 999,
                        "success": true,
                        "timestamp": 1759059000
                    }
                ]
            }),
        );
        let response =
            collect_unit_attempts(&repo_path, &make_unit("game_logic.dll", "DrawPrimitive"))
                .expect("join succeeds");
        let v2 = response
            .attempts
            .iter()
            .find(|a| a.attempt == 2)
            .expect("v2");
        assert_eq!(v2.strategy.as_deref(), Some("escalate"));
        assert_eq!(v2.context_tier.as_deref(), Some("with_tests"));
        assert_eq!(v2.tokens_used, Some(2500));
        assert_eq!(v2.success, Some(true));
        let v1 = response
            .attempts
            .iter()
            .find(|a| a.attempt == 1)
            .expect("v1");
        assert_eq!(
            v1.tokens_used, None,
            "the other function's entry never joins"
        );
    }

    #[test]
    fn fault_log_is_the_strategy_fallback() {
        let (_dir, repo_path) = seeded_workspace();
        write_json_file(
            &fault_log_path(&repo_path),
            &serde_json::json!({
                "entries": [
                    {
                        "binary": "game_logic.dll",
                        "function": "DrawPrimitive",
                        "attempt": 1,
                        "strategy": "compile_fix",
                        "category": "infinite_loop",
                        "severity": "critical",
                        "description": "build failed",
                        "recovery": "retry",
                        "timestamp": 1759053600
                    }
                ]
            }),
        );
        let response =
            collect_unit_attempts(&repo_path, &make_unit("game_logic.dll", "DrawPrimitive"))
                .expect("join succeeds");
        let v1 = response
            .attempts
            .iter()
            .find(|a| a.attempt == 1)
            .expect("v1");
        assert_eq!(v1.strategy.as_deref(), Some("compile_fix"));
        assert_eq!(v1.tokens_used, None, "the fault log carries no token count");
    }

    #[test]
    fn corrupt_logs_leave_metadata_absent_not_zeroed() {
        let (_dir, repo_path) = seeded_workspace();
        let analysis = repo_path.join("re").join("analysis");
        std::fs::create_dir_all(&analysis).expect("analysis dir");
        std::fs::write(analysis.join("token_usage.json"), "{ not json").expect("corrupt log");
        std::fs::write(analysis.join("fault_log.json"), "nope").expect("corrupt log");

        let response =
            collect_unit_attempts(&repo_path, &make_unit("game_logic.dll", "DrawPrimitive"))
                .expect("join succeeds");
        for attempt in &response.attempts {
            assert_eq!(attempt.strategy, None);
            assert_eq!(attempt.context_tier, None);
            assert_eq!(attempt.tokens_used, None);
            assert_eq!(attempt.success, None);
            // Patch-record fields survive the corrupt logs untouched.
            assert!(attempt.commit_hash.is_some());
        }
    }

    #[test]
    fn prompt_strategy_log_never_joins_a_function_unit() {
        // Its entries carry no function field — joining them on a
        // function-scoped triple would invent identity, so the log is
        // excluded even when it names the binary and attempt.
        let (_dir, repo_path) = seeded_workspace();
        write_json_file(
            &super::super::process::prompt_strategy_log_path(&repo_path),
            &serde_json::json!({
                "entries": [
                    {
                        "binary": "game_logic.dll",
                        "attempt": 1,
                        "strategy": "full_module",
                        "timestamp": 1759053600
                    }
                ]
            }),
        );
        let response =
            collect_unit_attempts(&repo_path, &make_unit("game_logic.dll", "DrawPrimitive"))
                .expect("join succeeds");
        let v1 = response
            .attempts
            .iter()
            .find(|a| a.attempt == 1)
            .expect("v1");
        assert_eq!(v1.strategy, None, "the prompt-strategy log is not a source");
    }

    #[test]
    fn patch_request_records_answer_identity_only() {
        // The request-patch action writes a placeholder record for the
        // next attempt before it has run — reporting its empty errors as
        // "compiled" would invent an outcome the disk never recorded.
        let (_dir, repo_path) = seeded_workspace();
        let patch_dir = repo_path
            .join("re")
            .join("patches")
            .join("game_logic.dll")
            .join("DrawPrimitive");
        let request = serde_json::json!({
            "binary": "game_logic.dll",
            "function": "DrawPrimitive",
            "attempt": 4,
            "branch_name": "re/game_logic.dll/DrawPrimitivev4",
            "committed_at": "2025-09-29T09:00:00Z",
            "error_message": "fix the shader mapping",
            "compilation_errors": [],
            "test_failures": [],
            "commit_hash": "",
            "patch_request": "fix the shader mapping",
        });
        std::fs::write(
            patch_dir.join("v4.json"),
            serde_json::to_string(&request).expect("record serializes"),
        )
        .expect("record written");

        let response =
            collect_unit_attempts(&repo_path, &make_unit("game_logic.dll", "DrawPrimitive"))
                .expect("join succeeds");
        let v4 = response
            .attempts
            .iter()
            .find(|a| a.attempt == 4)
            .expect("v4");
        assert_eq!(
            v4.branch.as_deref(),
            Some("re/game_logic.dll/DrawPrimitivev4"),
            "the request still proves the attempt exists"
        );
        assert_eq!(v4.compiled, None, "nothing has compiled yet — say nothing");
        assert_eq!(v4.compilation_errors, None);
        assert_eq!(v4.commit_hash, None);
        assert_eq!(
            v4.committed_at, None,
            "the request timestamp is not a commit timestamp"
        );
    }

    #[test]
    fn single_attempt_units_answer_not_comparable() {
        let dir = tempfile::tempdir().expect("tempdir");
        let repo_path = dir.path().to_path_buf();
        let git = GitManager::init_repo(&repo_path, None).expect("init repo");
        git.create_branch("game_logic.dll", "UpdateScene", 1, None)
            .expect("branch");
        let response =
            collect_unit_attempts(&repo_path, &make_unit("game_logic.dll", "UpdateScene"))
                .expect("join succeeds");
        assert_eq!(response.attempts.len(), 1);
        assert!(!response.comparable);
        assert_eq!(response.attempts[0].strategy, None);
    }
}
