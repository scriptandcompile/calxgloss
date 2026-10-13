//! Response types for the review dashboard API.

use axum::http::StatusCode;
use calxgloss_types::{
    BinaryIdentity, BinaryProgress, FaultCategory, FaultEvent, FaultSeverity, PhaseProgress,
    PhaseRecord, PipelinePhase, PipelineState, ReviewDashboard, ReviewStatus, TokenUsageEntry,
    TranslationPhase, UnitOfWork,
};
use serde::{Deserialize, Serialize};

/// Wrapper for successful API responses carrying the full dashboard.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardResponse {
    pub success: bool,
    pub dashboard: ReviewDashboard,
    /// Optional queue metadata computed at request time.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub queue_metadata: Option<QueueMetadata>,
    /// Queue effort estimates (issue #64): unit_id → average seconds per
    /// attempt from the token-usage log — the unit's own durations when it
    /// has them, otherwise the global average. Empty (and omitted from the
    /// payload) when the log carries no durations; the queue shows `—` then.
    #[serde(default, skip_serializing_if = "std::collections::HashMap::is_empty")]
    pub queue_effort: std::collections::HashMap<String, u64>,
    /// Binary counts per classification category (issue #66), sourced from
    /// the `re/classify` artifacts. Always lists all six categories.
    #[serde(default)]
    pub binary_categories: Vec<CategoryCount>,
    /// Aggregate quality metrics over the dashboard units (issue #66).
    #[serde(default)]
    pub quality_summary: QualitySummary,
    /// Token consumption totals from the pipeline usage log (issue #66).
    /// `None` when no usage has been recorded — the budget visual then
    /// says so instead of showing a fabricated zero.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_usage: Option<TokenUsageSummary>,
    /// The persisted manual queue overlay (issue #74): the reviewer's manual
    /// order and per-unit priorities. Empty when nothing has been recorded.
    #[serde(default)]
    pub queue_overlay: QueueOverlay,
    /// The effective queue order (issue #74): dependency order with the
    /// overlay breaking ties — unit ids in the order the queue view renders.
    #[serde(default)]
    pub queue_order: Vec<String>,
}

impl DashboardResponse {
    pub fn ok(dashboard: ReviewDashboard) -> Self {
        Self {
            success: true,
            dashboard,
            queue_metadata: None,
            queue_effort: std::collections::HashMap::new(),
            binary_categories: Vec::new(),
            quality_summary: QualitySummary::default(),
            token_usage: None,
            queue_overlay: QueueOverlay::default(),
            queue_order: Vec::new(),
        }
    }
}

/// Count of workspace binaries classified into one category (issue #66).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CategoryCount {
    /// The category these binaries were classified into.
    pub category: calxgloss_types::DllCategory,
    /// How many classified binaries fall into this category.
    pub count: usize,
}

/// Aggregate quality metrics over the dashboard units (issue #66). Each
/// rate is `None` when no unit carries the underlying data, so the
/// dashboard renders `—` rather than a fabricated zero.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct QualitySummary {
    /// Mean of the units' `unit_confidence`; `None` when no unit reports one.
    pub avg_unit_confidence: Option<f32>,
    /// Baseline tests passed / total summed across all units; `None` when no
    /// unit carries baseline counts.
    pub baseline_pass_rate: Option<f32>,
    /// Verification tests passed / total summed across all units; `None`
    /// when no unit carries verification counts.
    pub verification_pass_rate: Option<f32>,
}

/// Token consumption totals from the pipeline usage log (issue #66).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TokenUsageSummary {
    /// Total tokens consumed across every logged call.
    pub total_tokens: u64,
    /// Tokens consumed by calls that succeeded.
    pub successful_tokens: u64,
    /// Tokens consumed by calls that failed.
    pub failed_tokens: u64,
    /// Number of logged calls.
    pub calls: usize,
}

/// Wrapper for the dependency graph response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyGraphResponse {
    pub success: bool,
    pub graph: calxgloss_types::DependencyGraph,
}

impl DependencyGraphResponse {
    pub fn ok(graph: calxgloss_types::DependencyGraph) -> Self {
        Self {
            success: true,
            graph,
        }
    }
}

/// Wrapper for unit detail responses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnitResponse {
    pub success: bool,
    pub unit: UnitResponseInner,
}

/// Detailed information for a single unit of work.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnitResponseInner {
    /// Unique identifier for this unit of work.
    pub id: String,
    /// Display name (e.g., "DirectX_DrawPrimitive").
    pub name: String,
    /// Kind of work (e.g., "Function Translation").
    pub kind: String,
    /// Associated DLL name.
    pub binary: BinaryIdentity,
    /// Associated function name (if applicable).
    pub function: Option<String>,
    /// Attempt number (v1, v2, v3, etc.).
    pub attempt: u32,
    /// Current review status (e.g., "pending_review", "accepted").
    pub status: String,
    /// Whether this unit has been accepted and merged to main.
    pub accepted: bool,
    /// Unit confidence score (0.0 to 1.0).
    pub unit_confidence: Option<f32>,
    /// Number of baseline tests that passed.
    pub baseline_tests_passed: Option<usize>,
    /// Total number of baseline tests.
    pub baseline_tests_total: Option<usize>,
    /// Number of verification tests that passed.
    pub verification_tests_passed: Option<usize>,
    /// Total number of verification tests.
    pub verification_tests_total: Option<usize>,
    /// LLM model used for translation.
    pub llm_model: Option<String>,
    /// Context tier used for the translation (0–4).
    pub context_tier: Option<usize>,
    /// List of branch names this unit depends on.
    pub dependencies: Vec<String>,
    /// When this unit was created (RFC 3339).
    pub created_at: String,
    /// When this unit was last updated (RFC 3339).
    pub updated_at: String,
    /// Known gaps or caveats that could not be verified.
    pub known_gaps: Vec<String>,
    /// Staleness indicator: "fresh", "stale (2d 3h)", etc.
    pub stale: String,
    /// Git diff summary between this unit's branch and main.
    pub diff_summary: DiffSummary,
    /// Attempt history from patch records.
    pub attempt_history: Vec<AttemptRecord>,
    /// Total number of revisions (attempts) for this unit.
    pub revision_count: usize,
    /// Position of this unit in the dependency-ordered review queue.
    pub queue_position: QueuePosition,
    /// Run-process telemetry: context tier, faults, tokens, retry strategies.
    pub process: UnitProcess,
    /// Windows API mappings and caller/callee context for the unit's function.
    pub analysis: UnitAnalysis,
}

// ─── Unit analysis context types (issue #73) ─────────────────────────

/// Windows API mappings and call-graph context for a unit's function, read
/// from the per-function analysis artifact and the per-binary call-graph
/// record already stored under `re/analysis/`. Missing or corrupt artifacts
/// degrade to empty sections.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UnitAnalysis {
    /// Windows API calls identified for this function, with category and PAL mapping.
    pub api_mappings: Vec<ApiMappingRecord>,
    /// Who calls this function and what it calls, by name.
    pub call_graph: CallGraphContext,
}

/// A Windows API call identified for a function, with its PAL/crate mapping.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiMappingRecord {
    /// API name (e.g., "CreateFileA").
    pub name: String,
    /// API category (shared `ApiCategory` vocabulary, as recorded in the artifact).
    pub category: String,
    /// PAL/crate mapping target (e.g., "std::fs::File::open").
    pub pal_mapping: String,
}

/// Caller/callee names for a function, resolved from the per-binary call-graph
/// record. Caller addresses that no function in the graph owns render as hex
/// addresses rather than being dropped.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CallGraphContext {
    /// Names of functions that call this function, in graph order.
    pub callers: Vec<String>,
    /// Names of functions this function calls, in graph order.
    pub callees: Vec<String>,
}

// ─── Unit process telemetry types (issue #62) ────────────────────────

/// Run-process telemetry for a single unit, derived from the token-usage
/// log, fault log, and Ghidra analysis artifacts already stored under
/// `re/analysis/`. Missing or corrupt artifacts degrade to empty sections.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnitProcess {
    /// Context tier the unit was translated at, with rationale and history.
    pub tier: TierSection,
    /// Faults detected for this unit, in chronological order.
    pub faults: Vec<FaultRecord>,
    /// Token usage totals and per-attempt breakdown.
    pub tokens: TokenSection,
    /// Retry strategies used for this unit with their success rates.
    pub strategies: Vec<StrategyRecord>,
}

/// The context-tier section of the unit detail panel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TierSection {
    /// Tier number (0–4), or `None` when no telemetry records a tier.
    pub tier: Option<usize>,
    /// Tier label (e.g., "with_tests").
    pub label: Option<String>,
    /// Human-readable description of what the tier sends to the LLM.
    pub description: Option<String>,
    /// Whether the pipeline escalated through more than one tier.
    pub escalated: bool,
    /// Why this tier was selected (complexity, API call count), if the
    /// Ghidra analysis artifact is available.
    pub rationale: Option<TierRationale>,
    /// Per-attempt tier/strategy history from the token-usage log.
    pub attempts: Vec<TierAttemptRecord>,
}

/// Why a function's context tier was selected, recomputed from the
/// Ghidra analysis artifact.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TierRationale {
    /// Detected function complexity label (e.g., "standard").
    pub complexity: String,
    /// Number of Windows API call sites identified by Ghidra.
    pub api_call_count: usize,
}

/// One attempt's tier and retry strategy from the token-usage log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TierAttemptRecord {
    /// The 1-based attempt number.
    pub attempt: u32,
    /// Retry strategy label used for this attempt.
    pub strategy: String,
    /// Context tier label used for this attempt (empty when untracked).
    pub tier: String,
}

/// A single fault detected for this unit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FaultRecord {
    /// The attempt the fault was detected in.
    pub attempt: u32,
    /// Retry strategy active when the fault was detected.
    pub strategy: String,
    /// Fault category (shared `FaultCategory` vocabulary).
    pub category: FaultCategory,
    /// Fault severity ("warning", "error", "critical").
    pub severity: FaultSeverity,
    /// Human-readable description of what was detected.
    pub description: String,
    /// Recovery action taken or recommended.
    pub recovery: String,
    /// When the fault was detected (Unix seconds).
    pub timestamp: u64,
}

/// Token usage totals for a unit across all its attempts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenSection {
    /// Total tokens consumed by all attempts.
    pub total_tokens: usize,
    /// Tokens consumed by attempts that ultimately succeeded.
    pub successful_tokens: usize,
    /// Tokens consumed by attempts that failed.
    pub failed_tokens: usize,
    /// Number of recorded attempts.
    pub attempts: usize,
    /// Per-attempt breakdown, ordered by attempt number.
    pub per_attempt: Vec<TokenAttemptRecord>,
}

/// Token usage for a single attempt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenAttemptRecord {
    /// The 1-based attempt number.
    pub attempt: u32,
    /// Retry strategy label used for this attempt.
    pub strategy: String,
    /// Context tier label used for this attempt (empty when untracked).
    pub tier: String,
    /// Tokens consumed by this attempt.
    pub tokens_used: usize,
    /// Whether this attempt ultimately succeeded.
    pub success: bool,
    /// When the entry was recorded (Unix seconds).
    pub timestamp: u64,
}

/// Aggregate performance of one retry strategy for this unit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StrategyRecord {
    /// Retry strategy label (e.g., "initial", "compile_fix").
    pub strategy: String,
    /// Number of attempts that used this strategy.
    pub attempts: usize,
    /// How many of those attempts succeeded.
    pub successes: usize,
    /// Successes divided by attempts (0.0–1.0).
    pub success_rate: f64,
}

impl From<&FaultEvent> for FaultRecord {
    /// Projects a shared fault-log event onto the unit detail wire format,
    /// keeping the shared category/severity vocabulary unchanged.
    fn from(event: &FaultEvent) -> Self {
        Self {
            attempt: event.attempt,
            strategy: event.strategy.clone(),
            category: event.category.clone(),
            severity: event.severity.clone(),
            description: event.description.clone(),
            recovery: event.recovery.clone(),
            timestamp: event.timestamp,
        }
    }
}

impl From<&TokenUsageEntry> for TierAttemptRecord {
    /// Projects a token-usage entry onto the tier-history row (attempt,
    /// strategy, tier label).
    fn from(entry: &TokenUsageEntry) -> Self {
        Self {
            attempt: entry.attempt,
            strategy: entry.strategy.clone(),
            tier: entry.context_tier.clone(),
        }
    }
}

impl From<&TokenUsageEntry> for TokenAttemptRecord {
    /// Projects a token-usage entry onto the per-attempt token row.
    fn from(entry: &TokenUsageEntry) -> Self {
        Self {
            attempt: entry.attempt,
            strategy: entry.strategy.clone(),
            tier: entry.context_tier.clone(),
            tokens_used: entry.tokens_used,
            success: entry.success,
            timestamp: entry.timestamp,
        }
    }
}

/// Summary of a git diff between a branch and main.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffSummary {
    pub files_changed: usize,
    pub insertions: usize,
    pub deletions: usize,
}

// ─── Line-by-line diff types ──────────────────────────────────────────

/// Type of a diff line.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiffLineType {
    /// Context line (unchanged).
    Context,
    /// Added line.
    Addition,
    /// Removed line.
    Deletion,
}

/// A single line in a diff hunks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffLine {
    /// Line type.
    #[serde(rename = "type")]
    pub kind: DiffLineType,
    /// The line content (without the type-prefix character like + / - / space).
    pub content: String,
    /// Line number in the new file (None for deletions).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_line: Option<usize>,
    /// Line number in the old file (None for additions).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub old_line: Option<usize>,
}

/// A contiguous group of diff lines.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffHunk {
    /// New file start line.
    pub new_start: usize,
    /// New file line count in this hunk.
    pub new_lines: usize,
    /// Old file start line.
    pub old_start: usize,
    /// Old file line count in this hunk.
    pub old_lines: usize,
    /// Optional header text from git (e.g. `@@ -1,3 +1,4 @@ fn foo`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub header: Option<String>,
    /// The individual lines in this hunk.
    pub lines: Vec<DiffLine>,
}

/// A single file's diff content.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffFile {
    /// File path in the repo.
    pub path: String,
    /// Old path before rename/move (if applicable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub old_path: Option<String>,
    /// Whether this file was added (no old side).
    pub added: bool,
    /// Whether this file was deleted (no new side).
    pub deleted: bool,
    /// Whether this file was renamed.
    pub renamed: bool,
    /// The diff hunks for this file.
    pub hunks: Vec<DiffHunk>,
}

/// Information about a single translation attempt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttemptRecord {
    pub attempt: u32,
    pub compiled: bool,
    pub compilation_errors: Vec<String>,
    pub tests_passed: usize,
    pub tests_total: usize,
    pub failed_tests: Vec<String>,
    pub commit_hash: String,
    pub committed_at: String,
}

/// Metadata about the review queue's current state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueueMetadata {
    /// Total number of units in the queue (queued + pending + blocked).
    pub total: usize,
    /// Number of units awaiting initial review (Queued).
    pub queued: usize,
    /// Number of units under human review (PendingReview).
    pub pending_review: usize,
    /// Number of units blocked by unmet dependencies.
    pub blocked: usize,
}

/// Position of a unit within the dependency-ordered review queue.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueuePosition {
    /// Zero-based index in the dependency-ordered queue.
    /// `None` if the unit is already accepted or not in the active queue.
    pub index: Option<usize>,
    /// Total number of units in the active queue.
    pub total: usize,
}

/// Manual review priority for a queue unit (issue #74). The dependency
/// ordering still governs; priority only breaks ties between units the
/// dependency graph leaves at the same depth.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum QueuePriority {
    /// Review this unit first among its tie group.
    High,
    /// The default — no manual preference recorded.
    #[default]
    Normal,
    /// Review this unit last among its tie group.
    Low,
}

/// The persisted manual layer over the dependency-ordered queue (issue #74).
/// Stored at `re/review/queue_overlay.json` so both order and priorities
/// survive a server restart.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct QueueOverlay {
    /// Unit ids in the reviewer's manual order. Units missing from the list
    /// keep their dependency-order position within their tie group.
    #[serde(default)]
    pub order: Vec<String>,
    /// Per-unit priority; a unit with no entry is [`QueuePriority::Normal`].
    #[serde(default)]
    pub priorities: std::collections::HashMap<String, QueuePriority>,
}

/// Request body for `PUT /api/queue/overlay` (issue #74). Either field may
/// be omitted — an omitted field keeps its persisted value, a present one
/// replaces it wholesale (the frontend always sends the full current list).
#[derive(Debug, Clone, Default, Deserialize)]
pub struct QueueOverlayUpdate {
    /// The full manual order to persist, when present.
    pub order: Option<Vec<String>>,
    /// The full priority map to persist, when present.
    pub priorities: Option<std::collections::HashMap<String, QueuePriority>>,
}

/// Response for the queue overlay endpoints (issue #74): the persisted
/// overlay plus the effective queue order it produces, so the frontend can
/// re-render from the server's answer (a drag that would violate a
/// dependency snaps back to the legal position).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueueOverlayResponse {
    pub success: bool,
    /// The overlay as now persisted.
    pub overlay: QueueOverlay,
    /// Unit ids in effective queue order (dependency order, overlay ties).
    pub queue_order: Vec<String>,
}

/// Response for the review queue endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueueResponse {
    /// The sorted queue of units waiting for review.
    pub queue: Vec<QueueEntry>,
    /// Metadata about the queue state.
    pub metadata: QueueMetadata,
}

/// A single entry in the dependency-ordered review queue.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueueEntry {
    /// Unit ID.
    pub id: String,
    /// Display name.
    pub name: String,
    /// Kind of work.
    pub kind: String,
    /// Associated DLL.
    pub binary: BinaryIdentity,
    /// Associated function (if applicable).
    pub function: Option<String>,
    /// Current review status.
    pub status: String,
    /// Staleness indicator.
    pub stale: String,
    /// Whether this unit is blocked by unmet dependencies.
    #[serde(default)]
    pub blocked: bool,
}

impl QueueResponse {
    /// Builds a queue response from a [`ReviewDashboard`] and a pre-computed
    /// effective order — dependency order with the queue overlay breaking
    /// ties, as produced by `handlers::queue_order` (issue #74).
    pub fn from_ordered(dashboard: &ReviewDashboard, ordered: &[&UnitOfWork]) -> Self {
        let total = ordered.len();

        let queue: Vec<QueueEntry> = ordered
            .iter()
            .map(|u| QueueEntry {
                id: u.id.clone(),
                name: u.name.clone(),
                kind: u.kind.to_string(),
                binary: u.binary.clone(),
                function: u.function.clone(),
                status: u.status.to_string(),
                stale: u.stale.to_string(),
                blocked: matches!(u.status, ReviewStatus::Blocked),
            })
            .collect();

        QueueResponse {
            queue,
            metadata: QueueMetadata {
                total,
                queued: dashboard.status_counts.queued,
                pending_review: dashboard.status_counts.pending_review,
                blocked: dashboard.status_counts.blocked,
            },
        }
    }
}

/// Response for review action endpoints (accept, send-back, patch).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionResponse {
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rejection_path: Option<String>,
}

// ─── GC / Branch archive types ─────────────────────────────────────────

/// A branch candidate for archival (stale, unmerged translation branch).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GcCandidate {
    /// Full branch name (e.g. "re/game_logic.dll/DrawSpritev3").
    pub branch: String,
    /// DLL name extracted from the branch.
    pub binary: BinaryIdentity,
    /// Function name, if present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub function: Option<String>,
    /// Attempt number.
    pub attempt: u32,
    /// Days since last commit.
    pub days_old: f64,
    /// RFC 3339 timestamp of the branch's last commit.
    pub last_commit: String,
}

/// Response for the GC candidates endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GcCandidatesResponse {
    pub success: bool,
    /// Stale branch candidates eligible for archival.
    pub candidates: Vec<GcCandidate>,
    /// Number of recent (non-stale) branches kept.
    pub recent_count: usize,
    /// Configured staleness threshold in days.
    pub threshold_days: u64,
}

/// Request body for the GC archive endpoint.
#[derive(Debug, Default, Deserialize)]
pub struct GcArchiveRequest {
    /// Branches to archive (empty = archive all candidates).
    #[serde(default)]
    pub branches: Vec<String>,
}

/// Result of a single archive operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GcArchiveResult {
    pub branch: String,
    pub success: bool,
    pub archive_ref: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Response for the GC archive endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GcArchiveResponse {
    pub success: bool,
    pub results: Vec<GcArchiveResult>,
    pub archived: usize,
    pub failed: usize,
}

// ─── Request types ─────────────────────────────────────────────────────

/// Request body for the send-back endpoint.
#[derive(Debug, Deserialize)]
pub struct SendBackRequest {
    /// The reason for sending the unit back.
    pub reason: String,
}

/// Request body for the patch endpoint.
#[derive(Debug, Deserialize)]
pub struct PatchRequest {
    /// Description of the specific issue to fix.
    pub issue: String,
}

/// Request body for the batch review-action endpoints (issue #78). The same
/// shape serves accept, send-back, and skip — only send-back reads `reason`.
#[derive(Debug, Deserialize)]
pub struct BatchActionRequest {
    /// The units the batch action applies to, in the order results come back.
    pub unit_ids: Vec<String>,
    /// Reason recorded on each send-back; omitted means "Needs revision",
    /// matching the per-unit endpoint's default.
    #[serde(default)]
    pub reason: Option<String>,
}

/// Outcome of applying a batch action to one unit. A unit that fails (not
/// found, already accepted, merge conflict) is reported here rather than
/// aborting the batch — the other units still get their action.
#[derive(Debug, Clone, Serialize)]
pub struct BatchItemResult {
    /// The unit this result belongs to.
    pub unit_id: String,
    /// Whether the action landed on this unit.
    pub success: bool,
    /// The action's message on success, the failure reason otherwise.
    pub message: String,
}

/// Response for the batch review-action endpoints: one result per requested
/// unit in request order, plus the success/failure tally.
#[derive(Debug, Clone, Serialize)]
pub struct BatchActionResponse {
    /// True when every requested unit got its action.
    pub success: bool,
    /// The batch action performed ("accept", "send_back", "skip").
    pub action: String,
    /// Per-unit outcomes, in the order the units were requested.
    pub results: Vec<BatchItemResult>,
    /// How many units the action landed on.
    pub succeeded: usize,
    /// How many units the action failed on.
    pub failed: usize,
}

// ─── Error types ───────────────────────────────────────────────────────

/// Server error type for API responses.
#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    #[error("Internal error: {0}")]
    Internal(String),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Bad request: {0}")]
    BadRequest(String),

    /// The endpoint is reachable but the server cannot perform the action —
    /// e.g. `PATCH /api/server/log-level` on a server started without a
    /// reloadable log filter.
    #[error("Service unavailable: {0}")]
    ServiceUnavailable(String),

    /// The request is valid but conflicts with the unit's current persisted
    /// state — e.g. a review action refused because a different action landed
    /// on the unit in the meantime (issue #86).
    #[error("Conflict: {0}")]
    Conflict(String),
}

// ─── Fault analytics (issue #125, W3.1) ────────────────────────────────

/// One fault from the persisted log, verbatim, carrying the full attempt
/// identity triple (binary, function, attempt) so a fault pattern can be
/// traced straight to a unit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FaultAnalyticsEntry {
    /// The DLL containing the affected function.
    pub binary: BinaryIdentity,
    /// The function name.
    pub function: String,
    /// Which translation attempt the fault was detected in (1-based).
    pub attempt: u32,
    /// Retry strategy active when the fault was detected.
    pub strategy: String,
    /// Fault category (shared `FaultCategory` vocabulary).
    pub category: FaultCategory,
    /// Fault severity ("warning", "error", "critical").
    pub severity: FaultSeverity,
    /// Human-readable description of what was detected.
    pub description: String,
    /// Recovery guidance attached to the fault, verbatim.
    pub recovery: String,
    /// When the fault was detected (Unix seconds).
    pub timestamp: u64,
}

/// `GET /api/faults` response: the retained fault events after filtering.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FaultAnalytics {
    /// The matching faults, oldest first.
    pub entries: Vec<FaultAnalyticsEntry>,
    /// How many faults the log holds before filtering — lets the view tell
    /// "no faults at all" from "no faults match the filters".
    pub total_in_log: usize,
}

/// A named count in a summary breakdown (one fault category or severity).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FaultCount {
    /// The breakdown key (the category or severity name).
    pub name: String,
    /// How many faults carry it.
    pub count: usize,
}

/// `GET /api/faults/summary` response: total faults broken down by
/// category and severity, computed over the filtered retained window.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FaultSummaryResponse {
    /// Total faults after filtering.
    pub total: usize,
    /// Counts per fault category, highest first (ties alphabetical).
    /// Categories with no faults are omitted — the breakdown names what
    /// actually happened.
    pub by_category: Vec<FaultCount>,
    /// Counts per severity in fixed warning → error → critical order,
    /// always all three so the severity cards never shift shape.
    pub by_severity: Vec<FaultCount>,
}

/// Fault count for one target binary (the `by-binary` bar chart row).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FaultBinaryCount {
    /// The target binary, identity verbatim.
    pub binary: BinaryIdentity,
    /// How many faults name it.
    pub count: usize,
}

/// `GET /api/faults/by-binary` response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FaultByBinaryResponse {
    /// Fault counts per target binary, highest first (ties alphabetical).
    pub binaries: Vec<FaultBinaryCount>,
}

/// `GET /api/faults/trend` response: the faults-per-day series with the
/// 3-day moving average, bucketed server-side so the chart and the API
/// report the same numbers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FaultTrendResponse {
    /// One bucket per UTC day from the first to the last matching fault
    /// date, gap days included with zero counts, oldest first. Empty when
    /// nothing matches — the honest "no data" shape, not a fabricated run
    /// of zeros.
    pub days: Vec<FaultTrendPoint>,
}

/// One day bucket of the faults trend.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FaultTrendPoint {
    /// The bucket day as `YYYY-MM-DD` (UTC).
    pub date: String,
    /// Faults detected that day.
    pub count: usize,
    /// Trailing 3-day moving average ending at this day: the mean of this
    /// day and the two preceding days *within the bucketed range*, so the
    /// first two points average fewer days rather than inventing zeros
    /// before the first fault.
    pub moving_average: f64,
}

// ─── Token usage analytics (issue #126, W3.2) ──────────────────────────

/// `GET /api/token-usage/summary` response: total tokens consumed split
/// into successful and failed attempts, computed over the filtered
/// retained window. No budget indicator — token budgets are a deferred
/// constraints concept, so the summary reports measured totals only.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenUsageSummaryResponse {
    /// Total tokens consumed after filtering.
    pub total_tokens: usize,
    /// Tokens consumed by attempts that ultimately succeeded.
    pub successful_tokens: usize,
    /// Tokens consumed by attempts that failed.
    pub failed_tokens: usize,
    /// Translation attempts in the filtered set.
    pub total_attempts: usize,
    /// How many attempts the log holds before filtering — lets the view
    /// tell "no usage at all" from "no usage in the selected range".
    pub total_in_log: usize,
}

/// Token usage for one target binary (the `by-binary` bar chart row).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenUsageBinaryShare {
    /// The target binary, identity verbatim.
    pub binary: BinaryIdentity,
    /// Tokens consumed by this binary's attempts.
    pub tokens: usize,
    /// Its share of the filtered total, as a percentage (0.0–100.0).
    pub share_percent: f64,
}

/// `GET /api/token-usage/by-binary` response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenUsageByBinaryResponse {
    /// Token totals per target binary, highest first (ties alphabetical).
    pub binaries: Vec<TokenUsageBinaryShare>,
}

/// Token usage for one context tier. The tier label is the entry's
/// verbatim `context_tier`; entries written before tier tracking carry an
/// empty label and form their own honest bucket.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenUsageTierStats {
    /// The context tier label.
    pub tier: String,
    /// Tokens consumed at this tier.
    pub tokens: usize,
    /// Attempts made at this tier.
    pub attempts: usize,
}

/// `GET /api/token-usage/by-tier` response — the breakdown the operator
/// uses to judge whether tier escalation pays for itself.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenUsageByTierResponse {
    /// Token totals per context tier, highest first (ties alphabetical).
    pub tiers: Vec<TokenUsageTierStats>,
}

/// Token usage for one retry strategy, with the success rate that shows
/// which recovery paths burn tokens and which ones work.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenUsageStrategyStats {
    /// The retry strategy label.
    pub strategy: String,
    /// Tokens consumed by attempts using this strategy.
    pub tokens: usize,
    /// Attempts using this strategy.
    pub attempts: usize,
    /// Attempts using this strategy that ultimately succeeded.
    pub successes: usize,
    /// Success rate as a percentage (0.0–100.0): successes over attempts.
    pub success_rate: f64,
}

/// `GET /api/token-usage/by-strategy` response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenUsageByStrategyResponse {
    /// Token totals per retry strategy, highest first (ties alphabetical).
    pub strategies: Vec<TokenUsageStrategyStats>,
}

// ─── Strategy analytics (issue #127, W3.3) ─────────────────────────────

/// `GET /api/strategy-analytics/by-strategy` response: the pass-rate
/// evidence per retry strategy, computed over the filtered retained window
/// of the prompt-strategy log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StrategyAnalyticsByStrategyResponse {
    /// Pass rates per retry strategy, most attempts first (ties alphabetical).
    pub strategies: Vec<StrategyAnalyticsStrategyStats>,
    /// How many attempts the log holds before filtering — lets the view
    /// tell "no attempts at all" from "no attempts in the selected range".
    pub total_in_log: usize,
}

/// Outcome counts for one retry strategy — the evidence for whether the
/// strategy earns its place in the retry ladder.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StrategyAnalyticsStrategyStats {
    /// The retry strategy label, verbatim from the log.
    pub strategy: String,
    /// Attempts made with this strategy.
    pub attempts: usize,
    /// Attempts with this strategy that ultimately succeeded.
    pub successes: usize,
    /// Attempts with this strategy that failed.
    pub failures: usize,
    /// Pass rate as a percentage (0.0–100.0): successes over attempts.
    pub pass_rate: f64,
}

/// `GET /api/strategy-analytics/by-category` response: pass rates broken
/// down by binary category, revealing whether one class of binary
/// systematically defeats the current strategies.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StrategyAnalyticsByCategoryResponse {
    /// Pass rates per binary category, most attempts first (ties alphabetical).
    pub categories: Vec<StrategyAnalyticsCategoryStats>,
    /// How many attempts the log holds before filtering.
    pub total_in_log: usize,
}

/// Outcome counts for one DLL category. The category name is the
/// `DllCategory` debug label — the same vocabulary the log's own
/// `compute_stats` aggregates use.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StrategyAnalyticsCategoryStats {
    /// The binary category label.
    pub category: String,
    /// Attempts made against binaries in this category.
    pub attempts: usize,
    /// Attempts against this category that ultimately succeeded.
    pub successes: usize,
    /// Attempts against this category that failed.
    pub failures: usize,
    /// Pass rate as a percentage (0.0–100.0): successes over attempts.
    pub pass_rate: f64,
}

// ─── LLM performance metrics (issue #128, W3.4) ────────────────────────

/// `GET /api/llm-metrics/summary` response: attempt-duration percentiles
/// from the token usage log's recorded durations, and timeout frequency
/// from the fault log — both computed over the filtered retained window.
/// The durations are attempt-level wall-clock seconds (compile and tests
/// included), never raw per-LLM-call latency; entries written before
/// duration tracking existed are excluded from the percentile math, never
/// imputed as zero.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmMetricsSummaryResponse {
    /// Translation attempts in the filtered token-log window.
    pub total_attempts: usize,
    /// Of those, the attempts that recorded a wall-clock duration — the
    /// only ones the percentiles are computed over.
    pub measured_attempts: usize,
    /// P50 attempt duration in whole seconds — `None` when nothing in the
    /// filtered set was measured, so the view renders an em dash rather
    /// than a fabricated number.
    pub p50_secs: Option<u64>,
    /// P95 attempt duration in whole seconds, same honesty rule.
    pub p95_secs: Option<u64>,
    /// P99 attempt duration in whole seconds, same honesty rule.
    pub p99_secs: Option<u64>,
    /// Timeout-kind resource-exhaustion faults in the filtered fault-log
    /// window.
    pub timeouts: usize,
    /// The timeouts per UTC day, gap-filled between the first and last
    /// timeout day, oldest first — bucketed server-side so the chart and
    /// the API agree. Empty when no timeout matches the filters.
    pub timeout_trend: Vec<LlmMetricsTimeoutPoint>,
    /// How many attempts the token log holds before filtering — lets the
    /// view tell "no attempts at all" from "no attempts in the selected
    /// range".
    pub total_in_log: usize,
}

/// One day bucket of the timeout trend.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmMetricsTimeoutPoint {
    /// The bucket day as `YYYY-MM-DD` (UTC).
    pub date: String,
    /// Timeout-kind faults detected that day.
    pub count: usize,
}

/// `GET /api/llm-metrics/by-tier` response: attempt duration correlated
/// by context tier — the evidence for whether tier escalation costs wall-
/// clock time as well as tokens.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmMetricsByTierResponse {
    /// Duration stats per context tier, most attempts first (ties
    /// alphabetical).
    pub tiers: Vec<LlmMetricsTierStats>,
    /// How many attempts the token log holds before filtering.
    pub total_in_log: usize,
}

/// Attempt duration for one context tier. The tier label is the entry's
/// verbatim `context_tier`; entries written before tier tracking carry an
/// empty label and form their own honest bucket. A tier whose attempts
/// recorded no durations carries `None` percentiles — unmeasured, never
/// imputed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmMetricsTierStats {
    /// The context tier label.
    pub tier: String,
    /// Attempts made at this tier.
    pub attempts: usize,
    /// Attempts at this tier that recorded a wall-clock duration.
    pub measured_attempts: usize,
    /// P50 attempt duration in whole seconds at this tier, `None` when
    /// nothing at the tier was measured.
    pub p50_secs: Option<u64>,
    /// P95 attempt duration in whole seconds at this tier — the timeout-
    /// relevant tail — `None` when nothing at the tier was measured.
    pub p95_secs: Option<u64>,
}

// ─── Binaries view (issue #130, W4.1) ──────────────────────────────────

/// `GET /api/binaries/list` response: one row per classified target
/// binary, the summary the Binaries view renders. Rows come only from
/// persisted history — classification records with the override layer
/// applied, the review dashboard's function units, and the token-usage
/// log — so plain `serve` and `live` answer identically.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinariesListResponse {
    /// The classified binaries, alphabetical by binary name. A workspace
    /// whose classification records are missing or corrupt honestly
    /// answers with an empty list — never a wall of zero rows.
    pub binaries: Vec<BinarySummaryRow>,
}

/// One classified binary's summary row. Category and strategy carry the
/// decision actually in force: the recorded classification with the
/// persisted override layer applied on top. Function counts cover the
/// review dashboard's function-translation units for this binary —
/// `functions_total = functions_done + functions_queued + functions_failed`
/// always holds, so no unit hides in an unshown bucket.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinarySummaryRow {
    /// The binary identity — the filename verbatim, as the classification
    /// record names it.
    pub binary: BinaryIdentity,
    /// The category in force (e.g. "WindowsOs", "ProjectSpecific").
    pub category: String,
    /// The strategy in force (e.g. "PalMapping", "CrateReplacement",
    /// "ReverseEngineer").
    pub strategy: String,
    /// Target crate for crate-replacement strategies, absent when the
    /// strategy names none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub crate_replacement: Option<String>,
    /// Whether the category/strategy shown comes from a persisted
    /// classification override rather than the recorded classification.
    pub overridden: bool,
    /// Function-translation units this binary owns.
    pub functions_total: usize,
    /// Units accepted and merged to main.
    pub functions_done: usize,
    /// Units not done and not failing — queued, pending review, in
    /// progress, blocked, or skipped.
    pub functions_queued: usize,
    /// Units a reviewer or the run left failing — sent back or awaiting
    /// a patch.
    pub functions_failed: usize,
    /// Tokens the token-usage log recorded for this binary — 0 when the
    /// log holds no attempts for it.
    pub tokens_used: usize,
}

/// `GET /api/binaries/{name}` response: the full detail the Binaries
/// view's expandable panel renders for one classified binary — the
/// classification decision actually in force (override layer applied, the
/// same fold the summary rows and the analyzer honor) and the binary's
/// per-function list with each function's review status, so a reviewer
/// can find stalled functions inside a binary. An unknown binary name
/// honestly 404s rather than answering with an empty shell.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryDetailResponse {
    /// The binary identity — the filename verbatim, as the classification
    /// record names it (the request may have spelled it differently).
    pub binary: BinaryIdentity,
    /// The category in force (e.g. "WindowsOs", "ProjectSpecific").
    pub category: String,
    /// The strategy in force (e.g. "PalMapping", "CrateReplacement",
    /// "ReverseEngineer").
    pub strategy: String,
    /// Target crate for crate-replacement strategies, absent when the
    /// strategy names none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub crate_replacement: Option<String>,
    /// Whether the category/strategy shown comes from a persisted
    /// classification override rather than the recorded classification.
    pub overridden: bool,
    /// Whether the decision in force marks the binary as never a
    /// translation target — the glossary rule, mirroring the analyzer:
    /// the flag or a `RuntimeLibrary` category.
    pub known_runtime: bool,
    /// The reason in force: the analyzer's synthesized override reason
    /// when an override is, or the recorded reason verbatim when it is
    /// not — an override carries no heuristic reasoning of its own.
    /// Absent when the record stored none and no override is in force.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Exported symbols the classification record counted.
    pub exports_count: usize,
    /// Imported symbols the classification record counted.
    pub imports_count: usize,
    /// The binary's function-translation units, alphabetical by function
    /// then attempt — the same dashboard units the summary row's counts
    /// fold, so this list's length is always the row's `functions_total`.
    pub functions: Vec<BinaryFunctionRow>,
}

/// One function-translation unit inside a binary, as the detail panel's
/// function list renders it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryFunctionRow {
    /// The function name, verbatim from the unit's branch identity.
    pub function: String,
    /// Which translation attempt this unit is (1-based) — the same
    /// function can appear once per attempt, each with its own status.
    pub attempt: u32,
    /// The unit's review status (e.g. "Accepted", "PendingReview").
    pub status: calxgloss_types::ReviewStatus,
}

// ─── Unit attempts view (issue #131, W4.5) ─────────────────────────────

/// `GET /api/units/{id}/attempts` response: the attempt list the unit
/// detail panel renders. The attempt set is exactly what the workspace
/// persisted — translation branches named for this unit plus patch-record
/// files under `re/patches/` — nothing invented, nothing dropped.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnitAttemptsResponse {
    /// The unit's id, echoed back (e.g. "game_logic.dll/DrawPrimitive/v2").
    pub unit_id: String,
    /// The unit's attempts, ascending by attempt number.
    pub attempts: Vec<AttemptMetadata>,
    /// Whether a diff is possible — at least two attempts exist. The
    /// detail panel shows an honest "nothing to compare" note when false.
    pub comparable: bool,
}

/// One attempt's metadata, joined from persisted history only. Every
/// field except the attempt number is `Option`: a log missing or corrupt
/// leaves the field absent — never zeroed or guessed.
///
/// `tests_passed` is deliberately absent: no per-attempt pass count is
/// persisted anywhere (patch records store only failures), so reporting
/// one would invent it. `success` plus the failure lists carry the
/// honest outcome instead.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttemptMetadata {
    /// The attempt number, from the branch name or patch record.
    pub attempt: u32,
    /// The translation branch this attempt was recorded on, when one
    /// exists (e.g. "re/game_logic.dll/DrawPrimitivev1").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub branch: Option<String>,
    /// The prompt strategy the token-usage log recorded for this
    /// attempt, absent when no log entry names it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strategy: Option<String>,
    /// The context tier the token-usage log recorded, absent when the
    /// entry predates tier tracking or no entry exists.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_tier: Option<String>,
    /// Tokens the token-usage log recorded for this attempt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tokens_used: Option<usize>,
    /// Whether the token-usage log marks this attempt successful.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub success: Option<bool>,
    /// Whether the patch record says the attempt compiled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compiled: Option<bool>,
    /// Compile errors the patch record stored, absent when no patch
    /// record exists for this attempt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compilation_errors: Option<Vec<String>>,
    /// How many tests the attempt failed, per the patch record.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tests_failed: Option<usize>,
    /// The failing tests' names, per the patch record.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub test_failures: Option<Vec<String>>,
    /// Commit hash the patch record stored for this attempt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commit_hash: Option<String>,
    /// When the attempt was committed — the patch record's timestamp,
    /// falling back to the token-usage log's, absent when neither has one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub committed_at: Option<String>,
}

// ─── Ghidra context types ──────────────────────────────────────────────

/// Ghidra disassembly listing line.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GhidraDisasmLine {
    /// Address in hex.
    pub address: String,
    /// Raw instruction bytes as hex.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes: Option<String>,
    /// Disassembled instruction text.
    pub instruction: String,
    /// Ghidra comment or annotation (if any).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

/// Ghidra context for a function — decompiler output, disassembly, and metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GhidraContext {
    /// Function name.
    pub function_name: String,
    /// Function address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    /// DLL this function belongs to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub binary: Option<String>,
    /// Ghidra decompiler (pseudo-C) output.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decompiler_output: Option<String>,
    /// Disassembly listing.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disassembly: Option<Vec<GhidraDisasmLine>>,
    /// Windows API calls identified in the function.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub windows_apis: Option<Vec<GhidraApiCall>>,
    /// Note from Ghidra analysis.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// A Windows API call identified in Ghidra analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GhidraApiCall {
    /// API name (e.g., "CreateFileA").
    pub name: String,
    /// API category (e.g., "win32_file", "directx9").
    pub category: String,
    /// PAL/crate mapping target.
    pub pal_mapping: String,
}

/// Wrapper for successful diff responses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffResponse {
    pub success: bool,
    pub diff: Vec<DiffFile>,
}

impl DiffResponse {
    pub fn ok(diff: Vec<DiffFile>) -> Self {
        Self {
            success: true,
            diff,
        }
    }
}

/// Wrapper for successful Ghidra context responses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GhidraContextResponse {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<GhidraContext>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl GhidraContextResponse {
    pub fn ok(ctx: GhidraContext) -> Self {
        Self {
            success: true,
            context: Some(ctx),
            error: None,
        }
    }

    pub fn not_found(func: &str) -> Self {
        Self {
            success: true,
            context: None,
            error: Some(format!("Ghidra context not available for function: {func}")),
        }
    }
}

impl ServerError {
    pub fn internal(msg: &str) -> Self {
        Self::Internal(msg.to_string())
    }

    pub fn not_found(msg: &str) -> Self {
        Self::NotFound(msg.to_string())
    }

    pub fn bad_request(msg: &str) -> Self {
        Self::BadRequest(msg.to_string())
    }

    /// Build a 503 — the action is valid but this server cannot perform it.
    pub fn unavailable(msg: &str) -> Self {
        Self::ServiceUnavailable(msg.to_string())
    }

    /// Build a 409 — the request conflicts with the resource's current
    /// state (e.g. pausing an already-paused pipeline).
    pub fn conflict(msg: &str) -> Self {
        Self::Conflict(msg.to_string())
    }
}

impl From<super::lifecycle::LifecycleError> for ServerError {
    /// A failed filter reload means the process's logging setup is broken,
    /// which the operator cannot fix by changing the request — an internal
    /// error carrying the reload failure.
    fn from(err: super::lifecycle::LifecycleError) -> Self {
        ServerError::Internal(err.to_string())
    }
}

impl axum::response::IntoResponse for ServerError {
    fn into_response(self) -> axum::response::Response {
        let (status, message) = match self {
            ServerError::NotFound(msg) => (StatusCode::NOT_FOUND, msg),
            ServerError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg),
            ServerError::Internal(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
            ServerError::ServiceUnavailable(msg) => (StatusCode::SERVICE_UNAVAILABLE, msg),
            ServerError::Conflict(msg) => (StatusCode::CONFLICT, msg),
        };

        let body = serde_json::to_string(&serde_json::json!({
            "error": true,
            "message": message,
        }))
        .unwrap_or_default();

        let mut response = axum::response::Response::new(body.into());
        *response.status_mut() = status;
        response
    }
}

// ─── Progress response types ─────────────────────────────────────────

/// Information about a unit currently being translated.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgressInfo {
    pub binary: BinaryIdentity,
    pub function: String,
    pub attempt: u32,
    pub strategy: String,
    /// The pipeline step this unit is currently in.
    pub phase: TranslationPhase,
    /// Phases entered, in event order (re-entered phases appear again).
    pub phase_history: Vec<PhaseRecord>,
    /// Whether a terminal event (completed / failed / function-completed)
    /// has been observed — distinguishes finished units from in-flight ones.
    pub finished: bool,
    pub elapsed_secs: f64,
}

/// Response for the live progress endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgressResponse {
    pub in_progress: Vec<ProgressInfo>,
    pub count: usize,
}

impl ProgressResponse {
    pub fn empty() -> Self {
        Self {
            in_progress: Vec::new(),
            count: 0,
        }
    }
}

/// Pipeline-level progress for a single DLL.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineDllProgress {
    /// DLL/EXE file name.
    pub binary: BinaryIdentity,
    /// Whether the DLL has been classified.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub classification: Option<ClassificationInfo>,
    /// Whether batch translation has completed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub batch: Option<BatchInfo>,
    /// Current in-progress translation status (if any).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub in_progress: Option<CurrentDllStatus>,
    /// The order this DLL appears in the pipeline (0-based).
    pub order: usize,
}

/// Classification info from a ClassificationComplete event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassificationInfo {
    /// DLL this classification is for.
    pub binary: BinaryIdentity,
    pub category: String,
    pub strategy: String,
    pub crate_replacement: Option<String>,
    pub exported_symbols: usize,
    pub imported_symbols: usize,
}

/// Batch summary info from a BatchSummary event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchInfo {
    /// DLL this batch summary is for.
    pub binary: BinaryIdentity,
    pub total_functions: usize,
    pub success_count: usize,
    pub failure_count: usize,
    pub total_attempts: usize,
    pub total_tokens: usize,
}

/// Current DLL being translated.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CurrentDllStatus {
    pub binary: BinaryIdentity,
    pub total_entries: usize,
    pub completed_entries: usize,
}

/// Estimated wall-clock time remaining for the pipeline (issue #64),
/// derived from per-attempt durations recorded in the token-usage log.
/// Only present when at least one attempt has been measured and work
/// remains — never fabricated.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct PipelineTimeEstimate {
    /// Average seconds per translation attempt across the whole log.
    pub avg_attempt_secs: f64,
    /// Functions still to translate (known totals minus done/failed).
    pub remaining_units: usize,
    /// `avg_attempt_secs × remaining_units`, in seconds.
    pub estimated_secs: f64,
}

/// Overall pipeline progress response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineProgressResponse {
    /// Total number of DLLs/EXEs discovered.
    pub total_dlls: usize,
    /// Classification complete count.
    pub classified_count: usize,
    /// Batch translation complete count.
    pub batch_complete_count: usize,
    /// DLLs currently being translated (in ProgressState entries).
    pub currently_translating: Vec<BinaryIdentity>,
    /// Per-DLL progress information.
    pub dlls: Vec<PipelineDllProgress>,
    /// Progress through the master-plan phases (issue #61), in bar order:
    /// Phases 1–7 with Phase 2.5 (PAL Design) between 2 and 3. Phases with
    /// no backing data source report `NoDataSource`, never fabricated counts.
    pub phases: Vec<PhaseProgress>,
    /// Per-binary progress through the pipeline, sorted by name.
    pub binaries: Vec<BinaryProgress>,
    /// Time remaining estimate (issue #64), `None` when no attempt has a
    /// recorded duration or no work remains.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time_estimate: Option<PipelineTimeEstimate>,
}

impl PipelineProgressResponse {
    pub fn empty(total_dlls: usize) -> Self {
        Self {
            total_dlls,
            classified_count: 0,
            batch_complete_count: 0,
            currently_translating: Vec::new(),
            dlls: Vec::new(),
            // Honest empty payload: every phase is reported, no-data-source
            // phases stay NoDataSource, the rest start NotStarted.
            phases: PipelinePhase::ALL
                .iter()
                .map(|&phase| {
                    if phase.is_no_data_source() {
                        PhaseProgress::no_data_source(phase)
                    } else {
                        PhaseProgress::not_started(phase, Some(total_dlls))
                    }
                })
                .collect(),
            binaries: Vec::new(),
            time_estimate: None,
        }
    }
}

// ============================================================
// Server management (issue #59)
// ============================================================

/// State of the live translation pipeline as seen by the web server.
///
/// The web server only observes the pipeline when it was built with live
/// state (`calxgloss live`); on plain `serve` routers the pipeline is
/// [`PipelineStatus::Unavailable`] rather than a fabricated "idle".
///
/// Issue #90 (W2.1) widened this enum to mirror the shared
/// [`PipelineState`] machine — the status is **derived from the state
/// machine**, not inferred from in-flight unit counts, so the dashboard
/// header and the pipeline always agree even while a paused run still has
/// a unit record in flight.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PipelineStatus {
    /// No live translation state is attached to this server (plain `serve`).
    Unavailable,
    /// A live pipeline is attached but its run has not started translating.
    Idle,
    /// The run is translating (or between units of it).
    Running,
    /// A pause was requested; the run is halted at a unit boundary.
    Paused,
    /// A stop was requested; the current unit is finishing before the halt.
    Stopping,
    /// The run finished — naturally or after a stop.
    Complete,
    /// The run failed.
    Error,
}

/// The server-status mirror of the shared lifecycle machine (issue #90).
/// Only `Unavailable` has no counterpart — it means "no pipeline attached",
/// which the state machine itself never reports.
impl From<PipelineState> for PipelineStatus {
    fn from(state: PipelineState) -> Self {
        match state {
            PipelineState::Idle => PipelineStatus::Idle,
            PipelineState::Running => PipelineStatus::Running,
            PipelineState::Paused => PipelineStatus::Paused,
            PipelineState::Stopping => PipelineStatus::Stopping,
            PipelineState::Complete => PipelineStatus::Complete,
            PipelineState::Error => PipelineStatus::Error,
        }
    }
}

/// Snapshot of the server's own health and resource usage, served by
/// `GET /api/server/status`. Process metrics are gathered cross-platform
/// (Windows/macOS/Linux) via the `sysinfo` backends.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ServerStatus {
    /// Whether a live translation pipeline is attached and translating.
    pub pipeline_status: PipelineStatus,
    /// Seconds since the server state was created (process uptime).
    pub uptime_secs: u64,
    /// Calxgloss version the server binary was built with.
    pub version: String,
    /// Host name of the machine running the server.
    pub host: String,
    /// Active tracing log level (e.g. "warn", "info", "debug").
    pub log_level: String,
    /// Resident set size of the server process, in megabytes.
    pub memory_mb: f64,
    /// CPU usage of the server process, as a percentage of one core.
    pub cpu_percent: f64,
    /// Number of live WebSocket sessions currently connected.
    pub ws_connections: usize,
    /// Number of open file handles held by the server process.
    pub open_file_handles: u64,
}

/// Response body of the enhanced `GET /health` probe: port reachability
/// plus workspace accessibility, uptime, and version. One health endpoint
/// only — there is deliberately no second alias.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HealthResponse {
    /// Always "ok" when the server answered (mirrors the liveness contract).
    pub status: String,
    /// Whether the served workspace directory is accessible from the process.
    pub repo_accessible: bool,
    /// Seconds since the server state was created (process uptime).
    pub uptime_secs: u64,
    /// Calxgloss version the server binary was built with.
    pub version: String,
}

/// Request body of `PATCH /api/server/log-level`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogLevelRequest {
    /// Desired tracing level: off, error, warn, info, debug, or trace.
    /// Anything else is rejected with 400.
    pub level: String,
}

/// Response body of `PATCH /api/server/log-level` — the normalized level
/// now active for this process. The change is process-lifetime only: it
/// never persists across restarts.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LogLevelResponse {
    /// The log level now active.
    pub level: String,
}

/// Lifecycle state the server entered after a shutdown or restart request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleStatus {
    /// Graceful shutdown in progress: the server stops accepting requests
    /// and a live pipeline pauses at the current unit boundary.
    ShuttingDown,
    /// Process is stopping after a restart request — the operator must
    /// restart it manually.
    Stopping,
}

/// Response body of the `POST /api/server/shutdown` and
/// `POST /api/server/restart` lifecycle endpoints.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ServerLifecycleResponse {
    /// Lifecycle state the server entered.
    pub status: LifecycleStatus,
    /// Human-readable instruction for the operator.
    pub message: String,
    /// True for restart: the process stops and the operator must restart
    /// it manually — the web server does not own the pipeline process.
    pub restart_required: bool,
}

/// Response body of the `POST /api/pipeline/pause`, `.../resume` and
/// `.../stop` lifecycle control endpoints (issue #90, W2.1). Reports the
/// transition that actually happened — the state the pipeline moved from
/// and to — so the dashboard can reconcile its buttons without a second
/// round-trip.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PipelineLifecycleResponse {
    /// The state the pipeline was in when the request arrived.
    pub previous: PipelineState,
    /// The state the pipeline moved to.
    pub state: PipelineState,
    /// Human-readable confirmation for the operator.
    pub message: String,
}

/// Response body of `POST /api/pipeline/cancel-current` (issue #91, W2.2).
/// Names the unit that was cancelled — the operator sees exactly which
/// in-flight attempt the run just dropped — and confirms the run continues.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UnitCancelResponse {
    /// The binary of the cancelled unit.
    pub binary: String,
    /// The function of the cancelled unit.
    pub function: String,
    /// Human-readable confirmation for the operator.
    pub message: String,
}

/// Response body of `GET /api/llm-io` (issue #77) — the retained window of
/// the server-side LLM I/O log, oldest first. A workspace that has never
/// run live honestly reports an empty `entries`, never a 404.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmIoLogResponse {
    /// The retained entries in append order.
    pub entries: Vec<crate::server::llm_io_log::LlmIoEntry>,
}

/// Response body of `POST /api/llm-io/clear` — confirmation of how many
/// persisted entries the clear dropped. Idempotent: an already-empty log
/// answers with zero, never an error.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmIoClearResponse {
    /// Entries removed from the persisted log.
    pub dropped: usize,
}

// ─── Translation scope controls (issue #93, W2.5) ────────────────────

/// Response body of the scope endpoints (`GET /api/scope` and the POST
/// mutations): the operator's current scope, the active constraints, and
/// the tokens the current run has spent against the budget. Every mutation
/// echoes the full status so the caller sees the effect immediately.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScopeStatusResponse {
    /// What the run is allowed to touch.
    pub scope: calxgloss_types::TranslationScope,
    /// The consumption caps in force.
    pub constraints: calxgloss_types::TranslationConstraints,
    /// Tokens charged to the run so far (per-run, never persisted).
    pub tokens_spent: u64,
    /// Every context tier the `max_context_tier` cap may name, lowest to
    /// highest — the backend's own enumeration, so the dashboard populates
    /// its tier select from the server instead of hardcoding the variant
    /// names and silently turning a rename into a source of 400s
    /// (issue #109).
    pub context_tiers: Vec<calxgloss_types::ContextTier>,
}

/// Request body of `POST /api/scope/binaries` — the full replacement list
/// of target binaries. An empty list means every discovered binary is in
/// scope again.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopeBinariesRequest {
    /// Binaries to translate, filename verbatim.
    #[serde(default)]
    pub binaries: Vec<String>,
}

/// Request body of `POST /api/scope/skip-function` and
/// `POST /api/scope/priority-function` — one function in one binary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopeFunctionRequest {
    /// The target binary, filename verbatim.
    pub binary: String,
    /// The function name within that binary.
    pub function: String,
}

// ─── Per-unit reviewer overrides (issue #96, W2.7) ───────────────────

/// Request body of `POST /api/units/{id}/override` — the reviewer's
/// override record for this unit, replacing any previous one. Missing
/// fields mean "not overridden"; an all-defaults record removes the
/// override (the unit falls back to automatic behavior).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnitOverrideRequest {
    /// The override record to apply.
    #[serde(default, rename = "override")]
    pub r#override: calxgloss_types::FunctionOverride,
}

/// Response body of the override endpoints: the unit the call addressed
/// and the override now in force for it (`None` when none is set — after
/// a removal, or a GET over a never-overridden unit).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnitOverrideResponse {
    /// The unit id the call addressed, echoed back.
    pub unit: String,
    /// The override now in force, if any.
    #[serde(default, rename = "override")]
    pub r#override: Option<calxgloss_types::FunctionOverride>,
}

// ─── Binary classification overrides (issue #97, W2.8) ───────────────

/// The classification a run recorded for one binary — read from the
/// workspace's `re/classify/{binary}.json` artifact. Honesty rule: a
/// workspace that never classified this binary has no record, and the
/// reason is `None` for older artifacts written before reasons were
/// recorded — never a fabricated explanation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordedClassification {
    /// Classification category (e.g. "KnownThirdParty").
    pub category: String,
    /// Classification strategy (e.g. "CrateReplacement").
    pub strategy: String,
    /// Crate recommended for replacement, when the strategy names one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub crate_replacement: Option<String>,
    /// Whether the record marks the binary a known runtime library —
    /// never a translation target.
    #[serde(default)]
    pub known_runtime: bool,
    /// Why the classification was chosen, if the record carries one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Request body of `POST /api/binaries/{name}/classification` — the
/// operator's override record for this binary, replacing any previous
/// one. `override: null` removes the override (the binary falls back to
/// its recorded classification).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BinaryClassificationRequest {
    /// The override to apply, or `None` to remove it.
    #[serde(default, rename = "override")]
    pub r#override: Option<calxgloss_types::BinaryClassificationOverride>,
}

/// Response body of the classification-override endpoints: the binary the
/// call addressed, what the run recorded for it (`None` when the
/// workspace has no classification artifact), and the operator's override
/// now in force (`None` when none is set).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BinaryClassificationResponse {
    /// The binary the call addressed, echoed back verbatim.
    pub binary: String,
    /// The recorded classification, if the workspace has one.
    #[serde(default)]
    pub classification: Option<RecordedClassification>,
    /// The override now in force, if any.
    #[serde(default, rename = "override")]
    pub r#override: Option<calxgloss_types::BinaryClassificationOverride>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_server_status() -> ServerStatus {
        ServerStatus {
            pipeline_status: PipelineStatus::Running,
            uptime_secs: 3_600,
            version: "0.3.0".into(),
            host: "workstation".into(),
            log_level: "info".into(),
            memory_mb: 128.5,
            cpu_percent: 42.5,
            ws_connections: 3,
            open_file_handles: 27,
        }
    }

    /// `ServerStatus` must round-trip through JSON with every field present
    /// under its documented snake_case name.
    #[test]
    fn server_status_serde_round_trip_covers_every_field() {
        let status = sample_server_status();
        let json = serde_json::to_value(&status).expect("ServerStatus serializes");

        assert_eq!(json["pipeline_status"], "running");
        assert_eq!(json["uptime_secs"], 3_600);
        assert_eq!(json["version"], "0.3.0");
        assert_eq!(json["host"], "workstation");
        assert_eq!(json["log_level"], "info");
        assert_eq!(json["memory_mb"], 128.5);
        assert_eq!(json["cpu_percent"], 42.5);
        assert_eq!(json["ws_connections"], 3);
        assert_eq!(json["open_file_handles"], 27);
        assert_eq!(
            json.as_object().expect("object").len(),
            9,
            "exactly the nine documented fields"
        );

        let back: ServerStatus = serde_json::from_value(json).expect("ServerStatus deserializes");
        assert_eq!(back, status);
    }

    /// The pipeline status enum serializes to its three documented states.
    #[test]
    fn pipeline_status_serializes_to_documented_states() {
        assert_eq!(
            serde_json::to_value(PipelineStatus::Unavailable).expect("serializes"),
            "unavailable"
        );
        assert_eq!(
            serde_json::to_value(PipelineStatus::Idle).expect("serializes"),
            "idle"
        );
        assert_eq!(
            serde_json::to_value(PipelineStatus::Running).expect("serializes"),
            "running"
        );
        let back: PipelineStatus =
            serde_json::from_str("\"idle\"").expect("deserializes from state name");
        assert_eq!(back, PipelineStatus::Idle);
    }

    /// `HealthResponse` must round-trip through JSON with every field present.
    #[test]
    fn health_response_serde_round_trip_covers_every_field() {
        let health = HealthResponse {
            status: "ok".into(),
            repo_accessible: true,
            uptime_secs: 42,
            version: "0.3.0".into(),
        };
        let json = serde_json::to_value(&health).expect("HealthResponse serializes");

        assert_eq!(json["status"], "ok");
        assert_eq!(json["repo_accessible"], true);
        assert_eq!(json["uptime_secs"], 42);
        assert_eq!(json["version"], "0.3.0");
        assert_eq!(
            json.as_object().expect("object").len(),
            4,
            "exactly the four documented fields"
        );

        let back: HealthResponse = serde_json::from_value(json).expect("deserializes");
        assert_eq!(back, health);
    }
}
