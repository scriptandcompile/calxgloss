//! Response types for the review dashboard API.

use axum::http::StatusCode;
use calxgloss_types::{PhaseRecord, ReviewDashboard, ReviewStatus, TranslationPhase};
use serde::{Deserialize, Serialize};

/// Wrapper for successful API responses carrying the full dashboard.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardResponse {
    pub success: bool,
    pub dashboard: ReviewDashboard,
    /// Optional queue metadata computed at request time.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub queue_metadata: Option<QueueMetadata>,
}

impl DashboardResponse {
    pub fn ok(dashboard: ReviewDashboard) -> Self {
        Self {
            success: true,
            dashboard,
            queue_metadata: None,
        }
    }
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
    pub dll: String,
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
    pub dll: String,
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
    /// Builds a queue response from a [`ReviewDashboard`].
    pub fn from_dashboard(dashboard: &ReviewDashboard) -> Self {
        let sorted = dashboard.sorted_queue();
        let total = sorted.len();

        let queue: Vec<QueueEntry> = sorted
            .iter()
            .map(|u| QueueEntry {
                id: u.id.clone(),
                name: u.name.clone(),
                kind: u.kind.to_string(),
                dll: u.dll.clone(),
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
    /// Full branch name (e.g. "re/game_logic/DrawSpritev3").
    pub branch: String,
    /// DLL name extracted from the branch.
    pub dll: String,
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

    #[error("Service unavailable: {0}")]
    ServiceUnavailable(String),
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
    pub dll: Option<String>,
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

    pub fn unavailable(msg: &str) -> Self {
        Self::ServiceUnavailable(msg.to_string())
    }
}

impl axum::response::IntoResponse for ServerError {
    fn into_response(self) -> axum::response::Response {
        let (status, message) = match self {
            ServerError::NotFound(msg) => (StatusCode::NOT_FOUND, msg),
            ServerError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg),
            ServerError::Internal(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
            ServerError::ServiceUnavailable(msg) => (StatusCode::SERVICE_UNAVAILABLE, msg),
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
    pub dll: String,
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
    pub dll: String,
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
    pub dll: String,
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
    pub dll: String,
    pub total_functions: usize,
    pub success_count: usize,
    pub failure_count: usize,
    pub total_attempts: usize,
    pub total_tokens: usize,
}

/// Current DLL being translated.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CurrentDllStatus {
    pub dll: String,
    pub total_entries: usize,
    pub completed_entries: usize,
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
    pub currently_translating: Vec<String>,
    /// Per-DLL progress information.
    pub dlls: Vec<PipelineDllProgress>,
}

impl PipelineProgressResponse {
    pub fn empty(total_dlls: usize) -> Self {
        Self {
            total_dlls,
            classified_count: 0,
            batch_complete_count: 0,
            currently_translating: Vec::new(),
            dlls: Vec::new(),
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PipelineStatus {
    /// No live translation state is attached to this server (plain `serve`).
    Unavailable,
    /// A live pipeline is attached but no units are currently in flight.
    Idle,
    /// One or more units are currently being translated.
    Running,
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
