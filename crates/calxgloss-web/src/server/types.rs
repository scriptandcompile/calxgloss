//! Response types for the review dashboard API.

use serde::{Deserialize, Serialize};

/// Wrapper for successful API responses carrying the full dashboard.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardResponse {
    pub success: bool,
    pub dashboard: ReviewDashboard,
}

impl DashboardResponse {
    pub fn ok(dashboard: ReviewDashboard) -> Self {
        Self {
            success: true,
            dashboard,
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
    /// Type of work unit (e.g., "Function Translation").
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
    /// Translation confidence score (0.0 to 1.0).
    pub confidence: Option<f32>,
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
    /// Prompt tier used (0-4).
    pub prompt_tier: Option<usize>,
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
}

/// Summary of a git diff between a branch and main.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffSummary {
    pub files_changed: usize,
    pub insertions: usize,
    pub deletions: usize,
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
}

impl axum::response::IntoResponse for ServerError {
    fn into_response(self) -> axum::response::Response {
        let (status, message) = match self {
            ServerError::NotFound(msg) => (StatusCode::NOT_FOUND, msg),
            ServerError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg),
            ServerError::Internal(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
        };

        (status, Json(serde_json::json!({
            "error": true,
            "message": message,
        }))).into_response()
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
}
