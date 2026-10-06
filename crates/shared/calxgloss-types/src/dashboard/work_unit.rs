//! Unit of work — the central type for the review dashboard.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::types::{ReviewStatus, Staleness, WorkKind};

/// A single item in the review dashboard.
///
/// Each item is a discrete piece of work that can be reviewed and accepted
/// independently: a *unit of work* (a function translation — one function or
/// struct definition, delivered as one commit) or the supporting work around
/// it (a DLL classification, a shim layer, a PAL trait, …). See [`WorkKind`]
/// for the distinction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnitOfWork {
    /// Unique identifier for this unit.
    pub id: String,
    /// Human-readable name (e.g., "Classify d3d9.dll").
    pub name: String,
    /// The kind of work this item represents.
    pub kind: WorkKind,
    /// Associated DLL.
    pub dll: String,
    /// Associated function (if applicable).
    pub function: Option<String>,
    /// Attempt number (v1, v2, v3, etc.).
    pub attempt: u32,
    /// Current review status.
    pub status: ReviewStatus,
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
    /// When this unit was created.
    pub created_at: DateTime<Utc>,
    /// When this unit was last updated.
    pub updated_at: DateTime<Utc>,
    /// Known gaps or caveats that could not be verified.
    pub known_gaps: Vec<String>,
    /// Whether this unit has been pending for too long (staleness).
    ///
    /// Set by the dashboard builder based on `updated_at` vs. the current time.
    pub stale: Staleness,
}
