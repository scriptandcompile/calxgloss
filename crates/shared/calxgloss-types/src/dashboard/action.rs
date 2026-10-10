//! Review actions — human review operations on units of work.

use serde::{Deserialize, Serialize};

/// Represents a review action that a human can take on a unit of work.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReviewAction {
    /// The unit of work this action applies to.
    pub unit_id: String,
    /// The action being performed.
    pub action: ReviewActionKind,
    /// Optional comments from the reviewer.
    pub comments: Option<String>,
}

/// The kinds of review actions available.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ReviewActionKind {
    /// Accept the unit — merge to main.
    Accept,
    /// Send back to LLM with reviewer comments.
    SendBack,
    /// Request a patch for a specific issue.
    RequestPatch {
        /// Description of the issue to fix.
        issue: String,
    },
    /// View all LLM attempts for this unit.
    ViewAttempts,
    /// View the original Ghidra context.
    ViewGhidraContext,
}

/// Persisted skip state for review units (issue #75).
///
/// Stored as a JSON file at `re/review/skips.json` in the repo, written by
/// the web server when a unit is skipped/unskipped from the review queue,
/// and read by the dashboard builder so skipped units keep their `Skipped`
/// status across rebuilds (like send-back verdicts). A unit that has been
/// merged (Accepted) is never reported as skipped.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ReviewSkips {
    /// Unit IDs the reviewer has chosen to skip.
    pub skipped: Vec<String>,
}

impl ReviewSkips {
    /// Path of the persisted skip set inside the repo — review-UI state,
    /// filed beside the queue overlay rather than under `re/analysis`
    /// (which holds pipeline artifacts).
    pub fn path_in(repo_path: &std::path::Path) -> std::path::PathBuf {
        repo_path.join("re").join("review").join("skips.json")
    }
}
