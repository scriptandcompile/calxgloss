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
