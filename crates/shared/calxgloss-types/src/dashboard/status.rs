//! Status counts — summary of units by status.

use serde::{Deserialize, Serialize};

/// Summary counts of units of work by status.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct StatusCounts {
    pub queued: usize,
    pub pending_review: usize,
    pub in_progress: usize,
    pub accepted: usize,
    pub send_back: usize,
    pub patch_requested: usize,
    pub blocked: usize,
}

impl StatusCounts {
    /// Total number of units across all statuses.
    pub fn total(&self) -> usize {
        self.queued
            + self.pending_review
            + self.in_progress
            + self.accepted
            + self.send_back
            + self.patch_requested
            + self.blocked
    }
}

impl std::fmt::Display for StatusCounts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "queued: {}, pending: {}, in_progress: {}, accepted: {}, send_back: {}, patch: {}, blocked: {}",
            self.queued,
            self.pending_review,
            self.in_progress,
            self.accepted,
            self.send_back,
            self.patch_requested,
            self.blocked,
        )
    }
}
