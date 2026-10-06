//! Status counts — summary of units by status.

use super::types::ReviewStatus;
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

    /// The tally for one status. The single status→field mapping shared by
    /// the initial counting in [`ReviewDashboard::new`] and later rewrites
    /// (auto-blocking), so the two can't drift.
    pub(crate) fn tally_mut(&mut self, status: &ReviewStatus) -> &mut usize {
        match status {
            ReviewStatus::Queued => &mut self.queued,
            ReviewStatus::PendingReview => &mut self.pending_review,
            ReviewStatus::InProgress => &mut self.in_progress,
            ReviewStatus::Accepted => &mut self.accepted,
            ReviewStatus::SendBack => &mut self.send_back,
            ReviewStatus::PatchRequested => &mut self.patch_requested,
            ReviewStatus::Blocked => &mut self.blocked,
        }
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
