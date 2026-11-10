//! The queue overlay seam: the reviewer's persisted manual queue order
//! and priorities (`re/review/queue_overlay.json`, issue #74). Review-UI
//! state lives beside the other review records, and the record itself —
//! shape, path, read, and writer — lives in the shared record module
//! (`calxgloss_types::queue_overlay`), so the server and the tests file
//! the same document through the same writer (issue #467). This seam
//! keeps the review-facing reading: the surfaces degrade to the empty
//! overlay (pure dependency order) when nothing is filed.

use super::*;

use super::super::handlers::process::load_json_or_default;
use super::super::types::QueueOverlay;

impl ReviewSurfaceReader {
    /// The persisted queue overlay, degrading to the empty overlay
    /// (pure dependency order) when the file is missing or corrupt.
    pub(crate) fn queue_overlay(&self) -> QueueOverlay {
        load_json_or_default(&calxgloss_types::queue_overlay_path(&self.repo_path))
    }

    /// Writes the queue overlay through the shared record writer so a
    /// manual order or priority set in the UI survives a server restart
    /// and lands in the shape the shared read expects.
    pub(crate) fn save_queue_overlay(&self, overlay: &QueueOverlay) -> Result<(), ServerError> {
        calxgloss_types::save_queue_overlay(&self.repo_path, overlay)
            .map_err(|e| ServerError::internal(&format!("Failed to save queue overlay: {e}")))
    }
}
