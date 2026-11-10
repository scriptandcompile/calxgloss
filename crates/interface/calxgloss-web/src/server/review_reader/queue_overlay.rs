//! The queue overlay seam: the reviewer's persisted manual queue order
//! and priorities (`re/review/queue_overlay.json`, issue #74). Review-UI
//! state lives beside the other review records, and the review handlers
//! read and write it through this seam so no handler spells out the
//! record-tree path by hand (issue #464).

use super::*;

use super::super::handlers::process::load_json_or_default;
use super::super::types::QueueOverlay;

impl ReviewSurfaceReader {
    /// Path of the persisted queue overlay inside the repo — review-UI
    /// state, filed beside the other review records rather than under
    /// `re/analysis` (which holds pipeline artifacts).
    fn queue_overlay_path(&self) -> PathBuf {
        self.repo_path.join("re").join("review").join("queue_overlay.json")
    }

    /// The persisted queue overlay, degrading to the empty overlay
    /// (pure dependency order) when the file is missing or corrupt.
    pub(crate) fn queue_overlay(&self) -> QueueOverlay {
        load_json_or_default(&self.queue_overlay_path())
    }

    /// Writes the queue overlay atomically so a manual order or priority
    /// set in the UI survives a server restart.
    pub(crate) fn save_queue_overlay(&self, overlay: &QueueOverlay) -> Result<(), ServerError> {
        calxgloss_types::save_json(&self.queue_overlay_path(), overlay)
            .map_err(|e| ServerError::internal(&format!("Failed to save queue overlay: {e}")))
    }
}
