//! The queue overlay record: the reviewer's persisted manual queue order
//! and priorities, filed at `re/review/queue_overlay.json` (issue #74).
//!
//! This is an overlay record in the glossary sense — reviewer intent that
//! survives every derived rebuild. The record tree rule asks that each
//! document have exactly one owner naming its location, so the path, the
//! read, and the write all live here beside the shape itself: the server
//! and the tests file the document through the same writer (issue #467).

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::persist::{PersistError, load_json, save_json};

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
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueueOverlay {
    /// Unit ids in the reviewer's manual order. Units missing from the list
    /// keep their dependency-order position within their tie group.
    #[serde(default)]
    pub order: Vec<String>,
    /// Per-unit priority; a unit with no entry is [`QueuePriority::Normal`].
    #[serde(default)]
    pub priorities: std::collections::HashMap<String, QueuePriority>,
}

/// The persisted location of the queue overlay under a workspace:
/// `re/review/queue_overlay.json` — review-UI state, filed beside the
/// other review records rather than under `re/analysis/` (which holds
/// pipeline artifacts).
pub fn queue_overlay_path(workspace: impl AsRef<Path>) -> PathBuf {
    workspace
        .as_ref()
        .join("re")
        .join("review")
        .join("queue_overlay.json")
}

/// Read the workspace's queue overlay record from the record tree.
///
/// The two faults are distinct, as the other overlay records keep them
/// (issue #459): no document at the record's path is
/// [`PersistError::NotFound`], and bytes that do not parse as an overlay
/// are [`PersistError::Json`] naming the path — never a reading of the
/// empty overlay.
pub fn read_queue_overlay(workspace: impl AsRef<Path>) -> Result<QueueOverlay, PersistError> {
    load_json(&queue_overlay_path(workspace))
}

/// File the workspace's queue overlay record beside the shared read
/// (issue #467), written atomically like every other record document.
/// The web queue seam and a test's fixture both write through this one
/// call, so the persisted overlay cannot drift from the shape the read
/// expects.
pub fn save_queue_overlay(
    workspace: impl AsRef<Path>,
    overlay: &QueueOverlay,
) -> Result<(), PersistError> {
    save_json(&queue_overlay_path(workspace), overlay)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_overlay_filed_through_the_shared_writer_reads_whole_through_the_shared_read() {
        // The writer lands beside the reader (issue #467): a test states
        // what the overlay says, and the shared read hands it back whole.
        let workspace = tempfile::tempdir().expect("temp workspace");
        let overlay = QueueOverlay {
            order: vec!["func_B".into(), "func_A".into()],
            priorities: [(
                "game_logic.dll/DrawPrimitive/v2".to_string(),
                QueuePriority::High,
            )]
            .into_iter()
            .collect(),
        };
        save_queue_overlay(workspace.path(), &overlay).expect("file the overlay");

        let read_back = read_queue_overlay(workspace.path()).expect("the filed overlay reads");
        assert_eq!(
            read_back, overlay,
            "what the writer files, the shared read hands back whole"
        );
    }

    #[test]
    fn a_missing_queue_overlay_reads_as_a_named_missing_fault() {
        let workspace = tempfile::tempdir().expect("temp workspace");
        let err = read_queue_overlay(workspace.path()).expect_err("nothing has been filed");
        assert!(
            matches!(err, PersistError::NotFound { .. }),
            "absence is a named missing fault: {err}"
        );
    }

    #[test]
    fn unreadable_bytes_at_the_writer_path_read_as_a_corrupt_fault_naming_the_path() {
        // AC: unreadable bytes never read as an absent record (issue #467).
        let workspace = tempfile::tempdir().expect("temp workspace");
        let path = queue_overlay_path(workspace.path());
        std::fs::create_dir_all(path.parent().expect("review dir")).expect("create re/review");
        std::fs::write(&path, "\u{0}not an overlay").expect("file unreadable bytes");

        let err = read_queue_overlay(workspace.path()).expect_err("bytes that never parse");
        match err {
            PersistError::Json { path: named, .. } => assert_eq!(named, path),
            other => panic!("unreadable bytes are a corrupt fault naming the path: {other}"),
        }
    }

    #[test]
    fn the_record_path_names_the_review_tree_location() {
        // The overlay rides the record tree beside the other review
        // records, not under the pipeline's analysis directory.
        let path = queue_overlay_path(Path::new("/repo"));
        assert_eq!(path, Path::new("/repo/re/review/queue_overlay.json"));
    }
}
