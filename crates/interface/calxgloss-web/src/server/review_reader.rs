//! The web server has one review-surface reader (issue #460, P59). The
//! reader is built from the workspace path plus the live store, and every
//! review payload is served from it. It owns the single *live-merge fold*
//! — the code that patches in-flight units into the review rows — which
//! the dashboard and unit-detail endpoints each pasted by hand. It also
//! owns the classification reads: the record-and-override pair behind the
//! panel and the binaries pages (issue #461). Later P59 tickets route
//! more record reads through this reader.
//!
//! The module grows one seam file per read family: `live_merge` for the
//! live store's readings, `classification` for the classification records
//! and the persisted override layer, `obligations` for the obligation
//! ledger readings every review row carries (issue #462).

#![allow(unused_imports)] // header imports feed the seam files and the tests file through `use super::*;`
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use calxgloss_types::dashboard::ReviewDashboard;
use calxgloss_types::{
    BinaryClassificationOverride, BinaryIdentity, ClassificationOverrides, DllCategory,
    LiveUnitProgress, PersistError, classification_record_dir, read_classification_overrides,
    read_classification_record,
};
use tokio::sync::RwLock;

use super::ServerError;
use super::handlers::process::binary_matches;
use super::live_store::ProgressState;
use super::types::RecordedClassification;

mod classification;
mod live_merge;
mod obligations;

pub use classification::{
    BinaryClassifications, ClassificationDocument, ClassificationPair, ClassificationReading,
    InForceDecision,
};

// Each seam defines methods on this module's struct and free items the
// other files use; the globs bring them back into scope here, and the
// seams' and the tests file's `use super::*;` resolve names through them.
use classification::*;
use live_merge::*;
use obligations::*;

/// One reader over the record tree and the live store, serving every
/// review payload. Handlers receive it through [`super::CombinedState`]
/// and never walk the record tree or the live store's internals
/// themselves.
#[derive(Clone)]
pub struct ReviewSurfaceReader {
    repo_path: PathBuf,
    progress: Option<Arc<RwLock<ProgressState>>>,
}

impl ReviewSurfaceReader {
    /// Creates the reader for a workspace, with the live store attached
    /// when the server runs a live pipeline (`None` for plain `serve`).
    pub fn new(repo_path: PathBuf, progress: Option<Arc<RwLock<ProgressState>>>) -> Self {
        Self {
            repo_path,
            progress,
        }
    }

    /// The workspace this reader reads. Handlers that still carry their
    /// own non-classification reads (the dashboard build, the token log)
    /// take the path from here rather than re-joining record paths.
    pub fn repo_path(&self) -> &Path {
        &self.repo_path
    }
}

#[cfg(test)]
mod tests;
