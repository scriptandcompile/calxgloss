//! One pre-batch evidence scan's owned reads (issue #237).
//!
//! The scan-phase fan-out (spec #234) cannot spawn a scan that borrows
//! the batch, so every scan owns what it reads: [`ScanJob`] holds clones
//! of the two reads a scan makes — the workspace and the batch's shared
//! read source — and nothing else. The scan's shape — the cached-document
//! short-circuit, the analysis-engine call, the document persist, the
//! warn-and-continue degradation, and the completion log — lives in one
//! place now: the scan registry's generic pass
//! ([`ScanDescriptor::new`](crate::scan_registry::ScanDescriptor::new),
//! issue #302), which runs every scan from its row over this handle's
//! [`ScanContext`](crate::scan_registry::ScanContext).
//!
//! The handle once had fourteen hand-written scan methods, and the
//! pipeline's fourteen `ensure_*` entry points and per-analysis-engine
//! wrappers reached them one at a time; issue #308 deleted that whole
//! legacy surface, so nothing reaches this handle except through a row.
//! The pass heartbeat is the scan phase's — armed once around the whole
//! group by
//! [`run_prebatch_scans`](crate::TranslationPipeline::run_prebatch_scans),
//! not per scan (issue #239). The one ordering rule between scans comes
//! from the registry's declared row dependency and its generic
//! [`CompletionLatch`](crate::scan_registry::CompletionLatch): armed per
//! phase and passed on the row's context; this handle itself contains no
//! latch (issue #305).

use std::path::{Path, PathBuf};

use calxgloss_decomp::PipelineSource;

/// Everything one pre-batch evidence scan reads, owned by the scan itself.
///
/// The job holds clones of the two reads a scan makes — the workspace the
/// document is filed under and the batch's shared read source as armed by
/// [`begin_cached_source`](crate::TranslationPipeline::begin_cached_source)
/// — so it borrows nothing from the batch. Cloning is cheap
/// (every read is an `Arc`-backed handle or a small path) and the handle is
/// `Send + Sync`, so a caller can move a job onto a task — exactly what the
/// scan-phase fan-out (#240) needs.
#[derive(Clone)]
pub(crate) struct ScanJob {
    /// The binary the scan reads and the document is named after.
    binary: String,

    /// The workspace root the scan's document is filed under.
    workspace: PathBuf,

    /// The batch's shared read source at the moment the job was built: the
    /// armed [`CachedScanSource`](calxgloss_decomp::CachedScanSource) or the
    /// loaded analysis engine. Every analysis-engine read goes through this clone.
    source: PipelineSource,
}

impl ScanJob {
    /// Assemble the job for one scan of `binary` in `workspace`, reading
    /// through `source`.
    pub(crate) fn new(binary: &str, workspace: &Path, source: PipelineSource) -> Self {
        Self {
            binary: binary.to_string(),
            workspace: workspace.to_path_buf(),
            source,
        }
    }

    /// The registry's view of this job: the same owned reads, with empty
    /// completion latches (issues #302, #305) — the phase attaches the
    /// latches for the row's declared dependency to the context before the
    /// row runs, so the handle itself never contains or arms one.
    pub(crate) fn scan_context(&self) -> crate::scan_registry::ScanContext {
        crate::scan_registry::ScanContext {
            binary: self.binary.clone(),
            workspace: self.workspace.clone(),
            source: self.source.clone(),
            latches: crate::scan_registry::ScanLatches::default(),
        }
    }
}
