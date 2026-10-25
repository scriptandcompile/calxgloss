//! The real [`AnalysisDoc`] adapters and the registered projection table
//! (issue #312, spec #310).
//!
//! One unit struct per analysis document that feeds the prompt bundle:
//! each adapter spells its engine's persistor load (folding the engine's
//! own `NotFound` onto [`DocLoadError::Missing`] and every other failure
//! onto [`DocLoadError::Corrupt`], the same way each engine maps the
//! shared persistor's errors onto its crate error), delegates
//! per-function selection to the engine result's own `for_function`,
//! and converts records through the prompts crate's existing `From`
//! impls into its bundle field. Nothing else: the workspace check, the
//! miss logs, and the degradation contract all belong to
//! [`load_and_project`](super::load_and_project), so an adapter cannot
//! drift to a harsher or laxer failure mode than its neighbors.
//!
//! The `KIND` strings keep the miss-log wording shape the hand-copied
//! `extract_*` functions logged with ("No usable *algorithm recognition
//! result*; continuing without algorithm context"), so "why is this
//! engine absent from the prompt" stays answerable from the logs the
//! same way it is today.
//!
//! [`PROJECTION_ROWS`] is the registration point: the fold
//! [`gather_function_evidence`](crate::retry::helpers::gather_function_evidence)
//! runs fills its six fields, the parametrized suite in the helpers'
//! test module iterates these rows through the gather, and
//! [`the_registered_rows_are_the_migrated_engines`] pins the set — an
//! engine that forgets its row fails CI instead of silently vanishing
//! from prompts. The shared consts and type-inference documents join as
//! multi-field rows in #314; the remaining single-field engines follow;
//! libmatch's call-graph correlation stays bespoke outside this seam
//! (#310).

use std::path::Path;

use calxgloss_prompts::EvidenceBundle;

use super::{AnalysisDoc, DocLoadError, ProjectionRow};

// ============================================================
// The six single-field adapters of the first migration batch
// ============================================================

/// The algorithm recognition document, `re/analysis/algorithm/{binary}.json`:
/// the hints whose evidence lives in the function's body or whose name
/// the function carries, filling `recognized_algorithms`.
pub struct AlgorithmDoc;

impl AnalysisDoc for AlgorithmDoc {
    const KIND: &'static str = "algorithm recognition result";

    type Doc = calxgloss_algorithm::types::AlgorithmRecognitionResult;
    type Record<'a> = &'a calxgloss_algorithm::types::AlgorithmHint;

    fn load(workspace: &Path, binary: &str) -> Result<Self::Doc, DocLoadError> {
        calxgloss_algorithm::persist::AlgorithmPersistor::new(workspace)
            .load(binary)
            .map_err(|error| match error {
                calxgloss_algorithm::AlgorithmError::NotFound { path } => {
                    DocLoadError::Missing(path.display().to_string())
                }
                other => DocLoadError::Corrupt(other.into()),
            })
    }

    fn for_function<'a>(
        doc: &'a Self::Doc,
        function: &str,
    ) -> impl Iterator<Item = Self::Record<'a>> {
        doc.for_function(function)
    }

    fn fill(record: Self::Record<'_>, bundle: &mut EvidenceBundle) {
        bundle
            .recognized_algorithms
            .push(calxgloss_prompts::AlgorithmInfo::from(record));
    }
}

/// The memory lifecycle document, `re/analysis/memory/{binary}.json`:
/// the allocation lifecycles and handle pairs whose pairing lives in
/// the function's body, filling `memory_findings`.
pub struct MemoryDoc;

impl AnalysisDoc for MemoryDoc {
    const KIND: &'static str = "memory lifecycle result";

    type Doc = calxgloss_memory::types::MemoryResult;
    type Record<'a> = &'a calxgloss_memory::types::MemoryFinding;

    fn load(workspace: &Path, binary: &str) -> Result<Self::Doc, DocLoadError> {
        calxgloss_memory::persist::MemoryPersistor::new(workspace)
            .load(binary)
            .map_err(|error| match error {
                calxgloss_memory::MemoryError::NotFound { path } => {
                    DocLoadError::Missing(path.display().to_string())
                }
                other => DocLoadError::Corrupt(other.into()),
            })
    }

    fn for_function<'a>(
        doc: &'a Self::Doc,
        function: &str,
    ) -> impl Iterator<Item = Self::Record<'a>> {
        doc.for_function(function)
    }

    fn fill(record: Self::Record<'_>, bundle: &mut EvidenceBundle) {
        bundle
            .memory_findings
            .push(calxgloss_prompts::MemoryInfo::from(record));
    }
}

/// The concurrency document, `re/analysis/sync/{binary}.json`: the lock
/// pairings, atomic calls, and thread spawns whose calls live in the
/// function's body, filling `concurrency_findings`.
pub struct SyncDoc;

impl AnalysisDoc for SyncDoc {
    const KIND: &'static str = "concurrency result";

    type Doc = calxgloss_sync::types::SyncResult;
    type Record<'a> = &'a calxgloss_sync::types::SyncFinding;

    fn load(workspace: &Path, binary: &str) -> Result<Self::Doc, DocLoadError> {
        calxgloss_sync::persist::SyncPersistor::new(workspace)
            .load(binary)
            .map_err(|error| match error {
                calxgloss_sync::SyncError::NotFound { path } => {
                    DocLoadError::Missing(path.display().to_string())
                }
                other => DocLoadError::Corrupt(other.into()),
            })
    }

    fn for_function<'a>(
        doc: &'a Self::Doc,
        function: &str,
    ) -> impl Iterator<Item = Self::Record<'a>> {
        doc.for_function(function)
    }

    fn fill(record: Self::Record<'_>, bundle: &mut EvidenceBundle) {
        bundle
            .concurrency_findings
            .push(calxgloss_prompts::ConcurrencyInfo::from(record));
    }
}

/// The string-context document, `re/analysis/stringctx/{binary}.json`:
/// the classified strings the function references and the format-string
/// calls it makes, filling `string_findings`.
pub struct StringContextDoc;

impl AnalysisDoc for StringContextDoc {
    const KIND: &'static str = "string context result";

    type Doc = calxgloss_stringctx::types::StringContextResult;
    type Record<'a> = &'a calxgloss_stringctx::types::StringFinding;

    fn load(workspace: &Path, binary: &str) -> Result<Self::Doc, DocLoadError> {
        calxgloss_stringctx::persist::StringContextPersistor::new(workspace)
            .load(binary)
            .map_err(|error| match error {
                calxgloss_stringctx::StringCtxError::NotFound { path } => {
                    DocLoadError::Missing(path.display().to_string())
                }
                other => DocLoadError::Corrupt(other.into()),
            })
    }

    fn for_function<'a>(
        doc: &'a Self::Doc,
        function: &str,
    ) -> impl Iterator<Item = Self::Record<'a>> {
        doc.for_function(function)
    }

    fn fill(record: Self::Record<'_>, bundle: &mut EvidenceBundle) {
        bundle
            .string_findings
            .push(calxgloss_prompts::StringContextInfo::from(record));
    }
}

/// The API-identification document, `re/analysis/apidetect/{binary}.json`:
/// the usages the function records directly or reaches through its call
/// graph, filling `api_findings`. Binary-level import entries belong to
/// the binary, not to any function — the engine's own `for_function`
/// keeps them out, and the adapter delegates to it unchanged.
pub struct ApiDoc;

impl AnalysisDoc for ApiDoc {
    const KIND: &'static str = "API result";

    type Doc = calxgloss_apidetect::types::ApiDetectionResult;
    type Record<'a> = &'a calxgloss_apidetect::types::ApiFinding;

    fn load(workspace: &Path, binary: &str) -> Result<Self::Doc, DocLoadError> {
        calxgloss_apidetect::persist::ApiPersistor::new(workspace)
            .load(binary)
            .map_err(|error| match error {
                calxgloss_apidetect::ApiError::NotFound { path } => {
                    DocLoadError::Missing(path.display().to_string())
                }
                other => DocLoadError::Corrupt(other.into()),
            })
    }

    fn for_function<'a>(
        doc: &'a Self::Doc,
        function: &str,
    ) -> impl Iterator<Item = Self::Record<'a>> {
        doc.for_function(function)
    }

    fn fill(record: Self::Record<'_>, bundle: &mut EvidenceBundle) {
        bundle
            .api_findings
            .push(calxgloss_prompts::ApiInfo::from(record));
    }
}

/// The float/SIMD flag document, `re/analysis/floatsimd/{binary}.json`:
/// the at-most-one usage flag raised for the function — the shape
/// reading and the confidence band behind it — filling
/// `floatsimd_findings`.
pub struct FloatsimdDoc;

impl AnalysisDoc for FloatsimdDoc {
    const KIND: &'static str = "float/SIMD result";

    type Doc = calxgloss_floatsimd::types::FloatsimdResult;
    type Record<'a> = &'a calxgloss_floatsimd::types::FloatsimdFinding;

    fn load(workspace: &Path, binary: &str) -> Result<Self::Doc, DocLoadError> {
        calxgloss_floatsimd::persist::FloatsimdPersistor::new(workspace)
            .load(binary)
            .map_err(|error| match error {
                calxgloss_floatsimd::FloatsimdError::NotFound { path } => {
                    DocLoadError::Missing(path.display().to_string())
                }
                other => DocLoadError::Corrupt(other.into()),
            })
    }

    fn for_function<'a>(
        doc: &'a Self::Doc,
        function: &str,
    ) -> impl Iterator<Item = Self::Record<'a>> {
        doc.for_function(function)
    }

    fn fill(record: Self::Record<'_>, bundle: &mut EvidenceBundle) {
        bundle
            .floatsimd_findings
            .push(calxgloss_prompts::FloatsimdInfo::from(record));
    }
}

// ============================================================
// The registered projection table
// ============================================================

/// The projection rows the gather folds, in registered order: the six
/// single-field engines of the first migration batch (issue #312). A
/// field fed by several rows receives them in table order, so this
/// order is the prompts' order — changing it rewrites prompt sections
/// for no reason and must be a deliberate edit.
///
/// The shared consts and type-inference documents join here as
/// multi-field rows when #314 migrates them; the remaining single-field
/// engines follow the same one-row shape.
pub static PROJECTION_ROWS: &[ProjectionRow] = &[
    ProjectionRow::of::<AlgorithmDoc>(),
    ProjectionRow::of::<MemoryDoc>(),
    ProjectionRow::of::<SyncDoc>(),
    ProjectionRow::of::<StringContextDoc>(),
    ProjectionRow::of::<ApiDoc>(),
    ProjectionRow::of::<FloatsimdDoc>(),
];

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// The row-membership roster: the set of registered projection rows
    /// is exactly the engines that have migrated onto the fold. An
    /// engine that forgets to register its row — or registers one the
    /// migration never approved — fails here instead of silently
    /// vanishing from (or sneaking into) prompts. The parametrized
    /// suite in the helpers' test module then covers every row listed
    /// here at the gather seam, so registering a row is what pulls an
    /// engine into the triad tests.
    #[test]
    fn the_registered_rows_are_the_migrated_engines() {
        let mut kinds: Vec<&str> = PROJECTION_ROWS.iter().map(|row| row.kind).collect();
        kinds.sort_unstable();
        assert_eq!(
            kinds,
            [
                "API result",
                "algorithm recognition result",
                "concurrency result",
                "float/SIMD result",
                "memory lifecycle result",
                "string context result",
            ],
            "exactly the six engines of the first migration batch (issue #312) are registered"
        );
    }
}
