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
//! `gather_function_evidence` runs fills its fields, the parametrized
//! suite in the helpers' test module iterates these rows through the
//! gather, and the test `the_registered_rows_are_the_migrated_engines`
//! pins the set — an
//! engine that forgets its row fails CI instead of silently vanishing
//! from prompts. All fourteen documents that feed the bundle per
//! function are migrated: the twelve single-field ones (first batch in
//! #312, second in #313) and the shared consts and type-inference
//! documents as multi-field rows (#314); libmatch's call-graph
//! correlation stays bespoke outside this seam (#310).

use std::path::Path;

use calxgloss_prompts::EvidenceBundle;

use super::{AnalysisDoc, DocLoadError, ProjectionRow};

// ============================================================
// The six single-field adapters of the first migration batch (#312)
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

    fn fill_coverage(doc: &Self::Doc, bundle: &mut EvidenceBundle) {
        // Only a document that carries a coverage record fills one; a
        // pre-P19 document, whose field's absence reads as no record,
        // fills nothing and keeps the old render byte-identical. The
        // record says which bodies the scan never read and which caller
        // edges it could not pull — never a body it read and left
        // without a recognition (issue #351).
        if let Some(coverage) = doc.metadata.coverage.as_ref() {
            bundle.algorithm_coverage = calxgloss_prompts::CoverageInfo::from(coverage);
        }
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

    fn fill_coverage(doc: &Self::Doc, bundle: &mut EvidenceBundle) {
        // Only a document that carries a coverage record fills one; a
        // pre-P19 document, whose field's absence reads as no record,
        // fills nothing and keeps the old render byte-identical. The
        // record says which bodies the scan never reached — never an
        // examined-and-clean body its finding list left unmentioned
        // (issue #349).
        if let Some(coverage) = doc.metadata.coverage.as_ref() {
            bundle.memory_coverage = calxgloss_prompts::CoverageInfo::from(coverage);
        }
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

    fn fill_coverage(doc: &Self::Doc, bundle: &mut EvidenceBundle) {
        // Only a document that carries a coverage record fills one; a
        // pre-P19 document, whose field's absence reads as no record,
        // fills nothing and keeps the old render byte-identical. The
        // record says which bodies the scan never reached — never an
        // examined-and-clean body its finding list left unmentioned
        // (issue #349).
        if let Some(coverage) = doc.metadata.coverage.as_ref() {
            bundle.sync_coverage = calxgloss_prompts::CoverageInfo::from(coverage);
        }
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

    fn fill_coverage(doc: &Self::Doc, bundle: &mut EvidenceBundle) {
        // Only a document that carries a coverage record fills one; a
        // pre-P19 document, whose field's absence reads as no record,
        // fills nothing and keeps the old render byte-identical. The
        // record says which bodies the scan never read, whether the
        // program's string listing arrived, and which cross-reference
        // lookups refused — never a string it read and left unattached
        // (issue #351).
        if let Some(coverage) = doc.metadata.coverage.as_ref() {
            bundle.string_context_coverage = calxgloss_prompts::CoverageInfo::from(coverage);
        }
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

    fn fill_coverage(doc: &Self::Doc, bundle: &mut EvidenceBundle) {
        // Only a document that carries a coverage record fills one; a
        // pre-P19 document, whose field's absence reads as no record,
        // fills nothing and keeps the old render byte-identical
        // (issue #346).
        if let Some(coverage) = doc.metadata.coverage.as_ref() {
            bundle.api_coverage = calxgloss_prompts::CoverageInfo::from(coverage);
        }
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

    fn fill_coverage(doc: &Self::Doc, bundle: &mut EvidenceBundle) {
        // Only a document that carries a coverage record fills one; a
        // pre-P19 document, whose field's absence reads as no record,
        // fills nothing and keeps the old render byte-identical. The
        // record says which bodies the scan never reached — never an
        // examined-and-clean body its flag list left unmentioned
        // (issue #347).
        if let Some(coverage) = doc.metadata.coverage.as_ref() {
            bundle.floatsimd_coverage = calxgloss_prompts::CoverageInfo::from(coverage);
        }
    }
}

// ============================================================
// The six single-field adapters of the second migration batch (#313)
// ============================================================

/// The type database's two per-function record kinds as one item type:
/// [`TypeDatabaseDoc`]'s selection yields inferred candidates and named
/// types alike, and a `for_function` iterator yields a single item
/// type, so the two kinds ride a small sum the `fill` leg unpacks onto
/// their own `From` impls.
pub enum TypeDbRecord<'a> {
    Candidate(&'a calxgloss_typesdb::types::InferredStruct),
    Named(&'a calxgloss_typesdb::types::NamedType),
}

/// The type database document, `re/analysis/typesdb/{binary}.json`:
/// the data structures whose evidence names the function, filling
/// `data_structures`. Unlike every other adapter, its per-function
/// selection is spelled here, not delegated to the engine — the
/// database has no `for_function`, and the dual selection is what the
/// seam's second leg is for:
///
/// - inferred struct candidates whose literals the function
///   cross-references (the function appears in the candidate's
///   `referenced_by` list), in database order;
/// - named types recovered for classes whose vtable lists the function
///   as a method — the method list is the only per-function link the
///   database records for Type Manager types.
///
/// Candidates first, then named types: today's ordering, which keeps
/// prompt sections diffable across the migration.
pub struct TypeDatabaseDoc;

impl AnalysisDoc for TypeDatabaseDoc {
    const KIND: &'static str = "type database";

    type Doc = calxgloss_typesdb::types::TypeDatabase;
    type Record<'a> = TypeDbRecord<'a>;

    fn load(workspace: &Path, binary: &str) -> Result<Self::Doc, DocLoadError> {
        calxgloss_typesdb::persist::TypeDatabasePersistor::new(workspace)
            .load(binary)
            .map_err(|error| match error {
                calxgloss_typesdb::TypesDbError::NotFound { path } => {
                    DocLoadError::Missing(path.display().to_string())
                }
                other => DocLoadError::Corrupt(other.into()),
            })
    }

    fn for_function<'a>(
        doc: &'a Self::Doc,
        function: &str,
    ) -> impl Iterator<Item = Self::Record<'a>> {
        let class_names: std::collections::HashSet<&str> = doc
            .vtables
            .iter()
            .filter(|v| {
                v.methods
                    .iter()
                    .any(|m| m.name.as_deref() == Some(function))
            })
            .filter_map(|v| v.class_name.as_deref())
            .collect();
        let name = function.to_string();
        doc.inferred_structs
            .iter()
            .filter(move |s| s.referenced_by.iter().any(|f| f == &name))
            .map(TypeDbRecord::Candidate)
            .chain(
                doc.named_types
                    .iter()
                    .filter(move |t| class_names.contains(t.name.as_str()))
                    .map(TypeDbRecord::Named),
            )
    }

    fn fill(record: Self::Record<'_>, bundle: &mut EvidenceBundle) {
        let structure = match record {
            TypeDbRecord::Candidate(candidate) => {
                calxgloss_prompts::StructuredData::from(candidate)
            }
            TypeDbRecord::Named(named) => calxgloss_prompts::StructuredData::from(named),
        };
        bundle.data_structures.push(structure);
    }

    fn fill_coverage(doc: &Self::Doc, bundle: &mut EvidenceBundle) {
        // Only a document that carries a coverage record fills one; a
        // pre-P19 document, whose field's absence reads as no record,
        // fills nothing and keeps the old render byte-identical. The
        // record says the vtable evidence a target never yielded — never
        // a structure the scan read and left out of this function's list
        // (issue #348).
        if let Some(coverage) = doc.metadata.coverage.as_ref() {
            bundle.type_database_coverage = calxgloss_prompts::CoverageInfo::from(coverage);
        }
    }
}

/// The serialization document, `re/analysis/serialize/{binary}.json`:
/// the byte-swap calls, bit-packing chains, and file-format signature
/// comparisons whose expressions live in the function's body, plus the
/// program-wide endianness profile answering to its contributing
/// functions, filling `serialization_findings`.
pub struct SerializationDoc;

impl AnalysisDoc for SerializationDoc {
    const KIND: &'static str = "serialization result";

    type Doc = calxgloss_serialize::types::SerializeResult;
    type Record<'a> = &'a calxgloss_serialize::types::SerializeFinding;

    fn load(workspace: &Path, binary: &str) -> Result<Self::Doc, DocLoadError> {
        calxgloss_serialize::persist::SerializePersistor::new(workspace)
            .load(binary)
            .map_err(|error| match error {
                calxgloss_serialize::SerializeError::NotFound { path } => {
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
            .serialization_findings
            .push(calxgloss_prompts::SerializationInfo::from(record));
    }

    fn fill_coverage(doc: &Self::Doc, bundle: &mut EvidenceBundle) {
        // Only a document that carries a coverage record fills one; a
        // pre-P19 document, whose field's absence reads as no record,
        // fills nothing and keeps the old render byte-identical. The
        // record says which bodies the scan never reached — never a
        // body it read and left without a pattern (issue #351).
        if let Some(coverage) = doc.metadata.coverage.as_ref() {
            bundle.serialization_coverage = calxgloss_prompts::CoverageInfo::from(coverage);
        }
    }
}

/// The callback document, `re/analysis/callback/{binary}.json`: the
/// function-pointer array calls, callback registrations, and
/// jump-table dispatches whose calls live in the function's body,
/// filling `callback_findings`.
pub struct CallbackDoc;

impl AnalysisDoc for CallbackDoc {
    const KIND: &'static str = "callback result";

    type Doc = calxgloss_callback::types::CallbackResult;
    type Record<'a> = &'a calxgloss_callback::types::CallbackFinding;

    fn load(workspace: &Path, binary: &str) -> Result<Self::Doc, DocLoadError> {
        calxgloss_callback::persist::CallbackPersistor::new(workspace)
            .load(binary)
            .map_err(|error| match error {
                calxgloss_callback::CallbackError::NotFound { path } => {
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
            .callback_findings
            .push(calxgloss_prompts::CallbackInfo::from(record));
    }

    fn fill_coverage(doc: &Self::Doc, bundle: &mut EvidenceBundle) {
        // Only a document that carries a coverage record fills one; a
        // pre-P19 document, whose field's absence reads as no record,
        // fills nothing and keeps the old render byte-identical. The
        // record says which bodies the scan never reached — never an
        // examined-and-clean body its finding list left unmentioned
        // (issue #350).
        if let Some(coverage) = doc.metadata.coverage.as_ref() {
            bundle.callback_coverage = calxgloss_prompts::CoverageInfo::from(coverage);
        }
    }
}

/// The control-flow document, `re/analysis/controlflow/{binary}.json`:
/// the switch-shaped if-else chains, self-recursion, state-machine
/// patterns, and branch-site records whose code lives in the
/// function's body, filling `control_flow_findings` — the branch
/// inventory keeps its projection shape on this path. What the branch
/// inventory means for test generation stays outside this seam:
/// baseline generation consumes the `branch_site` records in their own
/// shape through the helpers' `load_control_flow_result` and
/// `branch_inventory_of`, which keep their one-load-per-unit role
/// inside `translate` (issue #261).
pub struct ControlFlowDoc;

impl AnalysisDoc for ControlFlowDoc {
    const KIND: &'static str = "control-flow result";

    type Doc = calxgloss_controlflow::types::ControlFlowResult;
    type Record<'a> = &'a calxgloss_controlflow::types::ControlFlowFinding;

    fn load(workspace: &Path, binary: &str) -> Result<Self::Doc, DocLoadError> {
        calxgloss_controlflow::persist::ControlFlowPersistor::new(workspace)
            .load(binary)
            .map_err(|error| match error {
                calxgloss_controlflow::ControlFlowError::NotFound { path } => {
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
            .control_flow_findings
            .push(calxgloss_prompts::ControlFlowInfo::from(record));
    }

    fn fill_coverage(doc: &Self::Doc, bundle: &mut EvidenceBundle) {
        // Only a document that carries a coverage record fills one; a
        // pre-P19 document, whose field's absence reads as no record,
        // fills nothing and keeps the old render byte-identical. The
        // record says which bodies the scan never reached — never an
        // examined-and-clean body its finding list left unmentioned
        // (issue #349).
        if let Some(coverage) = doc.metadata.coverage.as_ref() {
            bundle.control_flow_coverage = calxgloss_prompts::CoverageInfo::from(coverage);
        }
    }
}

/// The error-handling document, `re/analysis/errhandling/{binary}.json`:
/// the idiom readings (spelled frame, named handler, exception-API
/// call, `RaiseException` call, cleanup ladder) and the failure-code
/// records whose contract lives in the function's decompiled body, in
/// one lookup and the document's listing order, filling
/// `error_handling_findings` — so a retry maps the frame onto a Rust
/// error type and keeps the codes instead of guessing at the error
/// shape (issue #293).
pub struct ErrorHandlingDoc;

impl AnalysisDoc for ErrorHandlingDoc {
    const KIND: &'static str = "error-handling result";

    type Doc = calxgloss_errhandling::types::ErrhandlingResult;
    type Record<'a> = &'a calxgloss_errhandling::types::ErrhandlingFinding;

    fn load(workspace: &Path, binary: &str) -> Result<Self::Doc, DocLoadError> {
        calxgloss_errhandling::persist::ErrhandlingPersistor::new(workspace)
            .load(binary)
            .map_err(|error| match error {
                calxgloss_errhandling::ErrhandlingError::NotFound { path } => {
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
            .error_handling_findings
            .push(calxgloss_prompts::ErrhandlingInfo::from(record));
    }

    fn fill_coverage(doc: &Self::Doc, bundle: &mut EvidenceBundle) {
        // Only a document that carries a coverage record fills one; a
        // pre-P19 document, whose field's absence reads as no record,
        // fills nothing and keeps the old render byte-identical. The
        // record says which bodies the scan never reached — never an
        // examined-and-clean body its finding list left unmentioned
        // (issue #350).
        if let Some(coverage) = doc.metadata.coverage.as_ref() {
            bundle.error_handling_coverage = calxgloss_prompts::CoverageInfo::from(coverage);
        }
    }
}

/// The global-state document, `re/analysis/globalstate/{binary}.json`:
/// the access records made for the function — the program globals
/// whose value it reads and through which it stores, each with the
/// statement that carried the access and the confidence band the
/// reading scored on — filling `global_state_findings`. The
/// shared-globals index records name no single function, so they never
/// answer a by-function lookup; the engine's own `for_function` keeps
/// them out and the adapter delegates unchanged.
pub struct GlobalStateDoc;

impl AnalysisDoc for GlobalStateDoc {
    const KIND: &'static str = "global-state result";

    type Doc = calxgloss_globalstate::types::GlobalStateResult;
    type Record<'a> = &'a calxgloss_globalstate::types::GlobalStateFinding;

    fn load(workspace: &Path, binary: &str) -> Result<Self::Doc, DocLoadError> {
        calxgloss_globalstate::persist::GlobalStatePersistor::new(workspace)
            .load(binary)
            .map_err(|error| match error {
                calxgloss_globalstate::GlobalStateError::NotFound { path } => {
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
            .global_state_findings
            .push(calxgloss_prompts::GlobalStateInfo::from(record));
    }

    fn fill_coverage(doc: &Self::Doc, bundle: &mut EvidenceBundle) {
        // Only a document that carries a coverage record fills one; a
        // pre-P19 document, whose field's absence reads as no record,
        // fills nothing and keeps the old render byte-identical. The
        // record says which bodies the scan never reached — never an
        // examined-and-clean body its record list left unmentioned
        // (issue #350).
        if let Some(coverage) = doc.metadata.coverage.as_ref() {
            bundle.global_state_coverage = calxgloss_prompts::CoverageInfo::from(coverage);
        }
    }
}

// ============================================================
// The two shared multi-field adapters (#314)
// ============================================================

/// The constant document, `re/analysis/consts/{binary}.json`: every
/// finding naming the function rides the union `const_findings` — the
/// escalate CONSTANTS section reads the whole union, table included —
/// while a table record *also* fills `data_table_findings` for the
/// module-context DATA TABLES section. One row, one load, two fields:
/// the union and the table records can never disagree about what the
/// workspace holds.
pub struct ConstsDoc;

impl AnalysisDoc for ConstsDoc {
    const KIND: &'static str = "constant result";

    type Doc = calxgloss_consts::types::ConstResult;
    type Record<'a> = &'a calxgloss_consts::types::ConstFinding;

    fn load(workspace: &Path, binary: &str) -> Result<Self::Doc, DocLoadError> {
        calxgloss_consts::persist::ConstPersistor::new(workspace)
            .load(binary)
            .map_err(|error| match error {
                calxgloss_consts::ConstError::NotFound { path } => {
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
        // The table record fans out to its own field first; the union
        // entry it also rides keeps the escalate CONSTANTS section in
        // the same single pass.
        if let calxgloss_consts::types::ConstFinding::DataTable(table) = record {
            bundle
                .data_table_findings
                .push(calxgloss_prompts::DataTableInfo::from(table));
        }
        bundle
            .const_findings
            .push(calxgloss_prompts::ConstInfo::from(record));
    }

    fn fill_coverage(doc: &Self::Doc, bundle: &mut EvidenceBundle) {
        // Only a document that carries a coverage record fills one; a
        // pre-P19 document, whose field's absence reads as no record,
        // fills nothing and keeps the old render byte-identical. One
        // fill feeds both sections this load populates — the constants
        // union and the data-tables list — because one constant scan
        // stamped both. The record names the bodies and memory windows
        // it never reached, never a constant it read and did not name
        // (issue #348).
        if let Some(coverage) = doc.metadata.coverage.as_ref() {
            bundle.consts_coverage = calxgloss_prompts::CoverageInfo::from(coverage);
        }
    }
}

/// The type-inference document, `re/analysis/typeinfer/{binary}.json`:
/// every inference naming the function rides `type_info` — parameter,
/// local, call-site, return, and convention and direction readings
/// alike, each through the existing type-info conversion — while a
/// convention record *also* fills `convention_findings` and a direction
/// record *also* fills `parameter_direction_findings`. One row, one
/// load, three fields: the convention extraction no longer re-reads the
/// document a third time (issue #314).
pub struct TypeInferDoc;

impl AnalysisDoc for TypeInferDoc {
    const KIND: &'static str = "type inference result";

    type Doc = calxgloss_typeinfer::types::TypeInferenceResult;
    type Record<'a> = &'a calxgloss_typeinfer::types::InferredType;

    fn load(workspace: &Path, binary: &str) -> Result<Self::Doc, DocLoadError> {
        calxgloss_typeinfer::persist::TypeInferPersistor::new(workspace)
            .load(binary)
            .map_err(|error| match error {
                calxgloss_typeinfer::TypeInferError::NotFound { path } => {
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
        // Every reading lands in type_info exactly as the type-info
        // seam converted it before — the direction line rides this
        // section on the escalate side (issue #276). The two kinds with
        // a module-context section of their own fan out beside it.
        bundle
            .type_info
            .push(calxgloss_prompts::TypeInfo::from(record));
        match record {
            calxgloss_typeinfer::types::InferredType::Convention(reading) => {
                bundle
                    .convention_findings
                    .push(calxgloss_prompts::ConventionInfo::from(reading));
            }
            calxgloss_typeinfer::types::InferredType::Direction(reading) => {
                bundle
                    .parameter_direction_findings
                    .push(calxgloss_prompts::ParameterDirectionInfo::from(reading));
            }
            _ => {}
        }
    }

    fn fill_coverage(doc: &Self::Doc, bundle: &mut EvidenceBundle) {
        // Only a document that carries a coverage record fills one; a
        // pre-P19 document, whose field's absence reads as no record,
        // fills nothing and keeps the old render byte-identical. The
        // ONE record qualifies all THREE surfaces this row feeds — the
        // type information list, the calling convention list, and the
        // parameter direction list — because one type-inference scan
        // stamped them together; the same admission line lands in each
        // section. The record names the listings and edges the scan
        // never reached, never a reading it made and left unrecorded
        // (issue #351).
        if let Some(coverage) = doc.metadata.coverage.as_ref() {
            bundle.type_inference_coverage = calxgloss_prompts::CoverageInfo::from(coverage);
        }
    }
}

// ============================================================
// The registered projection table
// ============================================================

/// The projection rows the gather folds, in registered order: the six
/// single-field engines of the first migration batch (issue #312), the
/// six of the second (issue #313), and the two shared documents as
/// multi-field rows last (issue #314 — the fields they feed belong to
/// those rows alone, so their table position fixes nothing). A field
/// fed by several rows receives them in table order, so this order is
/// the prompts' order — changing it rewrites prompt sections for no
/// reason and must be a deliberate edit.
pub static PROJECTION_ROWS: &[ProjectionRow] = &[
    ProjectionRow::of::<AlgorithmDoc>(),
    ProjectionRow::of::<MemoryDoc>(),
    ProjectionRow::of::<SyncDoc>(),
    ProjectionRow::of::<StringContextDoc>(),
    ProjectionRow::of::<ApiDoc>(),
    ProjectionRow::of::<FloatsimdDoc>(),
    ProjectionRow::of::<TypeDatabaseDoc>(),
    ProjectionRow::of::<SerializationDoc>(),
    ProjectionRow::of::<CallbackDoc>(),
    ProjectionRow::of::<ControlFlowDoc>(),
    ProjectionRow::of::<ErrorHandlingDoc>(),
    ProjectionRow::of::<GlobalStateDoc>(),
    ProjectionRow::of::<ConstsDoc>(),
    ProjectionRow::of::<TypeInferDoc>(),
];

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::retry::helpers::gather_function_evidence;
    use tempfile::TempDir;

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
                "callback result",
                "concurrency result",
                "constant result",
                "control-flow result",
                "error-handling result",
                "float/SIMD result",
                "global-state result",
                "memory lifecycle result",
                "serialization result",
                "string context result",
                "type database",
                "type inference result",
            ],
            "exactly the fourteen engines of the three migration batches \
             (issues #312, #313, #314) are registered"
        );
    }

    /// The four fan-out rows' coverage legs (issue #351): one gather of a
    /// workspace whose four documents each carry a stamped record fills
    /// each coverage field exactly once — a second gather lands the same
    /// single record, never a doubled or merged one — and the fills
    /// follow the registered order of the rows, each landing in its own
    /// field. A document filed before coverage stamping (the standing
    /// kit's shape) leaves its field default-empty, and a missing or
    /// corrupt document fills neither findings nor coverage.
    #[test]
    fn coverage_projection_covers_the_engine_coverage_record_of_every_project_document() {
        use calxgloss_types::{CoverageStatus, FacetCoverage, ScanCoverage, ScanMetadata};

        let stamped = |facets: &[(&str, CoverageStatus, &str)]| ScanCoverage {
            status: if facets
                .iter()
                .any(|(_, status, _)| *status != CoverageStatus::Complete)
            {
                CoverageStatus::Partial
            } else {
                CoverageStatus::Complete
            },
            facets: facets
                .iter()
                .map(|(id, status, line)| FacetCoverage {
                    id: (*id).to_string(),
                    status: *status,
                    limitation: if *status == CoverageStatus::Complete {
                        None
                    } else {
                        Some((*line).to_string())
                    },
                })
                .collect(),
        };

        let workspace = TempDir::new().expect("fixture workspace");
        let dir = workspace.path();

        let mut metadata = ScanMetadata::new("eqmain.dll");
        metadata.coverage = Some(stamped(&[
            (
                "function-bodies",
                CoverageStatus::Partial,
                "ALGO-BODIES-LINE",
            ),
            (
                "caller-edges",
                CoverageStatus::Unavailable,
                "ALGO-EDGES-LINE",
            ),
        ]));
        let mut algorithm = calxgloss_algorithm::types::AlgorithmRecognitionResult::new(metadata);
        algorithm.hints = vec![calxgloss_algorithm::types::AlgorithmHint {
            function: "FUN_18003ab00".to_string(),
            algorithm: "CRC-32".to_string(),
            category: calxgloss_algorithm::types::AlgorithmCategory::Checksum,
            method: calxgloss_algorithm::types::DetectionMethod::CfgPattern,
            confidence: calxgloss_algorithm::types::Confidence::new(90),
            evidence: "0xEDB88320".to_string(),
        }];
        calxgloss_algorithm::persist::AlgorithmPersistor::new(dir)
            .save(&algorithm)
            .expect("the stamped algorithm document should be saved");

        let mut metadata = ScanMetadata::new("eqmain.dll");
        metadata.coverage = Some(stamped(&[
            (
                "function-bodies",
                CoverageStatus::Partial,
                "STR-BODIES-LINE",
            ),
            (
                "program-strings",
                CoverageStatus::Unavailable,
                "STR-LISTING-LINE",
            ),
            (
                "string-xrefs",
                CoverageStatus::Unavailable,
                "STR-XREFS-LINE",
            ),
        ]));
        let mut stringctx = calxgloss_stringctx::types::StringContextResult::new(metadata);
        stringctx.findings = vec![calxgloss_stringctx::types::StringFinding::Classified(
            calxgloss_stringctx::types::ClassifiedString {
                function: "FUN_18003ab00".to_string(),
                string_address: 0x180127cd8,
                string_value: "Journal.txt".to_string(),
                classification: calxgloss_stringctx::types::StringClassification::FilePath,
                purpose: "config file path".to_string(),
                source: calxgloss_stringctx::types::StringSource::BodyParse,
                confidence: calxgloss_stringctx::types::Confidence::new(60),
                evidence: "lpszVar1 = \"Journal.txt\";".to_string(),
            },
        )];
        calxgloss_stringctx::persist::StringContextPersistor::new(dir)
            .save(&stringctx)
            .expect("the stamped string-context document should be saved");

        let mut metadata = ScanMetadata::new("eqmain.dll");
        metadata.coverage = Some(stamped(&[(
            "function-bodies",
            CoverageStatus::Partial,
            "SER-BODIES-LINE",
        )]));
        let mut serialize = calxgloss_serialize::types::SerializeResult::new(metadata);
        serialize.findings = vec![calxgloss_serialize::types::SerializeFinding::ByteSwap(
            calxgloss_serialize::types::ByteSwapOperation {
                function: "FUN_18003ab00".to_string(),
                operation: "ntohl".to_string(),
                width: 32,
                suggestion: "byteorder::BE::read_u32".to_string(),
                confidence: calxgloss_serialize::types::Confidence::new(70),
                evidence: "uVar2 = ntohl(uVar1);".to_string(),
            },
        )];
        calxgloss_serialize::persist::SerializePersistor::new(dir)
            .save(&serialize)
            .expect("the stamped serialization document should be saved");

        let mut metadata = ScanMetadata::new("eqmain.dll");
        metadata.coverage = Some(stamped(&[
            ("function-bodies", CoverageStatus::Complete, ""),
            (
                "machine-listings",
                CoverageStatus::Partial,
                "TYPE-LISTINGS-LINE",
            ),
            (
                "import-names",
                CoverageStatus::Unavailable,
                "TYPE-IMPORTS-LINE",
            ),
            (
                "caller-edges",
                CoverageStatus::Unavailable,
                "TYPE-EDGES-LINE",
            ),
        ]));
        let mut typeinfer = calxgloss_typeinfer::types::TypeInferenceResult::new(metadata);
        typeinfer.inferences = vec![calxgloss_typeinfer::types::InferredType::Param(
            calxgloss_typeinfer::types::InferredParamType {
                function: "FUN_18003ab00".to_string(),
                param_index: 0,
                param_name: Some("param_1".to_string()),
                inferred_type: "char *".to_string(),
                method: calxgloss_typeinfer::types::InferenceMethod::StringFunction,
                scope: calxgloss_typeinfer::types::InferenceScope::Function,
                confidence: calxgloss_typeinfer::types::Confidence::new(80),
                evidence: "lstrlenA(param_1)".to_string(),
            },
        )];
        calxgloss_typeinfer::persist::TypeInferPersistor::new(dir)
            .save(&typeinfer)
            .expect("the stamped type-inference document should be saved");

        let bundle = gather_function_evidence(Some(dir), "eqmain.dll", "FUN_18003ab00", &[]);

        // Each field holds exactly its own engine's record: the admission
        // line joins the limitation lines of exactly the facets that fell
        // short, in the record's own facet order, so a facet landing in —
        // or merging across — another engine's field fails here. The
        // wording *style* itself is proven word-for-word at the gather
        // seam in the helpers' tests; these marker lines keep the fields
        // visibly distinct.
        assert_eq!(
            bundle.algorithm_coverage.status, "partial",
            "the algorithm record's overall status rides its own field"
        );
        assert_eq!(
            bundle.algorithm_coverage.admission,
            "partial — ALGO-BODIES-LINE; ALGO-EDGES-LINE"
        );
        assert_eq!(
            bundle.string_context_coverage.admission,
            "partial — STR-BODIES-LINE; STR-LISTING-LINE; STR-XREFS-LINE"
        );
        assert_eq!(
            bundle.serialization_coverage.admission,
            "partial — SER-BODIES-LINE"
        );
        assert_eq!(
            bundle.type_inference_coverage.admission,
            "partial — TYPE-LISTINGS-LINE; TYPE-IMPORTS-LINE; TYPE-EDGES-LINE",
            "the complete bodies facet drops out of the admission; the \
             three surfaces this row feeds all qualify from this one line"
        );

        // Each field was filled exactly once: the fills assign one record
        // per document, so gathering again lands the same single record,
        // never a doubled or merged one.
        let again = gather_function_evidence(Some(dir), "eqmain.dll", "FUN_18003ab00", &[]);
        assert_eq!(again.algorithm_coverage, bundle.algorithm_coverage);
        assert_eq!(
            again.string_context_coverage,
            bundle.string_context_coverage
        );
        assert_eq!(again.serialization_coverage, bundle.serialization_coverage);
        assert_eq!(
            again.type_inference_coverage,
            bundle.type_inference_coverage
        );

        // The one record qualifies all three type-inference surfaces: the
        // single load fills the type-information list beside the same one
        // coverage record — the convention and direction lists ride the
        // same field even when this fixture files none of their kind.
        assert_eq!(bundle.type_info.len(), 1);
        assert!(
            bundle.convention_findings.is_empty() && bundle.parameter_direction_findings.is_empty()
        );
    }

    /// A document filed before coverage stamping — the standing fixture
    /// kit's shape, with findings but no record — leaves its coverage
    /// field default-empty while the findings still ride: the old render
    /// stands (issue #351).
    #[test]
    fn fill_coverage_from_a_pre_p19_kit_document_fills_neither_findings_side_nor_coverage() {
        use calxgloss_types::ScanMetadata;

        let workspace = TempDir::new().expect("fixture workspace");
        let dir = workspace.path();

        let mut algorithm = calxgloss_algorithm::types::AlgorithmRecognitionResult::new(
            ScanMetadata::new("eqmain.dll"),
        );
        algorithm.hints = vec![calxgloss_algorithm::types::AlgorithmHint {
            function: "FUN_18003ab00".to_string(),
            algorithm: "CRC-32".to_string(),
            category: calxgloss_algorithm::types::AlgorithmCategory::Checksum,
            method: calxgloss_algorithm::types::DetectionMethod::CfgPattern,
            confidence: calxgloss_algorithm::types::Confidence::new(90),
            evidence: "0xEDB88320".to_string(),
        }];
        calxgloss_algorithm::persist::AlgorithmPersistor::new(dir)
            .save(&algorithm)
            .expect("the pre-P19 algorithm document should be saved");

        let mut stringctx =
            calxgloss_stringctx::types::StringContextResult::new(ScanMetadata::new("eqmain.dll"));
        stringctx.findings = vec![calxgloss_stringctx::types::StringFinding::Classified(
            calxgloss_stringctx::types::ClassifiedString {
                function: "FUN_18003ab00".to_string(),
                string_address: 0x180127cd8,
                string_value: "Journal.txt".to_string(),
                classification: calxgloss_stringctx::types::StringClassification::FilePath,
                purpose: "config file path".to_string(),
                source: calxgloss_stringctx::types::StringSource::BodyParse,
                confidence: calxgloss_stringctx::types::Confidence::new(60),
                evidence: "lpszVar1 = \"Journal.txt\";".to_string(),
            },
        )];
        calxgloss_stringctx::persist::StringContextPersistor::new(dir)
            .save(&stringctx)
            .expect("the pre-P19 string-context document should be saved");

        let mut serialize =
            calxgloss_serialize::types::SerializeResult::new(ScanMetadata::new("eqmain.dll"));
        serialize.findings = vec![calxgloss_serialize::types::SerializeFinding::ByteSwap(
            calxgloss_serialize::types::ByteSwapOperation {
                function: "FUN_18003ab00".to_string(),
                operation: "ntohl".to_string(),
                width: 32,
                suggestion: "byteorder::BE::read_u32".to_string(),
                confidence: calxgloss_serialize::types::Confidence::new(70),
                evidence: "uVar2 = ntohl(uVar1);".to_string(),
            },
        )];
        calxgloss_serialize::persist::SerializePersistor::new(dir)
            .save(&serialize)
            .expect("the pre-P19 serialization document should be saved");

        let mut typeinfer =
            calxgloss_typeinfer::types::TypeInferenceResult::new(ScanMetadata::new("eqmain.dll"));
        typeinfer.inferences = vec![calxgloss_typeinfer::types::InferredType::Param(
            calxgloss_typeinfer::types::InferredParamType {
                function: "FUN_18003ab00".to_string(),
                param_index: 0,
                param_name: Some("param_1".to_string()),
                inferred_type: "char *".to_string(),
                method: calxgloss_typeinfer::types::InferenceMethod::StringFunction,
                scope: calxgloss_typeinfer::types::InferenceScope::Function,
                confidence: calxgloss_typeinfer::types::Confidence::new(80),
                evidence: "lstrlenA(param_1)".to_string(),
            },
        )];
        calxgloss_typeinfer::persist::TypeInferPersistor::new(dir)
            .save(&typeinfer)
            .expect("the pre-P19 type-inference document should be saved");

        let bundle = gather_function_evidence(Some(dir), "eqmain.dll", "FUN_18003ab00", &[]);

        // The findings still ride their rows.
        assert_eq!(bundle.recognized_algorithms.len(), 1);
        assert_eq!(bundle.string_findings.len(), 1);
        assert_eq!(bundle.serialization_findings.len(), 1);
        assert_eq!(bundle.type_info.len(), 1);
        // The coverage fields stay default-empty: an empty admission is
        // exactly the includes' signal that there is nothing to admit,
        // so every old render stands byte-identically.
        for coverage in [
            &bundle.algorithm_coverage,
            &bundle.string_context_coverage,
            &bundle.serialization_coverage,
            &bundle.type_inference_coverage,
        ] {
            assert!(coverage.status.is_empty() && coverage.admission.is_empty());
        }
    }

    /// A missing document fills neither findings nor coverage, exactly as
    /// its findings-side degradation already reads (issue #351).
    #[test]
    fn a_missing_project_document_fills_neither_findings_nor_coverage() {
        let workspace = TempDir::new().expect("fixture workspace");
        let bundle =
            gather_function_evidence(Some(workspace.path()), "eqmain.dll", "FUN_18003ab00", &[]);
        assert!(
            bundle.recognized_algorithms.is_empty()
                && bundle.algorithm_coverage.admission.is_empty()
        );
        assert!(
            bundle.string_findings.is_empty()
                && bundle.string_context_coverage.admission.is_empty()
        );
        assert!(
            bundle.serialization_findings.is_empty()
                && bundle.serialization_coverage.admission.is_empty()
        );
        assert!(bundle.type_info.is_empty() && bundle.type_inference_coverage.admission.is_empty());
    }
}
