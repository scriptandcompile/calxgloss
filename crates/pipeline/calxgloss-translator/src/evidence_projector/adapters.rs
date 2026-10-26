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
}
