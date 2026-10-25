//! The evidence-bundle projector — one `AnalysisDoc` seam between the
//! persisted analysis documents and the prompt bundle (issue #311, spec #310).
//!
//! Nineteen near-identical `extract_*`/`load_*` functions in
//! [`retry::helpers`](crate::retry) currently spell the same three steps
//! per engine: load the engine's persisted analysis document for the
//! binary, keep the records for the target function, convert them
//! through the prompts crate's `From` impls. This module spells those
//! steps once, behind one interface: [`AnalysisDoc`] is the seam (load,
//! per-function selection, conversion), [`load_and_project`] is the
//! generic contract, and [`ProjectionRow`] pairs an adapter with the
//! bundle field(s) it fills so [`project_bundle`] can assemble the
//! bundle by fold — the same descriptor-table shape P34's
//! [`scan_registry`](crate::scan_registry) proved on the write side,
//! kept deliberately separate: the scan-descriptor table owns the scan
//! write path, this seam owns the prompt read path.
//!
//! The degradation contract, spelled exactly once here and inherited
//! by every adapter (an adapter never logs and never degrades):
//!
//! * no workspace configured → the field stays empty, nothing is
//!   logged — nothing was ever going to be there;
//! * document missing or unparseable → a `debug` line naming the
//!   document kind, the binary, and the error, then the field stays
//!   empty — missing context degrades the prompt, it never fails it,
//!   and the two failure kinds log distinctly (nothing persisted means
//!   the scan never ran; a broken artifact means the document on disk
//!   needs investigating);
//! * document present → exactly that function's records, converted, in
//!   scan order, pushed into the designated field(s).
//!
//! Documents that feed two bundle fields — the consts document (the
//! union findings and the data-table records) and the type-inference
//! document (type info and parameter directions) — are one multi-field
//! row: a single load feeds both fields, so they can never disagree
//! about what the workspace holds.
//!
//! This seam stands *beside* the existing gather: nothing in
//! `gather_function_evidence` moves onto rows until issue #312, and
//! the shared documents not until #314. What is proven here is the
//! fold itself, pinned against a fake in-memory adapter — the real
//! adapters arrive with the migration, and the parametrized suite
//! driven through `gather_function_evidence` covers them there.

use std::error::Error;
use std::path::Path;

use calxgloss_prompts::EvidenceBundle;
use thiserror::Error;
use tracing::debug;

/// Why loading one analysis document came up empty.
///
/// Both cases degrade the bundle identically — the fold projects
/// nothing and the prompt still builds — but they log distinctly, and
/// the distinction is why this type exists: a missing document says
/// the scan has not run for this binary (recompute), a corrupt one
/// says the artifact on disk is broken (investigate). An engine
/// adapter maps its persistor's error onto this type the way it maps
/// `PersistError` onto its own crate error: the persistor's
/// `NotFound` variant folds into [`Missing`](Self::Missing), every
/// other failure into [`Corrupt`](Self::Corrupt).
#[derive(Debug, Error)]
pub enum DocLoadError {
    /// Nothing is persisted for the binary — the engine's scan has
    /// never run. The payload names where the document would have
    /// been.
    #[error("nothing persisted at: {0}")]
    Missing(String),

    /// A document is persisted but cannot be read — corrupt JSON or an
    /// I/O failure while reading it.
    #[error("the persisted document is unusable: {0}")]
    Corrupt(#[from] Box<dyn Error + Send + Sync + 'static>),
}

/// One persisted analysis document, seen as what the projector needs
/// of it: a per-function record source for one target binary.
///
/// The seam exposes exactly the three steps every hand-copied
/// `extract_*` spelling repeats, and nothing else:
///
/// 1. [`load`](Self::load) — read the engine's persisted document for
///    the binary, through that engine's own persistor;
/// 2. [`for_function`](Self::for_function) — yield the records the
///    document holds for one function: other functions' records
///    dropped, program-level records naming the function included, in
///    scan/input order;
/// 3. [`fill`](Self::fill) — convert each record through the prompts
///    crate's existing `From` impls into the bundle field(s) this
///    document fills.
///
/// An implementor is a unit struct, one per analysis document, named
/// once by a [`ProjectionRow`] — all the shared machinery (the
/// workspace check, the miss logs, the degradation) belongs to
/// [`load_and_project`], never to the adapter. The nineteen documents
/// `gather_function_evidence` reads get their adapters as the gather
/// migrates (issues #312–#314); the libmatch document's call-graph
/// correlation and the whole-DLL extractions stay bespoke outside
/// this seam, exactly as specced (#310).
pub trait AnalysisDoc {
    /// The document kind, named in the miss log so an absent bundle
    /// field stays answerable from the logs — "why is this engine not
    /// in the prompt" — and doubling as the row's identity in the
    /// roster test that pins the registered rows.
    const KIND: &'static str;

    /// The whole loaded document for one binary, whatever the
    /// engine's result type happens to be.
    type Doc;

    /// One record of the document, as `for_function` hands it to
    /// `fill` — usually `&'a EngineRecord`, mirroring the engines' own
    /// `for_function`, so conversion rides the existing
    /// reference-taking `From` impls.
    type Record<'a>;

    /// Load this engine's persisted analysis document for `binary`
    /// from the workspace root.
    fn load(workspace: &Path, binary: &str) -> Result<Self::Doc, DocLoadError>;

    /// The records `doc` holds for `function`, in scan/input order.
    fn for_function<'a>(
        doc: &'a Self::Doc,
        function: &str,
    ) -> impl Iterator<Item = Self::Record<'a>>;

    /// Convert one record through the prompts crate's `From` impls and
    /// push it into the bundle field(s) this row fills. Called once
    /// per record of `for_function`'s iteration; a multi-field row —
    /// the shared consts and type-inference documents — pushes into
    /// more than one field here, from the single load its row performs.
    fn fill(record: Self::Record<'_>, bundle: &mut EvidenceBundle);
}

/// The fold's step for one row, type-erased: each engine's document is
/// its own type and the seventeen cannot sit in one list unboxed, so
/// [`ProjectionRow::of`] monomorphizes the whole seam into this one
/// function pointer.
type ProjectStep = fn(Option<&Path>, &str, &str, &mut EvidenceBundle);

/// The shared contract, spelled once: run one adapter's three legs
/// against the workspace and project the document's records into
/// `bundle`, with the whole degradation rule applied here and nowhere
/// else — no workspace configured projects nothing and logs nothing;
/// a missing or unparseable document logs its miss (see
/// [`DocLoadError`]) and projects nothing; a present document
/// contributes exactly its `for_function` records, converted by
/// `fill`, in scan order.
///
/// The prompt is never failed by absent context: this function cannot
/// fail at all.
pub fn load_and_project<D: AnalysisDoc>(
    workspace: Option<&Path>,
    binary: &str,
    function: &str,
    bundle: &mut EvidenceBundle,
) {
    let Some(workspace) = workspace else {
        // No workspace was ever configured — there is nothing to miss.
        return;
    };

    let doc = match D::load(workspace, binary) {
        Ok(doc) => doc,
        Err(e) => {
            // Missing and corrupt degrade alike but log distinctly.
            match &e {
                DocLoadError::Missing(_) => debug!(
                    doc = D::KIND,
                    binary,
                    error = %e,
                    "No {kind} persisted for the binary; continuing without its context",
                    kind = D::KIND
                ),
                DocLoadError::Corrupt(_) => debug!(
                    doc = D::KIND,
                    binary,
                    error = %e,
                    "The persisted {kind} is unusable; continuing without its context",
                    kind = D::KIND
                ),
            }
            return;
        }
    };

    for record in D::for_function(&doc, function) {
        D::fill(record, bundle);
    }
}

/// One row of the projection table: an [`AnalysisDoc`] adapter paired
/// with the `EvidenceBundle` field(s) its records fill, kept
/// type-erased so every row — each with its own document and record
/// types — is one entry of one static list.
///
/// A shared two-field document is one row, not two: its single load
/// feeds both fields, so the fields can never disagree about what the
/// workspace holds. `kind` is the row's identity — the row-membership
/// roster (issue #312) asserts the set of registered kinds, so an
/// engine that forgets its row fails CI instead of silently vanishing
/// from prompts.
#[derive(Debug, Clone, Copy)]
pub struct ProjectionRow {
    /// The document kind this row projects — its identity in the
    /// table and its name in the miss log.
    pub kind: &'static str,

    /// The row's adapter and field fills, monomorphized once by
    /// [`ProjectionRow::of`] and run through the shared contract.
    step: ProjectStep,
}

impl ProjectionRow {
    /// The row for one adapter type: the adapter, its per-function
    /// selection, and its field fills monomorphized behind
    /// [`load_and_project`], so a registered row adds no per-engine
    /// spelling of its own.
    pub fn of<D: AnalysisDoc>() -> Self {
        Self {
            kind: D::KIND,
            step: |workspace, binary, function, bundle| {
                load_and_project::<D>(workspace, binary, function, bundle)
            },
        }
    }

    /// Run this row's projection into `bundle`.
    pub fn project(
        &self,
        workspace: Option<&Path>,
        binary: &str,
        function: &str,
        bundle: &mut EvidenceBundle,
    ) {
        (self.step)(workspace, binary, function, bundle);
    }
}

/// Assemble an evidence bundle by folding the rows in their
/// registered order — the shape `gather_function_evidence` takes over
/// as the single-field engines migrate onto rows (issue #312) and the
/// shared documents follow (#314).
///
/// Row order is projection order: a field fed by several rows receives
/// them in table order, keeping prompt diffs between attempts diffable.
pub fn project_bundle(
    rows: &[ProjectionRow],
    workspace: Option<&Path>,
    binary: &str,
    function: &str,
) -> EvidenceBundle {
    let mut bundle = EvidenceBundle::default();
    for row in rows {
        row.project(workspace, binary, function, &mut bundle);
    }
    bundle
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use calxgloss_prompts::{ConstInfo, DataTableInfo, TypeInfo};
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::path::PathBuf;
    use tempfile::TempDir;
    use tracing_test::traced_test;

    // The fake in-memory adapters (issue #311, spec #310's seam 2):
    // the generic fold gets pinned once against these fakes, and the
    // real adapters get their coverage from the parametrized suite at
    // `gather_function_evidence` when they register (issue #312).
    //
    // Every scenario gets its own fake kind and its own binary name:
    // the log-capture buffer is process-global while tests run in
    // parallel, so each assertion quotes its scenario's own kind and
    // binary and stays meaningful regardless of what other tests log.

    /// One record of the fake store, shared by every fake adapter: the
    /// function it belongs to, a label the projected info carries, and
    /// the table flag the multi-field fake projects into a second
    /// field — standing in for the consts document's table records.
    #[derive(Debug, Clone)]
    struct FakeRecord {
        function: String,
        label: String,
        table: bool,
    }

    fn record(function: &str, label: &str, table: bool) -> FakeRecord {
        FakeRecord {
            function: function.to_string(),
            label: label.to_string(),
            table,
        }
    }

    /// What the fake workspace holds under one (document kind, binary)
    /// — a persisted document, a corrupt one, or, when the key is
    /// absent, no document at all.
    enum Stored {
        Present(Vec<FakeRecord>),
        Corrupt,
    }

    thread_local! {
        /// The fake workspace: every fake document, keyed by its kind
        /// and the binary it is filed for.
        static FAKE_STORE: RefCell<HashMap<(&'static str, String), Stored>> =
            HashMap::new().into();

        /// Loads counted per document kind — the pin that a
        /// multi-field row loads its shared document exactly once.
        static FAKE_LOAD_COUNTS: RefCell<HashMap<&'static str, usize>> = HashMap::new().into();
    }

    fn fake_put(kind: &'static str, binary: &str, records: Vec<FakeRecord>) {
        FAKE_STORE.with(|store| {
            store
                .borrow_mut()
                .insert((kind, binary.to_string()), Stored::Present(records));
        });
    }

    fn fake_corrupt(kind: &'static str, binary: &str) {
        FAKE_STORE.with(|store| {
            store
                .borrow_mut()
                .insert((kind, binary.to_string()), Stored::Corrupt);
        });
    }

    fn fake_load(kind: &'static str, binary: &str) -> Result<Vec<FakeRecord>, DocLoadError> {
        FAKE_LOAD_COUNTS.with(|counts| *counts.borrow_mut().entry(kind).or_insert(0) += 1);
        FAKE_STORE.with(
            |store| match store.borrow().get(&(kind, binary.to_string())) {
                // The miss texts quote the kind but never the binary, so
                // a log line naming the binary can only be the fold's
                // `binary` field.
                Some(Stored::Present(records)) => Ok(records.clone()),
                Some(Stored::Corrupt) => Err(DocLoadError::Corrupt(
                    format!("the persisted {kind} record is not parseable").into(),
                )),
                None => Err(DocLoadError::Missing(format!(
                    "no {kind} sits at the fake store location"
                ))),
            },
        )
    }

    fn fake_load_count(kind: &'static str) -> usize {
        FAKE_LOAD_COUNTS.with(|counts| counts.borrow().get(kind).copied().unwrap_or(0))
    }

    impl From<&FakeRecord> for TypeInfo {
        fn from(record: &FakeRecord) -> Self {
            TypeInfo {
                name: record.label.clone(),
                description: String::new(),
            }
        }
    }

    impl From<&FakeRecord> for ConstInfo {
        fn from(record: &FakeRecord) -> Self {
            ConstInfo {
                function: record.function.clone(),
                kind: if record.table {
                    "data_table"
                } else {
                    "named_constant"
                }
                .to_string(),
                suggestion: record.label.clone(),
                confidence: 90,
                evidence: String::new(),
            }
        }
    }

    impl From<&FakeRecord> for DataTableInfo {
        fn from(record: &FakeRecord) -> Self {
            DataTableInfo {
                name: record.label.clone(),
                element_type: "u16".to_string(),
                count: 3,
                confidence: 90,
            }
        }
    }

    /// One fake adapter filling the type-info field from the store,
    /// borrowing its records the way every real engine's
    /// `for_function` does. A kind of its own per scenario keeps the
    /// log assertions scenario-local.
    macro_rules! fake_single_doc {
        ($name:ident, $kind:literal) => {
            struct $name;

            impl AnalysisDoc for $name {
                const KIND: &'static str = $kind;
                type Doc = Vec<FakeRecord>;
                type Record<'a> = &'a FakeRecord;

                fn load(_workspace: &Path, binary: &str) -> Result<Self::Doc, DocLoadError> {
                    fake_load(Self::KIND, binary)
                }

                fn for_function<'a>(
                    doc: &'a Self::Doc,
                    function: &str,
                ) -> impl Iterator<Item = Self::Record<'a>> {
                    doc.iter().filter(move |r| r.function == function)
                }

                fn fill(record: Self::Record<'_>, bundle: &mut EvidenceBundle) {
                    bundle.type_info.push(TypeInfo::from(record));
                }
            }
        };
    }

    fake_single_doc!(FakePresentDoc, "fake present document");
    fake_single_doc!(FakeNoWorkspaceDoc, "fake unwritten document");
    fake_single_doc!(FakeMissingDoc, "fake missing document");
    fake_single_doc!(FakeCorruptDoc, "fake corrupt document");
    fake_single_doc!(FakeFirstRowDoc, "fake first-row document");
    fake_single_doc!(FakeSecondRowDoc, "fake second-row document");

    /// A fake multi-field document standing in for the shared consts
    /// document: every record rides the const-findings union, and a
    /// table record additionally rides the data-table findings — both
    /// fields from the row's single load.
    struct FakeSharedDoc;

    impl AnalysisDoc for FakeSharedDoc {
        const KIND: &'static str = "fake shared document";
        type Doc = Vec<FakeRecord>;
        type Record<'a> = &'a FakeRecord;

        fn load(_workspace: &Path, binary: &str) -> Result<Self::Doc, DocLoadError> {
            fake_load(Self::KIND, binary)
        }

        fn for_function<'a>(
            doc: &'a Self::Doc,
            function: &str,
        ) -> impl Iterator<Item = Self::Record<'a>> {
            doc.iter().filter(move |r| r.function == function)
        }

        fn fill(record: Self::Record<'_>, bundle: &mut EvidenceBundle) {
            bundle.const_findings.push(ConstInfo::from(record));
            if record.table {
                bundle.data_table_findings.push(DataTableInfo::from(record));
            }
        }
    }

    fn temp_workspace() -> (TempDir, PathBuf) {
        let dir = TempDir::new().expect("temp workspace");
        let path = dir.path().to_path_buf();
        (dir, path)
    }

    #[traced_test]
    #[test]
    fn a_persisted_document_projects_only_the_functions_records_in_order() {
        fake_put(
            FakePresentDoc::KIND,
            "persisted.dll",
            vec![
                record("FUN_18003ab00", "first-reading", false),
                record("FUN_zzz", "another-functions-reading", false),
                record("FUN_18003ab00", "second-reading", false),
            ],
        );
        let (_workspace, path) = temp_workspace();

        let bundle = project_bundle(
            &[ProjectionRow::of::<FakePresentDoc>()],
            Some(&path),
            "persisted.dll",
            "FUN_18003ab00",
        );

        let names: Vec<&str> = bundle.type_info.iter().map(|t| t.name.as_str()).collect();
        assert_eq!(
            names,
            ["first-reading", "second-reading"],
            "other functions' records dropped, the function's kept in document order"
        );
        assert!(
            !logs_contain("fake present document"),
            "a present document logs no miss"
        );
    }

    #[traced_test]
    #[test]
    fn no_workspace_configured_projects_nothing_and_logs_nothing() {
        fake_put(
            FakeNoWorkspaceDoc::KIND,
            "nowrite.dll",
            vec![record("FUN_18003ab00", "unread-reading", false)],
        );

        let bundle = project_bundle(
            &[ProjectionRow::of::<FakeNoWorkspaceDoc>()],
            None,
            "nowrite.dll",
            "FUN_18003ab00",
        );

        assert!(
            bundle.type_info.is_empty(),
            "no workspace configured → the field stays empty"
        );
        assert!(
            !logs_contain("fake unwritten document"),
            "nothing was ever going to be there: no miss log names the document"
        );
    }

    #[traced_test]
    #[test]
    fn a_missing_document_degrades_to_empty_and_logs_the_miss() {
        let (_workspace, path) = temp_workspace();

        let bundle = project_bundle(
            &[ProjectionRow::of::<FakeMissingDoc>()],
            Some(&path),
            "missingcase.dll",
            "FUN_18003ab00",
        );

        assert!(
            bundle.type_info.is_empty(),
            "a missing document is missing context, not a failed prompt"
        );
        assert!(
            logs_contain("No fake missing document persisted for the binary"),
            "the miss names the document kind, and a missing document says the scan never ran"
        );
        assert!(
            logs_contain("doc=")
                && logs_contain("missingcase.dll")
                && logs_contain("no fake missing document sits at the fake store location"),
            "the miss carries the fields: kind (`doc=`), binary (named nowhere else),
             and error (the fake's own text)"
        );
        assert!(
            !logs_contain("The persisted fake missing document is unusable"),
            "a missing document does not log the corrupt wording"
        );
    }

    #[traced_test]
    #[test]
    fn a_corrupt_document_degrades_to_empty_and_logs_distinctly() {
        fake_corrupt(FakeCorruptDoc::KIND, "corruptcase.dll");
        let (_workspace, path) = temp_workspace();

        let bundle = project_bundle(
            &[ProjectionRow::of::<FakeCorruptDoc>()],
            Some(&path),
            "corruptcase.dll",
            "FUN_18003ab00",
        );

        assert!(
            bundle.type_info.is_empty(),
            "a corrupt document degrades exactly as a missing one does"
        );
        assert!(
            logs_contain("The persisted fake corrupt document is unusable"),
            "but is logged distinctly: a broken artifact, not an unrun scan"
        );
        assert!(
            logs_contain("doc=")
                && logs_contain("corruptcase.dll")
                && logs_contain("the persisted fake corrupt document record is not parseable"),
            "the corrupt miss carries the same fields: kind, binary, and error"
        );
        assert!(
            !logs_contain("No fake corrupt document persisted for the binary"),
            "a corrupt document does not log the missing wording"
        );
    }

    #[traced_test]
    #[test]
    fn a_shared_multi_field_row_fills_both_fields_from_one_load() {
        fake_put(
            FakeSharedDoc::KIND,
            "sharedcase.dll",
            vec![
                record("FUN_18003ab00", "a-flag-family", false),
                record("FUN_18003ab00", "DAT_1400a1b60", true),
                record("FUN_zzz", "another-functions-table", true),
            ],
        );
        let (_workspace, path) = temp_workspace();

        let bundle = project_bundle(
            &[ProjectionRow::of::<FakeSharedDoc>()],
            Some(&path),
            "sharedcase.dll",
            "FUN_18003ab00",
        );

        assert_eq!(
            bundle.const_findings.len(),
            2,
            "the union findings carry the function's records"
        );
        assert_eq!(
            bundle.data_table_findings.len(),
            1,
            "and the table record also reaches its own field, from the same pass"
        );
        assert_eq!(bundle.data_table_findings[0].name, "DAT_1400a1b60");
        assert_eq!(
            bundle
                .const_findings
                .iter()
                .filter(|f| f.kind == "data_table")
                .count(),
            1,
            "the table still rides the union for the escalate CONSTANTS section"
        );
        assert_eq!(
            fake_load_count(FakeSharedDoc::KIND),
            1,
            "one multi-field row means exactly one load per gather"
        );
        assert!(!logs_contain("fake shared document"));
    }

    #[traced_test]
    #[test]
    fn the_fold_projects_rows_in_registered_order() {
        fake_put(
            FakeFirstRowDoc::KIND,
            "ordered.dll",
            vec![record("FUN_18003ab00", "first-row", false)],
        );
        fake_put(
            FakeSecondRowDoc::KIND,
            "ordered.dll",
            vec![record("FUN_18003ab00", "second-row", false)],
        );
        let (_workspace, path) = temp_workspace();

        let mut rows = vec![
            ProjectionRow::of::<FakeFirstRowDoc>(),
            ProjectionRow::of::<FakeSecondRowDoc>(),
        ];
        let bundle = project_bundle(&rows, Some(&path), "ordered.dll", "FUN_18003ab00");
        let names: Vec<&str> = bundle.type_info.iter().map(|t| t.name.as_str()).collect();
        assert_eq!(names, ["first-row", "second-row"]);

        rows.reverse();
        let bundle = project_bundle(&rows, Some(&path), "ordered.dll", "FUN_18003ab00");
        let names: Vec<&str> = bundle.type_info.iter().map(|t| t.name.as_str()).collect();
        assert_eq!(
            names,
            ["second-row", "first-row"],
            "flipping the table order flips the projection order — row order is the fold's order"
        );
    }
}
