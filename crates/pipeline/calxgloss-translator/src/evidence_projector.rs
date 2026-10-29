//! The evidence-bundle projector — one `AnalysisDoc` seam between the
//! persisted analysis documents and the prompt bundle (issue #311, spec #310).
//!
//! The bundle's read path used to repeat the same three steps for every
//! engine, as copies: nineteen near-identical `extract_*`/`load_*`
//! functions in [`retry::helpers`](crate::retry) each wrote them out —
//! load the engine's persisted analysis document for the binary, keep
//! the records for the target function, and convert them through the
//! prompts crate's `From` impls. This module writes those steps once,
//! behind one interface: [`AnalysisDoc`] is the seam (load,
//! per-function selection, conversion), [`load_and_project`] is the
//! generic contract, and [`ProjectionRow`] pairs an adapter with the
//! bundle field(s) it fills so [`project_bundle`] can assemble the
//! bundle by folding the rows — the same descriptor-table shape P34's
//! [`scan_registry`](crate::scan_registry) proved on the write side.
//! The two stay deliberately separate: the scan-descriptor table owns
//! the scan write path, this seam owns the prompt read path.
//!
//! The degradation rule, written exactly once here and inherited by
//! every adapter (an adapter never logs and never degrades):
//!
//! * no workspace configured → the field stays empty, nothing is
//!   logged — nothing was ever going to be there;
//! * document missing or unparseable → a `debug` line naming the
//!   document kind, the binary, and the error, then the field stays
//!   empty — missing context weakens the prompt, it never fails it,
//!   and the two failure kinds log distinctly (nothing persisted means
//!   the scan never ran; a broken artifact means the document on disk
//!   needs investigating);
//! * document present → exactly that function's records, converted, in
//!   scan order, put into the designated field(s).
//!
//! A document that feeds two bundle fields is one multi-field row, not
//! two rows: that covers the consts document (its union findings and
//! its data-table records) and the type-inference document (its type
//! info and its parameter directions). One load fills both fields, so
//! they can never disagree about what the workspace holds.
//!
//! The seam is live: issues #312 and #313 moved the twelve single-field
//! engines onto it. Their adapters and the
//! [`PROJECTION_ROWS`](adapters::PROJECTION_ROWS) table live in
//! [`adapters`], and `gather_function_evidence` now fills those fields
//! by running the registered rows in order — fourteen documents, with
//! the shared consts and type-inference ones as multi-field rows that
//! load once and fill every field they touch (#314). libmatch's
//! call-graph correlation and the whole-DLL extractions stay custom,
//! outside this seam, exactly as specced (#310). Every registered row
//! is covered by the parametrized suite driven through
//! `gather_function_evidence`; what is pinned *here* is the fold
//! itself, against a fake in-memory adapter.

pub mod adapters;

use std::error::Error;
use std::path::Path;

use calxgloss_prompts::EvidenceBundle;
use thiserror::Error;
use tracing::debug;

/// Why loading one analysis document produced nothing.
///
/// Both cases leave the bundle the same way — the fold projects
/// nothing and the prompt still builds — but they log distinctly, and
/// that distinction is why this type exists: a missing document says
/// the scan has not run for this binary (recompute), and a corrupt one
/// says the artifact on disk is broken (investigate). An engine
/// adapter maps its persistor's error onto this type the same way it
/// maps `PersistError` onto its own crate error: the persistor's
/// `NotFound` variant becomes [`Missing`](Self::Missing), and every
/// other failure becomes [`Corrupt`](Self::Corrupt).
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

/// One persisted analysis document, seen as the projector needs
/// it: a per-function record source for one target binary.
///
/// The seam exposes exactly the three steps that every hand-copied
/// `extract_*` function repeated, and nothing else:
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
/// once by a [`ProjectionRow`]. All the shared machinery (the
/// workspace check, the miss logs, the degradation rule) belongs to
/// [`load_and_project`], never to the adapter. The fourteen per-function
/// documents `gather_function_evidence` reads all have their adapters
/// here (issues #312–#314), beside the analysis's own unknown ledger row
/// (#370); the libmatch document's call graph correlation and the
/// whole-DLL extractions stay custom, outside this seam, exactly as
/// specced (#310).
pub trait AnalysisDoc {
    /// The document kind. The miss log names it, so an absent bundle
    /// field can be explained from the logs — "why is this engine not
    /// in the prompt?" It is also the row's identity in the roster
    /// test that pins which rows are registered.
    const KIND: &'static str;

    /// The whole loaded document for one binary, whatever the
    /// engine's result type happens to be.
    type Doc;

    /// One record of the document, as `for_function` hands it to
    /// `fill` — usually `&'a EngineRecord`, mirroring the engines' own
    /// `for_function`, so conversion can use the existing `From`
    /// impls that take a reference.
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

    /// Project what the loaded document itself admits about its scan's
    /// coverage into the bundle field(s) that sit beside this row's
    /// findings — called exactly once per successfully loaded document,
    /// before any per-record [`fill`](Self::fill) (issue #346). The
    /// default no-op serves engines that do not record coverage; a
    /// missing or corrupt document never reaches this step at all, so
    /// a bundle that read no document fills no coverage, and the
    /// section beside this row renders as it did before P19.
    fn fill_coverage(_doc: &Self::Doc, _bundle: &mut EvidenceBundle) {}

    /// The loaded document's own scan-coverage record, handed to the
    /// coverage-residue derivation beside the fold (issue #369): every
    /// facet it stamps `partial` or `unavailable` becomes one unknown
    /// record in the batch's ledger residue. The default `None` serves
    /// documents that state no coverage — a pre-P19 document's absence
    /// reads as unknown and derives nothing, and absence never produces
    /// a gap record.
    fn coverage(_doc: &Self::Doc) -> Option<&calxgloss_types::ScanCoverage> {
        None
    }
}

/// The fold's step for one row, with the concrete types hidden away:
/// each engine's document is its own type, and the registered
/// documents cannot sit unboxed in one list, so
/// [`ProjectionRow::of`] turns the whole seam into this one function
/// pointer for each concrete document type. The residue sink collects
/// the coverage-residue records the document's own admission derives
/// (issue #369); the fold never fails on them, exactly as it never
/// fails on the document itself.
type ProjectStep =
    fn(Option<&Path>, &str, &str, &mut EvidenceBundle, &mut Vec<calxgloss_types::UnknownRecord>);

/// The shared contract, written once: run one adapter's three steps
/// against the workspace and put the document's records into
/// `bundle`. The whole degradation rule applies here and nowhere
/// else — no workspace configured projects nothing and logs nothing;
/// a missing or unparseable document logs its miss (see
/// [`DocLoadError`]) and projects nothing; a present document
/// contributes exactly its `for_function` records, converted by
/// `fill`, in scan order.
///
/// Missing context never fails the prompt: this function cannot fail
/// at all.
pub fn load_and_project<D: AnalysisDoc>(
    workspace: Option<&Path>,
    binary: &str,
    function: &str,
    bundle: &mut EvidenceBundle,
    residue: &mut Vec<calxgloss_types::UnknownRecord>,
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

    // The coverage step runs once for the whole document — never per
    // record, and never on the miss path, which returned above — so one
    // document can never fill the bundle's coverage field twice
    // (issue #346).
    D::fill_coverage(&doc, bundle);

    // The same admission that qualifies the prompt's section beside this
    // row's findings also derives the ledger's coverage residue: every
    // facet the document stamps `partial` or `unavailable` for this unit
    // becomes one unknown record, in the coverage record's own facet
    // order (issue #369). A document stating no coverage — a pre-P19
    // document, whose absence reads as unknown — derives nothing here
    // and at the libmatch read alike: absence never produces a gap
    // record.
    if let Some(coverage) = D::coverage(&doc) {
        residue.extend(crate::coverage_residue::coverage_residue(
            binary,
            D::KIND,
            function,
            coverage,
            calxgloss_types::scan::now_unix_secs(),
        ));
    }

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
    /// code of its own.
    ///
    /// `const` because the registration table is a `static`: rows must
    /// be constructible in a static initializer, which the plain
    /// function-item-to-fn-pointer coercion of `load_and_project::<D>`
    /// provides without needing a closure.
    pub const fn of<D: AnalysisDoc>() -> Self {
        Self {
            kind: D::KIND,
            step: load_and_project::<D>,
        }
    }

    /// Run this row's projection into `bundle`, collecting the coverage
    /// residue the document's own admission derives into `residue`
    /// (issue #369).
    pub fn project(
        &self,
        workspace: Option<&Path>,
        binary: &str,
        function: &str,
        bundle: &mut EvidenceBundle,
        residue: &mut Vec<calxgloss_types::UnknownRecord>,
    ) {
        (self.step)(workspace, binary, function, bundle, residue);
    }
}

/// Assemble an evidence bundle by running the rows in their
/// registered order — the one-call shape of [`project_into`] over an
/// empty bundle, kept for readers (and tests) that want the whole
/// bundle from the table alone.
///
/// Row order is projection order: a field filled by several rows
/// receives them in table order, so prompt output stays diffable
/// between attempts.
pub fn project_bundle(
    rows: &[ProjectionRow],
    workspace: Option<&Path>,
    binary: &str,
    function: &str,
    residue: &mut Vec<calxgloss_types::UnknownRecord>,
) -> EvidenceBundle {
    let mut bundle = EvidenceBundle::default();
    project_into(rows, workspace, binary, function, &mut bundle, residue);
    bundle
}

/// The fold itself, into a bundle that may already hold fields from
/// custom extraction: `gather_function_evidence` runs the registered
/// rows through it after the shared loads and before returning, so the
/// migrated engines contribute their fields and nothing else (issue
/// #312). Rows run in table order; a row's degradation affects only
/// its own field. The residue sink collects every coverage-residue
/// record the read documents' own admissions derive, in row order and
/// then the coverage record's facet order (issue #369) — the fold's
/// deterministic scan order the batch's ledger files.
pub fn project_into(
    rows: &[ProjectionRow],
    workspace: Option<&Path>,
    binary: &str,
    function: &str,
    bundle: &mut EvidenceBundle,
    residue: &mut Vec<calxgloss_types::UnknownRecord>,
) {
    for row in rows {
        row.project(workspace, binary, function, bundle, residue);
    }
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
    // these fakes pin the generic fold once, and the real adapters
    // get their coverage from the parametrized suite at
    // `gather_function_evidence` when they register (issue #312).
    //
    // Every scenario gets its own fake kind and its own binary name:
    // the log-capture buffer is process-global while tests run in
    // parallel, so each assertion quotes its scenario's own kind and
    // binary and stays meaningful no matter what other tests log.

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
    /// `for_function` does. Each scenario gets its own kind, so its
    /// log assertions only concern that scenario.
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
    /// document: every record goes into the const-findings union, and
    /// a table record also goes into the data-table findings — both
    /// fields come from the row's single load.
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

    // The coverage-carrying fakes (issue #346): a document that admits
    // falling short beside its records, standing in for the apidetect
    // result, pinned against the same fold so the coverage step runs
    // once per document and never on a miss.

    /// A fake document's own coverage record, beside its records: the
    /// admission the engine wrote, or `None` standing in for a
    /// document written before coverage was recorded — present, but
    /// with nothing to admit.
    #[derive(Debug, Clone)]
    struct FakeStampedDoc {
        records: Vec<FakeRecord>,
        coverage: Option<String>,
    }

    thread_local! {
        /// Coverage steps run per document kind — the pins that one
        /// present document runs its coverage step exactly once and a
        /// missing or corrupt document never runs one at all.
        static FAKE_COVERAGE_FILLS: RefCell<HashMap<&'static str, usize>> =
            HashMap::new().into();

        /// The admission stored beside a fake document's records,
        /// keyed like the fake store.
        static FAKE_ADMISSIONS: RefCell<HashMap<(&'static str, String), Option<String>>> =
            HashMap::new().into();
    }

    fn fake_stamped_put(
        kind: &'static str,
        binary: &str,
        records: Vec<FakeRecord>,
        admission: Option<&str>,
    ) {
        fake_put(kind, binary, records);
        FAKE_ADMISSIONS.with(|admissions| {
            admissions
                .borrow_mut()
                .insert((kind, binary.to_string()), admission.map(str::to_string));
        });
    }

    fn fake_coverage_fill_count(kind: &'static str) -> usize {
        FAKE_COVERAGE_FILLS.with(|fills| fills.borrow().get(kind).copied().unwrap_or(0))
    }

    /// One fake stamped adapter: records come from the ordinary fake
    /// store, its admission from the beside-store, and it fills the
    /// API coverage field the way the real API row does.
    macro_rules! fake_stamped_doc {
        ($name:ident, $kind:literal) => {
            struct $name;

            impl AnalysisDoc for $name {
                const KIND: &'static str = $kind;
                type Doc = FakeStampedDoc;
                type Record<'a> = &'a FakeRecord;

                fn load(_workspace: &Path, binary: &str) -> Result<Self::Doc, DocLoadError> {
                    let records = fake_load(Self::KIND, binary)?;
                    let coverage = FAKE_ADMISSIONS.with(|admissions| {
                        admissions
                            .borrow()
                            .get(&(Self::KIND, binary.to_string()))
                            .cloned()
                            .flatten()
                    });
                    Ok(FakeStampedDoc { records, coverage })
                }

                fn for_function<'a>(
                    doc: &'a Self::Doc,
                    function: &str,
                ) -> impl Iterator<Item = Self::Record<'a>> {
                    doc.records.iter().filter(move |r| r.function == function)
                }

                fn fill(record: Self::Record<'_>, bundle: &mut EvidenceBundle) {
                    bundle.type_info.push(TypeInfo::from(record));
                }

                fn fill_coverage(doc: &Self::Doc, bundle: &mut EvidenceBundle) {
                    FAKE_COVERAGE_FILLS
                        .with(|fills| *fills.borrow_mut().entry(Self::KIND).or_insert(0) += 1);
                    if let Some(admission) = &doc.coverage {
                        bundle.api_coverage = calxgloss_prompts::CoverageInfo {
                            status: "partial".to_string(),
                            admission: admission.clone(),
                        };
                    }
                }
            }
        };
    }

    fake_stamped_doc!(FakeStampedPresentDoc, "fake stamped document");
    fake_stamped_doc!(FakeStampedBareDoc, "fake bare stamped document");
    fake_stamped_doc!(FakeStampedMissingDoc, "fake stamped missing document");
    fake_stamped_doc!(FakeStampedCorruptDoc, "fake stamped corrupt document");

    #[traced_test]
    #[test]
    fn a_stamped_document_fills_its_coverage_exactly_once_beside_its_records() {
        fake_stamped_put(
            FakeStampedPresentDoc::KIND,
            "stamped.dll",
            vec![
                record("FUN_18003ab00", "first-reading", false),
                record("FUN_18003ab00", "second-reading", false),
                record("FUN_zzz", "another-functions-reading", false),
            ],
            Some("partial — delay imports unexamined"),
        );
        let (_workspace, path) = temp_workspace();

        let bundle = project_bundle(
            &[ProjectionRow::of::<FakeStampedPresentDoc>()],
            Some(&path),
            "stamped.dll",
            "FUN_18003ab00",
            &mut Vec::new(),
        );

        assert_eq!(
            bundle.type_info.len(),
            2,
            "the record leg ran its ordinary fills"
        );
        assert_eq!(
            bundle.api_coverage.admission, "partial — delay imports unexamined",
            "the document's own admission reaches the bundle beside the findings"
        );
        assert_eq!(
            fake_coverage_fill_count(FakeStampedPresentDoc::KIND),
            1,
            "two records projected, but the coverage leg ran exactly once for the document"
        );
    }

    #[traced_test]
    #[test]
    fn a_document_written_before_coverage_stamping_fills_no_coverage() {
        fake_stamped_put(
            FakeStampedBareDoc::KIND,
            "pre-p19.dll",
            vec![record("FUN_18003ab00", "old-reading", false)],
            None,
        );
        let (_workspace, path) = temp_workspace();

        let bundle = project_bundle(
            &[ProjectionRow::of::<FakeStampedBareDoc>()],
            Some(&path),
            "pre-p19.dll",
            "FUN_18003ab00",
            &mut Vec::new(),
        );

        assert_eq!(bundle.type_info.len(), 1, "the records still project");
        assert!(
            bundle.api_coverage.admission.is_empty() && bundle.api_coverage.status.is_empty(),
            "a document that states no coverage fills nothing — the old render stands"
        );
    }

    #[traced_test]
    #[test]
    fn missing_and_corrupt_documents_fill_no_coverage_and_run_no_coverage_leg() {
        fake_corrupt(FakeStampedCorruptDoc::KIND, "stampedcorrupt.dll");
        let (_workspace, path) = temp_workspace();

        let missing = project_bundle(
            &[ProjectionRow::of::<FakeStampedMissingDoc>()],
            Some(&path),
            "stampedmissing.dll",
            "FUN_18003ab00",
            &mut Vec::new(),
        );
        let corrupt = project_bundle(
            &[ProjectionRow::of::<FakeStampedCorruptDoc>()],
            Some(&path),
            "stampedcorrupt.dll",
            "FUN_18003ab00",
            &mut Vec::new(),
        );

        for bundle in [missing, corrupt] {
            assert!(
                bundle.type_info.is_empty() && bundle.api_coverage.admission.is_empty(),
                "a document that never loaded fills neither findings nor coverage"
            );
        }
        assert_eq!(
            fake_coverage_fill_count(FakeStampedMissingDoc::KIND)
                + fake_coverage_fill_count(FakeStampedCorruptDoc::KIND),
            0,
            "the coverage leg belongs to the loaded document alone — a miss never runs it"
        );
        assert!(
            logs_contain("No fake stamped missing document persisted for the binary"),
            "the missing miss keeps its own wording"
        );
        assert!(
            logs_contain("The persisted fake stamped corrupt document is unusable"),
            "the corrupt miss keeps its distinct wording"
        );
    }

    // The residue-carrying fake (issue #369): a document holding the
    // shared coverage record verbatim — same type, same facet order —
    // surfaced through `coverage`, the way every real adapter surfaces
    // its metadata entry, so the fold's residue leg is pinned against
    // the shape it actually runs on.

    struct FakeResidueDoc {
        records: Vec<FakeRecord>,
        coverage: Option<calxgloss_types::ScanCoverage>,
    }

    thread_local! {
        /// The coverage record stored beside a fake document's records,
        /// keyed like the fake store — the shape the engines stamp.
        static FAKE_RESIDUE_COVERAGE:
            RefCell<HashMap<(&'static str, String), calxgloss_types::ScanCoverage>> =
            HashMap::new().into();
    }

    fn fake_residue_put(
        kind: &'static str,
        binary: &str,
        records: Vec<FakeRecord>,
        coverage: Option<calxgloss_types::ScanCoverage>,
    ) {
        fake_put(kind, binary, records);
        if let Some(coverage) = coverage {
            FAKE_RESIDUE_COVERAGE.with(|store| {
                store
                    .borrow_mut()
                    .insert((kind, binary.to_string()), coverage);
            });
        }
    }

    /// One fake residue adapter: records from the ordinary fake store,
    /// the coverage record from the beside-store, exposed through
    /// `coverage` exactly as the fourteen real adapters override it.
    macro_rules! fake_residue_doc {
        ($name:ident, $kind:literal) => {
            struct $name;

            impl AnalysisDoc for $name {
                const KIND: &'static str = $kind;
                type Doc = FakeResidueDoc;
                type Record<'a> = &'a FakeRecord;

                fn load(_workspace: &Path, binary: &str) -> Result<Self::Doc, DocLoadError> {
                    let records = fake_load(Self::KIND, binary)?;
                    let coverage = FAKE_RESIDUE_COVERAGE.with(|store| {
                        store
                            .borrow()
                            .get(&(Self::KIND, binary.to_string()))
                            .cloned()
                    });
                    Ok(FakeResidueDoc { records, coverage })
                }

                fn for_function<'a>(
                    doc: &'a Self::Doc,
                    function: &str,
                ) -> impl Iterator<Item = Self::Record<'a>> {
                    doc.records.iter().filter(move |r| r.function == function)
                }

                fn fill(record: Self::Record<'_>, bundle: &mut EvidenceBundle) {
                    bundle.type_info.push(TypeInfo::from(record));
                }

                fn coverage(doc: &Self::Doc) -> Option<&calxgloss_types::ScanCoverage> {
                    doc.coverage.as_ref()
                }
            }
        };
    }

    fake_residue_doc!(FakeResidueAdmittingDoc, "fake admitting document");
    fake_residue_doc!(FakeResidueQuietDoc, "fake quiet document");
    fake_residue_doc!(FakeResidueBareDoc, "fake residue bare document");
    fake_residue_doc!(FakeResidueMissingDoc, "fake residue missing document");
    fake_residue_doc!(FakeResidueCorruptDoc, "fake residue corrupt document");

    fn facet(
        id: &str,
        status: calxgloss_types::CoverageStatus,
        limitation: Option<&str>,
    ) -> calxgloss_types::FacetCoverage {
        calxgloss_types::FacetCoverage {
            id: id.to_string(),
            status,
            limitation: limitation.map(str::to_string),
        }
    }

    #[traced_test]
    #[test]
    fn an_admitting_fold_document_feeds_the_residue_sink_in_facet_order() {
        fake_residue_put(
            FakeResidueAdmittingDoc::KIND,
            "residue.dll",
            vec![record("FUN_18003ab00", "one-reading", false)],
            Some(calxgloss_types::ScanCoverage {
                status: calxgloss_types::CoverageStatus::Partial,
                facets: vec![
                    facet(
                        "function-bodies",
                        calxgloss_types::CoverageStatus::Complete,
                        None,
                    ),
                    facet(
                        "program-strings",
                        calxgloss_types::CoverageStatus::Partial,
                        Some("half the strings decoded"),
                    ),
                    facet(
                        "string-xrefs",
                        calxgloss_types::CoverageStatus::Unavailable,
                        None,
                    ),
                ],
            }),
        );
        fake_residue_put(
            FakeResidueQuietDoc::KIND,
            "residue.dll",
            vec![record("FUN_18003ab00", "quiet-reading", false)],
            Some(calxgloss_types::ScanCoverage {
                status: calxgloss_types::CoverageStatus::Complete,
                facets: vec![
                    facet(
                        "function-bodies",
                        calxgloss_types::CoverageStatus::Complete,
                        None,
                    ),
                    facet(
                        "delay-imports",
                        calxgloss_types::CoverageStatus::Unexamined,
                        None,
                    ),
                ],
            }),
        );
        let (_workspace, path) = temp_workspace();
        let mut residue = Vec::new();

        let bundle = project_bundle(
            &[
                ProjectionRow::of::<FakeResidueAdmittingDoc>(),
                ProjectionRow::of::<FakeResidueQuietDoc>(),
            ],
            Some(&path),
            "residue.dll",
            "FUN_18003ab00",
            &mut residue,
        );

        assert_eq!(
            bundle.type_info.len(),
            2,
            "the record legs run undisturbed beside the residue leg"
        );
        let slots: Vec<String> = residue.iter().map(|r| r.source_slot()).collect();
        assert_eq!(
            slots,
            vec![
                "fake admitting document#program-strings",
                "fake admitting document#string-xrefs",
            ],
            "only the admitting facets derive, in the coverage record's own \
             facet order, rows in table order; a document that admitted \
             nothing stays silent"
        );
        assert_eq!(residue[0].kind, calxgloss_types::UnknownKind::CoverageFacet);
        assert_eq!(residue[0].function.as_deref(), Some("FUN_18003ab00"));
        assert_eq!(
            residue[0].severity,
            calxgloss_types::UnknownSeverity::Material,
            "partial by its own admission"
        );
        assert_eq!(
            residue[1].severity,
            calxgloss_types::UnknownSeverity::Blocking,
            "unavailable: the evidence never arrived at all"
        );
    }

    #[traced_test]
    #[test]
    fn nothing_the_fold_cannot_read_feeds_the_residue_sink() {
        fake_residue_put(
            FakeResidueBareDoc::KIND,
            "residuesilent.dll",
            vec![record("FUN_18003ab00", "pre-p19-reading", false)],
            None,
        );
        fake_corrupt(FakeResidueCorruptDoc::KIND, "residuesilent.dll");
        let (_workspace, path) = temp_workspace();
        let mut residue = Vec::new();

        let bundle = project_bundle(
            &[
                // A pre-P19 document: present, but stating no coverage.
                ProjectionRow::of::<FakeResidueBareDoc>(),
                // No document at all, and an unparseable one.
                ProjectionRow::of::<FakeResidueMissingDoc>(),
                ProjectionRow::of::<FakeResidueCorruptDoc>(),
            ],
            Some(&path),
            "residuesilent.dll",
            "FUN_18003ab00",
            &mut residue,
        );
        assert_eq!(
            bundle.type_info.len(),
            1,
            "the bare document's records still project"
        );

        // The no-workspace path: the fold never even loads, so no residue
        // can come of it either.
        project_into(
            &[ProjectionRow::of::<FakeResidueAdmittingDoc>()],
            None,
            "residue.dll",
            "FUN_18003ab00",
            &mut EvidenceBundle::default(),
            &mut residue,
        );

        assert!(
            residue.is_empty(),
            "absence and unreadability read as unknown, and unknown never \
             produces a gap record: {residue:?}"
        );
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
            &mut Vec::new(),
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
            &mut Vec::new(),
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
            &mut Vec::new(),
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
            &mut Vec::new(),
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
            &mut Vec::new(),
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
            "the table is still part of the union for the escalate CONSTANTS section"
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
        let bundle = project_bundle(
            &rows,
            Some(&path),
            "ordered.dll",
            "FUN_18003ab00",
            &mut Vec::new(),
        );
        let names: Vec<&str> = bundle.type_info.iter().map(|t| t.name.as_str()).collect();
        assert_eq!(names, ["first-row", "second-row"]);

        rows.reverse();
        let bundle = project_bundle(
            &rows,
            Some(&path),
            "ordered.dll",
            "FUN_18003ab00",
            &mut Vec::new(),
        );
        let names: Vec<&str> = bundle.type_info.iter().map(|t| t.name.as_str()).collect();
        assert_eq!(
            names,
            ["second-row", "first-row"],
            "flipping the table order flips the projection order — row order is the fold's order"
        );
    }
}
