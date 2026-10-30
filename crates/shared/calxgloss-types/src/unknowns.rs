//! The unknown record — one unanswered question, shaped once (track P21, issue #368).
//!
//! A finished run whose queue went quiet and a finished run that established
//! everything used to look identical. ADR-0053 made *what a scan did not
//! examine* honest and ADR-0054/0055 made *what the analysis engine cannot
//! answer* honest; this module turns that admitted residue into named
//! questions. Each **unknown record** states its subject (a target binary
//! verbatim, plus the function where the gap is function-specific), its kind
//! from a closed set, one bounded question line, a severity from a closed
//! scale, one bounded `required_evidence` line naming what would establish
//! the fact, and the origin it was derived from — the filed document and
//! facet, the seam family, the case set, or the retry decision that admitted
//! the gap. Its identity is deterministic, derived from the subject and the
//! source slot and never from prose: the same gap re-derived across attempts
//! and runs is one record, re-worded admission text keeps the record's id
//! and keeps the reviewer's answer bound to it, and only a genuinely
//! different gap — a different facet, family, or export — is a different id.
//!
//! Two documents, two owners, joined at read time — never one shared file
//! (the shared JSON store replaces whole documents, so one shared document
//! would let either owner's write clobber the other's):
//!
//! * the pipeline's **unknown ledger** — `re/unknowns/<binary identity>.json`,
//!   one document per target binary, replaced outright on each batch write so
//!   it is always the current derived set and never an append log;
//! * the reviewer's **resolutions document** —
//!   `re/review/unknown_resolutions.json`, keyed by unknown id and sitting
//!   beside the skip set and the queue overlay: persisted reviewer intent
//!   that survives every dashboard rebuild and every later batch run.
//!
//! The join at read time is `open` / `resolved` / `dismissed`; nothing
//! downstream stores its own copy. Revisions guard writes rather than
//! recording history: a writer supplies the revision it read, and a stale
//! write fails with a changed-underneath conflict naming the landed state —
//! the same wording family the review actions already use. A record's
//! revision bumps only when a persisted field actually changed, and
//! reopening a settled record appends a revision: nothing is deleted and no
//! revision is rewritten.
//!
//! The ledger obeys the honesty doctrine its records descend from: the three
//! readings of a ledger are never collapsed. No document at all, and a filed
//! document whose `records` key is absent, both read as *unknown* — never as
//! a clean bill of health — and only a filed document carrying an explicitly
//! empty list means *known-and-none*. A corrupt document stays corrupt.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::display_serde_label;
use crate::identity::BinaryIdentity;
use crate::persist::{PersistError, load_json};

// ============================================================
// The closed sets: kind and severity
// ============================================================

/// What sort of gap an unknown records — the closed set paired one-for-one
/// against the producers that file it (issue #375).
///
/// A producer names one of these kinds at the point its gap is already
/// admitted; nothing invents a kind at read time, and nothing files a record
/// whose kind the roster never declared. A fifth producer (a future masked
/// byte search, P28) adds one kind here and one write site — forgetting
/// either half fails the shared checker, not a silent drift.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnknownKind {
    /// An evidence engine's filed coverage record admits a facet fell short
    /// for this function: the question is what the function really is, given
    /// that facet's evidence never fully arrived. Filed by the batch's
    /// coverage fold (P19's residue).
    CoverageFacet,
    /// The analysis engine declared one query family `unavailable` for the
    /// live session: answers of that family about this function cannot
    /// arrive from the seam at all. Filed against the units whose retry
    /// posture actually re-asks the family (P20's seam residue).
    AnalysisFamily,
    /// A unit reached review having run zero baseline cases: its behavior
    /// was never exercised, so "translated" and "proven" do not yet mean
    /// the same thing about it. Filed by the verification signal.
    BaselineNeverRun,
    /// No filed baseline document ever covered this export: no input vector
    /// ever called it. Filed by the verification signal against the export
    /// named in the source slot.
    ExportUncovered,
    /// The retry ladder pruned an escalate that would have re-asked a family
    /// the analysis engine cannot answer: the pruned path is a record, not a
    /// silent skip (P20's ladder residue).
    RetryPruned,
    /// The ladder refused a context-tier step because its family was
    /// unavailable: the context that tier would have carried never reached
    /// the prompt (P20's ladder residue).
    TierRefused,
}

display_serde_label!(UnknownKind {
    CoverageFacet => "coverage_facet",
    AnalysisFamily => "analysis_family",
    BaselineNeverRun => "baseline_never_run",
    ExportUncovered => "export_uncovered",
    RetryPruned => "retry_pruned",
    TierRefused => "tier_refused",
});

/// The declared roster of unknown kinds — the closed set every producer is
/// paired against, in declaration order.
///
/// ADR-0053's engine-stamps/roster-pins doctrine one level up (issue #375):
/// the roster pairs one-for-one with the producers through [`unknown_roster_faults`],
/// so a producer that starts admitting a gap without naming its kind — or a
/// declared kind nobody files any more — fails loudly, naming itself.
pub const DECLARED_UNKNOWN_KINDS: &[&str] = &[
    "coverage_facet",
    "analysis_family",
    "baseline_never_run",
    "export_uncovered",
    "retry_pruned",
    "tier_refused",
];

/// How much an open unknown matters — the closed severity scale.
///
/// The serde labels are the persisted wire format, so they are a
/// compatibility contract. Every level names an honest criterion a producer
/// can apply at the point the gap is admitted; none is a catch-all.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnknownSeverity {
    /// The gap qualifies what was established but leaves the subject
    /// standing enough to work on: the honest level when the missing
    /// evidence is the edge of a facet, not its core.
    Notable,
    /// A real hole: a significant share of the subject's direct evidence is
    /// missing while some of it was established — e.g. a facet that fell
    /// short by its own admission.
    Material,
    /// This gap blocks a done claim — the level the P26 conformance verdict
    /// gates on. A producer stamps it only where the evidence that would
    /// establish the subject never arrived at all: a facet admitted
    /// `unavailable`, zero baseline cases ever run, no filed baseline
    /// document for an export. It is honest today, not a future severity.
    Blocking,
}

display_serde_label!(UnknownSeverity {
    Notable => "notable",
    Material => "material",
    Blocking => "blocking",
});

// ============================================================
// The origin: the filed record or decision the gap was derived from
// ============================================================

/// The source an unknown record was derived from: the filed document and
/// facet, the seam family, the verification case set, or the retry decision
/// that admitted the gap. An origin names where the question came from; its
/// [`source_slot`](Self::source_slot) is the identity half the record id
/// folds beside the subject.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "origin", rename_all = "snake_case")]
pub enum UnknownOrigin {
    /// Derived from a filed evidence document's coverage entry for one
    /// facet: the document kind (the evidence engine's document) plus the
    /// engine's own facet id.
    Document { document: String, facet: String },
    /// Derived from a capability report's declared family: the seam's own
    /// family id.
    Family { family: String },
    /// Derived from a verification case set — the case set that ran zero
    /// cases, or the export no filed baseline document ever covered.
    CaseSet { case_set: String },
    /// Derived from a retry-ladder decision: the pruned escalate (naming
    /// the family it would have re-asked) or the refused tier step (naming
    /// the tier the ladder refused to step onto).
    RetryDecision { decision: String },
}

impl UnknownOrigin {
    /// The source slot: the identity this record's id folds beside the
    /// subject and the kind. Two records sharing a subject, a kind, and a
    /// slot are one gap — re-derived, not duplicated; a different facet,
    /// family, or export names a different slot and so a different gap. The
    /// question and required-evidence wording never enters the slot.
    pub fn source_slot(&self) -> String {
        match self {
            // A facet id is only unique inside one document kind — the same
            // `function-bodies` facet admitted short by two engines is two
            // gaps, so the slot carries the document kind ahead of it.
            UnknownOrigin::Document { document, facet } => format!("{document}#{facet}"),
            UnknownOrigin::Family { family } => family.clone(),
            UnknownOrigin::CaseSet { case_set } => case_set.clone(),
            UnknownOrigin::RetryDecision { decision } => decision.clone(),
        }
    }
}

// ============================================================
// The record
// ============================================================

/// One unanswered question about one subject: what has not been established,
/// how much it matters, and what evidence would establish it.
///
/// The record is written where the gap becomes known and read everywhere
/// else; every consumer — a prompt section, the review surface, the run
/// close — renders this same stored wording instead of restating it. The
/// three free-text-carrying fields in the track (a record's `question` and
/// `required_evidence`, and a reviewer resolution's reason) each hold one
/// bounded line, following the discipline P19's limitation line and P20's
/// reason line already share: the wording is owned once by the shared type,
/// and the doctrines' frames never merge on any surface — a coverage
/// admission, a capability admission, and an unknown's question line stay
/// their own three lines in their own three frames.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnknownRecord {
    /// The record's deterministic identity — see [`UnknownRecord::derive_id`].
    /// It is a key, never prose: the reviewer's resolutions document binds to
    /// it, and re-running a batch re-derives the same key.
    pub id: String,
    /// The target binary the gap is about, verbatim — the record tree's
    /// binary identity.
    pub binary: BinaryIdentity,
    /// The function the gap is function-specific to, absent when the record
    /// is about the binary itself (an export no baseline document covered).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub function: Option<String>,
    /// The kind of gap, from the closed declared roster.
    pub kind: UnknownKind,
    /// How much the open gap matters, from the closed severity scale.
    pub severity: UnknownSeverity,
    /// One bounded question line: the question the admission is asking.
    pub question: String,
    /// One bounded line naming the evidence that would establish the fact
    /// and close the record.
    pub required_evidence: String,
    /// The filed record or decision this record was derived from.
    pub origin: UnknownOrigin,
    /// When this gap was first admitted, as a Unix timestamp in seconds. It
    /// survives every later re-derivation untouched.
    pub first_seen: u64,
    /// When this gap was most recently admitted, as a Unix timestamp in
    /// seconds. A re-derivation always refreshes it — stamp moves never bump
    /// the revision.
    pub last_seen: u64,
    /// The guard every write is checked against. A re-derivation appends a
    /// new revision (one above the landed one) only when a persisted field
    /// actually changed, and reopening a settled record appends one; a
    /// revision number already landed is never rewritten.
    pub revision: u32,
}

impl UnknownRecord {
    /// Derive one record at the point its gap is admitted. The id is
    /// computed here from the subject, the kind, and the origin's source
    /// slot — never from the two wording lines — so two producers
    /// re-admitting the same gap in different words land one record. The
    /// derivation stamps this first sight: `first_seen` and `last_seen` are
    /// `now`, and the revision starts at 1. The batch's ledger merge
    /// ([`UnknownLedger::file`]) folds these stamps against what already
    /// landed.
    #[allow(clippy::too_many_arguments)]
    pub fn derive(
        binary: impl Into<BinaryIdentity>,
        function: Option<String>,
        kind: UnknownKind,
        severity: UnknownSeverity,
        question: impl Into<String>,
        required_evidence: impl Into<String>,
        origin: UnknownOrigin,
        now: u64,
    ) -> Self {
        let binary = binary.into();
        let id =
            UnknownRecord::derive_id(&binary, function.as_deref(), kind, &origin.source_slot());
        Self {
            id,
            binary,
            function,
            kind,
            severity,
            question: question.into(),
            required_evidence: required_evidence.into(),
            origin,
            first_seen: now,
            last_seen: now,
            revision: 1,
        }
    }

    /// The record's deterministic identity: the binary, the function where
    /// the record is function-specific (a literal `-` segment when it is
    /// about the binary itself), the kind label, and the source slot, joined
    /// by `/`. Function names never contain `/` (the unit-key rule the whole
    /// record tree shares), and a slot never contains one, so the segments
    /// cannot slide into one another.
    ///
    /// The question and required-evidence wording are deliberately excluded:
    /// re-wording an admission keeps this id, and with it the reviewer's
    /// resolution bound to the gap the resolution answered (issue #368). If
    /// the derivation ever changes, every existing resolution is orphaned —
    /// these pins are the ones not to relax.
    pub fn derive_id(
        binary: &BinaryIdentity,
        function: Option<&str>,
        kind: UnknownKind,
        source_slot: &str,
    ) -> String {
        format!("{binary}/{}/{kind}/{source_slot}", function.unwrap_or("-"))
    }

    /// The record's source slot, spelled by its origin.
    pub fn source_slot(&self) -> String {
        self.origin.source_slot()
    }

    /// Whether a re-derived record states the same persisted content as this
    /// landed one. The comparison covers every persisted field except the
    /// stamps and the revision: the revision bumps exactly when this says
    /// no, and says no when a persisted field actually changed — a stamp
    /// moving never counts.
    pub fn content_matches(&self, re_derived: &UnknownRecord) -> bool {
        self.binary == re_derived.binary
            && self.function == re_derived.function
            && self.kind == re_derived.kind
            && self.severity == re_derived.severity
            && self.question == re_derived.question
            && self.required_evidence == re_derived.required_evidence
            && self.origin == re_derived.origin
    }
}

// ============================================================
// The pipeline's ledger document and its three readings
// ============================================================

/// The pipeline's per-binary unknown ledger: the current derived set of open
/// gaps for one target binary, filed as `re/unknowns/<binary identity>.json`.
///
/// The document is replaced outright on each write, so it is always the
/// current derived set, never an append log — and it never stores reviewer
/// intent (the reviewer owns their own document). The filing envelope names
/// which binary the document was filed for and when, so a reader can tell a
/// filed document from a stray one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnknownLedger {
    /// The binary identity this ledger was filed for. A document without
    /// its envelope is not a filed ledger and fails at read, keeping the
    /// filing envelope the reader's stray-document check.
    pub binary: BinaryIdentity,
    /// When the ledger was filed, as a Unix timestamp in seconds.
    pub filed_at: u64,
    /// The current derived records, in the writer's deterministic scan
    /// order.
    ///
    /// The distinction the three readings turn on: an absent key says
    /// nothing at all — never an empty list — and reads as *unknown* by the
    /// same absent-field rule ADR-0053 established. Only a filed document
    /// carrying an explicitly empty list means known-and-none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub records: Option<Vec<UnknownRecord>>,
}

impl UnknownLedger {
    /// File (or re-file) the current derived set for `binary`, folding each
    /// derived record against the `landed` document — if any — under the
    /// revision doctrine (issue #368):
    ///
    /// * a derived record that never landed starts at revision 1, stamped
    ///   first-seen and last-seen at `now`;
    /// * a derived record whose persisted content matches the landed one
    ///   keeps the landed revision and first-seen, refreshing only
    ///   last-seen — re-running a batch never re-numbers a diff;
    /// * a derived record whose persisted content changed lands at the
    ///   landed revision + 1: a new revision is appended over the old, and
    ///   a revision that already landed is never rewritten;
    /// * a reopened record — one the reviewer settled and then reopened,
    ///   marked in the reviewer's `reopened` marks at the revision it was
    ///   reopened from — appends exactly one revision above the landed one
    ///   even though its content is unchanged, once: the mark stops firing
    ///   at any later revision. Nothing the pipeline owns is deleted or
    ///   rewritten by this.
    ///
    /// Records whose source slot disappeared stop being derived and simply
    /// stop landing; the reviewer's resolution for one remains as a durable
    /// reviewer record — this write never touches the reviewer's document.
    /// The new document keeps the derived order and names its filing
    /// envelope.
    pub fn file(
        binary: impl Into<BinaryIdentity>,
        landed: Option<&Self>,
        derived: &[UnknownRecord],
        reopened: &BTreeMap<String, u32>,
        now: u64,
    ) -> Self {
        let records = derived
            .iter()
            .map(|re_derived| {
                let mut record = re_derived.clone();
                record.last_seen = now;
                if let Some(prev) = landed.and_then(|l| l.record(&re_derived.id)) {
                    record.first_seen = prev.first_seen;
                    record.revision = if !prev.content_matches(re_derived)
                        || reopened.get(&re_derived.id) == Some(&prev.revision)
                    {
                        // Either a persisted field genuinely changed, or the
                        // reviewer's reopen mark still names the landed
                        // revision: one new revision appended above the old.
                        prev.revision + 1
                    } else {
                        prev.revision
                    };
                }
                record
            })
            .collect();
        Self {
            binary: binary.into(),
            filed_at: now,
            records: Some(records),
        }
    }

    /// The landed record for an id, if this document names one.
    pub fn record(&self, unknown_id: &str) -> Option<&UnknownRecord> {
        self.records
            .as_ref()
            .and_then(|records| records.iter().find(|r| r.id == unknown_id))
    }
}

/// The three readings of a ledger, never collapsed and never a clean bill of
/// health on their own (issue #368). This is the read-side shape every
/// consumer branches on; the writable document never carries it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EffectiveLedger {
    /// Nobody looked, or the filed document says nothing: no ledger document
    /// at all, or a filed document whose `records` key is absent. What is
    /// open on this binary is *unknown* — by the same one-way rule
    /// [`EffectiveCoverage`](crate::EffectiveCoverage) keeps — and absence
    /// must never render as zero open gaps.
    Unknown,
    /// The filed document speaks. Its records may be empty — that is the
    /// only honest *known-and-none*: the pipeline filed a document and
    /// filed it with nothing open.
    Filed(Vec<UnknownRecord>),
}

impl EffectiveLedger {
    /// The records the filed document names, or `None` when the reading is
    /// unknown. The two differ even when the filed list is empty: a
    /// known-and-none `Some([])` says nobody looked, while `None` says
    /// nobody filed.
    pub fn records(&self) -> Option<&[UnknownRecord]> {
        match self {
            EffectiveLedger::Unknown => None,
            EffectiveLedger::Filed(records) => Some(records),
        }
    }
}

/// The record tree's unknown-ledger directory: `re/unknowns/<workspace>`.
/// The pipeline owns the ledger documents filed here, one per target binary.
pub fn unknown_ledger_dir(workspace: impl AsRef<Path>) -> PathBuf {
    workspace.as_ref().join("re").join("unknowns")
}

/// The path of one binary's ledger document: `re/unknowns/<binary identity>.json`.
pub fn unknown_ledger_path(workspace: impl AsRef<Path>, binary: &BinaryIdentity) -> PathBuf {
    unknown_ledger_dir(workspace).join(format!("{binary}.json"))
}

/// Read one binary's ledger under the three-reading rule: a missing document
/// reads as [`EffectiveLedger::Unknown`] — nobody looked — and a filed
/// document whose `records` key is absent reads the same way, because an
/// absent key never means the list is empty. A filed document carrying an
/// explicitly empty list is the only [`EffectiveLedger::Filed`] nothing. The
/// missing-versus-corrupt distinction stays exactly as [`load_json`] draws
/// it: a corrupt document is a [`PersistError::Json`], never a reading of
/// unknown, and fails loudly.
pub fn read_unknown_ledger(
    workspace: impl AsRef<Path>,
    binary: &BinaryIdentity,
) -> Result<EffectiveLedger, PersistError> {
    match load_json::<UnknownLedger>(&unknown_ledger_path(workspace, binary)) {
        Ok(ledger) => Ok(match ledger.records {
            None => EffectiveLedger::Unknown,
            Some(records) => EffectiveLedger::Filed(records),
        }),
        Err(PersistError::NotFound { .. }) => Ok(EffectiveLedger::Unknown),
        Err(err) => Err(err),
    }
}

// ============================================================
// The reviewer's resolutions document
// ============================================================

/// What a reviewer settled an unknown as — the closed writable pair. There
/// is deliberately no `open` here: open is the *absence* of a resolution,
/// derived at join time as [`EffectiveDisposition::Open`], never written —
/// the same one-way rule the coverage and capability statuses keep.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnknownDisposition {
    /// The reviewer established the fact the record was asking about, on
    /// the grounds its reason line states. Settling is not a review verdict:
    /// it never accepts a unit, merges a branch, or changes a review status.
    Resolved,
    /// The reviewer judged the question irrelevant and says so with a
    /// reason. A dismissed record still counts in the audit ledger: a
    /// disposition records what was decided, never what was established.
    Dismissed,
}

display_serde_label!(UnknownDisposition {
    Resolved => "resolved",
    Dismissed => "dismissed",
});

/// The joined read-side state of a record: the two written dispositions plus
/// `Open`, derived at read time for a record the reviewer has not settled
/// (or whose settlement a reopen took back). `Open` is never written.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EffectiveDisposition {
    /// No resolution binds this record.
    Open,
    /// The reviewer established the fact.
    Resolved,
    /// The reviewer judged the question irrelevant.
    Dismissed,
}

impl From<UnknownDisposition> for EffectiveDisposition {
    fn from(disposition: UnknownDisposition) -> Self {
        match disposition {
            UnknownDisposition::Resolved => Self::Resolved,
            UnknownDisposition::Dismissed => Self::Dismissed,
        }
    }
}

/// One reviewer's answer to one unknown record. The four fields, pinned
/// verbatim: the disposition, the required bounded reason line — one line,
/// the same discipline the record's two wording fields keep, and free text
/// belongs here and nowhere else — the revision of the record the reviewer
/// expected when they wrote it (the write guard and the audit stamp), and
/// the timestamp.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnknownResolution {
    /// Whether the reviewer resolved or dismissed the record.
    pub disposition: UnknownDisposition,
    /// The reviewer's bounded one-line reason — required. A settle without
    /// its reason is refused at deserialization, so an answer that never
    /// says its grounds cannot land.
    pub reason: String,
    /// The record revision the reviewer had read when this was written.
    /// The guard every later settle or reopen is checked against.
    pub expected_revision: u32,
    /// When the reviewer wrote it, as a Unix timestamp in seconds.
    pub at: u64,
}

/// The reviewer's resolutions document — persisted reviewer intent at
/// `re/review/unknown_resolutions.json`, keyed by unknown id, beside the
/// skip set and the queue overlay because it obeys the same rule: it
/// survives every dashboard rebuild and every later batch run.
///
/// A `BTreeMap` keeps the serialized document deterministic: two owners who
/// settled the same records write byte-identical files. A resolution whose
/// record stops being derivable (its source slot disappeared) stays in this
/// document as a durable reviewer record — nothing here is ever silently
/// dropped, and the pipeline's ledger write never touches it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct UnknownResolutions {
    /// Unknown id → the reviewer's answer.
    pub resolutions: BTreeMap<String, UnknownResolution>,
    /// Reopen marks: unknown id → the record revision the reviewer reopened
    /// it from. Durable reviewer records, never deleted: each one is the
    /// reviewer's part of "reopening appends a revision" — the next ledger
    /// write appends one revision above the landed one at the marked
    /// revision, and the mark stops firing at any later revision.
    pub reopened: BTreeMap<String, u32>,
}

/// A reviewer settle or reopen was refused because the record changed
/// underneath them (issue #368). Same wording family as the review actions'
/// `ChangedUnderneath` conflict: the message names the state that is
/// actually landed, so a fresh batch run or a second reviewer can never be
/// silently overwritten.
#[derive(Debug, Error)]
pub enum UnknownActionError {
    #[error(
        "Unknown record {unknown_id} changed underneath you: it is now {current} — \
         not overwriting that decision"
    )]
    ChangedUnderneath {
        /// The unknown record the refused action targeted.
        unknown_id: String,
        /// The landed state found at check time, named for display.
        current: String,
    },
    #[error(
        "unknown record {unknown_id} cannot be settled without a reason line — \
         an answer must say its grounds"
    )]
    EmptyReason {
        /// The unknown record the reason-less settle targeted.
        unknown_id: String,
    },
}

/// Names the landed state a refused settle or reopen found, in the style the
/// review actions' `state_name` keeps: a missing entry reads as the open
/// state with the record's current revision, never as an empty string.
fn landed_state(record: &UnknownRecord, entry: Option<&UnknownResolution>) -> String {
    match entry {
        Some(entry) => format!(
            "{} at record revision {}",
            entry.disposition, entry.expected_revision
        ),
        None => format!("open at record revision {}", record.revision),
    }
}

impl UnknownResolutions {
    /// Settle a record as [`UnknownDisposition::Resolved`] (issue #368).
    ///
    /// The revision doctrine guards the write: the caller supplies the
    /// revision of the record the reviewer read, and a settle fails with
    /// [`UnknownActionError::ChangedUnderneath`] naming the landed state
    /// when the record has moved on since (a fresh batch re-derived it at a
    /// new revision) or when another settle already landed. `record` is the
    /// record as the ledger now files it.
    pub fn resolve(
        &mut self,
        record: &UnknownRecord,
        reason: impl Into<String>,
        expected_revision: u32,
        now: u64,
    ) -> Result<(), UnknownActionError> {
        self.settle(
            record,
            UnknownDisposition::Resolved,
            reason,
            expected_revision,
            now,
        )
    }

    /// Settle a record as [`UnknownDisposition::Dismissed`], under exactly
    /// the same revision guard as [`resolve`](Self::resolve).
    pub fn dismiss(
        &mut self,
        record: &UnknownRecord,
        reason: impl Into<String>,
        expected_revision: u32,
        now: u64,
    ) -> Result<(), UnknownActionError> {
        self.settle(
            record,
            UnknownDisposition::Dismissed,
            reason,
            expected_revision,
            now,
        )
    }

    fn settle(
        &mut self,
        record: &UnknownRecord,
        disposition: UnknownDisposition,
        reason: impl Into<String>,
        expected_revision: u32,
        now: u64,
    ) -> Result<(), UnknownActionError> {
        let reason = reason.into();
        if reason.trim().is_empty() {
            return Err(UnknownActionError::EmptyReason {
                unknown_id: record.id.clone(),
            });
        }
        if let Some(entry) = self.resolutions.get(&record.id) {
            return Err(UnknownActionError::ChangedUnderneath {
                unknown_id: record.id.clone(),
                current: landed_state(record, Some(entry)),
            });
        }
        if expected_revision != record.revision {
            return Err(UnknownActionError::ChangedUnderneath {
                unknown_id: record.id.clone(),
                current: landed_state(record, None),
            });
        }
        self.resolutions.insert(
            record.id.clone(),
            UnknownResolution {
                disposition,
                reason,
                expected_revision,
                at: now,
            },
        );
        Ok(())
    }

    /// Take a record back to open (issue #368): a resolution is a revision,
    /// never a deletion. The reopen is guarded by the same revision
    /// doctrine — the record must still stand at the revision the settled
    /// entry was written at — and on success the entry leaves the reviewer's
    /// map (it is their own intent they are taking back) while the reopen
    /// lands as a durable mark naming the revision it was taken back from.
    /// The next ledger write appends one revision above the landed one at
    /// that mark: nothing the pipeline owns is deleted or rewritten, and
    /// this write never touches the ledger document itself.
    pub fn reopen(&mut self, record: &UnknownRecord) -> Result<(), UnknownActionError> {
        let Some(entry) = self.resolutions.get(&record.id) else {
            return Err(UnknownActionError::ChangedUnderneath {
                unknown_id: record.id.clone(),
                current: landed_state(record, None),
            });
        };
        if entry.expected_revision != record.revision {
            return Err(UnknownActionError::ChangedUnderneath {
                unknown_id: record.id.clone(),
                current: landed_state(record, Some(entry)),
            });
        }
        self.resolutions.remove(&record.id);
        self.reopened.insert(record.id.clone(), record.revision);
        Ok(())
    }

    /// The reviewer's answer bound to a record, if one binds. Binding is by
    /// id alone — that is the resolution-attachment rule the deterministic
    /// ids make true: re-worded admission text keeps the record's id and
    /// keeps this resolution attached.
    pub fn resolution_for(&self, unknown_id: &str) -> Option<&UnknownResolution> {
        self.resolutions.get(unknown_id)
    }

    /// Join the pipeline's records with the reviewer's answers — the read
    /// time `open` / `resolved` / `dismissed` every consumer reads, in the
    /// ledger's own order. Nothing downstream stores its own copy: the join
    /// is recomputed from the two documents every time.
    pub fn join(&self, records: &[UnknownRecord]) -> Vec<JoinedUnknown> {
        records
            .iter()
            .map(|record| {
                let resolution = self.resolution_for(&record.id).cloned();
                let disposition = resolution
                    .as_ref()
                    .map_or(EffectiveDisposition::Open, |entry| entry.disposition.into());
                JoinedUnknown {
                    record: record.clone(),
                    disposition,
                    resolution,
                }
            })
            .collect()
    }
}

/// One unit's open record, as the review surface lists it: the question,
/// its severity, and the evidence that would close it — not the whole
/// joined record. The model carries the state a reviewer reads, never its
/// own copy of the join; the id is the same deterministic key the
/// reviewer's resolve and dismiss actions bind to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnitUnknown {
    /// The record's deterministic identity.
    pub id: String,
    /// The kind of gap, from the closed declared roster.
    pub kind: UnknownKind,
    /// How much the open gap matters, from the closed severity scale.
    pub severity: UnknownSeverity,
    /// One bounded question line, verbatim from the ledger.
    pub question: String,
    /// One bounded line naming the evidence that would close the record.
    pub required_evidence: String,
    /// The record's landed revision — the guard the reviewer's settle is
    /// checked against.
    pub revision: u32,
}

impl From<&UnknownRecord> for UnitUnknown {
    fn from(record: &UnknownRecord) -> Self {
        Self {
            id: record.id.clone(),
            kind: record.kind,
            severity: record.severity,
            question: record.question.clone(),
            required_evidence: record.required_evidence.clone(),
            revision: record.revision,
        }
    }
}

/// One unit of work's open unknown records, with their severity counts and
/// the settled records alongside — carried on the derived dashboard model
/// so the web unit detail, the review queue's tallies, and the terminal
/// dashboard all render the same open-unknown state (issue #376).
///
/// The shape is recomputed at build time from the pipeline's ledger and
/// the reviewer's resolutions document, exactly as
/// [`UnknownResolutions::join`] recomputes the joined readings; nothing
/// stores a second copy of the join.
///
/// The ledger's three readings ride through untouched: `open: None` is
/// *unknown* — no ledger document, a filed document whose `records` key is
/// absent, or a document that failed to parse — while `open: Some([])` is
/// the only honest known-and-none. Unknown never renders as zero.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnitUnknowns {
    /// This unit's open records, scoped to the unit; `None` when the
    /// ledger's reading is unknown.
    #[serde(default)]
    pub open: Option<Vec<UnitUnknown>>,
    /// Open counts per severity, derived from `open` — empty while the
    /// state is unknown, never standing in for the records themselves.
    #[serde(default)]
    pub open_by_severity: BTreeMap<UnknownSeverity, usize>,
    /// This unit's records the reviewer settled as resolved. A resolved or
    /// dismissed record reads as settled — visibly distinct from open —
    /// and a later re-derivation re-binds it by the record's deterministic
    /// id.
    #[serde(default)]
    pub resolved: usize,
    /// This unit's records the reviewer dismissed.
    #[serde(default)]
    pub dismissed: usize,
}

impl UnitUnknowns {
    /// The unknown reading: the ledger was never filed, carries no
    /// `records` key, or failed to parse. This is also the `Default` —
    /// a unit nobody filed against is unknown, never zero.
    pub fn unknown() -> Self {
        Self::default()
    }

    /// The honest reading for a unit's records already joined to their
    /// dispositions: the open ones ride with their severity counts, the
    /// settled ones land in their counts.
    pub fn from_joined(joined: &[JoinedUnknown]) -> Self {
        let mut unit = Self {
            open: Some(Vec::new()),
            ..Self::default()
        };
        for joined_unknown in joined {
            match joined_unknown.disposition {
                EffectiveDisposition::Open => {
                    let unknown = UnitUnknown::from(&joined_unknown.record);
                    *unit.open_by_severity.entry(unknown.severity).or_insert(0) += 1;
                    unit.open.as_mut().unwrap().push(unknown);
                }
                EffectiveDisposition::Resolved => unit.resolved += 1,
                EffectiveDisposition::Dismissed => unit.dismissed += 1,
            }
        }
        unit
    }

    /// This unit's open count; `None` means unknown and must never render
    /// as zero.
    pub fn open_count(&self) -> Option<usize> {
        self.open.as_ref().map(|open| open.len())
    }
}

/// One target binary's audit ledger as the run close and the dashboard
/// read it: the binary's whole ledger — every record filed against it,
/// function-scoped or binary-scoped — joined to the reviewer's resolutions
/// (issue #377). This is the same derived join [`UnitUnknowns`] carries per
/// unit, un-scoped: the run close prints it as the audit-ledger section,
/// and the terminal dashboard renders the identical section from the
/// builder's copy of the model, so the two readers never disagree.
///
/// The honesty rule rides through untouched: `unknowns.open` is `None`
/// when the ledger was never filed, carries no `records` key, or failed to
/// parse — what is open on this binary is *unknown*, and every surface
/// prints that as unknown, never as a clean run. The open, resolved, and
/// dismissed counts never fold into one another.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BinaryUnknownLedger {
    /// The binary identity the ledger speaks for, verbatim.
    pub binary: String,
    /// The joined state of every record in this binary's ledger: open
    /// records with their severity counts, and the counts the reviewer's
    /// resolutions settled.
    #[serde(default)]
    pub unknowns: UnitUnknowns,
}

/// One ledger record as the reviewer sees it: the record, the joined
/// disposition, and the reviewer's answer when one binds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JoinedUnknown {
    /// The pipeline's record, verbatim.
    pub record: UnknownRecord,
    /// The joined state: open, resolved, or dismissed.
    pub disposition: EffectiveDisposition,
    /// What the reviewer wrote, when their answer binds to the record.
    pub resolution: Option<UnknownResolution>,
}

/// The path of the reviewer's resolutions document:
/// `re/review/unknown_resolutions.json` — review-UI intent, stored beside
/// the skip set and the queue overlay rather than under the pipeline's
/// ledger directory.
pub fn unknown_resolutions_path(workspace: impl AsRef<Path>) -> PathBuf {
    workspace
        .as_ref()
        .join("re")
        .join("review")
        .join("unknown_resolutions.json")
}

/// Read the reviewer's resolutions document: a document that was never
/// written reads as nobody settled anything — the empty [`Default`], the
/// same reading the skip set and the queue overlay keep — while a corrupt
/// document stays corrupt: a [`PersistError::Json`], never an empty
/// reading, and it fails loudly.
pub fn read_unknown_resolutions(
    workspace: impl AsRef<Path>,
) -> Result<UnknownResolutions, PersistError> {
    match load_json::<UnknownResolutions>(&unknown_resolutions_path(workspace)) {
        Err(PersistError::NotFound { .. }) => Ok(UnknownResolutions::default()),
        result => result,
    }
}

// ============================================================
// The shared kind checker
// ============================================================

/// The shared checker for the closed kind roster — the one home of its
/// wording (issue #368), exactly as [`ScanCoverage::roster_faults`] is the
/// one home of the facet-pin wording (issue #352).
///
/// `declared` is the roster ([`DECLARED_UNKNOWN_KINDS`]); `produced` is what
/// the producers actually filed, as `(kind label, source slot)` pairs. Each
/// fault spells one drift in words, so a drift can only ever fail loudly:
/// a declared kind no producer files, a producer naming a kind the roster
/// never declared, or one kind produced twice from one source slot (the
/// same gap emitted twice is a duplicate question, never a second opinion).
/// An empty verdict means the producers pair one-for-one with the roster.
///
/// This ticket lands the checker and its own pins; the track-level sweep
/// that pairs the roster against the real producers through the real batch
/// path is issue #375.
pub fn unknown_roster_faults(declared: &[&str], produced: &[(&str, &str)]) -> Vec<String> {
    let mut faults = Vec::new();
    for kind in declared {
        if !produced
            .iter()
            .any(|(produced_kind, _)| produced_kind == kind)
        {
            faults.push(format!("declared kind `{kind}` has no producer"));
        }
    }
    for (i, (kind, slot)) in produced.iter().enumerate() {
        if !declared.contains(kind) {
            faults.push(format!(
                "producer files `{kind}`, a kind the roster never declared"
            ));
        }
        // One fault per offending slot, naming the kind and the slot: the
        // first occurrence reports, its later twins stay silent.
        let same = |k: &&str, s: &&str| *k == *kind && *s == *slot;
        let produced_twice = produced.iter().filter(|(k, s)| same(k, s)).count() > 1;
        let first_here = produced.iter().position(|(k, s)| same(k, s)) == Some(i);
        if produced_twice && first_here {
            faults.push(format!(
                "kind `{kind}` is produced twice from source slot `{slot}`"
            ));
        }
    }
    faults
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests;
