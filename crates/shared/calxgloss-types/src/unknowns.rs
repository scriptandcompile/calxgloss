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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
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
mod tests {
    use super::*;
    use crate::persist::{JsonStore, save_json};

    /// One coverage-residue record: the fixture every test reaches for, in
    /// the shape the batch's coverage fold (issue #369) will file.
    fn coverage_record(binary: &str, function: &str, question: &str, now: u64) -> UnknownRecord {
        UnknownRecord::derive(
            binary,
            Some(function.to_string()),
            UnknownKind::CoverageFacet,
            UnknownSeverity::Blocking,
            question,
            "the decompiled body of the function",
            UnknownOrigin::Document {
                document: "typesdb".to_string(),
                facet: "function-bodies".to_string(),
            },
            now,
        )
    }

    /// A ledger document as the pipeline files it, holding the given records.
    fn filed_ledger(binary: &str, records: Vec<UnknownRecord>) -> UnknownLedger {
        UnknownLedger {
            binary: BinaryIdentity::new(binary),
            filed_at: 1_760_000_000,
            records: Some(records),
        }
    }

    #[test]
    fn the_round_trip_through_the_shared_json_store_passes_everything_through_untouched() {
        // A full round trip (issue #368): ids, kinds, severities, question
        // and required-evidence lines, origins, order, and revisions all
        // pass through the shared JSON store byte-faithfully.
        let dir = tempfile::TempDir::new().expect("temp workspace");
        let store = JsonStore::<UnknownLedger>::new(unknown_ledger_dir(dir.path()));
        let records = vec![
            coverage_record(
                "eqmain.dll",
                "DrawSprite",
                "what does DrawSprite do, given its body never decompiled?",
                100,
            ),
            UnknownRecord::derive(
                "eqmain.dll",
                None,
                UnknownKind::ExportUncovered,
                UnknownSeverity::Blocking,
                "what calls DrawSprite really do to its arguments?",
                "a filed baseline document calling DrawSprite",
                UnknownOrigin::CaseSet {
                    case_set: "export-DrawSprite".to_string(),
                },
                101,
            ),
            UnknownRecord::derive(
                "eqmain.dll",
                Some("InitWorld".to_string()),
                UnknownKind::AnalysisFamily,
                UnknownSeverity::Material,
                "who calls InitWorld, given caller edges cannot be answered?",
                "caller-edge listings from the analysis engine",
                UnknownOrigin::Family {
                    family: "caller-edges".to_string(),
                },
                102,
            ),
            UnknownRecord::derive(
                "eqmain.dll",
                Some("InitWorld".to_string()),
                UnknownKind::RetryPruned,
                UnknownSeverity::Notable,
                "what context the escalate would have re-asked is still missing?",
                "an analysis engine that can answer decompilation",
                UnknownOrigin::RetryDecision {
                    decision: "escalate#decompilation".to_string(),
                },
                103,
            ),
        ];
        let ledger = filed_ledger("eqmain.dll", records);

        store.save("eqmain.dll", &ledger).expect("ledger files");

        let loaded = store.load("eqmain.dll").expect("ledger loads");
        assert_eq!(loaded, ledger, "every field passes through untouched");
        let loaded_records = loaded.records.expect("filed records key");
        assert_eq!(
            loaded_records
                .iter()
                .map(|r| r.id.as_str())
                .collect::<Vec<_>>(),
            ledger
                .records
                .as_ref()
                .expect("same records")
                .iter()
                .map(|r| r.id.as_str())
                .collect::<Vec<_>>(),
            "the filing order survives"
        );
        assert_eq!(loaded_records[1].kind, UnknownKind::ExportUncovered);
        assert_eq!(loaded_records[2].severity, UnknownSeverity::Material);
        assert_eq!(loaded_records[3].revision, 1);
        assert_eq!(
            loaded_records[0].question,
            ledger.records.as_ref().unwrap()[0].question,
            "the question line survives word for word"
        );
    }

    #[test]
    fn the_three_free_text_fields_pass_through_their_documents_verbatim() {
        // The bounded-one-line discipline the P19 and P20 shapes already
        // share: each field's wording is owned once by the shared type, and
        // the store carries it unchanged — em dashes and all.
        let dir = tempfile::TempDir::new().expect("temp workspace");
        let record = coverage_record(
            "eqmain.dll",
            "F",
            "what does F do — its body never arrived?",
            100,
        );
        let ledger = filed_ledger("eqmain.dll", vec![record.clone()]);
        save_json(&unknown_ledger_path(dir.path(), &ledger.binary), &ledger).expect("ledger files");

        let resolutions = UnknownResolutions {
            resolutions: [(
                record.id.clone(),
                UnknownResolution {
                    disposition: UnknownDisposition::Resolved,
                    reason: "read the disassembly listing — it matches the shim".to_string(),
                    expected_revision: 1,
                    at: 200,
                },
            )]
            .into_iter()
            .collect(),
            reopened: BTreeMap::new(),
        };
        save_json(&unknown_resolutions_path(dir.path()), &resolutions).expect("resolutions file");

        let loaded_ledger = read_unknown_ledger(dir.path(), &ledger.binary).expect("ledger loads");
        let EffectiveLedger::Filed(records) = loaded_ledger else {
            panic!("a filed document reads as filed");
        };
        assert_eq!(records[0], record);
        let loaded: UnknownResolutions =
            load_json(&unknown_resolutions_path(dir.path())).expect("resolutions load");
        assert_eq!(loaded, resolutions);
        assert_eq!(
            loaded.resolutions[&record.id].reason,
            "read the disassembly listing — it matches the shim"
        );
    }

    // --- the three readings of a ledger, never collapsed ------------------

    #[test]
    fn an_unfiled_ledger_reads_as_unknown_never_as_no_gaps() {
        let dir = tempfile::TempDir::new().expect("temp workspace");
        let reading = read_unknown_ledger(dir.path(), &BinaryIdentity::new("eqmain.dll"))
            .expect("absence reads");
        assert_eq!(reading, EffectiveLedger::Unknown);
        assert!(
            reading.records().is_none(),
            "an unfiled ledger carries no records to render — never a clean bill of health"
        );
    }

    #[test]
    fn a_filed_document_without_a_records_key_reads_as_unknown() {
        // The absent-field rule ADR-0053 established, applied to this
        // track's own artifact: an absent key never means the list is empty.
        let dir = tempfile::TempDir::new().expect("temp workspace");
        let path = unknown_ledger_path(dir.path(), &BinaryIdentity::new("eqmain.dll"));
        std::fs::create_dir_all(path.parent().expect("ledger dir")).expect("create re/unknowns");
        std::fs::write(&path, r#"{"binary": "eqmain.dll", "filed_at": 1760000000}"#)
            .expect("file the keyless document");

        let reading = read_unknown_ledger(dir.path(), &BinaryIdentity::new("eqmain.dll"))
            .expect("the keyless document loads");
        assert_eq!(reading, EffectiveLedger::Unknown);
    }

    #[test]
    fn a_filed_empty_list_is_the_only_known_and_none_reading() {
        let dir = tempfile::TempDir::new().expect("temp workspace");
        let ledger = filed_ledger("eqmain.dll", Vec::new());
        save_json(&unknown_ledger_path(dir.path(), &ledger.binary), &ledger).expect("file empty");

        let reading = read_unknown_ledger(dir.path(), &ledger.binary).expect("empty list loads");
        assert_eq!(reading, EffectiveLedger::Filed(Vec::new()));
        assert_eq!(
            reading.records().expect("a filed empty list"),
            &[] as &[UnknownRecord],
            "explicitly-empty is the one honest nothing-is-open-here"
        );
    }

    #[test]
    fn a_corrupt_ledger_stays_corrupt_and_never_reads_as_unknown() {
        // The missing-versus-corrupt distinction (NotFound vs Json) stays.
        let dir = tempfile::TempDir::new().expect("temp workspace");
        let path = unknown_ledger_path(dir.path(), &BinaryIdentity::new("eqmain.dll"));
        std::fs::create_dir_all(path.parent().expect("ledger dir")).expect("create re/unknowns");
        std::fs::write(&path, "{ not json").expect("corrupt the document");

        let err = read_unknown_ledger(dir.path(), &BinaryIdentity::new("eqmain.dll"))
            .expect_err("a corrupt document fails loudly");
        assert!(
            matches!(err, PersistError::Json { .. }),
            "corrupt is corrupt: {err}"
        );
    }

    #[test]
    fn a_document_without_its_filing_envelope_is_not_a_filed_ledger() {
        // The envelope — which binary it was filed for and when — is what
        // lets a reader tell a filed document from a stray one.
        let err = serde_json::from_str::<UnknownLedger>(r#"{"records": []}"#)
            .expect_err("an envelope-less document is refused");
        assert!(
            err.to_string().contains("binary"),
            "the refusal names the missing envelope field: {err}"
        );
    }

    // --- the id pins: the load-bearing ones --------------------------------

    #[test]
    fn the_same_inputs_re_derived_across_attempts_and_runs_lands_the_same_id() {
        let first_run = coverage_record(
            "game_logic.dll",
            "DrawSprite",
            "what does DrawSprite do, given its body never decompiled?",
            100,
        );
        let later_run = coverage_record(
            "game_logic.dll",
            "DrawSprite",
            "what does DrawSprite do, given its body never decompiled?",
            9_999,
        );
        assert_eq!(
            first_run.id, later_run.id,
            "re-derivation never duplicates a question"
        );
    }

    #[test]
    fn re_worded_admission_text_keeps_the_id() {
        // The engine re-worded its limitation line; the gap is the same
        // facet of the same document for the same function.
        let before = coverage_record(
            "game_logic.dll",
            "DrawSprite",
            "what is DrawSprite doing?",
            100,
        );
        let after = coverage_record(
            "game_logic.dll",
            "DrawSprite",
            "what does the never-decompiled body of DrawSprite contain?",
            200,
        );
        assert_eq!(before.id, after.id, "the id excludes the wording lines");
        assert_ne!(
            before.question, after.question,
            "the wording lines did change"
        );
    }

    #[test]
    fn the_id_excludes_the_question_and_required_evidence_wording() {
        let plain = coverage_record("a.dll", "F", "one question", 100);
        let reworded = UnknownRecord::derive(
            "a.dll",
            Some("F".to_string()),
            UnknownKind::CoverageFacet,
            UnknownSeverity::Notable,
            "an entirely different sentence about the same gap",
            "and a different evidence sentence too",
            UnknownOrigin::Document {
                document: "typesdb".to_string(),
                facet: "function-bodies".to_string(),
            },
            200,
        );
        assert_eq!(plain.id, reworded.id);
    }

    #[test]
    fn a_different_facet_family_or_export_yields_a_different_id() {
        let bodies = coverage_record("a.dll", "F", "q", 100);
        let other_facet = UnknownRecord::derive(
            "a.dll",
            Some("F".to_string()),
            UnknownKind::CoverageFacet,
            UnknownSeverity::Blocking,
            "q",
            "e",
            UnknownOrigin::Document {
                document: "typesdb".to_string(),
                facet: "data-objects".to_string(),
            },
            100,
        );
        let other_document = UnknownRecord::derive(
            "a.dll",
            Some("F".to_string()),
            UnknownKind::CoverageFacet,
            UnknownSeverity::Blocking,
            "q",
            "e",
            UnknownOrigin::Document {
                document: "callback".to_string(),
                facet: "function-bodies".to_string(),
            },
            100,
        );
        let family = UnknownRecord::derive(
            "a.dll",
            Some("F".to_string()),
            UnknownKind::AnalysisFamily,
            UnknownSeverity::Material,
            "q",
            "e",
            UnknownOrigin::Family {
                family: "decompilation".to_string(),
            },
            100,
        );
        let export = UnknownRecord::derive(
            "a.dll",
            None,
            UnknownKind::ExportUncovered,
            UnknownSeverity::Blocking,
            "q",
            "e",
            UnknownOrigin::CaseSet {
                case_set: "export-F".to_string(),
            },
            100,
        );
        let other_export = UnknownRecord::derive(
            "a.dll",
            None,
            UnknownKind::ExportUncovered,
            UnknownSeverity::Blocking,
            "q",
            "e",
            UnknownOrigin::CaseSet {
                case_set: "export-G".to_string(),
            },
            100,
        );
        let ids = [
            bodies.id,
            other_facet.id,
            other_document.id,
            family.id,
            export.id,
            other_export.id,
        ];
        for (i, a) in ids.iter().enumerate() {
            for b in ids.iter().skip(i + 1) {
                assert_ne!(a, b, "genuinely different gaps are different ids: {a}");
            }
        }
    }

    #[test]
    fn the_id_folds_the_binary_and_the_function_where_the_record_is_function_specific() {
        // Same kind and slot across two binaries, and across two functions
        // of one binary: four different records. And the binary-level
        // spelling differs from any function's.
        let one = coverage_record("a.dll", "F", "q", 100);
        let other_binary = coverage_record("b.dll", "F", "q", 100);
        let other_function = coverage_record("a.dll", "G", "q", 100);
        let binary_level = UnknownRecord::derive(
            "a.dll",
            None,
            UnknownKind::CoverageFacet,
            UnknownSeverity::Blocking,
            "q",
            "e",
            UnknownOrigin::Document {
                document: "typesdb".to_string(),
                facet: "function-bodies".to_string(),
            },
            100,
        );
        assert_ne!(one.id, other_binary.id);
        assert_ne!(one.id, other_function.id);
        assert_ne!(one.id, binary_level.id);
        assert!(
            !one.id.contains("game") && one.id.starts_with("a.dll/F/coverage_facet/"),
            "the id is readable and folds its subject, its kind, and its slot: {}",
            one.id
        );
    }

    // --- revisions guard writes --------------------------------------------

    #[test]
    fn re_deriving_an_unchanged_record_keeps_its_revision_and_first_seen() {
        // Diff-friendly across attempts and runs (issue #368): the landed
        // document re-derived whole keeps every record's revision and
        // first-seen, refreshing only last-seen.
        let landed = filed_ledger(
            "a.dll",
            UnknownLedger::file(
                "a.dll",
                None,
                &[coverage_record("a.dll", "F", "what is F doing?", 100)],
                &BTreeMap::new(),
                100,
            )
            .records
            .expect("filed"),
        );
        let re_derived = UnknownLedger::file(
            "a.dll",
            Some(&landed),
            &[coverage_record("a.dll", "F", "what is F doing?", 500)],
            &BTreeMap::new(),
            500,
        );
        let records = re_derived.records.expect("filed again");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].id, landed.records.as_ref().unwrap()[0].id);
        assert_eq!(
            records[0].revision, 1,
            "a stamp move is not a content change"
        );
        assert_eq!(records[0].first_seen, 100, "first-seen survives untouched");
        assert_eq!(
            records[0].last_seen, 500,
            "last-seen refreshes to this derivation"
        );
    }

    #[test]
    fn a_changed_persisted_field_appends_a_new_revision_and_never_rewrites_the_old_one() {
        let first = UnknownLedger::file(
            "a.dll",
            None,
            &[coverage_record("a.dll", "F", "first wording", 100)],
            &BTreeMap::new(),
            100,
        );
        // Re-worded admission (the question changed): a new revision, one
        // above the landed. First-seen stays; nothing is rewritten.
        let second = UnknownLedger::file(
            "a.dll",
            Some(&first),
            &[coverage_record("a.dll", "F", "second wording", 200)],
            &BTreeMap::new(),
            200,
        );
        let second_records = second.records.as_ref().expect("filed");
        assert_eq!(second_records[0].revision, 2);
        assert_eq!(second_records[0].first_seen, 100);
        // A second change appends again — 3, and the landed 2 was never
        // rewritten in place.
        let third = UnknownLedger::file(
            "a.dll",
            Some(&second),
            &[UnknownRecord::derive(
                "a.dll",
                Some("F".to_string()),
                UnknownKind::CoverageFacet,
                UnknownSeverity::Material,
                "second wording",
                "e",
                UnknownOrigin::Document {
                    document: "typesdb".to_string(),
                    facet: "function-bodies".to_string(),
                },
                300,
            )],
            &BTreeMap::new(),
            300,
        );
        assert_eq!(third.records.expect("filed")[0].revision, 3);
    }

    #[test]
    fn a_new_record_files_at_revision_one_and_a_disappeared_slot_stops_being_derivable() {
        let landed = UnknownLedger::file(
            "a.dll",
            None,
            &[
                coverage_record("a.dll", "F", "q", 100),
                coverage_record("a.dll", "G", "q", 100),
            ],
            &BTreeMap::new(),
            100,
        );
        // G's source slot disappeared from the filed documents: the next
        // derivation simply does not name it.
        let re_derived = UnknownLedger::file(
            "a.dll",
            Some(&landed),
            &[coverage_record("a.dll", "F", "q", 500)],
            &BTreeMap::new(),
            500,
        );
        let records = re_derived.records.expect("filed");
        assert_eq!(
            records.len(),
            1,
            "the stopped-derivable record stops landing"
        );
        assert_eq!(records[0].function.as_deref(), Some("F"));
    }

    #[test]
    fn a_disappeared_slot_its_resolution_survives_as_a_durable_reviewer_record() {
        // The ledger replaces outright; the reviewer's document is a
        // different owner and this write never touches it.
        let dir = tempfile::TempDir::new().expect("temp workspace");
        let settled = coverage_record("a.dll", "G", "q", 100);
        let mut resolutions = UnknownResolutions::default();
        resolutions
            .resolve(&settled, "not relevant to this target", 1, 150)
            .expect("settle");
        save_json(&unknown_resolutions_path(dir.path()), &resolutions).expect("resolutions file");

        let landed = UnknownLedger::file(
            "a.dll",
            None,
            std::slice::from_ref(&settled),
            &BTreeMap::new(),
            100,
        );
        save_json(&unknown_ledger_path(dir.path(), &landed.binary), &landed).expect("file ledger");
        let re_derived = UnknownLedger::file("a.dll", Some(&landed), &[], &BTreeMap::new(), 500);
        save_json(
            &unknown_ledger_path(dir.path(), &re_derived.binary),
            &re_derived,
        )
        .expect("file again");

        assert!(
            re_derived.record(&settled.id).is_none(),
            "no longer derivable"
        );
        let durable: UnknownResolutions =
            load_json(&unknown_resolutions_path(dir.path())).expect("resolutions still load");
        assert!(
            durable.resolutions.contains_key(&settled.id),
            "the reviewer's answer is a durable reviewer record, never silently dropped"
        );
    }

    #[test]
    fn a_stale_settle_write_fails_with_a_named_changed_underneath_conflict() {
        // A fresh batch re-derived the record (revision 9 landed) after the
        // reviewer read revision 8: the settle loses, naming the landed state.
        let record = UnknownRecord::derive(
            "a.dll",
            Some("F".to_string()),
            UnknownKind::BaselineNeverRun,
            UnknownSeverity::Blocking,
            "was F ever exercised?",
            "filed baseline cases calling F",
            UnknownOrigin::CaseSet {
                case_set: "cases-F".to_string(),
            },
            900,
        );
        let landed_at_9 = UnknownRecord {
            revision: 9,
            ..record.clone()
        };
        let mut resolutions = UnknownResolutions::default();
        let err = resolutions
            .resolve(&landed_at_9, "established by hand", 8, 1_000)
            .expect_err("a stale write must fail loudly");
        assert!(matches!(err, UnknownActionError::ChangedUnderneath { .. }));
        let message = err.to_string();
        assert!(
            message.contains(&record.id),
            "the conflict names the record: {message}"
        );
        assert!(
            message.contains("open at record revision 9"),
            "the conflict names the landed state: {message}"
        );
    }

    #[test]
    fn a_two_action_race_lands_exactly_one_and_the_loser_names_the_landed_settlement() {
        let record = coverage_record("a.dll", "F", "q", 100);
        let mut resolutions = UnknownResolutions::default();
        resolutions
            .resolve(&record, "established by hand", 1, 200)
            .expect("first settle lands");
        let err = resolutions
            .dismiss(&record, "not relevant", 1, 300)
            .expect_err("the second settle loses to the first");
        assert!(matches!(err, UnknownActionError::ChangedUnderneath { .. }));
        let message = err.to_string();
        assert!(
            message.contains("resolved at record revision 1"),
            "the loser learns what already landed: {message}"
        );
        assert_eq!(resolutions.resolutions.len(), 1);
        assert_eq!(
            resolutions
                .resolution_for(&record.id)
                .expect("bound")
                .disposition,
            UnknownDisposition::Resolved,
            "exactly one settle landed"
        );
    }

    #[test]
    fn reopening_appends_a_revision_and_deletes_nothing() {
        // A resolution is a revision, never a deletion (issue #368): the
        // reopen marks the revision it was taken back from, and the next
        // ledger write appends one revision above the landed one — once.
        let record = coverage_record("a.dll", "F", "q", 100);
        let landed = UnknownLedger::file(
            "a.dll",
            None,
            std::slice::from_ref(&record),
            &BTreeMap::new(),
            100,
        );
        let landed_record = landed.record(&record.id).expect("landed").clone();
        assert_eq!(
            landed_record.revision, 1,
            "a fresh record files at revision 1"
        );

        let mut resolutions = UnknownResolutions::default();
        resolutions
            .resolve(&landed_record, "established", 1, 150)
            .expect("settle at revision 1");
        resolutions
            .reopen(&landed_record)
            .expect("reopen at revision 1");
        assert!(
            resolutions.resolutions.is_empty(),
            "the reviewer took their intent back"
        );
        assert_eq!(
            resolutions.reopened.get(&record.id),
            Some(&1),
            "the reopen itself is a durable reviewer mark"
        );

        // The next batch re-derives the same content: the mark fires, and a
        // NEW revision lands above the old — the old was never rewritten.
        let after_reopen = UnknownLedger::file(
            "a.dll",
            Some(&landed),
            &[coverage_record("a.dll", "F", "q", 500)],
            &resolutions.reopened,
            500,
        );
        let reopened_record = after_reopen.record(&record.id).expect("still derivable");
        assert_eq!(
            reopened_record.revision, 2,
            "reopening appended a new revision"
        );
        assert_eq!(
            reopened_record.first_seen, 100,
            "nothing about the record was deleted"
        );
        assert_eq!(
            reopened_record.id, record.id,
            "the record kept its identity"
        );

        // A third derivation: the mark already fired at revision 1, and the
        // landed revision is now 2 — it fires exactly once.
        let third = UnknownLedger::file(
            "a.dll",
            Some(&after_reopen),
            &[coverage_record("a.dll", "F", "q", 600)],
            &resolutions.reopened,
            600,
        );
        assert_eq!(third.record(&record.id).expect("landed").revision, 2);
    }

    #[test]
    fn reopening_without_a_settlement_loses_naming_the_landed_open_state() {
        let record = coverage_record("a.dll", "F", "q", 100);
        let mut resolutions = UnknownResolutions::default();
        let err = resolutions
            .reopen(&record)
            .expect_err("reopening an open record is refused");
        assert!(matches!(err, UnknownActionError::ChangedUnderneath { .. }));
        assert!(
            err.to_string().contains("open at record revision 1"),
            "the refusal names the landed state: {err}"
        );
    }

    #[test]
    fn reopening_a_stale_settlement_loses_naming_the_landed_settlement() {
        let record = coverage_record("a.dll", "F", "q", 100);
        let mut resolutions = UnknownResolutions::default();
        resolutions
            .resolve(&record, "established", 1, 150)
            .expect("settle at revision 1");
        // A fresh batch moved the record to revision 2 under the reviewer.
        let landed_at_2 = UnknownRecord {
            revision: 2,
            ..record.clone()
        };
        let err = resolutions
            .reopen(&landed_at_2)
            .expect_err("the reopen is stale against the landed revision");
        assert!(matches!(err, UnknownActionError::ChangedUnderneath { .. }));
        assert!(
            err.to_string().contains("resolved at record revision 1"),
            "the refusal names what the reviewer settled at: {err}"
        );
    }

    #[test]
    fn a_resolution_entry_is_keyed_by_id_and_carries_its_four_fields() {
        let dir = tempfile::TempDir::new().expect("temp workspace");
        let record = coverage_record("a.dll", "F", "q", 100);
        let mut resolutions = UnknownResolutions::default();
        resolutions
            .dismiss(&record, "the shim contract says it away", 1, 1_700_000_000)
            .expect("dismiss");
        save_json(&unknown_resolutions_path(dir.path()), &resolutions).expect("resolutions file");
        let loaded: UnknownResolutions =
            load_json(&unknown_resolutions_path(dir.path())).expect("resolutions load");
        let entry = loaded
            .resolutions
            .get(&record.id)
            .expect("keyed by unknown id");
        assert_eq!(entry.disposition, UnknownDisposition::Dismissed);
        assert_eq!(entry.reason, "the shim contract says it away");
        assert_eq!(entry.expected_revision, 1);
        assert_eq!(entry.at, 1_700_000_000);
    }

    #[test]
    fn a_resolution_without_its_reason_is_refused() {
        // The reason is required: an answer that never says its grounds
        // cannot land, at the boundary of the document itself.
        let err = serde_json::from_str::<UnknownResolution>(
            r#"{"disposition": "resolved", "expected_revision": 1, "at": 10}"#,
        )
        .expect_err("a reason-less entry must not deserialize");
        assert!(
            err.to_string().contains("reason"),
            "the refusal names the missing field: {err}"
        );
    }

    #[test]
    fn a_blank_reason_is_refused_as_strictly_as_a_missing_one() {
        // Required means required: a whitespace-only reason is an answer
        // that says its grounds no better than no reason at all.
        let record = coverage_record("a.dll", "F", "q", 100);
        let mut resolutions = UnknownResolutions::default();
        let err = resolutions
            .dismiss(&record, "   ", 1, 200)
            .expect_err("a whitespace-only reason is no grounds");
        assert!(matches!(err, UnknownActionError::EmptyReason { .. }));
        assert!(
            err.to_string().contains(&record.id),
            "the refusal names the record: {err}"
        );
        assert!(resolutions.resolutions.is_empty(), "nothing landed");
    }

    #[test]
    fn the_severity_scale_is_closed_and_its_blocking_level_is_the_done_claim_gate() {
        // Three levels, none a catch-all (issue #368). `blocking` means the
        // establishing evidence never arrived at all — the level a done
        // claim gates on — and every level has a criterion a producer can
        // honestly apply today.
        for label in ["notable", "material", "blocking"] {
            let parsed: UnknownSeverity = serde_json::from_str(&format!("\"{label}\""))
                .unwrap_or_else(|err| panic!("severity label `{label}` must be declared: {err}"));
            assert_eq!(
                serde_json::to_value(parsed).expect("severity writes"),
                *label
            );
            assert_eq!(parsed.to_string(), *label, "Display emits the same label");
        }
        assert!(
            serde_json::from_str::<UnknownSeverity>("\"devastating\"").is_err(),
            "the scale is closed: no producer can invent a fourth level"
        );
    }

    // --- two documents, two owners: the writers never clobber ----------------

    #[test]
    fn the_two_writers_never_clobber_each_others_documents() {
        // The store's whole-document replace makes the split load-bearing
        // (issue #368): a ledger write never touches reviewer intent, and a
        // reviewer write never touches the ledger.
        let dir = tempfile::TempDir::new().expect("temp workspace");
        let record = coverage_record("a.dll", "F", "q", 100);
        let ledger = UnknownLedger::file(
            "a.dll",
            None,
            std::slice::from_ref(&record),
            &BTreeMap::new(),
            100,
        );
        save_json(&unknown_ledger_path(dir.path(), &record.binary), &ledger).expect("file ledger");

        let mut resolutions = UnknownResolutions::default();
        resolutions
            .resolve(&record, "established", 1, 200)
            .expect("settle lands in the reviewer's document");
        save_json(&unknown_resolutions_path(dir.path()), &resolutions).expect("resolutions file");
        let reviewer_bytes = std::fs::read_to_string(unknown_resolutions_path(dir.path()))
            .expect("resolutions read");

        // The batch re-files the ledger outright, twice.
        let refiled = UnknownLedger::file(
            "a.dll",
            Some(&ledger),
            &[coverage_record("a.dll", "F", "q", 500)],
            &resolutions.reopened,
            500,
        );
        save_json(&unknown_ledger_path(dir.path(), &record.binary), &refiled)
            .expect("re-file ledger");
        save_json(
            &unknown_ledger_path(dir.path(), &record.binary),
            &UnknownLedger::file("a.dll", Some(&refiled), &[], &resolutions.reopened, 600),
        )
        .expect("re-file again with nothing derived");
        assert_eq!(
            std::fs::read_to_string(unknown_resolutions_path(dir.path()))
                .expect("resolutions read"),
            reviewer_bytes,
            "the pipeline's whole-document replace never touches reviewer intent"
        );
        let ledger_bytes = std::fs::read_to_string(unknown_ledger_path(dir.path(), &record.binary))
            .expect("ledger read");

        // A reviewer cycle (settle, reopen, re-settle) never touches the
        // ledger bytes: a reopen's revision rides the next pipeline write,
        // never a reviewer write — so the landed record still stands at
        // revision 1 and a fresh re-settle lands.
        resolutions
            .reopen(&record)
            .expect("reopen in the reviewer's document");
        resolutions
            .dismiss(
                refiled.record(&record.id).expect("landed"),
                "not relevant",
                1,
                800,
            )
            .expect("the landed revision never moved, so the re-settle is fresh");
        assert_eq!(
            resolutions
                .resolution_for(&record.id)
                .expect("re-settled")
                .disposition,
            UnknownDisposition::Dismissed
        );
        save_json(&unknown_resolutions_path(dir.path()), &resolutions)
            .expect("resolutions re-file");
        assert_eq!(
            std::fs::read_to_string(unknown_ledger_path(dir.path(), &record.binary))
                .expect("ledger read"),
            ledger_bytes,
            "the reviewer's whole-document replace never touches the ledger"
        );
    }

    // --- the join: open / resolved / dismissed, recomputed every read -------

    #[test]
    fn re_worded_admission_text_keeps_the_resolution_bound() {
        // The spine of the feature (issue #368): the reviewer answered the
        // gap, the engine re-worded its admission, and the answer is still
        // attached — id-stability is what makes review's work outlive the
        // wording that revealed the question.
        let mut resolutions = UnknownResolutions::default();
        let settled = coverage_record("a.dll", "F", "what is F doing?", 100);
        resolutions
            .resolve(&settled, "established by hand", 1, 150)
            .expect("settle at revision 1");

        let landed = UnknownLedger::file(
            "a.dll",
            None,
            std::slice::from_ref(&settled),
            &BTreeMap::new(),
            100,
        );
        let re_derived = UnknownLedger::file(
            "a.dll",
            Some(&landed),
            &[coverage_record(
                "a.dll",
                "F",
                "what is the re-worded question about F?",
                500,
            )],
            &resolutions.reopened,
            500,
        );
        let records = re_derived.records.expect("filed");
        assert_eq!(
            records[0].id, settled.id,
            "the re-worded record is the same gap"
        );
        let joined = resolutions.join(&records);
        assert_eq!(joined.len(), 1);
        assert_eq!(joined[0].disposition, EffectiveDisposition::Resolved);
        assert_eq!(
            joined[0].resolution.as_ref().expect("still bound").reason,
            "established by hand"
        );
    }

    #[test]
    fn the_join_reads_open_resolved_and_dismissed_from_the_two_documents() {
        let open = coverage_record("a.dll", "Open", "q", 100);
        let resolved = coverage_record("a.dll", "Resolved", "q", 100);
        let dismissed = coverage_record("a.dll", "Dismissed", "q", 100);
        let mut resolutions = UnknownResolutions::default();
        resolutions
            .resolve(&resolved, "established", 1, 150)
            .expect("resolve");
        resolutions
            .dismiss(&dismissed, "not relevant", 1, 160)
            .expect("dismiss");
        let joined = resolutions.join(&[open, resolved, dismissed]);
        assert_eq!(
            joined.iter().map(|j| j.disposition).collect::<Vec<_>>(),
            vec![
                EffectiveDisposition::Open,
                EffectiveDisposition::Resolved,
                EffectiveDisposition::Dismissed,
            ],
            "the join keeps the ledger's own order"
        );
        assert!(
            joined[0].resolution.is_none(),
            "open is the absence of intent, never written"
        );
    }

    // --- the closed kind roster and the shared checker ----------------------

    #[test]
    fn the_declared_roster_is_exactly_the_labels_the_kind_set_serde_writes() {
        // The roster's strings and the enum's persisted labels are one set,
        // in one order: grepping a roster entry finds the label it writes.
        for label in DECLARED_UNKNOWN_KINDS {
            let parsed: UnknownKind =
                serde_json::from_str(&format!("\"{label}\"")).unwrap_or_else(|err| {
                    panic!("roster label `{label}` must be a declared kind: {err}")
                });
            assert_eq!(serde_json::to_value(parsed).expect("kind writes"), *label);
            assert_eq!(parsed.to_string(), *label, "Display emits the same label");
        }
        assert_eq!(
            DECLARED_UNKNOWN_KINDS.len(),
            6,
            "one kind per gap family — grow the set with a producer, never ahead of one"
        );
    }

    #[test]
    fn the_roster_pairs_clean_against_a_clean_producer_set() {
        let produced = [
            ("coverage_facet", "typesdb#function-bodies"),
            ("analysis_family", "decompilation"),
            ("baseline_never_run", "cases-F"),
            ("export_uncovered", "export-DrawSprite"),
            ("retry_pruned", "escalate#decompilation"),
            ("tier_refused", "tier#module_context"),
        ];
        assert_eq!(
            unknown_roster_faults(DECLARED_UNKNOWN_KINDS, &produced),
            Vec::<String>::new(),
            "every declared kind paired with exactly one producer, every producer with a declared kind"
        );
    }

    #[test]
    fn a_declared_kind_with_no_producer_fails_naming_itself() {
        let produced = [("coverage_facet", "typesdb#function-bodies")];
        let faults = unknown_roster_faults(DECLARED_UNKNOWN_KINDS, &produced);
        assert_eq!(
            faults,
            [
                "declared kind `analysis_family` has no producer",
                "declared kind `baseline_never_run` has no producer",
                "declared kind `export_uncovered` has no producer",
                "declared kind `retry_pruned` has no producer",
                "declared kind `tier_refused` has no producer",
            ],
            "every dead kind appears, each naming itself"
        );
    }

    #[test]
    fn a_producer_naming_an_undeclared_kind_fails_naming_itself() {
        let produced = [("smokewood", "some#slot")];
        let faults = unknown_roster_faults(DECLARED_UNKNOWN_KINDS, &produced);
        assert!(
            faults
                .iter()
                .any(|f| f == "producer files `smokewood`, a kind the roster never declared"),
            "an invented kind fails loudly, naming itself: {faults:?}"
        );
    }

    #[test]
    fn a_kind_produced_twice_from_one_source_slot_fails_naming_itself() {
        let produced = [
            ("coverage_facet", "typesdb#function-bodies"),
            ("coverage_facet", "typesdb#function-bodies"),
        ];
        let faults = unknown_roster_faults(&["coverage_facet"], &produced);
        assert_eq!(
            faults,
            ["kind `coverage_facet` is produced twice from source slot `typesdb#function-bodies`"],
            "the same gap emitted twice is a duplicate question, and it is named once"
        );
    }

    #[test]
    fn the_same_kind_from_two_different_slots_is_no_fault() {
        let produced = [
            ("coverage_facet", "typesdb#function-bodies"),
            ("coverage_facet", "callback#function-bodies"),
            ("coverage_facet", "typesdb#data-objects"),
        ];
        assert_eq!(
            unknown_roster_faults(&["coverage_facet"], &produced),
            Vec::<String>::new()
        );
    }

    // --- record-tree locations, named and pinned ----------------------------

    #[test]
    fn the_two_documents_land_at_their_named_record_tree_locations() {
        // The ledger beside the record tree's owner directories; the
        // reviewer's document beside the skip set and the queue overlay.
        assert_eq!(
            unknown_ledger_path("/ws", &BinaryIdentity::new("eqmain.dll")),
            PathBuf::from("/ws")
                .join("re")
                .join("unknowns")
                .join("eqmain.dll.json")
        );
        assert_eq!(
            unknown_resolutions_path("/ws"),
            PathBuf::from("/ws")
                .join("re")
                .join("review")
                .join("unknown_resolutions.json")
        );
        // The JsonStore default naming and the pinned path agree, so the
        // batch's per-binary writer can use either.
        let store = JsonStore::<UnknownLedger>::new(unknown_ledger_dir("/ws"));
        assert_eq!(
            store.path_for("eqmain.dll"),
            unknown_ledger_path("/ws", &BinaryIdentity::new("eqmain.dll"))
        );
    }
}
