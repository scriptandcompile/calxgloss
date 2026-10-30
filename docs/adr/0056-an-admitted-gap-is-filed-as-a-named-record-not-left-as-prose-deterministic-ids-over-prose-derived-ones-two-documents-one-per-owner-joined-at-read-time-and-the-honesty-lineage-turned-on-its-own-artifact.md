# ADR-0056: An admitted gap is filed as a named record, not left as prose — deterministic ids over prose-derived ones, two documents one per owner joined at read time, and the honesty lineage turned on its own artifact

- **Status:** Accepted
- **Date:** 2026-10-29 (P21 shipped, issues #368–#377, spec #367)
- **Deciders:** Arthur (solo project)

## Context

ADR-0053 made *what a scan did not examine* honest and ADR-0054/ADR-0055
made *what the analysis engine cannot answer* honest. By the time P21
started, both halves of the data existed — a filed coverage record could
admit `function-bodies: partial`, a capability report could admit a family
`unavailable` — yet every admission still asked a question nothing
recorded. An admission line qualified one prompt section for one attempt
and then vanished; a unit that reached review having run zero baseline
cases left no trace at all; and a finished run whose queue went quiet
looked identical to a finished run that established everything. Track P21
(#367) turns that admitted residue into questions: an **unknown record**
names its subject, its kind of gap, one question, one severity, and the
evidence that would close it, and a review action can answer it.

Four shape decisions were worth fixing the moment the vocabulary was
written down (issue #368), plus one deliberately left open: how a record
identifies itself when the same gap is re-admitted in different words
across attempts, batches, and runs; who owns the stored documents when the
shared JSON store replaces whole documents and two owners write; what a
ledger that was never filed means; whether a gap record can ever come from
*absent* admission data; and which severity level means *this gap blocks a
done claim* — a level P26 will gate on that this track must not gate on
itself.

## Decision

Turn the residue into records, and turn the honesty doctrine first on the
track's own artifact. Five decisions, filed as the continuation of the
ADR-0053 → ADR-0055 lineage:

- **Deterministic ids, never prose-derived ones.** An unknown record's id
  is `{binary}/{function or -}/{kind}/{source slot}` — the subject, the
  kind, and the slot its origin spells: the document kind plus facet id,
  the seam's family id, the case set, or the retry decision. The two
  wording lines — question and required evidence — are deliberately
  excluded, so re-admitting the same gap in new words lands the same id
  and keeps the reviewer's resolution bound to the question it answered,
  while a genuinely different gap (a different facet, family, or export)
  is a different id. The consequence is recorded with the decision: change
  the derivation and every existing resolution is orphaned, so the id
  pins (#368, re-pinned by every producer ticket) are the ones not to
  relax.
- **Two documents, two owners, joined only at read time.** The pipeline
  owns the **unknown ledger** — `re/unknowns/<binary identity>.json`, one
  document per target binary, replaced outright on each batch write in
  deterministic scan order, so it is always the current derived set and
  never an append log. The reviewer owns the **resolutions
  document** — `re/review/unknown_resolutions.json`, keyed by unknown id,
  beside the skip set and the queue overlay because it obeys the same
  rule: persisted reviewer intent, surviving every derived rebuild. A
  single shared document was rejected: the JSON store replaces whole
  documents, so the batch's write would clobber the reviewer's answers,
  and the derived/overlay separation the dashboard already practices
  would break. A record's effective state — *open*, *resolved*, or
  *dismissed* — exists only in the read-time join, and nothing downstream
  stores a copy of it. Revisions guard writes rather than recording
  history: a stale writer loses with the changed-underneath conflict the
  review actions already speak, reopening appends a revision and leaves a
  durable reviewer mark rather than deleting anything, and a settled
  record whose source slot stops deriving keeps its resolution as a
  durable reviewer record.
- **Absent reads `unknown` — now on the track's own artifact.** A ledger
  has three readings, never collapsed. No document at all, and a filed
  document whose `records` key is absent, both read *unknown* —
  ADR-0053's absent-field rule pointed at this track's own artifact — and
  only a filed document carrying an explicitly empty list means
  *known-and-none*. The missing-versus-corrupt distinction (`NotFound`
  against `Json`) stays exactly as the JSON store draws it: a corrupt
  document fails loudly, it is never a reading. No surface — prompt,
  dashboard, or the run close's audit ledger — renders any reading as a
  clean bill of health.
- **A declared `unknown` produces nothing.** Records exist only where a
  gap is already on disk, one write site per kind, from four producers:
  the batch's coverage fold (a facet recorded `partial` or `unavailable`),
  the batch's held capability report (a family declared `unavailable`,
  against the units whose retry posture actually re-asks it), the
  verification signal (a unit reaching review with zero baseline cases;
  an export no filed baseline document ever covered), and the ladder's
  own pruned escalate and refused tier step, carried up on the retry
  result. Both directions hold: absence never produces a gap record, and
  a produced record never rests on an absent record. The closed kind
  roster `DECLARED_UNKNOWN_KINDS` pairs one-for-one against the producers
  through the shared checker and the whole-track sweep (#375) — ADR-0053's
  roster doctrine one level up. A facet with no coverage record, and a
  family no engine declared, file no record, exactly as ADR-0055 pinned
  that unknown never prunes.
- **The open-blocking severity exists here and gates only in P26.**
  `blocking` — *this gap blocks a done claim* — is stamped by producers
  today, honestly, only where the establishing evidence never arrived at
  all: a facet admitted `unavailable`, zero baseline cases ever run, no
  filed baseline document for an export. It is no catch-all, and it is
  the exact level P26's conformance verdict will gate on. This track
  makes the gateable record exist and refuses nothing itself; refusing a
  "this binary is complete" claim stays P26's, and any strategy decision
  driven by unknowns stays P27's — the ladder keeps owning which prompt
  runs.

## Consequences

- A run no longer ends with a quiet queue: the run close and the terminal
  dashboard print the audit ledger per target binary — open records by
  severity, each with the evidence that would close it, and settled
  records counted apart, because a disposition records what was decided
  and never counts as established.
- Today the track ships honest silence: Kuna declares every family
  answerable and the fixture's scans read complete, so ledgers file
  empty-or-absent and every bundle-fed prompt renders byte-for-byte what
  it rendered before. The acceptance proof runs itself — the first
  partial scan, unavailable family, uncovered export, and pruned retry
  land in the ledger with no code change.
- A reviewer's answer outlives the run, the wording, and the batch that
  produced the question; and because each document has exactly one owner,
  neither owner can ever clobber the other's through a whole-document
  replace.
- Consumers ride doors that already exist: one projection row through
  ADR-0048's read seam, one evidence-bundle field, one shared section
  include (ADR-0049), and fields on the derived dashboard model — no new
  command, flag, or report row (ADR-0052), and the run-equals-`--show`
  contract is untouched because the ledger is not a scan document.
- P26 and P27 have their record side: P26 an open, severity-carrying,
  evidence-demanding record to gate on; P27 named open questions to
  declare hypotheses against.
- The vocabulary is defined where its carriers live — *unknown record*,
  *unknown ledger*, and *reviewer resolution* in the Shared glossary (the
  carriers), the Pipeline glossary (the producers and the ladder
  surface), and the Interface glossary (the review action and the ledger
  report) — and the record-tree entry names each document's owner. The
  five doctrines above live here, in this one place; the glossaries carry
  the terms and nothing more.
