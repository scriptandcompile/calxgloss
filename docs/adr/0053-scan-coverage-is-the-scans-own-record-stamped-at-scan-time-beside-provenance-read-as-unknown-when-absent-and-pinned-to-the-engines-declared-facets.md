# ADR-0053: Scan coverage is the scan's own record — stamped at scan time beside provenance, read as `unknown` when absent, and pinned to the engine's declared facets

- **Status:** Accepted
- **Date:** 2026-10-26 (P19 shipped, issues #345–#352, spec #344)
- **Deciders:** Arthur (solo project)

## Context

Every evidence engine reads only part of a target: a decompiler that skips
function bodies, a stripped binary with no vtable evidence, a scan that
never reads delay imports. Before P19 that partial reach left no trace in
the filed document: an empty control-flow section looked the same whether
the scan read every body or barely any, and the escalated retry prompt could
not tell "the program has no constants" from "the constants scan examined
little." ADR-0052 had already given each evidence engine exactly one
CLI-side home for such a field (the contribution entry's report printer),
and #345 shaped the record itself: `ScanCoverage` — a status, a facet
roster with limitation lines — living inside `ScanMetadata`. What the track
had to fix, across all fifteen evidence engines (#346's apidetect first
slice, #347 libmatch/floatsimd, #348 typesdb/consts, #349
controlflow/memory/sync, #350 globalstate/errhandling/callback, #351
algorithm/stringctx/serialize/typeinfer), was where the record lives, what
its absence means, and who keeps it honest.

The shape decisions worth fixing: whether the coverage record belongs
inside the evidence engine's findings payload or beside the scan's own
identity; whether a document with no record (every pre-P19 fixture) errors,
reads as complete, or reads as something else; whether the prompt and
report surfaces work out coverage downstream or only relay what the document
says; and how fifteen hand-written rosters stop drifting from the records
they describe.

## Decision

The scan's coverage is the scan's own record, stored in the envelope it
already has. An absent record reads as unknown. The evidence engines'
declared-facet tables are the single source of truth that the whole track
checks against.

- **Coverage is a property of the scan, so it lives in the scan's
  envelope — `ScanCoverage` inside `ScanMetadata`, beside provenance.** Run
  id, program path, timestamp, and the coverage record sit together in
  every filed document. The record is written once, inside the evidence
  engine's own scan, through the same single definition that the batch scan
  phase and the CLI's force-rescan share (ADR-0052's one-command design
  means fifteen evidence engines with one write site each). Nothing
  downstream recomputes or infers it. The persistor round-trip tests prove
  the filed document stores the recorded statuses, ids, order, and
  limitation lines exactly. The projection seam's `fill_coverage` legs read
  the record into the prompt bundle beside (never inside) the findings
  records it qualifies, exactly once per document, in registered order.
  Report printers print the shared dim admission line — the plain sentence
  saying what fell short — beside their counts only when a facet fell
  short. This is ADR-0052's rule — record a fact where it is produced,
  read it everywhere else — applied to meaning instead of plumbing.
- **Each evidence engine declares a static facet roster, and the roster
  holds the record to it at three levels.** Every evidence engine crate
  holds `pub const
  DECLARED_FACETS`, listing exactly the facets — the read
  surfaces — its scan could read. `ScanCoverage::roster_faults` in
  `calxgloss-types` spells every drift in one shared wording: a declared
  facet missing from the record, a facet appearing twice, or a record
  naming a facet the evidence engine never declared. Per evidence engine,
  a `roster_faults`
  test runs the checker over the written record against the crate's own
  table. Track-wide, the translator's test pass walks **every registered
  scan row's produced document** (fresh scans through the real pipeline:
  context, prebatch phase, filed documents read back) and checks each
  against the producing evidence engine's own `DECLARED_FACETS` — the table
  pairs registry row names with the crates' tables, so the check reads the
  tables' own data rather than a copy written on the test side — with one
  failure report naming every offending evidence engine at once. At the
  CLI, the
  #342 pairing tests keep rows and contribution entries one-for-one. A
  sixteenth evidence engine that writes no coverage record, or drifts a
  facet id, fails loudly at the track level, not at review time.
- **A document with no coverage record reads as `unknown` — never
  `complete`, never an error.** `ScanMetadata::coverage` is an `Option`;
  `coverage_status()` turns absence into `EffectiveCoverage::Unknown`. This
  is the compatibility rule for every pre-P19 fixture and every foreign
  document: it loads, its findings read as they always did, and coverage
  answers "we do not know." A track-wide test builds each evidence
  engine's pre-P19 document through its own persistor, asserts the raw
  bytes carry
  no `coverage` key, and asserts the load reads unknown — so old artifacts
  keep working for as long as the track stands.
- **Unknown and falling-short must never look like complete: the doctrine
  pair.** Empty findings under complete coverage and empty findings under a
  record admitting failure never render the same bytes — heading plus the
  admission line against bare heading, or a qualified empty section against
  a silent one. Every prompt surface shows the record's own bounded
  `Coverage:` qualification line (`ScanCoverage::admission` owns the
  wording once), and the prompts suite proves the pair for all fifteen
  evidence engines in one table. Typesdb keeps its established #348 exception inside
  the same doctrine: an empty structures list opens no section to qualify
  either way, so its pair runs on populated structures instead, and the
  invariant is asserted on the admission line itself.
- **The review UI needs nothing new.** The admission line is part of the
  prompt, and the viewer already shows the prompt verbatim — the web
  server's LLM I/O log records "the prompt sent to the LLM" as sent, so the
  qualification the LLM saw is the qualification a reviewer reads
  (`crates/interface/calxgloss-web/src/server/llm_io_log.rs`). No endpoint,
  view, or record type was added; the existing tests cover it.

## Consequences

- Operator-visible analysis behavior is unchanged by the close-out: the
  whole-track test pass, the orphan check, and the pre-P19 tests lock in
  what #345–#351 already shipped, and the fifteen run-equals-`--show`
  report tests — the contract that a command's run report and a later
  `--show` report of the same filed document are byte-identical — pass over
  the extended output untouched (names, flags, and report wording stand).
- Fifteen evidence engines now state their limits out loud in every
  document they file, and an empty section has exactly two honest readings
  — the target lacks the evidence, or the scan could not reach it — told
  apart by the record, not by guesswork.
- The rosters are the doctrine's single source of truth: an evidence engine
  adding a facet adds one string to `DECLARED_FACETS` and one line to its
  record, and forgetting either half fails its own test or the whole-track
  test pass immediately; the pass reports every offending evidence engine
  in one
  report, which keeps a track-wide regression diagnosable in one run.
- Pre-P19 documents are permanently supported: absence-as-unknown is tested
  per evidence engine through the real persistors, so a stale fixture and
  an
  accidental `complete` default both trip tests rather than quietly
  upgrading old records' authority.
- P21's verdict seam and P26's verdict consumption have their data side:
  the `unknown` value they must consume exists, is distinguished from
  `complete`, and is locked so it can never masquerade as it (roadmap
  updated).
- The next coverage-shaped feature (P20's cache-key work, verdict
  surfaces) inherits the rule: a fact the scan produces belongs in the
  envelope — written once where produced, absent reads as a named unknown,
  and the producing table is what the consumer's checks lean on.
