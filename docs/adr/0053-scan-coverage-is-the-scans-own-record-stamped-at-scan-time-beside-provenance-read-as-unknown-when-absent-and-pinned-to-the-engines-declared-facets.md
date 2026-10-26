# ADR-0053: Scan coverage is the scan's own record — stamped at scan time beside provenance, read as `unknown` when absent, and pinned to the engine's declared facets

- **Status:** Accepted
- **Date:** 2026-10-26 (P19 shipped, issues #345–#352, spec #344)
- **Deciders:** Arthur (solo project)

## Context

Every evidence engine reads only part of a target: a decompiler that skips
bodies, a stripped binary with no vtable evidence, a scan that never pulls
delay imports. Until P19 that partial sight left no trace in the filed
document — an empty control-flow section read the same whether the scan
walked every body or barely any, and the escalated retry prompt could not
tell "the program has no constants" from "the constants scan examined
little." ADR-0052 had already given each engine exactly one CLI-side home
for such a field (the contribution entry's report printer), and #345 shaped
the record itself: `ScanCoverage` — a status, a facet roster with limitation
lines — living inside `ScanMetadata`. What the track had to fix, across all
fifteen engines (#346's apidetect tracer, #347 libmatch/floatsimd, #348
typesdb/consts, #349 controlflow/memory/sync, #350 globalstate/errhandling/
callback, #351 algorithm/stringctx/serialize/typeinfer), was where the
record lives, what its absence means, and who keeps it honest.

The shape decisions worth fixing: whether coverage rides inside the engine's
findings payload or beside the scan's own identity; whether a document with
no record (every pre-P19 fixture) errors, reads complete, or reads
something else; whether the prompt and report surfaces infer coverage
downstream or only relay what the document says; and how fifteen hand-kept
rosters stop drifting from the records they describe.

## Decision

The scan's coverage is the scan's own record, carried in the envelope it
already has, absent reads as unknown, and the engines' declared-facet tables
are the single source of truth the whole track is pinned against.

- **Coverage is a property of the scan, so it rides the scan's envelope —
  `ScanCoverage` lives inside `ScanMetadata`, beside provenance.** Run id,
  program path, timestamp, and the coverage record sit together in every
  filed document; the record is stamped once, inside the engine's own scan,
  through the same single definition the batch scan phase and the CLI's
  force-rescan share (ADR-0052's one-command fold means fifteen engines,
  one stamp site each). Nothing downstream recomputes or infers it: the
  persistor round-trip pins prove the filed document carries the stamped
  statuses, ids, order, and limitation lines exactly; the projection seam's
  `fill_coverage` legs read the record into the prompt bundle beside (never
  inside) the findings records it qualifies, exactly once per document in
  registered order; report printers print the shared dim admission line
  beside their counts only when there is something to admit. This is
  ADR-0052's rule — recorded where produced, read everywhere else — applied
  to semantics instead of plumbing.
- **Each engine declares a static facet roster, and the roster pins the
  record at three levels.** Every engine crate carries `pub const
  DECLARED_FACETS` naming exactly the facets its scan could read;
  `ScanCoverage::roster_faults` in `calxgloss-types` spells every drift in
  one shared wording — a declared facet missing from the record, a facet
  appearing twice, a record naming a facet the engine never declared.
  Per engine, a `roster_faults` test runs the checker over the stamp against
  the crate's own table. Track-wide, the translator's sweep walks **every
  registered scan row's produced document** (fresh scans through the real
  pipeline: context, prebatch phase, filed documents read back) and pins
  each against the producing engine's own `DECLARED_FACETS` — the table
  pairs registry row names with the crates' tables, so the pin reads the
  tables' own data rather than a test-side re-spelling — one failure report
  naming every offending engine at once. At the CLI, the #342 pairing tests
  keep rows and contribution entries one-for-one. Adding a sixteenth engine
  that stamps nothing, or drifts a facet id, fails loudly at the track
  level, not at review time.
- **A document with no coverage record reads as `unknown` — never
  `complete`, never an error.** `ScanMetadata::coverage` is an `Option`;
  `coverage_status()` folds absence to `EffectiveCoverage::Unknown`. This is
  the compatibility rule for every pre-P19 fixture and every foreign
  document: it loads, its findings read as they always did, and coverage
  answers "we do not know." A track sweep builds each engine's pre-P19
  document through that engine's own persistor, asserts the raw bytes carry
  no `coverage` key, and asserts the load reads unknown — so old artifacts
  keep working for as long as the track stands.
- **Unknown and falling-short must never render like complete: the doctrine
  pair.** Empty findings under complete coverage and empty findings under a
  record admitting failure never render the same bytes — heading plus the
  admission line against bare heading, or a qualified empty section against
  a silent one. Every prompt surface carries the record's own bounded
  `Coverage:` qualification line (`ScanCoverage::admission` owns the
  wording once), and the prompts suite proves the pair for all fifteen
  engines in one table. Typesdb keeps its established #348 exception inside
  the same doctrine: an empty structures list opens no section to qualify
  either way, so its pair rides populated structures and the invariant is
  asserted on the admission line itself.
- **The review UI needs nothing new.** The admission line is part of the
  prompt, and the viewer already shows the prompt verbatim — the web
  server's LLM I/O log records "the prompt sent to the LLM" as sent, so the
  qualification the LLM saw is the qualification a reviewer reads
  (`crates/interface/calxgloss-web/src/server/llm_io_log.rs`). No endpoint,
  view, or record type was added; the existing pins cover it.

## Consequences

- Operator-visible analysis behavior is unchanged by the close-out: the
  sweep, orphan, and pre-P19 tests pin what #345–#351 already shipped, and
  the fifteen run-equals-`--show` report pins pass over the extended output
  untouched (names, flags, and report wording stand).
- Fifteen engines now speak their limits out loud in every document they
  file, and an empty section has exactly two honest readings — the target
  lacks the evidence, or the scan could not reach it — told apart by the
  record, not by guesswork.
- The rosters are the doctrine's single source of truth: an engine adding a
  facet adds one string to `DECLARED_FACETS` and one line to its stamp, and
  forgetting either half fails its own test or the track sweep immediately;
  the sweep's one-report-many-engines shape keeps a track-wide regression
  diagnosable in one run.
- Pre-P19 documents are permanently supported: absence-as-unknown is tested
  per engine through the real persistors, so fixture rot and accidental
  `complete` defaults both trip tests rather than silently upgrading old
  records' authority.
- P21's verdict seam and P26's verdict consumption have their data side:
  the `unknown` value they must consume exists, is distinguished from
  `complete`, and is pinned never to masquerade as it (roadmap updated).
- The next coverage-shaped feature (P20's cache-key work, verdict surfaces)
  inherits the rule: if a scan-produced fact rides the envelope, it is
  stamped once where produced, absent reads as a named unknown, and the
  producing table pins the consumer.
