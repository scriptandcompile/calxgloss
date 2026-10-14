# ADR-0023: One JSON pattern database replaces the standard sets whole, with per-entry confidence riding on the pattern types

- **Status:** Accepted
- **Date:** 2026-10-14 (P3.5-2 shipped, issue #153)
- **Deciders:** Arthur (solo project)

## Context

The algorithm scan's recognizable shapes lived entirely in Rust: three
`default_*` functions carrying the standard control flow signatures,
string signatures, and callback contracts. Teaching the scanner a new
sort variant or comparator contract meant editing Rust and recompiling,
and an operator working a binary with domain-specific algorithms had no
way to describe what the scan should look for.

Spec #151 asked for a dynamic pattern database: one JSON document, a
`--patterns <file>` flag, and no change to a scan that supplies no
file. The questions this had to settle: whether the file format is a
new wire format or the pattern types' existing serde shape; whether a
file's entries merge with the built-in sets or replace them; where a
per-entry confidence lives and how it interacts with the resolution
ADR-0022 established; and how a malformed file behaves.

## Decision

- **The database is one serde document with one section per detector,
  and its entries are exactly the pattern types' existing serde
  shapes.** `PatternDatabase` (new `pattern_db` module) carries
  `control_flow: Vec<AlgorithmPattern>`, `string_signatures:
  Vec<StringSignature>`, and `callback_contracts: Vec<CallbackPattern>`
  — no parallel wire format, so what a scan persists and what a
  database carries are the same thing, and every existing serde
  round-trip test already pins half the file format. The fourth
  section a correlation detector will need (#155) is an additive
  change to the same document.
- **A supplied database replaces the standard sets whole; it never
  merges.** `AlgorithmEngine::with_pattern_database` swaps all three
  detector sets at once, and a section the document omits is an empty
  set. Merging would make the effective set depend on both the file and
  the built-ins, leave no way to *retire* a built-in signature that
  misfires on one binary, and make two operators' files mean different
  things. With replacement, the file is exactly what the scan knows;
  the built-in sets stay the default only when no file is supplied.
- **The per-entry confidence rides on the pattern types, not on a
  database wrapper.** `AlgorithmPattern`, `StringSignature`, and
  `CallbackPattern` each gained `confidence: Option<u8>`
  (serde-defaulted, skipped when absent), and each detector pays
  `confidence.unwrap_or(standard_score)` when it emits a hint. The
  entry *is* the pattern, so the field belongs to the pattern type:
  built-in and file entries then share one type and one semantics, and
  a later programmatic caller can carry an override without a file.
  For a string signature the override stands for either reading —
  body or listing-only — because the entry states its own trust, not a
  per-evidence-kind ladder.
- **The override wins resolution only by being stronger.** Hints enter
  ADR-0022's `resolve_conflicts` carrying their final score, so a
  per-entry 90 outweighs a standard-score claim for the same
  algorithm, and a per-entry 20 loses to one at 60. Being from a file
  privileges nothing; resolution stays purely score-based.
- **Loading goes through the shared JSON persistence plumbing, and a
  bad file fails the run loudly.** `PatternDatabase::load` wraps
  `calxgloss_types::persist::load_json`; a missing, unreadable, or
  malformed document becomes `AlgorithmError::PatternDatabase` naming
  the path. A typo in the file must never silently degrade recognition
  to a partial set, so the document is strict: `deny_unknown_fields`
  rejects a misspelled section key or entry field as a malformed file
  rather than ignoring it. Inside a well-formed entry the detectors'
  lenient per-entry semantics are untouched: an uncompilable regex
  matches nothing and vetoes nothing, and the `{name}` placeholder
  keeps working — file entries are built-in entries in every other
  respect.
- **The CLI flag is scan-only.** `calxgloss algorithm --patterns
  <file>` configures the scan; `--show` prints a cached result and
  ignores the flag, because the flag describes how a scan was run, not
  what a persisted document holds.

## Consequences

- Operators can teach the scanner new algorithm shapes without
  recompiling; the format is pinned by serde round-trip tests over the
  document and by scan-seam tests over a parsed file.
- The three pattern types grew one optional field each. Documents
  persisted before the change still load (the field is
  serde-defaulted), and the standard sets serialize unchanged — the
  field is skipped when absent.
- A file that supplies only some sections silently leaves the other
  detectors with nothing to read — that is the replacement contract,
  and the CHANGELOG and command help state it. A future authoring aid
  (validation or reporting of empty sections) stays out of scope.
- Detector registration order keeps its ADR-0022 role for ties; file
  section order is now part of that same load-bearing configuration
  order.
- The `--patterns` path is covered at the engine seam and through the
  persist round trip; the CLI itself stays a thin wiring layer with no
  test harness of its own, like every other flag before it.
