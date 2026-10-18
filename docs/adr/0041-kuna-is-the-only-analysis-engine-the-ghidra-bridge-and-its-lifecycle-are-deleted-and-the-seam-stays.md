# ADR-0041: Kuna is the only analysis engine — the Ghidra bridge and its lifecycle are deleted, the seam stays, and no engine choice remains

- **Status:** Accepted
- **Date:** 2026-10-18 (#214 shipped, epic #203)
- **Deciders:** Arthur (solo project)
- **Supersedes:** ADR-0001 (bethington/ghidra-mcp bridge), ADR-0007 (calxgloss-owned Ghidra server lifecycle)

## Context

ADR-0039 put Kuna behind the `ScanSource` seam as a *choice*: config and CLI
picked `analysis.engine = ghidra | kuna`, `PipelineSource` dispatched
`Live | Cached | Kuna`, and Ghidra stayed the default while parity was
reviewed. Every Ghidra-dependent command still carried the whole stack that
epic #203 set out to escape: the bethington bridge strictly paired to one
Ghidra build (ADR-0001), and the attach-or-spawn lifecycle — JDK gate,
install discovery, extension pairing, pid files, orphan reaping, boot
budgets, the wrong-program guard (ADR-0007).

With #206–#212 the seam's full read surface, provenance, write-back,
dialect consumers, heartbeats, and budgets all shipped on Kuna, and the
web harness ran an end-to-end scan on it (#212). The parity question
resolved in practice: nothing in the pipeline needs a capability Kuna
lacks, and the Ghidra path had become pure maintenance surface — a second
engine, a second failure mode, and the only reason any test or command
could require an external service.

## Decision

Delete the Ghidra path outright — no compatibility shims, no deprecation
window (issue #214):

- **The client and lifecycle are gone.** `GhidraClient` and the entire
  `lifecycle/` module leave `calxgloss-ghidra`; `PipelineSource::Live`
  goes with them, leaving `Cached | Kuna`. The crate keeps only the
  seam: the `ScanSource`/`TypeWriteSource` traits, the answer shapes,
  the shared parse scraper, and the two-tier read cache.
- **No engine choice anywhere.** The `[ghidra]` config block, the
  `analysis.engine` key, the `--engine` flag, and the
  `GHIDRA_*`/`CALXGLOSS_GHIDRA_*`/`ANALYSIS_ENGINE` variables are
  deleted. A stale config that still names them fails as an unknown-key
  parse error that names the offending keys and prints the example —
  `deny_unknown_fields` does the refusing; there is no special-case
  message and no ignored-key path.
- **The seam's vocabulary stops claiming Ghidra.** `GhidraError` becomes
  `EngineError` (`Reported`/`NotFound`/`Malformed`); the translator's
  fetch failure becomes `ScanFetch`; the progress event
  `GhidraFetchComplete` becomes `ScanFetchComplete` and
  `TranslationPhase::GhidraFetch` becomes `ScanFetch` (serde tag
  `scan_fetch`). The three lifecycle events with no producer left —
  `GhidraServerStarted`, `GhidraProjectCreated`,
  `GhidraProgramAnalyzed` — are deleted. `CachedGhidraSource` becomes
  `CachedScanSource` wrapping `KunaSource` concretely, and
  `CACHE_FORMAT_VERSION` moves 1 → 2 so bridge-era documents are never
  replayed. The CLI flag `--refresh-ghidra-cache` becomes
  `--refresh-cache`.
- **`doctor` shrinks to what is checkable.** The install, pairing, and
  port probes are deleted; it loads the target under Kuna and reports.
  `--fix` stays and says there is nothing to install.

What deliberately stays: the seam itself, the read cache, the parse
scraper, and the Ghidra-shaped *text* vocabulary — `FUN_…` names, the
`WARNING` decompiler dialect, objdump-style lowercase listings — because
Kuna reproduces that dialect and the pipeline's text handling is live
vocabulary, not bridge residue.

## Consequences

- Any run — CLI or web — works with no Ghidra install, no JVM, and no
  server; the whole test suite runs offline. The e2e web scan against
  the fixture is the acceptance proof.
- ADR-0039's seam and in-process-load decisions stand; its
  "Ghidra stays the default" half is retired by this ADR. ADR-0039 and
  ADR-0040 are left as written (historical record).
- Deferred renames, recorded so the name-vs-thing gap is intentional:
  the crate stays `calxgloss-ghidra` (the seam predates the engine),
  the on-disk cache directory stays `re/ghidra-cache/` (existing
  workspaces keep their caches; v2 format markers do the invalidating),
  and the web UI's "Ghidra Context" tab and `/api/units/{id}/ghidra`
  route stay (they serve decompile-dialect content; renaming them is a
  UI change, not an engine one).
- The web pipeline view's `project_ingestion` phase loses its original
  producers (the preflight events). It still lights from classification
  counts, so the phase survives; if it ever reads as dead in practice,
  a follow-up can drop it.
