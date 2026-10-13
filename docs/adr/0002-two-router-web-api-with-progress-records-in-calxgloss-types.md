# ADR-0002: One shared route table, live-only WS router, progress records in calxgloss-types

- **Status:** Accepted
- **Date:** 2026-10-09 (W0 shipped, epic #55; recorded 2026-10-13)
- **Deciders:** Arthur (solo project)

## Context

The web UI was a review gate: it showed each unit's *result* but told the
operator nothing about the *process* — pipeline phase position, in-flight unit
phases, token spend, server state. The route table itself was three duplicated
router builders, and the WS-only registration of `/api/pipeline` and
`/api/progress` was an accident of that duplication, not a decision.

## Decision

Consolidate into **one shared route table where every endpoint declares its
router set**:

- Server management (`/api/server/*`) and the enhanced `/health` → **all
  routers** (`serve` and `live`).
- Live progress (`/api/progress`, `/api/progress/enhanced`, the WS upgrade) →
  **live router only**; plain `serve` has no live state to report.
- `/api/pipeline` → **shared**, answering an honest empty payload on plain
  `serve` rather than 404 (issue #61 precedent).

Cross-context progress records — `PipelinePhase`, `PhaseProgress`,
`BinaryProgress`, `TranslationPhase`, `LiveTranslationState` — live in
**`calxgloss-types`**, not the web crate or the CLI, so later tracks (W2's
`PipelineState`, W3's analytics) consume them without depending on the web
crate.

Every `PhaseProgress` carries an explicit state
(`NotStarted` / `InProgress` / `Complete` / `NoDataSource`); phases with no
backing data source (Restitching, Documentation) render as "no data source" —
**the UI must never fabricate progress**. Unmeasured values render as `—`,
never a zero.

## Consequences

The router-declaration rule binds every future endpoint ("every new endpoint
must state which router(s) it registers in"). The shared-types placement paid
off exactly as planned: W2 and W3–W4 reused those records. Honest degradation
became the standing vocabulary for all later web work.
