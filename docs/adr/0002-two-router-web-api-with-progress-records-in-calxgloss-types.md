# ADR-0002: One shared route table, live-only WS router, progress records in calxgloss-types

- **Status:** Accepted
- **Date:** 2026-10-09 (W0 shipped, epic #55; recorded 2026-10-13)
- **Deciders:** Arthur (solo project)

## Context

The web UI was a review gate. It showed each unit's *result*, but it told
the operator nothing about the *process*: where the pipeline stood among its
phases, which phases in-flight units were in, token spend, and server state.
The route table was three duplicated router builders. The WS-only
registration of `/api/pipeline` and `/api/progress` came from that
duplication. It was not a decision.

## Decision

Consolidate into **one shared route table where every endpoint declares its
router set**:

- Server management (`/api/server/*`) and the enhanced `/health` register on
  **all routers** (`serve` and `live`).
- Live progress (`/api/progress`, `/api/progress/enhanced`, the WS upgrade)
  registers on the **live router only**. Plain `serve` has no live state to
  report.
- `/api/pipeline` is **shared**. On plain `serve` it answers with an honest
  empty payload rather than a 404 (issue #61 precedent).

The cross-context progress records — `PipelinePhase`, `PhaseProgress`,
`BinaryProgress`, `TranslationPhase`, `LiveTranslationState` — live in
**`calxgloss-types`**, not in the web crate or the CLI. That lets later
tracks — W2's `PipelineState` and W3's analytics — use them without
depending on the web crate.

Every `PhaseProgress` has an explicit state (`NotStarted` / `InProgress` /
`Complete` / `NoDataSource`). A phase with no backing data source
(Restitching, Documentation) renders as "no data source". **The UI must
never fabricate progress.** An unmeasured value renders as `—`, never a
zero.

## Consequences

The router-declaration rule applies to every future endpoint: "every new
endpoint must state which router(s) it registers in". The shared-types
placement worked out exactly as planned: W2 and W3–W4 reused those records.
Honest degradation became the standing vocabulary for all later web work.
