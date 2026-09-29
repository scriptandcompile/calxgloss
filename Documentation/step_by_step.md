# Calxgloss — Post-MVP Step-by-Step Plan

**MVP Status: Complete.** All 14 workspace crates are built and wired together. The full translation pipeline (`classify` → `translate` → `verify`) works end-to-end via CLI with terminal review, automatic retry, and batch translation.

**What's done (from the original plan):**
- Retry logic — `RetryConfig`, `RetryStrategy` (CompileFix → TestFix → Escalate), `TranslationAttempt`, `RetryResult`, `FixTemplate` with `fix.j2`
- Batch translation — `batch_translate()` with per-function retry, pass-rate summary
- CLI — `classify`, `translate`, `verify` subcommands with configurable retries
- Git automation — branches, commits, merge, patch records
- Terminal reports — colored output, classification reports, box-drawing headers
- Web UI data models — `UnitOfWork`, `ReviewDashboard`, `DependencyGraph` (scaffolded, not wired)
- PAL mapping table — 100+ mappings across 10 categories

**What's NOT done:**
- **Stabilize base** — 3 tests failing (`calxgloss-config`, `calxgloss-verify`)
- **Prompt refinement** — `Escalate` strategy is unimplemented (warns "not yet implemented — falling back to compile_fix")
- **Terminal review dashboard** — CLI has per-function output but no structured queue/dashboard
- **Dependency-aware work queue** — no DAG, no topological sort, no blocked-unit detection
- **Web review UI** — only data models; no axum server, no frontend, no endpoints
- **Shim layer generation** — DLLs classified as `CrateReplacement` are skipped; no auto-generated shims
- **Fault detection** — nothing implemented
- **Context tiers** — `escalate_on_failure` flag exists but tiered context logic is not implemented
- **CI / cross-platform verification** — no CI workflow files
- **Branch cleanup & archive** — no gc or cleanup subcommand

---

## Phase 0 — Stabilize the Base

> **Goal:** Fix the one known regression so all crates pass cleanly. This is prerequisite work — nothing upstream can be built reliably on a broken base.

| Step | What | Details |
|------|------|---------|
| 0.1 | Fix `calxgloss-config` failing test | `test_a_missing_optional_file_is_not_an_error` panics at line 574 — `loaded.is_empty()` fails. A user-global `calxgloss.toml` exists on the dev machine. Fix: skip the assertion or mock the search paths so no config file is ever found. |
| 0.2 | Fix `calxgloss-verify` failing test | 1 of 17 tests fails. Diagnose root cause. |
| 0.3 | Run `cargo clippy --workspace` and fix all lints | Clean build baseline before adding features. |
| 0.4 | Confirm `cargo test --workspace` passes 0 failures | Gate: do not proceed until all tests pass. |

---

## Phase 1 — Complete Retry Strategy Implementation

> **Goal:** Finish the retry logic that's mostly done. The `Escalate` strategy stub needs a real implementation.

| Step | What | Details |
|------|------|---------|
| 1.1 | Implement `Escalate` strategy | Currently `warn!("Escalate strategy not yet implemented — falling back to compile_fix")`. Implement a prompt that injects additional Ghidra context: neighboring functions, call graph neighbors, shared data structures, and type information. |
| 1.2 | Add prompt variant for out-of-bounds / edge cases | When tests fail on boundary values (zero, max, negative), add a strategy that specifically instructs the LLM to handle edge cases. |
| 1.3 | Add `--strategy` CLI flag | Let the user pick: `compile_fix`, `test_fix`, `escalate`, or `auto` (cycles through them). |
| 1.4 | Track token usage per attempt | Log context size per attempt in terminal output and to a JSON file. |

---

## Phase 2 — Prompt Refinement & Complexity Branching

> **Goal:** Adapt prompts based on function complexity, API category, and failure history.

| Step | What | Details | Status |
|------|------|---------|--------|
| 2.1 | Implement complexity-based prompt selection | Simple functions (≤30 instructions): send minimal prompt. Complex (>100 instructions): inject Ghidra data flow hints, type inference notes. | ✅ Complete |
| 2.2 | Implement API-aware prompt augmentation | When a function calls DirectX/GDI, inject the relevant mapping table rows. When it calls Win32 core, inject std lib equivalents. | ✅ **Done** |
| 2.3 | Implement failure-informed prompting | If v1 failed because of wrong shader constant mapping, v2's prompt explicitly notes: "Previous attempt mapped SetTexture incorrectly. Ghidra shows the stage parameter comes from X, not Y." | ⬜ Pending |
| 2.4 | Experiment prompt variants | Track pass rate per strategy per DLL category. Store in `re/analysis/prompt_strategy_log.json`. | ⬜ Pending |

---

## Phase 3 — Terminal Review Dashboard

> **Goal:** Replace scattered `stdout` output with a structured terminal dashboard showing queue status, pass rates, and quick review actions.

| Step | What | Details |
|------|------|---------|
| 3.1 | Define dashboard data model | Add `ReviewDashboard` type to `calxgloss-types` (not `calxgloss-web` — this is terminal-only). Includes queued/accepted/pending/sent-back counts and dependency-sorted queue. |
| 3.2 | Implement `calxgloss-cli dashboard` subcommand | Reads git branches (`re/*`), aggregates test results, renders a text-based table. Supports `--follow` for live updates. |
| 3.3 | Add per-unit quick-view | `dashboard view <dll>/<function>` shows justification, diff summary, test results, and attempt history. |
| 3.4 | Add `accept` / `reject` from terminal | `dashboard accept <dll>/<function>/vN` merges to main. `dashboard reject <dll>/<function>/vN --reason "..."` sends back with comments. |
| 3.5 | Batch accept | `dashboard accept-all` accepts everything in dependency order. |
| 3.6 | Stale-work highlighting | Branches sitting in pending status >24 hours are highlighted in yellow/red. |

---

## Phase 4 — Dependency-Aware Work Queue

> **Goal:** Automatically discover and enforce the dependency graph between DLLs, shim layers, PAL traits, and functions.

| Step | What | Details |
|------|------|---------|
| 4.1 | Build dependency tracker | In `calxgloss-analysis`, add `DependencyGraph` that reads Ghidra call graphs + shim layer declarations to produce a DAG of work units. |
| 4.2 | Implement topological sort | Sort work units so shim layers → PAL traits → functions → integration respects dependency order. |
| 4.3 | Enforce dependency on branch creation | Before creating a branch for `func_DrawPrimitive`, verify that `re/shim/wgpu` and `re/pal/GraphicsDevice` are already merged. |
| 4.4 | Auto-queue unmet units | If `func_DrawPrimitive` is accepted but `shim_wgpu` fails, `func_DrawPrimitive` is marked `Blocked`. |
| 4.5 | Persist dependency graph | Save as `re/analysis/dependency_graph.json` in the resultant workspace. |

---

## Phase 5 — Web Review UI

> **Goal:** Replace the terminal review interface with a proper web dashboard. The data models in `calxgloss-web` are already scaffolded.

| Step | What | Details | Status |
|------|------|---------|--------|
| 5.1 | Implement axum API layer | Wire up the scaffolded `server` module to real data sources. Endpoints: `GET /api/dashboard`, `GET /api/units/:id`, `POST /api/units/:id/accept`, `POST /api/units/:id/send-back`, `POST /api/units/:id/patch`, `GET /api/graph`. Uses `DashboardBuilder` for dashboard/graph data, `GitManager` for accept/reject operations. | ✅ Complete |
| 5.2 | Implement review queue backend | API reads from git branches and `re/` directory artifacts, constructs `UnitOfWork` instances, sorts by dependency order. |
| 5.3 | Add WebSocket for live progress | Stream translation progress events during `translate` runs. |
| 5.4 | Implement HTML/JS/CSS frontend | Build actual UI components: `DashboardView`, `DependencyGraphView`, `UnitOfWorkCard`, `ReviewQueue`, `RecentActivity`. Served statically by the axum server. |
| 5.5 | Add diff viewer | Render `git diff` output with line-by-line highlighting, showing Ghidra notes alongside Rust code. |
| 5.6 | Add dependency graph visualization | Render the DAG with SVG or Canvas, interactive zoom/pan. |
| 5.7 | Human review actions → git operations | Accept/reject/send-back actions call into `calxgloss-git` and `calxgloss-translator`. | ✅ Complete |
| 5.8 | End-to-end test | Run web server in CI, headless browser, verify data renders correctly. |

---

## Phase 6 — Shim Layer Generation

> **Goal:** Replace DirectX/GDI/audio DLLs with Rust crate equivalents, with auto-generated shim layers. Currently all `CrateReplacement`-category DLLs are skipped.

| Step | What | Details |
|------|------|---------|
| 6.1 | Define shim layer API contract | Add `ShimLayer` type to `calxgloss-types`: `source_dll`, `target_crate`, `mappings: Vec<ApiMapping>`. |
| 6.2 | Implement mapping auto-generation | After DLL classification, the LLM generates a mapping table: original API → crate API with parameter transformations. |
| 6.3 | Generate shim source code | From the mapping table, generate a Rust module implementing the original DLL's export surface. |
| 6.4 | Generate shim tests | For each mapping, generate a test that verifies the crate API is invoked with correct parameters. |
| 6.5 | Verify shim behavior | Run the original binary's test suite through the shim layer. |
| 6.6 | Add to classification workflow | After `classify`, automatically suggest shim layers for all `CrateReplacement` DLLs with an estimated mapping complexity score. |

---

## Phase 7 — Fault Detection & Recovery

> **Goal:** Automatically detect and recover from the failure modes documented in `Calxgloss.md` (context window exceeded, hallucination, infinite loops, wrong behavior).

| Step | What | Details |
|------|------|---------|
| 7.1 | Implement context-window detector | After each LLM call, check response size vs. model's context limit. Auto-split the function and retry with a focused basic block. |
| 7.2 | Implement hallucination detector | Cross-reference LLM-generated function calls against Ghidra's actual symbols. Flag non-existent API references. |
| 7.3 | Implement infinite-loop detector | Track prompt → output hashes. If same bad output repeats 3+ times, escalate to manual intervention. |
| 7.4 | Implement behavior-divergence detector | If tests pass but output differs on unseen inputs, flag as "insufficient test coverage" and expand test suite. |
| 7.5 | Resource exhaustion monitoring | Monitor LLM client for OOM / timeout. Queue work when the local model is overloaded. |
| 7.6 | Fault event log | All detected faults logged to `re/analysis/fault_log.json` with detection method, severity, and recovery action. |

---

## Phase 8 — Context Tiers

> **Goal:** Optimize token usage by sending the LLM only the context it needs. `escalate_on_failure` flag exists but tiered context logic is not implemented.

| Step | What | Details |
|------|------|---------|
| 8.1 | Implement tier selection logic | In `calxgloss-translator`, add `select_context_tier(function)` based on function complexity, API call count, and previous success rates. |
| 8.2 | Implement Tier 0 (function stub) | Only function name, signature, call graph neighbors. |
| 8.3 | Implement Tier 1 (disassembly + decompiler) | Full disassembly + Ghidra pseudo-C + type info. |
| 8.4 | Implement Tier 2 (disassembly + decompiler + tests) | Tier 1 + baseline test results + failing test cases. |
| 8.5 | Implement Tier 3 (module context) | Tier 2 + neighboring functions + shared data structures. |
| 8.6 | Implement Tier 4 (full module + crate shims) | Tier 3 + shim layer code + PAL trait definitions. |
| 8.7 | Implement tier escalation | Start at minimum tier. On failure, escalate automatically. |
| 8.8 | Track token usage | Log context size per function in `workspace_config.json` and `re/analysis/token_usage.json`. |

---

## Phase 9 — CI / Cross-Platform Verification

> **Goal:** Ensure the translated project builds and passes tests on Linux, macOS, and Windows.

| Step | What | Details |
|------|------|---------|
| 9.1 | Add CI workflow files | GitHub Actions or equivalent: one job per target platform. |
| 9.2 | Add `--target` build matrix | Each CI job runs `cargo build --target <target>` and `cargo test`. |
| 9.3 | Cross-compile test harness | For platforms where the original binary cannot run, verification harness uses PAL implementation directly. |
| 9.4 | Screenshot checksums for graphics | For DirectX → wgpu, compare rendered frames across platforms. |
| 9.5 | Audio sample comparison | Compare output sample arrays bit-for-bit across platforms. |
| 9.6 | Staged CI rollout | Start with `cargo build` only → `cargo test` → behavioral verification. |

---

## Phase 10 — Branch Cleanup & Archive

> **Goal:** Prevent branch sprawl as hundreds of failed branches accumulate.

| Step | What | Details |
|------|------|---------|
| 10.1 | Implement cleanup policy | Add `re_compile gc` subcommand that archives branches older than 7 days with no reviewer interaction. |
| 10.2 | Archive to `refs/archive/` | Moved branches renamed to `refs/archive/re/{dll}/{function}/v{N}` rather than deleted. |
| 10.3 | Interactive cleanup | `re_compile gc --dry-run` shows what would be archived. |
| 10.4 | Dashboard integration | Web UI shows "stale branches" count and bulk archive. |

---

## Summary: Effort Estimate by Phase

| Phase | Description | Effort | Depends On |
|-------|-------------|--------|------------|
| 0 | Stabilize base (fix failing tests) | 1–2d | None |
| 1 | Complete retry strategy (Escalate) | 2–3d | 0 |
| 2 | Prompt refinement | 2–3d | 1 |
| 3 | Terminal review dashboard | 3–5d | 1 |
| 4 | Dependency-aware work queue | 4–6d | 0, 3 |
| 5 | Web review UI | 8–12d | 3, 4 |
| 6 | Shim layer generation | 5–8d | 1, 6 |
| 7 | Fault detection & recovery | 4–6d | 1, 2 |
| 8 | Context tiers | 3–5d | 1, 2 |
| 9 | CI / cross-platform verification | 3–5d | 0 |
| 10 | Branch cleanup & archive | 2–3d | 4, 5 |

**Total estimated effort: 37–58 working days** (roughly 2–3 months for a single developer).

---

## Recommended Execution Order

For maximum value delivery, execute phases in this sequence:

1. **Phase 0** (stabilize) — immediate blocker, do first
2. **Phase 1** (finish retry) — unblocks the `Escalate` strategy the pipeline already expects
3. **Phase 3** (terminal dashboard) — improves review UX before web UI
4. **Phase 2** (prompt refinement) + **Phase 7** (fault detection) — in parallel, both improve reliability
5. **Phase 8** (context tiers) — optimizes cost after scale grows
6. **Phase 4** (dependency queue) — enables full-DLL translations
7. **Phase 5** (web UI) — replaces terminal dashboard; blocks on 3 + 4
8. **Phase 6** (shim layers) — can start in parallel after Phase 1
9. **Phase 9** (CI) — parallel after Phase 0
10. **Phase 10** (cleanup) — last, when branch count justifies it
