# Calxgloss — Post-MVP Step-by-Step Plan

**MVP Status: Complete.** All 14 workspace crates are built and wired together. The full translation pipeline (`classify` → `translate` → `verify`) works end-to-end via CLI with terminal review, automatic retry, and batch translation.

**What's done (from the original plan):**
- Retry logic — `RetryConfig`, `RetryStrategy` (CompileFix → TestFix → Escalate → EdgeCaseFix), `TranslationAttempt`, `RetryResult`, `FixTemplate` with `fix.j2`
- Batch translation — `batch_translate()` with per-function retry, pass-rate summary
- CLI — `classify`, `translate`, `verify`, `dashboard`, `auto` subcommands with configurable retries and strategy flags
- Git automation — branches, commits, merge, patch records, auto-branch-creation policy
- Terminal reports — colored output, classification reports, box-drawing headers, `render_dashboard()` with stale-work highlighting, `render_dashboard_follow()` for live updates
- Terminal dashboard — `ReviewDashboard` with dependency-sorted queue, per-unit quick-view, accept/reject/batch-accept, staleness detection, `--follow` live mode
- Dependency-aware work queue — `DependencyTracker` builds DAG from Ghidra call graphs + shim declarations; `DependencyGraphPersistor` saves to `re/analysis/dependency_graph.json`; `auto_block_units()` marks blocked work
- Web review UI — axum server with API endpoints (`/api/dashboard`, `/api/queue`, `/api/graph`), WebSocket live progress, HTML/JS/CSS frontend with diff viewer, dependency graph visualization, review actions wired to git operations
- Prompt refinement — failure-informed prompts for all retry strategies, `PromptStrategyLogger` persists experiment log to JSON file, complexity- and API-aware prompt selection
- Fault detection — context-window detector with `ContextWindowFault`, function splitter (`FunctionSplitter`), truncation signal detection, and `FaultLogger` persistence (Phase 7, Step 7.1); hallucination detector with `HallucinationDetector`, identifier extraction, false-positive filtering, and close-match suggestions (Phase 7, Step 7.2)
- Shim layer generation — `ShimLayer` types, `generate_shim_mappings()` (LLM-driven), `generate_shim_source()`, `generate_shim_tests()`, `Verifier::verify_shim`, shim suggestion generation after classification
- PAL mapping table — 100+ mappings across 10 categories
- All workspace tests pass 0 failures

**What's NOT done:**
- **Context tiers** — Tier 0 (function stub) is implemented (8.2), but remaining tier-specific prompt assembly, escalation, and token tracking remain (8.3–8.8)
- **CI / cross-platform verification** — no CI workflow files (Phase 9)
- **Branch cleanup & archive** — no gc or cleanup subcommand (Phase 10)

---

## Phase 0 — Stabilize the Base

> **Goal:** Fix the one known regression so all crates pass cleanly. This is prerequisite work — nothing upstream can be built reliably on a broken base.

| Step | What | Details | Status |
|------|------|---------|--------|
| 0.1 | Fix `calxgloss-config` failing test | `test_a_missing_optional_file_is_not_an_error` panics at line 574 — `loaded.is_empty()` fails. A user-global `calxgloss.toml` exists on the dev machine. Fix: skip the assertion or mock the search paths so no config file is ever found. | ✅ Complete |
| 0.2 | Fix `calxgloss-verify` failing test | 1 of 17 tests fails. Diagnose root cause. | ✅ Complete |
| 0.3 | Run `cargo clippy --workspace` and fix all lints | Clean build baseline before adding features. | ✅ Complete |
| 0.4 | Confirm `cargo test --workspace` passes 0 failures | Gate: do not proceed until all tests pass. | ✅ Complete |

---

## Phase 1 — Complete Retry Strategy Implementation

> **Goal:** Finish the retry logic that's mostly done. All strategies (Escalate, EdgeCaseFix) are implemented; only per-attempt token logging to file remains.

| Step | What | Details | Status |
|------|------|---------|--------|
| 1.1 | Implement `Escalate` strategy | Currently `warn!("Escalate strategy not yet implemented — falling back to compile_fix")`. Implement a prompt that injects additional Ghidra context: neighboring functions, call graph neighbors, shared data structures, and type information. | ✅ Complete |
| 1.2 | Add prompt variant for out-of-bounds / edge cases | When tests fail on boundary values (zero, max, negative), add a strategy that specifically instructs the LLM to handle edge cases. | ✅ Complete |
| 1.3 | Add `--strategy` CLI flag | Let the user pick: `compile_fix`, `test_fix`, `escalate`, or `auto` (cycles through them). | ✅ Complete |
| 1.4 | Track token usage per attempt | Log context size per attempt in terminal output and to a JSON file at `re/analysis/token_usage.json`. | ✅ Complete |

---

## Phase 2 — Prompt Refinement & Complexity Branching

> **Goal:** Adapt prompts based on function complexity, API category, and failure history.

| Step | What | Details | Status |
|------|------|---------|--------|
| 2.1 | Implement complexity-based prompt selection | Simple functions (≤30 instructions): send minimal prompt. Complex (>100 instructions): inject Ghidra data flow hints, type inference notes. | ✅ Complete |
| 2.2 | Implement API-aware prompt augmentation | When a function calls DirectX/GDI, inject the relevant mapping table rows. When it calls Win32 core, inject std lib equivalents. | ✅ **Done** |
| 2.3 | Implement failure-informed prompting | If v1 failed because of wrong shader constant mapping, v2's prompt explicitly notes: "Previous attempt mapped SetTexture incorrectly. Ghidra shows the stage parameter comes from X, not Y." | ✅ Complete |
| 2.4 | Experiment prompt variants | Track pass rate per strategy per DLL category. Store in `re/analysis/prompt_strategy_log.json`. | ✅ Complete |

---

## Phase 3 — Terminal Review Dashboard

> **Goal:** Replace scattered `stdout` output with a structured terminal dashboard showing queue status, pass rates, and quick review actions.

| Step | What | Details | Status |
|------|------|---------|--------|
| 3.1 | Define dashboard data model | Add `ReviewDashboard` type to `calxgloss-types` (not `calxgloss-web` — this is terminal-only). Includes queued/accepted/pending/sent-back counts and dependency-sorted queue. | ✅ Complete |
| 3.2 | Implement `calxgloss-cli dashboard` subcommand | Reads git branches (`re/*`), aggregates test results, renders a text-based table. Supports `--follow` for live updates. | ✅ Complete |
| 3.3 | Add per-unit quick-view | `dashboard view <dll>/<function>` shows justification, diff summary, test results, and attempt history. | ✅ Complete |
| 3.4 | Add `accept` / `reject` from terminal | `dashboard accept <dll>/<function>/vN` merges to main. `dashboard reject <dll>/<function>/vN --reason "..."` sends back with comments. | ✅ Complete |
| 3.5 | Batch accept | `dashboard accept-all` accepts everything in dependency order. | ✅ Complete |
| 3.6 | Stale-work highlighting | Branches sitting in pending status >24 hours are highlighted in yellow/red. | ✅ Complete |

---

## Phase 4 — Dependency-Aware Work Queue

> **Goal:** Automatically discover and enforce the dependency graph between DLLs, shim layers, PAL traits, and functions.

| Step | What | Details | Status |
|------|------|---------|--------|
| 4.1 | Build dependency tracker | In `calxgloss-analysis`, add `DependencyGraph` that reads Ghidra call graphs + shim layer declarations to produce a DAG of work units. | ✅ Complete |
| 4.2 | Implement topological sort | Sort work units so shim layers → PAL traits → functions → integration respects dependency order. | ✅ Complete |
| 4.3 | Enforce dependency on branch creation | Before creating a branch for `func_DrawPrimitive`, verify that `re/shim/wgpu` and `re/pal/GraphicsDevice` are already merged. | ✅ Complete |
| 4.4 | Auto-queue unmet units | If `func_DrawPrimitive` is accepted but `shim_wgpu` fails, `func_DrawPrimitive` is marked `Blocked`. | ✅ Complete |
| 4.5 | Persist dependency graph | Save as `re/analysis/dependency_graph.json` in the resultant workspace. | ✅ Complete |

---

## Phase 5 — Web Review UI

> **Goal:** Replace the terminal review interface with a proper web dashboard. The data models in `calxgloss-web` are already scaffolded.

| Step | What | Details | Status |
|------|------|---------|--------|
| 5.1 | Implement axum API layer | Wire up the scaffolded `server` module to real data sources. Endpoints: `GET /api/dashboard`, `GET /api/units/:id`, `POST /api/units/:id/accept`, `POST /api/units/:id/send-back`, `POST /api/units/:id/patch`, `GET /api/graph`. Uses `DashboardBuilder` for dashboard/graph data, `GitManager` for accept/reject operations. | ✅ Complete |
| 5.2 | Implement review queue backend | API reads from git branches and `re/` directory artifacts, constructs `UnitOfWork` instances, sorts by dependency order. | ✅ Complete |
| 5.3 | Add WebSocket for live progress | Stream translation progress events during `translate` runs. | ✅ Complete |
| 5.4 | Implement HTML/JS/CSS frontend | Build actual UI components: `DashboardView`, `DependencyGraphView`, `UnitOfWorkCard`, `ReviewQueue`, `RecentActivity`. Served statically by the axum server. | ✅ Complete |
| 5.5 | Add diff viewer | Render `git diff` output with line-by-line highlighting, showing Ghidra notes alongside Rust code. | ✅ Complete |
| 5.6 | Add dependency graph visualization | Render the DAG with SVG or Canvas, interactive zoom/pan. | ✅ Complete |
| 5.7 | Human review actions → git operations | Accept/reject/send-back actions call into `calxgloss-git` and `calxgloss-translator`. | ✅ Complete |
| 5.8 | End-to-end test | Spin up the axum server with sample data, verify API responses (health, dashboard, units, queue, graph, diff, ghidra, pipeline, progress, websocket), and headless browser page rendering. | ✅ Complete |

---

## Phase 6 — Shim Layer Generation

> **Goal:** Replace DirectX/GDI/audio DLLs with Rust crate equivalents, with auto-generated shim layers.

| Step | What | Details | Status |
|------|------|---------|--------|
| 6.1 | Define shim layer API contract | Add `ShimLayer` type to `calxgloss-types`: `source_dll`, `target_crate`, `mappings: Vec<ApiMapping>`. | ✅ Complete |
| 6.2 | Implement mapping auto-generation | After DLL classification, the LLM generates a mapping table: original API → crate API with parameter transformations. | ✅ Complete |
| 6.3 | Generate shim source code | From the mapping table, generate a Rust module implementing the original DLL's export surface. | ✅ Complete |
| 6.4 | Generate shim tests | For each mapping, generate a test that verifies the crate API is invoked with correct parameters. | ✅ Complete |
| 6.5 | Verify shim behavior | Run the original binary's test suite through the shim layer. | ✅ Complete |
| 6.6 | Add to classification workflow | After `classify`, automatically suggest shim layers for all `CrateReplacement` DLLs with an estimated mapping complexity score. | ✅ Complete |
| 6.7 | Auto-shim pipeline | Wire 6.2 → 6.3 → 6.4 → 6.5 into an end-to-end pipeline triggered by classification. When classify marks a DLL as `CrateReplacement`, run the full shim generation flow (generate mappings → generate source → generate tests → verify → persist) automatically. Persist results to `re/shims/<dll>/` and commit to git. Exposed as `auto-shim` CLI command. | ✅ Complete |

---

## Phase 7 — Fault Detection & Recovery

> **Goal:** Automatically detect and recover from the failure modes documented in `Calxgloss.md` (context window exceeded, hallucination, infinite loops, wrong behavior).

| Step | What | Details | Status |
|------|------|---------|--------|
| 7.1 | Implement context-window detector | After each LLM call, check response size vs. model's context limit. Auto-split the function and retry with a focused basic block. | ✅ Complete |
| 7.2 | Implement hallucination detector | Cross-reference LLM-generated function calls against Ghidra's actual symbols. Flag non-existent API references with close-match suggestions. Integrated into `TranslationPipeline::send_to_llm()` with progress events. | ✅ Complete |
| 7.3 | Implement infinite-loop detector | Track prompt → output hashes. If same bad output repeats 3+ times, escalate to manual intervention. | ✅ Complete |
| 7.4 | Implement behavior-divergence detector | If tests pass but output differs on unseen inputs, flag as "insufficient test coverage" and expand test suite. `BehaviorDivergenceDetector` generates edge-case tests from disassembly hints, compares baseline vs. edge-case results, emits `BehaviorDivergenceDetected` progress events, and logs `FaultEvent::behavior_divergence()` with confidence scoring and actionable recommendations. Integrated into `retry_loop.rs` with `FunctionInfo.disassembly_hints` propagated through the pipeline. | ✅ Complete |
| 7.5 | Resource exhaustion monitoring | Monitor LLM client for OOM / timeout. Queue work when the local model is overloaded. `ResourceExhaustionDetector` with sliding window failure tracking, streak detection, configurable thresholds, and `should_queue_work()` / `should_switch_model()` helpers. Integrated into `LlmClient::complete()` (HTTP 429/503/507 → `LlmError::ResourceExhausted`). Retry loop records failures, emits `ResourceExhaustionDetected` progress events, logs faults, and tracks `RetryLoopCtx.resource_detector` + `RetryLoopCtx.fault_logger`. | ✅ Complete |
| 7.6 | Fault event log | All detected faults logged to `re/analysis/fault_log.json` with detection method, severity, and recovery action. `FaultLogger.record_resource_exhaustion()` convenience method. `FaultEvent::resource_exhaustion()` constructor. `ResourceExhaustionFault` metadata (reason, elapsed time, transient flag). | ✅ Complete |

---

## Phase 8 — Context Tiers

> **Goal:** Optimize token usage by sending the LLM only the context it needs. `escalate_on_failure` flag exists but tiered context logic is not implemented.

| Step | What | Details | Status |
|------|------|---------|--------|
| 8.1 | Implement tier selection logic | In `calxgloss-types`, added `ContextTier` enum (Stub/Disassembly/WithTests/ModuleContext/FullModule) and `select_context_tier()` function that selects the starting tier from function complexity and API call count. In `calxgloss-translator`, `Translation` struct includes `context_tier: ContextTier` field. `TranslationPipeline::translate()` computes the tier after complexity detection and emits `ContextTierSelected` progress event. Tier escalation on failure will be implemented in step 8.7. | ✅ Complete |
| 8.2 | Implement Tier 0 (function stub) | Only function name, signature, and call graph neighbors. Added `StubPromptData` and `StubTemplate` structs with `build_stub_prompt()` function in `calxgloss-prompts`. Template `stub_translate.j2` renders only the minimal context: function name, DLL, hex address, C signature from decompiler, and call graph neighbor names/signatures. Pipeline wired to use stub prompt when `ContextTier::Stub` is selected. | ✅ Complete |
| 8.3 | Implement Tier 1 (disassembly + decompiler) | Full disassembly + Ghidra pseudo-C + tagged Windows API calls + call graph neighbors. Added `DisassemblyPromptData` and `DisassemblyTemplate` structs with `build_disassembly_prompt()` function in `calxgloss-prompts`. Template `disassembly_translate.j2` renders disassembly, decompiler output, tagged API calls, call graph neighbors, external function handling rules, and translation requirements — without baseline tests. Pipeline wired to use disassembly prompt when `ContextTier::Disassembly` is selected. | ✅ Complete |
| 8.4 | Implement Tier 2 (disassembly + decompiler + tests) | Tier 1 + baseline test results + failing test cases. Added `FormattedTestResult` struct with `from_baseline()`, `from_baseline_with_failure()`, and `from_baseline_passing()` constructors. Added `WithTestsPromptData` with `from_request()` and `from_request_with_results()` constructors. Added `WithTestsTemplate` Askama template backed by `with_tests_translate.j2` which renders a prompt with function metadata, test summary, disassembly, decompiler output, tagged APIs, call graph neighbors, baseline test results with PASSED/FAILED markers and error details, external function handling rules, and translation requirements. Pipeline wired to use with-tests prompt when `ContextTier::WithTests` is selected. | ✅ Complete |
| 8.5 | Implement Tier 3 (module context) | Tier 2 + neighboring functions + shared data structures. Added `ModuleContextPromptData` struct with `from_request()` and `from_request_with_context()` constructors in `calxgloss-prompts/context.rs`. Added `ModuleContextTemplate` Askama template backed by `module_context_translate.j2` which renders a prompt with function metadata, test summary, disassembly, decompiler output, tagged APIs, call graph neighbors, baseline test results, full neighboring function context (disassembly + decompiler output for each neighbor), and shared data structure definitions (fields, types, offsets). Added `build_module_context_prompt()` builder function. Pipeline wired to use module context prompt when `ContextTier::ModuleContext` is selected — fetches neighboring function code and data structures from Ghidra via existing `extract_*` helpers. | ✅ Complete |
| 8.6 | Implement Tier 4 (full module + crate shims) | Tier 3 + shim layer code + PAL trait definitions. Added `ShimCode` and `PalTraitDef`/`PalTraitMethod` helper structs to `calxgloss-prompts/src/templates.rs`. Added `FullModulePromptData` struct with `from_request()` and `from_request_with_full_context()` constructors in `calxgloss-prompts/context.rs`. Added `FullModuleTemplate` Askama template backed by `full_module_translate.j2` which renders a prompt with function metadata, test summary, disassembly, decompiler output, tagged APIs, call graph neighbors, baseline test results, full neighboring function context, shared data structures, shim layer source code blocks (one per crate-replacement DLL), PAL trait definitions with method signatures for each API category the function touches, external function handling rules, and translation requirements that reference shim and PAL context. Added `build_full_module_prompt()` builder function in `calxgloss-prompts/src/build.rs`. Added `extract_shim_layers()` helper that reads shim source from `re/shims/<dll>/shim.rs` in the workspace. Added `extract_pal_traits()` helper that returns predefined PAL trait definitions (GraphicsDevice, Graphics2D, AudioDevice, WindowManager, PlatformCore, ComObject) keyed by the function's API categories. Pipeline wired to use full-module prompt when `ContextTier::FullModule` is selected — fetches all Tier 3 context from Ghidra, shim layers from workspace, and PAL traits from function's API categories. Removed the now-unreachable `_` catch-all arm in the tier match. | ✅ Complete |
| 8.7 | Implement tier escalation | Start at minimum tier. On failure, escalate automatically. | ⬜ Not started |
| 8.8 | Track token usage | Log context size per function in `workspace_config.json` and `re/analysis/token_usage.json`. | ⬜ Not started |

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

| Phase | Description | Effort | Depends On | Status |
|-------|-------------|--------|------------|--------|
| 0 | Stabilize base (fix failing tests) | 1–2d | None | ✅ Complete |
| 1 | Complete retry strategy (Escalate, EdgeCaseFix, strategy flag, token logging) | 2–3d | 0 | ✅ Complete |
| 2 | Prompt refinement (failure-informed, experiment log) | 2–3d | 1 | ✅ Complete |
| 3 | Terminal review dashboard | 3–5d | 1 | ✅ Complete |
| 4 | Dependency-aware work queue | 4–6d | 0, 3 | ✅ Complete |
| 5 | Web review UI | 8–12d | 3, 4 | ✅ Complete |
| 6 | Shim layer generation (types, generation, verification, suggestions, auto-pipeline) | 5–8d | 1 | ✅ Complete |
| 7 | Fault detection & recovery | 4–6d | 1, 2 | ✅ Complete |
| 8 | Context tiers | 3–5d | 1, 2 | 🟡 8.1–8.6 Complete (tier selection logic, ContextTier enum, progress event, Translation.context_tier field, Tier 0 stub prompt template and pipeline wiring, Tier 1 disassembly template and pipeline wiring, Tier 2 with-tests template, data structures, and pipeline wiring, Tier 3 module context template with neighboring functions + data structures and pipeline wiring, Tier 4 full-module template with shim layer code + PAL trait definitions, extract_shim_layers() and extract_pal_traits() helpers, pipeline wiring for FullModule tier) |
| 9 | CI / cross-platform verification | 3–5d | 0 | ⬜ Not started |
| 10 | Branch cleanup & archive | 2–3d | 4, 5 | ⬜ Not started |

**Remaining effort: 17–30 working days** (fault detection + context tiers + CI + cleanup).

---

## Recommended Execution Order

For maximum value delivery, execute phases in this sequence:

1. **Phase 7** (fault detection) — improves reliability of translation pipeline
2. **Phase 2.3** (failure-informed prompts) — already done, refine based on Phase 7 signals
3. **Phase 8** (context tiers) — optimizes cost after scale grows
4. **Phase 1.4** (token usage file logging) — observability for 7 + 8
5. **Phase 9** (CI) — parallel after Phase 0 (already done)
6. **Phase 5.8** (e2e web UI test) — validates the web review UI
7. **Phase 10** (cleanup) — last, when branch count justifies it
