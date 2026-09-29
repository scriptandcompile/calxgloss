# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


## [Unreleased]

### Phase 5, Step 5.7 — CLI: `init` Command and Smart `auto` Workflow

#### `calxgloss-cli`
- **`init` subcommand** — creates a `calxgloss.toml` in the current directory
  with a fully commented-out template listing every `[ghidra]` and `[llm]` key
  with sensible defaults.
- **`auto` subcommand** — detects project state and runs the next step
  automatically. Scans the target directory for `.dll` files, checks whether
  classification records exist in `re/classify/`, and either runs classification
  first (if any DLLs are unclassified) or prompts the user to select a DLL for
  batch translation.
- **No-subcommand defaults to `auto`** — calling `calxgloss-cli` with no
  subcommand is equivalent to `calxloss-cli auto`.
- **Auto flags**: `--target` (directory), `--dlls` (explicit comma-separated
  list), `--all-functions`, `--classify-only`, `--skip-git`.
- **`target_dir` in config** — `calxgloss.toml` can now set `target_dir = "..."`
  at the top level. Auto mode resolves: CLI flag > config file > CWD.
  `CALXGLOSS_TARGET_DIR` environment variable also supported.
- **`--target-dir` global CLI flag** — overrides config `target_dir`.
- **`scan_dlls()` helper** — looks for `.dll` files in the target directory.
- **`classification_record_exists()` helper** — checks whether a `re/classify/
  <dll>.json` file already exists.
- **Config render** — `calxgloss config` now shows `target_dir` path and source.

### Phase 5, Step 5.6 — Web Review UI: Dependency Graph Visualization

#### `calxgloss-web` (static frontend)
- **Enhanced `GraphRenderer`** — replaced basic BFS layout with a Sugiyama-style layered layout: longest-path layer assignment, 3-pass barycenter crossing reduction, centered node placement within each layer.
- **Bezier curve edges** — edges now use cubic Bézier curves routed from the source node's right edge to the target node's left edge, with adaptive control points. Replaces straight-line edges for clearer readability on complex graphs.
- **Hover tooltip** — a styled tooltip follows the cursor showing the node name, status (with colored dot), and kind label when hovering over a graph node.
- **Node selection & highlighting** — clicking a node selects it and highlights only directly connected nodes (dependencies + dependents), dimming all others. Clicking the same node deselects; clicking empty space clears selection.
- **Click-to-detail integration** — clicking any graph node opens the unit detail panel (same as clicking queue items), showing overview, test results, diff, Ghidra context, and review actions.
- **Status indicator dots** — each node has a small colored dot (top-right corner) showing the unit's status (green=accepted, yellow=pending, red=sendback, orange=blocked, blue=queued, purple=merged).
- **Proper fit-to-view** — `_fitView()` computes the bounding box with padding, clamps scale to 30%-150%, and centers the graph. Double-click canvas to fit.
- **Keyboard shortcuts** (graph view): `+`/`-` zoom in/out, arrow keys pan, `0` reset fit-to-view, `Escape` deselect.
- **Wheel zoom toward cursor** — zooms centered on the mouse pointer position instead of the canvas center.
- **Overlay graph controls** — "Fit" and "Reset" buttons in the graph view container, plus a zoom percentage indicator (bottom-right).
- **`escapeHtml()` utility** — moved to top level (was duplicated) to prevent XSS in diff and Ghidra viewers.
- **API graph node mapping** — `_mapGraphNode()` now handles both old API format (with `level` field) and new format (with `kind` field).
- **CSS additions** — `.graph-tooltip`, `.graph-controls`, `.graph-zoom-indicator`, `.graph-tooltip-dot` styles for tooltip, overlay controls, and status dots.

#### `calxgloss-web` (HTML)
- Graph view now wraps header buttons in a `.view-controls` div.
- Adds overlay `.graph-controls` div with "Fit" / "Reset" buttons.
- Adds `#zoom-indicator` element for current zoom percentage display.

### Web Review UI: Diff Viewer + Ghidra Context

#### `calxgloss-web`
- **Line-by-line diff API** — `GET /api/units/:id/diff` returns structured
  `DiffFile`/`DiffHunk`/`DiffLine` entries with line-by-line highlighting
  (addition, deletion, context) between a unit's branch and `main`. Parses
  raw unified diff output into a JSON representation suitable for
  client-side rendering.
- **Ghidra context API** — `GET /api/units/:id/ghidra` returns Ghidra
  analysis data (decompiler pseudo-C, disassembly listing, identified
  Windows API calls with PAL mappings) loaded from on-disk analysis
  artifacts. Returns graceful "not found" when no analysis is available.
- **Diff viewer component** — tabbed detail-panel view with "Diff" and
  "Ghidra Context" tabs. Renders line-by-line diffs with green-highlighted
  additions, red-highlighted deletions, dual line-number gutter, and
  hunk-header markers. Shows file rename annotations.
- **Ghidra context viewer** — displays decompiler output in a scrollable
  code block, disassembly listing with address/instruction columns, and
  tagged Windows API calls with PAL mappings. Loads metadata (DLL,
  function name, address) from analysis artifacts.
- **New API response types** — `DiffLineType`, `DiffLine`, `DiffHunk`,
  `DiffFile`, `DiffResponse`, `GhidraDisasmLine`, `GhidraContext`,
  `GhidraApiCall`, `GhidraContextResponse`.
- **`calxgloss-ghidra` optional dependency** — added to `server` feature
  for future GhidraMCP integration.

### Added

#### `calxgloss-config`
- `LlmSection.strategy` — retry strategy configuration (compile_fix, test_fix,
  escalate, edge_case_fix, auto) via CLI flag, environment variable
  (`CALXGLOSS_LLM_STRATEGY`), or config file

#### `calxgloss-translator`
- **Failure-informed retry prompts** — all retry
  strategies (`CompileFix`, `TestFix`, `Escalate`, `EdgeCaseFix`) now
  inject a "PREVIOUS ATTEMPT HISTORY" section into LLM prompts when
  prior attempts have failed. Includes
  `build_failure_informed_compile_fix_prompt()`,
  `build_failure_informed_test_fix_prompt()`,
  `build_failure_informed_escalate_prompt()`, and
  `build_failure_informed_edge_case_fix_prompt()`.

#### `calxgloss-cli`
- `--strategy` flag — select the initial retry strategy or `auto` for
  automatic cycling through all strategies
- `retry_strategy` displayed in `config` command output

### Added

#### `calxgloss-types`
- **Complexity-based prompt selection** (`calxgloss-types::complexity`) —
  `FunctionComplexity` enum (Minimal / Standard / Rich / Detailed) and
  `detect_complexity()` function that classifies functions by instruction
  count, branch density, call depth, and API-category diversity.
  `PromptVariant` struct for strategy selection and `FailureHint` for
  recording previous attempt failures.
- `ApiCategoryMapping` and `ApiMappingItem` — types for grouping Windows
  API mappings by category in rich and detailed translation prompts.

#### `calxgloss-prompts`
- **Complexity-aware prompt builder** (`build_complexity_prompt`) — selects
  the appropriate template based on function complexity: `MinimalTemplate`
  (≤30 instructions, disassembly + decompiler only), `TranslateTemplate` /
  `Standard` (31–100, adds API mappings + tests), `RichTemplate` (101–300,
  adds API category context + advanced guidelines), `DetailedTemplate`
  (>300, adds call graph + neighbors + data structures + type info).
- **New template files** — `minimal_translate.j2`, `rich_translate.j2`,
  `detailed_translate.j2` with complexity-appropriate context and guidance.
- `ComplexityPromptData` — aggregates all analysis data for use with the
  complexity-based prompt builder.

#### `calxgloss-analysis`
- `Analyzer::detect_complexity()` — detects function complexity from
  disassembly and tagged API calls.
- `Analyzer::build_prompt_variant()` — builds a `PromptVariant` with
  complexity classification and API awareness.

#### `calxgloss-translator`
- `TranslationPipeline::translate()` now uses complexity-based prompt
  selection, routing simple functions to minimal prompts and complex
  functions to rich or detailed prompts with extra Ghidra context.

#### `calxgloss-prompts`
- **Failure-informed retry prompts**  — `FixTemplate`,
  `EscalateTemplate`, and `EdgeCaseTemplate` all now accept a
  `failure_history: Vec<FailureHint>` field. When non-empty, each template
  renders a "PREVIOUS ATTEMPT HISTORY" section so the LLM can learn from
  specific past mistakes. Dedicated `with_history()` constructors and
  updated `build_escalate_prompt()` / `build_edge_case_prompt()` helpers.
  Embedded templates (`failure_fix.j2`, `escalate.j2`, `edge_case.j2`)
  updated to render the history section.

### Added

#### `calxgloss-types`
- **Prompt strategy experiment types** (`calxgloss-types::experiment_log`) —
  `PromptStrategyEntry` (single attempt outcome), `PromptStrategyLog`
  (collectible entries), `PromptStrategyStats` with `CategoryStats` and
  `StrategyStats` (aggregate pass/fail rates), and
  `current_timestamp()` helper. Full serde serialization for disk
  persistence.

#### `calxgloss-analysis`
- **Prompt strategy logger** (`PromptStrategyLogger`) — persists experiment
  entries to `<workspace>/re/analysis/prompt_strategy_log.json` with
  `record()`, `load()`, `compute_stats()`, and `log_path()` methods.
  Auto-creates directory structure; handles corrupted-file recovery by
  starting fresh.

#### `calxgloss-translator`
- **Experiment logging integration** — `try_translate_with_retry()` now
  accepts an optional workspace path; `TranslationPipeline` gains
  `with_workspace()` builder method. Every retry attempt is recorded
  (DLL name, auto-classified category, strategy label, success/fail,
  attempt number, timestamp). Skipped silently when no workspace is set.

### Fixed

#### `calxgloss-config`
- `test_a_missing_optional_file_is_not_an_error` and `test_a_found_file_is_reported` — both tests now temporarily neutralize `HOME`, `XDG_CONFIG_HOME`, and `CALXGLOSS_LLM_MODEL` so a user-global config or shell-profile env var cannot be picked up during test execution, breaking `loaded.is_empty()` and config-precedence assertions.


### Added

#### `calxgloss-web`
- **Dependency-sorted review queue endpoints** — `GET /api/queue` returns the full
  review queue sorted by dependency order (topological + level tie-breaking), with
  metadata on total/queued/pending/blocked counts. `GET /api/queue/next` returns the
  single next unit to review in the "review one at a time" workflow. Both endpoints
  exclude accepted and merged units; `Blocked` units are flagged in the response.
- **Queue metadata on dashboard** — `GET /api/dashboard` now includes optional
  `queue_metadata` with total, queued, pending-review, and blocked counts.
- **Queue position on unit detail** — `GET /api/units/:id` now includes
  `queue_position` (zero-based index in the dependency-sorted queue and total queue size)
  for each unit. New response types: `QueueMetadata`, `QueuePosition`, `QueueResponse`,
  `QueueEntry`.

#### `calxgloss-git`
- **Shim-layer dependency enforcement on branch creation** — `create_branch` accepts an
  optional `BranchCreationPolicy` parameter (`Skip`, `Warn`, or `Enforce`). The checker
  resolves the required shim layer branches for `MicrosoftSdk` and `KnownThirdParty` DLLs
  (e.g. `d3d9.dll` → `re/shim/wgpu`) by consulting a hardcoded mapping in
  `ShimDependencyMap`, then queries Git to verify each required branch is an ancestor of
  `main`. Enforce mode blocks creation when unmet; Warn mode logs a warning and proceeds.
- `DependencyCheckResult`, `DependencyChecker`, `ShimDependencyMap`, `BranchCreationPolicy`,
  `DependencyPolicy` — new types in `calxgloss-git` for dependency resolution and policy
  enforcement.
- `ShimDependencyMap` — hardcoded lookup covering 22 DLL → crate mappings across DirectX,
  audio, 2D graphics, UI frameworks, and geometry libraries.

#### `calxgloss-cli`
- `handle_translate` and `handle_batch_translate` now pass
  `BranchCreationPolicy::Warn` to `create_branch`, enabling dependency-aware branch
  creation with warning-level enforcement during translation.

### Terminal Review Dashboard

#### `calxgloss-types`
- **Dashboard data model** (`calxgloss-types::dashboard`) — new module with all
  review dashboard types, replacing the duplicate scaffolding in `calxgloss-web`:
  `WorkUnitKind` (7 unit types), `ReviewStatus` (7 statuses), `UnitOfWork`
  (full metadata struct with timestamps, test counts, confidence, dependencies,
  known gaps), `DependencyNode` / `DependencyEdge` / `DependencyGraph` (DAG with
  `roots()`, `dependents()`, `dependencies()` traversal), `StatusCounts` (aggregated
  counts with `total()`), `ReviewDashboard` (assembles units into a viewable
  dashboard with dependency-sorted queue, recent activity, and status counts), and
  `ReviewAction` / `ReviewActionKind` (human review actions). All types derive
  `serde::Serialize` and `serde::Deserialize`.
- `chrono` dependency — added to `calxgloss-types` for `DateTime<Utc>` fields
  in `UnitOfWork` timestamps.

#### `calxgloss-web`
- **Re-exported from `calxgloss-types`** — the domain data types
  (`UnitOfWork`, `ReviewDashboard`, `DependencyGraph`, `ReviewStatus`, etc.)
  are no longer defined locally; this crate re-exports them from
  `calxgloss-types` so downstream consumers get a single source of truth.
  The axum server scaffold (behind `server` feature) and tests are preserved.

#### `calxgloss-reports`
- **Terminal rendering** (`render_dashboard`) — flat text report with horizontal
  dividers (`═` / `─`), no vertical borders or corners. Color-coded status
  summary, dependency-sorted review queue table, blocked units section, and
  recent activity. Auto-refresh follow mode via `render_dashboard_follow`.

#### `calxgloss-cli`
- **`dashboard` subcommand** — reads all `re/*` git branches, patch records from
  `re/patches/`, and baseline files from `re/baseline/` to build and render a
  structured review dashboard. Supports `--follow` (continuous watch) and
  `--interval <secs>` (refresh cadence, default 2).
- **`dashboard view <target>`** — per-unit quick-view subcommand showing
  justification, diff summary, test results, and attempt history for a
  single translation unit. Target format: `<dll>/<function>` or
  `<dll>/<function>/vN` (e.g., `game_logic/DrawPrimitive/v3`).

#### `calxgloss-reports`
- **`render_unit_view()`** — renders a detailed single-unit view with
  sections: unit info (kind, status, confidence, dependencies), branch
  status (merged/unmerged), DLL classification, diff summary (files
  changed, insertions, deletions), baseline and verification test
  results, and attempt history loaded from patch records.
- `ViewTarget` — parses `dll/function` or `dll/function/vN` target strings
- `UnitViewData` — collects all data for a unit view (unit info, branch
  name, merge status, diff summary, attempt history, baseline tests,
  DLL classification)
- **Dependency diff summary** — computes `git diff` stats between branch
  and main (files changed, insertions, deletions)
- Clippy `filter_next` — replaced `.filter(...).into_iter()...next()`
  with `.find(...)` on branch list iteration
- Clippy `unnecessary_closure` — replaced `.or_else(|| { Some(...) })`
  with `.or(Some(...))` for static default values
- **Table column alignment** — switched from format-width specifiers (which
  counted invisible ANSI escape codes as characters) to hardcoded column
  widths per element, so colored headers no longer shift data columns.
- **Stale-work highlighting** (`Staleness`) — `Fresh` / `Stale` (≥24h,
  yellow highlight) / `Critical` (≥48h, red highlight) enum on
  `UnitOfWork`. Dashboard builder parses the actual commit timestamp from
  patch records to compute elapsed pending time. Queue table rows for
  stale units get a warning/critical prefix symbol and the dashboard
  renders a "Stale work" section listing them with elapsed durations.

#### `calxgloss-git`
- **`is_branch_merged_into_main()`** — checks if a branch is an ancestor
  of `main` via `graph_ahead_behind()`

### Added

#### `calxgloss-git`
- **`accept_branch()`** — merges a branch into `main` and writes an
  acceptance record to `re/accepts/{dll}/{function}/vN.json` for
  dashboard visibility
- **`reject_branch()`** — writes a rejection record to
  `re/rejections/{dll}/{function}/vN.json` with the reviewer's reason,
  enabling send-back history in the dashboard

#### `calxgloss-reports`
- **`branch_matches()`** — public predicate for matching a git branch name
  against a `{dll}/{function}/{attempt}` target, used by the accept/reject
  CLI handlers to resolve a target string to the actual branch

#### `calxgloss-cli`
- **`dashboard accept <target>`** — merges the named unit's branch into
  `main` and reports success, already-merged status, or merge conflicts;
  writes an acceptance record for the dashboard to discover
- **`dashboard reject <target> --reason "..."`** — records a rejection
  with an optional reason; the record is persisted so the dashboard can
  display send-back history

#### `calxgloss-types`
- **`DependencyGraph::topological_order()`** — returns all nodes in
  topological order (dependencies first) using Kahn's algorithm with
  depth tracking. Suitable for ordered batch operations like batch accept.
- **`ReviewDashboard::pending_in_dependency_order()`** — returns only
  `Queued` / `PendingReview` units sorted by dependency depth, ready for
  batch acceptance.

#### `calxgloss-cli`
- **`dashboard accept-all [--all]`** — accepts every pending unit in
  dependency order: topologically sorts the review queue, merges each
  branch into `main` sequentially, writes acceptance records. The `--all`
  flag extends acceptance to every unmerged branch (including blocked
  and send-back units). Reports per-unit status with merge hashes and a
  summary line (accepted / skipped / failed).

### Added

#### `calxgloss-analysis`
- **Dependency tracker** (`DependencyTracker`) — builds a `DependencyGraph`
  from DLL classifications and Ghidra call graph data. Automatically derives
  shim layer declarations from crate-replacement classifications. Produces a
  DAG in dependency order: DLL classifications (roots) → shim layers →
  function translations (depending on shim + call graph neighbors).
  `for_dll()` method for incremental single-DLL builds.
- `ShimLayerDeclaration` — declares a shim layer for a crate-replacement DLL;
  extracted from `DllClassification` via `from_classification()`.

### Changed

#### all crates
- Removed references to implementation phases and steps from
  doc-comments and inline comments. The planning document
  (`step_by_step.md`) remains as the planning reference; source
  comments now describe what the code does, not which phase it came
  from. Affected crates: `calxgloss-analysis`, `calxgloss-pal`,
  `calxgloss-prompts`, `calxgloss-reports`, `calxgloss-translator`,
  `calxgloss-types`.

### Topological Sort with Level-Aware Tie-Breaking

#### `calxgloss-types`
- **`WorkUnitLevel`** enum — defines 7 processing-phase levels for
  dependency-ordered pipeline execution: `DllClassification` →
  `ShimLayer` → `PalTrait` → `TestCaseAddition` →
  `FunctionTranslation` → `IntegrationStep` → `BugFix`. Derives
  `PartialOrd` / `Ord` so lower-level units are always processed before
  higher-level ones. Includes `label()` for human-readable output.
- **`WorkUnitKind::level()`** — maps each unit kind to its corresponding
  `WorkUnitLevel`, enabling automatic level assignment from existing data.
- **`DependencyNode::level`** — new `#[serde(default)]` field with
  constructors `DependencyNode::new()` (default level) and
  `DependencyNode::with_level()`. Backward-compatible: missing `level`
  fields deserialize to `WorkUnitLevel::DllClassification`.
- **`DependencyGraph::topological_order()`** — rewritten to return
  `(Vec<&DependencyNode>, Vec<String>)` (ordered nodes + cycle-involved
  nodes). Uses Kahn's algorithm with a merge-sorted priority queue keyed
  by `(depth, level, node_id)`. Level-aware tie-breaking ensures shim
  layers appear before PAL traits before function translations at the
  same topological depth. Cycle detection is non-fatal: nodes not
  involved in cycles are still correctly ordered.
- **`ReviewDashboard::sorted_queue()`** — canonical ordering for batch
  operations, using the full topological sort with level tie-breaking.
  Returns `Queued` / `PendingReview` units in dependency order, with
  already-accepted units at the end.
- **`ReviewDashboard::next_in_dependency_order()`** — returns the next
  unit to review in proper dependency-then-level order, replacing the
  deprecated `next_to_review()`.
- 8 new tests: `level_respects_pipeline_order`, `full_pipeline_order`,
  `cycle_detection`, `partial_cycle`, `work_unit_level_ordering`,
  `work_unit_kind_to_level`, `dependency_node_constructors`,
  `level_tiebreaks_same_depth`.

#### `calxgloss-analysis`
- **`DependencyTracker::build()` / `for_dll()`** — now assign correct
  `WorkUnitLevel` (`DllClassification`, `ShimLayer`) to nodes they
  create, instead of using default struct field syntax.

#### `calxgloss-web`
- Updated test fixtures to use `DependencyNode::new()` and
  `DependencyNode::with_level()` constructors.


### Persist Dependency Graph

#### `calxgloss-analysis`
- **`DependencyGraphPersistor`** — persists a `DependencyGraph` to
  `<workspace>/re/analysis/dependency_graph.json`. Provides `save()`,
  `load()`, `graph_path()`, and a convenience `build_and_save()` that
  combines `DependencyTracker::build()` with `save()`. Auto-creates the
  `re/analysis/` directory structure. Returns `None` on missing or
  corrupt files rather than erroring.

### Auto-queue Unmet Units

#### `calxgloss-types`
- **`ReviewDashboard::auto_block_units()`** — automatically marks units
  as `Blocked` when their dependencies are in a failing state
  (`SendBack` / `PatchRequested`). Propagates transitively: if A depends
  on B and B fails, A is blocked; if C depends on A and A is blocked, C
  is also blocked. Skips terminal statuses (`Accepted` / `Merged` /
  `Blocked`) and the failing units themselves (they keep their original
  status). Scans both `review_queue` and `recent_activity`. Returns the
  count of units changed to `Blocked`. Idempotent.
- 8 unit tests: basic blocking, no-op with all deps accepted, multiple
  deps (any failed blocks dependent), transitive propagation, terminal
  status respect, `PatchRequested` triggers blocking, empty graph,
  idempotency.

#### `calxgloss-reports`
- `DashboardBuilder::build()` now calls `auto_block_units()` after
  constructing the dashboard from git/file artifacts, ensuring the
  terminal dashboard always shows correct blocked status.

### Added

#### `calxgloss-web`
- **Axum API server** (`server` feature) — full HTTP API for the
  review dashboard: `GET /api/dashboard` (queue, graph, counts),
  `GET /api/units/:id` (unit detail with diff summary, attempt
  history, revision count), `POST /api/units/:id/accept` (merge
  branch to main), `POST /api/units/:id/send-back` (rejection with
  reason), `POST /api/units/:id/patch` (patch request),
  `GET /api/graph` (dependency graph for visualization),
  `GET /health` (health check). Uses `DashboardBuilder` from
  `calxgloss-reports` for data and `GitManager` from `calxgloss-git`
  for branch operations. `ServerState` holds the repo path; each
  request reads live Git data. `serve(state, port)` entry point
  binds to `0.0.0.0:port` for container/remote access.
- **Response types** — `DashboardResponse`, `DependencyGraphResponse`,
  `UnitResponse`/`UnitResponseInner` (enriched unit detail),
  `DiffSummary`, `AttemptRecord`, `ActionResponse`, `ServerError`
  with `IntoResponse` for proper HTTP status codes.
- **Request types** — `SendBackRequest` (reason for send-back),
  `PatchRequest` (issue description).

### Changed

#### all crates
- Rustfmt reformatting across the workspace: import ordering,
  struct field layouts, match arms, function signatures, doc
  comment examples.

### WebSocket Live Progress Streaming

#### `calxgloss-types`
- **`ProgressEvent` enum** — typed events emitted at pipeline milestones:
  `TranslationStarted`, `GhidraFetchComplete`, `ApiTaggingComplete`,
  `TestsGenerated`, `LlmCallStart`, `LlmCallComplete`,
  `TranslationAttemptCompleted`, `TranslationCompleted`, and
  `TranslationFailed`. All variants carry `dll`/`function` identifiers plus
  attempt-specific metadata; fully serializable via `serde` for JSON
  transport over WebSockets.
- **`TranslationEvents`** — broadcast-channel wrapper (`tokio::sync::broadcast`)
  for publishing progress events. `emit()` returns the subscriber count,
  `subscribe()` creates a new receiver. Callers don't need to handle errors —
  lost events when no subscribers are present are silently discarded.

#### `calxgloss-translator`
- **Pipeline event emission** — `TranslationPipeline::with_events()` attaches
  a `TranslationEvents` instance; `emit()` publishes events at every major
  milestone during `translate()` and `try_translate_with_retry()`.
- **`RetryLoopCtx` struct** — bundles verifier, LLM, Ghidra, config, workspace
  path, and event emitter into a single argument for `try_translate_with_retry()`,
  reducing the public function signature from 7 to 2 parameters.
- **`EscalatePromptCtx` struct** — groups context data for the escalation prompt
  builder (function name, DLL, code, failure description, Ghidra client,
  address, call graph, failure history), simplifying the 8-parameter API.
- **Per-attempt progress events** — the retry loop now emits
  `TranslationAttemptCompleted` after every attempt (initial, compile-fix,
  test-fix, escalate, edge-case-fix), so WebSocket clients can display
  real-time per-attempt status (compiled, tests passed, strategy label).

#### `calxgloss-web`
- **WebSocket server** (`server::events` module) — `SessionManager` owns a
  background broadcast loop that fans out `ProgressEvent` instances from an
  `mpsc` channel to all registered WebSocket clients.
- **`EventsBridge`** — connects the pipeline's `TranslationEvents` broadcast
  sender to the `SessionManager`'s `mpsc` channel, bridging the two channel
  types into a single streaming pipeline.
- **`WebSocketHandler`** — accepts an `axum::extract::WebSocket`, splits it
  into read/write halves, and drives concurrent event forwarding and
  keep-alive pings. Auto-cleans up on disconnect.
- **`build_router_with_ws()`** — extension of `build_router()` that mounts the
  `/api/events/upgrade` WebSocket upgrade route. Carries `SessionManager` and
  `EventsBridge` as additional axum state objects.
- **`api_events_upgrade()`** — WebSocket upgrade handler that registers the
  client with the session manager and starts streaming.
- **`[lints.cargo]`** — `unused_dependencies = "allow"` in Cargo.toml to
  suppress manifest-level warnings on `cfg(feature = "server")` gated
  optional dependencies (axum, calxgloss-reports, uuid).
- Removed unused `tokio-tungstenite` dependency; the WebSocket implementation
  uses axum's native `axum[ws]` support instead.

## [0.1.0] — 2025-09-27

### Added

#### `calxgloss-translator`
- **Batch translation** (`batch-translate` CLI subcommand) — translate multiple functions from a single DLL in one invocation; enumerates all exported functions via `--all-functions` or accepts a comma-separated list via `--functions`; per-function pass/fail reporting with a summary showing success/failure counts and pass rate; `--skip-git` for dry-run mode; automatically commits and merges each successful function to a git branch
- `batch_translate()` method on `TranslationPipeline` for batch-iterating the full pipeline + retry loop across many functions; `BatchTranslationResult` and `FunctionResult` types for aggregated and per-function outcomes
- Full translation pipeline: `TranslationPipeline` struct with end-to-end GhidraMCP → analysis → test generation → LLM → Rust code workflow, `Translator` struct for direct translation from pre-collected data, `Translation` result type, `TranslatorError` error type with 6 variants, parameter estimation from decompiler output, and 9 unit tests + 4 doc-tests
- **Retry logic** — `RetryConfig`, `RetryStrategy` (CompileFix / TestFix / Escalate), `TranslationAttempt`, `RetryResult`; `try_translate_with_retry()` with strategy escalation on failure; `FixTemplate` with embedded `fix.j2` for compile-fix and test-fix prompts; 7 unit tests

#### `calxgloss-ghidra`
- GhidraMCP HTTP client with session management, DLL queries (list, info, imports, exports), function queries (disassembly, decompiler, call graph, full analysis), error types, response mapping structs, and `Session` tracking
- Tracing instrumentation and comprehensive test coverage (10 tests)

#### `calxgloss-llm`
- Local LLM client (Ollama/vLLM compatible): `LlmClient` with non-streaming and SSE streaming completions, `LlmConfig` with builder pattern, `LlmMessage` with System/User/Assistant roles, `strip_code_fences()` utility, OpenAI-compatible `chat/completions` API, serde request/response structs, `LlmError` with 6 variants, tracing instrumentation, and 13 tests

#### `calxgloss-prompts`
- Full implementation with askama template engine: `TranslateTemplate` struct for building translation prompts, embedded `templates/translate.j2` covering disassembly, decompiler output, Windows API mappings, and baseline tests; `build_translate_prompt()` convenience function; `FixTemplate` for compile-fix and test-fix prompts; `PromptError` type; `ApiCategory` implements `Display` for template rendering

#### `calxgloss-pal`
- Platform abstraction layer with full Windows API → Rust equivalent mapping table: 100+ mappings across 10 categories (Win32 Core, GDI, DirectX, Win32 GUI, Audio, COM, Win32 Networking, Win32 Registry, VB6 Runtime), `ApiMappings::lookup()` / `for_category()` API, lazy-initialized category index, 19 tests, `iter()` method for full-table iteration

#### `calxgloss-analysis`
- DLL classification, call graph analysis, and Windows API tagging: `Analyzer` struct with `classify_dll()`, `classify_target()`, `analyze_function()`, `tag_windows_apis()`, and `classify_dll_info()` methods; classification heuristics with lookup tables for 70+ Windows OS DLLs, 15 Microsoft SDK DLLs (→ wgpu/tiny-skia/skrifa), and 40 known third-party DLLs (→ fmod-rs/cpal/mlua/pyo3/flate2/vb6runtime etc.); `Strategy` enum (`PalMapping`, `CrateReplacement`, `ReverseEngineer`); `DllClassification` and `FunctionAnalysis` types; `AnalysisError` error type with `Ghidra` variant; disassembly scanning for dynamically-loaded APIs; 30 unit tests covering all classification paths, deduplication, and API tagging

#### `calxgloss-testgen`
- FFI stub generation with comprehensive Windows type parsing (60+ type mappings, calling conventions, pointer handling), `FfiStubBuilder` for manual stub construction, test input generation with signature-based and disassembly-driven edge case detection (`cmp eax, 0`, `test ecx, 256` patterns), `BaselineRunner` for temporary Cargo project compilation and execution, JSON baseline save/load to `re/baseline/{dll}/{function}/baseline.json`, full module-level documentation and 18 unit tests

#### `calxgloss-verify`
- Full `Verifier` implementation: `Verifier::new()` creates sandboxed work directory, `Verifier::compile()` scaffolds temporary Cargo project and runs `cargo check`, `Verifier::verify()` performs full compilation + behavioral verification against baseline tests, `CompileResult` with error/warning capture, test harness generator with input pattern matching for array/number/null/object inputs, JSON baseline save/load, `parse_cargo_output()` and `parse_test_results()` helpers, `Stubs` module with `GraphicsDeviceStub`, `AudioDeviceStub`, `FileSystemStub`, `WindowManagerStub`, `ThreadStub` and common types (`Color`, `Font`, `Sample`, `Texture`, `RenderTarget`, etc.), 19 unit tests

#### `calxgloss-git`
- Git automation for translation workflow: `GitManager` with `init_repo`, `open`, `create_branch`, `commit`, `merge_to_main`, `list_branches`, `delete_branch`, `revert_commit`, `current_branch`, `current_commit`, `list_translation_branches`, `working_dir_status`, and `store_failure`; branch naming `re/{dll}/{function}v{N}`; fast-forward and 3-way merge strategies; patch record JSON files for failed translations; 17 unit tests

#### `calxgloss-reports`
- Terminal report formatting: colored ANSI output with `print_translation_summary`, `print_verification_results`, `print_git_status`, `print_success`, `print_failure`, `prompt_acceptance`, and `print_classification_report` functions; box-drawing characters for success/failure headers; pass rate color-coding (green/yellow/red); DLL classification report with strategy color-coding and summary counts
- `print_batch_summary()` for colored terminal output of batch translation results with per-function checkmarks/crosses and an overall pass-rate summary

#### `calxgloss-web`
- Web UI data models: `UnitOfWork`, `WorkUnitKind`, `ReviewStatus`, `DependencyGraph`, `ReviewDashboard`, `ReviewAction`; axum API router scaffold behind `server` feature flag; dependency-sorted review queue with status counts; 7 unit tests

#### `calxgloss` (meta-lib)
- Meta-lib re-exporting all workspace crates: `calxgloss-types`, `calxgloss-ghidra`, `calxgloss-llm`, `calxgloss-prompts`, `calxgloss-pal`, `calxgloss-analysis`, `calxgloss-testgen`, `calxgloss-translator`, `calxgloss-verify`, `calxgloss-git`, and `calxgloss-reports`

#### `calxgloss-config`
- Configuration crate with multi-source config loading (file, env, flag precedence), section validation, typed settings, and searched-path diagnostics

#### `calxgloss-types`
- Shared data structures with module organization: DLL analysis, function metadata, test cases, translation, verification, and Git automation (with `serde`/`thiserror` derive and doc comments)
- `ApiCategory` derives `Hash` for use as `IndexMap` key

#### `calxgloss-cli`
- Full CLI binary implementation: `clap`-based argument parsing with `classify`, `translate`, and `verify` subcommands; `handle_classify` wires GhidraMCP + `Analyzer` → classification report; `handle_translate` implements the full translation pipeline (Ghidra → analysis → test generation → LLM prompt → code → write → verify → git branch/commit/merge → report) with configurable retries, LLM config (URL/model/key/temperature/max-tokens), output directory, and skip-git flag; `handle_verify` loads existing Rust source + baseline JSON → runs `Verifier` → colored pass/fail output; `tracing-subscriber` logging with `RUST_LOG` support and text/json/pretty format options; ANSI-colored terminal formatting with box-drawing headers and pass-rate color-coding

#### Infrastructure
- Project scaffolding with 14 workspace crates
- Workspace root `Cargo.toml` with shared dependencies
