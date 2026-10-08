# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Pipeline phase progress bar** — the dashboard now shows where the whole effort stands against the master plan: a horizontal bar across all 7 pipeline phases plus Phase 2.5 (PAL Design), derived from live progress data, each segment honestly marked not started / in progress / complete — or, for Restitching and Documentation which have no backing data source yet, "no data source" rather than fabricated progress. `GET /api/pipeline` reports these phase states and per-binary function counts, and plain `calxgloss serve` now answers it with an honest empty payload instead of 404, so the bar renders in every mode.
- **Server lifecycle control** — the operator can stop and retune the running server without killing work, in both `serve` and `live`: `POST /api/server/shutdown` stops the server gracefully and pauses a live pipeline at the current unit boundary (the unit in flight finishes and is saved first); `POST /api/server/restart` saves state the same way, stops the process, and returns a manual-restart signal — the server never forks a replacement process; `PATCH /api/server/log-level` changes the running process's log verbosity (`off`/`error`/`warn`/`info`/`debug`/`trace`, invalid names rejected, nothing persists across restarts). The dashboard gained a server control panel with shutdown/restart buttons and a log-level selector.
- **Server status & enhanced health probe** — `GET /api/server/status` reports how the server itself is doing: pipeline state (no pipeline / idle / running), uptime, version, host, log level, memory and CPU usage, live WebSocket connection count, and open file handles — gathered cross-platform on Windows/macOS/Linux, and available in both `serve` and `live`. The `/health` probe now also reports workspace accessibility, uptime, and version, and the dashboard gained a server status card rendering these values.
- **In-flight translation phases** — during a live run every translating unit reports the pipeline step it is in (Ghidra fetch, API tagging, baseline-test generation, context-tier selection, LLM call, compiling, testing, review). `/api/progress` now carries the current phase, the phase history in event order (context-tier escalations stay visible), and elapsed time per unit.

### Refactored

- **Web router table consolidation** — the review UI's plain-`serve` and live (`calxgloss live`) surfaces are now assembled from one shared route table plus a live-only table, so the two can't drift apart and live pipeline endpoints answer only in live mode.
- **Frontend split into ES modules** — the review UI's monolithic ~2,250-line `app.js` is now one module per view plus shared fetch/format helpers, loaded natively by the browser with no build step.

## [0.2.0] — 2026-10-06

### Added

#### Output & pipeline

- **Crate-based output layout** — `translate` and `batch-translate` now produce `crates/<dll_stripped>/Cargo.toml` and one `src/<function>.rs` per function (DLL/EXE extension stripped, e.g. `EqGame.exe` → crate `EqGame`), with an auto-generated `mod.rs` registering every translated function.
- **Complexity-based prompt selection** — functions are classified by instruction count, branch density, call depth, and API-category diversity, and routed to a Minimal, Standard, Rich, or Detailed prompt with matching Ghidra context.
- **Failure-informed retry prompts** — every retry strategy injects a "PREVIOUS ATTEMPT HISTORY" section into the prompt when prior attempts failed, so the LLM can learn from specific past mistakes.
- **Per-attempt token usage logging** — every LLM call (initial, retry, and tier-escalated attempts) records token counts with DLL, function, attempt, strategy, context tier, and outcome to `re/analysis/token_usage.json`; the batch summary prints a total-tokens line.
- **Experiment logging** — each retry attempt is recorded to `re/analysis/prompt_strategy_log.json` with category, strategy, and outcome, and aggregate pass/fail stats can be computed from it.

#### Context tiers

- **Context tier selection** — five context tiers (`Signature`, `Disassembly`, `WithTests`, `ModuleContext`, `FullModule`) define how much context is sent to the LLM per function; the starting tier is chosen automatically from function complexity and API call count. Each tier has its own prompt, from a minimal signature-only prompt up to full-module context with neighboring functions, shared data structures, shim layer source, and PAL trait definitions.
- **Automatic context tier escalation** — a failed retry can bump the context tier to the next level and rebuild the prompt with escalated context, independently of strategy escalation.

#### Fault detection & analysis logging

- **Fault logging** — detected faults are persisted to `re/analysis/fault_log.json` with aggregate statistics.
- **Context-window detection** — LLM responses are checked against the model limit for truncation markers and oversized prompts are pre-checked; disassembly can be split into chunks for the LLM.
- **Hallucination detection** — generated code is cross-referenced against Ghidra symbols and the PAL catalogue; non-existent API references are logged and emitted as progress events.
- **Infinite-loop detection** — repeated identical (prompt, output) pairs across retries are detected before more tokens are wasted on a dead-end path.
- **Behavior-divergence detection** — code that passes baseline tests but fails generated edge-case inputs is flagged in the retry loop with confidence scoring and recovery advice.
- **Resource-exhaustion monitoring** — repeated failures and timeouts (OOM, swap thrash, HTTP 429/503/507) are tracked; the retry loop backs off, logs faults, and can suggest queueing work or switching models.

#### New analysis crates

All evidence results are saved as per-binary JSON documents under `re/analysis/<name>/<dll>.json`, carry shared scan provenance (binary name, finish timestamp, duration), and score findings with a shared 0–100 `Confidence` type.

- **`calxgloss-typesdb` — data structure recovery**: recovers named types from the Ghidra Type Manager, detects vtables (resolving method pointers and the MSVC RTTI chain to class and base-class names, flagging COM interfaces), and infers struct candidates from string literals.
- **`calxgloss-typeinfer` — type inference**: detects C++ `this` pointers from vtable dispatch, narrows parameter types from string-function usage and integer bit patterns, and propagates types from known signatures (`malloc`, `strlen`, `CreateFileW`, …); competing readings are resolved by confidence.
- **`calxgloss-algorithm` — algorithm recognition**: recognizes algorithm families (sorting, hashing, checksums, compression, …) from control-flow signatures, string markers, and callback contracts (e.g. a `qsort` compare function).
- **`calxgloss-memory` — memory lifecycle / RAII detection**: pairs allocations with releases (suggesting `Box<T>`/`Vec<T>`, or stack allocation for short-lived blocks), handle opens with closes (RAII guard suggestions), and reference-count bumps with drops (`Rc<T>`, narrowed to `Arc<T>` when shared across threads).
- **`calxgloss-sync` — concurrency detection**: pairs lock acquires with releases (`Mutex`/`RwLock`), detects interlocked/atomic calls (`AtomicU32`/`AtomicU64`), and thread spawns with or without joins (`std::thread::spawn` vs `tokio::spawn`).
- **`calxgloss-callback` — callback & function-pointer detection**: finds calls through function-pointer arrays, registration→callback pairs, and jump-table dispatches, suggesting `Vec<Box<dyn Fn(...)>>`, `Box<dyn Fn(...)>`, or `match`/dispatch tables.
- **`calxgloss-controlflow` — control-flow pattern recognition**: detects switch-shaped if-else chains, self-recursion (with tail-call detection), and state-machine patterns, suggesting `match`, loops, or `enum State`.
- **`calxgloss-stringctx` — string & configuration context**: classifies strings into nine categories (format strings, paths, error messages, …), maps strings to functions through body parsing and xrefs, and infers argument types from format specifiers.
- **`calxgloss-apidetect` — library & API identification**: identifies linked libraries from the import table and maps them to Rust crates (DirectX 9, SDL2, zlib, PNG, the C runtime, …), and summarizes which APIs each function reaches directly or through its callees.
- **`calxgloss-consts` — constant & enum recovery**: recovers bitflag groups from bitwise operations, enum candidates from contiguous switch cases, and repeated literals as named constants.
- **`calxgloss-serialize` — endianness & serialization detection**: detects byte-swap calls, bit-packing shift/mask chains, and magic-byte comparisons (PNG, gzip, ZIP), suggesting `byteorder` readers, field masking, or format decoders.

#### `calxgloss-ghidra`

- **New bridge capabilities** — auto-paged string, data-type, and data-item listings, struct layout and enum value lookups, raw memory reads, function tagging, and multi-program support (list open programs and switch which one queries run against).

#### `calxgloss-cli`

- **On-demand analysis commands** — `typesdb`, `typeinfer`, `algorithm`, `memory`, `sync`, `controlflow`, `callback`, `stringctx`, `apidetect`, `consts`, and `serialize` each run their scan against the program open in Ghidra and save the result to the matching `re/analysis/<name>/<dll>.json` cache the batch pipeline consumes. `--show` prints a cached result (counts, confidence, findings) without connecting to Ghidra; `--no-tag` keeps the vtable scan read-only.
- **`auto` subcommand** — detects project state and continues the workflow automatically: scans the target directory for DLLs, runs classification when records are missing, then batch-translates. Running with no subcommand is equivalent to `auto`. Supports `--target`, `--dlls`, `--all-functions`, `--classify-only`, `--skip-git`.
- **`init` subcommand** — creates a `calxgloss.toml` with a fully commented template of every `[ghidra]` and `[llm]` key.
- **`auto-shim` subcommand** — generates shim layers for all crate-replacement DLLs: API mappings (LLM) → source code → tests → verify → persist to `re/shims/<dll>/`, committed to git.
- **`dashboard` subcommand** — builds and renders a review dashboard from git branches and records, with `view`, `accept`, `reject`, and `accept-all` (dependency-ordered batch acceptance) and a `--follow` watch mode.
- **`serve` subcommand** — starts the web review UI HTTP server (port 3000 by default).
- **`live` subcommand** — runs batch translation and the web UI concurrently in one process, streaming progress over WebSocket.
- **`gc` subcommand** — archives stale unmerged translation branches to `refs/archive/…` instead of deleting them, with `--days` and `--dry-run`.
- **Config-driven directories** — `target_dir` and `workspace` can be set in `calxgloss.toml` or overridden by the global `--target-dir` / `--workspace` flags; `live` and `serve` use CWD unless explicitly overridden.
- **Incremental git commits during batch translation** — each function is committed and merged as soon as it succeeds, rather than deferring all git work to the end of the batch.
- **`classify` generates shim layer suggestions** — complexity estimates for crate-replacement DLLs are persisted to `re/shims/suggestions.json`.

#### Git & review workflow

- **Review records** — accepting a branch writes an acceptance record to `re/accepts/`, sending it back writes a rejection record to `re/rejections/`, and archiving renames a stale branch to `refs/archive/…` so it stays reachable.
- **Shim-layer dependency enforcement on branch creation** — branch creation can check that required shim layers (e.g. `d3d9.dll` → `re/shim/wgpu`) are already merged, in `Skip`/`Warn`/`Enforce` modes.
- **Dependency graph** — a DAG of DLL classifications → shim layers → function translations is built from classifications and call graph data, persisted to `re/analysis/dependency_graph.json`, and topologically ordered (level-aware) for batch operations.
- **Shim layer generation** — API mappings are generated by the LLM, shim source code (complete or skeletal) and per-mapping tests with mock call recorders are generated from the mapping table, and shim layers are verified in a sandboxed Cargo project.

#### Web review UI

- **Axum API server** (`server` feature) — dashboard, unit detail, dependency graph, dependency-sorted queue, line-by-line diff, Ghidra context, and health endpoints, plus accept / send-back / patch review actions wired into git and the translation pipeline (a patch request spawns a retry translation).
- **WebSocket progress streaming** — pipeline milestones, per-attempt status, and full LLM request/response events stream to the UI; a live "LLM I/O" tab shows the log.
- **Dependency-sorted review queue** — queue endpoints and the dashboard report dependency-ordered units with queue metadata and position; `Blocked` units are flagged.
- **Diff & Ghidra context viewers** — tabbed detail panel with line-by-line highlighted diffs against `main` and decompiler/disassembly context from on-disk analysis artifacts.
- **Interactive dependency graph** — layered layout with Bézier edges, hover tooltips, click-to-select with neighbor highlighting, click-to-detail, status dots, fit-to-view, wheel zoom toward cursor, and keyboard shortcuts.
- **Live progress panel** — per-DLL classification/strategy, in-progress translation with progress bar, and batch completion counts; completed functions mark their unit `Complete` in real time.
- **Stale branch cleanup** — a "Stale Branches" dashboard card and a "Branch Cleanup" view list unmerged branches past a staleness threshold and archive them from the UI.

#### `calxgloss-types`

- **Review dashboard data model** — work units, review statuses, dependency graph, status counts, and review actions shared across reports, web, and CLI, replacing the duplicate scaffolding in `calxgloss-web`.
- **Dependency-ordered queueing** — units carry processing levels (classification → shim → PAL → test → function → integration → fix), the dependency graph topologically sorts with level tie-breaking, and the dashboard auto-blocks units whose dependencies are in a failing state.
- **Typed progress events** — a serializable `ProgressEvent` enum (translation milestones, per-attempt completion, context tier selection, fault detections, LLM request/response) published over a broadcast channel for WebSocket transport.
- **Shim layer types** — API mappings, layers, complexity scores, and per-DLL shim suggestions with estimated complexity and confidence, produced from classification data without an LLM call.

### Changed

#### Vocabulary

- **Unified on *workspace*** — one directory, one name: `--repo-dir` is now `--workspace`, the config key `repo_dir` is now `workspace`, and `CALXGLOSS_REPO_DIR` is now `CALXGLOSS_WORKSPACE`. `translate`/`batch-translate` lost `--output-dir` (output always lands in the resolved workspace), and dead per-command `--repo` flags are gone.
- **Terminology corrections** — `ContextTier::Stub` → `Signature` ("stub" is reserved for mocks); FFI *stub* → FFI *binding* (the generated block calls the real DLL); `WorkUnitKind`/`WorkUnitLevel` → `WorkKind`/`WorkLevel`; `ReviewStatus::Merged` dropped (merging is the git effect of Accept, not a second verdict); the scratch PAL package renamed `calxgloss-pal` → `calxgloss-verify-pal`.
- **Confidence scales disambiguated** — evidence confidence (0–100, shared `Confidence` type), unit confidence (`unit_confidence`, 0.0–1.0), and fault-diagnosis confidence (`fault_confidence`, 0–10) now have distinct names.

#### Workspace layout

- **Reorganized `crates/` into the 5-context layout from `GLOSSARY-MAP.md`** — `crates/pipeline/`, `crates/evidence/`, `crates/integrations/`, `crates/interface/`, and `crates/shared/`, with the meta-crate re-exporting every library crate except `calxgloss-web`.

#### GhidraMCP 6.x migration

- **Migrated `calxgloss-ghidra` to the bethington GhidraMCP bridge** (v6.0.0, replacing the deprecated LaurieWired extension): snake_case endpoint surface, JSON response and error support, and name-based decompilation resolved through `search_functions`.

#### Pipeline & prompts

- **Evidence pre-analysis in batch translation** — `batch_translate` and `batch_translate_from_callgraph` run each evidence scan (type database, type inference, algorithm, memory, sync, callback, control flow, string context, API, constants, serialization) at the start of a batch when its cache file is missing; a missing workspace, unreachable Ghidra server, or failed save only logs a warning and the batch proceeds.
- **Analysis context in prompts** — the escalate prompt (and, for control flow, the ModuleContext and FullModule translation tiers) reads the persisted evidence caches and renders sections for recognized algorithms, memory lifecycle, concurrency, callbacks, control flow, strings, APIs, and constants; a missing or corrupt cache degrades to no context rather than failing the prompt.
- **Type and data-structure context from persisted caches** — the previously stubbed prompt context extractors now load the type inference and type database caches and keep the records tied to the target function.
- **Translation attempts record their context tier**, enabling post-hoc analysis of which context scope yields the best pass rates.
- **Boxed pipeline futures** — the retry loop's futures are boxed so downstream `Send` checks stop at the boundary instead of overflowing the compiler's trait-evaluation recursion limit.
- **`classify_dlls` reads PE headers** for accurate per-DLL export/import counts instead of the stale counts from whichever program happens to be open in Ghidra.
- **Classification records persisted to disk** — `classify` writes `re/classify/{dll}.json` and commits to `main`; later `auto` runs skip re-classification.

### Fixed

- **Wrapped decompiler signatures parse** — Ghidra's multi-line signature lines failed to parse, so every engine that scans all functions silently skipped those functions (~41 of eqmain.dll's 4,358). Signatures are now joined until the parameter list or body begins. Fixes #54.
- **Dashboard dependency edges (issue #10)** — the builder now wires the shim→function dependency edge the branch-creation policy already checks, so a sent-back shim cascades `Blocked` to everything translating on top of it; the classify edge's DLL matching and shim unit classification were also corrected. The `Blocked` cascade no longer leaves `StatusCounts` stale.
- **Review verdict durability (issue #9)** — the dashboard builder now reads send-back and patch-request records, so `SendBack`/`PatchRequested` survive rebuilds and failing roots can cascade `Blocked`. Patch records written before this change read unchanged.
- **`read_all_patch_records` walked the wrong tree depth** — it never found records at `re/patches/{dll}/{function}/vN.json`, leaving `PendingReview` unreachable in built dashboards.
- **Review actions 500'd on slashed unit ids** — accept/send-back/patch failed at the audit-trail write because nested parent directories under `re/actions/` were not created.
- **Default allocator names missed Ghidra's underscore-form `operator_new`/`operator_delete`** — the live 6.x decompiler writes the underscore form in function bodies, so whole-name matching never fired and allocation findings were missed. The default sets now carry both spellings. Fixes #6.
- **`println_content` blanked lines carrying multi-byte characters** — the report-line padding helper compared byte length against the column width while truncation counted characters, printing some short lines empty. It now counts visible characters.
- **Axum 0.8 route syntax** — routers used the legacy `:id` capture syntax that panicked on startup; all routes now use `{id}`.
- **Static file serving** — assets resolved against the process CWD instead of the crate directory, and the fallback extractor was incompatible with `fallback_service`, so JS and CSS returned 404.
- **Live units 404'd in the unit detail endpoint** — the endpoint now consults the live progress state and creates synthetic in-progress units.
- **LLM request/response log rendered HTML-entity-encoded** — content now renders as raw text with minimal escaping, so JSON and code display correctly.
- **`showDetail` body scope** — the error handler could not reference `body`; the declaration moved outside the `try/catch`.
- **`merge_to_main` stale main reference** — a cached ref handle caused merged branch file changes to be lost on hard reset.
- **Empty cross-reference responses** — a 200 with empty body from GhidraMCP (no callers/callees) is now treated as a valid empty result instead of an error.
- **Trims leading/trailing whitespace** from disassembly and decompiler output before sending to the LLM, keeping prompts cleaner and avoiding wasted tokens.

### Removed

- **Left sidebar dependency graph in the web UI** — the collapsible sidebar panel holding a small dependency graph, and its toggle button, are gone; the full graph view covers it.

### Refactored

- **Shared JSON persistence plumbing** (`calxgloss-types::persist`) — `save_json`/`load_json`/`analysis_dir` and a generic `JsonStore<T>` now back every evidence persistor and the analysis log persistors, replacing hand-written I/O in each crate.
- **Module splits across the workspace** — oversized files were split into focused modules: the CLI binary, the Ghidra/LLM/testgen clients, prompt templates/builders, the reports dashboard, the translator pipeline, the verify engine, the git manager, the analyzer, config, the dashboard types, the PAL crate, and the web handlers.
- **Shared CLI output helpers** — crate-setup and function-writing logic extracted into `utils.rs`, eliminating duplication between `translate` and `batch-translate`.
- **Shared types** — the duplicated `WindowsApiCall` collapsed into one type; a `display_serde_label!` macro replaces `Display` boilerplate on snake_case serde enums; Ghidra wire shapes and persisted recovered shapes now convert through `From` impls instead of scattered field-by-field copies.

### Documentation

- **Docs restructure** — `step_by_step.md` split into `docs/roadmap.md`, an archived frozen plan, and `docs/adr/0001-bethington-ghidra-mcp-bridge.md`; the `Documentation/` folder merged into `docs/`.
- **`docs/standards.md`** — documented coding standards (workspace/crate conventions, error handling, persistence, logging, testing, commit/process rules) for the `code-review` skill's Standards axis.
- **Ghidra docs split by lifespan** — the v6.0.0 endpoint mapping and record-format reference moved to `docs/ghidra_endpoint_map.md`; `ghidra_integration.md` stays the lifecycle-integration design doc.
- **Removed internal-roadmap references** from doc-comments and inline comments across the workspace; Rustfmt reformatting pass.

## [0.1.0] — 2025-09-27

### Added

#### `calxgloss-translator`
- **Batch translation** (`batch-translate` CLI subcommand) — translate multiple functions from a single DLL in one invocation; enumerates all exported functions via `--all-functions` or accepts a comma-separated list via `--functions`; per-function pass/fail reporting with a summary showing success/failure counts and pass rate; `--skip-git` for dry-run mode; automatically commits and merges each successful function to a git branch
- Full translation pipeline: end-to-end GhidraMCP → analysis → test generation → LLM → Rust code workflow, direct translation from pre-collected data, and parameter estimation from decompiler output
- **Retry logic** — strategy escalation on failure (CompileFix / TestFix / Escalate) with compile-fix and test-fix prompts

#### `calxgloss-ghidra`
- GhidraMCP HTTP client with session management, DLL queries (list, info, imports, exports), function queries (disassembly, decompiler, call graph, full analysis), and tracing instrumentation

#### `calxgloss-llm`
- Local LLM client (Ollama/vLLM compatible): non-streaming and SSE streaming completions via the OpenAI-compatible `chat/completions` API, builder-pattern config, code-fence stripping, and tracing instrumentation

#### `calxgloss-prompts`
- Prompt templates with the Askama template engine: translation prompts covering disassembly, decompiler output, Windows API mappings, and baseline tests, plus compile-fix and test-fix prompts

#### `calxgloss-pal`
- Platform abstraction layer with full Windows API → Rust equivalent mapping table: 100+ mappings across 10 categories (Win32 Core, GDI, DirectX, Win32 GUI, Audio, COM, Win32 Networking, Win32 Registry, VB6 Runtime)

#### `calxgloss-analysis`
- DLL classification, call graph analysis, and Windows API tagging: classification heuristics with lookup tables for 70+ Windows OS DLLs, 15 Microsoft SDK DLLs (→ wgpu/tiny-skia/skrifa), and 40 known third-party DLLs (→ fmod-rs/cpal/mlua/pyo3/flate2/vb6runtime etc.); `PalMapping` / `CrateReplacement` / `ReverseEngineer` strategies; disassembly scanning for dynamically-loaded APIs

#### `calxgloss-testgen`
- FFI binding generation with comprehensive Windows type parsing (60+ type mappings, calling conventions, pointer handling), test input generation with signature-based and disassembly-driven edge case detection, baseline runner for temporary Cargo project compilation and execution, and JSON baseline save/load to `re/baseline/{dll}/{function}/baseline.json`

#### `calxgloss-verify`
- Sandboxed verification: scaffolds a temporary Cargo project, runs `cargo check`, and verifies behavior against baseline tests; test harness generator and `cargo test` output parsing; PAL stub types for graphics, audio, filesystem, window, and thread abstractions

#### `calxgloss-git`
- Git automation for the translation workflow: branch naming `re/{dll}/{function}v{N}`, fast-forward and 3-way merges, patch record JSON files for failed translations, and branch/commit/merge/revert operations

#### `calxgloss-reports`
- Terminal report formatting: colored ANSI output for translation, verification, and classification reports with pass-rate color-coding, and batch summary output with per-function checkmarks/crosses

#### `calxgloss-web`
- Web UI data models and axum API router scaffold behind the `server` feature flag; dependency-sorted review queue with status counts

#### `calxgloss` (meta-lib)
- Meta-lib re-exporting all workspace crates

#### `calxgloss-config`
- Configuration crate with multi-source config loading (file, env, flag precedence), section validation, typed settings, and searched-path diagnostics

#### `calxgloss-types`
- Shared data structures with module organization: DLL analysis, function metadata, test cases, translation, verification, and Git automation

#### `calxgloss-cli`
- Full CLI binary: `clap`-based `classify`, `translate`, and `verify` subcommands wiring the full pipeline (Ghidra → analysis → test generation → LLM prompt → code → write → verify → git branch/commit/merge → report), with configurable retries, LLM config, and `tracing-subscriber` logging

#### Infrastructure
- Project scaffolding with 14 workspace crates and a workspace root `Cargo.toml` with shared dependencies
