# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


## [Unreleased]

### Added

#### Output directory structure

- **Crate-based output layout** — `translate` and `batch-translate` now produce `crates/<dll_stripped>/Cargo.toml` and `crates/<dll_stripped>/src/<function>.rs` (one file per function) instead of the previous `src/modules/<function>/translated.rs` layout. The DLL/EXE extension is stripped (e.g. `EqGame.exe` → crate `EqGame`). Each crate has a `Cargo.toml` and a `mod.rs` auto-generated in `src/` that registers every translated function as `pub mod <function>;`.

#### Context tier selection

- **`ContextTier` enum** (`calxgloss-types::context_tier`) — five tiers (`Stub`, `Disassembly`, `WithTests`, `ModuleContext`, `FullModule`) defining the context scope sent to the LLM per function. Each tier is a superset of the previous.
- **`select_context_tier()`** — selects the starting tier from function complexity classification and API call count. Historical success rate tracking is reserved for a follow-up.
- **`SuccessRate` struct** — tracks past success/failure counts for tier selection optimization.
- **`ProgressEvent::ContextTierSelected`** — emitted after complexity analysis with the selected tier label, complexity classification, and API call count.
- **`Translation.context_tier`** — new field recording which tier was used for each translation, enabling token usage tracking and future tier optimization.
- **Tier 0 stub prompt** — minimal context prompt that sends only the function name, inferred C signature, and call graph neighbors (no disassembly, no decompiler output). Reduces token usage for trivially simple functions.
  - `StubPromptData` struct with `from_function_info()` constructor
  - `StubTemplate` Askama template struct
  - `build_stub_prompt()` convenience function
  - `extract_signature_from_decompiler()` helper that parses the first non-blank line of Ghidra decompiler output as the C signature
  - Template `stub_translate.j2` renders the minimal prompt format
  - `TranslationPipeline::translate()` routes to stub prompt when `ContextTier::Stub` is selected
- **Tier 1 disassembly prompt** — sends full disassembly, Ghidra pseudo-C decompiler output, tagged Windows API calls, and call graph neighbors (no baseline tests, which are reserved for Tier 2). Reduces token usage over the full complexity prompt while preserving ground truth for accurate translation.
  - `DisassemblyPromptData` struct with `from_function_info()` and `from_request()` constructors
  - `DisassemblyTemplate` Askama template struct
  - `build_disassembly_prompt()` convenience function
  - Template `disassembly_translate.j2` renders disassembly, decompiler output, API mappings, call graph neighbors, external function handling rules, and translation requirements
  - `TranslationPipeline::translate()` routes to disassembly prompt when `ContextTier::Disassembly` is selected
  - Module docs updated to document all tier-specific prompt builders
- **Tier 2 with-tests prompt** — sends full disassembly, Ghidra pseudo-C decompiler output, tagged Windows API calls, call graph neighbors, and baseline test results with pass/fail status and error details. Enables the LLM to match concrete behavioral output on initial translation or fix specific failures on retry.
  - `FormattedTestResult` struct with `from_baseline()`, `from_baseline_with_failure()`, and `from_baseline_passing()` constructors
  - `WithTestsPromptData` struct with `from_request()` and `from_request_with_results()` constructors
  - `WithTestsTemplate` Askama template struct
  - `build_with_tests_prompt()` convenience function
  - Template `with_tests_translate.j2` renders function metadata, test summary, disassembly, decompiler output, tagged APIs, call graph neighbors, baseline test results with PASSED/FAILED markers and error details, external function handling rules, translation requirements, and example output format
  - Template handles empty test results gracefully with fallback text when no tests are available yet
  - `TranslationPipeline::translate()` routes to with-tests prompt when `ContextTier::WithTests` is selected
 - **Tier 3 module context prompt** — sends full disassembly, Ghidra pseudo-C decompiler output, tagged Windows API calls, call graph neighbors, baseline test results with pass/fail status, full neighboring function context (disassembly + pseudo-C for each neighbor), and shared data structure definitions (fields, types, byte offsets). This tier is used for complex functions whose translation requires understanding shared calling conventions, data layouts, or helper patterns from adjacent functions in the same module.
   - `ModuleContextPromptData` struct with `from_request()` and `from_request_with_context()` constructors
   - `ModuleContextTemplate` Askama template struct
   - `build_module_context_prompt()` convenience function
   - Template `module_context_translate.j2` renders function metadata, test summary, disassembly, decompiler output, tagged APIs, call graph neighbors, baseline test results with PASSED/FAILED markers and error details, full neighboring function context (disassembly + pseudo-C for each neighbor), shared data structure definitions (name, size, fields with types and offsets), external function handling rules, and translation requirements
   - Pipeline fetches neighboring function code and data structures from Ghidra via `extract_call_graph_neighbors()`, `extract_neighboring_context()`, and `extract_data_structures()` helpers when `ContextTier::ModuleContext` is selected
 - **Tier 4 full module prompt** — sends everything from Tier 3 plus shim layer source code for crate-replacement DLLs and PAL trait definitions for platform abstraction. This tier is used when translating functions that call through shim layers (e.g., DirectX → wgpu) and need the full translation-layer context including shim source and PAL trait interfaces to map correctly.
    - `FullModulePromptData` struct with `from_request()` and `from_request_with_full_context()` constructors
    - `ShimCode` struct — represents a generated shim layer (source DLL, target crate, mapping count, full Rust source)
    - `PalTraitDef` / `PalTraitMethod` structs — represent PAL trait definitions with method signatures, used to abstract platform-specific APIs
    - `FullModuleTemplate` Askama template struct
    - `build_full_module_prompt()` convenience function
    - Template `full_module_translate.j2` renders function metadata, test summary, disassembly, decompiler output, tagged APIs, call graph neighbors, baseline test results, full neighboring function context, shared data structures, shim layer source code blocks, PAL trait definitions with method signatures, external function handling rules, and translation requirements
    - Pipeline fetches shim layers from `re/shims/<dll>/shim.rs` in the workspace and PAL traits from the function's Windows API categories when `ContextTier::FullModule` is selected
    - Exhaustive match on all `ContextTier` variants (unreachable `_` catch-all removed)
- **Automatic context tier escalation** — when `escalate_on_failure` is enabled and a retry attempt fails, the tier is automatically bumped to the next level and a new prompt is built with escalated context. Escalation happens independently of strategy escalation. `ContextTierSelected` progress events are emitted when the tier changes. A `build_escalated_prompt()` helper reconstructs the appropriate prompt for any tier using the initial translation's data, fetching additional Ghidra/workspace context (neighboring functions, data structures, shim layers, PAL traits) for Tiers 3–4. Tier-escalated attempts are labeled `escalated(<tier_label>)` in progress events and attempt records. Failed tier escalation gracefully falls back to the strategy-based prompt.

#### Fault detection

- **Fault types** (`calxgloss-types::fault`) — `FaultCategory` (7 categories: `ContextWindowExceeded`, `Hallucination`, `InfiniteLoop`, `BehaviorDivergence`, `ResourceExhaustion`, `SlowResponse`, `PromptCorruption`), `FaultSeverity` (Warning/Error/Critical), `ContextWindowFault` (with truncation signal detection and suggested chunk count), `FaultEvent` (with factory constructors for context-window and hallucination faults), `FaultLog`, and `FaultStats` (aggregate statistics with serde serialization). Full test suite with serialization round-trips.
- **Context-window detector** (`calxgloss-llm::context`) — `ContextWindowDetector` checks LLM response size vs. model limit, scans for common truncation markers (Ollama, vLLM, llama.cpp, GPT), and pre-checks prompt size. `FunctionSplitter` divides disassembly into equal-sized chunks with metadata for the LLM. 13 unit tests.
- **Hallucination detector** (`calxgloss-llm::hallucination`) — `HallucinationDetector` cross-references LLM-generated code against Ghidra symbols (functions + imports) and the PAL API catalogue. Extracts function-call patterns from generated Rust, filters Rust keywords and standard-library type constructors as false positives, and reports non-existent API references with close-match suggestions. 21 unit tests.
- **`TranslationPipeline::with_hallucination_detector()`** — builder method to attach a pre-built detector; `hallucination_detector` field is `Option` so unit tests can construct the pipeline without a runtime. `build_hallucination_detector` exported as `pub async fn` for callers to initialize before pipeline construction.
- **Fault logger** (`calxgloss-analysis::fault_log`) — `FaultLogger` persists `FaultEvent` instances to `re/analysis/fault_log.json` with automatic directory creation, corrupted-file recovery, and `compute_stats()` aggregation. 7 unit tests.
- **Infinite-loop detector** (`calxgloss-llm::infinite_loop`) — `InfiniteLoopDetector` tracks `(prompt_hash, output_hash)` pairs across retry attempts. When the same bad output repeats three or more times in a row (configurable threshold, default 3), `detect()` returns an `InfiniteLoopSignal` with streak details. The detector fires before wasting tokens on a dead-end path. 15 unit tests + 1 doctest.
- **Behavior-divergence detector** (`calxgloss-llm::behavior_divergence`) — `BehaviorDivergenceDetector` identifies when a Rust implementation passes all baseline tests but fails on edge-case inputs not covered by the baseline suite. Generates targeted edge-case tests from disassembly hints (zero checks, null checks, overflow, negative values), compares results, and emits signals with confidence scoring and actionable recommendations. 36 unit tests.
- **`disassembly_hints` field** — added to `FunctionInfo` (with `#[serde(default)]` for backward compatibility) and `Translation`; propagated through all construction sites in `calxgloss-translator`, `calxgloss-analysis`, and `calxgloss-cli` to feed edge-case test generation.
- **Behavior-divergence detection integrated into retry loop** (`calxgloss-translator::retry`) — `try_translate_with_retry()` now runs the behavior-divergence detector after each successful compilation pass, emitting `ProgressEvent::BehaviorDivergenceDetected` when baseline/edge-case results diverge.
- **`FaultEvent::infinite_loop()`** — new factory constructor producing a `FaultCategory::InfiniteLoop` event with severity `Critical`, streak count, and streak attempt range.
- **`FaultEvent::behavior_divergence()`** — new factory constructor producing a `FaultCategory::BehaviorDivergence` event with severity `Warning` (confidence ≥ 7) or `Error` (confidence < 7), confidence score, and actionable recovery advice.
- **`ProgressEvent::InfiniteLoopDetected`** — new event emitted when the infinite-loop detector fires, carrying `dll`, `function`, `streak`, `streak_start_attempt`, `streak_end_attempt`, and `strategy` fields.
- **`ProgressEvent::BehaviorDivergenceDetected`** — new event emitted when the behavior-divergence detector fires, carrying `dll`, `function`, `attempt`, `strategy`, baseline/edge-case pass/fail counts, failing edge-case labels, and a confidence score.
- **Resource exhaustion monitoring** — `ResourceExhaustionDetector` with sliding-window failure tracking, streak detection, and configurable thresholds. Detects when the local LLM model is overloaded (OOM, swap thrash, too many concurrent requests) or requests time out. Integrates with `LlmClient::complete()` to catch HTTP 429/503/507 as `LlmError::ResourceExhausted`. Retry loop records failures, emits `ResourceExhaustionDetected` progress events, logs to the fault logger, and provides `should_queue_work()` / `should_switch_model()` helpers. 11 unit tests.
- **`ProgressEvent::ResourceExhaustionDetected`** — new event emitted when the resource-exhaustion detector fires, carrying `dll`, `function`, `attempt`, `strategy`, reason, elapsed seconds, and recommended backoff time.

#### `calxgloss-types`
- **Token usage types** (`calxgloss-types::token_usage`) — `TokenUsageEntry` (per-attempt token count with DLL, function, attempt number, strategy, and success status), `TokenUsageLog` (collectible entries with serde), `TokenUsageStats` (aggregate totals with per-DLL breakdown into `DllTokenStats`), and `current_timestamp()` helper. Full test suite with serialization round-trips.
- **Token usage with context tier tracking** — `TokenUsageEntry` now carries a `context_tier` field (serialized only when non-empty) and a `new_with_tier()` constructor. `log_token_usage()` accepts and persists a tier label alongside token counts. All retry loop code paths (initial, strategy-based, tier-escalated, resource exhaustion, empty code) log their tier with token counts to `re/analysis/token_usage.json`.

#### `calxgloss-analysis`
- **Token usage logger** (`TokenUsageLogger`) — persists per-attempt token entries to `<workspace>/re/analysis/token_usage.json`. Provides `record()`, `load()`, `compute_stats()`, and `log_path()` methods. Auto-creates the `re/analysis/` directory; handles corrupted-file recovery by starting fresh.

### Changed

#### GhidraMCP 6.x migration

- **Migrated `calxgloss-ghidra` to the new GhidraMCP bridge** (ghidra-mcp v6.0.0, replacing the deprecated LaurieWired extension). The client keeps talking raw HTTP to the Ghidra plugin but follows the 6.x endpoint surface:
  - Endpoint renames: `searchFunctions` → `search_functions` (param `query` → `name_pattern`), `segments` → `list_segments`, `xrefs_to`/`xrefs_from`/`function_xrefs` → `get_xrefs_to`/`get_xrefs_from`/`get_function_xrefs`, `exports`/`imports`/`strings`/`namespaces`/`classes`/`methods` → `list_*` variants.
  - JSON response support: `get_current_address`, `get_current_function`, and `list_imports` now answer JSON; parsers accept both the JSON and legacy plain-text shapes.
  - JSON error support: `error::classify` recognises `{"error": "..."}` bodies (sent as `200 OK`), and non-2xx HTTP statuses (the 6.x bridge 404s unknown endpoints) now surface as `GhidraError::Reported`.
  - `decompile_function_by_name()` no longer POSTs to the dropped `/decompile` endpoint; it resolves the name via `search_functions` and decompiles by address, preferring an exact name match.
  - **Multi-program support** — new `open_programs()` and `switch_program()` methods (and the `OpenProgram` model type) expose the 6.x bridge's ability to hold several programs open and move which one queries run against. `ProgramInfo` gained a `program` field.

### Refactored

#### `calxgloss-cli`
- **Shared translation output helpers** — extracted crate-setup and function-writing logic into `derive_crate_name()`, `setup_translation_crate()`, and `write_translation_function()` in `utils.rs`, eliminating duplication between `translate.rs` and `batch_translate.rs`.

#### `calxgloss-ghidra`
- **Client extraction** — extracted `GhidraError`, `GhidraConfig`, `GhidraClient`, `ProgramInfo`, `rva_from_va`, and tests into `client.rs` (711 lines). `lib.rs` is now 28 lines of module declarations and re-exports.

#### `calxgloss-llm`
- **Client extraction** — extracted `LlmError`, `LlmConfig`, `MessageRole`, `LlmMessage`, `LlmResponse`, `LlmClient`, `strip_code_fences`, and tests into `client.rs` (734 lines). `lib.rs` is now 31 lines.

#### `calxgloss-testgen`
- **Generator extraction** — extracted `TestGenerator` with its impl and tests into `generator.rs` (592 lines). `lib.rs` is now 62 lines.

#### `calxgloss-prompts`
- **Template extraction** — extracted Askama template structs into `templates.rs` (733 lines), prompt builders into `build.rs` (336 lines), and prompt data structs into `context.rs` (208 lines). `lib.rs` remains a thin re-export layer.

#### `calxgloss-reports`
- **Dashboard subdirectory** — extracted print functions and ANSI formatting into `dashboard/view.rs` (360 lines), `dashboard/builder.rs` (590 lines), and `dashboard/render.rs` (540 lines). Old `dashboard.rs` removed.

#### `calxgloss-translator`
- **Translator and pipeline split** — extracted core translator logic into `translator.rs` (231 lines) and pipeline into `pipeline.rs` (1180 lines).

#### `calxgloss-verify`
- **Engine extraction** — extracted `Verifier` + `CompileResult` + impl into `engine.rs` (1036 lines). Moved `cargo.rs`, `helpers.rs`, `parse.rs`, and `stubs.rs` into src/ directly.

#### `calxgloss-git`
- **GitManager extraction** — extracted `GitManager` into `git_manager.rs` (918 lines), dependency tracking into `dependency.rs` (290 lines), helpers into `helpers.rs` (49 lines). Tests extracted into `tests.rs` (514 lines). `lib.rs` is now 60 lines.

#### `calxgloss-analysis`
- **Analyzer extraction** — extracted `Analyzer` with `Strategy` enum, `DllClassification`, `FunctionAnalysis`, full impl, `suggest_shim`/`estimate_complexity`, and tests into `analyzer.rs` (1117 lines). `lib.rs` is now 64 lines.

#### `calxgloss-config`
- **Multi-file split** — extracted `ConfigError` into `error.rs` (32 lines), `FileConfig`/`GhidraSection`/`LlmSection` into `schema.rs` (91 lines), `LoadedConfig`/`load()`/`discovery` into `loader.rs` (128 lines), and `Source`/`Resolved<T>`/`Layers` + tests into `layers.rs` (453 lines). `lib.rs` is now 32 lines.

#### `calxgloss-types`
- **Dashboard subdirectory** — extracted dashboard data model into `dashboard/` subdirectory (`types.rs`, `work_unit.rs`, `graph.rs`, `status.rs`, `review.rs`, `action.rs`, `mod.rs`, `tests.rs`). Old `dashboard.rs` removed.

#### `calxgloss-pal`
- **Module split** — extracted `ApiMapping` and `ApiMappings` types with their implementations into `types.rs` (209 lines), moved all 20 unit tests into a separate `tests.rs` file. `lib.rs` is now 23 lines of module declarations and re-exports only.

#### `calxgloss-web`
- **`GET /api/gc/candidates` endpoint** — discovers unmerged stale translation branches, checks their last commit date, and returns structured candidate data sorted by age. Supports configurable `days` threshold via query parameter (default 7).
- **`POST /api/gc/archive` endpoint** — archives one or more stale branches to `refs/archive/re/{dll}/{function}v{N}` (or `refs/archive/re/{dll}v{N}` for branches without a function component). Accepts an optional list of specific branches; when empty, archives all available candidates.
- **"Stale Branches" status card** — clickable card on the dashboard showing the count of stale unmerged branches. Non-critical; loads in the background and navigates to the Branch Cleanup view when clicked.
- **"Branch Cleanup" nav tab** — standalone view with configurable staleness threshold (days), summary stats (stale count, recent count, threshold), a sortable table with per-row checkboxes, select-all, and "Archive All Stale" button.
- **GC types** — `GcCandidate`, `GcCandidatesResponse`, `GcArchiveRequest`, `GcArchiveResult`, `GcArchiveResponse` in `server/types.rs`.

#### `calxgloss-web`
- **Handlers module extraction** — split the monolithic `handlers.rs` (1300 lines) into a `handlers/` module directory with feature-based submodules: `api.rs` (core API endpoints), `diff.rs` (diff computation), `gc.rs` (GC/archive handlers), `ghidra.rs` (Ghidra helpers), `pipeline.rs` (progress/pipeline endpoints), `queue.rs` (queue management), and `static.rs` (static file serving).

#### `calxgloss-cli`
- **Unused import cleanup** — removed 27 unused imports across 11 files to eliminate all clippy warnings.
- **Command extraction** — split `main.rs` (3270 lines) into 16 files: `main.rs` (332), `cli_types.rs` (445), `utils.rs` (290), `settings.rs` (490), and `commands/` subdirectory with init, classify, auto_shim, auto, translate, batch_translate, dashboard, verify, serve, and live handlers.

### Changed

#### `calxgloss-translator`
- **Translation attempt context tier** — `TranslationAttempt` now carries a `context_tier` field recording which tier was used for each attempt. Enables post-hoc analysis of which context scope yields the best pass rates.
- **Per-attempt token logging** — `try_translate_with_retry()` now logs token usage to disk for every LLM call: the initial translation attempt, each retry attempt (compile_fix, test_fix, escalate, edge_case_fix), and empty-code failure cases. The log includes DLL name, function name, attempt number, strategy label, token count, and success/failure status. Tier-escalated attempts are also logged with their tier label.

#### Fault detection integration
- **Fault event persistence** — all detected faults (context-window exceeded, hallucination, infinite loop, behavior divergence, resource exhaustion) are now recorded to `re/analysis/fault_log.json` via `FaultLogger`. The translation pipeline wires the logger at the emission sites in both the main `translate()` path and the retry loop.
- **Hallucination detection in the translation pipeline** — `TranslationPipeline::try_translate_with_retry()` scans each LLM response for non-existent API references using the hallucination detector. Detected hallucinations are logged as warnings and emitted as `ProgressEvent::HallucinationDetected` for real-time dashboard visibility.

#### `calxgloss-web`
- **End-to-end integration tests** — 16 API-level tests that spin up the axum server with a realistic test fixture (git repo with branches, patches, baselines, classifications) and verify all endpoints: health, dashboard, unit detail, queue, graph, diff, ghidra, pipeline, progress, static files, websocket upgrade, and build_dashboard API. 1 headless browser test is marked `#[ignore]` and runs with `--ignored` (requires Chrome installed). Run with: `cargo test --features server --test e2e`.

#### `calxgloss-reports`
- **Token summary in batch output** — `print_batch_summary()` now displays a total tokens line (e.g., `Tokens: 29,440 tokens consumed across 12 attempts`) when token data is available.

### Documentation

- **`call_graph_assisted_translation.md`** — detailed plan for implementing root & leaf call graph analysis to skip known runtime functions, prioritize translation order, and enrich translation prompts with semantic context from API usage patterns.

### `calxgloss-translator`
- **`batch_translate()` accepts a per-function callback** — the batch method now takes an optional `&mut dyn FnMut(&str, &str, &mut FunctionResult) -> bool` closure that is invoked immediately after each function's translation pipeline (including retries) completes, before the next function is processed. The callback can perform post-processing (e.g. writing files, git operations) incrementally. Returns `true` to continue the batch or `false` to stop early.

### `calxgloss-cli`
- **`auto-shim` subcommand** — generates shim layers for all crate-replacement DLLs automatically. After `classify` marks DLLs as `CrateReplacement`, this command runs the full pipeline: generate API mappings (LLM) → generate source code → generate tests → verify → persist. Artifacts are written to `re/shims/<dll_name>/` and committed to git. Supports `--dll <name>` to process a single DLL.
- **Incremental git commits during batch translation** — `run_translation_for_dll()` and `handle_batch_translate()` now commit and merge each function immediately after its translation succeeds, rather than deferring all git work until the entire batch finishes. Each function's Rust code is written, a `re/{dll}/{function}v1` branch is created, the file is committed, and the branch is merged to `main` before the next function is processed.

### `calxgloss-types`
- **Shim layer types** — `ShimApiMapping`, `ShimLayer`, `ComplexityScore`, and `ReturnMapping` define the API contract for translating a Windows DLL's exported surface to an equivalent Rust crate. Mappings carry original and target signatures, parameter transformation descriptions, complexity scores, and optional return-value handling. `ShimLayer` provides aggregate helpers (`total_complexity()`, `overall_complexity()`, `mapping_count()`) and converts to existing `ApiMappingItem` for prompt inclusion.
- `ShimVerificationResult` — result of verifying a shim layer against tests; reports compilation status, per-mapping test counts (main + edge-case), failures, and per-mapping breakdowns. Provides `total_tests()`, `total_passed()`, `all_passed()`, and `pass_rate()` helpers.
- `ShimMappingTestResult` — per-mapping test result with `original_api`, `crate_api`, pass count, total count, and detailed failures.
- **`ShimSuggestion`** — per-DLL shim layer estimate with `source_dll`, `target_crate`, `estimated_mappings`, `estimated_complexity` (Low/Medium/High), and `estimated_confidence` in `[0.0, 1.0]`. Produced automatically from classification data without an LLM call.
- **`ShimSuggestionReport`** — aggregation of all `ShimSuggestion` instances for crate-replacement DLLs. Provides `total_dlls()`, `low_complexity_count()`, `medium_complexity_count()`, `high_complexity_count()`, `is_empty()`, and `average_confidence()`.
- **`ProgressEvent::FunctionCompleted`** — new event emitted immediately after each function completes during batch translation, carrying `dll`, `function`, `success`, `attempts`, and `branch` fields.
- **`ProgressEvent::HallucinationDetected`** — emitted after the LLM response is scanned and one or more hallucinated calls are detected. Carries `dll`, `function`, `attempt`, `strategy`, and `hallucinated_apis` fields.

### `calxgloss-web`
- **Progress state handles `FunctionCompleted`** — the `ProgressState` now processes the new `FunctionCompleted` event, marking the corresponding unit as `Complete` in the live progress dashboard.
- **Progress state handles `HallucinationDetected`** — hallucination events are forwarded through the progress state to keep the live dashboard aware of detected hallucinations.
- **Review Queue tab now populates on tab switch** — switching to the tab immediately renders the full queue list, no longer requires clicking a dashboard item first.
- **Queue item names include the function** — queue items now display `DLL function Status vN` (e.g. `LaunchPad.exe FUN_004011d0 InProgress v1`) instead of showing only the DLL name.
- **Review Queue view has a two-column layout** — the tab now shows an inline detail view (left) alongside the queue item list (right), replacing the previous floating sidebar panel.
- **Removed left sidebar dependency graph** — the collapsible sidebar panel that held a small dependency graph has been removed, along with the sidebar toggle button.

### `calxgloss-web`
- **`api_get_unit` merges live progress state** — the unit detail endpoint now also consults the `ProgressState` and creates synthetic units for in-progress translations (IDs prefixed with `live/`), so clicking a live unit no longer returns 404.
- **LLM request/response log renders raw text** — content is now shown inside `<pre>` with only `<`, `>`, and `&` escaped, so JSON and code (e.g. `{"param_0":0}`) displays correctly instead of HTML-entity-encoded (`&#34;param_0&#34;:0`).
- **Pipeline Progress panel** — new panel showing per-DLL status: classification category/strategy, in-progress translation with progress bar, and batch completion counts. Emitted on `classification_complete` and `batch_summary` WebSocket events.
- **`body` variable scope fix in `showDetail`** — moved `const body` declaration outside the `try/catch` block so the error handler can reference it.

### `calxgloss-cli`
- **`classify` generates shim layer suggestions** — after classifying DLLs, automatically produces complexity estimates for all crate-replacement DLLs and persists them to `re/shims/suggestions.json`. The suggestions file is committed to git on main.
- **`init` subcommand** — creates a `calxgloss.toml` in the current directory with a fully commented-out template listing every `[ghidra]` and `[llm]` key with sensible defaults.
- **`auto` subcommand** — detects project state and runs the next step automatically. Scans the target directory for `.dll` files, checks whether classification records exist in `re/classify/`, and either runs classification first (if any DLLs are unclassified) or prompts the user to select a DLL for batch translation.
- **No-subcommand defaults to `auto`** — calling `calxgloss-cli` with no subcommand is equivalent to `calxloss-cli auto`.
- **Auto flags**: `--target` (directory), `--dlls` (explicit comma-separated list), `--all-functions`, `--classify-only`, `--skip-git`.
- **`target_dir` in config** — `calxgloss.toml` can set `target_dir = "..."` at the top level. This is the directory containing DLLs/EXEs and is **required** for all commands that do real work. Resolved: CLI flag > config file > env var (`CALXGLOSS_TARGET_DIR`).
- **`--target-dir` global CLI flag** — overrides config `target_dir`.
- **`--repo-dir` global CLI flag** — overrides config `repo_dir`.
- **`repo_dir` in config** — `calxgloss.toml` can set `repo_dir = "..."` at the top level. This is the workspace directory where `src/`, `re/`, scratch, and `.git` are created. Defaults to CWD if not set. Resolved: CLI flag > config file > env var (`CALXGLOSS_REPO_DIR`) > CWD.
- **`live` and `serve` always use CWD for repo_dir** — these commands operate on the workspace where the user runs them, so config file and env var overrides are ignored. Only an explicit `--repo` flag can change the directory.
- **`scan_dlls()` helper** — looks for `.dll` files in the target directory.
- **`classification_record_exists()` helper** — checks whether a `re/classify/<dll>.json` file already exists.
- **Config render** — `calxgloss config` now shows `target_dir` path and source.
- `--strategy` flag — select the initial retry strategy or `auto` for automatic cycling through all strategies.
- `retry_strategy` displayed in `config` command output.
- **`dashboard` subcommand** — reads all `re/*` git branches, patch records from `re/patches/`, and baseline files from `re/baseline/` to build and render a structured review dashboard. Supports `--follow` (continuous watch) and `--interval <secs>` (refresh cadence, default 2).
- **`dashboard view <target>`** — per-unit quick-view subcommand showing justification, diff summary, test results, and attempt history for a single translation unit. Target format: `<dll>/<function>` or `<dll>/<function>/vN` (e.g., `game_logic/DrawPrimitive/v3`).
- **`dashboard accept <target>`** — merges the named unit's branch into `main` and reports success, already-merged status, or merge conflicts; writes an acceptance record for the dashboard to discover.
- **`dashboard reject <target> --reason "..."`** — records a rejection with an optional reason; the record is persisted so the dashboard can display send-back history.
- **`dashboard accept-all [--all]`** — accepts every pending unit in dependency order: topologically sorts the review queue, merges each branch into `main` sequentially, writes acceptance records. The `--all` flag extends acceptance to every unmerged branch (including blocked and send-back units). Reports per-unit status with merge hashes and a summary line (accepted / skipped / failed).
- `handle_translate` and `handle_batch_translate` now pass `BranchCreationPolicy::Warn` to `create_branch`, enabling dependency-aware branch creation with warning-level enforcement during translation.
- **`serve` subcommand** — starts the web review UI HTTP server. Resolves the repository path from an explicit `--repo` flag, git discovery, or CWD; defaults to port 3000 (`-p`). Prints a formatted startup banner listing all available API endpoints. Wires up the existing `calxgloss-web` axum server (behind the `server` feature) so the review dashboard is reachable at `http://127.0.0.1:{port}/`.
- **`serve` readiness signal** — the ready signal fires only after `TcpListener::bind()` succeeds, so the server is actually reachable before the caller proceeds. Bind failures are reported through the channel instead of being misinterpreted as panics.
- **`live` subcommand** — runs `auto` (batch translation) and `serve` (web UI) concurrently in one process. After classification completes, proceeds to translate all classified DLLs automatically (no interactive prompt). The web UI stays running throughout; pressing Ctrl+C stops both.
- **`live` server readiness** — the TCP listener is bound inside the serve task and the ready signal fires only after the socket is actively listening. Bind failures (e.g. port in use) are reported through the channel instead of being misinterpreted as a server panic.
- **`live` WebSocket support** — `handle_live` now builds the router with `build_router_with_ws()`, mounting `/api/events/upgrade` so the frontend can stream progress events via WebSocket. `serve_with_listener()` takes a pre-built `Router` so callers can choose the WS-enabled or basic router.
- **`run_translation_for_dll()` extracted** — shared helper so both `auto` and `live` reuse the same translation plumbing.
- **`auto` continue mode** — new `continue_mode: bool` parameter; when enabled, `auto` translates all classified DLLs sequentially without the interactive per-DLL prompt, and newly-classified DLLs are folded into the translation loop.

### `calxgloss-verify`
- Shared PAL stubs moved into a single `scratch/pal/` crate — each verification project now depends on it via path dependency instead of having ~16 KB of stub types, traits, and implementations duplicated inline in its `lib.rs`.
- **`Verifier::verify_shim()`** — verifies a shim layer by scaffolding a sandboxed Cargo project, compiling the generated shim source, running `cargo test`, and parsing the output. Accepts raw shim source and test code strings, scaffolds a project with the target crate as a dependency, and returns a `ShimVerificationResult` with compilation status, per-mapping test counts (main + edge-case), and detailed failure information.
- **`parse_shim_test_results()`** — parses `cargo test` output for shim test results. Extracts individual test names, categorizes them as parameter tests (`test_<fn>_params`) or edge-case tests (`test_<fn>_edge_*`), groups results by mapping function name, and returns per-mapping pass counts with detailed failure records.
- `parse_test_line()` — parses individual `cargo test` output lines to extract test names and pass/fail status.
- `extract_mapping_function()` — extracts the original API function name from a test name by stripping module prefix, `test_` prefix, and `_params` / `_edge_*` suffixes.

### `calxgloss-config`
- `LlmSection.strategy` — retry strategy configuration (compile_fix, test_fix, escalate, edge_case_fix, auto) via CLI flag, environment variable (`CALXGLOSS_LLM_STRATEGY`), or config file.

### `calxgloss-analysis`
- **`classify_dlls` reads PE headers for symbol counts** — export and import counts are now read from each DLL's PE header on disk via `goblin`, giving accurate per-DLL values instead of the stale counts from whichever program happens to be open in Ghidra. Missing or unreadable DLLs fall back to the Ghidra client. The method now takes a `target_dir` argument so it knows where to find the files.
- **Classification records persisted to disk** — `handle_classify` now writes `re/classify/{dll}.json` for every DLL and commits them to `main`. Subsequent `auto` runs detect existing records and skip re-classification. `Strategy` and `DllClassification` derive `Serialize`/`Deserialize` for JSON output.
- **Dependency tracker** (`DependencyTracker`) — builds a `DependencyGraph` from DLL classifications and Ghidra call graph data. Automatically derives shim layer declarations from crate-replacement classifications. Produces a DAG in dependency order: DLL classifications (roots) → shim layers → function translations (depending on shim + call graph neighbors). `for_dll()` method for incremental single-DLL builds.
- `ShimLayerDeclaration` — declares a shim layer for a crate-replacement DLL; extracted from `DllClassification` via `from_classification()`.
- **`DependencyGraphPersistor`** — persists a `DependencyGraph` to `<workspace>/re/analysis/dependency_graph.json`. Provides `save()`, `load()`, `graph_path()`, and a convenience `build_and_save()` that combines `DependencyTracker::build()` with `save()`. Auto-creates the `re/analysis/` directory structure. Returns `None` on missing or corrupt files rather than erroring.
- `Analyzer::detect_complexity()` — detects function complexity from disassembly and tagged API calls.
- `Analyzer::build_prompt_variant()` — builds a `PromptVariant` with complexity classification and API awareness.
- **`Analyzer::suggest_shim_layers()`** — generates shim layer complexity estimates for all crate-replacement DLLs from classification data. Uses a heuristic scoring formula (`exports * 5 + imports * 3`, weighted by crate familiarity and export-count factor) to produce estimated complexity (Low/Medium/High) and confidence scores without an LLM call. Re-exports `ShimSuggestionReport` from `calxgloss_types`.
- **`DependencyTracker::build()` / `for_dll()`** — now assign correct `WorkUnitLevel` (`DllClassification`, `ShimLayer`) to nodes they create, instead of using default struct field syntax.
- **Prompt strategy logger** (`PromptStrategyLogger`) — persists experiment entries to `<workspace>/re/analysis/prompt_strategy_log.json` with `record()`, `load()`, `compute_stats()`, and `log_path()` methods. Auto-creates directory structure; handles corrupted-file recovery by starting fresh.
- **Shim mapping auto-generation** (`shim` module) — `generate_shim_mappings()` sends a structured prompt to the LLM containing the DLL name, target crate, and all exported function signatures; the LLM returns a JSON array of `ShimApiMapping` entries. Includes `CrateContext` hints (description, common patterns, pitfalls) for wgpu, tiny-skia, cpal, fmod-rs, and vb6runtime to guide the LLM. Response parser strips markdown code fences, maps string values to typed enums, and handles missing optional fields gracefully.
- **Shim source code generation** (`shim_gen` module) — `generate_shim_source()` produces a complete Rust module from a `ShimLayer` mapping table. Two modes: `Complete` generates actual function calls with proper crate paths and return-value handling; `Skeletal` produces `TODO` stubs with detailed implementation hints. Auto-generates a `ShimState` struct when mappings require shared resource tracking (texture heaps, device contexts, etc.). Handles Windows API parameter-to-Rust type conversion for all common Win32 types (UINT, LPVOID, HWND, HRESULT, COM interface pointers, FMOD types). Provides `rust_fn_name()` for converting Windows DLL function names (e.g., `Direct3DCreate9`) to Rust snake_case identifiers.
- **`dll_to_module_name()`** — utility for converting DLL filenames to valid Rust module names (strips `.dll` extension, replaces hyphens and dots with underscores, lowercases).
- **Shim test generation** (`shim_test_gen` module) — `generate_shim_tests()` produces a complete Rust test module from a `ShimLayer` mapping table. For each mapping: generates a parameter correctness test verifying the shim calls the correct crate API with properly transformed parameters, returns the correct value type, and documents all transforms as inline comments; generates edge-case tests for boundary values (`zero`, `null`, `max`, `empty`, `negative`, `overflow`) found in parameter transforms; provides thread-local mock call recorders and per-crate mock modules (e.g. `mock_fmod_rs`, `mock_cpal`) that record invocations and arguments for verification; includes a summary test asserting the mapping count. Includes `rust_fn_name()` and `convert_param_to_rust()` helpers shared with `shim_gen`.
- Clippy fixes: `derivable_impls` (derive Default on `ShimGenerationMode`), `single_char_add_str` (use `push('\n')` instead of `push_str("\n")`), `needless_borrow` on `split()`.

### `calxgloss-git`
- **`accept_branch()`** — merges a branch into `main` and writes an acceptance record to `re/accepts/{dll}/{function}/vN.json` for dashboard visibility.
- **`reject_branch()`** — writes a rejection record to `re/rejections/{dll}/{function}/vN.json` with the reviewer's reason, enabling send-back history in the dashboard.
- **`is_branch_merged_into_main()`** — checks if a branch is an ancestor of `main` via `graph_ahead_behind()`.
- **`archive_branch()`** — archives a branch by renaming it from `re/{dll}/{function}vN` to `refs/archive/re/{dll}/{function}/vN` so it remains reachable for reference instead of being deleted. Used by the `gc` subcommand to prevent branch sprawl.
- **`GitManager::next_attempt_branch()`** — increments the attempt number and creates a new `GitBranch` for the next retry version.
- **Shim-layer dependency enforcement on branch creation** — `create_branch` accepts an optional `BranchCreationPolicy` parameter (`Skip`, `Warn`, or `Enforce`). The checker resolves the required shim layer branches for `MicrosoftSdk` and `KnownThirdParty` DLLs (e.g. `d3d9.dll` → `re/shim/wgpu`) by consulting a hardcoded mapping in `ShimDependencyMap`, then queries Git to verify each required branch is an ancestor of `main`. Enforce mode blocks creation when unmet; Warn mode logs a warning and proceeds.
- **`commit_to_main()`** — commits files directly to the `main` branch without creating a separate branch first. Used for metadata records like DLL classification.
- `DependencyCheckResult`, `DependencyChecker`, `ShimDependencyMap`, `BranchCreationPolicy`, `DependencyPolicy` — new types in `calxgloss-git` for dependency resolution and policy enforcement.
- `ShimDependencyMap` — hardcoded lookup covering 22 DLL → crate mappings across DirectX, audio, 2D graphics, UI frameworks, and geometry libraries.

### `calxgloss-reports`
- **Terminal rendering** (`render_dashboard`) — flat text report with horizontal dividers (`═` / `─`), no vertical borders or corners. Color-coded status summary, dependency-sorted review queue table, blocked units section, and recent activity. Auto-refresh follow mode via `render_dashboard_follow`.
- **`render_unit_view()`** — renders a detailed single-unit view with sections: unit info (kind, status, confidence, dependencies), branch status (merged/unmerged), DLL classification, diff summary (files changed, insertions, deletions), baseline and verification test results, and attempt history loaded from patch records.
- **`print_classification_report()`** now displays a SHIM LAYERS section showing per-DLL shim suggestion details: target crate, estimated mapping count, complexity (color-coded: green/yellow/red), and confidence percentage. Accepts a `ShimSuggestionReport` alongside classifications.
- `ViewTarget` — parses `dll/function` or `dll/function/vN` target strings.
- `UnitViewData` — collects all data for a unit view (unit info, branch name, merge status, diff summary, attempt history, baseline tests, DLL classification).
- **Dependency diff summary** — computes `git diff` stats between branch and main (files changed, insertions, deletions).
- Clippy `filter_next` — replaced `.filter(...).into_iter()...next()` with `.find(...)` on branch list iteration.
- Clippy `unnecessary_closure` — replaced `.or_else(|| { Some(...) })` with `.or(Some(...))` for static default values.
- **Table column alignment** — switched from format-width specifiers (which counted invisible ANSI escape codes as characters) to hardcoded column widths per element, so colored headers no longer shift data columns.
- **Stale-work highlighting** (`Staleness`) — `Fresh` / `Stale` (≥24h, yellow highlight) / `Critical` (≥48h, red highlight) enum on `UnitOfWork`. Dashboard builder parses the actual commit timestamp from patch records to compute elapsed pending time. Queue table rows for stale units get a warning/critical prefix symbol and the dashboard renders a "Stale work" section listing them with elapsed durations.
- **`branch_matches()`** — public predicate for matching a git branch name against a `{dll}/{function}/{attempt}` target, used by the accept/reject CLI handlers to resolve a target string to the actual branch.
- `DashboardBuilder::build()` now calls `auto_block_units()` after constructing the dashboard from git/file artifacts, ensuring the terminal dashboard always shows correct blocked status.

### `calxgloss-types`
- **`ProgressEvent::LlmRequest` / `LlmResponse`** — new event variants emitting the full prompt sent to the LLM and the full response received, including DLL/function identifiers, attempt number, strategy label, prompt text, response content, and token usage. Display impls show concise summaries.
- **`TranslationEvents` is `Clone`** — each clone shares the same underlying broadcast channel, so it can be passed to multiple pipeline instances simultaneously.
- **`SessionManager::new_with_broadcast()`** — creates a session manager that drives the broadcast loop from an existing `broadcast::Receiver`, allowing the translation pipeline's `TranslationEvents` channel to feed directly into the WebSocket server without an intermediate `mpsc` bridge.
- **Dashboard data model** (`calxgloss-types::dashboard`) — new module with all review dashboard types, replacing the duplicate scaffolding in `calxgloss-web`: `WorkUnitKind` (7 unit types), `ReviewStatus` (7 statuses), `UnitOfWork` (full metadata struct with timestamps, test counts, confidence, dependencies, known gaps), `DependencyNode` / `DependencyEdge` / `DependencyGraph` (DAG with `roots()`, `dependents()`, `dependencies()` traversal), `StatusCounts` (aggregated counts with `total()`), `ReviewDashboard` (assembles units into a viewable dashboard with dependency-sorted queue, recent activity, and status counts), and `ReviewAction` / `ReviewActionKind` (human review actions). All types derive `serde::Serialize` and `serde::Deserialize`.
- `chrono` dependency — added to `calxgloss-types` for `DateTime<Utc>` fields in `UnitOfWork` timestamps.
- **Complexity-based prompt selection** (`calxgloss-types::complexity`) — `FunctionComplexity` enum (Minimal / Standard / Rich / Detailed) and `detect_complexity()` function that classifies functions by instruction count, branch density, call depth, and API-category diversity. `PromptVariant` struct for strategy selection and `FailureHint` for recording previous attempt failures.
- `ApiCategoryMapping` and `ApiMappingItem` — types for grouping Windows API mappings by category in rich and detailed translation prompts.
- **Prompt strategy experiment types** (`calxgloss-types::experiment_log`) — `PromptStrategyEntry` (single attempt outcome), `PromptStrategyLog` (collectible entries), `PromptStrategyStats` with `CategoryStats` and `StrategyStats` (aggregate pass/fail rates), and `current_timestamp()` helper. Full serde serialization for disk persistence.
- **`WorkUnitLevel`** enum — defines 7 processing-phase levels for dependency-ordered pipeline execution: `DllClassification` → `ShimLayer` → `PalTrait` → `TestCaseAddition` → `FunctionTranslation` → `IntegrationStep` → `BugFix`. Derives `PartialOrd` / `Ord` so lower-level units are always processed before higher-level ones. Includes `label()` for human-readable output.
- **`WorkUnitKind::level()`** — maps each unit kind to its corresponding `WorkUnitLevel`, enabling automatic level assignment from existing data.
- **`DependencyNode::level`** — new `#[serde(default)]` field with constructors `DependencyNode::new()` (default level) and `DependencyNode::with_level()`. Backward-compatible: missing `level` fields deserialize to `WorkUnitLevel::DllClassification`.
- **`DependencyGraph::topological_order()`** — returns all nodes in topological order (dependencies first) using Kahn's algorithm with depth tracking. Suitable for ordered batch operations like batch accept. Rewritten to return `(Vec<&DependencyNode>, Vec<String>)` (ordered nodes + cycle-involved nodes). Uses a merge-sorted priority queue keyed by `(depth, level, node_id)`. Level-aware tie-breaking ensures shim layers appear before PAL traits before function translations at the same topological depth. Cycle detection is non-fatal: nodes not involved in cycles are still correctly ordered.
- **`ReviewDashboard::sorted_queue()`** — canonical ordering for batch operations, using the full topological sort with level tie-breaking. Returns `Queued` / `PendingReview` units in dependency order, with already-accepted units at the end.
- **`ReviewDashboard::next_in_dependency_order()`** — returns the next unit to review in proper dependency-then-level order, replacing the deprecated `next_to_review()`.
- **`ReviewDashboard::pending_in_dependency_order()`** — returns only `Queued` / `PendingReview` units sorted by dependency depth, ready for batch acceptance.
- **`ReviewDashboard::auto_block_units()`** — automatically marks units as `Blocked` when their dependencies are in a failing state (`SendBack` / `PatchRequested`). Propagates transitively: if A depends on B and B fails, A is blocked; if C depends on A and A is blocked, C is also blocked. Skips terminal statuses (`Accepted` / `Merged` / `Blocked`) and the failing units themselves (they keep their original status). Scans both `review_queue` and `recent_activity`. Returns the count of units changed to `Blocked`. Idempotent.
- **`ProgressEvent` enum** — typed events emitted at pipeline milestones: `TranslationStarted`, `GhidraFetchComplete`, `ApiTaggingComplete`, `TestsGenerated`, `LlmCallStart`, `LlmCallComplete`, `TranslationAttemptCompleted`, `TranslationCompleted`, and `TranslationFailed`. All variants carry `dll`/`function` identifiers plus attempt-specific metadata; fully serializable via `serde` for JSON transport over WebSockets.
- **`TranslationEvents`** — broadcast-channel wrapper (`tokio::sync::broadcast`) for publishing progress events. `emit()` returns the subscriber count, `subscribe()` creates a new receiver. Callers don't need to handle errors — lost events when no subscribers are present are silently discarded.

### `calxgloss-prompts`
- **Complexity-aware prompt builder** (`build_complexity_prompt`) — selects the appropriate template based on function complexity: `MinimalTemplate` (≤30 instructions, disassembly + decompiler only), `TranslateTemplate` / `Standard` (31–100, adds API mappings + tests), `RichTemplate` (101–300, adds API category context + advanced guidelines), `DetailedTemplate` (>300, adds call graph + neighbors + data structures + type info).
- **New template files** — `minimal_translate.j2`, `rich_translate.j2`, `detailed_translate.j2` with complexity-appropriate context and guidance.
- `ComplexityPromptData` — aggregates all analysis data for use with the complexity-based prompt builder.
- **Failure-informed retry prompts** — `FixTemplate`, `EscalateTemplate`, and `EdgeCaseTemplate` all now accept a `failure_history: Vec<FailureHint>` field. When non-empty, each template renders a "PREVIOUS ATTEMPT HISTORY" section so the LLM can learn from specific past mistakes. Dedicated `with_history()` constructors and updated `build_escalate_prompt()` / `build_edge_case_prompt()` helpers. Embedded templates (`failure_fix.j2`, `escalate.j2`, `edge_case.j2`) updated to render the history section.
- **`[package.metadata.askama]`** — `autoescape = "none"` set so templates render raw HTML without escaping.

### `calxgloss-translator`
- **LLM I/O event emission** — `TranslationPipeline::translate()` and `try_translate_with_retry()` now emit `LlmRequest` and `LlmResponse` events before and after every LLM call (initial and all retry attempts), carrying full prompt text, response content, attempt number, and strategy label.
- **Failure-informed retry prompts** — all retry strategies (`CompileFix`, `TestFix`, `Escalate`, `EdgeCaseFix`) now inject a "PREVIOUS ATTEMPT HISTORY" section into LLM prompts when prior attempts have failed. Includes `build_failure_informed_compile_fix_prompt()`, `build_failure_informed_test_fix_prompt()`, `build_failure_informed_escalate_prompt()`, and `build_failure_informed_edge_case_fix_prompt()`.
- `TranslationPipeline::translate()` now uses complexity-based prompt selection, routing simple functions to minimal prompts and complex functions to rich or detailed prompts with extra Ghidra context.
- **Experiment logging integration** — `try_translate_with_retry()` now accepts an optional workspace path; `TranslationPipeline` gains `with_workspace()` builder method. Every retry attempt is recorded (DLL name, auto-classified category, strategy label, success/fail, attempt number, timestamp). Skipped silently when no workspace is set.
- **Pipeline event emission** — `TranslationPipeline::with_events()` attaches a `TranslationEvents` instance; `emit()` publishes events at every major milestone during `translate()` and `try_translate_with_retry()`.
- **`RetryLoopCtx` struct** — bundles verifier, LLM, Ghidra, config, workspace path, and event emitter into a single argument for `try_translate_with_retry()`, reducing the public function signature from 7 to 2 parameters.
- **`EscalatePromptCtx` struct** — groups context data for the escalation prompt builder (function name, DLL, code, failure description, Ghidra client, address, call graph, failure history), simplifying the 8-parameter API.
- **Per-attempt progress events** — the retry loop now emits `TranslationAttemptCompleted` after every attempt (initial, compile-fix, test-fix, escalate, edge-case-fix), so WebSocket clients can display real-time per-attempt status (compiled, tests passed, strategy label).
- **Removed `#[instrument]` from `try_translate_with_retry`** — the tracing macro added deep nesting to the async future type (`Instrumented<ManuallyDrop<coroutine>>`), which caused the compiler's `Send` recursion limit to be exceeded when `tokio::task::spawn` checked the full type chain from `actions.rs`.
- **Trims leading/trailing whitespace** from disassembly and decompiler output before sending to the LLM, keeping prompts cleaner and avoiding wasted tokens.

### `calxgloss-web`
- **Axum API server** (`server` feature) — full HTTP API for the review dashboard: `GET /api/dashboard` (queue, graph, counts), `GET /api/units/:id` (unit detail with diff summary, attempt history, revision count), `POST /api/units/:id/accept` (merge branch to main), `POST /api/units/:id/send-back` (rejection with reason), `POST /api/units/:id/patch` (patch request), `GET /api/graph` (dependency graph for visualization), `GET /health` (health check). Uses `DashboardBuilder` from `calxgloss-reports` for data and `GitManager` from `calxgloss-git` for branch operations. `ServerState` holds the repo path; each request reads live Git data. `serve(state, port)` entry point binds to `0.0.0.0:port` for container/remote access.
- **Response types** — `DashboardResponse`, `DependencyGraphResponse`, `UnitResponse`/`UnitResponseInner` (enriched unit detail), `DiffSummary`, `AttemptRecord`, `ActionResponse`, `ServerError` with `IntoResponse` for proper HTTP status codes.
- **Request types** — `SendBackRequest` (reason for send-back), `PatchRequest` (issue description).
- **Actions backend module** (`server::actions`) — `accept_unit()`, `send_back_unit()`, and `request_patch()` integrate human review actions into Git operations and the async translation pipeline.
- **`ActionsState` + `build_router_with_actions()`** — provides shared state and a router builder that wires all three review actions into `calxgloss-git` and `calxgloss-translator`. The existing `build_router()` remains functional with legacy direct-Git paths (backward compatible).
- **Accept action** — merges the unit's branch into `main` via `calxgloss-git::GitManager::accept_branch()` and writes a persistent `re/actions/<unit_id>.json` record.
- **Send-back action** — writes a rejection record to `re/rejections/` and persists the action state.
- **Patch action** — creates a `v{N+1}` branch via `calxgloss-git::next_attempt_branch()`, writes a patch request record to `re/patches/`, and spawns an async retry translation via `tokio::task::spawn`. Git2 objects are safely dropped before the `await` using `catch_unwind`; a fresh `GitManager` is opened post-pipeline to commit the successful result.
- **Accept, send-back, and patch handlers** now delegate to the actions module when `ActionsState` is configured, returning rich `ActionResult` data. The basic router falls back to legacy direct-Git operations.
- **Re-exported from `calxgloss-types`** — the domain data types (`UnitOfWork`, `ReviewDashboard`, `DependencyGraph`, `ReviewStatus`, etc.) are no longer defined locally; this crate re-exports them from `calxgloss-types` so downstream consumers get a single source of truth. The axum server scaffold (behind `server` feature) and tests are preserved.
- Updated test fixtures to use `DependencyNode::new()` and `DependencyNode::with_level()` constructors.
- **Line-by-line diff API** — `GET /api/units/:id/diff` returns structured `DiffFile`/`DiffHunk`/`DiffLine` entries with line-by-line highlighting (addition, deletion, context) between a unit's branch and `main`. Parses raw unified diff output into a JSON representation suitable for client-side rendering.
- **Ghidra context API** — `GET /api/units/:id/ghidra` returns Ghidra analysis data (decompiler pseudo-C, disassembly listing, identified Windows API calls with PAL mappings) loaded from on-disk analysis artifacts. Returns graceful "not found" when no analysis is available.
- **Diff viewer component** — tabbed detail-panel view with "Diff" and "Ghidra Context" tabs. Renders line-by-line diffs with green-highlighted additions, red-highlighted deletions, dual line-number gutter, and hunk-header markers. Shows file rename annotations.
- **Ghidra context viewer** — displays decompiler output in a scrollable code block, disassembly listing with address/instruction columns, and tagged Windows API calls with PAL mappings. Loads metadata (DLL, function name, address) from analysis artifacts.
- **New API response types** — `DiffLineType`, `DiffLine`, `DiffHunk`, `DiffFile`, `DiffResponse`, `GhidraDisasmLine`, `GhidraContext`, `GhidraApiCall`, `GhidraContextResponse`.
- **WebSocket server** (`server::events` module) — `SessionManager` owns a background broadcast loop that fans out `ProgressEvent` instances from a `broadcast::Receiver` to all registered WebSocket clients.
- **`SessionManager::new_with_broadcast()`** — creates a session manager that drives the broadcast loop from an existing broadcast receiver, connecting a `TranslationEvents` channel directly to the WebSocket server without an intermediate `mpsc` bridge.
- **`build_router_with_ws()`** — extension of `build_router()` that mounts the `/api/events/upgrade` WebSocket upgrade route. Carries `SessionManager` as additional axum state (no longer requires `EventsBridge`).
- **`api_events_upgrade()`** — WebSocket upgrade handler that registers the client with the session manager and starts streaming.
- **Dependency-sorted review queue endpoints** — `GET /api/queue` returns the full review queue sorted by dependency order (topological + level tie-breaking), with metadata on total/queued/pending/blocked counts. `GET /api/queue/next` returns the single next unit to review in the "review one at a time" workflow. Both endpoints exclude accepted and merged units; `Blocked` units are flagged in the response.
- **Queue metadata on dashboard** — `GET /api/dashboard` now includes optional `queue_metadata` with total, queued, pending-review, and blocked counts.
- **Queue position on unit detail** — `GET /api/units/:id` now includes `queue_position` (zero-based index in the dependency-sorted queue and total queue size) for each unit. New response types: `QueueMetadata`, `QueuePosition`, `QueueResponse`, `QueueEntry`.
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
- **`[lints.cargo]`** — `unused_dependencies = "allow"` in Cargo.toml to suppress manifest-level warnings on `cfg(feature = "server")` gated optional dependencies (axum, calxgloss-reports, uuid).
- **Debug logging** — WebSocket broadcast loop and client-side JS manager now emit detailed logs (connection lifecycle, event forwarding, client counts) to aid troubleshooting.
- Removed unused `tokio-tungstenite` dependency; the WebSocket implementation uses axum's native `axum[ws]` support instead.
- Added optional dependencies on `calxgloss-translator`, `calxgloss-verify`, `calxgloss-llm`, and `calxgloss-pal` behind the `server` feature for full pipeline integration.
- Fixed axum 0.8 route syntax — all three router builders (`build_router`, `build_router_with_actions`, `build_router_with_ws`) now use `{id}` capture groups instead of the legacy `:id` syntax that caused the server to panic on startup.
- **Static file serving** — `serve_index()` and `static_fallback()` now resolve paths relative to `CARGO_MANIFEST_DIR` instead of the process CWD, so static assets (`index.html`, `app.js`, `app.css`) are served correctly regardless of where the server is launched. `static_fallback()` was rewritten to extract the path from the raw request URI (the old `axum::extract::Path<String>` parameter was incompatible with `fallback_service`, which is why JS and CSS files returned 404).
- Graph view now wraps header buttons in a `.view-controls` div.
- Adds overlay `.graph-controls` div with "Fit" / "Reset" buttons.
- Adds `#zoom-indicator` element for current zoom percentage display.
- **LLM I/O log view** — new "LLM I/O" tab in the web UI that displays a real-time log of LLM requests and responses, with full prompt/response content, DLL/function identifiers, attempt numbers, strategy labels, timestamps, and per-entry truncation (500-char preview with full length). Clear button available.

### `calxgloss-cli`
- **`gc` subcommand** — garbage-collects old translation branches by archiving them. Walks all unmerged `re/*` branches, checks their last commit date, and renames branches older than the staleness threshold (default 7 days) to `refs/archive/re/{dll}/{function}/vN` instead of deleting them. Branches remain reachable for reference. Supports `--days <N>` to set the threshold and `--dry-run` to preview without archiving. Only operates on `re/*` translation branches (skips classify, shim, pal, test, fix, and integration branches).
- **`live` event emission** — creates a shared `TranslationEvents` instance and passes it through `run_translation_for_dll()` so the translation pipeline can stream LLM I/O events to the WebSocket server. `auto` mode passes `None` (no streaming).

### `calxgloss-ghidra`
- Added optional dependency for future GhidraMCP integration behind the `server` feature.
- **Empty cross-reference responses handled gracefully** — `xrefs_to`, `xrefs_from`, and `function_xrefs` treat a 200 with empty body (sent by GhidraMCP when a function has no callers/callees) as valid empty results instead of surfacing a "server returned an empty response" error.

### All crates
- Removed references to implementation phases and steps from doc-comments and inline comments. The planning document (`step_by_step.md`) remains as the planning reference; source comments now describe what the code does, not which phase it came from. Affected crates: `calxgloss-analysis`, `calxgloss-pal`, `calxgloss-prompts`, `calxgloss-reports`, `calxgloss-translator`, `calxgloss-types`.
- Rustfmt reformatting across the workspace: import ordering, struct field layouts, match arms, function signatures, doc comment examples.

### Fixed

#### `calxgloss-git`
- **`merge_to_main` stale main reference** — the method used a cached `main_ref` handle after `repository.reference()` updates main's ref on disk, causing merged branch file changes to be lost on hard reset. Fixed by using `find_reference("refs/heads/main")` directly in both the fast-forward and 3-way merge paths.

#### `calxgloss-config`
- `test_a_missing_optional_file_is_not_an_error` and `test_a_found_file_is_reported` — both tests now temporarily neutralize `HOME`, `XDG_CONFIG_HOME`, and `CALXGLOSS_LLM_MODEL` so a user-global config or shell-profile env var cannot be picked up during test execution, breaking `loaded.is_empty()` and config-precedence assertions.

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
