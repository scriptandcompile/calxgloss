# Call Graph Assisted Translation — Step-by-Step Plan

This plan turns the concepts in `Calxgloss.md` and `call_graph_assisted_translation.md` into an actionable, dependency-ordered checklist. Each step is self-contained, branches from the previous milestone, and can be reviewed independently.

---

## Overview

| Milestone | Scope | Est. Effort | Status |
|-----------|-------|-------------|--------|
| **M0** — Foundations | Data types, new crate skeleton | 2–3 days | ✅ Partial |
| **M1** — Call Graph Extraction | Enhanced caller/callee discovery | 3–4 days | ✅ Partial |
| **M2** — Graph Builder & Persistence | Build adjacency map, persist to JSON | 2–3 days | ✅ Partial |
| **M3** — Root & Leaf Classification | Detect roots, leaves, middle nodes | 3–4 days | ✅ Partial |
| **M3.5** — Runtime Library Detection | RuntimeLibrary category, DLL wiring | 0.5 days | ✅ DONE |
| **M4** — Translation Ordering | Topological sort, priority queue | 2–3 days | ✅ DONE |
| **M5** — Context Enrichment | Call graph data in LLM prompts | 2–3 days | ✅ Partial |
| **M6** — Pipeline Integration | Wire everything into the analysis pipeline | 3–4 days | ✅ DONE |
| **M7** — CLI & Flags | `--no-callgraph`, streaming mode | 1–2 days | ✅ Partial |
| **M8** — Tests & Verification | Unit, integration, manual | 3–4 days | ✅ Partial |

---

## M0 — Foundations (Days 1–3)

### Step 0.1 — Create the `calxgloss-callgraph` Crate ✅ DONE

- New crate at `crates/calxgloss-callgraph/` added to workspace
- Modules: `models`, `builder`, `root_detector`, `leaf_detector`, `ordering`, `persist`, `context`

### Step 0.2 — Define Core Data Types ✅ DONE

In `crates/calxgloss-callgraph/src/models.rs`:
- `CallType` (Direct, Indirect, Virtual, Unknown)
- `CallGraphEdge` (source, target, call_site, call_type, callee_name)
- `FunctionCallGraph` (name, address, callers, callees, node_category)
- `CallGraph` (dll, functions)

**Serialized to JSON with round-trip tests.**

### Step 0.3 — Extend `calxgloss-types` ❌ NOT DONE

In `crates/calxgloss-types/src/function.rs`:
- `NodeCategory` enum exists (Root, Leaf, Middle, Skip)
- `FunctionInfo.call_graph: Vec<String>` exists

**Missing:**
- `callers: Vec<u64>` on `FunctionInfo`
- `callees: Vec<CallGraphEdge>` on `FunctionInfo`
- `call_type: FunctionCategory` on `FunctionInfo`
- `known_runtime: bool` on `FunctionInfo`
- `third_party_calls: Vec<String>` on `FunctionInfo`

The `NodeCategory` and `CallGraph` types live in the callgraph crate but are not woven into `FunctionInfo` in the analysis pipeline.

### Step 0.4 — Add `RuntimeLibrary` to DLL Classification ✅ DONE

In `crates/calxgloss-types/src/dll.rs`:
- `DllCategory` now has: `WindowsOs`, `MicrosoftSdk`, `KnownThirdParty`, `ProjectSpecific`, `UnknownThirdParty`, **`RuntimeLibrary`**
- `DllInfo.known_runtime: bool` field added

Wired into classification pipeline in `calxgloss-analysis/src/classify.rs`:
- `is_runtime_library_dll()` function matches `RootDetector::is_runtime_dll()` patterns
- `classify_dll_name()` checks runtime libraries **first** (highest priority)
- `crate_replacement_for()` returns `None` for runtime libraries

---

## M1 — Call Graph Extraction (Days 4–7)

### Step 1.1 — Improve Ghidra Caller Extraction ✅ DONE

`ghidra.xrefs_to(address)` returns all callers via Ghidra's cross-reference API. Verified working in `CallGraphBuilder`.

### Step 1.2 — Improve Ghidra Callee Extraction (Regex) ✅ DONE

Callees scraped from decompiled pseudo-C via `IDENT(` regex pattern in `CallGraphBuilder::callees_from_decompiled`.

### Step 1.3 — Add Disassembly-Level Indirect Call Detection ❌ NOT DONE

TODO in `builder.rs`:
```rust
// TODO: For indirect calls, scan disassembly for `call [reg]` and `call [rip + offset]`
```
No `indirect_calls()` method exists on `GhidraClient`.

### Step 1.4 — Add Virtual Call Detection ❌ NOT DONE

TODO in `builder.rs`:
```rust
// TODO: For virtual calls, detect `vtable->method()` patterns in decompiled output
```
No vtable detection implemented.

### Step 1.5 — Cross-DLL Import Mapping ❌ NOT DONE

TODO in `builder.rs`:
```rust
// TODO: Add import table analysis: cross-reference with PE imports for more reliable API detection
```
No PE import parsing module exists. The leaf detector relies solely on Ghidra decompiler output.

---

## M2 — Graph Builder & Persistence (Days 8–10)

### Step 2.1 — Call Graph Builder ✅ DONE

In `crates/calxgloss-callgraph/src/builder.rs`:
- `CallGraphBuilder::new(ghidra, dll_name)`
- `CallGraphBuilder::build()` → `CallGraph`
- Builds adjacency from callers (xrefs_to) + callees (decompiled regex)

### Step 2.2 — Persist to JSON ✅ DONE

In `crates/calxgloss-callgraph/src/persist.rs`:
- `CallGraphPersistor::save(&graph)` → `re/analysis/{dll}_call_graph.json`
- Includes DLL name, function nodes with categories, caller/callee data

### Step 2.3 — Incremental Loading ✅ DONE

- `CallGraphPersistor::load(dll_name)` → `Option<CallGraph>`
- `load_call_graph()` convenience function in `callgraph.rs`
- Returns `None` if file doesn't exist

---

## M3 — Root & Leaf Classification (Days 11–14)

### Step 3.1 — Root Pattern Database ✅ DONE (Expanded in Task 13)

In `crates/calxgloss-callgraph/src/root_detector.rs`:
- `RootDetector` with 7 built-in pattern categories
- `ConfigurableRootDetector` for user-defined JSON patterns

**Patterns (all working):**
| Category | Examples |
|----------|----------|
| C/C++ entry | `mainCRTStartup`, `_main`, `WinMain`, `WinMain@16`, `WinMain@20` |
| DLL entry | `DllMain` |
| Ghidra entry | `entry` |
| VB6 | `__vbaInitialize`, `__vbaInit`, `SUBMAIN` |
| .NET CLR | `__managed_main`, `_CorExeMain` |
| MinGW | `_start`, `__libc_start_main` |
| MSVC debug | `_RTC_Initialize` |

### Step 3.2 — Root Detection Algorithm ✅ DONE

`root_detector.is_root(func)` checks name patterns + zero-callers heuristic. Classification runs in `build_enriched_call_graph()`.

### Step 3.3 — API Signature Database ✅ DONE (Expanded in Task 13)

In `crates/calxgloss-callgraph/src/leaf_detector.rs`:
- 100+ API signatures across 10 categories
- Categories: Graphics, GDI, UI, Filesystem, COM, Audio, Network, Crypto, Vulkan, OpenGL

### Step 3.4 — Leaf Detection Algorithm ✅ DONE

`leaf_detector.classify(func)` → `Option<Vec<ApiSignature>>` with fuzzy matching.

### Step 3.5 — Runtime Library Detection ✅ DONE

**Wired into `DllCategory` classification (Step 0.4):**
- `RuntimeLibrary` variant added to `DllCategory` enum
- `DllInfo.known_runtime: bool` field tracks whether a DLL is a runtime library
- `is_runtime_library_dll()` in `calxgloss-analysis/src/classify.rs` uses the same patterns as `RootDetector::is_runtime_dll()`:
  - MSVC runtimes: `msvcr*.dll`
  - VB6 runtime: `msvbvm*.dll`
  - Qt runtimes: `Qt5*.dll`, `Qt6*.dll`
  - SDL2: `SDL2.dll`
- `classify_dll_name()` prioritizes runtime library detection before other categories
- Strategy matching in `analyzer.rs` treats `RuntimeLibrary` as `ReverseEngineer` (skipped during translation)
- Dependency checker excludes runtime libraries from shim layer requirements
- Reports display `"Runtime Library"` for the category

**Tests:** 9 new tests covering MSVC, VB6, Qt, SDL2 detection and classification.

### Step 3.6 — Run Classification on Call Graph ✅ DONE

In `crates/calxgloss-analysis/src/callgraph.rs`:
- `build_enriched_call_graph()` builds, classifies (root/leaf/middle), and persists
- Updates `NodeCategory` on each `FunctionCallGraph`

---

## M4 — Translation Ordering (Days 15–17)

### Step 4.1 — Translation Priority Enum ✅ DONE

In `crates/calxgloss-callgraph/src/ordering.rs`:
- `TranslationPriority` (Root=0, Middle=1, Leaf=2)
- `From<NodeCategory>` impl maps Skip→Root

### Step 4.2 — Topological Sort ✅ DONE

- Kahn's algorithm per tier
- Cycles resolved by appending in address order
- Duplicate address detection returns error

### Step 4.3 — Priority-Aware Sort ✅ DONE (in crate, not wired)

`TranslationOrderer::order(&graph)` → `VecDeque<FunctionTranslationPlan>`:
1. Groups by priority tier (Root → Middle → Leaf)
2. Topological sort within each tier
3. Returns plans with caller/callee counts and names

### Step 4.4 — Batch Planning ✅ DONE

**Implemented in `calxgloss-translator`:**
- `TranslationPipeline::plan_from_callgraph()` method added (`pipeline.rs`)
  - Takes a `CallGraph` and optional `max_functions` limit
  - Uses `TranslationOrderer` internally to produce `Vec<FunctionTranslationPlan>`
  - Returns `Result<Vec<FunctionTranslationPlan>>` with priority-ordered functions
- Added `TranslatorError::CallGraph(String)` variant for planning errors
- Added `calxgloss-callgraph` dependency to `calxgloss-translator/Cargo.toml`

The `TranslationOrderer` is now wired into the batch translation pipeline via the `TranslationPipeline` struct. Consumers can call `plan_from_callgraph(&call_graph, max)` to get a priority-ordered list of functions (Root → Middle → Leaf) for batch translation.

**Tests:** 3 new tests in `lib.rs` — empty graph, three-tier ordering with topological sort, and max-functions truncation.

---

## M5 — Context Enrichment (Days 18–20)

### Step 5.1 — Call Graph Context in Prompt Templates ✅ DONE

In `crates/calxgloss-prompts/src/templates.rs`:
- `call_graph_context: Vec<FunctionContext>` field on all prompt data structs
- Template rendering for callers, callees, leaf API context

### Step 5.2 — Context Enrichment Logic ✅ DONE

`ContextEnricher` in `crates/calxgloss-callgraph/src/context.rs` is now wired into production:

- `TranslationPipeline::translate()` builds an enriched call graph via `Analyzer::build_call_graph()` and uses `ContextEnricher::enrich()` to produce `Vec<FunctionContext>`.
- The enriched context is passed to all prompt data constructors that support it: `WithTestsPromptData`, `ModuleContextPromptData`, and `FullModulePromptData`.
- `EscalatePromptCtx` carries the stored `call_graph_context` from the initial `Translation` into escalation retries.
- `Translator` and `retry/helpers.rs::build_escalated_prompt()` populate `call_graph_context` from the stored data.
- `build_escalate_prompt_with_context()` in the prompts crate renders enriched context in escalation prompts.

All templates (`escalate.j2`, `with_tests_translate.j2`, `module_context_translate.j2`, `full_module_translate.j2`) already had rendering logic for the `call_graph_context` field.

### Step 5.3 — Caller/Callee Limiting ✅ DONE

**Implemented in `crates/calxgloss-callgraph/src/context.rs`:**

Added `ContextEnricherConfig` with configurable options for limiting enrichment data:

| Option | Default | Description |
|--------|---------|-------------|
| `max_callers` | 10 | Top-N limit on callers per function context (0 = no limit) |
| `max_callees` | 50 | Top-N limit on callees per function context (0 = no limit) |
| `filter_internal_callees` | true | When true, excludes callees that exist as nodes in the same call graph |
| `max_neighbor_count` | 200 | If total callers + callees exceeds this, enrichment is skipped entirely |

Added `ContextEnricher::with_config()` constructor for custom configuration.

**New types and functions exported from `context` module:**
- `ContextEnricherConfig` — configuration struct with public fields
- `skipped_contexts()` — utility to collect contexts where `context_skipped` is `true`

**`FunctionContext` extended with `context_skipped: bool` field** — indicates when a function's context was skipped due to exceeding the neighbor count threshold.

**Behavior:**
1. Size-based skip is checked on raw neighbor counts before limiting/filtering, ensuring functions with too many neighbors produce minimal context
2. Internal callee filtering removes callees whose addresses exist in the same call graph, keeping only external API calls
3. Top-N limiting truncates caller/callee lists to the configured maximum
4. When a function is skipped, all context fields (callers, callees, categorized_callees, leaf_api_context) are empty, and `context_skipped` is `true`

**Tests:** 12 new tests covering top-N caller/callee limiting, internal callee filtering, size-based skipping, skipped contexts helper, and default config values.

---

## M6 — Pipeline Integration (Days 21–24)

### Step 6.1 — Call Graph in `calxgloss-analysis` ✅ PARTIALLY DONE

- `build_enriched_call_graph()` exists and works
- `load_call_graph()` exists for cached loading
- **Missing:** Not integrated into `Analyzer::analyze_dlls()` pipeline. Requires a manual call to `build_call_graph()` on the `Analyzer`.

### Step 6.2 — Wire Call Graph to Dependency Tracker ✅ DONE

In `crates/calxgloss-analysis/src/callgraph.rs`:
- `build_dependency_graph_from_call_graph(classifications, call_graph)` → `DependencyGraph`
- Creates DLL classification nodes, shim layer nodes, function nodes
- Adds dependency edges based on call graph callee edges
- 8 unit tests, all passing

### Step 6.3 — Wire Call Graph to Translator ✅ DONE

**Implemented in `calxgloss-translator`:**

- `TranslationPipeline::with_call_graph(graph)` builder method added — attaches a pre-built `CallGraph` for reuse across all translations, avoiding redundant analysis
- `TranslationPipeline::translate()` refactored — builds the enriched call graph once per function call (using pre-built graph when available) and reuses it for all context tiers (WithTests, ModuleContext, FullModule)
- `extract_call_graph_neighbors_from_enriched()` helper added in `retry/helpers.rs` — extracts neighbor info directly from enriched `FunctionContext` data instead of performing expensive Ghidra name lookups
- `TranslationPipeline::batch_translate_from_callgraph(graph, config, verifier, callback)` method added — priority-ordered batch translation that:
  - Uses `TranslationOrderer` to derive a callee-before-caller translation order
  - Automatically skips root functions (entry points) with `FunctionResult::skipped`
  - Calls `try_translate_with_retry` for each function in priority order
- `FunctionResult::skipped()` constructor added to `batch` module
- `BatchTranslationResult::skipped_count()` method added

**Before:** `call_graph_context` was populated, but `translate()` rebuilt the entire call graph from Ghidra on each context tier. `batch_translate()` accepted an arbitrary function list without call-graph ordering.

**After:** The call graph is built once per `translate()` call and reused across all tiers. Neighbor extraction uses enriched context data directly. `batch_translate_from_callgraph()` uses `TranslationOrderer` for priority-ordered, callee-first translation.

### Step 6.4 — Stub Root Functions ✅ DONE

**Implemented in `calxgloss-translator`:**

- `NodeCategory` field added to `FunctionTranslationPlan` — carries the full classification so the pipeline can distinguish between entry points (`Root`) and runtime library functions (`Skip`), both of which map to `TranslationPriority::Root`.
- `TranslationPipeline::generate_stub(name, signature)` — generates minimal stub implementations for root functions. Handles common entry points (`mainCRTStartup`, `WinMain`, `DllMain`, `__vba*`, `FUN_*`), returning appropriate placeholder code with the function signature as a comment.
- `FunctionResult` extended with `stub_code: Option<String>` field and `FunctionResult::stubbed(dll, function, stub_code)` constructor.
- `BatchTranslationResult::stub_count()` — counts stubbed functions (separate from skipped). `skipped_count()` refined to exclude stubbed results.
- `batch_translate_from_callgraph()` updated — Root functions are now stubbed (via `generate_stub`) instead of skipped. `Skip`-category functions (runtime library) are still skipped with `FunctionResult::skipped()`.

---

## M7 — CLI & Flags (Days 25–26)

### Step 7.1 — Add `--no-callgraph` Flag ✅ DONE (Task 12)

Available on `translate`, `batch-translate`, `auto`, and `live` subcommands. Returns empty call graph when set.

### Step 7.2 — Add `--callgraph-cache` Flag ✅ DONE (Task 14)

Added `--callgraph-cache` flag to `translate`, `batch-translate`, `auto`, and `live` subcommands.
- `CallGraphPersistor::with_cache_dir()` constructor allows explicit cache path
- `CallGraphPersistor::new()` still defaults to `{workspace_root}/re/analysis/` for backward compatibility
- `build_enriched_call_graph()` and `load_call_graph()` accept optional `cache_dir` parameter
- `TranslationPipeline::with_callgraph_cache_dir()` builder method threads cache dir through the pipeline
- Default path remains `re/analysis/{dll}_call_graph.json` when flag is not specified

### Step 7.3 — Add `--callgraph-verbose` Flag ✅ DONE

Added `--callgraph-verbose` flag to `translate`, `batch-translate`, `auto`, and `live` subcommands.

When set, prints a formatted call graph statistics box after building the graph:
- Total function count
- Root / Middle / Leaf / Skip distribution
- Total edge count
- Call-type breakdown (Direct / Indirect / Virtual)
- Number of unique external APIs
- Average callees per function

Implementation:
- `print_call_graph_stats()` in `calxgloss-analysis/src/callgraph.rs` computes and prints statistics
- `with_callgraph_verbose()` builder method on `TranslationPipeline`
- Stats are printed in `translate()` after the call graph is built or loaded for context enrichment

---

## M8 — Tests & Verification (Days 27–30)

### Step 8.1 — Unit Tests for Call Graph Construction ✅ DONE

7 tests in `builder.rs` covering callee parsing, caller name mapping, empty input, edge types.

### Step 8.2 — Unit Tests for Root Detection ✅ DONE

17 tests covering all 7 pattern categories, configurable patterns, runtime DLL detection, plus 9 additional tests for runtime library classification in `calxgloss-analysis`.

### Step 8.3 — Unit Tests for Leaf Detection ✅ DONE

30 tests covering all 10 categories, fuzzy matching (A/W suffixes, stdcall, DLL-qualified), transitive analysis.

### Step 8.4 — Unit Tests for Translation Ordering ✅ DONE

12 tests covering priority ordering, topological sort, cycle handling, max functions truncation.

### Step 8.5 — Integration Test: End-to-End on Test DLL ✅ DONE

**Implemented in `crates/calxgloss-callgraph/tests/integration_tests.rs`:**

- `test_end_to_end_realistic_plugin_pipeline()` — comprehensive end-to-end test on a synthetic `game_plugin.dll` call graph that mimics a real DirectX rendering plugin.
- Exercises the full pipeline: graph construction → root/leaf classification → persistence round-trip → context enrichment → translation ordering → dependency graph construction.
- The synthetic graph contains 9 functions across a realistic hierarchy: `DllMain` → `Initialize`/`Cleanup` → `Setup` → `Render` → `Draw`/`UpdateParticles`/`PollInput`.
- Validates all invariants: category classification, caller/callee preservation after serialization, context enrichment correctness, priority-ordered translation plans, and dependency graph topological ordering.

### Step 8.6 — Integration Test: Context Quality ❌ NOT DONE

- No comparison of translation output with/without call graph context
- No LLM quality evaluation

### Step 8.7 — Manual Testing on Real Binaries ❌ NOT DONE

- Not tested on VB6, DirectX, or large DLL binaries
- No performance benchmarks (build time, memory usage)

---

## Summary

### Completed (~65%)

| Category | Details |
|----------|---------|
| **Crate + types** | `calxgloss-callgraph` crate with full type system |
| **Builder + persistence** | Ghidra extraction, JSON save/load, incremental loading |
| **Root detection** | 7 pattern categories + configurable rules + runtime DLL detection |
| **Leaf detection** | 100+ APIs, 10 categories, fuzzy matching, transitive analysis |
| **Translation ordering** | Priority tiers + topological sort (exists in crate) |
| **Batch planning** | `TranslationPipeline::plan_from_callgraph()` wires `TranslationOrderer` into the translator |
| **Batch translation** | `batch_translate_from_callgraph()` uses call-graph ordering for priority-ordered batch translation |
| **Dependency graph** | `build_dependency_graph_from_call_graph` with 8 tests |
| **Prompt templates** | `call_graph_context` fields on all templates |
| **Context enrichment wiring** | `ContextEnricher` called from `TranslationPipeline::translate()`, `retry/helpers.rs`, and `Translator` |
| **CLI flag** | `--no-callgraph`, `--callgraph-cache`, `--callgraph-verbose` on all subcommands |
| **Runtime library** | `RuntimeLibrary` DLL category with classification and skip logic |
| **Tests** | 104 unit tests + 5 integration tests across all modules |

### Not Yet Done (~32%)

| Category | Blockers |
|----------|----------|
| **`calxgloss-types` extension** | `FunctionInfo` needs callers/callees/known_runtime/third_party_calls fields |
| **Indirect call detection** | Disassembly scan for `call [reg]` patterns |
| **Virtual call detection** | Vtable pattern matching in decompiler output |
| **Cross-DLL import mapping** | PE import table parsing |
| **Pipeline integration** | `Analyzer` calls `build_enriched_call_graph` automatically |
| **Real-binary testing** | Manual validation on VB6, DirectX, large DLLs |

### Priority Order for Remaining Work

1. **Pipeline integration** (M6.1) — The most impactful: makes the call graph actually affect translation
2. **Types extension** (M0.3) — `FunctionInfo` needs richer call graph data
3. **Context enrichment** (M5.2) — Remaining context rendering in templates
4. **Advanced extraction** (M1.3, M1.4, M1.5) — Nice-to-have accuracy improvements
5. **Real-binary testing** (M8.5–8.7) — Validation before production
