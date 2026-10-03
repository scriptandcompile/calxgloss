# Call Graph Assisted Translation — Step-by-Step Plan

This plan turns the concepts in `Calxgloss.md` and `call_graph_assisted_translation.md` into an actionable, dependency-ordered checklist. Each step is self-contained, branches from the previous milestone, and can be reviewed independently.

---

## Overview

| Milestone | Scope | Est. Effort | Branch prefix |
|-----------|-------|-------------|---------------|
| **M0** — Foundations | Data types, new crate skeleton | 2–3 days | `re/callgraph/m0-foundations` |
| **M1** — Call Graph Extraction | Enhanced caller/callee discovery | 3–4 days | `re/callgraph/m1-extraction` |
| **M2** — Graph Builder & Persistence | Build adjacency map, persist to JSON | 2–3 days | `re/callgraph/m2-persist` |
| **M3** — Root & Leaf Classification | Detect roots, leaves, middle nodes | 3–4 days | `re/callgraph/m3-classify` |
| **M4** — Translation Ordering | Topological sort, priority queue | 2–3 days | `re/callgraph/m4-ordering` |
| **M5** — Context Enrichment | Call graph data in LLM prompts | 2–3 days | `re/callgraph/m5-context` |
| **M6** — Pipeline Integration | Wire everything into the analysis pipeline | 3–4 days | `re/callgraph/m6-integration` |
| **M7** — CLI & Flags | `--no-callgraph`, streaming mode | 1–2 days | `re/callgraph/m7-cli` |
| **M8** — Tests & Verification | Unit, integration, manual | 3–4 days | `re/callgraph/m8-tests` |

---

## M0 — Foundations (Days 1–3)

### Step 0.1 — Create the `calxgloss-callgraph` Crate

- Add a new crate to the workspace root `Cargo.toml`
- Directory: `crates/calxgloss-callgraph/`
- Minimal `lib.rs` with module declarations:
  - `mod models;`
  - `mod builder;`
  - `mod root_detector;`
  - `mod leaf_detector;`
  - `mod ordering;`
- Dependencies: `serde`, `serde_json`, `regex`, `thiserror`

### Step 0.2 — Define Core Data Types

In `crates/calxgloss-callgraph/src/models.rs`:

```rust
pub enum CallType {
    Direct,
    Indirect,
    Virtual,
    Unknown,
}

pub struct CallGraphEdge {
    pub source: u64,       // function entry address
    pub target: u64,       // target function address or 0 for external symbols
    pub call_site: u64,    // instruction address of the call
    pub call_type: CallType,
    pub symbol: Option<String>,  // function name for cross-DLL calls
}

pub enum FunctionCategory {
    Root,
    Leaf,
    Middle,
    Skip,
}

pub struct FunctionNode {
    pub name: String,
    pub address: u64,
    pub callers: Vec<u64>,
    pub callees: Vec<CallGraphEdge>,
    pub category: FunctionCategory,
    pub known_runtime: bool,
    pub third_party_calls: Vec<String>,
}

pub struct CallGraph {
    pub dll: String,
    pub functions: Vec<FunctionNode>,
    pub adjacency: HashMap<u64, Vec<u64>>,  // source -> targets
}
```

**Success criteria:** Types compile. Serialization to JSON works (round-trip test).

### Step 0.3 — Extend `calxgloss-types`

In `crates/calxgloss-types/src/dll.rs`:
- Add `RuntimeLibrary` variant to `DllCategory` enum.

In `crates/calxgloss-types/src/function.rs`:
- Add fields to `FunctionAnalysis`:
  - `pub callers: Vec<u64>`
  - `pub callees: Vec<CallGraphEdge>` (re-exported from callgraph crate)
  - `pub call_type: FunctionCategory`
  - `pub known_runtime: bool`
  - `pub third_party_calls: Vec<String>`

**Success criteria:** Types compile. Existing code that constructs `FunctionAnalysis` still compiles (add `Default` or constructor helpers).

### Step 0.4 — Add `RuntimeLibrary` to DLL Classification

In the DLL classification pipeline (likely in `calxgloss-analysis` or `calxgloss`):
- Detect known runtime DLLs (`msvcr*.dll`, `ucrtbase.dll`, `msvbvm60.dll`, `Qt5Core.dll`, `python3*.dll`, etc.)
- Classify them as `DllCategory::RuntimeLibrary`

**Success criteria:** A test binary whose import table contains a known runtime DLL is classified correctly.

---

## M1 — Call Graph Extraction (Days 4–7)

### Step 1.1 — Improve Ghidra Caller Extraction

In `crates/calxgloss-ghidra/src/lib.rs`:
- Verify `xrefs_to(address)` returns all callers (it already does via Ghidra's cross-reference API)
- Add a new method: `callers_at_address(address: u64) -> Result<Vec<u64>>`
- Test with a known DLL: verify callers are returned correctly

**Success criteria:** For a test DLL with 5 functions where F1 calls F2, querying callers of F2 returns F1's address.

### Step 1.2 — Improve Ghidra Callee Extraction (Regex)

Current state: callees are scraped from decompiled pseudo-C via `IDENT(` regex pattern.

In `crates/calxgloss-ghidra/src/lib.rs`:
- Add a new method: `callees_enhanced(address: u64) -> Result<Vec<CallGraphEdge>>`
- Improve regex patterns:
  - Match `IDENT(args...)` more broadly (not just `IDENT(`)
  - Match `result = IDENT(args)` (assignment form)
  - Match `return IDENT(args)` (return form)
  - Exclude local function names (functions defined in the same DLL with no import entry)
- Tag all matches as `CallType::Unknown` (conservative)

**Success criteria:** For a test DLL, the enhanced scraper finds 20%+ more callees than the regex-only version.

### Step 1.3 — Add Disassembly-Level Indirect Call Detection

In `crates/calxgloss-ghidra/src/lib.rs`:
- Add a method: `indirect_calls(address: u64) -> Result<Vec<CallGraphEdge>>`
- Scan disassembly for:
  - `call [reg]` patterns (x86 register-indirect)
  - `call [rip + offset]` patterns ( RIP-relative)
  - `call [rax]`, `call [rbx]`, etc.
- Tag these as `CallType::Indirect`
- Extract the register or offset as metadata

### Step 1.4 — Add Virtual Call Detection

In `crates/calxgloss-ghidra/src/lib.rs`:
- Scan decompiled output for `vtable->method()` patterns
- Tag as `CallType::Virtual`
- Extract method name and vtable type if parseable

### Step 1.5 — Cross-DLL Import Mapping

In `crates/calxgloss-ghidra/src/lib.rs` or a new `crates/calxgloss-pe/` module:
- Parse the PE import table of the target binary/DLL
- Build a map: `import_name -> (dll_name, original_name)`
- Use this map to classify callees:
  - If a callee name exists in the import table, tag it with the originating DLL
  - This is how we know `eqmain.dll` calls `d3d9.dll`

**Success criteria:** For a test binary importing `Direct3DCreate9` from `d3d9.dll`, the import map correctly associates the name with its DLL.

---

## M2 — Graph Builder & Persistence (Days 8–10)

### Step 2.1 — Call Graph Builder

In `crates/calxgloss-callgraph/src/builder.rs`:

```rust
pub struct CallGraphBuilder {
    ghidra: GhidraClient,
}

impl CallGraphBuilder {
    pub fn build(&self, dll_name: &str) -> Result<CallGraph>
    // 1. Enumerate all functions via Ghidra
    // 2. For each function, fetch callers + callees
    // 3. Build adjacency map
    // 4. Return CallGraph
}
```

Implementation:
- Use the Ghidra client's function enumeration API
- For each function, call `callers_at_address` and `callees_enhanced`
- Aggregate into `CallGraph` struct
- Deduplicate edges

**Success criteria:** Building a call graph for a test DLL with 50 functions completes in under 60 seconds.

### Step 2.2 — Persist to JSON

In `crates/calxgloss-callgraph/src/builder.rs`:
- Add method: `save_to_file(&self, graph: &CallGraph, path: &Path) -> Result<()>`
- Serialize `CallGraph` to `re/analysis/call_graph.json`
- Include: DLL name, function nodes, adjacency, categories

Persisted format:
```json
{
  "dll": "LaunchPad.exe",
  "functions": [
    {
      "name": "main",
      "address": 4198400,
      "callers": [],
      "callees": [{"target": 4198912, "call_type": "Direct", "symbol": "init_app"}],
      "category": "Root",
      "known_runtime": false,
      "third_party_calls": [],
      "call_site": 4198450
    },
    ...
  ],
  "adjacency": {
    "4198400": [4198912],
    "4198912": [4199500]
  }
}
```

**Success criteria:** A persisted graph file can be loaded back and matches the in-memory graph.

### Step 2.3 — Incremental Loading

In `crates/calxgloss-callgraph/src/builder.rs`:
- Add method: `load_from_file(path: &Path) -> Result<CallGraph>`
- If a call graph file already exists, load it instead of rebuilding
- Add a timestamp or hash to detect staleness when the DLL changes

**Success criteria:** Loading a persisted graph is instantaneous (sub-millisecond).

---

## M3 — Root & Leaf Classification (Days 11–14)

### Step 3.1 — Root Pattern Database

In `crates/calxgloss-callgraph/src/root_detector.rs`:

```rust
pub struct RootDetector {
    patterns: Vec<RootPattern>,
}

pub struct RootPattern {
    pub name_regex: regex::Regex,
    pub description: &'static str,
    pub action: RootAction,
}

pub enum RootAction {
    Skip,
    GenerateStub,
    Translate,
}
```

Patterns to include:

| Regex | Description | Action |
|-------|-------------|--------|
| `mainCRTStartup` | MSVC CRT entry | Skip |
| `_main` | MSVC C entry | Translate |
| `WinMain@[\d]+` | WinMain with decorations | Skip |
| `WinMain` | MinGW WinMain | Skip |
| `__vbaInitialize` | VB6 init | Skip |
| `__vbaInit` | VB6 init short | Skip |
| `DllMain` | DLL entry | Skip |
| `SUBMAIN` | VB6 SUB entry | Skip |
| `__wine_start` | Wine loader | Skip |
| `__managed_main` | .NET CLR | Skip |

### Step 3.2 — Root Detection Algorithm

In `root_detector.rs`:
- For each function node:
  1. Check name against all `RootPattern` regexes
  2. If no regex match, check if function has zero callers (potential entry point)
  3. If no regex match and has callers, check if it calls any known runtime init function
  4. Return `FunctionCategory::Root` or `FunctionCategory::Middle`

**Success criteria:** For a test DLL, `WinMain` is classified as Root, `mainCRTStartup` as Skip, and `init_app` (called by WinMain) as Middle.

### Step 3.3 — API Signature Database

In `crates/calxgloss-callgraph/src/leaf_detector.rs`:

```rust
pub struct ApiSignature {
    pub name: String,
    pub dll: Option<String>,
    pub rust_crate: String,
    pub category: LeafCategory,
}
```

Initial signatures (curated list — expand iteratively):

| Name | DLL | Crate | Category |
|------|-----|-------|----------|
| `Direct3DCreate9` | `d3d9.dll` | `wgpu` | Graphics |
| `Direct3DCreate8` | `d3d8.dll` | `wgpu` | Graphics |
| `CreateDXGIFactory` | `dxgi.dll` | `wgpu` | Graphics |
| `BeginPaint` | `user32.dll` | `egui` | Graphics |
| `CreateCompatibleDC` | `gdi32.dll` | `tiny-skia` | Graphics |
| `MessageBoxA` | `user32.dll` | `egui` | GUI |
| `CreateWindowExA` | `user32.dll` | `winit` | GUI |
| `CreateFileA` | `kernel32.dll` | `std::fs` | File I/O |
| `ReadFile` | `kernel32.dll` | `std::io` | File I/O |
| `WriteFile` | `kernel32.dll` | `std::io` | File I/O |
| `CoInitialize` | `ole32.dll` | `windows` | COM |
| `CoUninitialize` | `ole32.dll` | `windows` | COM |
| `FMOD_StudioSystem_Create` | `fmod.dll` | `fmod-rs` | Audio |
| `alutInit` | `openal32.dll` | `cpal` | Audio |
| `WSAStartup` | `ws2_32.dll` | `tokio` | Network |
| `socket` | `ws2_32.dll` | `tokio` | Network |
| `CryptAcquireContextA` | `advapi32.dll` | `ring` | Crypto |

### Step 3.4 — Leaf Detection Algorithm

In `leaf_detector.rs`:
- For each function node:
  1. For each callee, check if the symbol matches any `ApiSignature`
  2. If matched, tag the function as `FunctionCategory::Leaf`
  3. Record the matching APIs in `third_party_calls`
  4. Store the `LeafCategory` for context enrichment

**Success criteria:** For a test DLL, a function calling `Direct3DCreate9` is classified as Leaf with `third_party_calls = ["Direct3DCreate9"]`.

### Step 3.5 — Runtime Library Detection

In `root_detector.rs` (or a new `runtime_detector.rs`):
- Build a list of known runtime DLLs:
  - CRT: `msvcr*.dll`, `msvcp*.dll`, `ucrtbase.dll`
  - VB6: `msvbvm60.dll`
  - .NET: `mscorwks.dll`, `clr.dll`
  - Qt: `Qt5Core.dll`, `Qt5Gui.dll`, `Qt5Widgets.dll`
  - Python: `python3*.dll`
  - Lua: `lua5*.dll`
  - SDL: `SDL2.dll`, `SDL2_main.dll`
- When a DLL is classified as `RuntimeLibrary`, tag all its functions as `known_runtime = true`

**Success criteria:** A function in `msvbvm60.dll` is tagged `known_runtime = true`.

### Step 3.6 — Run Classification on Call Graph

In `builder.rs`:
- After building the graph, run `RootDetector` and `LeafDetector` on all nodes
- Assign each node a `category`
- Set `known_runtime` based on DLL classification
- Populate `third_party_calls` from leaf detection

**Success criteria:** A complete call graph for a test DLL has all nodes classified, with correct categories.

---

## M4 — Translation Ordering (Days 15–17)

### Step 4.1 — Translation Priority Enum

In `crates/calxgloss-callgraph/src/ordering.rs`:

```rust
pub enum TranslationPriority {
    Skip,        // Skip entirely (runtime entry points)
    Root,        // Translate/skip first to understand initialization
    Middle,      // Translate in topological order
    Leaf,        // Translate last, with full dependency context
}
```

### Step 4.2 — Topological Sort

In `ordering.rs`:
- Implement a topological sort over the call graph's adjacency map
- Only consider edges within the same DLL (cross-DLL edges are resolved via import table)
- For functions with cycles (e.g., mutual recursion), break ties by:
  1. Higher call count first (more called functions are dependencies)
  2. Alphabetical name tiebreak

```rust
pub fn topological_sort(graph: &CallGraph) -> Result<Vec<u64>>
// Returns addresses in translation-ready order
```

**Success criteria:** For a test graph with 10 functions and known call edges, the sort produces a valid topological ordering (no function appears before any function it calls).

### Step 4.3 — Priority-Aware Sort

```rust
pub fn priority_sort(graph: &CallGraph) -> Result<Vec<FunctionPlan>>
// 1. Sort by priority: Skip > Root > Middle > Leaf
//    (Skip first so we know what to exclude; Root first for init understanding; Leaf last)
// 2. Within each priority, use topological sort
// 3. Functions with no edges fall back to discovery order
```

Return `FunctionPlan` objects that include:
- Function address and name
- Priority
- Caller count (for context relevance)
- Callee count
- Known third-party calls list

**Success criteria:** The priority sort produces an ordering where all Skip functions come first (to be excluded), then Root, then Middle (topologically sorted), then Leaf.

### Step 4.4 — Batch Planning

In `crates/calxgloss-translator/src/batch.rs`:
- Add a new method: `plan_from_callgraph(graph: &CallGraph) -> Result<Vec<FunctionPlan>>`
- This replaces the current discovery-order plan with the call-graph-aware plan
- Accepts an optional `--no-callgraph` flag to fall back to discovery order

**Success criteria:** The translation batch uses call-graph-based ordering by default.

---

## M5 — Context Enrichment (Days 18–20)

### Step 5.1 — Call Graph Context in Prompt Templates

In `crates/calxgloss-prompts/src/lib.rs`:
- Add a new prompt section template:

```
## Call Graph Context

**Called by:**
{callers}

**Calls:**
{callees}

**Translation Guidance:**
{guidance}
```

Where:
- `{callers}` lists function names (top 5 by call frequency or all if < 10)
- `{callees}` lists third-party API calls with translation hints:
  - `Direct3DCreate9 (d3d9.dll → use wgpu)`
  - `CreateFileA (kernel32.dll → use std::fs)`
- `{guidance}` is auto-generated based on callee categories:
  - If any callee is in `LeafCategory::Graphics`: "This function uses graphics APIs. Use wgpu for 3D rendering, tiny-skia for 2D."
  - If any callee is in `LeafCategory::Audio`: "This function uses audio APIs. Use cpal or rodio."
  - If any callee is in `LeafCategory::COM`: "This function uses COM. Use the windows crate for COM operations."

### Step 5.2 — Context Enrichment Logic

In `crates/calxgloss-callgraph/src/ordering.rs` or a new `context.rs`:
- Build the enrichment text for a given `FunctionNode`:
  1. Look up caller names from the graph
  2. Look up callee third-party calls with their API signatures
  3. Generate translation guidance based on categories
- Return a `ContextEnvelope` struct that the translator can inject into prompts

### Step 5.3 — Caller/Callee Limiting

To avoid context window bloat:
- Limit callers to top-5 (by how many times they appear in the graph)
- Limit callees to only third-party APIs (not internal DLL functions)
- Skip enrichment for functions with 0 callers and 0 third-party callees

**Success criteria:** A function prompt with call graph context is 2–5x larger than without, but stays under 50% of the LLM's context window.

---

## M6 — Pipeline Integration (Days 21–24)

### Step 6.1 — Call Graph in `calxgloss-analysis`

In `crates/calxgloss-analysis/src/lib.rs`:
- Add a new analysis phase: `AnalyzePhase::CallGraph`
- After DLL classification (which populates `DllCategory`), run call graph analysis
- Store the `CallGraph` in the analysis results alongside DLL classification and function analysis

```rust
pub struct AnalysisResults {
    pub dll_classification: Vec<DllClassification>,
    pub call_graph: Option<CallGraph>,
    pub function_analyses: Vec<FunctionAnalysis>,
    pub dependency_tracker: DependencyTracker,
}
```

### Step 6.2 — Wire Call Graph to Dependency Tracker

In `crates/calxgloss-analysis/src/dependency.rs`:
- Add call graph edges to the dependency tracker's edge list
- Tag edges with call type (`Direct`, `Indirect`, `Virtual`)
- Use these edges for dependency-aware branch creation

### Step 6.3 — Wire Call Graph to Translator

In `crates/calxgloss-translator/src/lib.rs`:
- When processing a batch of functions:
  1. Load the call graph (from persistence or rebuild)
  2. For each function, look up its `FunctionPlan`
  3. Inject call graph context into the LLM prompt
  4. Respect the planned translation order

### Step 6.4 — Skip Runtime Functions

In `crates/calxgloss-translator/src/lib.rs`:
- Before translating a function, check:
  - `FunctionCategory == Skip` → skip entirely (do not create a translation unit)
  - `known_runtime == true` → skip entirely (handled by crate replacement)
  - `FunctionCategory == Root` with `RootAction::Skip` → skip
  - `FunctionCategory == Root` with `RootAction::GenerateStub` → generate minimal stub
  - `FunctionCategory == Root` with `RootAction::Translate` → translate normally

**Stub generation** (for CRT/VB6 entry points):
- For `mainCRTStartup`: generate a stub that calls the user's `main` function
- For `__vbaInitialize`: generate an empty stub (VB6 runtime replacement handles init)
- For `WinMain`: generate a stub that delegates to the translated application entry

**Success criteria:** A VB6 application's `__vbaInitialize` function is skipped; a C++ application's `WinMain` is skipped; an application's custom `init_app` function is translated.

---

## M7 — CLI & Flags (Days 25–26)

### Step 7.1 — Add `--no-callgraph` Flag

In `crates/calxgloss-cli/src/main.rs`:
- Add CLI flag: `--no-callgraph` (or `--skip-callgraph`)
- When set:
  - Skip call graph analysis entirely
  - Fall back to discovery-order translation
  - No call graph context in prompts
  - No root/leaf classification

### Step 7.2 — Add `--callgraph-cache` Flag (Optional)

In `crates/calxgloss-cli/src/main.rs`:
- Add: `--callgraph-cache <path>` to specify where call graph JSON is stored
- Default: `re/analysis/call_graph.json` relative to the project root

### Step 7.3 — Add `--callgraph-verbose` Flag (Optional)

In `crates/calxgloss-cli/src/main.rs`:
- Add: `--callgraph-verbose` to print call graph statistics during analysis:
  - Total functions
  - Root count
  - Leaf count
  - Middle count
  - Skip count
  - Build time

**Success criteria:** Running with `--no-callgraph` produces the same behavior as before this entire project.

---

## M8 — Tests & Verification (Days 27–30)

### Step 8.1 — Unit Tests for Call Graph Construction

In `crates/calxgloss-callgraph/src/builder.rs` (test module):
- Create synthetic `CallGraph` structs manually
- Verify serialization/deserialization round-trips
- Verify adjacency map is built correctly from function nodes

### Step 8.2 — Unit Tests for Root Detection

In `crates/calxgloss-callgraph/src/root_detector.rs`:
- Test each `RootPattern` against known entry point names
- Verify correct `RootAction` is returned for each
- Test zero-caller detection

### Step 8.3 — Unit Tests for Leaf Detection

In `crates/calxgloss-callgraph/src/leaf_detector.rs`:
- Test each `ApiSignature` against known function names
- Verify `third_party_calls` is populated correctly
- Test cross-category detection (e.g., a function calling both GDI and COM)

### Step 8.4 — Unit Tests for Translation Ordering

In `crates/calxgloss-callgraph/src/ordering.rs`:
- Test topological sort on a DAG with known ordering
- Test priority sort produces correct priority ordering
- Test cycle handling (mutual recursion)
- Test functions with no edges fall back to discovery order

### Step 8.5 — Integration Test: End-to-End on Test DLL

Create a test DLL (`crates/calxgloss-callgraph/tests/test_data/`):
- A small DLL with ~20 functions
- Mix of: entry points, leaf callers, middle functions, indirect calls
- Run the full pipeline:
  1. Build call graph
  2. Classify nodes
  3. Generate translation order
  4. Verify order is correct

### Step 8.6 — Integration Test: Context Quality

- Run the same translation task with and without call graph context
- Compare prompt sizes
- (Optional) Have an LLM evaluate translation quality with a scoring rubric:
  - Correct API mapping
  - Correct type usage
  - Correct control flow

### Step 8.7 — Manual Testing

Run on real binaries:
1. **CRT application**: A simple C/C++ app compiled with MSVC (test root detection)
2. **VB6 application**: Test `msvbvm60.dll` classification and VB6 init skipping
3. **DirectX application**: Test leaf detection for Direct3D calls, verify wgpu context guidance
4. **Large DLL**: A DLL with 1000+ functions. Measure:
   - Call graph build time
   - Memory usage
   - Whether streaming mode kicks in correctly

---

## Implementation Dependency Graph

```
M0 Foundations
├── M1 Extraction (depends on M0 types + ghidra crate)
│       ├── M2 Persistence (depends on M1 data)
│       │       ├── M3 Classification (depends on M2 graph)
│       │       │       ├── M4 Ordering (depends on M3 categories)
│       │       │       │       ├── M5 Context (depends on M3 + M4)
│       │       │       │       │       └── M6 Pipeline Integration (depends on M4 + M5)
│       │       │       │       │               └── M7 CLI (depends on M6)
│       │       │       │       └── M8 Tests (depends on all above)
```

**Parallelizable:** M1.3 (indirect calls) and M1.4 (virtual calls) can be done in parallel with M1.2. M3.1 (root patterns) and M3.3 (API signatures) can be done in parallel.

---

## MVP Definition

The MVP delivers a working call graph that skips known runtime functions and provides basic callee context in prompts:

- [x] M0: Types and crate (required)
- [x] M1.1–M1.2: Enhanced extraction via Ghidra + regex (required)
- [x] M2: Persistence (required)
- [x] M3.1–M3.2: Root detection with 5+ patterns (required)
- [x] M3.4: Leaf detection with 10+ API signatures (required)
- [x] M4.1–M4.2: Priority sort (required)
- [x] M5.1: Call graph context in prompts (required)
- [x] M6.3–M6.4: Pipeline integration + skip runtime (required)
- [ ] M1.3–M1.4: Indirect/virtual call detection (nice-to-have)
- [ ] M1.5: Cross-DLL import mapping (nice-to-have)
- [ ] M3.5: Runtime library detection (nice-to-have)
- [ ] M4.3: Batch planning (nice-to-have)
- [ ] M5.2–M5.3: Context envelope + limiting (nice-to-have)
- [ ] M6.2: Dependency tracker integration (nice-to-have)
- [ ] M7: CLI flags (nice-to-have)
- [ ] M8: Tests (required for merge)

---

## Rollback Strategy

Each milestone is a branch. If a milestone fails:

1. Abandon the branch (keep it for historical record)
2. Start from the last passing milestone's branch
3. Try a different approach (per Calxgloss.md's "fail fast, discard freely" principle)
