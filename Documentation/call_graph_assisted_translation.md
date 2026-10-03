# Call Graph Assisted Translation — Implementation Plan

## Prerequisites

- Spec doc: `Documentation/call_graph_assisted_translation.md`
- Target crate: `crates/calxgloss-callgraph/` (new workspace member)
- Workspace crate count: 15 → 16
- Pattern reference: existing crates (`calxgloss-analysis`, `calxgloss-git`) for structure
- Decision: New crate `calxgloss-callgraph`, JSON persistence, narrow MVP
- Decision: New crate is the source of truth; dependency tracker consumes from it

---

## Part A: MVP (Tasks 0–6)

The MVP delivers: **call graph extraction from Ghidra → root detection → persistence**. That's it. No translation ordering, no prompt integration, no CLI flag. These come later.

The MVP is self-contained in one crate. Integration touches are minimal: a `NodeCategory` field on `FunctionAnalysis`, and the dependency tracker reads from the persisted graph instead of building its own name-based graph.

---

### Task 0: Add Crate to Workspace ✅ COMPLETED

**Files:** `Cargo.toml`

**Action:** Add `"crates/calxgloss-callgraph"` to the `[workspace].members` array.

**Acceptance:** `cargo check` still passes with 16 members.

---

### Task 1: Crate Skeleton & Module Structure ✅ COMPLETED

**Files created:**
```
crates/calxgloss-callgraph/
├── Cargo.toml
└── src/
    ├── lib.rs           — re-exports, docs
    ├── models.rs        — CallGraphEdge, FunctionCallGraph, NodeCategory, CallGraph
    ├── builder.rs       — CallGraphBuilder (fetches from Ghidra, constructs graph)
    ├── root_detector.rs — RootDetector (skip patterns)
    ├── leaf_detector.rs — LeafDetector (API signature patterns)
    └── persist.rs       — CallGraphPersistor (JSON save/load)
```

**`Cargo.toml`:**
```toml
[package]
name = "calxgloss-callgraph"
version.workspace = true
edition.workspace = true
description = "Call graph analysis: root/leaf detection, translation ordering, context enrichment"

[dependencies]
calxgloss-ghidra = { path = "../calxgloss-ghidra" }
calxgloss-types = { path = "../calxgloss-types" }
calxgloss-pal = { path = "../calxgloss-pal" }
serde = { workspace = true }
serde_json = { workspace = true }
tokio = { workspace = true }
tracing = { workspace = true }
anyhow = { workspace = true }
regex = { workspace = true }
```

**`lib.rs` exports:**
```rust
pub mod models;
pub mod builder;
pub mod root_detector;
pub mod leaf_detector;
pub mod persist;

pub use models::*;
pub use builder::CallGraphBuilder;
pub use root_detector::RootDetector;
pub use leaf_detector::LeafDetector;
pub use persist::CallGraphPersistor;
```

**Acceptance:**
- ✅ `cargo build -p calxgloss-callgraph` compiles cleanly
- ✅ All public types re-exported from `lib.rs`
- ✅ Documentation comments on every public type and function

---

### Task 2: Model Types (`models.rs`) ✅ COMPLETED

**File:** `crates/calxgloss-callgraph/src/models.rs`

**Types:**

```rust
/// How a call between functions was detected.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum CallType {
    /// Function(name) — from decompiled text
    Direct,
    /// *func_ptr() — from disassembly scan
    Indirect,
    /// vtable->method() — from decompiler
    Virtual,
    /// Scraper hit, uncertain
    #[deprecated(note = "Falls back to text scraping; low confidence")]
    Unknown,
}

/// A single call edge between two functions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallGraphEdge {
    /// Entry address of the calling function.
    pub source: u64,
    /// Entry address of the called function.
    pub target: u64,
    /// Instruction address of the call site (0 if unknown).
    pub call_site: u64,
    /// How this edge was discovered.
    pub call_type: CallType,
}

/// Category of a function in the call graph.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum NodeCategory {
    /// Entry point or runtime init — skip or stub.
    Root,
    /// Calls known 3rd-party APIs — enriched context.
    Leaf,
    /// Application logic — normal translation.
    Middle,
    /// Known runtime library function — don't translate.
    Skip,
}

/// All call graph data for one binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallGraph {
    pub dll: String,
    pub functions: Vec<FunctionCallGraph>,
}

/// Call graph data for a single function.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionCallGraph {
    pub name: String,
    pub address: u64,
    /// Caller entry addresses.
    pub callers: Vec<u64>,
    /// Callee edges with metadata.
    pub callees: Vec<CallGraphEdge>,
    pub node_category: NodeCategory,
}
```

**TODO comments:**
```rust
// TODO: Add CallType::Thunk for IAT indirection detection
// TODO: Add CallType::JumpTable for switch/vtable dispatch detection
// TODO: Persist call_type_confidence: f32 on each edge
// TODO: Add NodeCategory::EntryPoint (binary entry, not function entry)
// TODO: Add NodeCategory::Callback (registered callback functions that need special handling)
```

**Acceptance:**
- ✅ All types serialize/deserialize via serde
- ✅ `CallType` and `NodeCategory` derive `PartialEq` for testing
- ✅ `#[deprecated]` attribute on `CallType::Unknown`

---

### Task 3: Call Graph Builder (`builder.rs`) ✅ COMPLETED

**File:** `crates/calxgloss-callgraph/src/builder.rs`

**Responsibilities:**
1. Fetch all function summaries from Ghidra
2. For each function: callers (via `xrefs_to`), callees (via `callees_from_decompiled`)
3. Build `CallGraph` from the collected data
4. Tag each function `NodeCategory` (initially all `Middle` — root/leaf classification happens in Tasks 5-6)

**API:**
```rust
pub struct CallGraphBuilder {
    ghidra: GhidraClient,
    dll_name: String,
}

impl CallGraphBuilder {
    pub fn new(ghidra: GhidraClient, dll_name: impl Into<String>) -> Self;
    pub async fn build(&self) -> anyhow::Result<CallGraph>;
    fn process_function(&self, summary: &FunctionSummary) -> anyhow::Result<FunctionCallGraph>;
}
```

**Implementation details:**
- Call `ghidra.list_functions()` to get all functions, build a name→address lookup
- For each function, call `ghidra.callers(address)` for callers
- For callees, reuse existing `parse::callees_from_decompiled()` on `ghidra.decompile_function(address)`
- Map callee names back to addresses using the lookup map
- All functions start as `NodeCategory::Middle` — classification comes later

**TODO comments:**
```rust
// TODO: For indirect calls, scan disassembly for `call [reg]` and `call [rip + offset]`
// TODO: For virtual calls, detect `vtable->method()` patterns in decompiled output
// TODO: Optimize: batch ghidra calls with tokio::join_all to reduce wall time
// TODO: Add progress reporting (callback or async channel for large DLLs)
// TODO: Fallback: if decompile fails, use xrefs_from as callee source
```

**Acceptance:**
- ✅ `build()` returns a valid `CallGraph` with all functions from Ghidra
- ✅ `callers` populated for functions with incoming references
- ✅ `callees` populated from decompiled output
- ✅ `FunctionCallGraph` fields populated correctly
- ✅ If decompile fails for one function, graph still completes (graceful degradation)

---

### Task 4: Root Detection (`root_detector.rs`) — Narrow MVP ✅ COMPLETED

**File:** `crates/calxgloss-callgraph/src/root_detector.rs`

**Goal:** Identify functions to skip during translation.

**MVP patterns (3 entries):**

| Pattern | Regex | Description | Action |
|---------|-------|-------------|--------|
| C/C++ entry | `^(mainCRTStartup|_main|WinMain|WinMain@16|WinMain@20)$` | MSVC/MinGW entry points | Skip |
| DLL entry | `^DllMain$` | DLL entry point | Skip |
| Generic entry | `^entry$` | Ghidra's generic entry | Skip |

**API:**
```rust
pub struct RootDetector {
    patterns: Vec<RootPattern>,
}

pub struct RootPattern {
    pub name_regex: Regex,
    pub description: &'static str,
    pub action: RootAction,
}

pub enum RootAction {
    Skip,
    GenerateStub,
    Translate,
}

impl RootDetector {
    pub fn new() -> Self;           // initializes with 3 MVP patterns
    pub fn classify(&self, name: &str) -> RootAction;
    pub fn is_root(&self, func: &FunctionCallGraph) -> bool;
}
```

**TODO comments:**
```rust
// TODO: Add VB6 runtime patterns: `__vbaInitialize`, `__vbaInit`, `SUBMAIN`
// TODO: Add .NET CLR patterns: `__managed_main`, `_CorExeMain`
// TODO: Add MinGW patterns: `_start`, `__libc_start_main`
// TODO: Add MSVC debug entry: `_RTC_Initialize`
// TODO: Add detection via zero callers + entry point address in PE header
// TODO: Add known runtime DLL detection (msvcr*.dll, msvbvm60.dll, Qt5*.dll, SDL2.dll)
// TODO: Add RuntimeLibrary NodeCategory variant
// TODO: Allow user to configure patterns via config file
```

**Acceptance:**
- ✅ All 3 MVP patterns correctly identified
- ✅ `is_root()` returns `true` for matching functions
- ✅ `classify()` returns the correct `RootAction`
- ✅ Unit tests with synthetic `FunctionCallGraph` data
- ✅ Function names with stdcall decoration (`WinMain@16`) correctly matched

---

### Task 5: Leaf Detection (`leaf_detector.rs`) — Narrow MVP ✅ COMPLETED

**File:** `crates/calxgloss-callgraph/src/leaf_detector.rs`

**Goal:** Identify functions that call known 3rd-party APIs, for context enrichment.

**MVP API signatures (8 categories, 22 APIs):**

| Category | Example APIs | Rust Equivalent |
|----------|-------------|-----------------|
| Direct3D | `Direct3DCreate9` | `wgpu` |
| GDI | `CreateCompatibleDC`, `BitBlt` | `tiny-skia` |
| User32 | `MessageBox`, `CreateWindowEx` | `winit` |
| Kernel32 | `CreateFile`, `ReadFile` | `std::fs` |
| COM | `CoInitialize`, `QueryInterface` | `windows` crate |
| Audio | `FMOD_StudioSystem_Create` | `rodio` |
| Network | `WSAStartup`, `socket` | `tokio` |
| Crypto | `CryptAcquireContext` | `ring` |

**API:**
```rust
pub struct LeafDetector {
    api_signatures: Vec<ApiSignature>,
}

pub struct ApiSignature {
    pub api_name: String,
    pub category: LeafCategory,
    pub rust_crate: String,
}

pub enum LeafCategory {
    Graphics,
    Gdi,
    Ui,
    Filesystem,
    Com,
    Audio,
    Network,
    Crypto,
}

impl LeafDetector {
    pub fn new() -> Self;       // initializes with ~20 MVP signatures
    pub fn classify(&self, func: &FunctionCallGraph) -> Option<Vec<ApiSignature>>;
    pub fn has_leaf_call(&self, func: &FunctionCallGraph) -> bool;
}
```

**How it works:**
1. For each function, check its `callees` (function names from decompiled output)
2. If any callee matches an `ApiSignature.api_name`, tag the function as leaf
3. Return the list of matched APIs for context enrichment

**TODO comments:**
```rust
// TODO: Expand to 200+ Windows API signatures (auto-generate from Windows SDK headers)
// TODO: Add 3rd-party library signatures: DirectX, Vulkan, OpenAL, SFML, etc.
// TODO: Add fuzzy matching for name variations (A/W suffixes, etc.)
// TODO: Add call graph reach analysis: if func calls funcA which calls D3D, funcA is also a leaf caller
// TODO: Add import table analysis: cross-reference with PE imports for more reliable API detection
// TODO: Support DLL-qualified names: `d3d9.Direct3DCreate9`
```

**Acceptance:**
- ✅ `Direct3DCreate9` in callees → leaf with `LeafCategory::Graphics`
- ✅ `MessageBox` in callees → leaf with `LeafCategory::Ui`
- ✅ Function with no known API callees → returns `None`
- ✅ Unit tests with synthetic `FunctionCallGraph` data

---

### Task 6: Integration with `calxgloss-analysis` ✅ COMPLETED

**Files modified:**
- `crates/calxgloss-analysis/src/lib.rs` — add `pub mod callgraph;`
- `crates/calxgloss-analysis/src/analyzer.rs` — use `CallGraphBuilder` after function analysis

**Changes:**
1. After building `FunctionAnalysis`, call `CallGraphBuilder` to enrich with root/leaf classification
2. Update `NodeCategory` on each function in the graph
3. Persist the enriched graph to `re/analysis/call_graph.json`
4. Add `node_category` to `FunctionAnalysis.call_graph` field (or create a new field alongside it)
5. The dependency tracker reads from the persisted graph

**Integration point:**
```rust
// In Analyzer::analyze_function, after FunctionInfo is built:
let graph_builder = CallGraphBuilder::new(self.ghidra.clone(), dll.clone());
let call_graph = graph_builder.build().await?;
let root_detector = RootDetector::new();
let leaf_detector = LeafDetector::new();

for func in &mut call_graph.functions {
    func.node_category = if root_detector.is_root(func) {
        NodeCategory::Root
    } else if leaf_detector.has_leaf_call(func) {
        NodeCategory::Leaf
    } else {
        NodeCategory::Middle
    };
}

// Persist the enriched graph
let persistor = CallGraphPersistor::new(&workspace);
persistor.save(&call_graph)?;
```

**TODO comments:**
```rust
// TODO: Cache CallGraphBuilder results to avoid rebuilding on every analysis run
// TODO: Add call graph analysis as a separate pipeline phase (Phase 1.5)
// TODO: Make call graph analysis optional via config flag
// TODO: Integrate with dependency tracker: use NodeCategory for translation ordering
// TODO: Add call graph data to `FunctionAnalysis` struct (callers, callees with metadata)
```

**Acceptance:**
- ✅ `Analyzer::analyze_function` enriches functions with root/leaf classification
- ✅ `CallGraph` is persisted to `re/analysis/call_graph.json`
- ✅ `FunctionAnalysis` includes call graph metadata
- ✅ Dependency tracker can read from persisted graph

---

### Task 7: Testing ✅ COMPLETED

**Unit tests per module:**

| Module | Test | What it validates |
|--------|------|-------------------|
| `models.rs` | Serialize/deserialize round-trip | `CallGraph` → JSON → `CallGraph` |
| `root_detector.rs` | Pattern matching | 3 MVP patterns match/don't match correctly |
| `leaf_detector.rs` | API signature matching | 8 categories of APIs correctly classified |
| `persist.rs` | Save/load round-trip | `CallGraphPersistor` mirrors `DependencyGraphPersistor` behavior |
| `builder.rs` | Graph construction | All functions from Ghidra appear in graph with correct callers/callees |

**Integration tests:**

| Test | What it validates |
|------|-------------------|
| Full pipeline: Ghidra → builder → root/leaf → persist | End-to-end graph construction |
| Persistence: build → save → load → classify | Graph survives disk round-trip |

**Acceptance:**
- ✅ All modules have `#[cfg(test)]` modules with ≥3 tests each
- ✅ `cargo test -p calxgloss-callgraph` passes (43 unit tests + 4 integration tests pass, 1 ignored)

---

### Task 8: Documentation ✅ COMPLETED

**Files updated:**
- `crates/calxgloss-callgraph/src/lib.rs` — module-level docs (architecture overview + example)
- `crates/calxgloss-callgraph/src/models.rs` — module-level docs with type descriptions
- `crates/calxgloss-callgraph/src/builder.rs` — module-level docs with algorithm and example
- `crates/calxgloss-callgraph/src/root_detector.rs` — module-level docs with example
- `crates/calxgloss-callgraph/src/leaf_detector.rs` — module-level docs with algorithm and example
- `crates/calxgloss-callgraph/src/persist.rs` — module-level docs with file layout and example
- `Documentation/call_graph_assisted_translation.md` — this file

**Acceptance:**
- ✅ `cargo doc -p calxgloss-callgraph --no-deps` builds without warnings
- ✅ `cargo test --doc -p calxgloss-callgraph` — all 5 doc tests pass

---

### MVP Summary

| Task | Est. Days |
|------|-----------|
| 0: Workspace registration | 0.25 |
| 1: Skeleton & modules | 0.5 |
| 2: Model types | 0.5 |
| 3: Builder | 2 |
| 4: Root detector | 0.5 |
| 5: Leaf detector | 1 |
| 6: Analysis integration | 1.5 |
| 7: Testing | 1 |
| 8: Documentation | 0.5 |
| **Total** | **~7-8 days** |

---

## Part B: Post-MVP (Tasks 9–13)

These are planned but not urgent. Each is a self-contained enhancement that can be done independently.

### Task 9: Translation Ordering ✅ COMPLETED

**File:** `crates/calxgloss-callgraph/src/ordering.rs` (new)

**Goal:** Produce a priority-ordered list of functions for the translation pipeline.

**MVP algorithm:**
1. Classify each function as Root/Middle/Leaf using Tasks 4-5
2. Sort by priority: Root (skip/stub first) → Middle (topological) → Leaf (context last)
3. Within each priority tier, use topological sort from call graph edges

**Types implemented:**
```rust
pub enum TranslationPriority { Root, Middle, Leaf }
pub struct FunctionTranslationPlan {
    pub name: String,
    pub address: u64,
    pub priority: TranslationPriority,
    pub caller_count: usize,
    pub callee_count: usize,
    pub caller_names: Vec<String>,
    pub callee_names: Vec<String>,
}
pub struct TranslationOrderer { /* ... */ }
impl TranslationOrderer {
    pub fn new() -> Self;
    pub fn with_max_functions(mut self, max: usize) -> Self;
    pub fn order(&self, graph: &CallGraph) -> Result<VecDeque<FunctionTranslationPlan>>;
}
```

**Topological sort:** Kahn's algorithm with edges reversed (callee → caller) so that
functions with no internal callees are placed first within their tier. Cycles are
resolved by appending cyclic nodes in address order.

**Remaining TODOs:**
```rust
// TODO: Add priority weighting: functions with more callers get higher priority within tier
// TODO: Add cycle detection and resolution (break cycles by picking lowest-address function)
// TODO: Add streaming: emit plans as functions are classified, don't wait for full graph
// TODO: Add batch ordering: group functions by DLL for batch translation
// TODO: Add configurable priority inversion (user can override via config)
```

**Acceptance:**
- ✅ Root functions listed before Middle and Leaf
- ✅ Middle functions respect topological order (callees before callers within tier)
- ✅ Leaf functions listed last
- ✅ `FunctionTranslationPlan` includes caller/callee counts and names
- ✅ Cyclic functions handled gracefully (appended at end of tier in address order)
- ✅ Duplicate address detection returns an error
- ✅ `max_functions` limit truncates the plan when set
- ✅ 15 unit tests covering all core behavior
- ✅ 1 doc test passes

---

### Task 10: Context Enrichment ✅ COMPLETED

**File:** `crates/calxgloss-callgraph/src/context.rs` (new)

**Goal:** Produce call graph context data for LLM prompt injection.

**MVP:** For each function, produce a list of:
1. **Callers** — function names that call this function (with signatures if available)
2. **Callees** — function names this function calls, grouped by category
3. **Leaf API context** — for leaf functions, the matched API signatures with Rust crate suggestions

**Types implemented:**
```rust
pub struct CallGraphNode {
    pub name: String,
    pub address: u64,
}

pub struct CallEdgeInfo {
    pub node: CallGraphNode,
    pub call_type: String,
}

pub struct CalleeGroup {
    pub category: LeafCategory,
    pub apis: Vec<String>,
}

pub struct LeafApiContext {
    pub api_name: String,
    pub category: LeafCategory,
    pub rust_crate: String,
}

pub struct FunctionContext {
    pub name: String,
    pub address: u64,
    pub callers: Vec<CallEdgeInfo>,
    pub callees: Vec<CallEdgeInfo>,
    pub categorized_callees: Vec<CalleeGroup>,
    pub leaf_api_context: Vec<LeafApiContext>,
}

pub struct ContextEnricher { /* ... */ }
impl ContextEnricher {
    pub fn new() -> Self;
    pub fn enrich(&self, graph: &CallGraph) -> Vec<FunctionContext>;
}
```

**How it works:**
1. Build an address-to-function lookup from the call graph.
2. For each function, resolve caller addresses to names.
3. Classify each callee using the `LeafDetector` for API categorization.
4. Collect leaf API context (matched APIs with Rust crate suggestions).
5. Unknown caller addresses fall back to `0x<hex>` display names.

**Remaining TODOs:**
```rust
// TODO: Add signature lookup from Ghidra decompiler for neighbors
// TODO: Add call frequency analysis (how many call sites)
// TODO: Add data flow context (what data this function receives/produces via parameters)
// TODO: Limit neighbor output to top-N by importance to avoid context window bloat
// TODO: Add "dependency chain" context: transitive callers/callees up to depth N
```

**Acceptance:**
- ✅ Empty graph returns empty context vector
- ✅ Functions with no neighbors have empty callers/callees
- ✅ Caller addresses resolved to function names (with hex fallback for unknowns)
- ✅ Callees included with call type metadata (direct/indirect/virtual)
- ✅ Leaf APIs grouped by category (`CalleeGroup`)
- ✅ Leaf API context includes API name, category, and Rust crate suggestion
- ✅ Non-leaf functions have empty categorized_callees and leaf_api_context
- ✅ Multiple leaf API categories correctly grouped
- ✅ `ContextEnricher` supports `Default` and `Clone`
- ✅ 15 unit tests covering all core behavior
- ✅ 2 doc tests pass

---

### Task 11: Prompt Integration

**Files to modify:**
- `crates/calxgloss-prompts/src/lib.rs`
- `crates/calxgloss-prompts/src/context.rs`
- `crates/calxgloss-prompts/src/templates.rs`

**Changes:**
1. Add `EnrichedContext` (from Task 10) as an optional field in prompt data structs
2. Add "CALL GRAPH CONTEXT" section to template structs
3. When `EnrichedContext` is present, render caller/callee/leaf-api information into the prompt

**TODO:**
```rust
// TODO: Make call graph context optional and size-limited (configurable max neighbors)
// TODO: Add context tier awareness: only include deep call graph context in T3/T4 tiers
// TODO: Add "skip context" for leaf APIs that are already covered by Windows API mappings
```

**Acceptance:**
- Existing tests still pass (call graph context is optional)
- When `call_graph_context` is `Some`, the prompt includes the new section
- Prompt is not bloat (only includes meaningful neighbors)

---

### Task 12: CLI `--no-callgraph` Flag

**Files to modify:** `crates/calxgloss-cli/src/main.rs`

**Changes:**
1. Add `--no-callgraph` flag to disable call graph analysis
2. When flag is present, skip `CallGraphBuilder` step
3. When flag is absent (default), run call graph analysis

**TODO:**
```rust
// TODO: Add `--callgraph-mode` with choices: full, root-only, leaf-only, none
// TODO: Add `--callgraph-timeout` for large binaries
// TODO: Log call graph analysis duration for performance tracking
```

---

### Task 13: Extended Root/Leaf Patterns

**Files to modify:** `crates/calxgloss-callgraph/src/root_detector.rs` and `leaf_detector.rs`

**Root detector expansion (TODOs from Task 4):**
- VB6: `__vbaInitialize`, `SUBMAIN`
- .NET: `__managed_main`, `_CorExeMain`
- MinGW: `_start`, `__libc_start_main`
- Runtime DLL detection: `msvcr*.dll`, `msvbvm60.dll`, `Qt5*.dll`, `SDL2.dll`
- Configurable patterns via user config file

**Leaf detector expansion (TODOs from Task 5):**
- 200+ Windows API signatures (auto-generate from Windows SDK headers)
- 3rd-party library signatures: DirectX, Vulkan, OpenAL, SFML
- Fuzzy matching for name variations
- Call graph reach analysis (transitive leaf callers)
- Import table analysis

---

### Post-MVP Summary

| Task | Est. Days | Blockers |
|------|-----------|----------|
| 9: Translation ordering | 3 | None ✅ |
| 10: Context enrichment | 2 | None ✅ |
| 11: Prompt integration | 3 | Depends on Task 10 |
| 12: CLI flag | 0.5 | None |
| 13: Extended patterns | 5 | Depends on Tasks 4-5 |
| **Total** | **~14 days** | |

---

### Full Implementation Order & Dependencies

```
Task 0  (workspace)
  │
  ▼
Task 1  (skeleton)
  │
  ├── Task 2  (models) ───► Task 6  (analysis integration) ──► Task 13 (extended patterns)
  │       │
  │       ▼
  │   Task 3  (builder) ───┘
  │                              │
  │                              ├── Task 4  (root detector) ──┘
  │                              │
  │                              └── Task 5  (leaf detector) ─┘
  │                                     │
  │                                     ▼
  │                                 Task 9  (translation ordering) ✅
  │                                     │
  │                                     ▼
  │                                 Task 10  (context enrichment) ✅
  │                                     │
  │                                     ▼
  │                                 Task 11  (prompt integration)
  │                                     │
  │                                     ▼
  │                                 Task 12  (CLI flag)
  │                                     │
  │                                     ▼
  │                                 Task 8  (docs)
  │                                     │
  └─────────────────────────────────────►
```

**MVP path** (Tasks 0-8): ~7-8 days. Delivers call graph extraction, root detection, persistence, and basic integration with analysis pipeline.

**Full path** (Tasks 9-13): +14 days after MVP. Delivers translation ordering, prompt context injection, CLI control, and expanded pattern libraries.
