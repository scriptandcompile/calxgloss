# Call Graph Assisted Translation — Root & Leaf Methodology

## Motivation

Currently, calxgloss discovers all functions in a DLL/exe and translates them in isolation. This misses two important structural insights:

1. **Root functions** (entry points, CRT/VB6 runtime initialization) are well-known patterns that don't need translation — they can be recognized and skipped or replaced with a single stub.
2. **Leaf functions** (calls to known third-party libraries like Direct3D, GDI, Win32 API) provide semantic context — knowing that a function calls `Direct3DCreate9` tells the LLM that this is a graphics-related function, which improves translation quality.

By building and analyzing the call graph, we can:
- **Skip** known runtime initialization functions (CRT `mainCRTStartup`, VB6 `__vbaInitialize`, etc.)
- **Prioritize** translation order — roots first (to understand initialization), leaves last (to understand dependencies)
- **Enrich** the translation context with call graph neighbors and their 3rd-party API usage
- **Detect** which functions belong to the application logic vs. which are just runtime glue code

## Current State

### Existing Call Graph Infrastructure

- **Ghidra client** (`calxgloss-ghidra`) exposes `callers()` (xrefs to function) and `callees()` (regex-scrapped from decompiled pseudo-C)
- **Function analysis** stores call graph neighbors in `FunctionAnalysis.call_graph: Vec<String>`
- **Dependency tracker** (`calxgloss-analysis/src/dependency.rs`) builds a DAG of work units based on call graph neighbors
- **Ghidra client gap**: callees are read from decompiled text via regex (`IDENT(` pattern), missing indirect calls and function pointer calls

### Known Gaps

| Gap | Impact |
|-----|--------|
| Callees are regex-scraped, not from Ghidra's call graph | Misses indirect calls, vtable calls, function pointers |
| Call graph is string-based (function names only) | No address-level correlation, no module-level dependency tracking |
| No call graph is persisted separately | Lives only in memory during analysis, lost between runs |
| Import data has no module names | Cannot map imports to specific DLLs for leaf detection |

## Proposed Architecture

```
┌─────────────────────────────────────────────────────┐
│                   Call Graph Builder                 │
│  (new crate: calxgloss-callgraph or submodule)       │
│                                                      │
│  1. Build adjacency map from callers + callees       │
│  2. Classify nodes as ROOT / LEAF / MIDDLE           │
│  3. Detect known runtime libraries                   │
│  4. Persist graph to JSON                            │
└──────────────────────┬──────────────────────────────┘
                       │
          ┌────────────┴────────────┐
          ▼                         ▼
┌─────────────────┐    ┌──────────────────────────┐
│   Root Detector   │    │   Leaf Detector          │
│                   │    │                          │
│ • Entry points    │    │ • Known third-party DLLs │
│ • CRT startup     │    │ • Direct3D/COM imports   │
│ • VB6 init        │    │ • GDI/User32 API usage   │
│ • Framework init  │    │ • Audio/video runtimes   │
└────────┬──────────┘    └────────┬─────────────────┘
         │                        │
         ▼                        ▼
┌──────────────────────────────────────────────────┐
│          Translation Order & Context Enrichment    │
│                                                   │
│ • Roots translated first (or skipped)            │
│ • Leaves translated last (with full context)     │
│ • Middle functions translated with neighbor info │
└──────────────────────────────────────────────────┘
```

## Implementation Plan

### Phase 1: Data Collection & Graph Building

**Goal**: Build a reliable call graph from Ghidra data.

#### 1.1 Enhanced Call Graph Extraction

**Location**: `calxgloss-ghidra` / `calxgloss-callgraph`

**Changes**:

```rust
// New model types
pub struct CallGraphEdge {
    pub source: Address,  // function entry address
    pub target: Address,  // function called
    pub call_site: Address,  // instruction address of call
    pub call_type: CallType,  // direct / indirect / virtual / unknown
}

pub enum CallType {
    Direct,          // function(name)
    Indirect,        // *func_ptr(args)
    Virtual,         // vtable->method()
    Unknown,         // scraped from text, uncertain
}

pub struct FunctionCallGraph {
    pub name: String,
    pub address: Address,
    pub callers: Vec<Address>,      // who calls this function
    pub callees: Vec<CallGraphEdge>,  // what this function calls
}
```

**Implementation details**:

1. **Direct callers** — already available via `xrefs_to(address)` from Ghidra
2. **Direct callees** — improve regex-based scraping:
   - Better pattern matching for decompiled output
   - Filter out local function calls (functions within the same DLL)
   - Tag calls as `CallType::Direct` when confident
3. **Indirect calls** — scan disassembly for `call [reg]` or `call [rip + offset]` patterns
4. **Virtual calls** — scan for `vtable->method()` patterns in decompiled output

**Key decision**: Should we use Ghidra's call graph API (if available in GhidraMCP) or continue with our regex scraping + disassembly analysis?

**Recommendation**: Check if GhidraMCP exposes a call graph endpoint. If not, use our hybrid approach (regex for direct calls, disassembly for indirect).

#### 1.2 Call Graph Builder

**Location**: `calxgloss-callgraph/src/lib.rs` (new module)

**Responsibilities**:

1. Fetch all functions from Ghidra
2. For each function, collect callers + callees
3. Build adjacency map: `Address -> Vec<Address>`
4. Classify nodes based on name/address patterns:
   - **Root candidates**: `main`, `WinMain`, `DllMain`, `mainCRTStartup`, `__vbaInitialize`, etc.
   - **Leaf candidates**: functions that call known third-party APIs
   - **Middle**: everything else

**Persisted format** (`re/analysis/call_graph.json`):

```json
{
  "dll": "LaunchPad.exe",
  "functions": [
    {
      "name": "main",
      "address": "0x401000",
      "callers": [],
      "callees": ["0x402000", "0x403000"],
      "call_type": "root",
      "known_runtime": true
    },
    {
      "name": "some_app_function",
      "address": "0x402000",
      "callers": ["0x401000"],
      "callees": ["Direct3DCreate9"],
      "call_type": "middle",
      "known_runtime": false
    }
  ]
}
```

### Phase 2: Root & Leaf Classification

**Goal**: Identify which functions are roots, leaves, or middle.

#### 2.1 Root Detection

**Known root patterns**:

| Pattern | Description | Action |
|---------|-------------|--------|
| `mainCRTStartup`, `_main`, `WinMain` | C/C++ entry points | Skip or generate stub |
| `DllMain` | DLL entry point | Skip or generate stub |
| `__vbaInitialize`, `__vbaInit` | VB6 runtime init | Skip, call Rust stub |
| `__wine_start` | Wine loader | Skip |
| `main` + no callers | Console app entry | Skip |
| `DllMain` + no callers | DLL entry | Skip |

**Implementation**:

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
    Skip,                    // Don't translate, just note it
    GenerateStub,            // Generate a minimal Rust stub
    Translate,               // Translate normally (some roots have app logic)
}
```

**Detection process**:

1. Check function name against known patterns
2. Check if function has zero callers (entry point)
3. Check if function is in the PE import table (e.g., `mainCRTStartup`)
4. Check if function calls known runtime initialization functions

#### 2.2 Leaf Detection

**Known leaf categories**:

| Category | Examples | Rust Equivalent |
|----------|----------|-----------------|
| Direct3D | `Direct3DCreate9`, `CreateDXGIFactory` | `wgpu`, `vulkan` |
| GDI/GDI+ | `BeginPaint`, `CreateCompatibleDC` | `tiny-skia`, `image` |
| User32 | `MessageBox`, `CreateWindowEx` | `winit`, `egui` |
| Kernel32 | `CreateFile`, `ReadFile` | `std::fs`, `std::io` |
| COM | `CoInitialize`, `QueryInterface` | `windows` crate |
| Audio | `FMOD_StudioSystem_Create`, `ALutInit` | `rodio`, `cpal` |
| Network | `WSAStartup`, `socket` | `tokio`, `async-std` |
| Crypto | `CryptAcquireContext`, `CryptEncrypt` | `ring`, `chacha` |

**Implementation**:

```rust
pub struct LeafDetector {
    api_signatures: Vec<ApiSignature>,
}

pub struct ApiSignature {
    pub dll: String,           // e.g., "d3d9.dll"
    pub function_name: String, // e.g., "Direct3DCreate9"
    pub rust_crate: String,    // e.g., "wgpu"
    pub category: LeafCategory,
}
```

**Detection process**:

1. For each function, check if any callees match known API signatures
2. If yes, tag the function as a "leaf caller"
3. Store which APIs are called (for context enrichment)

#### 2.3 Runtime Library Detection

**Goal**: Identify functions that belong to runtime libraries vs. application logic.

**Known runtime DLLs**:

| Runtime | DLLs | Languages |
|---------|------|-----------|
| CRT (MSVC) | `msvcr*.dll`, `ucrtbase.dll` | C/C++ |
| VB6 Runtime | `msvbvm60.dll` | VB6 |
| .NET CLR | `mscorwks.dll`, `clr.dll` | C#, VB.NET |
| Qt | `Qt5Core.dll`, `Qt5Gui.dll` | C++ (Qt) |
| Python | `python3*.dll` | Python |
| Lua | `lua54.dll` | Lua |
| SDL | `SDL2.dll` | C/C++ (SDL) |

**Detection process**:

1. Check if function's DLL is in the known runtime list
2. If yes, tag all functions in that DLL as "runtime"
3. Apply skip/replace strategy based on runtime type

### Phase 3: Translation Order & Context Enrichment

**Goal**: Use the call graph to improve translation quality.

#### 3.1 Translation Order

**Current behavior**: Functions are translated in discovery order (Ghidra list order).

**New behavior**:

1. **Root functions first** — either skipped or translated to understand initialization
2. **Leaf functions last** — translated with full context of dependencies
3. **Middle functions** — translated in topological order respecting call graph edges

**Implementation**:

```rust
pub enum TranslationPriority {
    Root,        // Translate/skip first
    Middle,      // Translate in topological order
    Leaf,        // Translate last, with full context
    Skip,        // Don't translate, just note
}

pub struct FunctionTranslationPlan {
    pub function: FunctionInfo,
    pub priority: TranslationPriority,
    pub caller_count: usize,
    pub callee_count: usize,
    pub runtime_calls: Vec<String>,  // e.g., ["Direct3DCreate9"]
}
```

**Ordering algorithm**:

```
1. Sort by priority (Root > Middle > Leaf > Skip)
2. Within each priority, use topological sort from call graph
3. For functions with no call graph edges, use dependency graph order
```

#### 3.2 Context Enrichment

**Goal**: Enhance the LLM prompt with call graph information.

**Current prompt includes**:

- Function signature
- Decompiled pseudo-C code
- Disassembly
- Windows API tags
- Known imports

**New additions**:

1. **Caller context**: List of functions that call this function (for understanding "who uses this")
2. **Callee context**: List of functions this function calls, especially known third-party APIs
3. **Runtime context**: If function calls CRT/VB6 runtime functions, note that
4. **Dependency context**: If function calls Direct3D/GDI/etc., note the library for translation guidance

**Prompt template addition**:

```
## Call Graph Context

This function is called by:
- `some_app_function`
- `DllMain`

This function calls:
- `Direct3DCreate9` (from d3d9.dll → use wgpu)
- `CreateWindowExA` (from user32.dll → use winit)
- `MessageBoxA` (from user32.dll → use egui)

## Translation Guidance

- This is a graphics-related function using Direct3D 9
- Use `wgpu` or `vulkan` for 3D rendering
- Use `winit` or `egui` for window creation
- Avoid manual COM initialization for D3D9
```

### Phase 4: Integration with Existing Pipeline

**Goal**: Integrate the call graph analysis into the existing classification and translation pipeline.

**Integration points**:

1. **DLL Classification** — extend `DllCategory` to include `RuntimeLibrary` variant
2. **Function Analysis** — add call graph data to `FunctionAnalysis`
3. **Dependency Tracker** — enhance edges with call type (direct/indirect/virtual)
4. **Translation Pipeline** — use call graph for ordering and context enrichment
5. **Batch Translation** — respect call graph ordering

**Changes to existing types**:

```rust
// In calxgloss-types/src/dll.rs
pub enum DllCategory {
    WindowsOs,
    MicrosoftSdk,
    KnownThirdParty,
    ProjectSpecific,
    RuntimeLibrary,  // NEW: CRT, VB6, .NET, etc.
}

// In calxgloss-types/src/function.rs
pub struct FunctionAnalysis {
    // ... existing fields ...
    pub call_graph: Vec<String>,  // existing
    pub callers: Vec<Address>,    // NEW
    pub callees: Vec<CallGraphEdge>,  // NEW
    pub call_type: FunctionCallType,  // NEW: root/middle/leaf/skip
    pub known_runtime: bool,      // NEW
    pub third_party_calls: Vec<String>,  // NEW: e.g., ["Direct3DCreate9"]
}
```

## Difficulties & Complexities

### 1. Call Graph Completeness

**Difficulty**: GhidraMCP doesn't expose a proper call graph endpoint.

**Impact**: We rely on regex-scraped callees, which miss:
- Indirect calls through function pointers
- Virtual function calls via vtables
- Indirect calls via registers (`call [reg]`)
- Thunk functions and import address table (IAT) indirection

**Mitigation**:
- Combine decompiled text regex + disassembly scanning
- Use Ghidra's `xrefs_from` for more reliable direct calls
- Accept that some indirect calls will be missed
- Tag uncertain calls with a confidence score

### 2. Cross-DLL Call Detection

**Difficulty**: Functions in one DLL can call functions in another DLL, but Ghidra reports them as external references without module names.

**Impact**: Cannot easily detect "eqmain.dll calls d3d9.dll" for dependency tracking.

**Mitigation**:
- Use import/export analysis to infer cross-DLL calls
- Check if a callee name matches a known DLL's exported symbols
- Use PE header analysis to map imports to DLLs

### 3. Runtime Library Identification

**Difficulty**: Different compilers/languages produce different entry point names:
- MSVC: `mainCRTStartup`, `_main`, `WinMain@16`
- MinGW: `main`, `WinMain`
- VB6: `__vbaInitialize`, `SUBMAIN`
- .NET: `__managed_main`, `main`

**Impact**: Need a comprehensive pattern database for runtime detection.

**Mitigation**:
- Build a comprehensive pattern database based on compiler/language
- Use name mangling analysis to detect compiler type
- Check for known runtime DLL imports to infer language

### 4. Scaling to Large DLLs

**Difficulty**: A large DLL might have 10,000+ functions. Building the call graph requires:
- 10,000+ Ghidra API calls (one per function)
- Significant memory to store the graph
- Long processing time before translation can start

**Impact**: Users may wait minutes/hours for call graph analysis before seeing any results.

**Mitigation**:
- Make call graph analysis optional (flag `--no-callgraph`)
- Stream the analysis: start translating as soon as enough data is available
- Cache the call graph to disk (already planned)
- Support incremental updates (rebuild graph when DLL changes)

### 5. Context Window Limits

**Difficulty**: Adding call graph context to prompts increases prompt size.

**Impact**: May exceed LLM context window limits or degrade translation quality due to too much noise.

**Mitigation**:
- Only include relevant context (e.g., only third-party API calls, not all callees)
- Limit to top-N most significant callers/callees
- Use separate context sections that LLM can choose to attend to

### 6. Maintaining the API Signature Database

**Difficulty**: Thousands of Windows API functions, hundreds of third-party library APIs.

**Impact**: Need a comprehensive, up-to-date database of known APIs.

**Mitigation**:
- Start with a curated list of common APIs (DirectX, GDI, COM, etc.)
- Allow users to extend the database via configuration
- Automate database generation from Windows SDK headers
- Use fuzzy matching to handle name variations

### 7. Indirect Call Analysis

**Difficulty**: Analyzing indirect calls requires disassembly-level analysis.

**Impact**: Misses function pointer calls, vtable calls, and jump tables.

**Mitigation**:
- Use Ghidra's decompiler for vtable detection
- Scan disassembly for common indirect call patterns
- Accept that some calls will be missed (tag with uncertainty)
- Prioritize direct calls for context enrichment

## Implementation Order

### Recommended Phase Order

1. **Phase 1.1**: Enhanced call graph extraction (regex improvements)
2. **Phase 1.2**: Call graph builder & persistence
3. **Phase 2.1**: Root detection (simple pattern matching)
4. **Phase 2.2**: Leaf detection (known API signatures)
5. **Phase 3.1**: Translation order (topological sort)
6. **Phase 3.2**: Context enrichment (prompt template additions)
7. **Phase 4**: Integration with existing pipeline

### Minimum Viable Product

The MVP can be achieved with:
- Basic call graph extraction (regex only)
- Root detection for common entry points (main, WinMain, DllMain)
- Skip roots during translation
- Simple context: list of callees in prompt

**Estimated effort**: 2-3 weeks

### Full Feature Set

The full feature set requires:
- All phases above
- Indirect call analysis
- Cross-DLL call detection
- Comprehensive API signature database
- Runtime library detection
- Streaming analysis

**Estimated effort**: 2-3 months

## Files to Create/Modify

### New Files

1. `crates/calxgloss-callgraph/src/lib.rs` — Call graph builder
2. `crates/calxgloss-callgraph/src/builder.rs` — Graph construction
3. `crates/calxgloss-callgraph/src/root_detector.rs` — Root detection
4. `crates/calxgloss-callgraph/src/leaf_detector.rs` — Leaf detection
5. `crates/calxgloss-callgraph/src/models.rs` — Data structures
6. `Documentation/call_graph_assisted_translation.md` — This document

### Modified Files

1. `crates/calxgloss-ghidra/src/lib.rs` — Enhanced call graph extraction
2. `crates/calxgloss-types/src/function.rs` — Add call graph fields
3. `crates/calxgloss-types/src/dll.rs` — Add RuntimeLibrary variant
4. `crates/calxgloss-analysis/src/lib.rs` — Integrate call graph analysis
5. `crates/calxgloss-analysis/src/dependency.rs` — Enhance edges
6. `crates/calxgloss-translator/src/lib.rs` — Use call graph for ordering/context
7. `crates/calxgloss-translator/src/batch.rs` — Batch ordering
8. `crates/calxgloss-prompts/src/lib.rs` — Add call graph context to prompts
9. `crates/calxgloss-cli/src/main.rs` — Add `--no-callgraph` flag

## Testing Strategy

### Unit Tests

1. **Call graph construction**: Test with synthetic function data
2. **Root detection**: Test with known entry point names
3. **Leaf detection**: Test with known API signatures
4. **Translation ordering**: Test topological sort with known graph
5. **Context enrichment**: Test prompt generation with call graph data

### Integration Tests

1. **End-to-end**: Run full pipeline on a test DLL
2. **Performance**: Measure time/memory for large DLLs
3. **Context quality**: Evaluate translation quality with/without call graph

### Manual Testing

1. **CRT application**: Test with a C/C++ app that uses MSVC runtime
2. **VB6 application**: Test with a VB6 app that uses msvbvm60.dll
3. **DirectX application**: Test with a game that uses Direct3D
4. **Large application**: Test with a DLL having 1000+ functions

## Open Questions

1. **Should we require the call graph, or make it optional?**
   - Recommended: Make it optional (`--no-callgraph`), use it by default

2. **How do we handle functions that call both third-party APIs and application functions?**
   - Classify as "middle" but include all callee context

3. **What if a function has no call graph data (missing from analysis)?**
   - Fall back to current behavior (translate in discovery order)

4. **Should we use the call graph for dependency tracking (translation order) or just for context enrichment?**
   - Both: use for ordering AND context enrichment

5. **How do we handle DLLs that are not PE format (e.g., Mach-O, ELF)?**
   - Currently calxgloss focuses on PE/DLL, so this is out of scope

6. **Should we infer call graph from decompiler call statements, disassembly, or both?**
   - Both: decompiler for direct calls, disassembly for indirect calls

## Conclusion

The Root & Leaf methodology represents a significant improvement over the current flat function discovery approach. By leveraging the call graph structure, we can:

1. **Skip** known runtime functions (saving translation time)
2. **Enrich** translation prompts with semantic context (improving quality)
3. **Prioritize** translation order (improving efficiency)
4. **Understand** function purpose through API usage patterns (improving accuracy)

The main challenges are call graph completeness (due to Ghidra limitations) and scaling to large DLLs. Both can be mitigated with hybrid analysis approaches and streaming processing.

The MVP is achievable in 2-3 weeks, with the full feature set requiring 2-3 months of development.
