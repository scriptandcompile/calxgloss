# Calxgloss — Unified Step-by-Step Implementation Plan

> **Purpose:** Consolidated implementation plan for all 16 methodologies (11 analysis crates + 5 web UI improvement phases), ordered by implementation priority.
>
> **Execution notes:** The analysis-crate track (P1–P4) and the web-UI track (W0–W4) are independent and can run in parallel. Within the web track, W0 comes first; W1–W4 depend only on backend pipeline data, not on the analysis crates. Test counts cited in phases are indicative targets, not exact requirements.
>
> **Bridge decision (2026-10-03):** the Ghidra bridge switches from the stock GhidraMCP plugin 1.4 to [bethington/ghidra-mcp](https://github.com/bethington/ghidra-mcp) **v6.0.0 (stable, 272 JSON REST endpoints)** — installed on the existing Ghidra 12.1.2, same port 8080. See P1 Phase 0a for the client port plan and endpoint mapping; all bridge-capability claims in this document reflect the new bridge. Our custom load port is 8089.

---

## Table of Contents

1. [P1 — Data Structure Recovery](#1-p1--data-structure-recovery)
2. [P2 — Type Inference & Propagation](#2-p2--type-inference--propagation)
3. [P3 — Algorithm Recognition](#3-p3--algorithm-recognition)
4. [P3 — Memory Lifecycle / RAII Detection](#4-p3--memory-lifecycle--raii-detection)
5. [P3 — Concurrency & Synchronization Detection](#5-p3--concurrency--synchronization-detection)
6. [P3 — Callback / Function Pointer Table Detection](#6-p3--callback--function-pointer-table-detection)
7. [P4 — Control Flow Pattern Recognition](#7-p4--control-flow-pattern-recognition)
8. [P4 — String & Configuration Context](#8-p4--string--configuration-context)
9. [P4 — Library & API Identification](#9-p4--library--api-identification)
10. [P4 — Constants & Enum Recovery](#10-p4--constants--enum-recovery)
11. [P4 — Endianness & Serialization Detection](#11-p4--endianness--serialization-detection)
12. [W0 — Web UI Foundation & Phase Progress](#12-w0--web-ui-foundation--phase-progress)
13. [W1 — Web UI Status & Visibility Enhancements](#13-w1--web-ui-status--visibility-enhancements)
14. [W2 — Web UI Process Control](#14-w2--web-ui-process-control)
15. [W3 — Web UI Historical & Analytical Views](#15-w3--web-ui-historical--analytical-views)
16. [W4 — Web UI New Views](#16-w4--web-ui-new-views)
17. [Global Checklist](#17-global-checklist)

---

## 1. P1 — Data Structure Recovery

**Estimated Effort:** 4–6 weeks
**Crate:** `calxgloss-typesdb`
**Dependencies:** Ghidra client port (see Phase 0a) — the bridge switches to [bethington/ghidra-mcp](https://github.com/bethington/ghidra-mcp), whose type-library endpoints (`list_data_types`, `get_struct_layout`, `get_enum_values`) close the gap that gated this phase; `list_data_items` exists in the new bridge but still has no client wrapper

### Overview

Automatic recovery of struct layouts, class hierarchies, vtables, and type aliases from binary analysis. Data flows from Ghidra through a dedicated type database recovery engine, gets persisted to disk, and is injected into LLM prompts as structured context.

### MVP Scope

| Feature | Signal Source |
|---------|--------------|
| Named types from Ghidra's Type Library | bethington bridge `list_data_types` + `get_struct_layout`/`get_enum_values` — full TypeManager, including types never applied to symbols; see Phase 0a |
| Basic struct inference from strings | bridge `list_strings` (regex filter + quality filtering) + cross-reference clustering |
| Vtable detection | `list_data_items` / `list_data_items_by_xrefs` (needs client wrapper) + `get_xrefs_to`; tag confirmed vtables with `add_function_tag` |

### Phases

#### Phase 0a — Ghidra Client Port to bethington/ghidra-mcp (Prerequisite)

**Decision (2026-10-03):** switch the bridge from the stock GhidraMCP plugin 1.4 (plain-text responses, ~20 endpoints) to [bethington/ghidra-mcp](https://github.com/bethington/ghidra-mcp) **v6.0.0 (stable)** — 272 JSON REST endpoints from the Ghidra GUI plugin on `127.0.0.1:8080` (its default port), We load on a cusotm port of 8089. plus a headless server exposing the same API. v6.0.0 is built for Ghidra 12.1.2, so no Ghidra upgrade is needed. Rationale: the two gaps that would have forced a patched fork of the stock plugin are solved upstream — TypeManager listing (`list_data_types`, `list_data_type_categories`, `search_data_types`, `get_struct_layout`, `get_enum_values`) and type creation for write-back (`create_struct`, `add_struct_field`, `modify_struct_field`, `create_enum`, `create_typedef`, `create_union`, `apply_data_type`, `set_global`). It also removes existing client workarounds: `get_function_callers`/`get_function_callees`/`get_full_call_graph`/`get_bulk_xrefs` (replaces callee-scraping from decompiled text in `function_report`), `get_metadata` (image base/arch/function count directly, replaces the min-segment `image_base()` hack), a `program=` selector on every program-scoped endpoint (fixes the silent "current program" hazard documented in `client.rs`), batch decompile (`decompile_function?functions=a,b,c`), and function tags (`add_function_tag`/`list_function_tags`).

Setup (done 2026-10-03): `GhidraMCP-6.0.0.zip` installed to `~/.config/ghidra/ghidra_12.1.2_PUBLIC/Extensions/GhidraMCP` — no build needed, the release zip is prebuilt against 12.1.2; the old LaurieWired extension was moved to `~/Downloads/GhidraMCP-lauriewired-backup`. Bridge repo: `~/Programming/ghidra-mcp` @ tag v6.0.0, run via `uv run --directory ~/Programming/ghidra-mcp bridge-mcp-ghidra` — the OpenCode MCP config now points at it. `calxgloss-ghidra` keeps talking raw HTTP to the Java plugin on 8080 (we run a custom port of 8089). Turn **Strict Naming Enforcement off** in Tool Options unless we want the Hungarian-notation gates on write endpoints; consider `GHIDRA_MCP_REQUIRE_PROGRAM_SELECTORS=1` once multiple programs can be open.

Endpoint mapping for the existing client methods (old HTTP path → new; responses are JSON only where the bridge answers JSON — most stay `text/plain`, see the Record formats note below; use `GET /mcp/schema` on the running server as the authoritative endpoint/param list):

| `calxgloss-ghidra` method | Stock plugin | bethington bridge |
|---|---|---|
| `list_functions` | `list_functions` | `list_functions` (paged: `offset`/`limit`) or `list_functions_enhanced` |
| `search_functions` | `searchFunctions` | `search_functions` |
| `decompile_function` | `decompile_function` | `decompile_function` (adds `functions=` batch + `timeout`) |
| `decompile_function_by_name` | POST `decompile` | `decompile_function?functions=<name>` |
| `disassemble_function` | `disassemble_function` | `disassemble_function` |
| `function_body` | `get_function_by_address` | `get_function_by_address` |
| `xrefs_to` / `xrefs_from` | `xrefs_to` / `xrefs_from` | `get_xrefs_to` / `get_xrefs_from` (JSON, typed ref categories) |
| `function_xrefs` | `function_xrefs` | `get_function_xrefs` |
| `exports` / `imports` | `exports` / `imports` | `list_exports` / `list_imports` |
| `strings` | `strings` | `list_strings` (regex `filter`, quality filtering) |
| `namespaces` / `classes` / `methods` | `namespaces` / `classes` / `methods` | `list_namespaces` / `list_classes` / `list_methods` |
| `segments` / `image_base` | `segments` | `list_segments`; prefer `get_metadata` for image base |
| `current_address` / `current_function` | same | same (GUI only) |
| `probe` | `get_current_address` + `get_current_function` | `check_connection` + `get_metadata` |
| *(new wrappers)* | — | `list_data_items` (paged), `list_data_items_by_xrefs`, `list_data_types`, `get_struct_layout`, `get_enum_values`, `get_function_callers`/`get_function_callees`, `get_bulk_xrefs` |

> **v6.0.0 naming:** the dev-branch docs' `set_variable_type` is `set_local_variable_type`/`set_decompiler_variable_type`/`batch_set_variable_types` in v6.0.0; `rename_symbol` is split into `rename_function`/`rename_data`/`rename_variables`/`rename_label`.

The `calxgloss-ghidra` client (`src/client.rs`) currently wraps none of the write-back tools and has no `list_data_items` wrapper; `classes()`/`methods()` return symbol names only (no field/layout data).

> **Record formats (corrected 2026-10-03, verified against the live v6.0.0 plugin):** the earlier premise that every endpoint returns JSON is wrong — the plugin still answers most endpoints `text/plain`, including the Phase 0a additions: `list_data_types` (`name | category | N bytes | path`), `list_data_items` (`LABEL @ addr [TYPE] (N bytes)`), and `get_struct_layout`/`get_enum_values` (header block + ` | ` field lines; misses arrive as prose sentinels like `Structure not found: X`, not `{"error": ...}`, so parsers must refuse them). Only a handful answer JSON (`get_current_address`, `get_current_function`, `list_imports`, `list_open_programs`); `list_data_items_by_xrefs` accepts `format=json`. `parse.rs` fixtures are re-captured live and the parsers accept both shapes. Domain facts that survive the switch: vftables appear in `list_data_items` as `vftable`-named items preceded by `vftable_meta_ptr` entries (MSVC RTTI pattern), `vftable` names are **not unique** — key by address, and `eqmain.dll` has ~22k–40k data items (page with `offset`/`limit`).

1. Port `client.rs` transport + `parse.rs` from plain-text line formats to JSON (`serde` structs replace the line parsers); update `error::classify` for JSON error bodies
2. Add the new wrappers from the mapping table — paged `list_data_items()` is the data-object source for vtable scanning, and `list_data_types` + `get_struct_layout` feed Phase 1 directly (the decompiled-pseudo-C fallback and the patched-fork option are both obsolete)
3. Wrap the write-back tools — `set_function_prototype`, `set_local_variable_type`, `rename_function`/`rename_data`, and the type-creation tools — so P2's inferred types (including new struct layouts) flow back into Ghidra
4. Re-capture unit-test fixtures live against the new bridge (no mock server exists yet); `GET /mcp/schema` documents every endpoint's params
5. `cargo clippy` clean

#### Phase 0 — Project Setup
1. Create `crates/calxgloss-typesdb` crate
2. Update workspace `Cargo.toml` with member and dependencies
3. Create module structure: `lib.rs`, `types.rs`, `scanner.rs`, `vtable.rs`, `string_infer.rs`, `persist.rs`, `error.rs`
4. Verify `cargo check` passes

#### Phase 1 — Named Type Recovery from Ghidra's Type Library
1. Define `NamedType`, `TypeKind`, `StructField` types with `Serialize`/`Deserialize`
2. Implement `TypeLibraryScanner` struct
3. Implement `scan_named_types()` — queries Ghidra and returns `Vec<NamedType>`
4. Parse `list_data_types`/`get_struct_layout` JSON (struct, class, union, enum)
5. Graceful degradation for missing/malformed types
6. Run all 11 Phase 1 unit tests
7. `cargo clippy` clean

#### Phase 2 — Vtable Detection
1. Define `Vtable`, `VtableMethod` types with `Serialize`/`Deserialize`
2. Implement `VtableDetector` struct
3. Implement `detect_vtables()` — scans `list_data_items` output for vtable-shaped data objects (e.g. `vftable`-named symbols; tag confirmed hits with `add_function_tag`)
4. Resolve method pointers to names and addresses
5. Track base class inheritance
6. COM interface detection (QueryInterface/AddRef/Release pattern)
7. Run all 8 Phase 2 unit tests
8. `cargo clippy` clean

#### Phase 3 — String-Guided Struct Inference
1. Define `InferredStruct`, `InferredField`, `FieldType` types
2. Implement `StringInferenceEngine` struct
3. Implement `infer_structures()` — full pipeline (collect → cluster → infer → score)
4. Implement confidence scoring with configurable threshold
5. Run all 8 Phase 3 unit tests
6. `cargo clippy` clean

#### Phase 4 — Integration with Translation Pipeline
1. Define `TypeDatabase`, `ScanMetadata` types
2. Implement `TypesDBEngine` — orchestrates all three scanners in parallel
3. Implement `TypeDatabasePersistor` — saves/loads JSON to `re/analysis/typesdb/`
4. Update `extract_data_structures()` (currently an empty stub in `calxgloss-translator/src/retry/helpers.rs`) to load from persisted DB
5. Implement `From<&NamedType>` and `From<&InferredStruct>` conversions to `StructuredData`
6. Add pre-processing phase to batch translation (checks cache, runs if missing)
7. Implement `calxgloss typesdb` CLI command
8. Run all engine unit tests and integration tests
9. `cargo clippy` clean

#### Phase 5 — Full Implementation TODOs (Future)
- Cross-reference clustering to group fields into structs
- Heuristic-based struct naming
- Nested structs and unions detection
- STL type detection (`std::string`, `std::vector`, `CString`)
- Output recovered structs to Rust codegen file
- Hybrid pre-processing + per-function refinement

---

## 2. P2 — Type Inference & Propagation

**Estimated Effort:** 3–4 weeks
**Crate:** `calxgloss-typeinfer`
**Dependencies:** Soft dependency on P1 (Data Structure Recovery)

### Overview

Propagate type information through function analysis — examining decompiled pseudo-C, disassembly, and known function signatures — to narrow parameter types from `undefined4` to concrete types like `Sprite *`, `u32`, `char *`.

### MVP Scope

| Feature | Signal Source |
|---------|--------------|
| C++ this-pointer detection | vtable[index] calls + first parameter usage |
| Parameter size detection | Dereference patterns (*param, param + offset) |
| Known type propagation | free(), malloc(), strlen(), and other known-library function signatures |

### Phases

#### Phase 0 — Project Setup
1. Create `crates/calxgloss-typeinfer` crate
2. Update workspace `Cargo.toml` with member and dependencies
3. Create module structure: `lib.rs`, `types.rs`, `this_ptr.rs`, `param_size.rs`, `known_type.rs`, `confidence.rs`, `persist.rs`, `error.rs` (do not create `cross_function.rs` yet — it belongs to the Phase 5 cross-function propagation work)
4. Verify `cargo check` passes

#### Phase 1 — C++ this-Pointer Detection
1. Define `InferredParamType`, `InferenceMethod`, `InferenceScope` types
2. Implement `ThisPointerDetector` struct
3. Implement `detect_this_pointer()` — parses decompiled output for vtable patterns
4. Extract class name from vtable function names
5. Avoid namespace false-positives (std::, operator::)
6. COM interface detection (IUnknown-derived)
7. Run all 8 Phase 1 unit tests
8. `cargo clippy` clean

#### Phase 2 — Parameter Size Detection
1. Implement `ParameterSizeDetector` struct
2. Implement `detect_parameter_sizes()` — scans decompiled text for pointer/integer/string patterns
3. Detect string function patterns (strlen, strcpy, strcmp, etc.)
4. Detect integer bit-pattern patterns (shift, bitwise AND)
5. Detect pointer arithmetic (offset, dereference, field access)
6. Ambiguity handling (highest confidence wins)
7. Run all 9 Phase 2 unit tests
8. `cargo clippy` clean

#### Phase 3 — Known Type Propagation
1. Implement `KnownTypePropagationEngine` struct
2. Build signature database: free, malloc, realloc, strlen, strcmp, strcpy, memcpy, memset, CloseHandle, CreateFileW
3. Implement call extraction from decompiled text
4. Name matching with prefix support (A/W suffixes)
5. Apply confidence scores per-signature
6. Run all 9 Phase 3 unit tests
7. `cargo clippy` clean

#### Phase 4 — Integration with Translation Pipeline
1. Define `TypeInferenceResult`, `InferredLocalType`, `InferredType`, `InferredCallType`, `ScanMetadata` types
2. Implement `TypeInferEngine` — orchestrates all three detectors
3. Implement `TypeInferPersistor` — saves/loads JSON to `re/analysis/typeinfer/`
4. Update `extract_type_info()` (currently an empty stub in `calxgloss-translator/src/retry/helpers.rs`) to load from persisted cache
5. Implement conflict resolution (keep highest-confidence inference per parameter)
6. Add pre-analysis to batch translation
7. Implement `calxgloss typeinfer` CLI command
8. Run all integration tests
9. `cargo clippy` clean

#### Phase 5 — Full Implementation TODOs (Future)
- Cross-function call-site propagation
- Integer bit-pattern analysis
- C++ mangling analysis
- Local variable type inference via assignment chains
- Return type inference
- Write inferred types back into Ghidra via `set_function_prototype`/`set_local_variable_type` (bethington bridge). The stock-plugin limit ("Base type not found" — no create-data-type tool) is gone: create the type first with `create_struct`/`create_enum`/`create_typedef`/`add_struct_field`, then apply it

---

## 3. P3 — Algorithm Recognition

**Estimated Effort:** 4–6 weeks
**Crate:** `calxgloss-algorithm`
**Dependencies:** Soft dependencies on P1 (Data Structure Recovery) + P2 (Type Inference)

### Overview

Detect when a function implements a known algorithm (sorting, hashing, parsing, compression, graph traversal) so the LLM gets a high-level specification to target. Results are cached per-DLL and injected into LLM prompts as structured `AlgorithmHint` sections.

### MVP Scope

| Feature | Signal Source |
|---------|--------------|
| Control flow signature matching | Decompiler pseudo-C patterns |
| String-guided algorithm hints | String literals ("CRC", "checksum", "inflate") |
| Callback pattern detection | Function signatures matching qsort-style compare functions |

### Phases

#### Phase 0 — Project Setup
1. Create `crates/calxgloss-algorithm` crate
2. Update workspace `Cargo.toml` with member and dependencies
3. Create module structure: `lib.rs`, `types.rs`, `cfg_patterns.rs`, `string_hints.rs`, `callback_db.rs`, `confidence.rs`, `persist.rs`, `error.rs`
4. Verify `cargo check` passes

#### Phase 1 — Control Flow Signature Matching
1. Define `AlgorithmHint`, `AlgorithmCategory`, `DetectionMethod`, `AlgorithmPattern` types
2. Implement `CfgPatternMatcher` struct
3. Implement `match_patterns()` — scans decompiled body against hardcoded patterns
4. Build MVP patterns: comparison sort, binary search, linear search, hash table lookup, state machine, recursion, linked list traversal
5. Regex pattern matching with configurable match/exclude patterns
6. Minimum line count check prevents false matches on tiny functions
7. Run all 13 Phase 1 unit tests
8. `cargo clippy` clean

#### Phase 2 — String-Guided Algorithm Hints
1. Implement `StringHintEngine` struct
2. Implement `detect_string_hints()` — scans decompiled body + binary strings
3. Build string signature database: CRC, checksum, inflate, deflate, gzip, bz2, lzo, serialize, deserialize, md5, sha, hmac, http, tcp, udp
4. Case-insensitive matching option per signature
5. Deduplication: same algorithm detected only once per function
6. Run all 14 Phase 2 unit tests
7. `cargo clippy` clean

#### Phase 3 — Callback Pattern Detection
1. Define `CallbackPattern`, `TypeHint` types
2. Implement `CallbackPatternDb` struct
3. Implement `detect_callback_patterns()` — matches function signatures and usage
4. Build MVP patterns: qsort compare, bsearch compare, hash table comparator
5. Caller name pattern matching via call graph
6. Run all Phase 3 unit tests
7. `cargo clippy` clean

#### Phase 4 — Integration with Translation Pipeline
1. Define `AlgorithmRecognitionResult`, `ScanMetadata` types
2. Implement `AlgorithmEngine` — orchestrates all three detectors
3. Implement `AlgorithmPersistor` — saves/loads JSON to `re/analysis/algorithm/`
4. Implement `extract_algorithm_hints()` in translation pipeline
5. Add pre-analysis to batch translation
6. Implement `calxgloss algorithm` CLI command
7. Run all integration tests
8. `cargo clippy` clean

#### Phase 5 — Full Implementation TODOs (Future)
- Confidence scoring and thresholding improvements
- Dynamic pattern database (load from JSON instead of hardcoded)
- Multi-function correlation (detect algorithms from cross-function analysis)
- Performance optimization (parallelize across functions)

---

## 4. P3 — Memory Lifecycle / RAII Detection

**Estimated Effort:** 3–4 weeks
**Crate:** `calxgloss-memory`
**Dependencies:** Soft dependency on P2 (Type Inference)

### Overview

Analysis of allocation/deallocation pairs, ownership transfer patterns, and resource lifetimes within each function and across the call graph. Results are injected as structured `MemoryHint` sections that suggest the appropriate Rust ownership pattern (`Box`, `Rc`, `Arc`, `Cow`, `ManuallyDrop`, etc.).

### MVP Scope

1. **Allocation → Deallocation pair tracking** — Within a single function, detect `malloc`/`new` paired with `free`/`delete`
2. **Handle lifecycle detection** — Detect Windows/POSIX handle creation and closure
3. **Reference counting detection** — Detect increment/decrement patterns

### Phase Structure

- **Phase 0** — Project Setup: Create `crates/calxgloss-memory` crate with standard module structure (`lib.rs`, `types.rs`, `allocator.rs`, `handle.rs`, `refcount.rs`, `persist.rs`, `error.rs`)
- **Phase 1** — Allocation/Deallocation Pair Tracking: Detect `malloc`/`calloc`/`realloc` → `free` pairs; suggest `Box<T>` or stack allocation
- **Phase 2** — Handle Lifecycle Detection: Detect `CreateFileW`/`CloseHandle`, `fopen`/`fclose` patterns; suggest RAII guard structs with `Drop` impl
- **Phase 3** — Reference Counting Detection: Detect `ref_count++`/`ref_count--` and `AddRef`/`Release` patterns; suggest `Rc<T>` / `Arc<T>`
- **Phase 4** — Integration with Translation Pipeline: Persist to `re/analysis/memory/{dll}.json`; add `extract_memory_hints()` helper; add `calxgloss memory` CLI command; integrate into prompt templates
- **Phase 5** — Full Implementation TODOs: Cross-function allocation tracking; ownership transfer detection; smart pointer conversion; resource leak detection; per-type Drop implementation suggestions

---

## 5. P3 — Concurrency & Synchronization Detection

**Estimated Effort:** 2–3 weeks
**Crate:** `calxgloss-sync`
**Dependencies:** Soft dependency on P2 (Type Inference)

### Overview

Detection of all synchronization primitives, threading constructs, and atomic operations in each function and across the call graph. Results are injected as structured `ConcurrencyHint` sections specifying the appropriate Rust synchronization primitive and threading model.

### MVP Scope

1. **Mutex/lock detection** — Detect all forms of mutex usage and classify them
2. **Atomic operation detection** — Detect inline assembly or builtin calls for atomics
3. **Threading detection** — Detect thread creation and join patterns

### Phase Structure

- **Phase 0** — Project Setup: Create `crates/calxgloss-sync` crate with standard module structure (`lib.rs`, `types.rs`, `mutex.rs`, `atomic.rs`, `threading.rs`, `persist.rs`, `error.rs`)
- **Phase 1** — Mutex/Lock Detection: Detect `pthread_mutex_lock/unlock`, `EnterCriticalSection/LeaveCriticalSection`, `pthread_rwlock_rdlock/wrlock`; suggest `std::sync::Mutex<T>`, `parking_lot::Mutex<T>`, `std::sync::RwLock<T>`
- **Phase 2** — Atomic Operation Detection: Detect `__atomic_fetch_add`, `InterlockedIncrement/Decrement`, `__sync_fetch_and_add`; suggest `std::sync::atomic::AtomicU32`/`AtomicU64`
- **Phase 3** — Threading Pattern Detection: Detect `CreateThread`, `pthread_create`, `std::thread::spawn`; suggest `std::thread::spawn` or `tokio::spawn`
- **Phase 4** — Integration with Translation Pipeline: Persist to `re/analysis/sync/{dll}.json`; add `extract_concurrency_hints()` helper; add `calxgloss sync` CLI command; integrate into prompt templates
- **Phase 5** — Full Implementation TODOs: Full data race analysis; lock ordering analysis; async runtime detection; thread-local storage detection; futex-based synchronization detection

---

## 6. P3 — Callback / Function Pointer Table Detection

**Estimated Effort:** 2–3 weeks
**Crate:** `calxgloss-callback`
**Dependencies:** Soft dependencies on P1 (Data Structure Recovery) + P2 (Type Inference)

### Overview

Detection of function pointer arrays, callback registration patterns, and dynamic dispatch mechanisms that are not C++ vtables. Results are injected as structured `CallbackHint` sections suggesting Rust representations (`fn` pointers, `Box<dyn Trait>`, `Arc<dyn Trait>`, etc.).

### MVP Scope

1. **Function pointer array detection** — Detect data objects that are arrays of pointers used as indirect call targets
2. **Callback registration detection** — Detect functions that accept function pointer parameters
3. **Jump table detection** — Detect indirect call through an array (dispatch table)

### Phase Structure

- **Phase 0** — Project Setup: Create `crates/calxgloss-callback` crate with standard module structure (`lib.rs`, `types.rs`, `fp_array.rs`, `callback_reg.rs`, `jump_table.rs`, `persist.rs`, `error.rs`)
- **Phase 1** — Function Pointer Array Detection: Detect `*(handlers[i])(args)` patterns; suggest `Box<dyn Fn(...)>`
- **Phase 2** — Callback Registration Detection: Detect `register_callback(func_ptr)` and `set_on_message(void (*callback)(...))` patterns; suggest Rust closure-based patterns
- **Phase 3** — Jump Table Detection: Detect `jmp [table + index*N]` patterns; suggest Rust `match` or function pointer arrays
- **Phase 4** — Integration with Translation Pipeline: Persist to `re/analysis/callback/{dll}.json`; add `extract_callback_hints()` helper; add `calxgloss callback` CLI command; integrate into prompt templates
- **Phase 5** — Full Implementation TODOs: Full callback chain analysis; plugin architecture detection; event system reconstruction; integration with Type Inference for closure signatures

---

## 7. P4 — Control Flow Pattern Recognition

**Estimated Effort:** 2–4 weeks
**Crate:** `calxgloss-controlflow`
**Dependencies:** Soft dependency on P2 (Type Inference)

### Overview

Analyze the control flow of each function to identify structural patterns that suggest a higher-level construct (switch statement → `match`, recursion → explicit stack, state machine → enum with `match`). Results are cached per-DLL and injected into LLM prompts.

### MVP Scope

| Feature | Signal Source |
|---------|--------------|
| Switch statement detection | if-else chain on same variable with sequential comparisons |
| Recursive function detection | Function name appears in its own decompiled body |
| State machine detection | if-else chain on single variable tracking state with transitions |

### Phases

#### Phase 0 — Project Setup
1. Create `crates/calxgloss-controlflow` crate
2. Update workspace `Cargo.toml` with member and dependencies
3. Create module structure: `lib.rs`, `types.rs`, `switch_detect.rs`, `recursion_detect.rs`, `state_machine.rs`, `confidence.rs`, `persist.rs`, `error.rs`
4. Verify `cargo check` passes

#### Phase 1 — Switch Statement Detection
1. Define `SwitchPattern` type with `Serialize`/`Deserialize`
2. Implement `SwitchDetector` struct
3. Implement `detect_switch()` — parses decompiled body for if-else-if chains
4. Extract switch variable name, count cases, check for default, extract constants
5. Minimum 3-case threshold; suggest dispatch table for 10+ cases
6. Run all 10 Phase 1 unit tests
7. `cargo clippy` clean

#### Phase 2 — Recursive Function Detection
1. Define `RecursionPattern` type with `Serialize`/`Deserialize`
2. Implement `RecursionDetector` struct
3. Implement `detect_recursion()` — scans decompiled body for self-calls
4. Count self-calls; detect tail-call status; confidence scoring
5. Run all 10 Phase 2 unit tests
6. `cargo clippy` clean

#### Phase 3 — State Machine Detection
1. Define `StateMachinePattern` type with `Serialize`/`Deserialize`
2. Implement `StateMachineDetector` struct
3. Implement `detect_state_machine()` — parses if-else chains on state variables
4. Named state constant detection (STATE_*, IDLE, RUNNING, etc.)
5. State transition assignment detection; minimum 3-state threshold
6. Run all 10 Phase 3 unit tests
7. `cargo clippy` clean

#### Phase 4 — Integration with Translation Pipeline
1. Define `ControlFlowResult`, `ScanMetadata` types
2. Implement `ControlFlowEngine` — orchestrates all three detectors
3. Implement `ControlFlowPersistor` — saves/loads JSON to `re/analysis/controlflow/`
4. Create `extract_control_flow_hints()` in translation pipeline (does not exist yet — add alongside the other extractors in `calxgloss-translator/src/retry/helpers.rs`)
5. Add `calxgloss controlflow` CLI command
6. Run all integration tests
7. `cargo clippy` clean

#### Phase 5 — Full Implementation TODOs (Future)
- Full control flow graph (CFG) extraction and structural analysis
- Accurate recursion depth analysis and tail-call detection
- Loop nesting depth detection (for vs while vs do-while vs goto)
- Branch density analysis (high = dispatch table, low = sequential scan)

---

## 8. P4 — String & Configuration Context

**Estimated Effort:** 1–2 weeks
**Crate:** `calxgloss-stringctx`
**Dependencies:** None (most independent — uses Ghidra-native string data)

### Overview

Extract all strings from Ghidra, classify each by type (user-visible, error message, file path, format string, resource name), map them to functions via hybrid cross-reference + decompiled-body analysis, and inject a structured **CONTEXT STRINGS** section into LLM prompts.

### MVP Scope

| Feature | Signal Source |
|---------|--------------|
| String classification | bridge `list_strings` (regex filter) + regex heuristics |
| Per-function string summary | Hybrid: decompiled-body parsing + `get_xrefs_to` fallback |
| Format string type inference | `%s`, `%d`, `%x`, `%.2f` → inferred parameter types |

### Phases

#### Phase 0 — Project Setup
1. Create `crates/calxgloss-stringctx` crate
2. Update workspace `Cargo.toml` with member and dependencies
3. Create module structure: `lib.rs`, `types.rs`, `classify.rs`, `hybrid_mapper.rs`, `format_str.rs`, `persist.rs`, `error.rs`
4. Verify `cargo check` passes

#### Phase 1 — String Classification
1. Define `StringContext`, `StringClassification`, `StringSource`, `FormatHint` types
2. Implement `StringClassifyEngine` struct
3. Implement `classify()` — priority-ordered pattern matching
4. 9 classification categories: UserVisible, Error, FilePath, FormatString, DebugLog, ResourceName, Network, InternalIdentifier, Generic
5. Format priority: FormatString > FilePath > ResourceName > Error > Network > DebugLog > UserVisible > InternalIdentifier > Generic
6. Implement `infer_purpose()` and `extract_format_hints()`
7. Run all 22 Phase 1 unit tests
8. `cargo clippy` clean

#### Phase 2 — Per-Function String Summary (Hybrid Cross-Ref + Decompiler)
1. Define `StringContextResult`, `ScanMetadata` types
2. Implement `HybridXrefMapper` struct
3. Implement `extract_strings_from_body()` — parse decompiled body (DAT_ refs, direct literals, format calls)
4. Implement `extract_strings_from_xrefs()` — parse `get_xrefs_to` JSON (typed ref categories; re-verify exact shape against the live bridge)
5. Hybrid fallback: skip xrefs when body has strings found
6. Deduplication by string address and value
7. Run all 12 Phase 2 unit tests
8. `cargo clippy` clean

#### Phase 3 — Format String Type Inference
1. Implement `FormatStringEngine` struct
2. Map format specifiers to Rust types (%s → `*const i8`, %d → `i32`, %.2f → `f32`, etc.)
3. Generate format string summaries for prompt injection
4. Run all Phase 3 unit tests
5. `cargo clippy` clean

#### Phase 4 — Integration with Translation Pipeline
1. Define `StringContextResult`, `ScanMetadata` types
2. Implement `StringContextEngine` — orchestrates all three engines
3. Implement `StringContextPersistor` — saves/loads JSON to `re/analysis/stringctx/`
4. Create `extract_string_context()` in translation pipeline (does not exist yet — add alongside the other extractors in `calxgloss-translator/src/retry/helpers.rs`)
5. Add `calxgloss stringctx` CLI command
6. Run all integration tests
7. `cargo clippy` clean

#### Phase 5 — Full Implementation TODOs (Future)
- Localization detection (multi-language string identification)
- Context-sensitive classification improvement
- Cross-function string correlation
- String-to-function confidence scoring

---

## 9. P4 — Library & API Identification

**Estimated Effort:** 1–2 weeks
**Crate:** `calxgloss-apidetect`
**Dependencies:** Call Graph (for caller context)

### Overview

Systematic identification of all imported and called external APIs in each function, mapped to their likely Rust crate equivalents. Results are injected into LLM prompts as structured `APISignature` sections.

### MVP Scope

1. **Import table extraction** — Parse all imported function names from the binary's import table
2. **Library-to-crate mapping** — Hardcoded database mapping common C library patterns to Rust crate names
3. **Per-function API summary** — List all imported APIs each function calls

### Phase Structure

- **Phase 0** — Project Setup: Create `crates/calxgloss-apidetect` crate with standard module structure (`lib.rs`, `types.rs`, `import_table.rs`, `lib_mapping.rs`, `api_summary.rs`, `persist.rs`, `error.rs`)
- **Phase 1** — Import Table Extraction: Parse all imported function names; handle PE/ELF import tables via Ghidra
- **Phase 2** — Library-to-Crate Mapping Database: Build mapping for DirectX 9, SDL2, Win32, POSIX, PNG, zlib, stdio, C++ STL
- **Phase 3** — Per-Function API Summary: Call graph traversal to find imported APIs called by each function
- **Phase 4** — Integration with Translation Pipeline: Persist to `re/analysis/apidetect/{dll}.json`; add `extract_api_hints()` helper; add `calxgloss apidetect` CLI command; integrate into prompt templates
- **Phase 5** — Full Implementation TODOs: API category enrichment; cross-reference with known-crate database including feature flags; Windows vs. POSIX divergence detection; COM interface method suggestions; auto-generate FFI bindings; per-DLL dependency manifest output

---

## 10. P4 — Constants & Enum Recovery

**Estimated Effort:** 2–3 weeks
**Crate:** `calxgloss-consts`
**Dependencies:** None (independent)

### Overview

Detection of constant groups that should be named enums or bitflags, magic values that should be named constants, and repeated numeric patterns suggesting protocol or format constants. Results are injected as structured `EnumHint` and `ConstantHint` sections.

### MVP Scope

1. **Bitmask enum detection** — Find groups of power-of-2 values used together in bitwise operations
2. **Sequential constant extraction** — Extract constants from switch statement cases
3. **Magic number frequency analysis** — Find constants appearing multiple times across the binary

### Phase Structure

- **Phase 0** — Project Setup: Create `crates/calxgloss-consts` crate with standard module structure (`lib.rs`, `types.rs`, `bitmask.rs`, `sequential.rs`, `frequency.rs`, `persist.rs`, `error.rs`)
- **Phase 1** — Bitmask Enum Detection: Detect power-of-2 groups used in bitwise operations; suggest `#[bitflags]` struct
- **Phase 2** — Sequential Constant Extraction: Extract constants from switch cases; classify as enum candidates
- **Phase 3** — Magic Number Frequency Analysis: Frequency analysis across the binary; suggest named constants for repeated values
- **Phase 4** — Integration with Translation Pipeline: Persist to `re/analysis/consts/{dll}.json`; add `extract_constant_hints()` helper; add `calxgloss consts` CLI command; integrate into prompt templates
- **Phase 5** — Full Implementation TODOs: Full bitmask enum reconstruction; named constant suggestion from context; protocol constant recovery; color/RGB constant grouping; integration with Data Structure Recovery; output generated code to separate Rust file

---

## 11. P4 — Endianness & Serialization Detection

**Estimated Effort:** 1–2 weeks
**Crate:** `calxgloss-serialize`
**Dependencies:** Independent — uses Ghidra-native data directly

### Overview

Detection of byte-order operations, manual bit-packing, binary serialization patterns, and known format signatures in data structures and functions. Results are injected as structured `SerializationHint` sections.

### MVP Scope

1. **Byte-swap operation detection** — Detect calls to byte-swap functions and bit-rotation patterns
2. **Bit-packing detection** — Detect manual bit extraction and insertion
3. **Magic byte detection** — Detect known file format signatures at specific data addresses

### Phase Structure

- **Phase 0** — Project Setup: Create `crates/calxgloss-serialize` crate with standard module structure (`lib.rs`, `types.rs`, `byteswap.rs`, `bitpack.rs`, `magic_bytes.rs`, `persist.rs`, `error.rs`)
- **Phase 1** — Byte-Swap Operation Detection: Detect `ntohs`, `ntohl`, `bswap32`, `__builtin_bswap32`; suggest `byteorder` crate
- **Phase 2** — Bit-Packing Detection: Detect manual `|`/`<<`/`>>` bit-packing patterns; suggest `bitvec` crate or manual masking
- **Phase 3** — Magic Byte & Format Detection: Detect known file format signatures (PNG, gzip, ZIP); suggest format-specific crates
- **Phase 4** — Integration with Translation Pipeline: Persist to `re/analysis/serialize/{dll}.json`; add `extract_serialization_hints()` helper; add `calxgloss serialize` CLI command; integrate into prompt templates
- **Phase 5** — Full Implementation TODOs: Full serialization format inference; cross-field validation detection; protocol message detection; network protocol identification; per-type endianness mapping; integration with Library API detection

---

## 12. W0 — Web UI Foundation & Phase Progress

**Estimated Effort:** 2–3 weeks (Phases 0–1)
**Crate:** `calxgloss-web`
**Dependencies:** None (builds on existing `calxgloss-web` foundation)

### Current State Summary

The web UI currently provides 5 tab-based views:

| View | Content |
|------|---------|
| **Dashboard** | Status cards (queued, pending, in_progress, accepted, send_back, blocked, merged), pipeline progress panel, review queue list, recent activity |
| **Review Queue** | Full queue list with status filter, inline detail with overview (kind, binary, function, attempt, model, confidence, staleness), test results, diff summary, diff viewer, Ghidra context tabs, action buttons (accept/send-back/patch) |
| **Dependency Graph** | Interactive node/edge graph with zoom, pan, hover tooltip, click-to-highlight neighbors |
| **Branch Cleanup** | Stale branch scanning (configurable threshold), select-and-archive table |
| **LLM I/O Log** | WebSocket-streamed request/response/error entries with clear/expand |

> **Frontend note:** `static/app.js` is a single ~2,250-line IIFE. Before adding the new views planned below, split it into per-view modules (plain ES modules, no build step) so each new view lives in its own file.

The UI is a **review gate** — it shows the *result* of each translation unit but does **not** show:
- Where we are in the overall pipeline beyond per-binary classification/batch status
- Why the LLM produced the output it did (what context tier was used, what prompt variant)
- What went wrong and how it was recovered (faults, escalations, retry strategies)
- How much we're spending (token counts, cost awareness)
- How to influence the pipeline (skip functions, force tiers, exclude binaries, set priorities)

### MVP Scope

| Feature | Signal Source |
|---------|--------------|
| Pipeline progress bar | Per-DLL classification, batch, and live progress (existing `/api/pipeline` endpoint) |
| Server health/status | `/health` and new `/api/server/status` endpoints |
| Token usage per unit | `TokenUsageLog` tracked per-attempt in `re/analysis/token_usage.json` (no web endpoint exposes it yet) |
| Fault history | `FaultLog` already tracked but invisible in UI |
| Context tier display | Context tier selection already happens but not surfaced |

### Phases

#### Phase 0 — Server Management Endpoints
1. Implement server status endpoint (`GET /api/server/status`) — returns pipeline status, server uptime, version, host, log level, memory/CPU usage, WebSocket connection count, open file handles
2. Enhance the existing `GET /health` endpoint — add repo accessibility, uptime, version (optionally alias as `GET /api/server/health`; do not leave two divergent health endpoints)
3. Implement graceful shutdown endpoint (`POST /api/server/shutdown`) — pause pipeline, complete current function, save state, stop web server
4. Implement graceful restart endpoint (`POST /api/server/restart`) — MVP scope: save state, stop server, require manual restart (the web server does not own the pipeline process; zero-downtime process forking is deferred)
5. Implement runtime log level change (`PATCH /api/server/log-level`)
6. Create `ServerStatus` type with `Serialize`/`Deserialize` in `calxgloss-web/src/server/types.rs`
7. Update server startup to track and expose resource metrics
8. Run all server lifecycle tests
9. `cargo clippy` clean

> **Router note:** `/api/pipeline` and `/api/progress` are registered **only** in the WebSocket router (`build_router_with_ws`, used by `calxgloss live`); the plain `serve` router has neither. Every endpoint added by W0–W4 must state which router(s) it registers in.

#### Phase 1 — Pipeline Progress Dashboard
1. Define `PipelinePhase`, `PhaseProgress`, `BinaryProgress` types for structured pipeline data
2. Enhance `/api/pipeline` endpoint to return per-phase progress (all 7 phases):
   - Phase 1 — Project Ingestion: Binary inventory, classification counts by category (WindowsOs, MicrosoftSdk, KnownThirdParty, ProjectSpecific, UnknownThirdParty, RuntimeLibrary)
   - Phase 2 — Disassembly & Tagging: Functions analyzed, APIs tagged, call graph built
   - Phase 3 — Test Generation: Total baseline tests generated, per-binary breakdown
   - Phase 4 — Rust Code Generation: Functions translated, LLM attempts, token usage
   - Phase 5 — Behavior Verification: Baseline pass rate, verification pass rate, cross-platform results
   - Phase 6 — Restitching: Remaining assembly count, FFI bridge entries, integration batches
   - Phase 7 — Documentation: Function registry completeness, mapping coverage
   - Note: `Calxgloss.md` also defines **Phase 2.5 (PAL Design)** — include it in the bar or fold it into Phase 2
   - Note: Phases 6 (Restitching) and 7 (Documentation) have **no backing data source in current code** — define what each reports (or mark them "not started") before building the UI
3. Build frontend `PipelinePhaseBar` component (horizontal progress bar through all 7 phases)
4. Add binary classification strategy to pipeline progress panel:
   - Strategy per binary (crate replacement / PAL mapping / full RE)
   - Per-binary function counts (total, translated, in-progress, queued, failed)
   - Per-binary token consumption
   - Per-binary success rate
   - Shim layer status and PAL trait status
5. Add time estimate based on average function translation time × remaining functions (requires per-function duration data — not persisted today; `token_usage.json` has timestamps but no durations, so add duration recording first)
6. Add quick-action buttons (Start Translation, Pause, Configure)
7. Add quality summary card (average confidence, baseline pass rate, verification pass rate)
8. Add token budget visual indicator
9. Run all integration tests
10. `cargo clippy` clean

#### Phase 2 — In-Flight Status & Token/Fault Display
1. Define `TranslationPhase` enum: GhidraFetch, ApiTagging, TestGen, ContextTier, LlmCall, Compiling, Testing, Review
2. Enhance WebSocket stream to emit per-function phase progress events
3. Add context tier info to unit detail panel:
   - Which tier was used (T0–T4)
   - Why it was selected (complexity + API count + history)
4. Add fault history to unit detail panel:
   - Fault types (match `FaultCategory` in `calxgloss-types/src/fault.rs`): ContextWindowExceeded, Hallucination, InfiniteLoop, BehaviorDivergence, ResourceExhaustion, SlowResponse, PromptCorruption
   - Severity and recovery actions taken
5. Add token count to unit detail panel (consumed across all attempts)
6. Add retry strategy display to unit detail panel (current strategy, previous strategies, success rate per strategy)
7. Add effort estimate column to queue (based on historical data)
8. Run all integration tests
9. `cargo clippy` clean

#### Phase 3 — Live Translation View
1. Define `LiveTranslationState` types for real-time function progress
2. Implement `/api/progress/enhanced` endpoint that returns per-function phase progress with elapsed time
3. Build `LiveView` with:
   - Per-function progress bars with phase labels (e.g., "LLM Call (47s)", "Compiling (8s)")
   - Context tier, retry strategy, and version shown per function
   - Baseline pass / verification pass / confidence shown per function
4. Real-time WebSocket updates for phase changes
5. `cargo clippy` clean

#### Phase 4 — Dashboard Enhancements
1. Add binary count cards (breakdown by category instead of just status counts)
2. Add "Quality summary" section with average confidence, baseline pass rate, verification pass rate
3. Add token budget visual
4. Move Pipeline Overview as default landing page option
5. `cargo clippy` clean

---

## 13. W1 — Web UI Status & Visibility Enhancements

**Estimated Effort:** 1–2 weeks
**Crate:** `calxgloss-web`
**Dependencies:** W0 Phase 0–1 (server status, pipeline progress)

### MVP Scope

| Feature | Impact | Effort |
|---------|--------|--------|
| Unit detail: context tier info | High | Low |
| Unit detail: fault history | High | Low |
| Pipeline overview phase progress | High | Medium |
| Unit detail: token count | Medium | Low |
| Pipeline panel: binary strategy | Medium | Medium |
| Server status card on dashboard | Medium | Low |

### Phases

#### Phase 0 — Unit Detail Enhancements
1. Add context tier info section to unit detail panel:
   - Display current tier (T0–T4) with label (e.g., "T2 (with_tests)")
   - Show selection rationale: complexity level, API count, historical success rate
2. Add fault history section to unit detail panel:
   - List all faults detected for this unit with severity and recovery action
   - Example: "[Error] context_window_exceeded → Split into 7 chunks, retrying"
3. Add token count display to unit overview:
   - Total tokens consumed across all attempts
   - Per-attempt token breakdown
4. Add retry strategy display:
   - Current strategy name, previous strategies used
   - Success rate per strategy shown inline
5. Add Windows API mapping section to unit detail:
   - Which Windows APIs were identified
   - Their PAL/crate mappings
6. Add call graph context section:
   - Who calls this function (callers)
   - What this function calls (callees)
7. Run all UI integration tests
8. `cargo clippy` clean

#### Phase 1 — Queue View Enhancements
1. Add priority column to queue list (HIGH / NORMAL / LOW)
2. Add skip checkbox column to queue items
3. Add estimate column showing predicted translation time
4. Add multi-select support:
   - Checkbox selection on all items
   - Batch action dropdown (Accept All, Skip All, Send Back All)
5. Add drag-and-drop reordering for queue items (requires a persistence mechanism for queue order — the queue is derived from file-based work units and has none today)
6. Wire batch actions to backend endpoints:
   - `POST /api/queue/batch-accept`
   - `POST /api/queue/batch-skip`
   - `POST /api/queue/batch-send-back`
7. Run all UI integration tests
8. `cargo clippy` clean

#### Phase 2 — Dependency Graph Enhancements
1. Add filter controls:
   - Filter by kind (function translation, shim layer, etc.)
   - Filter by status (failed, pending, all)
   - Filter by binary
2. Visual encoding enhancements:
   - Node size by token usage (larger = more tokens)
   - Node color by confidence (red = low, green = high)
   - Edge labels showing edge type (call, dependency, data flow)
3. Add export functionality:
   - Save graph as SVG/PNG
   - Shareable URL encoding current view state
4. Run all UI integration tests
5. `cargo clippy` clean

#### Phase 3 — LLM I/O Log Enhancements

> **Prerequisite:** The LLM I/O log is currently **client-side in-memory only** (a capped JS array fed by WebSocket events); prompts/responses are never persisted server-side. Full-text search and filtering by attempt/strategy require a server-side LLM I/O log (e.g. `re/analysis/llm_io/`) plus a read endpoint — build that first.

1. Add filter dropdowns:
   - Filter by binary, function, attempt number, strategy
2. Add full-text search through prompt content
3. Make entries collapsible (collapsed shows metadata, expanded shows full prompt/response)
4. Add one-click copy for prompts and responses
5. Add token count per entry in the log
6. Run all UI integration tests
7. `cargo clippy` clean

---

## 14. W2 — Web UI Process Control

**Estimated Effort:** 3–4 weeks
**Crate:** `calxgloss-web`, `calxgloss-types` (pipeline state), `calxgloss-translator` (state machine wiring)
**Dependencies:** W0 Phase 1 (pipeline progress data)

### MVP Scope

| Control | Why it matters |
|---------|---------------|
| Skip specific functions | Runtime entry points, hooks, callback stubs don't need translation |
| Skip specific binaries | Misclassified or persistently failing binaries can be excluded |
| Translate only priority functions | Focus on critical functions first (entry points, rendering path, core algorithms) |
| Force context tier | Override automatic tier selection if too aggressive |
| Set retry limits | Prevent runaway token consumption |

### Phase Structure

#### Phase 0 — Pipeline Lifecycle Control (Backend)
1. Define `PipelineState` enum in **`calxgloss-types`** (not `calxgloss-cli` — `calxgloss-web` cannot depend on the CLI): `Idle`, `Running`, `Paused`, `Stopping`, `Complete`, `Error`
2. Implement the pipeline state machine as shared `Arc` state wired between the translator pipeline and the web router (the pipeline and web server only coexist under `calxgloss live`; `serve` has no pipeline to control). Atomic transitions:
   ```
   Idle ──start()──> Running ──pause()──> Paused ──resume()──> Running
                                            │                     │
                                            │ stop()              │ stop_current()
                                            ▼                     ▼
                                      Stopping ─────────────> Complete
                                          │
                                          └───(error)──> Error
   ```
3. Implement `/api/pipeline/pause` endpoint (`POST`) — pauses at next safe point (after current LLM call finishes or timeouts)
4. Implement `/api/pipeline/resume` endpoint (`POST`) — resumes from paused state
5. Implement `/api/pipeline/stop` endpoint (`POST`) — completes current function, then halts; cleans up temp branches
6. Implement `/api/pipeline/restart` endpoint (`POST`) — restart from specified phase with scope selector (all functions, only queued, only failed)
7. Implement `/api/pipeline/cancel-current` endpoint (`POST`) — abort currently processing function
8. All lifecycle operations emit `ProgressEvent` for WebSocket consistency. Note: the WebSocket currently has **no client→server command channel** (`WsCommand` only has `Register`; inbound frames are discarded) — control must go through the REST endpoints above, or `WsCommand` must be extended
9. Run all pipeline control tests
10. `cargo clippy` clean

#### Phase 1 — Pipeline Controls UI
1. Build `PipelineControls` header component (always visible, fixed at top):
   - Status indicator: Running / Paused / Complete / Stopped
   - Target binary selector
   - Control buttons: Start, Pause, Stop, Restart, Shut Down Server
2. Implement restart options dialog:
   - Phase selector dropdown
   - Target selector (all queued, specific binary)
   - Scope selector (all functions, only queued, only failed)
   - Confirmation dialog with safety explanation
3. Implement shutdown confirmation dialog:
   - Lists actions: pause pipeline, complete current function (up to 2 min), save state, stop server
4. Wire controls to backend pipeline lifecycle endpoints
5. Real-time status updates via WebSocket events
6. Run all UI integration tests
7. `cargo clippy` clean

#### Phase 2 — Translation Scope Controls
1. Define `TranslationScope` and `TranslationConstraints` types
2. Implement scope control endpoints:
   - `POST /api/scope/set` — set global scope (which binaries to translate)
   - `POST /api/scope/skip-function` — skip a specific function
   - `POST /api/scope/priority-function` — set priority for a specific function
   - `GET /api/scope/status` — get current scope and constraints
3. Build `TranslationControls` panel component:
   - Scope checkboxes: skip runtime functions, translate project-specific, translate known third-party, skip unknown third-party
   - Priority functions list with add/remove
   - Constraints: max LLM attempts, max context tier, token budget remaining
4. Integrate scope filtering into translation pipeline queue selection
5. Run all integration tests
6. `cargo clippy` clean

#### Phase 3 — Per-Function Override Panel
1. Define `FunctionOverride` type with fields: tier_override, strategy_override, custom_hints, skip, notes
2. Implement override endpoints:
   - `POST /api/units/{id}/override` — apply overrides for a specific function
   - `GET /api/units/{id}/override` — get current overrides
   - `DELETE /api/units/{id}/override` — remove overrides
3. Build `Overrides` tab in unit detail panel:
   - Context tier force selector with apply button
   - Retry strategy force selector with apply button
   - Custom failure hints textarea (append to existing)
   - Function classification change dropdown
   - Reviewer notes textarea with submit to queue
4. Wire overrides into translation pipeline context builder
5. Run all UI integration tests
6. `cargo clippy` clean

#### Phase 4 — Binary Classification Override
1. Define `BinaryClassificationOverride` type
2. Implement override endpoint:
   - `POST /api/binaries/{name}/classification` — override binary classification
   - `GET /api/binaries/{name}/classification` — get current classification
3. Build binary classification override panel:
   - Current classification display with reasoning
   - Classification selector (WindowsOs, MicrosoftSdk, KnownThirdParty, ProjectSpecific, UnknownThirdParty, RuntimeLibrary)
   - Target crate selector for crate replacement mode
4. Integrate override into binary classification pipeline
5. Run all UI integration tests
6. `cargo clippy` clean

---

## 15. W3 — Web UI Historical & Analytical Views

**Estimated Effort:** 2–3 weeks
**Crate:** `calxgloss-web`
**Dependencies:** W0 Phase 1–2 (pipeline data, token usage, fault tracking)

### MVP Scope

| Feature | Impact | Effort |
|---------|--------|--------|
| Faults view | High — understand failure patterns | Medium |
| Token usage view | Medium — cost management | Medium |
| Strategy analytics view | Medium — improve strategy selection | Medium |
| LLM performance metrics | Low — operational insight | Medium |

### Phase Structure

#### Phase 0 — Faults & Errors View
1. Define `FaultAnalytics` type aggregating fault data by binary, type, and time
2. Implement `/api/faults` endpoint:
   - `GET /api/faults` — list all faults with filters (category, binary, date range)
   - `GET /api/faults/summary` — summary counts by category and severity
   - `GET /api/faults/by-binary` — fault counts per binary
3. Build `FaultsView` page:
   - Summary cards: total faults, warnings, errors, critical (with breakdown by type)
   - Bar chart: faults by binary
   - Table: recent faults with type, binary, function, attempt, description, recovery action
   - Trend line chart: faults per day with 3-day moving average
   - Export to CSV button
   - Filter by category and binary dropdowns
4. Run all UI integration tests
5. `cargo clippy` clean

#### Phase 1 — Token Usage View
1. Define `TokenAnalytics` type aggregating token data by binary, tier, strategy, and time
2. Implement `/api/token-usage` endpoint:
   - `GET /api/token-usage/summary` — total, successful, failed, budget remaining
   - `GET /api/token-usage/by-binary` — breakdown per binary with percentage
   - `GET /api/token-usage/by-tier` — breakdown by context tier
   - `GET /api/token-usage/by-strategy` — breakdown by retry strategy with success rate
   - `GET /api/token-usage/cost` — estimated cost based on token pricing
3. Build `TokenUsageView` page:
   - Overall tokens consumed with successful/failed split and budget indicator
   - Per-binary breakdown with horizontal bar chart
   - By context tier breakdown (T0–T4)
   - By retry strategy breakdown with success rate per strategy
   - Estimated cost display (configurable per-model pricing)
4. Run all UI integration tests
5. `cargo clippy` clean

#### Phase 2 — Strategy Analytics View
1. Define `StrategyAnalytics` type with pass rates by strategy, binary category, and complexity
2. Implement `/api/strategy-analytics` endpoint:
   - `GET /api/strategy-analytics/by-strategy` — attempts, success/fail counts, pass rate
   - `GET /api/strategy-analytics/by-category` — pass rate by binary category
   - `GET /api/strategy-analytics/by-complexity` — pass rate by complexity level
3. Build `StrategyAnalyticsView` page:
   - Pass rate table by strategy (with bar chart)
   - Pass rate table by binary category
   - Pass rate table by complexity level
   - Time range filter (last 7 days, 30 days, all time)
   - Export to CSV button
4. Run all UI integration tests
5. `cargo clippy` clean

#### Phase 3 — LLM Performance Metrics
1. Define `LlmPerformanceMetrics` type with latency percentiles, timeout rates, and response sizes
2. Implement `/api/llm-metrics` endpoint:
   - `GET /api/llm-metrics/summary` — average response time, P50/P95/P99, timeout frequency
   - `GET /api/llm-metrics/by-model` — metrics per model (if multiple models used)
   - `GET /api/llm-metrics/by-tier` — correlation between context tier and response time
3. Build `LlmPerformanceView` page or section:
   - Latency percentiles (P50, P95, P99) with trend line
   - Timeout frequency chart
   - Model-specific performance (if multi-model)
   - Context tier vs. response time correlation scatter plot
4. Run all UI integration tests
5. `cargo clippy` clean

---

## 16. W4 — Web UI New Views

**Estimated Effort:** 2–3 weeks
**Crate:** `calxgloss-web`
**Dependencies:** W0 Phase 1, W1 Phase 0–1 (pipeline data, unit detail data, binary classification)

### Phase 0 — Binaries View
1. Define `BinaryViewData` type aggregating all per-binary data
2. Implement `/api/binaries` endpoint:
   - `GET /api/binaries/list` — all binaries with summary data
   - `GET /api/binaries/{name}` — full binary detail (exports, imports, classification reasoning, per-function list)
   - `GET /api/binaries/{name}/shim-status` — shim layer status
   - `GET /api/binaries/{name}/pal-status` — PAL trait status
3. Build `BinariesView` page:
   - Binary summary table: name, category, strategy, functions (total/done/queued/failed), token usage, shim status, PAL status
   - Expandable detail panel per binary
   - Shim layer tracker: which shims exist, test pass rate, acceptance status
   - PAL trait tracker: defined traits, needed but missing traits
4. Run all UI integration tests
5. `cargo clippy` clean

### Phase 1 — Unit Detail Attempt Comparison
1. Build attempt comparison view in unit detail panel:
   - Side-by-side diff of code across all attempts (not just latest vs. main)
   - Per-attempt metadata (strategy, tier, tokens, success/failure)
   - Selectable attempt versions for comparison
2. Add attempt navigation in unit detail sidebar
3. Run all UI integration tests
4. `cargo clippy` clean

---

## 17. Global Checklist

> **Instructions:** Check off items as each phase completes. This is the single source of truth for all implementation steps across all 16 methodologies. Test counts cited below are indicative targets, not exact requirements.

### 1. P1 — Data Structure Recovery (`calxgloss-typesdb`)

- [x] **Phase 0a — Ghidra Client Port to bethington/ghidra-mcp (Prerequisite)** *(done 2026-10-03, except type write-back wrappers — deferred to P2 Phase 5, no P1 consumer; `add_function_tag` landed with vtable detection)*
  - [x] GhidraMCP 6.0.0 extension installed on Ghidra 12.1.2 (release zip → user Extensions dir; LaurieWired extension backed up to `~/Downloads/GhidraMCP-lauriewired-backup`)
  - [x] Plugin enabled in the CodeBrowser tool; `curl 127.0.0.1:8089/check_connection` green (verified live, `eqmain.dll` open); naming-enforcement setting chosen. We use a custom port of 8089 instead of the default of 8080.
  - [x] `client.rs`/`parse.rs` ported to the 6.x response formats (JSON where the bridge answers JSON — most endpoints stay `text/plain`, see the Record formats note); `error::classify` updated for JSON errors
  - [x] `list_data_items()` client wrapper + paged parser (text records, not JSON), unit-tested with re-captured fixtures + live tests
  - [x] Type-library wrappers added: `list_data_types`, `get_struct_layout`, `get_enum_values` (replaces the old strategy decision — fork/pseudo-C options obsolete)
  - [x] `read_memory()` (raw bytes via `parse_memory_bytes`) and `add_function_tag()` (POST write-back) wrappers added alongside the vtable work
  - [ ] Write-back wrappers added: `set_function_prototype`, `set_local_variable_type`, `rename_function`/`rename_data`, `create_struct`/`add_struct_field` — **deferred to P2 Phase 5** (no P1 consumer)
  - [x] `cargo clippy` clean

- [x] **Phase 0 — Project Setup**
  - [x] `calxgloss-typesdb` crate created at `crates/calxgloss-typesdb/`
  - [x] Added to workspace `Cargo.toml` members list
  - [x] Re-exported from the `calxgloss` meta-crate (`crates/calxgloss`)
  - [x] `Cargo.toml` dependencies correct (`calxgloss-ghidra`, `calxgloss-types`, `serde`, `tokio`, `tracing`, `thiserror`, `regex`)
  - [x] Module structure created: `lib.rs`, `types.rs`, `scanner.rs`, `vtable.rs`, `string_infer.rs`, `persist.rs`, `error.rs`
  - [x] `cargo check` passes with no errors
  - [x] `cargo clippy` clean

- [x] **Phase 1 — Named Type Recovery** *(done 2026-10-03, verified live against the v6.0.0 bridge with `eqmain.dll` open)*
  - [x] `NamedType`, `TypeKind`, `StructField` types defined with `Serialize`/`Deserialize` (plus `EnumMember`)
  - [x] `TypeLibraryScanner` struct implemented (generic over a `TypeLibrarySource` trait; `GhidraClient` implements it)
  - [x] `scan_named_types()` queries Ghidra and returns `Vec<NamedType>`
  - [x] Parsing handles `list_data_types`/`get_struct_layout`/`get_enum_values` responses (text formats, not JSON — see the Record formats note; prose sentinels like `Structure not found: X` refused as `NotFound`/`Malformed`)
  - [x] Graceful degradation for missing/malformed types (probe misses degrade to listing-only records; server failures abort)
  - [x] All Phase 1 unit tests pass (20: 14 scanner + 6 types) + 4 `#[ignore]`d live tests green against the running bridge
  - [x] `cargo clippy` clean
  - Verified live: `list_data_types`'s `category` filter matches the word as a case-insensitive substring against the category name **or** the type's classification (`struct`/`union`/`enum`/`typedef`/`pointer`/`array`/`function`/`primitive`) — `DataTypeService.listDataTypes`. The scanner's four kind-bucket listings rely on this; certainty = category name does not contain the kind word, and a certain bucket membership is trusted over a suspect one (a typedef in a category named e.g. `unions` would otherwise misclassify).

- [x] **Phase 2 — Vtable Detection** *(done 2026-10-03, verified live against the v6.0.0 bridge with `eqmain.dll` open)*
  - [x] `Vtable`, `VtableMethod` types defined with `Serialize`/`Deserialize`
  - [x] `VtableDetector` struct implemented (generic over a `VtableSource` trait; `GhidraClient` implements it)
  - [x] `detect_vtables()` scans `list_data_items` output for vtable-shaped data objects (`vftable`-named items keyed by address; a preceding `vftable_meta_ptr` entry is the RTTI confirmation)
  - [x] Method pointers resolved to names and addresses (table bytes read via `read_memory`; element size from the declared `pointer[N]` count)
  - [x] Base class inheritance tracked (RTTI chain: meta pointer → CompleteObjectLocator → TypeDescriptor + ClassHierarchyDescriptor; x64 RVAs resolved against the image base; `.?AVWidget@@` demangled to `Widget`)
  - [x] COM interface detection (QueryInterface/AddRef/Release pattern)
  - [x] Confirmed vtable methods tagged with `add_function_tag` (`without_tagging()` runs read-only)
  - [x] All Phase 2 unit tests pass (18: 16 detector + 2 model) + 2 `#[ignore]`d live tests green against the running bridge
  - [x] `cargo clippy` clean

- [x] **Phase 3 — String-Guided Inference** *(done 2026-10-03, verified live against the v6.0.0 bridge with `eqmain.dll` open)*
  - [x] `InferredStruct`, `InferredField`, `FieldType` types defined with `Serialize`/`Deserialize` (plus `NameOrigin`)
  - [x] `StringInferenceEngine` struct implemented (generic over a `StringSource` trait; `GhidraClient` implements it)
  - [x] `infer_structures()` runs full pipeline (collect → cluster → infer → score); collection uses the new auto-paged `list_strings()` client wrapper
  - [x] Confidence scoring implemented with configurable threshold (`with_min_confidence`, default 40; also `with_min_fields`, `with_max_literals`, `with_string_filter`, `with_pointer_size`)
  - [x] All Phase 3 unit tests pass (23: 20 engine + 3 model) + 3 `#[ignore]`d live tests green against the running bridge
  - [x] `cargo clippy` clean

- [x] **Phase 4 — Pipeline Integration** *(done 2026-10-03)*
  - [x] `TypeDatabase`, `ScanMetadata` types defined
  - [x] `TypesDBEngine` orchestrates all three scanners in parallel
  - [x] `TypeDatabasePersistor` saves/loads JSON to `re/analysis/typesdb/` (`new(workspace)` → `re/analysis/typesdb/{binary}.json`, `with_cache_dir` for an explicit dir, `exists()` as the cache check, `path_for()`; missing file → new `TypesDbError::NotFound`, corrupt file → `Json`; 10 unit tests)
  - [x] `extract_data_structures()` updated to load from persisted DB (reads `re/analysis/typesdb/{dll}.json` through `TypeDatabasePersistor`; keeps inferred candidates whose `referenced_by` names the function plus named types of classes whose vtable lists it as a method; enum members render as offset-less fields; sync now — takes workspace/dll/function instead of client/address, so `EscalatePromptCtx` gained a `workspace` field; missing/corrupt DB degrades to empty; 7 unit tests)
  - [x] `From<&NamedType>` and `From<&InferredStruct>` conversions to `StructuredData` (implemented on the recovered records in `calxgloss-typesdb/src/types.rs`; typesdb gained a `calxgloss-prompts` dependency for the target type, the translator's private conversion helpers were removed in favor of these; 4 unit tests)
  - [x] Pre-processing phase added to batch translation (`TranslationPipeline::ensure_type_database(dll)`: `exists()` cache check → skip, else run `TypesDBEngine::scan` and save; called at the top of `batch_translate` and `batch_translate_from_callgraph`; missing workspace, unreachable Ghidra server, or a failed save only log a warning and the batch proceeds; `auto.rs` now sets `with_workspace` so the database files under the output repo — `batch-translate` already set it; 3 unit tests)
  - [x] `calxgloss typesdb` CLI command implemented and wired up (`commands/typesdb.rs`: `--dll` runs the scan and saves, `--show` prints the cached database without connecting to Ghidra, `--no-tag` keeps the vtable scan read-only; exempt from the `target_dir` requirement like `config`/`gc`; verified live against the running bridge with `eqmain.dll` open — 300 named types, 73 RTTI-confirmed vtables, 38 inferred candidates in 52s)
  - [x] All 5 engine unit tests pass (canned-program orchestration: three-section assembly with RTTI vtable + inferred candidate, concurrent-scan overlap, server failure aborts the run, empty program, configuration reaching every scanner)
  - [x] All 10 integration tests pass (`tests/integration_tests.rs`, no server needed: scan → save → load round trip, `re/analysis/typesdb/` file layout, cache check gating a scan, rescan replacing the document, path/address lookups on the loaded document with layouts/methods/RTTI/evidence intact, and prompt rendering of a named struct, an enum, and an inferred candidate)
  - [x] `cargo clippy` clean (over the crates this phase touches: `calxgloss-typesdb`, `calxgloss-translator`, `calxgloss-cli`; the pre-existing `too_many_arguments` hits on `run_translation_for_dll` and `log_token_usage` carry the repo's standard `#[allow]`)

- [ ] **Phase 5 — Full Implementation (Future)**
  - [ ] Cross-reference clustering implemented
  - [ ] Heuristic-based struct naming implemented
  - [ ] Nested structs and unions detected
  - [ ] STL type detection implemented
  - [ ] Rust codegen output for recovered structs

---

### 2. P2 — Type Inference & Propagation (`calxgloss-typeinfer`)

- [x] **Phase 0 — Project Setup**
  - [x] `calxgloss-typeinfer` crate created at `crates/calxgloss-typeinfer/`
  - [x] Added to workspace `Cargo.toml` members list
  - [x] `Cargo.toml` dependencies correct (`calxgloss-ghidra`, `calxgloss-types`, `serde`, `serde_json`, `tokio`, `tracing`, `thiserror`, `regex`; unused-dependency lint allowed until the detectors land, same as `calxgloss-typesdb`)
  - [x] Module structure created: `lib.rs`, `types.rs`, `this_ptr.rs`, `param_size.rs`, `known_type.rs`, `confidence.rs`, `persist.rs`, `error.rs` (`cross_function.rs` deferred to Phase 5)
  - [x] `cargo check` passes with no errors
  - [x] `cargo clippy` clean

- [x] **Phase 1 — C++ this-Pointer Detection** *(done 2026-10-04)*
  - [x] `InferredParamType`, `InferenceMethod`, `InferenceScope` types defined *(done 2026-10-04, with 5 unit tests)*
  - [x] `ThisPointerDetector` struct implemented *(done 2026-10-04, stateless over `DecompiledFunction` text — the decompile fetch happens once per function in the orchestrating engine and is read by all three detectors, unlike the P1 scanners which own their sources; 2 unit tests)*
  - [x] `detect_this_pointer()` parses decompiled output for vtable patterns *(done 2026-10-04, string-aware indirect-call scan: cast-stripped double-deref callee + this-argument match, inline and hoisted-table-base spellings; unnamed class reads as `void *` at class scope, one strongest-evidence record per parameter; 13 unit tests)*
  - [x] Class name extraction from vtable function names *(done 2026-10-04, qualified member calls in the body (`Widget::paint(param_1, ...)`, cast-stripped first argument, destructor segments, nested namespace chains) and the analyzed function's own demangled name name the class; name beside a vtable dispatch narrows the record to `Class *` at VtableCall confidence 90, name alone reads as FirstParamUsage at 80; 8 unit tests)*
  - [x] Namespace false-positive avoidance *(done 2026-10-04, `class_name` refuses qualified chains carrying a `std` or `operator` segment — `std::string::compare(param_1)` and `Widget::operator()(param_1)` name no class, covering body calls and the analyzed function's own demangled name; whole-segment match, so `MyStd::string::paint` still names its chain; 3 unit tests)*
  - [x] COM interface detection *(done 2026-10-04, IUnknown slot prefix: each indirect dispatch resolves to a vtable slot (`[N]` index, `+ 0xNN` table byte offset ÷ 8, bare double-deref slot 0; an offset added to the object — `**(param_1 + 0x10)` — is slot 0 of a secondary table), and a parameter dispatched at two or three of slots 0/1/2 (QueryInterface/AddRef/Release) reads as `IUnknown *` via ComInterface at 88, below a named class but above an anonymous vtable call; 8 unit tests)*
  - [x] All Phase 1 unit tests pass (39: 34 this-pointer detector + 5 model)
  - [x] `cargo clippy` clean

- [x] **Phase 2 — Parameter Size Detection** *(done 2026-10-04)*
  - [x] `ParameterSizeDetector` struct implemented *(done 2026-10-04, stateless over `DecompiledFunction` text like the this-pointer detector — one detector serves the whole scan, the decompile fetched once per function and read by every detector; 2 unit tests)*
  - [x] `detect_parameter_sizes()` scans for pointer/integer/string patterns *(done 2026-10-04, one pass over the body per function: a string-aware direct-call scan matches callees against the string-function table and reads a parameter sitting in a character-pointer position as `char *` (casts seen through), and a whole-word occurrence scan reads shift/bitwise-AND operands as `u32` and stars or numeric offsets something reads through as `void *`, refusing multiplies, logical `&&`, unary address-of, and bare offsets; at most one reading per parameter per family with the first matching shape in source order as evidence, each scoped to its function — readings from competing families all stand until conflict resolution; 13 unit tests)*
  - [x] String function detection (strlen, strcpy, strcmp, etc.) *(done 2026-10-04, the table grown from the core six to the full C string family — `strlen`/`strnlen`, `strcpy`/`strncpy`, `strcat`/`strncat`, `strcmp`/`strncmp`/`strcasecmp`/`strncasecmp`, `strchr`/`strrchr`, `strstr`, `strpbrk`/`strspn`/`strcspn`, `strtok`, `strdup`/`strndup`, and the `sprintf`/`snprintf`/`vsprintf`/`vsnprintf` line — entries name the argument positions their contract reads as `char *` instead of a leading count, so `snprintf`'s format behind its size argument still reads while count, character, buffer-size, and variadic-tail positions get no reading; 5 unit tests)*
  - [x] Integer bit-pattern detection (shift, bitwise AND) *(done 2026-10-04, the skeleton's shape reading deepened with width weighing: the constant beside each bit operation bounds the parameter's width — a mask needs its own bit length, a shift the parameter is the operand of needs one bit more than its count, and left-hand masks (`0x100000000 & param_1`) and compound `&=` masks count; constants the word covers keep `u32` at 55, a mask or count beyond it (`param_1 & 0xffffffff00`, `param_1 >> 0x20`) widens the reading to `u64` at 60 with the line carrying the widest constant as evidence; refused: a shift whose count the parameter supplies (`0x20 << param_1`) and a parameter behind a cast (`(ulonglong)param_1 << 0x20`) — the cast types the expression; integer suffixes (`0xffffffffu`) parse without changing the width; 10 unit tests)*
  - [x] Pointer arithmetic detection (offset, dereference, field access) *(done 2026-10-04, the pointer family completed beside the skeleton's dereferencing star (`*param_1`, `(code *)*param_1`) and read-through numeric offset (`*(undefined4 *)(param_2 + 4)`): an arrow into a field (`param_1->count`, chained `param_1->next->value` — the arrow only exists on a pointer) and an array index (`param_2[2]` — the decompiler indexes what it types as a pointer) now read the parameter as `void *` at 65; a field's own bit operations (`param_1->flags & 0xff`) still read the field, not the parameter, as an integer; 3 unit tests)*
  - [x] Ambiguity handling (highest confidence wins) *(done 2026-10-04, competing family readings for one parameter resolve inside the detector: the highest-confidence reading is kept and the rest dropped — `strcpy`'s `char *` (70) beats a bare dereference's `void *` (65), which beats a pinned `u64` (60) and the default word (55) — a tie keeps the reading the body showed first, and the winner's evidence line travels with the record; 4 unit tests)*
  - [x] All Phase 2 unit tests pass (36: 2 detector state + 8 string family + 11 integer family + 7 pointer family + 4 misc/refusals + 4 ambiguity resolution)
  - [x] `cargo clippy` clean

- [x] **Phase 3 — Known Type Propagation** *(done 2026-10-04)*
  - [x] `KnownTypePropagationEngine` struct implemented *(done 2026-10-04, stateless over `DecompiledFunction` text like the this-pointer and parameter-size detectors — one engine serves the whole scan, the decompile fetched once per function and read by every detector; 2 unit tests)*
  - [x] Signature database: free, malloc, realloc, strlen, strcmp, strcpy, memcpy, memset, CloseHandle, CreateFileW *(done 2026-10-04, `KNOWN_SIGNATURES` in `known_type.rs`: `KnownSignature` entries carry the callee name, per-position `SignatureArg` readings, and a per-signature confidence; the contracts propagate `void *` to heap blocks/handles/raw buffers, `char *` to the string trio, `size_t` to allocator and byte-routine counts, `i32` to `memset`'s fill value (the position separating it from `memcpy`), and `wchar_t *` to `CreateFileW`'s name — the reading telling the `W` twin apart from its `A` spelling; positions the contract does not read (`CreateFileW`'s modes and flags) are absent, so an argument there gets no reading; confidence 70 for the C library names — same evidence class as the size detector's string-call readings, the trio deliberately repeating that table and letting conflict resolution pick — and 75 for the distinctive Win32 names; the engine exposes the shared set via `signatures()`; 9 unit tests)*
  - [x] Call extraction from decompiled text *(done 2026-10-04, the engine's `extract_calls()` walks a `DecompiledFunction` body with a string-aware scan and returns `ExtractedCall` records in source order — callee name, each top-level argument's text (split at depth-0 commas only, so nested calls and indexed operands stay whole), and the trimmed source line holding the call as evidence; plain-identifier callees only — indirect/vtable dispatches name no callee, and a name preceded by `.` or `->` is a member access; the control-flow keywords Ghidra writes with a parenthesised operand (`if`, `while`, `for`, `switch`, `case`, `return`, `sizeof`) are not calls, though calls inside their conditions are extracted; string literals are skipped whole, escaped quotes included, so a `name(` spelled inside a format string invents no call site; a truncated decompile's unbalanced argument list yields nothing, and nested calls are each extracted — `strlen(strcpy(a, b))` yields both sites; 11 unit tests)*
  - [x] Name matching with prefix support *(done 2026-10-04, the engine's `match_signature()` resolves a callee name against the database: exact spelling first, then the Win32 `A`/`W` family — an entry carrying a tail stands for both spellings of its base, so a `CreateFileA` call site resolves to the `CreateFileW` entry — and the returned `SignatureMatch` pairs the entry with the callee's own spelling, from which `resolved_args()` settles the character-set readings: a `W` tail reads string positions as `wchar_t *` and any other spelling as `char *`, while buffer, count, and fill-value readings stay the entry's own; refused: bare base names (the macro form never reaches a PE import table, and the tail letter is the only character-set evidence), longer or different contracts (`CreateFile2`, `CreateFileExW`, `myCreateFileW`), and suffixed callees beside tail-less entries (`CloseHandleA`, `strlenA`) — an entry without a tail opens no family; 9 unit tests)*
  - [x] Confidence scores per-signature *(done 2026-10-04, the engine's `propagate_known_types()` reads each matched call site's arguments at the contract positions into `InferredParamType` records (`known_signature` method), each carrying its entry's own confidence — 70 for the C library contracts, 75 for the distinctive Win32 names — with the character-set readings settled by the callee's spelling (`CreateFileA` sites propagate `char *`, the `W` twin `wchar_t *`); casts are seen through, an argument that is not one of the function's parameters (a local, a literal, a nested call) names no parameter to read, and a position the contract does not read (`CreateFileW`'s modes and flags) reads nothing sitting there; every reading carries `program` scope — the contract behind it holds at every call site carrying the same value, not just the site that produced the record — and when several call sites read one parameter differently the strongest signature wins and the rest drop (`CloseHandle`'s `void *` at 75 over `strlen`'s `char *` at 70), ties keeping the reading the body showed first; 9 unit tests)*
  - [x] All Phase 3 unit tests pass (40: 2 engine state + 9 signature database + 11 call extraction + 9 name matching + 9 confidence propagation)
  - [x] `cargo clippy` clean

- [x] **Phase 4 — Pipeline Integration** *(done 2026-10-04)*
  - [x] `TypeInferenceResult`, `InferredLocalType`, `InferredType`, `InferredCallType`, `ScanMetadata` types defined *(done 2026-10-04, `types.rs`: `InferredLocalType` (function + decompiled variable name + the shared payload) and `InferredCallType` (function + callee + argument position + optional argument name + payload) as siblings of `InferredParamType`; `InferredType` is the union over the three record kinds — serde-tagged by `kind` (`param`/`local`/`call_site`) with `function()`/`inferred_type()`/`confidence()` accessors reaching through every variant; `TypeInferenceResult` is the per-binary document — shared `ScanMetadata` (re-exported from `calxgloss-types`, typesdb convention) plus the inference list in scan order, empty list omitted from JSON, with `new`/`for_function`/`is_empty`; 9 unit tests)*
  - [x] `TypeInferEngine` orchestrates all three detectors *(done 2026-10-04, `engine.rs`: engine generic over a new `DecompileSource` trait (`functions()` + `decompile(name)`, implemented for `GhidraClient` via `list_functions`/`decompile_function_by_name`; RPITIT `Send` futures like the typesdb source traits, canned-source tests run the whole orchestration without a server) — one sequential pass over the function listing decompiling each function exactly once and reading it with all three detectors, unlike the P1 scans which own disjoint endpoint sets; records wrapped as `InferredType::Param` in scan order (function by function; this-pointer readings, then size readings, then known-signature readings) so two scans diff cleanly; a function whose body Ghidra cannot produce — or a nameless listing entry, which would send the by-name lookup into an arbitrary body — is skipped with a warning, only a failed listing aborts the run; competing readings for one parameter (`strlen` as string call and known signature) all stand until conflict resolution; metadata stamped with scan duration; 7 unit tests)*
  - [x] `TypeInferPersistor` saves/loads JSON to `re/analysis/typeinfer/` *(done 2026-10-04, `persist.rs`: wraps `calxgloss_types::persist::JsonStore<TypeInferenceResult>` the way the typesdb and call graph persistors do — `new(workspace)` → `re/analysis/typeinfer/{binary}.json`, `with_cache_dir` for an explicit dir, `exists()` as the cache check, `path_for()`; `save` keys the document on its metadata's binary name (a rescan replaces the previous document), `load` reads the whole document back — missing file → new `TypeInferError::NotFound` variant naming the path, corrupt file → `Json`, mapped from the store's `PersistError` through a new `From` impl; 10 unit tests)*
  - [x] `extract_type_info()` updated to load from persisted cache *(done 2026-10-04, reads `re/analysis/typeinfer/{dll}.json` through `TypeInferPersistor` and keeps the inferences made for the target function via `for_function`; sync now — takes workspace/dll/function instead of Ghidra client/name, so the escalate call site passes its existing `workspace` field; missing/corrupt cache degrades to empty like the data-structure extractor; prompt conversion `From<&InferredType> for TypeInfo` lives on the record in `types.rs` (typeinfer gained a `calxgloss-prompts` dependency, typesdb convention) — the name is what the inference types (`param_1`, unnamed parameters fall back to `param_{n}`, `local_8`, `CloseHandle(param_2)` / `CloseHandle arg 1`) and the description the narrowed type with method and confidence; translator gained a `calxgloss-typeinfer` dependency; 4 unit tests in types.rs + 5 in the translator)*
  - [x] Conflict resolution (highest-confidence per parameter) *(done 2026-10-04, `confidence.rs`: `resolve_conflicts()` collapses the records several detectors made for one target — each detector already resolves its own readings internally, but detectors read a body independently, so a finished scan can carry e.g. `strlen`'s argument read by the size detector and the known-signature engine at once — keyed per target: a parameter by function + position, a local variable by function + decompiled name, a call-site argument by function + callee + position; the highest-confidence record wins, ties keep the record the scan showed first, and the survivor stands where its target first appeared so the list keeps scan order and two scans diff cleanly; `TypeInferEngine::scan` runs it before assembling the result, so the persisted document carries at most one inference per target — the `strlen` tie keeps the size detector's `char *` (shown first), a `CloseHandle` + `strlen` contest keeps the Win32 `void *` at 75; 8 unit tests + 1 engine test)*
  - [x] Pre-analysis added to batch translation *(done 2026-10-04, `TranslationPipeline::ensure_type_inference(dll)` at the top of `batch_translate` and `batch_translate_from_callgraph`, beside the type database pre-processing: `exists()` cache check → skip, else run `TypeInferEngine::scan` and save to `re/analysis/typeinfer/{dll}.json`; missing workspace, unreachable Ghidra server, or a failed save only log a warning and the batch proceeds; 3 unit tests)*
  - [x] `calxgloss typeinfer` CLI command implemented *(done 2026-10-04, `commands/typeinfer.rs`: `handle_typeinfer` mirrors the typesdb command — `--dll` names the persisted file, runs `TypeInferEngine::scan` against the open Ghidra program and saves to `re/analysis/typeinfer/{dll}.json`; `--show` prints the cached document without connecting to Ghidra, a missing cache failing with a message pointing at the command; the report shows file, scan timestamp and duration, inference counts broken down by record kind, a per-detector-method breakdown wrapping onto continuation lines, top confidence, and up to ten inference rows — function, target, narrowed type, confidence colored by score with the method behind it; exempt from the `target_dir` requirement like `config`/`gc`/`typesdb`; beside it, the shared `println_content` padding helper counted visible *bytes* against the line width while its cut counted characters, so a line carrying a multi-byte bullet printed empty — it now counts characters)*
  - [x] All integration tests pass *(done 2026-10-04, `tests/integration_tests.rs`: a canned `DecompileSource` drives scan → save → load → consume without a server — the document round-trips exactly filed under `re/analysis/typeinfer/`, the persisted list carries at most one inference per parameter, a loaded result answers the pipeline's per-function lookups and renders into `TypeInfo` prompt data with scope and confidence surviving the round trip, `exists()` gates the scan, a rescan replaces the document, and two binaries stay independent; whole-workspace suite green)*
  - [x] `cargo clippy` clean *(done 2026-10-04, workspace `--all-targets` with `-D warnings`)*

- [ ] **Phase 5 — Full Implementation (Future)**
  - [ ] Cross-function call-site propagation
  - [ ] Integer bit-pattern analysis
  - [ ] C++ mangling analysis
  - [ ] Local variable type inference
  - [ ] Return type inference
  - [ ] Write inferred types back into Ghidra (`set_function_prototype`/`set_local_variable_type`; create missing types first via `create_struct`/`create_enum`/`create_typedef`)

---

### 3. P3 — Algorithm Recognition (`calxgloss-algorithm`)

- [x] **Phase 0 — Project Setup** *(done 2026-10-04)*
  - [x] `calxgloss-algorithm` crate created at `crates/calxgloss-algorithm/`
  - [x] Added to workspace `Cargo.toml` members list
  - [x] `Cargo.toml` dependencies correct (`calxgloss-ghidra`, `calxgloss-types`, `serde`, `serde_json`, `tokio`, `tracing`, `thiserror`, `regex`; unused-dependency lint allowed until the detectors land, same as `calxgloss-typesdb` and `calxgloss-typeinfer`)
  - [x] Module structure created: `lib.rs`, `types.rs`, `cfg_patterns.rs`, `string_hints.rs`, `callback_db.rs`, `confidence.rs`, `persist.rs`, `error.rs`
  - [x] `cargo check` passes with no errors
  - [x] `cargo clippy` clean

- [x] **Phase 1 — Control Flow Signature Matching** *(done 2026-10-04)*
  - [x] `AlgorithmHint`, `AlgorithmCategory`, `DetectionMethod`, `AlgorithmPattern` types defined *(done 2026-10-04, with 6 unit tests; `Confidence`/`ScanMetadata` re-exported from `calxgloss-types`, typesdb/typeinfer convention — `AlgorithmCategory` covers the families the three detectors hint at (sorting, searching, hashing, checksum, compression, serialization, parsing, state_machine, traversal, recursion, network_protocol), `DetectionMethod` names the three detectors (cfg_pattern, string_hint, callback_pattern), `AlgorithmPattern` is the cfg matcher's signature shape — name, category, all-must-match regexes, any-matches-reject exclusions (omitted from JSON when empty), and a minimum line-count floor (`DEFAULT_MIN_LINES` 10), and `AlgorithmHint` is the per-function record: function, algorithm, category, method, confidence, evidence)*
  - [x] `CfgPatternMatcher` struct implemented *(done 2026-10-04, holds the configurable signature set a scan reads bodies against — `AlgorithmPattern` records supplied whole with `with_patterns` or grown one at a time with `add_pattern`, reported in configuration order by `patterns()` so two matchers built alike scan identically; `new()` starts with no signatures until the standard set is built, `Default`/`Clone`/`PartialEq` derived so construction is free and alike matchers compare equal, and the matcher is `Send + Sync` — one matcher serves a whole scan, shared by reference across concurrent per-function passes, holding no Ghidra client and never writing back to the program; 4 unit tests)*
  - [x] `match_patterns()` scans decompiled body against hardcoded patterns *(done 2026-10-04, reads a `DecompiledFunction` body against every configured signature in configuration order and emits one `AlgorithmHint` per fit — the line floor runs before any regex (a body shorter than `min_lines` is too small to carry a real shape and is refused outright), then every required regex must match the body and no exclusion regex may; each hint names the pattern and its category, is marked `cfg_pattern` at confidence 60 (the body carries every shape the signature requires, but regexes over pseudo-C approximate the algorithm rather than prove it), and carries the trimmed body line holding the first match of the signature's first required regex as evidence; a signature asserting nothing fits nothing, and one carrying an uncompilable regex can make no claim — it matches nothing, an uncompilable exclusion rejects nothing; 11 unit tests)*
  - [x] MVP patterns: comparison sort, binary search, linear search, hash table lookup, state machine, recursion, linked list traversal *(done 2026-10-04, `default_patterns()` carries the standard signature set in scan order and `CfgPatternMatcher::with_default_patterns()` builds a matcher that scans against it — `comparison_sort` (loop inside a loop + ordering `<` + the three-assignment swap shape the decompiler emits, excluding bodies that call `qsort`), `binary_search` (probe loop + halved range `/ 2`/`>> 1` + midpoint `if`/`<>` comparison), `linear_search` (scan loop + `==` target test + early `return`/`break`, excluding halved ranges and `% ` bucket folding so a hash probe reads as a lookup, not a plain scan), `hash_table_lookup` (`% ` digest fold + `[` bucket access + probe/bucket check), `state_machine` (state/status/mode-named variable + `if`/`switch` dispatch + `else`/`case` chain), `recursion` (self-call via a new `{name}` placeholder — the matcher substitutes the scanned function's name, regex-escaped, into match and exclude sources, and the `);` tail keeps the signature line, where the name also appears, from reading as a call; its floor drops to 6 because a self-call is precise evidence even in a short body), `linked_list_traversal` (walk loop + `->` field reads + cursor advance `= x->`); 11 unit tests)*
  - [x] Regex pattern matching with configurable match/exclude patterns *(done 2026-10-04, the matcher's signature set is fully configurable — supplied whole with `with_patterns` or grown one at a time with `add_pattern`, reported in configuration order by `patterns()` — and each `AlgorithmPattern` carries its own regex sources: every one in `match_patterns` must appear in the body and any one in `exclude_patterns` rejects the match, so signatures can be tuned or new algorithms added without touching the matcher; both lists accept the `{name}` placeholder the matcher substitutes with the regex-escaped scanned function name; a broken source can never fabricate or veto a hint — an uncompilable match regex makes the signature match nothing and an uncompilable exclusion rejects nothing)*
  - [x] Minimum line count check prevents false matches *(done 2026-10-04, each pattern carries a `min_lines` floor — `AlgorithmPattern::DEFAULT_MIN_LINES` 10 for the standard set, dropped to 6 for `recursion` where a self-call is precise evidence even in a short body — and the floor runs before any regex in `match_patterns()`: a body shorter than it is too small to carry a real control flow shape and is refused outright, so the standard set stays quiet on a five-line stub; the floor is inclusive — a body spanning exactly `min_lines` lines clears it)*
  - [x] All 13 Phase 1 unit tests pass *(done 2026-10-04 — 32 unit tests pass: 6 in `types` (hint/pattern serde round trips, snake_case labels, pattern defaults) and 26 in `cfg_patterns` (matcher configuration and sharing, hint shape and evidence line, required-shape/exclusion/line-floor behavior, and each of the seven standard signatures recognized from a realistic decompiled body while the set stays quiet on tiny bodies); the plan's 13 was an indicative count)*
  - [x] `cargo clippy` clean *(done 2026-10-04, `cargo clippy --workspace --all-targets` with no warnings; `cargo fmt` clean)*

- [x] **Phase 2 — String-Guided Algorithm Hints** *(done 2026-10-04)*
  - [x] `StringHintEngine` struct implemented *(done 2026-10-04, holds the configurable signature set a scan reads against — `StringSignature` records (named algorithm, category, and the marker spellings that suggest it, `Serialize`/`Deserialize` with a `new` constructor like `AlgorithmPattern`) supplied whole with `with_signatures` or grown one at a time with `add_signature`, reported in configuration order by `signatures()` so two engines built alike scan identically; `new()` starts with no signatures until the string database is built, `Default`/`Clone`/`PartialEq` derived so alike engines compare equal, and the engine is `Send + Sync` — one engine serves a whole scan, shared by reference across concurrent per-function passes, holding no Ghidra client and never writing back to the program; 5 unit tests)*
  - [x] `detect_string_hints()` scans decompiled body + binary strings *(done 2026-10-04, takes the function's `DecompiledFunction` beside the program's `StringLiteral` listing — fetched once per binary by the orchestrating engine and read by every function, like the typeinfer detectors reading one shared decompile — and emits one `AlgorithmHint` per fitting signature in configuration order: a signature fits when any of its markers appears as a substring of the body or of a listing string, the body read first so a marker the function's own text carries wins the hint at confidence 60 (a substring hit evidences use rather than implementation — the hint sits beside a cfg match as a hypothesis) with the trimmed body line carrying the first marker match as evidence, while a listing-only match stands at 30 (program-wide evidence: it ties the program to the algorithm, not the function to its implementation) with the listing string itself as evidence; each signature yields at most one hint per function however many of its markers appear and however many places carry them, a signature asserting no marker fits nothing, and markers match the scanned text case-sensitively for now; 10 unit tests)*
  - [x] String signature database: CRC, checksum, inflate, deflate, gzip, bz2, lzo, serialize, deserialize, md5, sha, hmac, http, tcp, udp *(done 2026-10-04, `default_signatures()` in `string_hints.rs` carries the standard set in scan order and `StringHintEngine::with_default_signatures()` builds an engine that scans against it — fifteen signatures, each naming one algorithm by the spellings it actually appears under: the uppercase acronym where strings and names shout it (`CRC`, `HTTP`, `MD5Final`) and the lowercase spelling decompiled identifiers carry (`crc_table`, `inflate`, `sha1_block_data_order`), so one signature stands for both worlds even though markers match case-sensitively; markers are plain substrings and the set leans on that deliberately — `crc` answers every `crc32`/`crc16`/`crc_table` spelling and `http` every `https` — and where a substring would mislead it stays quiet: `sha` names only its digit-suffixed family (`sha1`/`sha2`/`sha3`), so `shadow` suggests no digest; where the overlap is real it reads through: `deserialize` carries `serialize`, so a mention of one reads as the whole serialization family, each signature with its own hint; 8 unit tests)*
  - [x] Case-insensitive matching per signature *(done 2026-10-04, `StringSignature` gained a `case_insensitive` flag — set with a `case_insensitive()` builder toggle over the exact-spelling `new` default — and a case-folded signature's markers match any casing of the scanned text: the fold runs over chars, not bytes, so the found offset stays a boundary of the original text and the evidence line reports the text's own casing; the flag is omitted from JSON when false and defaults to false on read, so signatures persisted before it existed still load; the standard set keeps spelling both casings rather than folding, keeping every marker an exact spelling of what it saw; 4 unit tests)*
  - [x] Deduplication: same algorithm detected only once per function *(done 2026-10-04, signatures naming the same algorithm fold into one hint per function: the strongest-evidence hint wins — a body match takes the hint even when a listing-only signature naming the same algorithm is configured first — ties keep the signature configured first, and the survivor holds the place the algorithm first appeared, so the hint list keeps configuration order and two scans diff cleanly; 4 unit tests)*
  - [x] All 14 Phase 2 unit tests pass *(done 2026-10-04 — 31 unit tests pass in `string_hints` (5 engine configuration + 10 detection + 8 standard set + 4 case-insensitive + 4 deduplication), 63 crate-wide; the plan's 14 was an indicative count)*
  - [x] `cargo clippy` clean *(done 2026-10-04, workspace `--all-targets` with `-D warnings`; `cargo fmt` clean)*

- [x] **Phase 3 — Callback Pattern Detection** *(done 2026-10-05)*
  - [x] `CallbackPattern`, `TypeHint` types defined *(done 2026-10-04, in `callback_db.rs` beside the detector that reads them, like `StringSignature` in `string_hints.rs`: `CallbackPattern` is the callback contract shape — the recognized callback role (`qsort_compare`), the host algorithm's category, host-name regex sources matched against caller names, the arity the contract expects, and two optional fields omitted from JSON when empty (body-shape regex sources the callback's body must carry, and the type hints the contract implies), all `Serialize`/`Deserialize` with snake_case categories and a `new` constructor plus `body_patterns`/`type_hints` builder toggles; `TypeHint` pairs a `TypeTarget` — the callback's return or its parameter at a 0-based index, serialized `"return"` / `{"param":N}` — with the C spelling the contract states for that position (`const void *`, `int`), built through `TypeHint::param`/`TypeHint::return_value`, so recognizing the role types the analyzed function's parameters and return beside naming its algorithm; 6 unit tests)*
  - [x] `CallbackPatternDb` struct implemented *(done 2026-10-04, holds the configurable contract set a scan reads functions against — `CallbackPattern` records supplied whole with `with_patterns` or grown one at a time with `add_pattern`, reported in configuration order by `patterns()` so two databases built alike scan identically and results diff cleanly; `new()` starts with no contracts until the set is built, `Default`/`Clone`/`PartialEq` derived so construction is free and alike databases compare equal, and the database is `Send + Sync` — one database serves a whole scan, shared by reference across concurrent per-function passes, holding no Ghidra client and never writing back to the program; 4 unit tests)*
  - [x] `detect_callback_patterns()` matches function signatures and usage *(done 2026-10-05, `CallbackPatternDb::detect_callback_patterns()` — handed the analyzed `DecompiledFunction` beside its caller names, reports each contract the function fits on both halves at once, in configuration order: the signature half requires the function to take exactly the contract's `param_count` parameters — the arity Ghidra's inferred signature line carries, read through `parameter_names` — and its body to carry a match for every `body_patterns` shape, a contract demanding no body shape fitting on signature and usage alone; the usage half is the same reading `match_callers()` reports — one of the contract's hosts reaching the function through the call graph — and the matched caller name stands as the hint's evidence; each fit is reported as a `CallbackDetection` pairing the shared `AlgorithmHint` (marked `callback_pattern` at confidence 75 — two independent signals agree, but the reading still rests on regexes over pseudo-C rather than a resolved indirect-call target, so it stands above a lone control flow or string match and below a direct vtable dispatch) with the contract itself, whose `type_hints` the fit carries over to the analyzed function's signature; a contract whose hosts never reach the function claims nothing, a function of the wrong arity fits no contract, and an uncompilable body pattern matches nothing, the same graceful degradation as the other detectors; 13 unit tests)*
  - [x] MVP patterns: qsort compare, bsearch compare, hash table comparator *(done 2026-10-04, `default_patterns()` in `callback_db.rs` carries the standard contract set in scan order and `CallbackPatternDb::with_default_patterns()` builds a database that scans against it — three contracts, each stating the callback signature its host demands: `qsort_compare` (Sorting, host `\bqsort\b`) and `bsearch_compare` (Searching, host `\bbsearch\b`) take two opaque element pointers and answer an ordering `int`, their bodies required to carry a comparison between two pointer touches in one statement (the `[^-]` guard keeps a field-access arrow's `>` from reading as a comparison); `hash_comparator` (Hashing, hosts `\bhash_(?:insert|lookup|find|add)\b`) narrows the same shape to `==` — a comparator answers equality, not ordering — and is reached through the insert/lookup helpers that probe a bucket; host names are word-anchored so the caller reads as the host itself — the import symbol appearing in the call graph — and a name merely carrying the host's letters stays outside: `qsort_s`'s callback takes a context parameter the two-parameter contract does not expect; 3 unit tests)*
  - [x] Caller name pattern matching via call graph *(done 2026-10-04, `CallbackPatternDb::match_callers()` — handed the analyzed function's caller names read from the call graph, `String` or `&str` alike — matches them against every configured contract's host-name regexes and reports each contract the function is used as a callback for as a `HostMatch { pattern, caller }`, in configuration order: a contract matches when any caller name carries a match for any of its host patterns — being reached by one of the hosts that take this callback is what separates a callback from an ordinary callee — and it reports once however many callers fit, the first caller name that matched standing as the evidence a detection will report; a contract with no host patterns claims nothing and an uncompilable host pattern matches nothing, the same graceful degradation as the cfg matcher; the database still holds no Ghidra client and never writes back — the caller names arrive from the orchestrating scan's call-graph read; 10 unit tests)*
  - [x] All Phase 3 unit tests pass *(done 2026-10-05 — 36 unit tests pass in `callback_db` (4 database configuration + 6 contracts and type hints + 10 caller matching + 13 detection + 3 standard set), 99 crate-wide; the plan's count was indicative)*
  - [x] `cargo clippy` clean *(done 2026-10-05, workspace `--all-targets` with `-D warnings`; `cargo fmt` clean)*

- [x] **Phase 4 — Pipeline Integration** *(done 2026-10-05)*
  - [x] `AlgorithmRecognitionResult`, `ScanMetadata` types defined *(done 2026-10-05, `types.rs`: `AlgorithmRecognitionResult` is the per-binary document — shared `ScanMetadata` (re-exported from `calxgloss-types`, typesdb/typeinfer convention) plus the hint list in scan order (function by function; within one function the control flow matches, then the string-guided hints, then the callback matches), empty list omitted from JSON, with `new`/`for_function`/`is_empty`; each detector already reports one algorithm once per function, and detectors naming different algorithms for one function all stand for the prompt to weigh together; 3 unit tests)*
  - [x] `AlgorithmEngine` orchestrates all three detectors *(done 2026-10-05, `engine.rs`: engine generic over a new `ScanSource` trait (`functions()` + `decompile(name)` + `strings()` + `callers(address)`, implemented for `GhidraClient` via `list_functions`/`decompile_function_by_name`/`list_strings`/`callers`; RPITIT `Send` futures like the typeinfer source traits, canned-source tests run the whole orchestration without a server) — one sequential pass over the function listing decompiling each function exactly once and reading it with all three detectors, the string listing fetched once per scan and shared by every function as program-wide evidence; hints kept in scan order so two scans diff cleanly; the caller fetch — the scan's only call-graph read — runs only for functions whose arity matches some configured contract's `param_count`, since a wrong-arity function fits no contract however it is used; a function whose body Ghidra cannot produce — or a nameless listing entry — is skipped with a warning, a failed caller fetch drops only that function's callback readings and keeps its other hints, and only a failed function or string listing aborts the run; detectors start on their standard signature sets and `with_matcher`/`with_string_engine`/`with_callback_db` swap a detector's set whole; metadata stamped with scan duration; 14 unit tests)*
  - [x] `AlgorithmPersistor` saves/loads JSON to `re/analysis/algorithm/` *(done 2026-10-05, `persist.rs`: wraps `calxgloss_types::persist::JsonStore<AlgorithmRecognitionResult>` the way the typesdb and typeinfer persistors do — `new(workspace)` → `re/analysis/algorithm/{binary}.json`, `with_cache_dir` for an explicit dir, `exists()` as the cache check, `path_for()`; `save` keys the document on its metadata's binary name (a rescan replaces the previous document), `load` reads the whole document back — missing file → new `AlgorithmError::NotFound` variant naming the path, corrupt file → `Json`, mapped from the store's `PersistError` through a new `From` impl; 10 unit tests)*
  - [x] `extract_algorithm_hints()` implemented in translation pipeline *(done 2026-10-05, `retry/helpers.rs` in the translator: reads `re/analysis/algorithm/{dll}.json` through `AlgorithmPersistor` and keeps the hints made for the target function via `for_function`; missing workspace, missing cache, or a corrupt document degrades to empty like the data-structure and type-info extractors; prompt conversion `From<&AlgorithmHint> for AlgorithmInfo` lives on the hint record in `types.rs` (algorithm gained a `calxgloss-prompts` dependency, typesdb/typeinfer convention) — the recognized algorithm and its category, the detector and confidence behind the claim, and the evidence line; prompts gained the `AlgorithmInfo` prompt struct and a RECOGNIZED ALGORITHMS section in the escalate template, threaded through `EscalateTemplate`'s constructors and `build_escalate_prompt_with_context` (`build_escalate_prompt` passes an empty list), and the escalate call site passes its existing `workspace` field; translator gained a `calxgloss-algorithm` dependency; 1 conversion test + 5 translator tests)*
  - [x] Pre-analysis added to batch translation *(done 2026-10-05, `TranslationPipeline::ensure_algorithm_recognition(dll)` at the top of `batch_translate` and `batch_translate_from_callgraph`, beside the type database and type inference pre-processing: `exists()` cache check → skip, else run `AlgorithmEngine::scan` and save to `re/analysis/algorithm/{dll}.json`; missing workspace, unreachable Ghidra server, or a failed save only log a warning and the batch proceeds; 3 unit tests)*
  - [x] `calxgloss algorithm` CLI command implemented *(done 2026-10-05, `commands/algorithm.rs`: `handle_algorithm` mirrors the typesdb and typeinfer commands — `--dll` names the persisted file, runs `AlgorithmEngine::scan` against the open Ghidra program and saves to `re/analysis/algorithm/{dll}.json`; `--show` prints the cached document without connecting to Ghidra, a missing cache failing with a message pointing at the command; the report shows file, scan timestamp and duration, hint counts broken down by detection method, top confidence, and up to ten hint rows — function, algorithm, and category beside confidence colored by score with the detector behind it; exempt from the `target_dir` requirement like `config`/`gc`/`typesdb`/`typeinfer`)*
  - [x] All integration tests pass *(done 2026-10-05, `tests/integration_tests.rs`: a canned `ScanSource` drives scan → save → load → consume without a server — the document round-trips exactly filed under `re/analysis/algorithm/`, the persisted list keeps every hint in scan order (function by function; within one function the control flow match, then the string hint, then the callback match), a loaded result answers the pipeline's per-function lookups and renders into `AlgorithmInfo` prompt data with method, confidence, and evidence surviving the round trip — the listing-only reading stands at 30 with the program-wide string as its evidence, and the `qsort` host name stays the callback match's evidence; `exists()` gates the scan, a rescan replaces the document, and two binaries stay independent; 6 integration tests, whole-workspace suite green)*
  - [x] `cargo clippy` clean *(done 2026-10-05, workspace `--all-targets` with `-D warnings`; `cargo fmt` clean)*

- [ ] **Phase 5 — Full Implementation (Future)**
  - [ ] Confidence scoring improvements
  - [ ] Dynamic pattern database (JSON-based)
  - [ ] Multi-function correlation
  - [ ] Performance optimization (parallelize across functions)

---

### 4. P4 — Memory Lifecycle / RAII Detection (`calxgloss-memory`)

- [ ] **Phase 0 — Project Setup**
  - [ ] `calxgloss-memory` crate created at `crates/calxgloss-memory/`
  - [ ] Added to workspace `Cargo.toml` members list
  - [ ] Module structure created: `lib.rs`, `types.rs`, `allocator.rs`, `handle.rs`, `refcount.rs`, `persist.rs`, `error.rs`
  - [ ] `cargo check` passes with no errors
  - [ ] `cargo clippy` clean

- [ ] **Phase 1 — Allocation/Deallocation Pair Tracking**
  - [ ] `MemoryHint`, `AllocationType` types defined with `Serialize`/`Deserialize`
  - [ ] `AllocatorTracker` struct implemented
  - [ ] Detect `malloc`/`calloc`/`realloc` → `free` pairs within a function
  - [ ] Suggest `Box<T>` or stack allocation for short-lived allocations
  - [ ] All unit tests pass
  - [ ] `cargo clippy` clean

- [ ] **Phase 2 — Handle Lifecycle Detection**
  - [ ] `HandleLifecycle` sub-type defined
  - [ ] Detect `CreateFileW`/`CloseHandle`, `fopen`/`fclose` patterns
  - [ ] Suggest RAII guard structs with `Drop` impl
  - [ ] All unit tests pass
  - [ ] `cargo clippy` clean

- [ ] **Phase 3 — Reference Counting Detection**
  - [ ] `ReferenceCount` sub-type defined
  - [ ] Detect `ref_count++`/`ref_count--` and `AddRef`/`Release` patterns
  - [ ] Suggest `Rc<T>` / `Arc<T>`
  - [ ] All unit tests pass
  - [ ] `cargo clippy` clean

- [ ] **Phase 4 — Pipeline Integration**
  - [ ] `MemoryResult`, `ScanMetadata` types defined
  - [ ] `MemoryEngine` orchestrates all detectors
  - [ ] `MemoryPersistor` saves/loads JSON to `re/analysis/memory/`
  - [ ] `extract_memory_hints()` implemented in translation pipeline
  - [ ] Pre-analysis added to batch translation
  - [ ] `calxgloss memory` CLI command implemented
  - [ ] All integration tests pass
  - [ ] `cargo clippy` clean

- [ ] **Phase 5 — Full Implementation (Future)**
  - [ ] Cross-function allocation tracking
  - [ ] Ownership transfer detection
  - [ ] Smart pointer conversion (Box, Rc, Arc, Cow, ManuallyDrop)
  - [ ] Resource leak detection
  - [ ] Per-type Drop implementation suggestions

---

### 5. P5 — Concurrency & Synchronization Detection (`calxgloss-sync`)

- [ ] **Phase 0 — Project Setup**
  - [ ] `calxgloss-sync` crate created at `crates/calxgloss-sync/`
  - [ ] Added to workspace `Cargo.toml` members list
  - [ ] Module structure created: `lib.rs`, `types.rs`, `mutex.rs`, `atomic.rs`, `threading.rs`, `persist.rs`, `error.rs`
  - [ ] `cargo check` passes with no errors
  - [ ] `cargo clippy` clean

- [ ] **Phase 1 — Mutex/Lock Detection**
  - [ ] `ConcurrencyHint`, `SyncType` types defined with `Serialize`/`Deserialize`
  - [ ] `MutexDetector` struct implemented
  - [ ] Detect `pthread_mutex_lock/unlock`, `EnterCriticalSection/LeaveCriticalSection`, `pthread_rwlock_rdlock/wrlock`
  - [ ] Suggest `std::sync::Mutex<T>`, `parking_lot::Mutex<T>`, `std::sync::RwLock<T>`
  - [ ] All unit tests pass
  - [ ] `cargo clippy` clean

- [ ] **Phase 2 — Atomic Operation Detection**
  - [ ] `AtomicDetector` struct implemented
  - [ ] Detect `__atomic_fetch_add`, `InterlockedIncrement/Decrement`, `__sync_fetch_and_add`
  - [ ] Suggest `std::sync::atomic::AtomicU32`/`AtomicU64` with proper `Ordering`
  - [ ] All unit tests pass
  - [ ] `cargo clippy` clean

- [ ] **Phase 3 — Threading Pattern Detection**
  - [ ] `ThreadingDetector` struct implemented
  - [ ] Detect `CreateThread`, `pthread_create`, `std::thread::spawn`
  - [ ] Suggest `std::thread::spawn` or `tokio::spawn`
  - [ ] All unit tests pass
  - [ ] `cargo clippy` clean

- [ ] **Phase 4 — Pipeline Integration**
  - [ ] `SyncResult`, `ScanMetadata` types defined
  - [ ] `SyncEngine` orchestrates all detectors
  - [ ] `SyncPersistor` saves/loads JSON to `re/analysis/sync/`
  - [ ] `extract_concurrency_hints()` implemented in translation pipeline
  - [ ] Pre-analysis added to batch translation
  - [ ] `calxgloss sync` CLI command implemented
  - [ ] All integration tests pass
  - [ ] `cargo clippy` clean

- [ ] **Phase 5 — Full Implementation (Future)**
  - [ ] Full data race analysis
  - [ ] Lock ordering analysis
  - [ ] Async runtime detection
  - [ ] Thread-local storage detection
  - [ ] Futex-based synchronization detection

---

### 6. P6 — Callback / Function Pointer Table Detection (`calxgloss-callback`)

- [ ] **Phase 0 — Project Setup**
  - [ ] `calxgloss-callback` crate created at `crates/calxgloss-callback/`
  - [ ] Added to workspace `Cargo.toml` members list
  - [ ] Module structure created: `lib.rs`, `types.rs`, `fp_array.rs`, `callback_reg.rs`, `jump_table.rs`, `persist.rs`, `error.rs`
  - [ ] `cargo check` passes with no errors
  - [ ] `cargo clippy` clean

- [ ] **Phase 1 — Function Pointer Array Detection**
  - [ ] `CallbackHint`, `CallbackCategory` types defined with `Serialize`/`Deserialize`
  - [ ] `FpArrayDetector` struct implemented
  - [ ] Detect `*(handlers[i])(args)` patterns
  - [ ] Suggest `Box<dyn Fn(...)>`
  - [ ] All unit tests pass
  - [ ] `cargo clippy` clean

- [ ] **Phase 2 — Callback Registration Detection**
  - [ ] `CallbackRegDetector` struct implemented
  - [ ] Detect `register_callback(func_ptr)` and `set_on_message(void (*callback)(...))`
  - [ ] Suggest Rust closure-based patterns
  - [ ] All unit tests pass
  - [ ] `cargo clippy` clean

- [ ] **Phase 3 — Jump Table Detection**
  - [ ] `JumpTableDetector` struct implemented
  - [ ] Detect `jmp [table + index*N]` patterns
  - [ ] Suggest Rust `match` or function pointer arrays
  - [ ] All unit tests pass
  - [ ] `cargo clippy` clean

- [ ] **Phase 4 — Pipeline Integration**
  - [ ] `CallbackResult`, `ScanMetadata` types defined
  - [ ] `CallbackEngine` orchestrates all detectors
  - [ ] `CallbackPersistor` saves/loads JSON to `re/analysis/callback/`
  - [ ] `extract_callback_hints()` implemented in translation pipeline
  - [ ] Pre-analysis added to batch translation
  - [ ] `calxgloss callback` CLI command implemented
  - [ ] All integration tests pass
  - [ ] `cargo clippy` clean

- [ ] **Phase 5 — Full Implementation (Future)**
  - [ ] Full callback chain analysis
  - [ ] Plugin architecture detection
  - [ ] Event system reconstruction
  - [ ] Integration with Type Inference for closure signatures

---

### 7. P7 — Control Flow Pattern Recognition (`calxgloss-controlflow`)

- [ ] **Phase 0 — Project Setup**
  - [ ] `calxgloss-controlflow` crate created at `crates/calxgloss-controlflow/`
  - [ ] Added to workspace `Cargo.toml` members list
  - [ ] `Cargo.toml` dependencies correct
  - [ ] Module structure created: `lib.rs`, `types.rs`, `switch_detect.rs`, `recursion_detect.rs`, `state_machine.rs`, `confidence.rs`, `persist.rs`, `error.rs`
  - [ ] `cargo check` passes with no errors
  - [ ] `cargo clippy` clean

- [ ] **Phase 1 — Switch Statement Detection**
  - [ ] `SwitchPattern` type defined with `Serialize`/`Deserialize`
  - [ ] `SwitchDetector` struct implemented
  - [ ] `detect_switch()` parses decompiled body for if-else-if chains
  - [ ] Variable name extraction, case counting, default case detection
  - [ ] Minimum 3-case threshold; dispatch table suggestion for 10+ cases
  - [ ] All 10 Phase 1 unit tests pass
  - [ ] `cargo clippy` clean

- [ ] **Phase 2 — Recursive Function Detection**
  - [ ] `RecursionPattern` type defined with `Serialize`/`Deserialize`
  - [ ] `RecursionDetector` struct implemented
  - [ ] `detect_recursion()` scans decompiled body for self-calls
  - [ ] Self-call count, tail-call detection, confidence scoring
  - [ ] All 10 Phase 2 unit tests pass
  - [ ] `cargo clippy` clean

- [ ] **Phase 3 — State Machine Detection**
  - [ ] `StateMachinePattern` type defined with `Serialize`/`Deserialize`
  - [ ] `StateMachineDetector` struct implemented
  - [ ] `detect_state_machine()` parses if-else chains on state variables
  - [ ] Named state constant detection, transition counting, idle state detection
  - [ ] Minimum 3-state threshold
  - [ ] All 10 Phase 3 unit tests pass
  - [ ] `cargo clippy` clean

- [ ] **Phase 4 — Pipeline Integration**
  - [ ] `ControlFlowResult`, `ScanMetadata` types defined
  - [ ] `ControlFlowEngine` orchestrates all three detectors
  - [ ] `ControlFlowPersistor` saves/loads JSON to `re/analysis/controlflow/`
  - [ ] `extract_control_flow_hints()` implemented in translation pipeline
  - [ ] Prompt data structs updated (ModuleContext, Complexity, FullModule)
  - [ ] Template sections added to all relevant templates
  - [ ] `calxgloss controlflow` CLI command implemented
  - [ ] All integration tests pass
  - [ ] `cargo clippy` clean

- [ ] **Phase 5 — Full Implementation (Future)**
  - [ ] Full control flow graph (CFG) extraction
  - [ ] Accurate recursion depth analysis
  - [ ] Loop nesting depth detection
  - [ ] Branch density analysis

---

### 8. P8 — String & Configuration Context (`calxgloss-stringctx`)

- [ ] **Phase 0 — Project Setup**
  - [ ] `calxgloss-stringctx` crate created at `crates/calxgloss-stringctx/`
  - [ ] Added to workspace `Cargo.toml` members list
  - [ ] `Cargo.toml` dependencies correct
  - [ ] Module structure created: `lib.rs`, `types.rs`, `classify.rs`, `hybrid_mapper.rs`, `format_str.rs`, `persist.rs`, `error.rs`
  - [ ] `cargo check` passes with no errors
  - [ ] `cargo clippy` clean

- [ ] **Phase 1 — String Classification**
  - [ ] `StringContext`, `StringClassification`, `StringSource`, `FormatHint` types defined
  - [ ] `StringClassification::Display` implementation
  - [ ] `StringClassifyEngine` struct implemented
  - [ ] `classify()` with priority-ordered pattern matching (9 categories)
  - [ ] Format priority: FormatString > FilePath > ResourceName > Error > Network > DebugLog > UserVisible > InternalIdentifier > Generic
  - [ ] `infer_purpose()` and `extract_format_hints()` implemented
  - [ ] All 22 Phase 1 unit tests pass
  - [ ] `cargo clippy` clean

- [ ] **Phase 2 — Per-Function String Summary (Hybrid)**
  - [ ] `StringContextResult`, `ScanMetadata` types defined
  - [ ] `HybridXrefMapper` struct implemented
  - [ ] `extract_strings_from_body()` parses decompiled body
  - [ ] `extract_strings_from_xrefs()` parses `get_xrefs_to` JSON (shape re-verified against the live bridge)
  - [ ] Hybrid fallback: skip xrefs when body has strings
  - [ ] Deduplication by address and value
  - [ ] All 12 Phase 2 unit tests pass
  - [ ] `cargo clippy` clean

- [ ] **Phase 3 — Format String Type Inference**
  - [ ] `FormatStringEngine` struct implemented
  - [ ] Format specifier → Rust type mapping (%s → `*const i8`, %d → `i32`, etc.)
  - [ ] Format string summaries for prompt injection
  - [ ] All unit tests pass
  - [ ] `cargo clippy` clean

- [ ] **Phase 4 — Pipeline Integration**
  - [ ] `StringContextEngine` orchestrates all three engines
  - [ ] `StringContextPersistor` saves/loads JSON to `re/analysis/stringctx/`
  - [ ] `extract_string_context()` implemented in translation pipeline
  - [ ] Pre-analysis added to batch translation
  - [ ] `calxgloss stringctx` CLI command implemented
  - [ ] All integration tests pass
  - [ ] `cargo clippy` clean

- [ ] **Phase 5 — Full Implementation (Future)**
  - [ ] Localization detection
  - [ ] Context-sensitive classification improvement
  - [ ] Cross-function string correlation
  - [ ] String-to-function confidence scoring

---

### 9. P9 — Library & API Identification (`calxgloss-apidetect`)

- [ ] **Phase 0 — Project Setup**
  - [ ] `calxgloss-apidetect` crate created at `crates/calxgloss-apidetect/`
  - [ ] Added to workspace `Cargo.toml` members list
  - [ ] Module structure created: `lib.rs`, `types.rs`, `import_table.rs`, `lib_mapping.rs`, `api_summary.rs`, `persist.rs`, `error.rs`
  - [ ] `cargo check` passes with no errors
  - [ ] `cargo clippy` clean

- [ ] **Phase 1 — Import Table Extraction**
  - [ ] `APISignature`, `LibraryMapping` types defined with `Serialize`/`Deserialize`
  - [ ] `ImportTableScanner` struct implemented
  - [ ] Parse all imported function names via Ghidra
  - [ ] All unit tests pass
  - [ ] `cargo clippy` clean

- [ ] **Phase 2 — Library-to-Crate Mapping Database**
  - [ ] Mapping built for: DirectX 9, SDL2, Win32, POSIX, PNG, zlib, stdio, C++ STL
  - [ ] All unit tests pass
  - [ ] `cargo clippy` clean

- [ ] **Phase 3 — Per-Function API Summary**
  - [ ] `ApiSummaryDetector` struct implemented
  - [ ] Call graph traversal to find imported APIs per function
  - [ ] All unit tests pass
  - [ ] `cargo clippy` clean

- [ ] **Phase 4 — Pipeline Integration**
  - [ ] `ApiResult`, `ScanMetadata` types defined
  - [ ] `ApiEngine` orchestrates all detectors
  - [ ] `ApiPersistor` saves/loads JSON to `re/analysis/apidetect/`
  - [ ] `extract_api_hints()` implemented in translation pipeline
  - [ ] `calxgloss apidetect` CLI command implemented
  - [ ] All integration tests pass
  - [ ] `cargo clippy` clean

- [ ] **Phase 5 — Full Implementation (Future)**
  - [ ] API category enrichment
  - [ ] Cross-reference with known-crate database (feature flags)
  - [ ] Windows vs. POSIX divergence detection
  - [ ] COM interface method suggestions
  - [ ] Auto-generate FFI bindings
  - [ ] Per-DLL dependency manifest output

---

### 10. P10 — Constants & Enum Recovery (`calxgloss-consts`)

- [ ] **Phase 0 — Project Setup**
  - [ ] `calxgloss-consts` crate created at `crates/calxgloss-consts/`
  - [ ] Added to workspace `Cargo.toml` members list
  - [ ] Module structure created: `lib.rs`, `types.rs`, `bitmask.rs`, `sequential.rs`, `frequency.rs`, `persist.rs`, `error.rs`
  - [ ] `cargo check` passes with no errors
  - [ ] `cargo clippy` clean

- [ ] **Phase 1 — Bitmask Enum Detection**
  - [ ] `EnumHint`, `ConstantHint` types defined with `Serialize`/`Deserialize`
  - [ ] `BitmaskDetector` struct implemented
  - [ ] Detect power-of-2 groups used in bitwise operations
  - [ ] Suggest `#[bitflags]` struct
  - [ ] All unit tests pass
  - [ ] `cargo clippy` clean

- [ ] **Phase 2 — Sequential Constant Extraction**
  - [ ] `SequentialDetector` struct implemented
  - [ ] Extract constants from switch cases; classify as enum candidates
  - [ ] All unit tests pass
  - [ ] `cargo clippy` clean

- [ ] **Phase 3 — Magic Number Frequency Analysis**
  - [ ] `FrequencyAnalyzer` struct implemented
  - [ ] Cross-binary frequency analysis of constants
  - [ ] Suggest named constants for repeated values
  - [ ] All unit tests pass
  - [ ] `cargo clippy` clean

- [ ] **Phase 4 — Pipeline Integration**
  - [ ] `ConstResult`, `ScanMetadata` types defined
  - [ ] `ConstEngine` orchestrates all detectors
  - [ ] `ConstPersistor` saves/loads JSON to `re/analysis/consts/`
  - [ ] `extract_constant_hints()` implemented in translation pipeline
  - [ ] `calxgloss consts` CLI command implemented
  - [ ] All integration tests pass
  - [ ] `cargo clippy` clean

- [ ] **Phase 5 — Full Implementation (Future)**
  - [ ] Full bitmask enum reconstruction
  - [ ] Named constant suggestion from context
  - [ ] Protocol constant recovery
  - [ ] Color/RGB constant grouping
  - [ ] Integration with Data Structure Recovery
  - [ ] Output generated code to separate Rust file

---

### 11. P11 — Endianness & Serialization Detection (`calxgloss-serialize`)

- [ ] **Phase 0 — Project Setup**
  - [ ] `calxgloss-serialize` crate created at `crates/calxgloss-serialize/`
  - [ ] Added to workspace `Cargo.toml` members list
  - [ ] Module structure created: `lib.rs`, `types.rs`, `byteswap.rs`, `bitpack.rs`, `magic_bytes.rs`, `persist.rs`, `error.rs`
  - [ ] `cargo check` passes with no errors
  - [ ] `cargo clippy` clean

- [ ] **Phase 1 — Byte-Swap Operation Detection**
  - [ ] `SerializationHint`, `SerializationType` types defined with `Serialize`/`Deserialize`
  - [ ] `ByteSwapDetector` struct implemented
  - [ ] Detect `ntohs`, `ntohl`, `bswap32`, `__builtin_bswap32`
  - [ ] Suggest `byteorder` crate
  - [ ] All unit tests pass
  - [ ] `cargo clippy` clean

- [ ] **Phase 2 — Bit-Packing Detection**
  - [ ] `BitPackDetector` struct implemented
  - [ ] Detect manual `|`/`<<`/`>>` bit-packing patterns
  - [ ] Suggest `bitvec` crate or manual masking
  - [ ] All unit tests pass
  - [ ] `cargo clippy` clean

- [ ] **Phase 3 — Magic Byte & Format Detection**
  - [ ] `MagicByteDetector` struct implemented
  - [ ] Detect known file format signatures (PNG, gzip, ZIP)
  - [ ] Suggest format-specific crates
  - [ ] All unit tests pass
  - [ ] `cargo clippy` clean

- [ ] **Phase 4 — Pipeline Integration**
  - [ ] `SerializeResult`, `ScanMetadata` types defined
  - [ ] `SerializeEngine` orchestrates all detectors
  - [ ] `SerializePersistor` saves/loads JSON to `re/analysis/serialize/`
  - [ ] `extract_serialization_hints()` implemented in translation pipeline
  - [ ] `calxgloss serialize` CLI command implemented
  - [ ] All integration tests pass
  - [ ] `cargo clippy` clean

- [ ] **Phase 5 — Full Implementation (Future)**
  - [ ] Full serialization format inference
  - [ ] Cross-field validation detection
  - [ ] Protocol message detection
  - [ ] Network protocol identification
  - [ ] Per-type endianness mapping
  - [ ] Integration with Library API detection

---

### 12. W0 — Web UI Foundation & Phase Progress (`calxgloss-web`)

- [ ] **Phase 0 — Server Management Endpoints**
  - [ ] `ServerStatus` type defined with `Serialize`/`Deserialize`
  - [ ] `GET /api/server/status` implemented (pipeline status, uptime, version, host, log level, memory, CPU, WebSocket conns, open files)
  - [ ] Enhance existing `GET /health` (add uptime, version, repo accessibility; optional `/api/server/health` alias)
  - [ ] `POST /api/server/shutdown` implemented (pause pipeline, complete current function, save state, stop server)
  - [ ] `POST /api/server/restart` implemented (MVP: save state + stop; manual restart)
  - [ ] Router registration decided for every new endpoint (`serve` vs `live`/WS router)
  - [ ] `PATCH /api/server/log-level` implemented
  - [ ] Resource metrics collection and exposure implemented
  - [ ] Server lifecycle tests pass
  - [ ] `cargo clippy` clean

- [ ] **Phase 1 — Pipeline Progress Dashboard**
  - [ ] `PipelinePhase`, `PhaseProgress`, `BinaryProgress` types defined
  - [ ] `/api/pipeline` endpoint enhanced with per-phase progress (all 7 phases + Phase 2.5 PAL; Phases 6–7 data sources defined first)
  - [ ] `PipelinePhaseBar` component built (horizontal progress bar)
  - [ ] Binary strategy info added to pipeline panel (strategy, function counts, tokens, success rate, shim/PAL status)
  - [ ] Time estimate implemented (per-function duration recording added first)
  - [ ] Quick-action buttons (Start, Pause, Configure) added
  - [ ] Quality summary card added (confidence, baseline pass rate, verification pass rate)
  - [ ] Token budget visual indicator added
  - [ ] Integration tests pass
  - [ ] `cargo clippy` clean

- [ ] **Phase 2 — In-Flight Status & Token/Fault Display**
  - [ ] `TranslationPhase` enum defined (GhidraFetch through Review)
  - [ ] WebSocket stream enhanced with per-function phase progress events
  - [ ] Context tier info added to unit detail panel (tier + selection rationale)
  - [ ] Fault history added to unit detail panel (type, severity, recovery)
  - [ ] Token count added to unit overview (total + per-attempt breakdown)
  - [ ] Retry strategy display added (current, previous, success rate)
  - [ ] Effort estimate column added to queue
  - [ ] Integration tests pass
  - [ ] `cargo clippy` clean

- [ ] **Phase 3 — Live Translation View**
  - [ ] `LiveTranslationState` types defined
  - [ ] `/api/progress/enhanced` endpoint implemented
  - [ ] `LiveView` page built with per-function progress bars, phase labels, strategy/tier display
  - [ ] Real-time WebSocket updates for phase changes
  - [ ] `cargo clippy` clean

- [ ] **Phase 4 — Dashboard Enhancements**
  - [ ] Binary count cards by category added
  - [ ] Quality summary section added
  - [ ] Token budget visual added
  - [ ] Pipeline Overview available as default landing page
  - [ ] `cargo clippy` clean

---

### 13. W1 — Web UI Status & Visibility (`calxgloss-web`)

- [ ] **Phase 0 — Unit Detail Enhancements**
  - [ ] Context tier info section added to unit detail panel
  - [ ] Fault history section added to unit detail panel
  - [ ] Token count display added to unit overview
  - [ ] Retry strategy display added to unit detail
  - [ ] Windows API mapping section added to unit detail
  - [ ] Call graph context section added (callers + callees)
  - [ ] UI integration tests pass
  - [ ] `cargo clippy` clean

- [ ] **Phase 1 — Queue View Enhancements**
  - [ ] Priority column added (HIGH / NORMAL / LOW)
  - [ ] Skip checkbox column added
  - [ ] Estimate column added
  - [ ] Multi-select with batch actions (Accept All, Skip All, Send Back All)
  - [ ] Drag-and-drop reordering (with queue-order persistence)
  - [ ] Batch action endpoints wired up (`batch-accept`, `batch-skip`, `batch-send-back`)
  - [ ] UI integration tests pass
  - [ ] `cargo clippy` clean

- [ ] **Phase 2 — Dependency Graph Enhancements**
  - [ ] Filter controls (by kind, status, binary)
  - [ ] Node size by token usage
  - [ ] Node color by confidence
  - [ ] Edge labels (call, dependency, data flow)
  - [ ] Export as SVG/PNG
  - [ ] Shareable URL encoding
  - [ ] UI integration tests pass
  - [ ] `cargo clippy` clean

- [ ] **Phase 3 — LLM I/O Log Enhancements**
  - [ ] Server-side LLM I/O persistence + read endpoint (prerequisite; log is client-side only today)
  - [ ] Filter dropdowns (binary, function, attempt, strategy)
  - [ ] Full-text search through prompts
  - [ ] Collapsible entries
  - [ ] One-click copy for prompts/responses
  - [ ] Token count per entry
  - [ ] UI integration tests pass
  - [ ] `cargo clippy` clean

---

### 14. W2 — Web UI Process Control (`calxgloss-web`, `calxgloss-types`, `calxgloss-translator`)

- [ ] **Phase 0 — Pipeline Lifecycle Control (Backend)**
  - [ ] `PipelineState` enum defined in `calxgloss-types` (Idle, Running, Paused, Stopping, Complete, Error)
  - [ ] Pipeline state machine implemented as shared `Arc` state between translator and web router (not in `calxgloss-cli`)
  - [ ] `POST /api/pipeline/pause` endpoint implemented
  - [ ] `POST /api/pipeline/resume` endpoint implemented
  - [ ] `POST /api/pipeline/stop` endpoint implemented
  - [ ] `POST /api/pipeline/restart` endpoint implemented (with phase selector)
  - [ ] `POST /api/pipeline/cancel-current` endpoint implemented
  - [ ] All lifecycle ops emit `ProgressEvent`
  - [ ] Pipeline control tests pass
  - [ ] `cargo clippy` clean

- [ ] **Phase 1 — Pipeline Controls UI**
  - [ ] `PipelineControls` header component built (status indicator, target selector, control buttons)
  - [ ] Restart options dialog implemented (phase, target, scope, confirmation)
  - [ ] Shutdown confirmation dialog implemented
  - [ ] Controls wired to backend endpoints
  - [ ] Real-time status via WebSocket
  - [ ] UI integration tests pass
  - [ ] `cargo clippy` clean

- [ ] **Phase 2 — Translation Scope Controls**
  - [ ] `TranslationScope` and `TranslationConstraints` types defined
  - [ ] Scope control endpoints implemented (`set`, `skip-function`, `priority-function`, `status`)
  - [ ] `TranslationControls` panel built (scope checkboxes, priority list, constraints)
  - [ ] Scope filtering integrated into pipeline queue selection
  - [ ] Integration tests pass
  - [ ] `cargo clippy` clean

- [ ] **Phase 3 — Per-Function Override Panel**
  - [ ] `FunctionOverride` type defined
  - [ ] Override endpoints implemented (`POST/GET/DELETE /api/units/{id}/override`)
  - [ ] `Overrides` tab built in unit detail (tier force, strategy force, custom hints, classification change, notes)
  - [ ] Overrides wired into context builder
  - [ ] UI integration tests pass
  - [ ] `cargo clippy` clean

- [ ] **Phase 4 — Binary Classification Override**
  - [ ] `BinaryClassificationOverride` type defined
  - [ ] Override endpoints implemented (`POST/GET /api/binaries/{name}/classification`)
  - [ ] Binary classification override panel built
  - [ ] Override integrated into classification pipeline
  - [ ] UI integration tests pass
  - [ ] `cargo clippy` clean

---

### 15. W3 — Web UI Historical & Analytical Views (`calxgloss-web`)

- [ ] **Phase 0 — Faults & Errors View**
  - [ ] `FaultAnalytics` type defined
  - [ ] `/api/faults` endpoints implemented (list, summary, by-binary)
  - [ ] `FaultsView` page built (summary cards, bar chart, recent faults table, trend line, CSV export, filters)
  - [ ] UI integration tests pass
  - [ ] `cargo clippy` clean

- [ ] **Phase 1 — Token Usage View**
  - [ ] `TokenAnalytics` type defined
  - [ ] `/api/token-usage` endpoints implemented (summary, by-binary, by-tier, by-strategy, cost)
  - [ ] `TokenUsageView` page built (overall stats, per-binary bars, by-tier breakdown, by-strategy with success rate, cost estimate)
  - [ ] UI integration tests pass
  - [ ] `cargo clippy` clean

- [ ] **Phase 2 — Strategy Analytics View**
  - [ ] `StrategyAnalytics` type defined
  - [ ] `/api/strategy-analytics` endpoints implemented (by-strategy, by-category, by-complexity)
  - [ ] `StrategyAnalyticsView` page built (pass rate tables with bars, time range filter, CSV export)
  - [ ] UI integration tests pass
  - [ ] `cargo clippy` clean

- [ ] **Phase 3 — LLM Performance Metrics**
  - [ ] `LlmPerformanceMetrics` type defined
  - [ ] `/api/llm-metrics` endpoints implemented (summary, by-model, by-tier)
  - [ ] `LlmPerformanceView` built (latency percentiles, timeout frequency, model performance, tier vs. time scatter)
  - [ ] UI integration tests pass
  - [ ] `cargo clippy` clean

---

### 16. W4 — Web UI New Views (`calxgloss-web`)

- [ ] **Phase 0 — Binaries View**
  - [ ] `BinaryViewData` type defined
  - [ ] `/api/binaries` endpoints implemented (list, detail, shim-status, pal-status)
  - [ ] `BinariesView` page built (summary table, expandable detail, shim tracker, PAL tracker)
  - [ ] UI integration tests pass
  - [ ] `cargo clippy` clean

- [ ] **Phase 1 — Unit Detail Attempt Comparison**
  - [ ] Attempt comparison view built in unit detail (side-by-side diff across all attempts)
  - [ ] Per-attempt metadata display
  - [ ] Attempt navigation in sidebar
  - [ ] UI integration tests pass
  - [ ] `cargo clippy` clean

---

### Cross-Cutting Checklist

- [ ] All 11 analysis crates compile together with `cargo build --workspace`
- [ ] All crates pass `cargo test --workspace`
- [ ] All crates pass `cargo clippy --workspace`
- [ ] All crates pass `cargo fmt --check`
- [ ] Shared integration-test backend: prefer bethington's headless server (same 272-endpoint JSON API, Docker-ready) over a hand-built mock; current tests use inline fixtures + `#[ignore]`d live tests against `CALXGLOSS_GHIDRA_URL`
- [ ] Integration tests use the bethington headless server (or mock) across all crates
- [ ] All 11 crates re-exported from the `calxgloss` meta-crate (`crates/calxgloss`)
- [ ] Shared `re/analysis/` path helper added (today every persistor builds the path ad hoc with `.join("re").join("analysis")`)
- [ ] All CLI commands registered in `calxgloss-cli`: typesdb, typeinfer, algorithm, memory, sync, callback, controlflow, stringctx, apidetect, consts, serialize
- [ ] All persisted data stored in `re/analysis/{crate_name}/{dll}.json`
- [ ] All crates output hints into LLM prompt templates — per hint type: new field on the relevant prompt data structs (`StubPromptData`, `WithTestsPromptData`, `ModuleContextPromptData`, `FullModulePromptData`, `ComplexityPromptData`), section in the matching `.j2` template, and builder wiring in `calxgloss-prompts/src/build.rs`
- [ ] Orphaned templates `fix.j2` and `disassembly_translate.j2` removed or wired up
- [ ] Architecture diagrams in source documentation match implementation
- [ ] This document updated to reflect all completed phases (`future_plans.md` was removed in a prior commit; this plan is the single source of truth)
- [ ] `data_flow.md` updated to include all methodologies in the data flow diagram
- [ ] All 8 web server lifecycle endpoints implemented and tested (`/api/pipeline/pause`, `/api/pipeline/resume`, `/api/pipeline/stop`, `/api/pipeline/restart`, `/api/pipeline/cancel-current`, `/api/server/shutdown`, `/api/server/restart`, `/api/server/log-level`)
- [ ] All web analytics endpoints implemented and tested (`/api/faults`, `/api/token-usage`, `/api/strategy-analytics`, `/api/llm-metrics`, `/api/binaries`, `/api/progress/enhanced`)
- [ ] All web process control endpoints implemented and tested (`/api/scope/set`, `/api/scope/skip-function`, `/api/scope/priority-function`, `/api/units/{id}/override`, `/api/queue/batch-*`)
- [ ] All 5 frontend views have matching backend data structures with `Serialize`/`Deserialize`
- [ ] WebSocket event types documented in `calxgloss-web/src/server/events.rs`
- [ ] `app.js` split into per-view ES modules (no build step) before new views are added
- [ ] All new frontend views added to tab navigation in `index.html`
- [ ] All new CSS classes follow existing dark theme patterns in `app.css`
- [ ] All new JavaScript modules follow existing vanilla JS patterns
