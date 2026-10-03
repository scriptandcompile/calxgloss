# Future Plans — Translation-Assisting Methodologies

This document catalogs potential methodologies that could be added to the calxgloss pipeline to further improve translation quality. Each section describes the idea, the data sources it would use, an MVP scope, a TODO list for full implementation, and the expected impact.

These are ordered by recommended implementation priority.

---

## Table of Contents

1. [Data Structure Recovery](#1-data-structure-recovery)
2. [Type Inference & Propagation](#2-type-inference--propagation)
3. [Algorithm Recognition](#3-algorithm-recognition)
4. [Control Flow Pattern Recognition](#4-control-flow-pattern-recognition)
5. [String & Configuration Context](#5-string--configuration-context)
6. [How They Compose](#6-how-they-compose)

---

## 1. Data Structure Recovery

### Problem

The LLM gets disassembly of a function like `DrawSprite(int x, int y)` but has no idea what the `Sprite` struct actually contains. It guesses the fields, and those guesses become the Rust struct — which will be wrong, causing downstream compilation failures.

### What It Is

Automatic recovery of `struct` layouts, class hierarchies, vtables, and type aliases from binary analysis — not just function code, but the *data* flowing through functions.

### Techniques

| Technique | What It Finds | Ghidra Source |
|-----------|--------------|---------------|
| Named struct recovery | Structs with known field types and offsets from Ghidra's Type Library | Data Type Manager |
| Vtable recovery | C++ class vtables → Rust `impl` blocks | `data @ address` declarations, cross-references |
| String-guided struct inference | If a struct's fields are all pointed to by strings in the binary, infer the struct's purpose and name | String literal analysis |
| Usage pattern matching | If `func_A` reads field[0], `func_B` writes field[1], and `func_C` reads field[2] → all functions share a struct layout | Cross-reference clustering |

### MVP Scope

1. **Named types from Ghidra's Type Library** — Ghidra already tags some structs as `struct Sprite` with known fields. Export these into calxgloss.
2. **Basic struct inference from strings** — If a struct's fields are all pointed to by strings in the binary, infer the struct's purpose and name.
3. **Vtable detection** — Identify `vtable`-tagged data objects and extract the method pointers. This tells you there's a C++ class with N virtual methods.

### TODO for Full Implementation

```rust
// TODO: Full vtable reconstruction from Ghidra's Data Manager
// TODO: Cross-reference clustering to group fields into structs
// TODO: Heuristic-based struct naming ("contains texture path → TextureData")
// TODO: Detect nested structs and unions
// TODO: Detect std::string / std::vector / CString usage patterns
// TODO: Detect COM interfaces (IUnknown-derived vtables)
// TODO: Output recovered structs to Rust file alongside translation
```

### Impact

High. This is arguably the *single biggest* thing that helps the LLM write correct code. A function calling `sprite->texture_id` is useless to translate if you don't know what `texture_id` is, what type it is, and what other fields exist in `Sprite`.

---

## 2. Type Inference & Propagation

### Problem

Ghidra names parameters `param_1`, `param_2` and types them `undefined4` (generic 32-bit). The LLM doesn't know whether `param_1` is a pointer to a struct, an enum, or an int. This is the #1 source of wrong code.

### What It Is

Propagating type information through the call graph and using data flow analysis to narrow parameter types, so the LLM gets `void func(Sprite *sprite, u32 texture_id)` instead of `void func(undefined4 param_1, undefined4 param_2)`.

### Techniques

| Technique | What It Does |
|-----------|-------------|
| Call-site type propagation | If `func_A(Sprite *)` calls `func_B(unknown)`, `func_B`'s first param is at least "possibly a pointer" |
| Assignment chain analysis | If `local_4 = param_1; if (*local_4 == 0x1234)...` → `local_4` is a pointer, `*local_4` has known constant fields |
| Cross-reference type inference | If data at `0x180123000` is tagged `struct Tag *` and function `F` reads from it, `F` likely takes `struct Tag *` |
| Convention detection | If the function has the signature of `__stdcall` with a `this` pointer, detect it as a C++ method |

### MVP Scope

1. **C++ this-pointer detection** — If a function calls `vtable[index]` and the first parameter is used as the object address, classify it as a method of the class whose vtable it uses.
2. **Parameter size detection** — If `param_1` is dereferenced as a 4-byte value (`*param_1`), mark it as a pointer. If used as `param_1 + offset`, also a pointer.
3. **Known type propagation** — If a parameter is passed to `free()` or `malloc()`, it's a pointer. If passed to `strlen()`, it's a `char *`.

### TODO for Full Implementation

```rust
// TODO: Full data flow analysis through all parameters
// TODO: Integer bit-pattern analysis (if a u32 has bits 0-7 always zero, it might be a struct pointer)
// TODO: Cross-reference data objects to infer function parameter types
// TODO: Detect std::string, std::vector, and other STL types from mangling and usage
// TODO: Output inferred types as additional prompt context
// TODO: Confidence scoring on inferred types
```

### Impact

High. This directly attacks the "undefined4 param_1" problem that every binary reversal engineer faces. Better parameter types = better code = fewer compilation failures.

---

## 3. Algorithm Recognition

### Problem

The LLM is translating a 200-line function implementing a linked list traversal or a hash table lookup. Without knowing *what* it's doing, the LLM produces a literal translation — which might be subtly wrong in a corner case and is harder to test against.

### What It Is

Detecting when a function implements a known algorithm (sorting, hashing, parsing, compression, graph traversal) so the LLM gets a high-level specification to target.

### Detection Signals

| Signal | Algorithm It Suggests | Method |
|--------|----------------------|--------|
| `qsort`-like compare function + call | Sorting | Pattern match compare logic |
| `memcmp` on fixed-size block + branching | Hash table bucket comparison | Heuristic matching |
| Stack-like push/pop pattern | LIFO data structure | Call graph + control flow analysis |
| `switch (key)` with sequential cases | Hash table index or lookup | Control flow graph analysis |
| CRC32 polynomial patterns | CRC checksum | Byte pattern matching |
| Known compression signatures (inflate/deflate) | zlib decompression | String literals + import table |

### MVP Scope

1. **Control flow signature matching** — Simple patterns like "compare + branch + loop" → sorting. "switch on value" → state machine or dispatch table.
2. **String-guided algorithm hints** — If a function contains the string `"CRC"` or `"checksum"`, suggest CRC computation. If it says `"inflate"`, suggest zlib.
3. **Callback pattern detection** — If a function matches `qsort`'s signature (takes two pointers, returns int), flag it as a compare function.

### TODO for Full Implementation

```rust
// TODO: Full control flow graph signature matching
// TODO: Recognize known algorithms from Ghidra's pseudocode patterns
// TODO: Detect serialization/deserialization functions by field access patterns
// TODO: Detect math/physics engine routines (matrix multiply, quaternion operations)
// TODO: Detect game-specific patterns (entity component system, ECS registry lookups)
// TODO: Maintain a database of algorithm signatures with known Rust equivalents
```

### Impact

Medium-High. This gives the LLM a *spec* to translate against rather than just a *function body to rewrite*. "Translate this to Rust — it's a binary search on a sorted array of structs" is dramatically more accurate than "Translate this assembly to Rust."

---

## 4. Control Flow Pattern Recognition

### Problem

The LLM sees a complex `switch` statement with 50 cases and produces verbose, error-prone code. It could instead be a state machine, a message dispatcher, or a lookup table.

### What It Is

Analyzing the control flow graph (CFG) of each function to identify structural patterns that suggest a higher-level construct.

### CFG Patterns

| Pattern | Likely Construct | Rust Translation Hint |
|---------|-----------------|----------------------|
| `switch(value)` with sequential cases | Enum match / dispatch table | `match value { ... }` |
| Binary tree of `if` comparisons | Binary search or trie | Binary search algorithm |
| `if-else` chain on same variable | Lookup table or state machine | `match` or table lookup |
| Nested loops with break/continue | Parsing loop or scan | Parser or searcher |
| Recursion | Tree traversal, divide-and-conquer | Recursive or iterative equivalent |
| `goto`-heavy with cleanup labels | Error handling (C-style try/catch) | `Result<T, E>` with `?` |

### MVP Scope

1. **Switch statement detection** — If the CFG has a `switch`-like pattern (one comparison branching to N cases), flag it.
2. **Recursive function detection** — If a function calls itself, flag it as recursive.
3. **State machine detection** — `if-else` chain on a single variable that tracks state, with transitions.

### TODO for Full Implementation

```rust
// TODO: Full control flow graph extraction and analysis
// TODO: Tree-like `if-else` detection (binary search, trie)
// TODO: Recursion depth analysis and tail-call detection
// TODO: Loop structure analysis (for vs while vs do-while vs goto-based)
// TODO: Error handling pattern detection (C try/catch via goto cleanup)
// TODO: Generate control flow summary for LLM prompt context
```

### Impact

Medium. This gives the LLM structural awareness. "This is a switch statement with 50 cases matching an enum" is much more useful than "here's 50 lines of assembly."

---

## 5. String & Configuration Context

### Problem

The binary has strings like `"Failed to load texture: %s"`, `"FPS: %d"`, and `"config/game.ini"` that reveal what the program does, but the LLM only sees function code.

### What It Is

Using the rich string/symbol data Ghidra already extracts to give the LLM contextual information about the program's purpose, data formats, and configuration.

### Data Sources

| Data | How It Helps |
|------|-------------|
| User-visible strings | "If this function references `"Loading..."`, it's a UI/load screen function" |
| File paths | `"config/settings.xml"` → this function reads config |
| Error messages | `"Failed to load texture: %s"` → this function loads textures |
| Format strings | `"%.2f"` → floating point math; `"%d"` → integer; `"%s"` → string handling |
| Resource names | `"sound/boss_theme.ogg"` → audio system function |
| Debug logging | `"Entity created, id=%d"` → game entity management |

### MVP Scope

1. **String classification** — Tag each string as user-visible, error message, file path, format string, internal identifier, etc.
2. **Per-function string summary** — Add a "CONTEXT STRINGS" section to the LLM prompt listing strings referenced by this function.

### TODO for Full Implementation

```rust
// TODO: Clustering strings by function to infer function purpose
// TODO: Detecting serialization formats from string templates (JSON, XML, INI)
// TODO: Detecting network protocols from string patterns
// TODO: Mapping file paths to likely config/data structures
// TODO: Detecting localization strings (multiple language variants)
```

### Impact

Medium. This is the easiest of the five to implement (Ghidra already extracts all strings), and it gives the LLM information it would never otherwise have access to. A function containing `"Failed to load texture: %s"` has immediate, high-confidence context.

---

## 6. How They Compose

These methodologies are not independent — they stack and reinforce each other:

```
Data Structure Recovery ───→ Tells LLM what fields exist
Type Inference            ───→ Tells LLM what types those fields are
Algorithm Recognition     ──→ Tells LLM what the function *does*
String Context            ───→ Tells LLM the function's *purpose*
Control Flow Patterns     ──→ Tells LLM the *structure* of the implementation
```

Put together, the prompt could say:

> This function is called by `DrawFrame` (caller) and implements a **sprite rendering loop** (algorithm). It iterates over a `Sprite[]` array (data structure, type inference) sorted by Z-depth (algorithm). It calls `Direct3D9::DrawPrimitive` (leaf API) for each visible sprite. The sprite struct has fields: `x:i32, y:i32, texture:u32, alpha:f32`. This is a game rendering function (string context).

That's dramatically better than "Translate this function."

### Data Flow Between Methodologies

```
┌─────────────────────────────────────────────────────────────────────┐
│                    String & Config Context                          │
│  (Ghidra strings → function purpose tags)                          │
│                       │                                            │
│                       ▼                                            │
│  ┌──────────────┐     ┌──────────────────┐                        │
│  │ Algorithm    │────→│ Data Structure   │                         │
│  │ Recognition  │     │ Recovery         │                         │
│  └──────────────┘     └────────┬─────────┘                        │
│                                │                                   │
│                                ▼                                   │
│                    ┌──────────────────────┐                        │
│                    │ Type Inference       │                        │
│                    │ & Propagation        │                        │
│                    └──────────┬───────────┘                        │
│                               │                                    │
│                               ▼                                    │
│                    ┌──────────────────────┐                        │
│                    │ Control Flow         │                        │
│                    │ Pattern Recognition  │                        │
│                    └──────────┬───────────┘                        │
│                               │                                    │
│                               ▼                                    │
│                    ┌──────────────────────┐                        │
│                    │  CALL GRAPH          │                        │
│                    │  (from existing plan)│                        │
│                    └──────────────────────┘                        │
└─────────────────────────────────────────────────────────────────────┘
```

**Dependency order for implementation:**

1. **Call Graph Assisted Translation** (root & leaf) — existing plan, prerequisite for data flow between methods
2. **Data Structure Recovery** — needs call graph for cross-reference clustering
3. **Type Inference** — needs call graph and data structures for propagation
4. **Algorithm Recognition** — independent but benefits from data structures
5. **Control Flow Patterns** — most independent; works on single functions
6. **String & Configuration Context** — most independent; Ghidra already provides all data

---

## Prioritized Roadmap

| Phase | Methodology | Est. Effort | Key Benefit |
|-------|------------|-------------|-------------|
| **Current** | Call Graph (Root & Leaf) | 2–3 weeks | Skip runtime functions, enrich context |
| **P1** | Data Structure Recovery | 4–6 weeks | Fix wrong struct field guesses (biggest correctness gain) |
| **P2** | Type Inference & Propagation | 3–4 weeks | Fix "undefined4 param_1" problem |
| **P3** | Algorithm Recognition | 4–6 weeks | Translate algorithms correctly, not just literally |
| **P4** | Control Flow Patterns | 2–4 weeks | Generate idiomatic Rust (match, Result, etc.) |
| **P4** | String & Config Context | 1–2 weeks | Highest ROI per hour spent (data is free from Ghidra) |

**Notes on sequencing:**

- **Data Structure Recovery** should be P1 because it feeds into everything else — type inference and algorithm recognition both benefit from knowing struct layouts.
- **Type Inference** is P2 because it also feeds downstream: better parameter types improve both algorithm recognition (can't recognize a hash table if you don't know the parameter types) and data structure recovery (you need to know what type a pointer points to).
- **Algorithm Recognition** is P3 because it depends on having reasonable struct/type context first — guessing an algorithm from raw `undefined4` parameters is nearly impossible.
- **Control Flow Patterns** and **String Context** are P4 because they are independently useful but don't enable or accelerate the others as much.
