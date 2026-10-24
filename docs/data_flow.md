# Data Flow & Workflow — `calxgloss-cli live`

## 1. Top-Level Architecture

`calxgloss live` spawns **two concurrent tasks** in a single process:

```
┌─────────────────────────────────────────────────────────────────┐
│                          calxgloss live                         │
│                                                                 │
│  ┌───────────────────────────┐    ┌──────────────────────────┐  │
│  │  Auto Pipeline            │    │  Web Review UI           │  │
│  │ (foreground / blocks)     │    │  (background task)       │  │
│  │                           │    │                          │  │
│  │  handle_auto()            │    │  handle_serve()          │  │
│  │    │                      │    │    ├─ axum HTTP server   │  │
│  │    ├─ handle_classify     │    │    ├─ REST API           │  │
│  │    └─ run_translation     │    │    └─ WebSocket events   │  │
│  │        _for_dll()×N       │    │                          │  │
│  │      │                    │    │  pause / resume / stop / │  │
│  │      ├─ Kuna engine load  │    │  start endpoints drive   │  │
│  │      │  (in-process)      │    │  the shared pipeline     │  │
│  │      ├─ analysis warmup   │    │  state machine           │  │
│  │      │  (11 evidence      │    │                          │  │
│  │      │   scans per binary)│    │                          │  │
│  │      └─ per-function      │    │                          │  │
│  │          translation      │    │                          │  │
│  └───────────────────────────┘    └──────────────────────────┘  │
│         │                                │                      │
│         └──────────┬─────────────────────┘                      │
│                    │                                            │
│              TranslationEvents                                  │
│              (broadcast channel, cap 256)                       │
│                    │                                            │
│         ProgressState (in-memory live tracker)                  │
└─────────────────────────────────────────────────────────────────┘
```

**Lifecycle:** The server starts first and waits for connections. The auto pipeline then runs to completion (classification + batch translation). The pipeline runs inside a loop: when a run reaches a terminal state the process keeps serving, and the review UI's Start/Restart endpoints queue a `PipelineRunRequest` that re-runs the pipeline in-process. A shared `PipelineControl` state machine (Idle → Running → Paused → Stopping → Complete/Error) is observed by the pipeline at unit boundaries and driven by the web server's pause/resume/stop endpoints. On `Ctrl+C` both tasks abort together.

---

## 2. Configuration Resolution

Before any work starts, three layers of configuration are merged (most specific first):

| Layer | Source | Override priority |
|-------|--------|-------------------|
| **Flags** | CLI args (`--llm-url`, `--llm-model`, etc.) | Highest |
| **Environment** | `CALXGLOSS_LLM_URL`, `CALXGLOSS_LLM_MODEL`, etc. | Middle |
| **File** | `./calxgloss.toml` or `~/.config/calxgloss/config.toml` | Lowest |
| **Defaults** | Built-in (e.g. `workspace` = current directory; the LLM has none) | Lowest |

All LLM keys are loaded but never printed — `calxgloss config` shows `<set>` for secrets.

The repo directory for `live` is always **CWD** (config/env overrides are ignored because the workspace where `.git`, `src/`, and `scratch/` live is always the current directory).

---

## 3. Step-by-Step Data Flow

### 3.1 Phase 1 — Binary Scanning & Classification

```
┌─────────────────────────────────────────────────────────┐
│  handle_auto()                                          │
│                                                         │
│  1. scan_targets(target_dir)                            │
│     └─ Reads directory for *.dll and *.exe files        │
│                                                         │
│  2. For each file, checks re/classify/{sanitized}.json  │
│     └─ Already classified? Skip to translation          │
│     └─ Not classified? Queue for handle_classify()      │
│                                                         │
│  3. handle_classify() for unclassified files            │
└─────────────────────────────────────────────────────────┘
```

**Classification (`handle_classify`):**

```
Binaries (from scan) ──► Analyzer.classify_dlls()
                                │
                    ┌───────────┴───────────┐
                    │                       │
              KunaSource                PE Parser
              (functions())             (fallback)
              for API tags              for export tables
                    │                       │
                    └───────────┬───────────┘
                                │
                    DllClassification[]
                                │
                ┌───────────────┼───────────────┐
                │               │               │
         Category       Strategy       Crate
         (e.g.         (e.g.         Replacement
          Microsoft     Compile)      (e.g. "wgpu")
          Sdk)
                │               │               │
                └───────────────┼───────────────┘
                                │
                    ┌───────────┴───────────┐
                    │                       │
              Write JSON            Commit
              re/classify/          to main
              {dll}.json            (metadata only)
                    │
              ┌─────┴─────────────────────────────┐
              │ Emit to Progress Channel          │
              │                                   │
              │ ClassificationComplete {          │
              │   binary, category, strategy,     │
              │   crate_replacement,              │
              │   exported_symbols,               │
              │   imported_symbols                │
              │ }                                 │
              └───────────────────────────────────┘
```

Classification records are written to **`re/classify/{dll_name}.json`** on disk and committed to `main`. They determine which binaries are ready for translation and inform dependency checking (shim layers must exist before translating functions from shim-layer DLLs). Reviewers can override a classification without re-running the scan through the override layer (`re/analysis/classification_overrides.json`), which the web UI and the analyzer both honor.

---

### 3.2 Phase 2 — Batch Translation Per Binary

For each classified binary, `run_translation_for_dll()` runs the full pipeline.

**Engine load (once per binary, ADR-0041):** before any listing, the target
binary is loaded in-process under the Kuna engine (`KunaSource::load`) — the
only engine (issue #214). There is no server to attach to or spawn, no JVM, no
install step, and no wrong-program guard: the engine answers from the exact
file the run hashes for its read cache.

```
run_translation_for_dll(binary, binary_path, workspace, skip_git, settings, …)
│
├──► emit BatchStarted { binary }
│
├──► KunaSource::load(binary_path)   ← the engine, in-process
│
├──► ScanSource::functions(&source)
│    └─ Returns FunctionSummary[] (name only — the engine lists
│       one program at a time)
│
├──► TranslationPipeline::new(kuna, llm, api_mappings)
│    └─ Also creates: TestGenerator, Analyzer
│
├──► GitManager::init_repo(workspace)
│    └─ Creates .git, README, initial "main" commit
│
├──► Verifier::new(workspace)
│    └─ Creates scratch/ directory for sandboxed builds
│
└──► pipeline.batch_translate(binary, functions, retry_config, verifier)
```

#### 3.2.1 Batch Warmup — Scan Read Cache + Analysis Methodologies

`batch_translate` opens with two steps before any function is translated
(`crates/pipeline/calxgloss-translator/src/pipeline.rs`):

```
pipeline.batch_translate(binary, functions, …)
│
├──► begin_cached_source(binary)
│    └─ Opens CachedScanSource over the KunaSource:
│       a two-tier read-through cache for every engine read
│       (memo → disk documents under re/cache/
│       {binary identity}/{sha256}/ → engine read, write-through).
│       Validity is the binary's SHA-256: changed bytes mean a
│       different directory. --refresh-cache wipes and rewrites
│       the directory. A failed cache build degrades to engine
│       reads, never fails the batch.
│
└──► ensure_* warmup — the eleven analysis scans, in order:
     ensure_type_database          → re/analysis/typesdb/{binary}.json
     ensure_type_inference         → re/analysis/typeinfer/{binary}.json
     ensure_algorithm_recognition  → re/analysis/algorithm/{binary}.json
     ensure_memory_detection       → re/analysis/memory/{binary}.json
     ensure_sync_detection         → re/analysis/sync/{binary}.json
     ensure_callback_detection     → re/analysis/callback/{binary}.json
     ensure_controlflow_detection  → re/analysis/controlflow/{binary}.json
     ensure_string_context         → re/analysis/stringctx/{binary}.json
     ensure_api_detection          → re/analysis/apidetect/{binary}.json
     ensure_const_detection        → re/analysis/consts/{binary}.json
     ensure_serialize_detection    → re/analysis/serialize/{binary}.json
```

Each `ensure_*` follows the same rule: **the persisted JSON is the cache** —
if a result is already saved for the binary, the scan is skipped entirely;
otherwise the engine runs over the batch's `ScanSource` (live or cached), and
its result is saved. A failed scan or failed save only logs a warning: missing
analysis context degrades the prompts, it never fails the batch. While the
scan phase runs, the engine's heartbeat is armed once around the whole
group (`begin_pass` / `end_pass`) under the phase name *evidence scans*
and beats a `BatchProgress { binary, pass, function, index, total }`
event, throttled to 500 ms, counting unique functions consumed — so the
dashboard shows one honest "n of m functions consumed" row for the phase
instead of one per scan (issue #239).

Every methodology also has a manual CLI entry point (§4) that runs the same
scan and can print a cached result with `--show`.

#### 3.2.2 Translation Pipeline — One Function

Each function in the binary goes through the full pipeline **sequentially**
(operator scope filters the queue first: skipped functions never enter it,
prioritized functions sort to the front):

```
pipeline.translate(binary, function)
│
│  Step 1: Fetch Function Metadata from the Engine
│  ─────────────────────────────────────────────
│  fetch_function(binary, function)
│    └─ Seam reads: functions() resolves the name,
│       decompile() gives the body, callers()/xrefs_to()
│       give the call edges → FunctionInfo {
│        name, address, disassembly, decompiler_output,
│        callers[], callees[]    ← from xrefs + decompiler
│      }
│
│  Step 2: Tag Windows APIs
│  ───────────────────────
│  ScanSource::imports(&source)     ← import names from the engine
│  Analyzer.tag_windows_apis(disassembly, imports)
│    └─ Matches disassembly tokens against PAL mappings
│    └─ Returns WindowsApiCall[] { name, category, pal_mapping }
│
│  Step 3: Generate Baseline Tests
│  ──────────────────────────────
│  parse_decompiled(decompiler_output)   ← extract C signature
│  generate_test_inputs(signature, disassembly)
│    └─ Boundary values: 0, min/max, null pointer, empty string
│    └─ Typical values: small positive integers, common strings
│    └─ Edge cases from disassembly patterns (cmp, ja, jl, etc.)
│    └─ Returns TestCase[] { inputs, expected_return (null), ... }
│
│  Step 4: Detect Complexity → Select Context Tier
│  ───────────────────────────────────────────
│  Analyzer.detect_complexity(disassembly, windows_apis)
│    └─ Simple / Moderate / Complex
│    └─ Picks a ContextTier: Signature → Disassembly → WithTests
│       → ModuleContext → FullModule
│    └─ Emits ContextTierSelected; a reviewer override can force a tier
│
│  Step 4b: Enrich Call-Graph Context
│  ──────────────────────────────────
│  Unless --no-callgraph: build_enriched_call_graph over the batch's
│  ScanSource — CallGraphBuilder fetches each function's metadata,
│  RootDetector/LeafDetector classify every node (Root/Leaf/Middle),
│  and the graph is persisted to re/analysis/{binary}_call_graph.json.
│  ContextEnricher turns it into per-function caller/callee context
│  with API categorization and crate suggestions.
│
│  Step 4c: Pull Analysis Findings for This Function
│  ─────────────────────────────────────────────────
│  ModuleContext / FullModule prompts read the persisted
│  methodology documents and keep the records tied to this function:
│    └─ extract_data_structures  ← re/analysis/typesdb/{binary}.json
│    └─ extract_control_flow_hints ← re/analysis/controlflow/{binary}.json
│    └─ (FullModule adds shim-layer code from re/shims/ and PAL
│        trait definitions for the function's API categories)
│
│  Step 5: Build Prompt & Send to LLM
│  ─────────────────────────────────
│  One askama template per tier:
│    Signature    → signature_translate.j2
│    Disassembly  → translate.j2
│    WithTests    → with_tests_translate.j2
│    ModuleContext→ module_context_translate.j2
│    FullModule   → full_module_translate.j2
│    └─ Includes: disassembly, decompiler output,
│                Windows API mappings, baseline test inputs,
│                call-graph context, data structures,
│                control-flow findings
│
│  LlmClient.complete([user_message: prompt])
│    └─ OpenAI-compatible HTTP POST
│    └─ Keepalive events every 30s while in flight
│    └─ Returns LlmResponse { content, tokens_used }
│
│  ──► Translation { binary, function, rust_code, prompt_used,
│                    model, tokens_used, baseline_tests, call_graph }
```

#### 3.2.3 Verification Loop

After the initial translation, the `retry` loop runs:

```
retry::try_translate_with_retry(initial_translation, context)
│
├──► Verifier.verify(binary, function, rust_code, baseline_tests)
│    │
│    ├──► Scaffold Cargo project in scratch/
│    │     ├── Cargo.toml (depends on pal = ../pal)
│    │     ├── src/lib.rs  (translated code + PAL stubs)
│    │     └── src/main.rs (test runner binary)
│    │
│    ├──► run_cargo_check()  ──► cargo check
│    │     └─ CompileResult { success, errors[], warnings[] }
│    │
│    └──► If compilation succeeded:
│         ├──► run_test_runner()  ──► cargo run
│         │     └─ Reads baseline.json, calls translated function,
│         │            compares outputs
│         │     └─ TestResult[] { passed, expected, actual, error }
│         │
│         └──► VerificationResult {
│               compiled, tests_passed, tests_total, failed_tests[]
│             }
│
│  ──► If success: return RetryResult (done)
│  ──► If failure: pick retry strategy and loop
│
│  Retry Strategy Cycle:
│  ───────────────────
│  compile_fix ──► feed compilation errors back to LLM
│       │
│       └─► LLM fixes code ──► verify again
│       │
│       └─► If still failing: test_fix
│       │
│  test_fix ──► feed failing test cases back to LLM
│       │
│       └─► LLM fixes code ──► verify again
│       │
│       └─► If still failing: escalate
│       │
│  escalate ──► add more context: the FULL evidence base —
│       │         every methodology's findings for this function
│       │         (types, inferred types, algorithms, memory,
│       │         concurrency, callbacks, control flow, strings,
│       │         APIs, constants, serialization) plus call graph,
│       │         neighboring bodies, and failure history
│       │
│       └─► LLM re-translates with more context
│       │
│       └─► If still failing: edge_case_fix
│       │
│  edge_case_fix ──► focus on edge case patterns
│       │
│       └─► LLM handles boundary conditions
│       │
│       └─► Back to compile_fix on failure
│
│  Repeat until: success OR max_attempts reached
│
└──► RetryResult {
        attempts: [TranslationAttempt, ...],
        success: bool,
        rust_code: Option<String>,
        success_strategy: Option<String>
      }
```

Each `TranslationAttempt` contains:
- `attempt` number, `strategy` name
- `rust_code`, `compiled`, `compilation_errors[]`
- `tests_passed`, `tests_total`, `failed_tests[]`
- `tokens_used`

Detectors watch the loop: a **hallucination detector** scans each response
for references to non-existent APIs (`HallucinationDetected`), an
**infinite-loop detector** fires when the same bad output repeats (`InfiniteLoopDetected`),
and fault events (`BehaviorDivergenceDetected`, `ResourceExhaustionDetected`)
are logged to `re/analysis/fault_log.json`. Every attempt's tokens are
recorded to `re/analysis/token_usage.json` and every prompt strategy to
`re/analysis/prompt_strategy_log.json` — the analytics endpoints compute from
these logs on demand.

---

### 3.3 Phase 3 — Git Operations Per Function

After a function translation succeeds (at any attempt), git operations follow:

```
for each successful function:
│
├──► Write translated.rs to disk
│     └─ workspace/src/modules/{function}/translated.rs
│
├──► GitManager.create_branch(binary, function, attempt, policy)
│     └─ Branch name: re/{binary}/{function}v{N}
│     └─ Branches from latest main commit
│     └─ Checks shim-layer dependencies (Warn policy)
│
├──► GitManager.commit(branch, message, [translated.rs])
│     └─ Stages the Rust file, creates commit
│     └─ Author: Calxgloss <calxgloss@system>
│
├──► GitManager.merge_to_main(branch)
│     └─ Fast-forward if branch is descendant of main
│     └─ 3-way merge otherwise
│     └─ Returns: Merged / AlreadyUpToDate / Conflicts
│
└──► Record branch name on FunctionResult
```

If git is skipped (`--skip-git`), these steps are bypassed but the code is still written to disk.

---

## 4. Analysis Methodologies — The Evidence Crates

Eleven methodology crates under `crates/evidence/` (beside the call-graph and
orchestration crates) each implement a **methodology**: a per-binary scan that reads engine facts through
the shared `ScanSource` seam, detects structured findings, persists them as one
JSON document per binary under `re/analysis/{methodology}/{binary}.json`, and
feeds the findings tied to a function into its translation prompts.

**Shared plumbing:**

- **`ScanSource` seam** (`crates/integrations/calxgloss-decomp/src/scan_source.rs`) —
  one trait for every read: `functions`, `decompile`, `strings`, `callers`,
  `xrefs_to`, `data_types`, `struct_layout`, `enum_values`, `data_items`,
  `imports`, `exports`, `image_base`, `read_memory`. Engines never talk HTTP;
  they run over a loaded `KunaSource`, a `CachedScanSource` (the batch read
  cache), or a canned program in tests.
- **One decompile per function per scan.** Each engine's orchestration walks
  the function listing once, decompiles each body exactly once (served from the
  batch cache after the first scan), and keeps the bodies. Cross-function
  passes — memory hand-offs, lock orders, callback chains, mutual recursion,
  cross-field correlation, string hand-offs — read those kept bodies, adding
  **no extra engine reads**.
- **The persisted JSON is the cache.** The batch warmup (§3.2.1) skips any
  scan whose document already exists; `--show` prints a cached document
  without loading the engine.
- **Graceful degradation.** A failed scan logs a warning and the batch
  proceeds; a missing or corrupt document yields empty prompt context —
  missing evidence degrades a prompt, it never fails a translation.
- **Confidence scores.** Every finding carries a 0–100 confidence; the
  detectors' false-positive gates are what floor it.

**The methodologies** (crate → what it detects → Rust shape it suggests):

| Methodology | Crate | Detectors | Prompt section |
|-------------|-------|-----------|----------------|
| Type database | `calxgloss-typesdb` | Named types from the Type Manager; vtable detection (method pointers, base-class inheritance, COM interfaces); string-guided struct inference; STL/MFC shape flagging | `DATA STRUCTURES` (escalate) / `SHARED DATA STRUCTURES` (module tiers) |
| Type inference | `calxgloss-typeinfer` | C++ this-pointer detection; parameter-size detection; known-type propagation through a signature database; cross-function propagation (callee→caller and caller→callee), local-variable chains, return types from caller usage, C-mangling contracts | `TYPE INFORMATION` |
| Algorithm recognition | `calxgloss-algorithm` | Control-flow signature matching (sort, search, hash lookup, state machine…); string-guided hints (CRC, md5, sha, gzip…); callback-shape patterns; multi-function correlation (divide-and-conquer, sort+comparator); a JSON pattern database can replace the built-in sets (`--patterns`) | `RECOGNIZED ALGORITHMS` |
| Memory lifecycle | `calxgloss-memory` | `malloc`/`free` pairs → `Box`; handle pairs (`CreateFileW`/`CloseHandle`, `fopen`/`fclose`) → RAII guard with `Drop`; ref-count patterns (`AddRef`/`Release`) → `Rc`/`Arc`; cross-function allocation tracking, leaks, ownership moves, per-type Drop suggestions | `MEMORY LIFECYCLE` |
| Concurrency | `calxgloss-sync` | Mutex/lock pairs → `std::sync::Mutex`/`RwLock`; atomics → `AtomicU32`/`U64`; thread spawns + joins → `std::thread`/`tokio`; thread-local storage families; async-runtime shapes; futex syscall shapes; cross-function lock orders; data-race claims on shared globals | `CONCURRENCY` |
| Callbacks | `calxgloss-callback` | Function-pointer array calls → `Vec<Box<dyn Fn>>`; registration sites → stored closures; jump tables → `match`; plugin architectures (`LoadLibrary`/`GetProcAddress` + entry point) → `Box<dyn Plugin>`; cross-function register-then-call chains; event-system reconstruction; closure contracts filled from the typeinfer cache | `CALLBACKS` |
| Control flow | `calxgloss-controlflow` | Switch-shaped if/else-if chains → `match`/dispatch table; self-recursion (+ tail calls, loop-nested depth); state machines (`STATE_*` chains); per-body CFG with loop nesting depth; branch density (dispatch-table vs sequential); mutual-recursion cycles | `CONTROL FLOW` (escalate) / `CONTROL FLOW PATTERNS` (module tiers) |
| String context | `calxgloss-stringctx` | Nine string categories (error, path, resource, log, format…); format-specifier → Rust argument types; string→function mapping via body parsing with xref fallback; localization signals; cross-function string hand-offs | `STRINGS` |
| API detection | `calxgloss-apidetect` | Import-table classification (DirectX 9, SDL2, Win32, POSIX, PNG, zlib, stdio, STL) → crate suggestions with feature flags; per-function API reachability through the call graph; category enrichment; platform divergence (Win32+POSIX mix) → cfg-gated translation; COM interface claims | `LIBRARIES AND APIS` |
| Constants | `calxgloss-consts` | Bitflag groups (power-of-two literals in bitwise contexts, composite-mask decomposition) → `bitflags!`; switch-run enum candidates → `enum`; program-wide repeated values → named `const`s with context-derived names; program-level flag-family merges; known protocol magics; RGB-shaped color groups | `CONSTANTS` |
| Serialization | `calxgloss-serialize` | Byte-swap calls (`ntohs`, `__builtin_bswap*`) → `byteorder`; shift-and-or pack/unpack chains → `bitvec`/named-field masking; magic-byte comparisons (PNG/gzip/ZIP) → decoder crates; cross-field validation (checksum + length framing); composed field layouts; protocol message identification; program-wide per-type endianness map | `SERIALIZATION` |
| Known-library identification | `calxgloss-libmatch` | Normalized decompiled bodies (Ghidra variable names, register temporaries, and volatile addresses become wildcards; calls, operators, constants, string literals, and control-flow keywords stand) matched against a signature set of statically linked CRT/STL code (`memcpy` idiom, `strlen` scan) → findings naming the matched symbol and its family (CRT/STL); competing claims resolve to the strongest | — (not yet rendered into prompts) |
| Error-handling idioms | `calxgloss-errhandling` | Per-function readings over the bodies the scan keeps — no extra engine reads: a body spelling a whole `try {` … `catch(...){` SEH frame → one finding quoting the `catch` clause line, at the strongest body-text band 80, suggesting an exception-mapped Rust error type over the straight-line logic that would drop the frame; a named personality-handler thunk (`__except_handler3`/`__except_handler4`) → band 70; an exception-API call (`SetUnhandledExceptionFilter`, `AddVectoredExceptionHandler(Ex)`, `SetWindowLongPtrA(GWLP_EXCEPTIONHANDLER)`) → band 60; a direct `RaiseException` site → its own finding, naming the raised exception code when the source spells one; a goto-cleanup ladder — two or more guarded forward gotos converging on one label block that releases a resource (`free`/`CloseHandle`/… vocabulary, builder-extensible) or returns a bare constant → one finding naming the join block by its printed label, at band 55 (release) or 45 (constant return), the release line as evidence, never outranking a spelled frame; a spelled frame beside a named handler or API call stays one finding — the strongest SEH family wins; failure codes of HRESULT (`0x8…`) or NTSTATUS (`0xC…`) shape landing in returns, guard comparisons, or `RaiseException` arguments → one record per distinct code per function naming the code, its site kind, and the band 74 (returned) / 72 (raised) / 64 (compared), strongest site winning the one record; BOOL-shaped `0`/`1` returns, small-integer comparisons, and out-of-band values like the C++ eh code `0xE06D7363` claim nothing — codes ride the same document under their own kind tag | — (not yet rendered into prompts) |
| Call graph | `calxgloss-callgraph` (+ `calxgloss-analysis` orchestration) | Full-program call graph with Root/Leaf/Middle classification (VB6/.NET/MinGW/MSVC runtime roots, third-party-API leaves); `ContextEnricher` prompt context; `TranslationOrderer` priority plans | call-graph context in every tiered prompt |

**Where the findings enter the prompts:**

- **Initial translation:** the `ModuleContext` and `FullModule` context tiers
  read the **typesdb** and **controlflow** documents (plus call-graph context,
  neighboring bodies, and — at FullModule — shim-layer code and PAL traits).
- **Escalate retry:** the escalate prompt pulls **all eleven** methodologies'
  findings for the target function, joined from the persisted documents by
  `retry/helpers::extract_*` (each keeps only the records whose evidence lives
  in this function's body, vtable, xrefs, or call path).

**Manual entry points** — every methodology is also a CLI command running the
same engine against a target binary loaded in-process:

```text
calxgloss typesdb     --binary eqmain.dll [--show] [--no-tag]
calxgloss typeinfer   --binary eqmain.dll [--show] [--write-back] [--confidence-floor 70]
calxgloss algorithm   --binary eqmain.dll [--show] [--patterns my-patterns.json]
calxgloss memory      --binary eqmain.dll [--show]
calxgloss sync        --binary eqmain.dll [--show]
calxgloss consts      --binary eqmain.dll [--show]
calxgloss callback    --binary eqmain.dll [--show]
calxgloss controlflow --binary eqmain.dll [--show]
calxgloss stringctx   --binary eqmain.dll [--show]
calxgloss apidetect   --binary eqmain.dll [--show]
calxgloss serialize   --binary eqmain.dll [--show]
```

**Write-back into the program** — the read cache never implements the write side;
type writes go through the separate `TypeWriteSource` trait
(`set_function_prototype`, `set_local_variable_type`, `create_struct`,
`create_enum`, `create_typedef`, `add_struct_field`):

- `typeinfer --write-back` applies surviving inferences in program order,
  creating missing named types and **narrowing only undefined-typed slots** —
  a concrete type already in the program is never overwritten. Records below
  the confidence floor (default 70) are skipped with the reason reported.
- `typesdb` tags detected vtable methods (`vtable-method`) back into the
  program unless `--no-tag`.

**Derived codegen artifacts** (rendered beside the JSON, never read back):

- `re/analysis/typesdb/{binary}.rs` — `#[repr(C)]` declarations recovered
  from the type database.
- `re/analysis/consts/{binary}.rs` — a `bitflags!`-style block per flag
  family, an `enum` block per enum candidate, named `const`s.
- `re/analysis/apidetect/{binary}.rs` — `extern "C"` declarations for the
  identified APIs; `re/analysis/apidetect/{binary}.toml` — a Cargo-style
  dependency manifest of the suggested crates.

---

## 5. Progress Events — The Live Data Stream

A `TranslationEvents` broadcast channel (capacity 256) carries progress events from the pipeline to the web UI. Every major milestone emits one:

| Event | When Emitted |
|-------|-------------|
| `PipelineStateChanged { previous, state }` | Any pipeline-control transition (start/pause/resume/stop/complete/fail) |
| `QueuePlanned { binaries }` | The live loop's ordered run plan, once before the first pass |
| `ClassificationComplete { binary, category, strategy, crate_replacement, exported_symbols, imported_symbols }` | After binary classification |
| `BatchStarted { binary }` | The per-binary pass begins (before any unit exists) |
| `BatchProgress { binary, pass, function, index, total }` | Heartbeat of a pre-translation pass (call graph, the evidence scans), throttled to 500 ms |
| `TranslationStarted { binary, function }` | Before the engine fetch |
| `ScanFetchComplete { binary, function, address, disassembly_lines }` | After function metadata loaded |
| `ApiTaggingComplete { binary, function, tagged_apis }` | After Windows API tagging |
| `TestsGenerated { binary, function, test_count }` | After baseline test generation |
| `ContextTierSelected { binary, function, tier, tier_label, complexity, api_call_count }` | After complexity analysis, before the first LLM call (re-emitted when the tier escalates) |
| `LlmCallStart { binary, function, attempt, strategy }` | Before LLM request |
| `LlmRequest { binary, function, attempt, strategy, prompt }` | Full prompt sent |
| `LlmCallInProgress { binary, function, attempt, strategy, elapsed_secs }` | Keepalive every 30s |
| `LlmCallComplete { binary, function, attempt, code_length, tokens_used }` | LLM response received |
| `LlmResponse { binary, function, attempt, strategy, content, tokens_used }` | Full response body |
| `LlmCallFailed { binary, function, attempt, strategy, error }` | HTTP/network failure |
| `HallucinationDetected { binary, function, attempt, strategy, hallucinated_apis }` | Response references non-existent APIs |
| `InfiniteLoopDetected { binary, function, streak, streak_start_attempt, streak_end_attempt, strategy }` | Same bad output repeated ≥3 times |
| `BehaviorDivergenceDetected { binary, function, attempt, strategy, baseline_passed, baseline_total, edge_tests_passed, edge_tests_total, failing_edge_cases, fault_confidence }` | Baseline passes but edge-case tests fail |
| `ResourceExhaustionDetected { binary, function, attempt, strategy, reason, elapsed_secs, recommended_backoff_secs }` | Local LLM overloaded / timed out |
| `TranslationAttemptCompleted { binary, function, attempt, success, compiled, tests_passed, tests_total, compilation_errors[], failed_tests[], strategy, tokens_used }` | After verify step |
| `TranslationCompleted { binary, function, total_attempts, success_strategy }` | Success after retry loop |
| `TranslationFailed { binary, function, total_attempts }` | All retries exhausted |
| `UnitCancelled { binary, function }` | Operator cancelled the in-flight unit |
| `FunctionCompleted { binary, function, success, attempts, branch }` | Immediately after each function completes |
| `BatchSummary { binary, total_functions, success_count, failure_count, total_attempts, total_tokens }` | After all functions in binary |

### Event Flow

```
TranslationPipeline
        │
        │ emit(ProgressEvent::BatchStarted{...})
        │ emit(ProgressEvent::BatchProgress{...})   ← scan heartbeats
        │ emit(ProgressEvent::TranslationStarted{...})
        │ emit(ProgressEvent::ScanFetchComplete{...})
        │ emit(ProgressEvent::ApiTaggingComplete{...})
        │ emit(ProgressEvent::TestsGenerated{...})
        │ emit(ProgressEvent::ContextTierSelected{...})
        │ emit(ProgressEvent::LlmCallStart{...})
        │ emit(ProgressEvent::LlmRequest{...})
        │ (keepalive every 30s via LlmCallInProgress)
        │ emit(ProgressEvent::LlmCallComplete{...})
        │ emit(ProgressEvent::TranslationAttemptCompleted{...})
        │ emit(ProgressEvent::FunctionCompleted{...})
        │
        └──────────► broadcast::Sender
                       │
                 ┌─────┴─────┐
                 │           │
           handle_live     WebSocket
           keeps original  server subscribes
           for retry loop  via SessionManager
                             │
                      ┌──────┴──────────────┐
                      │                     │
               ProgressState             WS Clients
               (in-memory)               (browser)
               updates live              receives JSON
               dashboard state           events
                      │
               LlmIoLog (live mode also appends
               prompts/responses to
               re/analysis/llm_io/log.jsonl)
```

The `ProgressState` in the web server maps `"binary/function"` keys to `ProgressEntry` objects with status (`Translating`, `LlmCall`, `Compiling`, `Testing`, `Complete`) for real-time dashboard overlay.

---

## 6. File System Layout

```
<workspace>/                          ← CWD (or --workspace)
│
├── .git/                            ← Git repo (auto-initialized)
│   ├── refs/heads/main              ← accepted translations land here
│   └── refs/heads/re/               ← all translation branches
│       ├── game_logic/DrawSpritev1
│       ├── game_logic/DrawSpritev2  ← retry attempt
│       └── ...
│
├── src/
│   └── modules/
│       └── {function}/
│           └── translated.rs        ← final accepted code (on main)
│
├── re/                              ← metadata and artifacts
│   ├── classify/
│   │   ├── game_logic.dll.json      ← classification record
│   │   ├── d3d9.dll.json
│   │   └── ...
│   ├── analysis/                    ← the methodology documents + run logs
│   │   ├── typesdb/
│   │   │   ├── {binary}.json        ← recovered type database
│   │   │   └── {binary}.rs          ← rendered #[repr(C)] declarations
│   │   ├── typeinfer/{binary}.json  ← inferred param/local/return types
│   │   ├── algorithm/{binary}.json  ← recognized algorithms
│   │   ├── memory/{binary}.json     ← allocation/handle/refcount findings
│   │   ├── sync/{binary}.json       ← lock/atomic/thread/tls/async findings
│   │   ├── consts/
│   │   │   ├── {binary}.json        ← flag groups, enums, named constants
│   │   │   └── {binary}.rs          ← rendered bitflags/enum/const blocks
│   │   ├── callback/{binary}.json   ← fp arrays, registrations, plugins
│   │   ├── controlflow/{binary}.json← switch chains, recursion, loops, CFG
│   │   ├── stringctx/{binary}.json  ← string roles + format-string types
│   │   ├── apidetect/
│   │   │   ├── {binary}.json        ← library/API identifications
│   │   │   ├── {binary}.rs          ← rendered extern "C" bindings
│   │   │   └── {binary}.toml        ← rendered dependency manifest
│   │   ├── serialize/{binary}.json  ← endianness, packing, formats
│   │   ├── {binary}_call_graph.json ← enriched call graph
│   │   ├── unit_overrides.json      ← reviewer per-unit overrides
│   │   ├── token_usage.json         ← per-attempt token log
│   │   ├── prompt_strategy_log.json ← per-prompt strategy outcomes
│   │   ├── fault_log.json           ← fault events with recovery guidance
│   │   └── llm_io/log.jsonl         ← live-mode prompt/response log
│   ├── cache/                       ← two-tier scan read cache
│   │   └── {binary identity}/       ← one directory per target binary
│   │       └── {sha256 of binary}/  ← manifest.json + per-read
│   │           ├── functions.json   ←   documents: functions,
│   │           ├── decompile/…      ←   decompile/{fn}.json,
│   │           ├── callers/…        ←   callers/{addr}.json,
│   │           └── ...              ←   memory/{addr}-{len}.json, …
│   ├── review/
│   │   ├── skips.json               ← reviewer-skipped units
│   │   └── queue_overlay.json       ← manual queue order + priority
│   ├── shims/
│   │   └── {dll}/                   ← generated shim-layer crates
│   ├── baseline/
│   │   └── {dll}/
│   │       └── {function}/
│   │           └── baseline.json    ← behavioral test results
│   ├── accepts/
│   │   └── {dll}/
│   │       └── {function}/
│   │           └── v{N}.json        ← merge timestamp records
│   ├── rejections/
│   │   └── {dll}/
│   │       └── {function}/
│   │           └── v{N}.json        ← send-back reasons
│   └── patches/
│       └── {dll}/
│           └── {function}/
│               └── v{N}.json        ← failure records
│
└── scratch/                         ← sandboxed Cargo projects
    ├── pal/                         ← shared PAL stub crate
    │   ├── Cargo.toml
    │   ├── src/lib.rs
    │   └── src/stub_content.rs
    ├── game_logic_DrawSprite_{ts}/  ← one per verify call
    │   ├── Cargo.toml
    │   ├── src/lib.rs               ← translated code + PAL stubs
    │   ├── src/main.rs              ← test runner binary
    │   └── baseline.json            ← test inputs + expected outputs
    └── ...
```

---

## 7. Web Review UI

### 7.1 Endpoints

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/` | Dashboard frontend (HTML/JS/CSS) |
| GET | `/api/dashboard` | Full review dashboard JSON (git branches, statuses) |
| GET | `/api/pipeline` | Pipeline state-machine snapshot + run plan |
| POST | `/api/pipeline/pause` / `resume` / `stop` / `start` | Drive the shared pipeline control |
| POST | `/api/pipeline/cancel-current` | Abort the unit in flight at the next safe point |
| POST | `/api/pipeline/restart` | Re-run a stopped pipeline in the same process |
| POST | `/api/pipeline/binaries/{binary}/pause` / `resume` | Per-binary pause: hold a discovered binary out of the auto run's queue (live router only) |
| GET/POST/DELETE | `/api/units/{id}/override` | Reviewer override for one unit's next attempt (forced tier/strategy, hints, skip) |
| GET/POST | `/api/binaries/{name}/classification` | View/override a binary's classification (analyzer honors it before strategy dispatch) |
| GET | `/api/units/{id}` | Single unit detail (justification, diff, tests, history, persisted analysis context: API mappings + call graph) |
| GET | `/api/units/{id}/diff` | Git diff between branch and main |
| GET | `/api/units/{id}/attempts` / `attempts/diff` | Persisted attempt list + side-by-side diff |
| GET | `/api/units/{id}/decomp` | Unit's engine-side view (decompiled context for the unit) |
| POST | `/api/units/{id}/accept` | Merge branch into main + write acceptance record |
| POST | `/api/units/{id}/send-back` | Record rejection reason |
| POST | `/api/units/{id}/patch` | Request retry translation |
| POST | `/api/units/{id}/skip` / `unskip` | Skip state (`re/review/skips.json`) |
| GET/POST | `/api/batch/accept` / `send-back` / `skip` | Batch review actions over a unit set |
| GET | `/api/queue` | Review queue, dependency-ordered |
| GET | `/api/queue/next` | Next unit to review |
| GET/PUT | `/api/queue/overlay` | Manual queue order + priority |
| GET | `/api/graph` | Dependency graph data |
| GET | `/api/progress` | Live translation progress (in-memory state) |
| GET | `/api/progress/enhanced` | Live view's per-unit progress records |
| GET | `/api/events/upgrade` | WebSocket upgrade for real-time events |
| GET | `/api/binaries/list` | Per-binary summary (classification + overrides + counts + tokens) |
| GET | `/api/binaries/{name}` | Binary detail: classification (with override state), export/import counts, per-function review status |
| GET | `/api/llm-io` (+ `/clear`) | LLM prompt/response log (`re/analysis/llm_io/log.jsonl`) |
| GET | `/api/faults` (+ `/summary`, `/by-binary`, `/trend`) | Fault-log analytics (`re/analysis/fault_log.json`) |
| GET | `/api/token-usage/…` | Token analytics by summary / binary / tier / strategy |
| GET | `/api/strategy-analytics/…` | Prompt-strategy analytics |
| GET | `/api/llm-metrics/…` | LLM performance by summary / tier |
| GET | `/api/scope` (+ subroutes) | Run scope: which binaries/functions re-enter the queue |
| GET/POST | `/api/gc/candidates` / `archive` | Stale-branch GC preview/archive |
| GET/POST | `/api/server/status` / `shutdown` / `restart` | Server lifecycle |
| GET | `/health` | Health check |

### 7.2 Review Actions

The web UI can act on translation units:

- **Accept** — merges the `re/{binary}/{function}v{N}` branch into `main`, writes `re/accepts/{dll}/{function}/v{N}.json` with timestamp
- **Reject/Send-Back** — writes `re/rejections/{dll}/{function}/v{N}.json` with reason (branch is NOT deleted)
- **Request Patch** — queues a retry (increments version, creates new branch)
- **Skip / Unskip** — keeps a unit out of (or back in) the translation queue
- **Cancel current unit** — aborts the in-flight unit at the earliest safe point
- **Pause/resume binary** — holds a discovered target binary out of the auto run's queue (an in-flight pass ends at the next unit boundary); the paused set rides the scope record and every change fans out to WS clients as a `binary_pause_changed` event
- **Override** — per-unit forced context tier, retry strategy, or reviewer hints that ride into the next prompt (`re/analysis/unit_overrides.json`)

### 7.3 Dashboard States

Each unit in the review dashboard has one of these statuses:

| Status | Meaning |
|--------|---------|
| `Queued` | Translation complete, awaiting review |
| `PendingReview` | Currently being reviewed |
| `Accepted` | Branch merged into main |
| `Merged` | Same as Accepted (historical) |
| `Blocked` | Waiting on dependency |
| `SendBack` | Sent back for fixes |

---

## 8. Retry Strategies in Detail

When a translation attempt fails verification, the strategy determines how the LLM is asked to fix it:

### `compile_fix`
1. LLM gets the original prompt + compilation error messages
2. LLM re-generates code fixing syntax/type errors
3. Verified again with `cargo check`

### `test_fix`
1. LLM gets the original prompt + failing test case details
2. LLM re-generates code fixing behavioral mismatches
3. Verified again with test runner

### `escalate`
1. LLM gets the original prompt + the **full evidence base**: all eleven
   methodology documents filtered to this function — data structures,
   inferred types, recognized algorithms, memory lifecycles, concurrency,
   callbacks, control-flow patterns, string context, API identifications,
   constants, serialization findings — plus call-graph neighbors,
   neighboring function bodies, and the unit's failure history
2. Full re-translation with richer context

### `edge_case_fix`
1. LLM gets the original prompt + identified edge case patterns
2. Focus on boundary values, null pointers, overflow conditions
3. Verified again

### `auto` (cycling)
Starts at `compile_fix` and cycles through all strategies on each failure:
`compile_fix` → `test_fix` → `escalate` → `edge_case_fix` → `compile_fix` → ...

---

## 9. Summary: Complete `live` Sequence

```
calxgloss live --port 3000
│
├──► [Background] WebSocket server starts on 0.0.0.0:3000
│     └─ Listens for browser connections
│     └─ Broadcasts ProgressEvents to all WS clients
│
├──► Engine load (in-process, ADR-0041)
│     └─ KunaSource::load per binary — no server, no JVM
│
├──► handle_auto() in continue_mode = true
│     │
│     ├──► scan_targets(target_dir)
│     │     └─ Finds: eqgame.dll, d3d9.dll, etc.
│     │
│     ├──► Check re/classify/*.json
│     │     └─ eqgame.dll: done
│     │     └─ d3d9.dll: pending
│     │
│     ├──► handle_classify() [unclassified binaries only]
│     │     └─ Engine scan → PE parse → classification
│     │     └─ Write re/classify/{dll}.json
│     │     └─ Commit to main
│     │     └─ Emit ClassificationComplete event
│     │
│     ├──► For each classified binary:
│     │   │
│     │   └──► run_translation_for_dll(binary)
│     │         │
│     │         ├──► emit BatchStarted; wrong-program guard
│     │         ├──► ScanSource::functions()
│     │         │     └─ ["DrawPrimitive", "DrawSprite", ...]
│     │         │
│     │         ├──► batch_translate warmup
│     │         │     ├──► Open scan read cache (re/cache/)
│     │         │     └──► ensure_* the 11 analysis scans
│     │         │           (typesdb, typeinfer, algorithm, memory,
│     │         │            sync, callback, controlflow, stringctx,
│     │         │            apidetect, consts, serialize)
│     │         │           each: cached JSON → skip; else scan
│     │         │           (heartbeat → BatchProgress) → save
│     │         │
│     │         └──► For each function:
│     │               │
│     │               ├──► TranslationPipeline::translate()
│     │               │     └─ Steps: fetch → tag → testgen → tier
│     │               │        → call-graph enrichment → findings
│     │               │        → prompt → LLM
│     │               │     └─ Returns Translation { rust_code, ... }
│     │               │
│     │               ├──► retry::try_translate_with_retry()
│     │               │     └─ Verifier → compile → test → retry loop
│     │               │     └─ escalate pulls all 11 findings
│     │               │     └─ Emits progress events at each milestone
│     │               │     └─ Returns RetryResult { success, attempts[] }
│     │               │
│     │               └──► If git enabled:
│     │                     ├──► Write src/modules/{func}/translated.rs
│     │                     ├──► create_branch: re/{dll}/{func}v{N}
│     │                     ├──► commit translated.rs
│     │                     └──► merge_to_main → main
│     │
│     └──► Emit BatchSummary event
│
└──► Auto pipeline done → pipeline state → Complete
     └──► serve keeps running; UI Start/Restart can re-run the pipeline
```

**Total data flow per function:**
1. **Engine scan** → disassembly, decompiler pseudo-C, call graph, imports
2. **PAL mappings** → Windows API tags attached to disassembly tokens
3. **Baseline tests** → 10-20+ test cases with input patterns (no expected output yet)
4. **Evidence base** → the eleven methodology documents (recovered once per binary, cached under `re/analysis/`) supply per-function context: types, inferred types, algorithms, memory, concurrency, callbacks, control flow, strings, APIs, constants, serialization
5. **LLM** → prompt sized by context tier, findings injected where they apply → Rust code (with token usage tracking)
6. **Verifier** → sandboxed `cargo check` + `cargo run` against baseline
7. **Git** → branch → commit → merge to main (on success)
8. **Events** → broadcast → WebSocket → live dashboard UI
