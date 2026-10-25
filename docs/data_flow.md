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
│  │      │  (14 evidence      │    │                          │  │
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
run_translation_for_dll(binary, binary_path, scope, plumbing, …)
│
├──► emit BatchStarted { binary }
│
├──► KunaSource::load(binary_path)   ← the engine, in-process
│
├──► ScanSource::functions(&source)
│    └─ Returns FunctionSummary[] (name only — the engine lists
│       one program at a time)
│
├──► GitManager::init_repo(workspace)
│    └─ Creates .git, README, initial "main" commit; when git is in
│       play, the pass description carries the git accepted-attempt
│       port for carry-over seeding
│
├──► assemble(&pass_spec, &kuna) → AssembledPass        (P37, ADR-0050)
│    └─ The pipeline is assembled, never hand-built: pass_spec is the
│       resolved settings folded once into a pass description (LLM
│       endpoint/model/key, context window, temperature, timeout,
│       workspace, Kuna budgets, retry policy) with the run's flags,
│       live control handles, and this binary's identity layered on.
│       Assembly wires the LLM client, Analyzer, hallucination
│       detector, TestGenerator, Verifier (scratch/ for sandboxed
│       builds), and RetryConfig; the pass hands them over as
│       { pipeline, verifier, retry }.
│
└──► pass.pipeline.batch_translate(binary, functions,
                                   &pass.retry, &pass.verifier, …)
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
├──► run_prebatch_scans — the fifteen registered scan rows, fan-out four at a time:
     control-flow            → re/analysis/controlflow/{binary}.json
     memory-lifecycle        → re/analysis/memory/{binary}.json
     concurrency             → re/analysis/sync/{binary}.json
     global-state            → re/analysis/globalstate/{binary}.json
     constants               → re/analysis/consts/{binary}.json
     error-handling          → re/analysis/errhandling/{binary}.json
     float-simd              → re/analysis/floatsimd/{binary}.json
     type-database           → re/analysis/typesdb/{binary}.json
     algorithm-recognition   → re/analysis/algorithm/{binary}.json
     string-context          → re/analysis/stringctx/{binary}.json
     library-api             → re/analysis/apidetect/{binary}.json
     serialization           → re/analysis/serialize/{binary}.json
     type-inference          → re/analysis/typeinfer/{binary}.json
     callback-detection      → re/analysis/callback/{binary}.json
     known-library           → re/analysis/libmatch/{binary}.json
     (one descriptor row per scan in scan_registry's table — name, document
     location, engine constructor, log wording; the roster test names all
     fifteen, issue #308)
│
└──► pair_previous_versions — binary-version pairing, run by the same
     scan step right after the scan pass closes (issue #298): when a
     surviving scan cache from an earlier version of the same binary
     sits beside the fresh one (the read cache keys on identity +
     SHA-256, so changed bytes leave the old directory standing),
     `calxgloss-bdiff` pairs the two scans and persists
     re/analysis/bdiff/{binary}-{old-sha256}-{new-sha256}.json.
     Document-level only — the two directories' cached function listings,
     exports, and kept bodies, read back through the surviving-scan
     surface: zero engine reads, milliseconds, never a failure path.
     With no sibling directory nothing is written and the queue behaves
     exactly as before.
```

Each registered scan row follows the same rule: **the persisted JSON is the cache** —
if a result is already saved for the binary, the scan is skipped entirely;
otherwise the row's engine runs over the batch's `ScanSource` (live or cached), and
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

**Carry-over seeding from the pairing documents** (issue #299): before the
batch queues functions, the pipeline loads the pairing documents left in
`re/analysis/bdiff/` for the binary's *current* bytes. A new-version function
paired at **≥ 80** confidence (`CARRY_OVER_CONFIDENCE_FLOOR`) to an
old-version function whose translation is *accepted* (a merged
`re/{binary}/{function}…` branch) gets its first attempt **seeded** from that
merged `translated.rs` — no prompt built, no LLM called, no token spent — and
then rides the ordinary pipeline: baseline re-capture from the new binary,
full verification against the new bytes, review as usual. Guards: a pairing
document that does not self-name the binary and hash its current bytes as
`new_bytes_sha256` seeds nothing (staleness gate); one accepted translation
seeds at most one new function, strongest pairing wins; below-floor pairings
persist but queue fresh. Seeded results keep provenance — old function,
attempt branch, pairing family, confidence — and the seeded branch's commit
reads `seeded from {old} attempt {n} (paired, {conf}% confidence)`. No pairing
documents, unreadable documents, and functions without an accepted twin all
degrade to the fresh queue, never a failed run.

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
│    └─ (module-context also reads the globalstate, floatsimd,
│        errhandling, typeinfer (parameter directions), consts
│        (data tables) and libmatch (matched *callees*, never the
│        target) documents — §4 for the prompt sections)
│    └─ (FullModule adds shim-layer code from re/shims/ and PAL
│        trait definitions for the function's API categories)
│
│  Step 4d: Carry-Over Seed Check (issue #299)
│  ────────────────────────────────────────────
│  If a fresh bdiff pairing document pairs this function to an
│  accepted previous-version twin at ≥ 80 confidence, the function
│  returns a seeded Translation right here: model "carry-over",
│  no LLM call, provenance in prompt_used — and Step 5 never runs.
│  The retry/verification loop below still judges the seed against
│  the new bytes.
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
│       │         concurrency, global state, callbacks, control
│       │         flow, strings, APIs, constants, serialization,
│       │         float/SIMD arithmetic, error-handling idioms
│       │         and failure codes) plus call graph, neighboring
│       │         bodies, and failure history
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

Fifteen methodology crates under `crates/evidence/` (beside the call-graph,
version-pairing, and orchestration crates) each implement a
**methodology**: a per-binary scan that reads engine facts through
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
| Global state | `calxgloss-globalstate` | Per-function global accesses — which globals (`DAT_*` names) each function reads and writes, with the evidence line and a confidence band — rolled up into a shared-globals index; the sync engine consumes the rollup instead of re-deriving the same reading, and the call-graph orderer takes its state-sharing edges (`with_state_sharing`) from it | `GLOBAL STATE` (module-context and escalate) |
| Callbacks | `calxgloss-callback` | Function-pointer array calls → `Vec<Box<dyn Fn>>`; registration sites → stored closures; jump tables → `match`; plugin architectures (`LoadLibrary`/`GetProcAddress` + entry point) → `Box<dyn Plugin>`; cross-function register-then-call chains; event-system reconstruction; closure contracts filled from the typeinfer cache | `CALLBACKS` |
| Control flow | `calxgloss-controlflow` | Switch-shaped if/else-if chains → `match`/dispatch table; self-recursion (+ tail calls, loop-nested depth); state machines (`STATE_*` chains); per-body CFG with loop nesting depth; branch density (dispatch-table vs sequential); mutual-recursion cycles | `CONTROL FLOW` (escalate) / `CONTROL FLOW PATTERNS` (module tiers) |
| String context | `calxgloss-stringctx` | Nine string categories (error, path, resource, log, format…); format-specifier → Rust argument types; string→function mapping via body parsing with xref fallback; localization signals; cross-function string hand-offs | `STRINGS` |
| API detection | `calxgloss-apidetect` | Import-table classification (DirectX 9, SDL2, Win32, POSIX, PNG, zlib, stdio, STL) → crate suggestions with feature flags; per-function API reachability through the call graph; category enrichment; platform divergence (Win32+POSIX mix) → cfg-gated translation; COM interface claims | `LIBRARIES AND APIS` |
| Constants | `calxgloss-consts` | Bitflag groups (power-of-two literals in bitwise contexts, composite-mask decomposition) → `bitflags!`; switch-run enum candidates → `enum`; program-wide repeated values → named `const`s with context-derived names; program-level flag-family merges; known protocol magics; RGB-shaped color groups | `CONSTANTS` |
| Serialization | `calxgloss-serialize` | Byte-swap calls (`ntohs`, `__builtin_bswap*`) → `byteorder`; shift-and-or pack/unpack chains → `bitvec`/named-field masking; magic-byte comparisons (PNG/gzip/ZIP) → decoder crates; cross-field validation (checksum + length framing); composed field layouts; protocol message identification; program-wide per-type endianness map | `SERIALIZATION` |
| Float/SIMD | `calxgloss-floatsimd` | Per-function float-usage flags read off the kept bodies — scalar float math, vector/matrix idioms (the `CONCAT44`/`SUB4`-style mangled spellings), or both — one flag per flagged function naming the shape, its strongest evidence line, and a confidence band, so mangled vector pseudo-C stops being mistranslated as integer or pointer logic | `FLOAT/SIMD` (module-context and escalate) |
| Known-library identification | `calxgloss-libmatch` | Normalized decompiled bodies (Ghidra variable names, register temporaries, and volatile addresses become wildcards; calls, operators, constants, string literals, and control-flow keywords stand) matched against a signature set of statically linked CRT/STL code (`memcpy` idiom, `strlen` scan) → findings naming the matched symbol and its family (CRT/STL); competing claims resolve to the strongest; identical normalized bodies (linker folding, COMDAT/ICF) and bare tail-call thunks inherit a match — thunks pay one confidence penalty per chain, not per hop; `--signatures <file>` replaces the built-in set wholesale under the pattern-database contract | `KNOWN LIBRARY FUNCTIONS` (module-context: joins the matched **callees**, never the target) and keeps the matched functions out of the queue as `Skip` at the 80 confidence floor |
| Error-handling idioms | `calxgloss-errhandling` | Per-function readings over the bodies the scan keeps — no extra engine reads: a body spelling a whole `try {` … `catch(...){` SEH frame → one finding quoting the `catch` clause line, at the strongest body-text band 80, suggesting an exception-mapped Rust error type over the straight-line logic that would drop the frame; a named personality-handler thunk (`__except_handler3`/`__except_handler4`) → band 70; an exception-API call (`SetUnhandledExceptionFilter`, `AddVectoredExceptionHandler(Ex)`, `SetWindowLongPtrA(GWLP_EXCEPTIONHANDLER)`) → band 60; a direct `RaiseException` site → its own finding, naming the raised exception code when the source spells one; a goto-cleanup ladder — two or more guarded forward gotos converging on one label block that releases a resource (`free`/`CloseHandle`/… vocabulary, builder-extensible) or returns a bare constant → one finding naming the join block by its printed label, at band 55 (release) or 45 (constant return), the release line as evidence, never outranking a spelled frame; a spelled frame beside a named handler or API call stays one finding — the strongest SEH family wins; failure codes of HRESULT (`0x8…`) or NTSTATUS (`0xC…`) shape landing in returns, guard comparisons, or `RaiseException` arguments → one record per distinct code per function naming the code, its site kind, and the band 74 (returned) / 72 (raised) / 64 (compared), strongest site winning the one record; BOOL-shaped `0`/`1` returns, small-integer comparisons, and out-of-band values like the C++ eh code `0xE06D7363` claim nothing — codes ride the same document under their own kind tag, and a callee's failure codes travel one hop onto the caller's record at a confidence penalty (inherited codes) | `ERROR HANDLING` (module-context and escalate) |
| Call graph | `calxgloss-callgraph` (+ `calxgloss-analysis` orchestration) | Full-program call graph with Root/Leaf/Middle classification (VB6/.NET/MinGW/MSVC runtime roots, third-party-API leaves); `ContextEnricher` prompt context; `TranslationOrderer` priority plans | call-graph context in every tiered prompt |
| Binary-version pairing | `calxgloss-bdiff` | Pairs two versions of one binary through a confidence ladder, over the scan documents only — no engine read: exported or demangled names matching exactly pair at 95 (`name_identity`); byte-equal *normalized* bodies (libmatch's normalization, shared rule) pair at 90 and a non-equal body scores on its line-diff ratio between the 60 floor and 90 (`normalized_body`, diff evidence quoted); renamed bodies that moved pair when at least two distinct paired neighbors agree in the same direction (`call_topology`, 70, iterating to a fixed point), and a body pair the topology corroborates gets +5, never past 95. Pairs resolve one-to-one, best score wins, ties keep scan order | not rendered — the pairing document drives **carry-over seeding** (§3.2.1) instead of a prompt section |

**Where the findings enter the prompts:**

- **Initial translation:** the `ModuleContext` and `FullModule` context tiers
  read the **typesdb** and **controlflow** documents (plus call-graph context,
  neighboring bodies, and — at FullModule — shim-layer code and PAL traits).
  The `ModuleContext` tier also gains `GLOBAL STATE`, `FLOAT/SIMD`,
  `ERROR HANDLING`, `PARAMETER DIRECTIONS` (typeinfer), `DATA TABLES`
  (consts), and `KNOWN LIBRARY FUNCTIONS` (libmatch matches joined against the
  target's **callees**, never the target itself — the section is omitted when
  a function has no matched callees).
- **Escalate retry:** the escalate prompt pulls the fourteen scan
  methodologies' findings for the target function — data structures,
  inferred types, algorithms, memory, concurrency, global state, callbacks,
  control flow, strings, APIs, constants, serialization, float/SIMD, error
  handling — joined from the persisted documents by `retry/helpers::extract_*`
  (each keeps only the records whose evidence lives in this function's body,
  vtable, xrefs, or call path; the escalate path's module-context prompt also
  rides the libmatch loader).
- **Queue shaping:** libmatch marks best-match-at-or-above-80 functions
  `Skip` in the call graph's classification pass, so statically linked
  `memcpy` bodies never enter the translation queue at all.

**Manual entry points** — every methodology is also a CLI command running the
same engine against a target binary loaded in-process:

```text
calxgloss typesdb     --binary eqmain.dll [--show] [--no-tag]
calxgloss typeinfer   --binary eqmain.dll [--show] [--write-back] [--confidence-floor 70]
calxgloss algorithm   --binary eqmain.dll [--show] [--patterns my-patterns.json]
calxgloss memory      --binary eqmain.dll [--show]
calxgloss sync        --binary eqmain.dll [--show]
calxgloss globalstate --binary eqmain.dll [--show]
calxgloss consts      --binary eqmain.dll [--show]
calxgloss callback    --binary eqmain.dll [--show]
calxgloss controlflow --binary eqmain.dll [--show]
calxgloss stringctx   --binary eqmain.dll [--show]
calxgloss apidetect   --binary eqmain.dll [--show]
calxgloss serialize   --binary eqmain.dll [--show]
calxgloss errhandling --binary eqmain.dll [--show]
calxgloss floatsimd   --binary eqmain.dll [--show]
calxgloss libmatch    --binary eqmain.dll [--show] [--signatures my-signatures.json]
calxgloss bdiff       --binary eqmain.dll    ← report the version pairing; pure
                          report, no scan, no engine read, no write-back
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
| `BinaryPauseChanged { binary, paused }` | A per-binary pause/resume/start press changes the paused set; fans out to every WS client so all dashboards show the same pause state |
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
│   │   ├── globalstate/{binary}.json← which globals each function reads/writes
│   │   ├── errhandling/{binary}.json← SEH frames, goto ladders, failure codes
│   │   ├── floatsimd/{binary}.json  ← float/vector/SIMD usage flags
│   │   ├── libmatch/{binary}.json   ← statically linked CRT/STL matches
│   │   ├── bdiff/                   ← binary-version pairing documents,
│   │   │   └── {binary}-{old-sha256}-{new-sha256}.json
│   │   │        ←   keyed by the hash triple; the document names both
│   │   │            hashes so a stale pairing is detectable, never trusted
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
| POST | `/api/pipeline/binaries/{binary}/focus` | Park a binary in the scope record's single focus slot — the running worklist hoists it to the front at the next unit boundary and consumes the slot (live router only, issue #284) |
| POST | `/api/pipeline/binaries/{binary}/start` | One press composes the swap: pause the in-flight binary, resume and focus the pressed one at the front of the queue plan (live router only, issue #285) |
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

Each unit in the review dashboard has one of these statuses (`ReviewStatus`):

| Status | Meaning |
|--------|---------|
| `Queued` | Queued, waiting to be processed |
| `PendingReview` | Translation complete, awaiting human review |
| `InProgress` | A human is currently reviewing this unit |
| `Accepted` | Branch merged into main |
| `SendBack` | Sent back to the LLM with reviewer comments |
| `PatchRequested` | A patch was requested for a specific issue |
| `Blocked` | Waiting on a dependency not in a passing state |
| `Skipped` | Reviewer explicitly skipped the unit — out of the active queue, still visible, unskippable back in; a reviewer decision, not a pipeline verdict |
| `DoNotTranslate` | The unit's binary was classified `DoNotTranslate` (a .NET managed assembly, issue #235) — a pipeline verdict derived from the classification record: cannot be unskipped, never overwritten by the blocking cascade, sorts last |

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
1. LLM gets the original prompt + the **full evidence base**: all fourteen
   methodology documents filtered to this function — data structures,
   inferred types, recognized algorithms, memory lifecycles, concurrency,
   global state, callbacks, control-flow patterns, string context, API
   identifications, constants, serialization findings, float/SIMD shapes,
   error-handling idioms and failure codes — plus call-graph neighbors,
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
│     │         │     ├──► run_prebatch_scans — the 15 registered scan rows
│     │         │     │     (typesdb, typeinfer, algorithm, memory,
│     │         │     │      sync, globalstate, callback, controlflow,
│     │         │     │      stringctx, apidetect, consts, serialize,
│     │         │     │      errhandling, floatsimd, libmatch)
│     │         │     │     each: cached JSON → skip; else scan
│     │         │     │     (heartbeat → BatchProgress) → save
│     │         │     └──► pair_previous_versions — pair the fresh scan
│     │         │           with any surviving scan of an earlier version
│     │         │           (documents only, zero engine reads) →
│     │         │           re/analysis/bdiff/{bin}-{old}-{new}.json
│     │         │
│     │         └──► For each function:
│     │               │
│     │               ├──► TranslationPipeline::translate()
│     │               │     └─ Steps: fetch → tag → testgen → tier
│     │               │        → call-graph enrichment → findings
│     │               │        → carry-over seed check (paired accepted
│     │               │           twin ≥80 → seeded attempt, no LLM)
│     │               │        → prompt → LLM
│     │               │     └─ Returns Translation { rust_code, ... }
│     │               │
│     │               ├──► retry::try_translate_with_retry()
│     │               │     └─ Verifier → compile → test → retry loop
│     │               │     └─ escalate pulls all 14 findings
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
4. **Evidence base** → the fourteen methodology documents (recovered once per binary, cached under `re/analysis/`) supply per-function context: types, inferred types, algorithms, memory, concurrency, global state, callbacks, control flow, strings, APIs, constants, serialization, error handling, float/SIMD — with libmatch matches naming the *callees* and the `re/analysis/bdiff/` pairing documents able to seed a first attempt instead of asking the LLM cold
5. **LLM** → prompt sized by context tier, findings injected where they apply → Rust code (with token usage tracking)
6. **Verifier** → sandboxed `cargo check` + `cargo run` against baseline
7. **Git** → branch → commit → merge to main (on success)
8. **Events** → broadcast → WebSocket → live dashboard UI
