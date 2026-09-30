# Data Flow & Workflow — `calxgloss-cli live`

## 1. Top-Level Architecture

`calxgloss live` spawns **two concurrent tasks** in a single process:

```
┌─────────────────────────────────────────────────────────────┐
│                        calxgloss live                       │
│                                                             │
│  ┌──────────────────────┐    ┌──────────────────────────┐   │
│  │  Auto Pipeline       │    │  Web Review UI           │   │
│  │ (foreground / blocks)│    │  (background task)       │   │
│  │                      │    │                          │   │
│  │  handle_auto()       │    │  handle_serve()          │   │
│  │    │                 │    │    │                     │   │
│  │    ├─ handle_classify│    │    ├─ axum HTTP server   │   │
│  │    └─ run_translation│    │    ├─ REST API           │   │
│  │      _for_dll()×N    │    │    └─ WebSocket events   │   │
│  └──────────────────────┘    └──────────────────────────┘   │
│         │                              │                    │
│         └──────────┬───────────────────┘                    │
│                    │                                        │
│              TranslationEvents                              │
│              (broadcast channel, cap 256)                   │
│                    │                                        │
│         ProgressState (in-memory live tracker)              │
└─────────────────────────────────────────────────────────────┘
```

**Lifecycle:** The server starts first and waits for connections. The auto pipeline then runs to completion (classification + batch translation). On `Ctrl+C` both tasks abort together.

---

## 2. Configuration Resolution

Before any work starts, three layers of configuration are merged (most specific first):

| Layer | Source | Override priority |
|-------|--------|-------------------|
| **Flags** | CLI args (`--ghidra-url`, `--llm-url`, etc.) | Highest |
| **Environment** | `CALXGLOSS_GHIDRA_URL`, `CALXGLOSS_LLM_URL`, etc. | Middle |
| **File** | `./calxgloss.toml` or `~/.config/calxgloss/config.toml` | Lowest |
| **Defaults** | Built-in (e.g. GhidraMCP at `http://127.0.0.1:8080`) | Lowest |

All LLM keys are loaded but never printed — `calxgloss config` shows `<set>` for secrets.

The repo directory for `live` is always **CWD** (config/env overrides are ignored because the workspace where `.git`, `src/`, and `scratch/` live is always the current directory).

---

## 3. Step-by-Step Data Flow

### 3.1 Phase 1 — DLL Scanning & Classification

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
DLLs (from scan) ──► Analyzer.classify_dlls()
                                │
                    ┌───────────┴───────────┐
                    │                       │
              GhidraClient              PE Parser
              (list_functions)          (fallback)
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
              ┌─────┴─────┐
              │ Emit to   │
              │ Progress  │
              │ Channel   │
              │           │
              │ ClassificationComplete {
              │   dll, category, strategy,
              │   crate_replacement,
              │   exported_symbols,
              │   imported_symbols
              │ }
              └───────────┘
```

Classification records are written to **`re/classify/{dll_name}.json`** on disk and committed to `main`. They determine which DLLs are ready for translation and inform dependency checking (shim layers must exist before translating functions from shim-layer DLLs).

---

### 3.2 Phase 2 — Batch Translation Per DLL

For each classified DLL, `run_translation_for_dll()` runs the full pipeline:

```
run_translation_for_dll(dll, output_dir, settings, events)
│
├──► GhidraClient.list_functions()
│    └─ Returns FunctionSummary[] (name only — Ghidra serves
│       one open program at a time)
│
├──► TranslationPipeline::new(ghidra, llm, api_mappings)
│    └─ Also creates: TestGenerator, Analyzer
│
├──► GitManager::init_repo(output_dir)
│    └─ Creates .git, README, initial "main" commit
│
├──► Verifier::new(output_dir)
│    └─ Creates scratch/ directory for sandboxed builds
│
└──► pipeline.batch_translate(dll, functions, retry_config, verifier)
```

#### 3.2.1 Translation Pipeline — One Function

Each function in the DLL goes through the full pipeline **sequentially**:

```
pipeline.translate(dll, function)
│
│  Step 1: Fetch Function Metadata from GhidraMCP
│  ─────────────────────────────────────────────
│  GhidraClient.search_functions(function)
│    └─ Exact match lookup
│  GhidraClient.function_report(address)
│    └─ Returns FunctionInfo {
│        name, address, disassembly, decompiler_output,
│        callers[], callees[]    ← from xrefs + decompiler
│      }
│
│  Step 2: Tag Windows APIs
│  ───────────────────────
│  GhidraClient.imports()           ← import names from Ghidra
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
│  Step 4: Detect Complexity
│  ────────────────────────
│  Analyzer.detect_complexity(disassembly, windows_apis)
│    └─ Simple / Moderate / Complex
│
│  Step 5: Build Prompt & Send to LLM
│  ─────────────────────────────────
│  ComplexityPromptData::from_request(request)
│  build_complexity_prompt(complexity, data)
│    └─ Minimal / Rich / Detailed template selected
│    └─ Includes: disassembly, decompiler output,
│                Windows API mappings, baseline test inputs
│
│  LlmClient.complete([user_message: prompt])
│    └─ OpenAI-compatible HTTP POST
│    └─ Keepalive events every 30s while in flight
│    └─ Returns LlmResponse { content, tokens_used }
│
│  ──► Translation { dll, function, rust_code, prompt_used,
│                    model, tokens_used, baseline_tests, call_graph }
```

#### 3.2.2 Verification Loop

After the initial translation, the `retry` loop runs:

```
retry::try_translate_with_retry(initial_translation, context)
│
├──► Verifier.verify(dll, function, rust_code, baseline_tests)
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
│  escalate ──► add more context (call graph,
│       │         related functions, caller info)
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

---

### 3.3 Phase 3 — Git Operations Per Function

After a function translation succeeds (at any attempt), git operations follow:

```
for each successful function:
│
├──► Write translated.rs to disk
│     └─ output_dir/src/modules/{function}/translated.rs
│
├──► GitManager.create_branch(dll, function, attempt, policy)
│     └─ Branch name: re/{dll}/{function}v{N}
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

## 4. Progress Events — The Live Data Stream

A `TranslationEvents` broadcast channel (capacity 256) carries progress events from the pipeline to the web UI. Every major milestone emits one:

| Event | When Emitted |
|-------|-------------|
| `TranslationStarted { dll, function }` | Before Ghidra fetch |
| `GhidraFetchComplete { dll, function, address, disassembly_lines }` | After function metadata loaded |
| `ApiTaggingComplete { dll, function, tagged_apis }` | After Windows API tagging |
| `TestsGenerated { dll, function, test_count }` | After baseline test generation |
| `LlmCallStart { dll, function, attempt, strategy }` | Before LLM request |
| `LlmRequest { dll, function, attempt, strategy, prompt }` | Full prompt sent |
| `LlmCallInProgress { dll, function, attempt, strategy, elapsed_secs }` | Keepalive every 30s |
| `LlmCallComplete { dll, function, attempt, code_length, tokens_used }` | LLM response received |
| `LlmResponse { dll, function, attempt, strategy, content, tokens_used }` | Full response body |
| `LlmCallFailed { dll, function, attempt, strategy, error }` | HTTP/network failure |
| `TranslationAttemptCompleted { dll, function, attempt, success, compiled, tests_passed, tests_total, compilation_errors[], failed_tests[], strategy }` | After verify step |
| `TranslationCompleted { dll, function, total_attempts, success_strategy }` | Success after retry loop |
| `TranslationFailed { dll, function, total_attempts }` | All retries exhausted |
| `ClassificationComplete { dll, category, strategy, crate_replacement, exported_symbols, imported_symbols }` | After DLL classification |
| `BatchSummary { dll, total_functions, success_count, failure_count, total_attempts, total_tokens }` | After all functions in DLL |

### Event Flow

```
TranslationPipeline
       │
       │ emit(ProgressEvent::TranslationStarted{...})
       │ emit(ProgressEvent::GhidraFetchComplete{...})
       │ emit(ProgressEvent::ApiTaggingComplete{...})
       │ emit(ProgressEvent::TestsGenerated{...})
       │ emit(ProgressEvent::LlmCallStart{...})
       │ emit(ProgressEvent::LlmRequest{...})
       │ (keepalive every 30s via LlmCallInProgress)
       │ emit(ProgressEvent::LlmCallComplete{...})
       │ emit(ProgressEvent::TranslationAttemptCompleted{...})
       │
       └──────────► broadcast::Sender
                      │
                ┌─────┴─────┐
                │           │
          handle_live     WebSocket
          keeps original  server subscribes
          for retry loop  via SessionManager
                            │
                     ┌──────┴──────┐
                     │             │
              ProgressState      WS Clients
              (in-memory)        (browser)
              updates live        receives JSON
              dashboard state     events every 30s
```

The `ProgressState` in the web server maps `"dll/function"` keys to `ProgressEntry` objects with status (`Translating`, `LlmCall`, `Compiling`, `Testing`, `Complete`) for real-time dashboard overlay.

---

## 5. File System Layout

```
<repo_dir>/                          ← CWD (or --repo)
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

## 6. Web Review UI

### 6.1 Endpoints

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/` | Dashboard frontend (HTML/JS/CSS) |
| GET | `/api/dashboard` | Full review dashboard JSON (git branches, statuses) |
| GET | `/api/units/{id}` | Single unit detail (justification, diff, tests, history) |
| GET | `/api/units/{id}/diff` | Git diff between branch and main |
| POST | `/api/units/{id}/accept` | Merge branch into main + write acceptance record |
| POST | `/api/units/{id}/send-back` | Record rejection reason |
| POST | `/api/units/{id}/patch` | Request retry translation |
| GET | `/api/queue` | Review queue, dependency-ordered |
| GET | `/api/queue/next` | Next unit to review |
| GET | `/api/graph` | Dependency graph data |
| GET | `/api/progress` | Live translation progress (in-memory state) |
| GET | `/api/events/upgrade` | WebSocket upgrade for real-time events |
| GET | `/health` | Health check |

### 6.2 Review Actions

The web UI can act on translation units:

- **Accept** — merges the `re/{dll}/{function}v{N}` branch into `main`, writes `re/accepts/{dll}/{function}/v{N}.json` with timestamp
- **Reject/Send-Back** — writes `re/rejections/{dll}/{function}/v{N}.json` with reason (branch is NOT deleted)
- **Request Patch** — queues a retry (increments version, creates new branch)

### 6.3 Dashboard States

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

## 7. Retry Strategies in Detail

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
1. LLM gets the original prompt + call graph context
2. Additional context from callers/callees is added
3. Full re-translation with richer context

### `edge_case_fix`
1. LLM gets the original prompt + identified edge case patterns
2. Focus on boundary values, null pointers, overflow conditions
3. Verified again

### `auto` (cycling)
Starts at `compile_fix` and cycles through all strategies on each failure:
`compile_fix` → `test_fix` → `escalate` → `edge_case_fix` → `compile_fix` → ...

---

## 8. Summary: Complete `live` Sequence

```
calxgloss live --port 3000
│
├──► [Background] WebSocket server starts on 0.0.0.0:3000
│     └─ Listens for browser connections
│     └─ Broadcasts ProgressEvents to all WS clients
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
│     ├──► handle_classify() [unclassified DLLs only]
│     │     └─ Ghidra → PE parse → classification
│     │     └─ Write re/classify/{dll}.json
│     │     └─ Commit to main
│     │     └─ Emit ClassificationComplete event
│     │
│     ├──► For each classified DLL:
│     │   │
│     │   └──► run_translation_for_dll(dll)
│     │         │
│     │         ├──► GhidraClient.list_functions()
│     │         │     └─ ["DrawPrimitive", "DrawSprite", ...]
│     │         │
│     │         └──► For each function:
│     │               │
│     │               ├──► TranslationPipeline::translate()
│     │               │     └─ Steps: fetch → tag → testgen → prompt → LLM
│     │               │     └─ Returns Translation { rust_code, ... }
│     │               │
│     │               ├──► retry::try_translate_with_retry()
│     │               │     └─ Verifier → compile → test → retry loop
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
└──► Auto pipeline done
     └──► abort serve task
     └──► Exit
```

**Total data flow per function:**
1. **GhidraMCP** → disassembly, decompiler pseudo-C, call graph, imports
2. **PAL mappings** → Windows API tags attached to disassembly tokens
3. **Baseline tests** → 10-20+ test cases with input patterns (no expected output yet)
4. **LLM** → prompt with all context → Rust code (with token usage tracking)
5. **Verifier** → sandboxed `cargo check` + `cargo run` against baseline
6. **Git** → branch → commit → merge to main (on success)
7. **Events** → broadcast → WebSocket → live dashboard UI
