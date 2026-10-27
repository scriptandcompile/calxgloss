# Calxgloss, in Literate Form

*A walking tour of the source code, in the order the ideas need to be read
rather than the order they live in files. Each section states what a piece of
the system must do, then shows the code that does it, with exact `file:line`
references so you can open the span and edit it.*

---

## 0. How to read this document

Calxgloss is a Cargo workspace of thirty-four crates in five contexts:

```
crates/
├── calxgloss/          the meta-lib (one file of re-exports)
├── shared/             calxgloss-types, calxgloss-config
├── integrations/       calxgloss-decomp, -kuna, -llm, -pal, -prompts,
│                       -testfixtures
├── evidence/           18 crates: 15 methodology scan engines, bdiff,
│                       callgraph, analysis
├── pipeline/           calxgloss-translator, -verify, -testgen, -git
└── interface/          calxgloss-cli, -web, -reports
```

The tour proceeds bottom-up. Chapter 1 gives the shared records every
crate exchanges. Chapters 2–3 give the parts that observe the target
binary. Chapters 4–6 give the act of translation and the verification that
follows it. Chapter 7 gives the memory that makes the work reversible.
Chapters 8–9 give scale-out and the operator's seat. Chapters 10–11 give
the telemetry that lets the whole system be audited.

Code excerpts are verbatim from the current source, and line numbers refer
to the files as they exist now. Where a quote leaves part of a span out,
the gap is marked `…`.

---

## 1. Shared records: `calxgloss-types`

Everything the harness does is a flow of serializable values between
crates, and the crates never call each other directly. That vocabulary
lives in `crates/shared/calxgloss-types`, re-exported flat at the crate
root (`src/lib.rs:L56-L146`) so consumers write `calxgloss_types::FunctionInfo`.
The crate deliberately contains **no analysis logic and no service calls**:
the analysis engine, the local LLM, and the test runners live in other
crates, and those crates only exchange these records.

### 1.1 A DLL's category is the strategy switch

Before a single function is translated, the system classifies each DLL.
The classification *is* the handling strategy:

```rust
// crates/shared/calxgloss-types/src/dll.rs:L16-L50
pub enum DllCategory {
    /// Core Windows OS DLLs (`kernel32.dll`, `user32.dll`, etc.).
    /// Strategy: PAL mapping to std / winit / etc.
    WindowsOs,

    /// Official Microsoft SDK DLLs with known Rust crate equivalents.
    /// Strategy: crate replacement + shim layer.
    MicrosoftSdk,

    /// Known third-party libraries with existing Rust crate counterparts.
    /// Strategy: crate replacement + shim layer.
    KnownThirdParty,

    /// DLLs built from this project's own source code.
    /// Strategy: reverse engineer from disassembly.
    ProjectSpecific,

    /// Third-party DLLs with no known Rust crate equivalent.
    /// Strategy: reverse engineer from disassembly.
    UnknownThirdParty,

    /// Runtime library DLLs (e.g. `msvcr*.dll`, `msvbvm60.dll`, `Qt5*.dll`,
    /// `SDL2.dll`). These are not target binaries — their functions should be
    /// skipped during translation.
    RuntimeLibrary,

    /// .NET (managed) assemblies — PE files carrying a COM descriptor
    /// (data directory 14). They are not native machine code, so the
    /// disassembly pipeline has nothing to translate; we do not yet
    /// decompile managed code. Strategy: `DoNotTranslate` (issue #235).
    /// Distinct from [`Self::RuntimeLibrary`]: the `known_runtime` flag
    /// stays false for managed assemblies — it names runtime libraries,
    /// not every binary that is out of translation scope.
    DotNetManaged,
}
```

One enum, four strategies: *map the API* (WindowsOs → PAL), *replace the
crate* (Sdk/ThirdParty → shim layer), *reverse engineer function by
function* (ProjectSpecific/Unknown), or *park the binary* (DotNetManaged →
Do Not Translate, see ADR-0044). `RuntimeLibrary` is a veto: its functions
are skipped during translation. Every statistic, fault log, and shim
suggestion is grouped by category, so a wrong classification silently
distorts every downstream report. This is the single most consequential
decision the system makes.

### 1.2 What a function *is*, before it is translated

The analysis engine produces one record per function. That record is the
pipeline's primary input:

```rust
// crates/shared/calxgloss-types/src/function.rs:L135-L162
pub struct FunctionInfo {
    pub name: String,
    pub address: u64,
    pub binary: BinaryIdentity,
    /// Raw disassembly listing from the decompiler.
    pub disassembly: String,
    /// Pseudo-C decompiler output.
    pub decompiler_output: String,
    /// Windows API calls identified within this function, with their PAL mappings.
    pub windows_apis: Vec<WindowsApiCall>,
    /// Names of functions called by (or calling) this function.
    pub call_graph: Vec<String>,
    /// Patterns discovered in the disassembly (e.g., `"zero_check"`,
    /// `"null_check"`, `"overflow"`). Used for edge-case test generation
    /// and behavior-divergence detection.
    #[serde(default)]
    pub disassembly_hints: Vec<String>,
}
```

One assumption is built into the type: *the analysis engine has already
run*. These records never call the analysis engine. Consumers must treat
the text as opaque, and possibly stale. Each tagged API call names its
translation target alongside it:

```rust
// crates/shared/calxgloss-types/src/function.rs:L99-L108
pub struct WindowsApiCall {
    pub name: String,          // e.g. `CreateFileA`
    pub category: ApiCategory, // e.g. Win32Core
    pub pal_mapping: String,   // e.g. `std::fs::File::open`
}
```

And each call-graph neighbor is labeled with an *instruction*, not an
observation:

```rust
// crates/shared/calxgloss-types/src/function.rs:L120-L129
pub enum NodeCategory {
    Root,   // entry point or runtime init — skip or stub
    Leaf,   // calls known 3rd-party APIs — enriched context
    Middle, // application logic — normal translation
    Skip,   // known runtime library function — don't translate
}
```

### 1.3 The behavioral contract: `TestCase`

The project's core principle is *functional equivalence over binary
precision*. That contract is a data type:

```rust
// crates/shared/calxgloss-types/src/test.rs:L96-L106
pub struct TestCase {
    /// The test inputs as a JSON value. Parameters are serialized according to
    /// their types (integers, strings, booleans, or null for pointers).
    pub inputs: serde_json::Value,

    /// The expected return value from the original function, as JSON.
    pub expected_return: serde_json::Value,

    /// Expected side effects the function produces when called with these inputs.
    pub expected_side_effects: Vec<SideEffect>,
}
```

Using JSON on both sides is a deliberate choice: the same shape goes to
the CLI, the dashboard, the generated Wine harness, and remote services
without custom serialization. A side effect is a typed `SideEffectKind`
plus a free-form `detail: String`, with an `Other(String)` fallback. The
effects the model covers are listed; the ones it does not cover are still
recorded.

### 1.4 The prompt is sized to the function: `ContextTier`

```rust
// crates/shared/calxgloss-types/src/context_tier.rs:L57-L68
pub enum ContextTier {
    Signature,     // Tier 0 — name and signature only.
    Disassembly,   // Tier 1 — disassembly + decompiler + type info.
    WithTests,     // Tier 2 — Tier 1 + baseline tests.
    ModuleContext, // Tier 3 — Tier 2 + module context (neighbors, data structures).
    FullModule,    // Tier 4 — Tier 3 + shim layer + PAL traits.
}
```

The tier is chosen automatically from complexity, API count, and historical
success rate (`select_context_tier` at `context_tier.rs:L223`). The choice
is emitted as a progress event and recorded in every token-usage entry, so
cost and pass rate can be traced back to the tier that produced them.
`ContextTier::ALL` (`context_tier.rs:L76`) is the one list the dashboard
takes its tier controls from; the frontend never hardcodes variant names.

### 1.5 The identity triple: `(dll, function, attempt)`

Every unit of work is named by a triple, spelled identically everywhere:
in the git branch name, and in every token-usage entry, fault event, and
progress event:

```rust
// crates/shared/calxgloss-types/src/git.rs:L70-L89
pub fn new(
    binary: impl Into<BinaryIdentity>,
    function: &str,
    attempt: u32,
) -> Result<Self, TypesError> {
    let binary = binary.into();
    if binary.is_empty() {
        return Err(TypesError::EmptyBinaryName);
    }
    if function.is_empty() {
        return Err(TypesError::EmptyFunctionName);
    }
    let branch_name = format!("re/{binary}/{function}v{attempt}");
    Ok(GitBranch { name: branch_name, binary, function: function.to_string(), attempt })
}
```

`re/game_logic.dll/DrawSpritev1`. To line up a failed run — the branch diff,
the tokens spent, and the fault that ended it — all three fields must match
across every artifact. That one `format!` is the join key for the whole
harness.

---

## 2. Reading the target binary: the analysis engine and the PAL

### 2.1 `KunaSource` — the program, loaded in-process

The analysis engine is Kuna — a Rust port of Ghidra's decompiler — loaded
in-process, inside the harness process, from the target binary (ADR-0041,
replacing ADR-0001's HTTP bridge and ADR-0007's JVM lifecycle; issue #214
retired those completely). The seam crate keeps the names the pipeline was
written against: the `ScanSource`/`TypeWriteSource` traits, the answer
shapes, and the scan read cache. Every read is a command sent to the
analysis-engine thread; name lookups resolve inside the analysis engine:

```rust
// crates/integrations/calxgloss-kuna/src/source.rs:L548-L569
pub async fn decompile_function(&self, name: &str) -> Result<KunaDecompiled> {
    let (reply, answer) = oneshot::channel();
    self.send(Command::Decompile {
        name: name.to_string(),
        reply,
    })?;
    let outcome = answer.await.map_err(|_| KunaError::EngineUnavailable)?;
    // The round trip completed — one work item of any armed pass done,
    // whether or not the engine answered with a body: a function that
    // tripped a budget or refused still consumed its slot, so the
    // pass's progress must move (issue #211).
    self.tick(name);
    // Engine-call accounting (issue #240): one entry per completed
    // round trip, same rule as the tick — a function that tripped a
    // budget still paid the engine and still shows in the log.
    self.inner
        .decompile_calls
        .lock()
        .expect("decompile accounting lock")
        .push(name.to_string());
    outcome
}
```

One detail matters: a long scan can look like a hang on the web dashboard,
because a full decompile pass over a DLL can take minutes. So the source
sends a *heartbeat* into the progress-event channel — `begin_pass`/`end_pass`
plus a `tick` for each decompile (`source.rs:L462-L532`) — and the UI can
show *which function* the analysis engine is working on. Since issue #240
the source also keeps its own ledger of every completed decompile round
trip, in call order. Kuna is the scan phase's one serial resource, and the
scan read cache's per-key cell means one function body costs at most one
analysis-engine request per key. So the ledger records what the analysis
engine was actually asked to do.

### 2.2 The PAL — a static Windows-API → Rust mapping table

The Platform Abstraction Layer (PAL) is not runtime code. It is a lookup
table, fixed at compile time, that is inserted into prompts:

```rust
// crates/integrations/calxgloss-pal/src/types.rs:L19-L31
pub struct ApiMapping {
    pub windows_api: &'static str,     // `CreateFileA`, `Direct3DCreate9`
    pub category: ApiCategory,
    pub rust_equivalent: &'static str, // `std::fs::File::open`, `wgpu::Instance [PAL placeholder]`
    pub notes: &'static str,           // "PAL placeholder — not yet implemented"
}
```

`ApiMappings` wraps a `&'static [ApiMapping]` (`types.rs:L75`), so it is
`Send + Sync` automatically and can be shared across the whole pipeline.
When a function's tagged APIs fall in a category, the prompt builder puts
the full mapping-table rows for that category into the prompt
(`for_categories`, `types.rs:L163-L188`) — the LLM is never asked to guess
what `CreateFileA` should become.

---

## 3. Ground truth: capturing behavior from the *original* binary

Tests must record what the original function actually does. The obvious
approach — generate an `extern "C"` block and link against the DLL — fails
for the functions that matter. The clearest statement of this problem in
the codebase is the module header of
`crates/pipeline/calxgloss-testgen/src/wine.rs:L1-L45`. Its opening
sections, verbatim:

```rust
//! Cross-compile and run a Windows harness under Wine to capture a ground-truth
//! baseline from an original DLL.
//!
//! # Why this is not a link-time FFI
//!
//! The obvious way to call an original function is to generate an
//! `extern "C"` block and link against the DLL. That only works for *exported*
//! symbols. The interesting functions in a real binary are internal: the decompiler
//! names them `FUN_18008ed50` and they appear in no export table. Reaching them
//! means loading the module at runtime and calling `module_base + rva`, which is
//! what this module generates.
//!
//! # Address arithmetic
//!
//! The decompiler reports addresses at the image's preferred base, so the RVA is
//! `va - image_base` (see [`crate::PeImage::rva_from_va`]). The image is
//! normally *not* loaded at its preferred base — ASLR and Wine's allocator pick
//! the address — so the runtime call target is `actual_base + rva`.
```

Two load modes exist, because Delphi binaries need runtime state that a
bare mapping does not provide: `NoResolve` (map without `DllMain`) and
`Full` (run `DllMain`, resolve imports). The generated harness has **zero
dependencies**, and a test asserts it
(`calxgloss-testgen/tests/baseline.rs:L354-L371`), so cross-compiling it
never touches a registry. Test cases cross the process boundary as
`<tag>:<value>` lines on stdin. Results come back as
`<index>\t<ok|err>\t<value>` on stdout. And because a faulting function
kills the harness process, a batch that dies mid-run is retried case by
case: one bad input does not discard the rest (`wine.rs:L40-L45`).

`ffi.rs` handles the signature side of this: it turns Ghidra's
`int __stdcall FUN_…(int a,
LPCSTR b)` into a callable Rust binding. It holds a `TYPE_MAP` of Windows
types to Rust types with pointer depth and bit width
(`ffi.rs:L101-L141`), `parse_signature` (`ffi.rs:L154`), and
`generate_ffi_binding` (`ffi.rs:L229`).

---

## 4. The act of translation: `TranslationPipeline::translate`

The heart is one function:
`crates/pipeline/calxgloss-translator/src/pipeline.rs:L827-L1238`. The
pipeline itself is a struct of clients and optional controls
(`pipeline.rs:L197-L367`). It is **never built by hand**: the constructor
and its `with_*` setter methods are assembly-internal. Every pass comes
into existence through the assembly seam: `assemble` builds a
`PipelineSpec` pass description (`assembly.rs:L270-L285`), and the CLI
folds its resolved settings into that description once (ADR-0050).
`translate` runs seven steps.

**Step 0 — refuse what has no logic.** Before spending a token:

```rust
// crates/pipeline/calxgloss-translator/src/pipeline.rs:L909-L916
// Root symbols — entry points and import thunks — own no logic to
// translate. … a `DelayLoad_` thunk is the classic trap: its resolved-import
// jump decompiles to an unrecovered jumptable plus a bare `return`, and
// the LLM faithfully translates the wreckage. Refuse before the
// scan fetch, before any token is spent.
self.refuse_root_function(binary, function)?;
```

The same refusal has a body-shaped twin (#269). The symbol table names some
thunks *after their own import* — `SetCursor` may hold only
`SetCursor(); return;`. No name pattern matches these, but the body is one
unconditional call to the thunk's own name, so `refuse_self_call_thunk`
(call at `pipeline.rs:L935`, the function at `L1603-L1647`) turns it away
right after the scan fetch, before a prompt is built.

**Step 1 — fetch, then triage the decompiler's own failures.** The
decompiler's analysis failures appear inside the pseudo-C as `WARNING`
comments:

```rust
// pipeline.rs:L937-L942
// Triage: Ghidra's analysis failures ride inside the pseudo-C as
// WARNING comments. Name them before the LLM sees the body — an
// unrecovered jump table otherwise becomes a plausible, hollow
// `return` in the generated Rust, with nothing marking the address
// that needs human recovery.
self.triage_decompiler_warnings(binary, function, &function_info.decompiler_output);
```

**Steps 2–3 — tag APIs, generate baseline tests.** Imports are fetched once
per binary and intersected with the function's call sites
(`tag_windows_apis`, `pipeline.rs:L1727`). Baseline test inputs come from
the testgen crate of Chapter 3 (`generate_baseline_tests`,
`pipeline.rs:L1747`).

**Step 4 — size the prompt.** Complexity detection picks a tier, and a
reviewer override can force one:

```rust
// pipeline.rs:L1011-L1030
let auto_tier = calxgloss_types::select_context_tier(
    &complexity,
    api_call_count,
    calxgloss_types::SuccessRate::default(),
);
// W2.7: a reviewer override forces the tier — the automatic selector
// is bypassed for this unit (issue #96).
let tier = match self.forced_context_tier(binary, function) {
    Some(forced) => {
        info!(… "Reviewer override forces the context tier");
        forced
    }
    None => auto_tier,
};
```

A `match tier` (`pipeline.rs:L1158-L1245`) then builds the prompt from the
corresponding template in `calxgloss-prompts`. The tiers build on one
another: `ModuleContext` adds call-graph neighbors, neighboring function
bodies, and recovered data structures. `FullModule` also extracts
shim-layer code and PAL trait definitions from the workspace. Every tier
path adds context with the same `helpers::extract_*` functions the retry
loop uses for escalation — one set of context-extraction functions, two
callers.

**Step 4b — the carry-over seed short-circuits the LLM call.** Just before
the prompt is built, one deterministic check can end the whole generation
(issue #299; data-flow doc §3.2.1):

```rust
// pipeline.rs:L1102-L1156
// Carry-over seeding (issue #299): when a pairing document pairs
// this function confidently with a previous-version twin whose
// translation was *accepted* (a merged review branch), attempt 1
// carries that code — no prompt built, no LLM called, no tokens
// spent. … the accepted translation is a
// hypothesis the new bytes get to reject, and a rejection hands the
// unit to the fresh attempt chain like any other failed attempt.
// Nothing here marks the unit verified; the review overlay's model
// (ADR-0003) is untouched — the new branch starts unmerged.
if let Some(seed) = self.carry_over_seeds.lock()… .get(function).cloned() {
    return Ok(Translation { rust_code: seed.rust_code,
                            model: "carry-over".to_string(),
                            tokens_used: None, … });
}
```

Everything deterministic has already run: the scan fetch and refusals,
baseline tests, and tier selection. The full verification against the
*new* binary's bytes follows in the retry loop. The seed comes from
`carry_over::collect_seeds` (`carry_over.rs:L107`), which reads the bdiff
pairing document plus the review branches. The pipeline refreshes its seed
table between binaries (`refresh_carry_over_seeds`, `pipeline.rs:L2451`)
and records the accepted attempt's provenance on the review overlay
(`attach_carry_over_provenance`, `pipeline.rs:L2485`).

**Steps 5–7 — send, check, return.** The prompt goes to the LLM
(`send_to_llm`, `pipeline.rs:L2053`). An empty response is an error, not a
result. The returned `Translation` contains everything downstream stages
need: code, prompt, tier, baseline tests, and token count:

```rust
// pipeline.rs:L1315-L1329
Ok(Translation {
    binary: binary.to_string().into(),
    function: function.to_string(),
    function_address: Some(function_info.address),
    rust_code: response.content,
    prompt_used: prompt,
    model: self.llm.model().to_string(),
    tokens_used: response.tokens_used,
    baseline_tests,
    call_graph: function_info.call_graph.clone(),
    call_graph_context: enriched_context,
    disassembly_hints: function_info.disassembly_hints.clone(),
    context_tier: tier,
})
```

Notice what is *not* here: no compilation, no test execution, no git.
`translate` is pure generation. Verification is separate.

### 4.1 The LLM client is defensive about the context window

`calxgloss-llm` uses the OpenAI-compatible chat API that Ollama and vLLM
serve. Two details come from hard-won experience:

```rust
// crates/integrations/calxgloss-llm/src/client.rs:L353-L361
fn output_budget(&self, messages: &[LlmMessage]) -> usize {
    const CHARS_PER_TOKEN: usize = 3;
    let prompt_chars: usize = messages.iter().map(|m| m.content().len()).sum();
    let prompt_tokens = prompt_chars * 9 / (CHARS_PER_TOKEN * 8) + 1;
    self.config
        .context_window
        .saturating_sub(prompt_tokens)
        .max(256)
}
```

Every request caps `max_tokens` to the space left in the context window.
An uncapped request is how a local server gets OOM-killed. In `complete`
(`client.rs:L380-L451`), HTTP 429/503/507 map to the typed
`LlmError::ResourceExhausted` instead of a generic server error, because
the retry loop treats an overloaded server differently from a bad prompt
(Chapter 6). The response content comes back with markdown fences removed
(`strip_code_fences`, `client.rs:L602`): the LLM's habit of wrapping code
in rust code blocks is handled at the client boundary, not in every
consumer. The request also has a wall-clock deadline:
`LlmConfig::timeout_secs` (`client.rs:L81`, `with_timeout_secs` at `L120`)
becomes the reqwest client's `.timeout()` (`L314`), so a wedged local
server cannot block a batch forever.

---

## 5. Verification: `Verifier`

For each check, `crates/pipeline/calxgloss-verify/src/engine.rs` builds a
throwaway cargo project — the scratch project — compiles the translated
code in it, and runs the behavioral tests:

```rust
// crates/pipeline/calxgloss-verify/src/engine.rs:L136-L186 (abridged)
pub async fn verify(
    &self,
    binary: &str,
    function: &str,
    rust_code: &str,
    baseline_tests: &[TestCase],
) -> Result<VerificationResult> {
    let compile_result = self.compile(binary, function, rust_code).await?;

    if !compile_result.success {
        info!(binary, function, "Skipping tests — compilation failed");
        return Ok(VerificationResult {
            compiled: false,
            compilation_errors: compile_result.errors,
            tests_passed: 0,
            tests_total: baseline_tests.len(),
            failed_tests: Vec::new(),
        });
    }

    let project = self.scaffold_test_project(binary, function, rust_code, baseline_tests)?;
    let test_output = cargo::run_test_runner(&project)
        .await
        .unwrap_or_else(|e| format!("Test execution failed: {}", e));

    let (tests_passed, tests_total, failed_tests) =
        parse::parse_test_results(&test_output, baseline_tests);

    Ok(VerificationResult { compiled: true, compilation_errors: Vec::new(), tests_passed, tests_total, failed_tests })
}
```

Three design points:

1. **A compile failure skips the tests and returns a *result*, not an
   error.** The retry loop needs the compiler's error text as prompt
   material. If a compile failure came back as an error, the fix
   strategies would have nothing to work on.
2. **The scratch project is self-contained.** `scaffold_project` writes a
   minimal `Cargo.toml` and a PAL stub crate (`ensure_pal_crate`,
   `engine.rs:L194`), so translated code that references PAL placeholders
   still passes type checking.
3. **`parse_test_results` parses `cargo test` JSON output** into one
   `FailedTest` record per failed test — the same type the shim
   verification uses unchanged.

A parallel `verify_shim` (`engine.rs:L488`) serves the crate-replacement
strategy: it builds a project whose `Cargo.toml` includes the real
replacement crate (`shim_crate_root_for_cargo`, `engine.rs:L621`) and runs
the shim mapping tests.

---

## 6. The retry loop: `try_translate_with_retry`

One LLM call rarely produces passing code. The retry loop —
`crates/pipeline/calxgloss-translator/src/retry/retry_loop.rs:L72-L1344` —
is what makes the harness work. Its shape:

**Attempt 1** is verified as it stands (compile, run tests). If it passes,
the loop returns. Otherwise, for attempts `2..=max`, the loop alternates
between two prompt sources, and after each failure it raises both the
*retry strategy* and the *context tier* one step.

### 6.1 Retry strategies that put each failure into the next prompt

```rust
// retry_loop.rs:L698-L890 (abridged)
let (prompt, strategy_name) = match &current_strategy {
    RetryStrategy::Default => {
        // Re-send original prompt — skip (would be identical to initial)
        result.add_attempt(… "skip_default" …);
        continue;
    }
    RetryStrategy::CompileFix => {
        let fix_ctx = FixPromptCtx {
            function_name: initial_translation.function.clone(),
            dll_name: initial_translation.binary.to_string(),
            original_rust_code: initial_translation.rust_code.clone(),
            compilation_errors: initial_errors.clone(),
            failed_tests: Vec::new(),
            history: failure_history.clone(),
        };
        // Use failure-informed prompts after first retry
        let prompt = if failure_history.is_empty() {
            build_compile_fix_prompt(&fix_ctx)
        } else {
            build_failure_informed_compile_fix_prompt(&fix_ctx)
        };
        (prompt, "compile_fix".to_string())
    }
    RetryStrategy::TestFix => {
        // Run verification first to get failing tests, then build a prompt
        // that quotes "Test 3: expected 30, got 0 — assertion failed".
        …
    }
    RetryStrategy::Escalate => { /* rebuild the prompt with more decompiler/workspace context */ }
    RetryStrategy::EdgeCaseFix => { /* re-verify edge-case tests, prompt with those failures */ }
};
```

The `failure_history: Vec<FailureHint>` collects one entry per failed
attempt: attempt number, retry strategy, and a human-readable failure
description. After the first retry, every fix prompt is *failure-informed*:
the LLM sees what has already been tried and why it failed. Reviewer hints
from the web UI enter the history as attempt 0 with strategy `"reviewer"`
(`retry_loop.rs:L88-L95`), so the very first fix prompt for a steered unit
already includes what the reviewer knows.

### 6.2 The retry strategy cycles; the context tier only goes up

```rust
// retry_loop.rs:L1304-L1340 (abridged)
if ctx.config.escalate_on_failure {
    current_strategy = match current_strategy {
        RetryStrategy::CompileFix => RetryStrategy::TestFix,
        RetryStrategy::TestFix => RetryStrategy::Escalate,
        RetryStrategy::Escalate => RetryStrategy::EdgeCaseFix,
        RetryStrategy::EdgeCaseFix => RetryStrategy::CompileFix, // cycle back
        RetryStrategy::Default => RetryStrategy::CompileFix,
    };
    // W2.5: an operator `max_context_tier` constraint caps the walk —
    // escalation stops at the cap instead of going past it.
    if let Some(next_tier) = ctx.config.next_tier_within_cap(current_tier) {
        warn!(… "Context tier escalated");
        if let Some(em) = ctx.events {
            let _ = em.emit(ProgressEvent::ContextTierSelected { … });
        }
        current_tier = next_tier;
        tier_escalated = true;
    }
}
```

When `tier_escalated` is set, the next iteration takes a different branch
at the top of the loop (`retry_loop.rs:L262-L696`): it builds the prompt
from the *next* context tier — adding more neighbors, data structures, and
shim layers — instead of only sending the errors back in. The retry
strategy cycles; the context tier only ever goes up, and only within the
operator's cap.

### 6.3 The infinite-loop detector

LLMs can return byte-identical garbage to different prompts. The detector
tracks `(prompt_hash, output_hash)` pairs, and three identical bad outputs
in a row trigger it:

```rust
// retry_loop.rs:L96-L150 (abridged)
detector.record_attempt(prompt, code, success, strategy, attempt);
if let Some(signal) = detector.detect() {
    // Emit progress event … persist a fault event for post-hoc analysis …
    warn!(binary, function, streak = signal.streak,
        "Infinite loop detected — stopping retry");
    return true; // loop detected
}
```

When it fires, the detector emits a `ProgressEvent::InfiniteLoopDetected`
*and* records a `FaultEvent::infinite_loop`. The live UI and the
after-the-fact audit trail both get the same signal.

### 6.4 Every attempt is recorded

After each attempt, the loop does the following, in this order: records the
attempt in the loop detector, appends a `TranslationAttempt` to the
result, emits `TranslationAttemptCompleted`, writes a token-usage entry
with the wall-clock duration (`log_token_usage`,
`retry_loop.rs:L1247-L1262` — the dashboard's time estimates come from
these entries), adds a `FailureHint` to the failure history, and logs a
prompt-variant experiment (`log_prompt_variant_experiment`,
`retry_loop.rs:L1295` — the A/B data behind "which strategy actually
works"). Only then does the loop decide whether to break or escalate.

The public entry point combines generation with this loop
(`pipeline.rs:L1462-L1558`): it calls `translate` once, then runs
`try_translate_with_retry` around that result. (The futures are boxed at
that boundary for a compiler reason, not a design one: recursive `Send`
evaluation through the whole pipeline overflows rustc's trait recursion
limit, rust-lang/rust#159228.)

---

## 7. Memory: git as the system of record

Principle 6 — *source-control backed reversibility* — means every attempt,
pass or fail, lands as a commit on its own branch.

### 7.1 Branch creation is a dependency gate

```rust
// crates/pipeline/calxgloss-git/src/git_manager.rs:L269-L363 (abridged)
pub fn create_branch(&self, binary: &str, function: &str, attempt: u32,
                     policy: Option<&BranchCreationPolicy>) -> Result<BranchResult, TypesError> {
    let branch = GitBranch::new(binary, function, attempt)?;
    …
    match policy {
        BranchCreationPolicy::Skip => {}
        BranchCreationPolicy::Warn(_) => {
            if check_result.has_unmet() {
                warn!(binary, unmet = ?check_result.unmet,
                    "Dependencies unmet — continuing anyway (Warn policy)");
            }
        }
        BranchCreationPolicy::Enforce(_) => {
            if check_result.has_unmet() {
                return Err(TypesError::InvalidBranchName(format!(
                    "Cannot create branch '{}': unmet dependencies: {}. Merge these branches into main first.",
                    branch.name, check_result.unmet.join(", "))));
            }
        }
    }
    // branch is created from main, then checked out
    …
}
```

The dependency check reads the call graph. If `FUN_a` calls `FUN_b`, a
branch for `FUN_a` is refused under the `Enforce` policy until `FUN_b`'s
branch has merged into main. The translation order is therefore enforced
by git's branch structure, not by convention.

### 7.2 The commit convention

From the CLI's translate command
(`crates/interface/calxgloss-cli/src/commands/translate.rs:L236-L247`):

```rust
let _commit = git.commit(
    branch_info,
    &format!(
        "re/translation/{}: translate {} (attempt {}, strategy: {})",
        function, binary, attempt.attempt, attempt.strategy
    ),
    &[&output_path_str],
)?;
```

Every commit message records the unit, the attempt number, and the retry
strategy that produced the attempt. Failed branches are kept: they are the
historical record of what did not work, and they can be diffed against the
branch that did.

### 7.3 Acceptance is a merge, with a race guard

The web UI's accept button runs `accept_unit`
(`crates/interface/calxgloss-web/src/server/actions.rs:L249-L307`):

```rust
// actions.rs:L253-L283 (abridged)
let (captured, _action_guard) = state.begin_action(unit_id).await;
…
// Re-check before merging: the lock guarantees nothing lands between here
// and the persist below, so a stale capture means the unit changed
// underneath us — fail without merging or overwriting (issue #86).
check_action_conflict(state.repo_path(), unit_id, captured)?;

let merge_result = git.accept_branch(&branch)?;
let merge_hash = match &merge_result {
    calxgloss_git::MergeResult::Merged { merge_hash } => Some(merge_hash.clone()),
    calxgloss_git::MergeResult::AlreadyUpToDate => None,
    // A conflicted merge landed nothing on main — fail before persisting
    // any action state so the unit keeps its pre-accept status (issue #83).
    calxgloss_git::MergeResult::Conflicts { conflicted_files, error } =>
        return Err(anyhow::anyhow!(…)),
};
```

A per-unit async lock plus a captured-state re-check makes accept/send-back
races resolve to exactly one winner (a test proves it:
`actions.rs:L956-L1014`). The action itself is also persisted as a JSON
record under the workspace, separate from the git state. Reviewer intent
lives in overlay files and is never derived from artifacts (ADR-0003).

---

## 8. Many functions at once: call graphs and batch translation

### 8.1 The graph decides the order

`calxgloss-callgraph` builds the graph from the analysis engine's xrefs. It
classifies every node `Root`/`Leaf`/`Middle`/`Skip` (root_detector,
leaf_detector), and the orderer turns the graph into a work queue:

```rust
// crates/evidence/calxgloss-callgraph/src/ordering.rs:L104-L132 (abridged)
pub enum TranslationPriority { … }

impl From<NodeCategory> for TranslationPriority {
    fn from(category: NodeCategory) -> Self { … }
}
```

`TranslationOrderer::order` (`ordering.rs:L230-L334`) produces a
`VecDeque<FunctionTranslationPlan>` in three tiers: roots and skips first
(they're stubbed or skipped cheaply), then middles, then leaves. Within
each tier a topological sort (`topological_sort_tier`, `ordering.rs:L343`)
puts callees before callers, so a function is translated only after the
functions it calls already have Rust translations to reference.

The sort takes one more input than pure call edges: a `StateSharingEdges`
set (`ordering.rs:L86-L99`) of pairs of functions that touch the same
global, supplied through `with_state_sharing` (`ordering.rs:L217`) from
the global-state scan's rollup. A writer is ordered before its readers,
just as a callee is ordered before its caller, because the reader's
translation needs the writer's Rust already in place.

Cycles don't hang the sort: cyclic functions are appended at the end of
their tier (test: `ordering.rs:L886-L925`).

Why are leaves *last*, then? Because "Leaf" is not the known third-party
function — it's the application function that *calls* one (`create_display`
→ `Direct3DCreate9`, `leaf_detector.rs:L1-L21`). The known APIs themselves
are never in the queue: they're PAL-mapped or shimmed. Their type
information reaches the prompts through the evidence engines (typesdb,
typeinfer, apidetect) that run *before* the batch — type propagation
happens at analysis time (ADR-0014/0015), not through translation order. The tiering is a
cost/difficulty ordering: roots are stubs, middles are translated bottom-up,
and leaves go last because they need the most context — including the
already-translated Rust of their internal neighbors.

### 8.2 The batch loop is an operator-facing state machine

`batch_translate` (`pipeline.rs:L3109-L3365`) and
`batch_translate_from_callgraph` (`pipeline.rs:L3459-L3731`) walk the plan,
calling `try_translate_with_retry` per function.

Before either runs, the carry-over machinery runs first. The pre-batch
scan runner ends with a version-pairing step (`pair_previous_versions`,
`version_pairing.rs:L45`, called from `run_prebatch_scans` at
`pipeline.rs:L2380-L2439`). Each binary's function list then gets a fresh
seed table (`refresh_carry_over_seeds`, `pipeline.rs:L2451`) built by
`carry_over::collect_seeds` (`carry_over.rs:L107`) from the bdiff pairing
document and the previous branch's merged review records. The pipeline
learns which attempts were accepted through the injectable
`with_accepted_attempt_source` port (`pipeline.rs:L766`); assembly supplies
it from the pass description's accepted-attempt field (issue #326).

After a unit finishes, `attach_carry_over_provenance` (`pipeline.rs:L2485`)
records the seeded commit on the review overlay. A seeded function's own
translate call never reaches the LLM (Chapter 4's Step 4b).

The batch core is surrounded by control machinery — all of it tested from
the pipeline's own `mod tests`:

- **Stop** breaks at the next unit boundary, never mid-LLM-call
  (`pipeline.rs:L3988-L4019`).
- **Pause/park** halts the loop and resumes exactly where it stopped
  (`pipeline.rs:L4541-L4603`); a stop during a pause ends the pause
  (`pipeline.rs:L4653-L4698`).
- **Cancel-current** aborts the in-flight unit's future and continues with
  the next (`pipeline.rs:L4820-L4902`).
- **Token budget**: a spent budget ends the batch before any unit runs
  (`pipeline.rs:L4467-L4497`).
- **Skips**: operator-skipped functions (`pipeline.rs:L4026-L4053`) and
  reviewer-skipped functions (`pipeline.rs:L4097-L4131`) are never queued.

The control objects (`StopSignal`, `PipelineControl`, `UnitCancellation`)
are shared-state types in `calxgloss-types`, held by both the CLI and the
web server. The same pipeline can therefore be steered from a terminal or
from a browser (ADR-0004).

### 8.3 Evidence is gathered lazily, cached, and failures are survivable

Before a batch translates, the pipeline ensures the evidence engines have
run. Every scan enters the phase through exactly one entry point: a
descriptor row in the evidence-scan registry (`scan_rows`,
`scan_registry.rs:L525-L543`). Each row follows one pattern, implemented
once by the generic scan pass: check the workspace cache; if it misses,
run the scan; on failure, *degrade*:

```rust
// crates/pipeline/calxgloss-translator/src/scan_registry.rs:L360+ (the shape, abridged)
pub fn new<T, P, ScanError, SaveError>(row: ScanRow<T, P, ScanError, SaveError>) -> Self {
    // cached re/analysis/<domain>/<binary>.json? log the cached-hit debug, done.
    // else build the row's engine from the batch's shared read source,
    //     run its scan, save through the row's persistor.
    // on scan or save failure: warn! with the row's own wording — the batch
    //     continues with less context rather than dying.
}
```

The row contributes only what differs per evidence engine — document
location, evidence-engine constructor, log wording, success counts, and
any declared ordering edge. The scan shape itself is written once, in
`ScanDescriptor::new` (`scan_registry.rs:L360-L475`).

The pipeline once carried, per scan, a hand-written scan method, its
wrapper, and a public `ensure_*` entry point — fourteen scan methods and
fourteen `ensure_*` entry points in all. Issue #308 deleted them: the
registry is now the only way a scan enters the phase. A roster test lists
all fifteen rows, so a row can only join or leave through a deliberate
edit. Each old scan's seam test quad pinned the same three shapes; those
shapes are now pinned once, generically, at the phase seam: *cached
result reused without rescanning*, *cold phase files each row's document
where its descriptor names*, *save failure degrades without losing the
batch*.

One preamble, `run_prebatch_scans` (`pipeline.rs:L2316-L2374`), runs all
fifteen scans as `JoinSet` tasks through a concurrency window:
`MAX_CONCURRENT_EVIDENCE_SCANS = 4`, one named decision. The high-water
mark is recorded, so the fan-out cap is provable
(`registered_scan_tasks`, `pipeline.rs:L143-L163`). One heartbeat pass
covers the whole group rather than one per scan (issue #239). A test that
tampers the cached scan documents and re-runs the batch proves the second
batch replays the tampered bytes back into its results — the cache's
contents are really used, not kept only for speed.

---

## 9. The human touchpoints: CLI and web

### 9.1 `main` is configuration layering plus dispatch

`crates/interface/calxgloss-cli/src/main.rs:L94-L595` does three things
before any command runs: initialize reloadable logging, layer configuration,
and dispatch. The layering is explicit and ordered:

```rust
// main.rs:L111-L151 (abridged)
// Layer configuration once, so every command sees the same values and a
// malformed file is reported before any work starts rather than halfway
// through a translation.
let loaded = load(cli.config.as_deref())?;
let mut layers = Layers::from_env();
layers.file = loaded.file.clone();

// The global flags form the highest-priority layer, shared by every
// subcommand so `config` reports the same values a real run would use.
let flags = FileConfig { … };
let settings = Settings::resolve(&layers, flags, &loaded);
```

Flags > environment (`CALXGLOSS_LLM_URL`, …) > config file
(`./calxgloss.toml`) > built-in defaults. Secrets load but never print —
`calxgloss config` shows `<set>`.

The `Command` enum (`cli_types.rs:L197-L1041`) is the full surface: `init`,
`doctor` (checks that the Kuna analysis engine loads the target; `--fix` is
accepted for compatibility but has nothing to install), `classify`,
`translate`, `batch-translate`, `auto`, `serve`, `live`, `verify`,
`dashboard` — whose `view`/`accept`/`send-back`/`accept-all` subcommands live in
`DashboardSubcommand` (`cli_types.rs:L1045-L1135`) — `auto-shim`, `gc`,
`config`, and one command per evidence engine (`typesdb`, `typeinfer`,
`algorithm`, `memory`, `sync`, `globalstate`, `consts`, `callback`,
`controlflow`, `stringctx`, `apidetect`, `serialize`, `errhandling`,
`floatsimd`, `libmatch`, and the version comparison, `bdiff`). The doc
comments on the enum variants are themselves documentation. For example,
the `Doctor` variant's comment specifies the whole command contract: one
read-only pass; nothing to install, because Kuna is compiled in; and
every failure carries a remediation hint and exits non-zero so CI can
gate on it (`cli_types.rs:L204-L218`).

`live` is the recommended day-to-day entry point: it runs the auto
pipeline and the web review server as two tasks in one process, connected
by the progress-event broadcast channel. The lifecycle is documented in
`docs/data_flow.md`.

### 9.2 One event vocabulary, three consumers

Every stage emits `ProgressEvent`s into a `TranslationEvents` broadcast
channel (capacity 256). The same events feed:

1. the web dashboard's in-memory `ProgressState`
   (`server/mod.rs:L476-L737` — `on_event` builds per-unit entries from
   the event stream),
2. the WebSocket fan-out (`events.rs`, the most depended-upon module in the
   repo), and
3. the heartbeat/scan-pass machinery (Chapter 2.1).

Emitting an event is fire-and-forget (`let _ = em.emit(…)`): observability
must never fail a translation. The flip side is documented as a known
hazard — lenient observability defaults can hide failures. That is why the
*persisted* logs (Chapter 11), not the events, are the audit trail.

### 9.3 The web server is two routers over one state

`build_router` (`server/mod.rs:L1149-L1157`) composes `shared_routes` and
`live_only_routes` (`server/mod.rs:L848-L1125`) behind one axum `Router`
sharing a single `CombinedState`. The review-action routes — `accept_unit`,
`send_back_unit`, `request_patch` — live in the shared table. Apart from
those routes, `serve` mode only reads existing artifacts (ADR-0006);
`live` mode adds the live-pipeline and WebSocket endpoints on top.

Both servers build a settings-backed action backend (issue #327;
`build_router_with_actions`, `build_router_with_ws`). The server folds its
resolved settings into a `PipelineSpec` once at startup. `request_patch`
(`actions.rs:L424`, spawning retry at `L441`) then adds the request's
run-scoped fields (the repo as workspace, patch mode, the unit's binary)
to that description and assembles the whole retry pass through
`assemble_patch` before anything is created. The LLM is required first,
so a server started without LLM settings meets the assembly refusal at
request time, with no branch record or task left behind. The reviewer's
hints seed the retry loop's failure history (Chapter 6.1), and the new
attempt lands on a fresh attempt branch. Before issue #327, a router
could be built without any action backend at all: the patch endpoint
answered with a fabricated stub "Patch requested" response, and the
retry machinery never ran (ADR-0050).

---

## 10. The evidence engines

Eighteen crates under `crates/evidence/` each answer one question about
the target binary. All of them read the *loaded program* through the
`ScanSource` seam and write JSON documents into the workspace's
`re/analysis/` tree. One is the exception: `calxgloss-bdiff` reads the
*scan read cache* instead, and it gets its own section below. In the
Cargo.toml's words:

| Crate | Question it answers |
|---|---|
| `calxgloss-analysis` | What is this DLL? (classification, API tagging, shim generation) |
| `calxgloss-callgraph` | Who calls whom, and in what order should we translate? |
| `calxgloss-typesdb` | What data structures exist? (type manager, vtables, string-guided structs) |
| `calxgloss-typeinfer` | What are the types? (this-pointers, parameter sizes, propagation) |
| `calxgloss-algorithm` | Which known algorithms is this code? (control-flow signatures) |
| `calxgloss-memory` | How is memory managed? (alloc/free pairs, handles, refcounting) |
| `calxgloss-sync` | Where is concurrency? (mutex pairs, atomics, threads) |
| `calxgloss-globalstate` | Which functions read and write which globals? (per-function access records quoting the access statement at a confidence band, rolled up into a shared-globals index the sync engine and the call-graph orderer both consume) |
| `calxgloss-consts` | Which constants and enums are real? (bitflags, magic numbers) |
| `calxgloss-callback` | Where are function-pointer tables and jump-table dispatches? |
| `calxgloss-controlflow` | Which if-else chains are switches or state machines? |
| `calxgloss-stringctx` | What do the strings mean? (nine-category classification, format strings) |
| `calxgloss-apidetect` | Which third-party library is this? (import-table fingerprinting → crate mapping) |
| `calxgloss-serialize` | Where is endianness/serialization logic? (byte swaps, magic bytes) |
| `calxgloss-floatsimd` | Which functions use float, and what shape? (four evidence families over the kept bodies — explicit float tokens, CRT math calls, `CONCAT44`/`SUB4` vector idioms, x/y/z component triplets — one flag per function spelling `scalar_float`, `vector_matrix`, or `mixed`) |
| `calxgloss-libmatch` | Which functions are statically linked library code? (body-shape signatures → CRT/STL symbols) |
| `calxgloss-errhandling` | Which functions guard their work in an exception frame, raise directly, or clean up through a goto ladder, and what failure codes do they trade in? (spelled `try`/`catch` blocks, named handler thunks, exception-API calls, `RaiseException` sites, guarded forward gotos converging on one releasing join block, and HRESULT/NTSTATUS-shaped literals in returns, guard comparisons, or raise arguments → the error-handling idiom, its Rust mapping, and the codes a baseline test must preserve) |
| `calxgloss-bdiff` | Which functions in an older version of this binary are the *same function* here? (name identity → byte-equal normalized bodies → call topology, at 95 / 90 / 70; near-equal bodies score on a diff ratio with a 60 floor; a lone address equality claims nothing) |

They share two helpers from `calxgloss-types`: `ScanMetadata`, the
provenance header written into every cached scan JSON (`scan.rs:L21-L58`),
and the JSON persistence helpers (`persist.rs`). Their findings enter
prompts through the context-tier machinery of Chapter 1.4: data
structures, control-flow findings, and shim layers are extracted from the
cached JSON at prompt build time (`retry/helpers.rs`).

One note on the shim path: for `MicrosoftSdk`/`KnownThirdParty` DLLs,
`calxgloss-analysis`'s `shim_pipeline` proposes replacing the whole DLL
with a Rust crate plus a thin adapter layer. The mapping contract is
positional: `ShimApiMapping` keeps `original_params`, `crate_params`, and
`parameter_transforms` aligned by index (`shim.rs:L56-L96`). The adapter
is verified with the same `Verifier` machinery as everything else
(Chapter 5, `verify_shim`).

`calxgloss-bdiff` is the exception: not a methodology scan, never run
through an `ensure_*` fan-out, and it reads nothing from the analysis
engine. Using the two versions' **scan-cache documents**, it answers the
question the carry-over story (§8.2) would otherwise have to assume —
*which function of the older version is the same function here?* The scan
step writes its scan read cache under `re/cache/{identity}/{sha256}`
(ADR-0043). When the binary's bytes change, the previous version's cache
directory survives beside the new one. `pair_previous_versions` (issue
#298, `version_pairing.rs`) assembles both document sets into two
`ScanSnapshot`s and calls `pair_versions` (`engine.rs`): documents in,
one pairing document out, in milliseconds, at no cost — ADR-0026 still
holds: no program mutation, no LLM.

The match ladder — which signals pair functions, and at what confidence —
is the artifact.

First, **name identity**: an exported name or a demangled name present on
both sides pairs at band 95 — one band below certainty, because stripped
exports and demangler rewrites can still rename the same code.

Second, the **normalized-body family**: kept bodies put through the
shared libmatch normalizer (#294's public cross-crate rule — one
normalizer, one owner, never a second) pair byte-equal at 90 — *the
address shift renamed the `FUN_…` spelling and the rebuild re-lettered
the variables, but the shape survived* — while a near-equal pair scores
on its structural-diff ratio with a floor of 60: below 60% shared
normalized lines a pair claims nothing.

Third, **call topology**: a function that neither of the first two
signals claimed pairs when at least two already-paired callers and/or
callees reach it on both sides through call edges of a call map derived
purely from the kept bodies. This step iterates to a fixed point, so
chains of renamed functions pair through neighbors that converged
themselves. It scores 70 and records its paired-neighbor evidence lines.

The lone-signal gate (ADR-0038) is the design: address equality pairs
nothing on its own, and neither does a matching address-derived `FUN_…`
spelling. That spelling *is* an address, and pairing on it would bring
back the relocation signal the gate exists to refuse.

Topology corroborating a body-family pair is not a new signal: on the
flag-family agreement precedent (agreement beats any single reading) the
record gets a 5-point bump — a corroborated byte-equal pair reaches 95,
never past it.

Pairings resolve one-to-one: the strongest claim wins, ties keep the
first-seen.

The confidence floor lives downstream by design: `CARRY_OVER_CONFIDENCE_
FLOOR = 80` is an instruction to the consumer, not a filter on the record.
The pass persists every resolved pairing. A below-floor or unpaired
function queues fresh exactly as before, so a wrong pairing can never
silently seed a wrong translation. A lone topology pair (70) cannot drive
carry-over. Name identity and byte-equal bodies clear the floor; a
ratio-scored body pair clears it only where the ratio lands it at 80 or
above.

The document is keyed by both versions' file-bytes SHA-256
(`re/analysis/bdiff/{binary}-{old}-{new}.json`). Pairing runs exactly once
per (old, new) hash pair. A persisted document that does not name the live
hash pair is detected as stale and recomputed — never silently trusted.
`carry_over::collect_seeds` (`carry_over.rs:L107`) adds its own staleness
gate: only a document whose `new_bytes_sha256` *is* the exact bytes being
translated right now can seed.

The accepted code arrives through the `AcceptedAttemptSource` port — the
translator never touches git itself. The port reads the highest merged
`re/{binary}/{function}…` branch's `translated.rs`, one branch per seed.
Provenance survives into the record: the seed records the old function
and the attempt branch its code came from, the commit on the new branch
says *seeded from*, and nothing carries a Verified mark. Carry-over is
the hypothesis; deterministic verification against the new bytes is the
verdict.

And `bdiff --binary` is a pure report over these documents: every pair
with its confidence and family (`name_identity` / `normalized_body` /
`call_topology`), plus the functions paired on neither side — old-only
and new-only. The report tells the live document apart from stale ones.

Three of the sections the escalate and module-context prompts now carry
are the blind spots issue #278 identified. Each gained its scan in this
batch.

**`## GLOBAL STATE`** shows the global-state scan's readings. Each
per-function access record lists the program globals (`DAT_*` names as
the decompiler spells them) that the function *reads* and that it
*writes*, and quotes the access statement as its evidence: an exact
`DAT_*` spelling scores 85, a shape-only sighting 60. Each record also
carries a suggestion the prompt renders verbatim: give the global's
storage a place in a struct that the translation passes through its
units, rather than in a Rust `static`. The same document appends the
rollup's shared-globals index — every reader and writer of one global,
grouped. That index feeds two consumers: the sync engine reads it
instead of re-deriving the same access reading, and the call-graph
orderer derives its `with_state_sharing` override (§8.2) from
`state_sharing_pairs`.

**`## FLOAT/SIMD`** shows the float/SIMD scan's one flag per flagged
function. The reading has four families keyed on shapes in the
pseudo-C. An explicit `float`/`double` token or float literal scores
90. A CRT math call (`sqrt`, `sin`, `floor`) scores 75. `CONCAT44`-style
concatenations and `SUB4` extractions — the shapes the decompiler
mangles SIMD register work into — score 60. Parallel `x`/`y`/`z` member
reads are the weakest family. The strongest family sets the confidence.
Which families fired sets the shape: `scalar_float`, `vector_matrix`, or
one `mixed` flag covering both. The translator is therefore told to
render the math as floats or component arrays, instead of reading
mangled vector pseudo-C as integer and pointer logic.

**`## ERROR HANDLING`** shows the error-handling scan's readings from
§3.2.2: spelled frames, personality handlers, exception APIs,
goto-cleanup ladders, and failure codes. The failure-code entries
distinguish codes the function itself returned, raised, or compared from
*inherited* codes that travelled one hop from a callee. Both are to be
surfaced as the numeric codes of the Rust error values the function
hands back, rather than collapsed into ad-hoc variants.

The module-context prompt gained two more sections from the same batch.
One is **KNOWN LIBRARY FUNCTIONS**: the calls this function makes that
the libmatch scan identified as statically linked CRT/STL code, each
recording the matched symbol. The translator maps each call onto the
suggested Rust equivalent instead of re-implementing a `memcpy` body it
does not own. The module-context prompt renders **PARAMETER
DIRECTIONS**, too: the type-inference scan's per-pointer-parameter
reading of which way data flows (an `in` parameter becomes a shared
borrow, an `out` parameter a mutable borrow or a value handed back, an
`inout` parameter a read-modify-write); a direction reading claims no
mutability of its own. And **DATA TABLES**: data objects whose bytes
decode coherently at one element width and nothing writes, each rendered
as a named `const` array of element type and entry count instead of
re-scattered match arms, from the consts scan's `ConstFinding::DataTable`
records.

---

## 11. The audit trail: faults, tokens, experiments

Three append-only JSON documents, all keyed by the identity triple, all
analyzed *on demand* rather than incrementally (ADR-0005):

- **`FaultLog`** (`fault.rs`) — a closed vocabulary of LLM failure modes:
  context-window overflow (with `suggested_chunk_count` recovery guidance),
  hallucination, infinite loop, behavior divergence, resource exhaustion.
  Each `FaultEvent` carries severity and the attempt that produced it.
- **`TokenUsageLog`** (`token_usage.rs`) — one entry per attempt: tokens,
  strategy, context tier, wall-clock seconds. The dashboard's ETA and cost
  reports are computed from this file.
- **`PromptStrategyLog`** (`experiment_log.rs`) — per (dll, strategy):
  successes, attempts, pass rate. This is the A/B evidence for the
  escalation ladder in Chapter 6.2.

All three cap their retained entries (`MAX_LOG_ENTRIES = 10_000`,
`lib.rs:L54`) by *trimming into a summary block* rather than dropping
data. `compute_stats` covers trimmed entries, so a truncated file still
yields honest statistics (tests at `fault.rs:L1033-L1059`,
`experiment_log.rs:L590-L615`).

---

## Epilogue: the invariants to hold in your head

1. **The triple `(dll, function, attempt)` is everywhere.** Branch names,
   logs, events, and review records all use it. Rename it in one place and
   the audit trail silently stops joining up.
2. **Generation and judgment are separate.** `translate` produces code;
   `Verifier` judges it; the retry loop is the only thing that joins them.
3. **Every failure is data.** Every failed attempt gets a branch, every
   fault gets an event, and every prompt variant gets an experiment entry.
   The system is designed to be *read after the fact* as much as it is
   designed to be run.
4. **Degrade, don't die.** Call-graph build fails → translate without
   enrichment. Evidence scan fails → batch continues. Event emit fails →
   translation continues. Only the LLM call itself and git commits are
   allowed to be fatal.
5. **The human is in the loop by construction.** Reviewer overrides force
   context tiers and retry strategies; reviewer hints are included in the
   prompts; acceptance is a git merge with conflict detection. The machine
   proposes; `main` decides.

*Further reading:* `docs/Calxgloss.md` (design), `docs/data_flow.md`
(the `live` workflow end to end), `docs/adr/` (the forty-seven decisions),
`GLOSSARY-MAP.md` (the domain vocabulary per context), and `graft/` (the
generated per-file wiring cards this tour was built from).
