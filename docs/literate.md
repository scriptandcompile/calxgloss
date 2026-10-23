# Calxgloss, in Literate Form

*A walking tour of the source code, in the order the ideas need to be read
rather than the order they live in files. Each section states what a piece of
the system must do, then shows the code that does it, with exact `file:line`
references so you can open the span and edit it.*

---

## 0. How to read this document

Calxgloss is a Cargo workspace of 27 crates in five contexts:

```
crates/
├── calxgloss/          the meta-lib (one file of re-exports)
├── shared/             calxgloss-types, calxgloss-config
├── integrations/       calxgloss-decomp, -kuna, -llm, -pal, -prompts
├── evidence/           13 analysis engines (analysis, callgraph, typesdb, …)
├── pipeline/           calxgloss-translator, -verify, -testgen, -git
└── interface/          calxgloss-cli, -web, -reports
```

The tour proceeds bottom-up: first the nouns every crate exchanges
(Chapter 1), then the senses that observe the binary (Chapters 2–3), then the
act of translation and the judgment that follows it (Chapters 4–6), then the
memory that makes the work reversible (Chapter 7), then scale-out and the
human seat (Chapters 8–9), and finally the telemetry that lets the whole
machine be audited (Chapters 10–11).

Code excerpts are verbatim from the current source; line numbers refer to the
files as they exist now. Where a span is longer than quoted, the elision is
marked `…`.

---

## 1. The nouns: `calxgloss-types`

Everything the harness does is a flow of serializable values between crates
that never call each other directly. That vocabulary lives in
`crates/shared/calxgloss-types`, re-exported flat at the crate root
(`src/lib.rs:L56-L82`) so consumers write `calxgloss_types::FunctionInfo`.
It deliberately contains **no analysis logic and no service calls** — the
engine, the LLM, and test runners live in crates that only exchange these
records.

### 1.1 A DLL's category is the strategy switch

Before a single function is translated, each DLL is classified, and the
classification *is* the handling strategy:

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
Do Not Translate, see ADR-0044). `RuntimeLibrary` is a veto. Because every
statistic, fault log, and shim suggestion groups by category, a wrong
classification silently skews every downstream report — this is the single
most consequential decision the system makes.

### 1.2 What a function *is*, before it is translated

The record the engine produces for one function is the primary input to
the pipeline:

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

Note the assumption baked into the type: *the engine has already run*. These
records never invoke it; consumers must treat the text as opaque and possibly
stale. Each tagged API call carries its translation target with it:

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
// crates/shared/calxgloss-types/src/test.rs:L77-L87
pub struct TestCase {
    /// The test inputs as a JSON value.
    pub inputs: serde_json::Value,
    /// The expected return value from the original function, as JSON.
    pub expected_return: serde_json::Value,
    /// Expected side effects the function produces when called with these inputs.
    pub expected_side_effects: Vec<SideEffect>,
}
```

JSON on both sides is a deliberate choice: the same shape travels to the CLI,
the dashboard, the generated Wine harness, and remote services without
custom serialization. Side-effect details are a typed `SideEffectKind` with a
free-form `detail: String` and an `Other(String)` escape hatch — the modeled
effects are enumerated, the unmodeled ones are not lost.

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

The tier is chosen automatically (complexity + API count + historical success
rate, `select_context_tier` at `context_tier.rs:L223`), emitted as a progress
event, and recorded per token-usage entry — so cost and pass rate can be
attributed to the tier that produced them. `ContextTier::ALL`
(`context_tier.rs:L76`) is the single enumeration the dashboard populates its
tier controls from; the frontend never hardcodes variant names.

### 1.5 The identity triple: `(dll, function, attempt)`

Every unit of work is named by a triple that is spelled identically
everywhere — in the git branch name, in every token-usage entry, fault event,
and progress event:

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

`re/game_logic.dll/DrawSpritev1`. Correlating a failed run — branch diff vs.
tokens burned vs. the fault that ended it — requires all three fields to match
across every artifact. This one `format!` is the join key of the whole
harness.

---

## 2. The eyes: the engine and the PAL

### 2.1 `KunaSource` — the program, loaded in-process

The analysis engine is Kuna — a Rust port of Ghidra's decompiler — loaded
in-process from the target binary (ADR-0041, superseding ADR-0001's HTTP
bridge and ADR-0007's JVM lifecycle; issue #214 retired those outright).
The seam crate keeps the vocabulary the pipeline was built against: the
`ScanSource`/`TypeWriteSource` traits, the answer shapes, and the read
cache. Every read is a command to the engine thread; name-based lookups
resolve inside the engine:

```rust
// crates/integrations/calxgloss-kuna/src/source.rs:L514-L528
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
    outcome
}
```

A subtlety worth noticing: long scans (a full decompile pass over a DLL can
take minutes) would look like a hang on the web dashboard. The engine source
carries a *heartbeat* — `begin_pass`/`end_pass` plus a `tick` per decompile
(`source.rs:L440-L500`) — that beats into the progress-event channel so the
UI can show *which function* the engine is chewing on.

### 2.2 The PAL — a static Windows-API → Rust mapping table

The Platform Abstraction Layer is not runtime code; it is a compile-time
lookup table injected into prompts:

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
`Send + Sync` for free and can be shared across the whole pipeline. When a
function's tagged APIs fall in a category, the prompt builder injects the
full mapping-table rows for that category (`for_categories`,
`types.rs:L163-L188`) — the LLM is never asked to guess what `CreateFileA`
should become.

---

## 3. Ground truth: capturing behavior from the *original* binary

Tests must record what the original function actually does. The obvious
approach — generate an `extern "C"` block and link against the DLL — fails
for the functions that matter. The module header of
`crates/pipeline/calxgloss-testgen/src/wine.rs:L1-L45` is the clearest
statement of the problem in the codebase, quoted in full:

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

Two load modes exist because Delphi binaries need runtime state a bare
mapping won't provide: `NoResolve` (map without `DllMain`) and `Full` (run
`DllMain`, resolve imports). The generated harness has **zero dependencies**
— a test asserts it (`calxgloss-testgen/tests/baseline.rs:L354-L371`) — so
cross-compiling it never touches a registry. Test cases cross the process
boundary as `<tag>:<value>` lines on stdin; results return as
`<index>\t<ok|err>\t<value>` on stdout. And because a faulting function kills
the harness process, a batch that dies mid-run is retried case-by-case so one
bad input doesn't discard the rest (`wine.rs:L40-L45`).

The signature side of this — turning Ghidra's `int __stdcall FUN_…(int a,
LPCSTR b)` into a callable Rust binding — is `ffi.rs`: a `TYPE_MAP` of Windows
types to Rust types with pointer depth and bit width
(`ffi.rs:L101-L141`), `parse_signature` (`ffi.rs:L154`), and
`generate_ffi_binding` (`ffi.rs:L229`).

---

## 4. The act of translation: `TranslationPipeline::translate`

The heart is one function:
`crates/pipeline/calxgloss-translator/src/pipeline.rs:L709-L1071`. The
pipeline itself is a struct of clients and optional controls
(`pipeline.rs:L108-L266`) assembled with builder methods —
`with_workspace`, `with_events`, `with_call_graph`, `with_fault_logger`,
`with_stop_signal`, and about a dozen more. `translate` runs seven steps.

**Step 0 — refuse what has no logic.** Before spending a token:

```rust
// crates/pipeline/calxgloss-translator/src/pipeline.rs:L712-L719
// Root symbols — entry points and import thunks — own no logic to
// translate. … a `DelayLoad_` thunk is the classic trap: its resolved-import
// jump decompiles to an unrecovered jumptable plus a bare `return`, and
// the LLM faithfully translates the wreckage. Refuse before the
// scan fetch, before any token is spent.
self.refuse_root_function(binary, function)?;
```

**Step 1 — fetch, then triage the decompiler's own failures.** Ghidra's
analysis failures ride inside the pseudo-C as `WARNING` comments:

```rust
// pipeline.rs:L740-L745
// Triage: Ghidra's analysis failures ride inside the pseudo-C as
// WARNING comments. Name them before the LLM sees the body — an
// unrecovered jump table otherwise becomes a plausible, hollow
// `return` in the generated Rust, with nothing marking the address
// that needs human recovery.
self.triage_decompiler_warnings(binary, function, &function_info.decompiler_output);
```

**Steps 2–3 — tag APIs, generate baseline tests.** Imports are fetched once
per binary and intersected with the function's call sites
(`tag_windows_apis`, `pipeline.rs:L1423`); baseline test inputs come from the
testgen crate of Chapter 3 (`generate_baseline_tests`, `pipeline.rs:L1440`).

**Step 4 — size the prompt.** Complexity detection picks a tier, and a
reviewer override can force one:

```rust
// pipeline.rs:L794-L814
let auto_tier = calxgloss_types::select_context_tier(
    &complexity, api_call_count, calxgloss_types::SuccessRate::default(),
);
// W2.7: a reviewer override forces the tier — the automatic selector
// is bypassed for this unit (issue #96).
let tier = match self.forced_context_tier(binary, function) {
    Some(forced) => forced,
    None => auto_tier,
};
```

Then a `match tier` (`pipeline.rs:L894-L986`) builds the prompt from the
corresponding template in `calxgloss-prompts`. The tiers nest:
`ModuleContext` adds call-graph neighbors, neighboring function bodies, and
recovered data structures; `FullModule` additionally extracts shim-layer code
and PAL trait definitions from the workspace. Every tier path enriches with
the same `helpers::extract_*` functions the retry loop uses for escalation —
one context-extraction vocabulary, two callers.

**Steps 5–7 — send, check, return.** The prompt goes to the LLM
(`send_to_llm`, `pipeline.rs:L1649`); an empty response is an error, not a
result; and the returned `Translation` carries everything downstream stages
need — code, prompt, tier, baseline tests, token count:

```rust
// pipeline.rs:L1057-L1070
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
`translate` is pure generation. Judgment is separate.

### 4.1 The LLM client is defensive about the context window

`calxgloss-llm` talks the OpenAI-compatible chat API that Ollama and vLLM
serve. Two details encode hard-won experience:

```rust
// crates/integrations/calxgloss-llm/src/client.rs:L340-L348
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

Every request caps `max_tokens` to what's left of the window — an
uncapped request is how a local server gets OOM-killed. And in `complete`
(`client.rs:L367-L438`), HTTP 429/503/507 are mapped to a typed
`LlmError::ResourceExhausted` rather than a generic server error, because the
retry loop treats overload differently from a bad prompt (Chapter 6). The
response content comes back with markdown fences stripped
(`strip_code_fences`, `client.rs:L589`) — the LLM's habit of wrapping code in
rust code blocks is normalized at the boundary, not in every consumer.

---

## 5. The judgment: `Verifier`

`crates/pipeline/calxgloss-verify/src/engine.rs` scaffolds a throwaway cargo
project per check, compiles, and runs the behavioral tests:

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

1. **Compile failure short-circuits to a *result*, not an error.** The retry
   loop needs the compiler's error text as prompt material; throwing it away
   would starve the fix strategies.
2. **The scratch project is hermetic.** `scaffold_project` writes a minimal
   `Cargo.toml` and a PAL stub crate (`ensure_pal_crate`, `engine.rs:L194`)
   so translated code that references PAL placeholders still type-checks.
3. **`parse_test_results` parses `cargo test` JSON output** into per-test
   `FailedTest` records — the same type the shim verification reuses verbatim.

There is a parallel `verify_shim` (`engine.rs:L488`) for the crate-replacement
strategy: it scaffolds a project whose `Cargo.toml` pulls in the real
replacement crate (`shim_crate_root_for_cargo`, `engine.rs:L621`) and runs
the shim mapping tests.

---

## 6. The persistence loop: `try_translate_with_retry`

One LLM call rarely produces passing code. The retry loop —
`crates/pipeline/calxgloss-translator/src/retry/retry_loop.rs:L72-L1353` —
is where the harness earns its keep. Its shape:

**Attempt 1** is verified as-is (compile, run tests). If it passes, return.
Otherwise, for attempts `2..=max`, the loop alternates between two prompt
sources and escalates both a *strategy* and a *context tier* on each failure.

### 6.1 Strategies that feed the failure back into the prompt

```rust
// retry_loop.rs:L697-L737 (abridged)
let (prompt, strategy_name) = match &current_strategy {
    RetryStrategy::Default => { /* skip — re-sending an identical prompt wastes tokens */ }
    RetryStrategy::CompileFix => {
        let prompt = if failure_history.is_empty() {
            build_compile_fix_prompt(&initial_translation.function, &initial_translation.binary,
                &initial_translation.rust_code, &initial_errors)
        } else {
            build_failure_informed_compile_fix_prompt(&initial_translation.function,
                &initial_translation.binary, &initial_translation.rust_code,
                &initial_errors, &failure_history)
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

The `failure_history: Vec<FailureHint>` accumulates one entry per failed
attempt — attempt number, strategy, human-readable failure — and after the
first retry every fix prompt is *failure-informed*: the LLM sees what has
already been tried and why it failed. Reviewer hints from the web UI seed the
history as attempt 0 with strategy `"reviewer"` (`retry_loop.rs:L88-L94`),
so a steered unit's very first fix prompt already carries the reviewer's
knowledge.

### 6.2 Escalation is a ratchet, not a random walk

```rust
// retry_loop.rs:L1313-L1348 (abridged)
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
        current_tier = next_tier;
        tier_escalated = true;
    }
}
```

When `tier_escalated` is set, the next iteration takes a different branch at
the top of the loop (`retry_loop.rs:L262-L694`): it rebuilds the prompt from
the *next* context tier — pulling in more neighbors, data structures, shim
layers — instead of just re-feeding errors. Strategy cycles; tier only ever
walks up, and only within the operator's cap.

### 6.3 The infinite-loop detector

LLMs can return byte-identical garbage for different prompts. The detector
tracks `(prompt_hash, output_hash)` pairs; three identical bad outputs in a
row fire:

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

Firing emits a `ProgressEvent::InfiniteLoopDetected` *and* records a
`FaultEvent::infinite_loop` — the live UI and the post-hoc audit trail are
fed from the same signal.

### 6.4 Every attempt leaves a paper trail

After each attempt the loop (in order): records the loop detector, appends a
`TranslationAttempt` to the result, emits
`TranslationAttemptCompleted`, writes a token-usage entry with wall-clock
duration (`log_token_usage`, `retry_loop.rs:L1256-L1270` — the dashboard's
time estimates come from these), pushes a `FailureHint`, logs a prompt-variant
experiment (`log_prompt_variant_experiment`, `retry_loop.rs:L1304` — the A/B
data behind "which strategy actually works"), and only then decides whether
to break or escalate.

The public entry point composes generation and this loop
(`pipeline.rs:L1195-L1291`): `translate` once, then `try_translate_with_retry`
around it. (The futures are boxed at that boundary for a compiler reason, not
a design one — recursive `Send` evaluation through the whole pipeline
overflows rustc's trait recursion limit, rust-lang/rust#159228.)

---

## 7. Memory: git as the system of record

Principle 6 — *source-control backed reversibility* — means every attempt,
pass or fail, lands as a commit on its own branch.

### 7.1 Branch creation is a dependency gate

```rust
// crates/pipeline/calxgloss-git/src/git_manager.rs:L254-L348 (abridged)
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

The dependency check consults the call graph: if `FUN_a` calls `FUN_b`, a
branch for `FUN_a` is only enforceable once `FUN_b`'s branch has merged.
Translation order is thus enforced by git topology, not by convention.

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

Every commit message names the unit, the attempt number, and the retry
strategy that produced it. Failed branches are retained — they are the
historical record of what didn't work, diffable against the branch that did.

### 7.3 Acceptance is a merge, with a race guard

The web UI's accept button ends in `accept_unit`
(`crates/interface/calxgloss-web/src/server/actions.rs:L232-L290`):

```rust
// actions.rs:L236-L267 (abridged)
let (captured, _action_guard) = state.begin_action(unit_id).await;
…
// Re-check before merging: the lock guarantees nothing lands between here
// and the persist below, so a stale capture means the unit changed
// underneath us — fail without merging or overwriting (issue #86).
check_action_conflict(state.repo_path(), unit_id, captured)?;

let merge_result = git.accept_branch(&branch)?;
match &merge_result {
    MergeResult::Merged { merge_hash } => …,
    MergeResult::AlreadyUpToDate => …,
    // A conflicted merge landed nothing on main — fail before persisting
    // any action state so the unit keeps its pre-accept status (issue #83).
    MergeResult::Conflicts { conflicted_files, error } => return Err(anyhow!(…)),
}
```

A per-unit async lock plus a captured-state re-check makes accept/send-back
races resolve to exactly one winner (a test proves it:
`actions.rs:L922-L980`). The action itself is persisted as a JSON record
under the workspace, separate from the git state — reviewer intent lives in
overlay files, never derived from artifacts (ADR-0003).

---

## 8. Many functions at once: call graphs and batch translation

### 8.1 The graph decides the order

`calxgloss-callgraph` builds the graph from engine xrefs, classifies every
node `Root`/`Leaf`/`Middle`/`Skip` (root_detector, leaf_detector), and the
orderer turns it into a work queue:

```rust
// crates/evidence/calxgloss-callgraph/src/ordering.rs:L66-L94 (abridged)
pub enum TranslationPriority { … }

impl From<NodeCategory> for TranslationPriority {
    fn from(category: NodeCategory) -> Self { … }
}
```

`TranslationOrderer::order` (`ordering.rs:L170-L269`) produces a
`VecDeque<FunctionTranslationPlan>` in three tiers — roots and skips first
(they're stubbed or skipped cheaply), then middles, then leaves — and within
each tier a topological sort (`topological_sort_tier`, `ordering.rs:L276`)
puts callees before callers, so a function is translated only after the
functions it calls already have Rust translations to reference. Cycles don't
hang the sort; cyclic functions are appended at the end of their tier
(test: `ordering.rs:L794-L832`).

Why are leaves *last*, then? Because "Leaf" is not the known third-party
function — it's the application function that *calls* one (`create_display`
→ `Direct3DCreate9`, `leaf_detector.rs:L1-L21`). The known APIs themselves
are never in the queue: they're PAL-mapped or shimmed, and their type
information reaches prompts through the evidence engines (typesdb, typeinfer,
apidetect) that run *before* the batch — type propagation happens at analysis
time (ADR-0014/0015), not through translation order. The tiering is a
cost/difficulty ordering: roots are stubs, middles are translated bottom-up,
and leaves go last because they need the most context — including the
already-translated Rust of their internal neighbors.

### 8.2 The batch loop is an operator-facing state machine

`batch_translate` (`pipeline.rs:L2801-L3045`) and
`batch_translate_from_callgraph` (`pipeline.rs:L3149-L3381`) walk the plan,
calling `try_translate_with_retry` per function. Around that core sits a
surprising amount of control machinery — all of it tested from the pipeline's
own `mod tests`:

- **Stop** breaks at the next unit boundary, never mid-LLM-call
  (`pipeline.rs:L3473-L3504`).
- **Pause/park** halts the loop and resumes exactly where it stopped
  (`pipeline.rs:L3876-L3938`); a stop during a pause releases the park
  (`pipeline.rs:L3988-L4033`).
- **Cancel-current** aborts the in-flight unit's future and continues with
  the next (`pipeline.rs:L4062-L4137`).
- **Token budget**: a spent budget ends the batch before any unit runs
  (`pipeline.rs:L3802-L3832`).
- **Skips**: operator-skipped and reviewer-skipped functions are never queued
  (`pipeline.rs:L3511-L3582`).

The control objects (`StopSignal`, `PipelineControl`, `UnitCancellation`)
are shared-state types in `calxgloss-types` that both the CLI and the web
server hold — the same pipeline can be steered from a terminal or a browser
(ADR-0004).

### 8.3 Evidence is recovered lazily, cached, and failure is survivable

Before a batch translates, the pipeline ensures the evidence engines have
run. Each `ensure_*` follows one pattern — check the workspace cache, else
scan, else *degrade*:

```rust
// crates/pipeline/calxgloss-translator/src/pipeline.rs:L1923+ (pattern, abridged)
pub async fn ensure_type_database(&self, binary: &str) -> bool {
    // cached re/analysis/typesdb/<binary>.json? reuse it.
    // else run the three recovery scans against the loaded program,
    //     save the JSON + generated #[repr(C)] declarations.
    // on scan or save failure: warn! and return false — the batch continues
    //     with less context rather than dying.
}
```

There are eleven of these (`ensure_type_database` through
`ensure_serialize_detection`, `pipeline.rs:L1917-L2661`), one per evidence
engine, and each has the same trio of tests: *cached result reused without
rescanning*, *cache miss scans and saves through the engine*, *no workspace
skips the recovery*. A test that tampers the cached scan documents and
re-runs the batch proves the second batch replays the tampered bytes back
into its results — the cache is load-bearing, not decorative.

---

## 9. The human seat: CLI and web

### 9.1 `main` is configuration layering plus dispatch

`crates/interface/calxgloss-cli/src/main.rs:L86-L536` does three things
before any command runs: initialize reloadable logging, layer configuration,
and dispatch. The layering is explicit and ordered:

```rust
// main.rs:L110-L160 (abridged)
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

The `Command` enum (`cli_types.rs:L224-L924`) is the full surface: `init`,
`doctor` (checks the Kuna engine loads the target; `--fix` has nothing to install), `classify`,
`translate`, `batch-translate`, `auto`, `serve`, `live`, `verify`,
`dashboard` — whose `view`/`accept`/`reject`/`accept-all` subcommands live in
`DashboardSubcommand` (`cli_types.rs:L928-L1018`) — `auto-shim`, `gc`,
`config`, and one command per evidence engine (`typesdb`, `typeinfer`,
`algorithm`, `memory`, `sync`, `consts`, `callback`, `controlflow`,
`stringctx`, `apidetect`, `serialize`). The doc comments on the enum variants
are themselves documentation — e.g. `doctor --fix`'s plugin-first pairing and
sha256-verified downloads are specified in the variant's comment
(`cli_types.rs:L236-L256`).

`live` is the flagship: it runs the auto pipeline and the web review server
as two tasks in one process, joined by the progress-event broadcast channel —
the lifecycle is documented in `docs/data_flow.md`.

### 9.2 One event vocabulary, three consumers

Every stage emits `ProgressEvent`s into a `TranslationEvents` broadcast
channel (capacity 256). The same events feed:

1. the web dashboard's in-memory `ProgressState`
   (`server/mod.rs:L475-L755` — `on_event` folds the stream into per-unit
   entries),
2. the WebSocket fan-out (`events.rs`, the 307-incoming-edge hotspot of the
   repo), and
3. the heartbeat/scan-pass machinery (Chapter 2.1).

Events are fire-and-forget (`let _ = em.emit(…)`): observability must never
fail a translation. The flip side is documented as a known hazard — lenient
observability defaults can mask failure — which is why the *persisted* logs
(Chapter 11), not the events, are the audit trail.

### 9.3 The web server is two routers over one state

`build_router` (`server/mod.rs:L1139-L1147`) composes `shared_routes` and
`live_only_routes` (`server/mod.rs:L866-L1115`) behind an axum `Router` with
a `CombinedState`. `serve` mode is read-only over existing artifacts
(ADR-0006); `live` mode adds the action routes — `accept_unit`,
`send_back_unit`, `request_patch` (`actions.rs:L232-L513`) — where
`request_patch` spawns a reviewer-steered retry: the reviewer's hints seed
the retry loop's failure history (Chapter 6.1) and the new attempt lands on a
fresh attempt branch.

---

## 10. The evidence engines

Thirteen crates under `crates/evidence/` each answer one question about the
binary, all reading the *loaded program* through the `ScanSource` seam and
writing JSON documents into the workspace's `re/analysis/` tree. In the
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
| `calxgloss-consts` | Which constants and enums are real? (bitflags, magic numbers) |
| `calxgloss-callback` | Where are function-pointer tables and jump-table dispatches? |
| `calxgloss-controlflow` | Which if-else chains are switches or state machines? |
| `calxgloss-stringctx` | What do the strings mean? (nine-category classification, format strings) |
| `calxgloss-apidetect` | Which third-party library is this? (import-table fingerprinting → crate mapping) |
| `calxgloss-serialize` | Where is endianness/serialization logic? (byte swaps, magic bytes) |
| `calxgloss-libmatch` | Which functions are statically linked library code? (body-shape signatures → CRT/STL symbols) |
| `calxgloss-errhandling` | Which functions guard their work in an exception frame? (spelled `try`/`catch` blocks → the error-handling idiom and its Rust mapping) |

They share two pieces of plumbing from `calxgloss-types`: `ScanMetadata` —
the provenance header stamped on every cached scan JSON (`scan.rs:L19-L48`) —
and the JSON persistence helpers (`persist.rs`). Their findings ride into
prompts through the tier machinery of Chapter 1.4: data structures, control
flow findings, and shim layers are extracted from the cached JSON at prompt
build time (`retry/helpers.rs`).

The shim path deserves one note: for `MicrosoftSdk`/`KnownThirdParty` DLLs,
`calxgloss-analysis`'s `shim_pipeline` proposes replacing the whole DLL with a
Rust crate plus a thin adapter layer. The contract is positional —
`ShimApiMapping` keeps `original_params`, `crate_params`, and
`parameter_transforms` index-synchronized (`shim.rs:L56-L96`) — and the
adapter is verified with the same `Verifier` machinery (Chapter 5,
`verify_shim`).

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
  successes, attempts, pass rate. This is the A/B evidence for the escalation
  ladder in Chapter 6.2.

All three cap retained entries (`MAX_LOG_ENTRIES = 10_000`,
`lib.rs:L54`) by *trimming into a summary block* rather than dropping data —
`compute_stats` covers trimmed entries, so a truncated file still yields
honest statistics (tests at `fault.rs:L996-L1058`,
`experiment_log.rs:L553-L616`).

---

## Epilogue: the invariants to hold in your head

1. **The triple `(dll, function, attempt)` is everywhere.** Branch names,
   logs, events, review records. Rename it in one place and the audit trail
   silently unjoins.
2. **Generation and judgment are separate.** `translate` produces code;
   `Verifier` judges it; the retry loop is the only thing that couples them.
3. **Every failure is data.** Failed attempts get branches, faults get
   events, prompt variants get experiment entries. The system is designed to
   be *read after the fact* as much as run.
4. **Degrade, don't die.** Call-graph build fails → translate without
   enrichment. Evidence scan fails → batch continues. Event emit fails →
   translation continues. Only the LLM call itself and git commits are
   allowed to be fatal.
5. **The human is in the loop by construction.** Reviewer overrides force
   tiers and strategies; reviewer hints ride into prompts; acceptance is a
   git merge with conflict detection. The machine proposes; `main` decides.

*Further reading:* `docs/Calxgloss.md` (design), `docs/data_flow.md`
(the `live` workflow end to end), `docs/adr/` (the thirty-eight decisions),
`GLOSSARY-MAP.md` (the domain vocabulary per context), and `graft/` (the
generated per-file wiring cards this tour was built from).
