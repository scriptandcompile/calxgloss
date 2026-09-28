# Calxgloss MVP — Step-by-Step Plan

## Objective

Prove the core concept: **can an LLM reliably translate disassembled functions to Rust that passes behavior tests?**

MVP scope: Translate a single function from a single DLL from disassembly to working Rust that compiles and passes baseline tests.

MVP exclusions: No web UI (scaffolded only), no fault detection, no context tiers, no dependency-aware branching, no shim layer infrastructure.

---

## Workspace Architecture

The MVP is a Cargo workspace with separate crates for each concern. The library crates are designed to be reusable in the full system (with web UI, fault detection, etc.).

```
calxgloss/
├── Cargo.toml                    # Workspace manifest
├── crates/
│   ├── calxgloss-ghidra/         # GhidraMCP client — talks to Ghidra server
│   ├── calxgloss-llm/            # LLM client — talks to local LLM (Ollama/vLLM)
│   ├── calxgloss-types/          # Shared types — DLL, Function, TestCase, etc.
│   ├── calxgloss-analysis/       # DLL classification, call graph analysis, API tagging
│   ├── calxgloss-testgen/        # FFI stubs, test input generation, baseline execution
│   ├── calxgloss-translator/     # Translation pipeline — Ghidra + LLM + prompt orchestration
│   ├── calxgloss-verify/         # Compile, test, compare against baseline
│   ├── calxgloss-git/            # Git branch/commit/merge automation
│   ├── calxgloss-prompts/        # Prompt templates and rendering
│   ├── calxgloss-pal/            # Platform Abstraction Layer — minimal MVP mappings
│   ├── calxgloss-reports/        # Terminal output formatting (MVP review UI)
│   ├── calxgloss/                # Core library — re-exports all public APIs
│   ├── calxgloss-cli/            # CLI binary — wires everything together
│   └── calxgloss-web/            # Web UI — scaffolded, not implemented in MVP
└── tests/                        # Workspace-level integration tests
    └── e2e/                      # End-to-end test on a sample DLL
```

### Crate Dependency Graph

```
calxgloss-cli
  ├── calxgloss (meta-lib)
  │     ├── calxgloss-ghidra
  │     ├── calxgloss-llm
  │     ├── calxgloss-types
  │     ├── calxgloss-analysis
  │     ├── calxgloss-testgen
  │     ├── calxgloss-translator
  │     ├── calxgloss-verify
  │     ├── calxgloss-git
  │     ├── calxgloss-prompts
  │     ├── calxgloss-pal
  │     └── calxgloss-reports
  ├── calxgloss-ghidra
  ├── calxgloss-analysis
  ├── calxgloss-testgen
  ├── calxgloss-translator
  ├── calxgloss-verify
  ├── calxgloss-git
  └── calxgloss-reports
```

Detailed dependency graph:
```
calxgloss-types (types crate, no deps on other workspace crates)
calxgloss-ghidra — depends on: calxgloss-types
calxgloss-llm — depends on: calxgloss-types
calxgloss-prompts — depends on: calxgloss-types
calxgloss-pal — depends on: calxgloss-types
calxgloss-analysis — depends on: calxgloss-types, calxgloss-ghidra
calxgloss-testgen — depends on: calxgloss-types, calxgloss-ghidra
calxgloss-translator — depends on: calxgloss-types, calxgloss-ghidra, calxgloss-llm, calxgloss-prompts, calxgloss-pal, calxgloss-testgen
calxgloss-verify — depends on: calxgloss-types
calxgloss-git — depends on: calxgloss-types
calxgloss-reports — depends on: calxgloss-types
calxgloss (meta-lib) — re-exports all workspace crates
calxgloss-cli — depends on: calxgloss + direct deps on ghidra, analysis, testgen, translator, verify, git, reports
calxgloss-web — depends on: calxgloss-types (scaffolded only in MVP)
```

---

## Step 1: Scaffold the Cargo Workspace

**Duration:** 0.5 days

1. Create workspace root with `Cargo.toml`:
   ```toml
   [workspace]
   resolver = "2"
   members = [
       "crates/calxgloss-types",
       "crates/calxgloss-ghidra",
       "crates/calxgloss-llm",
       "crates/calxgloss-analysis",
       "crates/calxgloss-testgen",
       "crates/calxgloss-translator",
       "crates/calxgloss-verify",
       "crates/calxgloss-git",
       "crates/calxgloss-prompts",
       "crates/calxgloss-pal",
       "crates/calxgloss-reports",
       "crates/calxgloss",
       "crates/calxgloss-cli",
       "crates/calxgloss-web",
   ]
   ```

2. Create all crate directories with `cargo new --lib` (or `--bin` for CLI):
   ```bash
   for crate in calxgloss-types calxgloss-ghidra calxgloss-llm calxgloss-analysis calxgloss-testgen calxgloss-translator calxgloss-verify calxgloss-git calxgloss-prompts calxgloss-pal calxgloss-reports; do
       cargo new --lib crates/$crate
   done
   cargo new calxgloss-cli crates/calxgloss-cli
   cargo new --lib crates/calxgloss
   cargo new --lib crates/calxgloss-web
   ```

3. Set up shared workspace dependencies in root `Cargo.toml`:
   ```toml
   [workspace.dependencies]
   anyhow = "1"
   thiserror = "2"
   serde = { version = "1", features = ["derive"] }
   serde_json = "1"
   reqwest = { version = "0.12", features = ["json", "streaming"] }
   tokio = { version = "1", features = ["full"] }
   tracing = "0.1"
   tracing-subscriber = { version = "0.3", features = ["env-filter"] }
   git2 = "0.19"
   clap = { version = "4", features = ["derive"] }
   url = "2"
   ```

---

## Step 2: Implement calxgloss-types (Shared Types)

**Duration:** 1 day

**Goal:** Define all shared data structures used across crates.

1. Create `crates/calxgloss-types/src/lib.rs` with core types:

   ```rust
   // DLL analysis
   pub struct DllInfo {
       pub name: String,
       pub version: Option<String>,
       pub category: DllCategory,  // WindowsOS, MicrosoftSDK, ThirdParty, ProjectSpecific, Unknown
       pub exports: Vec<Export>,
       pub imports: Vec<Import>,
   }

   pub enum DllCategory {
       WindowsOs,
       MicrosoftSdk,
       KnownThirdParty,
       ProjectSpecific,
       UnknownThirdParty,
   }

   pub struct Export {
       pub name: String,
       pub r#address: u64,
       pub signature: String,
   }

   pub struct Import {
       pub dll: String,
       pub function: String,
   }

   // Function analysis
   pub struct FunctionInfo {
       pub name: String,
       pub r#address: u64,
       pub dll: String,
       pub disassembly: String,
       pub decompiler_output: String,
       pub windows_apis: Vec<WindowsApiCall>,
       pub call_graph: Vec<String>,
   }

   pub struct WindowsApiCall {
       pub name: String,
       pub category: ApiCategory,  // Win32Core, DirectX, Gdi, Audio, etc.
       pub pal_mapping: String,
   }

   // Test generation
   pub struct TestCase {
       pub inputs: serde_json::Value,
       pub expected_return: serde_json::Value,
       pub expected_side_effects: Vec<SideEffect>,
   }

   pub struct SideEffect {
       pub kind: SideEffectKind,  // FileWrite, RegistryWrite, WindowUpdate, etc.
       pub detail: String,
   }

   pub struct TestResult {
       pub test_case: TestCase,
       pub actual_return: serde_json::Value,
       pub actual_side_effects: Vec<SideEffect>,
       pub passed: bool,
       pub error: Option<String>,
   }

   // Translation
   pub struct TranslationRequest {
       pub dll: String,
       pub function: String,
       pub disassembly: String,
       pub decompiler_output: String,
       pub windows_apis: Vec<WindowsApiCall>,
       pub baseline_tests: Vec<TestCase>,
   }

   pub struct TranslationResult {
       pub rust_code: String,
       pub prompt_used: String,
       pub model: String,
       pub tokens_used: Option<usize>,
   }

   // Verification
   pub struct VerificationResult {
       pub compiled: bool,
       pub compilation_errors: Vec<String>,
       pub tests_passed: usize,
       pub tests_total: usize,
       pub failed_tests: Vec<FailedTest>,
   }

   pub struct FailedTest {
       pub test_index: usize,
       pub inputs: serde_json::Value,
       pub expected: serde_json::Value,
       pub actual: serde_json::Value,
       pub error: String,
   }

   // Git
   pub struct GitBranch {
       pub name: String,
       pub dll: String,
       pub function: String,
       pub attempt: u32,
   }

   pub struct GitCommit {
       pub branch: String,
       pub message: String,
       pub hash: String,
       pub files: Vec<String>,
   }
   ```

2. Add `serde` derive for all types (serialization for JSON storage/review).

3. Add `thiserror::Error` implementation for type-specific error types.

---

## Step 3: Implement calxgloss-ghidra (GhidraMCP Client)

**Duration:** 2-3 days

**Goal:** Pull function disassembly, decompiler output, DLL imports/exports from GhidraMCP server.

1. Create `crates/calxgloss-ghidra/src/lib.rs` with `GhidraClient`:

   ```rust
   pub struct GhidraClient {
       base_url: url::Url,
       http: reqwest::Client,
   }

   impl GhidraClient {
       pub fn new(base_url: &str) -> Result<Self>;
       pub async fn get_function(&self, dll: &str, function: &str) -> Result<FunctionInfo>;
       pub async fn get_dll_info(&self, dll: &str) -> Result<DllInfo>;
       pub async fn list_dlls(&self, target_exe: &str) -> Result<Vec<String>>;
       pub async fn get_disassembly(&self, dll: &str, function: &str) -> Result<String>;
       pub async fn get_decompiler(&self, dll: &str, function: &str) -> Result<String>;
       pub async fn get_imports(&self, dll: &str) -> Result<Vec<Import>>;
       pub async fn get_exports(&self, dll: &str) -> Result<Vec<Export>>;
       pub async fn get_call_graph(&self, dll: &str, function: &str) -> Result<Vec<String>>;
   }
   ```

2. The GhidraMCP server exposes an HTTP API. Define the expected endpoints:
   - `POST /sessions/{session}/disassembly` — returns disassembly for a function
   - `POST /sessions/{session}/decompiler` — returns pseudo-C decompiler output
   - `POST /sessions/{session}/imports` — returns imported symbols from a DLL
   - `POST /sessions/{session}/exports` — returns exported symbols from a DLL
   - `POST /sessions/{session}/callgraph` — returns call graph for a function
   - `GET /sessions` — list existing analysis sessions
   - `POST /sessions` — create a new session for a target binary

3. Map GhidraMCP responses to `calxgloss-types` structures.

4. Handle errors: server offline, function not found, session expired, malformed response.

5. Add tracing instrumentation for all network calls.

---

## Step 4: Implement calxgloss-llm (LLM Client)

**Duration:** 2-3 days

**Goal:** Send prompts to local LLM, receive Rust code.

1. Create `crates/calxgloss-llm/src/lib.rs` with `LlmClient`:

   ```rust
   pub struct LlmClient {
       endpoint: url::Url,
       model: String,
       http: reqwest::Client,
   }

   pub struct LlmConfig {
       pub endpoint: String,
       pub model: String,
       pub api_key: Option<String>,
       pub max_tokens: usize,
       pub temperature: f32,
   }

   impl LlmClient {
       pub fn new(config: LlmConfig) -> Result<Self>;
       pub async fn complete(&self, messages: &[LlmMessage]) -> Result<LlmResponse>;
       pub async fn complete_streaming(&self, messages: &[LlmMessage]) -> Result<Stream<LlmChunk>>;
   }

   pub struct LlmMessage {
       pub role: MessageRole,  // User, Assistant, System
       pub content: String,
   }

   pub struct LlmResponse {
       pub content: String,
       pub model: String,
       pub tokens_used: Option<usize>,
   }
   ```

2. Uses `reqwest` to call an OpenAI-compatible API (Ollama, vLLM, llama.cpp, etc.):
   ```json
   {
       "model": "qwen3-235b-a22b",
       "messages": [{"role": "user", "content": "..."}],
       "max_tokens": 8192,
       "temperature": 0.1
   }
   ```

3. Add a response validator:
   - Strip markdown code fences if present
   - Light-weight syntax check using `syn` crate (optional, can be deferred)
   - Return raw Rust code string

4. Add `reqwest` and `serde` as dependencies.

---

## Step 5: Implement calxgloss-prompts (Prompt Templates)

**Duration:** 0.5 days

**Goal:** Define and render prompt templates for translation tasks.

1. Create `crates/calxgloss-prompts/src/lib.rs`:

   ```rust
   pub struct PromptTemplate {
       pub name: &'static str,
       pub template: &'static str,
   }

   pub const TRANSLATE_TEMPLATE: &PromptTemplate = &PromptTemplate {
       name: "translate",
       template: include_str!("templates/translate.j2"),
   };

   pub fn render(template: &PromptTemplate, vars: &[(&str, &str)]) -> Result<String>;
   pub fn build_translate_prompt(req: &TranslationRequest, api_mappings: &ApiMappings) -> Result<String>;
   ```

2. Create `crates/calxgloss-prompts/src/templates/translate.j2`:
   ```jinja2
   You are a reverse engineering specialist. Translate the following function from assembly to Rust.

   ORIGINAL FUNCTION: {{ function_name }}
   SOURCE DLL: {{ dll_name }}
   DISASSEMBLY:
   {{ disassembly }}

   DECOMPILER OUTPUT (pseudo-C):
   {{ decompiler_output }}

   WINDOWS API CALLS IDENTIFIED:
   {% for api in windows_apis %}
   - {{ api.name }} -> {{ api.pal_mapping }}
   {% endfor %}

   BASELINE TESTS (must pass):
   {% for test in test_cases %}
   Input: {{ test.inputs }}
   Expected return: {{ test.expected_return }}
   {% endfor %}

   REQUIREMENTS:
   - Output ONLY valid Rust code
   - Use standard library for Win32 calls (std::fs, std::thread, etc.)
   - For DirectX calls, use placeholder trait methods (PAL pattern)
   - Preserve function signature with FFI-compatible types
   - Do NOT include explanations, comments outside the function, or markdown fences

   RUST CODE:
   ```

3. Use `include_str!` for template embedding. For MVP, use manual string replacement or a lightweight templating approach. For the full system, this would use `askama` or `liquid`.

4. This crate is the right place for prompt templates because:
   - Prompts are reusable across LLM backends
   - Templates are independent of network/HTTP concerns
   - Template changes don't require rebuilding the LLM client

---

## Step 6: Implement calxgloss-pal (Platform Abstraction Layer)

**Duration:** 1 day

**Goal:** Minimal MVP Windows API → Rust equivalent mapping table.

1. Create `crates/calxgloss-pal/src/lib.rs`:

   ```rust
   pub struct ApiMappings(&'static [ApiMapping]);

   pub struct ApiMapping {
       pub windows_api: &'static str,
       pub category: ApiCategory,
       pub rust_equivalent: &'static str,
       pub notes: &'static str,  // e.g., "PAL placeholder — not yet implemented"
   }

   impl ApiMappings {
       pub fn lookup(&self, api: &str) -> Option<&ApiMapping>;
       pub fn for_category(&self, category: ApiCategory) -> &[ApiMapping];
   }
   ```

2. Populate mappings for MVP-relevant APIs:
   ```rust
   // Win32 Core → std lib
   ("CreateFile", Win32Core, "std::fs::File::open/open options"),
   ("ReadFile", Win32Core, "std::fs::read / BufReader"),
   ("WriteFile", Win32Core, "std::fs::write / BufWriter"),
   ("CreateThread", Win32Core, "std::thread::spawn"),
   ("Sleep", Win32Core, "std::thread::sleep"),
   ("VirtualAlloc", Win32Core, "std::alloc / mmap crate"),
   ("LoadLibrary", Win32Core, "libloading::Library::load"),
   ("CreateMutex", Win32Core, "std::sync::Mutex"),
   ("GetTickCount", Win32Core, "std::time::Instant"),

   // GDI → tiny-skia (PAL placeholder for MVP)
   ("BitBlt", Gdi, "tiny_skia::Pixmap::blit_rect [PAL placeholder]"),
   ("TextOut", Gdi, "tiny_skia::Pixmap::draw_string [PAL placeholder]"),

   // DirectX → wgpu (PAL placeholder for MVP)
   ("Direct3DCreate9", DirectX, "wgpu::Instance [PAL placeholder]"),
   ("CreateDevice", DirectX, "wgpu::Instance::request_device [PAL placeholder]"),
   ("Present", DirectX, "wgpu::Queue::submit [PAL placeholder]"),
   ```

3. This is intentionally minimal for MVP. The full system would have platform-specific implementations behind feature flags.

---

## Step 7: Implement calxgloss-analysis (DLL Classification & Analysis)

**Duration:** 2-3 days

**Goal:** Classify DLLs, extract call graphs, tag Windows API calls.

1. Create `crates/calxgloss-analysis/src/lib.rs`:

   ```rust
   pub struct Analyzer {
       ghidra: GhidraClient,
       api_mappings: ApiMappings,
   }

   impl Analyzer {
       pub fn new(ghidra: GhidraClient, api_mappings: ApiMappings) -> Self;
       pub async fn classify_dll(&self, dll: &str) -> Result<DllClassification>;
       pub async fn classify_target(&self, target_exe: &str) -> Result<Vec<DllClassification>>;
       pub async fn analyze_function(&self, dll: &str, function: &str) -> Result<FunctionAnalysis>;
       pub async fn tag_windows_apis(&self, disassembly: &str, imports: &[Import]) -> Result<Vec<WindowsApiCall>>;
   }

   pub struct DllClassification {
       pub dll: String,
       pub category: DllCategory,
       pub strategy: Strategy,  // Pal, CrateReplacement, ReverseEngineer
       pub exports_count: usize,
       pub imports_count: usize,
       pub crate_replacement: Option<String>,  // e.g., "wgpu" for d3d9.dll
   }

   pub enum Strategy {
       PalMapping,
       CrateReplacement { crate_name: String },
       ReverseEngineer,
   }
   ```

2. Classification heuristics:
   - Check DLL name against known Windows OS DLLs (`kernel32.dll`, `user32.dll`, etc.) → `PalMapping`
   - Check DLL name against known Microsoft SDK DLLs (`d3d9.dll`, `d3d11.dll`, `gdi32.dll`) → `CrateReplacement` with known crate
   - Check DLL name against known third-party DLLs (`fmod.dll`, `openal32.dll`, `lua51.dll`) → `CrateReplacement` with known crate
   - Otherwise → `ReverseEngineer`

3. API tagging:
   - Cross-reference disassembly/imports against `calxgloss-pal` mappings
   - Tag each Windows API call found with its category and PAL mapping

4. Call graph extraction:
   - Use `GhidraClient::get_call_graph()` to build function dependency map
   - Store as adjacency list in `FunctionAnalysis`

---

## Step 8: Implement calxgloss-testgen (Test Generation)

**Duration:** 3-4 days

**Goal:** Generate FFI stubs and baseline tests that capture the original function's behavior.

1. Create `crates/calxgloss-testgen/src/lib.rs`:

   ```rust
   pub struct TestGenerator {
       target_dir: PathBuf,
   }

   impl TestGenerator {
       pub fn new(target_dir: &Path) -> Self;
       pub async fn generate_ffi_stub(&self, dll: &str, function: &str, signature: &str) -> Result<String>;
       pub async fn generate_test_inputs(&self, signature: &str, disassembly: &str) -> Result<Vec<TestCase>>;
       pub async fn run_baseline_tests(&self, dll: &str, function: &str, tests: &[TestCase]) -> Result<Vec<TestResult>>;
   }
   ```

2. FFI stub generation:
   - Take the function's exported signature from Ghidra analysis (`FunctionInfo`)
   - Generate a Rust `extern "C"` block that links against the original DLL
   - Example output:
     ```rust
     extern "C" {
         fn DrawSprite(x: i32, y: i32, texture_index: u32) -> i32;
     }
     ```

3. Test input generation:
   - Parse function signature to identify parameter types
   - Generate diverse test inputs:
     - Boundary values: 0, -1, i32::MAX, i32::MIN, null pointers
     - Typical values: small positive integers, common string inputs
     - Edge cases from disassembly: if function has `cmp eax, 0` check, include zero and near-zero values
   - Target: 10-20 test inputs per function

4. Baseline test execution:
   - Compile the FFI stub + test harness as a temporary Rust project
   - Link against the original DLL (copy from source directory)
   - Run each test case, capture return value and side effects
   - Store results as `Vec<TestResult>`

5. Output baseline data to `re/baseline/{dll}/{function}.json` in the resultant directory.

---

## Step 9: Implement calxgloss-translator (Translation Pipeline)

**Duration:** 2-3 days

**Goal:** Wire together GhidraMCP → LLM → Rust code.

1. Create `crates/calxgloss-translator/src/lib.rs`:

   ```rust
   pub struct Translator {
       ghidra: GhidraClient,
       llm: LlmClient,
       prompts: PromptLibrary,
       api_mappings: ApiMappings,
   }

   pub struct TranslationPipeline {
       ghidra: GhidraClient,
       analyzer: Analyzer,
       testgen: TestGenerator,
       llm: LlmClient,
       prompts: PromptLibrary,
       api_mappings: ApiMappings,
   }

   impl TranslationPipeline {
       pub async fn translate(&self, target_exe: &Path, dll: &str, function: &str) -> Result<Translation>;
   }

   pub struct Translation {
       pub dll: String,
       pub function: String,
       pub rust_code: String,
       pub prompt_used: String,
       pub model: String,
       pub baseline_tests: Vec<TestCase>,
   }
   ```

2. Translation pipeline flow:
   a. Call `GhidraClient::get_function(dll, function)` → `FunctionInfo`
   b. Call `Analyzer::tag_windows_apis(disassembly, imports)` → `Vec<WindowsApiCall>`
   c. Call `TestGenerator::run_baseline_tests(dll, function, ...)` → `Vec<TestResult>`
   d. Build prompt using `PromptLibrary::build_translate_prompt(function_info, api_mappings, baseline_tests)`
   e. Send prompt to LLM → `LlmResponse { content: rust_code }`
   f. Return `Translation` with code, prompt, model name, and baseline tests

3. The `Translator` struct is a simpler version for direct use; `TranslationPipeline` includes the `Analyzer` for full end-to-end flow.

---

## Step 10: Implement calxgloss-verify (Verification)

**Duration:** 1-2 days

**Goal:** Compile the Rust code, run tests, compare against baseline.

1. Create `crates/calxgloss-verify/src/lib.rs`:

   ```rust
   pub struct Verifier {
       work_dir: PathBuf,
   }

   impl Verifier {
       pub fn new(work_dir: &Path) -> Self;
       pub async fn compile(&self, rust_code: &str, dll: &str, function: &str) -> Result<CompileResult>;
       pub async fn verify(&self, rust_code: &str, dll: &str, function: &str, baseline: &[TestCase]) -> Result<VerificationResult>;
   }

   pub struct CompileResult {
       pub success: bool,
       pub errors: Vec<String>,
       pub warnings: Vec<String>,
   }
   ```

2. Compilation step:
   - Write the Rust code to a temporary module in a scratch Cargo project
   - Run `cargo check` via `std::process::Command`
   - Parse output for errors and warnings

3. Test execution step:
   - Generate a test harness that imports the translated function
   - For each baseline test case, invoke the Rust function with the same inputs
   - Compare outputs against baseline expected values
   - Record pass/fail with failure details

4. Returns `VerificationResult` with compilation status, test pass count, and detailed failure info.

---

## Step 11: Implement calxgloss-git (Git Automation)

**Duration:** 1-2 days

**Goal:** Create branches, commit work, merge on success.

1. Create `crates/calxgloss-git/src/lib.rs`:

   ```rust
   pub struct GitManager {
       repo_path: PathBuf,
   }

   impl GitManager {
       pub fn new(repo_path: &Path) -> Result<Self>;
       pub fn create_branch(&self, dll: &str, function: &str, attempt: u32) -> Result<GitBranch>;
       pub fn commit(&self, branch: &GitBranch, message: &str, files: &[&str]) -> Result<GitCommit>;
       pub fn merge_to_main(&self, branch: &GitBranch) -> Result<()>;
       pub fn current_branch(&self) -> Result<String>;
       pub fn list_branches(&self) -> Result<Vec<String>>;
       pub fn init_repo(&self, target_name: &str) -> Result<()>;
   }
   ```

2. Branch naming: `re/{dll_without_dotdll}/{function}/v{N}`
    - Example: `re/game_logic/DrawSprite/v1`

3. On translation success:
   - Create branch → commit → merge to `main`

4. On translation failure:
   - Keep branch, do not merge
    - Store failure details in `re/patches/{dll}/{function}/v{N}.diff`

5. Uses `git2` crate for git operations.

---

## Step 12: Implement calxgloss-reports (Terminal Output)

**Duration:** 0.5 days

**Goal:** Format results for human review via terminal.

1. Create `crates/calxgloss-reports/src/lib.rs`:

   ```rust
   pub fn print_translation_summary(translation: &Translation);
   pub fn print_verification_results(result: &VerificationResult);
   pub fn print_git_status(branch: &GitBranch, merged: bool);
   pub fn print_success(branch: &GitBranch, verification: &VerificationResult) -> bool;
   pub fn print_failure(branch: &GitBranch, verification: &VerificationResult);
   pub fn prompt_acceptance() -> bool;
   ```

2. Output format for successful translation:
   ```
   Translation of DrawSprite (game_logic.dll):
     Compiled: yes
     Tests: 18/20 passed
      Failed: test_input_7 (expected 42, got 43), test_input_15 (panicked)
      Branch: re/game_logic/DrawSprite/v1
      Status: PASS (with warnings)

   Accept (y/n): y
   ```

3. Output format for failed translation:
   ```
   Translation of DrawSprite (game_logic.dll):
     Compiled: no
     Errors:
       error[E0308]: mismatched types
         --> src/modules/game_logic/DrawSprite.rs:23:5
          |
       23 |     return texture_index;
           |     ^^^^^^^^^^^^^^^^^^^^ expected `()`, found `u32`

      Branch: re/game_logic/DrawSprite/v1
      Status: FAIL - fix required

   Accept (y/n): n
   ```

4. Uses `anstyle` or `colored` crate for terminal colors (optional, MVP can be plain text).

---

## Step 13: Implement calxgloss (Meta-Lib)

**Duration:** 0.5 days

**Goal:** Re-export all public APIs from workspace crates for convenient single-crate dependency.

1. Create `crates/calxgloss/src/lib.rs`:
   ```rust
   pub use calxgloss_types::*;
   pub use calxgloss_ghidra::*;
   pub use calxgloss_llm::*;
   pub use calxgloss_prompts::*;
   pub use calxgloss_pal::*;
   pub use calxgloss_analysis::*;
   pub use calxgloss_testgen::*;
   pub use calxgloss_translator::*;
   pub use calxgloss_verify::*;
   pub use calxgloss_git::*;
   pub use calxgloss_reports::*;
   ```

2. This allows users of the library to do:
   ```rust
   use calxgloss::{GhidraClient, LlmClient, TranslationPipeline, Verifier};
   ```

3. Add workspace crate dependencies in `Cargo.toml`:
   ```toml
   [dependencies]
   calxgloss-types = { path = "../calxgloss-types" }
   calxgloss-ghidra = { path = "../calxgloss-ghidra" }
   calxgloss-llm = { path = "../calxgloss-llm" }
   calxgloss-prompts = { path = "../calxgloss-prompts" }
   calxgloss-pal = { path = "../calxgloss-pal" }
   calxgloss-analysis = { path = "../calxgloss-analysis" }
   calxgloss-testgen = { path = "../calxgloss-testgen" }
   calxgloss-translator = { path = "../calxgloss-translator" }
   calxgloss-verify = { path = "../calxgloss-verify" }
   calxgloss-git = { path = "../calxgloss-git" }
   calxgloss-reports = { path = "../calxgloss-reports" }
   ```

---

## Step 14: Implement calxgloss-cli (CLI Binary)

**Duration:** 2-3 days

**Goal:** Wire everything together into a working CLI.

1. Create `crates/calxgloss-cli/src/main.rs` with `clap` argument parsing:
   ```rust
   #[derive(Parser)]
   #[command(name = "calxgloss", about = "Reverse Engineering Harness")]
   struct Cli {
       #[command(subcommand)]
       command: Command,
   }

   #[derive(Subcommand)]
   enum Command {
       /// Classify DLLs for a target executable
       Classify {
           #[arg(long)]
           target: PathBuf,
           #[arg(long, default_value = "http://localhost:8080")]
           ghidra_url: String,
       },
       /// Translate a single function from disassembly to Rust
       Translate {
           #[arg(long)]
           target: PathBuf,
           #[arg(long)]
           dll: String,
           #[arg(long)]
           function: String,
           #[arg(long, default_value = "http://localhost:8080")]
           ghidra_url: String,
           #[arg(long, default_value = "http://localhost:8081/v1")]
           llm_url: String,
           #[arg(long, default_value = "qwen3-235b-a22b")]
           llm_model: String,
           #[arg(long)]
           output_dir: Option<PathBuf>,
       },
       /// Verify a previously translated function
       Verify {
           #[arg(long)]
           dll: String,
           #[arg(long)]
           function: String,
           #[arg(long)]
           rust_source: PathBuf,
       },
   }
   ```

2. Implement `translate` command handler:
   ```rust
   async fn handle_translate(cmd: TranslateArgs) -> Result<()> {
       // 1. Initialize components
       let ghidra = GhidraClient::new(&cmd.ghidra_url)?;
       let llm = LlmClient::new(LlmConfig {
           endpoint: cmd.llm_url,
           model: cmd.llm_model,
           ..Default::default()
       })?;
       let api_mappings = ApiMappings::default();
       let analyzer = Analyzer::new(ghidra.clone(), api_mappings);
       let testgen = TestGenerator::new(&cmd.target);
       let prompts = PromptLibrary::default();
       let pipeline = TranslationPipeline::new(ghidra, analyzer, testgen, llm, prompts, api_mappings);

       // 2. Run translation
       let translation = pipeline.translate(&cmd.target, &cmd.dll, &cmd.function).await?;

       // 3. Write translated code
       let output_dir = cmd.output_dir.unwrap_or_else(|| cmd.target.clone());
       write_rust_code(&output_dir, &translation)?;

       // 4. Verify
       let verifier = Verifier::new(&output_dir);
       let verification = verifier.verify(&translation.rust_code, &cmd.dll, &cmd.function, &translation.baseline_tests).await?;

       // 5. Git automation
       let git = GitManager::new(&output_dir)?;
       let branch = git.create_branch(&cmd.dll, &cmd.function, 1)?;
       git.commit(&branch, &format!("re/{}: translate {} (attempt 1)", cmd.dll, cmd.function), &["src/modules/"])
           .await?;

       // 6. Report
       if verification.tests_passed == verification.tests_total {
           git.merge_to_main(&branch).await?;
           reports::print_success(&branch, &verification);
       } else {
           reports::print_failure(&branch, &verification);
       }

       Ok(())
   }
   ```

3. Implement `classify` command handler:
   - Initialize Ghidra client and analyzer
   - For each DLL in target's import table, classify and print report

4. Add `tracing-subscriber` for CLI logging (configurable via `RUST_LOG` env var).

---

## Step 15: Implement calxgloss-web (Web UI Scaffold)

**Duration:** 0.5 days

**Goal:** Scaffold the web UI crate for future use. Not implemented in MVP.

1. Create `crates/calxgloss-web/src/lib.rs`:
   ```rust
   // MVP: empty lib, future work
   // This crate will house the review UI (axum + leptos/dioxus or actix-web + svelte)
   // For MVP, review happens via terminal (calxgloss-reports)

   pub struct ReviewDashboard;
   pub struct UnitOfWork;
   pub struct DependencyGraph;

   // TODO: Implement web UI in post-MVP
   ```

2. Placeholder `Cargo.toml` with future dependencies:
   ```toml
   [dependencies]
   calxgloss-types = { path = "../calxgloss-types" }
   axum = { version = "0.8", optional = true }
   leptos = { version = "0.7", optional = true }
   ```

3. Mark web UI features as optional so the MVP builds without them.

---

## Step 16: End-to-End Testing on Sample DLL

**Duration:** 2-3 days

**Goal:** Translate one complete function from a sample DLL, from GhidraMCP to merged git commit.

1. Select a simple sample DLL:
   - Low function complexity
   - Few external dependencies
   - Clear input/output behavior (not graphics/audio)
   - Example: a utility DLL with math/string/manipulation functions

2. Run the full pipeline:
   ```bash
   cargo run --bin calxgloss-cli -- translate \
       --target myapp.exe \
       --dll sample_util.dll \
       --function CalculateHash \
       --ghidra-url http://localhost:8080 \
       --llm-url http://localhost:8081/v1 \
       --llm-model qwen3-235b-a22b
   ```

3. Verify:
   - Disassembly pulled successfully from GhidraMCP
   - DLL classified correctly
   - Baseline tests generated and run against original DLL
   - LLM produces compilable Rust code
   - Rust code passes baseline tests
   - Git branch created and merged to main
   - Terminal output is readable and informative

4. If failures occur:
   - Analyze why (LLM produced invalid code? tests insufficient? compilation errors?)
   - Adjust prompt, test generation, or error handling
   - Retry

5. Add workspace-level integration test in `tests/e2e/`:
   ```rust
   #[tokio::test]
   #[ignore] // requires GhidraMCP + LLM server running
   async fn e2e_translate_sample_function() {
       // Spins up local test infrastructure
       // Runs translate pipeline on known-good sample
       // Asserts translation compiles and passes tests
   }
   ```

---

## MVP Success Criteria

| Criterion | Threshold |
|-----------|-----------|
| Function translated to Rust | Compiles without errors |
| Baseline tests generated | ≥ 10 test inputs per function |
| Test pass rate | ≥ 90% on first successful attempt |
| Git commit | Every translated function has a branch + commit |
| Manual review | Human can read diff and test output to judge correctness |
| End-to-end | One complete translation from GhidraMCP to merged git commit |
| Workspace builds | `cargo build --workspace` succeeds with all crates |

---

## Total Estimated Timeline

| Step | Crate | Duration |
|------|-------|----------|
| 1. Scaffold workspace | All | 0.5 days |
| 2. Shared types | `calxgloss-types` | 1 day |
| 3. GhidraMCP client | `calxgloss-ghidra` | 2-3 days |
| 4. LLM client | `calxgloss-llm` | 2-3 days |
| 5. Prompt templates | `calxgloss-prompts` | 0.5 days |
| 6. PAL mappings | `calxgloss-pal` | 1 day |
| 7. DLL classification | `calxgloss-analysis` | 2-3 days |
| 8. Test generation | `calxgloss-testgen` | 3-4 days |
| 9. Translation pipeline | `calxgloss-translator` | 2-3 days |
| 10. Verification | `calxgloss-verify` | 1-2 days |
| 11. Git automation | `calxgloss-git` | 1-2 days |
| 12. Terminal reports | `calxgloss-reports` | 0.5 days |
| 13. Meta-lib | `calxgloss` | 0.5 days |
| 14. CLI binary | `calxgloss-cli` | 2-3 days |
| 15. Web UI scaffold | `calxgloss-web` | 0.5 days |
| 16. E2E testing | All | 2-3 days |
| **Total** | | **~22-32 days (~3-4 weeks)** |

---

## Crate Summary

| Crate | Type | Purpose | MVP Status |
|-------|------|---------|------------|
| `calxgloss-types` | Library | Shared data structures | Required |
| `calxgloss-ghidra` | Library | GhidraMCP HTTP client | Required |
| `calxgloss-llm` | Library | Local LLM client (Ollama/vLLM) | Required |
| `calxgloss-prompts` | Library | Prompt templates | Required |
| `calxgloss-pal` | Library | Windows API → Rust mappings | Required |
| `calxgloss-analysis` | Library | DLL classification, call graphs, API tagging | Required |
| `calxgloss-testgen` | Library | FFI stubs, test inputs, baseline execution | Required |
| `calxgloss-translator` | Library | Ghidra → LLM → Rust pipeline + batch translation | Required |
| `calxgloss-verify` | Library | Compile and test verification | Required |
| `calxgloss-git` | Library | Git branch/commit/merge automation | Required |
| `calxgloss-reports` | Library | Terminal output formatting (including batch summaries) | Required |
| `calxgloss` | Library | Re-exports all public APIs | Required |
| `calxgloss-cli` | Binary | CLI entry point with `translate` and `batch-translate` commands | Required |
| `calxgloss-web` | Library | Web review UI (axum + leptos) | Scaffolded only |

---

## What's NOT in MVP (Post-MVP Features)

| Feature | When to Add |
|---------|-------------|
| Web UI implementation | After MVP proves the loop is reliable |
| Fault detection | After MVP, when scaling to many functions |
| Context tiers | When functions get too large for one prompt |
| Dependency-aware branching | After MVP, when translating multi-function DLLs |
| Shim layer infrastructure | After MVP, when replacing DirectX/GDI |
| Retry logic | After MVP, to reduce human overhead |
| Confidence scoring | After MVP, for large-scale review |
| Branch cleanup | After MVP, when history gets messy |
| CI/CD integration | After MVP, for production readiness |

---

## Post-MVP Extension Roadmap

Once the MVP proves the core loop works, add features in this order:

1. **Retry logic** — automatic retry with different prompts on test failure (`calxgloss-translator`)
2. **Prompt template refinement** — refine prompts based on what works (`calxgloss-prompts`)
3. **Batch translation** — translate all functions in a DLL (✅ implemented)
4. **Simple dependency tracking** — link branches when one function calls another (`calxgloss-git`)
5. **Terminal-based review dashboard** — text-based UI showing queue, status, test results (`calxgloss-reports`)
6. **Shim layer generation** — start replacing DirectX/GDI with crate equivalents (`calxgloss-analysis`)
7. **Web UI** — replace terminal review with proper interface (`calxgloss-web`)
8. **Context tiers** — optimize token usage for large functions (`calxgloss-llm`, `calxgloss-translator`)
9. **Fault detection** — automate recovery from common LLM failures (new `calxgloss-faults` crate)
10. **CI integration** — add cross-platform verification builds (`calxgloss-verify`)
