//! Retry logic for the translation pipeline.
//!
//! When the LLM's first translation attempt fails verification, this module
//! provides a structured retry loop that feeds compilation errors or failing
//! test cases back to the LLM with targeted fix prompts.
//!
//! # Flow
//!
//! 1. Initial translation via the normal pipeline
//! 2. Verify the generated Rust code
//! 3. If verification fails, build a fix prompt with error details
//! 4. Send the fix prompt to the LLM
//! 5. Repeat up to `max_attempts` times
//!
//! # Strategies
//!
//! - **Default** — re-send the same prompt (useful when the first attempt was
//!   an LLM hiccup or network glitch)
//! - **CompileFix** — feed compilation errors back to the LLM with a targeted
//!   "fix these errors" prompt
//! - **TestFix** — compilation passed but behavioral tests failed; feed the
//!   failing test cases back with a "fix these test cases" prompt
//! - **Escalate** — add more context from disassembly (call graph neighbors,
//!   neighboring functions, data structures, type info) and try again
//! - **EdgeCaseFix** — compilation passed, tests failed specifically on
//!   boundary values (zero, max, negative); feed a boundary-aware fix prompt
//!
//! # Strategy Selection
//!
//! The user can request a specific strategy, or choose `Auto` which cycles
//! through `[compile_fix → test_fix → escalate → edge_case_fix]` on each
//! failure.

use crate::Translation;
use askama::Template;
use calxgloss_ghidra::GhidraClient;
use calxgloss_llm::{LlmClient, LlmMessage};
use calxgloss_prompts::{
    CallGraphNeighbor, EdgeCaseTest, NeighborFunction, StructuredData, TypeInfo,
};
use calxgloss_types::FailureHint;
use calxgloss_verify::{CompileResult, Verifier};
use tracing::{info, warn};

// ============================================================
// Public types
// ============================================================

/// Configuration for translation retry behavior.
#[derive(Debug, Clone)]
pub struct RetryConfig {
    /// Maximum number of total attempts (including the first).
    pub max_attempts: u32,

    /// The strategy to use on the first retry attempt.
    pub strategy: RetryStrategy,

    /// Whether to escalate context on subsequent failures.
    pub escalate_on_failure: bool,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            strategy: RetryStrategy::CompileFix,
            escalate_on_failure: true,
        }
    }
}

/// The strategy for fixing a failed translation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RetryStrategy {
    /// Default — re-send the same prompt (first attempt only).
    Default,
    /// Feed compilation errors back to the LLM for a targeted fix.
    CompileFix,
    /// Compilation passed but tests failed; feed failing test cases back.
    TestFix,
    /// Add more context from disassembly and try again.
    Escalate,
    /// Compilation passed but tests failed specifically on boundary values;
    /// feed a boundary-aware fix prompt.
    EdgeCaseFix,
}

impl std::fmt::Display for RetryStrategy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Default => write!(f, "default"),
            Self::CompileFix => write!(f, "compile_fix"),
            Self::TestFix => write!(f, "test_fix"),
            Self::Escalate => write!(f, "escalate"),
            Self::EdgeCaseFix => write!(f, "edge_case_fix"),
        }
    }
}

/// The sequence of strategies to try when using auto mode.
///
/// Each strategy is tried in order; on failure the next one in the cycle is used.
pub const AUTO_STRATEGY_CYCLE: &[RetryStrategy] = &[
    RetryStrategy::CompileFix,
    RetryStrategy::TestFix,
    RetryStrategy::Escalate,
    RetryStrategy::EdgeCaseFix,
];

/// Details about a single translation attempt.
#[derive(Debug, Clone)]
pub struct TranslationAttempt {
    /// The attempt number (1-based).
    pub attempt: u32,

    /// The generated Rust code.
    pub rust_code: String,

    /// Whether this attempt compiled.
    pub compiled: bool,

    /// Compilation error messages, if any.
    pub compilation_errors: Vec<String>,

    /// Number of tests that passed.
    pub tests_passed: usize,

    /// Total number of tests.
    pub tests_total: usize,

    /// The failing test cases, if any.
    pub failed_tests: Vec<String>,

    /// The retry strategy used for this attempt (0 = initial, 1+ = retry).
    pub strategy: String,

    /// Number of tokens the LLM used for this attempt, if reported.
    pub tokens_used: Option<usize>,
}

impl TranslationAttempt {
    /// Whether this attempt was successful (all tests pass or no tests exist).
    pub fn is_successful(&self) -> bool {
        self.tests_passed == self.tests_total || self.tests_total == 0
    }
}

/// The result of a retry loop.
#[derive(Debug, Clone)]
pub struct RetryResult {
    /// All attempts made, in order.
    pub attempts: Vec<TranslationAttempt>,

    /// Whether the final result is successful.
    pub success: bool,

    /// The successful translation code, if any.
    pub rust_code: Option<String>,

    /// The strategy that produced success, if any.
    pub success_strategy: Option<String>,
}

impl Default for RetryResult {
    fn default() -> Self {
        Self::new()
    }
}

impl RetryResult {
    /// Create a new retry result with no attempts.
    pub fn new() -> Self {
        Self {
            attempts: Vec::new(),
            success: false,
            rust_code: None,
            success_strategy: None,
        }
    }

    /// Append an attempt to the result.
    pub fn add_attempt(&mut self, attempt: TranslationAttempt) {
        if attempt.is_successful() {
            self.success = true;
            self.rust_code = Some(attempt.rust_code.clone());
            self.success_strategy = Some(attempt.strategy.clone());
        }
        self.attempts.push(attempt);
    }
}

// ============================================================
// Retry logic
// ============================================================

/// Build a fix prompt for compilation errors.
pub fn build_compile_fix_prompt(
    function_name: &str,
    dll_name: &str,
    original_rust_code: &str,
    compilation_errors: &[String],
) -> String {
    use calxgloss_prompts::FixTemplate;

    let failure_desc = if compilation_errors.is_empty() {
        "Compilation failed but no error details were captured.".to_string()
    } else {
        format!(
            "The code failed to compile with {} error(s):\n\n{}",
            compilation_errors.len(),
            compilation_errors.join("\n\n")
        )
    };

    let template = FixTemplate::new(
        function_name.to_string(),
        dll_name.to_string(),
        original_rust_code.to_string(),
        failure_desc,
    );
    template.render().unwrap_or_else(|_| {
        format!(
            "Fix the compilation errors:\n{}",
            compilation_errors.join("\n")
        )
    })
}

/// Build a fix prompt for failing behavioral tests.
pub fn build_test_fix_prompt(
    function_name: &str,
    dll_name: &str,
    original_rust_code: &str,
    failed_tests: &[String],
) -> String {
    use calxgloss_prompts::FixTemplate;

    let failure_desc = if failed_tests.is_empty() {
        "Behavioral tests failed but no failure details were captured.".to_string()
    } else {
        format!(
            "The code compiled but {} behavioral test(s) failed:\n\n{}",
            failed_tests.len(),
            failed_tests.join("\n\n")
        )
    };

    let template = FixTemplate::new(
        function_name.to_string(),
        dll_name.to_string(),
        original_rust_code.to_string(),
        failure_desc,
    );
    template
        .render()
        .unwrap_or_else(|_| format!("Fix the failing tests:\n{}", failed_tests.join("\n")))
}

/// Build an escalated fix prompt that injects additional Ghidra context.
///
/// This prompt is used when previous `compile_fix` or `test_fix` attempts have
/// failed. It adds call graph neighbors, neighboring function code, data
/// structures, and type information to help the LLM resolve the failure.
pub async fn build_escalate_prompt_with_context(
    function_name: &str,
    dll_name: &str,
    original_rust_code: &str,
    failure_description: &str,
    ghidra: &GhidraClient,
    address: u64,
    call_graph: &[String],
) -> String {
    // Extract call graph neighbors from the address-based lookup
    let call_graph_neighbors = extract_call_graph_neighbors(ghidra, call_graph, address).await;

    // Extract neighboring function context (callees and callers)
    let neighboring_functions = extract_neighboring_context(ghidra, call_graph).await;

    // Data structures and type info come from Ghidra's symbol table
    let data_structures = extract_data_structures(ghidra, address).await;
    let type_info = extract_type_info(ghidra, function_name).await;

    calxgloss_prompts::build_escalate_prompt(
        function_name.to_string(),
        dll_name.to_string(),
        original_rust_code.to_string(),
        failure_description.to_string(),
        call_graph_neighbors,
        neighboring_functions,
        data_structures,
        type_info,
        Vec::new(), // no failure history for non-informed variant
    )
    .unwrap_or_else(|e| {
        format!(
            "Escalated prompt failed to render: {}\n\n---\n\n{} (failure details above)",
            e, original_rust_code
        )
    })
}

/// Build an edge-case fix prompt focused on boundary value handling.
///
/// This prompt is used when tests fail specifically on boundary values
/// (zero, max, negative, null) rather than on typical inputs.
pub fn build_edge_case_fix_prompt(
    function_name: &str,
    dll_name: &str,
    original_rust_code: &str,
    failed_tests: &[EdgeCaseTest],
) -> String {
    calxgloss_prompts::build_edge_case_prompt(
        function_name.to_string(),
        dll_name.to_string(),
        original_rust_code.to_string(),
        failed_tests.to_vec(),
        Vec::new(), // boundary values extracted separately by caller
        Vec::new(), // failure history — not used for edge case prompts directly
    )
    .unwrap_or_else(|e| {
        format!(
            "Edge case prompt failed to render: {}\n\n---\n\n{} (failure details above)",
            e, original_rust_code
        )
    })
}

/// Build a failure-informed edge case fix prompt.
///
/// Like [`build_edge_case_fix_prompt`] but includes failure history
/// when available (Phase 2, step 2.3).
pub fn build_failure_informed_edge_case_fix_prompt(
    function_name: &str,
    dll_name: &str,
    original_rust_code: &str,
    failed_tests: &[EdgeCaseTest],
    history: &[FailureHint],
) -> String {
    calxgloss_prompts::build_edge_case_prompt(
        function_name.to_string(),
        dll_name.to_string(),
        original_rust_code.to_string(),
        failed_tests.to_vec(),
        Vec::new(), // boundary values extracted separately by caller
        history.to_vec(),
    )
    .unwrap_or_else(|e| {
        format!(
            "Edge case prompt failed to render: {}\n\n---\n\n{} (failure details above)",
            e, original_rust_code
        )
    })
}

// ============================================================
// Failure-informed prompts (Phase 2, step 2.3)
// ============================================================

/// Build a failure-informed compile fix prompt.
///
/// When `history` contains prior failures, the prompt includes a
/// "PREVIOUS ATTEMPT HISTORY" section so the LLM can learn from
/// specific past mistakes (e.g., "v1 mapped SetTexture incorrectly").
pub fn build_failure_informed_compile_fix_prompt(
    function_name: &str,
    dll_name: &str,
    original_rust_code: &str,
    compilation_errors: &[String],
    history: &[FailureHint],
) -> String {
    let failure_desc = if compilation_errors.is_empty() {
        "Compilation failed but no error details were captured.".to_string()
    } else {
        format!(
            "The code failed to compile with {} error(s):\n\n{}",
            compilation_errors.len(),
            compilation_errors.join("\n\n")
        )
    };

    let template = calxgloss_prompts::FixTemplate::with_history(
        function_name.to_string(),
        dll_name.to_string(),
        original_rust_code.to_string(),
        failure_desc,
        history.to_vec(),
    );
    template.render().unwrap_or_else(|_| {
        format!(
            "Fix the compilation errors:\n{}",
            compilation_errors.join("\n")
        )
    })
}

/// Build a failure-informed test fix prompt.
///
/// When `history` contains prior failures, the prompt includes a
/// "PREVIOUS ATTEMPT HISTORY" section so the LLM can learn from
/// specific past mistakes.
pub fn build_failure_informed_test_fix_prompt(
    function_name: &str,
    dll_name: &str,
    original_rust_code: &str,
    failed_tests: &[String],
    history: &[FailureHint],
) -> String {
    let failure_desc = if failed_tests.is_empty() {
        "Behavioral tests failed but no failure details were captured.".to_string()
    } else {
        format!(
            "The code compiled but {} behavioral test(s) failed:\n\n{}",
            failed_tests.len(),
            failed_tests.join("\n\n")
        )
    };

    let template = calxgloss_prompts::FixTemplate::with_history(
        function_name.to_string(),
        dll_name.to_string(),
        original_rust_code.to_string(),
        failure_desc,
        history.to_vec(),
    );
    template
        .render()
        .unwrap_or_else(|_| format!("Fix the failing tests:\n{}", failed_tests.join("\n")))
}

/// Build a failure-informed escalated prompt.
///
/// When `history` contains prior failures, the prompt includes a
/// "PREVIOUS ATTEMPT HISTORY" section so the LLM can learn from
/// specific past mistakes, in addition to the standard Ghidra context.
#[allow(clippy::too_many_arguments)]
pub async fn build_failure_informed_escalate_prompt(
    function_name: &str,
    dll_name: &str,
    original_rust_code: &str,
    failure_description: &str,
    ghidra: &GhidraClient,
    address: u64,
    call_graph: &[String],
    history: &[FailureHint],
) -> String {
    // Extract call graph neighbors from the address-based lookup
    let call_graph_neighbors = extract_call_graph_neighbors(ghidra, call_graph, address).await;

    // Extract neighboring function context (callees and callers)
    let neighboring_functions = extract_neighboring_context(ghidra, call_graph).await;

    // Data structures and type info come from Ghidra's symbol table
    let data_structures = extract_data_structures(ghidra, address).await;
    let type_info = extract_type_info(ghidra, function_name).await;

    calxgloss_prompts::build_escalate_prompt(
        function_name.to_string(),
        dll_name.to_string(),
        original_rust_code.to_string(),
        failure_description.to_string(),
        call_graph_neighbors,
        neighboring_functions,
        data_structures,
        type_info,
        history.to_vec(),
    )
    .unwrap_or_else(|e| {
        format!(
            "Escalated prompt failed to render: {}\n\n---\n\n{} (failure details above)",
            e, original_rust_code
        )
    })
}

/// Detect whether test failures are concentrated on boundary values.
///
/// Returns `true` if the failing tests are likely edge cases (zero, max, negative,
/// null, empty, overflow). This is used to decide whether `EdgeCaseFix` is
/// appropriate.
pub fn is_edge_case_failure(
    failed_tests: &[String],
    _tests_passed: usize,
    _tests_total: usize,
) -> bool {
    // Need some failures to matter
    if failed_tests.is_empty() {
        return false;
    }

    // Check if failures are all in boundary-value territory.
    // Word-boundary indicators avoid matching "0" inside "100".
    let boundary_indicators = [
        "zero",
        "null",
        "max",
        "overflow",
        "underflow",
        "negative",
        "empty",
        "min",
        "boundary",
        "i32::",
        "u32::",
        "i16::",
        "u16::",
        "i64::",
        "u64::",
        "i8::",
        "u8::",
    ];

    let total_failing = failed_tests.len();
    let mut boundary_matches = 0u32;

    for test_desc in failed_tests {
        let lower = test_desc.to_lowercase();
        for indicator in &boundary_indicators {
            if lower.contains(indicator) {
                boundary_matches += 1;
                break;
            }
        }
    }

    // If the majority of failing tests mention boundary indicators,
    // treat as edge case failure.
    boundary_matches as f64 >= (total_failing as f64 * 0.5)
}

// ============================================================
// Ghidra context extraction helpers
// ============================================================

/// Extract call graph neighbor details from Ghidra.
async fn extract_call_graph_neighbors(
    ghidra: &GhidraClient,
    call_graph: &[String],
    _target_address: u64,
) -> Vec<CallGraphNeighbor> {
    let mut neighbors = Vec::new();
    for name in call_graph {
        // Search for the neighbor function to get its address
        if let Ok(matches) = ghidra.search_functions(name, Some(5)).await
            && let Some(found) = matches.iter().find(|m| m.name == *name)
        {
            // Try to get the signature from decompilation
            let signature = match ghidra.decompile_function(found.address).await {
                Ok(decompiled) => decompiled.signature,
                Err(_) => String::new(),
            };
            neighbors.push(CallGraphNeighbor {
                name: found.name.clone(),
                address: found.address,
                signature,
                role: "callee".to_string(), // simplified: most are callees
            });
            continue;
        }
        // If not found, just add a stub
        neighbors.push(CallGraphNeighbor {
            name: name.clone(),
            address: 0,
            signature: String::new(),
            role: "unknown".to_string(),
        });
    }
    neighbors
}

/// Extract neighboring function context (full code) from Ghidra.
async fn extract_neighboring_context(
    ghidra: &GhidraClient,
    call_graph: &[String],
) -> Vec<NeighborFunction> {
    let mut neighbors = Vec::new();
    // Limit to a few neighbors to avoid context window bloat
    for name in call_graph.iter().take(3) {
        if let Ok(matches) = ghidra.search_functions(name, Some(5)).await
            && let Some(found) = matches.iter().find(|m| m.name == *name)
            && let Ok(report) = ghidra.function_report(found.address).await
        {
            neighbors.push(NeighborFunction {
                name: report.name.clone(),
                dll: String::new(),
                address: report.address,
                disassembly: report.disassembly.clone(),
                decompiler_output: report.decompiled.body.clone(),
            });
        }
    }
    neighbors
}

/// Extract data structure information from Ghidra.
async fn extract_data_structures(_ghidra: &GhidraClient, _address: u64) -> Vec<StructuredData> {
    // GhidraMCP doesn't have a dedicated data-structure endpoint,
    // so we return empty for now. This is a placeholder for future
    // integration with Ghidra's type database.
    Vec::new()
}

/// Extract type information from Ghidra for the given function.
async fn extract_type_info(_ghidra: &GhidraClient, _function_name: &str) -> Vec<TypeInfo> {
    // GhidraMCP doesn't expose type inference directly.
    // This is a placeholder for future integration.
    Vec::new()
}

/// Execute a translation with retry logic.
///
/// This is the main retry entry point. It:
/// 1. Takes the initial translation result
/// 2. Verifies it against baseline tests
/// 3. On failure, builds a fix prompt and sends it to the LLM
/// 4. Re-verifies each fix attempt
/// 5. Escalates strategy after each failure
/// 6. Returns a [`RetryResult`] with all attempt details
/// 7. Logs benchmark data per attempt (Phase 2, step 2.4)
///
/// # Arguments
///
/// * `initial_translation` — The initial [`Translation`] to verify and retry.
/// * `verifier` — The verification engine.
/// * `config` — Retry configuration.
/// * `llm` — The LLM client for sending fix prompts.
/// * `ghidra` — The Ghidra client, used for context extraction during escalation.
/// * `strategy` — The starting retry strategy.
/// * `workspace` — Optional workspace path for benchmark logging (Phase 2, step 2.4).
pub async fn try_translate_with_retry(
    initial_translation: Translation,
    verifier: &Verifier,
    config: &RetryConfig,
    llm: &LlmClient,
    ghidra: &GhidraClient,
    strategy: RetryStrategy,
    workspace: Option<&std::path::Path>,
) -> RetryResult {
    let mut result = RetryResult::new();
    let max = config.max_attempts;
    let mut current_strategy = strategy;

    // Failure history for failure-informed prompting (Phase 2, step 2.3)
    let mut failure_history: Vec<FailureHint> = Vec::new();

    // First attempt: verify the initial translation
    let compile_result = match verifier
        .compile(
            &initial_translation.dll,
            &initial_translation.function,
            &initial_translation.rust_code,
        )
        .await
    {
        Ok(cr) => cr,
        Err(e) => {
            warn!(error = %e, "Compilation check failed during retry");
            CompileResult {
                success: false,
                errors: vec![e.to_string()],
                warnings: Vec::new(),
                output: e.to_string(),
            }
        }
    };

    let attempt = TranslationAttempt {
        attempt: 1,
        rust_code: initial_translation.rust_code.clone(),
        compiled: compile_result.success,
        compilation_errors: compile_result.errors.clone(),
        tests_passed: 0,
        tests_total: 0,
        failed_tests: Vec::new(),
        strategy: "initial".to_string(),
        tokens_used: initial_translation.tokens_used,
    };
    result.add_attempt(attempt);

    // If the first attempt succeeded, we're done
    if result.success {
        return result;
    }

    // Retry loop
    for attempt_num in 2..=max {
        info!(
            attempt = attempt_num,
            max = max,
            current_strategy = %current_strategy,
            "Retry attempt"
        );

        // Build fix prompt based on current strategy
        let (prompt, strategy_name) = match &current_strategy {
            RetryStrategy::Default => {
                // Re-send original prompt — skip (would be identical to initial)
                warn!("Default retry strategy — skipping (would be identical to initial)");
                result.add_attempt(TranslationAttempt {
                    attempt: attempt_num,
                    rust_code: initial_translation.rust_code.clone(),
                    compiled: false,
                    compilation_errors: vec![
                        "Skipped: default strategy would re-send identical prompt".to_string(),
                    ],
                    tests_passed: 0,
                    tests_total: 0,
                    failed_tests: Vec::new(),
                    strategy: "skip_default".to_string(),
                    tokens_used: None,
                });
                continue;
            }
            RetryStrategy::CompileFix => {
                // Phase 2, step 2.3: Use failure-informed prompts after first retry
                let prompt = if failure_history.is_empty() {
                    build_compile_fix_prompt(
                        &initial_translation.function,
                        &initial_translation.dll,
                        &initial_translation.rust_code,
                        &compile_result.errors,
                    )
                } else {
                    build_failure_informed_compile_fix_prompt(
                        &initial_translation.function,
                        &initial_translation.dll,
                        &initial_translation.rust_code,
                        &compile_result.errors,
                        &failure_history,
                    )
                };
                (prompt, "compile_fix".to_string())
            }
            RetryStrategy::TestFix => {
                // Run verification first to get failing tests
                let verification = verifier
                    .verify(
                        &initial_translation.dll,
                        &initial_translation.function,
                        &initial_translation.rust_code,
                        &initial_translation.baseline_tests,
                    )
                    .await;

                let failed_tests: Vec<String> = match &verification {
                    Ok(vr) => vr
                        .failed_tests
                        .iter()
                        .map(|ft| {
                            format!(
                                "Test {}: expected {}, got {} \u{2014} {}",
                                ft.test_index, ft.expected, ft.actual, ft.error
                            )
                        })
                        .collect(),
                    Err(_) => vec!["Verification failed".to_string()],
                };

                // Phase 2, step 2.3: Use failure-informed prompts after first retry
                let prompt = if failure_history.is_empty() {
                    build_test_fix_prompt(
                        &initial_translation.function,
                        &initial_translation.dll,
                        &initial_translation.rust_code,
                        &failed_tests,
                    )
                } else {
                    build_failure_informed_test_fix_prompt(
                        &initial_translation.function,
                        &initial_translation.dll,
                        &initial_translation.rust_code,
                        &failed_tests,
                        &failure_history,
                    )
                };
                (prompt, "test_fix".to_string())
            }
            RetryStrategy::Escalate => {
                // Build an escalated prompt with additional Ghidra context.
                // The initial translation carries the function address and call graph.
                let failure_desc = if !compile_result.errors.is_empty() {
                    format!(
                        "Compilation failed with {} error(s):\n\n{}",
                        compile_result.errors.len(),
                        compile_result.errors.join("\n\n")
                    )
                } else {
                    // Get test failure details if compilation passed
                    let verification = verifier
                        .verify(
                            &initial_translation.dll,
                            &initial_translation.function,
                            &initial_translation.rust_code,
                            &initial_translation.baseline_tests,
                        )
                        .await;
                    match verification {
                        Ok(vr) => format!(
                            "{} test(s) failed:\n\n{}",
                            vr.failed_tests.len(),
                            vr.failed_tests
                                .iter()
                                .map(|ft| format!(
                                    "Test {}: expected {}, got {} — {}",
                                    ft.test_index, ft.expected, ft.actual, ft.error
                                ))
                                .collect::<Vec<_>>()
                                .join("\n\n")
                        ),
                        Err(_) => "Verification failed".to_string(),
                    }
                };

                // Phase 2, step 2.3: Use failure-informed escalated prompt
                let prompt = if failure_history.is_empty() {
                    build_escalate_prompt_with_context(
                        &initial_translation.function,
                        &initial_translation.dll,
                        &initial_translation.rust_code,
                        &failure_desc,
                        ghidra,
                        initial_translation.function_address.unwrap_or(0),
                        &initial_translation.call_graph,
                    )
                    .await
                } else {
                    build_failure_informed_escalate_prompt(
                        &initial_translation.function,
                        &initial_translation.dll,
                        &initial_translation.rust_code,
                        &failure_desc,
                        ghidra,
                        initial_translation.function_address.unwrap_or(0),
                        &initial_translation.call_graph,
                        &failure_history,
                    )
                    .await
                };
                (prompt, "escalate".to_string())
            }
            RetryStrategy::EdgeCaseFix => {
                // Get test failure details and build an edge-case-focused prompt
                let verification = verifier
                    .verify(
                        &initial_translation.dll,
                        &initial_translation.function,
                        &initial_translation.rust_code,
                        &initial_translation.baseline_tests,
                    )
                    .await;

                let failed_tests: Vec<EdgeCaseTest> = match &verification {
                    Ok(vr) => vr
                        .failed_tests
                        .iter()
                        .map(|ft| EdgeCaseTest {
                            index: ft.test_index,
                            inputs: ft.inputs.clone(),
                            expected: ft.expected.clone(),
                            actual: ft.actual.clone(),
                            error: ft.error.clone(),
                            disassembly_hints: String::new(),
                        })
                        .collect(),
                    Err(_) => vec![EdgeCaseTest {
                        index: 0,
                        inputs: serde_json::Value::Null,
                        expected: serde_json::Value::Null,
                        actual: serde_json::Value::Null,
                        error: "Verification failed".to_string(),
                        disassembly_hints: String::new(),
                    }],
                };

                // Phase 2, step 2.3: Use failure-informed edge case prompt
                let prompt = if failure_history.is_empty() {
                    build_edge_case_fix_prompt(
                        &initial_translation.function,
                        &initial_translation.dll,
                        &initial_translation.rust_code,
                        &failed_tests,
                    )
                } else {
                    build_failure_informed_edge_case_fix_prompt(
                        &initial_translation.function,
                        &initial_translation.dll,
                        &initial_translation.rust_code,
                        &failed_tests,
                        &failure_history,
                    )
                };
                (prompt, "edge_case_fix".to_string())
            }
        };

        // Send fix prompt to LLM
        let messages = vec![LlmMessage::user(&prompt)];
        let response = match llm.complete(&messages).await {
            Ok(r) => r,
            Err(e) => {
                warn!(
                    attempt = attempt_num,
                    error = %e,
                    "LLM call failed during retry"
                );
                result.add_attempt(TranslationAttempt {
                    attempt: attempt_num,
                    rust_code: initial_translation.rust_code.clone(),
                    compiled: false,
                    compilation_errors: vec![format!("LLM call failed: {}", e)],
                    tests_passed: 0,
                    tests_total: 0,
                    failed_tests: Vec::new(),
                    strategy: strategy_name.clone(),
                    tokens_used: None,
                });
                // Continue to next attempt (might get a different strategy)
                continue;
            }
        };

        let new_rust_code = response.content.trim().to_string();
        let tokens_used = response.tokens_used;

        if new_rust_code.is_empty() {
            warn!(
                attempt = attempt_num,
                "LLM returned empty code during retry"
            );
            result.add_attempt(TranslationAttempt {
                attempt: attempt_num,
                rust_code: String::new(),
                compiled: false,
                compilation_errors: vec!["LLM returned empty code".to_string()],
                tests_passed: 0,
                tests_total: 0,
                failed_tests: Vec::new(),
                strategy: strategy_name.clone(),
                tokens_used,
            });
            continue;
        }

        // Verify the fix attempt
        let compile_result = match verifier
            .compile(
                &initial_translation.dll,
                &initial_translation.function,
                &new_rust_code,
            )
            .await
        {
            Ok(cr) => cr,
            Err(e) => CompileResult {
                success: false,
                errors: vec![e.to_string()],
                warnings: Vec::new(),
                output: e.to_string(),
            },
        };

        // Get test results
        let (tests_passed, tests_total, failed_tests) = if compile_result.success {
            match verifier
                .verify(
                    &initial_translation.dll,
                    &initial_translation.function,
                    &new_rust_code,
                    &initial_translation.baseline_tests,
                )
                .await
            {
                Ok(vr) => (
                    vr.tests_passed,
                    vr.tests_total,
                    vr.failed_tests
                        .iter()
                        .map(|ft| {
                            format!(
                                "Test {}: expected {}, got {} — {}",
                                ft.test_index, ft.expected, ft.actual, ft.error
                            )
                        })
                        .collect::<Vec<_>>(),
                ),
                Err(_) => (0, 0, vec!["Verification failed".to_string()]),
            }
        } else {
            (0, 0, Vec::new())
        };

        let attempt = TranslationAttempt {
            attempt: attempt_num,
            rust_code: new_rust_code,
            compiled: compile_result.success,
            compilation_errors: compile_result.errors,
            tests_passed,
            tests_total,
            failed_tests,
            strategy: strategy_name.clone(),
            tokens_used,
        };
        result.add_attempt(attempt);

        // Phase 2, step 2.3: Track failure history for informed prompting
        // Only record history for failed attempts (not the initial one, not successful retries)
        if attempt_num >= 1 && !result.success {
            // Reconstruct the failure info from the attempt we just added
            let tests_passed = result.attempts.last().map(|a| a.tests_passed).unwrap_or(0);
            let tests_total = result.attempts.last().map(|a| a.tests_total).unwrap_or(0);
            let comp_errors = result
                .attempts
                .last()
                .map(|a| a.compilation_errors.clone())
                .unwrap_or_default();
            let failure_desc = if !comp_errors.is_empty() {
                format!("Compilation failed: {}", comp_errors.join("; "))
            } else if tests_passed < tests_total {
                format!("{} of {} tests passed", tests_passed, tests_total)
            } else {
                "Unknown failure".to_string()
            };
            failure_history.push(FailureHint::new(
                attempt_num,
                strategy_name.clone(),
                failure_desc,
            ));
        }

        // If this attempt succeeded, we're done
        if result.success {
            break;
        }

        // Phase 2, step 2.4: Log benchmark data for prompt variant tracking
        let dll_name = &initial_translation.dll;
        log_prompt_variant_benchmark(dll_name, &strategy_name, result.success, attempt_num, workspace);

        // Escalate strategy for next attempt
        if config.escalate_on_failure {
            current_strategy = match current_strategy {
                RetryStrategy::CompileFix => RetryStrategy::TestFix,
                RetryStrategy::TestFix => RetryStrategy::Escalate,
                RetryStrategy::Escalate => RetryStrategy::EdgeCaseFix,
                RetryStrategy::EdgeCaseFix => RetryStrategy::CompileFix, // cycle back
                RetryStrategy::Default => RetryStrategy::CompileFix,
            };
        }
    }

    result
}

// ============================================================
// Benchmark logging (Phase 2, step 2.4)
// ============================================================

/// Log a prompt variant benchmark entry for analysis.
///
/// Persists the entry to `re/analysis/prompt_strategy_log.json` via the
/// [`PromptStrategyLogger`](calxgloss_analysis::PromptStrategyLogger).
/// If the workspace path is `None`, the entry is silently discarded.
///
/// # Arguments
///
/// * `dll_name` — The DLL filename (e.g., `"game_logic.dll"`).
/// * `strategy` — The retry strategy used (e.g., `"compile_fix"`, `"test_fix"`).
/// * `success` — Whether this attempt succeeded.
/// * `attempt_num` — The attempt number (1-based).
/// * `workspace` — The workspace root path for the log file. `None` to skip logging.
pub fn log_prompt_variant_benchmark(
    dll_name: &str,
    strategy: &str,
    success: bool,
    attempt_num: u32,
    workspace: Option<&std::path::Path>,
) {
    let Some(ws) = workspace else {
        return;
    };

    let dll_category = calxgloss_analysis::classify_dll_name(dll_name);
    let entry = calxgloss_types::PromptStrategyEntry::new(
        dll_name,
        dll_category,
        strategy,
        success,
        attempt_num,
    );

    let logger = calxgloss_analysis::PromptStrategyLogger::new(ws);
    logger.record(entry);
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_retry_config_default() {
        let config = RetryConfig::default();
        assert_eq!(config.max_attempts, 3);
        assert_eq!(config.strategy, RetryStrategy::CompileFix);
        assert!(config.escalate_on_failure);
    }

    #[test]
    fn test_retry_strategy_display() {
        assert_eq!(format!("{}", RetryStrategy::Default), "default");
        assert_eq!(format!("{}", RetryStrategy::CompileFix), "compile_fix");
        assert_eq!(format!("{}", RetryStrategy::TestFix), "test_fix");
        assert_eq!(format!("{}", RetryStrategy::Escalate), "escalate");
        assert_eq!(format!("{}", RetryStrategy::EdgeCaseFix), "edge_case_fix");
    }

    #[test]
    fn test_translation_attempt_is_successful() {
        let mut attempt = TranslationAttempt {
            attempt: 1,
            rust_code: "fn foo() {}".to_string(),
            compiled: true,
            compilation_errors: Vec::new(),
            tests_passed: 5,
            tests_total: 5,
            failed_tests: Vec::new(),
            strategy: "initial".to_string(),
            tokens_used: Some(1024),
        };
        assert!(attempt.is_successful());

        attempt.tests_passed = 4;
        assert!(!attempt.is_successful());

        // No tests = successful by definition
        attempt.tests_passed = 0;
        attempt.tests_total = 0;
        assert!(attempt.is_successful());
    }

    #[test]
    fn test_retry_result_new() {
        let result = RetryResult::new();
        assert!(!result.success);
        assert!(result.rust_code.is_none());
        assert!(result.attempts.is_empty());
    }

    #[test]
    fn test_retry_result_add_successful_attempt() {
        let mut result = RetryResult::new();
        result.add_attempt(TranslationAttempt {
            attempt: 1,
            rust_code: "fn foo() -> i32 { 42 }".to_string(),
            compiled: true,
            compilation_errors: Vec::new(),
            tests_passed: 3,
            tests_total: 3,
            failed_tests: Vec::new(),
            strategy: "initial".to_string(),
            tokens_used: Some(512),
        });
        assert!(result.success);
        assert!(result.rust_code.is_some());
        assert_eq!(
            result.rust_code.as_deref().unwrap(),
            "fn foo() -> i32 { 42 }"
        );
        assert_eq!(result.success_strategy.as_deref().unwrap(), "initial");
    }

    #[test]
    fn test_build_compile_fix_prompt() {
        let prompt = build_compile_fix_prompt(
            "entry",
            "eqmain.dll",
            "fn entry() { __security_init_cookie(); }",
            &["error[E0425]: not found: `__security_init_cookie`".to_string()],
        );
        assert!(prompt.contains("entry"));
        assert!(prompt.contains("eqmain.dll"));
        assert!(prompt.contains("__security_init_cookie"));
        assert!(prompt.contains("E0425"));
    }

    #[test]
    fn test_build_test_fix_prompt() {
        let prompt = build_test_fix_prompt(
            "DrawSprite",
            "game_logic.dll",
            "fn draw_sprite(x: i32) -> i32 { x }",
            &[
                "Test 0: expected 42, got 10 — input was 10".to_string(),
                "Test 1: expected 0, got 5 — input was 5".to_string(),
            ],
        );
        assert!(prompt.contains("DrawSprite"));
        assert!(prompt.contains("expected 42"));
        assert!(prompt.contains("expected 0"));
    }

    #[test]
    fn test_is_edge_case_failure_boundary() {
        let failed = vec![
            "Test 0: expected 0, got 1 — input was 0 (zero check)".to_string(),
            "Test 1: expected 2147483647, got 0 — input was max (overflow)".to_string(),
        ];
        assert!(is_edge_case_failure(&failed, 0, 2));
    }

    #[test]
    fn test_is_edge_case_failure_normal_failure() {
        let failed = vec![
            "Test 0: expected 100, got 50 — wrong multiplication".to_string(),
            "Test 1: expected 200, got 100 — wrong addition".to_string(),
        ];
        assert!(!is_edge_case_failure(&failed, 0, 2));
    }

    #[test]
    fn test_is_edge_case_failure_mixed() {
        // Mixed: 2 boundary + 1 normal — should be edge case (majority)
        let failed = vec![
            "Test 0: expected 0, got 1 — zero input".to_string(),
            "Test 1: expected 0, got -1 — negative input".to_string(),
            "Test 2: expected 100, got 50 — wrong value".to_string(),
        ];
        assert!(is_edge_case_failure(&failed, 0, 3));
    }

    #[test]
    fn test_is_edge_case_failure_all_passed() {
        let failed: Vec<String> = vec![];
        assert!(!is_edge_case_failure(&failed, 5, 5));
    }

    // ============================================================
    // Phase 2, step 2.3 — Failure-informed prompt builder tests
    // ============================================================

    #[test]
    fn test_failure_informed_compile_fix_includes_history() {
        let hints = vec![
            FailureHint::new(
                1,
                "compile_fix",
                "Compilation failed: E0425 — `__security_init_cookie` not found",
            ),
            FailureHint::new(2, "test_fix", "Wrong result on boundary input"),
        ];

        let prompt = build_failure_informed_compile_fix_prompt(
            "entry",
            "eqmain.dll",
            "fn entry() { __security_init_cookie(); }",
            &["error[E0425]: not found: `__security_init_cookie`".to_string()],
            &hints,
        );

        assert!(prompt.contains("entry"));
        assert!(prompt.contains("eqmain.dll"));
        assert!(prompt.contains("PREVIOUS ATTEMPT HISTORY"));
        assert!(prompt.contains("Attempt #1"));
        assert!(prompt.contains("compile_fix"));
        assert!(prompt.contains("Attempt #2"));
        assert!(prompt.contains("test_fix"));
    }

    #[test]
    fn test_failure_informed_compile_fix_empty_history() {
        let prompt = build_failure_informed_compile_fix_prompt(
            "entry",
            "eqmain.dll",
            "fn entry() { }",
            &["error[E0425]: not found: `foo`".to_string()],
            &[], // empty history — should not include history section
        );

        assert!(prompt.contains("entry"));
        assert!(!prompt.contains("PREVIOUS ATTEMPT HISTORY"));
    }

    #[test]
    fn test_failure_informed_test_fix_includes_history() {
        let hints = vec![FailureHint::new(
            1,
            "compile_fix",
            "Compilation failed: E0412",
        )];

        let prompt = build_failure_informed_test_fix_prompt(
            "DrawSprite",
            "game_logic.dll",
            "fn draw_sprite(x: i32) -> i32 { x }",
            &["Test 0: expected 42, got 10 — input was 10".to_string()],
            &hints,
        );

        assert!(prompt.contains("DrawSprite"));
        assert!(prompt.contains("game_logic.dll"));
        assert!(prompt.contains("PREVIOUS ATTEMPT HISTORY"));
        assert!(prompt.contains("compile_fix"));
        assert!(prompt.contains("Compilation failed: E0412"));
    }

    #[test]
    fn test_failure_informed_edge_case_fix_includes_history() {
        let hints = vec![
            FailureHint::new(1, "test_fix", "Wrong result on zero input"),
            FailureHint::new(2, "escalate", "Still wrong on zero after adding context"),
        ];

        let failed_tests = vec![EdgeCaseTest {
            index: 1,
            inputs: serde_json::json!({"x": 0}),
            expected: serde_json::json!(0),
            actual: serde_json::json!(1),
            error: "Expected 0, got 1".to_string(),
            disassembly_hints: "cmp eax, 0\nje .zero_branch".to_string(),
        }];

        let prompt = build_failure_informed_edge_case_fix_prompt(
            "DrawSprite",
            "game_logic.dll",
            "fn draw_sprite(x: i32) -> i32 { x + 1 }",
            &failed_tests,
            &hints,
        );

        assert!(prompt.contains("DrawSprite"));
        assert!(prompt.contains("PREVIOUS ATTEMPT HISTORY"));
        assert!(prompt.contains("Learn from past failures"));
    }
}
