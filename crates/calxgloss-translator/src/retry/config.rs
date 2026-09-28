//! Retry and translation result types.

/// Configuration for the retry loop.
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
