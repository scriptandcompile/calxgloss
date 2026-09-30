//! Batch translation — translate multiple functions in sequence.
//!
//! This module provides types for batch translation results. The actual
//! [`batch_translate`](TranslationPipeline::batch_translate) method lives
//! directly on [`TranslationPipeline`] in the parent module to avoid trait
//! self-reference issues.
//!
//! # Example
//!
//! ```no_run
//! use calxgloss_translator::TranslationPipeline;
//! use calxgloss_verify::Verifier;
//! use std::path::Path;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let ghidra = calxgloss_ghidra::GhidraClient::new("http://localhost:8080")?;
//! let llm = calxgloss_llm::LlmClient::from_url("http://localhost:11434/v1", "qwen3")?;
//! let pipeline = TranslationPipeline::new(ghidra, llm, calxgloss_pal::ApiMappings::default());
//! let verifier = Verifier::new(Path::new("/tmp/calxgloss-work"))?;
//! let config = calxgloss_translator::RetryConfig::default();
//!
//! let functions = vec!["DrawSprite".to_string(), "UpdatePosition".to_string()];
//! let results = pipeline.batch_translate(
//!     "game_logic.dll",
//!     &functions,
//!     &config,
//!     &verifier,
//!     None, // git handled by caller via callback
//! ).await?;
//!
//! println!("{} succeeded, {} failed", results.success_count(), results.failure_count());
//! # Ok(())
//! # }
//! ```

use calxgloss_types::GitBranch;

use crate::RetryResult;

// ============================================================
// Public types
// ============================================================

/// The result of translating a single function within a batch.
#[derive(Debug, Clone)]
pub struct FunctionResult {
    /// The DLL containing the function.
    pub dll: String,

    /// The function name that was translated.
    pub function: String,

    /// Whether this function's translation ultimately succeeded.
    pub success: bool,

    /// The generated Rust code, if the translation succeeded.
    pub rust_code: Option<String>,

    /// The full retry result for this function, including all attempts.
    pub retry_result: RetryResult,

    /// The git branch created for this function (if git is enabled).
    pub branch: Option<GitBranch>,
}

impl FunctionResult {
    /// Create a new failure result for a function.
    pub(crate) fn failure(dll: String, function: String, retry_result: RetryResult) -> Self {
        Self {
            dll,
            function,
            success: false,
            rust_code: None,
            retry_result,
            branch: None,
        }
    }

    /// Create a new success result for a function.
    pub(crate) fn success(
        dll: String,
        function: String,
        rust_code: String,
        retry_result: RetryResult,
        branch: Option<GitBranch>,
    ) -> Self {
        Self {
            dll,
            function,
            success: true,
            rust_code: Some(rust_code),
            retry_result,
            branch,
        }
    }
}

/// The aggregated result of translating an entire batch of functions.
#[derive(Debug, Clone)]
pub struct BatchTranslationResult {
    /// The DLL being translated.
    pub dll: String,

    /// Per-function results, in the order the functions were listed.
    pub results: Vec<FunctionResult>,
}

impl BatchTranslationResult {
    /// Create a new batch result.
    pub fn new(dll: String) -> Self {
        Self {
            dll,
            results: Vec::new(),
        }
    }

    /// Append a per-function result.
    pub fn add(&mut self, result: FunctionResult) {
        self.results.push(result);
    }

    /// Number of functions that succeeded.
    pub fn success_count(&self) -> usize {
        self.results.iter().filter(|r| r.success).count()
    }

    /// Number of functions that failed.
    pub fn failure_count(&self) -> usize {
        self.results.iter().filter(|r| !r.success).count()
    }

    /// Total number of functions in the batch.
    pub fn total_count(&self) -> usize {
        self.results.len()
    }

    /// Whether every function in the batch succeeded.
    pub fn all_success(&self) -> bool {
        self.success_count() == self.total_count() && self.total_count() > 0
    }

    /// Whether any function in the batch succeeded.
    pub fn any_success(&self) -> bool {
        self.success_count() > 0
    }

    /// The first successful translation, if any.
    pub fn first_success(&self) -> Option<&FunctionResult> {
        self.results.iter().find(|r| r.success)
    }
}
