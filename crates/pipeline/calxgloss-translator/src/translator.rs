//! Direct translation — the [`Translator`] struct and [`Translation`] result type.
//!
//! This module provides the simplest translation path: you provide the LLM with
//! disassembly and decompiler output, and it returns Rust code. It skips
//! GhidraMCP fetching, API tagging, and test generation — useful for manual
//! or cached data.

use calxgloss_llm::{LlmClient, LlmMessage};
use calxgloss_types::{BinaryIdentity, ContextTier, TestCase, TranslationRequest};

use crate::error::{Result, TranslatorError};

// ============================================================
// Public types
// ============================================================

/// The result of a successful translation.
///
/// Contains the generated Rust code, the prompt that produced it,
/// the LLM model used, baseline test inputs, and optional token usage data.
#[derive(Debug, Clone)]
pub struct Translation {
    /// The DLL containing the translated function.
    pub binary: BinaryIdentity,

    /// The function name that was translated.
    pub function: String,

    /// The virtual address of the function entry point, if known.
    pub function_address: Option<u64>,

    /// The generated Rust source code.
    pub rust_code: String,

    /// The full prompt sent to the LLM (for reproducibility).
    pub prompt_used: String,

    /// The LLM model name used for this translation.
    pub model: String,

    /// Number of tokens used, if reported by the LLM.
    pub tokens_used: Option<usize>,

    /// Baseline test inputs generated for this function.
    /// These are used by the verifier to check behavioral equivalence.
    pub baseline_tests: Vec<TestCase>,

    /// Call graph neighbors (callers and callees) from Ghidra analysis.
    /// Used for context extraction during escalate retries.
    pub call_graph: Vec<String>,

    /// Patterns discovered in the disassembly (e.g., `"zero_check"`,
    /// `"null_check"`, `"overflow"`).
    /// Used by the behavior-divergence detector to generate targeted
    /// edge-case tests.
    pub disassembly_hints: Vec<String>,

    /// The context tier that was used for this translation.
    /// Indicates how much context the LLM received; used for
    /// token usage tracking and future tier selection.
    pub context_tier: ContextTier,

    /// Enriched call graph context with caller/callee details and
    /// leaf API suggestions, used during escalation retries.
    ///
    /// Populated during the initial translation by the
    /// [`ContextEnricher`](calxgloss_callgraph::ContextEnricher). When present,
    /// escalation prompts include structured context about callers, callees,
    /// and matched third-party API signatures alongside the simpler neighbor list.
    pub call_graph_context: Vec<calxgloss_callgraph::FunctionContext>,
}

// ============================================================
// Translator — simple direct translation
// ============================================================

/// Direct translation using pre-collected function data.
///
/// Use this when you already have the function's disassembly and decompiler
/// output from another source (e.g., cached Ghidra data, manual extraction).
/// It skips the analysis step and sends the data directly to the LLM.
///
/// # Example
///
/// ```no_run
/// use calxgloss_translator::Translator;
/// use calxgloss_llm::{LlmClient, LlmConfig};
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let llm = LlmClient::from_url("http://localhost:11434/v1", "qwen3")?;
/// let translator = Translator::new(llm);
///
/// // Use with raw data — no GhidraMCP call
/// let translation = translator
///     .translate_raw("game_logic.dll", "DrawSprite", "disassembly text here", "pseudo-C here")
///     .await?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct Translator {
    /// Client for sending prompts to the LLM.
    llm: LlmClient,
}

impl Translator {
    /// Create a new translator with the given LLM client.
    pub fn new(llm: LlmClient) -> Self {
        Self { llm }
    }

    /// Translate a function using raw disassembly and decompiler output.
    ///
    /// This is the simplest translation path — no analysis or test generation.
    /// It builds a minimal prompt from the provided data and sends it to the LLM.
    ///
    /// # Arguments
    ///
    /// * `binary` — The DLL containing the function.
    /// * `function` — The function name.
    /// * `disassembly` — Raw disassembly text.
    /// * `decompiler_output` — Pseudo-C decompiler output (may be empty).
    ///
    /// # Returns
    ///
    /// A [`Translation`] with the generated Rust code and metadata.
    pub async fn translate_raw(
        &self,
        binary: &str,
        function: &str,
        disassembly: &str,
        decompiler_output: &str,
    ) -> Result<Translation> {
        tracing::debug!(binary, function, "Translating with raw data");

        let prompt = self.build_minimal_prompt(binary, function, disassembly, decompiler_output)?;
        let response = self.send_to_llm(&prompt).await?;

        Ok(Translation {
            binary: binary.into(),
            function: function.to_string(),
            function_address: None,
            rust_code: response.content,
            prompt_used: prompt,
            model: self.llm.model().to_string(),
            tokens_used: response.tokens_used,
            baseline_tests: Vec::new(),
            call_graph: Vec::new(),
            call_graph_context: Vec::new(),
            disassembly_hints: Vec::new(),
            context_tier: ContextTier::Disassembly,
        })
    }

    /// Translate using a structured translation request with full context.
    ///
    /// This builds a rich prompt including Windows API mappings and baseline
    /// tests, providing the LLM with maximum context for accurate translation.
    ///
    /// # Arguments
    ///
    /// * `binary` — The DLL containing the function.
    /// * `function` — The function name.
    /// * `request` — A [`TranslationRequest`] with disassembly, decompiler output,
    ///   API mappings, and baseline tests.
    ///
    /// # Returns
    ///
    /// A [`Translation`] with the generated Rust code and metadata.
    pub async fn translate_with_request(
        &self,
        binary: &str,
        function: &str,
        request: TranslationRequest,
    ) -> Result<Translation> {
        tracing::debug!(binary, function, "Translating with full request context");

        if request.disassembly.is_empty() && request.decompiler_output.is_empty() {
            return Err(TranslatorError::MissingContext(
                "Both disassembly and decompiler output are empty".to_string(),
            ));
        }

        let prompt = calxgloss_prompts::build_translate_prompt(&request)?;
        let response = self.send_to_llm(&prompt).await?;

        Ok(Translation {
            binary: binary.into(),
            function: function.to_string(),
            function_address: None,
            rust_code: response.content,
            prompt_used: prompt,
            model: self.llm.model().to_string(),
            tokens_used: response.tokens_used,
            baseline_tests: request.baseline_tests,
            call_graph: Vec::new(),
            call_graph_context: Vec::new(),
            disassembly_hints: Vec::new(),
            context_tier: ContextTier::WithTests,
        })
    }

    /// Build a minimal translation prompt without test/API context.
    pub(crate) fn build_minimal_prompt(
        &self,
        binary: &str,
        function: &str,
        disassembly: &str,
        decompiler_output: &str,
    ) -> Result<String> {
        // Build a minimal request for the template
        let req = TranslationRequest {
            binary: binary.into(),
            function: function.to_string(),
            disassembly: disassembly.trim().to_string(),
            decompiler_output: decompiler_output.trim().to_string(),
            windows_apis: Vec::new(),
            baseline_tests: Vec::new(),
        };
        Ok(calxgloss_prompts::build_translate_prompt(&req)?)
    }

    /// Send a prompt to the LLM and extract the Rust code response.
    async fn send_to_llm(&self, prompt: &str) -> Result<calxgloss_llm::LlmResponse> {
        let messages = vec![LlmMessage::user(prompt)];
        let response = self.llm.complete(&messages).await?;

        if response.content.is_empty() {
            return Err(TranslatorError::EmptyCode {
                code_len: response.content.len(),
            });
        }

        tracing::debug!(
            code_len = response.content.len(),
            model = %self.llm.model(),
            "Received LLM response"
        );

        Ok(response)
    }
}
