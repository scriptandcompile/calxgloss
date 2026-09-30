//! Translation pipeline — GhidraMCP + LLM + prompt orchestration.
//!
//! This crate provides the [`TranslationPipeline`] struct, which wires together
//! all the pieces needed to translate a disassembled function to Rust:
//!
//! 1. Pull function data from GhidraMCP (disassembly, decompiler output)
//! 2. Tag Windows API calls with their PAL mappings
//! 3. Generate baseline test inputs from function signature and disassembly
//! 4. Build a structured prompt bundling all context
//! 5. Send the prompt to the LLM for Rust code generation
//! 6. Return the translated code along with metadata
//!
//! # Example
//!
//! ```no_run
//! use calxgloss_translator::TranslationPipeline;
//! use calxgloss_ghidra::GhidraClient;
//! use calxgloss_llm::{LlmClient, LlmConfig};
//! use calxgloss_pal::ApiMappings;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let ghidra = GhidraClient::new("http://localhost:8080")?;
//! let llm = LlmClient::from_url("http://localhost:11434/v1", "qwen3")?;
//! let pipeline = TranslationPipeline::new(ghidra, llm, ApiMappings::default());
//!
//! let translation = pipeline.translate("game_logic.dll", "DrawSprite").await?;
//! println!("Translated code:\n{}", translation.rust_code);
//! # Ok(())
//! # }
//! ```

pub mod error;
pub mod retry;

pub use error::{Result, TranslatorError};
pub use retry::{
    RetryConfig, RetryResult, RetryStrategy, TranslationAttempt, try_translate_with_retry,
};

pub mod batch;

pub use batch::{BatchTranslationResult, FunctionResult};

use calxgloss_analysis::Analyzer;
use calxgloss_ghidra::GhidraClient;
use calxgloss_llm::{LlmClient, LlmMessage};
use calxgloss_pal::ApiMappings;
use calxgloss_prompts::build_translate_prompt;
use calxgloss_testgen::TestGenerator;
use calxgloss_types::{
    Export, FunctionInfo, ProgressEvent, TestCase, TranslationEvents, TranslationRequest,
};
use calxgloss_verify::Verifier;
use tokio;
use tracing::{debug, info, instrument, warn};

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
    pub dll: String,

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
    /// * `dll` — The DLL containing the function.
    /// * `function` — The function name.
    /// * `disassembly` — Raw disassembly text.
    /// * `decompiler_output` — Pseudo-C decompiler output (may be empty).
    ///
    /// # Returns
    ///
    /// A [`Translation`] with the generated Rust code and metadata.
    pub async fn translate_raw(
        &self,
        dll: &str,
        function: &str,
        disassembly: &str,
        decompiler_output: &str,
    ) -> Result<Translation> {
        debug!(dll, function, "Translating with raw data");

        let prompt = self.build_minimal_prompt(dll, function, disassembly, decompiler_output)?;
        let response = self.send_to_llm(&prompt).await?;

        Ok(Translation {
            dll: dll.to_string(),
            function: function.to_string(),
            function_address: None,
            rust_code: response.content,
            prompt_used: prompt,
            model: self.llm.model().to_string(),
            tokens_used: response.tokens_used,
            baseline_tests: Vec::new(),
            call_graph: Vec::new(),
        })
    }

    /// Translate using a structured translation request with full context.
    ///
    /// This builds a rich prompt including Windows API mappings and baseline
    /// tests, providing the LLM with maximum context for accurate translation.
    ///
    /// # Arguments
    ///
    /// * `dll` — The DLL containing the function.
    /// * `function` — The function name.
    /// * `request` — A [`TranslationRequest`] with disassembly, decompiler output,
    ///   API mappings, and baseline tests.
    ///
    /// # Returns
    ///
    /// A [`Translation`] with the generated Rust code and metadata.
    pub async fn translate_with_request(
        &self,
        dll: &str,
        function: &str,
        request: TranslationRequest,
    ) -> Result<Translation> {
        debug!(dll, function, "Translating with full request context");

        if request.disassembly.is_empty() && request.decompiler_output.is_empty() {
            return Err(TranslatorError::MissingContext(
                "Both disassembly and decompiler output are empty".to_string(),
            ));
        }

        let prompt = build_translate_prompt(&request)?;
        let response = self.send_to_llm(&prompt).await?;

        Ok(Translation {
            dll: dll.to_string(),
            function: function.to_string(),
            function_address: None,
            rust_code: response.content,
            prompt_used: prompt,
            model: self.llm.model().to_string(),
            tokens_used: response.tokens_used,
            baseline_tests: request.baseline_tests,
            call_graph: Vec::new(),
        })
    }

    /// Build a minimal translation prompt without test/API context.
    fn build_minimal_prompt(
        &self,
        dll: &str,
        function: &str,
        disassembly: &str,
        decompiler_output: &str,
    ) -> Result<String> {
        // Build a minimal request for the template
        let req = TranslationRequest {
            dll: dll.to_string(),
            function: function.to_string(),
            disassembly: disassembly.trim().to_string(),
            decompiler_output: decompiler_output.trim().to_string(),
            windows_apis: Vec::new(),
            baseline_tests: Vec::new(),
        };
        Ok(build_translate_prompt(&req)?)
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

        debug!(
            code_len = response.content.len(),
            model = %self.llm.model(),
            "Received LLM response"
        );

        Ok(response)
    }
}

// ============================================================
// TranslationPipeline — full end-to-end pipeline
// ============================================================

/// Full translation pipeline: Ghidra → Analysis → Tests → LLM → Rust code.
///
/// This is the main entry point for the translation workflow. It orchestrates
/// all the steps needed to translate a function from disassembly to working Rust:
///
/// 1. Fetch function metadata from GhidraMCP (disassembly, decompiler output)
/// 2. Tag Windows API calls with PAL mappings using the analyzer
/// 3. Generate baseline test inputs from function signature and disassembly
/// 4. Build a structured prompt bundling all context
/// 5. Send the prompt to the LLM for Rust code generation
/// 6. Return a [`Translation`] with the code and all metadata
///
/// # Construction
///
/// ```
/// use calxgloss_translator::TranslationPipeline;
/// use calxgloss_ghidra::GhidraClient;
/// use calxgloss_llm::{LlmClient, LlmConfig};
/// use calxgloss_pal::ApiMappings;
///
/// let ghidra = GhidraClient::new("http://localhost:8080").unwrap();
/// let llm = LlmClient::from_url("http://localhost:11434/v1", "qwen3").unwrap();
/// let pipeline = TranslationPipeline::new(ghidra, llm, ApiMappings::default());
/// ```
#[derive(Debug)]
pub struct TranslationPipeline {
    /// Client for querying GhidraMCP.
    ghidra: GhidraClient,

    /// Client for sending prompts to the LLM.
    llm: LlmClient,

    /// Windows API → Rust mapping table.
    api_mappings: ApiMappings,

    /// Analyzer for DLL classification and API tagging.
    analyzer: Analyzer,

    /// Optional test generator for baseline test input creation.
    testgen: Option<TestGenerator>,

    /// Optional exports for signature extraction during test generation.
    exports: Vec<Export>,

    /// Optional DLL name override for test generation context.
    target_dll: Option<String>,

    /// Optional workspace root path for experiment logging.
    workspace: Option<std::path::PathBuf>,

    /// Optional broadcast channel for progress events.
    /// When present, events are emitted at key pipeline milestones
    /// and can be consumed by a WebSocket server for live progress.
    #[allow(dead_code)]
    events: Option<TranslationEvents>,
}

impl TranslationPipeline {
    /// Create a new translation pipeline with the given Ghidra and LLM clients.
    ///
    /// This sets up the full pipeline with default analyzer and empty exports/tests.
    pub fn new(ghidra: GhidraClient, llm: LlmClient, api_mappings: ApiMappings) -> Self {
        let analyzer = Analyzer::new(ghidra.clone(), api_mappings.clone());
        Self {
            ghidra,
            llm,
            api_mappings,
            analyzer,
            testgen: None,
            exports: Vec::new(),
            target_dll: None,
            workspace: None,
            events: None,
        }
    }

    /// Set the workspace root path for experiment logging.
    ///
    /// When set, every translation attempt is recorded to
    /// `<workspace>/re/analysis/prompt_strategy_log.json`.
    pub fn with_workspace(mut self, workspace: impl Into<std::path::PathBuf>) -> Self {
        self.workspace = Some(workspace.into());
        self
    }

    /// Attach a progress event emitter for live WebSocket streaming.
    ///
    /// When set, the pipeline emits [`ProgressEvent`] instances at every
    /// major milestone. Subscribers to the channel (typically a WebSocket
    /// server) can relay these events to connected clients in real time.
    pub fn with_events(mut self, events: TranslationEvents) -> Self {
        self.events = Some(events);
        self
    }

    /// Emit a progress event if an event emitter was attached.
    fn emit(&self, event: ProgressEvent) {
        if let Some(ref emitter) = self.events {
            let _ = emitter.emit(event);
        }
    }

    /// Set the test generator for baseline test creation.
    pub fn with_testgen(mut self, testgen: TestGenerator) -> Self {
        self.testgen = Some(testgen);
        self
    }

    /// Set exports to use for function signature extraction.
    pub fn with_exports(mut self, exports: Vec<Export>) -> Self {
        self.exports = exports;
        self
    }

    /// Set the target DLL name for test generation context.
    pub fn with_target_dll(mut self, dll: String) -> Self {
        self.target_dll = Some(dll);
        self
    }

    /// Translate a function from the program open in Ghidra.
    ///
    /// This is the main pipeline entry point. It fetches all data from Ghidra,
    /// analyzes the function, generates tests, builds a prompt, and sends it
    /// to the LLM.
    ///
    /// # Arguments
    ///
    /// * `dll` — The DLL containing the function. Recorded on the result; the
    ///   lookup is against the program Ghidra has open, which must be this DLL.
    /// * `function` — The function name to translate.
    ///
    /// # Returns
    ///
    /// A [`Translation`] with the generated Rust code and metadata, or an error
    /// if any step in the pipeline fails.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use calxgloss_translator::TranslationPipeline;
    /// use calxgloss_ghidra::GhidraClient;
    /// use calxgloss_llm::LlmClient;
    /// use calxgloss_pal::ApiMappings;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let ghidra = GhidraClient::new("http://localhost:8080")?;
    /// let llm = LlmClient::from_url("http://localhost:11434/v1", "qwen3")?;
    /// let pipeline = TranslationPipeline::new(ghidra, llm, ApiMappings::default());
    ///
    /// let translation = pipeline.translate("game_logic.dll", "DrawSprite").await?;
    /// println!("Generated {} lines of Rust code", translation.rust_code.lines().count());
    /// # Ok(())
    /// # }
    /// ```
    #[instrument(skip(self), fields(dll, function, base_url = %self.ghidra.base_url()))]
    pub async fn translate(&self, dll: &str, function: &str) -> Result<Translation> {
        debug!(dll, function, "Starting translation pipeline");

        // Emit: translation started
        self.emit(ProgressEvent::TranslationStarted {
            dll: dll.to_string(),
            function: function.to_string(),
        });

        // Step 1: Fetch function metadata from Ghidra
        let function_info = self.fetch_function(dll, function).await?;
        info!(dll, function, "Fetched function metadata");

        // Emit: Ghidra fetch complete
        self.emit(ProgressEvent::GhidraFetchComplete {
            dll: dll.to_string(),
            function: function.to_string(),
            address: Some(function_info.address),
            disassembly_lines: function_info.disassembly.lines().count(),
        });

        // Step 2: Fetch imports and tag Windows APIs
        let imports = self.fetch_imports(dll).await?;
        let tagged_apis = self.tag_windows_apis(&function_info.disassembly, &imports)?;
        info!(
            dll,
            function,
            tagged_apis = tagged_apis.len(),
            "Tagged Windows APIs"
        );

        // Emit: API tagging complete
        self.emit(ProgressEvent::ApiTaggingComplete {
            dll: dll.to_string(),
            function: function.to_string(),
            tagged_apis: tagged_apis.len(),
        });

        // Step 3: Generate baseline test inputs
        let baseline_tests = self
            .generate_baseline_tests(&function_info, &imports)
            .await?;
        info!(
            dll,
            function,
            tests = baseline_tests.len(),
            "Generated baseline tests"
        );

        // Emit: tests generated
        self.emit(ProgressEvent::TestsGenerated {
            dll: dll.to_string(),
            function: function.to_string(),
            test_count: baseline_tests.len(),
        });

        // Step 4: Detect function complexity and build translation request
        let complexity = self
            .analyzer
            .detect_complexity(&function_info.disassembly, &function_info.windows_apis);
        info!(
            dll,
            function,
            complexity = %complexity,
            "Detected function complexity"
        );

        let request = self.build_translation_request(
            dll,
            function,
            &function_info,
            tagged_apis.clone(),
            baseline_tests.clone(),
        );

        // Step 5: Build a complexity-aware prompt and send to LLM
        self.emit(ProgressEvent::LlmCallStart {
            dll: dll.to_string(),
            function: function.to_string(),
            attempt: 1,
            strategy: "initial".to_string(),
        });

        let data = calxgloss_prompts::ComplexityPromptData::from_request(&request);
        let prompt = calxgloss_prompts::build_complexity_prompt(&complexity, &data)?;

        // Emit: LLM request (full prompt)
        self.emit(ProgressEvent::LlmRequest {
            dll: dll.to_string(),
            function: function.to_string(),
            attempt: 1,
            strategy: "initial".to_string(),
            prompt: prompt.clone(),
        });

        let response = self
            .send_to_llm(
                &prompt,
                self.events.as_ref(),
                dll,
                function,
                1,
                "initial",
            )
            .await?;

        if response.content.is_empty() {
            return Err(TranslatorError::EmptyCode {
                code_len: response.content.len(),
            });
        }

        // Emit: LLM response (full content)
        self.emit(ProgressEvent::LlmResponse {
            dll: dll.to_string(),
            function: function.to_string(),
            attempt: 1,
            strategy: "initial".to_string(),
            content: response.content.clone(),
            tokens_used: response.tokens_used,
        });

        // Emit: LLM call complete
        self.emit(ProgressEvent::LlmCallComplete {
            dll: dll.to_string(),
            function: function.to_string(),
            attempt: 1,
            code_length: response.content.len(),
            tokens_used: response.tokens_used,
        });

        info!(
            dll,
            function,
            code_len = response.content.len(),
            model = %response.model,
            "Translation complete"
        );

        Ok(Translation {
            dll: dll.to_string(),
            function: function.to_string(),
            function_address: Some(function_info.address),
            rust_code: response.content,
            prompt_used: prompt,
            model: self.llm.model().to_string(),
            tokens_used: response.tokens_used,
            baseline_tests,
            call_graph: function_info.call_graph.clone(),
        })
    }

    /// Translate using a pre-built [`TranslationRequest`].
    ///
    /// Skips the Ghidra fetch and analysis steps, going straight to prompt
    /// building and LLM invocation. Useful when the request data comes from
    /// a cache or manual source.
    ///
    /// # Arguments
    ///
    /// * `request` — A pre-built [`TranslationRequest`] with all context.
    pub async fn translate_from_request(&self, request: TranslationRequest) -> Result<Translation> {
        debug!(dll = %request.dll, function = %request.function, "Translating from request");

        if request.disassembly.is_empty() && request.decompiler_output.is_empty() {
            return Err(TranslatorError::MissingContext(
                "Both disassembly and decompiler output are empty".to_string(),
            ));
        }

        let prompt = build_translate_prompt(&request)?;
        let response = self
            .send_to_llm(
                &prompt,
                self.events.as_ref(),
                &request.dll,
                &request.function,
                1,
                "initial",
            )
            .await?;

        if response.content.is_empty() {
            return Err(TranslatorError::EmptyCode {
                code_len: response.content.len(),
            });
        }

        info!(
            dll = %request.dll,
            function = %request.function,
            code_len = response.content.len(),
            "Translation from request complete"
        );

        Ok(Translation {
            dll: request.dll,
            function: request.function,
            function_address: None,
            rust_code: response.content,
            prompt_used: prompt,
            model: self.llm.model().to_string(),
            tokens_used: response.tokens_used,
            baseline_tests: request.baseline_tests,
            call_graph: Vec::new(),
        })
    }

    /// Translate with automatic retry on verification failure.
    ///
    /// This is the main entry point for production use. It performs the full
    /// translation pipeline, verifies the result, and if verification fails
    /// it retries with escalating strategies:
    ///
    /// 1. **Initial attempt** — full pipeline, then verify
    /// 2. **Compile fix** — if compilation fails, feed errors back to LLM
    /// 3. **Test fix** — if tests fail, feed failing cases back to LLM
    /// 4. **Escalate** — add more context and retry
    ///
    /// The retry loop continues until success or `max_attempts` is reached.
    ///
    /// # Arguments
    ///
    /// * `dll` — The DLL containing the function.
    /// * `function` — The function name to translate.
    /// * `config` — Retry configuration (default: 3 attempts, compile_fix strategy).
    /// * `verifier` — The verification engine to use for checking translations.
    ///
    /// # Returns
    ///
    /// A [`RetryResult`] containing all attempts and the final outcome.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use calxgloss_translator::{TranslationPipeline, RetryConfig, RetryStrategy};
    /// use calxgloss_verify::Verifier;
    /// use std::path::Path;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let ghidra = calxgloss_ghidra::GhidraClient::new("http://localhost:8080")?;
    /// let llm = calxgloss_llm::LlmClient::from_url("http://localhost:11434/v1", "qwen3")?;
    /// let pipeline = TranslationPipeline::new(ghidra, llm, calxgloss_pal::ApiMappings::default());
    /// let verifier = Verifier::new(Path::new("/tmp/calxgloss-work"))?;
    /// let config = RetryConfig::default();
    ///
    /// let result = pipeline.try_translate_with_retry(
    ///     "game_logic.dll",
    ///     "DrawSprite",
    ///     &config,
    ///     &verifier,
    /// ).await?;
    ///
    /// if result.success {
    ///     println!("Success after {} attempts", result.attempts.len());
    ///     println!("{}", result.rust_code.as_ref().unwrap());
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn try_translate_with_retry(
        &self,
        dll: &str,
        function: &str,
        config: &RetryConfig,
        verifier: &Verifier,
    ) -> Result<RetryResult> {
        debug!(
            dll,
            function, "Starting translation with retry (max {} attempts)", config.max_attempts
        );

        // Step 1: Initial translation via the full pipeline
        let initial = self.translate(dll, function).await?;

        info!(
            dll,
            function,
            code_len = initial.rust_code.len(),
            "Initial translation complete, beginning verification loop"
        );

        // Step 2: Run the retry loop
        let ctx = retry::RetryLoopCtx {
            verifier,
            llm: &self.llm,
            ghidra: &self.ghidra,
            config,
            workspace: self.workspace.as_deref(),
            events: self.events.as_ref(),
        };
        let result = retry::try_translate_with_retry(initial, &ctx).await;

        if result.success {
            self.emit(ProgressEvent::TranslationCompleted {
                dll: dll.to_string(),
                function: function.to_string(),
                total_attempts: result.attempts.len(),
                success_strategy: result.success_strategy.clone(),
            });
            info!(
                dll,
                function,
                attempts = result.attempts.len(),
                strategy = %result.success_strategy.as_deref().unwrap_or("unknown"),
                "Translation succeeded via retry loop"
            );
        } else {
            self.emit(ProgressEvent::TranslationFailed {
                dll: dll.to_string(),
                function: function.to_string(),
                total_attempts: result.attempts.len(),
            });
            warn!(
                dll,
                function,
                attempts = result.attempts.len(),
                "All retry attempts exhausted without success"
            );
        }

        Ok(result)
    }

    /// Fetch function metadata from GhidraMCP.
    ///
    /// Ghidra serves the one program open in its CodeBrowser, so this is a
    /// lookup in that program. The name is resolved to an address first, and
    /// only an exact match is accepted: a substring match would silently
    /// translate a different function.
    async fn fetch_function(&self, dll: &str, function: &str) -> Result<FunctionInfo> {
        let context = |source| TranslatorError::GhidraFetch {
            dll: dll.to_string(),
            function: function.to_string(),
            source,
        };

        let matches = self
            .ghidra
            .search_functions(function, Some(10))
            .await
            .map_err(context)?;
        let found = matches.iter().find(|m| m.name == function).ok_or_else(|| {
            TranslatorError::GhidraFetch {
                dll: dll.to_string(),
                function: function.to_string(),
                source: calxgloss_ghidra::GhidraError::NotFound {
                    kind: "function",
                    query: format!(
                        "{function} (the search matched {:?})",
                        matches.iter().map(|m| &m.name).collect::<Vec<_>>()
                    ),
                },
            }
        })?;

        let report = self
            .ghidra
            .function_report(found.address)
            .await
            .map_err(context)?;

        // Ghidra has no call-graph endpoint. Callers come from the
        // cross-references to the entry; callees are read out of the
        // decompiled body and so cannot include calls through a function pointer.
        let call_graph: Vec<String> = report
            .callers
            .iter()
            .chain(report.callees.iter())
            .cloned()
            .collect();

        Ok(FunctionInfo {
            name: report.name,
            address: report.address,
            dll: dll.to_string(),
            disassembly: report.disassembly,
            decompiler_output: report.decompiled.body,
            windows_apis: Vec::new(),
            call_graph,
        })
    }

    /// Fetch the names of the open program's imports.
    ///
    /// Returned as names rather than [`Import`] values: Ghidra reports an import
    /// as a name and an external slot with no module attached, so there is no
    /// module name to put in an `Import`.
    async fn fetch_imports(&self, dll: &str) -> Result<Vec<String>> {
        self.ghidra
            .imports(None)
            .await
            .map(|symbols| symbols.into_iter().map(|s| s.name).collect())
            .map_err(|e| TranslatorError::GhidraFetch {
                dll: dll.to_string(),
                function: "<imports>".to_string(),
                source: e,
            })
    }

    /// Tag Windows API calls in the function's disassembly and imports.
    fn tag_windows_apis(
        &self,
        disassembly: &str,
        imports: &[String],
    ) -> Result<Vec<calxgloss_types::translation::WindowsApiCall>> {
        // Use the analyzer's tagging logic via the analyzer we constructed
        let tagged = self
            .analyzer
            .tag_windows_apis(disassembly, imports)
            .map_err(|e| TranslatorError::TestGen(anyhow::anyhow!("API tagging failed: {e}")))?;

        // Convert from analysis WindowsApiCall to translation WindowsApiCall
        Ok(tagged
            .into_iter()
            .map(|api| calxgloss_types::translation::WindowsApiCall {
                name: api.name,
                category: api.category,
                pal_mapping: api.pal_mapping,
            })
            .collect())
    }

    /// Generate baseline test inputs for a function.
    async fn generate_baseline_tests(
        &self,
        function_info: &FunctionInfo,
        _imports: &[String],
    ) -> Result<Vec<TestCase>> {
        // The signature Ghidra's decompiler inferred, used to derive the
        // parameters the test cases feed in.
        let signature = self.signature_for(function_info);

        // Generate test inputs from signature and disassembly
        let tests = calxgloss_testgen::generate_test_inputs(&signature, &function_info.disassembly)
            .map_err(TranslatorError::TestGen)?;

        Ok(tests)
    }

    /// The function's C signature, as Ghidra inferred it.
    ///
    /// The decompiler's first line is a real signature carrying real parameter
    /// types, so it is preferred. Only when that line is unusable — the
    /// decompilation failed, or the text is not pseudo-C — does this fall back
    /// to a placeholder, which yields boundary-value tests for the wrong
    /// parameter count rather than no tests at all.
    fn signature_for(&self, function_info: &FunctionInfo) -> String {
        if let Some(parsed) =
            calxgloss_ghidra::parse::parse_decompiled(&function_info.decompiler_output)
        {
            return parsed.signature;
        }

        warn!(
            function = %function_info.name,
            "No signature in the decompiled output; falling back to a parameter-less one"
        );
        format!("int __stdcall {}()", function_info.name)
    }

    /// Build a [`TranslationRequest`] with all gathered context.
    fn build_translation_request(
        &self,
        dll: &str,
        function: &str,
        function_info: &FunctionInfo,
        tagged_apis: Vec<calxgloss_types::translation::WindowsApiCall>,
        baseline_tests: Vec<TestCase>,
    ) -> TranslationRequest {
        TranslationRequest {
            dll: dll.to_string(),
            function: function.to_string(),
            disassembly: function_info.disassembly.trim().to_string(),
            decompiler_output: function_info.decompiler_output.trim().to_string(),
            windows_apis: tagged_apis,
            baseline_tests,
        }
    }

    /// Send a prompt to the LLM and extract the Rust code response.
    ///
    /// If `events` is provided, emits `LlmCallInProgress` keepalive events
    /// every 30 seconds while the request is in flight.
    async fn send_to_llm(
        &self,
        prompt: &str,
        events: Option<&TranslationEvents>,
        dll: &str,
        function: &str,
        attempt: u32,
        strategy: &str,
    ) -> Result<calxgloss_llm::LlmResponse> {
        let messages = vec![LlmMessage::user(prompt)];

        let response = if let Some(em) = events {
            let em = em.clone();
            let em_err = em.clone();
            let dll_s = dll.to_string();
            let function_s = function.to_string();
            let strategy_s = strategy.to_string();
            let attempt = attempt;

            // Clone values before moving into the keepalive closure
            let dll_kp = dll_s.clone();
            let function_kp = function_s.clone();
            let strategy_kp = strategy_s.clone();

            // Spawn a keepalive task that emits progress events every 30s
            let keepalive_handle = tokio::task::spawn(async move {
                let interval = std::time::Duration::from_secs(30);
                let mut elapsed = interval;
                loop {
                    tokio::time::sleep(interval).await;
                    let secs = elapsed.as_secs();
                    let _ = em.emit(ProgressEvent::LlmCallInProgress {
                        dll: dll_kp.clone(),
                        function: function_kp.clone(),
                        attempt,
                        strategy: strategy_kp.clone(),
                        elapsed_secs: secs,
                    });
                    elapsed += interval;
                }
            });

            let result = self.llm.complete(&messages).await;
            keepalive_handle.abort();

            match &result {
                Ok(_) => {}
                Err(e) => {
                    let _ = em_err.emit(ProgressEvent::LlmCallFailed {
                        dll: dll_s.clone(),
                        function: function_s.clone(),
                        attempt,
                        strategy: strategy_s.clone(),
                        error: e.to_string(),
                    });
                }
            }

            result
        } else {
            self.llm.complete(&messages).await
        }?;

        debug!(
            code_len = response.content.len(),
            model = %self.llm.model(),
            "Received LLM response"
        );

        Ok(response)
    }

    /// Get a reference to the underlying Ghidra client.
    pub fn ghidra(&self) -> &GhidraClient {
        &self.ghidra
    }

    /// Get a reference to the underlying LLM client.
    pub fn llm(&self) -> &LlmClient {
        &self.llm
    }

    /// Get a reference to the API mappings.
    pub fn api_mappings(&self) -> &ApiMappings {
        &self.api_mappings
    }

    // =========================================================
    // Batch translation
    // =========================================================

    /// Translate multiple functions from a single DLL, one at a time.
    ///
    /// For each function, this runs the full translation pipeline with retry
    /// logic (same as the single-function
    /// [`try_translate_with_retry`](Self::try_translate_with_retry) path).
    /// Functions are processed sequentially in the order provided.
    ///
    /// Unlike the single-function path, this method **does not perform git
    /// operations** — that is left to the caller so the CLI can batch the git
    /// commits or skip them entirely for a dry-run.
    ///
    /// # Arguments
    ///
    /// * `dll` — The DLL containing all functions to translate.
    /// * `functions` — Function names to translate.
    /// * `config` — Retry configuration applied to every function.
    /// * `verifier` — Verification engine used for checking translations.
    ///
    /// # Returns
    ///
    /// A [`BatchTranslationResult`] with per-function outcomes.  A function
    /// counts as a failure when all retry attempts are exhausted without
    /// producing passing tests.
    ///
    /// # Notes
    ///
    /// - If the LLM or GhidraMCP server is unreachable, the batch continues
    ///   with the remaining functions (each failure is recorded individually).
    /// - The retry strategy (compile_fix → test_fix → escalate) is applied
    ///   independently to each function.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use calxgloss_translator::TranslationPipeline;
    /// use calxgloss_verify::Verifier;
    /// use std::path::Path;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let ghidra = calxgloss_ghidra::GhidraClient::new("http://localhost:8080")?;
    /// let llm = calxgloss_llm::LlmClient::from_url("http://localhost:11434/v1", "qwen3")?;
    /// let pipeline = TranslationPipeline::new(ghidra, llm, calxgloss_pal::ApiMappings::default());
    /// let verifier = Verifier::new(Path::new("/tmp/calxgloss-work"))?;
    /// let config = calxgloss_translator::RetryConfig::default();
    ///
    /// let functions = vec!["DrawSprite".to_string(), "UpdatePosition".to_string()];
    /// let results = pipeline.batch_translate(
    ///     "game_logic.dll",
    ///     &functions,
    ///     &config,
    ///     &verifier,
    /// ).await?;
    ///
    /// println!("{} succeeded, {} failed", results.success_count(), results.failure_count());
    /// # Ok(())
    /// # }
    /// ```
    pub async fn batch_translate(
        &self,
        dll: &str,
        functions: &[String],
        config: &RetryConfig,
        verifier: &Verifier,
    ) -> Result<batch::BatchTranslationResult> {
        debug!(dll, count = functions.len(), "Starting batch translation");

        let mut batch_result = batch::BatchTranslationResult::new(dll.to_string());

        for (idx, function) in functions.iter().enumerate() {
            info!(
                dll,
                function,
                index = idx + 1,
                total = functions.len(),
                "Translating function in batch"
            );

            match self
                .try_translate_with_retry(dll, function, config, verifier)
                .await
            {
                Ok(retry_result) => {
                    if retry_result.success {
                        info!(
                            dll,
                            function,
                            attempts = retry_result.attempts.len(),
                            "Batch function succeeded"
                        );
                        let rust_code = retry_result.rust_code.clone().unwrap_or_default();
                        batch_result.add(batch::FunctionResult::success(
                            dll.to_string(),
                            function.clone(),
                            rust_code,
                            retry_result,
                            None, // git handled by caller
                        ));
                    } else {
                        warn!(
                            dll,
                            function,
                            attempts = retry_result.attempts.len(),
                            "Batch function exhausted all retries"
                        );
                        batch_result.add(batch::FunctionResult::failure(
                            dll.to_string(),
                            function.clone(),
                            retry_result,
                        ));
                    }
                }
                Err(e) => {
                    warn!(
                        dll,
                        function,
                        error = %e,
                        "Batch function translation failed (pipeline error)"
                    );
                    // Create a minimal failed result so the caller sees it
                    let empty_result = retry::RetryResult::new();
                    batch_result.add(batch::FunctionResult::failure(
                        dll.to_string(),
                        function.clone(),
                        empty_result,
                    ));
                }
            }
        }

        info!(
            dll,
            total = batch_result.total_count(),
            success = batch_result.success_count(),
            failure = batch_result.failure_count(),
            "Batch translation complete"
        );

        Ok(batch_result)
    }
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_translator_creation() {
        let llm = LlmClient::from_url("http://localhost:11434/v1", "qwen3").unwrap();
        let translator = Translator::new(llm);
        // Translator doesn't expose internal state, just verify construction
        let _ = &translator;
    }

    #[test]
    fn test_pipeline_creation() {
        let ghidra = GhidraClient::new("http://localhost:8080").unwrap();
        let llm = LlmClient::from_url("http://localhost:11434/v1", "qwen3").unwrap();
        let pipeline = TranslationPipeline::new(ghidra, llm, ApiMappings::default());

        assert!(!pipeline.api_mappings().is_empty());
    }

    #[test]
    fn test_pipeline_with_exports() {
        let ghidra = GhidraClient::new("http://localhost:8080").unwrap();
        let llm = LlmClient::from_url("http://localhost:11434/v1", "qwen3").unwrap();
        let exports = vec![Export {
            name: "DrawSprite".to_string(),
            address: 0x1000,
            signature: "int __stdcall DrawSprite(int x, int y, unsigned int texture_index)"
                .to_string(),
        }];

        let pipeline =
            TranslationPipeline::new(ghidra, llm, ApiMappings::default()).with_exports(exports);

        assert!(!pipeline.exports.is_empty());
    }

    #[test]
    fn test_translation_clone() {
        let translation = Translation {
            dll: "game_logic.dll".to_string(),
            function: "DrawSprite".to_string(),
            function_address: Some(0x1000),
            rust_code: "fn draw_sprite(x: i32, y: i32, texture_index: u32) -> i32 { x + y }"
                .to_string(),
            prompt_used: "Translate this...".to_string(),
            model: "qwen3".to_string(),
            tokens_used: Some(1024),
            baseline_tests: vec![],
            call_graph: vec!["helper_func".to_string()],
        };

        let cloned = translation.clone();
        assert_eq!(cloned.dll, translation.dll);
        assert_eq!(cloned.function, translation.function);
        assert_eq!(cloned.function_address, translation.function_address);
        assert_eq!(cloned.rust_code, translation.rust_code);
        assert_eq!(cloned.tokens_used, translation.tokens_used);
        assert_eq!(cloned.call_graph, translation.call_graph);
    }

    #[test]
    fn test_signature_comes_from_the_decompiler() {
        let ghidra = GhidraClient::new("http://localhost:8080").unwrap();
        let llm = LlmClient::from_url("http://localhost:11434/v1", "qwen3").unwrap();
        let pipeline = TranslationPipeline::new(ghidra, llm, ApiMappings::default());

        let func_info = FunctionInfo {
            name: "DrawSprite".to_string(),
            address: 0x1000,
            dll: "game_logic.dll".to_string(),
            disassembly: String::new(),
            decompiler_output: "int __stdcall DrawSprite(int x, int y, unsigned int texture_index) {\n    return x + y;\n}".to_string(),
            windows_apis: Vec::new(),
            call_graph: Vec::new(),
        };

        // The inferred signature is used as-is, parameter types included.
        assert_eq!(
            pipeline.signature_for(&func_info),
            "int __stdcall DrawSprite(int x, int y, unsigned int texture_index)"
        );
    }

    #[test]
    fn test_signature_takes_the_declarator_not_the_whole_body() {
        let ghidra = GhidraClient::new("http://localhost:8080").unwrap();
        let llm = LlmClient::from_url("http://localhost:11434/v1", "qwen3").unwrap();
        let pipeline = TranslationPipeline::new(ghidra, llm, ApiMappings::default());

        // This is the verbatim decompilation of `FUN_18008ed50` in `eqmain.dll`.
        // Reading the parameter list as everything between the first `(` and the
        // last `)` would swallow the whole body and report the parameters of the
        // expression, not of the function.
        let func_info = FunctionInfo {
            name: "FUN_18008ed50".to_string(),
            address: 0x18008ed50,
            dll: "eqmain.dll".to_string(),
            disassembly: String::new(),
            decompiler_output: "\nlonglong FUN_18008ed50(longlong param_1,int param_2)\n\n{\n  return param_1 + ((longlong)param_2 + 4) * 8;\n}\n".to_string(),
            windows_apis: Vec::new(),
            call_graph: Vec::new(),
        };

        let signature = pipeline.signature_for(&func_info);
        assert_eq!(
            signature,
            "longlong FUN_18008ed50(longlong param_1,int param_2)"
        );
        assert_eq!(
            calxgloss_testgen::parse_signature(&signature)
                .unwrap()
                .parameters
                .len(),
            2
        );
    }

    #[test]
    fn test_signature_falls_back_when_there_is_no_decompilation() {
        let ghidra = GhidraClient::new("http://localhost:8080").unwrap();
        let llm = LlmClient::from_url("http://localhost:11434/v1", "qwen3").unwrap();
        let pipeline = TranslationPipeline::new(ghidra, llm, ApiMappings::default());

        let func_info = FunctionInfo {
            name: "SomeFunc".to_string(),
            address: 0x2000,
            dll: "test.dll".to_string(),
            disassembly: String::new(),
            decompiler_output: String::new(),
            windows_apis: Vec::new(),
            call_graph: Vec::new(),
        };

        // With nothing to read, the fallback declares no parameters. It
        // previously invented three, which generated test cases feeding
        // arguments to a function that takes none.
        assert_eq!(
            pipeline.signature_for(&func_info),
            "int __stdcall SomeFunc()"
        );
    }

    #[test]
    fn test_build_minimal_prompt() {
        let llm = LlmClient::from_url("http://localhost:11434/v1", "qwen3").unwrap();
        let translator = Translator::new(llm);

        let prompt = translator
            .build_minimal_prompt(
                "game_logic.dll",
                "DrawSprite",
                "mov eax, [esp+4]\nret",
                "int DrawSprite(int x) { return x; }",
            )
            .unwrap();

        assert!(prompt.contains("DrawSprite"));
        assert!(prompt.contains("game_logic.dll"));
        assert!(prompt.contains("DISASSEMBLY"));
        assert!(prompt.contains("DECOMPILER OUTPUT"));
        assert!(!prompt.is_empty());
    }

    #[test]
    fn test_build_translation_request() {
        let ghidra = GhidraClient::new("http://localhost:8080").unwrap();
        let llm = LlmClient::from_url("http://localhost:11434/v1", "qwen3").unwrap();
        let pipeline = TranslationPipeline::new(ghidra, llm, ApiMappings::default());

        let func_info = FunctionInfo {
            name: "DrawSprite".to_string(),
            address: 0x1000,
            dll: "game_logic.dll".to_string(),
            disassembly: "mov eax, [esp+4]\nret".to_string(),
            decompiler_output: "int DrawSprite(int x) { return x; }".to_string(),
            windows_apis: Vec::new(),
            call_graph: Vec::new(),
        };

        let request = pipeline.build_translation_request(
            "game_logic.dll",
            "DrawSprite",
            &func_info,
            vec![],
            vec![],
        );

        assert_eq!(request.dll, "game_logic.dll");
        assert_eq!(request.function, "DrawSprite");
        assert_eq!(request.disassembly, "mov eax, [esp+4]\nret");
        assert_eq!(
            request.decompiler_output,
            "int DrawSprite(int x) { return x; }"
        );
    }

    #[tokio::test]
    async fn test_translate_raw_empty_response() {
        // We can't easily mock the LLM, so just verify the structure compiles
        // and the error path exists
        let llm = LlmClient::from_url("http://localhost:11434/v1", "qwen3").unwrap();
        let translator = Translator::new(llm);

        // This will fail because there's no LLM server, but that's expected
        let result = translator
            .translate_raw("test.dll", "TestFunc", "code", "")
            .await;
        assert!(result.is_err());
    }
}
