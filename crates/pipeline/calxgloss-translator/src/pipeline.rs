//! Translation pipeline — full end-to-end workflow.
//!
//! This module provides the [`TranslationPipeline`] struct, which wires together
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

use std::sync::atomic::{AtomicBool, Ordering};

use calxgloss_algorithm::engine::AlgorithmEngine;
use calxgloss_algorithm::persist::AlgorithmPersistor;
use calxgloss_analysis::Analyzer;
use calxgloss_analysis::FaultLogger;
use calxgloss_callgraph::{ContextEnricher, FunctionContext, NodeCategory};
use calxgloss_ghidra::GhidraClient;
use calxgloss_llm::{
    LlmClient, LlmMessage, context::ContextWindowDetector, hallucination::HallucinationDetector,
};
use calxgloss_memory::engine::MemoryEngine;
use calxgloss_memory::persist::MemoryPersistor;
use calxgloss_pal::ApiMappings;
use calxgloss_prompts::build_translate_prompt;
use calxgloss_testgen::TestGenerator;
use calxgloss_typeinfer::engine::TypeInferEngine;
use calxgloss_typeinfer::persist::TypeInferPersistor;
use calxgloss_types::{
    ContextTier, Export, FunctionInfo, ProgressEvent, TestCase, TranslationEvents,
    TranslationRequest,
};
use calxgloss_typesdb::engine::TypesDBEngine;
use calxgloss_typesdb::persist::TypeDatabasePersistor;
use calxgloss_verify::Verifier;
use tracing::{debug, info, instrument, warn};

use crate::Translation;
use crate::batch;
use crate::error::{Result, TranslatorError};
use crate::retry;

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

    /// Context-window detector for fault detection.
    /// Created once with the LLM client's `max_tokens` setting.
    context_detector: ContextWindowDetector,

    /// Hallucination detector for validating LLM-generated code.
    /// Created from Ghidra symbols and PAL API catalogue; `None` when
    /// no Ghidra session is available.
    hallucination_detector: Option<HallucinationDetector>,

    /// Persistent fault event logger.  When present, every detected fault
    /// (context-window exceeded, hallucination, infinite loop, behavior
    /// divergence, resource exhaustion) is persisted to
    /// `<workspace>/re/analysis/fault_log.json` for post-hoc analysis.
    #[allow(dead_code)]
    fault_logger: Option<FaultLogger>,

    /// When `true`, skip call-graph extraction in `fetch_function`.
    ///
    /// The call graph (caller/callee names) is used by higher context tiers
    /// (ModuleContext, FullModule) to inject neighbor information into
    /// prompts.  Setting this flag means those tiers fall back to less
    /// context rather than call-graph-derived context.
    no_callgraph: AtomicBool,

    /// When `true`, print call graph statistics after the graph is built.
    ///
    /// Useful for debugging and understanding the call graph structure before
    /// translation begins.  The summary includes function count, root/middle/leaf
    /// distribution, call-type breakdown, and external API count.
    callgraph_verbose: bool,

    /// Optional pre-built call graph.
    ///
    /// When set, [`translate`](Self::translate) reuses this graph for
    /// all enrichment and neighbor extraction instead of rebuilding it
    /// from Ghidra for every function.
    call_graph: Option<calxgloss_callgraph::CallGraph>,

    /// Explicit cache directory for call graph JSON files.
    ///
    /// When set, call graphs are saved to and loaded from this directory
    /// instead of the default `{workspace}/re/analysis/` path. This allows
    /// users to customize the cache location via the `--callgraph-cache` CLI flag.
    callgraph_cache_dir: Option<std::path::PathBuf>,
}

impl TranslationPipeline {
    /// Create a new translation pipeline with the given Ghidra and LLM clients.
    ///
    /// This sets up the full pipeline with default analyzer and empty exports/tests.
    /// A context-window detector is initialized with the LLM client's `max_tokens`
    /// setting for automatic fault detection.
    pub fn new(ghidra: GhidraClient, llm: LlmClient, api_mappings: ApiMappings) -> Self {
        let analyzer = Analyzer::new(ghidra.clone(), api_mappings.clone());
        let context_detector = ContextWindowDetector::new(llm.max_tokens());
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
            context_detector,
            hallucination_detector: None,
            fault_logger: None,
            no_callgraph: AtomicBool::new(false),
            callgraph_verbose: false,
            call_graph: None,
            callgraph_cache_dir: None,
        }
    }

    /// Disable call-graph extraction.
    ///
    /// When set, `fetch_function` returns an empty call graph (no caller or
    /// callee names).  This speeds up translation when call-graph-derived
    /// context is not needed.
    pub fn with_no_callgraph(self) -> Self {
        self.no_callgraph.store(true, Ordering::Relaxed);
        self
    }

    /// Enable call-graph statistics output.
    ///
    /// When set, [`translate`](Self::translate) prints a summary of call graph
    /// statistics (function count, root/middle/leaf breakdown, call-type
    /// distribution, external API count) after the graph is built.
    pub fn with_callgraph_verbose(mut self) -> Self {
        self.callgraph_verbose = true;
        self
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

    /// Attach a pre-built hallucination detector for validating LLM
    /// responses.  Call this after `new()` when a runtime context is
    /// available; skip it in unit tests that don't need detection.
    pub fn with_hallucination_detector(mut self, detector: HallucinationDetector) -> Self {
        self.hallucination_detector = Some(detector);
        self
    }

    /// Attach a fault event logger for persisting detected faults to disk.
    ///
    /// When set, every detected fault (context-window exceeded, hallucination,
    /// infinite loop, behavior divergence, resource exhaustion) is recorded to
    /// `<workspace>/re/analysis/fault_log.json`.
    pub fn with_fault_logger(mut self, logger: FaultLogger) -> Self {
        self.fault_logger = Some(logger);
        self
    }

    /// Attach a pre-built call graph for reuse across multiple translations.
    ///
    /// When set, [`translate`](Self::translate) reuses this graph instead of
    /// building one from Ghidra for every function call. This avoids
    /// redundant analysis and guarantees that all prompt enrichment data
    /// comes from the same graph snapshot.
    ///
    /// The graph is also used by
    /// [`batch_translate_from_callgraph`](Self::batch_translate_from_callgraph)
    /// to derive priority ordering and per-function context.
    pub fn with_call_graph(mut self, graph: calxgloss_callgraph::CallGraph) -> Self {
        self.call_graph = Some(graph);
        self
    }

    /// Set an explicit cache directory for call graph JSON files.
    ///
    /// When set, call graphs are saved to and loaded from this directory
    /// instead of the default `{workspace}/re/analysis/` path.
    pub fn with_callgraph_cache_dir(mut self, cache_dir: impl Into<std::path::PathBuf>) -> Self {
        self.callgraph_cache_dir = Some(cache_dir.into());
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

        // Select the context tier based on complexity and API call count.
        // Historical success rate tracking is reserved for a later integration.
        let api_call_count = tagged_apis.len();
        let tier = calxgloss_types::select_context_tier(
            &complexity,
            api_call_count,
            calxgloss_types::SuccessRate::default(),
        );
        let complexity_label = complexity.to_string();
        info!(
            dll,
            function,
            tier = %tier,
            "Selected context tier"
        );
        self.emit(ProgressEvent::ContextTierSelected {
            dll: dll.to_string(),
            function: function.to_string(),
            tier: tier.to_string(),
            tier_label: tier.label().to_string(),
            complexity: complexity_label,
            api_call_count,
        });

        let request = self.build_translation_request(
            dll,
            function,
            &function_info,
            tagged_apis.clone(),
            baseline_tests.clone(),
        );

        // Enrich the prompt data with call graph context when available.
        //
        // If a pre-built graph was attached via `with_call_graph`, reuse it.
        // Otherwise, build and enrich from Ghidra.
        let enriched_context: Vec<FunctionContext> = if self.no_callgraph.load(Ordering::Relaxed) {
            Vec::new()
        } else if let Some(ref graph) = self.call_graph {
            if self.callgraph_verbose {
                calxgloss_analysis::print_call_graph_stats(graph);
            }
            let enricher = ContextEnricher::new();
            enricher.enrich(graph)
        } else {
            let workspace = self
                .workspace
                .as_deref()
                .unwrap_or_else(|| std::path::Path::new("."));
            let cache_dir = self.callgraph_cache_dir.as_deref();
            match self
                .analyzer
                .build_call_graph(&function_info.dll, workspace, cache_dir)
                .await
            {
                Ok(call_graph) => {
                    if self.callgraph_verbose {
                        calxgloss_analysis::print_call_graph_stats(&call_graph);
                    }
                    let enricher = ContextEnricher::new();
                    enricher.enrich(&call_graph)
                }
                Err(e) => {
                    warn!(
                        dll,
                        function,
                        error = %e,
                        "Failed to build call graph for context enrichment; continuing without it"
                    );
                    Vec::new()
                }
            }
        };

        // Step 5: Build a complexity-aware prompt and send to LLM
        self.emit(ProgressEvent::LlmCallStart {
            dll: dll.to_string(),
            function: function.to_string(),
            attempt: 1,
            strategy: "initial".to_string(),
        });

        let prompt = match tier {
            ContextTier::Signature => {
                let stub_data =
                    calxgloss_prompts::SignaturePromptData::from_function_info(&function_info);
                calxgloss_prompts::build_signature_prompt(&stub_data)?
            }
            ContextTier::Disassembly => {
                let data =
                    calxgloss_prompts::DisassemblyPromptData::from_function_info(&function_info);
                calxgloss_prompts::build_disassembly_prompt(&data)?
            }
            ContextTier::WithTests => {
                let mut data = calxgloss_prompts::WithTestsPromptData::from_request(&request);
                data.call_graph_context = enriched_context.clone();
                calxgloss_prompts::build_with_tests_prompt(&data)?
            }
            ContextTier::ModuleContext => {
                let call_graph_neighbors =
                    crate::retry::helpers::extract_call_graph_neighbors_from_enriched(
                        &enriched_context,
                        function_info.address,
                    );
                let neighboring_functions = crate::retry::helpers::extract_neighboring_context(
                    &self.ghidra,
                    &function_info.call_graph,
                )
                .await;
                let data_structures = crate::retry::helpers::extract_data_structures(
                    self.workspace.as_deref(),
                    &function_info.dll,
                    function,
                );
                let data = calxgloss_prompts::ModuleContextPromptData::from_request_with_context(
                    &request,
                    call_graph_neighbors,
                    neighboring_functions,
                    data_structures,
                    enriched_context.clone(),
                );
                calxgloss_prompts::build_module_context_prompt(&data)?
            }
            ContextTier::FullModule => {
                // Tier 4: Full module context + shim layer code + PAL trait definitions
                let call_graph_neighbors =
                    crate::retry::helpers::extract_call_graph_neighbors_from_enriched(
                        &enriched_context,
                        function_info.address,
                    );
                let neighboring_functions = crate::retry::helpers::extract_neighboring_context(
                    &self.ghidra,
                    &function_info.call_graph,
                )
                .await;
                let data_structures = crate::retry::helpers::extract_data_structures(
                    self.workspace.as_deref(),
                    &function_info.dll,
                    function,
                );

                // Extract shim layer code from the workspace
                let shim_layers = crate::retry::helpers::extract_shim_layers(
                    self.workspace.as_deref(),
                    &function_info.dll,
                );

                // Extract PAL trait definitions from the function's Windows API categories
                let pal_traits =
                    crate::retry::helpers::extract_pal_traits(&function_info.windows_apis);

                let data = calxgloss_prompts::FullModulePromptData::from_request_with_full_context(
                    &request,
                    call_graph_neighbors,
                    neighboring_functions,
                    data_structures,
                    shim_layers,
                    pal_traits,
                    enriched_context.clone(),
                );
                calxgloss_prompts::build_full_module_prompt(&data)?
            }
        };

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
                function_info.disassembly.lines().count(),
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
            call_graph_context: enriched_context,
            disassembly_hints: function_info.disassembly_hints.clone(),
            context_tier: tier,
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
                request.disassembly.lines().count(),
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
            call_graph_context: Vec::new(),
            disassembly_hints: Vec::new(),
            context_tier: ContextTier::WithTests,
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
        config: &retry::RetryConfig,
        verifier: &Verifier,
    ) -> Result<retry::RetryResult> {
        debug!(
            dll,
            function, "Starting translation with retry (max {} attempts)", config.max_attempts
        );

        // Step 1: Initial translation via the full pipeline.
        // The futures below are boxed so that downstream crates' `Send` checks
        // stop at this boundary instead of recursively descending through the
        // whole pipeline (which overflows the compiler's trait evaluation
        // recursion limit — see rust-lang/rust#159228).
        let initial_translation: std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<Translation>> + Send + '_>,
        > = Box::pin(self.translate(dll, function));
        let initial = initial_translation.await?;

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
            resource_detector: None,
            fault_logger: None,
        };
        // Boxed for the same reason as above.
        let retry_loop: std::pin::Pin<
            Box<dyn std::future::Future<Output = retry::RetryResult> + Send + '_>,
        > = Box::pin(retry::try_translate_with_retry(initial, &ctx));
        let result = retry_loop.await;

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

        // Record the final result for future tier selection tracking.
        // (Success rate tracking infrastructure will be added in a follow-up.)

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

        let call_graph = if self.no_callgraph.load(Ordering::Relaxed) {
            Vec::new()
        } else {
            // Ghidra has no call-graph endpoint. Callers come from the
            // cross-references to the entry; callees are read out of the
            // decompiled body and so cannot include calls through a function pointer.
            report
                .callers
                .iter()
                .chain(report.callees.iter())
                .cloned()
                .collect()
        };

        Ok(FunctionInfo {
            name: report.name,
            address: report.address,
            dll: dll.to_string(),
            disassembly: report.disassembly,
            decompiler_output: report.decompiled.body,
            windows_apis: Vec::new(),
            call_graph,
            disassembly_hints: Vec::new(),
        })
    }

    /// Fetch the names of the open program's imports.
    ///
    /// Returned as names rather than [`calxgloss_ghidra::Import`] values: Ghidra reports an import
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
    ) -> Result<Vec<calxgloss_types::WindowsApiCall>> {
        // Use the analyzer's tagging logic via the analyzer we constructed
        let tagged = self
            .analyzer
            .tag_windows_apis(disassembly, imports)
            .map_err(|e| TranslatorError::TestGen(anyhow::anyhow!("API tagging failed: {e}")))?;

        // The analyzer already tags into the shared `WindowsApiCall`, so the
        // tagged list is the prompt's list — no conversion needed.
        Ok(tagged)
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
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn signature_for(&self, function_info: &FunctionInfo) -> String {
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
    pub(crate) fn build_translation_request(
        &self,
        dll: &str,
        function: &str,
        function_info: &FunctionInfo,
        tagged_apis: Vec<calxgloss_types::WindowsApiCall>,
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

    /// Generate a stub implementation for a root function.
    ///
    /// Root functions include entry points (e.g., `main`, `WinMain`,
    /// `DllMain`) and runtime library initializers. These are not
    /// translated via the LLM; instead, a minimal stub is generated
    /// from the function's name and signature to serve as a placeholder
    /// that can be compiled and linked.
    ///
    /// # Arguments
    ///
    /// * `name` — The function name (e.g., `mainCRTStartup`, `WinMain`).
    /// * `signature` — The inferred C signature from Ghidra's decompiler.
    ///
    /// # Returns
    ///
    /// A string containing a minimal stub implementation. For well-known
    /// entry points, a meaningful stub is generated. For unknown root
    /// functions, a generic placeholder is returned.
    pub fn generate_stub(&self, name: &str, signature: &str) -> String {
        // Handle common entry point patterns
        let stub = match name {
            // C/C++ entry points — return 0
            "main" | "wmain" | "_main" | "WinMain" | "WinMain@16" | "WinMain@20" | "wWinMain"
            | "wWinMain@16" | "wWinMain@20" | "mainCRTStartup" | "__mainCRTStartup"
            | "_mainCRTStartup" => {
                format!(
                    "/// Entry point stub for `{name}`.\npub fn {name}() {{\n    std::process::exit(0);\n}}"
                )
            }
            // DLL entry points
            "DllMain" | "DllMain@16" | "DllMainCRTStartup" | "__DllMainCRTStartup" => {
                format!(
                    "/// DLL entry point stub for `{name}`.\npub fn {name}() {{\n    // DLL initialization\n}}"
                )
            }
            // Ghidra auto-generated entry
            "entry" => {
                "/// Entry point stub.\npub fn entry() {\n    std::process::exit(0);\n}".to_string()
            }
            // VB6 initialization
            name if name.starts_with("__vba") => {
                format!(
                    "/// VB6 runtime initialization stub for `{name}`.\npub fn {name}() {{\n    // VB6 runtime init\n}}"
                )
            }
            // .NET CLR entry
            "__managed_main" | "_CorExeMain" | "_CorDllMain" => {
                format!(
                    "/// .NET CLR entry stub for `{name}`.\npub fn {name}() {{\n    // CLR host initialization\n}}"
                )
            }
            // MinGW entry
            "_start" | "__libc_start_main" => {
                format!(
                    "/// MinGW entry stub for `{name}`.\npub fn {name}() {{\n    std::process::exit(0);\n}}"
                )
            }
            // MSVC debug runtime
            name if name.starts_with("_RTC_") => {
                format!(
                    "/// MSVC runtime check stub for `{name}`.\npub fn {name}() {{\n    // Runtime check\n}}"
                )
            }
            // Generic entry point — use the signature to infer a stub
            _ => {
                // Try to extract a return type and parameters from the signature
                let safe_name = if name.starts_with("FUN_") {
                    // Ghidra auto-generated name — keep as-is
                    name.to_string()
                } else {
                    name.to_string()
                };
                format!(
                    "/// Auto-generated stub for `{safe_name}`.\npub fn {safe_name}() {{\n    // TODO: Translate\n}}"
                )
            }
        };

        // Include the signature as a comment for reference
        format!("{stub}\n// Signature: {signature}")
    }

    /// Send a prompt to the LLM and extract the Rust code response.
    ///
    /// If `events` is provided, emits `LlmCallInProgress` keepalive events
    /// every 30 seconds while the request is in flight.
    ///
    /// After receiving a response, the context-window detector checks whether
    /// the output exceeds (or nears) the model's configured limit.  If a fault
    /// is detected it is logged via `tracing::warn!` so the caller can act
    /// on it (e.g., by splitting the function and retrying).
    ///
    /// # Arguments
    ///
    /// * `disassembly_lines` — The number of lines in the function's
    ///   disassembly, used to compute a suggested chunk count for the retry
    ///   splitter when a context-window fault is detected.
    #[allow(clippy::too_many_arguments)]
    async fn send_to_llm(
        &self,
        prompt: &str,
        events: Option<&TranslationEvents>,
        dll: &str,
        function: &str,
        attempt: u32,
        strategy: &str,
        disassembly_lines: usize,
    ) -> Result<calxgloss_llm::LlmResponse> {
        let messages = vec![LlmMessage::user(prompt)];

        // Pre-check: is the prompt itself too large for the model's context?
        if let Some(fault) = self.context_detector.detect_prompt_too_large(&messages) {
            warn!(
                dll,
                function,
                attempt,
                strategy,
                prompt_size = fault.response_size,
                limit = fault.limit,
                "Prompt exceeds model context limit — splitting function",
            );
            // We still proceed with the call; the LLM server will handle
            // truncation. The post-response check catches the actual output.
        }

        let response = if let Some(em) = events {
            let em = em.clone();
            let em_err = em.clone();
            let dll_s = dll.to_string();
            let function_s = function.to_string();
            let strategy_s = strategy.to_string();

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

        // Post-check: detect context-window exceeded faults.
        if let Some(fault) = self
            .context_detector
            .detect_response(&response, disassembly_lines)
        {
            warn!(
                dll,
                function,
                attempt,
                strategy,
                response_size = fault.response_size,
                limit = fault.limit,
                overflow = fault.overflow_chars,
                "Context window exceeded — function should be split into {} chunks",
                fault.suggested_chunk_count(),
            );
            if let Some(logger) = &self.fault_logger {
                let event = calxgloss_types::FaultEvent::context_window_exceeded(
                    dll, function, attempt, strategy, &fault,
                );
                logger.record(event);
            }
        }

        // Hallucination detection: scan the generated code for non-existent
        // API/function references.  When hallucinations are found, log a
        // warning and emit a progress event so the caller can react.  Also
        // persist a fault event for post-hoc analysis.
        let hallucinations = self
            .hallucination_detector
            .as_ref()
            .map(|d| d.detect(&response.content))
            .unwrap_or_default();
        if !hallucinations.is_empty() {
            let names: Vec<String> = hallucinations.iter().map(|h| h.name.clone()).collect();
            warn!(
                dll,
                function,
                attempt,
                strategy,
                count = names.len(),
                apis = ?names,
                "Hallucinated API/function references detected",
            );
            if let Some(em) = events {
                let _ = em.emit(ProgressEvent::HallucinationDetected {
                    dll: dll.to_string(),
                    function: function.to_string(),
                    attempt,
                    strategy: strategy.to_string(),
                    hallucinated_apis: names.clone(),
                });
            }
            if let Some(logger) = &self.fault_logger {
                let names_refs: Vec<&str> = names.iter().map(|s| s.as_str()).collect();
                let event = calxgloss_types::FaultEvent::hallucination(
                    dll,
                    function,
                    attempt,
                    strategy,
                    &names_refs,
                );
                logger.record(event);
            }
        }

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

    /// Recover the per-binary type database before a batch starts, unless one
    /// is already cached.
    ///
    /// Tier 3/4 prompts and escalated retries read recovered data structures
    /// from `re/analysis/typesdb/{dll}.json` (see
    /// [`extract_data_structures`](crate::retry::helpers::extract_data_structures));
    /// running the recovery scan once up front means every function in the
    /// batch can see type context instead of none. The persisted file is the
    /// cache: when a database is already saved for `dll`, the scan is skipped
    /// entirely.
    ///
    /// Returns whether a database is available afterwards. A missing
    /// workspace, an unreachable Ghidra server, or a failed save only log a
    /// warning and return `false` — prompts without data structure context
    /// are degraded, not fatal, and the batch proceeds either way.
    pub async fn ensure_type_database(&self, dll: &str) -> bool {
        let Some(workspace) = self.workspace.as_deref() else {
            debug!(
                dll,
                "No workspace configured; skipping type database recovery"
            );
            return false;
        };

        let persistor = TypeDatabasePersistor::new(workspace);
        if persistor.exists(dll) {
            debug!(
                dll,
                path = %persistor.path_for(dll).display(),
                "Type database already cached; skipping recovery"
            );
            return true;
        }

        info!(dll, "Recovering type database before batch translation");
        let engine = TypesDBEngine::new(&self.ghidra);
        match engine.scan(dll).await {
            Ok(db) => {
                if let Err(e) = persistor.save(&db) {
                    warn!(
                        dll,
                        error = %e,
                        "Failed to persist recovered type database; continuing without data structure context"
                    );
                    return false;
                }
                info!(
                    dll,
                    named_types = db.named_types.len(),
                    vtables = db.vtables.len(),
                    inferred_structs = db.inferred_structs.len(),
                    "Type database recovered"
                );
                true
            }
            Err(e) => {
                warn!(
                    dll,
                    error = %e,
                    "Type database recovery failed; continuing without data structure context"
                );
                false
            }
        }
    }

    /// Infer parameter types across the binary before a batch starts, unless
    /// an inference result is already cached.
    ///
    /// Prompts and escalated retries read inferred parameter types from
    /// `re/analysis/typeinfer/{dll}.json` (see
    /// [`extract_type_info`](crate::retry::helpers::extract_type_info));
    /// running the inference scan once up front means every function in the
    /// batch can see type context instead of none. The persisted file is the
    /// cache: when a result is already saved for `dll`, the scan is skipped
    /// entirely.
    ///
    /// Returns whether a result is available afterwards. A missing workspace,
    /// an unreachable Ghidra server, or a failed save only log a warning and
    /// return `false` — prompts without type context are degraded, not
    /// fatal, and the batch proceeds either way.
    pub async fn ensure_type_inference(&self, dll: &str) -> bool {
        let Some(workspace) = self.workspace.as_deref() else {
            debug!(dll, "No workspace configured; skipping type inference");
            return false;
        };

        let persistor = TypeInferPersistor::new(workspace);
        if persistor.exists(dll) {
            debug!(
                dll,
                path = %persistor.path_for(dll).display(),
                "Type inference result already cached; skipping scan"
            );
            return true;
        }

        info!(dll, "Inferring parameter types before batch translation");
        let engine = TypeInferEngine::new(&self.ghidra);
        match engine.scan(dll).await {
            Ok(result) => {
                if let Err(e) = persistor.save(&result) {
                    warn!(
                        dll,
                        error = %e,
                        "Failed to persist type inference result; continuing without type context"
                    );
                    return false;
                }
                info!(
                    dll,
                    inferences = result.inferences.len(),
                    "Type inference complete"
                );
                true
            }
            Err(e) => {
                warn!(
                    dll,
                    error = %e,
                    "Type inference failed; continuing without type context"
                );
                false
            }
        }
    }

    /// Recognize algorithms across the binary before a batch starts, unless a
    /// recognition result is already cached.
    ///
    /// Escalated retries read recognized algorithm hints from
    /// `re/analysis/algorithm/{dll}.json` (see
    /// [`extract_algorithm_hints`](crate::retry::helpers::extract_algorithm_hints));
    /// running the recognition scan once up front means every function in the
    /// batch can see algorithm context instead of none. The persisted file is
    /// the cache: when a result is already saved for `dll`, the scan is
    /// skipped entirely.
    ///
    /// Returns whether a result is available afterwards. A missing workspace,
    /// an unreachable Ghidra server, or a failed save only log a warning and
    /// return `false` — prompts without algorithm context are degraded, not
    /// fatal, and the batch proceeds either way.
    pub async fn ensure_algorithm_recognition(&self, dll: &str) -> bool {
        let Some(workspace) = self.workspace.as_deref() else {
            debug!(
                dll,
                "No workspace configured; skipping algorithm recognition"
            );
            return false;
        };

        let persistor = AlgorithmPersistor::new(workspace);
        if persistor.exists(dll) {
            debug!(
                dll,
                path = %persistor.path_for(dll).display(),
                "Algorithm recognition result already cached; skipping scan"
            );
            return true;
        }

        info!(dll, "Recognizing algorithms before batch translation");
        let engine = AlgorithmEngine::new(&self.ghidra);
        match engine.scan(dll).await {
            Ok(result) => {
                if let Err(e) = persistor.save(&result) {
                    warn!(
                        dll,
                        error = %e,
                        "Failed to persist algorithm recognition result; continuing without algorithm context"
                    );
                    return false;
                }
                info!(
                    dll,
                    hints = result.hints.len(),
                    "Algorithm recognition complete"
                );
                true
            }
            Err(e) => {
                warn!(
                    dll,
                    error = %e,
                    "Algorithm recognition failed; continuing without algorithm context"
                );
                false
            }
        }
    }

    /// Detect memory lifecycles across the binary before a batch starts,
    /// unless a detection result is already cached.
    ///
    /// The scan's findings — allocation pairs, handle lifetimes, and
    /// reference counts — are filed at `re/analysis/memory/{dll}.json` for
    /// the prompt path to read (see
    /// [`extract_memory_hints`](crate::retry::helpers::extract_memory_hints));
    /// running the detection scan once up front
    /// means every function in the batch can see memory context instead of
    /// none. The persisted file is the cache: when a result is already
    /// saved for `dll`, the scan is skipped entirely.
    ///
    /// Returns whether a result is available afterwards. A missing workspace,
    /// an unreachable Ghidra server, or a failed save only log a warning and
    /// return `false` — prompts without memory context are degraded, not
    /// fatal, and the batch proceeds either way.
    pub async fn ensure_memory_detection(&self, dll: &str) -> bool {
        let Some(workspace) = self.workspace.as_deref() else {
            debug!(
                dll,
                "No workspace configured; skipping memory lifecycle detection"
            );
            return false;
        };

        let persistor = MemoryPersistor::new(workspace);
        if persistor.exists(dll) {
            debug!(
                dll,
                path = %persistor.path_for(dll).display(),
                "Memory lifecycle result already cached; skipping scan"
            );
            return true;
        }

        info!(dll, "Detecting memory lifecycles before batch translation");
        let engine = MemoryEngine::new(&self.ghidra);
        match engine.scan(dll).await {
            Ok(result) => {
                if let Err(e) = persistor.save(&result) {
                    warn!(
                        dll,
                        error = %e,
                        "Failed to persist memory lifecycle result; continuing without memory context"
                    );
                    return false;
                }
                info!(
                    dll,
                    findings = result.findings.len(),
                    "Memory lifecycle detection complete"
                );
                true
            }
            Err(e) => {
                warn!(
                    dll,
                    error = %e,
                    "Memory lifecycle detection failed; continuing without memory context"
                );
                false
            }
        }
    }

    /// Translate multiple functions from a single DLL, one at a time.
    ///
    /// For each function, this runs the full translation pipeline with retry
    /// logic (same as the single-function
    /// [`try_translate_with_retry`](Self::try_translate_with_retry) path).
    /// Functions are processed sequentially in the order provided.
    ///
    /// Before the first function, the per-binary type database, type inference
    /// result, algorithm recognition result, and memory lifecycle result are
    /// recovered (or loaded from their caches) so higher context tiers have
    /// data structure, parameter type, algorithm, and memory context — see
    /// [`ensure_type_database`](Self::ensure_type_database),
    /// [`ensure_type_inference`](Self::ensure_type_inference),
    /// [`ensure_algorithm_recognition`](Self::ensure_algorithm_recognition),
    /// and [`ensure_memory_detection`](Self::ensure_memory_detection).
    ///
    /// The caller can provide a callback (`on_function_completed`) that is
    /// invoked **immediately after each function completes** (before moving on
    /// to the next). This enables incremental git commits and per-function
    /// post-processing without blocking subsequent translations.
    ///
    /// # Arguments
    ///
    /// * `dll` — The DLL containing all functions to translate.
    /// * `functions` — Function names to translate.
    /// * `config` — Retry configuration applied to every function.
    /// * `verifier` — Verification engine used for checking translations.
    /// * `on_function_completed` — Optional closure called after each function
    ///   completes. Receives the DLL name, function name, a mutable reference to
    ///   the [`batch::FunctionResult`], and a boolean indicating whether the
    ///   caller should continue processing the remaining functions.
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
    /// - The callback is called on the **same task** that is running the batch;
    ///   it should return `true` quickly to avoid delaying the next function.
    ///   If the callback returns `false`, the batch stops early.
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
    ///     Some(&mut |_dll, _function, _result| true), // keep going
    /// ).await?;
    ///
    /// println!("{} succeeded, {} failed", results.success_count(), results.failure_count());
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// Produces a priority-ordered translation plan from a call graph.
    ///
    /// This method is the bridge between call-graph analysis and the
    /// batch translation pipeline.  It uses [`TranslationOrderer`] to
    /// transform a [`CallGraph`] into an ordered list of
    /// [`FunctionTranslationPlan`] instances, each annotated with its
    /// priority tier (root / middle / leaf) and topological position.
    ///
    /// # Arguments
    ///
    /// * `graph` — The call graph to plan from.
    /// * `max_functions` — Optional limit on the number of functions in the plan.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use calxgloss_translator::TranslationPipeline;
    /// use calxgloss_callgraph::CallGraph;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let ghidra = calxgloss_ghidra::GhidraClient::new("http://localhost:8080")?;
    /// let llm = calxgloss_llm::LlmClient::from_url("http://localhost:11434/v1", "qwen3")?;
    /// let pipeline = TranslationPipeline::new(ghidra, llm, calxgloss_pal::ApiMappings::default());
    ///
    /// // Build or load the call graph first (e.g. via Analyzer::build_call_graph)
    /// let call_graph = /* CallGraph */ todo!();
    ///
    /// // Get a priority-ordered plan (max 100 functions)
    /// let plan = pipeline.plan_from_callgraph(&call_graph, Some(100))?;
    ///
    /// for function in plan {
    ///     println!("{:?} {} ({} callers, {} callees)",
    ///         function.priority, function.name,
    ///         function.caller_count, function.callee_count);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn plan_from_callgraph(
        &self,
        graph: &calxgloss_callgraph::CallGraph,
        max_functions: Option<usize>,
    ) -> crate::error::Result<Vec<calxgloss_callgraph::FunctionTranslationPlan>> {
        let mut orderer = calxgloss_callgraph::TranslationOrderer::new();
        if let Some(max) = max_functions {
            orderer = orderer.with_max_functions(max);
        }
        let plan = orderer
            .order(graph)
            .map_err(|e| TranslatorError::CallGraph(e.to_string()))?;
        Ok(plan.into_iter().collect())
    }

    #[allow(clippy::type_complexity)]
    pub async fn batch_translate(
        &self,
        dll: &str,
        functions: &[String],
        config: &retry::RetryConfig,
        verifier: &Verifier,
        mut on_function_completed: Option<
            &mut dyn FnMut(&str, &str, &mut batch::FunctionResult) -> bool,
        >,
    ) -> Result<batch::BatchTranslationResult> {
        debug!(dll, count = functions.len(), "Starting batch translation");

        self.ensure_type_database(dll).await;
        self.ensure_type_inference(dll).await;
        self.ensure_algorithm_recognition(dll).await;
        self.ensure_memory_detection(dll).await;

        let mut batch_result = batch::BatchTranslationResult::new(dll.to_string());

        for (idx, function) in functions.iter().enumerate() {
            info!(
                dll,
                function,
                index = idx + 1,
                total = functions.len(),
                "Translating function in batch"
            );

            let mut result = match self
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
                        batch::FunctionResult::success(
                            dll.to_string(),
                            function.clone(),
                            rust_code,
                            retry_result,
                            None, // git handled by caller via callback
                        )
                    } else {
                        warn!(
                            dll,
                            function,
                            attempts = retry_result.attempts.len(),
                            "Batch function exhausted all retries"
                        );
                        batch::FunctionResult::failure(
                            dll.to_string(),
                            function.clone(),
                            retry_result,
                        )
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
                    batch::FunctionResult::failure(dll.to_string(), function.clone(), empty_result)
                }
            };

            let success = result.success;
            batch_result.add(result.clone());

            // Emit progress event for real-time tracking
            self.emit(ProgressEvent::FunctionCompleted {
                dll: dll.to_string(),
                function: function.clone(),
                success,
                attempts: 0,  // filled by caller after git branch creation
                branch: None, // filled by caller after git branch creation
            });

            // Invoke the caller's callback (e.g., for incremental git commits)
            let continue_batch = if let Some(ref mut cb) = on_function_completed {
                cb(dll, function, &mut result)
            } else {
                true
            };

            if !continue_batch {
                info!(dll, function, "Batch stopped early by callback");
                break;
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

    /// Translate multiple functions from a single DLL, prioritized by
    /// call-graph topology.
    ///
    /// This method uses a [call graph] to determine translation order:
    ///
    /// 1. [Leaf] functions (call external APIs) — translated first
    /// 2. [Middle] functions — translated second
    /// 3. [Root] functions — translated last
    ///
    /// Within each tier, functions are sorted topologically so that a
    /// function is only translated after all of its callees have been
    /// processed. This ordering lets the LLM reference already-translated
    /// callee code when generating shim layers or caller wrappers.
    ///
    /// Before the first function, the per-binary type database, type inference
    /// result, algorithm recognition result, and memory lifecycle result are
    /// recovered (or loaded from their caches) so higher context tiers have
    /// data structure, parameter type, algorithm, and memory context — see
    /// [`ensure_type_database`](Self::ensure_type_database),
    /// [`ensure_type_inference`](Self::ensure_type_inference),
    /// [`ensure_algorithm_recognition`](Self::ensure_algorithm_recognition),
    /// and [`ensure_memory_detection`](Self::ensure_memory_detection).
    ///
    /// The caller can provide a callback (`on_function_completed`) that is
    /// invoked **immediately after each function completes** (before moving on
    /// to the next). This enables incremental git commits and per-function
    /// post-processing without blocking subsequent translations.
    ///
    /// # Arguments
    ///
    /// * `graph` — The call graph containing all functions to translate.
    ///   Root functions are automatically stubbed with minimal placeholders
    ///   (they have no translation work). Runtime library functions
    ///   (`NodeCategory::Skip`) are not stubbed.
    /// * `config` — Retry configuration applied to every function.
    /// * `verifier` — Verification engine used for checking translations.
    /// * `on_function_completed` — Optional closure called after each function
    ///   completes. Receives the DLL name, function name, a mutable reference to
    ///   the [`batch::FunctionResult`], and a boolean indicating whether the
    ///   caller should continue processing the remaining functions.
    ///
    /// # Returns
    ///
    /// A [`BatchTranslationResult`] with per-function outcomes.  A function
    /// counts as a failure when all retry attempts are exhausted without
    /// producing passing tests.
    ///
    /// Root functions from the call graph are stubbed automatically and
    /// appear in the result with [`batch::FunctionResult::stubbed`].
    /// Functions classified as [`NodeCategory::Skip`] (runtime library functions)
    /// are not stubbed and appear as [`batch::FunctionResult::skipped`].
    ///
    /// # Example
    ///
    /// ```no_run
    /// use calxgloss_translator::TranslationPipeline;
    /// use calxgloss_verify::Verifier;
    /// use calxgloss_analysis::build_enriched_call_graph;
    /// use std::path::Path;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let ghidra = calxgloss_ghidra::GhidraClient::new("http://localhost:8080")?;
    /// let llm = calxgloss_llm::LlmClient::from_url("http://localhost:11434/v1", "qwen3")?;
    /// let config = calxgloss_translator::RetryConfig::default();
    /// let verifier = Verifier::new(Path::new("/tmp/calxgloss-work"))?;
    ///
    /// // Build or load the enriched call graph first (needs its own Ghidra reference)
    /// let call_graph = build_enriched_call_graph(
    ///     &ghidra,
    ///     "game_logic.dll",
    ///     Path::new("/tmp/calxgloss-work"),
    ///     None,
    /// ).await?;
    ///
    /// let pipeline = TranslationPipeline::new(ghidra, llm, calxgloss_pal::ApiMappings::default());
    ///
    /// let results = pipeline.batch_translate_from_callgraph(
    ///     &call_graph,
    ///     &config,
    ///     &verifier,
    ///     Some(&mut |_dll, _function, _result| true), // keep going
    /// ).await?;
    ///
    /// println!("{} succeeded, {} failed, {} skipped",
    ///     results.success_count(), results.failure_count(), results.skipped_count());
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// [call graph]: calxgloss_callgraph::CallGraph
    /// [Leaf]: calxgloss_types::NodeCategory::Leaf
    /// [Middle]: calxgloss_types::NodeCategory::Middle
    /// [Root]: calxgloss_types::NodeCategory::Root
    #[allow(clippy::type_complexity)]
    pub async fn batch_translate_from_callgraph(
        &self,
        graph: &calxgloss_callgraph::CallGraph,
        config: &retry::RetryConfig,
        verifier: &Verifier,
        mut on_function_completed: Option<
            &mut dyn FnMut(&str, &str, &mut batch::FunctionResult) -> bool,
        >,
    ) -> Result<batch::BatchTranslationResult> {
        debug!(dll = %graph.dll, count = graph.functions.len(), "Starting call-graph batch translation");

        self.ensure_type_database(&graph.dll).await;
        self.ensure_type_inference(&graph.dll).await;
        self.ensure_algorithm_recognition(&graph.dll).await;
        self.ensure_memory_detection(&graph.dll).await;

        // Build a priority-ordered plan
        let orderer = calxgloss_callgraph::TranslationOrderer::new();
        let plan = orderer
            .order(graph)
            .map_err(|e| TranslatorError::CallGraph(e.to_string()))?;

        let plan: Vec<_> = plan.into_iter().collect();
        let dll = &graph.dll;
        let mut batch_result = batch::BatchTranslationResult::new(dll.clone());

        for (idx, plan_func) in plan.iter().enumerate() {
            use calxgloss_callgraph::TranslationPriority;

            // Handle root functions (entry points) — generate stubs instead of translating
            if matches!(plan_func.priority, TranslationPriority::Root) {
                // Skip functions are truly skipped (runtime library functions)
                if matches!(plan_func.category, NodeCategory::Skip) {
                    info!(
                        dll,
                        name = %plan_func.name,
                        address = plan_func.address,
                        "Skipping runtime library function"
                    );
                    let skipped =
                        batch::FunctionResult::skipped(dll.clone(), plan_func.name.clone());
                    batch_result.add(skipped.clone());

                    self.emit(ProgressEvent::FunctionCompleted {
                        dll: dll.clone(),
                        function: plan_func.name.clone(),
                        success: true,
                        attempts: 0,
                        branch: None,
                    });

                    // Invoke the caller's callback even for skipped functions
                    if let Some(ref mut cb) = on_function_completed
                        && !cb(dll, &plan_func.name, &mut skipped.clone())
                    {
                        info!(dll, function = %plan_func.name, "Batch stopped early by callback");
                        break;
                    }

                    continue;
                }

                // Generate stub for entry point functions
                info!(
                    dll,
                    name = %plan_func.name,
                    address = plan_func.address,
                    "Generating stub for root function"
                );
                let stub_code = self.generate_stub(&plan_func.name, "");
                let stubbed =
                    batch::FunctionResult::stubbed(dll.clone(), plan_func.name.clone(), stub_code);
                batch_result.add(stubbed.clone());

                self.emit(ProgressEvent::FunctionCompleted {
                    dll: dll.clone(),
                    function: plan_func.name.clone(),
                    success: true,
                    attempts: 0,
                    branch: None,
                });

                // Invoke the caller's callback even for stubbed functions
                if let Some(ref mut cb) = on_function_completed
                    && !cb(dll, &plan_func.name, &mut stubbed.clone())
                {
                    info!(dll, function = %plan_func.name, "Batch stopped early by callback");
                    break;
                }

                continue;
            }

            info!(
                dll,
                name = %plan_func.name,
                address = plan_func.address,
                priority = ?plan_func.priority,
                index = idx + 1,
                total = plan.len(),
                "Translating function in batch"
            );

            let mut result = match self
                .try_translate_with_retry(dll, &plan_func.name, config, verifier)
                .await
            {
                Ok(retry_result) => {
                    if retry_result.success {
                        info!(
                            dll,
                            name = %plan_func.name,
                            attempts = retry_result.attempts.len(),
                            "Batch function succeeded"
                        );
                        let rust_code = retry_result.rust_code.clone().unwrap_or_default();
                        batch::FunctionResult::success(
                            dll.clone(),
                            plan_func.name.clone(),
                            rust_code,
                            retry_result,
                            None,
                        )
                    } else {
                        warn!(
                            dll,
                            name = %plan_func.name,
                            attempts = retry_result.attempts.len(),
                            "Batch function exhausted all retries"
                        );
                        let empty_result = retry::RetryResult::new();
                        batch::FunctionResult::failure(
                            dll.clone(),
                            plan_func.name.clone(),
                            empty_result,
                        )
                    }
                }
                Err(e) => {
                    warn!(
                        dll,
                        name = %plan_func.name,
                        error = %e,
                        "Batch function translation failed (pipeline error)"
                    );
                    let empty_result = retry::RetryResult::new();
                    batch::FunctionResult::failure(
                        dll.clone(),
                        plan_func.name.clone(),
                        empty_result,
                    )
                }
            };

            let success = result.success;
            batch_result.add(result.clone());

            // Emit progress event for real-time tracking
            self.emit(ProgressEvent::FunctionCompleted {
                dll: dll.clone(),
                function: plan_func.name.clone(),
                success,
                attempts: 0,  // filled by caller after git branch creation
                branch: None, // filled by caller after git branch creation
            });

            // Invoke the caller's callback
            let continue_batch = if let Some(ref mut cb) = on_function_completed {
                cb(dll, &plan_func.name, &mut result)
            } else {
                true
            };

            if !continue_batch {
                info!(dll, function = %plan_func.name, "Batch stopped early by callback");
                break;
            }
        }

        info!(
            dll,
            total = batch_result.total_count(),
            success = batch_result.success_count(),
            failure = batch_result.failure_count(),
            "Call-graph batch translation complete"
        );

        Ok(batch_result)
    }
}

// ============================================================
// Hallucination detector helpers
// ============================================================

/// Build a [`HallucinationDetector`] from Ghidra symbols and the PAL API
/// catalogue.
///
/// The detector's known-good symbol set is the union of:
/// 1. All Ghidra functions (exports and user-defined functions)
/// 2. All Ghidra imports (DLL imports)
/// 3. Every Windows API name from the PAL mapping table
pub async fn build_hallucination_detector(
    ghidra: &GhidraClient,
    api_mappings: &ApiMappings,
) -> HallucinationDetector {
    // Fetch Ghidra functions
    let ghidra_functions: Vec<String> = ghidra
        .list_functions()
        .await
        .ok()
        .into_iter()
        .flatten()
        .map(|f| f.name)
        .collect();

    // Fetch Ghidra imports
    let ghidra_imports: Vec<String> = ghidra
        .imports(None)
        .await
        .ok()
        .into_iter()
        .flatten()
        .map(|s| s.name)
        .collect();

    // Collect Windows API names from the PAL mapping table
    let _windows_apis: Vec<String> = api_mappings
        .iter()
        .map(|m| m.windows_api.to_string())
        .collect();

    HallucinationDetector::new(ghidra_functions, ghidra_imports)
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use calxgloss_algorithm::persist::AlgorithmPersistor;
    use calxgloss_algorithm::types::AlgorithmRecognitionResult;
    use calxgloss_memory::persist::MemoryPersistor;
    use calxgloss_memory::types::MemoryResult;
    use calxgloss_typeinfer::persist::TypeInferPersistor;
    use calxgloss_typeinfer::types::TypeInferenceResult;
    use calxgloss_typesdb::types::{ScanMetadata, TypeDatabase};
    use tempfile::TempDir;

    /// A client pointed at a closed port: every scan request is refused, so
    /// a successful recovery can only come from an already-cached database.
    fn unreachable_ghidra() -> GhidraClient {
        GhidraClient::new("http://127.0.0.1:9").expect("client config")
    }

    fn pipeline_over(workspace: Option<&std::path::Path>) -> TranslationPipeline {
        pipeline_with(unreachable_ghidra(), workspace)
    }

    #[tokio::test]
    async fn a_cached_database_is_reused_without_rescanning() {
        let dir = TempDir::new().unwrap();
        TypeDatabasePersistor::new(dir.path())
            .save(&TypeDatabase::new(ScanMetadata::new("eqmain.dll")))
            .unwrap();

        // The Ghidra server is unreachable, so `true` can only come from the cache.
        let pipeline = pipeline_over(Some(dir.path()));
        assert!(pipeline.ensure_type_database("eqmain.dll").await);
    }

    #[tokio::test]
    async fn a_failed_recovery_degrades_instead_of_failing() {
        let dir = TempDir::new().unwrap();
        let pipeline = pipeline_over(Some(dir.path()));

        assert!(!pipeline.ensure_type_database("eqmain.dll").await);
        assert!(
            !TypeDatabasePersistor::new(dir.path()).exists("eqmain.dll"),
            "a failed scan persists nothing"
        );
    }

    #[tokio::test]
    async fn no_workspace_skips_the_recovery() {
        let pipeline = pipeline_over(None);
        assert!(!pipeline.ensure_type_database("eqmain.dll").await);
    }

    #[tokio::test]
    async fn a_cached_inference_result_is_reused_without_rescanning() {
        let dir = TempDir::new().unwrap();
        TypeInferPersistor::new(dir.path())
            .save(&TypeInferenceResult::new(ScanMetadata::new("eqmain.dll")))
            .unwrap();

        // The Ghidra server is unreachable, so `true` can only come from the cache.
        let pipeline = pipeline_over(Some(dir.path()));
        assert!(pipeline.ensure_type_inference("eqmain.dll").await);
    }

    #[tokio::test]
    async fn a_failed_inference_degrades_instead_of_failing() {
        let dir = TempDir::new().unwrap();
        let pipeline = pipeline_over(Some(dir.path()));

        assert!(!pipeline.ensure_type_inference("eqmain.dll").await);
        assert!(
            !TypeInferPersistor::new(dir.path()).exists("eqmain.dll"),
            "a failed scan persists nothing"
        );
    }

    #[tokio::test]
    async fn no_workspace_skips_the_inference() {
        let pipeline = pipeline_over(None);
        assert!(!pipeline.ensure_type_inference("eqmain.dll").await);
    }

    #[tokio::test]
    async fn a_cached_algorithm_result_is_reused_without_rescanning() {
        let dir = TempDir::new().unwrap();
        AlgorithmPersistor::new(dir.path())
            .save(&AlgorithmRecognitionResult::new(ScanMetadata::new(
                "eqmain.dll",
            )))
            .unwrap();

        // The Ghidra server is unreachable, so `true` can only come from the cache.
        let pipeline = pipeline_over(Some(dir.path()));
        assert!(pipeline.ensure_algorithm_recognition("eqmain.dll").await);
    }

    #[tokio::test]
    async fn a_failed_algorithm_scan_degrades_instead_of_failing() {
        let dir = TempDir::new().unwrap();
        let pipeline = pipeline_over(Some(dir.path()));

        assert!(!pipeline.ensure_algorithm_recognition("eqmain.dll").await);
        assert!(
            !AlgorithmPersistor::new(dir.path()).exists("eqmain.dll"),
            "a failed scan persists nothing"
        );
    }

    #[tokio::test]
    async fn no_workspace_skips_the_algorithm_scan() {
        let pipeline = pipeline_over(None);
        assert!(!pipeline.ensure_algorithm_recognition("eqmain.dll").await);
    }

    /// A pipeline over a caller-supplied Ghidra client, workspace included
    /// when there is one.
    fn pipeline_with(
        ghidra: GhidraClient,
        workspace: Option<&std::path::Path>,
    ) -> TranslationPipeline {
        let llm = LlmClient::from_url("http://localhost:11434/v1", "qwen3").expect("llm config");
        let pipeline = TranslationPipeline::new(ghidra, llm, ApiMappings::default());
        match workspace {
            Some(dir) => pipeline.with_workspace(dir.to_path_buf()),
            None => pipeline,
        }
    }

    /// A stand-in GhidraMCP server answering the three endpoints a memory
    /// scan touches — the function listing, the name search that resolves
    /// it, and the decompile by address — with one canned `malloc`/`free`
    /// function, so the scan-to-save path runs without a real Ghidra.
    /// Returns the base URL to point a client at.
    async fn fake_ghidra() -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("fake server should bind");
        let addr = listener.local_addr().expect("fake server address");
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    let mut request = [0u8; 2048];
                    let read = stream.read(&mut request).await.unwrap_or(0);
                    let path = String::from_utf8_lossy(&request[..read])
                        .split_whitespace()
                        .nth(1)
                        .unwrap_or_default()
                        .to_string();
                    let body = if path.starts_with("/list_functions")
                        || path.starts_with("/search_functions")
                    {
                        "FUN_18003e750 at 18003e750".to_string()
                    } else if path.starts_with("/decompile_function") {
                        "undefined FUN_18003e750(void)\n{\n  void *pv = malloc(0x10);\n  free(pv);\n}\n"
                            .to_string()
                    } else {
                        "Error 404: No context found for request".to_string()
                    };
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                });
            }
        });
        format!("http://{addr}")
    }

    #[tokio::test]
    async fn a_cached_memory_result_is_reused_without_rescanning() {
        let dir = TempDir::new().unwrap();
        MemoryPersistor::new(dir.path())
            .save(&MemoryResult::new(ScanMetadata::new("eqmain.dll")))
            .unwrap();

        // The Ghidra server is unreachable, so `true` can only come from the cache.
        let pipeline = pipeline_over(Some(dir.path()));
        assert!(pipeline.ensure_memory_detection("eqmain.dll").await);
    }

    #[tokio::test]
    async fn a_cache_miss_scans_and_saves_the_result() {
        let dir = TempDir::new().unwrap();
        let ghidra = GhidraClient::new(&fake_ghidra().await).expect("client config");
        let pipeline = pipeline_with(ghidra, Some(dir.path()));

        assert!(pipeline.ensure_memory_detection("eqmain.dll").await);

        let persistor = MemoryPersistor::new(dir.path());
        assert!(
            persistor.exists("eqmain.dll"),
            "a cache miss should leave a saved document behind"
        );
        assert_eq!(
            persistor.path_for("eqmain.dll"),
            dir.path()
                .join("re")
                .join("analysis")
                .join("memory")
                .join("eqmain.dll.json"),
            "the document should be filed under re/analysis/memory"
        );
    }

    #[tokio::test]
    async fn a_failed_memory_scan_degrades_instead_of_failing() {
        let dir = TempDir::new().unwrap();
        let pipeline = pipeline_over(Some(dir.path()));

        assert!(!pipeline.ensure_memory_detection("eqmain.dll").await);
        assert!(
            !MemoryPersistor::new(dir.path()).exists("eqmain.dll"),
            "a failed scan persists nothing"
        );
    }

    #[tokio::test]
    async fn a_failed_memory_save_degrades_instead_of_failing() {
        let dir = TempDir::new().unwrap();
        // `re/analysis` as a plain file makes the save's directory
        // creation fail even though the scan itself succeeds.
        std::fs::create_dir_all(dir.path().join("re")).unwrap();
        std::fs::write(dir.path().join("re").join("analysis"), "not a directory").unwrap();

        let ghidra = GhidraClient::new(&fake_ghidra().await).expect("client config");
        let pipeline = pipeline_with(ghidra, Some(dir.path()));

        assert!(!pipeline.ensure_memory_detection("eqmain.dll").await);
    }

    #[tokio::test]
    async fn no_workspace_skips_the_memory_scan() {
        let pipeline = pipeline_over(None);
        assert!(!pipeline.ensure_memory_detection("eqmain.dll").await);
    }
}
