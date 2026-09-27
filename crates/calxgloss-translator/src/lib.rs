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
//! let translation = pipeline.translate("myapp.exe", "game_logic.dll", "DrawSprite").await?;
//! println!("Translated code:\n{}", translation.rust_code);
//! # Ok(())
//! # }
//! ```

pub mod error;

pub use error::{Result, TranslatorError};

use calxgloss_analysis::Analyzer;
use calxgloss_ghidra::GhidraClient;
use calxgloss_llm::{LlmClient, LlmMessage};
use calxgloss_pal::ApiMappings;
use calxgloss_prompts::build_translate_prompt;
use calxgloss_testgen::TestGenerator;
use calxgloss_types::{Export, FunctionInfo, Import, TestCase, TranslationRequest};
use tracing::{debug, info, instrument};

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
            rust_code: response.content,
            prompt_used: prompt,
            model: self.llm.model().to_string(),
            tokens_used: response.tokens_used,
            baseline_tests: Vec::new(),
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
            rust_code: response.content,
            prompt_used: prompt,
            model: self.llm.model().to_string(),
            tokens_used: response.tokens_used,
            baseline_tests: request.baseline_tests,
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
            disassembly: disassembly.to_string(),
            decompiler_output: decompiler_output.to_string(),
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

    /// Translate a function from a target executable.
    ///
    /// This is the main pipeline entry point. It fetches all data from Ghidra,
    /// analyzes the function, generates tests, builds a prompt, and sends it
    /// to the LLM.
    ///
    /// # Arguments
    ///
    /// * `target_exe` — The target executable name (used for Ghidra session).
    /// * `dll` — The DLL containing the function.
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
    /// let translation = pipeline.translate("myapp.exe", "game_logic.dll", "DrawSprite").await?;
    /// println!("Generated {} lines of Rust code", translation.rust_code.lines().count());
    /// # Ok(())
    /// # }
    /// ```
    #[instrument(skip(self), fields(target_exe, dll, function, base_url = %self.ghidra.base_url()))]
    pub async fn translate(
        &self,
        target_exe: &str,
        dll: &str,
        function: &str,
    ) -> Result<Translation> {
        debug!(target_exe, dll, function, "Starting translation pipeline");

        // Step 1: Fetch function metadata from Ghidra
        let function_info = self.fetch_function(target_exe, dll, function).await?;
        info!(dll, function, "Fetched function metadata");

        // Step 2: Fetch imports and tag Windows APIs
        let imports = self.fetch_imports(target_exe, dll).await?;
        let tagged_apis = self.tag_windows_apis(&function_info.disassembly, &imports)?;
        info!(
            dll,
            function,
            tagged_apis = tagged_apis.len(),
            "Tagged Windows APIs"
        );

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

        // Step 4: Build translation request and prompt
        let request = self.build_translation_request(
            dll,
            function,
            &function_info,
            tagged_apis,
            baseline_tests.clone(),
        );
        let prompt = build_translate_prompt(&request)?;
        info!(
            dll,
            function,
            prompt_len = prompt.len(),
            "Built translation prompt"
        );

        // Step 5: Send to LLM
        let response = self.send_to_llm(&prompt).await?;

        if response.content.is_empty() {
            return Err(TranslatorError::EmptyCode {
                code_len: response.content.len(),
            });
        }

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
            rust_code: response.content,
            prompt_used: prompt,
            model: self.llm.model().to_string(),
            tokens_used: response.tokens_used,
            baseline_tests,
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
        let response = self.send_to_llm(&prompt).await?;

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
            rust_code: response.content,
            prompt_used: prompt,
            model: self.llm.model().to_string(),
            tokens_used: response.tokens_used,
            baseline_tests: request.baseline_tests,
        })
    }

    /// Fetch function metadata from GhidraMCP.
    async fn fetch_function(
        &self,
        target_exe: &str,
        dll: &str,
        function: &str,
    ) -> Result<FunctionInfo> {
        self.ghidra
            .get_function_full(target_exe, dll, function)
            .await
            .map_err(|e| TranslatorError::GhidraFetch {
                dll: dll.to_string(),
                function: function.to_string(),
                source: e,
            })
    }

    /// Fetch imports for a DLL from GhidraMCP.
    async fn fetch_imports(&self, target_exe: &str, dll: &str) -> Result<Vec<Import>> {
        self.ghidra
            .get_imports(target_exe, dll)
            .await
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
        imports: &[Import],
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
        imports: &[Import],
    ) -> Result<Vec<TestCase>> {
        // Build a mock signature from the function name and DLL for test generation
        let signature = self.extract_mock_signature(function_info, imports);

        // Generate test inputs from signature and disassembly
        let tests = calxgloss_testgen::generate_test_inputs(&signature, &function_info.disassembly)
            .map_err(TranslatorError::TestGen)?;

        Ok(tests)
    }

    /// Extract a mock function signature for test input generation.
    ///
    /// Since Ghidra may not always provide a clean C-style signature, we
    /// construct a plausible one from the function name and imports.
    fn extract_mock_signature(&self, function_info: &FunctionInfo, imports: &[Import]) -> String {
        // Try to build a signature that looks like a C function declaration
        // The test generator parses this to create boundary-value inputs
        let param_count = self.estimate_params(function_info, imports);
        let params: Vec<String> = (0..param_count)
            .map(|i| format!("int param_{}", i))
            .collect();
        let params_str = params.join(", ");

        format!("int __stdcall {}({})", function_info.name, params_str)
    }

    /// Estimate the number of parameters a function takes.
    fn estimate_params(&self, function_info: &FunctionInfo, _imports: &[Import]) -> usize {
        // Heuristic: if we have exports, try to extract the real signature
        if let Some(ref dll_name) = self.target_dll
            && dll_name == &function_info.dll
            && let Some(export) = self.exports.iter().find(|e| e.name == function_info.name)
            && let Ok(parsed) = calxgloss_testgen::parse_signature(&export.signature)
        {
            return parsed.parameters.len();
        }

        // Fallback: guess based on decompiler output or disassembly
        if function_info.decompiler_output.contains('(')
            && function_info.decompiler_output.contains(')')
        {
            // Try to extract from pseudo-C
            let open = function_info.decompiler_output.find('(').unwrap_or(0);
            let close = function_info
                .decompiler_output
                .rfind(')')
                .unwrap_or(function_info.decompiler_output.len());
            let params = &function_info.decompiler_output[open + 1..close];
            if !params.trim().is_empty() {
                return params.split(',').count();
            }
        }

        // Default guess
        3
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
            disassembly: function_info.disassembly.clone(),
            decompiler_output: function_info.decompiler_output.clone(),
            windows_apis: tagged_apis,
            baseline_tests,
        }
    }

    /// Send a prompt to the LLM and extract the Rust code response.
    async fn send_to_llm(&self, prompt: &str) -> Result<calxgloss_llm::LlmResponse> {
        let messages = vec![LlmMessage::user(prompt)];
        let response = self.llm.complete(&messages).await?;

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
            rust_code: "fn draw_sprite(x: i32, y: i32, texture_index: u32) -> i32 { x + y }"
                .to_string(),
            prompt_used: "Translate this...".to_string(),
            model: "qwen3".to_string(),
            tokens_used: Some(1024),
            baseline_tests: vec![],
        };

        let cloned = translation.clone();
        assert_eq!(cloned.dll, translation.dll);
        assert_eq!(cloned.function, translation.function);
        assert_eq!(cloned.rust_code, translation.rust_code);
        assert_eq!(cloned.tokens_used, translation.tokens_used);
    }

    #[test]
    fn test_estimate_params_from_decompiler() {
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

        let params = pipeline.estimate_params(&func_info, &[]);
        assert_eq!(params, 3);
    }

    #[test]
    fn test_estimate_params_default() {
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

        let params = pipeline.estimate_params(&func_info, &[]);
        assert_eq!(params, 3); // default fallback
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
