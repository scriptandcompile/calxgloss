//! Translation pipeline — analysis-engine scan + LLM + prompt orchestration.
//!
//! This crate provides the [`TranslationPipeline`] struct: it brings together
//! everything needed to translate a disassembled function to Rust. A pass is
//! never hand-built: it is described with a
//! [`PipelineSpec`](assembly::PipelineSpec) and assembled once by the
//! [`assembly`] module — the constructor and `with_*` setters are
//! assembly-internal (issue #328). The steps an assembled pass runs:
//!
//! 1. Fetch function data from the analysis engine (disassembly, decompiler output)
//! 2. Tag Windows API calls with their PAL mappings
//! 3. Generate baseline test inputs from function signature and disassembly
//! 4. Build a structured prompt that includes all context
//! 5. Send the prompt to the LLM for Rust code generation
//! 6. Return the translated code along with metadata

// The pipeline's `Send` inference descends through the generic `ScanSource`
// delegation chain (translate → retry helpers → `PipelineSource::decompile` →
// …), which overflows the default trait-resolution depth.
#![recursion_limit = "256"]

pub mod assembly;
pub mod carry_over;
pub mod coverage_residue;
pub mod error;
pub mod evidence_projector;
mod pipeline;
pub mod retry;
mod scan_job;
pub mod scan_registry;
pub mod seam_residue;
mod translator;
pub mod triage;
mod version_pairing;

pub mod batch;

pub use batch::{BatchTranslationResult, FunctionResult};
pub use carry_over::{AcceptedAttemptSource, CarryOverRecord, CarryOverSeed};
pub use error::{Result, TranslatorError};
pub use pipeline::{TranslationPipeline, build_hallucination_detector, callback_signature_map};
pub use retry::{
    RetryConfig, RetryResult, RetryStrategy, TranslationAttempt, try_translate_with_retry,
};
pub use translator::{Translation, Translator};
pub use triage::{UnrecoveredJumpTable, scan_unrecovered_jump_tables};

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use calxgloss_callgraph::CallGraph;
    use calxgloss_llm::LlmClient;
    use calxgloss_pal::ApiMappings;
    use calxgloss_types::ContextTier;
    use calxgloss_types::FunctionInfo;

    /// The fixture target loaded through the Kuna analysis engine — the
    /// only one (issue #214). These tests never read through the source;
    /// it only sets the pipeline up.
    fn fixture_kuna() -> calxgloss_kuna::KunaSource {
        let target = calxgloss_testfixtures::load_target()
            .expect("fixture target should build and validate");
        calxgloss_kuna::KunaSource::load(target.path())
            .expect("the fixture must load for scanning with Kuna")
    }

    #[test]
    fn test_translator_creation() {
        let llm = LlmClient::from_url("http://localhost:11434/v1", "qwen3").unwrap();
        let translator = Translator::new(llm);
        // Translator doesn't expose internal state, just verify construction
        let _ = &translator;
    }

    #[tokio::test]
    async fn test_pipeline_creation() {
        let kuna = fixture_kuna();
        let llm = LlmClient::from_url("http://localhost:11434/v1", "qwen3").unwrap();
        let pipeline = TranslationPipeline::new(kuna, llm, ApiMappings::default());

        assert!(!pipeline.api_mappings().is_empty());
    }

    #[test]
    fn test_translation_clone() {
        let translation = Translation {
            binary: "game_logic.dll".to_string().into(),
            function: "DrawSprite".to_string(),
            function_address: Some(0x1000),
            rust_code: "fn draw_sprite(x: i32, y: i32, texture_index: u32) -> i32 { x + y }"
                .to_string(),
            prompt_used: "Translate this...".to_string(),
            model: "qwen3".to_string(),
            tokens_used: Some(1024),
            baseline_tests: vec![],
            call_graph: vec!["helper_func".to_string()],
            call_graph_context: vec![],
            disassembly_hints: vec![],
            context_tier: ContextTier::WithTests,
        };

        let cloned = translation.clone();
        assert_eq!(cloned.binary, translation.binary);
        assert_eq!(cloned.function, translation.function);
        assert_eq!(cloned.function_address, translation.function_address);
        assert_eq!(cloned.rust_code, translation.rust_code);
        assert_eq!(cloned.tokens_used, translation.tokens_used);
        assert_eq!(cloned.call_graph, translation.call_graph);
        assert_eq!(
            cloned.call_graph_context.len(),
            translation.call_graph_context.len()
        );
        assert_eq!(cloned.context_tier, translation.context_tier);
    }

    #[tokio::test]
    async fn test_signature_comes_from_the_decompiler() {
        let kuna = fixture_kuna();
        let llm = LlmClient::from_url("http://localhost:11434/v1", "qwen3").unwrap();
        let pipeline = TranslationPipeline::new(kuna, llm, ApiMappings::default());

        let func_info = FunctionInfo {
            name: "DrawSprite".to_string(),
            address: 0x1000,
            binary: "game_logic.dll".to_string().into(),
            disassembly: String::new(),
            decompiler_output: "int __stdcall DrawSprite(int x, int y, unsigned int texture_index) {\n    return x + y;\n}".to_string(),
            windows_apis: Vec::new(),
            call_graph: Vec::new(),
            disassembly_hints: Vec::new(),
        };

        // The inferred signature is used as-is, parameter types included.
        assert_eq!(
            pipeline.signature_for(&func_info),
            "int __stdcall DrawSprite(int x, int y, unsigned int texture_index)"
        );
    }

    #[tokio::test]
    async fn test_signature_takes_the_declarator_not_the_whole_body() {
        let kuna = fixture_kuna();
        let llm = LlmClient::from_url("http://localhost:11434/v1", "qwen3").unwrap();
        let pipeline = TranslationPipeline::new(kuna, llm, ApiMappings::default());

        // This is the verbatim decompilation of `FUN_18008ed50` in `eqmain.dll`.
        // Reading the parameter list as everything between the first `(` and the
        // last `)` would take the whole body as the parameter list and report the
        // expression's parameters, not the function's.
        let func_info = FunctionInfo {
            name: "FUN_18008ed50".to_string(),
            address: 0x18008ed50,
            binary: "eqmain.dll".to_string().into(),
            disassembly: String::new(),
            decompiler_output: "\nlonglong FUN_18008ed50(longlong param_1,int param_2)\n\n{\n  return param_1 + ((longlong)param_2 + 4) * 8;\n}\n".to_string(),
            windows_apis: Vec::new(),
            call_graph: Vec::new(),
            disassembly_hints: Vec::new(),
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

    #[tokio::test]
    async fn test_signature_falls_back_when_there_is_no_decompilation() {
        let kuna = fixture_kuna();
        let llm = LlmClient::from_url("http://localhost:11434/v1", "qwen3").unwrap();
        let pipeline = TranslationPipeline::new(kuna, llm, ApiMappings::default());

        let func_info = FunctionInfo {
            name: "SomeFunc".to_string(),
            address: 0x2000,
            binary: "test.dll".to_string().into(),
            disassembly: String::new(),
            decompiler_output: String::new(),
            windows_apis: Vec::new(),
            call_graph: Vec::new(),
            disassembly_hints: Vec::new(),
        };

        // With nothing to read, the fallback declares no parameters. It
        // previously invented three, which generated test cases passing
        // arguments to a function that takes none.
        assert_eq!(
            pipeline.signature_for(&func_info),
            "int __stdcall SomeFunc()"
        );
    }

    // --- Signature synthesis meets the detected convention (issue #251) ---

    /// A function standing in for the synthesis tests: only the name and the
    /// decompiler line vary; everything else stays empty.
    fn synthesis_function(name: &str, binary: &str, decompiler_output: &str) -> FunctionInfo {
        FunctionInfo {
            name: name.to_string(),
            address: 0x1000,
            binary: binary.to_string().into(),
            disassembly: String::new(),
            decompiler_output: decompiler_output.to_string(),
            windows_apis: Vec::new(),
            call_graph: Vec::new(),
            disassembly_hints: Vec::new(),
        }
    }

    /// One persisted convention record, shaped like the scan's own.
    fn convention_inference(
        function: &str,
        callee: Option<&str>,
        convention: calxgloss_typeinfer::types::CallingConvention,
        method: calxgloss_typeinfer::types::InferenceMethod,
        confidence: u8,
        evidence: &str,
    ) -> calxgloss_typeinfer::types::InferredType {
        calxgloss_typeinfer::types::InferredType::Convention(
            calxgloss_typeinfer::types::InferredConvention {
                function: function.to_string(),
                callee: callee.map(str::to_string),
                convention,
                method,
                confidence: calxgloss_typeinfer::types::Confidence::new(confidence),
                evidence: evidence.to_string(),
            },
        )
    }

    /// File the per-binary type-inference artifact the synthesis reads,
    /// holding exactly `inferences` for `binary`.
    fn persist_typeinfer_artifact(
        workspace: &std::path::Path,
        binary: &str,
        inferences: Vec<calxgloss_typeinfer::types::InferredType>,
    ) {
        let mut result = calxgloss_typeinfer::types::TypeInferenceResult::new(
            calxgloss_typeinfer::types::ScanMetadata::new(binary),
        );
        result.inferences = inferences;
        calxgloss_typeinfer::persist::TypeInferPersistor::new(workspace)
            .save(&result)
            .expect("the artifact should save");
    }

    #[tokio::test]
    async fn test_detected_convention_is_spelled_when_the_decompiler_line_names_none() {
        let dir = tempfile::TempDir::new().expect("temp workspace should be created");
        persist_typeinfer_artifact(
            dir.path(),
            "game_logic.dll",
            vec![convention_inference(
                "DrawSprite",
                None,
                calxgloss_typeinfer::types::CallingConvention::Cdecl,
                calxgloss_typeinfer::types::InferenceMethod::CallerCleanup,
                70,
                "00401103  ADD ESP, 0x10",
            )],
        );
        let kuna = fixture_kuna();
        let llm = LlmClient::from_url("http://localhost:11434/v1", "qwen3").unwrap();
        let pipeline =
            TranslationPipeline::new(kuna, llm, ApiMappings::default()).with_workspace(dir.path());

        let func_info = synthesis_function(
            "DrawSprite",
            "game_logic.dll",
            "int DrawSprite(int x, int y, unsigned int texture_index) {\n    return x + y;\n}",
        );

        // The line names no convention, so the detected cdecl is spelled
        // into the slot the signature parser reads — the default __stdcall
        // no longer stands in for a function the scan read as cdecl.
        let signature = pipeline.signature_for(&func_info);
        assert_eq!(
            signature,
            "int __cdecl DrawSprite(int x, int y, unsigned int texture_index)"
        );

        // The spelling parses back out as a convention on the parsed
        // signature the binding builder is handed.
        assert_eq!(
            calxgloss_testgen::parse_signature(&signature)
                .unwrap()
                .calling_convention
                .as_deref(),
            Some("__cdecl")
        );
    }

    #[tokio::test]
    async fn test_a_decompiler_named_convention_wins_over_the_detected_record() {
        let dir = tempfile::TempDir::new().expect("temp workspace should be created");
        persist_typeinfer_artifact(
            dir.path(),
            "game_logic.dll",
            vec![convention_inference(
                "DrawSprite",
                None,
                calxgloss_typeinfer::types::CallingConvention::Stdcall,
                calxgloss_typeinfer::types::InferenceMethod::CalleeEpilogue,
                80,
                "00401007  RET 0xC",
            )],
        );
        let kuna = fixture_kuna();
        let llm = LlmClient::from_url("http://localhost:11434/v1", "qwen3").unwrap();
        let pipeline =
            TranslationPipeline::new(kuna, llm, ApiMappings::default()).with_workspace(dir.path());

        let func_info = synthesis_function(
            "DrawSprite",
            "game_logic.dll",
            "int __cdecl DrawSprite(int x, int y) {\n    return x + y;\n}",
        );

        // The decompiler line names cdecl itself — the line is the better
        // witness of the function, so the stdcall record never overwrites it.
        assert_eq!(
            pipeline.signature_for(&func_info),
            "int __cdecl DrawSprite(int x, int y)"
        );
    }

    #[tokio::test]
    async fn test_the_fallback_spells_the_detected_convention() {
        let dir = tempfile::TempDir::new().expect("temp workspace should be created");
        persist_typeinfer_artifact(
            dir.path(),
            "test.dll",
            vec![convention_inference(
                "SomeFunc",
                None,
                calxgloss_typeinfer::types::CallingConvention::Fastcall,
                calxgloss_typeinfer::types::InferenceMethod::MangledConvention,
                90,
                "?SomeFunc@@YIHH@Z",
            )],
        );
        let kuna = fixture_kuna();
        let llm = LlmClient::from_url("http://localhost:11434/v1", "qwen3").unwrap();
        let pipeline =
            TranslationPipeline::new(kuna, llm, ApiMappings::default()).with_workspace(dir.path());

        let func_info = synthesis_function("SomeFunc", "test.dll", "");

        // With no decompiler line at all, the placeholder spells the detected
        // fastcall instead of using the `__stdcall` default.
        assert_eq!(
            pipeline.signature_for(&func_info),
            "int __fastcall SomeFunc()"
        );
    }

    #[tokio::test]
    async fn test_the_spelled_convention_reaches_the_ffi_binding() {
        let dir = tempfile::TempDir::new().expect("temp workspace should be created");
        persist_typeinfer_artifact(
            dir.path(),
            "game_logic.dll",
            vec![convention_inference(
                "DrawSprite",
                None,
                calxgloss_typeinfer::types::CallingConvention::Thiscall,
                calxgloss_typeinfer::types::InferenceMethod::MangledConvention,
                90,
                "?draw@Sprite@@IAEXXZ",
            )],
        );
        let kuna = fixture_kuna();
        let llm = LlmClient::from_url("http://localhost:11434/v1", "qwen3").unwrap();
        let pipeline =
            TranslationPipeline::new(kuna, llm, ApiMappings::default()).with_workspace(dir.path());

        let func_info = synthesis_function(
            "DrawSprite",
            "game_logic.dll",
            "int DrawSprite(int x, int y) {\n    return x + y;\n}",
        );
        let signature = pipeline.signature_for(&func_info);

        // The binding built from the refined signature includes the detected
        // thiscall instead of a default. The parser and the binding builder
        // already store the convention field, so the spelling passes through
        // them unchanged, and shim signatures rendered from the same refined
        // string include it the same way.
        let binding =
            calxgloss_testgen::generate_ffi_binding("game_logic.dll", "DrawSprite", &signature)
                .expect("the refined signature should still parse into a binding");
        assert_eq!(
            binding.signature.calling_convention.as_deref(),
            Some("__thiscall")
        );
    }

    #[tokio::test]
    async fn test_no_convention_record_leaves_todays_spellings_untouched() {
        let dir = tempfile::TempDir::new().expect("temp workspace should be created");
        // An artifact that exists but read no convention for this function —
        // a parameter record only — changes nothing.
        persist_typeinfer_artifact(
            dir.path(),
            "test.dll",
            vec![calxgloss_typeinfer::types::InferredType::Param(
                calxgloss_typeinfer::types::InferredParamType {
                    function: "SomeFunc".to_string(),
                    param_index: 0,
                    param_name: Some("param_1".to_string()),
                    inferred_type: "int".to_string(),
                    method: calxgloss_typeinfer::types::InferenceMethod::KnownSignature,
                    scope: calxgloss_typeinfer::types::InferenceScope::Function,
                    confidence: calxgloss_typeinfer::types::Confidence::new(80),
                    evidence: "SomeFunc(param_1)".to_string(),
                },
            )],
        );
        let kuna = fixture_kuna();
        let llm = LlmClient::from_url("http://localhost:11434/v1", "qwen3").unwrap();
        let pipeline =
            TranslationPipeline::new(kuna, llm, ApiMappings::default()).with_workspace(dir.path());

        let fallback = synthesis_function("SomeFunc", "test.dll", "");
        assert_eq!(
            pipeline.signature_for(&fallback),
            "int __stdcall SomeFunc()"
        );

        let line = synthesis_function(
            "DrawSprite",
            "test.dll",
            "int DrawSprite(int x, int y) {\n    return x + y;\n}",
        );
        assert_eq!(
            pipeline.signature_for(&line),
            "int DrawSprite(int x, int y)",
            "with no convention record the decompiler line is used exactly as it is today"
        );
    }

    #[tokio::test]
    async fn test_a_missing_artifact_leaves_todays_spellings_untouched() {
        let dir = tempfile::TempDir::new().expect("temp workspace should be created");
        // A workspace with no type-inference artifact at all — the scan has
        // not run — behaves exactly as it did before the feature.
        let kuna = fixture_kuna();
        let llm = LlmClient::from_url("http://localhost:11434/v1", "qwen3").unwrap();
        let pipeline =
            TranslationPipeline::new(kuna, llm, ApiMappings::default()).with_workspace(dir.path());

        let fallback = synthesis_function("SomeFunc", "test.dll", "");
        assert_eq!(
            pipeline.signature_for(&fallback),
            "int __stdcall SomeFunc()"
        );
    }

    #[tokio::test]
    async fn test_a_call_site_record_never_spells_the_callers_signature() {
        let dir = tempfile::TempDir::new().expect("temp workspace should be created");
        // The caller's artifact holds only its view of its callee's
        // convention — the caller itself was never read. That record keys
        // beside the caller's own and must not be mistaken for it.
        persist_typeinfer_artifact(
            dir.path(),
            "game_logic.dll",
            vec![convention_inference(
                "DrawSprite",
                Some("BlitToScreen"),
                calxgloss_typeinfer::types::CallingConvention::Stdcall,
                calxgloss_typeinfer::types::InferenceMethod::CallSiteConvention,
                80,
                "00401103  CALL BlitToScreen",
            )],
        );
        let kuna = fixture_kuna();
        let llm = LlmClient::from_url("http://localhost:11434/v1", "qwen3").unwrap();
        let pipeline =
            TranslationPipeline::new(kuna, llm, ApiMappings::default()).with_workspace(dir.path());

        let func_info = synthesis_function(
            "DrawSprite",
            "game_logic.dll",
            "int DrawSprite(int x, int y) {\n    return x + y;\n}",
        );
        assert_eq!(
            pipeline.signature_for(&func_info),
            "int DrawSprite(int x, int y)",
            "the callee's convention belongs to the callee's binding, not the caller's signature"
        );
    }

    #[tokio::test]
    async fn test_a_microsoft_x64_record_spells_no_convention_word() {
        let dir = tempfile::TempDir::new().expect("temp workspace should be created");
        persist_typeinfer_artifact(
            dir.path(),
            "eqmain.dll",
            vec![convention_inference(
                "FUN_18003e750",
                None,
                calxgloss_typeinfer::types::CallingConvention::MicrosoftX64,
                calxgloss_typeinfer::types::InferenceMethod::X64Shape,
                65,
                "140001000  SUB RSP, 0x28",
            )],
        );
        let kuna = fixture_kuna();
        let llm = LlmClient::from_url("http://localhost:11434/v1", "qwen3").unwrap();
        let pipeline =
            TranslationPipeline::new(kuna, llm, ApiMappings::default()).with_workspace(dir.path());

        // Microsoft x64 has no C word — the parser's default already is the
        // x64 ABI — so the placeholder leaves the convention slot empty
        // rather than inventing a spelling, and a usable line is untouched.
        let fallback = synthesis_function("FUN_18003e750", "eqmain.dll", "");
        assert_eq!(pipeline.signature_for(&fallback), "int FUN_18003e750()");

        let line = synthesis_function(
            "FUN_18003e750",
            "eqmain.dll",
            "\nlonglong FUN_18003e750(longlong param_1,int param_2)\n\n{\n  return param_1 + param_2;\n}\n",
        );
        assert_eq!(
            pipeline.signature_for(&line),
            "longlong FUN_18003e750(longlong param_1,int param_2)"
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

    #[tokio::test]
    async fn test_build_translation_request() {
        let kuna = fixture_kuna();
        let llm = LlmClient::from_url("http://localhost:11434/v1", "qwen3").unwrap();
        let pipeline = TranslationPipeline::new(kuna, llm, ApiMappings::default());

        let func_info = FunctionInfo {
            name: "DrawSprite".to_string(),
            address: 0x1000,
            binary: "game_logic.dll".to_string().into(),
            disassembly: "mov eax, [esp+4]\nret".to_string(),
            decompiler_output: "int DrawSprite(int x) { return x; }".to_string(),
            windows_apis: Vec::new(),
            call_graph: Vec::new(),
            disassembly_hints: Vec::new(),
        };

        let request = pipeline.build_translation_request(
            "game_logic.dll",
            "DrawSprite",
            &func_info,
            vec![],
            vec![],
        );

        assert_eq!(request.binary, "game_logic.dll");
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

    #[test]
    fn test_plan_from_callgraph_empty_graph() {
        let kuna = fixture_kuna();
        let llm = LlmClient::from_url("http://localhost:11434/v1", "qwen3").unwrap();
        let pipeline = TranslationPipeline::new(kuna, llm, ApiMappings::default());

        let graph = calxgloss_callgraph::CallGraph {
            binary: "empty.dll".to_string(),
            functions: vec![],
        };

        let plan = pipeline.plan_from_callgraph(&graph, None).unwrap();
        assert!(plan.is_empty());
    }

    #[test]
    fn test_plan_from_callgraph_uses_translation_orderer() {
        let kuna = fixture_kuna();
        let llm = LlmClient::from_url("http://localhost:11434/v1", "qwen3").unwrap();
        let pipeline = TranslationPipeline::new(kuna, llm, ApiMappings::default());

        use calxgloss_callgraph::{CallGraphEdge, CallType, FunctionCallGraph};

        // Build a graph with three tiers
        let graph = CallGraph {
            binary: "tiers.dll".to_string(),
            functions: vec![
                // Leaf: render_frame — calls Direct3DCreate9
                FunctionCallGraph {
                    name: "render_frame".to_string(),
                    address: 0x404000,
                    callers: vec![0x403000],
                    callees: vec![CallGraphEdge {
                        source: 0x404000,
                        target: 0x500000,
                        call_site: 0,
                        call_type: CallType::Direct,
                        callee_name: "Direct3DCreate9".to_string(),
                    }],
                    node_category: calxgloss_types::NodeCategory::Leaf,
                },
                // Middle: game_loop — calls render_frame
                FunctionCallGraph {
                    name: "game_loop".to_string(),
                    address: 0x403000,
                    callers: vec![0x402000],
                    callees: vec![CallGraphEdge {
                        source: 0x403000,
                        target: 0x404000,
                        call_site: 0,
                        call_type: CallType::Direct,
                        callee_name: "render_frame".to_string(),
                    }],
                    node_category: calxgloss_types::NodeCategory::Middle,
                },
                // Root: WinMain — entry point
                FunctionCallGraph {
                    name: "WinMain".to_string(),
                    address: 0x401000,
                    callers: vec![],
                    callees: vec![CallGraphEdge {
                        source: 0x401000,
                        target: 0x402000,
                        call_site: 0,
                        call_type: CallType::Direct,
                        callee_name: "app_init".to_string(),
                    }],
                    node_category: calxgloss_types::NodeCategory::Root,
                },
                // Middle: app_init — calls game_loop
                FunctionCallGraph {
                    name: "app_init".to_string(),
                    address: 0x402000,
                    callers: vec![0x401000],
                    callees: vec![CallGraphEdge {
                        source: 0x402000,
                        target: 0x403000,
                        call_site: 0,
                        call_type: CallType::Direct,
                        callee_name: "game_loop".to_string(),
                    }],
                    node_category: calxgloss_types::NodeCategory::Middle,
                },
            ],
        };

        let plan = pipeline.plan_from_callgraph(&graph, None).unwrap();

        assert_eq!(plan.len(), 4);

        // Root functions first
        assert_eq!(plan[0].name, "WinMain");
        assert_eq!(
            plan[0].priority,
            calxgloss_callgraph::TranslationPriority::Root
        );

        // Middle functions (topologically sorted: game_loop before app_init)
        assert_eq!(plan[1].name, "game_loop");
        assert_eq!(
            plan[1].priority,
            calxgloss_callgraph::TranslationPriority::Middle
        );

        assert_eq!(plan[2].name, "app_init");
        assert_eq!(
            plan[2].priority,
            calxgloss_callgraph::TranslationPriority::Middle
        );

        // Leaf functions last
        assert_eq!(plan[3].name, "render_frame");
        assert_eq!(
            plan[3].priority,
            calxgloss_callgraph::TranslationPriority::Leaf
        );
    }

    #[test]
    fn test_plan_from_callgraph_max_functions_limit() {
        let kuna = fixture_kuna();
        let llm = LlmClient::from_url("http://localhost:11434/v1", "qwen3").unwrap();
        let pipeline = TranslationPipeline::new(kuna, llm, ApiMappings::default());

        use calxgloss_callgraph::FunctionCallGraph;

        let graph = CallGraph {
            binary: "trunc.dll".to_string(),
            functions: (0..10)
                .map(|i| FunctionCallGraph {
                    name: format!("func_{i}"),
                    address: 0x1000 + i * 0x100,
                    callers: vec![],
                    callees: vec![],
                    node_category: calxgloss_types::NodeCategory::Middle,
                })
                .collect(),
        };

        let plan = pipeline.plan_from_callgraph(&graph, Some(3)).unwrap();
        assert_eq!(plan.len(), 3);
    }

    #[test]
    fn test_plan_from_callgraph_orders_shared_globals_behind_the_persisted_index() {
        // The plan reads the persisted shared-globals index: the document
        // was hand-written into the workspace through the persistor — no
        // global-state scan runs, and plan_from_callgraph never reads the
        // analysis engine — and its index entry puts the definer ahead of
        // the reuser within the tier (issue #256).
        use calxgloss_callgraph::FunctionCallGraph;
        use calxgloss_globalstate::persist::GlobalStatePersistor;
        use calxgloss_globalstate::types::{
            GlobalStateFinding, GlobalStateResult, SharedGlobalRecord,
        };
        use calxgloss_types::ScanMetadata;

        let dir = tempfile::TempDir::new().expect("temp workspace");
        let mut result = GlobalStateResult::new(ScanMetadata::new("shared.dll"));
        result
            .findings
            .push(GlobalStateFinding::SharedGlobal(SharedGlobalRecord {
                global: "DAT_180064e80".to_string(),
                readers: vec!["reader_a".to_string()],
                writers: vec!["writer_b".to_string()],
                confidence: 85.into(),
            }));
        GlobalStatePersistor::new(dir.path())
            .save(&result)
            .expect("the document saves");

        let kuna = fixture_kuna();
        let llm = LlmClient::from_url("http://localhost:11434/v1", "qwen3").unwrap();
        let pipeline =
            TranslationPipeline::new(kuna, llm, ApiMappings::default()).with_workspace(dir.path());

        let graph = CallGraph {
            binary: "shared.dll".to_string(),
            functions: vec![
                FunctionCallGraph {
                    name: "reader_a".to_string(),
                    address: 0x401000,
                    callers: vec![],
                    callees: vec![],
                    node_category: calxgloss_types::NodeCategory::Middle,
                },
                FunctionCallGraph {
                    name: "writer_b".to_string(),
                    address: 0x402000,
                    callers: vec![],
                    callees: vec![],
                    node_category: calxgloss_types::NodeCategory::Middle,
                },
            ],
        };

        let plan = pipeline.plan_from_callgraph(&graph, None).unwrap();
        assert_eq!(
            plan[0].name, "writer_b",
            "the first definer precedes the reuser"
        );
        assert_eq!(plan[1].name, "reader_a");
    }

    #[test]
    fn test_plan_from_callgraph_without_a_globalstate_document_keeps_dependency_order() {
        // Same graph, no document in the workspace: the edge set is empty
        // and today's dependency order stands exactly — address order
        // within the tier (issue #256).
        use calxgloss_callgraph::FunctionCallGraph;

        let dir = tempfile::TempDir::new().expect("temp workspace");
        let kuna = fixture_kuna();
        let llm = LlmClient::from_url("http://localhost:11434/v1", "qwen3").unwrap();
        let pipeline =
            TranslationPipeline::new(kuna, llm, ApiMappings::default()).with_workspace(dir.path());

        let graph = CallGraph {
            binary: "shared.dll".to_string(),
            functions: vec![
                FunctionCallGraph {
                    name: "reader_a".to_string(),
                    address: 0x401000,
                    callers: vec![],
                    callees: vec![],
                    node_category: calxgloss_types::NodeCategory::Middle,
                },
                FunctionCallGraph {
                    name: "writer_b".to_string(),
                    address: 0x402000,
                    callers: vec![],
                    callees: vec![],
                    node_category: calxgloss_types::NodeCategory::Middle,
                },
            ],
        };

        let plan = pipeline.plan_from_callgraph(&graph, None).unwrap();
        assert_eq!(plan[0].name, "reader_a", "no document, no reordering");
        assert_eq!(plan[1].name, "writer_b");
    }

    #[test]
    fn test_generate_stub_main() {
        let kuna = fixture_kuna();
        let llm = LlmClient::from_url("http://localhost:11434/v1", "qwen3").unwrap();
        let pipeline = TranslationPipeline::new(kuna, llm, ApiMappings::default());

        let stub = pipeline.generate_stub("mainCRTStartup", "int main()");
        assert!(stub.contains("mainCRTStartup"));
        assert!(stub.contains("std::process::exit"));
    }

    #[test]
    fn test_generate_stub_dllmain() {
        let kuna = fixture_kuna();
        let llm = LlmClient::from_url("http://localhost:11434/v1", "qwen3").unwrap();
        let pipeline = TranslationPipeline::new(kuna, llm, ApiMappings::default());

        let stub = pipeline.generate_stub("DllMain", "int DllMain()");
        assert!(stub.contains("DllMain"));
        assert!(stub.contains("DLL initialization"));
    }

    #[test]
    fn test_generate_stub_vb6() {
        let kuna = fixture_kuna();
        let llm = LlmClient::from_url("http://localhost:11434/v1", "qwen3").unwrap();
        let pipeline = TranslationPipeline::new(kuna, llm, ApiMappings::default());

        let stub = pipeline.generate_stub("__vbaInitialize", "int __vbaInitialize()");
        assert!(stub.contains("__vbaInitialize"));
        assert!(stub.contains("VB6"));
    }

    #[test]
    fn test_generate_stub_generic() {
        let kuna = fixture_kuna();
        let llm = LlmClient::from_url("http://localhost:11434/v1", "qwen3").unwrap();
        let pipeline = TranslationPipeline::new(kuna, llm, ApiMappings::default());

        let stub = pipeline.generate_stub("FUN_18001000", "int FUN_18001000()");
        assert!(stub.contains("FUN_18001000"));
        assert!(stub.contains("TODO: Translate"));
    }

    #[test]
    fn test_plan_from_callgraph_includes_category() {
        let kuna = fixture_kuna();
        let llm = LlmClient::from_url("http://localhost:11434/v1", "qwen3").unwrap();
        let pipeline = TranslationPipeline::new(kuna, llm, ApiMappings::default());

        let graph = CallGraph {
            binary: "categories.dll".to_string(),
            functions: vec![
                calxgloss_callgraph::FunctionCallGraph {
                    name: "WinMain".to_string(),
                    address: 0x401000,
                    callers: vec![],
                    callees: vec![],
                    node_category: calxgloss_types::NodeCategory::Root,
                },
                calxgloss_callgraph::FunctionCallGraph {
                    name: "runtime_helper".to_string(),
                    address: 0x402000,
                    callers: vec![],
                    callees: vec![],
                    node_category: calxgloss_types::NodeCategory::Skip,
                },
                calxgloss_callgraph::FunctionCallGraph {
                    name: "app_logic".to_string(),
                    address: 0x403000,
                    callers: vec![],
                    callees: vec![],
                    node_category: calxgloss_types::NodeCategory::Middle,
                },
            ],
        };

        let plan = pipeline.plan_from_callgraph(&graph, None).unwrap();
        assert_eq!(plan.len(), 3);

        // Root and Skip both map to Root priority
        let winmain = plan.iter().find(|f| f.name == "WinMain").unwrap();
        assert_eq!(
            winmain.priority,
            calxgloss_callgraph::TranslationPriority::Root
        );
        assert_eq!(winmain.category, calxgloss_types::NodeCategory::Root);

        let runtime = plan.iter().find(|f| f.name == "runtime_helper").unwrap();
        assert_eq!(
            runtime.priority,
            calxgloss_callgraph::TranslationPriority::Root
        );
        assert_eq!(runtime.category, calxgloss_types::NodeCategory::Skip);

        let app = plan.iter().find(|f| f.name == "app_logic").unwrap();
        assert_eq!(
            app.priority,
            calxgloss_callgraph::TranslationPriority::Middle
        );
        assert_eq!(app.category, calxgloss_types::NodeCategory::Middle);
    }
}
