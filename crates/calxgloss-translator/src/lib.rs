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

pub mod error;
mod pipeline;
pub mod retry;
mod translator;

pub mod batch;

pub use batch::{BatchTranslationResult, FunctionResult};
pub use error::{Result, TranslatorError};
pub use pipeline::{TranslationPipeline, build_hallucination_detector};
pub use retry::{
    RetryConfig, RetryResult, RetryStrategy, TranslationAttempt, try_translate_with_retry,
};
pub use translator::{Translation, Translator};

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use calxgloss_ghidra::GhidraClient;
    use calxgloss_llm::LlmClient;
    use calxgloss_pal::ApiMappings;
    use calxgloss_types::ContextTier;
    use calxgloss_types::Export;
    use calxgloss_types::FunctionInfo;
    use calxgloss_callgraph::CallGraph;

    #[test]
    fn test_translator_creation() {
        let llm = LlmClient::from_url("http://localhost:11434/v1", "qwen3").unwrap();
        let translator = Translator::new(llm);
        // Translator doesn't expose internal state, just verify construction
        let _ = &translator;
    }

    #[tokio::test]
    async fn test_pipeline_creation() {
        let ghidra = GhidraClient::new("http://localhost:8080").unwrap();
        let llm = LlmClient::from_url("http://localhost:11434/v1", "qwen3").unwrap();
        let pipeline = TranslationPipeline::new(ghidra, llm, ApiMappings::default());

        assert!(!pipeline.api_mappings().is_empty());
    }

    #[tokio::test]
    async fn test_pipeline_with_exports() {
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

        assert!(!pipeline.api_mappings().is_empty());
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
            disassembly_hints: vec![],
            context_tier: ContextTier::WithTests,
        };

        let cloned = translation.clone();
        assert_eq!(cloned.dll, translation.dll);
        assert_eq!(cloned.function, translation.function);
        assert_eq!(cloned.function_address, translation.function_address);
        assert_eq!(cloned.rust_code, translation.rust_code);
        assert_eq!(cloned.tokens_used, translation.tokens_used);
        assert_eq!(cloned.call_graph, translation.call_graph);
        assert_eq!(cloned.context_tier, translation.context_tier);
    }

    #[tokio::test]
    async fn test_signature_comes_from_the_decompiler() {
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
            disassembly_hints: Vec::new(),
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

    #[tokio::test]
    async fn test_build_translation_request() {
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
            disassembly_hints: Vec::new(),
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

    #[test]
    fn test_plan_from_callgraph_empty_graph() {
        let ghidra = GhidraClient::new("http://localhost:8080").unwrap();
        let llm = LlmClient::from_url("http://localhost:11434/v1", "qwen3").unwrap();
        let pipeline = TranslationPipeline::new(ghidra, llm, ApiMappings::default());

        let graph = calxgloss_callgraph::CallGraph {
            dll: "empty.dll".to_string(),
            functions: vec![],
        };

        let plan = pipeline.plan_from_callgraph(&graph, None).unwrap();
        assert!(plan.is_empty());
    }

    #[test]
    fn test_plan_from_callgraph_uses_translation_orderer() {
        let ghidra = GhidraClient::new("http://localhost:8080").unwrap();
        let llm = LlmClient::from_url("http://localhost:11434/v1", "qwen3").unwrap();
        let pipeline = TranslationPipeline::new(ghidra, llm, ApiMappings::default());

        use calxgloss_callgraph::{CallGraphEdge, CallType, FunctionCallGraph};

        // Build a graph with three tiers
        let graph = CallGraph {
            dll: "tiers.dll".to_string(),
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
        assert_eq!(plan[0].priority, calxgloss_callgraph::TranslationPriority::Root);

        // Middle functions (topologically sorted: game_loop before app_init)
        assert_eq!(plan[1].name, "game_loop");
        assert_eq!(plan[1].priority, calxgloss_callgraph::TranslationPriority::Middle);

        assert_eq!(plan[2].name, "app_init");
        assert_eq!(plan[2].priority, calxgloss_callgraph::TranslationPriority::Middle);

        // Leaf functions last
        assert_eq!(plan[3].name, "render_frame");
        assert_eq!(plan[3].priority, calxgloss_callgraph::TranslationPriority::Leaf);
    }

    #[test]
    fn test_plan_from_callgraph_max_functions_limit() {
        let ghidra = GhidraClient::new("http://localhost:8080").unwrap();
        let llm = LlmClient::from_url("http://localhost:11434/v1", "qwen3").unwrap();
        let pipeline = TranslationPipeline::new(ghidra, llm, ApiMappings::default());

        use calxgloss_callgraph::FunctionCallGraph;

        let graph = CallGraph {
            dll: "trunc.dll".to_string(),
            functions: (0..10)
                .map(|i| {
                    FunctionCallGraph {
                        name: format!("func_{i}"),
                        address: 0x1000 + i * 0x100,
                        callers: vec![],
                        callees: vec![],
                        node_category: calxgloss_types::NodeCategory::Middle,
                    }
                })
                .collect(),
        };

        let plan = pipeline.plan_from_callgraph(&graph, Some(3)).unwrap();
        assert_eq!(plan.len(), 3);
    }
}
