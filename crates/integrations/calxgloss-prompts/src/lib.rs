//! Prompt templates and rendering for the Calxgloss LLM translation pipeline.
//!
//! This crate provides a lightweight template engine for building prompts
//! sent to the local LLM. Templates are embedded at compile time via
//! `include_str!` and rendered with structured data from the translation
//! pipeline.
//!
//! # Architecture
//!
//! - [`context`] — Data structs (`SignaturePromptData`, `ComplexityPromptData`, etc.)
//! - [`templates`] — Askama template structs (`MinimalTemplate`, `TranslateTemplate`, etc.)
//! - [`build_translate_prompt`] — Builds a standard translation prompt
//! - [`build_complexity_prompt`] — Selects template by complexity
//! - [`build_signature_prompt`] — Builds a Tier 0 (name-and-signature-only) prompt
//! - [`build_disassembly_prompt`] — Builds a Tier 1 (disassembly + decompiler) prompt
//! - [`build_with_tests_prompt`] — Builds a Tier 2 (disassembly + decompiler + tests) prompt
//! - [`ComplexityPromptData::api_categories`] — Extracts API categories
//!
//! # Call Graph Context (Task 11)
//!
//! Starting with Tier 2+, prompts can include enriched call graph context
//! produced by [`calxgloss_callgraph::ContextEnricher`]. The context includes:
//!
//! - **Callers** — functions that call this function, with call type
//! - **Categorized callees** — APIs grouped by category (UI, Graphics, etc.)
//! - **Leaf API suggestions** — matched APIs with Rust crate recommendations
//!
//! Use the `from_request_with_call_graph` constructor on prompt data structs
//! to automatically enrich the context from a call graph.
//!
//! # API-Aware Prompt Augmentation
//!
//! When a function calls Windows APIs, the prompt builder automatically
//! injects the full mapping table rows for each API category the function touches.
//! This gives the LLM detailed context about how to translate specific APIs
//! (e.g., every Win32 Core mapping, every DirectX mapping, every GDI mapping)
//! rather than just the one-liner `api.name → api.pal_mapping` shown in the
//! "WINDOWS APIS IDENTIFIED" section.

mod build;
pub mod context;
pub mod error;
pub mod templates;

pub use build::{
    build_complexity_prompt, build_disassembly_prompt, build_edge_case_prompt,
    build_escalate_prompt, build_escalate_prompt_with_context, build_full_module_prompt,
    build_module_context_prompt, build_signature_prompt, build_translate_prompt,
    build_with_tests_prompt, extract_signature_from_decompiler,
};
pub use context::{
    ComplexityPromptData, DisassemblyPromptData, FullModulePromptData, ModuleContextPromptData,
    SignaturePromptData, WithTestsPromptData,
};
pub use error::PromptError;
pub use templates::{
    AlgorithmInfo, ApiInfo, BoundaryValue, CallGraphNeighbor, CallbackInfo, ConcurrencyInfo,
    ConstInfo, ControlFlowInfo, EdgeCaseTemplate, EdgeCaseTest, EscalateTemplate, FixTemplate,
    FormattedTestResult, FullModuleTemplate, MemoryInfo, MinimalTemplate, ModuleContextTemplate,
    NeighborFunction, PalTraitDef, PalTraitMethod, SerializationInfo, ShimCode, SignatureTemplate,
    StringContextInfo, StructField, StructuredData, TestCaseFormatted, TranslateTemplate, TypeInfo,
    WithTestsTemplate,
};

// Re-export types used by template constructors
pub use calxgloss_types::{ApiCategory, FunctionComplexity, TranslationRequest};

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use askama::Template;
    use calxgloss_types::TestCase;
    use serde_json::json;

    fn sample_request() -> TranslationRequest {
        TranslationRequest {
            binary: "game_logic.dll".to_string().into(),
            function: "DrawSprite".to_string(),
            disassembly: "mov eax, [esp+4]\nadd eax, ebx\nret".to_string(),
            decompiler_output: "int DrawSprite(int x, int y) { return x + y; }".to_string(),
            windows_apis: vec![
                calxgloss_types::WindowsApiCall {
                    name: "GetTickCount".to_string(),
                    category: ApiCategory::Win32Core,
                    pal_mapping: "std::time::Instant::now()".to_string(),
                },
                calxgloss_types::WindowsApiCall {
                    name: "CreateFileA".to_string(),
                    category: ApiCategory::Win32Core,
                    pal_mapping: "std::fs::File::open".to_string(),
                },
            ],
            baseline_tests: vec![
                TestCase {
                    inputs: json!({"x": 10, "y": 20}),
                    expected_return: json!(30),
                    expected_side_effects: vec![],
                },
                TestCase {
                    inputs: json!({"x": 0, "y": 0}),
                    expected_return: json!(0),
                    expected_side_effects: vec![],
                },
            ],
        }
    }

    #[test]
    fn test_build_translate_variables() {
        let req = sample_request();
        let template = TranslateTemplate::from_request(&req);

        assert_eq!(template.function_name, "DrawSprite");
        assert_eq!(template.dll_name, "game_logic.dll");
        assert!(!template.no_windows_apis);
        assert_eq!(template.windows_apis.len(), 2);
        assert_eq!(template.test_cases.len(), 2);
    }

    #[test]
    fn test_build_translate_prompt_basic() {
        let req = sample_request();
        let prompt = build_translate_prompt(&req).unwrap();

        assert!(prompt.contains("DrawSprite"));
        assert!(prompt.contains("game_logic.dll"));
        assert!(prompt.contains("GetTickCount"));
        assert!(prompt.contains("std::time::Instant::now()"));
        assert!(prompt.contains("CreateFileA"));
        assert!(prompt.contains("std::fs::File::open"));
        assert!(prompt.contains("DISASSEMBLY"));
        assert!(prompt.contains("DECOMPILER OUTPUT"));
        assert!(prompt.contains("WINDOWS API CALLS IDENTIFIED"));
        assert!(prompt.contains("BASELINE TESTS"));
        assert!(prompt.contains("TRANSLATION REQUIREMENTS"));
    }

    #[test]
    fn test_prompt_with_no_apis() {
        let mut req = sample_request();
        req.windows_apis = vec![];
        let prompt = build_translate_prompt(&req).unwrap();
        assert!(prompt.contains("No Windows API calls were identified"));
    }

    #[test]
    fn test_prompt_with_no_tests() {
        let mut req = sample_request();
        req.baseline_tests = vec![];
        let template = TranslateTemplate::from_request(&req);
        assert_eq!(template.test_cases.len(), 0);
    }

    #[test]
    fn test_escalate_prompt_basic() {
        let prompt = build_escalate_prompt(
            "DrawSprite".to_string(),
            "game_logic.dll".to_string(),
            "fn draw_sprite(x: i32) -> i32 { x }".to_string(),
            "Tests failed: boundary case x=0 produced wrong result".to_string(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )
        .unwrap();

        assert!(prompt.contains("DrawSprite"));
        assert!(prompt.contains("game_logic.dll"));
        assert!(prompt.contains("No call graph neighbors identified"));
        assert!(prompt.contains("No neighboring function context available"));
        assert!(prompt.contains("No data structure context available"));
        assert!(prompt.contains("No additional type information available"));
    }

    #[test]
    fn test_escalate_prompt_with_neighbors() {
        let neighbors = vec![CallGraphNeighbor {
            name: "helper_compute".to_string(),
            address: 0x1000,
            signature: "int __stdcall helper_compute(int x, int y)".to_string(),
            role: "callee".to_string(),
        }];

        let prompt = build_escalate_prompt(
            "DrawSprite".to_string(),
            "game_logic.dll".to_string(),
            "fn draw_sprite(x: i32) -> i32 { x }".to_string(),
            "Wrong result".to_string(),
            neighbors,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )
        .unwrap();

        assert!(prompt.contains("helper_compute"));
        assert!(prompt.contains("int __stdcall helper_compute(int x, int y)"));
    }

    #[test]
    fn test_edge_case_prompt_basic() {
        let failed_tests = vec![EdgeCaseTest {
            index: 1,
            inputs: json!({"x": 0}),
            expected: json!(0),
            actual: json!(1),
            error: "Expected 0, got 1".to_string(),
            disassembly_hints: "cmp eax, 0\nje .zero_branch".to_string(),
        }];

        let prompt = build_edge_case_prompt(
            "DrawSprite".to_string(),
            "game_logic.dll".to_string(),
            "fn draw_sprite(x: i32) -> i32 { x + 1 }".to_string(),
            failed_tests,
            Vec::new(),
            Vec::new(),
        )
        .unwrap();

        assert!(prompt.contains("DrawSprite"));
        assert!(prompt.contains("x + 1"));
        assert!(prompt.contains("Expected 0, got 1"));
        assert!(prompt.contains("cmp eax, 0"));
    }

    #[test]
    fn test_edge_case_prompt_with_boundary_values() {
        let bvs = vec![BoundaryValue {
            description: "Zero check for input index".to_string(),
            condition: "x <= 0".to_string(),
            branch_address: 0x2000,
        }];

        let prompt = build_edge_case_prompt(
            "DrawSprite".to_string(),
            "game_logic.dll".to_string(),
            "fn draw_sprite(x: i32) -> i32 { x }".to_string(),
            Vec::new(),
            bvs,
            Vec::new(),
        )
        .unwrap();

        assert!(prompt.contains("Zero check for input index"));
        assert!(prompt.contains("x <= 0"));
        assert!(prompt.contains("0x2000"));
    }

    #[test]
    fn test_complexity_prompt_selects_minimal_template() {
        let data = ComplexityPromptData {
            function_name: "SimpleFunc".to_string(),
            dll_name: "test.dll".to_string(),
            address: 0x1000,
            disassembly: "mov eax, 0\nret".to_string(),
            decompiler_output: "int SimpleFunc() { return 0; }".to_string(),
            windows_apis: Vec::new(),
            test_cases: Vec::new(),
            api_category_mappings: Vec::new(),
            call_graph_neighbors: Vec::new(),
            neighboring_functions: Vec::new(),
            data_structures: Vec::new(),
            type_info: Vec::new(),
            control_flow_findings: Vec::new(),
        };

        let prompt = build_complexity_prompt(&FunctionComplexity::Minimal, &data).unwrap();
        assert!(prompt.contains("SimpleFunc"));
        assert!(prompt.contains("test.dll"));
        assert!(prompt.contains("DISASSEMBLY"));
    }

    #[test]
    fn test_complexity_prompt_selects_standard_template() {
        let data = ComplexityPromptData {
            function_name: "StdFunc".to_string(),
            dll_name: "game.dll".to_string(),
            address: 0x2000,
            disassembly: "mov eax, [esp+4]\nadd eax, ebx\nret".to_string(),
            decompiler_output: "int StdFunc(int x, int y) { return x + y; }".to_string(),
            windows_apis: vec![calxgloss_types::WindowsApiCall {
                name: "GetTickCount".to_string(),
                category: ApiCategory::Win32Core,
                pal_mapping: "std::time::Instant::now()".to_string(),
            }],
            test_cases: Vec::new(),
            api_category_mappings: Vec::new(),
            call_graph_neighbors: Vec::new(),
            neighboring_functions: Vec::new(),
            data_structures: Vec::new(),
            type_info: Vec::new(),
            control_flow_findings: Vec::new(),
        };

        let prompt = build_complexity_prompt(&FunctionComplexity::Standard, &data).unwrap();
        assert!(prompt.contains("StdFunc"));
        assert!(prompt.contains("game.dll"));
        assert!(prompt.contains("WINDOWS API CALLS IDENTIFIED"));
    }

    #[test]
    fn test_api_categories_extracted_from_windows_apis() {
        let data = ComplexityPromptData {
            function_name: "TestFunc".to_string(),
            dll_name: "test.dll".to_string(),
            address: 0x1000,
            disassembly: "mov eax, 0\nret".to_string(),
            decompiler_output: "int TestFunc() { return 0; }".to_string(),
            windows_apis: vec![
                calxgloss_types::WindowsApiCall {
                    name: "CreateFileA".to_string(),
                    category: ApiCategory::Win32Core,
                    pal_mapping: "std::fs::File::open".to_string(),
                },
                calxgloss_types::WindowsApiCall {
                    name: "Direct3DCreate9".to_string(),
                    category: ApiCategory::DirectX,
                    pal_mapping: "wgpu::Instance::new [PAL placeholder]".to_string(),
                },
            ],
            test_cases: Vec::new(),
            api_category_mappings: Vec::new(),
            call_graph_neighbors: Vec::new(),
            neighboring_functions: Vec::new(),
            data_structures: Vec::new(),
            type_info: Vec::new(),
            control_flow_findings: Vec::new(),
        };

        let categories = data.api_categories();
        assert_eq!(categories.len(), 2);
        assert!(categories.contains(&ApiCategory::Win32Core));
        assert!(categories.contains(&ApiCategory::DirectX));
    }

    #[test]
    fn test_api_categories_deduplicates() {
        let data = ComplexityPromptData {
            function_name: "TestFunc".to_string(),
            dll_name: "test.dll".to_string(),
            address: 0x1000,
            disassembly: "mov eax, 0\nret".to_string(),
            decompiler_output: "int TestFunc() { return 0; }".to_string(),
            windows_apis: vec![
                calxgloss_types::WindowsApiCall {
                    name: "CreateFileA".to_string(),
                    category: ApiCategory::Win32Core,
                    pal_mapping: "std::fs::File::open".to_string(),
                },
                calxgloss_types::WindowsApiCall {
                    name: "ReadFile".to_string(),
                    category: ApiCategory::Win32Core,
                    pal_mapping: "std::fs::read".to_string(),
                },
            ],
            test_cases: Vec::new(),
            api_category_mappings: Vec::new(),
            call_graph_neighbors: Vec::new(),
            neighboring_functions: Vec::new(),
            data_structures: Vec::new(),
            type_info: Vec::new(),
            control_flow_findings: Vec::new(),
        };

        let categories = data.api_categories();
        assert_eq!(categories.len(), 1);
        assert_eq!(categories[0], ApiCategory::Win32Core);
    }

    #[test]
    fn test_api_categories_empty_when_no_apis() {
        let data = ComplexityPromptData {
            function_name: "TestFunc".to_string(),
            dll_name: "test.dll".to_string(),
            address: 0x1000,
            disassembly: "mov eax, 0\nret".to_string(),
            decompiler_output: "int TestFunc() { return 0; }".to_string(),
            windows_apis: Vec::new(),
            test_cases: Vec::new(),
            api_category_mappings: Vec::new(),
            call_graph_neighbors: Vec::new(),
            neighboring_functions: Vec::new(),
            data_structures: Vec::new(),
            type_info: Vec::new(),
            control_flow_findings: Vec::new(),
        };

        let categories = data.api_categories();
        assert!(categories.is_empty());
    }

    #[test]
    fn test_standard_prompt_includes_api_mapping_reference() {
        let data = ComplexityPromptData {
            function_name: "TestFunc".to_string(),
            dll_name: "game.dll".to_string(),
            address: 0x2000,
            disassembly: "mov eax, [esp+4]\nret".to_string(),
            decompiler_output: "int TestFunc(int x) { return x; }".to_string(),
            windows_apis: vec![calxgloss_types::WindowsApiCall {
                name: "CreateFileA".to_string(),
                category: ApiCategory::Win32Core,
                pal_mapping: "std::fs::File::open".to_string(),
            }],
            test_cases: Vec::new(),
            api_category_mappings: Vec::new(),
            call_graph_neighbors: Vec::new(),
            neighboring_functions: Vec::new(),
            data_structures: Vec::new(),
            type_info: Vec::new(),
            control_flow_findings: Vec::new(),
        };

        let prompt = build_complexity_prompt(&FunctionComplexity::Standard, &data).unwrap();

        assert!(prompt.contains("API MAPPING REFERENCE"));
        assert!(prompt.contains("Win32Core Category"));
        assert!(prompt.contains("CreateFileA"));
        assert!(prompt.contains("std::fs::File::open"));
    }

    #[test]
    fn test_minimal_prompt_includes_api_mapping_reference() {
        let data = ComplexityPromptData {
            function_name: "SimpleFunc".to_string(),
            dll_name: "test.dll".to_string(),
            address: 0x1000,
            disassembly: "mov eax, 0\nret".to_string(),
            decompiler_output: "int SimpleFunc() { return 0; }".to_string(),
            windows_apis: vec![calxgloss_types::WindowsApiCall {
                name: "BitBlt".to_string(),
                category: ApiCategory::Gdi,
                pal_mapping: "tiny_skia::Pixmap::blit_rect [PAL placeholder]".to_string(),
            }],
            test_cases: Vec::new(),
            api_category_mappings: Vec::new(),
            call_graph_neighbors: Vec::new(),
            neighboring_functions: Vec::new(),
            data_structures: Vec::new(),
            type_info: Vec::new(),
            control_flow_findings: Vec::new(),
        };

        let prompt = build_complexity_prompt(&FunctionComplexity::Minimal, &data).unwrap();

        assert!(prompt.contains("API MAPPING REFERENCE"));
        assert!(prompt.contains("GDI Category"));
        assert!(prompt.contains("BitBlt"));
        assert!(prompt.contains("tiny_skia"));
    }

    #[test]
    fn test_rich_prompt_includes_api_mapping_reference() {
        let data = ComplexityPromptData {
            function_name: "ComplexFunc".to_string(),
            dll_name: "render.dll".to_string(),
            address: 0x3000,
            disassembly: (0..200)
                .map(|i| format!("0x{:08X}: nop", 0x3000 + i * 4))
                .collect::<Vec<_>>()
                .join("\n"),
            decompiler_output: "int ComplexFunc() { return 0; }".to_string(),
            windows_apis: vec![
                calxgloss_types::WindowsApiCall {
                    name: "Direct3DCreate9".to_string(),
                    category: ApiCategory::DirectX,
                    pal_mapping: "wgpu::Instance::new [PAL placeholder]".to_string(),
                },
                calxgloss_types::WindowsApiCall {
                    name: "GetDC".to_string(),
                    category: ApiCategory::Gdi,
                    pal_mapping: "tiny_skia::Pixmap::new [PAL placeholder]".to_string(),
                },
            ],
            test_cases: Vec::new(),
            api_category_mappings: Vec::new(),
            call_graph_neighbors: Vec::new(),
            neighboring_functions: Vec::new(),
            data_structures: Vec::new(),
            type_info: Vec::new(),
            control_flow_findings: Vec::new(),
        };

        let prompt = build_complexity_prompt(&FunctionComplexity::Rich, &data).unwrap();

        assert!(prompt.contains("API MAPPING REFERENCE"));
        assert!(prompt.contains("DirectX Category"));
        assert!(prompt.contains("GDI Category"));
        assert!(prompt.contains("Direct3DCreate9"));
        assert!(prompt.contains("wgpu::Instance::new"));
        assert!(prompt.contains("GetDC"));
        assert!(prompt.contains("tiny_skia"));
    }

    #[test]
    fn test_prompt_has_no_api_mapping_reference_when_no_apis() {
        let data = ComplexityPromptData {
            function_name: "NoApiFunc".to_string(),
            dll_name: "test.dll".to_string(),
            address: 0x1000,
            disassembly: "mov eax, 0\nret".to_string(),
            decompiler_output: "int NoApiFunc() { return 0; }".to_string(),
            windows_apis: Vec::new(),
            test_cases: Vec::new(),
            api_category_mappings: Vec::new(),
            call_graph_neighbors: Vec::new(),
            neighboring_functions: Vec::new(),
            data_structures: Vec::new(),
            type_info: Vec::new(),
            control_flow_findings: Vec::new(),
        };

        let prompt = build_complexity_prompt(&FunctionComplexity::Standard, &data).unwrap();

        assert!(!prompt.contains("Win32Core Category"));
        assert!(!prompt.contains("DirectX Category"));
    }

    #[test]
    fn test_fix_template_with_failure_history() {
        let hints = vec![
            calxgloss_types::FailureHint::new(
                1,
                "compile_fix",
                "Compilation failed: E0425 — `__security_init_cookie` not found",
            ),
            calxgloss_types::FailureHint::new(
                2,
                "test_fix",
                "2 of 5 tests passed — wrong return on boundary",
            ),
        ];

        let template = FixTemplate::with_history(
            "entry".to_string(),
            "eqmain.dll".to_string(),
            "fn entry() { __security_init_cookie(); }".to_string(),
            "Tests failed on boundary input".to_string(),
            hints,
        );
        let rendered = template.render().unwrap();

        assert!(rendered.contains("entry"));
        assert!(rendered.contains("eqmain.dll"));
        assert!(rendered.contains("PREVIOUS ATTEMPT HISTORY"));
        assert!(rendered.contains("Attempt #1"));
        assert!(rendered.contains("compile_fix"));
        assert!(rendered.contains("E0425"));
        assert!(rendered.contains("Attempt #2"));
        assert!(rendered.contains("test_fix"));
        assert!(rendered.contains("wrong return on boundary"));
    }

    #[test]
    fn test_fix_template_without_history_has_no_history_section() {
        let template = FixTemplate::new(
            "entry".to_string(),
            "eqmain.dll".to_string(),
            "fn entry() { __security_init_cookie(); }".to_string(),
            "Tests failed".to_string(),
        );
        let rendered = template.render().unwrap();

        assert!(rendered.contains("entry"));
        assert!(!rendered.contains("PREVIOUS ATTEMPT HISTORY"));
    }

    #[test]
    fn test_escalate_template_with_failure_history() {
        let hints = vec![calxgloss_types::FailureHint::new(
            1,
            "compile_fix",
            "Wrong shader constant mapping",
        )];

        let prompt = build_escalate_prompt(
            "DrawSprite".to_string(),
            "game_logic.dll".to_string(),
            "fn draw_sprite(x: i32) -> i32 { x }".to_string(),
            "Wrong result".to_string(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            hints,
        )
        .unwrap();

        assert!(prompt.contains("DrawSprite"));
        assert!(prompt.contains("PREVIOUS ATTEMPT HISTORY"));
        assert!(prompt.contains("Attempt #1"));
        assert!(prompt.contains("compile_fix"));
        assert!(prompt.contains("Wrong shader constant mapping"));
    }

    #[test]
    fn test_escalate_template_with_memory_findings() {
        let findings = vec![MemoryInfo {
            function: "FUN_18003ab00".to_string(),
            kind: "handle".to_string(),
            suggestion: "RAII guard struct with Drop impl".to_string(),
            confidence: 70,
            evidence: "hFile = CreateFileW(...); CloseHandle(hFile);".to_string(),
        }];

        let prompt = build_escalate_prompt_with_context(
            "FUN_18003ab00".to_string(),
            "eqmain.dll".to_string(),
            "fn fun_18003ab00() { /* manual open/close */ }".to_string(),
            "Wrong result".to_string(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            findings,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )
        .expect("the escalate prompt should render");

        assert!(prompt.contains("MEMORY LIFECYCLE"));
        assert!(prompt.contains("RAII guard struct with Drop impl"));
        assert!(prompt.contains("handle lifecycle"));
        assert!(prompt.contains("confidence 70"));
        assert!(prompt.contains("hFile = CreateFileW(...); CloseHandle(hFile);"));
    }

    #[test]
    fn test_escalate_template_without_memory_findings_says_so() {
        let prompt = build_escalate_prompt(
            "DrawSprite".to_string(),
            "game_logic.dll".to_string(),
            "fn draw_sprite(x: i32) -> i32 { x }".to_string(),
            "Wrong result".to_string(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )
        .expect("the escalate prompt should render");

        assert!(prompt.contains("MEMORY LIFECYCLE"));
        assert!(prompt.contains("No memory lifecycle context available."));
    }

    #[test]
    fn test_escalate_template_with_concurrency_findings() {
        let findings = vec![ConcurrencyInfo {
            function: "FUN_18003ab00".to_string(),
            kind: "mutex".to_string(),
            suggestion: "std::sync::Mutex<T>".to_string(),
            confidence: 70,
            evidence: "pthread_mutex_lock(&mtx); ... pthread_mutex_unlock(&mtx);".to_string(),
        }];

        let prompt = build_escalate_prompt_with_context(
            "FUN_18003ab00".to_string(),
            "eqmain.dll".to_string(),
            "fn fun_18003ab00() { /* manual lock/unlock */ }".to_string(),
            "Wrong result".to_string(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            findings,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )
        .expect("the escalate prompt should render");

        assert!(prompt.contains("CONCURRENCY"));
        assert!(prompt.contains("std::sync::Mutex<T>"));
        assert!(prompt.contains("mutex construct"));
        assert!(prompt.contains("confidence 70"));
        assert!(prompt.contains("pthread_mutex_lock(&mtx); ... pthread_mutex_unlock(&mtx);"));
    }

    #[test]
    fn test_escalate_template_without_concurrency_findings_says_so() {
        let prompt = build_escalate_prompt(
            "DrawSprite".to_string(),
            "game_logic.dll".to_string(),
            "fn draw_sprite(x: i32) -> i32 { x }".to_string(),
            "Wrong result".to_string(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )
        .expect("the escalate prompt should render");

        assert!(prompt.contains("CONCURRENCY"));
        assert!(prompt.contains("No concurrency context available."));
    }

    #[test]
    fn test_escalate_template_with_callback_findings() {
        let findings = vec![CallbackInfo {
            function: "FUN_18003ab00".to_string(),
            kind: "fp_array".to_string(),
            suggestion: "Vec<Box<dyn Fn(i32)>>".to_string(),
            confidence: 70,
            evidence: "handlers[uVar2](iVar3);".to_string(),
        }];

        let prompt = build_escalate_prompt_with_context(
            "FUN_18003ab00".to_string(),
            "eqmain.dll".to_string(),
            "fn fun_18003ab00() { /* raw table indexing */ }".to_string(),
            "Wrong result".to_string(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            findings,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )
        .expect("the escalate prompt should render");

        assert!(prompt.contains("CALLBACKS"));
        assert!(prompt.contains("Vec<Box<dyn Fn(i32)>>"));
        assert!(prompt.contains("fp_array pattern"));
        assert!(prompt.contains("confidence 70"));
        assert!(prompt.contains("handlers[uVar2](iVar3);"));
    }

    #[test]
    fn test_escalate_template_with_control_flow_findings() {
        let findings = vec![ControlFlowInfo {
            function: "FUN_18003ab00".to_string(),
            kind: "switch".to_string(),
            suggestion: "replace the if-else chain with match command { /* 5 arms */ }".to_string(),
            confidence: 70,
            evidence: "if (command == 1) ... else if (command == 5)".to_string(),
        }];

        let prompt = build_escalate_prompt_with_context(
            "FUN_18003ab00".to_string(),
            "eqmain.dll".to_string(),
            "fn fun_18003ab00() { /* if-else ladder */ }".to_string(),
            "Wrong result".to_string(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            findings,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )
        .expect("the escalate prompt should render");

        assert!(prompt.contains("CONTROL FLOW"));
        assert!(prompt.contains("match command { /* 5 arms */ }"));
        assert!(prompt.contains("switch construct"));
        assert!(prompt.contains("confidence 70"));
        assert!(prompt.contains("if (command == 1) ... else if (command == 5)"));
    }

    #[test]
    fn test_escalate_template_without_control_flow_findings_says_so() {
        let prompt = build_escalate_prompt(
            "DrawSprite".to_string(),
            "game_logic.dll".to_string(),
            "fn draw_sprite(x: i32) -> i32 { x }".to_string(),
            "Wrong result".to_string(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )
        .expect("the escalate prompt should render");

        assert!(prompt.contains("CONTROL FLOW"));
        assert!(prompt.contains("No control-flow context available."));
    }

    #[test]
    fn test_escalate_template_with_string_findings() {
        let findings = vec![
            StringContextInfo {
                function: "FUN_18003ab00".to_string(),
                kind: "file_path".to_string(),
                suggestion: "config file path".to_string(),
                confidence: 70,
                evidence: "lFile = CreateFileA(\"Journal.txt\",...);".to_string(),
            },
            StringContextInfo {
                function: "FUN_18003ab00".to_string(),
                kind: "format_string".to_string(),
                suggestion: "`*const i8`, `i32`".to_string(),
                confidence: 70,
                evidence: "sprintf(local_10, \"%s: %d hits\", pcVar2, uVar3);".to_string(),
            },
        ];

        let prompt = build_escalate_prompt_with_context(
            "FUN_18003ab00".to_string(),
            "eqmain.dll".to_string(),
            "fn fun_18003ab00() { /* raw literals */ }".to_string(),
            "Wrong result".to_string(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            findings,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )
        .expect("the escalate prompt should render");

        assert!(prompt.contains("STRINGS"));
        assert!(prompt.contains("config file path"));
        assert!(prompt.contains("file_path string"));
        assert!(prompt.contains("`*const i8`, `i32`"));
        assert!(prompt.contains("format_string string"));
        assert!(prompt.contains("confidence 70"));
        assert!(prompt.contains("sprintf(local_10, \"%s: %d hits\", pcVar2, uVar3);"));
    }

    #[test]
    fn test_escalate_template_with_api_findings() {
        let findings = vec![
            ApiInfo {
                function: String::new(),
                api: "inflate".to_string(),
                library: "zlib".to_string(),
                suggestion: "flate2".to_string(),
                kind: "import".to_string(),
                confidence: 90,
                evidence: "inflate".to_string(),
            },
            ApiInfo {
                function: "FUN_18003ab00".to_string(),
                api: "CreateFileA".to_string(),
                library: "Win32".to_string(),
                suggestion: "windows / std::fs".to_string(),
                kind: "transitive".to_string(),
                confidence: 60,
                evidence: "FUN_18003ab00 → FUN_18003c000 → CreateFileA".to_string(),
            },
        ];

        let prompt = build_escalate_prompt_with_context(
            "FUN_18003ab00".to_string(),
            "eqmain.dll".to_string(),
            "fn fun_18003ab00() { /* raw imports */ }".to_string(),
            "Wrong result".to_string(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            findings,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )
        .expect("the escalate prompt should render");

        assert!(prompt.contains("LIBRARIES AND APIS"));
        assert!(prompt.contains("flate2"));
        assert!(prompt.contains("zlib import"));
        assert!(prompt.contains("confidence 90"));
        assert!(prompt.contains("windows / std::fs"));
        assert!(prompt.contains("Win32 transitive"));
        assert!(prompt.contains("Reached by: `FUN_18003ab00`"));
        assert!(prompt.contains("FUN_18003ab00 → FUN_18003c000 → CreateFileA"));
    }

    #[test]
    fn test_escalate_template_without_api_findings_says_so() {
        let prompt = build_escalate_prompt(
            "DrawSprite".to_string(),
            "game_logic.dll".to_string(),
            "fn draw_sprite(x: i32) -> i32 { x }".to_string(),
            "Wrong result".to_string(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )
        .expect("the escalate prompt should render");

        assert!(prompt.contains("LIBRARIES AND APIS"));
        assert!(prompt.contains("No library/API context available."));
    }

    #[test]
    fn test_escalate_template_with_const_findings() {
        let findings = vec![
            ConstInfo {
                function: "FUN_18003ab00".to_string(),
                kind: "bitflag_group".to_string(),
                suggestion: "bitflags! struct Flags: u32".to_string(),
                confidence: 70,
                evidence: "if ((uVar1 & 0x10) != 0) { ... } uVar1 = uVar1 | 0x20;".to_string(),
            },
            ConstInfo {
                function: "FUN_18003ab00".to_string(),
                kind: "enum_candidate".to_string(),
                suggestion: "enum State { /* variants for 0..=3 */ }".to_string(),
                confidence: 70,
                evidence: "switch(local_4) case 0x0: case 0x1: case 0x2: case 0x3:".to_string(),
            },
            ConstInfo {
                function: "FUN_18003ab00".to_string(),
                kind: "named_constant".to_string(),
                suggestion: "const VALUE_0x400: u32 = 0x400;".to_string(),
                confidence: 60,
                evidence: "0x400 in FUN_18003ab00, FUN_18003e750".to_string(),
            },
        ];

        let prompt = build_escalate_prompt_with_context(
            "FUN_18003ab00".to_string(),
            "eqmain.dll".to_string(),
            "fn fun_18003ab00() { /* bare literals */ }".to_string(),
            "Wrong result".to_string(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            findings,
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )
        .expect("the escalate prompt should render");

        assert!(prompt.contains("CONSTANTS"));
        assert!(prompt.contains("bitflags! struct Flags: u32"));
        assert!(prompt.contains("bitflag_group"));
        assert!(prompt.contains("enum State { /* variants for 0..=3 */ }"));
        assert!(prompt.contains("enum_candidate"));
        assert!(prompt.contains("const VALUE_0x400: u32 = 0x400;"));
        assert!(prompt.contains("named_constant"));
        assert!(prompt.contains("confidence 70"));
        assert!(prompt.contains("confidence 60"));
        assert!(prompt.contains("if ((uVar1 & 0x10) != 0) { ... } uVar1 = uVar1 | 0x20;"));
    }

    #[test]
    fn test_escalate_template_without_const_findings_says_so() {
        let prompt = build_escalate_prompt(
            "DrawSprite".to_string(),
            "game_logic.dll".to_string(),
            "fn draw_sprite(x: i32) -> i32 { x }".to_string(),
            "Wrong result".to_string(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )
        .expect("the escalate prompt should render");

        assert!(prompt.contains("CONSTANTS"));
        assert!(prompt.contains("No constant context available."));
    }

    #[test]
    fn test_escalate_template_without_string_findings_says_so() {
        let prompt = build_escalate_prompt(
            "DrawSprite".to_string(),
            "game_logic.dll".to_string(),
            "fn draw_sprite(x: i32) -> i32 { x }".to_string(),
            "Wrong result".to_string(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )
        .expect("the escalate prompt should render");

        assert!(prompt.contains("STRINGS"));
        assert!(prompt.contains("No string context available."));
    }

    fn control_flow_fixture() -> ControlFlowInfo {
        ControlFlowInfo {
            function: "FUN_18003ab00".to_string(),
            kind: "state_machine".to_string(),
            suggestion: "enum State + match state { /* 3 states */ }".to_string(),
            confidence: 70,
            evidence: "state variable state with 3 states idle: STATE_IDLE".to_string(),
        }
    }

    #[test]
    fn test_module_context_template_renders_control_flow_section() {
        let req = sample_request();
        let data = ModuleContextPromptData::from_request_with_context(
            &req,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            vec![control_flow_fixture()],
        );

        let prompt = build_module_context_prompt(&data).expect("the prompt should render");

        assert!(prompt.contains("CONTROL FLOW PATTERNS"));
        assert!(prompt.contains("enum State + match state { /* 3 states */ }"));
        assert!(prompt.contains("state_machine construct"));
        assert!(prompt.contains("confidence 70"));
        assert!(prompt.contains("idle: STATE_IDLE"));
    }

    #[test]
    fn test_module_context_template_without_control_flow_findings_says_so() {
        let req = sample_request();
        let data = ModuleContextPromptData::from_request(&req);

        let prompt = build_module_context_prompt(&data).expect("the prompt should render");

        assert!(prompt.contains("CONTROL FLOW PATTERNS"));
        assert!(prompt.contains("No control-flow context available."));
    }

    #[test]
    fn test_full_module_template_renders_control_flow_section() {
        let req = sample_request();
        let data = FullModulePromptData::from_request_with_full_context(
            &req,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            vec![control_flow_fixture()],
        );

        let prompt = build_full_module_prompt(&data).expect("the prompt should render");

        assert!(prompt.contains("CONTROL FLOW PATTERNS"));
        assert!(prompt.contains("enum State + match state { /* 3 states */ }"));
        assert!(prompt.contains("state_machine construct"));
        assert!(prompt.contains("confidence 70"));
    }

    #[test]
    fn test_full_module_template_without_control_flow_findings_says_so() {
        let req = sample_request();
        let data = FullModulePromptData::from_request(&req);

        let prompt = build_full_module_prompt(&data).expect("the prompt should render");

        assert!(prompt.contains("CONTROL FLOW PATTERNS"));
        assert!(prompt.contains("No control-flow context available."));
    }

    #[test]
    fn test_rich_template_renders_control_flow_section() {
        let data = ComplexityPromptData {
            function_name: "FUN_18003ab00".to_string(),
            dll_name: "eqmain.dll".to_string(),
            address: 0x3000,
            disassembly: "mov eax, 0\nret".to_string(),
            decompiler_output: "undefined FUN_18003ab00(void) { }".to_string(),
            windows_apis: Vec::new(),
            test_cases: Vec::new(),
            api_category_mappings: Vec::new(),
            call_graph_neighbors: Vec::new(),
            neighboring_functions: Vec::new(),
            data_structures: Vec::new(),
            type_info: Vec::new(),
            control_flow_findings: vec![control_flow_fixture()],
        };

        let prompt = build_complexity_prompt(&FunctionComplexity::Rich, &data)
            .expect("the rich prompt should render");

        assert!(prompt.contains("CONTROL FLOW PATTERNS"));
        assert!(prompt.contains("enum State + match state { /* 3 states */ }"));
        assert!(prompt.contains("state_machine construct"));
        assert!(prompt.contains("confidence 70"));
    }

    #[test]
    fn test_rich_template_without_control_flow_findings_says_so() {
        let data = ComplexityPromptData {
            function_name: "SimpleFunc".to_string(),
            dll_name: "test.dll".to_string(),
            address: 0x3000,
            disassembly: "mov eax, 0\nret".to_string(),
            decompiler_output: "int SimpleFunc() { return 0; }".to_string(),
            windows_apis: Vec::new(),
            test_cases: Vec::new(),
            api_category_mappings: Vec::new(),
            call_graph_neighbors: Vec::new(),
            neighboring_functions: Vec::new(),
            data_structures: Vec::new(),
            type_info: Vec::new(),
            control_flow_findings: Vec::new(),
        };

        let prompt = build_complexity_prompt(&FunctionComplexity::Rich, &data)
            .expect("the rich prompt should render");

        assert!(prompt.contains("CONTROL FLOW PATTERNS"));
        assert!(prompt.contains("No control-flow context available."));
    }

    #[test]
    fn test_detailed_template_renders_control_flow_section() {
        let data = ComplexityPromptData {
            function_name: "FUN_18003ab00".to_string(),
            dll_name: "eqmain.dll".to_string(),
            address: 0x4000,
            disassembly: "mov eax, 0\nret".to_string(),
            decompiler_output: "undefined FUN_18003ab00(void) { }".to_string(),
            windows_apis: Vec::new(),
            test_cases: Vec::new(),
            api_category_mappings: Vec::new(),
            call_graph_neighbors: Vec::new(),
            neighboring_functions: Vec::new(),
            data_structures: Vec::new(),
            type_info: Vec::new(),
            control_flow_findings: vec![control_flow_fixture()],
        };

        let prompt = build_complexity_prompt(&FunctionComplexity::Detailed, &data)
            .expect("the detailed prompt should render");

        assert!(prompt.contains("CONTROL FLOW PATTERNS"));
        assert!(prompt.contains("enum State + match state { /* 3 states */ }"));
        assert!(prompt.contains("state_machine construct"));
        assert!(prompt.contains("confidence 70"));
    }

    #[test]
    fn test_detailed_template_without_control_flow_findings_says_so() {
        let data = ComplexityPromptData {
            function_name: "SimpleFunc".to_string(),
            dll_name: "test.dll".to_string(),
            address: 0x4000,
            disassembly: "mov eax, 0\nret".to_string(),
            decompiler_output: "int SimpleFunc() { return 0; }".to_string(),
            windows_apis: Vec::new(),
            test_cases: Vec::new(),
            api_category_mappings: Vec::new(),
            call_graph_neighbors: Vec::new(),
            neighboring_functions: Vec::new(),
            data_structures: Vec::new(),
            type_info: Vec::new(),
            control_flow_findings: Vec::new(),
        };

        let prompt = build_complexity_prompt(&FunctionComplexity::Detailed, &data)
            .expect("the detailed prompt should render");

        assert!(prompt.contains("CONTROL FLOW PATTERNS"));
        assert!(prompt.contains("No control-flow context available."));
    }

    #[test]
    fn test_minimal_and_standard_templates_stay_clean_of_control_flow() {
        let data = ComplexityPromptData {
            function_name: "SimpleFunc".to_string(),
            dll_name: "test.dll".to_string(),
            address: 0x1000,
            disassembly: "mov eax, 0\nret".to_string(),
            decompiler_output: "int SimpleFunc() { return 0; }".to_string(),
            windows_apis: Vec::new(),
            test_cases: Vec::new(),
            api_category_mappings: Vec::new(),
            call_graph_neighbors: Vec::new(),
            neighboring_functions: Vec::new(),
            data_structures: Vec::new(),
            type_info: Vec::new(),
            control_flow_findings: vec![control_flow_fixture()],
        };

        for tier in [FunctionComplexity::Minimal, FunctionComplexity::Standard] {
            let prompt = build_complexity_prompt(&tier, &data).expect("the prompt should render");
            assert!(!prompt.contains("CONTROL FLOW"));
        }
    }

    #[test]
    fn test_escalate_template_without_callback_findings_says_so() {
        let prompt = build_escalate_prompt(
            "DrawSprite".to_string(),
            "game_logic.dll".to_string(),
            "fn draw_sprite(x: i32) -> i32 { x }".to_string(),
            "Wrong result".to_string(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )
        .expect("the escalate prompt should render");

        assert!(prompt.contains("CALLBACKS"));
        assert!(prompt.contains("No callback context available."));
    }

    #[test]
    fn test_edge_case_template_with_failure_history() {
        let hints = vec![
            calxgloss_types::FailureHint::new(1, "test_fix", "Wrong result on zero input"),
            calxgloss_types::FailureHint::new(
                2,
                "escalate",
                "Still wrong on zero after adding context",
            ),
        ];

        let failed_tests = vec![EdgeCaseTest {
            index: 1,
            inputs: json!({"x": 0}),
            expected: json!(0),
            actual: json!(1),
            error: "Expected 0, got 1".to_string(),
            disassembly_hints: "cmp eax, 0\nje .zero_branch".to_string(),
        }];

        let prompt = build_edge_case_prompt(
            "DrawSprite".to_string(),
            "game_logic.dll".to_string(),
            "fn draw_sprite(x: i32) -> i32 { x + 1 }".to_string(),
            failed_tests,
            Vec::new(),
            hints,
        )
        .unwrap();

        assert!(prompt.contains("DrawSprite"));
        assert!(prompt.contains("PREVIOUS ATTEMPT HISTORY"));
        assert!(prompt.contains("Attempt #1"));
        assert!(prompt.contains("Attempt #2"));
        assert!(prompt.contains("Learn from past failures"));
    }

    #[test]
    fn test_fix_template_with_fix_attempted() {
        let hint = calxgloss_types::FailureHint::new(1, "compile_fix", "Wrong parameter type")
            .with_fix("Added explicit casting to u32");

        let template = FixTemplate::with_history(
            "entry".to_string(),
            "eqmain.dll".to_string(),
            "fn entry() { }".to_string(),
            "Compilation failed".to_string(),
            vec![hint],
        );
        let rendered = template.render().unwrap();

        assert!(rendered.contains("PREVIOUS ATTEMPT HISTORY"));
        assert!(rendered.contains("Wrong parameter type"));
        assert!(rendered.contains("Fix attempted:"));
        assert!(rendered.contains("Added explicit casting to u32"));
    }

    #[test]
    fn test_build_signature_prompt_basic() {
        let data = SignaturePromptData {
            function_name: "SimpleFunc".to_string(),
            dll_name: "test.dll".to_string(),
            address_hex: "0x1000".to_string(),
            signature: "int __stdcall SimpleFunc(int x, int y)".to_string(),
            call_graph_neighbors: Vec::new(),
        };

        let prompt = build_signature_prompt(&data).unwrap();

        assert!(prompt.contains("SimpleFunc"));
        assert!(prompt.contains("test.dll"));
        assert!(prompt.contains("0x1000"));
        assert!(prompt.contains("int __stdcall SimpleFunc(int x, int y)"));
        assert!(prompt.contains("FUNCTION:"));
        assert!(prompt.contains("SIGNATURE"));
        assert!(!prompt.contains("DISASSEMBLY"));
        assert!(!prompt.contains("DECOMPILER OUTPUT"));
    }

    #[test]
    fn test_build_signature_prompt_with_neighbors() {
        let data = SignaturePromptData {
            function_name: "DrawSprite".to_string(),
            dll_name: "game_logic.dll".to_string(),
            address_hex: "0x5000".to_string(),
            signature: "int __stdcall DrawSprite(int x, int y, unsigned int texture_index)"
                .to_string(),
            call_graph_neighbors: vec![
                CallGraphNeighbor {
                    name: "helper_compute".to_string(),
                    address: 0x4000,
                    signature: "int __stdcall helper_compute(int a, int b)".to_string(),
                    role: "callee".to_string(),
                },
                CallGraphNeighbor {
                    name: "sprite_manager".to_string(),
                    address: 0x3000,
                    signature: "void __stdcall sprite_manager(void)".to_string(),
                    role: "caller".to_string(),
                },
            ],
        };

        let prompt = build_signature_prompt(&data).unwrap();

        assert!(prompt.contains("DrawSprite"));
        assert!(prompt.contains("CALL GRAPH NEIGHBORS"));
        assert!(prompt.contains("helper_compute"));
        assert!(prompt.contains("callee"));
        assert!(prompt.contains("int __stdcall helper_compute(int a, int b)"));
        assert!(prompt.contains("sprite_manager"));
        assert!(prompt.contains("caller"));
        assert!(prompt.contains("void __stdcall sprite_manager(void)"));
    }

    #[test]
    fn test_build_signature_prompt_no_neighbors_section() {
        let data = SignaturePromptData {
            function_name: "Standalone".to_string(),
            dll_name: "utils.dll".to_string(),
            address_hex: "0x0".to_string(),
            signature: "void __stdcall Standalone()".to_string(),
            call_graph_neighbors: Vec::new(),
        };

        let prompt = build_signature_prompt(&data).unwrap();

        assert!(prompt.contains("Standalone"));
        assert!(prompt.contains("void __stdcall Standalone()"));
        assert!(!prompt.contains("CALL GRAPH NEIGHBORS"));
    }

    #[test]
    fn test_extract_signature_from_decompiler() {
        let output = "int __stdcall DrawSprite(int x, int y) {\n    return x + y;\n}";
        assert_eq!(
            extract_signature_from_decompiler(output),
            "int __stdcall DrawSprite(int x, int y)"
        );

        let output2 =
            "longlong FUN_18008ed50(longlong param_1,int param_2)\n\n{\n  return param_1;\n}";
        assert_eq!(
            extract_signature_from_decompiler(output2),
            "longlong FUN_18008ed50(longlong param_1,int param_2)"
        );

        assert_eq!(extract_signature_from_decompiler(""), "");
        assert_eq!(extract_signature_from_decompiler("  \n  "), "");
    }
}
