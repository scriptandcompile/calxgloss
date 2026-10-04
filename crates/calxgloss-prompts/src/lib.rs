//! Prompt templates and rendering for the Calxgloss LLM translation pipeline.
//!
//! This crate provides a lightweight template engine for building prompts
//! sent to the local LLM. Templates are embedded at compile time via
//! `include_str!` and rendered with structured data from the translation
//! pipeline.
//!
//! # Architecture
//!
//! - [`context`] — Data structs (`StubPromptData`, `ComplexityPromptData`, etc.)
//! - [`templates`] — Askama template structs (`MinimalTemplate`, `TranslateTemplate`, etc.)
//! - [`build_translate_prompt`] — Builds a standard translation prompt
//! - [`build_complexity_prompt`] — Selects template by complexity
//! - [`build_stub_prompt`] — Builds a Tier 0 (stub-only) prompt
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
    build_module_context_prompt, build_stub_prompt, build_translate_prompt,
    build_with_tests_prompt, extract_signature_from_decompiler,
};
pub use context::{
    ComplexityPromptData, DisassemblyPromptData, FullModulePromptData, ModuleContextPromptData,
    StubPromptData, WithTestsPromptData,
};
pub use error::PromptError;
pub use templates::{
    BoundaryValue, CallGraphNeighbor, EdgeCaseTemplate, EdgeCaseTest, EscalateTemplate,
    FixTemplate, FormattedTestResult, FullModuleTemplate, MinimalTemplate, ModuleContextTemplate,
    NeighborFunction, PalTraitDef, PalTraitMethod, ShimCode, StructField, StructuredData,
    StubTemplate, TestCaseFormatted, TranslateTemplate, TypeInfo, WithTestsTemplate,
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
            dll: "game_logic.dll".to_string(),
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
    fn test_build_stub_prompt_basic() {
        let data = StubPromptData {
            function_name: "SimpleFunc".to_string(),
            dll_name: "test.dll".to_string(),
            address_hex: "0x1000".to_string(),
            signature: "int __stdcall SimpleFunc(int x, int y)".to_string(),
            call_graph_neighbors: Vec::new(),
        };

        let prompt = build_stub_prompt(&data).unwrap();

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
    fn test_build_stub_prompt_with_neighbors() {
        let data = StubPromptData {
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

        let prompt = build_stub_prompt(&data).unwrap();

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
    fn test_build_stub_prompt_no_neighbors_section() {
        let data = StubPromptData {
            function_name: "Standalone".to_string(),
            dll_name: "utils.dll".to_string(),
            address_hex: "0x0".to_string(),
            signature: "void __stdcall Standalone()".to_string(),
            call_graph_neighbors: Vec::new(),
        };

        let prompt = build_stub_prompt(&data).unwrap();

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
