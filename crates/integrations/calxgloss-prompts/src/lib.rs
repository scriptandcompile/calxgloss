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
//! adds the full mapping table rows for each API category those calls belong to.
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
    ComplexityPromptData, DisassemblyPromptData, SignaturePromptData, WithTestsPromptData,
};
pub use error::PromptError;
pub use templates::capability_for;
pub use templates::{
    AlgorithmInfo, ApiInfo, BoundaryValue, CallGraphNeighbor, CallbackInfo, CapabilityInfo,
    ConcurrencyInfo, ConstInfo, ControlFlowInfo, ConventionInfo, CoverageInfo, DataTableInfo,
    EdgeCaseTemplate, EdgeCaseTest, ErrhandlingInfo, EscalateTemplate, EvidenceBundle, FixTemplate,
    FloatsimdInfo, FormattedTestResult, FullModuleTemplate, GlobalStateInfo, LibmatchInfo,
    MemoryInfo, MinimalTemplate, ModuleContextTemplate, NeighborFunction, PalTraitDef,
    PalTraitMethod, ParameterDirectionInfo, SerializationInfo, ShimCode, SignatureTemplate,
    StringContextInfo, StructField, StructuredData, TestCaseFormatted, TranslateTemplate, TypeInfo,
    UnknownInfo, WithTestsTemplate,
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
    fn prompts_use_one_blank_line_between_sections_and_no_dash_rules() {
        // Regression: block tags and `---` rules used to leave sections
        // separated by runs of blank lines and horizontal rules.
        let req = sample_request();
        let prompt = build_translate_prompt(&req).unwrap();

        assert!(
            !prompt.lines().any(|line| line.trim() == "---"),
            "no standalone --- separator lines"
        );
        assert!(
            !prompt.contains("\n\n\n"),
            "sections sit exactly one blank line apart"
        );
    }

    #[test]
    fn test_prompt_with_no_apis() {
        let mut req = sample_request();
        req.windows_apis = vec![];
        let prompt = build_translate_prompt(&req).unwrap();
        assert!(!prompt.contains("WINDOWS API CALLS IDENTIFIED"));
    }

    #[test]
    fn test_prompt_with_no_tests() {
        let mut req = sample_request();
        req.baseline_tests = vec![];
        let template = TranslateTemplate::from_request(&req);
        assert_eq!(template.test_cases.len(), 0);
    }

    #[test]
    fn the_evidence_bundle_carries_every_finding_list_and_defaults_empty() {
        let empty = EvidenceBundle::default();
        assert!(empty.call_graph_neighbors.is_empty());
        assert!(empty.neighboring_functions.is_empty());
        assert!(empty.data_structures.is_empty());
        assert!(empty.type_info.is_empty());
        assert!(empty.recognized_algorithms.is_empty());
        assert!(empty.memory_findings.is_empty());
        assert!(empty.concurrency_findings.is_empty());
        assert!(empty.callback_findings.is_empty());
        assert!(empty.control_flow_findings.is_empty());
        assert!(empty.convention_findings.is_empty());
        assert!(empty.global_state_findings.is_empty());
        assert!(empty.string_findings.is_empty());
        assert!(empty.api_findings.is_empty());
        assert!(empty.const_findings.is_empty());
        assert!(empty.serialization_findings.is_empty());
        assert!(empty.libmatch_findings.is_empty());
        assert!(empty.parameter_direction_findings.is_empty());
        assert!(empty.call_graph_context.is_empty());

        let filled = EvidenceBundle {
            call_graph_neighbors: vec![CallGraphNeighbor {
                name: "helper_compute".to_string(),
                address: 0x1000,
                signature: "int __stdcall helper_compute(int x)".to_string(),
                role: "callee".to_string(),
            }],
            ..Default::default()
        };
        assert_eq!(filled.call_graph_neighbors.len(), 1);
        assert!(
            filled.memory_findings.is_empty(),
            "a named-field bundle keeps the other lists at their default"
        );
    }

    #[test]
    fn test_escalate_prompt_basic() {
        let prompt = build_escalate_prompt(
            "DrawSprite".to_string(),
            "game_logic.dll".to_string(),
            "fn draw_sprite(x: i32) -> i32 { x }".to_string(),
            "Tests failed: boundary case x=0 produced wrong result".to_string(),
            EvidenceBundle::default(),
            Vec::new(),
        )
        .unwrap();

        assert!(prompt.contains("DrawSprite"));
        assert!(prompt.contains("game_logic.dll"));
        assert!(!prompt.contains("CALL GRAPH NEIGHBORS"));
        assert!(!prompt.contains("NEIGHBORING FUNCTIONS"));
        assert!(!prompt.contains("DATA STRUCTURES"));
        assert!(!prompt.contains("TYPE INFORMATION"));
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
            EvidenceBundle {
                call_graph_neighbors: neighbors,
                ..Default::default()
            },
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
            type_inference_coverage: CoverageInfo::default(),
            decompilation_cap_line: String::new(),
            disassembly_cap_line: String::new(),
            caller_edges_cap_line: String::new(),
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
            type_inference_coverage: CoverageInfo::default(),
            decompilation_cap_line: String::new(),
            disassembly_cap_line: String::new(),
            caller_edges_cap_line: String::new(),
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
            type_inference_coverage: CoverageInfo::default(),
            decompilation_cap_line: String::new(),
            disassembly_cap_line: String::new(),
            caller_edges_cap_line: String::new(),
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
            type_inference_coverage: CoverageInfo::default(),
            decompilation_cap_line: String::new(),
            disassembly_cap_line: String::new(),
            caller_edges_cap_line: String::new(),
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
            type_inference_coverage: CoverageInfo::default(),
            decompilation_cap_line: String::new(),
            disassembly_cap_line: String::new(),
            caller_edges_cap_line: String::new(),
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
            type_inference_coverage: CoverageInfo::default(),
            decompilation_cap_line: String::new(),
            disassembly_cap_line: String::new(),
            caller_edges_cap_line: String::new(),
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
            type_inference_coverage: CoverageInfo::default(),
            decompilation_cap_line: String::new(),
            disassembly_cap_line: String::new(),
            caller_edges_cap_line: String::new(),
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
            type_inference_coverage: CoverageInfo::default(),
            decompilation_cap_line: String::new(),
            disassembly_cap_line: String::new(),
            caller_edges_cap_line: String::new(),
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
            type_inference_coverage: CoverageInfo::default(),
            decompilation_cap_line: String::new(),
            disassembly_cap_line: String::new(),
            caller_edges_cap_line: String::new(),
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
            EvidenceBundle::default(),
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
            EvidenceBundle {
                memory_findings: findings,
                ..Default::default()
            },
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
    fn test_escalate_template_without_memory_findings_omits_the_section() {
        let prompt = build_escalate_prompt(
            "DrawSprite".to_string(),
            "game_logic.dll".to_string(),
            "fn draw_sprite(x: i32) -> i32 { x }".to_string(),
            "Wrong result".to_string(),
            EvidenceBundle::default(),
            Vec::new(),
        )
        .expect("the escalate prompt should render");

        assert!(!prompt.contains("MEMORY LIFECYCLE"));
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
            EvidenceBundle {
                concurrency_findings: findings,
                ..Default::default()
            },
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
    fn test_escalate_template_without_concurrency_findings_omits_the_section() {
        let prompt = build_escalate_prompt(
            "DrawSprite".to_string(),
            "game_logic.dll".to_string(),
            "fn draw_sprite(x: i32) -> i32 { x }".to_string(),
            "Wrong result".to_string(),
            EvidenceBundle::default(),
            Vec::new(),
        )
        .expect("the escalate prompt should render");

        assert!(!prompt.contains("CONCURRENCY"));
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
            EvidenceBundle {
                callback_findings: findings,
                ..Default::default()
            },
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
            EvidenceBundle {
                control_flow_findings: findings,
                ..Default::default()
            },
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
    fn test_escalate_template_renders_branch_inventory_records() {
        // A retry after a divergence sees the same branch context as the
        // first attempt: the escalate CONTROL FLOW section shows each
        // branch record's kind, suggestion, confidence, and evidence.
        let findings = vec![
            ControlFlowInfo {
                function: "FUN_18003ab00".to_string(),
                kind: "switch".to_string(),
                suggestion: "replace the if-else chain with match command { /* 5 arms */ }"
                    .to_string(),
                confidence: 70,
                evidence: "if (command == 1) ... else if (command == 5)".to_string(),
            },
            branch_site_fixture(),
        ];

        let prompt = build_escalate_prompt_with_context(
            "FUN_18003ab00".to_string(),
            "eqmain.dll".to_string(),
            "fn fun_18003ab00() { /* if-else ladder */ }".to_string(),
            "Wrong result".to_string(),
            EvidenceBundle {
                control_flow_findings: findings,
                ..Default::default()
            },
            Vec::new(),
        )
        .expect("the escalate prompt should render");

        assert!(prompt.contains("CONTROL FLOW"));
        assert!(prompt.contains("keep the early return behind param_1 == 0"));
        assert!(prompt.contains("branch_site construct"));
        assert!(prompt.contains("confidence 80"));
        assert!(prompt.contains("if (param_1 == 0) {"));
        // The inventory joins the other findings in one section.
        assert!(prompt.contains("match command { /* 5 arms */ }"));
        assert!(prompt.contains("switch construct"));
    }

    #[test]
    fn test_escalate_template_without_control_flow_findings_omits_the_section() {
        let prompt = build_escalate_prompt(
            "DrawSprite".to_string(),
            "game_logic.dll".to_string(),
            "fn draw_sprite(x: i32) -> i32 { x }".to_string(),
            "Wrong result".to_string(),
            EvidenceBundle::default(),
            Vec::new(),
        )
        .expect("the escalate prompt should render");

        assert!(!prompt.contains("CONTROL FLOW"));
    }

    #[test]
    fn test_escalate_template_with_calling_convention_findings() {
        let findings = vec![
            ConventionInfo {
                function: "FUN_18003ab00".to_string(),
                callee: None,
                convention: "stdcall".to_string(),
                method: "callee_epilogue".to_string(),
                confidence: 80,
                evidence: "00401007  RET 0xC".to_string(),
            },
            ConventionInfo {
                function: "FUN_18003ab00".to_string(),
                callee: Some("FUN_1800412a0".to_string()),
                convention: "cdecl".to_string(),
                method: "caller_cleanup".to_string(),
                confidence: 70,
                evidence: "00401103  ADD ESP, 0x10".to_string(),
            },
        ];

        let prompt = build_escalate_prompt_with_context(
            "FUN_18003ab00".to_string(),
            "eqmain.dll".to_string(),
            "fn fun_18003ab00() { /* __stdcall extern */ }".to_string(),
            "Stack corruption".to_string(),
            EvidenceBundle {
                convention_findings: findings,
                ..Default::default()
            },
            Vec::new(),
        )
        .expect("the escalate prompt should render");

        assert!(prompt.contains("CALLING CONVENTION"));
        assert!(prompt.contains("stdcall"));
        assert!(prompt.contains("callee_epilogue"));
        assert!(prompt.contains("confidence 80"));
        assert!(prompt.contains("00401007  RET 0xC"));
        assert!(prompt.contains("cdecl"));
        assert!(prompt.contains("for `FUN_1800412a0`"));
        assert!(prompt.contains("00401103  ADD ESP, 0x10"));
    }

    #[test]
    fn test_escalate_template_without_calling_convention_findings_omits_the_section() {
        let prompt = build_escalate_prompt(
            "DrawSprite".to_string(),
            "game_logic.dll".to_string(),
            "fn draw_sprite(x: i32) -> i32 { x }".to_string(),
            "Wrong result".to_string(),
            EvidenceBundle::default(),
            Vec::new(),
        )
        .expect("the escalate prompt should render");

        assert!(!prompt.contains("CALLING CONVENTION"));
    }

    fn global_state_fixture() -> GlobalStateInfo {
        GlobalStateInfo {
            function: "FUN_18003ab00".to_string(),
            kind: "global_write".to_string(),
            global: "DAT_180064e80".to_string(),
            suggestion: "model the program global as shared struct state, not a Rust static"
                .to_string(),
            confidence: 85,
            evidence: "DAT_180064e80 = param_1".to_string(),
        }
    }

    #[test]
    fn test_escalate_template_with_global_state_findings() {
        let findings = vec![global_state_fixture()];

        let prompt = build_escalate_prompt_with_context(
            "FUN_18003ab00".to_string(),
            "eqmain.dll".to_string(),
            "fn fun_18003ab00(param_1: i32) { /* DAT store */ }".to_string(),
            "Wrong result".to_string(),
            EvidenceBundle {
                global_state_findings: findings,
                ..Default::default()
            },
            Vec::new(),
        )
        .expect("the escalate prompt should render");

        assert!(prompt.contains("GLOBAL STATE"));
        assert!(
            prompt.contains("model the program global as shared struct state, not a Rust static")
        );
        assert!(prompt.contains("global_write of `DAT_180064e80`"));
        assert!(prompt.contains("confidence 85"));
        assert!(prompt.contains("DAT_180064e80 = param_1"));
        // The purity flag changes the steering text: a function with
        // global accesses is directed to struct state, never a static.
        assert!(prompt.contains("rather than in a Rust `static`"));
    }

    #[test]
    fn test_escalate_template_without_global_state_findings_omits_the_section() {
        let prompt = build_escalate_prompt(
            "DrawSprite".to_string(),
            "game_logic.dll".to_string(),
            "fn draw_sprite(x: i32) -> i32 { x }".to_string(),
            "Wrong result".to_string(),
            EvidenceBundle::default(),
            Vec::new(),
        )
        .expect("the escalate prompt should render");

        assert!(!prompt.contains("GLOBAL STATE"));
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
            EvidenceBundle {
                string_findings: findings,
                ..Default::default()
            },
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
            EvidenceBundle {
                api_findings: findings,
                ..Default::default()
            },
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
    fn test_escalate_template_without_api_findings_omits_the_section() {
        let prompt = build_escalate_prompt(
            "DrawSprite".to_string(),
            "game_logic.dll".to_string(),
            "fn draw_sprite(x: i32) -> i32 { x }".to_string(),
            "Wrong result".to_string(),
            EvidenceBundle::default(),
            Vec::new(),
        )
        .expect("the escalate prompt should render");

        assert!(!prompt.contains("LIBRARIES AND APIS"));
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
            EvidenceBundle {
                const_findings: findings,
                ..Default::default()
            },
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
    fn test_escalate_template_without_const_findings_omits_the_section() {
        let prompt = build_escalate_prompt(
            "DrawSprite".to_string(),
            "game_logic.dll".to_string(),
            "fn draw_sprite(x: i32) -> i32 { x }".to_string(),
            "Wrong result".to_string(),
            EvidenceBundle::default(),
            Vec::new(),
        )
        .expect("the escalate prompt should render");

        assert!(!prompt.contains("CONSTANTS"));
    }

    #[test]
    fn test_escalate_template_data_table_rides_the_const_findings_section() {
        // The table facts reach a retry through the finding union's
        // prompt conversion — the escalate side of the table context,
        // so a retry after a divergence does not scatter the table
        // across the prompt again.
        let findings = vec![ConstInfo {
            function: String::new(),
            kind: "data_table".to_string(),
            suggestion: "const DAT_1400A1B60: [u16; 12];".to_string(),
            confidence: 70,
            evidence: "12 bytes decode cleanly as 6 u16 entries at 0x1400a1b60".to_string(),
        }];

        let prompt = build_escalate_prompt_with_context(
            "FUN_18003ab00".to_string(),
            "eqmain.dll".to_string(),
            "fn fun_18003ab00() { /* magic numbers */ }".to_string(),
            "Wrong result".to_string(),
            EvidenceBundle {
                const_findings: findings,
                ..Default::default()
            },
            Vec::new(),
        )
        .expect("the escalate prompt should render");

        assert!(prompt.contains("CONSTANTS"));
        assert!(prompt.contains("const DAT_1400A1B60: [u16; 12];"));
        assert!(prompt.contains("data_table"));
        assert!(prompt.contains("confidence 70"));
    }

    #[test]
    fn test_escalate_template_without_string_findings_omits_the_section() {
        let prompt = build_escalate_prompt(
            "DrawSprite".to_string(),
            "game_logic.dll".to_string(),
            "fn draw_sprite(x: i32) -> i32 { x }".to_string(),
            "Wrong result".to_string(),
            EvidenceBundle::default(),
            Vec::new(),
        )
        .expect("the escalate prompt should render");

        assert!(!prompt.contains("STRINGS"));
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

    fn branch_site_fixture() -> ControlFlowInfo {
        ControlFlowInfo {
            function: "FUN_18003ab00".to_string(),
            kind: "branch_site".to_string(),
            suggestion: "keep the early return behind param_1 == 0".to_string(),
            confidence: 80,
            evidence: "if (param_1 == 0) {".to_string(),
        }
    }

    #[test]
    fn test_module_context_template_renders_control_flow_section() {
        let req = sample_request();
        let prompt = build_module_context_prompt(
            &req,
            EvidenceBundle {
                control_flow_findings: vec![control_flow_fixture()],
                ..Default::default()
            },
        )
        .expect("the prompt should render");

        assert!(prompt.contains("CONTROL FLOW PATTERNS"));
        assert!(prompt.contains("enum State + match state { /* 3 states */ }"));
        assert!(prompt.contains("state_machine construct"));
        assert!(prompt.contains("confidence 70"));
        assert!(prompt.contains("idle: STATE_IDLE"));
    }

    #[test]
    fn test_module_context_template_renders_branch_inventory_records() {
        // A function's branch inventory appears in the same CONTROL FLOW
        // section as the other findings: each branch site is listed by
        // what it guards and the condition behind it, beside the
        // switch/loop/recursion readings.
        let req = sample_request();
        let prompt = build_module_context_prompt(
            &req,
            EvidenceBundle {
                control_flow_findings: vec![control_flow_fixture(), branch_site_fixture()],
                ..Default::default()
            },
        )
        .expect("the prompt should render");

        assert!(prompt.contains("CONTROL FLOW PATTERNS"));
        assert!(prompt.contains("keep the early return behind param_1 == 0"));
        assert!(prompt.contains("branch_site construct"));
        assert!(prompt.contains("confidence 80"));
        assert!(prompt.contains("if (param_1 == 0) {"));
        // The inventory joins the section, it does not replace it.
        assert!(prompt.contains("enum State + match state { /* 3 states */ }"));
        assert!(prompt.contains("state_machine construct"));
    }

    #[test]
    fn test_module_context_template_without_control_flow_findings_omits_the_section() {
        let req = sample_request();
        let prompt = build_module_context_prompt(&req, EvidenceBundle::default())
            .expect("the prompt should render");

        assert!(!prompt.contains("CONTROL FLOW PATTERNS"));
    }

    fn data_table_fixture() -> DataTableInfo {
        DataTableInfo {
            name: "DAT_1400a1b60".to_string(),
            element_type: "u16".to_string(),
            count: 12,
            confidence: 70,
        }
    }

    #[test]
    fn test_module_context_template_renders_data_tables_section() {
        let req = sample_request();
        let prompt = build_module_context_prompt(
            &req,
            EvidenceBundle {
                data_table_findings: vec![data_table_fixture()],
                ..Default::default()
            },
        )
        .expect("the prompt should render");

        assert!(prompt.contains("DATA TABLES"));
        assert!(prompt.contains("DAT_1400a1b60"));
        assert!(prompt.contains("[u16; 12]"));
        assert!(prompt.contains("u16"));
        assert!(prompt.contains("confidence 70"));
    }

    #[test]
    fn test_module_context_template_without_data_table_findings_omits_the_section() {
        let req = sample_request();
        let prompt = build_module_context_prompt(&req, EvidenceBundle::default())
            .expect("the prompt should render");

        assert!(!prompt.contains("DATA TABLES"));
    }

    fn convention_fixture() -> ConventionInfo {
        ConventionInfo {
            function: "FUN_18003ab00".to_string(),
            callee: None,
            convention: "stdcall".to_string(),
            method: "callee_epilogue".to_string(),
            confidence: 80,
            evidence: "00401007  RET 0xC".to_string(),
        }
    }

    #[test]
    fn test_module_context_template_renders_calling_convention_section() {
        let req = sample_request();
        let prompt = build_module_context_prompt(
            &req,
            EvidenceBundle {
                convention_findings: vec![convention_fixture()],
                ..Default::default()
            },
        )
        .expect("the prompt should render");

        assert!(prompt.contains("CALLING CONVENTION"));
        assert!(prompt.contains("stdcall"));
        assert!(prompt.contains("callee_epilogue"));
        assert!(prompt.contains("confidence 80"));
        assert!(prompt.contains("00401007  RET 0xC"));
    }

    #[test]
    fn test_module_context_template_renders_call_site_convention_naming_its_callee() {
        let req = sample_request();
        let mut finding = convention_fixture();
        finding.callee = Some("FUN_1800412a0".to_string());
        finding.convention = "microsoft_x64".to_string();
        finding.method = "call_site_convention".to_string();
        let prompt = build_module_context_prompt(
            &req,
            EvidenceBundle {
                convention_findings: vec![finding],
                ..Default::default()
            },
        )
        .expect("the prompt should render");

        assert!(prompt.contains("CALLING CONVENTION"));
        assert!(prompt.contains("microsoft_x64"));
        assert!(prompt.contains("for `FUN_1800412a0`"));
        assert!(prompt.contains("call_site_convention"));
    }

    #[test]
    fn test_module_context_template_without_convention_findings_omits_the_section() {
        let req = sample_request();
        let prompt = build_module_context_prompt(&req, EvidenceBundle::default())
            .expect("the prompt should render");

        assert!(!prompt.contains("CALLING CONVENTION"));
    }

    #[test]
    fn test_module_context_template_renders_global_state_section() {
        let req = sample_request();
        let prompt = build_module_context_prompt(
            &req,
            EvidenceBundle {
                global_state_findings: vec![global_state_fixture()],
                ..Default::default()
            },
        )
        .expect("the prompt should render");

        assert!(prompt.contains("GLOBAL STATE"));
        assert!(
            prompt.contains("model the program global as shared struct state, not a Rust static")
        );
        assert!(prompt.contains("global_write of `DAT_180064e80`"));
        assert!(prompt.contains("confidence 85"));
        assert!(prompt.contains("DAT_180064e80 = param_1"));
        // The purity flag changes the steering text: a function with
        // global accesses is directed to struct state, never a static.
        assert!(prompt.contains("rather than in a Rust `static`"));
    }

    #[test]
    fn test_module_context_template_without_global_state_findings_omits_the_section() {
        let req = sample_request();
        let prompt = build_module_context_prompt(&req, EvidenceBundle::default())
            .expect("the prompt should render");

        assert!(!prompt.contains("GLOBAL STATE"));
    }

    fn floatsimd_fixture() -> FloatsimdInfo {
        FloatsimdInfo {
            function: "FUN_18003ab00".to_string(),
            kind: "vector_matrix".to_string(),
            suggestion: "translate as a small vector struct or component array, not integer or \
                         pointer arithmetic"
                .to_string(),
            confidence: 60,
            evidence: "local_10 = CONCAT44(uVar2 >> 4, uVar2 & 0xfffffff);".to_string(),
        }
    }

    #[test]
    fn test_escalate_template_with_floatsimd_findings() {
        let findings = vec![floatsimd_fixture()];

        let prompt = build_escalate_prompt_with_context(
            "FUN_18003ab00".to_string(),
            "eqmain.dll".to_string(),
            "fn fun_18003ab00(param_1: i32) { /* CONCAT44 mangle */ }".to_string(),
            "Wrong result".to_string(),
            EvidenceBundle {
                floatsimd_findings: findings,
                ..Default::default()
            },
            Vec::new(),
        )
        .expect("the escalate prompt should render");

        assert!(prompt.contains("FLOAT/SIMD"));
        assert!(prompt.contains("small vector struct or component array"));
        assert!(prompt.contains("vector_matrix shape"));
        assert!(prompt.contains("confidence 60"));
        assert!(prompt.contains("CONCAT44(uVar2 >> 4, uVar2 & 0xfffffff)"));
        // The steering text makes the section's point: mangled vector
        // pseudo-C is float math, never integer or pointer logic.
        assert!(prompt.contains("Translate the math as float"));
    }

    #[test]
    fn test_escalate_template_without_floatsimd_findings_omits_the_section() {
        let prompt = build_escalate_prompt(
            "DrawSprite".to_string(),
            "game_logic.dll".to_string(),
            "fn draw_sprite(x: i32) -> i32 { x }".to_string(),
            "Wrong result".to_string(),
            EvidenceBundle::default(),
            Vec::new(),
        )
        .expect("the escalate prompt should render");

        assert!(!prompt.contains("FLOAT/SIMD"));
    }

    #[test]
    fn test_module_context_template_renders_floatsimd_section() {
        let req = sample_request();
        let prompt = build_module_context_prompt(
            &req,
            EvidenceBundle {
                floatsimd_findings: vec![floatsimd_fixture()],
                ..Default::default()
            },
        )
        .expect("the prompt should render");

        assert!(prompt.contains("FLOAT/SIMD"));
        assert!(prompt.contains("small vector struct or component array"));
        assert!(prompt.contains("vector_matrix shape"));
        assert!(prompt.contains("confidence 60"));
        assert!(prompt.contains("CONCAT44(uVar2 >> 4, uVar2 & 0xfffffff)"));
    }

    #[test]
    fn test_module_context_template_without_floatsimd_findings_omits_the_section() {
        let req = sample_request();
        let prompt = build_module_context_prompt(&req, EvidenceBundle::default())
            .expect("the prompt should render");

        assert!(!prompt.contains("FLOAT/SIMD"));
    }

    fn libmatch_fixture() -> LibmatchInfo {
        LibmatchInfo {
            function: "FUN_18003ab00".to_string(),
            symbol: "memcpy".to_string(),
            family: "crt".to_string(),
            suggestion: "slice copy / std::ptr::copy_nonoverlapping".to_string(),
            confidence: 90,
            evidence: "  *(undefined8 *)((long)puVar1 + -8) = *(undefined8 *)((long)lVar2 + -8);"
                .to_string(),
            // The section body was pinned before P19-3 gave match records
            // a version-authority note, so this fixture has none — the
            // pinned render stays byte-identical. A finding with a note
            // renders one extra "Admission:" line, pinned alongside.
            admission: String::new(),
        }
    }

    #[test]
    fn test_module_context_template_renders_known_library_section() {
        // The section lists the matched callee by symbol, family, and
        // confidence, and points the translator to the call's Rust equivalent.
        let req = sample_request();
        let prompt = build_module_context_prompt(
            &req,
            EvidenceBundle {
                libmatch_findings: vec![libmatch_fixture()],
                ..Default::default()
            },
        )
        .expect("the prompt should render");

        assert!(prompt.contains("KNOWN LIBRARY FUNCTIONS"));
        assert!(prompt.contains("`FUN_18003ab00` matches `memcpy`"));
        assert!(prompt.contains("crt library"));
        assert!(prompt.contains("confidence 90"));
        assert!(prompt.contains("slice copy / std::ptr::copy_nonoverlapping"));
        assert!(prompt.contains("= *(undefined8"));
        assert!(prompt.contains("map each call onto the"));
    }

    #[test]
    fn test_module_context_template_without_libmatch_findings_omits_the_section() {
        let req = sample_request();
        let prompt = build_module_context_prompt(&req, EvidenceBundle::default())
            .expect("the prompt should render");

        assert!(!prompt.contains("KNOWN LIBRARY FUNCTIONS"));
    }

    fn parameter_direction_fixture() -> ParameterDirectionInfo {
        ParameterDirectionInfo {
            function: "FUN_18003ab00".to_string(),
            parameter: "param_2".to_string(),
            direction: "out".to_string(),
            method: "param_direction".to_string(),
            confidence: 75,
            evidence: "*param_2 = 0;".to_string(),
        }
    }

    #[test]
    fn test_module_context_template_renders_parameter_direction_section() {
        // Each record states its parameter, its direction, and the body
        // line that decided it — the shape the first attempt needs to
        // pick the right Rust borrow instead of guessing from the type.
        let req = sample_request();
        let mut inout = parameter_direction_fixture();
        inout.parameter = "param_3".to_string();
        inout.direction = "inout".to_string();
        inout.confidence = 70;
        inout.evidence = "  param_3[0] = 3;".to_string();
        let prompt = build_module_context_prompt(
            &req,
            EvidenceBundle {
                parameter_direction_findings: vec![parameter_direction_fixture(), inout],
                ..Default::default()
            },
        )
        .expect("the prompt should render");

        assert!(prompt.contains("PARAMETER DIRECTIONS"));
        assert!(prompt.contains("param_2 is out"));
        assert!(prompt.contains("param_direction"));
        assert!(prompt.contains("confidence 75"));
        assert!(prompt.contains("*param_2 = 0;"));
        assert!(prompt.contains("param_3 is inout"));
        assert!(prompt.contains("confidence 70"));
        assert!(prompt.contains("param_3[0] = 3;"));
        // The section directs the signature shape that the readings identify.
        assert!(prompt.contains("a read-modify-write through a mutable borrow"));
    }

    #[test]
    fn test_module_context_template_without_parameter_direction_findings_omits_the_section() {
        let req = sample_request();
        let prompt = build_module_context_prompt(&req, EvidenceBundle::default())
            .expect("the prompt should render");

        assert!(!prompt.contains("PARAMETER DIRECTIONS"));
    }

    #[test]
    fn test_full_module_template_renders_control_flow_section() {
        let req = sample_request();
        let prompt = build_full_module_prompt(
            &req,
            EvidenceBundle {
                control_flow_findings: vec![control_flow_fixture()],
                ..Default::default()
            },
            Vec::new(),
            Vec::new(),
        )
        .expect("the prompt should render");

        assert!(prompt.contains("CONTROL FLOW PATTERNS"));
        assert!(prompt.contains("enum State + match state { /* 3 states */ }"));
        assert!(prompt.contains("state_machine construct"));
        assert!(prompt.contains("confidence 70"));
    }

    #[test]
    fn test_full_module_template_without_control_flow_findings_omits_the_section() {
        let req = sample_request();
        let prompt =
            build_full_module_prompt(&req, EvidenceBundle::default(), Vec::new(), Vec::new())
                .expect("the prompt should render");

        assert!(!prompt.contains("CONTROL FLOW PATTERNS"));
    }

    #[test]
    fn test_rich_template_renders_control_flow_section() {
        let data = ComplexityPromptData {
            type_inference_coverage: CoverageInfo::default(),
            decompilation_cap_line: String::new(),
            disassembly_cap_line: String::new(),
            caller_edges_cap_line: String::new(),
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
    fn test_rich_template_without_control_flow_findings_omits_the_section() {
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
            type_inference_coverage: CoverageInfo::default(),
            decompilation_cap_line: String::new(),
            disassembly_cap_line: String::new(),
            caller_edges_cap_line: String::new(),
        };

        let prompt = build_complexity_prompt(&FunctionComplexity::Rich, &data)
            .expect("the rich prompt should render");

        assert!(!prompt.contains("CONTROL FLOW PATTERNS"));
    }

    #[test]
    fn test_detailed_template_renders_control_flow_section() {
        let data = ComplexityPromptData {
            type_inference_coverage: CoverageInfo::default(),
            decompilation_cap_line: String::new(),
            disassembly_cap_line: String::new(),
            caller_edges_cap_line: String::new(),
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
    fn test_detailed_template_without_control_flow_findings_omits_the_section() {
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
            type_inference_coverage: CoverageInfo::default(),
            decompilation_cap_line: String::new(),
            disassembly_cap_line: String::new(),
            caller_edges_cap_line: String::new(),
        };

        let prompt = build_complexity_prompt(&FunctionComplexity::Detailed, &data)
            .expect("the detailed prompt should render");

        assert!(!prompt.contains("CONTROL FLOW PATTERNS"));
    }

    #[test]
    fn test_minimal_and_standard_templates_stay_clean_of_control_flow() {
        let data = ComplexityPromptData {
            type_inference_coverage: CoverageInfo::default(),
            decompilation_cap_line: String::new(),
            disassembly_cap_line: String::new(),
            caller_edges_cap_line: String::new(),
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

    fn type_info_pair() -> Vec<TypeInfo> {
        // The two readings of one pointer parameter's records render through
        // the typeinfer union's prompt conversion (issue #274): the type
        // reading and the direction reading. Both state the parameter's
        // name, so the pair lands side by side in one section (issue #276).
        vec![
            TypeInfo {
                name: "param_1".to_string(),
                description: "char * (via string_function, confidence 70)".to_string(),
            },
            TypeInfo {
                name: "param_1".to_string(),
                description: "out parameter (via param_direction, confidence 75)".to_string(),
            },
        ]
    }

    #[test]
    fn test_escalate_template_renders_direction_line_beside_the_type_line() {
        // An escalated attempt sees the direction beside the type: the
        // existing type-info section renders both lines, and no separate
        // directions section joins the prompt.
        let prompt = build_escalate_prompt_with_context(
            "FUN_1800412a0".to_string(),
            "eqmain.dll".to_string(),
            "fn fun_1800412a0(param_1: *mut i8) { /* ... */ }".to_string(),
            "Wrong result".to_string(),
            EvidenceBundle {
                type_info: type_info_pair(),
                ..Default::default()
            },
            Vec::new(),
        )
        .expect("the escalate prompt should render");

        assert!(prompt.contains("ADDITIONAL CONTEXT — TYPE INFORMATION"));
        assert!(prompt.contains("- `param_1`: char * (via string_function, confidence 70)"));
        assert!(prompt.contains("- `param_1`: out parameter (via param_direction, confidence 75)"));
        assert!(
            !prompt.contains("PARAMETER DIRECTION"),
            "directions go into the existing section, not a new one"
        );
    }

    #[test]
    fn test_rich_template_renders_type_info_section_with_direction_line() {
        let data = ComplexityPromptData {
            function_name: "FUN_1800412a0".to_string(),
            dll_name: "eqmain.dll".to_string(),
            address: 0x3000,
            disassembly: "mov eax, 0\nret".to_string(),
            decompiler_output: "undefined FUN_1800412a0(void) { }".to_string(),
            windows_apis: Vec::new(),
            test_cases: Vec::new(),
            api_category_mappings: Vec::new(),
            call_graph_neighbors: Vec::new(),
            neighboring_functions: Vec::new(),
            data_structures: Vec::new(),
            type_info: type_info_pair(),
            control_flow_findings: Vec::new(),
            type_inference_coverage: CoverageInfo::default(),
            decompilation_cap_line: String::new(),
            disassembly_cap_line: String::new(),
            caller_edges_cap_line: String::new(),
        };

        let prompt = build_complexity_prompt(&FunctionComplexity::Rich, &data)
            .expect("the rich prompt should render");

        assert!(prompt.contains("TYPE INFORMATION"));
        assert!(prompt.contains("- `param_1`: char * (via string_function, confidence 70)"));
        assert!(prompt.contains("- `param_1`: out parameter (via param_direction, confidence 75)"));
        assert!(
            !prompt.contains("PARAMETER DIRECTION"),
            "directions go into the existing section, not a new one"
        );
    }

    #[test]
    fn test_detailed_template_renders_type_info_section_with_direction_line() {
        let data = ComplexityPromptData {
            function_name: "FUN_1800412a0".to_string(),
            dll_name: "eqmain.dll".to_string(),
            address: 0x4000,
            disassembly: "mov eax, 0\nret".to_string(),
            decompiler_output: "undefined FUN_1800412a0(void) { }".to_string(),
            windows_apis: Vec::new(),
            test_cases: Vec::new(),
            api_category_mappings: Vec::new(),
            call_graph_neighbors: Vec::new(),
            neighboring_functions: Vec::new(),
            data_structures: Vec::new(),
            type_info: type_info_pair(),
            control_flow_findings: Vec::new(),
            type_inference_coverage: CoverageInfo::default(),
            decompilation_cap_line: String::new(),
            disassembly_cap_line: String::new(),
            caller_edges_cap_line: String::new(),
        };

        let prompt = build_complexity_prompt(&FunctionComplexity::Detailed, &data)
            .expect("the detailed prompt should render");

        assert!(prompt.contains("TYPE INFORMATION"));
        assert!(prompt.contains("- `param_1`: char * (via string_function, confidence 70)"));
        assert!(prompt.contains("- `param_1`: out parameter (via param_direction, confidence 75)"));
        assert!(
            !prompt.contains("PARAMETER DIRECTION"),
            "directions go into the existing section, not a new one"
        );
    }

    #[test]
    fn test_rich_and_detailed_templates_without_type_info_omit_the_section() {
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
            type_inference_coverage: CoverageInfo::default(),
            decompilation_cap_line: String::new(),
            disassembly_cap_line: String::new(),
            caller_edges_cap_line: String::new(),
        };

        for tier in [FunctionComplexity::Rich, FunctionComplexity::Detailed] {
            let prompt = build_complexity_prompt(&tier, &data).expect("the prompt should render");
            assert!(
                !prompt.contains("TYPE INFORMATION"),
                "a scan that read nothing leaves the tier's prompt as it was"
            );
        }
    }

    #[test]
    fn test_minimal_and_standard_templates_stay_clean_of_type_info() {
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
            type_info: type_info_pair(),
            control_flow_findings: Vec::new(),
            type_inference_coverage: CoverageInfo::default(),
            decompilation_cap_line: String::new(),
            disassembly_cap_line: String::new(),
            caller_edges_cap_line: String::new(),
        };

        for tier in [FunctionComplexity::Minimal, FunctionComplexity::Standard] {
            let prompt = build_complexity_prompt(&tier, &data).expect("the prompt should render");
            assert!(
                !prompt.contains("TYPE INFORMATION"),
                "the low tiers stay as sparse as they are today"
            );
        }
    }

    #[test]
    fn test_escalate_template_without_callback_findings_omits_the_section() {
        let prompt = build_escalate_prompt(
            "DrawSprite".to_string(),
            "game_logic.dll".to_string(),
            "fn draw_sprite(x: i32) -> i32 { x }".to_string(),
            "Wrong result".to_string(),
            EvidenceBundle::default(),
            Vec::new(),
        )
        .expect("the escalate prompt should render");

        assert!(!prompt.contains("CALLBACKS"));
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

    fn seh_finding() -> ErrhandlingInfo {
        ErrhandlingInfo {
            function: "FUN_1800014a0".to_string(),
            kind: "seh_frame".to_string(),
            target: "try/catch frame".to_string(),
            suggestion: "translate the frame as a Rust match arms ladder".to_string(),
            confidence: 100,
            evidence: "  catch(...) {".to_string(),
            code: None,
            site: None,
            partner: None,
        }
    }

    fn code_finding() -> ErrhandlingInfo {
        ErrhandlingInfo {
            function: "FUN_1800014a0".to_string(),
            kind: "error_code".to_string(),
            target: "failure code".to_string(),
            suggestion: "treat the constant as a failure code and name it in the error enum"
                .to_string(),
            confidence: 85,
            evidence: "  mov eax, 80070057h".to_string(),
            code: Some("0x80070057".to_string()),
            site: Some("return".to_string()),
            partner: None,
        }
    }

    #[test]
    fn test_module_context_template_renders_error_handling_section() {
        let req = sample_request();
        let prompt = build_module_context_prompt(
            &req,
            EvidenceBundle {
                error_handling_findings: vec![seh_finding(), code_finding()],
                ..Default::default()
            },
        )
        .expect("the prompt should render");

        assert!(prompt.contains("ERROR HANDLING"));
        // The idiom bullet states its suggestion, target, and band.
        assert!(prompt.contains("translate the frame as a Rust match arms ladder"));
        assert!(prompt.contains("try/catch frame"));
        assert!(prompt.contains("confidence 100"));
        assert!(prompt.contains("  catch(...) {"));
        // The failure code arrives spelled as the translator's hex
        // literal, and the line states the site it surfaced at.
        assert!(prompt.contains("failure code 0x80070057"));
        assert!(prompt.contains("from a `return` site"));
        assert!(prompt.contains("confidence 85"));
    }

    #[test]
    fn test_module_context_template_without_error_handling_findings_omits_the_section() {
        let req = sample_request();
        let prompt = build_module_context_prompt(&req, EvidenceBundle::default())
            .expect("the prompt should render");

        assert!(!prompt.contains("ERROR HANDLING"));
    }

    #[test]
    fn test_module_context_template_error_handling_codes_only_omits_the_mapping_guidance() {
        // Codes without idioms steer the error mapping but claim no frame
        // to translate.
        let req = sample_request();
        let prompt = build_module_context_prompt(
            &req,
            EvidenceBundle {
                error_handling_findings: vec![code_finding()],
                ..Default::default()
            },
        )
        .expect("the prompt should render");

        assert!(prompt.contains("ERROR HANDLING"));
        assert!(prompt.contains("failure code 0x80070057"));
        // Codes alone state no idiom to translate.
        assert!(!prompt.contains("frame idiom"));
        assert!(!prompt.contains("idiom,"));
    }

    #[test]
    fn test_module_context_template_error_handling_idioms_only_omit_the_code_line() {
        let req = sample_request();
        let prompt = build_module_context_prompt(
            &req,
            EvidenceBundle {
                error_handling_findings: vec![seh_finding()],
                ..Default::default()
            },
        )
        .expect("the prompt should render");

        assert!(prompt.contains("ERROR HANDLING"));
        assert!(prompt.contains("try/catch frame"));
        // An idiom without a code states no failure code.
        assert!(!prompt.contains("failure code 0x"));
    }

    #[test]
    fn test_module_context_template_error_handling_raise_idiom_names_the_code_it_raises() {
        let mut finding = seh_finding();
        finding.kind = "raise_exception".to_string();
        finding.target = "raised exception".to_string();
        finding.suggestion = "surface the raise as the matching Rust panic".to_string();
        finding.code = Some("0xe06d7363".to_string());
        let req = sample_request();
        let prompt = build_module_context_prompt(
            &req,
            EvidenceBundle {
                error_handling_findings: vec![finding],
                ..Default::default()
            },
        )
        .expect("the prompt should render");

        // The raise idiom bullet states the code it raises, inline.
        assert!(prompt.contains("raised exception idiom"));
        assert!(prompt.contains("raising code 0xe06d7363"));
    }

    #[test]
    fn test_module_context_template_error_handling_inherited_code_names_its_partner() {
        let mut finding = code_finding();
        finding.kind = "inherited_error_code".to_string();
        finding.target = "inherited failure code".to_string();
        finding.site = None;
        finding.partner = Some("FUN_1800412a0".to_string());
        let req = sample_request();
        let prompt = build_module_context_prompt(
            &req,
            EvidenceBundle {
                error_handling_findings: vec![finding],
                ..Default::default()
            },
        )
        .expect("the prompt should render");

        // The inherited-code bullet states the code and the partner that
        // passes it up.
        assert!(prompt.contains("inherited failure code"));
        assert!(prompt.contains("carried from `FUN_1800412a0`"));
        assert!(prompt.contains("failure code 0x80070057"));
    }

    #[test]
    fn test_escalate_template_with_error_handling_findings() {
        let prompt = build_escalate_prompt_with_context(
            "FUN_1800014a0".to_string(),
            "eqmain.dll".to_string(),
            "fn fun_1800014a0() { /* flattened guarded block */ }".to_string(),
            "Wrong result".to_string(),
            EvidenceBundle {
                error_handling_findings: vec![seh_finding(), code_finding()],
                ..Default::default()
            },
            Vec::new(),
        )
        .expect("the escalate prompt should render");

        assert!(prompt.contains("ADDITIONAL CONTEXT — ERROR HANDLING"));
        assert!(prompt.contains("try/catch frame"));
        assert!(prompt.contains("confidence 100"));
        assert!(prompt.contains("failure code 0x80070057"));
        assert!(prompt.contains("from a `return` site"));
    }

    #[test]
    fn test_escalate_template_without_error_handling_findings_omits_the_section() {
        let prompt = build_escalate_prompt(
            "FUN_1800014a0".to_string(),
            "eqmain.dll".to_string(),
            "fn fun_1800014a0() {} ".to_string(),
            "Wrong result".to_string(),
            EvidenceBundle::default(),
            Vec::new(),
        )
        .expect("the escalate prompt should render");

        assert!(!prompt.contains("ERROR HANDLING"));
    }

    // ============================================================
    // Shared section includes — parametrized section suite and
    // (template × section) include roster (issues #317, #318, #319)
    // ============================================================

    /// The verbatim steering paragraph of the shared global-state section,
    /// pinned byte-for-byte from the pre-include renders: the move into
    /// `templates/sections/global_state.j2` may not drift a character.
    const GLOBAL_STATE_STEERING: &str = "The program globals this function reads and writes, recorded by static\n\
        analysis. This function does not own this state — it shares it with the\n\
        rest of the binary. Give each global's storage a home in a struct the\n\
        translation threads through its units rather than in a Rust `static`, and\n\
        read or update it through that shared state instead of inventing a local\n\
        for it:";

    /// The global-state entry lines rendered from `global_state_fixture()`,
    /// verbatim.
    const GLOBAL_STATE_ENTRY: &str = "- **model the program global as shared struct state, not a Rust static** \
        (global_write of `DAT_180064e80`, confidence 85)\n  Evidence: `DAT_180064e80 = param_1`";

    /// The global-state section exactly as it must render: heading line,
    /// blank line, steering paragraph, blank line, entry lines.
    fn expected_global_state_section(heading: &str) -> String {
        format!("## {heading}\n\n{GLOBAL_STATE_STEERING}\n\n{GLOBAL_STATE_ENTRY}")
    }

    // Fixtures for the sections moved onto shared includes by #318. Each
    // fixture puts a single finding (or pair) into the matching bundle
    // list, so each section-suite run renders one section.

    fn algorithm_fixture() -> AlgorithmInfo {
        AlgorithmInfo {
            algorithm: "comparison_sort".to_string(),
            category: "sorting".to_string(),
            method: "cfg_pattern".to_string(),
            confidence: 70,
            evidence:
                "for (iVar1 = 0; iVar1 < count; iVar1++) { if (puVar2[iVar1] > puVar2[iVar1 + 1]) {"
                    .to_string(),
        }
    }

    fn memory_fixture() -> MemoryInfo {
        MemoryInfo {
            function: "FUN_18003ab00".to_string(),
            kind: "handle".to_string(),
            suggestion: "RAII guard struct with Drop impl".to_string(),
            confidence: 70,
            evidence: "hFile = CreateFileW(...); CloseHandle(hFile);".to_string(),
        }
    }

    fn concurrency_fixture() -> ConcurrencyInfo {
        ConcurrencyInfo {
            function: "FUN_18003ab00".to_string(),
            kind: "mutex".to_string(),
            suggestion: "std::sync::Mutex<T>".to_string(),
            confidence: 70,
            evidence: "pthread_mutex_lock(&mtx); ... pthread_mutex_unlock(&mtx);".to_string(),
        }
    }

    fn serialization_fixture() -> SerializationInfo {
        SerializationInfo {
            function: "FUN_18003ab00".to_string(),
            kind: "byteswap".to_string(),
            suggestion: "byteorder::BE::read_u32".to_string(),
            confidence: 70,
            evidence: "uVar1 = (uVar4 << 24) | ((uVar4 >> 8) & 0xff00);".to_string(),
        }
    }

    fn const_fixture() -> ConstInfo {
        ConstInfo {
            function: "FUN_18003ab00".to_string(),
            kind: "bitflag_group".to_string(),
            suggestion: "bitflags! struct Flags: u32".to_string(),
            confidence: 70,
            evidence: "if ((uVar1 & 0x10) != 0) { ... } uVar1 = uVar1 | 0x20;".to_string(),
        }
    }

    /// The type database passes two structures to the shared include. The
    /// pinned body therefore covers the blank line the include keeps
    /// between structures as well as each structure's size and fields.
    fn data_structures_fixtures() -> Vec<StructuredData> {
        vec![
            StructuredData {
                name: "Player".to_string(),
                size: 16,
                fields: vec![
                    StructField {
                        name: "hp".to_string(),
                        type_: "u32".to_string(),
                        offset: 0,
                    },
                    StructField {
                        name: "mp".to_string(),
                        type_: "u16".to_string(),
                        offset: 4,
                    },
                ],
            },
            StructuredData {
                name: "SaveGame".to_string(),
                size: 8,
                fields: vec![StructField {
                    name: "slot".to_string(),
                    type_: "u32".to_string(),
                    offset: 0,
                }],
            },
        ]
    }

    fn callback_fixture() -> CallbackInfo {
        CallbackInfo {
            function: "FUN_18003ab00".to_string(),
            kind: "fp_array".to_string(),
            suggestion: "Vec<Box<dyn Fn(i32)>>".to_string(),
            confidence: 70,
            evidence: "handlers[uVar2](iVar3);".to_string(),
        }
    }

    fn string_fixture() -> StringContextInfo {
        StringContextInfo {
            function: "FUN_18003ab00".to_string(),
            kind: "file_path".to_string(),
            suggestion: "config file path".to_string(),
            confidence: 70,
            evidence: "lFile = CreateFileA(\"Journal.txt\",...);".to_string(),
        }
    }

    fn api_fixture() -> ApiInfo {
        ApiInfo {
            function: String::new(),
            api: "inflate".to_string(),
            library: "zlib".to_string(),
            suggestion: "flate2".to_string(),
            kind: "import".to_string(),
            confidence: 90,
            evidence: "inflate".to_string(),
        }
    }

    /// Renders the escalate template against an arbitrary bundle. All the
    /// escalate call sites of the shared includes live in this one
    /// template, so one render helper drives every escalate row.
    fn render_escalate_full(bundle: &EvidenceBundle) -> String {
        build_escalate_prompt(
            "FUN_18003ab00".to_string(),
            "eqmain.dll".to_string(),
            "fn fun_18003ab00(param_1: i32) { /* DAT store */ }".to_string(),
            "Wrong result".to_string(),
            bundle.clone(),
            Vec::new(),
        )
        .expect("the escalate prompt should render")
    }

    /// Renders the module-context template against an arbitrary bundle.
    fn render_module_context_full(bundle: &EvidenceBundle) -> String {
        let req = sample_request();
        build_module_context_prompt(&req, bundle.clone())
            .expect("the module-context prompt should render")
    }

    /// Renders the full-module template against an arbitrary bundle.
    fn render_full_module_full(bundle: &EvidenceBundle) -> String {
        let req = sample_request();
        build_full_module_prompt(&req, bundle.clone(), Vec::new(), Vec::new())
            .expect("the full-module prompt should render")
    }

    /// Renders the rich template against an arbitrary bundle. The tier
    /// templates render from the finding lists that come with their
    /// request, not from a gathered bundle, so this helper copies the
    /// include-fed lists out of the bundle and into the tier's prompt
    /// data (#319).
    fn render_rich_full(bundle: &EvidenceBundle) -> String {
        let req = sample_request();
        let mut data = ComplexityPromptData::from_request(&req);
        data.type_info = bundle.type_info.clone();
        data.control_flow_findings = bundle.control_flow_findings.clone();
        data.type_inference_coverage = bundle.type_inference_coverage.clone();
        data.decompilation_cap_line = bundle.decompilation_cap_line.clone();
        data.disassembly_cap_line = bundle.disassembly_cap_line.clone();
        data.caller_edges_cap_line = bundle.caller_edges_cap_line.clone();
        build_complexity_prompt(&FunctionComplexity::Rich, &data)
            .expect("the rich prompt should render")
    }

    /// Renders the detailed template against an arbitrary bundle, fed the
    /// same way as the rich one.
    fn render_detailed_full(bundle: &EvidenceBundle) -> String {
        let req = sample_request();
        let mut data = ComplexityPromptData::from_request(&req);
        data.type_info = bundle.type_info.clone();
        data.control_flow_findings = bundle.control_flow_findings.clone();
        data.type_inference_coverage = bundle.type_inference_coverage.clone();
        data.decompilation_cap_line = bundle.decompilation_cap_line.clone();
        data.disassembly_cap_line = bundle.disassembly_cap_line.clone();
        data.caller_edges_cap_line = bundle.caller_edges_cap_line.clone();
        build_complexity_prompt(&FunctionComplexity::Detailed, &data)
            .expect("the detailed prompt should render")
    }

    /// #320: with a wholly empty bundle the escalate template shows no
    /// evidence section at all. Every one of those headings starts with
    /// the `## ADDITIONAL CONTEXT — ` prefix — and no stray blank line
    /// is left where the sections used to be.
    #[test]
    fn empty_bundle_escalate_omits_every_evidence_section() {
        let prompt = render_escalate_full(&EvidenceBundle::default());
        assert!(!prompt.contains("## ADDITIONAL CONTEXT"));
        assert!(!prompt.contains("## OPEN UNKNOWNS"));
        assert!(prompt.contains("## TRANSLATION REQUIREMENTS"));
        assert!(!prompt.contains("\n\n\n"));
    }

    /// #320: the same empty-bundle contract for the module-context
    /// template: every heading fed by the bundle is absent, the sections
    /// fed by the request still render, and the blank lines between them
    /// stay clean.
    #[test]
    fn empty_bundle_module_context_omits_every_evidence_section() {
        let prompt = render_module_context_full(&EvidenceBundle::default());
        for heading in [
            "## CALL GRAPH NEIGHBORS",
            "## CALL GRAPH CONTEXT",
            "## NEIGHBORING FUNCTION CONTEXT",
            "## SHARED DATA STRUCTURES",
            "## CONTROL FLOW PATTERNS",
            "## CALLING CONVENTION",
            "## GLOBAL STATE",
            "## FLOAT/SIMD",
            "## KNOWN LIBRARY FUNCTIONS",
            "## PARAMETER DIRECTIONS",
            "## DATA TABLES",
            "## ERROR HANDLING",
            "## OPEN UNKNOWNS",
        ] {
            assert!(
                !prompt.contains(heading),
                "the module-context prompt rendered {heading} with an empty bundle"
            );
        }
        assert!(prompt.contains("## TRANSLATION REQUIREMENTS"));
        assert!(prompt.contains("## BASELINE TESTS"));
        assert!(!prompt.contains("\n\n\n"));
    }

    /// #320: the full-module template's five bundle-fed sections all
    /// disappear with an empty bundle while its tier-fixed sections remain.
    #[test]
    fn empty_bundle_full_module_omits_every_evidence_section() {
        let prompt = render_full_module_full(&EvidenceBundle::default());
        for heading in [
            "## CALL GRAPH NEIGHBORS",
            "## CALL GRAPH CONTEXT",
            "## NEIGHBORING FUNCTION CONTEXT",
            "## SHARED DATA STRUCTURES",
            "## CONTROL FLOW PATTERNS",
            "## OPEN UNKNOWNS",
        ] {
            assert!(
                !prompt.contains(heading),
                "the full-module prompt rendered {heading} with an empty bundle"
            );
        }
        assert!(prompt.contains("## TRANSLATION REQUIREMENTS"));
        assert!(prompt.contains("## BASELINE TESTS"));
        assert!(!prompt.contains("\n\n\n"));
    }

    /// The full body of the type information section — steering paragraph
    /// and entries — pinned byte-for-byte from the pre-include renders.
    /// Shared by its consuming templates: escalate, rich, and detailed.
    /// Before the tier bodies merged onto this one include, they were
    /// checked against the escalate body for identity. The section suite
    /// re-renders each consuming template against it.
    const TYPE_INFORMATION_SECTION_BODY: &str = "The following types were inferred by Ghidra's type database:\n\n- `param_1`: char * (via string_function, confidence 70)\n\n- `param_1`: out parameter (via param_direction, confidence 75)";

    fn expected_type_information_section(heading: &str) -> String {
        format!("## {heading}\n\n{TYPE_INFORMATION_SECTION_BODY}")
    }

    /// The full body of the recognized algorithms section — steering
    /// paragraph and entries — pinned byte-for-byte from the pre-include
    /// renders. Its only consumer is the escalate template. The section
    /// suite re-renders each consuming template against it.
    const RECOGNIZED_ALGORITHMS_SECTION_BODY: &str = "The following known algorithms were recognized in this function by static\nanalysis. Where a recognition is credible, implement the known algorithm\nidiomatically in Rust instead of transliterating the pseudo-C line by line:\n\n- **comparison_sort** (sorting; via cfg_pattern, confidence 70)\n  Evidence: `for (iVar1 = 0; iVar1 &#60; count; iVar1++) { if (puVar2[iVar1] &#62; puVar2[iVar1 + 1]) {`";

    fn expected_recognized_algorithms_section(heading: &str) -> String {
        format!("## {heading}\n\n{RECOGNIZED_ALGORITHMS_SECTION_BODY}")
    }

    /// The full body of the memory lifecycle section — steering
    /// paragraph and entries — pinned byte-for-byte from the pre-include
    /// renders. Its only consumer is the escalate template. The section
    /// suite re-renders each consuming template against it.
    const MEMORY_LIFECYCLE_SECTION_BODY: &str = "The following memory lifecycles were recognized in this function by static\nanalysis. Where a finding is credible, express the resource with the suggested\nRust ownership pattern instead of transliterating the manual allocate/free or\nopen/close pairs:\n\n- **RAII guard struct with Drop impl** (handle lifecycle, confidence 70)\n  Evidence: `hFile = CreateFileW(...); CloseHandle(hFile);`";

    fn expected_memory_lifecycle_section(heading: &str) -> String {
        format!("## {heading}\n\n{MEMORY_LIFECYCLE_SECTION_BODY}")
    }

    /// The full body of the concurrency section — steering paragraph and
    /// entries — pinned byte-for-byte from the pre-include renders. Its
    /// only consumer is the escalate template. The section suite
    /// re-renders each consuming template against it.
    const CONCURRENCY_SECTION_BODY: &str = "The following concurrency constructs were recognized in this function by static\nanalysis. Where a finding is credible, express the synchronization with the\nsuggested Rust type instead of transliterating the manual lock/unlock or\nspawn/join calls:\n\n- **std::sync::Mutex<T>** (mutex construct, confidence 70)\n  Evidence: `pthread_mutex_lock(&mtx); ... pthread_mutex_unlock(&mtx);`";

    fn expected_concurrency_section(heading: &str) -> String {
        format!("## {heading}\n\n{CONCURRENCY_SECTION_BODY}")
    }

    /// The full body of the serialization section — steering paragraph
    /// and entries — pinned byte-for-byte from the pre-include renders.
    /// Its only consumer is the escalate template. The section suite
    /// re-renders each consuming template against it.
    const SERIALIZATION_SECTION_BODY: &str = "The following endianness and serialization patterns were recognized in this\nfunction by static analysis — byte-swap calls, hand-rolled bit-packing chains,\nand file-format signature comparisons. Where a finding is credible, express\nthe format with the suggested Rust type or crate instead of transliterating\nthe manual swaps, shifts, and masks:\n\n- **byteorder::BE::read_u32** (byteswap pattern, confidence 70)\n  Evidence: `uVar1 = (uVar4 << 24) | ((uVar4 >> 8) & 0xff00);`";

    fn expected_serialization_section(heading: &str) -> String {
        format!("## {heading}\n\n{SERIALIZATION_SECTION_BODY}")
    }

    /// The full body of the constants section — steering paragraph and
    /// entries — pinned byte-for-byte from the pre-include renders. Its
    /// only consumer is the escalate template. The section suite
    /// re-renders each consuming template against it.
    const CONSTANTS_SECTION_BODY: &str = "The following constant structures were recognized in this function by static\nanalysis — flag-bit groups, enumerated dispatch runs, and values repeated\nacross the program. Where a finding is credible, express it with the suggested\nRust shape instead of scattering the bare integer literals:\n\n- **bitflags! struct Flags: u32** (bitflag_group, confidence 70)\n  Evidence: `if ((uVar1 & 0x10) != 0) { ... } uVar1 = uVar1 | 0x20;`";

    fn expected_constants_section(heading: &str) -> String {
        format!("## {heading}\n\n{CONSTANTS_SECTION_BODY}")
    }

    /// The full body of the callbacks section — steering paragraph and
    /// entries — pinned byte-for-byte from the pre-include renders. Its
    /// only consumer is the escalate template. The section suite
    /// re-renders each consuming template against it.
    const CALLBACKS_SECTION_BODY: &str = "The following callback and function-pointer patterns were recognized in this\nfunction by static analysis. Where a finding is credible, express the callback\nboundary with the suggested Rust pattern instead of transliterating the raw\ntable indexing or registration call:\n\n- **Vec<Box<dyn Fn(i32)>>** (fp_array pattern, confidence 70)\n  Evidence: `handlers[uVar2](iVar3);`";

    fn expected_callbacks_section(heading: &str) -> String {
        format!("## {heading}\n\n{CALLBACKS_SECTION_BODY}")
    }

    /// The full body of the control flow section — steering paragraph and
    /// entries — pinned byte-for-byte from the pre-include renders. Shared
    /// by its consuming templates: escalate, full-module, rich, and
    /// detailed. Before merging, the tier bodies were identical to the
    /// escalate body. The section suite re-renders each consuming template
    /// against it.
    const CONTROL_FLOW_SECTION_BODY: &str = "The following control-flow patterns were recognized in this function by static\nanalysis. Where a finding is credible, express the construct with the suggested\nRust pattern instead of transliterating the raw conditional chain or recursive\ncall:\n\n- **enum State + match state { /* 3 states */ }** (state_machine construct, confidence 70)\n  Evidence: `state variable state with 3 states idle: STATE_IDLE`";

    fn expected_control_flow_section(heading: &str) -> String {
        format!("## {heading}\n\n{CONTROL_FLOW_SECTION_BODY}")
    }

    /// The full body of the control flow branch section — steering
    /// paragraph and entries — pinned byte-for-byte from the pre-include
    /// renders. Its consumer is module-context, driven by
    /// `branch_site_fixture`. The section suite re-renders each consuming
    /// template against it.
    const CONTROL_FLOW_BRANCH_SECTION_BODY: &str = "The following control-flow patterns were recognized in this function by static\nanalysis. Where a finding is credible, express the construct with the suggested\nRust pattern instead of transliterating the raw conditional chain or recursive\ncall:\n\n- **keep the early return behind param_1 == 0** (branch_site construct, confidence 80)\n  Evidence: `if (param_1 == 0) {`";

    fn expected_control_flow_branch_section(heading: &str) -> String {
        format!("## {heading}\n\n{CONTROL_FLOW_BRANCH_SECTION_BODY}")
    }

    /// The full body of the calling convention section — steering
    /// paragraph and entries — pinned byte-for-byte from the pre-include
    /// renders. Shared by its consuming templates: escalate and
    /// module-context. The section suite re-renders each consuming
    /// template against it.
    const CALLING_CONVENTION_SECTION_BODY: &str = "The calling conventions detected for this function and its callees by\nstatic analysis — mangled-name letters, `@N` import decorations, callee\nepilogues, caller stack cleanup, and the x64 call shape. Spell extern\ndeclarations and any stack cleanup with the detected convention instead\nof assuming `__stdcall`, and do not invent stack cleanup for a convention\nthat leaves none:\n\n- **stdcall** (via callee_epilogue, confidence 80)\n  Evidence: `00401007  RET 0xC`";

    fn expected_calling_convention_section(heading: &str) -> String {
        format!("## {heading}\n\n{CALLING_CONVENTION_SECTION_BODY}")
    }

    /// The full body of the floatsimd section — steering paragraph and
    /// entries — pinned byte-for-byte from the pre-include renders.
    /// Shared by its consuming templates: escalate and module-context.
    /// The section suite re-renders each consuming template against it.
    const FLOATSIMD_SECTION_BODY: &str = "This function's body carries float/SIMD evidence, recorded by static\nanalysis — the decompiler mangles vector math into concatenations,\nextractions, and undefined-typed arithmetic, and reading it as integer\nor pointer logic mistranslates it. Translate the math as float: for a\nscalar shape use plain `f32`/`f64` operations; for a vector/matrix\nshape use component arrays or small vector structs, never packed\nintegers:\n\n- **translate as a small vector struct or component array, not integer or pointer arithmetic** (vector_matrix shape, confidence 60)\n  Evidence: `local_10 = CONCAT44(uVar2 >> 4, uVar2 & 0xfffffff);`";

    fn expected_floatsimd_section(heading: &str) -> String {
        format!("## {heading}\n\n{FLOATSIMD_SECTION_BODY}")
    }

    /// The full body of the string context section — steering paragraph
    /// and entries — pinned byte-for-byte from the pre-include renders.
    /// Its only consumer is the escalate template. The section suite
    /// re-renders each consuming template against it.
    const STRING_CONTEXT_SECTION_BODY: &str = "The following strings were mapped to this function by static analysis —\nclassified into their role, and for format-string calls the Rust argument\ntypes the specifiers imply. Where a finding is credible, name the string's\nrole in the translation instead of transliterating the raw literal or\n`DAT_` reference:\n\n- **config file path** (file_path string, confidence 70)\n  Evidence: `lFile = CreateFileA(\"Journal.txt\",...);`";

    fn expected_string_context_section(heading: &str) -> String {
        format!("## {heading}\n\n{STRING_CONTEXT_SECTION_BODY}")
    }

    /// The full body of the libraries apis section — steering paragraph
    /// and entries — pinned byte-for-byte from the pre-include renders.
    /// Its only consumer is the escalate template. The section suite
    /// re-renders each consuming template against it.
    const LIBRARIES_APIS_SECTION_BODY: &str = "The following library APIs were identified by static analysis — from the\nbinary's import table and from the call paths reaching them out of this\nfunction. Where a finding is credible, call the API through the suggested\nRust crate instead of transliterating the raw import or declaring it as an\n`extern \"C\"` stub:\n\n- **flate2** for `inflate` (zlib import, confidence 90)\n  Evidence: `inflate`";

    fn expected_libraries_apis_section(heading: &str) -> String {
        format!("## {heading}\n\n{LIBRARIES_APIS_SECTION_BODY}")
    }

    /// The full body of the libmatch section — steering paragraph and
    /// entries — pinned byte-for-byte from the pre-include renders. Its
    /// only consumer is the module-context template. The section suite
    /// re-renders each consuming template against it.
    const LIBMATCH_SECTION_BODY: &str = "The functions this one calls that static analysis has identified as\nstatically linked known-library code — the C runtime or the C++ standard\nlibrary. Do NOT re-implement these bodies: map each call onto the\nsuggested Rust equivalent instead:\n\n- **slice copy / std::ptr::copy_nonoverlapping** — `FUN_18003ab00` matches `memcpy` (crt library, confidence 90)\n  Evidence: `  *(undefined8 *)((long)puVar1 + -8) = *(undefined8 *)((long)lVar2 + -8);`";

    fn expected_libmatch_section(heading: &str) -> String {
        format!("## {heading}\n\n{LIBMATCH_SECTION_BODY}")
    }

    /// The full body of the parameter direction section — steering
    /// paragraph and entries — pinned byte-for-byte from the pre-include
    /// renders. Its only consumer is the module-context template. The
    /// section suite re-renders each consuming template against it.
    const PARAMETER_DIRECTION_SECTION_BODY: &str = "Which way data flows through this function's pointer parameters, read from\nits body by static analysis. Give each parameter the Rust shape its\ndirection names — an `in` parameter a shared borrow, an `out` parameter a\nmutable borrow or a value handed back to the caller, an `inout` parameter\na read-modify-write through a mutable borrow — and add no mutability a\ndirection reading does not claim:\n\n- **param_2 is out** (via param_direction, confidence 75)\n  Evidence: `*param_2 = 0;`";

    fn expected_parameter_direction_section(heading: &str) -> String {
        format!("## {heading}\n\n{PARAMETER_DIRECTION_SECTION_BODY}")
    }

    /// The full body of the data tables section — steering paragraph and
    /// entries — pinned byte-for-byte from the pre-include renders. Its
    /// only consumer is the module-context template. The section suite
    /// re-renders each consuming template against it.
    const DATA_TABLES_SECTION_BODY: &str = "The defined data objects this function indexes that static analysis has\nrecognized as constant data tables — objects whose bytes decode coherently\nat one element width and that nothing in the program writes. Where a\nfinding is credible, render each lookup of one of these objects as a named\n`const` array of the element type and entry count shown, indexed where the\noriginal offsets the object — do not re-scatter the decoded entries as\nmatch arms or magic numbers:\n\n- **DAT_1400a1b60**: `const [u16; 12]` (confidence 70)";

    fn expected_data_tables_section(heading: &str) -> String {
        format!("## {heading}\n\n{DATA_TABLES_SECTION_BODY}")
    }

    /// The full body of the data-structure section — steering paragraph
    /// and entries — pinned byte-for-byte from the pre-include renders.
    /// Shared by its three consuming templates: escalate, module-context,
    /// and full-module. The section suite re-renders each consuming
    /// template against it. The fixture holds two structures, so the pin
    /// covers the blank line the include keeps between them as well as
    /// each structure's size and field lines.
    const DATA_STRUCTURES_SECTION_BODY: &str = "The following data structures are used in or near this function:\n\n### Player\nSize: 16 bytes\nFields:\n\n- `hp` : u32 (offset: 0)\n\n- `mp` : u16 (offset: 4)\n\n### SaveGame\nSize: 8 bytes\nFields:\n\n- `slot` : u32 (offset: 0)";

    fn expected_data_structures_section(heading: &str) -> String {
        format!("## {heading}\n\n{DATA_STRUCTURES_SECTION_BODY}")
    }

    /// The full body of the open-unknowns section — steering paragraph,
    /// entry lines, and the fold — pinned byte-for-byte (issue #370).
    /// Shared by its three consuming templates: escalate, module-context,
    /// and full-module. The fixture holds two open records, so the pin
    /// covers the two-line entry shape — the question line and its
    /// required-evidence line — as well as the paragraph above them.
    const OPEN_UNKNOWNS_SECTION_BODY: &str = "The analysis filed these open questions about this function: facts it could\nnot establish from what it read, each beside the evidence that would settle\nit. They are admitted gaps, not tasks — treat them as limits on what is\nestablished about this function, and never fill one in with invention.\n\n- What does the second parameter point at?\n  Required evidence: a decompiler re-run with the pointer type pinned\n\n- Does the body share a lock with FUN_18003cd00?\n  Required evidence: a cross-reference sweep of the global at 0x180140a30";

    fn expected_open_unknowns_section(heading: &str) -> String {
        format!("## {heading}\n\n{OPEN_UNKNOWNS_SECTION_BODY}")
    }

    /// The open-unknowns fixture pair — two records in ledger order, the
    /// wording each carries being one bounded line of its own.
    fn open_unknowns_fixtures() -> Vec<UnknownInfo> {
        vec![
            UnknownInfo {
                question: "What does the second parameter point at?".to_string(),
                required_evidence: "a decompiler re-run with the pointer type pinned".to_string(),
            },
            UnknownInfo {
                question: "Does the body share a lock with FUN_18003cd00?".to_string(),
                required_evidence: "a cross-reference sweep of the global at 0x180140a30"
                    .to_string(),
            },
        ]
    }

    /// One (section × consuming template) pair of the parametrized
    /// section suite (issues #317, #318, #319). A new engine that includes a
    /// shared section registers one row here and is covered by both
    /// halves of the suite test and by the include roster automatically.
    struct SectionRow {
        /// The shared section include, template-dir relative.
        section: &'static str,
        /// The consuming engine template, template-dir relative.
        template: &'static str,
        /// The heading text the template passes to the include.
        heading: &'static str,
        /// Injects this section's findings into an otherwise-empty bundle.
        populate: fn(&mut EvidenceBundle),
        /// Renders the consuming template against the populated bundle.
        render: fn(&EvidenceBundle) -> String,
        /// The verbatim rendered section, given the heading.
        expected: fn(heading: &str) -> String,
    }

    static SECTION_SUITE_ROWS: &[SectionRow] = &[
        SectionRow {
            section: "sections/global_state.j2",
            template: "escalate.j2",
            heading: "ADDITIONAL CONTEXT — GLOBAL STATE",
            populate: |b| b.global_state_findings.push(global_state_fixture()),
            render: render_escalate_full,
            expected: expected_global_state_section,
        },
        SectionRow {
            section: "sections/type_information.j2",
            template: "escalate.j2",
            heading: "ADDITIONAL CONTEXT — TYPE INFORMATION",
            populate: |b| b.type_info.extend(type_info_pair()),
            render: render_escalate_full,
            expected: expected_type_information_section,
        },
        SectionRow {
            section: "sections/recognized_algorithms.j2",
            template: "escalate.j2",
            heading: "ADDITIONAL CONTEXT — RECOGNIZED ALGORITHMS",
            populate: |b| b.recognized_algorithms.push(algorithm_fixture()),
            render: render_escalate_full,
            expected: expected_recognized_algorithms_section,
        },
        SectionRow {
            section: "sections/memory_lifecycle.j2",
            template: "escalate.j2",
            heading: "ADDITIONAL CONTEXT — MEMORY LIFECYCLE",
            populate: |b| b.memory_findings.push(memory_fixture()),
            render: render_escalate_full,
            expected: expected_memory_lifecycle_section,
        },
        SectionRow {
            section: "sections/concurrency.j2",
            template: "escalate.j2",
            heading: "ADDITIONAL CONTEXT — CONCURRENCY",
            populate: |b| b.concurrency_findings.push(concurrency_fixture()),
            render: render_escalate_full,
            expected: expected_concurrency_section,
        },
        SectionRow {
            section: "sections/serialization.j2",
            template: "escalate.j2",
            heading: "ADDITIONAL CONTEXT — SERIALIZATION",
            populate: |b| b.serialization_findings.push(serialization_fixture()),
            render: render_escalate_full,
            expected: expected_serialization_section,
        },
        SectionRow {
            section: "sections/constants.j2",
            template: "escalate.j2",
            heading: "ADDITIONAL CONTEXT — CONSTANTS",
            populate: |b| b.const_findings.push(const_fixture()),
            render: render_escalate_full,
            expected: expected_constants_section,
        },
        SectionRow {
            section: "sections/data_structures.j2",
            template: "escalate.j2",
            heading: "ADDITIONAL CONTEXT — DATA STRUCTURES",
            populate: |b| b.data_structures.extend(data_structures_fixtures()),
            render: render_escalate_full,
            expected: expected_data_structures_section,
        },
        SectionRow {
            section: "sections/callbacks.j2",
            template: "escalate.j2",
            heading: "ADDITIONAL CONTEXT — CALLBACKS",
            populate: |b| b.callback_findings.push(callback_fixture()),
            render: render_escalate_full,
            expected: expected_callbacks_section,
        },
        SectionRow {
            section: "sections/control_flow.j2",
            template: "escalate.j2",
            heading: "ADDITIONAL CONTEXT — CONTROL FLOW",
            populate: |b| b.control_flow_findings.push(control_flow_fixture()),
            render: render_escalate_full,
            expected: expected_control_flow_section,
        },
        SectionRow {
            section: "sections/calling_convention.j2",
            template: "escalate.j2",
            heading: "ADDITIONAL CONTEXT — CALLING CONVENTION",
            populate: |b| b.convention_findings.push(convention_fixture()),
            render: render_escalate_full,
            expected: expected_calling_convention_section,
        },
        SectionRow {
            section: "sections/floatsimd.j2",
            template: "escalate.j2",
            heading: "ADDITIONAL CONTEXT — FLOAT/SIMD",
            populate: |b| b.floatsimd_findings.push(floatsimd_fixture()),
            render: render_escalate_full,
            expected: expected_floatsimd_section,
        },
        SectionRow {
            section: "sections/string_context.j2",
            template: "escalate.j2",
            heading: "ADDITIONAL CONTEXT — STRINGS",
            populate: |b| b.string_findings.push(string_fixture()),
            render: render_escalate_full,
            expected: expected_string_context_section,
        },
        SectionRow {
            section: "sections/libraries_apis.j2",
            template: "escalate.j2",
            heading: "ADDITIONAL CONTEXT — LIBRARIES AND APIS",
            populate: |b| b.api_findings.push(api_fixture()),
            render: render_escalate_full,
            expected: expected_libraries_apis_section,
        },
        SectionRow {
            section: "sections/global_state.j2",
            template: "module_context_translate.j2",
            heading: "GLOBAL STATE",
            populate: |b| b.global_state_findings.push(global_state_fixture()),
            render: render_module_context_full,
            expected: expected_global_state_section,
        },
        SectionRow {
            section: "sections/control_flow.j2",
            template: "module_context_translate.j2",
            heading: "CONTROL FLOW PATTERNS",
            populate: |b| b.control_flow_findings.push(branch_site_fixture()),
            render: render_module_context_full,
            expected: expected_control_flow_branch_section,
        },
        SectionRow {
            section: "sections/calling_convention.j2",
            template: "module_context_translate.j2",
            heading: "CALLING CONVENTION",
            populate: |b| b.convention_findings.push(convention_fixture()),
            render: render_module_context_full,
            expected: expected_calling_convention_section,
        },
        SectionRow {
            section: "sections/floatsimd.j2",
            template: "module_context_translate.j2",
            heading: "FLOAT/SIMD",
            populate: |b| b.floatsimd_findings.push(floatsimd_fixture()),
            render: render_module_context_full,
            expected: expected_floatsimd_section,
        },
        SectionRow {
            section: "sections/libmatch.j2",
            template: "module_context_translate.j2",
            heading: "KNOWN LIBRARY FUNCTIONS",
            populate: |b| b.libmatch_findings.push(libmatch_fixture()),
            render: render_module_context_full,
            expected: expected_libmatch_section,
        },
        SectionRow {
            section: "sections/parameter_direction.j2",
            template: "module_context_translate.j2",
            heading: "PARAMETER DIRECTIONS",
            populate: |b| {
                b.parameter_direction_findings
                    .push(parameter_direction_fixture())
            },
            render: render_module_context_full,
            expected: expected_parameter_direction_section,
        },
        SectionRow {
            section: "sections/data_tables.j2",
            template: "module_context_translate.j2",
            heading: "DATA TABLES",
            populate: |b| b.data_table_findings.push(data_table_fixture()),
            render: render_module_context_full,
            expected: expected_data_tables_section,
        },
        SectionRow {
            section: "sections/data_structures.j2",
            template: "module_context_translate.j2",
            heading: "SHARED DATA STRUCTURES",
            populate: |b| b.data_structures.extend(data_structures_fixtures()),
            render: render_module_context_full,
            expected: expected_data_structures_section,
        },
        SectionRow {
            section: "sections/control_flow.j2",
            template: "full_module_translate.j2",
            heading: "CONTROL FLOW PATTERNS",
            populate: |b| b.control_flow_findings.push(control_flow_fixture()),
            render: render_full_module_full,
            expected: expected_control_flow_section,
        },
        SectionRow {
            section: "sections/data_structures.j2",
            template: "full_module_translate.j2",
            heading: "SHARED DATA STRUCTURES",
            populate: |b| b.data_structures.extend(data_structures_fixtures()),
            render: render_full_module_full,
            expected: expected_data_structures_section,
        },
        SectionRow {
            section: "sections/type_information.j2",
            template: "rich_translate.j2",
            heading: "TYPE INFORMATION",
            populate: |b| b.type_info.extend(type_info_pair()),
            render: render_rich_full,
            expected: expected_type_information_section,
        },
        SectionRow {
            section: "sections/control_flow.j2",
            template: "rich_translate.j2",
            heading: "CONTROL FLOW PATTERNS",
            populate: |b| b.control_flow_findings.push(control_flow_fixture()),
            render: render_rich_full,
            expected: expected_control_flow_section,
        },
        SectionRow {
            section: "sections/type_information.j2",
            template: "detailed_translate.j2",
            heading: "TYPE INFORMATION",
            populate: |b| b.type_info.extend(type_info_pair()),
            render: render_detailed_full,
            expected: expected_type_information_section,
        },
        SectionRow {
            section: "sections/control_flow.j2",
            template: "detailed_translate.j2",
            heading: "CONTROL FLOW PATTERNS",
            populate: |b| b.control_flow_findings.push(control_flow_fixture()),
            render: render_detailed_full,
            expected: expected_control_flow_section,
        },
        SectionRow {
            section: "sections/open_unknowns.j2",
            template: "escalate.j2",
            heading: "OPEN UNKNOWNS",
            populate: |b| b.open_unknowns.extend(open_unknowns_fixtures()),
            render: render_escalate_full,
            expected: expected_open_unknowns_section,
        },
        SectionRow {
            section: "sections/open_unknowns.j2",
            template: "module_context_translate.j2",
            heading: "OPEN UNKNOWNS",
            populate: |b| b.open_unknowns.extend(open_unknowns_fixtures()),
            render: render_module_context_full,
            expected: expected_open_unknowns_section,
        },
        SectionRow {
            section: "sections/open_unknowns.j2",
            template: "full_module_translate.j2",
            heading: "OPEN UNKNOWNS",
            populate: |b| b.open_unknowns.extend(open_unknowns_fixtures()),
            render: render_full_module_full,
            expected: expected_open_unknowns_section,
        },
    ];

    /// The parametrized section suite: every row's populated findings must
    /// render its heading and entries verbatim, and an empty findings list
    /// must omit the section without leaving stray blank lines between the
    /// sections that remain.
    #[test]
    fn the_section_suite_renders_populated_findings_and_omits_empty_ones() {
        for row in SECTION_SUITE_ROWS {
            let mut bundle = EvidenceBundle::default();
            (row.populate)(&mut bundle);
            // A scan that read everything it attempted admits nothing, so
            // every row renders the section exactly as it did before any
            // coverage record existed — the suite pins that identity.
            bundle.algorithm_coverage = CoverageInfo::from(&complete_coverage());
            bundle.string_context_coverage = CoverageInfo::from(&complete_coverage());
            bundle.type_inference_coverage = CoverageInfo::from(&complete_coverage());
            bundle.serialization_coverage = CoverageInfo::from(&complete_coverage());

            let populated = (row.render)(&bundle);
            let expected = (row.expected)(row.heading);
            assert!(
                populated.contains(&format!("\n\n{expected}\n\n")),
                "{} renders the {} section verbatim under '{}'",
                row.template,
                row.section,
                row.heading
            );
            assert!(
                !populated.contains("\n\n\n"),
                "{} leaves no stray blank lines with populated {}",
                row.template,
                row.section
            );

            let empty = (row.render)(&EvidenceBundle::default());
            assert!(
                !empty.contains(&format!("## {}", row.heading)),
                "{} omits the {} section for an empty findings list",
                row.template,
                row.section
            );
            assert!(
                !empty.contains("\n\n\n"),
                "{} leaves no stray blank lines at the omitted {}",
                row.template,
                row.section
            );
        }
    }

    /// A scan coverage record in the shape an apidetect scan files: a
    /// complete import table beside an unexamined delay-imports facet.
    fn api_admitting_coverage() -> calxgloss_types::ScanCoverage {
        calxgloss_types::ScanCoverage {
            status: calxgloss_types::CoverageStatus::Partial,
            facets: vec![
                calxgloss_types::FacetCoverage {
                    id: "import-table".to_string(),
                    status: calxgloss_types::CoverageStatus::Complete,
                    limitation: None,
                },
                calxgloss_types::FacetCoverage {
                    id: "delay-imports".to_string(),
                    status: calxgloss_types::CoverageStatus::Unexamined,
                    limitation: Some("delay imports unexamined".to_string()),
                },
            ],
        }
    }

    /// A scan that read every facet it attempted, filed under the named
    /// engine. Each producing scan has one row in the section-suite
    /// table.
    fn complete_coverage() -> calxgloss_types::ScanCoverage {
        calxgloss_types::ScanCoverage {
            status: calxgloss_types::CoverageStatus::Complete,
            facets: vec![
                calxgloss_types::FacetCoverage {
                    id: "function-bodies".to_string(),
                    status: calxgloss_types::CoverageStatus::Complete,
                    limitation: None,
                },
                calxgloss_types::FacetCoverage {
                    id: "caller-edges".to_string(),
                    status: calxgloss_types::CoverageStatus::Complete,
                    limitation: None,
                },
                calxgloss_types::FacetCoverage {
                    id: "program-strings".to_string(),
                    status: calxgloss_types::CoverageStatus::Complete,
                    limitation: None,
                },
                calxgloss_types::FacetCoverage {
                    id: "string-xrefs".to_string(),
                    status: calxgloss_types::CoverageStatus::Complete,
                    limitation: None,
                },
                calxgloss_types::FacetCoverage {
                    id: "machine-listings".to_string(),
                    status: calxgloss_types::CoverageStatus::Complete,
                    limitation: None,
                },
                calxgloss_types::FacetCoverage {
                    id: "import-names".to_string(),
                    status: calxgloss_types::CoverageStatus::Complete,
                    limitation: None,
                },
            ],
        }
    }

    /// The one qualification wording the section suite pins (issue #346).
    const API_ADMISSION: &str = "partial — delay imports unexamined";

    /// The heading the escalate template passes the libraries-apis include.
    const LIBRARIES_APIS_HEADING: &str = "ADDITIONAL CONTEXT — LIBRARIES AND APIS";

    /// The pinned wording is checked at both ends: the shared coverage
    /// type produces it from an apidetect-shaped record, and the rendered
    /// prompt shows that same line verbatim.
    #[test]
    fn the_api_admission_wording_is_pinned_at_both_ends_of_its_journey() {
        assert_eq!(
            api_admitting_coverage()
                .admission()
                .expect("partial admits"),
            API_ADMISSION,
            "the shared type's own admission is the pinned line"
        );
        assert_eq!(
            CoverageInfo::from(&api_admitting_coverage()).admission,
            API_ADMISSION,
            "the template-side view carries the same line, word for word"
        );
    }

    /// A complete coverage record is nothing to admit: the section renders
    /// byte-for-byte what it rendered when the document stated no coverage
    /// at all (issue #346).
    #[test]
    fn a_complete_api_coverage_record_renders_the_section_byte_identically() {
        let mut bundle = EvidenceBundle::default();
        bundle.api_findings.push(api_fixture());
        let unstamped = render_escalate_full(&bundle);
        bundle.api_coverage = CoverageInfo::from(&calxgloss_types::ScanCoverage {
            status: calxgloss_types::CoverageStatus::Complete,
            facets: Vec::new(),
        });
        let stamped_complete = render_escalate_full(&bundle);
        assert_eq!(
            unstamped, stamped_complete,
            "a complete record adds no bytes to the prompt"
        );
        assert!(
            !stamped_complete.contains("Coverage:"),
            "complete coverage has nothing to admit"
        );
    }

    /// A falling-short record appends exactly one bounded qualification
    /// line, pinned byte-for-byte as the line the include renders after
    /// the entries (issue #346).
    #[test]
    fn a_partial_api_coverage_record_appends_exactly_one_qualification_line() {
        let mut bundle = EvidenceBundle::default();
        bundle.api_findings.push(api_fixture());
        let clean = render_escalate_full(&bundle);
        bundle.api_coverage = CoverageInfo::from(&api_admitting_coverage());
        let admitted = render_escalate_full(&bundle);
        assert_eq!(
            admitted,
            clean.replace(
                &format!("{LIBRARIES_APIS_SECTION_BODY}\n\n"),
                &format!("{LIBRARIES_APIS_SECTION_BODY}\n\nCoverage: {API_ADMISSION}\n\n"),
            ),
            "the admission appears in the section as exactly one line beside the entries"
        );
        assert_eq!(
            admitted
                .matches(&format!("## {LIBRARIES_APIS_HEADING}"))
                .count(),
            1,
            "the admission never opens a second section"
        );
    }

    /// The doctrine pair (issue #346): findings silence under complete
    /// coverage and under a falling-short record must never render alike —
    /// an empty list from a scan that admits falling short still says
    /// something, while silence from a complete scan says nothing.
    #[test]
    fn empty_api_findings_under_complete_and_partial_coverage_never_render_alike() {
        let under_complete = render_escalate_full(&EvidenceBundle::default());
        assert!(
            !under_complete.contains(&format!("## {LIBRARIES_APIS_HEADING}")),
            "silence from an unstamped record stays section-less, as before P19"
        );
        let under_partial = render_escalate_full(&EvidenceBundle {
            api_coverage: CoverageInfo::from(&api_admitting_coverage()),
            ..Default::default()
        });
        assert_ne!(
            under_complete, under_partial,
            "empty findings under a falling-short record must render observably \
             different bytes than the same emptiness under a complete one"
        );
        assert!(
            under_partial.contains(&format!(
                "## {LIBRARIES_APIS_HEADING}\n\nCoverage: {API_ADMISSION}\n\n"
            )),
            "the empty list still carries the one admission line"
        );
    }

    // ---- #355: the seam's own capability admission ----------------------

    /// A reason line no other family in this repo invents. If a seam
    /// admission ever appears outside the imported-APIs section, in
    /// another family's section, this string appears with it and the
    /// pinned test fails.
    const SEAM_UNREACHED: &str = "Zanthoxylum";

    /// The one admission wording the section suite pins for the seam's
    /// `imports` family (issue #355).
    fn seam_imports_unavailable() -> calxgloss_types::FamilyCapability {
        calxgloss_types::FamilyCapability {
            id: "imports".to_string(),
            status: calxgloss_types::AvailabilityStatus::Unavailable,
            reason: Some(format!(
                "{SEAM_UNREACHED} sessions never load the import table"
            )),
        }
    }

    const SEAM_IMPORTS_ADMISSION: &str =
        "unavailable — Zanthoxylum sessions never load the import table";

    /// The seam's answerable declaration for the same family — nothing to
    /// admit, the shape Kuna files today.
    fn seam_imports_answerable() -> calxgloss_types::FamilyCapability {
        calxgloss_types::FamilyCapability {
            id: "imports".to_string(),
            status: calxgloss_types::AvailabilityStatus::Answerable,
            reason: None,
        }
    }

    /// The pinned wording is checked at both ends (issue #355): the shared
    /// capability type produces the admission line from its own entry, and
    /// the rendered prompt shows that same line verbatim — one set of words,
    /// from the engine's declaration to the rendered line.
    #[test]
    fn the_seam_admission_wording_is_pinned_at_both_ends_of_its_journey() {
        assert_eq!(
            seam_imports_unavailable()
                .admission()
                .expect("unavailable admits"),
            SEAM_IMPORTS_ADMISSION,
            "the shared type's own admission is the pinned line"
        );
        assert_eq!(
            CapabilityInfo::from(&seam_imports_unavailable()).admission,
            SEAM_IMPORTS_ADMISSION,
            "the template-side view carries the same line, word for word"
        );
        let report = calxgloss_types::CapabilityReport {
            families: vec![seam_imports_unavailable()],
        };
        assert_eq!(
            capability_for(&report, "imports").admission,
            SEAM_IMPORTS_ADMISSION,
            "folding the held report for one family yields the same line"
        );
    }

    /// A declared-unavailable family appends exactly one bounded admission
    /// line beside the entries, pinned byte-for-byte (issue #355). The
    /// unreached family's name occurs exactly once in the whole prompt: if
    /// it appears in another family's section, this test fails.
    #[test]
    fn a_seam_unavailable_admission_appends_exactly_one_line_beside_entries() {
        let mut bundle = EvidenceBundle::default();
        bundle.api_findings.push(api_fixture());
        let clean = render_escalate_full(&bundle);
        bundle.api_capability = CapabilityInfo::from(&seam_imports_unavailable());
        let admitted = render_escalate_full(&bundle);
        assert_eq!(
            admitted,
            clean.replace(
                &format!("{LIBRARIES_APIS_SECTION_BODY}\n\n"),
                &format!(
                    "{LIBRARIES_APIS_SECTION_BODY}\n\nAnalysis engine: {SEAM_IMPORTS_ADMISSION}\n\n"
                ),
            ),
            "the seam admission appears in the section as exactly one line beside the entries"
        );
        assert_eq!(
            admitted
                .matches(&format!("## {LIBRARIES_APIS_HEADING}"))
                .count(),
            1,
            "the admission never opens a second section"
        );
        assert_eq!(
            admitted.matches(SEAM_UNREACHED).count(),
            1,
            "the unreached family's name appears exactly once — never inside \
             another family's section, never anywhere else in the prompt"
        );
    }

    /// When the surface filed nothing, the admission line still says its
    /// one thing: the section opens with its heading and the line, and
    /// never a bare silence (issue #355).
    #[test]
    fn a_seam_admission_on_an_otherwise_empty_surface_opens_heading_and_line() {
        let rendered = render_escalate_full(&EvidenceBundle {
            api_capability: CapabilityInfo::from(&seam_imports_unavailable()),
            ..Default::default()
        });
        assert!(
            rendered.contains(&format!(
                "## {LIBRARIES_APIS_HEADING}\n\nAnalysis engine: {SEAM_IMPORTS_ADMISSION}\n\n"
            )),
            "an empty filed surface under an unavailable seam still admits itself"
        );
        assert_eq!(
            rendered.matches(SEAM_UNREACHED).count(),
            1,
            "one line, one name, one home"
        );
    }

    /// The doctrine pair (issue #355): findings silence under an answerable
    /// declaration and under an unavailable one must never share bytes —
    /// an empty surface from a seam that admits the family is unreachable
    /// says something, while silence from a seam that can answer says
    /// nothing.
    #[test]
    fn empty_api_surface_under_answerable_and_unavailable_seams_never_render_alike() {
        let under_answerable = render_escalate_full(&EvidenceBundle {
            api_capability: CapabilityInfo::from(&seam_imports_answerable()),
            ..Default::default()
        });
        assert_eq!(
            under_answerable,
            render_escalate_full(&EvidenceBundle::default()),
            "an answerable family admits nothing, on an empty surface as anywhere"
        );
        let under_unavailable = render_escalate_full(&EvidenceBundle {
            api_capability: CapabilityInfo::from(&seam_imports_unavailable()),
            ..Default::default()
        });
        assert_ne!(
            under_answerable, under_unavailable,
            "an empty surface under an unavailable seam must render observably \
             different bytes than the same emptiness under an answerable one"
        );
    }

    /// Answerable and unknown (the report declaring nothing about the
    /// family) render byte-identically to today — the empty-bundle pin
    /// included (issue #355).
    #[test]
    fn answerable_and_undeclared_seam_families_render_byte_identically_to_silence() {
        let untouched = render_escalate_full(&EvidenceBundle::default());
        let mut bundle = EvidenceBundle::default();
        bundle.api_findings.push(api_fixture());
        let rich_clean = render_escalate_full(&bundle);

        bundle.api_capability = CapabilityInfo::from(&seam_imports_answerable());
        assert_eq!(
            render_escalate_full(&bundle),
            rich_clean,
            "the seam saying 'answerable' adds no bytes anywhere"
        );

        let undeclared = calxgloss_types::CapabilityReport::default();
        bundle.api_capability = capability_for(&undeclared, "imports");
        assert_eq!(
            bundle.api_capability,
            CapabilityInfo::default(),
            "an undeclared family folds to the empty view — silence, not absence"
        );
        assert_eq!(
            render_escalate_full(&bundle),
            rich_clean,
            "an undeclared family adds no bytes anywhere"
        );
        assert_eq!(
            render_escalate_full(&EvidenceBundle {
                api_capability: capability_for(&undeclared, "imports"),
                ..Default::default()
            }),
            untouched,
            "the empty bundle is byte-identical under an all-silent report"
        );
    }

    /// The seam admission and the scan's own coverage admission are two
    /// different admissions: one the document's, one the live engine's.
    /// When both fall short, each keeps exactly its own line, in order,
    /// and the two never merge (issue #355).
    #[test]
    fn the_scan_admission_and_the_seam_admission_keep_their_own_lines() {
        let mut bundle = EvidenceBundle::default();
        bundle.api_findings.push(api_fixture());
        bundle.api_coverage = CoverageInfo::from(&api_admitting_coverage());
        bundle.api_capability = CapabilityInfo::from(&seam_imports_unavailable());
        let admitted = render_escalate_full(&bundle);
        assert!(
            admitted.contains(&format!(
                "{LIBRARIES_APIS_SECTION_BODY}\n\nCoverage: {API_ADMISSION}\n\n\
                 Analysis engine: {SEAM_IMPORTS_ADMISSION}\n\n"
            )),
            "both admissions appear, each as its own line, scan first"
        );
        assert_eq!(
            admitted
                .matches(&format!("## {LIBRARIES_APIS_HEADING}"))
                .count(),
            1,
            "two admits, still one section"
        );
    }

    /// The doctrine pair, byte-level (issue #359). The scan coverage
    /// doctrine (P19, what a filed scan examined) and the seam capability
    /// doctrine (P20, what the open session can answer) are two different
    /// admissions, and their shared wording may collide on purpose: a
    /// coverage admission and a capability admission CAN be byte-identical
    /// as raw data. So the proof sits at both ends of each admission: each
    /// keeps its own frame and the two lines never merge. The `Tanglewood`
    /// sentinel is coined here and belongs to neither doctrine's fixtures.
    #[test]
    fn a_coverage_admission_and_a_capability_admission_worded_alike_never_share_bytes_at_either_end()
     {
        const SENTINEL: &str = "Tanglewood bridge offline";

        // The collision, built on purpose: the same status word and the
        // same sentence make the two doctrines' raw admission strings
        // byte-identical at the data level. That is exactly why each
        // admission needs its own frame.
        let coverage = calxgloss_types::ScanCoverage {
            status: calxgloss_types::CoverageStatus::Unavailable,
            facets: vec![calxgloss_types::FacetCoverage {
                id: "import-table".to_string(),
                status: calxgloss_types::CoverageStatus::Unavailable,
                limitation: Some(SENTINEL.to_string()),
            }],
        };
        let capability = calxgloss_types::FamilyCapability {
            id: "imports".to_string(),
            status: calxgloss_types::AvailabilityStatus::Unavailable,
            reason: Some(SENTINEL.to_string()),
        };
        assert_eq!(
            coverage.admission().as_deref(),
            capability.admission().as_deref(),
            "raw, the two admissions DO collide — the pin proves the \
             frames separate them, not that the words differ"
        );

        // The prompt end: each colliding admission appears inside its
        // own frame — `Coverage:` for the scan record, `Analysis engine:`
        // for the seam. Each framed line appears exactly once, and the
        // shared sentence exactly twice, once per line. A merge or a lost
        // line would drop a frame or count the sentence only once.
        let mut bundle = EvidenceBundle::default();
        bundle.api_findings.push(api_fixture());
        bundle.api_coverage = CoverageInfo::from(&coverage);
        bundle.api_capability = CapabilityInfo::from(&capability);
        let admitted = render_escalate_full(&bundle);
        assert_eq!(
            admitted.matches(&format!("Coverage: {SENTINEL}")).count(),
            0,
            "the coverage line carries the shared status word ahead of the sentence, as always"
        );
        assert!(
            admitted.contains(&format!(
                "Coverage: unavailable — {SENTINEL}\n\nAnalysis engine: unavailable — {SENTINEL}"
            )),
            "the two admissions render as two framed lines, scan first, \
             each byte-identical to its own doctrine's wording"
        );
        assert_eq!(
            admitted.matches("Coverage: unavailable — ").count(),
            1,
            "the coverage frame opens exactly one line"
        );
        assert_eq!(
            admitted.matches("Analysis engine: unavailable — ").count(),
            1,
            "the seam frame opens exactly one line"
        );
        assert_eq!(
            admitted.matches(SENTINEL).count(),
            2,
            "the shared sentence stands exactly twice — once per frame, never merged"
        );
    }

    // ---- #357: the capability fan-out to every prompt-fed family ---------

    /// One unreached reason name per fed family. All are plant names and
    /// all are distinct, including from the names the other tracks coined
    /// (`Zanthoxylum` for imports here, `Quincunx` and `Ginkgo` in the
    /// translator). If a reason's name appears in a section its family
    /// feeds nothing to, one of the absence assertions below fails.
    fn set_decompilation_cap(b: &mut EvidenceBundle, line: &str) {
        b.decompilation_cap_line = line.to_string();
    }
    fn set_disassembly_cap(b: &mut EvidenceBundle, line: &str) {
        b.disassembly_cap_line = line.to_string();
    }
    fn set_strings_cap(b: &mut EvidenceBundle, line: &str) {
        b.strings_cap_line = line.to_string();
    }
    fn set_caller_edges_cap(b: &mut EvidenceBundle, line: &str) {
        b.caller_edges_cap_line = line.to_string();
    }
    fn set_xrefs_cap(b: &mut EvidenceBundle, line: &str) {
        b.xrefs_cap_line = line.to_string();
    }
    fn set_type_database_cap(b: &mut EvidenceBundle, line: &str) {
        b.type_database_cap_line = line.to_string();
    }
    fn set_data_items_cap(b: &mut EvidenceBundle, line: &str) {
        b.data_items_cap_line = line.to_string();
    }

    /// One fed family's whole fan-out: its roster id, its unreached
    /// reason, the bundle field the fan-out writes, and the headings of
    /// every section its facets feed, per host template — in host order
    /// escalate, module-context, full-module, rich, detailed. This table
    /// IS the facet-lineage record on the prompt side: it is where the
    /// family→section matching is reviewable as data.
    struct FanoutRow {
        family: &'static str,
        reason: &'static str,
        set: fn(&mut EvidenceBundle, &str),
        fed: [&'static [&'static str]; 5],
    }

    const ESCALATE: usize = 0;
    const MODULE: usize = 1;
    const FULL: usize = 2;
    const HOST_LABELS: [&str; 5] = [
        "escalate",
        "module-context",
        "full-module",
        "rich",
        "detailed",
    ];

    const FANOUT_ROWS: &[FanoutRow] = &[
        FanoutRow {
            family: "decompilation",
            reason: "Cascara sessions never produce a body",
            set: set_decompilation_cap,
            fed: [
                &[
                    "ADDITIONAL CONTEXT — DATA STRUCTURES",
                    "ADDITIONAL CONTEXT — TYPE INFORMATION",
                    "ADDITIONAL CONTEXT — RECOGNIZED ALGORITHMS",
                    "ADDITIONAL CONTEXT — MEMORY LIFECYCLE",
                    "ADDITIONAL CONTEXT — CONCURRENCY",
                    "ADDITIONAL CONTEXT — SERIALIZATION",
                    "ADDITIONAL CONTEXT — CONSTANTS",
                    "ADDITIONAL CONTEXT — CALLBACKS",
                    "ADDITIONAL CONTEXT — CONTROL FLOW",
                    "ADDITIONAL CONTEXT — CALLING CONVENTION",
                    "ADDITIONAL CONTEXT — GLOBAL STATE",
                    "ADDITIONAL CONTEXT — FLOAT/SIMD",
                    "ADDITIONAL CONTEXT — STRINGS",
                    "ADDITIONAL CONTEXT — ERROR HANDLING",
                ],
                &[
                    "SHARED DATA STRUCTURES",
                    "CONTROL FLOW PATTERNS",
                    "CALLING CONVENTION",
                    "GLOBAL STATE",
                    "FLOAT/SIMD",
                    "KNOWN LIBRARY FUNCTIONS",
                    "PARAMETER DIRECTIONS",
                    "DATA TABLES",
                    "ERROR HANDLING",
                ],
                &["SHARED DATA STRUCTURES", "CONTROL FLOW PATTERNS"],
                &["TYPE INFORMATION", "CONTROL FLOW PATTERNS"],
                &["TYPE INFORMATION", "CONTROL FLOW PATTERNS"],
            ],
        },
        FanoutRow {
            family: "disassembly",
            reason: "Yarrow listings never surface an opcode",
            set: set_disassembly_cap,
            fed: [
                &[
                    "ADDITIONAL CONTEXT — TYPE INFORMATION",
                    "ADDITIONAL CONTEXT — CALLING CONVENTION",
                ],
                &["CALLING CONVENTION", "PARAMETER DIRECTIONS"],
                &[],
                &["TYPE INFORMATION"],
                &["TYPE INFORMATION"],
            ],
        },
        FanoutRow {
            family: "strings",
            reason: "Juniper builds carry no string data",
            set: set_strings_cap,
            fed: [&["ADDITIONAL CONTEXT — STRINGS"], &[], &[], &[], &[]],
        },
        FanoutRow {
            family: "caller-edges",
            reason: "Kelp walks never follow a call edge",
            set: set_caller_edges_cap,
            fed: [
                &[
                    "ADDITIONAL CONTEXT — CALL GRAPH NEIGHBORS",
                    "ADDITIONAL CONTEXT — CALL GRAPH ANALYSIS",
                    "ADDITIONAL CONTEXT — NEIGHBORING FUNCTIONS",
                    "ADDITIONAL CONTEXT — TYPE INFORMATION",
                    "ADDITIONAL CONTEXT — RECOGNIZED ALGORITHMS",
                    "ADDITIONAL CONTEXT — CALLING CONVENTION",
                ],
                &[
                    "CALL GRAPH NEIGHBORS",
                    "CALL GRAPH CONTEXT",
                    "NEIGHBORING FUNCTION CONTEXT",
                    "CALLING CONVENTION",
                    "PARAMETER DIRECTIONS",
                ],
                &[
                    "CALL GRAPH NEIGHBORS",
                    "CALL GRAPH CONTEXT",
                    "NEIGHBORING FUNCTION CONTEXT",
                ],
                &["TYPE INFORMATION"],
                &["TYPE INFORMATION"],
            ],
        },
        FanoutRow {
            family: "xrefs",
            reason: "Lovage sessions leave xrefs dark",
            set: set_xrefs_cap,
            fed: [&["ADDITIONAL CONTEXT — STRINGS"], &[], &[], &[], &[]],
        },
        FanoutRow {
            family: "type-database",
            reason: "Mallow sessions open no type database",
            set: set_type_database_cap,
            fed: [
                &["ADDITIONAL CONTEXT — DATA STRUCTURES"],
                &["SHARED DATA STRUCTURES"],
                &["SHARED DATA STRUCTURES"],
                &[],
                &[],
            ],
        },
        FanoutRow {
            family: "data-items",
            reason: "Nettle bins hold no data objects",
            set: set_data_items_cap,
            fed: [
                &[
                    "ADDITIONAL CONTEXT — DATA STRUCTURES",
                    "ADDITIONAL CONTEXT — CONSTANTS",
                ],
                &["SHARED DATA STRUCTURES", "DATA TABLES"],
                &["SHARED DATA STRUCTURES"],
                &[],
                &[],
            ],
        },
    ];

    /// The fan-out at the prompt surface. Every fed family's admission
    /// appears in exactly the sections its facets feed, as exactly one
    /// `Analysis engine:` line per fed section — heading plus line where
    /// the surface filed nothing — on all five host templates. No other
    /// family's name ever appears in a section the family feeds nothing
    /// of, and a family that feeds a host nothing leaves that host's
    /// bytes untouched. This pins issue #357's counting, crossing, and
    /// doctrine criteria at once.
    #[test]
    fn every_fed_familys_admission_rides_exactly_its_own_sections() {
        let renderers: [fn(&EvidenceBundle) -> String; 5] = [
            render_escalate_full,
            render_module_context_full,
            render_full_module_full,
            render_rich_full,
            render_detailed_full,
        ];
        for row in FANOUT_ROWS {
            let admission = format!("unavailable — {}", row.reason);
            let line = format!("Analysis engine: {admission}");
            for (host, render) in renderers.iter().enumerate() {
                let mut bundle = EvidenceBundle::default();
                (row.set)(&mut bundle, &admission);
                let admitted = render(&bundle);
                assert_eq!(
                    admitted.matches(&line).count(),
                    row.fed[host].len(),
                    "{} must render exactly one admission line per section it feeds on \
                     the {} host",
                    row.family,
                    HOST_LABELS[host],
                );
                for heading in row.fed[host] {
                    assert!(
                        admitted.contains(&format!("## {heading}\n\n{line}\n\n")),
                        "{family}'s admission must appear as heading-plus-line when {host}'s \
                         {heading} section filed nothing",
                        family = row.family,
                        host = HOST_LABELS[host],
                        heading = heading,
                    );
                }
                for other in FANOUT_ROWS {
                    if other.family != row.family {
                        assert!(
                            !admitted.contains(other.reason),
                            "the {}-only fixture must never quote {}'s name — a value \
                             crossing into another family's fan-out fails here",
                            row.family,
                            other.family,
                        );
                    }
                }
                let clean = render(&EvidenceBundle::default());
                if row.fed[host].is_empty() {
                    assert_eq!(
                        clean, admitted,
                        "{} feeds the {} host nothing, so its field alone must not \
                         move a byte there",
                        row.family, HOST_LABELS[host],
                    );
                } else {
                    assert_ne!(
                        clean, admitted,
                        "the {} host's empty sections under an answerable seam and under \
                         {}'s unavailable one must never share bytes",
                        HOST_LABELS[host], row.family,
                    );
                }
            }
        }
    }

    /// One prompt, every fed family unavailable at once. Each family
    /// still owns exactly its own line count. A section fed by several
    /// families shows every one of their lines under the one heading
    /// it opens — in roster order, beside the entries when entries
    /// exist — and each family's wording stays in its own lines
    /// (issue #357).
    #[test]
    fn all_families_unavailable_at_once_still_speak_one_line_per_section() {
        let line_of = |reason: &str| format!("Analysis engine: unavailable — {reason}");
        let mut bundle = EvidenceBundle::default();
        for row in FANOUT_ROWS {
            (row.set)(&mut bundle, &format!("unavailable — {}", row.reason));
        }

        let escalate = render_escalate_full(&bundle);
        for row in FANOUT_ROWS {
            let line = line_of(row.reason);
            assert_eq!(
                escalate.matches(&line).count(),
                row.fed[ESCALATE].len(),
                "{}'s line count in the all-unavailable escalate render",
                row.family,
            );
        }
        assert_eq!(
            escalate
                .matches("## ADDITIONAL CONTEXT — DATA STRUCTURES")
                .count(),
            1,
            "three unavailable families, still one heading for the section they share",
        );
        assert!(
            escalate.contains(&format!(
                "## ADDITIONAL CONTEXT — DATA STRUCTURES\n\n{}\n\n{}\n\n{}\n\n",
                line_of("Cascara sessions never produce a body"),
                line_of("Mallow sessions open no type database"),
                line_of("Nettle bins hold no data objects"),
            )),
            "the shared section's lines appear in roster order, with no other family's words between",
        );
        assert!(
            escalate.contains(&format!(
                "## ADDITIONAL CONTEXT — STRINGS\n\n{}\n\n{}\n\n{}\n\n",
                line_of("Cascara sessions never produce a body"),
                line_of("Juniper builds carry no string data"),
                line_of("Lovage sessions leave xrefs dark"),
            )),
            "the string section's three families admit in order under the one heading",
        );

        let module = render_module_context_full(&bundle);
        for row in FANOUT_ROWS {
            let line = line_of(row.reason);
            assert_eq!(
                module.matches(&line).count(),
                row.fed[MODULE].len(),
                "{}'s line count in the all-unavailable module-context render",
                row.family,
            );
        }
        assert!(
            module.contains(&format!(
                "## PARAMETER DIRECTIONS\n\n{}\n\n{}\n\n{}\n\n",
                line_of("Cascara sessions never produce a body"),
                line_of("Yarrow listings never surface an opcode"),
                line_of("Kelp walks never follow a call edge"),
            )),
            "the parameter-direction section admits its three families in order",
        );

        let full = render_full_module_full(&bundle);
        let rich = render_rich_full(&bundle);
        let detailed = render_detailed_full(&bundle);
        for (host, rendered) in [(FULL, &full), (3, &rich), (4, &detailed)] {
            for row in FANOUT_ROWS {
                let line = line_of(row.reason);
                assert_eq!(
                    rendered.matches(&line).count(),
                    row.fed[host].len(),
                    "{}'s line count in the all-unavailable {} render",
                    row.family,
                    HOST_LABELS[host],
                );
            }
        }
        assert!(
            rich.contains(&format!(
                "## TYPE INFORMATION\n\n{}\n\n{}\n\n{}\n\n",
                line_of("Cascara sessions never produce a body"),
                line_of("Yarrow listings never surface an opcode"),
                line_of("Kelp walks never follow a call edge"),
            )),
            "the tier templates' shared type-information section admits all three in order",
        );
    }

    /// Beside populated entries the admission lines still appear — one
    /// per fed family, after the entries — and the very next section's
    /// heading opens cleanly beneath them (issue #357, the
    /// beside-the-entries half of the #355 shape fanned out).
    #[test]
    fn fanout_admissions_ride_beside_entries_and_leave_the_next_heading_clean() {
        let mut bundle = EvidenceBundle::default();
        bundle.data_structures.extend(data_structures_fixtures());
        for row in FANOUT_ROWS {
            (row.set)(&mut bundle, &format!("unavailable — {}", row.reason));
        }
        let escalate = render_escalate_full(&bundle);
        assert!(escalate.contains(&format!(
            "Analysis engine: unavailable — {}\n\n\
             Analysis engine: unavailable — {}\n\n\
             Analysis engine: unavailable — {}\n\n\
             ## ADDITIONAL CONTEXT — TYPE INFORMATION\n\n\
             Analysis engine: unavailable — {}",
            "Cascara sessions never produce a body",
            "Mallow sessions open no type database",
            "Nettle bins hold no data objects",
            "Cascara sessions never produce a body",
        )));
        assert!(
            !escalate.contains("\n\n\n"),
            "entries, three admits, next section — still no stray blank line at the seam",
        );
    }

    /// Both silence-shapes across the whole fan-out: with every family
    /// answerable, and with every family undeclared, the fields are empty
    /// either way. Every host then renders byte-for-byte what it rendered
    /// before the seam admission existed — the all-answerable fixture
    /// identity the criteria demand at every consumer (issue #357).
    #[test]
    fn answerable_and_undeclared_families_render_byte_identically_to_silence() {
        let answerable = calxgloss_types::CapabilityReport {
            families: FANOUT_ROWS
                .iter()
                .map(|row| calxgloss_types::FamilyCapability {
                    id: row.family.to_string(),
                    status: calxgloss_types::AvailabilityStatus::Answerable,
                    reason: None,
                })
                .collect(),
        };
        let undeclared = calxgloss_types::CapabilityReport::default();
        let renderers: [fn(&EvidenceBundle) -> String; 5] = [
            render_escalate_full,
            render_module_context_full,
            render_full_module_full,
            render_rich_full,
            render_detailed_full,
        ];
        for (label, report) in [("answerable", &answerable), ("undeclared", &undeclared)] {
            let mut bundle = EvidenceBundle::default();
            for row in FANOUT_ROWS {
                (row.set)(&mut bundle, &capability_for(report, row.family).admission);
            }
            for (host, render) in renderers.iter().enumerate() {
                assert_eq!(
                    render(&bundle),
                    render(&EvidenceBundle::default()),
                    "the {} host must render byte-identically under an all-{} report",
                    HOST_LABELS[host],
                    label,
                );
            }
        }
    }

    /// The families that feed no prompt surface go no further than the
    /// seam declaration: `function-inventory`, `exports`, `image-base`,
    /// and `memory-reads` gain no bundle field, no include parameter, and
    /// no template reference anywhere in this crate. The pins scan the
    /// very sources the renderer compiles from (issue #357).
    #[test]
    fn families_that_feed_no_prompt_surface_grow_no_field_and_no_parameter() {
        let manifest = env!("CARGO_MANIFEST_DIR");
        let mut sources: Vec<String> = vec![
            std::fs::read_to_string(format!("{manifest}/src/templates.rs")).expect("templates.rs"),
            std::fs::read_to_string(format!("{manifest}/src/context.rs")).expect("context.rs"),
            std::fs::read_to_string(format!("{manifest}/src/build.rs")).expect("build.rs"),
        ];
        let mut pending = vec![format!("{manifest}/templates")];
        while let Some(dir) = pending.pop() {
            for entry in std::fs::read_dir(&dir).expect("template dir") {
                let path = entry.expect("template entry").path();
                if path.is_dir() {
                    pending.push(path.display().to_string());
                } else if path.extension().is_some_and(|e| e == "j2") {
                    sources.push(
                        std::fs::read_to_string(&path)
                            .unwrap_or_else(|e| panic!("{} readable: {e}", path.display())),
                    );
                }
            }
        }
        for ghost in [
            "function_inventory_cap",
            "exports_cap",
            "image_base_cap",
            "memory_reads_cap",
        ] {
            for source in &sources {
                assert!(
                    !source.contains(ghost),
                    "a declaration-only family grew a parameter named {ghost} — \
                     the roster line must stay drawn at the seam",
                );
            }
        }
        // The fed families, by contrast, each own exactly one field name
        // on this side: seven on the bundle, and the tier trio.
        let bundle_src = &sources[0];
        for field in [
            "decompilation_cap_line",
            "disassembly_cap_line",
            "strings_cap_line",
            "caller_edges_cap_line",
            "xrefs_cap_line",
            "type_database_cap_line",
            "data_items_cap_line",
        ] {
            assert!(
                bundle_src.contains(&format!("pub {field}: String,")),
                "the fed family field {field} must exist on the bundle",
            );
        }
    }

    /// A scan coverage record in the shape a libmatch scan files (issue
    /// #347): its one `function-bodies` facet fell short, naming the two
    /// bodies the decompiler never produced.
    fn libmatch_admitting_coverage() -> calxgloss_types::ScanCoverage {
        calxgloss_types::ScanCoverage {
            status: calxgloss_types::CoverageStatus::Partial,
            facets: vec![calxgloss_types::FacetCoverage {
                id: "function-bodies".to_string(),
                status: calxgloss_types::CoverageStatus::Partial,
                limitation: Some(
                    "2 function bodies unreached: FUN_180099000, FUN_180099100".to_string(),
                ),
            }],
        }
    }

    /// The one qualification wording the section suite pins for the
    /// known-library section (issue #347).
    const LIBMATCH_ADMISSION: &str =
        "partial — 2 function bodies unreached: FUN_180099000, FUN_180099100";

    /// The heading the module-context template passes the libmatch include.
    const KNOWN_LIBRARY_HEADING: &str = "KNOWN LIBRARY FUNCTIONS";

    /// The pinned wording is checked at both ends: the shared coverage
    /// type produces it from a libmatch-shaped record, and the rendered
    /// prompt shows that same line verbatim.
    #[test]
    fn the_libmatch_admission_wording_is_pinned_at_both_ends_of_its_journey() {
        assert_eq!(
            libmatch_admitting_coverage()
                .admission()
                .expect("partial admits"),
            LIBMATCH_ADMISSION,
            "the shared type's own admission is the pinned line"
        );
        assert_eq!(
            CoverageInfo::from(&libmatch_admitting_coverage()).admission,
            LIBMATCH_ADMISSION,
            "the template-side view carries the same line, word for word"
        );
    }

    /// A complete coverage record is nothing to admit: the known-library
    /// section renders byte-for-byte what it rendered when the document
    /// stated no coverage at all (issue #347).
    #[test]
    fn a_complete_libmatch_coverage_record_renders_the_section_byte_identically() {
        let mut bundle = EvidenceBundle::default();
        bundle.libmatch_findings.push(libmatch_fixture());
        let unstamped = render_module_context_full(&bundle);
        bundle.libmatch_coverage = CoverageInfo::from(&calxgloss_types::ScanCoverage {
            status: calxgloss_types::CoverageStatus::Complete,
            facets: Vec::new(),
        });
        let stamped_complete = render_module_context_full(&bundle);
        assert_eq!(
            unstamped, stamped_complete,
            "a complete record adds no bytes to the prompt"
        );
        assert!(
            !stamped_complete.contains("Coverage:"),
            "complete coverage has nothing to admit"
        );
    }

    /// A falling-short record appends exactly one bounded qualification
    /// line, pinned byte-for-byte as the line the include renders after
    /// the entries (issue #347).
    #[test]
    fn a_partial_libmatch_coverage_record_appends_exactly_one_qualification_line() {
        let mut bundle = EvidenceBundle::default();
        bundle.libmatch_findings.push(libmatch_fixture());
        let clean = render_module_context_full(&bundle);
        bundle.libmatch_coverage = CoverageInfo::from(&libmatch_admitting_coverage());
        let admitted = render_module_context_full(&bundle);
        assert_eq!(
            admitted,
            clean.replace(
                &format!("{LIBMATCH_SECTION_BODY}\n\n"),
                &format!("{LIBMATCH_SECTION_BODY}\n\nCoverage: {LIBMATCH_ADMISSION}\n\n"),
            ),
            "the admission appears in the section as exactly one line beside the entries"
        );
        assert_eq!(
            admitted
                .matches(&format!("## {KNOWN_LIBRARY_HEADING}"))
                .count(),
            1,
            "the admission never opens a second section"
        );
    }

    /// The doctrine pair, libmatch side (issue #347): silence under
    /// complete coverage and under a falling-short record must never
    /// render alike — an empty list from a scan that admits bodies it
    /// never reached still says something about which callees the match
    /// picture simply does not cover.
    #[test]
    fn empty_libmatch_findings_under_complete_and_partial_coverage_never_render_alike() {
        let under_complete = render_module_context_full(&EvidenceBundle::default());
        assert!(
            !under_complete.contains(&format!("## {KNOWN_LIBRARY_HEADING}")),
            "silence from an unstamped record stays section-less, as before P19"
        );
        let under_partial = render_module_context_full(&EvidenceBundle {
            libmatch_coverage: CoverageInfo::from(&libmatch_admitting_coverage()),
            ..Default::default()
        });
        assert_ne!(
            under_complete, under_partial,
            "empty findings under a falling-short record must render observably \
             different bytes than the same emptiness under a complete one"
        );
        assert!(
            under_partial.contains(&format!(
                "## {KNOWN_LIBRARY_HEADING}\n\nCoverage: {LIBMATCH_ADMISSION}\n\n"
            )),
            "the empty list still carries the one admission line"
        );
    }

    /// The per-finding note (issue #347): a match record that includes its
    /// version-authority admission renders one extra line beside its
    /// evidence, so the prompt is never shown a versioned claim the
    /// signature never established. A record with no note renders the
    /// pinned body untouched (pinned by the section suite above).
    #[test]
    fn an_admitted_libmatch_finding_renders_its_note_beside_its_evidence() {
        let mut finding = libmatch_fixture();
        finding.admission = "Signature match, version unknown".to_string();
        let admitted = render_module_context_full(&EvidenceBundle {
            libmatch_findings: vec![finding],
            ..Default::default()
        });
        let clean = render_module_context_full(&EvidenceBundle {
            libmatch_findings: vec![libmatch_fixture()],
            ..Default::default()
        });
        // Remove the note line from the admitted render: what is left
        // must be exactly the note-less render. The note adds exactly one
        // line, right after the evidence line, and nothing else moves.
        assert_eq!(
            admitted.replace(
                &format!("{LIBMATCH_SECTION_BODY}\n  Admission: Signature match, version unknown"),
                LIBMATCH_SECTION_BODY,
            ),
            clean,
            "the note adds exactly one extra line, right after the evidence line"
        );
        assert!(
            admitted.contains("  Admission: Signature match, version unknown"),
            "the note is actually there to be unstamped"
        );
    }

    /// A scan coverage record in the shape a floatsimd scan files (issue
    /// #347): its one `function-bodies` facet fell short, naming the one
    /// body the decompiler never produced — never an examined-and-clean
    /// body the flag list left unmentioned.
    fn floatsimd_admitting_coverage() -> calxgloss_types::ScanCoverage {
        calxgloss_types::ScanCoverage {
            status: calxgloss_types::CoverageStatus::Partial,
            facets: vec![calxgloss_types::FacetCoverage {
                id: "function-bodies".to_string(),
                status: calxgloss_types::CoverageStatus::Partial,
                limitation: Some("1 function body unreached: FUN_1800412a0".to_string()),
            }],
        }
    }

    /// The one qualification wording the section suite pins for the
    /// float/SIMD section (issue #347).
    const FLOATSIMD_ADMISSION: &str = "partial — 1 function body unreached: FUN_1800412a0";

    /// The heading the escalate template passes the floatsimd include.
    const ESCALATE_FLOATSIMD_HEADING: &str = "ADDITIONAL CONTEXT — FLOAT/SIMD";

    /// The pinned wording is checked at both ends: the shared coverage
    /// type produces it from a floatsimd-shaped record, and the rendered
    /// prompt shows that same line verbatim.
    #[test]
    fn the_floatsimd_admission_wording_is_pinned_at_both_ends_of_its_journey() {
        assert_eq!(
            floatsimd_admitting_coverage()
                .admission()
                .expect("partial admits"),
            FLOATSIMD_ADMISSION,
            "the shared type's own admission is the pinned line"
        );
        assert_eq!(
            CoverageInfo::from(&floatsimd_admitting_coverage()).admission,
            FLOATSIMD_ADMISSION,
            "the template-side view carries the same line, word for word"
        );
    }

    /// A complete coverage record is nothing to admit: the float/SIMD
    /// section renders byte-for-byte what it rendered when the document
    /// stated no coverage at all (issue #347).
    #[test]
    fn a_complete_floatsimd_coverage_record_renders_the_section_byte_identically() {
        let mut bundle = EvidenceBundle::default();
        bundle.floatsimd_findings.push(floatsimd_fixture());
        let unstamped = render_escalate_full(&bundle);
        bundle.floatsimd_coverage = CoverageInfo::from(&calxgloss_types::ScanCoverage {
            status: calxgloss_types::CoverageStatus::Complete,
            facets: Vec::new(),
        });
        let stamped_complete = render_escalate_full(&bundle);
        assert_eq!(
            unstamped, stamped_complete,
            "a complete record adds no bytes to the prompt"
        );
        assert!(
            !stamped_complete.contains("Coverage:"),
            "complete coverage has nothing to admit"
        );
    }

    /// A falling-short record appends exactly one bounded qualification
    /// line, pinned byte-for-byte as the line the include renders after
    /// the entries (issue #347).
    #[test]
    fn a_partial_floatsimd_coverage_record_appends_exactly_one_qualification_line() {
        let mut bundle = EvidenceBundle::default();
        bundle.floatsimd_findings.push(floatsimd_fixture());
        let clean = render_escalate_full(&bundle);
        bundle.floatsimd_coverage = CoverageInfo::from(&floatsimd_admitting_coverage());
        let admitted = render_escalate_full(&bundle);
        assert_eq!(
            admitted,
            clean.replace(
                &format!("{FLOATSIMD_SECTION_BODY}\n\n"),
                &format!("{FLOATSIMD_SECTION_BODY}\n\nCoverage: {FLOATSIMD_ADMISSION}\n\n"),
            ),
            "the admission appears in the section as exactly one line beside the entries"
        );
        assert_eq!(
            admitted
                .matches(&format!("## {ESCALATE_FLOATSIMD_HEADING}"))
                .count(),
            1,
            "the admission never opens a second section"
        );
    }

    /// The doctrine pair, floatsimd side (issue #347): an unflagged
    /// function under a complete record means examined-and-clean, and
    /// silence from a record that names bodies it never reached must
    /// never render the same bytes — the clean body and the never-
    /// reached body part company in the prompt.
    #[test]
    fn empty_floatsimd_findings_under_complete_and_partial_coverage_never_render_alike() {
        let under_complete = render_escalate_full(&EvidenceBundle::default());
        assert!(
            !under_complete.contains(&format!("## {ESCALATE_FLOATSIMD_HEADING}")),
            "silence from an unstamped record stays section-less, as before P19"
        );
        let under_partial = render_escalate_full(&EvidenceBundle {
            floatsimd_coverage: CoverageInfo::from(&floatsimd_admitting_coverage()),
            ..Default::default()
        });
        assert_ne!(
            under_complete, under_partial,
            "empty findings under a falling-short record must render observably \
             different bytes than the same emptiness under a complete one"
        );
        assert!(
            under_partial.contains(&format!(
                "## {ESCALATE_FLOATSIMD_HEADING}\n\nCoverage: {FLOATSIMD_ADMISSION}\n\n"
            )),
            "the empty list still carries the one admission line"
        );
    }

    // -- admitted coverage: the typesdb and consts sections (issue #348) --

    /// The coverage record a typesdb scan stamps over a target that
    /// yields no vtable evidence: the single `vtables` facet, `unavailable`,
    /// naming its reason — zero recorded vtables as a property of the
    /// target, never as the program having no classes.
    fn typesdb_unavailable_coverage() -> calxgloss_types::ScanCoverage {
        calxgloss_types::ScanCoverage {
            status: calxgloss_types::CoverageStatus::Unavailable,
            facets: vec![calxgloss_types::FacetCoverage {
                id: "vtables".to_string(),
                status: calxgloss_types::CoverageStatus::Unavailable,
                limitation: Some("no vtable evidence on this target".to_string()),
            }],
        }
    }

    /// The one qualification wording the section suite pins for the
    /// data-structures section (issue #348).
    const TYPESDB_ADMISSION: &str = "unavailable — no vtable evidence on this target";

    /// The headings the consuming templates pass the data-structures include.
    const ESCALATE_DATA_STRUCTURES_HEADING: &str = "ADDITIONAL CONTEXT — DATA STRUCTURES";
    const SHARED_DATA_STRUCTURES_HEADING: &str = "SHARED DATA STRUCTURES";

    /// The coverage record a consts scan stamps over a region-limited run:
    /// both facets `partial`, one naming the bodies it never reached and
    /// one the memory windows it never read. The wording is the engine's
    /// own, pinned in the engine's tests too, so a drift at either end
    /// fails loudly.
    fn consts_partial_coverage() -> calxgloss_types::ScanCoverage {
        calxgloss_types::ScanCoverage {
            status: calxgloss_types::CoverageStatus::Partial,
            facets: vec![
                calxgloss_types::FacetCoverage {
                    id: "function-bodies".to_string(),
                    status: calxgloss_types::CoverageStatus::Partial,
                    limitation: Some(
                        "2 function bodies unreached: FUN_18003e750, +1 more".to_string(),
                    ),
                },
                calxgloss_types::FacetCoverage {
                    id: "data-objects".to_string(),
                    status: calxgloss_types::CoverageStatus::Partial,
                    limitation: Some(
                        "1 data-object memory window unreadable: DAT_1400a1c00".to_string(),
                    ),
                },
            ],
        }
    }

    /// The one qualification wording that appears in both consts sections
    /// (issue #348): the same line beside the constants entries and beside
    /// the data-tables entries, since one constants scan feeds both.
    const CONSTS_ADMISSION: &str = "partial — 2 function bodies unreached: FUN_18003e750, +1 more; \
                                    1 data-object memory window unreadable: DAT_1400a1c00";

    /// The headings the templates pass the constants and data-tables includes.
    const ESCALATE_CONSTANTS_HEADING: &str = "ADDITIONAL CONTEXT — CONSTANTS";
    const MODULE_CONTEXT_DATA_TABLES_HEADING: &str = "DATA TABLES";

    /// The pinned wording is checked at both ends for both engines: the
    /// shared coverage type produces it from the records their scans
    /// stamp, and the rendered prompt shows that same line verbatim.
    #[test]
    fn the_typesdb_and_consts_admission_wording_is_pinned_at_both_ends_of_their_journeys() {
        assert_eq!(
            typesdb_unavailable_coverage()
                .admission()
                .expect("unavailable admits"),
            TYPESDB_ADMISSION,
            "the shared type's own admission is the pinned line"
        );
        assert_eq!(
            CoverageInfo::from(&typesdb_unavailable_coverage()).admission,
            TYPESDB_ADMISSION,
            "the template-side view carries the same line, word for word"
        );
        assert_eq!(
            consts_partial_coverage()
                .admission()
                .expect("partial admits"),
            CONSTS_ADMISSION,
            "both falling-short facets speak in one shared line"
        );
        assert_eq!(
            CoverageInfo::from(&consts_partial_coverage()).admission,
            CONSTS_ADMISSION,
            "the template-side view carries the same line, word for word"
        );
    }

    /// A complete coverage record is nothing to admit: the data-structures
    /// section renders byte-for-byte what it rendered when the database
    /// stated no coverage at all, at every one of its three consumers
    /// (issue #348).
    #[test]
    fn a_complete_typesdb_coverage_record_renders_the_section_byte_identically() {
        let mut bundle = EvidenceBundle::default();
        bundle.data_structures.extend(data_structures_fixtures());
        let unstamped = (
            render_escalate_full(&bundle),
            render_module_context_full(&bundle),
            render_full_module_full(&bundle),
        );
        bundle.type_database_coverage = CoverageInfo::from(&calxgloss_types::ScanCoverage {
            status: calxgloss_types::CoverageStatus::Complete,
            facets: Vec::new(),
        });
        let stamped = (
            render_escalate_full(&bundle),
            render_module_context_full(&bundle),
            render_full_module_full(&bundle),
        );
        assert_eq!(unstamped, stamped, "a complete record adds no bytes");
        assert!(
            !stamped.0.contains("Coverage:")
                && !stamped.1.contains("Coverage:")
                && !stamped.2.contains("Coverage:"),
            "complete coverage has nothing to admit"
        );
    }

    /// A falling-short typesdb record appends exactly one bounded
    /// qualification line beside the structures. The admission joins the
    /// section without replacing or reflowing it, and one line is the
    /// whole growth allowed (issue #348).
    #[test]
    fn a_falling_short_typesdb_record_qualifies_the_section_beyond_its_entries() {
        let mut bundle = EvidenceBundle::default();
        bundle.data_structures.extend(data_structures_fixtures());
        let clean = render_escalate_full(&bundle);
        bundle.type_database_coverage = CoverageInfo::from(&typesdb_unavailable_coverage());
        let admitted = render_escalate_full(&bundle);
        assert_eq!(
            admitted,
            clean.replace(
                &format!("{DATA_STRUCTURES_SECTION_BODY}\n\n"),
                &format!("{DATA_STRUCTURES_SECTION_BODY}\n\nCoverage: {TYPESDB_ADMISSION}\n\n"),
            ),
            "the admission appears in the section as exactly one line beside the entries"
        );
        assert_eq!(
            admitted
                .matches(&format!("## {ESCALATE_DATA_STRUCTURES_HEADING}"))
                .count(),
            1,
            "the admission never opens a second section"
        );
        assert_eq!(
            admitted.matches("Coverage:").count(),
            clean.matches("Coverage:").count() + 1,
            "one admission line, never a paragraph"
        );
    }

    /// The empty-findings doctrine, typesdb side (issue #348). Structures
    /// the scan never recovered establish nothing about the function, so a
    /// falling-short record over an empty list opens no section to qualify.
    /// This differs from the constants and float/SIMD sections, whose
    /// headings the admission does open. What the reader sees is the
    /// entries plus a line, or nothing at all.
    #[test]
    fn empty_data_structures_under_a_falling_short_typesdb_record_establish_no_section() {
        let unstamped = render_module_context_full(&EvidenceBundle::default());
        let admitted = render_module_context_full(&EvidenceBundle {
            type_database_coverage: CoverageInfo::from(&typesdb_unavailable_coverage()),
            ..Default::default()
        });
        assert_eq!(
            unstamped, admitted,
            "no structures recovered is no section to qualify, coverage or no coverage"
        );
        assert!(
            !admitted.contains(&format!("## {SHARED_DATA_STRUCTURES_HEADING}")),
            "the admission alone never opens the data-structures heading"
        );
    }

    /// A complete consts record is nothing to admit: the constants and
    /// data-tables sections render byte-for-byte what they rendered when
    /// the document stated no coverage at all (issue #348).
    #[test]
    fn a_complete_consts_coverage_record_renders_both_sections_byte_identically() {
        let mut bundle = EvidenceBundle::default();
        bundle.const_findings.push(const_fixture());
        bundle.data_table_findings.push(data_table_fixture());
        let unstamped = (
            render_escalate_full(&bundle),
            render_module_context_full(&bundle),
        );
        bundle.consts_coverage = CoverageInfo::from(&calxgloss_types::ScanCoverage {
            status: calxgloss_types::CoverageStatus::Complete,
            facets: Vec::new(),
        });
        let stamped = (
            render_escalate_full(&bundle),
            render_module_context_full(&bundle),
        );
        assert_eq!(unstamped, stamped, "a complete record adds no bytes");
        assert!(
            !stamped.0.contains("Coverage:") && !stamped.1.contains("Coverage:"),
            "complete coverage has nothing to admit"
        );
    }

    /// A region-limited consts record qualifies each of its two sections
    /// with exactly one line — the same admission beside the constants
    /// entries and beside the data-tables entries, each pinned byte-for-
    /// byte as the line its include renders (issue #348).
    #[test]
    fn a_region_limited_consts_record_qualifies_both_sections_with_one_line_each() {
        let mut bundle = EvidenceBundle::default();
        bundle.const_findings.push(const_fixture());
        bundle.data_table_findings.push(data_table_fixture());
        let clean = (
            render_escalate_full(&bundle),
            render_module_context_full(&bundle),
        );
        bundle.consts_coverage = CoverageInfo::from(&consts_partial_coverage());
        let admitted = (
            render_escalate_full(&bundle),
            render_module_context_full(&bundle),
        );
        assert_eq!(
            admitted.0,
            clean.0.replace(
                &format!("{CONSTANTS_SECTION_BODY}\n\n"),
                &format!("{CONSTANTS_SECTION_BODY}\n\nCoverage: {CONSTS_ADMISSION}\n\n"),
            ),
            "the constants section carries the one admission line beside its entries"
        );
        assert_eq!(
            admitted.1,
            clean.1.replace(
                &format!("{DATA_TABLES_SECTION_BODY}\n\n"),
                &format!("{DATA_TABLES_SECTION_BODY}\n\nCoverage: {CONSTS_ADMISSION}\n\n"),
            ),
            "the data-tables section carries the same line beside its entries"
        );
        assert_eq!(
            admitted
                .0
                .matches(&format!("## {ESCALATE_CONSTANTS_HEADING}"))
                .count(),
            1,
            "the admission never opens a second constants section"
        );
        assert_eq!(
            admitted
                .1
                .matches(&format!("## {MODULE_CONTEXT_DATA_TABLES_HEADING}"))
                .count(),
            1,
            "the admission never opens a second data-tables section"
        );
    }

    /// The doctrine pair, consts side (issue #348): a program with no
    /// findings under a complete record means examined-and-clean, and
    /// silence from a record that names bodies and windows it never
    /// reached must never render the same bytes — an escalate retry can
    /// tell "this binary has no constants" from "the constants scan
    /// examined little and filed almost nothing".
    #[test]
    fn empty_consts_findings_under_complete_and_partial_coverage_never_render_alike() {
        let under_complete = (
            render_escalate_full(&EvidenceBundle::default()),
            render_module_context_full(&EvidenceBundle::default()),
        );
        assert!(
            !under_complete
                .0
                .contains(&format!("## {ESCALATE_CONSTANTS_HEADING}")),
            "silence from an unstamped record stays section-less, as before P19"
        );
        assert!(
            !under_complete
                .1
                .contains(&format!("## {MODULE_CONTEXT_DATA_TABLES_HEADING}")),
            "silence from an unstamped record stays section-less, as before P19"
        );
        let coverage = CoverageInfo::from(&consts_partial_coverage());
        let under_partial = (
            render_escalate_full(&EvidenceBundle {
                consts_coverage: coverage.clone(),
                ..Default::default()
            }),
            render_module_context_full(&EvidenceBundle {
                consts_coverage: coverage,
                ..Default::default()
            }),
        );
        assert_ne!(
            under_complete.0, under_partial.0,
            "empty findings under a falling-short record must render observably \
             different bytes than the same emptiness under a complete one"
        );
        assert_ne!(
            under_complete.1, under_partial.1,
            "empty findings under a falling-short record must render observably \
             different bytes than the same emptiness under a complete one"
        );
        assert!(
            under_partial.0.contains(&format!(
                "## {ESCALATE_CONSTANTS_HEADING}\n\nCoverage: {CONSTS_ADMISSION}\n\n"
            )),
            "the empty list still carries the one admission line"
        );
        assert!(
            under_partial.1.contains(&format!(
                "## {MODULE_CONTEXT_DATA_TABLES_HEADING}\n\nCoverage: {CONSTS_ADMISSION}\n\n"
            )),
            "the empty list still carries the one admission line"
        );
    }

    // -- admitted coverage: the control-flow, memory, and concurrency
    //    sections (issue #349) --

    /// Coverage records in the shape these three scans file: each one's
    /// single `function-bodies` facet fell short, naming the bodies the
    /// decompiler never produced — never an examined-and-clean body the
    /// finding list left unmentioned. Each engine names different bodies,
    /// so if one engine's coverage value appears in another engine's
    /// section, every pin below fails.
    fn control_flow_admitting_coverage() -> calxgloss_types::ScanCoverage {
        calxgloss_types::ScanCoverage {
            status: calxgloss_types::CoverageStatus::Partial,
            facets: vec![calxgloss_types::FacetCoverage {
                id: "function-bodies".to_string(),
                status: calxgloss_types::CoverageStatus::Partial,
                limitation: Some("1 function body unreached: FUN_1800412a0".to_string()),
            }],
        }
    }

    fn memory_admitting_coverage() -> calxgloss_types::ScanCoverage {
        calxgloss_types::ScanCoverage {
            status: calxgloss_types::CoverageStatus::Partial,
            facets: vec![calxgloss_types::FacetCoverage {
                id: "function-bodies".to_string(),
                status: calxgloss_types::CoverageStatus::Partial,
                limitation: Some(
                    "2 function bodies unreached: FUN_180049abc, FUN_18004def0".to_string(),
                ),
            }],
        }
    }

    fn sync_admitting_coverage() -> calxgloss_types::ScanCoverage {
        calxgloss_types::ScanCoverage {
            status: calxgloss_types::CoverageStatus::Partial,
            facets: vec![calxgloss_types::FacetCoverage {
                id: "function-bodies".to_string(),
                status: calxgloss_types::CoverageStatus::Partial,
                limitation: Some("1 function body unreached: FUN_18003e999".to_string()),
            }],
        }
    }

    /// The one qualification wording each section suite pins for its
    /// engine's section (issue #349).
    const CONTROL_FLOW_ADMISSION: &str = "partial — 1 function body unreached: FUN_1800412a0";
    const MEMORY_ADMISSION: &str =
        "partial — 2 function bodies unreached: FUN_180049abc, FUN_18004def0";
    const SYNC_ADMISSION: &str = "partial — 1 function body unreached: FUN_18003e999";

    /// The headings the consuming templates pass the three includes.
    const ESCALATE_CONTROL_FLOW_HEADING: &str = "ADDITIONAL CONTEXT — CONTROL FLOW";
    const SHARED_CONTROL_FLOW_HEADING: &str = "CONTROL FLOW PATTERNS";
    const ESCALATE_MEMORY_HEADING: &str = "ADDITIONAL CONTEXT — MEMORY LIFECYCLE";
    const ESCALATE_CONCURRENCY_HEADING: &str = "ADDITIONAL CONTEXT — CONCURRENCY";

    /// The pinned wording is checked at both ends for all three engines:
    /// the shared coverage type produces it from the records their scans
    /// stamp, and the rendered prompt shows those same lines verbatim.
    #[test]
    fn the_control_flow_memory_and_sync_admission_wording_is_pinned_at_both_ends() {
        assert_eq!(
            control_flow_admitting_coverage()
                .admission()
                .expect("partial admits"),
            CONTROL_FLOW_ADMISSION,
            "the shared type's own admission is the pinned line"
        );
        assert_eq!(
            CoverageInfo::from(&control_flow_admitting_coverage()).admission,
            CONTROL_FLOW_ADMISSION,
            "the template-side view carries the same line, word for word"
        );
        assert_eq!(
            memory_admitting_coverage()
                .admission()
                .expect("partial admits"),
            MEMORY_ADMISSION,
            "the shared type's own admission is the pinned line"
        );
        assert_eq!(
            CoverageInfo::from(&memory_admitting_coverage()).admission,
            MEMORY_ADMISSION,
            "the template-side view carries the same line, word for word"
        );
        assert_eq!(
            sync_admitting_coverage()
                .admission()
                .expect("partial admits"),
            SYNC_ADMISSION,
            "the shared type's own admission is the pinned line"
        );
        assert_eq!(
            CoverageInfo::from(&sync_admitting_coverage()).admission,
            SYNC_ADMISSION,
            "the template-side view carries the same line, word for word"
        );
    }

    /// A complete coverage record is nothing to admit: the three sections
    /// render byte-for-byte what they rendered when their documents
    /// stated no coverage at all, at every consumer of each (issue #349).
    #[test]
    fn a_complete_coverage_record_renders_the_three_sections_byte_identically() {
        let mut bundle = EvidenceBundle::default();
        bundle.control_flow_findings.push(control_flow_fixture());
        bundle.memory_findings.push(memory_fixture());
        bundle.concurrency_findings.push(concurrency_fixture());
        let unstamped = (
            render_escalate_full(&bundle),
            render_module_context_full(&bundle),
            render_full_module_full(&bundle),
        );
        let complete = CoverageInfo::from(&calxgloss_types::ScanCoverage {
            status: calxgloss_types::CoverageStatus::Complete,
            facets: Vec::new(),
        });
        bundle.control_flow_coverage = complete.clone();
        bundle.memory_coverage = complete.clone();
        bundle.sync_coverage = complete;
        let stamped = (
            render_escalate_full(&bundle),
            render_module_context_full(&bundle),
            render_full_module_full(&bundle),
        );
        assert_eq!(unstamped, stamped, "a complete record adds no bytes");
        assert!(
            !stamped.0.contains("Coverage:")
                && !stamped.1.contains("Coverage:")
                && !stamped.2.contains("Coverage:"),
            "complete coverage has nothing to admit"
        );
    }

    /// A falling-short control-flow record appends exactly one bounded
    /// qualification line at each of the section's three consumers. The
    /// admission joins the section without replacing or reflowing it, and
    /// one line is the whole growth allowed (issue #349). The
    /// module-context row feeds the branch-site fixture, so its pinned
    /// body is the branch entry's.
    #[test]
    fn a_partial_control_flow_record_appends_exactly_one_line_at_each_consumer() {
        let mut patterns = EvidenceBundle::default();
        patterns.control_flow_findings.push(control_flow_fixture());
        let escalate_clean = render_escalate_full(&patterns);
        let full_clean = render_full_module_full(&patterns);
        let mut branch = EvidenceBundle::default();
        branch.control_flow_findings.push(branch_site_fixture());
        let module_clean = render_module_context_full(&branch);

        patterns.control_flow_coverage = CoverageInfo::from(&control_flow_admitting_coverage());
        branch.control_flow_coverage = CoverageInfo::from(&control_flow_admitting_coverage());
        let escalate_admitted = render_escalate_full(&patterns);
        let full_admitted = render_full_module_full(&patterns);
        let module_admitted = render_module_context_full(&branch);

        for (clean, admitted, heading) in [
            (
                escalate_clean,
                escalate_admitted,
                ESCALATE_CONTROL_FLOW_HEADING,
            ),
            (full_clean, full_admitted, SHARED_CONTROL_FLOW_HEADING),
            (module_clean, module_admitted, SHARED_CONTROL_FLOW_HEADING),
        ] {
            let is_branch = heading == SHARED_CONTROL_FLOW_HEADING
                && clean.contains(&CONTROL_FLOW_BRANCH_SECTION_BODY.to_string());
            let body = if is_branch {
                &CONTROL_FLOW_BRANCH_SECTION_BODY
            } else {
                &CONTROL_FLOW_SECTION_BODY
            };
            assert_eq!(
                admitted,
                clean.replace(
                    &format!("{body}\n\n"),
                    &format!("{body}\n\nCoverage: {CONTROL_FLOW_ADMISSION}\n\n"),
                ),
                "the admission appears in the {heading} section as exactly one line beside the entries"
            );
            assert_eq!(
                admitted.matches(&format!("## {heading}")).count(),
                1,
                "the admission never opens a second {heading} section"
            );
            assert_eq!(
                admitted.matches("Coverage:").count(),
                clean.matches("Coverage:").count() + 1,
                "one admission line, never a paragraph"
            );
        }
    }

    /// A falling-short memory record and a falling-short sync record each
    /// append exactly one bounded qualification line beside their own
    /// entries in the escalate prompt — the two admissions never use each
    /// other's wording, and each section keeps one heading (issue
    /// #349).
    #[test]
    fn partial_memory_and_sync_records_append_one_qualification_line_each() {
        let mut bundle = EvidenceBundle::default();
        bundle.memory_findings.push(memory_fixture());
        bundle.concurrency_findings.push(concurrency_fixture());
        let clean = render_escalate_full(&bundle);
        bundle.memory_coverage = CoverageInfo::from(&memory_admitting_coverage());
        bundle.sync_coverage = CoverageInfo::from(&sync_admitting_coverage());
        let admitted = render_escalate_full(&bundle);
        let expected = clean
            .replace(
                &format!("{MEMORY_LIFECYCLE_SECTION_BODY}\n\n"),
                &format!("{MEMORY_LIFECYCLE_SECTION_BODY}\n\nCoverage: {MEMORY_ADMISSION}\n\n"),
            )
            .replace(
                &format!("{CONCURRENCY_SECTION_BODY}\n\n"),
                &format!("{CONCURRENCY_SECTION_BODY}\n\nCoverage: {SYNC_ADMISSION}\n\n"),
            );
        assert_eq!(
            admitted, expected,
            "each admission appears in its own section as exactly one line beside the entries"
        );
        assert_eq!(
            admitted
                .matches(&format!("## {ESCALATE_MEMORY_HEADING}"))
                .count(),
            1,
            "the memory admission never opens a second section"
        );
        assert_eq!(
            admitted
                .matches(&format!("## {ESCALATE_CONCURRENCY_HEADING}"))
                .count(),
            1,
            "the sync admission never opens a second section"
        );
    }

    /// The doctrine pair for all three engines (issue #349): an
    /// unmentioned function under a complete record means examined-and-
    /// clean, and silence from a record that names bodies it never
    /// reached must never render the same bytes — a retry or a module
    /// translation can tell "this function has no such findings" from
    /// "the scan never read this function".
    #[test]
    fn empty_findings_under_complete_and_partial_coverage_never_render_alike() {
        let under_complete = (
            render_escalate_full(&EvidenceBundle::default()),
            render_module_context_full(&EvidenceBundle::default()),
            render_full_module_full(&EvidenceBundle::default()),
        );
        for (prompt, heading) in [
            (&under_complete.0, ESCALATE_CONTROL_FLOW_HEADING),
            (&under_complete.1, SHARED_CONTROL_FLOW_HEADING),
            (&under_complete.2, SHARED_CONTROL_FLOW_HEADING),
        ] {
            assert!(
                !prompt.contains(&format!("## {heading}")),
                "silence from an unstamped record stays section-less, as before P19"
            );
        }
        let escalate_partial = render_escalate_full(&EvidenceBundle {
            control_flow_coverage: CoverageInfo::from(&control_flow_admitting_coverage()),
            memory_coverage: CoverageInfo::from(&memory_admitting_coverage()),
            sync_coverage: CoverageInfo::from(&sync_admitting_coverage()),
            ..Default::default()
        });
        let module_partial = render_module_context_full(&EvidenceBundle {
            control_flow_coverage: CoverageInfo::from(&control_flow_admitting_coverage()),
            ..Default::default()
        });
        let full_partial = render_full_module_full(&EvidenceBundle {
            control_flow_coverage: CoverageInfo::from(&control_flow_admitting_coverage()),
            ..Default::default()
        });
        assert_ne!(
            under_complete.0, escalate_partial,
            "empty findings under a falling-short record must render observably \
             different bytes than the same emptiness under a complete one"
        );
        assert_ne!(
            under_complete.1, module_partial,
            "empty findings under a falling-short record must render observably \
             different bytes than the same emptiness under a complete one"
        );
        assert_ne!(
            under_complete.2, full_partial,
            "empty findings under a falling-short record must render observably \
             different bytes than the same emptiness under a complete one"
        );
        for (prompt, heading, admission) in [
            (
                &escalate_partial,
                ESCALATE_CONTROL_FLOW_HEADING,
                CONTROL_FLOW_ADMISSION,
            ),
            (&escalate_partial, ESCALATE_MEMORY_HEADING, MEMORY_ADMISSION),
            (
                &escalate_partial,
                ESCALATE_CONCURRENCY_HEADING,
                SYNC_ADMISSION,
            ),
            (
                &module_partial,
                SHARED_CONTROL_FLOW_HEADING,
                CONTROL_FLOW_ADMISSION,
            ),
            (
                &full_partial,
                SHARED_CONTROL_FLOW_HEADING,
                CONTROL_FLOW_ADMISSION,
            ),
        ] {
            assert!(
                prompt.contains(&format!("## {heading}\n\nCoverage: {admission}\n\n")),
                "the empty list still carries the one admission line"
            );
        }
    }

    // -- admitted coverage: the algorithm, string-context, type-inference,
    //    and serialization sections (issue #351) --

    /// Coverage records in the shape these four scans file. The
    /// algorithm-recognition scan names the bodies its decompiler never
    /// produced beside the caller edges it could not read. The
    /// string-context scan lost its program-string listing, and the
    /// cross-references that depended on it went with it, while still
    /// reading every body. The type-inference scan read a truncated
    /// machine listing, lost its import listing, and could not read one
    /// caller edge. The serialization-pattern scan — like the
    /// global-state scan before it — has one facet and one missing body.
    /// Each engine names different functions, so if one engine's coverage
    /// value appears in another engine's section, every pin below fails.
    fn algorithm_admitting_coverage() -> calxgloss_types::ScanCoverage {
        calxgloss_types::ScanCoverage {
            status: calxgloss_types::CoverageStatus::Partial,
            facets: vec![
                calxgloss_types::FacetCoverage {
                    id: "function-bodies".to_string(),
                    status: calxgloss_types::CoverageStatus::Partial,
                    limitation: Some("1 function body unreached: FUN_180070010".to_string()),
                },
                calxgloss_types::FacetCoverage {
                    id: "caller-edges".to_string(),
                    status: calxgloss_types::CoverageStatus::Partial,
                    limitation: Some("1 caller edge unreadable: FUN_180070020".to_string()),
                },
            ],
        }
    }

    fn stringctx_admitting_coverage() -> calxgloss_types::ScanCoverage {
        calxgloss_types::ScanCoverage {
            status: calxgloss_types::CoverageStatus::Partial,
            facets: vec![
                calxgloss_types::FacetCoverage {
                    id: "function-bodies".to_string(),
                    status: calxgloss_types::CoverageStatus::Complete,
                    limitation: None,
                },
                calxgloss_types::FacetCoverage {
                    id: "program-strings".to_string(),
                    status: calxgloss_types::CoverageStatus::Unavailable,
                    limitation: Some("program string listing unreadable".to_string()),
                },
                calxgloss_types::FacetCoverage {
                    id: "string-xrefs".to_string(),
                    status: calxgloss_types::CoverageStatus::Unavailable,
                    limitation: Some("no string cross-reference could be read".to_string()),
                },
            ],
        }
    }

    fn typeinfer_admitting_coverage() -> calxgloss_types::ScanCoverage {
        calxgloss_types::ScanCoverage {
            status: calxgloss_types::CoverageStatus::Partial,
            facets: vec![
                calxgloss_types::FacetCoverage {
                    id: "function-bodies".to_string(),
                    status: calxgloss_types::CoverageStatus::Complete,
                    limitation: None,
                },
                calxgloss_types::FacetCoverage {
                    id: "machine-listings".to_string(),
                    status: calxgloss_types::CoverageStatus::Partial,
                    limitation: Some("1 machine listing unreadable: FUN_180088000".to_string()),
                },
                calxgloss_types::FacetCoverage {
                    id: "import-names".to_string(),
                    status: calxgloss_types::CoverageStatus::Unavailable,
                    limitation: Some("import listing unreadable".to_string()),
                },
                calxgloss_types::FacetCoverage {
                    id: "caller-edges".to_string(),
                    status: calxgloss_types::CoverageStatus::Partial,
                    limitation: Some("1 caller edge unreadable: FUN_180088010".to_string()),
                },
            ],
        }
    }

    fn serialize_admitting_coverage() -> calxgloss_types::ScanCoverage {
        calxgloss_types::ScanCoverage {
            status: calxgloss_types::CoverageStatus::Partial,
            facets: vec![calxgloss_types::FacetCoverage {
                id: "function-bodies".to_string(),
                status: calxgloss_types::CoverageStatus::Partial,
                limitation: Some("1 function body unreached: FUN_180099900".to_string()),
            }],
        }
    }

    /// The one qualification wording each section suite pins for its
    /// engine's section (issue #351). The type-inference admission is one
    /// record whose joined form names three gaps, shared by the type
    /// information, calling convention, and parameter direction surfaces.
    const ALGORITHM_ADMISSION: &str = "partial — 1 function body unreached: FUN_180070010; 1 caller edge unreadable: FUN_180070020";
    const STRINGCTX_ADMISSION: &str =
        "partial — program string listing unreadable; no string cross-reference could be read";
    const TYPEINFER_ADMISSION: &str = "partial — 1 machine listing unreadable: FUN_180088000; import listing unreadable; 1 caller edge unreadable: FUN_180088010";
    const SERIALIZE_ADMISSION: &str = "partial — 1 function body unreached: FUN_180099900";

    /// The headings the consuming templates pass each section.
    const ESCALATE_RECOGNIZED_ALGORITHMS_HEADING: &str =
        "ADDITIONAL CONTEXT — RECOGNIZED ALGORITHMS";
    const ESCALATE_STRING_CONTEXT_HEADING: &str = "ADDITIONAL CONTEXT — STRINGS";
    const ESCALATE_SERIALIZATION_HEADING: &str = "ADDITIONAL CONTEXT — SERIALIZATION";
    const ESCALATE_CALLING_CONVENTION_HEADING: &str = "ADDITIONAL CONTEXT — CALLING CONVENTION";
    const MODULE_CALLING_CONVENTION_HEADING: &str = "CALLING CONVENTION";
    const MODULE_PARAMETER_DIRECTION_HEADING: &str = "PARAMETER DIRECTIONS";

    /// The pinned wording is checked at both ends: the shared coverage
    /// type produces each admission from a scan-shaped record, and the
    /// rendered prompt shows that same line verbatim (issue #351).
    #[test]
    fn the_four_admission_wordings_are_pinned_at_both_ends_of_their_journey() {
        for (record, pinned) in [
            (algorithm_admitting_coverage(), ALGORITHM_ADMISSION),
            (stringctx_admitting_coverage(), STRINGCTX_ADMISSION),
            (typeinfer_admitting_coverage(), TYPEINFER_ADMISSION),
            (serialize_admitting_coverage(), SERIALIZE_ADMISSION),
        ] {
            assert_eq!(
                record.admission().expect("partial admits"),
                pinned,
                "the shared type's own admission is the pinned line"
            );
            assert_eq!(
                CoverageInfo::from(&record).admission,
                pinned,
                "the template-side view carries the same line, word for word"
            );
        }
    }

    /// A complete coverage record is nothing to admit: each of the six
    /// sections — including all three type-inference surfaces on all their
    /// consumers, and both tier templates — renders byte-for-byte what it
    /// rendered when the document stated no coverage at all (issue #351).
    #[test]
    fn complete_coverage_for_all_four_scans_renders_every_section_byte_identically() {
        let mut bundle = EvidenceBundle::default();
        bundle.recognized_algorithms.push(algorithm_fixture());
        bundle.string_findings.push(string_fixture());
        bundle.serialization_findings.push(serialization_fixture());
        bundle.convention_findings.push(convention_fixture());
        bundle
            .parameter_direction_findings
            .push(parameter_direction_fixture());
        let unstamped = (
            render_escalate_full(&bundle),
            render_module_context_full(&bundle),
        );

        bundle.algorithm_coverage = CoverageInfo::from(&complete_coverage());
        bundle.string_context_coverage = CoverageInfo::from(&complete_coverage());
        bundle.type_inference_coverage = CoverageInfo::from(&complete_coverage());
        bundle.serialization_coverage = CoverageInfo::from(&complete_coverage());
        let stamped = (
            render_escalate_full(&bundle),
            render_module_context_full(&bundle),
        );
        assert_eq!(
            unstamped, stamped,
            "four complete records add no bytes to the escalate or module-context prompt"
        );
        for prompt in [stamped.0, stamped.1] {
            assert!(
                !prompt.contains("Coverage:"),
                "complete coverage has nothing to admit"
            );
        }

        // The tier templates render the type information surface; a
        // complete type-inference record must leave their renders
        // byte-identical too.
        let req = sample_request();
        let mut rich_data = ComplexityPromptData::from_request(&req);
        rich_data.type_info = type_info_pair();
        let rich_unstamped = build_complexity_prompt(&FunctionComplexity::Rich, &rich_data)
            .expect("rich prompt should render");
        rich_data.type_inference_coverage = CoverageInfo::from(&complete_coverage());
        let rich_stamped = build_complexity_prompt(&FunctionComplexity::Rich, &rich_data)
            .expect("rich prompt with complete coverage should render");
        assert_eq!(
            rich_unstamped, rich_stamped,
            "a complete type-inference record adds no bytes to the rich template"
        );

        let mut detailed_data = ComplexityPromptData::from_request(&req);
        detailed_data.type_info = type_info_pair();
        let detailed_unstamped =
            build_complexity_prompt(&FunctionComplexity::Detailed, &detailed_data)
                .expect("detailed prompt should render");
        detailed_data.type_inference_coverage = CoverageInfo::from(&complete_coverage());
        let detailed_stamped =
            build_complexity_prompt(&FunctionComplexity::Detailed, &detailed_data)
                .expect("detailed prompt with complete coverage should render");
        assert_eq!(
            detailed_unstamped, detailed_stamped,
            "a complete type-inference record adds no bytes to the detailed template"
        );
    }

    /// A falling-short record appends exactly one bounded qualification
    /// line beside the entries of every section the producing scan feeds.
    /// For type inference, that ONE record lands identically on all THREE
    /// of its surfaces across BOTH their consumers (issue #351).
    #[test]
    fn each_falling_short_record_appends_one_line_per_section_it_qualifies() {
        let mut bundle = EvidenceBundle::default();
        bundle.recognized_algorithms.push(algorithm_fixture());
        bundle.string_findings.push(string_fixture());
        bundle.serialization_findings.push(serialization_fixture());
        bundle.convention_findings.push(convention_fixture());
        bundle
            .parameter_direction_findings
            .push(parameter_direction_fixture());
        let escalate_clean = render_escalate_full(&bundle);
        let module_clean = render_module_context_full(&bundle);

        bundle.algorithm_coverage = CoverageInfo::from(&algorithm_admitting_coverage());
        bundle.string_context_coverage = CoverageInfo::from(&stringctx_admitting_coverage());
        bundle.type_inference_coverage = CoverageInfo::from(&typeinfer_admitting_coverage());
        bundle.serialization_coverage = CoverageInfo::from(&serialize_admitting_coverage());
        let escalate_admitted = render_escalate_full(&bundle);
        let module_admitted = render_module_context_full(&bundle);

        let escalate_expected = escalate_clean
            .replace(
                "## ADDITIONAL CONTEXT — RECOGNIZED ALGORITHMS",
                &format!(
                    "## ADDITIONAL CONTEXT — TYPE INFORMATION\n\nCoverage: {TYPEINFER_ADMISSION}\n\n## ADDITIONAL CONTEXT — RECOGNIZED ALGORITHMS"
                ),
            )
            .replace(
                &format!("{RECOGNIZED_ALGORITHMS_SECTION_BODY}\n\n"),
                &format!(
                    "{RECOGNIZED_ALGORITHMS_SECTION_BODY}\n\nCoverage: {ALGORITHM_ADMISSION}\n\n"
                ),
            )
            .replace(
                &format!("{STRING_CONTEXT_SECTION_BODY}\n\n## TRANSLATION REQUIREMENTS"),
                &format!(
                    "{STRING_CONTEXT_SECTION_BODY}\n\nCoverage: {STRINGCTX_ADMISSION}\n\n## TRANSLATION REQUIREMENTS"
                ),
            )
            .replace(
                &format!("{SERIALIZATION_SECTION_BODY}\n\n"),
                &format!(
                    "{SERIALIZATION_SECTION_BODY}\n\nCoverage: {SERIALIZE_ADMISSION}\n\n"
                ),
            )
            .replace(
                &format!("{CALLING_CONVENTION_SECTION_BODY}\n\n"),
                &format!(
                    "{CALLING_CONVENTION_SECTION_BODY}\n\nCoverage: {TYPEINFER_ADMISSION}\n\n"
                ),
            );
        assert_eq!(
            escalate_admitted, escalate_expected,
            "each admission appears in its own escalate section as exactly one line beside the entries"
        );
        let module_expected = module_clean
            .replace(
                &format!("{CALLING_CONVENTION_SECTION_BODY}\n\n"),
                &format!(
                    "{CALLING_CONVENTION_SECTION_BODY}\n\nCoverage: {TYPEINFER_ADMISSION}\n\n"
                ),
            )
            .replace(
                &format!("{PARAMETER_DIRECTION_SECTION_BODY}\n\n"),
                &format!(
                    "{PARAMETER_DIRECTION_SECTION_BODY}\n\nCoverage: {TYPEINFER_ADMISSION}\n\n"
                ),
            );
        assert_eq!(
            module_admitted, module_expected,
            "the one type-inference admission appears in both of its module-context surfaces"
        );
        for (prompt, heading) in [
            (&escalate_admitted, ESCALATE_RECOGNIZED_ALGORITHMS_HEADING),
            (&escalate_admitted, ESCALATE_STRING_CONTEXT_HEADING),
            (&escalate_admitted, ESCALATE_SERIALIZATION_HEADING),
            (&escalate_admitted, ESCALATE_CALLING_CONVENTION_HEADING),
            (&module_admitted, MODULE_CALLING_CONVENTION_HEADING),
            (&module_admitted, MODULE_PARAMETER_DIRECTION_HEADING),
        ] {
            assert_eq!(
                prompt.matches(&format!("## {heading}")).count(),
                1,
                "the admissions never open a second {heading} section"
            );
        }
        assert_eq!(
            escalate_admitted.matches("Coverage:").count(),
            escalate_clean.matches("Coverage:").count() + 5,
            "five admission lines across five escalate sections — the one \
             type-inference record qualifies type information and calling \
             convention there — never a paragraph"
        );
        assert_eq!(
            module_admitted.matches("Coverage:").count(),
            module_clean.matches("Coverage:").count() + 2,
            "the one type-inference record qualifies exactly two module-context surfaces"
        );
        assert_eq!(
            module_admitted
                .matches(&format!("Coverage: {TYPEINFER_ADMISSION}"))
                .count(),
            2,
            "the type-inference admission renders byte-identically on the calling \
             convention surface and the parameter direction surface"
        );
    }

    /// The type information surface's two tier consumers use the same
    /// record too: one type-inference admission renders identical bytes in
    /// the type information section of the rich and detailed templates
    /// (issue #351).
    #[test]
    fn the_type_inference_admission_qualifies_its_third_surface_identically_on_both_tiers() {
        let req = sample_request();
        let admitted_line = format!("Coverage: {TYPEINFER_ADMISSION}");
        for complexity in [FunctionComplexity::Rich, FunctionComplexity::Detailed] {
            let mut data = ComplexityPromptData::from_request(&req);
            data.type_info = type_info_pair();
            let clean = build_complexity_prompt(&complexity, &data).expect("tier prompt renders");
            data.type_inference_coverage = CoverageInfo::from(&typeinfer_admitting_coverage());
            let admitted = build_complexity_prompt(&complexity, &data)
                .expect("tier prompt with admitted coverage renders");
            assert_eq!(
                admitted,
                clean.replace(
                    &format!("{TYPE_INFORMATION_SECTION_BODY}\n\n"),
                    &format!("{TYPE_INFORMATION_SECTION_BODY}\n\n{admitted_line}\n\n")
                ),
                "{complexity:?} appends exactly the one shared qualification line"
            );
            assert_eq!(
                admitted.matches(&admitted_line).count(),
                1,
                "{complexity:?} carries the type-inference admission exactly once"
            );
        }
    }

    /// The doctrine pair for all four engines (issue #351): an unmentioned
    /// function under a complete record means examined-and-clean, and
    /// silence from a record that names bodies it never reached must never
    /// render the same bytes — a retry or a module translation can tell
    /// "this function has no such findings" from "the scan never read
    /// this function".
    #[test]
    fn empty_algorithm_string_typeinfer_and_serialize_findings_under_complete_and_partial_coverage_never_render_alike()
     {
        let under_complete = (
            render_escalate_full(&EvidenceBundle::default()),
            render_module_context_full(&EvidenceBundle::default()),
        );
        for (prompt, heading) in [
            (&under_complete.0, ESCALATE_RECOGNIZED_ALGORITHMS_HEADING),
            (&under_complete.0, ESCALATE_STRING_CONTEXT_HEADING),
            (&under_complete.0, ESCALATE_SERIALIZATION_HEADING),
            (&under_complete.0, ESCALATE_CALLING_CONVENTION_HEADING),
            (&under_complete.1, MODULE_CALLING_CONVENTION_HEADING),
            (&under_complete.1, MODULE_PARAMETER_DIRECTION_HEADING),
        ] {
            assert!(
                !prompt.contains(&format!("## {heading}")),
                "silence from an unstamped record stays section-less, as before P19"
            );
        }
        let escalate_partial = render_escalate_full(&EvidenceBundle {
            algorithm_coverage: CoverageInfo::from(&algorithm_admitting_coverage()),
            string_context_coverage: CoverageInfo::from(&stringctx_admitting_coverage()),
            type_inference_coverage: CoverageInfo::from(&typeinfer_admitting_coverage()),
            serialization_coverage: CoverageInfo::from(&serialize_admitting_coverage()),
            ..Default::default()
        });
        let module_partial = render_module_context_full(&EvidenceBundle {
            type_inference_coverage: CoverageInfo::from(&typeinfer_admitting_coverage()),
            ..Default::default()
        });
        assert_ne!(
            under_complete.0, escalate_partial,
            "empty findings under a falling-short record must render observably \
             different bytes than the same emptiness under a complete one"
        );
        assert_ne!(
            under_complete.1, module_partial,
            "empty findings under a falling-short record must render observably \
             different bytes than the same emptiness under a complete one"
        );
        for (prompt, heading, admission) in [
            (
                &escalate_partial,
                ESCALATE_RECOGNIZED_ALGORITHMS_HEADING,
                ALGORITHM_ADMISSION,
            ),
            (
                &escalate_partial,
                ESCALATE_STRING_CONTEXT_HEADING,
                STRINGCTX_ADMISSION,
            ),
            (
                &escalate_partial,
                ESCALATE_SERIALIZATION_HEADING,
                SERIALIZE_ADMISSION,
            ),
            (
                &escalate_partial,
                ESCALATE_CALLING_CONVENTION_HEADING,
                TYPEINFER_ADMISSION,
            ),
            (
                &module_partial,
                MODULE_CALLING_CONVENTION_HEADING,
                TYPEINFER_ADMISSION,
            ),
            (
                &module_partial,
                MODULE_PARAMETER_DIRECTION_HEADING,
                TYPEINFER_ADMISSION,
            ),
        ] {
            assert!(
                prompt.contains(&format!("## {heading}\n\nCoverage: {admission}\n\n")),
                "the empty list still carries the one admission line"
            );
        }
    }

    // -- admitted coverage: the global-state, error-handling, and callback
    //    sections (issue #350) --

    /// Coverage records in the shape these three scans file: each one's
    /// single `function-bodies` facet fell short, naming the bodies the
    /// decompiler never produced — never an examined-and-clean body the
    /// finding list left unmentioned. Each engine names different bodies,
    /// so if one engine's coverage value appears in another engine's
    /// section, every pin below fails.
    fn globalstate_admitting_coverage() -> calxgloss_types::ScanCoverage {
        calxgloss_types::ScanCoverage {
            status: calxgloss_types::CoverageStatus::Partial,
            facets: vec![calxgloss_types::FacetCoverage {
                id: "function-bodies".to_string(),
                status: calxgloss_types::CoverageStatus::Partial,
                limitation: Some("1 function body unreached: FUN_180045670".to_string()),
            }],
        }
    }

    fn errhandling_admitting_coverage() -> calxgloss_types::ScanCoverage {
        calxgloss_types::ScanCoverage {
            status: calxgloss_types::CoverageStatus::Partial,
            facets: vec![calxgloss_types::FacetCoverage {
                id: "function-bodies".to_string(),
                status: calxgloss_types::CoverageStatus::Partial,
                limitation: Some(
                    "2 function bodies unreached: FUN_18004abcd, FUN_18006beef".to_string(),
                ),
            }],
        }
    }

    fn callback_admitting_coverage() -> calxgloss_types::ScanCoverage {
        calxgloss_types::ScanCoverage {
            status: calxgloss_types::CoverageStatus::Partial,
            facets: vec![calxgloss_types::FacetCoverage {
                id: "function-bodies".to_string(),
                status: calxgloss_types::CoverageStatus::Partial,
                limitation: Some("1 function body unreached: FUN_180050001".to_string()),
            }],
        }
    }

    /// The one qualification wording each section suite pins for its
    /// engine's section (issue #350).
    const GLOBALSTATE_ADMISSION: &str = "partial — 1 function body unreached: FUN_180045670";
    const ERRHANDLING_ADMISSION: &str =
        "partial — 2 function bodies unreached: FUN_18004abcd, FUN_18006beef";
    const CALLBACK_ADMISSION: &str = "partial — 1 function body unreached: FUN_180050001";

    /// The headings the consuming templates pass each section.
    const ESCALATE_GLOBAL_STATE_HEADING: &str = "ADDITIONAL CONTEXT — GLOBAL STATE";
    const MODULE_GLOBAL_STATE_HEADING: &str = "GLOBAL STATE";
    const ESCALATE_CALLBACKS_HEADING: &str = "ADDITIONAL CONTEXT — CALLBACKS";
    const ESCALATE_ERROR_HANDLING_HEADING: &str = "ADDITIONAL CONTEXT — ERROR HANDLING";
    const MODULE_ERROR_HANDLING_HEADING: &str = "ERROR HANDLING";

    /// The error-handling section's body as each host template renders it
    /// inline. The steering wording genuinely differs between the retry
    /// prompt and the module translation, so this is the one section kept
    /// inline rather than moved onto an include; each copy is pinned
    /// beside its own steering (issue #350). Both rows below are what
    /// `seh_finding()` and `code_finding()` render, in list order.
    const ERROR_HANDLING_ROWS: &str = "- **translate the frame as a Rust match arms ladder** (try/catch frame idiom, confidence 100)\n  \
        Evidence: `  catch(...) {`\n\n\
        - **failure code 0x80070057** (failure code from a `return` site, confidence 85)\n  \
        Evidence: `  mov eax, 80070057h`";
    const ESCALATE_ERROR_HANDLING_BODY: &str = "The error-handling contract this function's body carries, read by static\n\
        analysis — the same findings the first attempt saw. Translate the idiom into\n\
        the suggested Rust shape — an exception-mapped error type for a try/catch\n\
        frame, early returns plus RAII or scope guards for a cleanup ladder — and\n\
        surface the failure codes below as the numeric codes of the Rust error values\n\
        the function hands back; a divergence here is usually the translation dropping\n\
        or reshaping this contract:";
    const MODULE_ERROR_HANDLING_BODY: &str = "The error-handling contract this function's body carries, read by static\n\
        analysis. Where a finding is credible, translate the idiom into the suggested\n\
        Rust shape — an exception-mapped error type for a try/catch frame, early\n\
        returns plus RAII or scope guards for a cleanup ladder — instead of flattening\n\
        the guarded block into straight-line logic, and surface the failure codes\n\
        below as the numeric codes of the Rust error values the function hands back\n\
        instead of collapsing them into ad-hoc error variants:";

    /// The pinned wording is checked at both ends for all three engines:
    /// the shared coverage type produces it from the records their scans
    /// stamp, and the rendered prompt shows those same lines verbatim.
    #[test]
    fn the_global_state_error_handling_and_callback_admission_wording_is_pinned_at_both_ends() {
        assert_eq!(
            globalstate_admitting_coverage()
                .admission()
                .expect("partial admits"),
            GLOBALSTATE_ADMISSION,
            "the shared type's own admission is the pinned line"
        );
        assert_eq!(
            CoverageInfo::from(&globalstate_admitting_coverage()).admission,
            GLOBALSTATE_ADMISSION,
            "the template-side view carries the same line, word for word"
        );
        assert_eq!(
            errhandling_admitting_coverage()
                .admission()
                .expect("partial admits"),
            ERRHANDLING_ADMISSION,
            "the shared type's own admission is the pinned line"
        );
        assert_eq!(
            CoverageInfo::from(&errhandling_admitting_coverage()).admission,
            ERRHANDLING_ADMISSION,
            "the template-side view carries the same line, word for word"
        );
        assert_eq!(
            callback_admitting_coverage()
                .admission()
                .expect("partial admits"),
            CALLBACK_ADMISSION,
            "the shared type's own admission is the pinned line"
        );
        assert_eq!(
            CoverageInfo::from(&callback_admitting_coverage()).admission,
            CALLBACK_ADMISSION,
            "the template-side view carries the same line, word for word"
        );
    }

    /// A complete coverage record is nothing to admit: the three sections
    /// render byte-for-byte what they rendered when their documents
    /// stated no coverage at all, at every consumer of each (issue #350).
    #[test]
    fn a_complete_coverage_record_renders_the_global_state_error_handling_and_callback_sections_byte_identically()
     {
        let mut bundle = EvidenceBundle::default();
        bundle.global_state_findings.push(global_state_fixture());
        bundle
            .error_handling_findings
            .extend([seh_finding(), code_finding()]);
        bundle.callback_findings.push(callback_fixture());
        let unstamped = (
            render_escalate_full(&bundle),
            render_module_context_full(&bundle),
        );
        let complete = CoverageInfo::from(&calxgloss_types::ScanCoverage {
            status: calxgloss_types::CoverageStatus::Complete,
            facets: Vec::new(),
        });
        bundle.global_state_coverage = complete.clone();
        bundle.error_handling_coverage = complete.clone();
        bundle.callback_coverage = complete;
        let stamped = (
            render_escalate_full(&bundle),
            render_module_context_full(&bundle),
        );
        assert_eq!(unstamped, stamped, "a complete record adds no bytes");
        assert!(
            !stamped.0.contains("Coverage:") && !stamped.1.contains("Coverage:"),
            "complete coverage has nothing to admit"
        );
    }

    /// A falling-short record for each engine appends exactly one bounded
    /// qualification line beside its own entries at each of the
    /// section's consumers. The admission joins the section without
    /// replacing or reflowing it, and one line is the whole growth
    /// allowed (issue #350).
    #[test]
    fn the_global_state_error_handling_and_callback_rides_append_exactly_one_qualification_line() {
        let mut bundle = EvidenceBundle::default();
        bundle.global_state_findings.push(global_state_fixture());
        bundle
            .error_handling_findings
            .extend([seh_finding(), code_finding()]);
        bundle.callback_findings.push(callback_fixture());
        let escalate_clean = render_escalate_full(&bundle);
        let module_clean = render_module_context_full(&bundle);

        bundle.global_state_coverage = CoverageInfo::from(&globalstate_admitting_coverage());
        bundle.error_handling_coverage = CoverageInfo::from(&errhandling_admitting_coverage());
        bundle.callback_coverage = CoverageInfo::from(&callback_admitting_coverage());
        let escalate_admitted = render_escalate_full(&bundle);
        let module_admitted = render_module_context_full(&bundle);

        let escalate_expected = escalate_clean
            .replace(
                &format!("{GLOBAL_STATE_STEERING}\n\n{GLOBAL_STATE_ENTRY}\n\n"),
                &format!(
                    "{GLOBAL_STATE_STEERING}\n\n{GLOBAL_STATE_ENTRY}\n\nCoverage: {GLOBALSTATE_ADMISSION}\n\n"
                ),
            )
            .replace(
                &format!("{ESCALATE_ERROR_HANDLING_BODY}\n\n{ERROR_HANDLING_ROWS}\n\n"),
                &format!(
                    "{ESCALATE_ERROR_HANDLING_BODY}\n\n{ERROR_HANDLING_ROWS}\n\nCoverage: {ERRHANDLING_ADMISSION}\n\n"
                ),
            )
            .replace(
                &format!("{CALLBACKS_SECTION_BODY}\n\n"),
                &format!("{CALLBACKS_SECTION_BODY}\n\nCoverage: {CALLBACK_ADMISSION}\n\n"),
            );
        assert_eq!(
            escalate_admitted, escalate_expected,
            "each admission appears in its own escalate section as exactly one line beside the entries"
        );
        let module_expected = module_clean
            .replace(
                &format!("{GLOBAL_STATE_STEERING}\n\n{GLOBAL_STATE_ENTRY}\n\n"),
                &format!(
                    "{GLOBAL_STATE_STEERING}\n\n{GLOBAL_STATE_ENTRY}\n\nCoverage: {GLOBALSTATE_ADMISSION}\n\n"
                ),
            )
            .replace(
                &format!("{MODULE_ERROR_HANDLING_BODY}\n\n{ERROR_HANDLING_ROWS}\n\n"),
                &format!(
                    "{MODULE_ERROR_HANDLING_BODY}\n\n{ERROR_HANDLING_ROWS}\n\nCoverage: {ERRHANDLING_ADMISSION}\n\n"
                ),
            );
        assert_eq!(
            module_admitted, module_expected,
            "each admission appears in its own module-context section as exactly one line beside the entries"
        );
        for (prompt, heading) in [
            (&escalate_admitted, ESCALATE_GLOBAL_STATE_HEADING),
            (&escalate_admitted, ESCALATE_CALLBACKS_HEADING),
            (&escalate_admitted, ESCALATE_ERROR_HANDLING_HEADING),
            (&module_admitted, MODULE_GLOBAL_STATE_HEADING),
            (&module_admitted, MODULE_ERROR_HANDLING_HEADING),
        ] {
            assert_eq!(
                prompt.matches(&format!("## {heading}")).count(),
                1,
                "the admissions never open a second {heading} section"
            );
        }
        assert_eq!(
            escalate_admitted.matches("Coverage:").count(),
            escalate_clean.matches("Coverage:").count() + 3,
            "three admission lines across three sections, never a paragraph"
        );
        assert_eq!(
            module_admitted.matches("Coverage:").count(),
            module_clean.matches("Coverage:").count() + 2,
            "two admission lines across two sections, never a paragraph"
        );
    }

    /// The doctrine pair for all three engines (issue #350): an
    /// unmentioned function under a complete record means examined-and-
    /// clean, and silence from a record that names bodies it never
    /// reached must never render the same bytes — a retry or a module
    /// translation can tell "this function has no such findings" from
    /// "the scan never read this function".
    #[test]
    fn empty_global_state_error_handling_and_callback_findings_under_complete_and_partial_coverage_never_render_alike()
     {
        let under_complete = (
            render_escalate_full(&EvidenceBundle::default()),
            render_module_context_full(&EvidenceBundle::default()),
        );
        for (prompt, heading) in [
            (&under_complete.0, ESCALATE_GLOBAL_STATE_HEADING),
            (&under_complete.0, ESCALATE_CALLBACKS_HEADING),
            (&under_complete.0, ESCALATE_ERROR_HANDLING_HEADING),
            (&under_complete.1, MODULE_GLOBAL_STATE_HEADING),
            (&under_complete.1, MODULE_ERROR_HANDLING_HEADING),
        ] {
            assert!(
                !prompt.contains(&format!("## {heading}")),
                "silence from an unstamped record stays section-less, as before P19"
            );
        }
        let escalate_partial = render_escalate_full(&EvidenceBundle {
            global_state_coverage: CoverageInfo::from(&globalstate_admitting_coverage()),
            error_handling_coverage: CoverageInfo::from(&errhandling_admitting_coverage()),
            callback_coverage: CoverageInfo::from(&callback_admitting_coverage()),
            ..Default::default()
        });
        let module_partial = render_module_context_full(&EvidenceBundle {
            global_state_coverage: CoverageInfo::from(&globalstate_admitting_coverage()),
            error_handling_coverage: CoverageInfo::from(&errhandling_admitting_coverage()),
            ..Default::default()
        });
        assert_ne!(
            under_complete.0, escalate_partial,
            "empty findings under a falling-short record must render observably \
             different bytes than the same emptiness under a complete one"
        );
        assert_ne!(
            under_complete.1, module_partial,
            "empty findings under a falling-short record must render observably \
             different bytes than the same emptiness under a complete one"
        );
        for (prompt, heading, admission) in [
            (
                &escalate_partial,
                ESCALATE_GLOBAL_STATE_HEADING,
                GLOBALSTATE_ADMISSION,
            ),
            (
                &escalate_partial,
                ESCALATE_CALLBACKS_HEADING,
                CALLBACK_ADMISSION,
            ),
            (
                &escalate_partial,
                ESCALATE_ERROR_HANDLING_HEADING,
                ERRHANDLING_ADMISSION,
            ),
            (
                &module_partial,
                MODULE_GLOBAL_STATE_HEADING,
                GLOBALSTATE_ADMISSION,
            ),
            (
                &module_partial,
                MODULE_ERROR_HANDLING_HEADING,
                ERRHANDLING_ADMISSION,
            ),
        ] {
            assert!(
                prompt.contains(&format!("## {heading}\n\nCoverage: {admission}\n\n")),
                "the empty list still carries the one admission line"
            );
        }
    }

    /// The track-level doctrine pair (issue #352): one sweep over every
    /// engine on the P19 track. For each, an empty findings list under a
    /// complete record renders byte-identically to the unstamped silence
    /// P19 shipped on — and never the same bytes as the same emptiness
    /// under that engine's own falling-short record, whose section shows
    /// its one admission line. Tickets #346-#351 each pinned a pair for
    /// their own engine; this sweep is the track statement that no engine
    /// was left out, one failure report naming the engine that broke it.
    ///
    /// typesdb is the one row whose pair has its own established shape
    /// (issue #348): with no structures recovered the section stays shut
    /// under either record — zero vtables is a property of the target,
    /// not a gap beside entries — so the typesdb pair uses populated
    /// structures, pinned after the sweep.
    #[test]
    fn the_whole_track_renders_empty_findings_under_complete_and_falling_short_coverage_never_alike()
     {
        type Render = fn(&EvidenceBundle) -> String;
        type Load = fn(&mut EvidenceBundle, CoverageInfo);
        type Coverage = fn() -> calxgloss_types::ScanCoverage;
        let rows: [(&str, Render, Load, Coverage, &str, &str); 14] = [
            (
                "library-api",
                render_escalate_full,
                |b, c| b.api_coverage = c,
                api_admitting_coverage,
                LIBRARIES_APIS_HEADING,
                API_ADMISSION,
            ),
            (
                "known-library",
                render_module_context_full,
                |b, c| b.libmatch_coverage = c,
                libmatch_admitting_coverage,
                KNOWN_LIBRARY_HEADING,
                LIBMATCH_ADMISSION,
            ),
            (
                "float-simd",
                render_escalate_full,
                |b, c| b.floatsimd_coverage = c,
                floatsimd_admitting_coverage,
                ESCALATE_FLOATSIMD_HEADING,
                FLOATSIMD_ADMISSION,
            ),
            (
                "constants",
                render_escalate_full,
                |b, c| b.consts_coverage = c,
                consts_partial_coverage,
                ESCALATE_CONSTANTS_HEADING,
                CONSTS_ADMISSION,
            ),
            (
                "control-flow",
                render_escalate_full,
                |b, c| b.control_flow_coverage = c,
                control_flow_admitting_coverage,
                ESCALATE_CONTROL_FLOW_HEADING,
                CONTROL_FLOW_ADMISSION,
            ),
            (
                "memory-lifecycle",
                render_escalate_full,
                |b, c| b.memory_coverage = c,
                memory_admitting_coverage,
                ESCALATE_MEMORY_HEADING,
                MEMORY_ADMISSION,
            ),
            (
                "concurrency",
                render_escalate_full,
                |b, c| b.sync_coverage = c,
                sync_admitting_coverage,
                ESCALATE_CONCURRENCY_HEADING,
                SYNC_ADMISSION,
            ),
            (
                "global-state",
                render_escalate_full,
                |b, c| b.global_state_coverage = c,
                globalstate_admitting_coverage,
                ESCALATE_GLOBAL_STATE_HEADING,
                GLOBALSTATE_ADMISSION,
            ),
            (
                "error-handling",
                render_escalate_full,
                |b, c| b.error_handling_coverage = c,
                errhandling_admitting_coverage,
                ESCALATE_ERROR_HANDLING_HEADING,
                ERRHANDLING_ADMISSION,
            ),
            (
                "callback-detection",
                render_escalate_full,
                |b, c| b.callback_coverage = c,
                callback_admitting_coverage,
                ESCALATE_CALLBACKS_HEADING,
                CALLBACK_ADMISSION,
            ),
            (
                "algorithm-recognition",
                render_escalate_full,
                |b, c| b.algorithm_coverage = c,
                algorithm_admitting_coverage,
                ESCALATE_RECOGNIZED_ALGORITHMS_HEADING,
                ALGORITHM_ADMISSION,
            ),
            (
                "string-context",
                render_escalate_full,
                |b, c| b.string_context_coverage = c,
                stringctx_admitting_coverage,
                ESCALATE_STRING_CONTEXT_HEADING,
                STRINGCTX_ADMISSION,
            ),
            (
                "serialization",
                render_escalate_full,
                |b, c| b.serialization_coverage = c,
                serialize_admitting_coverage,
                ESCALATE_SERIALIZATION_HEADING,
                SERIALIZE_ADMISSION,
            ),
            (
                // The empty type-inference admission appears on its
                // convention and parameter-direction sections — the
                // escalate heading the #351 pin established.
                "type-inference",
                render_escalate_full,
                |b, c| b.type_inference_coverage = c,
                typeinfer_admitting_coverage,
                ESCALATE_CALLING_CONVENTION_HEADING,
                TYPEINFER_ADMISSION,
            ),
        ];
        for (engine, render, set_coverage, admitting, heading, admission) in rows {
            let mut under_complete = EvidenceBundle::default();
            set_coverage(
                &mut under_complete,
                CoverageInfo::from(&complete_coverage()),
            );
            assert_eq!(
                render(&under_complete),
                render(&EvidenceBundle::default()),
                "{engine}: a complete record beside empty findings adds no bytes \
                 to the render"
            );
            let mut under_falling_short = EvidenceBundle::default();
            set_coverage(&mut under_falling_short, CoverageInfo::from(&admitting()));
            assert_ne!(
                render(&under_complete),
                render(&under_falling_short),
                "{engine}: empty findings under a complete record and under the \
                 engine's falling-short record must never render the same bytes"
            );
            assert!(
                render(&under_falling_short)
                    .contains(&format!("## {heading}\n\nCoverage: {admission}\n\n")),
                "{engine}: the falling-short side carries its one admission line \
                 under its heading"
            );
        }

        // The typesdb row, per its established shape (#348): the pair
        // uses populated structures — complete adds nothing,
        // falling-short adds its one line.
        let mut structures = EvidenceBundle::default();
        structures
            .data_structures
            .extend(data_structures_fixtures());
        let unstamped = render_escalate_full(&structures);
        structures.type_database_coverage = CoverageInfo::from(&complete_coverage());
        let under_complete = render_escalate_full(&structures);
        assert_eq!(
            under_complete, unstamped,
            "type-database: a complete record beside the structures adds no bytes"
        );
        structures.type_database_coverage = CoverageInfo::from(&typesdb_unavailable_coverage());
        let under_falling_short = render_escalate_full(&structures);
        assert_ne!(
            under_complete, under_falling_short,
            "type-database: findings under a complete record and under the \
             engine's falling-short record must never render the same bytes"
        );
        assert!(
            under_falling_short.contains(&format!("Coverage: {TYPESDB_ADMISSION}")),
            "type-database: the falling-short side carries its one admission line \
             beside the entries — its exact position is pinned by the #348 pair"
        );
    }

    /// Scans template source for `{% import "<path>" as <scope> %}`
    /// directives, returning each (path, scope) pair.
    fn imported_sections(source: &str) -> Vec<(&str, &str)> {
        let mut found = Vec::new();
        let mut rest = source;
        while let Some(start) = rest.find("{%") {
            let tag = &rest[start + 2..];
            let Some(end) = tag.find("%}") else {
                break;
            };
            let inner = tag[..end].trim().trim_start_matches(['-', '+', '~']).trim();
            if let Some(after) = inner.strip_prefix("import").map(str::trim) {
                let mut parts = after.split_whitespace();
                let path = parts
                    .next()
                    .and_then(|p| p.strip_prefix('"').and_then(|p| p.strip_suffix('"')));
                let scope = parts
                    .next()
                    .filter(|p| *p == "as")
                    .and_then(|_| parts.next());
                if let (Some(path), Some(scope)) = (path, scope) {
                    found.push((path, scope));
                }
            }
            rest = &rest[start + 2..];
        }
        found
    }

    /// The include roster — P35's projector-roster pattern moved to the
    /// render side: the (template × section) include set across the template
    /// tree is exactly the rows of the section suite above, and every
    /// imported scope must actually be called. A forgotten or
    /// accidentally dropped include fails here loudly, instead of silently
    /// making a prompt smaller.
    #[test]
    fn the_template_section_include_set_is_exactly_the_registered_rows() {
        let templates_dir = std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/templates"));
        let mut discovered: Vec<(String, String)> = Vec::new();
        let mut dangling: Vec<(String, String)> = Vec::new();
        let mut dirs = vec![templates_dir.to_path_buf()];
        while let Some(dir) = dirs.pop() {
            for entry in std::fs::read_dir(&dir).expect("the templates dir is readable") {
                let path = entry.expect("a readable template entry").path();
                if path.is_dir() {
                    dirs.push(path);
                    continue;
                }
                if path.extension().and_then(|e| e.to_str()) != Some("j2") {
                    continue;
                }
                let source = std::fs::read_to_string(&path).expect("a readable template file");
                let template = path
                    .strip_prefix(templates_dir)
                    .expect("the template lives under templates/")
                    .to_string_lossy()
                    .into_owned();
                for (section, scope) in imported_sections(&source) {
                    discovered.push((template.clone(), section.to_string()));
                    if !source.contains(&format!("{scope}::")) {
                        dangling.push((template.clone(), section.to_string()));
                    }
                }
            }
        }
        assert!(
            dangling.is_empty(),
            "every imported section must be called by its importing template: {dangling:?}"
        );
        discovered.sort();
        let mut expected: Vec<(String, String)> = SECTION_SUITE_ROWS
            .iter()
            .map(|row| (row.template.to_string(), row.section.to_string()))
            .collect();
        expected.sort();
        assert_eq!(
            discovered, expected,
            "the (template × section) include roster changed — a section joins a \
             template by adding an import/call pair in the template and a section-\
             suite row together, and this roster moves only with them"
        );
    }

    /// The bundle carries the ledger's whole open list, but the include
    /// owns the render bound (issue #370): the first five records ride
    /// in ledger order, the sixth and later never render at all, and the
    /// remainder folds into exactly one count line beside the listed
    /// five — the P19 five-names-plus-count discipline, kept by the
    /// escalate reader.
    #[test]
    fn open_unknowns_render_in_ledger_order_and_fold_the_remainder_into_one_count_line() {
        let bundle = EvidenceBundle {
            open_unknowns: (0..7)
                .map(|n| UnknownInfo {
                    question: format!("question-{n}?"),
                    required_evidence: format!("evidence-{n}"),
                })
                .collect(),
            ..EvidenceBundle::default()
        };
        let prompt = render_escalate_full(&bundle);
        assert_eq!(
            prompt.matches("## OPEN UNKNOWNS").count(),
            1,
            "the section opens exactly once however many records the ledger filed"
        );
        let mut cursor = 0;
        for n in 0..5 {
            let needle = format!("- question-{n}?");
            let at = cursor
                + prompt[cursor..]
                    .find(&needle)
                    .unwrap_or_else(|| panic!("`{needle}` must render"));
            assert!(
                !prompt[cursor..at].contains("- question-"),
                "`question-{n}` is the entry right after the previous one — the \
                 list rides in ledger order, never a sorted or grouped one"
            );
            cursor = at + needle.len();
        }
        for n in 5..7 {
            assert!(
                !prompt.contains(&format!("question-{n}?")),
                "the sixth and later open records never render their question"
            );
            assert!(
                !prompt.contains(&format!("evidence-{n}")),
                "the sixth and later open records never render their evidence line"
            );
        }
        assert_eq!(
            prompt
                .matches("(+2 more open questions not listed)")
                .count(),
            1,
            "the remainder folds into exactly one count line"
        );
        assert!(
            !prompt.contains("\n\n\n"),
            "the folded section leaves no stray blank lines"
        );
    }

    /// A unit with forty open gaps still keeps the section bounded
    /// (issue #370): every bundle-fed reader renders exactly the first
    /// five questions, names none of the other thirty-five, and folds
    /// them into one count line.
    #[test]
    fn forty_open_unknowns_keep_the_section_bounded_in_every_reader() {
        let bundle = EvidenceBundle {
            open_unknowns: (0..40)
                .map(|n| UnknownInfo {
                    question: format!("question-{n}?"),
                    required_evidence: format!("evidence-{n}"),
                })
                .collect(),
            ..EvidenceBundle::default()
        };
        for render in [
            render_escalate_full,
            render_module_context_full,
            render_full_module_full,
        ] {
            let prompt = render(&bundle);
            assert_eq!(
                prompt.matches("## OPEN UNKNOWNS").count(),
                1,
                "the section opens exactly once"
            );
            for n in 0..5 {
                assert!(
                    prompt.contains(&format!("- question-{n}?")),
                    "the first five open questions ride in, question-{n} missing"
                );
            }
            for n in 5..40 {
                assert!(
                    !prompt.contains(&format!("question-{n}?")),
                    "question-{n} sits past the bound and never renders"
                );
            }
            assert_eq!(
                prompt
                    .matches("(+35 more open questions not listed)")
                    .count(),
                1,
                "the thirty-five hidden records fold into exactly one count line"
            );
            assert!(
                !prompt.contains("\n\n\n"),
                "the bounded section leaves no stray blank lines"
            );
        }
    }
}
