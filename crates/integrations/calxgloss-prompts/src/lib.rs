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
    ComplexityPromptData, DisassemblyPromptData, SignaturePromptData, WithTestsPromptData,
};
pub use error::PromptError;
pub use templates::{
    AlgorithmInfo, ApiInfo, BoundaryValue, CallGraphNeighbor, CallbackInfo, ConcurrencyInfo,
    ConstInfo, ControlFlowInfo, ConventionInfo, CoverageInfo, DataTableInfo, EdgeCaseTemplate,
    EdgeCaseTest, ErrhandlingInfo, EscalateTemplate, EvidenceBundle, FixTemplate, FloatsimdInfo,
    FormattedTestResult, FullModuleTemplate, GlobalStateInfo, LibmatchInfo, MemoryInfo,
    MinimalTemplate, ModuleContextTemplate, NeighborFunction, PalTraitDef, PalTraitMethod,
    ParameterDirectionInfo, SerializationInfo, ShimCode, SignatureTemplate, StringContextInfo,
    StructField, StructuredData, TestCaseFormatted, TranslateTemplate, TypeInfo, WithTestsTemplate,
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
        // first attempt: the inventory records ride the escalate CONTROL
        // FLOW section carrying kind, suggestion, confidence, and evidence.
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
        // The purity flag renders as the steering: a function with
        // global accesses is pushed to struct state, never a static.
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
        // so a retry after a divergence does not re-scatter the table.
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
        // A function's branch inventory rides the same CONTROL FLOW
        // section as the other findings: each branch site is named by
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
        // The purity flag renders as the steering: a function with
        // global accesses is pushed to struct state, never a static.
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
        // The steering renders as the section's point: mangled vector
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
            // a version-authority note, so the fixture carries none —
            // the pinned render stays byte-identical, and a note-bearing
            // finding renders one extra "Admission:" line, pinned beside.
            admission: String::new(),
        }
    }

    #[test]
    fn test_module_context_template_renders_known_library_section() {
        // The section names the matched callee by symbol, family, and
        // confidence, and steers the call onto the Rust equivalent.
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
        // Each record names its parameter, its direction, and the body
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
        // The section steers the signature shape the readings name.
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
        };

        let prompt = build_complexity_prompt(&FunctionComplexity::Rich, &data)
            .expect("the rich prompt should render");

        assert!(!prompt.contains("CONTROL FLOW PATTERNS"));
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
        };

        let prompt = build_complexity_prompt(&FunctionComplexity::Detailed, &data)
            .expect("the detailed prompt should render");

        assert!(!prompt.contains("CONTROL FLOW PATTERNS"));
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

    fn type_info_pair() -> Vec<TypeInfo> {
        // The two readings one pointer parameter's records render through
        // the typeinfer union's prompt conversion (issue #274): the type
        // reading and the direction reading, both naming the parameter,
        // so the pair lands side by side in one section (issue #276).
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
        // existing type-info section carries both lines, and no separate
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
            "directions ride the existing section, not a new one"
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
        };

        let prompt = build_complexity_prompt(&FunctionComplexity::Rich, &data)
            .expect("the rich prompt should render");

        assert!(prompt.contains("TYPE INFORMATION"));
        assert!(prompt.contains("- `param_1`: char * (via string_function, confidence 70)"));
        assert!(prompt.contains("- `param_1`: out parameter (via param_direction, confidence 75)"));
        assert!(
            !prompt.contains("PARAMETER DIRECTION"),
            "directions ride the existing section, not a new one"
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
        };

        let prompt = build_complexity_prompt(&FunctionComplexity::Detailed, &data)
            .expect("the detailed prompt should render");

        assert!(prompt.contains("TYPE INFORMATION"));
        assert!(prompt.contains("- `param_1`: char * (via string_function, confidence 70)"));
        assert!(prompt.contains("- `param_1`: out parameter (via param_direction, confidence 75)"));
        assert!(
            !prompt.contains("PARAMETER DIRECTION"),
            "directions ride the existing section, not a new one"
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
        // literal, with the site it surfaced at named.
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

        // The raise idiom bullet names the code it raises inline.
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

        // The inherited-code bullet names the code and the partner that
        // hands it up.
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
    /// pinned byte-for-byte from the pre-include renders: the lift into
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

    // Fixtures for the sections lifted onto shared includes by #318. Each
    // one feeds a single finding (or pair) of the matching bundle list so
    // the section suite renders one section per template run.

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

    /// The structures the type database feeds the shared include: two of
    /// them, so the pinned body covers the blank line the include keeps
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

    /// Renders the escalate template against an arbitrary bundle — the
    /// escalate call sites of the shared includes all live in this one
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

    /// Renders the rich template against an arbitrary bundle — the tier
    /// templates render from their request-sourced finding lists rather
    /// than from a gathered bundle, so this helper carries the include-fed
    /// lists out of the bundle into the tier's prompt data (#319).
    fn render_rich_full(bundle: &EvidenceBundle) -> String {
        let req = sample_request();
        let mut data = ComplexityPromptData::from_request(&req);
        data.type_info = bundle.type_info.clone();
        data.control_flow_findings = bundle.control_flow_findings.clone();
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
        build_complexity_prompt(&FunctionComplexity::Detailed, &data)
            .expect("the detailed prompt should render")
    }

    /// #320: with a wholly empty bundle the escalate template shows no
    /// evidence section at all — every one of its headings carries the
    /// `## ADDITIONAL CONTEXT — ` prefix — and leaves no stray blank line
    /// where the sections used to be.
    #[test]
    fn empty_bundle_escalate_omits_every_evidence_section() {
        let prompt = render_escalate_full(&EvidenceBundle::default());
        assert!(!prompt.contains("## ADDITIONAL CONTEXT"));
        assert!(prompt.contains("## TRANSLATION REQUIREMENTS"));
        assert!(!prompt.contains("\n\n\n"));
    }

    /// #320: the same empty-bundle contract for the module-context
    /// template — every bundle-fed heading is absent, the request-fed
    /// sections still render, and the seams between them stay clean.
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

    /// The type information section
    /// body — steering paragraph and entries — pinned byte-for-byte from
    /// the pre-include renders, shared by its consumers (escalate, rich and
    /// detailed — the tier bodies were checked against the escalate body for
    /// identity before merging onto this one include); the
    /// section suite re-renders each consuming template against it.
    const TYPE_INFORMATION_SECTION_BODY: &str = "The following types were inferred by Ghidra's type database:\n\n- `param_1`: char * (via string_function, confidence 70)\n\n- `param_1`: out parameter (via param_direction, confidence 75)";

    fn expected_type_information_section(heading: &str) -> String {
        format!("## {heading}\n\n{TYPE_INFORMATION_SECTION_BODY}")
    }

    /// The recognized algorithms section
    /// body — steering paragraph and entries — pinned byte-for-byte from
    /// the pre-include renders, shared by its consumers (escalate); the
    /// section suite re-renders each consuming template against it.
    const RECOGNIZED_ALGORITHMS_SECTION_BODY: &str = "The following known algorithms were recognized in this function by static\nanalysis. Where a recognition is credible, implement the known algorithm\nidiomatically in Rust instead of transliterating the pseudo-C line by line:\n\n- **comparison_sort** (sorting; via cfg_pattern, confidence 70)\n  Evidence: `for (iVar1 = 0; iVar1 &#60; count; iVar1++) { if (puVar2[iVar1] &#62; puVar2[iVar1 + 1]) {`";

    fn expected_recognized_algorithms_section(heading: &str) -> String {
        format!("## {heading}\n\n{RECOGNIZED_ALGORITHMS_SECTION_BODY}")
    }

    /// The memory lifecycle section
    /// body — steering paragraph and entries — pinned byte-for-byte from
    /// the pre-include renders, shared by its consumers (escalate); the
    /// section suite re-renders each consuming template against it.
    const MEMORY_LIFECYCLE_SECTION_BODY: &str = "The following memory lifecycles were recognized in this function by static\nanalysis. Where a finding is credible, express the resource with the suggested\nRust ownership pattern instead of transliterating the manual allocate/free or\nopen/close pairs:\n\n- **RAII guard struct with Drop impl** (handle lifecycle, confidence 70)\n  Evidence: `hFile = CreateFileW(...); CloseHandle(hFile);`";

    fn expected_memory_lifecycle_section(heading: &str) -> String {
        format!("## {heading}\n\n{MEMORY_LIFECYCLE_SECTION_BODY}")
    }

    /// The concurrency section
    /// body — steering paragraph and entries — pinned byte-for-byte from
    /// the pre-include renders, shared by its consumers (escalate); the
    /// section suite re-renders each consuming template against it.
    const CONCURRENCY_SECTION_BODY: &str = "The following concurrency constructs were recognized in this function by static\nanalysis. Where a finding is credible, express the synchronization with the\nsuggested Rust type instead of transliterating the manual lock/unlock or\nspawn/join calls:\n\n- **std::sync::Mutex<T>** (mutex construct, confidence 70)\n  Evidence: `pthread_mutex_lock(&mtx); ... pthread_mutex_unlock(&mtx);`";

    fn expected_concurrency_section(heading: &str) -> String {
        format!("## {heading}\n\n{CONCURRENCY_SECTION_BODY}")
    }

    /// The serialization section
    /// body — steering paragraph and entries — pinned byte-for-byte from
    /// the pre-include renders, shared by its consumers (escalate); the
    /// section suite re-renders each consuming template against it.
    const SERIALIZATION_SECTION_BODY: &str = "The following endianness and serialization patterns were recognized in this\nfunction by static analysis — byte-swap calls, hand-rolled bit-packing chains,\nand file-format signature comparisons. Where a finding is credible, express\nthe format with the suggested Rust type or crate instead of transliterating\nthe manual swaps, shifts, and masks:\n\n- **byteorder::BE::read_u32** (byteswap pattern, confidence 70)\n  Evidence: `uVar1 = (uVar4 << 24) | ((uVar4 >> 8) & 0xff00);`";

    fn expected_serialization_section(heading: &str) -> String {
        format!("## {heading}\n\n{SERIALIZATION_SECTION_BODY}")
    }

    /// The constants section
    /// body — steering paragraph and entries — pinned byte-for-byte from
    /// the pre-include renders, shared by its consumers (escalate); the
    /// section suite re-renders each consuming template against it.
    const CONSTANTS_SECTION_BODY: &str = "The following constant structures were recognized in this function by static\nanalysis — flag-bit groups, enumerated dispatch runs, and values repeated\nacross the program. Where a finding is credible, express it with the suggested\nRust shape instead of scattering the bare integer literals:\n\n- **bitflags! struct Flags: u32** (bitflag_group, confidence 70)\n  Evidence: `if ((uVar1 & 0x10) != 0) { ... } uVar1 = uVar1 | 0x20;`";

    fn expected_constants_section(heading: &str) -> String {
        format!("## {heading}\n\n{CONSTANTS_SECTION_BODY}")
    }

    /// The callbacks section
    /// body — steering paragraph and entries — pinned byte-for-byte from
    /// the pre-include renders, shared by its consumers (escalate); the
    /// section suite re-renders each consuming template against it.
    const CALLBACKS_SECTION_BODY: &str = "The following callback and function-pointer patterns were recognized in this\nfunction by static analysis. Where a finding is credible, express the callback\nboundary with the suggested Rust pattern instead of transliterating the raw\ntable indexing or registration call:\n\n- **Vec<Box<dyn Fn(i32)>>** (fp_array pattern, confidence 70)\n  Evidence: `handlers[uVar2](iVar3);`";

    fn expected_callbacks_section(heading: &str) -> String {
        format!("## {heading}\n\n{CALLBACKS_SECTION_BODY}")
    }

    /// The control flow section
    /// body — steering paragraph and entries — pinned byte-for-byte from
    /// the pre-include renders, shared by its consumers (escalate, full-module,
    /// rich and detailed — the tier bodies were identical to the escalate body
    /// before merging); the
    /// section suite re-renders each consuming template against it.
    const CONTROL_FLOW_SECTION_BODY: &str = "The following control-flow patterns were recognized in this function by static\nanalysis. Where a finding is credible, express the construct with the suggested\nRust pattern instead of transliterating the raw conditional chain or recursive\ncall:\n\n- **enum State + match state { /* 3 states */ }** (state_machine construct, confidence 70)\n  Evidence: `state variable state with 3 states idle: STATE_IDLE`";

    fn expected_control_flow_section(heading: &str) -> String {
        format!("## {heading}\n\n{CONTROL_FLOW_SECTION_BODY}")
    }

    /// The control flow branch section
    /// body — steering paragraph and entries — pinned byte-for-byte from
    /// the pre-include renders, shared by its consumers (module-context, driven by `branch_site_fixture`); the
    /// section suite re-renders each consuming template against it.
    const CONTROL_FLOW_BRANCH_SECTION_BODY: &str = "The following control-flow patterns were recognized in this function by static\nanalysis. Where a finding is credible, express the construct with the suggested\nRust pattern instead of transliterating the raw conditional chain or recursive\ncall:\n\n- **keep the early return behind param_1 == 0** (branch_site construct, confidence 80)\n  Evidence: `if (param_1 == 0) {`";

    fn expected_control_flow_branch_section(heading: &str) -> String {
        format!("## {heading}\n\n{CONTROL_FLOW_BRANCH_SECTION_BODY}")
    }

    /// The calling convention section
    /// body — steering paragraph and entries — pinned byte-for-byte from
    /// the pre-include renders, shared by its consumers (escalate and module-context); the
    /// section suite re-renders each consuming template against it.
    const CALLING_CONVENTION_SECTION_BODY: &str = "The calling conventions detected for this function and its callees by\nstatic analysis — mangled-name letters, `@N` import decorations, callee\nepilogues, caller stack cleanup, and the x64 call shape. Spell extern\ndeclarations and any stack cleanup with the detected convention instead\nof assuming `__stdcall`, and do not invent stack cleanup for a convention\nthat leaves none:\n\n- **stdcall** (via callee_epilogue, confidence 80)\n  Evidence: `00401007  RET 0xC`";

    fn expected_calling_convention_section(heading: &str) -> String {
        format!("## {heading}\n\n{CALLING_CONVENTION_SECTION_BODY}")
    }

    /// The floatsimd section
    /// body — steering paragraph and entries — pinned byte-for-byte from
    /// the pre-include renders, shared by its consumers (escalate and module-context); the
    /// section suite re-renders each consuming template against it.
    const FLOATSIMD_SECTION_BODY: &str = "This function's body carries float/SIMD evidence, recorded by static\nanalysis — the decompiler mangles vector math into concatenations,\nextractions, and undefined-typed arithmetic, and reading it as integer\nor pointer logic mistranslates it. Translate the math as float: for a\nscalar shape use plain `f32`/`f64` operations; for a vector/matrix\nshape use component arrays or small vector structs, never packed\nintegers:\n\n- **translate as a small vector struct or component array, not integer or pointer arithmetic** (vector_matrix shape, confidence 60)\n  Evidence: `local_10 = CONCAT44(uVar2 >> 4, uVar2 & 0xfffffff);`";

    fn expected_floatsimd_section(heading: &str) -> String {
        format!("## {heading}\n\n{FLOATSIMD_SECTION_BODY}")
    }

    /// The string context section
    /// body — steering paragraph and entries — pinned byte-for-byte from
    /// the pre-include renders, shared by its consumers (escalate); the
    /// section suite re-renders each consuming template against it.
    const STRING_CONTEXT_SECTION_BODY: &str = "The following strings were mapped to this function by static analysis —\nclassified into their role, and for format-string calls the Rust argument\ntypes the specifiers imply. Where a finding is credible, name the string's\nrole in the translation instead of transliterating the raw literal or\n`DAT_` reference:\n\n- **config file path** (file_path string, confidence 70)\n  Evidence: `lFile = CreateFileA(\"Journal.txt\",...);`";

    fn expected_string_context_section(heading: &str) -> String {
        format!("## {heading}\n\n{STRING_CONTEXT_SECTION_BODY}")
    }

    /// The libraries apis section
    /// body — steering paragraph and entries — pinned byte-for-byte from
    /// the pre-include renders, shared by its consumers (escalate); the
    /// section suite re-renders each consuming template against it.
    const LIBRARIES_APIS_SECTION_BODY: &str = "The following library APIs were identified by static analysis — from the\nbinary's import table and from the call paths reaching them out of this\nfunction. Where a finding is credible, call the API through the suggested\nRust crate instead of transliterating the raw import or declaring it as an\n`extern \"C\"` stub:\n\n- **flate2** for `inflate` (zlib import, confidence 90)\n  Evidence: `inflate`";

    fn expected_libraries_apis_section(heading: &str) -> String {
        format!("## {heading}\n\n{LIBRARIES_APIS_SECTION_BODY}")
    }

    /// The libmatch section
    /// body — steering paragraph and entries — pinned byte-for-byte from
    /// the pre-include renders, shared by its consumers (module-context); the
    /// section suite re-renders each consuming template against it.
    const LIBMATCH_SECTION_BODY: &str = "The functions this one calls that static analysis has identified as\nstatically linked known-library code — the C runtime or the C++ standard\nlibrary. Do NOT re-implement these bodies: map each call onto the\nsuggested Rust equivalent instead:\n\n- **slice copy / std::ptr::copy_nonoverlapping** — `FUN_18003ab00` matches `memcpy` (crt library, confidence 90)\n  Evidence: `  *(undefined8 *)((long)puVar1 + -8) = *(undefined8 *)((long)lVar2 + -8);`";

    fn expected_libmatch_section(heading: &str) -> String {
        format!("## {heading}\n\n{LIBMATCH_SECTION_BODY}")
    }

    /// The parameter direction section
    /// body — steering paragraph and entries — pinned byte-for-byte from
    /// the pre-include renders, shared by its consumers (module-context); the
    /// section suite re-renders each consuming template against it.
    const PARAMETER_DIRECTION_SECTION_BODY: &str = "Which way data flows through this function's pointer parameters, read from\nits body by static analysis. Give each parameter the Rust shape its\ndirection names — an `in` parameter a shared borrow, an `out` parameter a\nmutable borrow or a value handed back to the caller, an `inout` parameter\na read-modify-write through a mutable borrow — and add no mutability a\ndirection reading does not claim:\n\n- **param_2 is out** (via param_direction, confidence 75)\n  Evidence: `*param_2 = 0;`";

    fn expected_parameter_direction_section(heading: &str) -> String {
        format!("## {heading}\n\n{PARAMETER_DIRECTION_SECTION_BODY}")
    }

    /// The data tables section
    /// body — steering paragraph and entries — pinned byte-for-byte from
    /// the pre-include renders, shared by its consumers (module-context); the
    /// section suite re-renders each consuming template against it.
    const DATA_TABLES_SECTION_BODY: &str = "The defined data objects this function indexes that static analysis has\nrecognized as constant data tables — objects whose bytes decode coherently\nat one element width and that nothing in the program writes. Where a\nfinding is credible, render each lookup of one of these objects as a named\n`const` array of the element type and entry count shown, indexed where the\noriginal offsets the object — do not re-scatter the decoded entries as\nmatch arms or magic numbers:\n\n- **DAT_1400a1b60**: `const [u16; 12]` (confidence 70)";

    fn expected_data_tables_section(heading: &str) -> String {
        format!("## {heading}\n\n{DATA_TABLES_SECTION_BODY}")
    }

    /// The data-structure section
    /// body — steering paragraph and entries — pinned byte-for-byte from
    /// the pre-include renders, shared by its three consumers (escalate,
    /// module-context, full-module); the section suite re-renders each
    /// consuming template against it. Two structures, so the pin covers
    /// the blank line the include keeps between them as well as each
    /// structure's size and field lines.
    const DATA_STRUCTURES_SECTION_BODY: &str = "The following data structures are used in or near this function:\n\n### Player\nSize: 16 bytes\nFields:\n\n- `hp` : u32 (offset: 0)\n\n- `mp` : u16 (offset: 4)\n\n### SaveGame\nSize: 8 bytes\nFields:\n\n- `slot` : u32 (offset: 0)";

    fn expected_data_structures_section(heading: &str) -> String {
        format!("## {heading}\n\n{DATA_STRUCTURES_SECTION_BODY}")
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
    ];

    /// The parametrized section suite: every row's populated findings must
    /// render its heading and entries verbatim, and an empty findings list
    /// must omit the section without leaving stray blank lines at the seam.
    #[test]
    fn the_section_suite_renders_populated_findings_and_omits_empty_ones() {
        for row in SECTION_SUITE_ROWS {
            let mut bundle = EvidenceBundle::default();
            (row.populate)(&mut bundle);

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

    /// The one qualification wording the section suite pins (issue #346).
    const API_ADMISSION: &str = "partial — delay imports unexamined";

    /// The heading the escalate template passes the libraries-apis include.
    const LIBRARIES_APIS_HEADING: &str = "ADDITIONAL CONTEXT — LIBRARIES AND APIS";

    /// The pinned wording stands at both ends of its journey: the shared
    /// coverage type produces it from an apidetect-shaped record, and the
    /// prompt-side view carries that same line verbatim.
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
            "the admission rides the section as exactly one line beside the entries"
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

    /// The pinned wording stands at both ends of its journey: the shared
    /// coverage type produces it from a libmatch-shaped record, and the
    /// prompt-side view carries that same line verbatim.
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
            "the admission rides the section as exactly one line beside the entries"
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

    /// The per-finding note (issue #347): a match record carrying its
    /// version-authority admission renders one extra line beside its
    /// evidence — the prompt is never shown a versioned claim the
    /// signature never established — while a note-less record renders
    /// the pinned body untouched (pinned by the section suite above).
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
        // Un-stamp the note line from the admitted render: what's left
        // must be exactly the note-less render — the note rides exactly
        // one extra line, right after the evidence line, and nothing
        // else moves.
        assert_eq!(
            admitted.replace(
                &format!("{LIBMATCH_SECTION_BODY}\n  Admission: Signature match, version unknown"),
                LIBMATCH_SECTION_BODY,
            ),
            clean,
            "the note rides exactly one extra line, right after the evidence line"
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

    /// The pinned wording stands at both ends of its journey: the shared
    /// coverage type produces it from a floatsimd-shaped record, and the
    /// prompt-side view carries that same line verbatim.
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
            "the admission rides the section as exactly one line beside the entries"
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

    /// The one qualification wording the consts sections carry (issue
    /// #348) — the same line beside the constants entries and beside the
    /// data-tables entries, since one constant scan feeds both.
    const CONSTS_ADMISSION: &str = "partial — 2 function bodies unreached: FUN_18003e750, +1 more; \
                                    1 data-object memory window unreadable: DAT_1400a1c00";

    /// The headings the templates pass the constants and data-tables includes.
    const ESCALATE_CONSTANTS_HEADING: &str = "ADDITIONAL CONTEXT — CONSTANTS";
    const MODULE_CONTEXT_DATA_TABLES_HEADING: &str = "DATA TABLES";

    /// The pinned wording stands at both ends of its journey for both
    /// engines: the shared coverage type produces it from the records
    /// their scans stamp, and the prompt-side view carries that same line
    /// verbatim.
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
    /// qualification line beside the structures — the admission rides the
    /// section, it never replaces or reflows it, and one line is the whole
    /// of the bloat budget (issue #348).
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
            "the admission rides the section as exactly one line beside the entries"
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

    /// The empty-findings doctrine, typesdb side (issue #348): structures
    /// the scan never recovered establish nothing about the function, so a
    /// falling-short record over an empty list opens no section to qualify
    /// — unlike the constants and float/SIMD sections, whose headings the
    /// admission does open. What the reader sees is the entries plus a
    /// line, or nothing at all.
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
    /// so a coverage value crossing into another engine's section fails
    /// every pin below.
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

    /// The pinned wording stands at both ends of its journey for all
    /// three engines: the shared coverage type produces it from the
    /// records their scans stamp, and the prompt-side view carries those
    /// same lines verbatim.
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
    /// qualification line at each of the section's three consumers — the
    /// admission rides the section, it never replaces or reflows it, and
    /// one line is the whole of the bloat budget (issue #349). The
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
            (escalate_clean, escalate_admitted, ESCALATE_CONTROL_FLOW_HEADING),
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
                "the admission rides the {heading} section as exactly one line beside the entries"
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
    /// entries in the escalate prompt — the two admissions never borrow
    /// each other's wording, and each section keeps one heading (issue
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
            "each admission rides its own section as exactly one line beside the entries"
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
            (&full_partial, SHARED_CONTROL_FLOW_HEADING, CONTROL_FLOW_ADMISSION),
        ] {
            assert!(
                prompt.contains(&format!(
                    "## {heading}\n\nCoverage: {admission}\n\n"
                )),
                "the empty list still carries the one admission line"
            );
        }
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
    /// accidentally-dropped include fails here loudly instead of silently
    /// shrinking a prompt.
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
}
