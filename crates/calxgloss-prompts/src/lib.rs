//! Prompt templates and rendering for the Calxgloss LLM translation pipeline.
//!
//! This crate provides a lightweight template engine for building prompts
//! sent to the local LLM. Templates are embedded at compile time via
//! `include_str!` and rendered with structured data from the translation
//! pipeline.
//!
//! # Architecture
//!
//! - [`PromptLibrary`] — a collection of named templates (e.g. `"translate"`)
//!   that can be looked up and rendered in one call.
//! - [`build_translate_prompt`] — convenience function that assembles all
//!   context from a [`TranslationRequest`](calxgloss_types::TranslationRequest)
//!   into a rendered prompt string.
//!
//! # Template Syntax
//!
//! Uses [Askama](https://docs.rs/askama) templating syntax (Jinja2-inspired):
//!
//! | Syntax | Meaning |
//! |---|---|
//! | `{{var}}` | Substitute variable as string |
//! | `{{#items}}...{{/items}}` | Iterate over JSON array (via `iter()`) |
//! | `{% if var %}...{% endif %}` | Conditional (truthy) |
//! | `{% unless var %}...{% endif %}` | Conditional (falsy, via `!var`) |

pub mod error;

pub use error::PromptError;

use calxgloss_types::TranslationRequest;
use askama::Template;
use serde_json::json;

// ============================================================
// Prompt templates (Askama structs)
// ============================================================

/// Template for function translation prompts.
///
/// Rendered via Askama from the embedded `templates/translate.j2` file.
#[derive(Template)]
#[template(path = "translate.j2")]
pub struct TranslateTemplate {
    /// The function name to translate.
    pub function_name: String,

    /// The DLL containing the function.
    pub dll_name: String,

    /// The virtual address of the function entry point.
    pub address: u64,

    /// Raw disassembly listing from Ghidra.
    pub disassembly: String,

    /// Pseudo-C decompiler output from Ghidra.
    pub decompiler_output: String,

    /// Windows API calls identified in the disassembly.
    pub windows_apis: Vec<calxgloss_types::translation::WindowsApiCall>,

    /// Baseline test cases the translated Rust code must pass.
    pub test_cases: Vec<TestCaseFormatted>,

    /// Whether there are no Windows API calls (for conditional rendering).
    pub no_windows_apis: bool,
}

/// A formatted test case for template rendering.
#[derive(serde::Serialize)]
pub struct TestCaseFormatted {
    /// Test case index (1-based).
    pub index: usize,

    /// The test inputs as JSON.
    pub inputs: serde_json::Value,

    /// Expected return value as JSON.
    pub expected_return: serde_json::Value,

    /// Expected side effects as JSON.
    pub side_effects: serde_json::Value,
}

impl TranslateTemplate {
    /// Create a new translate template from a translation request.
    pub fn from_request(req: &TranslationRequest) -> Self {
        let test_cases: Vec<TestCaseFormatted> = req
            .baseline_tests
            .iter()
            .enumerate()
            .map(|(i, test)| {
                TestCaseFormatted {
                    index: i + 1,
                    inputs: test.inputs.clone(),
                    expected_return: test.expected_return.clone(),
                    side_effects: serde_json::to_value(&test.expected_side_effects).unwrap_or_else(|_| json!([])),
                }
            })
            .collect();

        TranslateTemplate {
            function_name: req.function.clone(),
            dll_name: req.dll.clone(),
            address: 0, // Not provided in TranslationRequest
            disassembly: req.disassembly.clone(),
            decompiler_output: req.decompiler_output.clone(),
            windows_apis: req.windows_apis.clone(),
            test_cases,
            no_windows_apis: req.windows_apis.is_empty(),
        }
    }
}

// ============================================================
// Convenience functions
// ============================================================

/// Build and render a translation prompt from a [`TranslationRequest`].
///
/// This is the main convenience function for the translation pipeline.
/// It extracts all relevant fields from the request and renders the
/// `"translate"` template.
pub fn build_translate_prompt(req: &TranslationRequest) -> Result<String, PromptError> {
    let template = TranslateTemplate::from_request(req);
    let rendered = template.render().map_err(|e| PromptError::Render(e.to_string()))?;
    if rendered.trim().is_empty() {
        return Err(PromptError::EmptyPrompt);
    }
    Ok(rendered)
}

// ============================================================
// Built-in templates
// ============================================================

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use calxgloss_types::{ApiCategory, TestCase};
    use serde_json::json;

    fn sample_request() -> TranslationRequest {
        TranslationRequest {
            dll: "game_logic.dll".to_string(),
            function: "DrawSprite".to_string(),
            disassembly: "mov eax, [esp+4]\nadd eax, ebx\nret".to_string(),
            decompiler_output: "int DrawSprite(int x, int y) { return x + y; }".to_string(),
            windows_apis: vec![
                calxgloss_types::translation::WindowsApiCall {
                    name: "GetTickCount".to_string(),
                    category: ApiCategory::Win32Core,
                    pal_mapping: "std::time::Instant::now()".to_string(),
                },
                calxgloss_types::translation::WindowsApiCall {
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
        assert_eq!(template.no_windows_apis, false);
        assert_eq!(template.windows_apis.len(), 2);
        assert_eq!(template.test_cases.len(), 2);
    }

    #[test]
    fn test_build_translate_prompt_basic() {
        let req = sample_request();
        let prompt = build_translate_prompt(&req).unwrap();

        // Check that key sections are present
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
}
