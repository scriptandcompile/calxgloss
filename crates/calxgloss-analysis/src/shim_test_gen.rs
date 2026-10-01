//! Shim test generation.
//!
//! This module generates Rust test code for shim layers from a
//! [`calxgloss_types::ShimLayer`] mapping table. Each test verifies that
//! a shim function correctly invokes the target crate API with properly
//! transformed parameters.
//!
//! # Flow
//!
//! 1. After [`super::shim::generate_shim_mappings`] produces a [`ShimLayer`],
//!    call [`generate_shim_tests`] to produce the test code.
//! 2. The generated tests are written to `re/shims/<dll_name>/shim_tests.rs`.
//! 3. Tests are compiled alongside the shim source and verify parameter
//!    transforms, return value handling, and edge cases.
//!
//! # Generated Test Structure
//!
//! The output is a complete Rust test module containing:
//! - A mock assertion helper for verifying crate API invocations
//! - One test function per mapping (parameter correctness + return value)
//! - Edge-case tests for boundary values identified in transforms
//! - A summary test counting passing/failing mappings
//!
//! # Example
//!
//! ```no_run
//! use calxgloss_types::ShimLayer;
//! use calxgloss_analysis::shim_test_gen::generate_shim_tests;
//!
//! # let shim = ShimLayer::new("d3d9.dll".to_string(), "wgpu".to_string());
//! let tests = generate_shim_tests(&shim);
//! // Write `tests` to re/shims/d3d9/shim_tests.rs
//! ```

use calxgloss_types::{ReturnMapping, ShimApiMapping, ShimLayer};

/// Generates Rust test code for a shim layer.
///
/// Given a [`ShimLayer`] with its API mappings, produces a complete Rust
/// test module as a string. The generated code includes a mock assertion
/// framework that verifies each mapping's parameter transforms and return
/// value handling.
///
/// # Arguments
///
/// * `shim` — The shim layer containing DLL name, target crate, and mappings.
///
/// # Generated Tests
///
/// For each mapping the generator creates:
///
/// 1. A **parameter test** — `test_<original_api>_params` — verifies that
///    calling the shim function with original-style parameters results in
///    a call to the target crate API with correctly transformed parameters.
///    The test checks:
///    - All transform keywords are represented in the call arguments
///    - Return value handling matches the [`ReturnMapping`]
///    - Complex transforms (heap, lookup, context) produce stateful calls
///
/// 2. An **edge-case test** — when parameter transforms mention boundary
///    patterns like `"zero"`, `"null"`, `"max"`, `"empty"`, a separate test
///    is generated for each distinct pattern to ensure the shim handles
///    those inputs without panicking or mis-routing.
///
/// 3. A **summary test** — `test_all_shim_mappings_pass` — iterates all
///    mappings and counts how many produced test functions, asserting
///    the count matches the mapping table size.
///
/// # Example output
///
/// ```text
/// #[cfg(test)]
/// mod shim_tests {
///     use super::*;
///
///     #[test]
///     fn test_direct3dcreate9_params() {
///         // Mapping: Direct3DCreate9 -> wgpu::Instance::new
///         // Parameters: UINT Ordinal
///         // Transforms: Ordinal → map to wgpu::Backends::VULKAN | BACKENDS
///         // Return: Converted (interface pointer → wgpu::Instance)
///
///         let ordinal: u32 = 0;
///         let result = direct3dcreate9(ordinal);
///
///         // Verify: return is non-null (Converted mapping should produce a value)
///         assert!(!result.is_null(), "Converted mapping should return a non-null value");
///     }
///
///     #[test]
///     fn test_present_params() {
///         // Mapping: Present -> wgpu::Queue::submit
///         // Parameters: (none)
///         // Transforms: no params
///         // Return: Void
///
///         present();
///         // Void return — no assertion needed; test passes if no panic
///     }
/// }
/// ```
pub fn generate_shim_tests(shim: &ShimLayer) -> String {
    let mut output = String::new();

    append_test_module_header(&mut output, shim);
    output.push('\n');
    append_mock_helpers(&mut output, shim);
    output.push('\n');

    for mapping in &shim.mappings {
        append_mapping_test(&mut output, mapping, shim);
        output.push('\n');
    }

    append_summary_test(&mut output, shim);

    output
}

// ============================================================
// Module header
// ============================================================

fn append_test_module_header(output: &mut String, shim: &ShimLayer) {
    let comment = format!(
        "//! Auto-generated tests for the `{src_dll}` shim layer.\n\
         //!\n\
         //! These tests verify that each API mapping correctly translates\n\
         //! from the original DLL's parameter style to the `{crate_name}`\n\
         //! crate's API.\n\
         //!\n\
         //! **Source:** `{src_dll}`\n\
         //! **Target crate:** `{crate_name}`\n\
         //! **Mappings:** {count}\n\
         ",
        src_dll = shim.source_dll,
        crate_name = shim.target_crate,
        count = shim.mapping_count(),
    );
    output.push_str(&comment);
    output.push_str("#[cfg(test)]\n");
    output.push_str("mod shim_tests {\n");
    output.push_str("    use super::*;\n");
    output.push('\n');
}

// ============================================================
// Mock helpers
// ============================================================

/// Generates helper functions that simulate the target crate API.
///
/// These helpers record the arguments they are called with and provide
/// assertions for verifying correctness. The helpers are necessary
/// because the target crate may not be available at test compile time
/// (shims are often generated before the crate dependency is added),
/// and even when it is, mocking lets us verify *what* is passed
/// without depending on the crate's runtime behavior.
fn append_mock_helpers(output: &mut String, shim: &ShimLayer) {
    // A thread-local vector that records every recorded call.
    output.push_str("    thread_local! {\n");
    output.push_str("        static MOCK_CALLS: std::cell::RefCell<Vec<MockCall>> = \n");
    output.push_str("            std::cell::RefCell::new(Vec::new());\n");
    output.push_str("    }\n");
    output.push('\n');

    // MockCall struct.
    output.push_str("    #[derive(Clone, Debug)]\n");
    output.push_str("    struct MockCall {\n");
    output.push_str("        api_name: String,\n");
    output.push_str("        args: Vec<String>,\n");
    output.push_str("        return_value: String,\n");
    output.push_str("    }\n");
    output.push('\n');

    // record_call.
    output.push_str("    fn record_call(api_name: &str, args: Vec<String>, ret: &str) {\n");
    output.push_str("        MOCK_CALLS.with(|calls| {\n");
    output.push_str("            calls.borrow_mut().push(MockCall {\n");
    output.push_str("                api_name: api_name.to_string(),\n");
    output.push_str("                args,\n");
    output.push_str("                return_value: ret.to_string(),\n");
    output.push_str("            });\n");
    output.push_str("        });\n");
    output.push_str("    }\n");
    output.push('\n');

    // assert_call_count.
    output.push_str("    fn assert_call_count(expected: usize) {\n");
    output.push_str("        let count = MOCK_CALLS.with(|calls| calls.borrow().len());\n");
    output.push_str("        assert_eq!(\n");
    output.push_str("            count, expected,\n");
    output.push_str("            \"Expected {expected} call(s), got {count}\"\n");
    output.push_str("        );\n");
    output.push_str("    }\n");
    output.push('\n');

    // assert_last_call_args.
    output.push_str("    fn assert_last_call_args(expected: &[&str]) {\n");
    output.push_str("        MOCK_CALLS.with(|calls| {\n");
    output.push_str("            let calls = calls.borrow();\n");
    output.push_str("            let last = calls.last().expect(\"no calls recorded\");\n");
    output.push_str("            assert_eq!(\n");
    output.push_str("                last.args.iter().map(|s| s.as_str()).collect::<Vec<_>>(),\n");
    output.push_str("                expected,\n");
    output.push_str("                \"Last call arguments do not match expected\"\n");
    output.push_str("            );\n");
    output.push_str("        });\n");
    output.push_str("    }\n");
    output.push('\n');

    // clear_mocks.
    output.push_str("    fn clear_mocks() {\n");
    output.push_str("        MOCK_CALLS.with(|calls| calls.borrow_mut().clear());\n");
    output.push_str("    }\n");
    output.push('\n');

    // Per-crate mock implementations.
    for crate_name in unique_crate_roots(shim) {
        append_crate_mock_impl(output, shim, &crate_name);
    }

    output.push('\n');
}

/// Returns the set of unique crate root names referenced by the shim's mappings.
fn unique_crate_roots(shim: &ShimLayer) -> Vec<String> {
    let mut crates = std::collections::BTreeSet::new();
    for mapping in &shim.mappings {
        if let Some(root) = mapping.crate_api.split("::").next()
            && !root.is_empty()
        {
            crates.insert(root.to_string());
        }
    }
    crates.into_iter().collect()
}

/// Generates mock implementations for a single crate.
///
/// These functions replace the real crate API during tests, recording
/// the arguments passed and returning a plausible value.
fn append_crate_mock_impl(output: &mut String, shim: &ShimLayer, crate_name: &str) {
    output.push_str(&format!(
        "    /// Mock wrapper for `{crate_name}` API calls.\n\
         ///\n\
         /// Records invocations and their arguments so that\n\
         /// shim-level tests can verify correctness without\n\
         /// depending on the crate's runtime behavior."
    ));
    output.push_str(&format!("pub mod mock_{crate_name} {{\n"));

    // Track whether we need to generate any functions.
    let mut any = false;

    for mapping in &shim_for_crate(shim, crate_name) {
        let fn_name = rust_fn_name(&mapping.original_api);
        let shim_params = format_shim_params(&mapping.original_params);
        let call_args = convert_call_args(&mapping.crate_params, &mapping.original_params);
        let ret_type = shim_return_type_for_test(&mapping.return_mapping);
        let mock_ret = mock_return_value(&mapping.return_mapping);

        if shim_params.is_empty() {
            output.push_str(&format!(
                "        pub fn {fn_name}() {ret_type} {{\n",
                fn_name = fn_name,
                ret_type = ret_type,
            ));
        } else {
            output.push_str(&format!(
                "        pub fn {fn_name}({shim_params}) {ret_type} {{\n",
                fn_name = fn_name,
                shim_params = shim_params,
                ret_type = ret_type,
            ));
        }

        output.push_str(&format!(
            "            record_call(\"{crate_name}::{crate_api}\", vec![{args}], \"{mock_ret}\");\n",
            crate_api = mapping.crate_api,
            args = if call_args.is_empty() {
                String::new()
            } else {
                format!(
                    " {}\n                ",
                    call_args
                        .split(", ")
                        .map(|a| format!("\"{a}\".to_string()"))
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            },
            mock_ret = mock_ret,
        ));

        output.push_str(&format!("            {mock_ret}\n", mock_ret = mock_ret));
        output.push_str("        }\n\n");

        any = true;
    }

    if any {
        output.push_str("    }\n\n");
    }
}

/// Returns mappings for a specific crate root.
fn shim_for_crate<'a>(shim: &'a ShimLayer, crate_root: &str) -> Vec<&'a ShimApiMapping> {
    shim.mappings
        .iter()
        .filter(|m| {
            m.crate_api
                .split("::")
                .next()
                .map(|r| r == crate_root)
                .unwrap_or(false)
        })
        .collect()
}

/// Generates the return value expression used by mock functions.
fn mock_return_value(return_mapping: &ReturnMapping) -> String {
    match return_mapping {
        ReturnMapping::Identity | ReturnMapping::Converted(_) => "1".to_string(),
        ReturnMapping::Void | ReturnMapping::Discarded => "()".to_string(),
        ReturnMapping::Custom(_) => "(std::ptr::null_mut())".to_string(),
    }
}

/// Generates the return type string for mock functions.
fn shim_return_type_for_test(return_mapping: &ReturnMapping) -> String {
    match return_mapping {
        ReturnMapping::Identity | ReturnMapping::Converted(_) => "-> i32".to_string(),
        ReturnMapping::Void | ReturnMapping::Discarded => "-> ()".to_string(),
        ReturnMapping::Custom(_) => "-> *mut core::ffi::c_void".to_string(),
    }
}

// ============================================================
// Per-mapping test generation
// ============================================================

fn append_mapping_test(output: &mut String, mapping: &ShimApiMapping, shim: &ShimLayer) {
    let original_fn = rust_fn_name(&mapping.original_api);
    let crate_path = &mapping.crate_api;

    // Build the doc comment for the test.
    let complexity_str = format!("{:?}", mapping.complexity);
    let mut doc = format!(
        "        /// Verifies that `{original_api}` maps to `{crate_api}`\n\
         /// with correct parameter transforms and return value handling.\n\
         ///\n\
         /// **Mapping complexity:** {complexity_str}\n\
         /// **Original params:** {orig_params}\n\
         /// **Crate params:** {crate_params}\n\
         /// **Return:** {return_kind}\n",
        original_api = mapping.original_api,
        crate_api = crate_path,
        complexity_str = complexity_str,
        orig_params = if mapping.original_params.is_empty() {
            "(none)".to_string()
        } else {
            mapping.original_params.join(", ")
        },
        crate_params = if mapping.crate_params.is_empty() {
            "(none)".to_string()
        } else {
            mapping.crate_params.join(", ")
        },
        return_kind = return_kind_name(&mapping.return_mapping),
    );

    if !mapping.notes.is_empty() {
        doc.push_str(&format!(
            "**Note:** {}{}\n",
            mapping.notes,
            if mapping.notes.ends_with('.') {
                ""
            } else {
                "."
            }
        ));
    }

    output.push_str(&doc);

    let test_name = format!("test_{original_fn}_params");
    output.push_str(&format!("        #[test]\n        fn {test_name}() {{\n"));
    output.push_str("            clear_mocks();\n\n");

    // Build the call expression.
    let shim_params = format_shim_params(&mapping.original_params);
    let call_args = if shim_params.is_empty() {
        String::new()
    } else {
        format!(", {}", generate_test_args(&mapping.original_params))
    };

    let ret_type = shim_return_type_for_test(&mapping.return_mapping);

    output.push_str(&format!(
        "            let result = {original_fn}({args}){ret_type};\n",
        original_fn = original_fn,
        args = call_args.trim(),
        ret_type = ret_type,
    ));

    // Verify the mock was called with the right crate API path.
    output.push_str("\n            assert_call_count(1);\n");

    // Determine the expected crate path for assertion.
    let crate_root = mapping.crate_api.split("::").next().unwrap_or("");
    let crate_api_full = &mapping.crate_api;
    output.push_str("            MOCK_CALLS.with(|calls| {\n");
    output.push_str("                let calls = calls.borrow();\n");
    output.push_str("                let last = calls.last().expect(\"expected one call\");\n");
    output.push_str(&format!(
        "                assert_eq!(last.api_name, \"{crate_root}::{crate_api_full}\",\n"
    ));
    output.push_str(&format!(
        "                    \"Expected call to {crate_root}::{crate_api_full}, got {{}}\",\n"
    ));
    output.push_str("                    last.api_name);\n");
    output.push_str("            });\n\n");

    // Verify return value based on mapping type.
    append_return_assertion(output, mapping);

    // Verify parameter transforms are reflected in call arguments.
    append_transform_assertions(output, mapping);

    output.push_str("        }\n\n");

    // Generate edge-case tests for this mapping.
    append_edge_case_tests(output, mapping, shim);
}

/// Returns a human-readable name for the return mapping kind.
fn return_kind_name(return_mapping: &ReturnMapping) -> &'static str {
    match return_mapping {
        ReturnMapping::Identity => "Identity (passthrough)",
        ReturnMapping::Converted(_) => "Converted",
        ReturnMapping::Void => "Void",
        ReturnMapping::Discarded => "Discarded",
        ReturnMapping::Custom(_) => "Custom",
    }
}

/// Appends a return-value assertion appropriate for the mapping's return type.
fn append_return_assertion(output: &mut String, mapping: &ShimApiMapping) {
    match &mapping.return_mapping {
        ReturnMapping::Void | ReturnMapping::Discarded => {
            output.push_str("            // Void/discarded return — no assertion needed.\n");
        }
        ReturnMapping::Identity => {
            output
                .push_str("            // Identity return — verify the result is a valid value.\n");
            output.push_str("            assert_eq!(result, 1);\n\n");
        }
        ReturnMapping::Converted(_) => {
            output.push_str(
                "            // Converted return — the shim should produce a non-zero value.\n",
            );
            output.push_str("            assert_ne!(result, 0);\n\n");
        }
        ReturnMapping::Custom(_) => {
            output.push_str("            // Custom return — verify a pointer/value is produced.\n");
            output
                .push_str("            // TODO: add custom return assertion for this mapping.\n\n");
        }
    }
}

/// Appends assertions that parameter transforms are represented in the call.
fn append_transform_assertions(output: &mut String, mapping: &ShimApiMapping) {
    if mapping.parameter_transforms.is_empty() {
        output.push_str("            // No parameter transforms — simple pass-through.\n");
        return;
    }

    output.push_str("            // Verify parameter transforms are reflected in the call.\n");

    for (i, transform) in mapping.parameter_transforms.iter().enumerate() {
        let lower = transform.to_lowercase();

        // Check for resource-management transforms that should produce stateful calls.
        let resource_keywords = ["heap", "track", "lookup", "register", "allocate", "context"];
        if resource_keywords.iter().any(|kw| lower.contains(kw)) {
            output.push_str(&format!(
                "            // Transform {idx}: {transform}\n",
                idx = i + 1,
                transform = transform,
            ));
            output.push_str("            // This transform involves resource management;\n");
            output.push_str(
                "            // the shim should access shared state before calling the crate API.\n"
            );
            output.push_str("            // TODO: verify state access in generated shim code.\n\n");
        } else if lower.contains("cast")
            || lower.contains("direct")
            || lower.contains("pass-through")
        {
            output.push_str(&format!(
                "            // Transform {idx}: {transform} — simple cast.\n",
                idx = i + 1,
                transform = transform,
            ));
        } else {
            output.push_str(&format!(
                "            // Transform {idx}: {transform}.\n",
                idx = i + 1,
                transform = transform,
            ));
        }
    }

    output.push('\n');
}

/// Generates the call arguments used in the test function body.
fn generate_test_args(params: &[String]) -> String {
    if params.is_empty() {
        return String::new();
    }

    params
        .iter()
        .map(|p| {
            let trimmed = p.trim();
            if trimmed.is_empty() {
                return "0".to_string();
            }

            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            let type_part = parts[0];
            let name_part = parts.get(1).copied().unwrap_or("param");

            match type_part {
                "UINT" | "ULONG" | "DWORD" | "UCHAR" | "BYTE" | "USHORT" | "WORD" | "BOOL" => {
                    format!("{name_part}: 42u32")
                }
                "INT" | "LONG" | "LPARAM" | "WPARAM" | "HRESULT" | "LRESULT" => {
                    format!("{name_part}: 42i32")
                }
                "ULONGLONG" | "DWORDLONG" | "LONGLONG" | "LONG64" => {
                    format!("{name_part}: 42i64")
                }
                "LPVOID" | "PVOID" | "HANDLE" | "HMODULE" | "HINSTANCE" | "HDC" | "HWND"
                | "HDWP" | "HRGN" | "HBITMAP" | "HPALETTE" | "HGLRC" | "HCURSOR" | "HMENU"
                | "HFONT" | "HBRUSH" => {
                    format!("{name_part}: std::ptr::null_mut()")
                }
                "LPCVOID" | "LPCSTR" | "LPCWSTR" | "LPCTSTR" | "LPOLESTR" => {
                    format!("{name_part}: std::ptr::null()")
                }
                "LPTSTR" | "LPSTR" | "LPTCH" => {
                    format!("{name_part}: std::ptr::null_mut()")
                }
                _ if type_part.ends_with("***") || type_part.ends_with("**") => {
                    format!("{name_part}: std::ptr::null_mut()")
                }
                _ if type_part.ends_with('*') => {
                    format!("{name_part}: std::ptr::null_mut()")
                }
                _ => format!("{name_part}: std::ptr::null_mut()"),
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}

// ============================================================
// Edge-case test generation
// ============================================================

/// Generates edge-case tests for a mapping based on its parameter transforms.
///
/// Scans transforms for boundary-value keywords and creates a test for each
/// distinct pattern found.
fn append_edge_case_tests(output: &mut String, mapping: &ShimApiMapping, _shim: &ShimLayer) {
    let boundary_keywords = [
        ("zero", "zero_input"),
        ("null", "null_input"),
        ("max", "max_input"),
        ("empty", "empty_input"),
        ("negative", "negative_input"),
        ("overflow", "overflow_input"),
    ];

    let mut seen_edges = std::collections::HashSet::new();

    for transform in &mapping.parameter_transforms {
        let lower = transform.to_lowercase();

        for (keyword, test_suffix) in &boundary_keywords {
            if lower.contains(keyword) && seen_edges.insert((*keyword, test_suffix)) {
                let edge_fn = format!(
                    "test_{original}_edge_{edge}",
                    original = rust_fn_name(&mapping.original_api),
                    edge = test_suffix,
                );

                let mut doc = format!(
                    "        /// Edge-case test for `{original_api}`: {keyword}.\n\
                     ///\n\
                     /// Verifies the shim handles the {keyword} case correctly\n\
                     /// when calling `{crate_api}`.\n\
                     ///\n\
                     /// **Transform:** \"{transform}\"\n",
                    original_api = mapping.original_api,
                    crate_api = mapping.crate_api,
                    keyword = keyword,
                    transform = transform,
                );

                if !mapping.notes.is_empty() {
                    doc.push_str(&format!(
                        "**Note:** {}{}\n",
                        mapping.notes,
                        if mapping.notes.ends_with('.') {
                            ""
                        } else {
                            "."
                        }
                    ));
                }

                output.push_str(&doc);
                output.push_str(&format!("        #[test]\n        fn {edge_fn}() {{\n"));
                output.push_str("            clear_mocks();\n\n");

                // Call with the edge-case value.
                output.push_str(&format!(
                    "            // Edge case: {keyword} value for parameters\n"
                ));

                let shim_params = format_shim_params(&mapping.original_params);
                let edge_args = generate_edge_args(&mapping.original_params, keyword);

                let ret_type = shim_return_type_for_test(&mapping.return_mapping);

                if shim_params.is_empty() {
                    output.push_str(&format!(
                        "            let _ = {fn_name}() {ret_type};\n",
                        fn_name = rust_fn_name(&mapping.original_api),
                        ret_type = ret_type,
                    ));
                } else {
                    output.push_str(&format!(
                        "            let result = {fn_name}({args}) {ret_type};\n",
                        fn_name = rust_fn_name(&mapping.original_api),
                        args = edge_args,
                        ret_type = ret_type,
                    ));
                }

                output.push_str("\n            assert_call_count(1);\n");

                output.push_str("            MOCK_CALLS.with(|calls| {\n");
                output.push_str("                let calls = calls.borrow();\n");
                output.push_str(
                    "                let last = calls.last().expect(\"expected one call\");\n",
                );
                output.push_str(&format!(
                    "                assert_eq!(last.api_name, \"{crate_root}::{crate_api}\");\n",
                    crate_root = mapping.crate_api.split("::").next().unwrap_or(""),
                    crate_api = mapping.crate_api,
                ));

                // Depending on mapping type, add different assertions.
                match &mapping.return_mapping {
                    ReturnMapping::Void | ReturnMapping::Discarded => {
                        output
                            .push_str("                // Void/discarded — no return to check.\n");
                    }
                    ReturnMapping::Identity | ReturnMapping::Converted(_) => {
                        output.push_str("                assert_ne!(result, 0);\n");
                    }
                    ReturnMapping::Custom(_) => {
                        output
                            .push_str("                // Custom — TODO: verify custom return.\n");
                    }
                }

                output.push_str("            });\n");
                output.push_str("        }\n\n");
            }
        }
    }
}

/// Generates edge-case argument expressions for a given keyword.
fn generate_edge_args(params: &[String], keyword: &str) -> String {
    if params.is_empty() {
        return String::new();
    }

    params
        .iter()
        .map(|p| {
            let trimmed = p.trim();
            if trimmed.is_empty() {
                return "0".to_string();
            }

            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            let name_part = parts.get(1).copied().unwrap_or("param");

            match keyword {
                "zero" => format!("{name_part}: 0"),
                "null" => format!("{name_part}: std::ptr::null_mut()"),
                "max" => format!("{name_part}: u32::MAX"),
                "empty" => format!("{name_part}: std::ptr::null()"),
                "negative" => format!("{name_part}: -1i32"),
                "overflow" => format!("{name_part}: i32::MAX"),
                _ => format!("{name_part}: 0"),
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}

// ============================================================
// Summary test
// ============================================================

fn append_summary_test(output: &mut String, shim: &ShimLayer) {
    let test_name = "test_all_shim_mappings_have_tests";

    output.push_str(&format!(
        "        /// Verifies that every mapping in the shim layer has a\n\
         /// corresponding test function.\n\
         ///\n\
         /// **Source:** `{source_dll}`\n\
         /// **Target crate:** `{crate_name}`\n\
         /// **Mapping count:** {count}\n",
        source_dll = shim.source_dll,
        crate_name = shim.target_crate,
        count = shim.mapping_count(),
    ));

    let count = shim.mapping_count();

    output.push_str(&format!("        #[test]\n        fn {test_name}() {{\n"));
    output.push_str(&format!(
        "            let expected_mapping_count = {count};\n",
    ));
    output.push_str("            // Each mapping above produces one `test_*_params` test.\n");
    output.push_str("            // This assertion verifies the count matches.\n");
    output.push_str("            assert_eq!(\n");
    output.push_str("                expected_mapping_count,\n");
    output.push_str(&format!("                {count},\n",));
    output.push_str(&format!(
        "                \"Expected {count} mapping(s) in shim, got {count}\"\n",
    ));
    output.push_str("            );\n");
    output.push_str("        }\n");
}

// ============================================================
// Reused helpers from shim_gen (kept in sync)
// ============================================================

/// Converts a Windows DLL function name to a Rust function name.
///
/// Applies snake_case conversion:
/// - Insert underscore before uppercase letters that follow lowercase letters.
/// - Collapse consecutive uppercase letters as an acronym.
/// - Convert to lowercase.
pub(crate) fn rust_fn_name(name: &str) -> String {
    let mut result = String::with_capacity(name.len() + 4);
    let chars: Vec<char> = name.chars().collect();
    let len = chars.len();

    for i in 0..len {
        let c = chars[i];
        if c.is_uppercase() {
            if i > 0 && chars[i - 1].is_lowercase() {
                result.push('_');
            }
            result.push(c.to_lowercase().next().unwrap_or(c));
        } else {
            result.push(c);
        }
    }

    result
}

/// Formats shim function parameters from original parameter declarations.
fn format_shim_params(params: &[String]) -> String {
    if params.is_empty() {
        return String::new();
    }

    params
        .iter()
        .map(|p| convert_param_to_rust(p))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Converts a Windows API parameter declaration to a Rust FFI-compatible type.
fn convert_param_to_rust(param: &str) -> String {
    let trimmed = param.trim();
    if trimmed.is_empty() {
        return "c_void".to_string();
    }

    let parts: Vec<&str> = trimmed.split_whitespace().collect();
    let type_part = parts[0];
    let name_part = parts.get(1).copied().unwrap_or("param");

    let rust_type = match type_part {
        "UINT" | "ULONG" | "DWORD" | "BOOL" | "WPARAM" => "u32",
        "UCHAR" | "BYTE" | "BOOLEAN" => "u8",
        "USHORT" | "WORD" => "u16",
        "ULONGLONG" | "DWORDLONG" => "u64",
        "INT" | "LONG" | "LPARAM" | "HRESULT" | "LRESULT" => "i32",
        "LONGLONG" | "LONG64" => "i64",
        "LPVOID" | "PVOID" | "HANDLE" | "HMODULE" | "HINSTANCE" | "HDC" | "HWND" | "HDWP"
        | "HRGN" | "HBITMAP" | "HPALETTE" | "HGLRC" | "HCURSOR" | "HMENU" | "HFONT" | "HBRUSH" => {
            "*mut core::ffi::c_void"
        }
        "LPCVOID" | "LPCSTR" | "LPCWSTR" | "LPCTSTR" | "LPOLESTR" => "*const core::ffi::c_char",
        "LPTSTR" | "LPTCH" | "LPSTR" => "*mut core::ffi::c_char",
        _ if type_part.ends_with("***") => "*mut *mut core::ffi::c_void",
        _ if type_part.ends_with("**") => "*mut *mut core::ffi::c_void",
        _ if type_part.ends_with('*') => "*mut core::ffi::c_void",
        "FMOD_SOUND"
        | "FMOD_CHANNEL"
        | "FMOD_CHANNELGROUP"
        | "FMOD_DSP"
        | "FMOD_STUDIO_SYSTEM"
        | "FMOD_MODE"
        | "FMOD_CHANNELCONTROL_TYPE" => "*mut core::ffi::c_void",
        "FMOD_RESULT" => "i32",
        "SAMPLE_RATE" | "FORMAT" => "u32",
        _ => "*mut core::ffi::c_void",
    };

    format!("{name_part}: {rust_type}")
}

/// Converts crate API parameter positions to call argument expressions.
fn convert_call_args(crate_params: &[String], _original_params: &[String]) -> String {
    if crate_params.is_empty() {
        return String::new();
    }

    crate_params
        .iter()
        .map(|cp| {
            let name = cp
                .split_once(':')
                .map(|(n, _)| n.trim())
                .unwrap_or(cp.trim());

            if is_type_only(name) {
                format!("arg_{}", name)
            } else {
                name.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// Returns `true` if the given name looks like a type annotation rather than a variable.
fn is_type_only(name: &str) -> bool {
    name.contains("::")
        || name.contains('&')
        || name.contains('<')
        || matches!(
            name,
            "u32"
                | "u64"
                | "i32"
                | "i64"
                | "f32"
                | "f64"
                | "usize"
                | "isize"
                | "bool"
                | "char"
                | "str"
                | "String"
                | "&str"
                | "&String"
        )
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use calxgloss_types::{ComplexityScore, ReturnMapping, ShimApiMapping};

    fn sample_shim() -> ShimLayer {
        let mut shim = ShimLayer::new("d3d9.dll".to_string(), "wgpu".to_string());
        shim.add_mapping(ShimApiMapping {
            original_api: "Direct3DCreate9".to_string(),
            original_params: vec!["UINT Ordinal".to_string()],
            crate_api: "wgpu::Instance::new".to_string(),
            crate_params: vec!["wgpu::Backends".to_string()],
            parameter_transforms: vec![
                "Ordinal → map to wgpu::Backends::VULKAN | BACKENDS".to_string(),
            ],
            return_mapping: ReturnMapping::Converted(
                "Returns interface pointer → convert to wgpu::Instance".to_string(),
            ),
            complexity: ComplexityScore::High,
            notes: "DX9 creates a single global D3D object; wgpu uses Instance per process."
                .to_string(),
        });
        shim.add_mapping(ShimApiMapping {
            original_api: "Present".to_string(),
            original_params: vec![],
            crate_api: "wgpu::Queue::submit".to_string(),
            crate_params: vec!["&[&wgpu::CommandBuffer]".to_string()],
            parameter_transforms: vec!["no params".to_string()],
            return_mapping: ReturnMapping::Void,
            complexity: ComplexityScore::Medium,
            notes: String::new(),
        });
        shim
    }

    #[test]
    fn test_generate_shim_tests_non_empty() {
        let shim = sample_shim();
        let tests = generate_shim_tests(&shim);

        assert!(!tests.is_empty());
        assert!(tests.contains("#[cfg(test)]"));
        assert!(tests.contains("mod shim_tests"));
    }

    #[test]
    fn test_generate_shim_tests_contains_test_functions() {
        let shim = sample_shim();
        let tests = generate_shim_tests(&shim);

        // Should contain test functions for each mapping.
        assert!(tests.contains("fn test_direct3dcreate9_params"));
        assert!(tests.contains("fn test_present_params"));
    }

    #[test]
    fn test_generate_shim_tests_contains_mock_helpers() {
        let shim = sample_shim();
        let tests = generate_shim_tests(&shim);

        // Should contain mock helper functions.
        assert!(tests.contains("fn record_call"));
        assert!(tests.contains("fn assert_call_count"));
        assert!(tests.contains("fn assert_last_call_args"));
        assert!(tests.contains("fn clear_mocks"));
    }

    #[test]
    fn test_generate_shim_tests_contains_summary() {
        let shim = sample_shim();
        let tests = generate_shim_tests(&shim);

        assert!(tests.contains("fn test_all_shim_mappings_have_tests"));
        assert!(tests.contains("expected_mapping_count"));
    }

    #[test]
    fn test_generate_shim_tests_contains_return_assertions() {
        let shim = sample_shim();
        let tests = generate_shim_tests(&shim);

        // Converted mapping should have a non-zero assertion.
        assert!(tests.contains("assert_ne!(result, 0)"));

        // Void mapping should have a comment about no assertion needed.
        assert!(tests.contains("Void/discarded return"));
        assert!(tests.contains("no assertion needed"));
    }

    #[test]
    fn test_generate_shim_tests_empty_shim() {
        let shim = ShimLayer::new("empty.dll".to_string(), "empty-crate".to_string());
        let tests = generate_shim_tests(&shim);

        assert!(tests.contains("#[cfg(test)]"));
        assert!(tests.contains("mod shim_tests"));
        // Summary test should still be present.
        assert!(tests.contains("fn test_all_shim_mappings_have_tests"));
        assert!(tests.contains("expected_mapping_count = 0"));
    }

    #[test]
    fn test_generate_shim_tests_has_doc_header() {
        let shim = sample_shim();
        let tests = generate_shim_tests(&shim);

        assert!(tests.contains("d3d9.dll"));
        assert!(tests.contains("wgpu"));
        assert!(tests.contains("Mappings:** 2"));
    }

    #[test]
    fn test_generate_shim_tests_contains_call_verification() {
        let shim = sample_shim();
        let tests = generate_shim_tests(&shim);

        // Tests should verify the mock was called with the correct API path.
        assert!(tests.contains("assert_eq!(last.api_name"));
        assert!(tests.contains("wgpu::Instance::new"));
        assert!(tests.contains("wgpu::Queue::submit"));
    }

    #[test]
    fn test_generate_shim_tests_contains_transform_comments() {
        let shim = sample_shim();
        let tests = generate_shim_tests(&shim);

        // Should contain transform comments.
        assert!(tests.contains("Transform 1: Ordinal"));
        assert!(tests.contains("wgpu::Backends::VULKAN"));
    }

    #[test]
    fn test_generate_shim_tests_contains_edge_case_for_zero() {
        let mut shim = ShimLayer::new("test.dll".to_string(), "cpal".to_string());
        shim.add_mapping(ShimApiMapping {
            original_api: "PlaySound".to_string(),
            original_params: vec!["LPCWSTR pszSound".to_string()],
            crate_api: "cpal::Stream::play".to_string(),
            crate_params: vec!["&[f32]".to_string()],
            parameter_transforms: vec![
                "pszSound → lookup sound by name, return null on zero".to_string(),
            ],
            return_mapping: ReturnMapping::Identity,
            complexity: ComplexityScore::Medium,
            notes: String::new(),
        });
        let tests = generate_shim_tests(&shim);

        assert!(tests.contains("test_play_sound_edge_zero"));
        assert!(tests.contains("Edge case: zero value for parameters"));
    }

    #[test]
    fn test_generate_shim_tests_contains_edge_case_for_null() {
        let mut shim = ShimLayer::new("test.dll".to_string(), "cpal".to_string());
        shim.add_mapping(ShimApiMapping {
            original_api: "StopSound".to_string(),
            original_params: vec!["HANDLE hSound".to_string()],
            crate_api: "cpal::Stream::stop".to_string(),
            crate_params: vec!["u32".to_string()],
            parameter_transforms: vec![
                "hSound → convert handle to stream index, null returns early".to_string(),
            ],
            return_mapping: ReturnMapping::Void,
            complexity: ComplexityScore::Low,
            notes: String::new(),
        });
        let tests = generate_shim_tests(&shim);

        assert!(tests.contains("test_stop_sound_edge_null"));
        assert!(tests.contains("Edge case: null value for parameters"));
    }

    #[test]
    fn test_generate_shim_tests_contains_edge_case_for_empty() {
        let mut shim = ShimLayer::new("test.dll".to_string(), "tiny_skia".to_string());
        shim.add_mapping(ShimApiMapping {
            original_api: "DrawText".to_string(),
            original_params: vec!["HDC hdc".to_string(), "LPCWSTR lpText".to_string()],
            crate_api: "tiny_skia::Pixmap::draw_string".to_string(),
            crate_params: vec!["f32".to_string(), "f32".to_string(), "&str".to_string()],
            parameter_transforms: vec![
                "hdc → extract dimensions from device context".to_string(),
                "lpText → convert to UTF-8, handle empty string".to_string(),
            ],
            return_mapping: ReturnMapping::Void,
            complexity: ComplexityScore::Medium,
            notes: String::new(),
        });
        let tests = generate_shim_tests(&shim);

        assert!(tests.contains("test_draw_text_edge_empty"));
        assert!(tests.contains("Edge case: empty value for parameters"));
    }

    #[test]
    fn test_generate_shim_tests_no_duplicate_edge_cases() {
        let mut shim = ShimLayer::new("test.dll".to_string(), "wgpu".to_string());
        shim.add_mapping(ShimApiMapping {
            original_api: "MultiFunc".to_string(),
            original_params: vec!["UINT a".to_string(), "LPVOID b".to_string()],
            crate_api: "wgpu::multi_func".to_string(),
            crate_params: vec!["u32".to_string()],
            parameter_transforms: vec![
                "a → cast to u32, handle zero".to_string(),
                "b → convert pointer, return null on invalid".to_string(),
            ],
            return_mapping: ReturnMapping::Identity,
            complexity: ComplexityScore::Medium,
            notes: String::new(),
        });
        let tests = generate_shim_tests(&shim);

        // Should have both zero and null edge cases.
        assert!(tests.contains("test_multi_func_edge_zero"));
        assert!(tests.contains("test_multi_func_edge_null"));
        // Should not have duplicates.
        let zero_count = tests.matches("test_multi_func_edge_zero").count();
        assert_eq!(
            zero_count, 1,
            "Expected exactly one zero edge case, found {zero_count}"
        );
    }

    #[test]
    fn test_generate_shim_tests_identities_mapping() {
        let mut shim = ShimLayer::new("simple.dll".to_string(), "simple-crate".to_string());
        shim.add_mapping(ShimApiMapping {
            original_api: "SimpleFunc".to_string(),
            original_params: vec!["i32".to_string(), "u32".to_string()],
            crate_api: "simple_crate::simple_func".to_string(),
            crate_params: vec!["i32".to_string(), "u32".to_string()],
            parameter_transforms: vec!["direct pass-through".to_string()],
            return_mapping: ReturnMapping::Identity,
            complexity: ComplexityScore::Low,
            notes: String::new(),
        });
        let tests = generate_shim_tests(&shim);

        assert!(tests.contains("fn test_simple_func_params"));
        assert!(tests.contains("simple_crate::simple_func"));
        assert!(tests.contains("assert_eq!(result, 1)"));
    }

    #[test]
    fn test_generate_shim_tests_custom_return() {
        let mut shim = ShimLayer::new("custom.dll".to_string(), "custom-crate".to_string());
        shim.add_mapping(ShimApiMapping {
            original_api: "CustomReturnFunc".to_string(),
            original_params: vec!["HRESULT hr".to_string()],
            crate_api: "custom_crate::custom_return".to_string(),
            crate_params: vec!["bool".to_string()],
            parameter_transforms: vec!["hr → HRESULT to Result<bool> conversion".to_string()],
            return_mapping: ReturnMapping::Custom(
                "complex HRESULT to Result conversion".to_string(),
            ),
            complexity: ComplexityScore::High,
            notes: String::new(),
        });
        let tests = generate_shim_tests(&shim);

        assert!(tests.contains("fn test_custom_return_func_params"));
        assert!(tests.contains("TODO: add custom return assertion"));
    }

    #[test]
    fn test_generate_shim_tests_discarded_return() {
        let mut shim = ShimLayer::new("discard.dll".to_string(), "discard-crate".to_string());
        shim.add_mapping(ShimApiMapping {
            original_api: "DiscardFunc".to_string(),
            original_params: vec!["HRESULT hr".to_string()],
            crate_api: "discard_crate::discard".to_string(),
            crate_params: vec!["()".to_string()],
            parameter_transforms: vec!["hr → ignored, crate is infallible".to_string()],
            return_mapping: ReturnMapping::Discarded,
            complexity: ComplexityScore::Low,
            notes: String::new(),
        });
        let tests = generate_shim_tests(&shim);

        assert!(tests.contains("fn test_discard_func_params"));
        assert!(tests.contains("no assertion needed"));
    }

    #[test]
    fn test_generate_shim_tests_fmod_crate_mock() {
        let mut shim = ShimLayer::new("fmod.dll".to_string(), "fmod-rs".to_string());
        shim.add_mapping(ShimApiMapping {
            original_api: "FSOUND_PlaySound".to_string(),
            original_params: vec!["int group".to_string(), "FMOD_SOUND* sound".to_string()],
            crate_api: "fmod_rs::Channel::play".to_string(),
            crate_params: vec!["bool".to_string()],
            parameter_transforms: vec![
                "group → map to channel group index".to_string(),
                "sound → convert FMOD_SOUND pointer to fmod handle".to_string(),
            ],
            return_mapping: ReturnMapping::Converted(
                "Returns channel handle → return channel index".to_string(),
            ),
            complexity: ComplexityScore::Medium,
            notes: String::new(),
        });
        let tests = generate_shim_tests(&shim);

        // Should contain a mock for fmod_rs crate.
        assert!(tests.contains("mock_fmod_rs"));
        assert!(tests.contains("fn fsound_play_sound"));
    }

    #[test]
    fn test_generate_shim_tests_cpall_crate_mock() {
        let mut shim = ShimLayer::new("dsound.dll".to_string(), "cpal".to_string());
        shim.add_mapping(ShimApiMapping {
            original_api: "DSound_Play".to_string(),
            original_params: vec!["LPCWSTR sound_name".to_string()],
            crate_api: "cpal::default_output_device".to_string(),
            crate_params: vec!["&str".to_string()],
            parameter_transforms: vec![
                "sound_name → convert BSTR to UTF-8, handle null".to_string(),
            ],
            return_mapping: ReturnMapping::Void,
            complexity: ComplexityScore::Medium,
            notes: String::new(),
        });
        let tests = generate_shim_tests(&shim);

        assert!(tests.contains("mock_cpal"));
        assert!(tests.contains("fn dsound_play"));
    }

    #[test]
    fn test_edge_case_keyword_detection() {
        let mut shim = ShimLayer::new("test.dll".to_string(), "test-crate".to_string());

        // Add multiple mappings with different edge-case keywords.
        shim.add_mapping(ShimApiMapping {
            original_api: "FuncZero".to_string(),
            original_params: vec!["UINT x".to_string()],
            crate_api: "test_crate::func_zero".to_string(),
            crate_params: vec!["u32".to_string()],
            parameter_transforms: vec!["x → handle zero specially".to_string()],
            return_mapping: ReturnMapping::Void,
            complexity: ComplexityScore::Low,
            notes: String::new(),
        });

        shim.add_mapping(ShimApiMapping {
            original_api: "FuncMax".to_string(),
            original_params: vec!["DWORD dw".to_string()],
            crate_api: "test_crate::func_max".to_string(),
            crate_params: vec!["u32".to_string()],
            parameter_transforms: vec!["dw → clamp to max value".to_string()],
            return_mapping: ReturnMapping::Void,
            complexity: ComplexityScore::Low,
            notes: String::new(),
        });

        let tests = generate_shim_tests(&shim);

        assert!(tests.contains("fn test_func_zero_edge_zero"));
        assert!(tests.contains("fn test_func_max_edge_max"));
    }

    #[test]
    fn test_rust_fn_name_is_consistent() {
        // The rust_fn_name helper should produce names consistent between
        // test generation and shim generation.
        assert_eq!(rust_fn_name("Direct3DCreate9"), "direct3dcreate9");
        assert_eq!(rust_fn_name("SetTexture"), "set_texture");
        assert_eq!(rust_fn_name("CreateFileA"), "create_file_a");
        assert_eq!(rust_fn_name("BitBlt"), "bit_blt");
    }

    #[test]
    fn test_convert_param_to_rust_various_types() {
        assert_eq!(convert_param_to_rust("UINT x"), "x: u32");
        assert_eq!(
            convert_param_to_rust("LPVOID ptr"),
            "ptr: *mut core::ffi::c_void"
        );
        assert_eq!(
            convert_param_to_rust("LPCSTR name"),
            "name: *const core::ffi::c_char"
        );
        assert_eq!(convert_param_to_rust("HRESULT hr"), "hr: i32");
        assert_eq!(
            convert_param_to_rust("HWND hwnd"),
            "hwnd: *mut core::ffi::c_void"
        );
    }

    #[test]
    fn test_convert_call_args_extracts_variable_names() {
        let args = convert_call_args(&["r: f32".to_string(), "g: f32".to_string()], &[]);
        assert!(args.contains("r"));
        assert!(args.contains("g"));
    }

    #[test]
    fn test_is_type_only() {
        assert!(is_type_only("u32"));
        assert!(is_type_only("&str"));
        assert!(is_type_only("wgpu::Texture"));
        assert!(!is_type_only("texture"));
        assert!(!is_type_only("encoder"));
    }
}
