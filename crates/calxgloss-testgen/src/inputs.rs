//! Test input generation for function baseline testing.
//!
//! This module provides functionality to generate diverse test inputs based on
//! function signatures and disassembly analysis. Generated inputs cover boundary
//! values, typical values, and edge cases identified from the disassembly.
//!
//! # Generation Strategy
//!
//! Test inputs are generated using the following strategy:
//!
//! 1. **Signature-based generation** — parse parameter types and generate
//!    boundary values (min/max/zero) for each type
//! 2. **Disassembly-based generation** — analyze disassembly for edge cases
//!    like boundary checks (`cmp eax, 256`), null checks (`test eax, eax`),
//!    and negative checks
//! 3. **Combination** — merge both sets and deduplicate to produce the final
//!    test case list

use std::collections::HashSet;

use anyhow::{Context, Result};
use calxgloss_types::TestCase;
use serde_json::json;
use tracing::{debug, instrument};

use crate::ffi::{ParameterTypeInfo, ParsedSignature};

/// A source of edge cases for test input generation.
///
/// Edge cases may come from disassembly patterns or be derived from
/// type information.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EdgeCaseSource {
    /// Zero value check (e.g., `cmp eax, 0` or `test eax, eax`).
    Zero,

    /// Negative one check.
    NegativeOne,

    /// Minimum i32 value.
    MinI32,

    /// Maximum i32 value.
    MaxI32,

    /// Minimum u32 value (zero).
    MinU32,

    /// Maximum u32 value.
    MaxU32,

    /// Null pointer check.
    NullPointer,

    /// Empty string check.
    EmptyString,

    /// Maximum string length.
    MaxStringLength,

    /// Minimum float value.
    MinFloat,

    /// Maximum float value.
    MaxFloat,

    /// NaN value.
    NaN,

    /// A pattern extracted from disassembly.
    DisassemblyPattern(String),
}

/// Edge cases extracted from disassembly analysis.
///
/// Parses disassembly for common patterns that indicate boundary checks
/// and edge cases the function handles.
#[derive(Debug, Clone, Default)]
pub struct DisassemblyEdgeCases {
    /// Values compared against in boundary checks (e.g., `cmp eax, 256`).
    pub boundary_checks: Vec<i64>,

    /// Values compared against for negative range checks.
    pub negative_checks: Vec<i64>,

    /// Zero comparison targets found.
    pub zero_checks: HashSet<String>,

    /// Maximum value checks found.
    pub max_value_checks: Vec<i64>,
}

impl DisassemblyEdgeCases {
    /// Extract edge cases from disassembly text.
    ///
    /// Analyzes the disassembly for common patterns:
    /// - `cmp reg, N` / `test reg, N` — immediate value comparisons
    /// - `cmp reg, 0` — zero checks
    /// - `cmp reg, -1` — negative one checks
    /// - `cmp reg, 256` / `cmp reg, 65536` — common boundary values
    ///
    /// # Arguments
    ///
    /// * `disassembly` — Raw disassembly text to analyze.
    ///
    /// # Returns
    ///
    /// A [`DisassemblyEdgeCases`] struct populated with found edge cases.
    #[instrument(skip(disassembly))]
    pub fn from_disassembly(disassembly: &str) -> Self {
        debug!(
            length = disassembly.len(),
            "Extracting edge cases from disassembly"
        );

        let mut cases = Self::default();

        for line in disassembly.lines() {
            let line = line.trim();
            Self::extract_cmp_values(line, &mut cases);
            Self::extract_test_values(line, &mut cases);
            Self::extract_jump_targets(line, &mut cases);
        }

        // Deduplicate
        cases.zero_checks = cases.zero_checks.drain().collect();

        debug!(
            boundaries = cases.boundary_checks.len(),
            negatives = cases.negative_checks.len(),
            zeros = cases.zero_checks.len(),
            max_values = cases.max_value_checks.len(),
            "Extracted disassembly edge cases"
        );

        cases
    }

    /// Extract values from `cmp` instructions.
    fn extract_cmp_values(line: &str, cases: &mut Self) {
        // Match patterns like "cmp eax, 256" or "cmp ecx, -1"
        if let Some(cap) = regex::Regex::new(r"cmp\s+\w+,\s*(-?\d+)")
            .ok()
            .and_then(|r| r.captures(line))
        {
            if let Some(val_str) = cap.get(1) {
                if let Ok(val) = val_str.as_str().parse::<i64>() {
                    match val {
                        0 => {
                            cases.zero_checks.insert("cmp_zero".to_string());
                        }
                        -1 => {
                            cases.negative_checks.push(val);
                        }
                        1..=1000 => {
                            // Likely a boundary check for small values
                            if !cases.boundary_checks.contains(&val) {
                                cases.boundary_checks.push(val);
                            }
                        }
                        _ => {
                            // Large values might be addresses or flags
                            if !cases.boundary_checks.contains(&val)
                                && !cases.max_value_checks.contains(&val)
                            {
                                cases.max_value_checks.push(val);
                            }
                        }
                    }
                }
            }
        }
    }

    /// Extract values from `test` instructions.
    fn extract_test_values(line: &str, cases: &mut Self) {
        // Match patterns like "test eax, eax" or "test ecx, 0FFh"
        if let Some(cap) = regex::Regex::new(r"test\s+(\w+),\s*(\w+)")
            .ok()
            .and_then(|r| r.captures(line))
        {
            let operand2 = cap.get(2).map(|m| m.as_str()).unwrap_or("");
            if operand2 == "0" || operand2 == "0h" || operand2 == "0H" {
                cases.zero_checks.insert("test_zero".to_string());
            } else if operand2.ends_with('h') || operand2.ends_with('H') {
                // Hexadecimal value
                if let Ok(val) = i64::from_str_radix(&operand2[..operand2.len() - 1], 16) {
                    if val == 0 {
                        cases.zero_checks.insert("test_hex_zero".to_string());
                    } else if val > 0 && val <= 1000 {
                        if !cases.boundary_checks.contains(&val) {
                            cases.boundary_checks.push(val);
                        }
                    }
                }
            }
        }
    }

    /// Extract jump targets from conditional jump instructions.
    fn extract_jump_targets(line: &str, cases: &mut Self) {
        // Match patterns like "je zero_handler" or "jz null_exit"
        if let Some(cap) = regex::Regex::new(r"j(e|z|nz|l|le|g|ge|be|ae|c|nc)\s+(\w+)")
            .ok()
            .and_then(|r| r.captures(line))
        {
            if let Some(target) = cap.get(2) {
                let target_lower = target.as_str().to_lowercase();
                if target_lower.contains("zero")
                    || target_lower.contains("null")
                    || target_lower.contains("empty")
                    || target_lower.contains("neg")
                    || target_lower.contains("underflow")
                    || target_lower.contains("overflow")
                {
                    cases.zero_checks.insert(format!("jump_{}", target.as_str()));
                }
            }
        }
    }

    /// Get all unique boundary values for test generation.
    pub fn get_boundary_values(&self) -> Vec<i64> {
        let mut values: Vec<i64> = self.boundary_checks.clone();
        values.extend(self.negative_checks.clone());
        values.extend(self.max_value_checks.clone());
        values.sort();
        values.dedup();
        values
    }
}

/// Generate diverse test inputs for a function.
///
/// This is the main entry point for test input generation. It combines
/// signature-based and disassembly-based test generation to produce
/// comprehensive test coverage.
///
/// # Arguments
///
/// * `signature` — The function signature string.
/// * `disassembly` — Raw disassembly for edge case detection.
///
/// # Returns
///
/// A vector of [`TestCase`] structs with populated inputs. The expected
/// return values and side effects are left empty (null/empty) since they
/// must be captured from baseline execution.
///
/// # Example
///
/// ```
/// use calxgloss_testgen::generate_test_inputs;
///
/// let sig = "int __stdcall DrawSprite(int x, int y, unsigned int texture_index)";
/// let disassembly = "cmp eax, 0\nje null_handler\ncmp ecx, 256\nja out_of_bounds";
///
/// let tests = generate_test_inputs(sig, disassembly).unwrap();
/// assert!(!tests.is_empty());
/// ```
#[instrument(skip(signature, disassembly))]
pub fn generate_test_inputs(signature: &str, disassembly: &str) -> Result<Vec<TestCase>> {
    let mut test_cases = Vec::new();

    // Parse signature if available
    let parsed = if !signature.is_empty() {
        crate::parse_signature(signature).ok()
    } else {
        None
    };

    // Extract disassembly edge cases
    let edge_cases = DisassemblyEdgeCases::from_disassembly(disassembly);

    if let Some(ref parsed) = parsed {
        // Generate signature-based test cases
        let sig_tests = generate_signature_tests(parsed, &edge_cases);
        test_cases.extend(sig_tests);

        // Generate disassembly-guided test cases
        let dis_tests = generate_disassembly_tests(parsed, &edge_cases);
        test_cases.extend(dis_tests);
    } else if !disassembly.is_empty() {
        // No signature, generate generic tests based on disassembly patterns
        let generic_tests = generate_generic_tests(&edge_cases);
        test_cases.extend(generic_tests);
    }

    // Ensure we have a reasonable minimum number of tests
    if test_cases.len() < 3 {
        test_cases.extend(generate_generic_tests(&edge_cases));
    }

    // Deduplicate test inputs
    test_cases = deduplicate_tests(test_cases);

    debug!(count = test_cases.len(), "Generated test inputs");

    Ok(test_cases)
}

/// Generate test inputs based on the function signature.
fn generate_signature_tests(parsed: &ParsedSignature, edge_cases: &DisassemblyEdgeCases) -> Vec<TestCase> {
    let mut tests = Vec::new();
    let params = &parsed.parameters;

    if params.is_empty() {
        // No parameters, just one test with empty inputs
        tests.push(TestCase {
            inputs: json!({}),
            expected_return: json!(null),
            expected_side_effects: Vec::new(),
        });
        return tests;
    }

    // Generate one test for each combination of boundary values
    let param_boundaries: Vec<Vec<serde_json::Value>> = params
        .iter()
        .map(|p| param_boundary_values(p, edge_cases))
        .collect();

    // Generate cross-product of first two params with remaining at default
    let param_count = params.len();

    // Generate individual parameter boundary tests
    for i in 0..param_count {
        for boundary_value in &param_boundaries[i] {
            let mut inputs = serde_json::Map::new();
            for j in 0..param_count {
                if j == i {
                    inputs.insert(format!("param_{}", j), boundary_value.clone());
                } else {
                    // Use default value for other params
                    inputs.insert(
                        format!("param_{}", j),
                        param_default_value(&params[j]),
                    );
                }
            }
            tests.push(TestCase {
                inputs: json!(inputs),
                expected_return: json!(null),
                expected_side_effects: Vec::new(),
            });
        }
    }

    // Generate a "zero" test if the function has integer parameters
    if has_integer_params(params) {
        let mut inputs = serde_json::Map::new();
        for (i, param) in params.iter().enumerate() {
            inputs.insert(
                format!("param_{}", i),
                param_zero_value(param),
            );
        }
        tests.push(TestCase {
            inputs: json!(inputs),
            expected_return: json!(null),
            expected_side_effects: Vec::new(),
        });
    }

    // Generate a "typical" test with reasonable default values
    let mut inputs = serde_json::Map::new();
    for (i, param) in params.iter().enumerate() {
        inputs.insert(format!("param_{}", i), param_typical_value(param));
    }
    tests.push(TestCase {
        inputs: json!(inputs),
        expected_return: json!(null),
        expected_side_effects: Vec::new(),
    });

    // Generate a "max value" test for the first integer param
    if let Some(first_int_idx) = params.iter().position(|p| is_integer_type(&p.r#type)) {
        let mut inputs = serde_json::Map::new();
        for (j, param) in params.iter().enumerate() {
            if j == first_int_idx {
                inputs.insert(format!("param_{}", j), param_max_value(param));
            } else {
                inputs.insert(format!("param_{}", j), param_default_value(param));
            }
        }
        tests.push(TestCase {
            inputs: json!(inputs),
            expected_return: json!(null),
            expected_side_effects: Vec::new(),
        });
    }

    tests
}

/// Generate test inputs guided by disassembly edge cases.
fn generate_disassembly_tests(
    parsed: &ParsedSignature,
    edge_cases: &DisassemblyEdgeCases,
) -> Vec<TestCase> {
    let mut tests = Vec::new();
    let params = &parsed.parameters;

    if params.is_empty() {
        return tests;
    }

    // Use boundary values from disassembly
    let boundary_values = edge_cases.get_boundary_values();

    for boundary in &boundary_values {
        let mut inputs = serde_json::Map::new();
        // Apply boundary to first integer parameter
        for (i, param) in params.iter().enumerate() {
            if is_integer_type(&param.r#type) {
                inputs.insert(
                    format!("param_{}", i),
                    json!(if param.is_signed { *boundary as i64 } else { ((*boundary as u64).min(u32::MAX as u64) as i64) }),
                );
                break;
            }
        }

        // Fill remaining params with defaults
        for (i, param) in params.iter().enumerate() {
            if !inputs.contains_key(&format!("param_{}", i)) {
                inputs.insert(format!("param_{}", i), param_default_value(param));
            }
        }

        tests.push(TestCase {
            inputs: json!(inputs),
            expected_return: json!(null),
            expected_side_effects: Vec::new(),
        });
    }

    tests
}

/// Generate generic test inputs when no signature is available.
fn generate_generic_tests(edge_cases: &DisassemblyEdgeCases) -> Vec<TestCase> {
    let mut tests = Vec::new();
    let boundary_values = edge_cases.get_boundary_values();

    // Generate a few generic integer test inputs
    let generic_values = vec![0i64, -1, 1, 100, 1000];
    let all_values: Vec<i64> = boundary_values
        .into_iter()
        .chain(generic_values.into_iter())
        .collect();

    for value in all_values {
        let mut inputs = serde_json::Map::new();
        inputs.insert("param_0".to_string(), json!(value));
        inputs.insert("param_1".to_string(), json!(0));
        inputs.insert("param_2".to_string(), json!(0));

        tests.push(TestCase {
            inputs: json!(inputs),
            expected_return: json!(null),
            expected_side_effects: Vec::new(),
        });
    }

    tests
}

/// Get boundary values for a single parameter type.
fn param_boundary_values(param: &ParameterTypeInfo, edge_cases: &DisassemblyEdgeCases) -> Vec<serde_json::Value> {
    let mut values = Vec::new();

    match param.r#type.as_str() {
        "int" | "i32" | "INT32" | "LONG" | "DWORD" => {
            if param.is_signed {
                values.push(json!(0));
                values.push(json!(-1));
                values.push(json!(i32::MIN as i64));
                values.push(json!(i32::MAX as i64));
                values.push(json!(1));
                values.push(json!(-100));
                values.push(json!(100));
            } else {
                values.push(json!(0));
                values.push(json!(u32::MAX));
                values.push(json!(1));
                values.push(json!(100));
                values.push(json!(256));
            }
        }
        "short" | "i16" | "INT16" | "USHORT" | "WORD" => {
            if param.is_signed {
                values.push(json!(0));
                values.push(json!(-1));
                values.push(json!(i16::MIN as i64));
                values.push(json!(i16::MAX as i64));
                values.push(json!(1));
            } else {
                values.push(json!(0));
                values.push(json!(u16::MAX));
                values.push(json!(1));
                values.push(json!(100));
            }
        }
        "char" | "i8" | "INT8" | "UCHAR" | "BYTE" => {
            if param.is_signed {
                values.push(json!(0));
                values.push(json!(-1));
                values.push(json!(i8::MIN as i64));
                values.push(json!(i8::MAX as i64));
            } else {
                values.push(json!(0));
                values.push(json!(u8::MAX));
                values.push(json!(1));
                values.push(json!(255));
            }
        }
        "long long" | "i64" | "INT64" | "LONGLONG" | "ULONG64" => {
            if param.is_signed {
                values.push(json!(0));
                values.push(json!(-1));
                values.push(json!(i64::MIN));
                values.push(json!(i64::MAX));
            } else {
                values.push(json!(0u64));
                values.push(json!(u64::MAX));
                values.push(json!(1u64));
            }
        }
        "bool" | "BOOL" => {
            values.push(json!(false));
            values.push(json!(true));
        }
        "float" => {
            values.push(json!(0.0f32));
            values.push(json!(-1.0f32));
            values.push(json!(1.0f32));
            values.push(json!(f32::MAX));
            values.push(json!(f32::MIN));
        }
        "double" => {
            values.push(json!(0.0f64));
            values.push(json!(-1.0f64));
            values.push(json!(1.0f64));
            values.push(json!(f64::MAX));
            values.push(json!(f64::MIN));
        }
        _ if param.is_pointer => {
            // Null and valid pointer (represented as address)
            values.push(json!(0));
            values.push(json!(0x1000u64));
        }
        _ if param.r#type.contains("char") && param.is_pointer => {
            // String/char pointer
            values.push(json!(""));
            values.push(json!("a"));
            values.push(json!("test"));
            values.push(json!(null));
        }
        _ => {
            // Default: zero/null values
            values.push(json!(0));
            values.push(json!(0u32));
            values.push(json!(0u64));
        }
    }

    // Add edge cases from disassembly that apply to this parameter
    for boundary in edge_cases.get_boundary_values() {
        if is_integer_type(&param.r#type) {
            values.push(json!(if param.is_signed { boundary as i64 } else { ((boundary as u64).min(u32::MAX as u64) as i64) }));
        }
    }

    // Deduplicate
    let mut seen = HashSet::new();
    values.retain(|v| seen.insert(v.to_string()));

    values
}

/// Get the default value for a parameter type.
fn param_default_value(param: &ParameterTypeInfo) -> serde_json::Value {
    if is_integer_type(&param.r#type) {
        if param.is_signed {
            json!(0i64)
        } else {
            json!(0u32)
        }
    } else if is_pointer_type(&param.r#type) {
        json!(null)
    } else if param.r#type.contains("float") || param.r#type.contains("double") {
        json!(0.0f64)
    } else if param.r#type.contains("bool") || param.r#type.contains("BOOL") {
        json!(false)
    } else {
        json!(0)
    }
}

/// Get a zero value for a parameter type.
fn param_zero_value(param: &ParameterTypeInfo) -> serde_json::Value {
    if is_pointer_type(&param.r#type) {
        json!(0u64)
    } else if is_integer_type(&param.r#type) {
        json!(0i64)
    } else {
        json!(0)
    }
}

/// Get a typical/normal value for a parameter type.
fn param_typical_value(param: &ParameterTypeInfo) -> serde_json::Value {
    if is_integer_type(&param.r#type) {
        if param.is_signed {
            json!(42i64)
        } else {
            json!(42u32)
        }
    } else if is_pointer_type(&param.r#type) {
        json!(0u64)
    } else if param.r#type.contains("float") || param.r#type.contains("double") {
        json!(1.0f64)
    } else if param.r#type.contains("bool") || param.r#type.contains("BOOL") {
        json!(true)
    } else {
        json!(0)
    }
}

/// Get the maximum value for a parameter type.
fn param_max_value(param: &ParameterTypeInfo) -> serde_json::Value {
    match param.r#type.as_str() {
        "int" | "i32" | "INT32" | "LONG" => json!(i32::MAX as i64),
        "unsigned int" | "UINT" | "DWORD" => json!(u32::MAX),
        "short" | "i16" | "INT16" => json!(i16::MAX as i64),
        "unsigned short" | "USHORT" | "WORD" => json!(u16::MAX),
        "char" | "i8" | "INT8" => json!(i8::MAX as i64),
        "unsigned char" | "UCHAR" | "BYTE" => json!(u8::MAX),
        "long long" | "i64" | "INT64" | "LONGLONG" => json!(i64::MAX),
        "unsigned long long" | "ULONG64" | "ULONGLONG" => json!(u64::MAX),
        "float" => json!(f32::MAX as f64),
        "double" => json!(f64::MAX),
        "bool" | "BOOL" => json!(true),
        _ if param.r#type.ends_with('*') => json!(0u64),
        _ => json!(0),
    }
}

/// Check if a parameter type is an integer type.
fn is_integer_type(type_str: &str) -> bool {
    let t = type_str.trim().to_lowercase();
    t.contains("int")
        || t.contains("long")
        || t.contains("short")
        || t.contains("char")
        || t.contains("byte")
        || t.contains("uint")
        || t.contains("ulong")
        || t.contains("ushort")
        || t.contains("uchar")
        || t == "bool"
        || t == "BOOL"
        || t == "integer"
}

/// Check if a parameter type is a pointer type.
fn is_pointer_type(type_str: &str) -> bool {
    type_str.trim().ends_with('*')
}

/// Check if the parameter list has any integer parameters.
fn has_integer_params(params: &[ParameterTypeInfo]) -> bool {
    params.iter().any(|p| is_integer_type(&p.r#type))
}

/// Deduplicate test cases by their input values.
fn deduplicate_tests(tests: Vec<TestCase>) -> Vec<TestCase> {
    let mut seen = HashSet::new();
    tests
        .into_iter()
        .filter(|t| {
            let key = t.inputs.to_string();
            seen.insert(key)
        })
        .collect()
}

/// Generate parameter names for a function with unnamed parameters.
pub fn generate_param_names(param_count: usize) -> Vec<String> {
    (0..param_count).map(|i| format!("param_{}", i)).collect()
}
