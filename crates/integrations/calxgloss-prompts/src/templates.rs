//! Prompt templates — Askama template structs for LLM prompt generation.
//!
//! This module contains all the Askama [`Template`](askama::Template) structs
//! used to render translation, fix, and escalation prompts.
//!
//! - [`MinimalTemplate`] — Tier 0: function name, signature, call graph
//! - [`TranslateTemplate`] — Standard translation (disassembly + decompiler + tests)
//! - [`FixTemplate`] — Retry after verification failure
//! - [`EscalateTemplate`] — Retry with additional decompiler context
//! - [`EdgeCaseTemplate`] — Boundary-value test failure fix
//! - [`RichTemplate`] — Complex functions (101-300 instructions)
//! - [`DetailedTemplate`] — Very complex functions (>300 instructions)
//! - [`SignatureTemplate`] — Tier 0: name and signature only
//! - [`WithTestsTemplate`] — Tier 2: disassembly + decompiler + tests
//! - [`ModuleContextTemplate`] — Tier 3: module context with neighbors + data structures
//! - [`FullModuleTemplate`] — Tier 4: full module with shim layer + PAL traits

use askama::Template;
use calxgloss_types::{ApiCategoryMapping, FailureHint, TranslationRequest};
use serde_json::json;

// ============================================================
// Helper structs (non-template)
// ============================================================

/// A formatted test case for template rendering.
#[derive(serde::Serialize, Clone, Debug)]
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

/// A failing edge case test with context.
#[derive(Debug, Clone, serde::Serialize)]
pub struct EdgeCaseTest {
    /// Test index (1-based).
    pub index: usize,
    /// Test inputs as JSON.
    pub inputs: serde_json::Value,
    /// Expected output.
    pub expected: serde_json::Value,
    /// Actual output.
    pub actual: serde_json::Value,
    /// Error message from the test harness.
    pub error: String,
    /// Disassembly hints from the decompiler that explain this branch.
    pub disassembly_hints: String,
}

/// A boundary value check identified in the disassembly.
#[derive(Debug, Clone, serde::Serialize)]
pub struct BoundaryValue {
    /// Human-readable description.
    pub description: String,
    /// The condition being checked (e.g., "x <= 0").
    pub condition: String,
    /// Address of the branch instruction.
    pub branch_address: u64,
}

/// A function that is a direct caller or callee of the target function.
#[derive(Debug, Clone, serde::Serialize)]
pub struct CallGraphNeighbor {
    /// The neighbor function's name.
    pub name: String,
    /// Virtual address of the neighbor.
    pub address: u64,
    /// Signature as the decompiler reports it.
    pub signature: String,
    /// Whether this neighbor calls or is called by the target.
    pub role: String,
}

/// A neighboring function with shared context.
#[derive(Debug, Clone, serde::Serialize)]
pub struct NeighborFunction {
    /// The function name.
    pub name: String,
    /// The DLL containing the function.
    pub binary: String,
    /// Virtual address.
    pub address: u64,
    /// Disassembly listing.
    pub disassembly: String,
    /// Pseudo-C decompiler output.
    pub decompiler_output: String,
}

/// A data structure referenced near the target function.
#[derive(Debug, Clone, serde::Serialize)]
pub struct StructuredData {
    /// Name or type tag.
    pub name: String,
    /// Size in bytes, or 0 if unknown.
    pub size: usize,
    /// Struct fields.
    pub fields: Vec<StructField>,
}

/// A single field within a data structure.
#[derive(Debug, Clone, serde::Serialize)]
pub struct StructField {
    /// Field name.
    pub name: String,
    /// Field type as inferred by the decompiler.
    pub type_: String,
    /// Byte offset from struct start, or -1 if unknown.
    pub offset: i64,
}

/// Type information inferred by the decompiler's type database.
#[derive(Debug, Clone, serde::Serialize)]
pub struct TypeInfo {
    /// Type name or signature.
    pub name: String,
    /// Human-readable description, or empty string when none available.
    pub description: String,
}

/// An algorithm recognized in the target function by the analysis pipeline.
#[derive(Debug, Clone, serde::Serialize)]
pub struct AlgorithmInfo {
    /// The recognized algorithm, e.g. `comparison_sort`.
    pub algorithm: String,
    /// The family the algorithm belongs to, e.g. `sorting`.
    pub category: String,
    /// The detector that recognized it, e.g. `cfg_pattern`.
    pub method: String,
    /// Confidence that the recognition is right, 0–100.
    pub confidence: u8,
    /// The decompiled line or string that supports the recognition.
    pub evidence: String,
}

/// A memory lifecycle finding about the target function, made by the
/// analysis pipeline.
///
/// One finding whichever detector made it — the kind names the detector
/// behind the claim (`allocation`, `handle`, `ref_count`) so the prompt
/// can weigh the hypothesis beside the evidence without knowing the
/// record shape that produced it.
#[derive(Debug, Clone, serde::Serialize)]
pub struct MemoryInfo {
    /// The function the finding is about, e.g. `FUN_18003ab00`.
    pub function: String,
    /// The kind of finding, e.g. `allocation`, `handle`, `ref_count`.
    pub kind: String,
    /// The Rust pattern the pairing suggests, e.g. `Box<T>`.
    pub suggestion: String,
    /// Confidence that the finding is right, 0–100.
    pub confidence: u8,
    /// The decompiled lines that support the finding.
    pub evidence: String,
}

/// A concurrency finding about the target function, made by the
/// analysis pipeline.
///
/// One finding whichever detector made it — the kind names the detector
/// behind the claim (`mutex`, `atomic`, `thread`) so the prompt can weigh
/// the hypothesis beside the evidence without knowing the record shape
/// that produced it.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ConcurrencyInfo {
    /// The function the finding is about, e.g. `FUN_18003ab00`.
    pub function: String,
    /// The kind of finding, e.g. `mutex`, `atomic`, `thread`.
    pub kind: String,
    /// The Rust pattern the finding suggests, e.g. `std::sync::Mutex<T>`.
    pub suggestion: String,
    /// Confidence that the finding is right, 0–100.
    pub confidence: u8,
    /// The decompiled lines that support the finding.
    pub evidence: String,
}

/// A serialization finding about the target function, made by the
/// analysis pipeline.
///
/// One finding whichever detector made it — the kind names the detector
/// behind the claim (`byteswap`, `bitpack`, `magic`,
/// `cross_field_validation`, `serialization_format`,
/// `protocol_message`, `endianness_map`) so the prompt can
/// weigh the hypothesis beside the evidence without knowing the record
/// shape that produced it.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SerializationInfo {
    /// The function the finding is about, e.g. `FUN_18003ab00`.
    pub function: String,
    /// The kind of finding, e.g. `byteswap`, `bitpack`, `magic`,
    /// `cross_field_validation`, `serialization_format`,
    /// `protocol_message`, `endianness_map`.
    pub kind: String,
    /// The Rust pattern the finding suggests, e.g. `byteorder::BE::read_u32`.
    pub suggestion: String,
    /// Confidence that the finding is right, 0–100.
    pub confidence: u8,
    /// The decompiled lines that support the finding.
    pub evidence: String,
}

/// A callback or function-pointer-table finding about one function,
/// made by the `calxgloss-callback` detectors.
///
/// The escalate prompt shows these alongside the other analysis findings
/// so the LLM expresses the callback boundary with a Rust `dyn Fn`
/// pattern instead of transliterating the raw table indexing or
/// registration call.
#[derive(Debug, Clone, serde::Serialize)]
pub struct CallbackInfo {
    /// The function the finding is about, e.g. `FUN_18003ab00`.
    pub function: String,
    /// The kind of finding, e.g. `fp_array`, `registration`, `jump_table`,
    /// `plugin`, `chain`.
    pub kind: String,
    /// The Rust pattern the finding suggests, e.g. `Vec<Box<dyn Fn(...)>>`.
    pub suggestion: String,
    /// Confidence that the finding is right, 0–100.
    pub confidence: u8,
    /// The decompiled lines that support the finding.
    pub evidence: String,
}

/// A control-flow finding about one function, made by the
/// `calxgloss-controlflow` detectors.
///
/// The escalate and context-tier prompts show these alongside the other
/// analysis findings so the LLM expresses switch chains, recursion, and
/// state machines with Rust `match`/`loop`/`enum` patterns instead of
/// transliterating the raw conditional chain or recursive call.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ControlFlowInfo {
    /// The function the finding is about, e.g. `FUN_18003ab00`.
    pub function: String,
    /// The kind of finding, e.g. `switch`, `recursion`, `state_machine`,
    /// `loop`, `branch_density`, `branch_site`, `mutual_recursion`.
    pub kind: String,
    /// The Rust pattern the finding suggests, e.g. `match local_4 { ... }`.
    pub suggestion: String,
    /// Confidence that the finding is right, 0–100.
    pub confidence: u8,
    /// The decompiled lines that support the finding.
    pub evidence: String,
}

/// A global-state access record about one function, made by the
/// `calxgloss-globalstate` detector.
///
/// The module-context and escalate prompts show these so the LLM models
/// the program globals a function reads and writes as shared state with
/// a home in a struct threaded through the translation, instead of
/// inventing a local or reaching for a Rust `static`. The kind names the
/// access direction — `global_read` or `global_write` — and the record
/// names the global it touched.
#[derive(Debug, Clone, serde::Serialize)]
pub struct GlobalStateInfo {
    /// The function that made the access, e.g. `FUN_18003ab00`.
    pub function: String,
    /// The kind of access, e.g. `global_read`, `global_write`.
    pub kind: String,
    /// The global accessed, spelled as the decompiler names it, e.g.
    /// `DAT_180064e80`.
    pub global: String,
    /// The Rust pattern the access steers the translation toward.
    pub suggestion: String,
    /// Confidence that the reading is right, 0–100.
    pub confidence: u8,
    /// The access statement quoted from the body.
    pub evidence: String,
}

/// A float/SIMD usage flag about one function, made by the
/// `calxgloss-floatsimd` detector.
///
/// The module-context and escalate prompts show these so the LLM reads
/// mangled vector pseudo-C — `CONCAT44`-style concatenations,
/// `SUB4`-style extractions, undefined-typed arithmetic over `DAT_*`
/// loads — as float math and translates it as float instead of integer
/// or pointer logic. The kind names the shape the reading found —
/// `scalar_float`, `vector_matrix`, or `mixed` — so the LLM picks the
/// right Rust shape: plain `f32`/`f64` operations versus component
/// arrays or small vector structs.
#[derive(Debug, Clone, serde::Serialize)]
pub struct FloatsimdInfo {
    /// The function the flag is about, e.g. `FUN_18003ab00`.
    pub function: String,
    /// The shape the reading found, e.g. `scalar_float`,
    /// `vector_matrix`, `mixed`.
    pub kind: String,
    /// The Rust shape the flag steers the translation toward.
    pub suggestion: String,
    /// Confidence that the reading is right, 0–100.
    pub confidence: u8,
    /// The body line quoted as the flag's evidence.
    pub evidence: String,
}

/// A known-library identification of one function, made by the
/// `calxgloss-libmatch` body-signature matcher.
///
/// The module-context prompt shows these for the *callees* of the
/// function being translated — a matched target is stubbed, never
/// prompted — so the LLM maps a call onto the suggested Rust equivalent
/// instead of re-implementing statically linked CRT or STL code. The
/// symbol names the matched library routine, the family says which body
/// of standard code it came from (`crt` or `stl`), and the evidence
/// carries the body shape that matched.
#[derive(Debug, Clone, serde::Serialize)]
pub struct LibmatchInfo {
    /// The function the identification is about — a callee of the
    /// function being translated, e.g. `FUN_18003ab00`.
    pub function: String,
    /// The matched library symbol, e.g. `memcpy`.
    pub symbol: String,
    /// The library family the symbol belongs to, `crt` or `stl`.
    pub family: String,
    /// The Rust equivalent the match suggests, e.g. a `std` slice copy
    /// for `memcpy`.
    pub suggestion: String,
    /// Confidence that the match is right, 0–100.
    pub confidence: u8,
    /// The normalized body shape that carried the match.
    pub evidence: String,
}

/// One pointer parameter's direction reading about one function, made by
/// the `calxgloss-typeinfer` direction detector.
///
/// The module-context prompt shows these so the LLM shapes each pointer
/// parameter to the way its data actually flows — a shared borrow for an
/// `in` parameter, a mutable borrow or handed-back value for an `out`
/// parameter, a read-modify-write for an `inout` — instead of guessing
/// the Rust shape from the narrowed type alone. The parameter is named
/// exactly as the type records name it, so the section and the retry
/// prompts' type-info lines agree on which parameter a claim is about,
/// and the evidence line carries the deciding write or read from the
/// body so a reviewer can check the claim.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ParameterDirectionInfo {
    /// The function the parameter belongs to, e.g. `FUN_18003ab00`.
    pub function: String,
    /// The parameter the reading is about, spelled as the decompiler
    /// names it, e.g. `param_2`.
    pub parameter: String,
    /// The direction the body reads: `in`, `out`, or `inout`.
    pub direction: String,
    /// The reading that produced the direction, e.g. `param_direction`.
    pub method: String,
    /// Confidence that the reading is right, 0–100.
    pub confidence: u8,
    /// The decompiled line carrying the deciding write or read.
    pub evidence: String,
}

/// A string-context finding about one function, made by the
/// `calxgloss-stringctx` engines.
///
/// The escalate prompt shows these alongside the other analysis findings
/// so the LLM names the string's role — a file path, an error message, a
/// format string with typed arguments — instead of transliterating the
/// raw literal or `DAT_` reference.
#[derive(Debug, Clone, serde::Serialize)]
pub struct StringContextInfo {
    /// The function the finding is about, e.g. `FUN_18003ab00`.
    pub function: String,
    /// The kind of finding, e.g. `file_path`, `format_string`.
    pub kind: String,
    /// The Rust pattern the finding suggests, e.g. `Path::new("Journal.txt")`.
    pub suggestion: String,
    /// Confidence that the finding is right, 0–100.
    pub confidence: u8,
    /// The decompiled line or xref that supports the finding.
    pub evidence: String,
}

/// A library/API finding about one function or about the binary, made by
/// the `calxgloss-apidetect` engines.
///
/// The escalate prompt shows these alongside the other analysis findings
/// so the LLM calls the API through the suggested Rust crate instead of
/// transliterating the raw import or declaring it as an `extern "C"`
/// stub. The kind names how the API was reached — `import` for a
/// binary-level import-table entry, `direct` or `transitive` for a
/// function-level call-graph usage.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ApiInfo {
    /// The function the finding is about, e.g. `FUN_18003ab00`; empty
    /// for a binary-level import entry.
    pub function: String,
    /// The API the finding names, e.g. `inflate`.
    pub api: String,
    /// The library the API belongs to, e.g. `zlib`.
    pub library: String,
    /// The Rust crate standing in for the API, e.g. `flate2`.
    pub suggestion: String,
    /// The kind of finding, e.g. `import`, `direct`, `transitive`.
    pub kind: String,
    /// Confidence that the finding is right, 0–100.
    pub confidence: u8,
    /// The call path or import entry that supports the finding.
    pub evidence: String,
}

/// A constant or enum finding about one function, made by the
/// `calxgloss-consts` detectors.
///
/// The escalate prompt shows these alongside the other analysis findings
/// so the LLM expresses flag bits, enumerated dispatch, and repeated
/// magic numbers with a bitflags struct, an `enum`, or a named `const`
/// instead of scattering bare integer literals. The kind names the
/// finding family — `bitflag_group`, `enum_candidate`, `named_constant`,
/// `flag_family`, `protocol_constant`.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ConstInfo {
    /// The function the finding is about, e.g. `FUN_18003ab00`.
    pub function: String,
    /// The kind of finding, e.g. `bitflag_group`, `enum_candidate`,
    /// `named_constant`, `flag_family`, `protocol_constant`.
    pub kind: String,
    /// The Rust shape the finding suggests, e.g. a `bitflags!` struct.
    pub suggestion: String,
    /// Confidence that the finding is right, 0–100.
    pub confidence: u8,
    /// The decompiled lines that support the finding.
    pub evidence: String,
}

/// A read-only data table the target function reads, made by the
/// `calxgloss-consts` table reader.
///
/// The module-context prompt names each table the function reads —
/// its listing label, element type, and entry count — so the first
/// translation attempt renders the lookup as a named `const` array
/// instead of match arms over the magic numbers the scattered reads
/// decode to.
#[derive(Debug, Clone, serde::Serialize)]
pub struct DataTableInfo {
    /// The listing label of the table object, e.g. `DAT_1400a1b60`.
    pub name: String,
    /// The element type the entries decode as, e.g. `u16`.
    pub element_type: String,
    /// The full number of entries in the table.
    pub count: usize,
    /// Confidence that the record is right, 0–100.
    pub confidence: u8,
}

/// A calling-convention reading about one function, made by the
/// `calxgloss-typeinfer` convention detector.
///
/// The module-context and escalate prompts show these so the LLM spells
/// extern declarations and any stack cleanup with the detected convention
/// instead of assuming `__stdcall`. The method names the evidence channel
/// behind the claim — `mangled_convention`, `import_decoration`,
/// `callee_epilogue`, `caller_cleanup`, `x64_shape`,
/// `corroborated_convention`, `call_site_convention` — and a call-site
/// record names its callee in `callee`, the caller's view of the function
/// it calls rather than the caller's own convention.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ConventionInfo {
    /// The function the record is about, e.g. `FUN_18003ab00`. For a
    /// call-site record this is the caller holding the site.
    pub function: String,
    /// The callee whose convention the record reads, when the record is
    /// a call-site view rather than the function's own reading.
    pub callee: Option<String>,
    /// The detected convention, e.g. `cdecl`, `stdcall`, `fastcall`,
    /// `thiscall`, `microsoft_x64`.
    pub convention: String,
    /// The evidence channel that produced the reading, e.g.
    /// `callee_epilogue`, `import_decoration`.
    pub method: String,
    /// Confidence that the reading is right, 0–100.
    pub confidence: u8,
    /// The listing or name line that supports the reading, e.g.
    /// `00401007  RET 0xC`.
    pub evidence: String,
}

/// An error-handling finding about one function, made by the
/// `calxgloss-errhandling` scan.
///
/// The module-context and escalate prompts show these so the LLM keeps
/// the function's error-handling contract — an SEH frame mapped to an
/// exception-carrying Rust error type, a `goto`-cleanup ladder mapped to
/// early returns plus RAII or scope guards — instead of flattening the
/// frame into straight-line logic or collapsing the failure codes into
/// ad-hoc error values. The kind spells the serde tag — `seh_frame`,
/// `named_handler`, `exception_api_call`, `raise_exception`,
/// `goto_cleanup`, `error_code`, `inherited_error_code` — and the target
/// names the same reading spelled for a reader. Code-bearing records
/// carry the code in its spelled `0x…` form: failure-code records name
/// the site the literal was read from (`return`, `raise`, `guard`) or
/// the callee an inherited code travels from; a `RaiseException` idiom
/// names the code it raises without becoming a failure-code record.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ErrhandlingInfo {
    /// The function the finding is about, e.g. `FUN_18003ab00`.
    pub function: String,
    /// The kind of finding, e.g. `seh_frame`, `goto_cleanup`,
    /// `error_code`, `inherited_error_code`.
    pub kind: String,
    /// What the finding names, spelled for a reader, e.g.
    /// `try/catch frame`, `failure code`.
    pub target: String,
    /// The Rust pattern the finding steers the translation toward.
    pub suggestion: String,
    /// Confidence that the finding is right, 0–100.
    pub confidence: u8,
    /// The body line that supports the claim.
    pub evidence: String,
    /// The code value in its spelled `0x…` form, for failure-code
    /// records and for a `RaiseException` idiom whose argument named it.
    pub code: Option<String>,
    /// The site kind a failure-code record was read from — `return`,
    /// `raise`, or `guard`.
    pub site: Option<String>,
    /// The callee an inherited failure code travels from.
    pub partner: Option<String>,
}

/// A formatted test result for template rendering.
///
/// Carries the test case data alongside the pass/fail outcome observed
/// during verification, plus the error message for any failed test.
#[derive(serde::Serialize, Clone, Debug)]
pub struct FormattedTestResult {
    /// Test index (1-based).
    pub index: usize,
    /// The test inputs as JSON.
    pub inputs: serde_json::Value,
    /// Expected return value as JSON.
    pub expected: serde_json::Value,
    /// Actual return value observed during verification.
    pub actual: serde_json::Value,
    /// Whether this test passed verification.
    pub passed: bool,
    /// Error message from the test harness, if the test failed.
    pub error: String,
    /// Expected side effects as JSON.
    pub side_effects: serde_json::Value,
}

impl FormattedTestResult {
    /// Build a `FormattedTestResult` from a baseline [`calxgloss_types::TestCase`].
    pub fn from_baseline(test: &calxgloss_types::TestCase, index: usize) -> Self {
        Self {
            index,
            inputs: test.inputs.clone(),
            expected: test.expected_return.clone(),
            actual: test.expected_return.clone(),
            passed: false,
            error: String::new(),
            side_effects: serde_json::to_value(&test.expected_side_effects)
                .unwrap_or_else(|_| serde_json::json!([])),
        }
    }

    /// Build a `FormattedTestResult` from a baseline + [`calxgloss_types::FailedTest`].
    pub fn from_baseline_with_failure(
        baseline: &calxgloss_types::TestCase,
        failed: &calxgloss_types::FailedTest,
        index: usize,
    ) -> Self {
        Self {
            index,
            inputs: failed.inputs.clone(),
            expected: failed.expected.clone(),
            actual: failed.actual.clone(),
            passed: false,
            error: failed.error.clone(),
            side_effects: serde_json::to_value(&baseline.expected_side_effects)
                .unwrap_or_else(|_| serde_json::json!([])),
        }
    }

    /// Build a `FormattedTestResult` for a passing test from baseline.
    pub fn from_baseline_passing(baseline: &calxgloss_types::TestCase, index: usize) -> Self {
        Self {
            index,
            inputs: baseline.inputs.clone(),
            expected: baseline.expected_return.clone(),
            actual: baseline.expected_return.clone(),
            passed: true,
            error: String::new(),
            side_effects: serde_json::to_value(&baseline.expected_side_effects)
                .unwrap_or_else(|_| serde_json::json!([])),
        }
    }
}

// ============================================================
// Minimal template — Tier 0: function name, signature, call graph
// ============================================================

/// Template for minimal translation prompts.
///
/// Used for simple functions (≤30 instructions). Contains disassembly,
/// decompiler output, baseline tests, and optionally API-category-specific
/// mapping table rows when API-aware augmentation is enabled.
#[derive(Template)]
#[template(path = "minimal_translate.j2")]
pub struct MinimalTemplate {
    /// The function name to translate.
    pub function_name: String,
    /// The DLL containing the function.
    pub dll_name: String,
    /// The virtual address of the function entry point.
    pub address: u64,
    /// Raw disassembly listing from the decompiler.
    pub disassembly: String,
    /// Pseudo-C decompiler output.
    pub decompiler_output: String,
    /// Windows API calls identified in the disassembly.
    pub windows_apis: Vec<calxgloss_types::WindowsApiCall>,
    /// Baseline test cases the translated Rust code must pass.
    pub test_cases: Vec<TestCaseFormatted>,
    /// Whether there are no Windows API calls (for conditional rendering).
    pub no_windows_apis: bool,
    /// API-category-specific mapping rows.
    pub api_category_mappings: Vec<calxgloss_types::ApiCategoryMapping>,
}

impl MinimalTemplate {
    /// Create a new minimal template from a translation request.
    pub fn from_request(req: &TranslationRequest) -> Self {
        let test_cases: Vec<TestCaseFormatted> = req
            .baseline_tests
            .iter()
            .enumerate()
            .map(|(i, test)| TestCaseFormatted {
                index: i + 1,
                inputs: test.inputs.clone(),
                expected_return: test.expected_return.clone(),
                side_effects: serde_json::to_value(&test.expected_side_effects)
                    .unwrap_or_else(|_| json!([])),
            })
            .collect();

        MinimalTemplate {
            function_name: req.function.clone(),
            dll_name: req.binary.to_string(),
            address: 0,
            disassembly: req.disassembly.clone(),
            decompiler_output: req.decompiler_output.clone(),
            windows_apis: req.windows_apis.clone(),
            test_cases,
            no_windows_apis: req.windows_apis.is_empty(),
            api_category_mappings: Vec::new(),
        }
    }
}

// ============================================================
// Translate template — standard translation prompt
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
    /// Raw disassembly listing from the decompiler.
    pub disassembly: String,
    /// Pseudo-C decompiler output.
    pub decompiler_output: String,
    /// Windows API calls identified in the disassembly.
    pub windows_apis: Vec<calxgloss_types::WindowsApiCall>,
    /// Baseline test cases the translated Rust code must pass.
    pub test_cases: Vec<TestCaseFormatted>,
    /// Whether there are no Windows API calls (for conditional rendering).
    pub no_windows_apis: bool,
    /// API-category-specific mapping rows.
    pub api_category_mappings: Vec<calxgloss_types::ApiCategoryMapping>,
}

impl TranslateTemplate {
    /// Create a new translate template from a translation request.
    pub fn from_request(req: &TranslationRequest) -> Self {
        let test_cases: Vec<TestCaseFormatted> = req
            .baseline_tests
            .iter()
            .enumerate()
            .map(|(i, test)| TestCaseFormatted {
                index: i + 1,
                inputs: test.inputs.clone(),
                expected_return: test.expected_return.clone(),
                side_effects: serde_json::to_value(&test.expected_side_effects)
                    .unwrap_or_else(|_| json!([])),
            })
            .collect();

        TranslateTemplate {
            function_name: req.function.clone(),
            dll_name: req.binary.to_string(),
            address: 0,
            disassembly: req.disassembly.clone(),
            decompiler_output: req.decompiler_output.clone(),
            windows_apis: req.windows_apis.clone(),
            test_cases,
            no_windows_apis: req.windows_apis.is_empty(),
            api_category_mappings: Vec::new(),
        }
    }
}

// ============================================================
// Fix template — for retrying after verification failure
// ============================================================

/// Template for "fix the compilation errors" or "fix the failing tests" prompts.
///
/// Rendered via Askama from the embedded `templates/failure_fix.j2` file.
#[derive(Template)]
#[template(path = "failure_fix.j2")]
pub struct FixTemplate {
    /// The function name being fixed.
    pub function_name: String,
    /// The DLL containing the function.
    pub dll_name: String,
    /// The previously generated (failing) Rust code.
    pub original_rust_code: String,
    /// A description of what went wrong during verification.
    pub failure_description: String,
    /// Previous attempt failures to reference in the prompt.
    pub failure_history: Vec<FailureHint>,
}

impl FixTemplate {
    /// Create a new fix template without failure history.
    pub fn new(
        function_name: String,
        dll_name: String,
        original_rust_code: String,
        failure_description: String,
    ) -> Self {
        Self {
            function_name,
            dll_name,
            original_rust_code,
            failure_description,
            failure_history: Vec::new(),
        }
    }

    /// Create a new fix template with failure history for informed prompting.
    pub fn with_history(
        function_name: String,
        dll_name: String,
        original_rust_code: String,
        failure_description: String,
        failure_history: Vec<FailureHint>,
    ) -> Self {
        Self {
            function_name,
            dll_name,
            original_rust_code,
            failure_description,
            failure_history,
        }
    }
}

// ============================================================
// Evidence bundle — the finding lists a fix prompt is built from
// ============================================================

/// The decompiler-derived evidence every bundle-fed prompt template renders from.
///
/// Every finding list a template may read, grouped into one struct so the
/// builders take a bundle instead of a dozen same-typed positional lists
/// (issue #268). The bundle is the single render input of the bundle-fed
/// templates (issue #320) — which evidence sections a template shows is a
/// property of which shared section includes that template calls, never of
/// this struct's shape. Each list is optional: a bundle that populates only
/// some findings renders exactly what the old call with empty lists
/// elsewhere rendered.
#[derive(Debug, Clone, Default)]
pub struct EvidenceBundle {
    /// Functions directly called by or calling this function.
    pub call_graph_neighbors: Vec<CallGraphNeighbor>,
    /// Other functions sharing context with this function.
    pub neighboring_functions: Vec<NeighborFunction>,
    /// Data structures referenced near this function.
    pub data_structures: Vec<StructuredData>,
    /// Type information inferred by the decompiler.
    pub type_info: Vec<TypeInfo>,
    /// Algorithms recognized in this function by the analysis pipeline.
    pub recognized_algorithms: Vec<AlgorithmInfo>,
    /// Memory lifecycle findings about this function made by the analysis
    /// pipeline.
    pub memory_findings: Vec<MemoryInfo>,
    /// Concurrency findings about this function made by the analysis
    /// pipeline.
    pub concurrency_findings: Vec<ConcurrencyInfo>,
    /// Callback and function-pointer-table findings about this function
    /// made by the analysis pipeline.
    pub callback_findings: Vec<CallbackInfo>,
    /// Control-flow findings about this function made by the analysis
    /// pipeline.
    pub control_flow_findings: Vec<ControlFlowInfo>,
    /// Calling-convention readings about this function and its callees
    /// made by the type-inference engine.
    pub convention_findings: Vec<ConventionInfo>,
    /// Global-state access records about this function made by the
    /// global-state scan.
    pub global_state_findings: Vec<GlobalStateInfo>,
    /// String-context findings about this function made by the analysis
    /// pipeline.
    pub string_findings: Vec<StringContextInfo>,
    /// Library/API findings about this function and its binary made by
    /// the analysis pipeline.
    pub api_findings: Vec<ApiInfo>,
    /// Constant and enum findings about this function made by the
    /// analysis pipeline.
    pub const_findings: Vec<ConstInfo>,
    /// Endianness and serialization findings about this function made
    /// by the analysis pipeline.
    pub serialization_findings: Vec<SerializationInfo>,
    /// Library-match findings about this function and its call graph —
    /// shown where the module-context template's known-library include
    /// renders them; the escalate template calls no include for this list.
    pub libmatch_findings: Vec<LibmatchInfo>,
    /// Parameter-direction readings about this function made by the
    /// type-inference direction detector — shown where the module-context
    /// template's parameter-directions include renders them; the escalate
    /// template calls no include for this list, its direction lines ride
    /// the type-information include through the finding union's prompt
    /// conversion instead.
    pub parameter_direction_findings: Vec<ParameterDirectionInfo>,
    /// Data tables the target function reads, made by the
    /// `calxgloss-consts` table reader — shown where the module-context
    /// template's data-tables include renders them; the escalate template
    /// calls no include for this list, whose table facts ride the
    /// constants include through the constant findings' union prompt
    /// conversion.
    pub data_table_findings: Vec<DataTableInfo>,
    /// Error-handling findings about this function made by the
    /// `calxgloss-errhandling` scan — the idiom the body guards its
    /// work with and the failure codes it states.
    pub error_handling_findings: Vec<ErrhandlingInfo>,
    /// The float/SIMD usage flag for this function made by the
    /// `calxgloss-floatsimd` scan — one record naming the shape the
    /// body's float evidence spells.
    pub floatsimd_findings: Vec<FloatsimdInfo>,
    /// Enriched call graph context with caller/callee/leaf-API details.
    pub call_graph_context: Vec<calxgloss_callgraph::FunctionContext>,
}

// ============================================================
// Escalate template — for retrying with additional decompiler context
// ============================================================

/// Template for "add more context and retry" prompts.
///
/// Used when previous attempts failed with compile_fix or test_fix strategies.
/// The gathered evidence rides in as one [`EvidenceBundle`] — the single
/// render input of every bundle-fed template (issue #320) — so the template
/// carries only what is genuinely escalate-tier: the function identity, the
/// failing code and its failure description, and the failure history. Which
/// evidence sections the prompt shows is a property of the includes
/// `escalate.j2` calls, not of this struct's fields.
#[derive(Template)]
#[template(path = "escalate.j2")]
pub struct EscalateTemplate {
    /// The function name being fixed.
    pub function_name: String,
    /// The DLL containing the function.
    pub dll_name: String,
    /// The previously generated (failing) Rust code.
    pub original_rust_code: String,
    /// A description of what went wrong during verification.
    pub failure_description: String,
    /// The gathered decompiler evidence, rendered through the template's
    /// shared section includes as one bundle.
    pub evidence: EvidenceBundle,
    /// Previous attempt failures to reference in the prompt.
    pub failure_history: Vec<FailureHint>,
}

impl EscalateTemplate {
    /// Create a new escalate template without failure history.
    pub fn new(
        function_name: String,
        dll_name: String,
        original_rust_code: String,
        failure_description: String,
        evidence: EvidenceBundle,
    ) -> Self {
        Self::with_history(
            function_name,
            dll_name,
            original_rust_code,
            failure_description,
            evidence,
            Vec::new(),
        )
    }

    /// Create a new escalate template with failure history.
    pub fn with_history(
        function_name: String,
        dll_name: String,
        original_rust_code: String,
        failure_description: String,
        evidence: EvidenceBundle,
        failure_history: Vec<FailureHint>,
    ) -> Self {
        Self {
            function_name,
            dll_name,
            original_rust_code,
            failure_description,
            evidence,
            failure_history,
        }
    }
}

// ============================================================
// Edge case template — for boundary-value test failures
// ============================================================

/// Template for "fix edge cases" prompts.
///
/// Used when tests fail specifically on boundary values (zero, max, negative).
#[derive(Template)]
#[template(path = "edge_case.j2")]
pub struct EdgeCaseTemplate {
    /// The function name being fixed.
    pub function_name: String,
    /// The DLL containing the function.
    pub dll_name: String,
    /// The previously generated (failing) Rust code.
    pub original_rust_code: String,
    /// Failing edge case test details.
    pub failed_tests: Vec<EdgeCaseTest>,
    /// Boundary checks identified from the disassembly.
    pub boundary_values: Vec<BoundaryValue>,
    /// Previous attempt failures to reference in the prompt.
    pub failure_history: Vec<FailureHint>,
}

impl EdgeCaseTemplate {
    /// Create a new edge case template without failure history.
    pub fn new(
        function_name: String,
        dll_name: String,
        original_rust_code: String,
        failed_tests: Vec<EdgeCaseTest>,
        boundary_values: Vec<BoundaryValue>,
    ) -> Self {
        Self {
            function_name,
            dll_name,
            original_rust_code,
            failed_tests,
            boundary_values,
            failure_history: Vec::new(),
        }
    }

    /// Create a new edge case template with failure history.
    pub fn with_history(
        function_name: String,
        dll_name: String,
        original_rust_code: String,
        failed_tests: Vec<EdgeCaseTest>,
        boundary_values: Vec<BoundaryValue>,
        failure_history: Vec<FailureHint>,
    ) -> Self {
        Self {
            function_name,
            dll_name,
            original_rust_code,
            failed_tests,
            boundary_values,
            failure_history,
        }
    }
}

// ============================================================
// Rich template — for complex functions (101-300 instructions)
// ============================================================

/// Template for "rich context" translation prompts.
///
/// Used when a function has 101–300 instructions, multiple API categories,
/// or high branch density.
#[derive(Template)]
#[template(path = "rich_translate.j2")]
pub struct RichTemplate {
    /// The function name to translate.
    pub function_name: String,
    /// The DLL containing the function.
    pub dll_name: String,
    /// The virtual address of the function entry point.
    pub address: u64,
    /// Raw disassembly listing from the decompiler.
    pub disassembly: String,
    /// Pseudo-C decompiler output.
    pub decompiler_output: String,
    /// Windows API calls identified in the disassembly.
    pub windows_apis: Vec<calxgloss_types::WindowsApiCall>,
    /// Whether there are no Windows API calls.
    pub no_windows_apis: bool,
    /// Baseline test cases.
    pub test_cases: Vec<TestCaseFormatted>,
    /// API-category-specific mapping rows.
    pub api_category_mappings: Vec<ApiCategoryMapping>,
    /// Type information inferred by the decompiler.
    pub type_info: Vec<TypeInfo>,
    /// Control-flow findings about this function made by the analysis
    /// pipeline.
    pub control_flow_findings: Vec<ControlFlowInfo>,
}

impl RichTemplate {
    /// Create a new rich template from a translation request.
    pub fn from_request(req: &TranslationRequest) -> Self {
        let test_cases: Vec<TestCaseFormatted> = req
            .baseline_tests
            .iter()
            .enumerate()
            .map(|(i, test)| TestCaseFormatted {
                index: i + 1,
                inputs: test.inputs.clone(),
                expected_return: test.expected_return.clone(),
                side_effects: serde_json::to_value(&test.expected_side_effects)
                    .unwrap_or_else(|_| json!([])),
            })
            .collect();

        RichTemplate {
            function_name: req.function.clone(),
            dll_name: req.binary.to_string(),
            address: 0,
            disassembly: req.disassembly.clone(),
            decompiler_output: req.decompiler_output.clone(),
            windows_apis: req.windows_apis.clone(),
            no_windows_apis: req.windows_apis.is_empty(),
            test_cases,
            api_category_mappings: Vec::new(),
            type_info: Vec::new(),
            control_flow_findings: Vec::new(),
        }
    }
}

// ============================================================
// Detailed template — for very complex functions (>300 instructions)
// ============================================================

/// Template for "detailed context" translation prompts.
///
/// Used when a function exceeds 300 instructions or has extreme complexity.
#[derive(Template)]
#[template(path = "detailed_translate.j2")]
pub struct DetailedTemplate {
    /// The function name to translate.
    pub function_name: String,
    /// The DLL containing the function.
    pub dll_name: String,
    /// The virtual address of the function entry point.
    pub address: u64,
    /// Raw disassembly listing from the decompiler.
    pub disassembly: String,
    /// Pseudo-C decompiler output.
    pub decompiler_output: String,
    /// Windows API calls identified in the disassembly.
    pub windows_apis: Vec<calxgloss_types::WindowsApiCall>,
    /// Whether there are no Windows API calls.
    pub no_windows_apis: bool,
    /// Baseline test cases.
    pub test_cases: Vec<TestCaseFormatted>,
    /// API-category-specific mapping rows.
    pub api_category_mappings: Vec<ApiCategoryMapping>,
    /// Functions directly called by or calling this function.
    pub call_graph_neighbors: Vec<CallGraphNeighbor>,
    /// Other functions sharing context with this function.
    pub neighboring_functions: Vec<NeighborFunction>,
    /// Data structures referenced near this function.
    pub data_structures: Vec<StructuredData>,
    /// Type information inferred by the decompiler.
    pub type_info: Vec<TypeInfo>,
    /// Control-flow findings about this function made by the analysis
    /// pipeline.
    pub control_flow_findings: Vec<ControlFlowInfo>,
}

impl DetailedTemplate {
    /// Create a new detailed template from a translation request.
    pub fn from_request(req: &TranslationRequest) -> Self {
        let test_cases: Vec<TestCaseFormatted> = req
            .baseline_tests
            .iter()
            .enumerate()
            .map(|(i, test)| TestCaseFormatted {
                index: i + 1,
                inputs: test.inputs.clone(),
                expected_return: test.expected_return.clone(),
                side_effects: serde_json::to_value(&test.expected_side_effects)
                    .unwrap_or_else(|_| json!([])),
            })
            .collect();

        DetailedTemplate {
            function_name: req.function.clone(),
            dll_name: req.binary.to_string(),
            address: 0,
            disassembly: req.disassembly.clone(),
            decompiler_output: req.decompiler_output.clone(),
            windows_apis: req.windows_apis.clone(),
            no_windows_apis: req.windows_apis.is_empty(),
            test_cases,
            api_category_mappings: Vec::new(),
            call_graph_neighbors: Vec::new(),
            neighboring_functions: Vec::new(),
            data_structures: Vec::new(),
            type_info: Vec::new(),
            control_flow_findings: Vec::new(),
        }
    }
}

// ============================================================
// Signature template — Tier 0: function name, signature, call graph
// ============================================================

/// Template for Tier 0 translation prompts (name and signature only).
///
/// Contains only the function name, signature, and call graph neighbors.
#[derive(Template)]
#[template(path = "signature_translate.j2")]
pub struct SignatureTemplate {
    /// The function name to translate.
    pub function_name: String,
    /// The DLL containing the function.
    pub dll_name: String,
    /// Virtual address as a hex string.
    pub address_hex: String,
    /// The inferred C signature from the decompiler.
    pub signature: String,
    /// Functions directly called by or calling this function.
    pub call_graph_neighbors: Vec<CallGraphNeighbor>,
}

impl SignatureTemplate {
    /// Create a new signature template from tier-0 data.
    pub fn from_data(data: &super::context::SignaturePromptData) -> Self {
        SignatureTemplate {
            function_name: data.function_name.clone(),
            dll_name: data.dll_name.clone(),
            address_hex: data.address_hex.clone(),
            signature: data.signature.clone(),
            call_graph_neighbors: data.call_graph_neighbors.clone(),
        }
    }
}

// ============================================================
// With-tests template — Tier 2: disassembly + decompiler + tests
// ============================================================

/// Template for Tier 2 translation prompts (disassembly + decompiler + baseline tests).
///
/// Contains full disassembly, decompiler pseudo-C, tagged Windows API calls,
/// call graph neighbors, and baseline test results with pass/fail status.
#[derive(Template)]
#[template(path = "with_tests_translate.j2")]
pub struct WithTestsTemplate {
    /// The function name to translate.
    pub function_name: String,
    /// The DLL containing the function.
    pub dll_name: String,
    /// Virtual address of the function entry point.
    pub address: u64,
    /// Raw disassembly listing from the decompiler.
    pub disassembly: String,
    /// Pseudo-C decompiler output.
    pub decompiler_output: String,
    /// Windows API calls identified in the disassembly.
    pub windows_apis: Vec<calxgloss_types::WindowsApiCall>,
    /// Whether there are no Windows API calls.
    pub no_windows_apis: bool,
    /// Functions directly called by or calling this function.
    pub call_graph_neighbors: Vec<CallGraphNeighbor>,
    /// Baseline test results with pass/fail status and error details.
    pub test_results: Vec<FormattedTestResult>,
    /// Enriched call graph context with caller/callee/leaf-API details.
    pub call_graph_context: Vec<calxgloss_callgraph::FunctionContext>,
}

impl WithTestsTemplate {
    /// Create a new with-tests template from tier-2 data.
    pub fn from_data(data: &super::context::WithTestsPromptData) -> Self {
        WithTestsTemplate {
            function_name: data.function_name.clone(),
            dll_name: data.dll_name.clone(),
            address: data.address,
            disassembly: data.disassembly.clone(),
            decompiler_output: data.decompiler_output.clone(),
            windows_apis: data.windows_apis.clone(),
            no_windows_apis: data.no_windows_apis,
            call_graph_neighbors: data.call_graph_neighbors.clone(),
            test_results: data.test_results.clone(),
            call_graph_context: data.call_graph_context.clone(),
        }
    }
}

// ============================================================
// Module context template — Tier 3: disassembly + tests + neighbors
// ============================================================

/// Template for Tier 3 translation prompts (disassembly + decompiler + tests
/// + neighboring function context + shared data structures).
///
/// Contains full disassembly, decompiler pseudo-C, tagged Windows API calls,
/// baseline test results, and — through the one [`EvidenceBundle`] it renders
/// over (issue #320) — call graph neighbors, neighboring function code and
/// decompiler output, shared data structure definitions, and the shared
/// evidence sections its includes call. The bundle is the single render
/// input; this struct keeps only the tier's own fields.
#[derive(Template)]
#[template(path = "module_context_translate.j2")]
pub struct ModuleContextTemplate {
    /// The function name to translate.
    pub function_name: String,
    /// The DLL containing the function.
    pub dll_name: String,
    /// Virtual address of the function entry point.
    pub address: u64,
    /// Raw disassembly listing from the decompiler.
    pub disassembly: String,
    /// Pseudo-C decompiler output.
    pub decompiler_output: String,
    /// Windows API calls identified in the disassembly.
    pub windows_apis: Vec<calxgloss_types::WindowsApiCall>,
    /// Whether there are no Windows API calls.
    pub no_windows_apis: bool,
    /// Baseline test results with pass/fail status and error details.
    pub test_results: Vec<FormattedTestResult>,
    /// The gathered decompiler evidence, rendered through the template's
    /// shared section includes as one bundle.
    pub evidence: EvidenceBundle,
}

impl ModuleContextTemplate {
    /// Create a new module context template from a [`TranslationRequest`]
    /// and the gathered [`EvidenceBundle`] — the builder's
    /// `(request, bundle)` seam (issue #320). The finding lists move into
    /// the template as one bundle; nothing copies them field by field.
    pub fn from_request(req: &TranslationRequest, evidence: EvidenceBundle) -> Self {
        let test_results: Vec<FormattedTestResult> = req
            .baseline_tests
            .iter()
            .enumerate()
            .map(|(i, test)| FormattedTestResult::from_baseline(test, i + 1))
            .collect();

        ModuleContextTemplate {
            function_name: req.function.clone(),
            dll_name: req.binary.to_string(),
            address: 0,
            disassembly: req.disassembly.clone(),
            decompiler_output: req.decompiler_output.clone(),
            windows_apis: req.windows_apis.clone(),
            no_windows_apis: req.windows_apis.is_empty(),
            test_results,
            evidence,
        }
    }
}

// ============================================================
// Helper structs for Tier 4 — shim layer code + PAL traits
// ============================================================

/// A shim layer code block for a crate-replacement DLL.
///
/// Contains the generated Rust shim source code that bridges
/// the original Windows DLL's API surface to a target Rust crate.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ShimCode {
    /// The original DLL filename (e.g., `"d3d9.dll"`).
    pub source_dll: String,
    /// The target Rust crate name (e.g., `"wgpu"`).
    pub target_crate: String,
    /// Number of API mappings in this shim layer.
    pub mapping_count: usize,
    /// The full generated Rust source code of the shim layer.
    pub source: String,
}

/// A Platform Abstraction Layer (PAL) trait definition.
///
/// Represents a PAL trait with its methods, used to abstract
/// platform-specific APIs (DirectX → wgpu, GDI → tiny-skia, etc.)
/// so the LLM knows the exact trait interface to call.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PalTraitDef {
    /// The trait name (e.g., `"GraphicsDevice"`).
    pub trait_name: String,
    /// The crate or module this trait belongs to (e.g., `"pal"`).
    pub module: String,
    /// A one-line description of what this trait abstracts.
    pub description: String,
    /// The list of methods in this trait.
    pub methods: Vec<PalTraitMethod>,
}

/// A single method within a PAL trait definition.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PalTraitMethod {
    /// The method name.
    pub name: String,
    /// The full method signature (e.g., `"fn create_texture(&mut self, width: u32, height: u32) -> Self::Texture"`).
    pub signature: String,
    /// A one-line description of what the method does.
    pub description: String,
}

// ============================================================
// Full module template — Tier 4: module context + shims + PAL
// ============================================================

/// Template for Tier 4 translation prompts (full module context).
///
/// Contains everything from Tier 3 — rendered through the one
/// [`EvidenceBundle`] it builds over alongside [`ModuleContextTemplate`]
/// (issue #320) — plus shim layer code for crate-replacement DLLs and PAL
/// trait definitions for platform abstraction. This tier is used when
/// translating functions that call through shim layers and need the full
/// translation-layer context to map correctly.
#[derive(Template)]
#[template(path = "full_module_translate.j2")]
pub struct FullModuleTemplate {
    /// The function name to translate.
    pub function_name: String,
    /// The DLL containing the function.
    pub dll_name: String,
    /// Virtual address of the function entry point.
    pub address: u64,
    /// Raw disassembly listing from the decompiler.
    pub disassembly: String,
    /// Pseudo-C decompiler output.
    pub decompiler_output: String,
    /// Windows API calls identified in the disassembly.
    pub windows_apis: Vec<calxgloss_types::WindowsApiCall>,
    /// Whether there are no Windows API calls.
    pub no_windows_apis: bool,
    /// Baseline test results with pass/fail status and error details.
    pub test_results: Vec<FormattedTestResult>,
    /// Shim layer code for crate-replacement DLLs (e.g., d3d9 → wgpu).
    pub shim_layers: Vec<ShimCode>,
    /// PAL trait definitions for platform abstraction.
    pub pal_traits: Vec<PalTraitDef>,
    /// The gathered decompiler evidence, rendered through the template's
    /// shared section includes as one bundle.
    pub evidence: EvidenceBundle,
}

impl FullModuleTemplate {
    /// Create a new full module template from a [`TranslationRequest`], the
    /// gathered [`EvidenceBundle`], and the workspace's shim layers and PAL
    /// traits — the builder's `(request, bundle)` seam (issue #320). The
    /// finding lists move into the template as one bundle; nothing copies
    /// them field by field.
    pub fn from_request(
        req: &TranslationRequest,
        evidence: EvidenceBundle,
        shim_layers: Vec<ShimCode>,
        pal_traits: Vec<PalTraitDef>,
    ) -> Self {
        let test_results: Vec<FormattedTestResult> = req
            .baseline_tests
            .iter()
            .enumerate()
            .map(|(i, test)| FormattedTestResult::from_baseline(test, i + 1))
            .collect();

        FullModuleTemplate {
            function_name: req.function.clone(),
            dll_name: req.binary.to_string(),
            address: 0,
            disassembly: req.disassembly.clone(),
            decompiler_output: req.decompiler_output.clone(),
            windows_apis: req.windows_apis.clone(),
            no_windows_apis: req.windows_apis.is_empty(),
            test_results,
            shim_layers,
            pal_traits,
            evidence,
        }
    }
}
