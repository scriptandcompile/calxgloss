//! Shim layer API contract for crate-replacement DLLs.
//!
//! This module defines the types that represent a shim layer — a translation
//! bridge between a Windows DLL's exported API surface and a Rust crate's API.
//! Shim layers are produced by the translation pipeline after DLL classification
//! identifies crate-replacement candidates.
//!
//! # Flow
//!
//! 1. DLL classification marks a DLL as [`DllCategory::MicrosoftSdk`] or
//!    [`DllCategory::KnownThirdParty`] → [`ShimLayerDeclaration`] is produced
//!    by the dependency tracker in `calxgloss-analysis`.
//! 2. The LLM generates [`ShimApiMapping`] entries mapping each exported
//!    function to a target crate API with parameter transformations.
//! 3. [`ShimLayer`] holds the complete mapping set; downstream tools
//!    (code generator, test generator, verifier) consume it to produce
//!    shim source code, shim tests, and verification harnesses.

use serde::{Deserialize, Serialize};

use crate::FailedTest;

/// A single API mapping between an original DLL export and a target crate API.
///
/// Each entry describes how to translate one call from the original DLL's
/// API surface into a call on the equivalent Rust crate.
///
/// # Example
///
/// Mapping a DirectX 9 texture-set call to wgpu:
///
/// ```
/// use calxgloss_types::{ShimApiMapping, ComplexityScore, ReturnMapping};
///
/// let mapping = ShimApiMapping {
///     original_api: "SetTexture".to_string(),
///     original_params: vec![
///         "UINT Stage".to_string(),
///         "IDirect3DBaseTexture9* pTexture".to_string(),
///     ],
///     crate_api: "encoder.set_bind_group".to_string(),
///     crate_params: vec![
///         "stage_index: u32".to_string(),
///         "bind_group: &BindGroup".to_string(),
///     ],
///     parameter_transforms: vec![
///         "Stage → stage_index (direct cast to u32)".to_string(),
///         "pTexture → lookup texture view from heap, create/bind group".to_string(),
///     ],
///     return_mapping: ReturnMapping::Identity,
///     complexity: ComplexityScore::Medium,
///     notes: "Requires managing a texture-to-bindgroup heap.".to_string(),
/// };
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShimApiMapping {
    /// The original DLL exported function name (e.g., `"SetTexture"`).
    pub original_api: String,

    /// The original function's parameter signatures as declared by the DLL
    /// (e.g., `["UINT Stage", "IDirect3DBaseTexture9* pTexture"]`).
    ///
    /// The vector should be ordered to match the function's parameter order.
    #[serde(default)]
    pub original_params: Vec<String>,

    /// The target Rust crate API path (e.g., `"wgpu::CommandEncoder::set_bind_group"`).
    pub crate_api: String,

    /// The crate API's parameter signatures as they should appear in the
    /// generated shim (e.g., `["stage_index: u32", "bind_group: &BindGroup"]`).
    #[serde(default)]
    pub crate_params: Vec<String>,

    /// Human-readable descriptions of how each original parameter maps to
    /// the target parameter, including any transformation logic.
    ///
    /// Each entry should correspond positionally to
    /// [`Self::original_params`].
    #[serde(default)]
    pub parameter_transforms: Vec<String>,

    /// How the return value (if any) is handled by the shim.
    #[serde(default)]
    pub return_mapping: ReturnMapping,

    /// Estimated implementation complexity, used for prioritizing shim work
    /// and for surfacing complexity scores in the review dashboard.
    #[serde(default)]
    pub complexity: ComplexityScore,

    /// Additional notes about the mapping — edge cases, known divergences,
    /// or context the LLM or reviewer should be aware of.
    #[serde(default)]
    pub notes: String,
}

impl ShimApiMapping {
    /// Creates a new shim API mapping with owned string fields.
    ///
    /// Use this constructor when all fields need to be set at once.
    /// For mostly-identity mappings with few transforms, consider
    /// the more ergonomic builder-style pattern instead.
    pub fn new(
        original_api: String,
        crate_api: String,
        complexity: ComplexityScore,
    ) -> Self {
        Self {
            original_api,
            original_params: Vec::new(),
            crate_api,
            crate_params: Vec::new(),
            parameter_transforms: Vec::new(),
            return_mapping: ReturnMapping::default(),
            complexity,
            notes: String::new(),
        }
    }

    /// Returns `true` if this mapping is an identity pass-through
    /// (same parameter types, same return type, no transforms).
    pub fn is_identity(&self) -> bool {
        self.original_params.len() == self.crate_params.len()
            && self.original_params == self.crate_params
            && self.parameter_transforms.is_empty()
            && matches!(self.return_mapping, ReturnMapping::Identity)
    }
}

/// How the return value of an original API call is handled in the shim.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum ReturnMapping {
    /// The return value is passed through unchanged.
    #[default]
    Identity,

    /// The original returns a Windows-specific type that needs
    /// conversion to the crate's equivalent.
    Converted(String),

    /// The original returns a value but the crate's equivalent
    /// is infallible (no return value, returns `()`).
    Discarded,

    /// The original function does not return a value.
    Void,

    /// Custom conversion logic is needed beyond what the crate
    /// supports.
    Custom(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum ComplexityScore {
    /// Straightforward one-to-one mapping with no parameter transforms.
    #[default]
    Low,
    /// Requires parameter transformation or a small amount of helper logic.
    Medium,
    /// Complex transformations, multi-step translation, or significant
    /// divergence between the original API and the crate's API.
    High,
}

impl ComplexityScore {
    /// Returns the numeric score for this complexity level.
    ///
    /// `Low` = 1, `Medium` = 3, `High` = 5.
    pub fn as_score(&self) -> usize {
        match self {
            ComplexityScore::Low => 1,
            ComplexityScore::Medium => 3,
            ComplexityScore::High => 5,
        }
    }
}

/// A complete shim layer for a single crate-replacement DLL.
///
/// The shim layer bridges the gap between the original DLL's exported
/// API surface and the target Rust crate's API. It is the artifact that
/// the translation pipeline produces from classifications and LLM-generated
/// API mappings.
///
/// # Example
///
/// ```
/// use calxgloss_types::{ShimLayer, ShimApiMapping, ComplexityScore};
///
/// let shim = ShimLayer {
///     source_dll: "d3d9.dll".to_string(),
///     target_crate: "wgpu".to_string(),
///     mappings: vec![
///         ShimApiMapping::new(
///             "Present".to_string(),
///             "wgpu::Queue::submit".to_string(),
///             ComplexityScore::Medium,
///         ),
///         ShimApiMapping::new(
///             "ClearRenderTargetView".to_string(),
///             "wgpu::RenderPass::clear_color".to_string(),
///             ComplexityScore::Medium,
///         ),
///     ],
/// };
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShimLayer {
    /// The original DLL filename (e.g., `"d3d9.dll"`).
    pub source_dll: String,

    /// The Rust crate that provides equivalent functionality (e.g., `"wgpu"`).
    pub target_crate: String,

    /// The API mappings that translate each exported function from the
    /// original DLL to the target crate's API.
    pub mappings: Vec<ShimApiMapping>,
}

impl ShimLayer {
    /// Creates a new shim layer with the given DLL, crate, and an empty
    /// mapping list.
    ///
    /// Use [`ShimLayer::add_mapping`] to populate mappings incrementally.
    pub fn new(source_dll: String, target_crate: String) -> Self {
        Self {
            source_dll,
            target_crate,
            mappings: Vec::new(),
        }
    }

    /// Adds an API mapping to this shim layer.
    pub fn add_mapping(&mut self, mapping: ShimApiMapping) {
        self.mappings.push(mapping);
    }

    /// Returns `true` if this shim layer has no mappings.
    pub fn is_empty(&self) -> bool {
        self.mappings.is_empty()
    }

    /// Returns the number of API mappings in this shim layer.
    pub fn mapping_count(&self) -> usize {
        self.mappings.len()
    }

    /// Returns the total estimated complexity across all mappings.
    ///
    /// `Low` counts as 1, `Medium` as 3, `High` as 5.
    pub fn total_complexity(&self) -> usize {
        self.mappings.iter().map(|m| m.complexity.as_score()).sum()
    }

    /// Categorizes the shim by its dominant complexity level.
    pub fn overall_complexity(&self) -> ComplexityScore {
        if self.mappings.is_empty() {
            return ComplexityScore::Low;
        }
        let total = self.total_complexity();
        let avg = total as f64 / self.mappings.len() as f64;
        if avg < 2.0 {
            ComplexityScore::Low
        } else if avg < 4.0 {
            ComplexityScore::Medium
        } else {
            ComplexityScore::High
        }
    }
}

impl ShimApiMapping {
    /// Converts this mapping into a [`crate::ApiMappingItem`] suitable
    /// for inclusion in translation prompts.
    ///
    /// The resulting item maps the original API name to the crate API,
    /// with the parameter transforms and notes folded into the notes field.
    pub fn to_api_mapping_item(&self) -> crate::ApiMappingItem {
        let rust_equivalent = self.crate_api.clone();
        let mut notes = String::new();
        if !self.notes.is_empty() {
            notes.push_str(&self.notes);
        }
        if !self.parameter_transforms.is_empty() {
            if !notes.is_empty() {
                notes.push('\n');
            }
            notes.push_str("Parameter transforms:\n");
            for (i, t) in self.parameter_transforms.iter().enumerate() {
                let idx = i + 1;
                notes.push_str(&format!("  {idx}. {t}\n"));
            }
        }
        crate::ApiMappingItem {
            windows_api: self.original_api.clone(),
            rust_equivalent,
            notes,
        }
    }
}

/// Converts a DLL filename into a valid Rust module name.
///
/// Strips the `.dll` extension (if present) and replaces hyphens
/// and dots with underscores, converting the result to lowercase.
///
/// # Examples
///
/// ```
/// use calxgloss_types::dll_to_module_name;
///
/// assert_eq!(dll_to_module_name("d3d9.dll"), "d3d9");
/// assert_eq!(dll_to_module_name("fmod.dll"), "fmod");
/// assert_eq!(dll_to_module_name("my_lib.dll"), "my_lib");
/// assert_eq!(dll_to_module_name("kernel32"), "kernel32");
/// ```
pub fn dll_to_module_name(dll_name: &str) -> String {
    dll_name
        .trim_end_matches(".dll")
        .trim_end_matches(".DLL")
        .replace(['-', '.'], "_")
        .to_lowercase()
}

/// Result of verifying a shim layer's behavior against baseline tests.
///
/// Produced by [`calxgloss_verify::Verifier::verify_shim`] after the shim
/// code is compiled and tested in a sandboxed scratch project. Reports
/// compilation status, per-mapping test results, and overall pass rate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShimVerificationResult {
    /// Whether the shim code compiled without errors.
    pub compiled: bool,

    /// Compilation error messages, if compilation failed.
    pub compilation_errors: Vec<String>,

    /// Compilation warnings, if any were emitted.
    pub compilation_warnings: Vec<String>,

    /// Number of shim mapping tests that passed.
    pub tests_passed: usize,

    /// Total number of shim mapping tests executed.
    pub tests_total: usize,

    /// Edge-case tests that passed.
    pub edge_tests_passed: usize,

    /// Edge-case tests that were executed.
    pub edge_tests_total: usize,

    /// Detailed information about each shim test that failed.
    pub failed_tests: Vec<FailedTest>,

    /// Per-mapping pass counts.  Each entry corresponds one-to-one with
    /// the mappings in the shim layer that was verified.
    pub mapping_results: Vec<ShimMappingTestResult>,
}

impl ShimVerificationResult {
    /// Returns the total number of tests executed (mapping + edge-case).
    pub fn total_tests(&self) -> usize {
        self.tests_total + self.edge_tests_total
    }

    /// Returns the total number of tests that passed (mapping + edge-case).
    pub fn total_passed(&self) -> usize {
        self.tests_passed + self.edge_tests_passed
    }

    /// Returns `true` if the shim passed all tests on all mappings.
    pub fn all_passed(&self) -> bool {
        self.compiled
            && self.total_passed() == self.total_tests()
            && self.total_tests() > 0
    }

    /// Returns the overall pass rate as a floating-point ratio in `[0.0, 1.0]`.
    ///
    /// Returns `1.0` when there are no tests, and `0.0` when there are tests
    /// but none passed.
    pub fn pass_rate(&self) -> f64 {
        let total = self.total_tests();
        if total == 0 {
            return 1.0;
        }
        self.total_passed() as f64 / total as f64
    }
}

/// Per-mapping test result within a [`ShimVerificationResult`].
///
/// Each entry records how many of the mapping's associated tests
/// (parameter test + edge-case tests) passed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShimMappingTestResult {
    /// The original API function name (e.g., `"Direct3DCreate9"`).
    pub original_api: String,

    /// The target crate API path.
    pub crate_api: String,

    /// Number of tests that passed for this mapping.
    pub passed: usize,

    /// Total number of tests for this mapping.
    pub total: usize,

    /// Detailed failures for this mapping.
    pub failures: Vec<FailedTest>,
}

/// A suggested shim layer for a crate-replacement DLL.
///
/// Produced automatically after DLL classification. It estimates
/// the mapping complexity from symbol counts and known crate patterns
/// without requiring an LLM call. The suggestion is persisted to
/// `re/shims/<dll_name>/suggestion.json` so the reviewer can inspect
/// expected shim size and complexity before triggering the full
/// LLM-driven mapping generation.
///
/// # Example
///
/// ```
/// use calxgloss_types::{ShimSuggestion, ComplexityScore};
///
/// let suggestion = ShimSuggestion {
///     source_dll: "d3d9.dll".to_string(),
///     target_crate: "wgpu".to_string(),
///     estimated_mappings: 47,
///     estimated_complexity: ComplexityScore::High,
///     estimated_confidence: 0.85,
/// };
/// assert_eq!(suggestion.source_dll, "d3d9.dll");
/// assert_eq!(suggestion.estimated_complexity, ComplexityScore::High);
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ShimSuggestion {
    /// The original DLL filename (e.g., `"d3d9.dll"`).
    pub source_dll: String,

    /// The target Rust crate name (e.g., `"wgpu"`).
    pub target_crate: String,

    /// Estimated number of exported functions that will need mapping.
    ///
    /// This is derived from the DLL's export count at classification time.
    /// The actual mapping count after LLM generation may differ.
    #[serde(default)]
    pub estimated_mappings: usize,

    /// Estimated implementation complexity based on symbol counts
    /// and known crate patterns.
    #[serde(default)]
    pub estimated_complexity: ComplexityScore,

    /// Confidence in the complexity estimate, in `[0.0, 1.0]`.
    ///
    /// Higher values indicate more reliable estimates, typically
    /// because the target crate is well-known (e.g., wgpu, cpal) and
    /// the DLL's export count matches expected patterns.
    #[serde(default)]
    pub estimated_confidence: f64,
}

impl ShimSuggestion {
    /// Creates a new shim suggestion with the given DLL and crate name.
    pub fn new(source_dll: String, target_crate: String) -> Self {
        Self {
            source_dll,
            target_crate,
            estimated_mappings: 0,
            estimated_complexity: ComplexityScore::Low,
            estimated_confidence: 0.0,
        }
    }
}

/// A report containing shim layer suggestions for all crate-replacement DLLs.
///
/// Produced after the classification phase. Each entry corresponds to a DLL
/// whose category is `MicrosoftSdk` or `KnownThirdParty`, meaning it will
/// need a shim layer to bridge the original API to a Rust crate.
///
/// The report includes a summary with total DLL count, complexity distribution,
/// and an overall implementation readiness estimate.
///
/// # Example
///
/// ```
/// use calxgloss_types::{ShimSuggestion, ShimSuggestionReport, ComplexityScore};
///
/// let report = ShimSuggestionReport {
///     suggestions: vec![
///         ShimSuggestion {
///             source_dll: "d3d9.dll".to_string(),
///             target_crate: "wgpu".to_string(),
///             estimated_mappings: 47,
///             estimated_complexity: ComplexityScore::High,
///             estimated_confidence: 0.85,
///         },
///     ],
/// };
/// assert_eq!(report.total_dlls(), 1);
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShimSuggestionReport {
    /// The individual shim suggestions, one per crate-replacement DLL.
    pub suggestions: Vec<ShimSuggestion>,
}

impl ShimSuggestionReport {
    /// Returns the total number of suggested shim layers.
    pub fn total_dlls(&self) -> usize {
        self.suggestions.len()
    }

    /// Returns the number of suggested shim layers with low complexity.
    pub fn low_complexity_count(&self) -> usize {
        self.suggestions
            .iter()
            .filter(|s| matches!(s.estimated_complexity, ComplexityScore::Low))
            .count()
    }

    /// Returns the number of suggested shim layers with medium complexity.
    pub fn medium_complexity_count(&self) -> usize {
        self.suggestions
            .iter()
            .filter(|s| matches!(s.estimated_complexity, ComplexityScore::Medium))
            .count()
    }

    /// Returns the number of suggested shim layers with high complexity.
    pub fn high_complexity_count(&self) -> usize {
        self.suggestions
            .iter()
            .filter(|s| matches!(s.estimated_complexity, ComplexityScore::High))
            .count()
    }

    /// Returns `true` if no shim layer suggestions were generated.
    pub fn is_empty(&self) -> bool {
        self.suggestions.is_empty()
    }

    /// Returns the average estimated confidence across all suggestions.
    pub fn average_confidence(&self) -> f64 {
        if self.suggestions.is_empty() {
            return 0.0;
        }
        let total: f64 = self.suggestions.iter().map(|s| s.estimated_confidence).sum();
        total / self.suggestions.len() as f64
    }
}

impl PartialOrd for ComplexityScore {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ComplexityScore {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.as_score().cmp(&other.as_score())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shim_api_mapping_is_identity_when_no_changes() {
        let mapping = ShimApiMapping {
            original_api: "SomeFunc".to_string(),
            original_params: vec!["i32".to_string(), "u32".to_string()],
            crate_api: "some_func".to_string(),
            crate_params: vec!["i32".to_string(), "u32".to_string()],
            parameter_transforms: Vec::new(),
            return_mapping: ReturnMapping::default(),
            complexity: ComplexityScore::Low,
            notes: String::new(),
        };
        assert!(mapping.is_identity());
    }

    #[test]
    fn test_shim_api_mapping_not_identity_with_transforms() {
        let mapping = ShimApiMapping {
            original_api: "SetTexture".to_string(),
            original_params: vec!["UINT".to_string()],
            crate_api: "set_bind_group".to_string(),
            crate_params: vec!["u32".to_string()],
            parameter_transforms: vec!["UINT → u32 cast".to_string()],
            return_mapping: ReturnMapping::default(),
            complexity: ComplexityScore::Medium,
            notes: String::new(),
        };
        assert!(!mapping.is_identity());
    }

    #[test]
    fn test_return_mapping_serialization() {
        let json = serde_json::to_string(&ReturnMapping::Identity).unwrap();
        assert_eq!(json, "\"Identity\"");

        let json = serde_json::to_string(&ReturnMapping::Void).unwrap();
        assert_eq!(json, "\"Void\"");

        let json = serde_json::to_string(&ReturnMapping::Discarded).unwrap();
        assert_eq!(json, "\"Discarded\"");

        let json = serde_json::to_string(&ReturnMapping::Converted("custom".to_string())).unwrap();
        let deserialized: ReturnMapping = serde_json::from_str(&json).unwrap();
        assert!(matches!(deserialized, ReturnMapping::Converted(ref s) if s == "custom"));
    }

    #[test]
    fn test_complexity_score_ordering() {
        assert!(ComplexityScore::Low < ComplexityScore::Medium);
        assert!(ComplexityScore::Medium < ComplexityScore::High);
    }

    #[test]
    fn test_shim_layer_new_empty() {
        let shim = ShimLayer::new("d3d9.dll".to_string(), "wgpu".to_string());
        assert_eq!(shim.source_dll, "d3d9.dll");
        assert_eq!(shim.target_crate, "wgpu");
        assert!(shim.is_empty());
        assert_eq!(shim.mapping_count(), 0);
        assert_eq!(shim.total_complexity(), 0);
        assert_eq!(shim.overall_complexity(), ComplexityScore::Low);
    }

    #[test]
    fn test_shim_layer_add_mapping() {
        let mut shim = ShimLayer::new("d3d9.dll".to_string(), "wgpu".to_string());
        shim.add_mapping(ShimApiMapping::new(
            "Present".to_string(),
            "queue.submit".to_string(),
            ComplexityScore::Medium,
        ));
        assert!(!shim.is_empty());
        assert_eq!(shim.mapping_count(), 1);
        assert_eq!(shim.total_complexity(), 3);
    }

    #[test]
    fn test_shim_layer_complexity_aggregation() {
        let mut shim = ShimLayer::new("d3d9.dll".to_string(), "wgpu".to_string());
        shim.add_mapping(ShimApiMapping::new(
            "Present".to_string(),
            "queue.submit".to_string(),
            ComplexityScore::Low,
        ));
        shim.add_mapping(ShimApiMapping::new(
            "SetTexture".to_string(),
            "set_bind_group".to_string(),
            ComplexityScore::High,
        ));
        assert_eq!(shim.total_complexity(), 1 + 5);
        // Average: 3.0 → Medium
        assert_eq!(shim.overall_complexity(), ComplexityScore::Medium);
    }

    #[test]
    fn test_shim_layer_serialization_roundtrip() {
        let mut shim = ShimLayer::new("d3d9.dll".to_string(), "wgpu".to_string());
        shim.add_mapping(ShimApiMapping::new(
            "Present".to_string(),
            "queue.submit".to_string(),
            ComplexityScore::Medium,
        ));
        let json = serde_json::to_string(&shim).unwrap();
        let deserialized: ShimLayer = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.source_dll, "d3d9.dll");
        assert_eq!(deserialized.target_crate, "wgpu");
        assert_eq!(deserialized.mapping_count(), 1);
        assert_eq!(
            deserialized.mappings[0].original_api,
            "Present"
        );
        assert_eq!(
            deserialized.mappings[0].crate_api,
            "queue.submit"
        );
    }

    #[test]
    fn test_to_api_mapping_item() {
        let mapping = ShimApiMapping {
            original_api: "SetTexture".to_string(),
            original_params: vec!["UINT".to_string()],
            crate_api: "encoder.set_bind_group".to_string(),
            crate_params: vec!["u32".to_string()],
            parameter_transforms: vec!["UINT → stage_index (cast)".to_string()],
            return_mapping: ReturnMapping::Void,
            complexity: ComplexityScore::Medium,
            notes: "Maps DirectX texture stage to wgpu bind group.".to_string(),
        };
        let item = mapping.to_api_mapping_item();
        assert_eq!(item.windows_api, "SetTexture");
        assert_eq!(item.rust_equivalent, "encoder.set_bind_group");
        assert!(item.notes.contains("Maps DirectX"));
        assert!(item.notes.contains("UINT → stage_index"));
    }

    #[test]
    fn test_shim_verification_result_all_passed() {
        let result = ShimVerificationResult {
            compiled: true,
            compilation_errors: Vec::new(),
            compilation_warnings: Vec::new(),
            tests_passed: 5,
            tests_total: 5,
            edge_tests_passed: 3,
            edge_tests_total: 3,
            failed_tests: Vec::new(),
            mapping_results: Vec::new(),
        };
        assert!(result.all_passed());
        assert_eq!(result.total_tests(), 8);
        assert_eq!(result.total_passed(), 8);
        assert!((result.pass_rate() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_shim_verification_result_compilation_failed() {
        let result = ShimVerificationResult {
            compiled: false,
            compilation_errors: vec!["type mismatch".to_string()],
            compilation_warnings: Vec::new(),
            tests_passed: 0,
            tests_total: 0,
            edge_tests_passed: 0,
            edge_tests_total: 0,
            failed_tests: Vec::new(),
            mapping_results: Vec::new(),
        };
        assert!(!result.all_passed());
        assert_eq!(result.total_tests(), 0);
        assert!((result.pass_rate() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_shim_verification_result_partial_pass() {
        let result = ShimVerificationResult {
            compiled: true,
            compilation_errors: Vec::new(),
            compilation_warnings: vec!["unused variable".to_string()],
            tests_passed: 3,
            tests_total: 5,
            edge_tests_passed: 1,
            edge_tests_total: 3,
            failed_tests: Vec::new(),
            mapping_results: Vec::new(),
        };
        assert!(!result.all_passed());
        assert_eq!(result.total_tests(), 8);
        assert_eq!(result.total_passed(), 4);
        let rate = result.pass_rate();
        assert!((rate - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn test_shim_verification_result_empty() {
        let result = ShimVerificationResult {
            compiled: false,
            compilation_errors: Vec::new(),
            compilation_warnings: Vec::new(),
            tests_passed: 0,
            tests_total: 0,
            edge_tests_passed: 0,
            edge_tests_total: 0,
            failed_tests: Vec::new(),
            mapping_results: Vec::new(),
        };
        assert!(!result.all_passed());
        assert_eq!(result.total_tests(), 0);
        assert!((result.pass_rate() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_shim_mapping_test_result_serialization() {
        let mapping_result = ShimMappingTestResult {
            original_api: "Present".to_string(),
            crate_api: "queue.submit".to_string(),
            passed: 2,
            total: 3,
            failures: Vec::new(),
        };
        let json = serde_json::to_string(&mapping_result).unwrap();
        let deserialized: ShimMappingTestResult = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.original_api, "Present");
        assert_eq!(deserialized.passed, 2);
        assert_eq!(deserialized.total, 3);
    }

    #[test]
    fn test_shim_verification_result_serialization() {
        let result = ShimVerificationResult {
            compiled: true,
            compilation_errors: Vec::new(),
            compilation_warnings: vec!["warning1".to_string()],
            tests_passed: 1,
            tests_total: 2,
            edge_tests_passed: 1,
            edge_tests_total: 1,
            failed_tests: Vec::new(),
            mapping_results: vec![ShimMappingTestResult {
                original_api: "Present".to_string(),
                crate_api: "queue.submit".to_string(),
                passed: 2,
                total: 2,
                failures: Vec::new(),
            }],
        };
        let json = serde_json::to_string(&result).unwrap();
        let deserialized: ShimVerificationResult = serde_json::from_str(&json).unwrap();
        assert!(deserialized.compiled);
        assert_eq!(deserialized.tests_passed, 1);
        assert_eq!(deserialized.edge_tests_total, 1);
        assert_eq!(deserialized.mapping_results.len(), 1);
    }
}
