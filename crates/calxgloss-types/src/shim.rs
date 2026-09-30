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
}
