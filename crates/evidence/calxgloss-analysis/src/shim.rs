//! Shim layer mapping auto-generation.
//!
//! This module produces [`ShimLayer`] instances for DLLs classified as
//! `CrateReplacement` (Microsoft SDK or Known Third Party). After
//! [`super::classify_dll_name`] determines which Rust crate replaces a
//! Windows DLL, the LLM generates a mapping table that translates every
//! exported function from the original DLL's API surface to the target
//! crate's equivalent API.
//!
//! # Flow
//!
//! 1. DLL classification marks a DLL as [`CrateReplacement`] → exports are
//!    collected from Ghidra.
//! 2. [`generate_shim_mappings`] builds a prompt with the DLL name, target
//!    crate, export signatures, and crate context.
//! 3. The LLM returns structured JSON describing each mapping:
//!    original API → crate API, parameter transforms, complexity, notes.
//! 4. The response is parsed into a [`ShimLayer`], which is persisted to
//!    `re/shims/<dll_name>/mappings.json`.
//!
//! # Example
//!
//! ```no_run
//! use calxgloss_analysis::{Analyzer, shim::generate_shim_mappings};
//! use calxgloss_llm::LlmClient;
//! use calxgloss_types::{ShimLayer, DllInfo, Export, Import};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let analyzer = Analyzer::new(
//!     calxgloss_ghidra::GhidraClient::new("http://localhost:8080")?,
//!     Default::default(),
//! );
//! let llm = LlmClient::from_url("http://localhost:11434/v1", "qwen3")?;
//!
//! let dll_name = "d3d9.dll";
//! let exports = vec![
//!     Export {
//!         name: "Direct3DCreate9".to_string(),
//!         address: 0x1000,
//!         signature: "IDirect3D9* __stdcall Direct3DCreate9(UINT)".to_string(),
//!     },
//!     Export {
//!         name: "Direct3DCreate9Ex".to_string(),
//!         address: 0x2000,
//!         signature: "HRESULT __stdcall Direct3DCreate9Ex(UINT, IDirect3D9***)".to_string(),
//!     },
//! ];
//!
//! let shim: ShimLayer = generate_shim_mappings(
//!     dll_name,
//!     "wgpu",
//!     &exports,
//!     &llm,
//! ).await?;
//!
//! println!("Generated {} mappings for {}", shim.mapping_count(), dll_name);
//! # Ok(())
//! # }
//! ```

use calxgloss_llm::{LlmClient, LlmMessage};
use calxgloss_types::{Export, ShimLayer};
use tracing::{debug, info, warn};

/// Contextual hints about the target crate that are injected into the prompt.
///
/// These hints help the LLM produce more accurate mappings by describing
/// the target crate's philosophy, API style, and common patterns.
#[derive(Debug, Clone, Default)]
pub(crate) struct CrateContext {
    /// A one-sentence description of the crate's purpose.
    pub description: String,
    /// Common translation patterns (one per line).
    pub patterns: Vec<&'static str>,
    /// Common pitfalls or divergences from the Windows API.
    pub pitfalls: Vec<&'static str>,
}

impl CrateContext {
    /// Build a description string suitable for injection into an LLM prompt.
    pub(crate) fn to_prompt_text(&self) -> String {
        let mut parts: Vec<String> = Vec::new();
        if !self.description.is_empty() {
            parts.push(self.description.clone());
        }
        if !self.patterns.is_empty() {
            parts.push("Common patterns:".to_string());
            for p in &self.patterns {
                parts.push(p.to_string());
            }
        }
        if !self.pitfalls.is_empty() {
            parts.push("Pitfalls to watch out for:".to_string());
            for p in &self.pitfalls {
                parts.push(p.to_string());
            }
        }
        parts.join("\n")
    }
}

/// Known crate context hints used to guide the LLM during mapping generation.
///
/// Each entry provides the LLM with domain-specific knowledge about the
/// target crate, reducing the chance of incorrect or suboptimal mappings.
pub(crate) fn crate_context(crate_name: &str) -> CrateContext {
    match crate_name {
        "wgpu" => CrateContext {
            description: "wgpu is a cross-platform GPU graphics and compute library for Rust, \
                          supporting Vulkan, Metal, DX12, DX11, and WebGL2. It uses an immediate- \
                          mode API with command encoders, bind groups, and render/pipelines."
                .to_string(),
            patterns: vec![
                "CreateDevice → Instance::request_adapter + request_device",
                "CreateTexture → Device::create_texture",
                "SetTexture/DrawPrimitive → encoder.set_bind_group + encoder.draw",
                "Present → queue.submit + surface texture",
                "StretchBlt → texture resize + blit pass",
                "CreateSwapChain → SwapChainDescriptor + surface",
            ],
            pitfalls: vec![
                "DX9 fixed-function pipeline → wgpu requires explicit pipeline creation",
                "DX9 textures have implicit mip chains; wgpu requires explicit mip levels",
                "DX9 render states → wgpu pipeline descriptors (frontface_winding, cull_mode, etc.)",
                "DX9 vertex shaders are bytecode; wgpu uses WGSL source strings",
                "DX9 immediate mode → wgpu command buffer / encoder model",
            ],
        },
        "tiny-skia" => CrateContext {
            description: "tiny-skia is a 2D graphics library for Rust, supporting \
                          rasterization, path drawing, and image manipulation. It is the Rust \
                          equivalent of GDI's 2D drawing primitives."
                .to_string(),
            patterns: vec![
                "CreateDC → Pixmap::new(width, height)",
                "BitBlt → pixmap.blit_rect",
                "SelectObject → use Pixmap directly as target",
                "Rectangle/Ellipse → pixmap.fill_rect with path",
                "LineTo/MoveToEx → pixmap.stroke_path",
                "TextOut → pixmap.drawString with rusttype/skrifa font",
            ],
            pitfalls: vec![
                "GDI uses device context (DC) state machine; tiny-skia is functional",
                "GDI coordinate system origin is top-left; tiny-skia matches",
                "GDI pens/brushes → tiny-skia Pen and Fill",
            ],
        },
        "cpal" => CrateContext {
            description: "cpal is a cross-platform audio library for Rust, providing \
                          unified access to audio input and output across platforms."
                .to_string(),
            patterns: vec![
                "DirectSound::Play → stream.play() / buffer queue",
                "DirectSound::Stop → stream.stop()",
                "DirectSound::SetVolume → stream.set_volume()",
            ],
            pitfalls: vec![
                "DirectSound buffers → cpal stream callback / sample buffer",
                "DirectSound volume is 0.0–1.0; cpal matches",
                "DirectSound 3D → cpal does not support 3D audio natively",
            ],
        },
        "fmod-rs" => CrateContext {
            description: "fmod-rs is a Rust binding for the FMOD Low-Level audio API, \
                          providing sound playback, mixing, and effects."
                .to_string(),
            patterns: vec![
                "FMUSIC_PlaySong → Channel::play",
                "FSOUND_PlaySound → Channel::play",
                "FSOUND_SetVolume → Channel::set_volume",
            ],
            pitfalls: vec!["FMOD uses handle-based API; fmod-rs wraps it with idiomatic Rust"],
        },
        "vb6runtime" => CrateContext {
            description: "vb6runtime is a Rust crate that replicates the Microsoft Visual \
                          Basic 6.0 runtime (msvbvm60.dll), including object model, BSTR \
                          strings, Variants, and the form/control lifecycle."
                .to_string(),
            patterns: vec![
                "IUnknown::AddRef/Release → Rust RefCell/Arc for reference counting",
                "BSTR → String with UTF-16 encoding/decoding",
                "VARIANT → serde_json::Value with type tagging",
                "Form_Initialize → constructor with self initialization",
                "Control events → Rust closures / event handlers",
            ],
            pitfalls: vec![
                "VB6 default instance pattern → explicit object creation",
                "VB6 Variant coercion rules → explicit type conversions",
                "VB6 string handling is UTF-16; Rust is UTF-8",
            ],
        },
        _ => CrateContext::default(),
    }
}

/// Generate shim API mappings for a crate-replacement DLL.
///
/// This function sends a prompt to the LLM containing the DLL name, target crate,
/// and all exported function signatures. The LLM responds with a JSON array of
/// [`ShimApiMapping`] entries describing how each exported function maps to the
/// target crate's API.
///
/// # Arguments
///
/// * `dll_name` — The original DLL filename (e.g., `"d3d9.dll"`).
/// * `target_crate` — The Rust crate that replaces the DLL (e.g., `"wgpu"`).
/// * `exports` — The list of exported functions with their signatures.
/// * `client` — The LLM client used to generate mappings.
///
/// # Returns
///
/// A [`ShimLayer`] containing the generated API mappings, or an error if the
/// LLM call fails or the response cannot be parsed.
///
/// # LLM Prompt Structure
///
/// The prompt includes:
/// - The DLL name and target crate
/// - All exported function signatures from the DLL
/// - Crate context hints (description, common patterns, pitfalls)
/// - A request to output structured JSON matching the [`ShimApiMapping`] schema
pub async fn generate_shim_mappings(
    dll_name: &str,
    target_crate: &str,
    exports: &[Export],
    client: &LlmClient,
) -> calxgloss_llm::Result<ShimLayer> {
    debug!(
        dll = dll_name,
        crate_name = target_crate,
        export_count = exports.len(),
        "Generating shim mappings"
    );

    // Build export summary for the prompt.
    let export_lines: Vec<String> = exports
        .iter()
        .map(|e| format!("  - {} ({})", e.name, e.signature))
        .collect();
    let export_summary = export_lines.join("\n");

    // Get crate-specific context hints.
    let crate_ctx = crate_context(target_crate);
    let context_text = crate_ctx.to_prompt_text();

    // Build the prompt.
    let prompt = format!(
        "You are a reverse engineering specialist. Your job is to create API mapping \
         entries for a shim layer that replaces a Windows DLL with a Rust crate.

## ORIGINAL DLL: {dll_name}
## TARGET CRATE: {target_crate}

## EXPORTED FUNCTIONS

{export_summary}

## TARGET CRATE CONTEXT

{context_text}

## TASK

For each exported function above, generate a mapping entry that describes how to \
translate a call from the original DLL's API into the target crate's API.

### Required fields for each mapping:

1. `original_api` — The DLL's exported function name.
2. `original_params` — Array of parameter types as declared in the export signature.
3. `crate_api` — The Rust crate API path that provides equivalent functionality.
   Use the crate's public API, not internal implementation details.
4. `crate_params` — Array of the crate API's parameter types (as they appear in Rust code).
5. `parameter_transforms` — Array describing how each original parameter maps to the \
crate parameter. Include any transformation logic (lookups, heap allocations, type \
conversions, etc.). If a parameter maps directly, write \"direct pass-through\".
6. `return_mapping` — How the return value is handled. Use one of:
   - \"Identity\" — returned unchanged
   - \"Void\" — no return value
   - \"Discarded\" — original returns value but crate is infallible
   - \"Converted\" — needs type conversion (add description)
   - \"Custom\" — custom logic needed (add description)
7. `complexity` — One of: \"Low\", \"Medium\", \"High\".
   - Low: direct one-to-one mapping, no transforms needed.
   - Medium: requires parameter transformation or small helper logic.
   - High: complex transformation, multi-step translation, or significant divergence.
8. `notes` — Any additional context: edge cases, divergence from original behavior, \
implementation hints.

### Output format

Return **only** a JSON array of mapping objects. Do not include any markdown fences, \
explanations, or other text. The response must be parseable as a JSON array.

Example output format:
```json
[
  {{
    \"original_api\": \"ExampleFunc\",
    \"original_params\": [\"UINT param1\", \"LPVOID param2\"],
    \"crate_api\": \"crate::example_function\",
    \"crate_params\": [\"u32\", \"&[u8]\"],
    \"parameter_transforms\": [
      \"param1 → direct cast to u32\",
      \"param2 → reinterpret as slice, handle null as empty\"
    ],
    \"return_mapping\": \"Identity\",
    \"complexity\": \"Medium\",
    \"notes\": \"Null param2 is valid in original but crate expects non-empty slice.\"
  }}
]
```",
        dll_name = dll_name,
        target_crate = target_crate,
        export_summary = export_summary,
        context_text = context_text,
    );

    // Send to LLM.
    let messages = vec![LlmMessage::user(&prompt)];
    let response = client.complete(&messages).await?;

    // Parse the LLM response as JSON.
    parse_shim_mappings(dll_name, target_crate, &response.content)
}

/// Parse an LLM response string into a [`ShimLayer`].
///
/// The response is expected to be a JSON array of mapping objects. Each object
/// must have at minimum `original_api` and `crate_api` fields.
///
/// If the response is not valid JSON or contains no mappings, returns an
/// [`LlmError::EmptyResponse`].
fn parse_shim_mappings(
    dll_name: &str,
    target_crate: &str,
    content: &str,
) -> calxgloss_llm::Result<ShimLayer> {
    let trimmed = content.trim();

    // Strip markdown code fences if present (LLMs often wrap JSON in ```).
    let json_str = if trimmed.starts_with("```") {
        let stripped = trimmed.strip_prefix("```").unwrap_or(trimmed);
        let stripped = stripped.trim_start();
        // Strip language tag if present (e.g., "json")
        let stripped = stripped.strip_prefix("json").unwrap_or(stripped);
        stripped
            .trim()
            .strip_suffix("```")
            .unwrap_or(stripped)
            .trim()
    } else {
        trimmed
    };

    // Try parsing as a full JSON array of mapping objects.
    let mappings: Vec<ShimApiMappingEntry> = serde_json::from_str(json_str).map_err(|_e| {
        calxgloss_llm::LlmError::EmptyResponse // Reuse EmptyResponse for parse failures
    })?;

    if mappings.is_empty() {
        warn!(dll = dll_name, "LLM returned empty mapping array");
        return Err(calxgloss_llm::LlmError::EmptyResponse);
    }

    let mut shim = ShimLayer::new(dll_name.to_string(), target_crate.to_string());

    for entry in mappings {
        let complexity = match entry.complexity.as_str() {
            "High" => calxgloss_types::ComplexityScore::High,
            "Medium" => calxgloss_types::ComplexityScore::Medium,
            _ => calxgloss_types::ComplexityScore::Low,
        };

        let return_mapping = match entry.return_mapping.as_str() {
            "Void" => calxgloss_types::ReturnMapping::Void,
            "Discarded" => calxgloss_types::ReturnMapping::Discarded,
            "Converted" => calxgloss_types::ReturnMapping::Converted(
                entry.return_mapping_details.unwrap_or_default(),
            ),
            "Custom" => calxgloss_types::ReturnMapping::Custom(
                entry.return_mapping_details.unwrap_or_default(),
            ),
            _ => calxgloss_types::ReturnMapping::Identity,
        };

        shim.add_mapping(calxgloss_types::ShimApiMapping {
            original_api: entry.original_api,
            original_params: entry.original_params,
            crate_api: entry.crate_api,
            crate_params: entry.crate_params,
            parameter_transforms: entry.parameter_transforms,
            return_mapping,
            complexity,
            notes: entry.notes,
        });
    }

    info!(
        dll = dll_name,
        crate_name = target_crate,
        mapping_count = shim.mapping_count(),
        "Generated shim mappings"
    );

    Ok(shim)
}

/// Internal representation of a shim mapping entry from the LLM response.
///
/// This is a minimal JSON-compatible struct used solely for deserializing
/// the LLM's structured output. Field names match the expected JSON keys
/// in the LLM prompt.
#[derive(Debug, Clone, serde::Deserialize)]
struct ShimApiMappingEntry {
    original_api: String,
    #[serde(default)]
    original_params: Vec<String>,
    crate_api: String,
    #[serde(default)]
    crate_params: Vec<String>,
    #[serde(default)]
    parameter_transforms: Vec<String>,
    #[serde(default)]
    return_mapping: String,
    #[serde(default = "default_return_details")]
    return_mapping_details: Option<String>,
    #[serde(default)]
    complexity: String,
    #[serde(default)]
    notes: String,
}

fn default_return_details() -> Option<String> {
    None
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_valid_mapping_array() {
        let json = r#"[
            {
                "original_api": "Direct3DCreate9",
                "original_params": ["UINT Ordinal"],
                "crate_api": "wgpu::Instance::new",
                "crate_params": ["wgpu::Backends"],
                "parameter_transforms": ["Ordinal → map to wgpu::Backends::VULKAN | BACKENDS"],
                "return_mapping": "Converted",
                "return_mapping_details": "Returns interface pointer → convert to wgpu::Instance",
                "complexity": "High",
                "notes": "DX9 creates a single global D3D object; wgpu uses Instance per process."
            }
        ]"#;

        let shim = parse_shim_mappings("d3d9.dll", "wgpu", json).unwrap();
        assert_eq!(shim.source_dll, "d3d9.dll");
        assert_eq!(shim.target_crate, "wgpu");
        assert_eq!(shim.mapping_count(), 1);
        assert_eq!(shim.mappings[0].original_api, "Direct3DCreate9");
        assert_eq!(shim.mappings[0].crate_api, "wgpu::Instance::new");
        assert!(matches!(
            shim.mappings[0].return_mapping,
            calxgloss_types::ReturnMapping::Converted(_)
        ));
        assert_eq!(
            shim.mappings[0].complexity,
            calxgloss_types::ComplexityScore::High
        );
    }

    #[test]
    fn test_parse_multiple_mappings() {
        let json = r#"[
            {
                "original_api": "Present",
                "original_params": [],
                "crate_api": "queue.submit",
                "crate_params": ["&[&CommandBuffer]"],
                "parameter_transforms": ["no params"],
                "return_mapping": "Void",
                "complexity": "Medium",
                "notes": "DX9 present copies back buffer to front; wgpu submits queue."
            },
            {
                "original_api": "ClearRenderTargetView",
                "original_params": ["IDirect3DSurface9* pRenderTarget", "const D3DCOLOR* pColor"],
                "crate_api": "render_pass.clear_color",
                "crate_params": ["r: f32", "g: f32", "b: f32", "a: f32"],
                "parameter_transforms": [
                    "pRenderTarget → current render target from encoder",
                    "pColor → D3DCOLOR to RGBA f32 conversion"
                ],
                "return_mapping": "Void",
                "complexity": "Medium",
                "notes": ""
            }
        ]"#;

        let shim = parse_shim_mappings("d3d9.dll", "wgpu", json).unwrap();
        assert_eq!(shim.mapping_count(), 2);
        assert_eq!(shim.mappings[0].original_api, "Present");
        assert_eq!(shim.mappings[1].original_api, "ClearRenderTargetView");
        assert_eq!(shim.mappings[1].original_params.len(), 2);
    }

    #[test]
    fn test_parse_with_markdown_fences() {
        let json = r#"```json
[
    {
        "original_api": "CreateDevice",
        "original_params": [],
        "crate_api": "instance.request_adapter",
        "crate_params": ["RequestAdapterOptions"],
        "parameter_transforms": ["no direct equivalent"],
        "return_mapping": "Converted",
        "complexity": "High",
        "notes": "DX9 CreateDevice creates hardware device; wgpu requests adapter."
    }
]
```"#;

        let shim = parse_shim_mappings("d3d9.dll", "wgpu", json).unwrap();
        assert_eq!(shim.mapping_count(), 1);
        assert_eq!(shim.mappings[0].original_api, "CreateDevice");
    }

    #[test]
    fn test_parse_empty_array_returns_error() {
        let result = parse_shim_mappings("d3d9.dll", "wgpu", "[]");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_invalid_json_returns_error() {
        let result = parse_shim_mappings("d3d9.dll", "wgpu", "not json at all");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_missing_required_fields_defaults() {
        // LLM may return minimal mappings; required fields are original_api and crate_api.
        let json = r#"[
            {
                "original_api": "SimpleFunc",
                "crate_api": "simple_func"
            }
        ]"#;

        let shim = parse_shim_mappings("test.dll", "my-crate", json).unwrap();
        assert_eq!(shim.mapping_count(), 1);
        assert_eq!(shim.mappings[0].original_params.len(), 0);
        assert_eq!(shim.mappings[0].crate_params.len(), 0);
        assert_eq!(shim.mappings[0].parameter_transforms.len(), 0);
        assert_eq!(
            shim.mappings[0].complexity,
            calxgloss_types::ComplexityScore::Low
        );
        assert_eq!(shim.mappings[0].notes, "");
    }

    #[test]
    fn test_complexity_score_mapping() {
        let json = r#"[
            {"original_api": "A", "crate_api": "a", "complexity": "Low"},
            {"original_api": "B", "crate_api": "b", "complexity": "Medium"},
            {"original_api": "C", "crate_api": "c", "complexity": "High"},
            {"original_api": "D", "crate_api": "d", "complexity": "Unknown"}
        ]"#;

        let shim = parse_shim_mappings("test.dll", "crate", json).unwrap();
        assert_eq!(
            shim.mappings[0].complexity,
            calxgloss_types::ComplexityScore::Low
        );
        assert_eq!(
            shim.mappings[1].complexity,
            calxgloss_types::ComplexityScore::Medium
        );
        assert_eq!(
            shim.mappings[2].complexity,
            calxgloss_types::ComplexityScore::High
        );
        // Unknown complexity defaults to Low
        assert_eq!(
            shim.mappings[3].complexity,
            calxgloss_types::ComplexityScore::Low
        );
    }

    #[test]
    fn test_return_mapping_parsing() {
        let json = r#"[
            {"original_api": "A", "crate_api": "a", "return_mapping": "Identity"},
            {"original_api": "B", "crate_api": "b", "return_mapping": "Void"},
            {"original_api": "C", "crate_api": "c", "return_mapping": "Discarded"},
            {"original_api": "D", "crate_api": "d", "return_mapping": "Converted"},
            {"original_api": "E", "crate_api": "e", "return_mapping": "Converted", "return_mapping_details": "HRESULT to Result"}
        ]"#;

        let shim = parse_shim_mappings("test.dll", "crate", json).unwrap();
        assert!(matches!(
            shim.mappings[0].return_mapping,
            calxgloss_types::ReturnMapping::Identity
        ));
        assert!(matches!(
            shim.mappings[1].return_mapping,
            calxgloss_types::ReturnMapping::Void
        ));
        assert!(matches!(
            shim.mappings[2].return_mapping,
            calxgloss_types::ReturnMapping::Discarded
        ));
        assert!(
            matches!(shim.mappings[3].return_mapping, calxgloss_types::ReturnMapping::Converted(ref s) if s.is_empty())
        );
        assert!(
            matches!(shim.mappings[4].return_mapping, calxgloss_types::ReturnMapping::Converted(ref s) if s == "HRESULT to Result")
        );
    }

    #[test]
    fn test_shim_layer_persistence_roundtrip() {
        let shim = parse_shim_mappings(
            "d3d9.dll",
            "wgpu",
            r#"[
                {
                    "original_api": "Present",
                    "crate_api": "queue.submit",
                    "complexity": "Medium",
                    "notes": "DX9 present → wgpu queue submit"
                }
            ]"#,
        )
        .unwrap();

        // Verify the ShimLayer can be serialized (it already is via serde).
        let json = serde_json::to_string_pretty(&shim).unwrap();
        let deserialized: ShimLayer = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.mapping_count(), 1);
        assert_eq!(deserialized.mappings[0].original_api, "Present");
    }

    #[test]
    fn test_crate_context_wgpu() {
        let ctx = crate_context("wgpu");
        assert!(ctx.description.contains("cross-platform GPU"));
        assert!(ctx.patterns.len() >= 3);
        assert!(ctx.pitfalls.len() >= 3);
    }

    #[test]
    fn test_crate_context_unknown_returns_default() {
        let ctx = crate_context("nonexistent-crate");
        assert!(ctx.description.is_empty());
        assert!(ctx.patterns.is_empty());
        assert!(ctx.pitfalls.is_empty());
    }

    #[test]
    fn test_crate_context_description_text() {
        let ctx = crate_context("cpal");
        let text = CrateContext::to_prompt_text(&ctx);
        assert!(text.contains("cross-platform audio"));
        assert!(text.contains("Common patterns:"));
        assert!(text.contains("DirectSound::Play"));
    }
}
