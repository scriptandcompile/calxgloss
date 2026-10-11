//! Context extraction helpers used by prompt builders.

use crate::Translation;
use calxgloss_callgraph::FunctionContext;
use calxgloss_ghidra::ScanSource;
use calxgloss_prompts::{
    CallGraphNeighbor, NeighborFunction, PalTraitDef, PalTraitMethod, ShimCode,
};
use calxgloss_types::{ApiCategory, ContextTier, TranslationRequest, WindowsApiCall};
use tracing::debug;

/// Extract call graph neighbor details from an enriched context list.
///
/// This is a lightweight alternative to
/// [`extract_call_graph_neighbors`](extract_call_graph_neighbors) that
/// operates on already-enriched [`FunctionContext`] data instead of
/// querying Ghidra for every neighbor.  When the enriched context
/// contains a matching entry for `target_address`, the function returns
/// its caller/callee edges converted into [`CallGraphNeighbor`]
/// instances.  When no matching entry exists (or the context list is
/// empty), an empty vector is returned.
pub fn extract_call_graph_neighbors_from_enriched(
    enriched: &[FunctionContext],
    target_address: u64,
) -> Vec<CallGraphNeighbor> {
    let target = enriched.iter().find(|c| c.address == target_address);
    let Some(target_ctx) = target else {
        return Vec::new();
    };
    let mut neighbors = Vec::new();

    // Build a set of all function addresses in the enriched context for
    // determining whether a neighbor is a caller or callee.
    let all_addresses: std::collections::HashSet<u64> =
        enriched.iter().map(|c| c.address).collect();

    for caller_edge in &target_ctx.callers {
        let is_internal = all_addresses.contains(&caller_edge.node.address);
        neighbors.push(CallGraphNeighbor {
            name: caller_edge.node.name.clone(),
            address: caller_edge.node.address,
            signature: String::new(),
            role: if is_internal {
                "caller".to_string()
            } else {
                "external_caller".to_string()
            },
        });
    }

    for callee_edge in &target_ctx.callees {
        let is_internal = all_addresses.contains(&callee_edge.node.address);
        neighbors.push(CallGraphNeighbor {
            name: callee_edge.node.name.clone(),
            address: callee_edge.node.address,
            signature: String::new(),
            role: if is_internal {
                "callee".to_string()
            } else {
                "external_callee".to_string()
            },
        });
    }

    neighbors
}
/// Extract call graph neighbor details from the scan source.
///
/// Resolves each neighbor name through the (cached) function listing and
/// pulls its signature from the cached decompile, so a warm batch pays
/// nothing for neighbor context.
pub async fn extract_call_graph_neighbors<S: ScanSource>(
    source: &S,
    call_graph: &[String],
    _target_address: u64,
) -> Vec<CallGraphNeighbor> {
    // One (cached) function listing resolves every neighbor name to its
    // address — no per-name search request.
    let functions = source.functions().await.unwrap_or_default();
    let address_of = |name: &str| functions.iter().find(|f| f.name == name).map(|f| f.address);

    let mut neighbors = Vec::new();
    for name in call_graph {
        // Try to get the signature from decompilation
        let signature = match source.decompile(name).await {
            Ok(decompiled) => decompiled.signature,
            Err(_) => String::new(),
        };
        match address_of(name) {
            Some(address) => neighbors.push(CallGraphNeighbor {
                name: name.clone(),
                address,
                signature,
                role: "callee".to_string(), // simplified: most are callees
            }),
            // If not found, just add a stub
            None => neighbors.push(CallGraphNeighbor {
                name: name.clone(),
                address: 0,
                signature,
                role: "unknown".to_string(),
            }),
        }
    }
    neighbors
}

/// Extract neighboring function context (full code) from the scan source.
///
/// Bodies come from the cached decompile; the raw disassembly listing has no
/// place in the read seam, so the disassembly field stays empty — the prompt
/// templates render it as an empty block.
pub async fn extract_neighboring_context<S: ScanSource>(
    source: &S,
    call_graph: &[String],
) -> Vec<NeighborFunction> {
    let functions = source.functions().await.unwrap_or_default();
    let mut neighbors = Vec::new();
    // Limit to a few neighbors to avoid context window bloat
    for name in call_graph.iter().take(3) {
        if let Some(found) = functions.iter().find(|f| f.name == *name)
            && let Ok(decompiled) = source.decompile(name).await
        {
            neighbors.push(NeighborFunction {
                name: decompiled.name,
                binary: String::new(),
                address: found.address,
                disassembly: String::new(),
                decompiler_output: decompiled.body.trim().to_string(),
            });
        }
    }
    neighbors
}

/// Extract data structure information from the persisted type database.
///
/// Reads the per-binary database recovered by the `calxgloss-typesdb`
/// engines from `re/analysis/typesdb/{binary}.json` and keeps the records
/// tied to the target function:
///
/// - inferred struct candidates whose literals the function
///   cross-references (the function appears in the candidate's
///   `referenced_by` list);
/// - named types recovered for classes whose vtable lists the function
///   as a method — the method list is the only per-function link the
///   database records for Type Manager types.
///
/// Returns an empty vector when no workspace is configured, no database
/// is persisted for `binary` (the scan has not run), or the document is
/// corrupt: missing data structure context degrades the prompt, it never
/// fails it.
pub fn extract_data_structures(
    workspace: Option<&std::path::Path>,
    binary: &str,
    function: &str,
) -> Vec<calxgloss_prompts::StructuredData> {
    let Some(workspace) = workspace else {
        return Vec::new();
    };

    let persistor = calxgloss_typesdb::persist::TypeDatabasePersistor::new(workspace);
    let db = match persistor.load(binary) {
        Ok(db) => db,
        Err(e) => {
            debug!(
                binary,
                error = %e,
                "No usable type database; continuing without data structure context"
            );
            return Vec::new();
        }
    };

    let mut structures = Vec::new();

    for candidate in db
        .inferred_structs
        .iter()
        .filter(|s| s.referenced_by.iter().any(|f| f == function))
    {
        structures.push(calxgloss_prompts::StructuredData::from(candidate));
    }

    let class_names: std::collections::HashSet<&str> = db
        .vtables
        .iter()
        .filter(|v| {
            v.methods
                .iter()
                .any(|m| m.name.as_deref() == Some(function))
        })
        .filter_map(|v| v.class_name.as_deref())
        .collect();
    for named in db
        .named_types
        .iter()
        .filter(|t| class_names.contains(t.name.as_str()))
    {
        structures.push(calxgloss_prompts::StructuredData::from(named));
    }

    structures
}

/// Extract inferred type information from the persisted inference cache.
///
/// Reads the per-binary result produced by the `calxgloss-typeinfer`
/// engine from `re/analysis/typeinfer/{binary}.json` and keeps the
/// inferences made for the target function — the parameter, local
/// variable, and call-site readings whose evidence lives in
/// `function`'s decompiled body.
///
/// Returns an empty vector when no workspace is configured, no result
/// is persisted for `binary` (the scan has not run), or the document is
/// corrupt: missing type context degrades the prompt, it never fails it.
pub fn extract_type_info(
    workspace: Option<&std::path::Path>,
    binary: &str,
    function: &str,
) -> Vec<calxgloss_prompts::TypeInfo> {
    let Some(workspace) = workspace else {
        return Vec::new();
    };

    let persistor = calxgloss_typeinfer::persist::TypeInferPersistor::new(workspace);
    let result = match persistor.load(binary) {
        Ok(result) => result,
        Err(e) => {
            debug!(
                binary,
                error = %e,
                "No usable type inference result; continuing without type context"
            );
            return Vec::new();
        }
    };

    result
        .for_function(function)
        .map(calxgloss_prompts::TypeInfo::from)
        .collect()
}

/// Extract recognized algorithm hints from the persisted recognition result.
///
/// Reads the per-binary result produced by the `calxgloss-algorithm`
/// engine from `re/analysis/algorithm/{binary}.json` and keeps the hints
/// made for the target function — the algorithms whose evidence lives in
/// `function`'s decompiled body or whose name the function carries.
///
/// Returns an empty vector when no workspace is configured, no result
/// is persisted for `binary` (the scan has not run), or the document is
/// corrupt: missing algorithm context degrades the prompt, it never
/// fails it.
pub fn extract_algorithm_hints(
    workspace: Option<&std::path::Path>,
    binary: &str,
    function: &str,
) -> Vec<calxgloss_prompts::AlgorithmInfo> {
    let Some(workspace) = workspace else {
        return Vec::new();
    };

    let persistor = calxgloss_algorithm::persist::AlgorithmPersistor::new(workspace);
    let result = match persistor.load(binary) {
        Ok(result) => result,
        Err(e) => {
            debug!(
                binary,
                error = %e,
                "No usable algorithm recognition result; continuing without algorithm context"
            );
            return Vec::new();
        }
    };

    result
        .for_function(function)
        .map(calxgloss_prompts::AlgorithmInfo::from)
        .collect()
}

/// Extract memory lifecycle findings for a function from the persisted
/// detection result.
///
/// Reads the per-binary result produced by the `calxgloss-memory`
/// engine from `re/analysis/memory/{binary}.json` and keeps the findings
/// made for the target function — the lifecycles whose pairing lives in
/// `function`'s decompiled body.
///
/// Returns an empty vector when no workspace is configured, no result
/// is persisted for `binary` (the scan has not run), or the document is
/// corrupt: missing memory context degrades the prompt, it never fails
/// it.
pub fn extract_memory_hints(
    workspace: Option<&std::path::Path>,
    binary: &str,
    function: &str,
) -> Vec<calxgloss_prompts::MemoryInfo> {
    let Some(workspace) = workspace else {
        return Vec::new();
    };

    let persistor = calxgloss_memory::persist::MemoryPersistor::new(workspace);
    let result = match persistor.load(binary) {
        Ok(result) => result,
        Err(e) => {
            debug!(
                binary,
                error = %e,
                "No usable memory lifecycle result; continuing without memory context"
            );
            return Vec::new();
        }
    };

    result
        .for_function(function)
        .map(calxgloss_prompts::MemoryInfo::from)
        .collect()
}

/// Extract concurrency findings for a function from the persisted
/// detection result.
///
/// Reads the per-binary result produced by the `calxgloss-sync` engine
/// from `re/analysis/sync/{binary}.json` and keeps the findings made for
/// the target function — the lock pairings, atomic calls, and thread
/// spawns whose calls live in `function`'s decompiled body.
///
/// Returns an empty vector when no workspace is configured, no result
/// is persisted for `binary` (the scan has not run), or the document is
/// corrupt: missing concurrency context degrades the prompt, it never
/// fails it.
pub fn extract_concurrency_hints(
    workspace: Option<&std::path::Path>,
    binary: &str,
    function: &str,
) -> Vec<calxgloss_prompts::ConcurrencyInfo> {
    let Some(workspace) = workspace else {
        return Vec::new();
    };

    let persistor = calxgloss_sync::persist::SyncPersistor::new(workspace);
    let result = match persistor.load(binary) {
        Ok(result) => result,
        Err(e) => {
            debug!(
                binary,
                error = %e,
                "No usable concurrency result; continuing without concurrency context"
            );
            return Vec::new();
        }
    };

    result
        .for_function(function)
        .map(calxgloss_prompts::ConcurrencyInfo::from)
        .collect()
}

/// Extract library/API findings for a function from the persisted
/// detection result.
///
/// Reads the per-binary result produced by the `calxgloss-apidetect`
/// engine from `re/analysis/apidetect/{binary}.json` and keeps the usages
/// recorded for the target function — the identified APIs the function
/// calls directly or reaches through its call graph. Binary-level
/// import entries belong to the binary, not to any function, and do not
/// appear here.
///
/// Returns an empty vector when no workspace is configured, no result
/// is persisted for `binary` (the scan has not run), or the document is
/// corrupt: missing API context degrades the prompt, it never fails it.
pub fn extract_api_hints(
    workspace: Option<&std::path::Path>,
    binary: &str,
    function: &str,
) -> Vec<calxgloss_prompts::ApiInfo> {
    let Some(workspace) = workspace else {
        return Vec::new();
    };

    let persistor = calxgloss_apidetect::persist::ApiPersistor::new(workspace);
    let result = match persistor.load(binary) {
        Ok(result) => result,
        Err(e) => {
            debug!(
                binary,
                error = %e,
                "No usable API result; continuing without library/API context"
            );
            return Vec::new();
        }
    };

    result
        .for_function(function)
        .map(calxgloss_prompts::ApiInfo::from)
        .collect()
}

/// Extract constant findings for a function from the persisted
/// detection result.
///
/// Reads the per-binary result produced by the `calxgloss-consts`
/// engine from `re/analysis/consts/{binary}.json` and keeps the findings
/// about the target function — the bitflag groups and enum candidates
/// made in `function`'s decompiled body, plus the program-level named
/// constants whose value `function` repeats.
///
/// Returns an empty vector when no workspace is configured, no result
/// is persisted for `binary` (the scan has not run), or the document is
/// corrupt: missing constant context degrades the prompt, it never
/// fails it.
pub fn extract_constant_hints(
    workspace: Option<&std::path::Path>,
    binary: &str,
    function: &str,
) -> Vec<calxgloss_prompts::ConstInfo> {
    let Some(workspace) = workspace else {
        return Vec::new();
    };

    let persistor = calxgloss_consts::persist::ConstPersistor::new(workspace);
    let result = match persistor.load(binary) {
        Ok(result) => result,
        Err(e) => {
            debug!(
                binary,
                error = %e,
                "No usable constant result; continuing without constant context"
            );
            return Vec::new();
        }
    };

    result
        .for_function(function)
        .map(calxgloss_prompts::ConstInfo::from)
        .collect()
}

/// Extract serialization findings for a function from the persisted
/// detection result.
///
/// Reads the per-binary result produced by the `calxgloss-serialize`
/// engine from `re/analysis/serialize/{binary}.json` and keeps the
/// findings made for the target function — the byte-swap calls,
/// bit-packing chains, and file-format signature comparisons whose
/// expressions live in `function`'s decompiled body.
///
/// Returns an empty vector when no workspace is configured, no result
/// is persisted for `binary` (the scan has not run), or the document is
/// corrupt: missing serialization context degrades the prompt, it
/// never fails it.
pub fn extract_serialization_hints(
    workspace: Option<&std::path::Path>,
    binary: &str,
    function: &str,
) -> Vec<calxgloss_prompts::SerializationInfo> {
    let Some(workspace) = workspace else {
        return Vec::new();
    };

    let persistor = calxgloss_serialize::persist::SerializePersistor::new(workspace);
    let result = match persistor.load(binary) {
        Ok(result) => result,
        Err(e) => {
            debug!(
                binary,
                error = %e,
                "No usable serialization result; continuing without serialization context"
            );
            return Vec::new();
        }
    };

    result
        .for_function(function)
        .map(calxgloss_prompts::SerializationInfo::from)
        .collect()
}

/// Extract callback findings for a function from the persisted
/// detection result.
///
/// Reads the per-binary result produced by the `calxgloss-callback`
/// engine from `re/analysis/callback/{binary}.json` and keeps the findings
/// made for the target function — the function-pointer array calls,
/// callback registrations, and jump-table dispatches whose calls live
/// in `function`'s decompiled body.
///
/// Returns an empty vector when no workspace is configured, no result
/// is persisted for `binary` (the scan has not run), or the document is
/// corrupt: missing callback context degrades the prompt, it never
/// fails it.
pub fn extract_callback_hints(
    workspace: Option<&std::path::Path>,
    binary: &str,
    function: &str,
) -> Vec<calxgloss_prompts::CallbackInfo> {
    let Some(workspace) = workspace else {
        return Vec::new();
    };

    let persistor = calxgloss_callback::persist::CallbackPersistor::new(workspace);
    let result = match persistor.load(binary) {
        Ok(result) => result,
        Err(e) => {
            debug!(
                binary,
                error = %e,
                "No usable callback result; continuing without callback context"
            );
            return Vec::new();
        }
    };

    result
        .for_function(function)
        .map(calxgloss_prompts::CallbackInfo::from)
        .collect()
}

/// Extract control-flow findings for a function from the cached control-flow
/// detection result.
///
/// Reads the per-binary result produced by the `calxgloss-controlflow`
/// engine from `re/analysis/controlflow/{binary}.json` and keeps the findings
/// made for the target function — the switch-shaped if-else chains,
/// self-recursion, and state-machine patterns whose code lives in
/// `function`'s decompiled body.
///
/// Returns an empty vector when no workspace is configured, no result
/// is persisted for `binary` (the scan has not run), or the document is
/// corrupt: missing control-flow context degrades the prompt, it never
/// fails it.
pub fn extract_control_flow_hints(
    workspace: Option<&std::path::Path>,
    binary: &str,
    function: &str,
) -> Vec<calxgloss_prompts::ControlFlowInfo> {
    let Some(workspace) = workspace else {
        return Vec::new();
    };

    let persistor = calxgloss_controlflow::persist::ControlFlowPersistor::new(workspace);
    let result = match persistor.load(binary) {
        Ok(result) => result,
        Err(e) => {
            debug!(
                binary,
                error = %e,
                "No usable control-flow result; continuing without control-flow context"
            );
            return Vec::new();
        }
    };

    result
        .for_function(function)
        .map(calxgloss_prompts::ControlFlowInfo::from)
        .collect()
}

/// Extract string-context findings for a function from the persisted
/// scan result.
///
/// Reads the per-binary result produced by the `calxgloss-stringctx`
/// engine from `re/analysis/stringctx/{binary}.json` and keeps the findings
/// made for the target function — the classified strings the function
/// references and the format-string calls it makes, with the argument
/// types those calls imply.
///
/// Returns an empty vector when no workspace is configured, no result
/// is persisted for `binary` (the scan has not run), or the document is
/// corrupt: missing string context degrades the prompt, it never fails
/// it.
pub fn extract_string_context(
    workspace: Option<&std::path::Path>,
    binary: &str,
    function: &str,
) -> Vec<calxgloss_prompts::StringContextInfo> {
    let Some(workspace) = workspace else {
        return Vec::new();
    };

    let persistor = calxgloss_stringctx::persist::StringContextPersistor::new(workspace);
    let result = match persistor.load(binary) {
        Ok(result) => result,
        Err(e) => {
            debug!(
                binary,
                error = %e,
                "No usable string context result; continuing without string context"
            );
            return Vec::new();
        }
    };

    result
        .for_function(function)
        .map(calxgloss_prompts::StringContextInfo::from)
        .collect()
}

// ============================================================
// Tier 4 — Shim layer and PAL trait extraction
// ============================================================

/// Extract shim layer code for a given DLL from the workspace.
///
/// Reads the generated shim source from `re/shims/<dll_name>/shim.rs` in
/// the workspace directory. Returns an empty vector when no shim exists
/// or the workspace path is not configured.
pub fn extract_shim_layers(workspace: Option<&std::path::Path>, dll_name: &str) -> Vec<ShimCode> {
    let Some(workspace) = workspace else {
        return Vec::new();
    };

    let shim_dir = workspace.join("re").join("shims").join(dll_name);
    let shim_file = shim_dir.join("shim.rs");

    if !shim_file.exists() {
        return Vec::new();
    }

    match std::fs::read_to_string(&shim_file) {
        Ok(source) => vec![ShimCode {
            source_dll: dll_name.to_string(),
            target_crate: String::new(), // filled by caller from mappings.json
            mapping_count: 0,            // filled by caller from mappings.json
            source,
        }],
        Err(_) => Vec::new(),
    }
}

/// Extract PAL trait definitions based on the Windows API categories
/// found in a function's disassembly.
///
/// Returns a set of PAL traits that cover the API categories the
/// function touches. This gives the LLM the exact trait method
/// signatures it needs to use for each API category.
pub fn extract_pal_traits(windows_apis: &[WindowsApiCall]) -> Vec<PalTraitDef> {
    if windows_apis.is_empty() {
        return Vec::new();
    }

    // Collect unique API categories from the function's Windows API calls
    let categories: std::collections::HashSet<&ApiCategory> =
        windows_apis.iter().map(|api| &api.category).collect();

    let mut traits = Vec::new();

    for category in &categories {
        match category {
            ApiCategory::DirectX
            | ApiCategory::DirectX10
            | ApiCategory::DirectX11
            | ApiCategory::DirectX12 => {
                traits.push(PalTraitDef {
                    trait_name: "GraphicsDevice".to_string(),
                    module: "pal".to_string(),
                    description:
                        "Abstracts DirectX graphics device operations (create, render, present)"
                            .to_string(),
                    methods: vec![
                        PalTraitMethod {
                            name: "create_device".to_string(),
                            signature: "fn create_device(width: u32, height: u32) -> Self"
                                .to_string(),
                            description: "Create a new graphics device / swap chain".to_string(),
                        },
                        PalTraitMethod {
                            name: "render".to_string(),
                            signature: "fn render(&mut self, encoder: &mut wgpu::CommandEncoder)"
                                .to_string(),
                            description: "Execute rendering commands via a wgpu encoder"
                                .to_string(),
                        },
                        PalTraitMethod {
                            name: "present".to_string(),
                            signature: "fn present(&mut self)".to_string(),
                            description: "Present the rendered frame to the screen".to_string(),
                        },
                        PalTraitMethod {
                            name: "set_texture".to_string(),
                            signature:
                                "fn set_texture(&mut self, stage: u32, texture: &TextureView)"
                                    .to_string(),
                            description:
                                "Bind a texture to a pipeline stage (maps DirectX SetTexture)"
                                    .to_string(),
                        },
                    ],
                });
            }
            ApiCategory::Gdi | ApiCategory::GdiPlus | ApiCategory::Direct2D => {
                traits.push(PalTraitDef {
                    trait_name: "Graphics2D".to_string(),
                    module: "pal".to_string(),
                    description: "Abstracts 2D graphics operations (GDI → tiny-skia)".to_string(),
                    methods: vec![
                        PalTraitMethod {
                            name: "create_pixmap".to_string(),
                            signature: "fn create_pixmap(width: u32, height: u32) -> Self".to_string(),
                            description: "Create a new 2D rendering surface".to_string(),
                        },
                        PalTraitMethod {
                            name: "blit".to_string(),
                            signature: "fn blit(&mut self, src: &Pixmap, dest_x: i32, dest_y: i32)".to_string(),
                            description: "Copy pixels from source to destination (maps BitBlt)".to_string(),
                        },
                        PalTraitMethod {
                            name: "draw_line".to_string(),
                            signature: "fn draw_line(&mut self, x1: f32, y1: f32, x2: f32, y2: f32, color: Color)".to_string(),
                            description: "Draw a line segment".to_string(),
                        },
                        PalTraitMethod {
                            name: "draw_rect".to_string(),
                            signature: "fn draw_rect(&mut self, x: f32, y: f32, w: f32, h: f32, color: Color)".to_string(),
                            description: "Draw a filled rectangle".to_string(),
                        },
                        PalTraitMethod {
                            name: "draw_text".to_string(),
                            signature: "fn draw_text(&mut self, x: f32, y: f32, text: &str, font: &Font, color: Color)".to_string(),
                            description: "Render text at position".to_string(),
                        },
                    ],
                });
            }
            ApiCategory::Audio => {
                traits.push(PalTraitDef {
                    trait_name: "AudioDevice".to_string(),
                    module: "pal".to_string(),
                    description: "Abstracts audio playback operations (DirectSound → cpal)".to_string(),
                    methods: vec![
                        PalTraitMethod {
                            name: "open_stream".to_string(),
                            signature: "fn open_stream(&mut self, config: &StreamConfig) -> Result<Self, AudioError>".to_string(),
                            description: "Open an audio output stream".to_string(),
                        },
                        PalTraitMethod {
                            name: "play".to_string(),
                            signature: "fn play(&mut self, samples: &[f32]) -> Result<(), AudioError>".to_string(),
                            description: "Play audio samples through the output stream".to_string(),
                        },
                        PalTraitMethod {
                            name: "stop".to_string(),
                            signature: "fn stop(&mut self)".to_string(),
                            description: "Stop the audio stream".to_string(),
                        },
                        PalTraitMethod {
                            name: "set_volume".to_string(),
                            signature: "fn set_volume(&mut self, volume: f32)".to_string(),
                            description: "Set the output volume (0.0 = mute, 1.0 = full)".to_string(),
                        },
                    ],
                });
            }
            ApiCategory::Win32Gui => {
                traits.push(PalTraitDef {
                    trait_name: "WindowManager".to_string(),
                    module: "pal".to_string(),
                    description: "Abstracts windowing and GUI operations (Win32 → winit + egui)"
                        .to_string(),
                    methods: vec![
                        PalTraitMethod {
                            name: "create_window".to_string(),
                            signature:
                                "fn create_window(title: &str, width: u32, height: u32) -> Self"
                                    .to_string(),
                            description: "Create a new application window".to_string(),
                        },
                        PalTraitMethod {
                            name: "process_events".to_string(),
                            signature: "fn process_events(&mut self, handler: impl FnMut(Event))"
                                .to_string(),
                            description: "Process pending window events and dispatch to handler"
                                .to_string(),
                        },
                        PalTraitMethod {
                            name: "get_size".to_string(),
                            signature: "fn get_size(&self) -> (u32, u32)".to_string(),
                            description: "Get the current window client area size".to_string(),
                        },
                        PalTraitMethod {
                            name: "set_title".to_string(),
                            signature: "fn set_title(&mut self, title: &str)".to_string(),
                            description: "Set the window title bar text".to_string(),
                        },
                    ],
                });
            }
            ApiCategory::Win32Core => {
                traits.push(PalTraitDef {
                    trait_name: "PlatformCore".to_string(),
                    module: "pal".to_string(),
                    description:
                        "Abstracts core Win32 operations (VirtualAlloc, CreateThread, Sleep, etc.)"
                            .to_string(),
                    methods: vec![
                        PalTraitMethod {
                            name: "allocate_memory".to_string(),
                            signature: "fn allocate_memory(size: usize, writable: bool) -> *mut u8"
                                .to_string(),
                            description: "Allocate memory (maps VirtualAlloc)".to_string(),
                        },
                        PalTraitMethod {
                            name: "free_memory".to_string(),
                            signature: "fn free_memory(ptr: *mut u8, size: usize)".to_string(),
                            description: "Free previously allocated memory (maps VirtualFree)"
                                .to_string(),
                        },
                        PalTraitMethod {
                            name: "sleep".to_string(),
                            signature: "fn sleep(ms: u64)".to_string(),
                            description: "Sleep for the specified milliseconds".to_string(),
                        },
                        PalTraitMethod {
                            name: "get_tick_count".to_string(),
                            signature: "fn get_tick_count() -> u64".to_string(),
                            description: "Get system uptime in milliseconds (maps GetTickCount)"
                                .to_string(),
                        },
                    ],
                });
            }
            ApiCategory::Com => {
                traits.push(PalTraitDef {
                    trait_name: "ComObject".to_string(),
                    module: "pal".to_string(),
                    description: "Abstracts COM object operations (IUnknown vtable, CoCreateInstance)".to_string(),
                    methods: vec![
                        PalTraitMethod {
                            name: "create_instance".to_string(),
                            signature: "fn create_instance<T: ComInterface>(clsid: &Guid) -> Result<T, ComError>".to_string(),
                            description: "Create a COM object instance (maps CoCreateInstance)".to_string(),
                        },
                        PalTraitMethod {
                            name: "add_ref".to_string(),
                            signature: "fn add_ref(&self) -> u32".to_string(),
                            description: "Increment the reference count (maps IUnknown::AddRef)".to_string(),
                        },
                        PalTraitMethod {
                            name: "release".to_string(),
                            signature: "fn release(&self) -> u32".to_string(),
                            description: "Decrement the reference count and free if zero (maps IUnknown::Release)".to_string(),
                        },
                    ],
                });
            }
            _ => {}
        }
    }

    traits
}

// ============================================================
// Tier escalation prompt builder
// ============================================================

/// Build an escalated prompt for a given context tier using the initial
/// translation's data.
///
/// This function is called during the retry loop when a tier escalation
/// is needed. It reconstructs the appropriate prompt data from the initial
/// translation and, for higher tiers (≥3), fetches additional context from
/// Ghidra or the workspace.
///
/// # Arguments
///
/// * `translation` — The initial [`Translation`] produced by the pipeline.
/// * `tier` — The target context tier to build for.
/// * `source` — scan source for fetching additional context (live client
///   or the batch's read cache).
/// * `workspace` — Optional workspace path for shim layer and type
///   database extraction.
///
/// # Returns
///
/// A prompt string suitable for sending to the LLM, or an error string
/// if prompt construction fails.
pub async fn build_escalated_prompt<S: ScanSource>(
    translation: &Translation,
    tier: ContextTier,
    source: &S,
    workspace: Option<&std::path::Path>,
) -> Result<String, String> {
    let binary = &translation.binary;
    let function = &translation.function;

    match tier {
        ContextTier::Signature => {
            // Tier 0: signature prompt — only function name, signature, call graph
            let neighbors = translation
                .call_graph
                .iter()
                .map(|name| CallGraphNeighbor {
                    name: name.clone(),
                    address: 0,
                    signature: String::new(),
                    role: String::new(),
                })
                .collect();
            let data = calxgloss_prompts::SignaturePromptData {
                function_name: function.clone(),
                dll_name: binary.to_string(),
                address_hex: format!("{:#x}", translation.function_address.unwrap_or(0)),
                signature: String::new(),
                call_graph_neighbors: neighbors,
            };
            calxgloss_prompts::build_signature_prompt(&data).map_err(|e| e.to_string())
        }
        ContextTier::Disassembly => {
            // Tier 1: disassembly + decompiler + type info
            let call_graph: Vec<calxgloss_types::WindowsApiCall> = translation
                .call_graph
                .iter()
                .map(|name| calxgloss_types::WindowsApiCall {
                    name: name.clone(),
                    category: ApiCategory::Win32Core,
                    pal_mapping: String::new(),
                })
                .collect();
            let data = calxgloss_prompts::DisassemblyPromptData {
                function_name: function.clone(),
                dll_name: binary.to_string(),
                address: translation.function_address.unwrap_or(0),
                disassembly: translation.prompt_used.clone(),
                decompiler_output: String::new(),
                windows_apis: call_graph,
                no_windows_apis: translation.call_graph.is_empty(),
                test_cases: Vec::new(),
            };
            calxgloss_prompts::build_disassembly_prompt(&data).map_err(|e| e.to_string())
        }
        ContextTier::WithTests => {
            // Tier 2: disassembly + decompiler + baseline tests
            let call_graph: Vec<calxgloss_types::WindowsApiCall> = translation
                .call_graph
                .iter()
                .map(|name| calxgloss_types::WindowsApiCall {
                    name: name.clone(),
                    category: ApiCategory::Win32Core,
                    pal_mapping: String::new(),
                })
                .collect();

            let request = TranslationRequest {
                binary: binary.clone(),
                function: function.clone(),
                disassembly: translation.prompt_used.clone(),
                decompiler_output: String::new(),
                windows_apis: call_graph,
                baseline_tests: translation.baseline_tests.clone(),
            };
            let mut data = calxgloss_prompts::WithTestsPromptData::from_request(&request);
            data.call_graph_context = translation.call_graph_context.clone();
            calxgloss_prompts::build_with_tests_prompt(&data).map_err(|e| e.to_string())
        }
        ContextTier::ModuleContext => {
            // Tier 3: module context + neighboring functions + data structures
            let call_graph: Vec<calxgloss_types::WindowsApiCall> = translation
                .call_graph
                .iter()
                .map(|name| calxgloss_types::WindowsApiCall {
                    name: name.clone(),
                    category: ApiCategory::Win32Core,
                    pal_mapping: String::new(),
                })
                .collect();

            let request = TranslationRequest {
                binary: binary.clone(),
                function: function.clone(),
                disassembly: translation.prompt_used.clone(),
                decompiler_output: String::new(),
                windows_apis: call_graph,
                baseline_tests: translation.baseline_tests.clone(),
            };

            let call_graph_neighbors = extract_call_graph_neighbors(
                source,
                &translation.call_graph,
                translation.function_address.unwrap_or(0),
            )
            .await;
            let neighboring_functions =
                extract_neighboring_context(source, &translation.call_graph).await;
            let data_structures = extract_data_structures(workspace, binary, function);

            let control_flow_findings = extract_control_flow_hints(workspace, binary, function);

            let data = calxgloss_prompts::ModuleContextPromptData::from_request_with_context(
                &request,
                call_graph_neighbors,
                neighboring_functions,
                data_structures,
                translation.call_graph_context.clone(),
                control_flow_findings,
            );
            calxgloss_prompts::build_module_context_prompt(&data).map_err(|e| e.to_string())
        }
        ContextTier::FullModule => {
            // Tier 4: full module + shim layer code + PAL trait definitions
            let call_graph: Vec<calxgloss_types::WindowsApiCall> = translation
                .call_graph
                .iter()
                .map(|name| calxgloss_types::WindowsApiCall {
                    name: name.clone(),
                    category: ApiCategory::Win32Core,
                    pal_mapping: String::new(),
                })
                .collect();

            let request = TranslationRequest {
                binary: binary.clone(),
                function: function.clone(),
                disassembly: translation.prompt_used.clone(),
                decompiler_output: String::new(),
                windows_apis: call_graph,
                baseline_tests: translation.baseline_tests.clone(),
            };

            let call_graph_neighbors = extract_call_graph_neighbors(
                source,
                &translation.call_graph,
                translation.function_address.unwrap_or(0),
            )
            .await;
            let neighboring_functions =
                extract_neighboring_context(source, &translation.call_graph).await;
            let data_structures = extract_data_structures(workspace, binary, function);

            let shim_layers = extract_shim_layers(workspace, binary);
            let pal_traits = Vec::<PalTraitDef>::new();

            let control_flow_findings = extract_control_flow_hints(workspace, binary, function);

            let data = calxgloss_prompts::FullModulePromptData::from_request_with_full_context(
                &request,
                call_graph_neighbors,
                neighboring_functions,
                data_structures,
                shim_layers,
                pal_traits,
                translation.call_graph_context.clone(),
                control_flow_findings,
            );
            calxgloss_prompts::build_full_module_prompt(&data).map_err(|e| e.to_string())
        }
    }
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use calxgloss_typeinfer::persist::TypeInferPersistor;
    use calxgloss_typeinfer::types::{
        Confidence, InferenceMethod, InferenceScope, InferredCallType, InferredLocalType,
        InferredParamType, InferredType, TypeInferenceResult,
    };
    use calxgloss_typesdb::persist::TypeDatabasePersistor;
    use calxgloss_typesdb::types::{
        EnumMember, FieldType, InferredField, InferredStruct, NameOrigin, NamedType, ScanMetadata,
        TypeDatabase, TypeKind, Vtable, VtableMethod,
    };
    use tempfile::TempDir;

    fn inferred_struct(name: &str, referenced_by: &[&str]) -> InferredStruct {
        InferredStruct {
            name: name.to_string(),
            name_origin: NameOrigin::LiteralPrefix,
            fields: vec![
                InferredField {
                    name: "x".into(),
                    field_type: FieldType::Integer,
                    size: Some(4),
                    offset: Some(0),
                    source_value: format!("{name}.x"),
                    source_address: 0x1801_29350,
                },
                InferredField {
                    name: "label".into(),
                    field_type: FieldType::String,
                    size: Some(8),
                    offset: None,
                    source_value: format!("{name}.label"),
                    source_address: 0x1801_29360,
                },
            ],
            confidence: 79.into(),
            referenced_by: referenced_by.iter().map(|f| f.to_string()).collect(),
        }
    }

    fn named_struct(name: &str) -> NamedType {
        NamedType {
            name: name.to_string(),
            kind: TypeKind::Struct,
            category: "excpt.h".into(),
            path: format!("/excpt.h/{name}"),
            size: Some(16),
            alignment: None,
            fields: vec![calxgloss_typesdb::types::StructField {
                name: "header".into(),
                offset: 0,
                size: 4,
                type_name: "dword".into(),
            }],
            members: Vec::new(),
        }
    }

    fn vtable_for(class: &str, method: &str) -> Vtable {
        Vtable {
            address: 0x1801_306f0,
            label: "vftable".into(),
            size: 8,
            meta_ptr_address: None,
            methods: vec![VtableMethod {
                slot: 0,
                address: 0x1800_3ab00,
                name: Some(method.to_string()),
            }],
            class_name: Some(class.to_string()),
            base_classes: Vec::new(),
            is_com_interface: false,
        }
    }

    fn persist(dir: &TempDir, db: TypeDatabase) {
        TypeDatabasePersistor::new(dir.path()).save(&db).unwrap();
    }

    #[test]
    fn no_workspace_configured_yields_no_structures() {
        assert!(extract_data_structures(None, "eqmain.dll", "FUN_18000b620").is_empty());
    }

    #[test]
    fn a_missing_database_yields_no_structures() {
        let dir = TempDir::new().unwrap();
        assert!(
            extract_data_structures(Some(dir.path()), "eqmain.dll", "FUN_18000b620").is_empty()
        );
    }

    #[test]
    fn a_corrupt_database_degrades_to_no_structures() {
        let dir = TempDir::new().unwrap();
        let path = dir
            .path()
            .join("re")
            .join("analysis")
            .join("typesdb")
            .join("eqmain.dll.json");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "{ not json").unwrap();

        assert!(
            extract_data_structures(Some(dir.path()), "eqmain.dll", "FUN_18000b620").is_empty()
        );
    }

    #[test]
    fn inferred_candidates_the_function_references_are_converted() {
        let dir = TempDir::new().unwrap();
        let mut db = TypeDatabase::new(ScanMetadata::new("eqmain.dll"));
        db.inferred_structs = vec![
            inferred_struct("Player", &["FUN_18000b620"]),
            inferred_struct("Other", &["FUN_zzz"]),
        ];
        persist(&dir, db);

        let found = extract_data_structures(Some(dir.path()), "eqmain.dll", "FUN_18000b620");

        assert_eq!(found.len(), 1, "only the referenced candidate is kept");
        assert_eq!(found[0].name, "Player");
        assert_eq!(found[0].size, 12, "both fields carry a size");
        assert_eq!(found[0].fields[0].name, "x");
        assert_eq!(found[0].fields[0].type_, "int");
        assert_eq!(found[0].fields[0].offset, 0);
        assert_eq!(found[0].fields[1].type_, "char *");
        assert_eq!(
            found[0].fields[1].offset, -1,
            "an unplaced field stays unknown"
        );
    }

    #[test]
    fn named_types_of_classes_the_function_methods_are_included() {
        let dir = TempDir::new().unwrap();
        let mut db = TypeDatabase::new(ScanMetadata::new("eqmain.dll"));
        db.vtables = vec![vtable_for("Widget", "FUN_18003ab00")];
        db.named_types = vec![named_struct("Widget"), named_struct("Unrelated")];
        persist(&dir, db);

        let found = extract_data_structures(Some(dir.path()), "eqmain.dll", "FUN_18003ab00");

        assert_eq!(found.len(), 1, "only the class the function is a method of");
        assert_eq!(found[0].name, "Widget");
        assert_eq!(found[0].size, 16);
        assert_eq!(found[0].fields[0].name, "header");
        assert_eq!(found[0].fields[0].type_, "dword");
        assert_eq!(found[0].fields[0].offset, 0);

        let none = extract_data_structures(Some(dir.path()), "eqmain.dll", "FUN_zzz");
        assert!(none.is_empty(), "an unrelated function gets nothing");
    }

    #[test]
    fn enum_members_arrive_as_fields_without_offsets() {
        let dir = TempDir::new().unwrap();
        let mut db = TypeDatabase::new(ScanMetadata::new("eqmain.dll"));
        db.vtables = vec![vtable_for("Mode", "FUN_18003e750")];
        db.named_types = vec![NamedType {
            members: vec![
                EnumMember {
                    name: "Idle".into(),
                    value: 0,
                },
                EnumMember {
                    name: "Running".into(),
                    value: 1,
                },
            ],
            ..named_struct("Mode")
        }];
        persist(&dir, db);

        let found = extract_data_structures(Some(dir.path()), "eqmain.dll", "FUN_18003e750");

        assert_eq!(found.len(), 1);
        // Structure fields come first, then the enum members.
        assert_eq!(found[0].fields[0].name, "header");
        assert_eq!(found[0].fields[1].name, "Idle");
        assert_eq!(found[0].fields[2].name, "Running");
        assert_eq!(
            found[0].fields[2].type_, "1",
            "the member value is its type"
        );
        assert_eq!(found[0].fields[2].offset, -1);
    }

    #[test]
    fn both_evidence_paths_land_in_one_result() {
        let dir = TempDir::new().unwrap();
        let mut db = TypeDatabase::new(ScanMetadata::new("eqmain.dll"));
        db.inferred_structs = vec![inferred_struct("Player", &["FUN_18000b620"])];
        db.vtables = vec![vtable_for("Widget", "FUN_18000b620")];
        db.named_types = vec![named_struct("Widget")];
        persist(&dir, db);

        let found = extract_data_structures(Some(dir.path()), "eqmain.dll", "FUN_18000b620");

        let names: Vec<&str> = found.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, vec!["Player", "Widget"]);
    }

    fn param_inference(function: &str, index: usize, inferred_type: &str) -> InferredType {
        InferredType::Param(InferredParamType {
            function: function.to_string(),
            param_index: index,
            param_name: Some(format!("param_{}", index + 1)),
            inferred_type: inferred_type.to_string(),
            method: InferenceMethod::VtableCall,
            scope: InferenceScope::Class,
            confidence: Confidence::new(85),
            evidence: "(*(code *)(**param_1))[3](param_1)".into(),
        })
    }

    fn persist_inferences(dir: &TempDir, inferences: Vec<InferredType>) {
        let mut result = TypeInferenceResult::new(ScanMetadata::new("eqmain.dll"));
        result.inferences = inferences;
        TypeInferPersistor::new(dir.path()).save(&result).unwrap();
    }

    #[test]
    fn no_workspace_configured_yields_no_type_info() {
        assert!(extract_type_info(None, "eqmain.dll", "FUN_18003ab00").is_empty());
    }

    #[test]
    fn a_missing_cache_yields_no_type_info() {
        let dir = TempDir::new().unwrap();
        assert!(
            extract_type_info(Some(dir.path()), "eqmain.dll", "FUN_18003ab00").is_empty(),
            "a scan that has not run yet just means no type context"
        );
    }

    #[test]
    fn a_corrupt_cache_degrades_to_no_type_info() {
        let dir = TempDir::new().unwrap();
        let path = dir
            .path()
            .join("re")
            .join("analysis")
            .join("typeinfer")
            .join("eqmain.dll.json");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "{ not json").unwrap();

        assert!(extract_type_info(Some(dir.path()), "eqmain.dll", "FUN_18003ab00").is_empty());
    }

    #[test]
    fn inferences_of_other_functions_are_dropped() {
        let dir = TempDir::new().unwrap();
        persist_inferences(
            &dir,
            vec![
                param_inference("FUN_18003ab00", 0, "Widget *"),
                param_inference("FUN_zzz", 0, "char *"),
            ],
        );

        let found = extract_type_info(Some(dir.path()), "eqmain.dll", "FUN_18003ab00");

        assert_eq!(found.len(), 1, "only the target function's inference");
        assert_eq!(found[0].name, "param_1");
        assert_eq!(
            found[0].description,
            "Widget * (via vtable_call, confidence 85)"
        );
    }

    #[test]
    fn every_record_kind_of_the_function_lands_in_the_prompt() {
        let dir = TempDir::new().unwrap();
        persist_inferences(
            &dir,
            vec![
                param_inference("FUN_18003ab00", 0, "Widget *"),
                InferredType::Local(InferredLocalType {
                    function: "FUN_18003ab00".into(),
                    variable_name: "local_8".into(),
                    inferred_type: "char *".into(),
                    method: InferenceMethod::KnownSignature,
                    scope: InferenceScope::Function,
                    confidence: Confidence::new(60),
                    evidence: "local_8 = (char *)malloc(0x10);".into(),
                }),
                InferredType::CallSite(InferredCallType {
                    function: "FUN_18003ab00".into(),
                    callee: "CloseHandle".into(),
                    arg_index: 0,
                    arg_name: None,
                    inferred_type: "void *".into(),
                    method: InferenceMethod::KnownSignature,
                    scope: InferenceScope::Program,
                    confidence: Confidence::new(75),
                    evidence: "CloseHandle(0x1234);".into(),
                }),
            ],
        );

        let found = extract_type_info(Some(dir.path()), "eqmain.dll", "FUN_18003ab00");

        let names: Vec<&str> = found.iter().map(|t| t.name.as_str()).collect();
        assert_eq!(names, vec!["param_1", "local_8", "CloseHandle arg 1"]);
        assert_eq!(
            found[2].description,
            "void * (via known_signature, confidence 75)"
        );
    }

    fn algorithm_hint(
        function: &str,
        algorithm: &str,
    ) -> calxgloss_algorithm::types::AlgorithmHint {
        calxgloss_algorithm::types::AlgorithmHint {
            function: function.to_string(),
            algorithm: algorithm.to_string(),
            category: calxgloss_algorithm::types::AlgorithmCategory::Sorting,
            method: calxgloss_algorithm::types::DetectionMethod::CfgPattern,
            confidence: calxgloss_algorithm::types::Confidence::new(60),
            evidence: "for (local_10 = 0; local_10 < uVar2; local_10 = local_10 + 1)".into(),
        }
    }

    fn persist_hints(dir: &TempDir, hints: Vec<calxgloss_algorithm::types::AlgorithmHint>) {
        let mut result = calxgloss_algorithm::types::AlgorithmRecognitionResult::new(
            ScanMetadata::new("eqmain.dll"),
        );
        result.hints = hints;
        calxgloss_algorithm::persist::AlgorithmPersistor::new(dir.path())
            .save(&result)
            .unwrap();
    }

    #[test]
    fn no_workspace_configured_yields_no_algorithm_hints() {
        assert!(extract_algorithm_hints(None, "eqmain.dll", "FUN_18003ab00").is_empty());
    }

    #[test]
    fn a_missing_cache_yields_no_algorithm_hints() {
        let dir = TempDir::new().unwrap();
        assert!(
            extract_algorithm_hints(Some(dir.path()), "eqmain.dll", "FUN_18003ab00").is_empty(),
            "a scan that has not run yet just means no algorithm context"
        );
    }

    #[test]
    fn a_corrupt_cache_degrades_to_no_algorithm_hints() {
        let dir = TempDir::new().unwrap();
        let path = dir
            .path()
            .join("re")
            .join("analysis")
            .join("algorithm")
            .join("eqmain.dll.json");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "{ not json").unwrap();

        assert!(
            extract_algorithm_hints(Some(dir.path()), "eqmain.dll", "FUN_18003ab00").is_empty()
        );
    }

    #[test]
    fn hints_of_other_functions_are_dropped() {
        let dir = TempDir::new().unwrap();
        persist_hints(
            &dir,
            vec![
                algorithm_hint("FUN_18003ab00", "comparison_sort"),
                algorithm_hint("FUN_zzz", "binary_search"),
            ],
        );

        let found = extract_algorithm_hints(Some(dir.path()), "eqmain.dll", "FUN_18003ab00");

        assert_eq!(found.len(), 1, "only the target function's hint");
        assert_eq!(found[0].algorithm, "comparison_sort");
        assert_eq!(found[0].category, "sorting");
        assert_eq!(found[0].method, "cfg_pattern");
        assert_eq!(found[0].confidence, 60);
        assert!(found[0].evidence.starts_with("for (local_10 = 0;"));
    }

    #[test]
    fn every_hint_of_the_function_lands_in_the_prompt() {
        let dir = TempDir::new().unwrap();
        persist_hints(
            &dir,
            vec![
                algorithm_hint("FUN_18003ab00", "comparison_sort"),
                calxgloss_algorithm::types::AlgorithmHint {
                    function: "FUN_18003ab00".into(),
                    algorithm: "crc".into(),
                    category: calxgloss_algorithm::types::AlgorithmCategory::Checksum,
                    method: calxgloss_algorithm::types::DetectionMethod::StringHint,
                    confidence: calxgloss_algorithm::types::Confidence::new(30),
                    evidence: "crc_table".into(),
                },
            ],
        );

        let found = extract_algorithm_hints(Some(dir.path()), "eqmain.dll", "FUN_18003ab00");

        let algorithms: Vec<&str> = found.iter().map(|a| a.algorithm.as_str()).collect();
        assert_eq!(algorithms, vec!["comparison_sort", "crc"]);
        assert_eq!(found[1].category, "checksum");
        assert_eq!(found[1].method, "string_hint");
    }

    fn allocation_hint(function: &str, suggestion: &str) -> calxgloss_memory::types::MemoryHint {
        calxgloss_memory::types::MemoryHint {
            function: function.to_string(),
            allocation_type: calxgloss_memory::types::AllocationType::Malloc,
            suggestion: suggestion.to_string(),
            confidence: calxgloss_memory::types::Confidence::new(70),
            evidence: "pvVar1 = malloc(0x20); free(pvVar1);".into(),
        }
    }

    fn handle_record(function: &str) -> calxgloss_memory::types::HandleLifecycle {
        calxgloss_memory::types::HandleLifecycle {
            function: function.to_string(),
            handle_type: calxgloss_memory::types::HandleType::KernelObject,
            opener: "CreateFileW".into(),
            closer: "CloseHandle".into(),
            suggestion: "RAII guard struct with Drop impl".into(),
            confidence: calxgloss_memory::types::Confidence::new(70),
            evidence: "hFile = CreateFileW(...); CloseHandle(hFile);".into(),
        }
    }

    fn persist_findings(dir: &TempDir, findings: Vec<calxgloss_memory::types::MemoryFinding>) {
        let mut result =
            calxgloss_memory::types::MemoryResult::new(ScanMetadata::new("eqmain.dll"));
        result.findings = findings;
        calxgloss_memory::persist::MemoryPersistor::new(dir.path())
            .save(&result)
            .expect("the memory result should be saved");
    }

    #[test]
    fn no_workspace_configured_yields_no_memory_findings() {
        assert!(extract_memory_hints(None, "eqmain.dll", "FUN_18003ab00").is_empty());
    }

    #[test]
    fn a_missing_cache_yields_no_memory_findings() {
        let dir = TempDir::new().expect("temp dir should be created");
        assert!(
            extract_memory_hints(Some(dir.path()), "eqmain.dll", "FUN_18003ab00").is_empty(),
            "a scan that has not run yet just means no memory context"
        );
    }

    #[test]
    fn a_corrupt_cache_degrades_to_no_memory_findings() {
        let dir = TempDir::new().expect("temp dir should be created");
        let path = dir
            .path()
            .join("re")
            .join("analysis")
            .join("memory")
            .join("eqmain.dll.json");
        std::fs::create_dir_all(
            path.parent()
                .expect("the document path should have a parent"),
        )
        .expect("the cache directory should be creatable");
        std::fs::write(&path, "{ not json").expect("the corrupt document should be writable");

        assert!(extract_memory_hints(Some(dir.path()), "eqmain.dll", "FUN_18003ab00").is_empty());
    }

    #[test]
    fn findings_of_other_functions_are_dropped() {
        let dir = TempDir::new().expect("temp dir should be created");
        persist_findings(
            &dir,
            vec![
                calxgloss_memory::types::MemoryFinding::Allocation(allocation_hint(
                    "FUN_18003ab00",
                    "Box<T>",
                )),
                calxgloss_memory::types::MemoryFinding::Allocation(allocation_hint(
                    "FUN_zzz", "Box<T>",
                )),
            ],
        );

        let found = extract_memory_hints(Some(dir.path()), "eqmain.dll", "FUN_18003ab00");

        assert_eq!(found.len(), 1, "only the target function's finding");
        assert_eq!(found[0].function, "FUN_18003ab00");
        assert_eq!(found[0].kind, "allocation");
        assert_eq!(found[0].suggestion, "Box<T>");
        assert_eq!(found[0].confidence, 70);
        assert_eq!(found[0].evidence, "pvVar1 = malloc(0x20); free(pvVar1);");
    }

    #[test]
    fn every_finding_of_the_function_lands_in_the_prompt() {
        let dir = TempDir::new().expect("temp dir should be created");
        persist_findings(
            &dir,
            vec![
                calxgloss_memory::types::MemoryFinding::Allocation(allocation_hint(
                    "FUN_18003ab00",
                    "stack allocation",
                )),
                calxgloss_memory::types::MemoryFinding::Handle(handle_record("FUN_18003ab00")),
                calxgloss_memory::types::MemoryFinding::Allocation(allocation_hint(
                    "FUN_zzz", "Box<T>",
                )),
            ],
        );

        let found = extract_memory_hints(Some(dir.path()), "eqmain.dll", "FUN_18003ab00");

        let kinds: Vec<&str> = found.iter().map(|f| f.kind.as_str()).collect();
        assert_eq!(kinds, vec!["allocation", "handle"]);
        assert_eq!(found[0].suggestion, "stack allocation");
        assert_eq!(found[1].suggestion, "RAII guard struct with Drop impl");
    }

    // ---- concurrency hints ----

    fn mutex_hint(function: &str, suggestion: &str) -> calxgloss_sync::types::ConcurrencyHint {
        calxgloss_sync::types::ConcurrencyHint {
            function: function.to_string(),
            sync_type: calxgloss_sync::types::SyncType::StdMutex,
            acquire: "EnterCriticalSection".into(),
            release: "LeaveCriticalSection".into(),
            suggestion: suggestion.to_string(),
            confidence: calxgloss_sync::types::Confidence::new(70),
            evidence: "EnterCriticalSection(&local_20); LeaveCriticalSection(&local_20);".into(),
        }
    }

    fn atomic_record(function: &str) -> calxgloss_sync::types::AtomicOperation {
        calxgloss_sync::types::AtomicOperation {
            function: function.to_string(),
            operation: "InterlockedIncrement".into(),
            suggestion: "std::sync::atomic::AtomicU32".into(),
            confidence: calxgloss_sync::types::Confidence::new(70),
            evidence: "uVar1 = InterlockedIncrement(&local_28);".into(),
        }
    }

    fn thread_record(function: &str) -> calxgloss_sync::types::ThreadSpawn {
        calxgloss_sync::types::ThreadSpawn {
            function: function.to_string(),
            spawn: "CreateThread".into(),
            join: Some("WaitForSingleObject".into()),
            suggestion: "std::thread::spawn".into(),
            confidence: calxgloss_sync::types::Confidence::new(70),
            evidence: "hThread = CreateThread(...); WaitForSingleObject(hThread, ...);".into(),
        }
    }

    fn persist_sync_findings(dir: &TempDir, findings: Vec<calxgloss_sync::types::SyncFinding>) {
        let mut result = calxgloss_sync::types::SyncResult::new(ScanMetadata::new("eqmain.dll"));
        result.findings = findings;
        calxgloss_sync::persist::SyncPersistor::new(dir.path())
            .save(&result)
            .expect("the concurrency result should be saved");
    }

    #[test]
    fn no_workspace_configured_yields_no_concurrency_findings() {
        assert!(
            extract_concurrency_hints(None, "eqmain.dll", "FUN_18003ab00").is_empty(),
            "no workspace means no concurrency context"
        );
    }

    #[test]
    fn a_missing_cache_yields_no_concurrency_findings() {
        let dir = TempDir::new().expect("temp dir should be created");
        assert!(
            extract_concurrency_hints(Some(dir.path()), "eqmain.dll", "FUN_18003ab00").is_empty(),
            "a scan that has not run yet just means no concurrency context"
        );
    }

    #[test]
    fn a_corrupt_cache_degrades_to_no_concurrency_findings() {
        let dir = TempDir::new().expect("temp dir should be created");
        let path = dir
            .path()
            .join("re")
            .join("analysis")
            .join("sync")
            .join("eqmain.dll.json");
        std::fs::create_dir_all(
            path.parent()
                .expect("the document path should have a parent"),
        )
        .expect("the cache directory should be creatable");
        std::fs::write(&path, "{ not json").expect("the corrupt document should be writable");

        assert!(
            extract_concurrency_hints(Some(dir.path()), "eqmain.dll", "FUN_18003ab00").is_empty()
        );
    }

    #[test]
    fn concurrency_findings_of_other_functions_are_dropped() {
        let dir = TempDir::new().expect("temp dir should be created");
        persist_sync_findings(
            &dir,
            vec![
                calxgloss_sync::types::SyncFinding::Mutex(mutex_hint(
                    "FUN_18003ab00",
                    "std::sync::Mutex<T>",
                )),
                calxgloss_sync::types::SyncFinding::Mutex(mutex_hint(
                    "FUN_zzz",
                    "std::sync::Mutex<T>",
                )),
            ],
        );

        let found = extract_concurrency_hints(Some(dir.path()), "eqmain.dll", "FUN_18003ab00");

        assert_eq!(found.len(), 1, "only the target function's finding");
        assert_eq!(found[0].function, "FUN_18003ab00");
        assert_eq!(found[0].kind, "mutex");
        assert_eq!(found[0].suggestion, "std::sync::Mutex<T>");
        assert_eq!(found[0].confidence, 70);
        assert_eq!(
            found[0].evidence,
            "EnterCriticalSection(&local_20); LeaveCriticalSection(&local_20);"
        );
    }

    #[test]
    fn every_concurrency_finding_of_the_function_lands_in_the_prompt() {
        let dir = TempDir::new().expect("temp dir should be created");
        persist_sync_findings(
            &dir,
            vec![
                calxgloss_sync::types::SyncFinding::Mutex(mutex_hint(
                    "FUN_18003ab00",
                    "std::sync::Mutex<T>",
                )),
                calxgloss_sync::types::SyncFinding::Atomic(atomic_record("FUN_18003ab00")),
                calxgloss_sync::types::SyncFinding::Thread(thread_record("FUN_18003ab00")),
                calxgloss_sync::types::SyncFinding::Atomic(atomic_record("FUN_zzz")),
            ],
        );

        let found = extract_concurrency_hints(Some(dir.path()), "eqmain.dll", "FUN_18003ab00");

        let kinds: Vec<&str> = found.iter().map(|f| f.kind.as_str()).collect();
        assert_eq!(kinds, vec!["mutex", "atomic", "thread"]);
        assert_eq!(found[0].suggestion, "std::sync::Mutex<T>");
        assert_eq!(found[1].suggestion, "std::sync::atomic::AtomicU32");
        assert_eq!(found[2].suggestion, "std::thread::spawn");
    }

    fn api_usage(
        function: &str,
        api: &str,
        library: &str,
        rust_crate: &str,
        direct: bool,
    ) -> calxgloss_apidetect::types::ApiFinding {
        calxgloss_apidetect::types::ApiFinding::ApiUsage(calxgloss_apidetect::types::ApiUsage {
            function: function.to_string(),
            api: api.to_string(),
            library: library.to_string(),
            rust_crate: rust_crate.to_string(),
            direct,
            confidence: calxgloss_apidetect::types::Confidence::new(if direct { 80 } else { 60 }),
            evidence: format!("{function} → {api}"),
        })
    }

    fn persist_api_findings(dir: &TempDir, findings: Vec<calxgloss_apidetect::types::ApiFinding>) {
        let mut result =
            calxgloss_apidetect::types::ApiDetectionResult::new(ScanMetadata::new("eqmain.dll"));
        result.findings = findings;
        calxgloss_apidetect::persist::ApiPersistor::new(dir.path())
            .save(&result)
            .expect("the API result should be saved");
    }

    #[test]
    fn no_workspace_configured_yields_no_api_findings() {
        assert!(
            extract_api_hints(None, "eqmain.dll", "FUN_18003ab00").is_empty(),
            "no workspace means no library/API context"
        );
    }

    #[test]
    fn a_missing_cache_yields_no_api_findings() {
        let dir = TempDir::new().expect("temp dir should be created");
        assert!(
            extract_api_hints(Some(dir.path()), "eqmain.dll", "FUN_18003ab00").is_empty(),
            "a scan that has not run yet just means no library/API context"
        );
    }

    #[test]
    fn a_corrupt_cache_degrades_to_no_api_findings() {
        let dir = TempDir::new().expect("temp dir should be created");
        let path = dir
            .path()
            .join("re")
            .join("analysis")
            .join("apidetect")
            .join("eqmain.dll.json");
        std::fs::create_dir_all(
            path.parent()
                .expect("the document path should have a parent"),
        )
        .expect("the cache directory should be creatable");
        std::fs::write(&path, "{ not json").expect("the corrupt document should be writable");

        assert!(extract_api_hints(Some(dir.path()), "eqmain.dll", "FUN_18003ab00").is_empty());
    }

    #[test]
    fn api_findings_of_other_functions_and_import_entries_are_dropped() {
        let dir = TempDir::new().expect("temp dir should be created");
        persist_api_findings(
            &dir,
            vec![
                calxgloss_apidetect::types::ApiFinding::Import(
                    calxgloss_apidetect::types::ApiSignature {
                        api: "inflate".to_string(),
                        library: Some("zlib".to_string()),
                        rust_crate: Some("flate2".to_string()),
                        confidence: calxgloss_apidetect::types::Confidence::new(90),
                    },
                ),
                api_usage("FUN_18003ab00", "inflate", "zlib", "flate2", true),
                api_usage("FUN_zzz", "inflate", "zlib", "flate2", true),
            ],
        );

        let found = extract_api_hints(Some(dir.path()), "eqmain.dll", "FUN_18003ab00");

        assert_eq!(found.len(), 1, "only the target function's usage");
        assert_eq!(found[0].function, "FUN_18003ab00");
        assert_eq!(found[0].api, "inflate");
        assert_eq!(found[0].library, "zlib");
        assert_eq!(found[0].suggestion, "flate2");
        assert_eq!(found[0].kind, "direct");
        assert_eq!(found[0].confidence, 80);
        assert_eq!(found[0].evidence, "FUN_18003ab00 → inflate");
    }

    #[test]
    fn direct_and_transitive_usages_of_the_function_land_in_the_prompt() {
        let dir = TempDir::new().expect("temp dir should be created");
        persist_api_findings(
            &dir,
            vec![
                api_usage("FUN_18003ab00", "inflate", "zlib", "flate2", true),
                api_usage(
                    "FUN_18003ab00",
                    "CreateFileA",
                    "Win32",
                    "windows / std::fs",
                    false,
                ),
                api_usage("FUN_zzz", "malloc", "POSIX", "std::fs / std::io", true),
            ],
        );

        let found = extract_api_hints(Some(dir.path()), "eqmain.dll", "FUN_18003ab00");

        let kinds: Vec<&str> = found.iter().map(|f| f.kind.as_str()).collect();
        assert_eq!(kinds, vec!["direct", "transitive"]);
        assert_eq!(found[0].suggestion, "flate2");
        assert_eq!(found[1].suggestion, "windows / std::fs");
        assert_eq!(found[1].confidence, 60);
    }

    fn fp_array_hint(function: &str) -> calxgloss_callback::types::CallbackFinding {
        calxgloss_callback::types::CallbackFinding::FpArray(
            calxgloss_callback::types::FpArrayCall {
                function: function.to_string(),
                table: "handlers".into(),
                suggestion: "Vec<Box<dyn Fn(i32)>>".into(),
                confidence: calxgloss_callback::types::Confidence::new(70),
                evidence: "handlers[uVar1](param_1);".into(),
            },
        )
    }

    fn registration_hint(function: &str) -> calxgloss_callback::types::CallbackFinding {
        calxgloss_callback::types::CallbackFinding::Registration(
            calxgloss_callback::types::CallbackRegistration {
                function: function.to_string(),
                registration: "register_callback".into(),
                callback: "my_handler".into(),
                suggestion: "Box<dyn Fn(i32)>".into(),
                confidence: calxgloss_callback::types::Confidence::new(70),
                evidence: "register_callback(my_handler);".into(),
            },
        )
    }

    fn jump_table_hint(function: &str) -> calxgloss_callback::types::CallbackFinding {
        calxgloss_callback::types::CallbackFinding::JumpTable(
            calxgloss_callback::types::JumpTable {
                function: function.to_string(),
                table: "DAT_1400a1b60".into(),
                index: "uVar2".into(),
                target_count: Some(5),
                suggestion: "[fn(...); 5]".into(),
                confidence: calxgloss_callback::types::Confidence::new(70),
                evidence: "if (uVar2 < 5) { (*DAT_1400a1b60[uVar2])(); }".into(),
            },
        )
    }

    fn persist_callback_findings(
        dir: &TempDir,
        findings: Vec<calxgloss_callback::types::CallbackFinding>,
    ) {
        let mut result =
            calxgloss_callback::types::CallbackResult::new(ScanMetadata::new("eqmain.dll"));
        result.findings = findings;
        calxgloss_callback::persist::CallbackPersistor::new(dir.path())
            .save(&result)
            .expect("the callback result should be saved");
    }

    #[test]
    fn no_workspace_configured_yields_no_callback_findings() {
        assert!(
            extract_callback_hints(None, "eqmain.dll", "FUN_18003ab00").is_empty(),
            "no workspace means no callback context"
        );
    }

    #[test]
    fn a_missing_cache_yields_no_callback_findings() {
        let dir = TempDir::new().expect("temp dir should be created");
        assert!(
            extract_callback_hints(Some(dir.path()), "eqmain.dll", "FUN_18003ab00").is_empty(),
            "a scan that has not run yet just means no callback context"
        );
    }

    #[test]
    fn a_corrupt_cache_degrades_to_no_callback_findings() {
        let dir = TempDir::new().expect("temp dir should be created");
        let path = dir
            .path()
            .join("re")
            .join("analysis")
            .join("callback")
            .join("eqmain.dll.json");
        std::fs::create_dir_all(
            path.parent()
                .expect("the document path should have a parent"),
        )
        .expect("the cache directory should be creatable");
        std::fs::write(&path, "{ not json").expect("the corrupt document should be writable");

        assert!(extract_callback_hints(Some(dir.path()), "eqmain.dll", "FUN_18003ab00").is_empty());
    }

    #[test]
    fn callback_findings_of_other_functions_are_dropped() {
        let dir = TempDir::new().expect("temp dir should be created");
        persist_callback_findings(
            &dir,
            vec![fp_array_hint("FUN_18003ab00"), fp_array_hint("FUN_zzz")],
        );

        let found = extract_callback_hints(Some(dir.path()), "eqmain.dll", "FUN_18003ab00");

        assert_eq!(found.len(), 1, "only the target function's finding");
        assert_eq!(found[0].function, "FUN_18003ab00");
        assert_eq!(found[0].kind, "fp_array");
        assert_eq!(found[0].suggestion, "Vec<Box<dyn Fn(i32)>>");
        assert_eq!(found[0].confidence, 70);
        assert_eq!(found[0].evidence, "handlers[uVar1](param_1);");
    }

    #[test]
    fn every_callback_finding_of_the_function_lands_in_the_prompt() {
        let dir = TempDir::new().expect("temp dir should be created");
        persist_callback_findings(
            &dir,
            vec![
                fp_array_hint("FUN_18003ab00"),
                registration_hint("FUN_18003ab00"),
                jump_table_hint("FUN_18003ab00"),
                registration_hint("FUN_zzz"),
            ],
        );

        let found = extract_callback_hints(Some(dir.path()), "eqmain.dll", "FUN_18003ab00");

        let kinds: Vec<&str> = found.iter().map(|f| f.kind.as_str()).collect();
        assert_eq!(kinds, vec!["fp_array", "registration", "jump_table"]);
        assert_eq!(found[0].suggestion, "Vec<Box<dyn Fn(i32)>>");
        assert_eq!(found[1].suggestion, "Box<dyn Fn(i32)>");
        assert_eq!(found[2].suggestion, "[fn(...); 5]");
    }

    // ---- constant hints ----

    fn bitflag_record(function: &str) -> calxgloss_consts::types::BitflagGroup {
        calxgloss_consts::types::BitflagGroup {
            function: function.to_string(),
            bits: vec![8, 10],
            mask: 0x500,
            bit_width: 11,
            suggestion: "bitflags! struct Flags: u16 { /* bits: 0x100, 0x400 */ }".into(),
            confidence: calxgloss_consts::types::Confidence::new(70),
            evidence: "if ((uVar1 & 0x400) != 0) { uVar1 |= 0x100; }".into(),
        }
    }

    fn enum_record(function: &str) -> calxgloss_consts::types::EnumCandidate {
        calxgloss_consts::types::EnumCandidate {
            function: function.to_string(),
            values: vec![0, 1, 2, 3],
            count: 4,
            suggestion: "enum State { /* variants for 0..=3 */ }".into(),
            confidence: calxgloss_consts::types::Confidence::new(70),
            evidence: "switch(uVar2) { case 0: case 1: case 2: case 3: }".into(),
        }
    }

    fn named_record(functions: &[&str]) -> calxgloss_consts::types::NamedConstant {
        calxgloss_consts::types::NamedConstant {
            value: 0x400,
            count: 5,
            functions: functions.iter().map(|f| f.to_string()).collect(),
            suggestion: "const VALUE_0x400: u32 = 0x400;".into(),
            confidence: calxgloss_consts::types::Confidence::new(60),
            evidence: "0x400 used 5 times in FUN_18003ab00, FUN_zzz".into(),
        }
    }

    fn persist_const_findings(dir: &TempDir, findings: Vec<calxgloss_consts::types::ConstFinding>) {
        let mut result = calxgloss_consts::types::ConstResult::new(ScanMetadata::new("eqmain.dll"));
        result.findings = findings;
        calxgloss_consts::persist::ConstPersistor::new(dir.path())
            .save(&result)
            .expect("the constant result should be saved");
    }

    #[test]
    fn no_workspace_configured_yields_no_constant_findings() {
        assert!(
            extract_constant_hints(None, "eqmain.dll", "FUN_18003ab00").is_empty(),
            "no workspace means no constant context"
        );
    }

    #[test]
    fn a_missing_cache_yields_no_constant_findings() {
        let dir = TempDir::new().expect("temp dir should be created");
        assert!(
            extract_constant_hints(Some(dir.path()), "eqmain.dll", "FUN_18003ab00").is_empty(),
            "a scan that has not run yet just means no constant context"
        );
    }

    #[test]
    fn a_corrupt_cache_degrades_to_no_constant_findings() {
        let dir = TempDir::new().expect("temp dir should be created");
        let path = dir
            .path()
            .join("re")
            .join("analysis")
            .join("consts")
            .join("eqmain.dll.json");
        std::fs::create_dir_all(
            path.parent()
                .expect("the document path should have a parent"),
        )
        .expect("the cache directory should be creatable");
        std::fs::write(&path, "{ not json").expect("the corrupt document should be writable");

        assert!(extract_constant_hints(Some(dir.path()), "eqmain.dll", "FUN_18003ab00").is_empty());
    }

    #[test]
    fn constant_findings_of_other_functions_are_dropped() {
        let dir = TempDir::new().expect("temp dir should be created");
        persist_const_findings(
            &dir,
            vec![
                calxgloss_consts::types::ConstFinding::BitflagGroup(bitflag_record(
                    "FUN_18003ab00",
                )),
                calxgloss_consts::types::ConstFinding::BitflagGroup(bitflag_record("FUN_zzz")),
            ],
        );

        let found = extract_constant_hints(Some(dir.path()), "eqmain.dll", "FUN_18003ab00");

        assert_eq!(found.len(), 1, "only the target function's finding");
        assert_eq!(found[0].function, "FUN_18003ab00");
        assert_eq!(found[0].kind, "bitflag_group");
        assert_eq!(
            found[0].suggestion,
            "bitflags! struct Flags: u16 { /* bits: 0x100, 0x400 */ }"
        );
        assert_eq!(found[0].confidence, 70);
        assert_eq!(
            found[0].evidence,
            "if ((uVar1 & 0x400) != 0) { uVar1 |= 0x100; }"
        );
    }

    #[test]
    fn every_constant_finding_of_the_function_lands_in_the_prompt() {
        let dir = TempDir::new().expect("temp dir should be created");
        persist_const_findings(
            &dir,
            vec![
                calxgloss_consts::types::ConstFinding::BitflagGroup(bitflag_record(
                    "FUN_18003ab00",
                )),
                calxgloss_consts::types::ConstFinding::EnumCandidate(enum_record("FUN_18003ab00")),
                calxgloss_consts::types::ConstFinding::EnumCandidate(enum_record("FUN_zzz")),
                calxgloss_consts::types::ConstFinding::NamedConstant(named_record(&[
                    "FUN_18003ab00",
                    "FUN_zzz",
                ])),
            ],
        );

        let found = extract_constant_hints(Some(dir.path()), "eqmain.dll", "FUN_18003ab00");

        let kinds: Vec<&str> = found.iter().map(|f| f.kind.as_str()).collect();
        assert_eq!(
            kinds,
            vec!["bitflag_group", "enum_candidate", "named_constant"]
        );
        assert_eq!(
            found[0].suggestion,
            "bitflags! struct Flags: u16 { /* bits: 0x100, 0x400 */ }"
        );
        assert_eq!(
            found[1].suggestion,
            "enum State { /* variants for 0..=3 */ }"
        );
        assert_eq!(found[2].suggestion, "const VALUE_0x400: u32 = 0x400;");
        assert_eq!(found[2].confidence, 60);
    }

    // ---- serialization hint extraction --------------------------------

    fn swap_record(function: &str) -> calxgloss_serialize::types::SerializeFinding {
        calxgloss_serialize::types::SerializeFinding::ByteSwap(
            calxgloss_serialize::types::ByteSwapOperation {
                function: function.into(),
                operation: "ntohl".into(),
                width: 32,
                suggestion: "byteorder::BE::read_u32".into(),
                confidence: calxgloss_serialize::types::Confidence::new(70),
                evidence: "uVar1 = ntohl(local_18);".into(),
            },
        )
    }

    fn pack_record(function: &str) -> calxgloss_serialize::types::SerializeFinding {
        calxgloss_serialize::types::SerializeFinding::BitPack(
            calxgloss_serialize::types::BitPackRecord {
                function: function.into(),
                pattern: calxgloss_serialize::types::BitPackPattern::ShiftOrPack,
                widths: vec![8, 8, 8, 8],
                suggestion: "bitvec or named-field masking/shifting".into(),
                confidence: calxgloss_serialize::types::Confidence::new(60),
                evidence:
                    "uVar1 = (uVar2 << 0x18) | ((uint)uVar3 << 0x10) | (uVar4 << 8) | (uint)uVar5;"
                        .into(),
            },
        )
    }

    fn magic_record(function: &str) -> calxgloss_serialize::types::SerializeFinding {
        calxgloss_serialize::types::SerializeFinding::Magic(
            calxgloss_serialize::types::MagicFormat {
                function: function.into(),
                magic: 0x8950_4E47,
                format: "PNG".into(),
                suggestion: "png::Decoder".into(),
                confidence: calxgloss_serialize::types::Confidence::new(80),
                evidence: "if (uVar1 == 0x89504e47) {".into(),
            },
        )
    }

    fn persist_serialize_findings(
        dir: &TempDir,
        findings: Vec<calxgloss_serialize::types::SerializeFinding>,
    ) {
        let mut result =
            calxgloss_serialize::types::SerializeResult::new(ScanMetadata::new("eqmain.dll"));
        result.findings = findings;
        calxgloss_serialize::persist::SerializePersistor::new(dir.path())
            .save(&result)
            .expect("the serialization result should be saved");
    }

    #[test]
    fn no_workspace_configured_yields_no_serialization_findings() {
        assert!(
            extract_serialization_hints(None, "eqmain.dll", "FUN_18003ab00").is_empty(),
            "no workspace means no serialization context"
        );
    }

    #[test]
    fn a_missing_cache_yields_no_serialization_findings() {
        let dir = TempDir::new().expect("temp dir should be created");
        assert!(
            extract_serialization_hints(Some(dir.path()), "eqmain.dll", "FUN_18003ab00").is_empty(),
            "a scan that has not run yet just means no serialization context"
        );
    }

    #[test]
    fn a_corrupt_cache_degrades_to_no_serialization_findings() {
        let dir = TempDir::new().expect("temp dir should be created");
        let path = dir
            .path()
            .join("re")
            .join("analysis")
            .join("serialize")
            .join("eqmain.dll.json");
        std::fs::create_dir_all(
            path.parent()
                .expect("the document path should have a parent"),
        )
        .expect("the cache directory should be creatable");
        std::fs::write(&path, "{ not json").expect("the corrupt document should be writable");

        assert!(
            extract_serialization_hints(Some(dir.path()), "eqmain.dll", "FUN_18003ab00").is_empty()
        );
    }

    #[test]
    fn serialization_findings_of_other_functions_are_dropped() {
        let dir = TempDir::new().expect("temp dir should be created");
        persist_serialize_findings(
            &dir,
            vec![swap_record("FUN_18003ab00"), swap_record("FUN_zzz")],
        );

        let found = extract_serialization_hints(Some(dir.path()), "eqmain.dll", "FUN_18003ab00");

        assert_eq!(found.len(), 1, "only the target function's finding");
        assert_eq!(found[0].function, "FUN_18003ab00");
        assert_eq!(found[0].kind, "byteswap");
        assert_eq!(found[0].suggestion, "byteorder::BE::read_u32");
        assert_eq!(found[0].confidence, 70);
        assert_eq!(found[0].evidence, "uVar1 = ntohl(local_18);");
    }

    #[test]
    fn every_serialization_finding_of_the_function_lands_in_the_prompt() {
        let dir = TempDir::new().expect("temp dir should be created");
        persist_serialize_findings(
            &dir,
            vec![
                swap_record("FUN_18003ab00"),
                pack_record("FUN_18003ab00"),
                magic_record("FUN_18003ab00"),
                swap_record("FUN_zzz"),
            ],
        );

        let found = extract_serialization_hints(Some(dir.path()), "eqmain.dll", "FUN_18003ab00");

        let kinds: Vec<&str> = found.iter().map(|f| f.kind.as_str()).collect();
        assert_eq!(kinds, vec!["byteswap", "bitpack", "magic"]);
        assert_eq!(found[0].suggestion, "byteorder::BE::read_u32");
        assert_eq!(
            found[1].suggestion,
            "bitvec or named-field masking/shifting"
        );
        assert_eq!(found[2].suggestion, "png::Decoder");
        assert_eq!(found[2].confidence, 80);
    }

    // ---- control-flow hint extraction ---------------------------------

    fn switch_hint(function: &str) -> calxgloss_controlflow::types::ControlFlowFinding {
        calxgloss_controlflow::types::ControlFlowFinding::Switch(
            calxgloss_controlflow::types::SwitchChain {
                function: function.into(),
                variable: "local_4".into(),
                cases: vec!["1".into(), "2".into(), "0x10".into()],
                has_default: true,
                suggestion: "match local_4 { /* 3 arms */ } + _".into(),
                confidence: calxgloss_controlflow::types::Confidence::new(70),
                evidence: "if (local_4 == 1) ... else if (local_4 == 0x10) + default".into(),
            },
        )
    }

    fn recursion_hint(function: &str) -> calxgloss_controlflow::types::ControlFlowFinding {
        calxgloss_controlflow::types::ControlFlowFinding::Recursion(
            calxgloss_controlflow::types::SelfRecursion {
                function: function.into(),
                is_tail_call: true,
                self_calls: 1,
                suggestion: "replace with loop { ... } (tail call)".into(),
                confidence: calxgloss_controlflow::types::Confidence::new(80),
                evidence: "FUN_18003ab00() calls itself 1x (tail call)".into(),
            },
        )
    }

    fn state_machine_hint(function: &str) -> calxgloss_controlflow::types::ControlFlowFinding {
        calxgloss_controlflow::types::ControlFlowFinding::StateMachine(
            calxgloss_controlflow::types::StateMachine {
                function: function.into(),
                state_var: "state".into(),
                states: vec![
                    "STATE_IDLE".into(),
                    "STATE_RUNNING".into(),
                    "STATE_DONE".into(),
                ],
                transitions: vec!["STATE_DONE".into()],
                idle_state: Some("STATE_IDLE".into()),
                suggestion: "enum State + match state { /* 3 states */ }".into(),
                confidence: calxgloss_controlflow::types::Confidence::new(70),
                evidence: "state variable state with 3 states idle: STATE_IDLE".into(),
            },
        )
    }

    fn persist_controlflow_findings(
        dir: &TempDir,
        findings: Vec<calxgloss_controlflow::types::ControlFlowFinding>,
    ) {
        let mut result =
            calxgloss_controlflow::types::ControlFlowResult::new(ScanMetadata::new("eqmain.dll"));
        result.findings = findings;
        calxgloss_controlflow::persist::ControlFlowPersistor::new(dir.path())
            .save(&result)
            .expect("the control-flow result should be saved");
    }

    #[test]
    fn no_workspace_configured_yields_no_control_flow_findings() {
        assert!(
            extract_control_flow_hints(None, "eqmain.dll", "FUN_18003ab00").is_empty(),
            "no workspace means no control-flow context"
        );
    }

    #[test]
    fn a_missing_cache_yields_no_control_flow_findings() {
        let dir = TempDir::new().expect("temp dir should be created");
        assert!(
            extract_control_flow_hints(Some(dir.path()), "eqmain.dll", "FUN_18003ab00").is_empty(),
            "a scan that has not run yet just means no control-flow context"
        );
    }

    #[test]
    fn a_corrupt_cache_degrades_to_no_control_flow_findings() {
        let dir = TempDir::new().expect("temp dir should be created");
        let path = dir
            .path()
            .join("re")
            .join("analysis")
            .join("controlflow")
            .join("eqmain.dll.json");
        std::fs::create_dir_all(
            path.parent()
                .expect("the document path should have a parent"),
        )
        .expect("the cache directory should be creatable");
        std::fs::write(&path, "{ not json").expect("the corrupt document should be writable");

        assert!(
            extract_control_flow_hints(Some(dir.path()), "eqmain.dll", "FUN_18003ab00").is_empty()
        );
    }

    #[test]
    fn control_flow_findings_of_other_functions_are_dropped() {
        let dir = TempDir::new().expect("temp dir should be created");
        persist_controlflow_findings(
            &dir,
            vec![switch_hint("FUN_18003ab00"), switch_hint("FUN_zzz")],
        );

        let found = extract_control_flow_hints(Some(dir.path()), "eqmain.dll", "FUN_18003ab00");

        assert_eq!(found.len(), 1, "only the target function's finding");
        assert_eq!(found[0].function, "FUN_18003ab00");
        assert_eq!(found[0].kind, "switch");
        assert_eq!(found[0].suggestion, "match local_4 { /* 3 arms */ } + _");
        assert_eq!(found[0].confidence, 70);
        assert_eq!(
            found[0].evidence,
            "if (local_4 == 1) ... else if (local_4 == 0x10) + default"
        );
    }

    #[test]
    fn every_control_flow_finding_of_the_function_lands_in_the_prompt() {
        let dir = TempDir::new().expect("temp dir should be created");
        persist_controlflow_findings(
            &dir,
            vec![
                switch_hint("FUN_18003ab00"),
                recursion_hint("FUN_18003ab00"),
                state_machine_hint("FUN_18003ab00"),
                switch_hint("FUN_zzz"),
            ],
        );

        let found = extract_control_flow_hints(Some(dir.path()), "eqmain.dll", "FUN_18003ab00");

        let kinds: Vec<&str> = found.iter().map(|f| f.kind.as_str()).collect();
        assert_eq!(kinds, vec!["switch", "recursion", "state_machine"]);
        assert_eq!(found[0].suggestion, "match local_4 { /* 3 arms */ } + _");
        assert_eq!(found[1].suggestion, "replace with loop { ... } (tail call)");
        assert_eq!(
            found[2].suggestion,
            "enum State + match state { /* 3 states */ }"
        );
    }
}
