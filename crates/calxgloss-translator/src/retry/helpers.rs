//! Context extraction helpers used by prompt builders.

use crate::Translation;
use calxgloss_callgraph::FunctionContext;
use calxgloss_ghidra::GhidraClient;
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
pub async fn extract_call_graph_neighbors(
    ghidra: &GhidraClient,
    call_graph: &[String],
    _target_address: u64,
) -> Vec<CallGraphNeighbor> {
    let mut neighbors = Vec::new();
    for name in call_graph {
        // Search for the neighbor function to get its address
        if let Ok(matches) = ghidra.search_functions(name, Some(5)).await
            && let Some(found) = matches.iter().find(|m| m.name == *name)
        {
            // Try to get the signature from decompilation
            let signature = match ghidra.decompile_function(found.address).await {
                Ok(decompiled) => decompiled.signature,
                Err(_) => String::new(),
            };
            neighbors.push(CallGraphNeighbor {
                name: found.name.clone(),
                address: found.address,
                signature,
                role: "callee".to_string(), // simplified: most are callees
            });
            continue;
        }
        // If not found, just add a stub
        neighbors.push(CallGraphNeighbor {
            name: name.clone(),
            address: 0,
            signature: String::new(),
            role: "unknown".to_string(),
        });
    }
    neighbors
}

/// Extract neighboring function context (full code) from Ghidra.
pub async fn extract_neighboring_context(
    ghidra: &GhidraClient,
    call_graph: &[String],
) -> Vec<NeighborFunction> {
    let mut neighbors = Vec::new();
    // Limit to a few neighbors to avoid context window bloat
    for name in call_graph.iter().take(3) {
        if let Ok(matches) = ghidra.search_functions(name, Some(5)).await
            && let Some(found) = matches.iter().find(|m| m.name == *name)
            && let Ok(report) = ghidra.function_report(found.address).await
        {
            neighbors.push(NeighborFunction {
                name: report.name.clone(),
                dll: String::new(),
                address: report.address,
                disassembly: report.disassembly.trim().to_string(),
                decompiler_output: report.decompiled.body.trim().to_string(),
            });
        }
    }
    neighbors
}

/// Extract data structure information from the persisted type database.
///
/// Reads the per-binary database recovered by the `calxgloss-typesdb`
/// engines from `re/analysis/typesdb/{dll}.json` and keeps the records
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
/// is persisted for `dll` (the scan has not run), or the document is
/// corrupt: missing data structure context degrades the prompt, it never
/// fails it.
pub fn extract_data_structures(
    workspace: Option<&std::path::Path>,
    dll: &str,
    function: &str,
) -> Vec<calxgloss_prompts::StructuredData> {
    let Some(workspace) = workspace else {
        return Vec::new();
    };

    let persistor = calxgloss_typesdb::persist::TypeDatabasePersistor::new(workspace);
    let db = match persistor.load(dll) {
        Ok(db) => db,
        Err(e) => {
            debug!(
                dll,
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
/// engine from `re/analysis/typeinfer/{dll}.json` and keeps the
/// inferences made for the target function — the parameter, local
/// variable, and call-site readings whose evidence lives in
/// `function`'s decompiled body.
///
/// Returns an empty vector when no workspace is configured, no result
/// is persisted for `dll` (the scan has not run), or the document is
/// corrupt: missing type context degrades the prompt, it never fails it.
pub fn extract_type_info(
    workspace: Option<&std::path::Path>,
    dll: &str,
    function: &str,
) -> Vec<calxgloss_prompts::TypeInfo> {
    let Some(workspace) = workspace else {
        return Vec::new();
    };

    let persistor = calxgloss_typeinfer::persist::TypeInferPersistor::new(workspace);
    let result = match persistor.load(dll) {
        Ok(result) => result,
        Err(e) => {
            debug!(
                dll,
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
/// * `ghidra` — Ghidra client for fetching additional context.
/// * `workspace` — Optional workspace path for shim layer and type
///   database extraction.
///
/// # Returns
///
/// A prompt string suitable for sending to the LLM, or an error string
/// if prompt construction fails.
pub async fn build_escalated_prompt(
    translation: &Translation,
    tier: ContextTier,
    ghidra: &GhidraClient,
    workspace: Option<&std::path::Path>,
) -> Result<String, String> {
    let dll = &translation.dll;
    let function = &translation.function;

    match tier {
        ContextTier::Stub => {
            // Tier 0: stub prompt — only function name, signature, call graph
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
            let data = calxgloss_prompts::StubPromptData {
                function_name: function.clone(),
                dll_name: dll.clone(),
                address_hex: format!("{:#x}", translation.function_address.unwrap_or(0)),
                signature: String::new(),
                call_graph_neighbors: neighbors,
            };
            calxgloss_prompts::build_stub_prompt(&data).map_err(|e| e.to_string())
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
                dll_name: dll.clone(),
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
                dll: dll.clone(),
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
                dll: dll.clone(),
                function: function.clone(),
                disassembly: translation.prompt_used.clone(),
                decompiler_output: String::new(),
                windows_apis: call_graph,
                baseline_tests: translation.baseline_tests.clone(),
            };

            let call_graph_neighbors = extract_call_graph_neighbors(
                ghidra,
                &translation.call_graph,
                translation.function_address.unwrap_or(0),
            )
            .await;
            let neighboring_functions =
                extract_neighboring_context(ghidra, &translation.call_graph).await;
            let data_structures = extract_data_structures(workspace, dll, function);

            let data = calxgloss_prompts::ModuleContextPromptData::from_request_with_context(
                &request,
                call_graph_neighbors,
                neighboring_functions,
                data_structures,
                translation.call_graph_context.clone(),
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
                dll: dll.clone(),
                function: function.clone(),
                disassembly: translation.prompt_used.clone(),
                decompiler_output: String::new(),
                windows_apis: call_graph,
                baseline_tests: translation.baseline_tests.clone(),
            };

            let call_graph_neighbors = extract_call_graph_neighbors(
                ghidra,
                &translation.call_graph,
                translation.function_address.unwrap_or(0),
            )
            .await;
            let neighboring_functions =
                extract_neighboring_context(ghidra, &translation.call_graph).await;
            let data_structures = extract_data_structures(workspace, dll, function);

            let shim_layers = extract_shim_layers(workspace, dll);
            let pal_traits = Vec::<PalTraitDef>::new();

            let data = calxgloss_prompts::FullModulePromptData::from_request_with_full_context(
                &request,
                call_graph_neighbors,
                neighboring_functions,
                data_structures,
                shim_layers,
                pal_traits,
                translation.call_graph_context.clone(),
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
}
