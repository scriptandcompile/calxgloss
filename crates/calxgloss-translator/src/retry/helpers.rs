//! Ghidra context extraction helpers used by prompt builders.

use calxgloss_ghidra::GhidraClient;
use calxgloss_prompts::{CallGraphNeighbor, NeighborFunction, PalTraitDef, PalTraitMethod, ShimCode};
use calxgloss_types::{ApiCategory, WindowsApiCall};

/// Extract call graph neighbor details from Ghidra.
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

/// Extract data structure information from Ghidra.
pub async fn extract_data_structures(
    _ghidra: &GhidraClient,
    _address: u64,
) -> Vec<calxgloss_prompts::StructuredData> {
    // GhidraMCP doesn't have a dedicated data-structure endpoint,
    // so we return empty for now. This is a placeholder for future
    // integration with Ghidra's type database.
    Vec::new()
}

/// Extract type information from Ghidra for the given function.
pub async fn extract_type_info(
    _ghidra: &GhidraClient,
    _function_name: &str,
) -> Vec<calxgloss_prompts::TypeInfo> {
    // GhidraMCP doesn't expose type inference directly.
    // This is a placeholder for future integration.
    Vec::new()
}

// ============================================================
// Tier 4 — Shim layer and PAL trait extraction
// ============================================================

/// Extract shim layer code for a given DLL from the workspace.
///
/// Reads the generated shim source from `re/shims/<dll_name>/shim.rs` in
/// the workspace directory. Returns an empty vector when no shim exists
/// or the workspace path is not configured.
pub fn extract_shim_layers(
    workspace: Option<&std::path::Path>,
    dll_name: &str,
) -> Vec<ShimCode> {
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
            mapping_count: 0,             // filled by caller from mappings.json
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
pub fn extract_pal_traits(
    windows_apis: &[WindowsApiCall],
) -> Vec<PalTraitDef> {
    if windows_apis.is_empty() {
        return Vec::new();
    }

    // Collect unique API categories from the function's Windows API calls
    let categories: std::collections::HashSet<&ApiCategory> = windows_apis
        .iter()
        .map(|api| &api.category)
        .collect();

    let mut traits = Vec::new();

    for category in &categories {
        match category {
            ApiCategory::DirectX | ApiCategory::DirectX10 | ApiCategory::DirectX11 |
            ApiCategory::DirectX12 => {
                traits.push(PalTraitDef {
                    trait_name: "GraphicsDevice".to_string(),
                    module: "pal".to_string(),
                    description: "Abstracts DirectX graphics device operations (create, render, present)".to_string(),
                    methods: vec![
                        PalTraitMethod {
                            name: "create_device".to_string(),
                            signature: "fn create_device(width: u32, height: u32) -> Self".to_string(),
                            description: "Create a new graphics device / swap chain".to_string(),
                        },
                        PalTraitMethod {
                            name: "render".to_string(),
                            signature: "fn render(&mut self, encoder: &mut wgpu::CommandEncoder)".to_string(),
                            description: "Execute rendering commands via a wgpu encoder".to_string(),
                        },
                        PalTraitMethod {
                            name: "present".to_string(),
                            signature: "fn present(&mut self)".to_string(),
                            description: "Present the rendered frame to the screen".to_string(),
                        },
                        PalTraitMethod {
                            name: "set_texture".to_string(),
                            signature: "fn set_texture(&mut self, stage: u32, texture: &TextureView)".to_string(),
                            description: "Bind a texture to a pipeline stage (maps DirectX SetTexture)".to_string(),
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
                    description: "Abstracts windowing and GUI operations (Win32 → winit + egui)".to_string(),
                    methods: vec![
                        PalTraitMethod {
                            name: "create_window".to_string(),
                            signature: "fn create_window(title: &str, width: u32, height: u32) -> Self".to_string(),
                            description: "Create a new application window".to_string(),
                        },
                        PalTraitMethod {
                            name: "process_events".to_string(),
                            signature: "fn process_events(&mut self, handler: impl FnMut(Event))".to_string(),
                            description: "Process pending window events and dispatch to handler".to_string(),
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
                    description: "Abstracts core Win32 operations (VirtualAlloc, CreateThread, Sleep, etc.)".to_string(),
                    methods: vec![
                        PalTraitMethod {
                            name: "allocate_memory".to_string(),
                            signature: "fn allocate_memory(size: usize, writable: bool) -> *mut u8".to_string(),
                            description: "Allocate memory (maps VirtualAlloc)".to_string(),
                        },
                        PalTraitMethod {
                            name: "free_memory".to_string(),
                            signature: "fn free_memory(ptr: *mut u8, size: usize)".to_string(),
                            description: "Free previously allocated memory (maps VirtualFree)".to_string(),
                        },
                        PalTraitMethod {
                            name: "sleep".to_string(),
                            signature: "fn sleep(ms: u64)".to_string(),
                            description: "Sleep for the specified milliseconds".to_string(),
                        },
                        PalTraitMethod {
                            name: "get_tick_count".to_string(),
                            signature: "fn get_tick_count() -> u64".to_string(),
                            description: "Get system uptime in milliseconds (maps GetTickCount)".to_string(),
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
