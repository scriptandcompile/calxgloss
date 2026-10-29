//! Context extraction helpers used by prompt builders.

use crate::Translation;
use crate::evidence_projector::project_into;
use calxgloss_callgraph::FunctionContext;
use calxgloss_decomp::ScanSource;
use calxgloss_prompts::{
    CallGraphNeighbor, EvidenceBundle, NeighborFunction, PalTraitDef, PalTraitMethod, ShimCode,
};
use calxgloss_types::{ApiCategory, ContextTier, TranslationRequest, WindowsApiCall};
use tracing::debug;

/// The query family the imported-APIs prompt section asks of the seam
/// (issue #355) — the seam crate's own roster id for its import reads,
/// spelled once here because this is where the escalate fold names it.
pub(crate) const IMPORTS_FAMILY: &str = "imports";

/// The prompt-fed query families of the #357 fan-out: every seam family whose
/// facets feed a bundle-fed or tier prompt section besides `imports` (which
/// has kept its own `api_capability` field since #355), in the order the
/// bundle keeps its capability fields. A family that feeds no prompt surface
/// (`function-inventory`, `exports`, `image-base`, `memory-reads`) stops at
/// the seam report — no bundle field, no include parameter — and the roster
/// here is where that line is drawn.
pub(crate) const FED_CAP_FAMILIES: &[&str] = &[
    "decompilation",
    "disassembly",
    "strings",
    "caller-edges",
    "xrefs",
    "type-database",
    "data-items",
];

/// Fold the held seam capability report into one function's evidence bundle
/// (issue #355, fanned out by issue #357): the `imports` family's entry sits
/// beside (never inside) the document's own `api_coverage` coverage half, and
/// every other prompt-fed family's admission wording sits in its own
/// `*_cap_line` field beside the coverage lines of every section that
/// family's facets feed. An answerable entry and an undeclared family both
/// fold to the empty view the includes render silently — the seam's word only
/// ever lands as the engine's own admission line, never a template-side
/// invention, and one family's wording never reaches another family's field.
pub(crate) fn fold_seam_capability(
    report: &calxgloss_types::CapabilityReport,
    evidence: &mut EvidenceBundle,
) {
    evidence.api_capability = calxgloss_prompts::capability_for(report, IMPORTS_FAMILY);
    for family in FED_CAP_FAMILIES {
        let admission = calxgloss_prompts::capability_for(report, family).admission;
        match *family {
            "decompilation" => evidence.decompilation_cap_line = admission,
            "disassembly" => evidence.disassembly_cap_line = admission,
            "strings" => evidence.strings_cap_line = admission,
            "caller-edges" => evidence.caller_edges_cap_line = admission,
            "xrefs" => evidence.xrefs_cap_line = admission,
            "type-database" => evidence.type_database_cap_line = admission,
            "data-items" => evidence.data_items_cap_line = admission,
            _ => {}
        }
    }
}

/// The query families an escalate-shaped retry re-asks of the seam
/// (issue #356): both re-read postures — the escalate strategy's prompt
/// and the tier-escalated prompt at a tier that re-reads — resolve the
/// neighbors through the seam's function listing and pull their
/// signatures and bodies through its decompile. These are exactly the
/// two families `extract_call_graph_neighbors` and
/// `extract_neighboring_context` ask of the source; when a future arm
/// starts asking the seam for another family's answers, the roster grows
/// here and nowhere else.
pub(crate) const ESCALATE_REASK_FAMILIES: &[&str] = &["function-inventory", "decompilation"];

/// Whether the escalated prompt built at `tier` re-asks the seam (issue
/// #356): the tier walk's context comes from the persisted translation
/// record up through WithTests, while ModuleContext and FullModule pull
/// neighbor lists and bodies through the scan source — the arms of
/// [`build_escalated_prompt`](build_escalated_prompt) that read it.
/// The retry ladder's tier gate branches on this, so a step the walk
/// could take without any re-ask is never pruned.
pub(crate) fn tier_re_asks_seam(tier: calxgloss_types::ContextTier) -> bool {
    matches!(
        tier,
        calxgloss_types::ContextTier::ModuleContext | calxgloss_types::ContextTier::FullModule
    )
}

/// The retry ladder's one consultation (issue #356): which of the
/// families an escalate-shaped retry would re-ask does the held report
/// read as answerably unavailable — declared, and stated by the engine
/// to be unanswerable right now?
///
/// Only a declared `unavailable` blocks: an answerable family never
/// blocks, and a family the report never declared — which reads
/// `unknown` — never blocks either. Unknown must never be read as
/// unavailable, exactly as absence must never be read as complete;
/// P19's two-directional rule governs this axis too. An empty verdict
/// means the ladder chooses exactly as it chose before the seam spoke.
pub(crate) fn unavailable_reask_families<'a>(
    report: &'a calxgloss_types::CapabilityReport,
    families: &[&str],
) -> Vec<&'a calxgloss_types::FamilyCapability> {
    families
        .iter()
        .filter_map(|family| {
            report.families.iter().find(|entry| {
                entry.id == *family
                    && entry.status == calxgloss_types::AvailabilityStatus::Unavailable
            })
        })
        .collect()
}

/// The prune's reviewable reason (issue #356): every blocked family
/// named beside the seam's own admission wording — the shared
/// [`FamilyCapability::admission`](calxgloss_types::FamilyCapability::admission)
/// home the run report's seam line already renders — joined into one
/// line, so the pruned path always says which family went empty and why
/// the engine says it cannot answer it.
pub(crate) fn reask_admission_lines(blocked: &[&calxgloss_types::FamilyCapability]) -> String {
    blocked
        .iter()
        .map(|entry| {
            format!(
                "{} — {}",
                entry.id,
                // An unavailable entry always admits itself; the bare
                // word is the fallback for an entry that gave no reason,
                // exactly what `admission` itself spells.
                entry
                    .admission()
                    .unwrap_or_else(|| "unavailable".to_string())
            )
        })
        .collect::<Vec<_>>()
        .join("; ")
}

/// Collect every synchronous per-analyzer evidence list for one function
/// in a single pass — the bundle the escalate and module-context prompts
/// read (issue #268).
///
/// Each analyzer document is read exactly once. The fourteen documents
/// migrated onto the evidence projector — the twelve single-field
/// engines (issues #312 and #313) and the shared consts and
/// type-inference documents as multi-field rows (issue #314) — arrive
/// by folding the registered [`PROJECTION_ROWS`]: a multi-field row
/// loads its document once and fills every field it feeds from that
/// single pass, so two fields can never disagree about what the
/// workspace holds. Only the libmatch document stays outside the fold —
/// its call-graph correlation consumes the live call graph, not just
/// the function name — and the shim and PAL-trait extractions stay
/// bespoke whole-DLL reads (issue #310). The call-graph lists stay out
/// of the gather: they come from the live scan source or an enriched
/// context, not the persisted analyzer caches, so callers set them on
/// the returned bundle themselves.
pub fn gather_function_evidence(
    workspace: Option<&std::path::Path>,
    binary: &str,
    function: &str,
    call_graph: &[String],
) -> EvidenceBundle {
    gather_function_evidence_residue(workspace, binary, function, call_graph).0
}

/// The per-unit evidence fold, additionally returning its coverage
/// residue: the unknown records derived from every filed document the
/// fold read that admitted a facet `partial` or `unavailable` for this
/// unit, in the fold's deterministic scan order — the libmatch document
/// read first, outside the seam, then the fourteen folded documents in
/// table order and each coverage record's own facet order (issue #369).
/// The batch accumulates these and files the per-binary ledger; nothing
/// here files anything itself, and a document stating no coverage
/// contributes nothing — absence never produces a gap record.
pub fn gather_function_evidence_residue(
    workspace: Option<&std::path::Path>,
    binary: &str,
    function: &str,
    call_graph: &[String],
) -> (EvidenceBundle, Vec<calxgloss_types::UnknownRecord>) {
    // The libmatch document is loaded once here: its findings join the live
    // call-graph neighbor list outside the projection fold — the correlation
    // is not a per-function fold row — and its coverage record, what the
    // libmatch scan admitted about the bodies it read, sits beside those
    // findings (issue #347). A document stating no coverage, or complete
    // coverage, leaves the qualification field default-empty, exactly the
    // pre-P19 render — and derives no residue either (issue #369).
    let libmatch = load_libmatch_result(workspace, binary);
    let libmatch_coverage = libmatch
        .as_ref()
        .and_then(|document| document.metadata.coverage.as_ref())
        .map(calxgloss_prompts::CoverageInfo::from)
        .unwrap_or_default();
    let mut residue = libmatch
        .as_ref()
        .and_then(|document| document.metadata.coverage.as_ref())
        .map(|coverage| {
            crate::coverage_residue::coverage_residue(
                binary,
                crate::coverage_residue::LIBMATCH_DOCUMENT,
                function,
                coverage,
                calxgloss_types::scan::now_unix_secs(),
            )
        })
        .unwrap_or_default();
    let mut evidence = EvidenceBundle {
        libmatch_findings: libmatch_hints_from(libmatch.as_ref(), function, call_graph),
        libmatch_coverage,
        ..Default::default()
    };
    // The fold fills every other persisted-document field, the shared
    // consts and type-inference documents included — each is one
    // multi-field row, so its load happens exactly once per gather.
    // Row order is the prompts' order, and every row degrades on its
    // own without ever failing the gather (see the projector module docs).
    project_into(
        crate::evidence_projector::adapters::PROJECTION_ROWS,
        workspace,
        binary,
        function,
        &mut evidence,
        &mut residue,
    );
    (evidence, residue)
}

/// Extract call graph neighbor details from an enriched context list.
///
/// This is a lightweight alternative to
/// [`extract_call_graph_neighbors`](extract_call_graph_neighbors) that
/// operates on already-enriched [`FunctionContext`] data instead of
/// querying the engine for every neighbor.  When the enriched context
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

/// Load the persisted control-flow document for a binary.
///
/// Reads the per-binary result produced by the `calxgloss-controlflow`
/// engine from `re/analysis/controlflow/{binary}.json`. Returns `None`
/// when no workspace is configured, no result is persisted for `binary`
/// (the scan has not run), or the document is corrupt: consumers degrade
/// to no control-flow context rather than failing.
///
/// Inside `translate`, one load per unit serves both consumers — the
/// prompt's CONTROL FLOW section and the branch inventory that targets
/// baseline test generation — so the LLM's context and its test oracle
/// come from the same findings (issue #261). The retry and escalate
/// prompt paths build their prompts outside `translate` and arrive at
/// the same findings by folding the control-flow projection row in
/// `gather_function_evidence` (issue #313).
pub fn load_control_flow_result(
    workspace: Option<&std::path::Path>,
    binary: &str,
) -> Option<calxgloss_controlflow::types::ControlFlowResult> {
    let workspace = workspace?;

    let persistor = calxgloss_controlflow::persist::ControlFlowPersistor::new(workspace);
    match persistor.load(binary) {
        Ok(result) => Some(result),
        Err(e) => {
            debug!(
                binary,
                error = %e,
                "No usable control-flow result; continuing without control-flow context"
            );
            None
        }
    }
}

/// The prompt-shaped control-flow findings for a function, taken from an
/// already-loaded document — the switch-shaped if-else chains,
/// self-recursion, state-machine patterns, and branch-site records whose
/// code lives in `function`'s decompiled body. `None` (no usable
/// document) yields an empty vector.
pub fn control_flow_hints_from(
    result: Option<&calxgloss_controlflow::types::ControlFlowResult>,
    function: &str,
) -> Vec<calxgloss_prompts::ControlFlowInfo> {
    let Some(result) = result else {
        return Vec::new();
    };
    result
        .for_function(function)
        .map(calxgloss_prompts::ControlFlowInfo::from)
        .collect()
}

/// The branch-inventory records an already-loaded document carries for a
/// function, in document order: the `branch_site` findings, kept in their
/// record shape because baseline test generation consumes them directly
/// (issue #261). Other finding kinds and other functions contribute
/// nothing; `None` (no usable document) yields an empty vector, which
/// leaves generation at exactly today's suite.
pub fn branch_inventory_of(
    result: Option<&calxgloss_controlflow::types::ControlFlowResult>,
    function: &str,
) -> Vec<calxgloss_controlflow::types::BranchSite> {
    let Some(result) = result else {
        return Vec::new();
    };
    result
        .for_function(function)
        .filter_map(|finding| match finding {
            calxgloss_controlflow::types::ControlFlowFinding::BranchSite(record) => {
                Some(record.clone())
            }
            _ => None,
        })
        .collect()
}

/// Load the persisted known-library identification document for a binary.
///
/// Reads the per-binary result produced by the `calxgloss-libmatch`
/// matcher from `re/analysis/libmatch/{binary}.json`. Returns `None`
/// when no workspace is configured, no result is persisted for `binary`
/// (the scan has not run), or the document is corrupt: missing
/// known-library context degrades the prompt, it never fails a
/// translation run — exactly as the call graph tolerates the same
/// document for its Skip marking.
pub fn load_libmatch_result(
    workspace: Option<&std::path::Path>,
    binary: &str,
) -> Option<calxgloss_libmatch::types::LibmatchResult> {
    let workspace = workspace?;

    let persistor = calxgloss_libmatch::persist::LibmatchPersistor::new(workspace);
    match persistor.load(binary) {
        Ok(result) => Some(result),
        Err(e) => {
            debug!(
                binary,
                error = %e,
                "No usable libmatch result; continuing without known-library context"
            );
            None
        }
    }
}

/// The prompt-shaped known-library findings for a function's call-graph
/// neighbors, taken from an already-loaded document: the neighbors whose
/// bodies the matcher identified as statically linked known-library code,
/// each naming the matched symbol, its family, and the confidence behind
/// the match. The join is against the neighbors, never the target — a
/// matched target is stubbed at the call graph, not prompted — so the
/// target's own name is dropped from the neighbor list even when the
/// function calls itself, and neighbors without a finding contribute
/// nothing. `None` (no usable document) yields an empty vector.
///
/// Findings keep document order — scan order, function by function — so
/// two prompts built over one document name the same callees the same
/// way.
pub fn libmatch_hints_from(
    result: Option<&calxgloss_libmatch::types::LibmatchResult>,
    function: &str,
    neighbors: &[String],
) -> Vec<calxgloss_prompts::LibmatchInfo> {
    let Some(result) = result else {
        return Vec::new();
    };
    let joined: std::collections::HashSet<&str> = neighbors
        .iter()
        .map(String::as_str)
        .filter(|name| *name != function)
        .collect();
    result
        .findings
        .iter()
        .filter(|finding| joined.contains(finding.function()))
        .map(calxgloss_prompts::LibmatchInfo::from)
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
/// The engine or the workspace.
///
/// # Arguments
///
/// * `translation` — The initial [`Translation`] produced by the pipeline.
/// * `tier` — The target context tier to build for.
/// * `source` — scan source for fetching additional context (live client
///   or the batch's read cache).
/// * `workspace` — Optional workspace path for shim layer and type
///   database extraction.
/// * `seam_report` — The capability report the pipeline holds for the
///   run (issue #357): the ModuleContext and FullModule arms fold it
///   into the gathered bundle exactly like the escalate strategy does,
///   so a family the seam admits as unavailable renders its one
///   admission line beside the empty context it could not produce. A
///   run without a seam declares nothing, and an empty report folds
///   silence — nothing renders.
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
    seam_report: &calxgloss_types::CapabilityReport,
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

            // One gather over the analyzer caches, plus the two lists
            // that come from the scan source (issue #268).
            let mut evidence =
                gather_function_evidence(workspace, binary, function, &translation.call_graph);
            evidence.call_graph_neighbors = extract_call_graph_neighbors(
                source,
                &translation.call_graph,
                translation.function_address.unwrap_or(0),
            )
            .await;
            evidence.neighboring_functions =
                extract_neighboring_context(source, &translation.call_graph).await;
            evidence.call_graph_context = translation.call_graph_context.clone();
            // Capability fan-out (issue #357): the held report folds into
            // this gather exactly like the escalate strategy's does, so
            // the prompt says which seam queries produced the emptiness.
            fold_seam_capability(seam_report, &mut evidence);

            calxgloss_prompts::build_module_context_prompt(&request, evidence)
                .map_err(|e| e.to_string())
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

            // One gather over the analyzer caches, plus the lists from
            // the scan source and the workspace shim layer (issue #268).
            let mut evidence =
                gather_function_evidence(workspace, binary, function, &translation.call_graph);
            evidence.call_graph_neighbors = extract_call_graph_neighbors(
                source,
                &translation.call_graph,
                translation.function_address.unwrap_or(0),
            )
            .await;
            evidence.neighboring_functions =
                extract_neighboring_context(source, &translation.call_graph).await;
            evidence.call_graph_context = translation.call_graph_context.clone();
            // Capability fan-out (issue #357): same fold as the
            // ModuleContext arm — the held report beside the gather.
            fold_seam_capability(seam_report, &mut evidence);

            let shim_layers = extract_shim_layers(workspace, binary);
            let pal_traits = Vec::<PalTraitDef>::new();

            calxgloss_prompts::build_full_module_prompt(&request, evidence, shim_layers, pal_traits)
                .map_err(|e| e.to_string())
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
        Confidence, Direction, InferenceMethod, InferenceScope, InferredCallType,
        InferredConvention, InferredLocalType, InferredParamDirection, InferredParamType,
        InferredType, TypeInferenceResult,
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
                    stl_kind: None,
                },
                InferredField {
                    name: "label".into(),
                    field_type: FieldType::String,
                    size: Some(8),
                    offset: None,
                    source_value: format!("{name}.label"),
                    source_address: 0x1801_29360,
                    stl_kind: None,
                },
            ],
            confidence: 79.into(),
            referenced_by: referenced_by.iter().map(|f| f.to_string()).collect(),
            linked_vtable: None,
            merged_from: None,
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
                linked_type: None,
                linked_kind: None,
            }],
            members: Vec::new(),
            stl_kind: None,
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
            stl_kind: None,
        }
    }

    fn persist(dir: &TempDir, db: TypeDatabase) {
        TypeDatabasePersistor::new(dir.path()).save(&db).unwrap();
    }

    // The degradation trio and the merged-ordering case for this row are
    // covered by the parametrized projection-row suite below (issue #313);
    // what stays here are the conversion-content checks the row suite does
    // not pin, run through the gather seam like any prompt input.

    #[test]
    fn inferred_candidates_the_function_references_are_converted() {
        let dir = TempDir::new().unwrap();
        let mut db = TypeDatabase::new(ScanMetadata::new("eqmain.dll"));
        db.inferred_structs = vec![
            inferred_struct("Player", &["FUN_18000b620"]),
            inferred_struct("Other", &["FUN_zzz"]),
        ];
        persist(&dir, db);

        let found = gather_function_evidence(Some(dir.path()), "eqmain.dll", "FUN_18000b620", &[])
            .data_structures;

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

        let found = gather_function_evidence(Some(dir.path()), "eqmain.dll", "FUN_18003ab00", &[])
            .data_structures;

        assert_eq!(found.len(), 1, "only the class the function is a method of");
        assert_eq!(found[0].name, "Widget");
        assert_eq!(found[0].size, 16);
        assert_eq!(found[0].fields[0].name, "header");
        assert_eq!(found[0].fields[0].type_, "dword");
        assert_eq!(found[0].fields[0].offset, 0);

        let none = gather_function_evidence(Some(dir.path()), "eqmain.dll", "FUN_zzz", &[])
            .data_structures;
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

        let found = gather_function_evidence(Some(dir.path()), "eqmain.dll", "FUN_18003e750", &[])
            .data_structures;

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

    fn direction_inference(function: &str, index: usize, direction: Direction) -> InferredType {
        InferredType::Direction(InferredParamDirection {
            function: function.to_string(),
            param_index: index,
            param_name: Some(format!("param_{}", index + 1)),
            direction,
            method: InferenceMethod::ParamDirection,
            scope: InferenceScope::Function,
            confidence: Confidence::new(75),
            evidence: "*param_1 = 0;".to_string(),
        })
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
            type_name: None,
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
            category: None,
            features: Vec::new(),
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
            name: None,
            suggestion: "const VALUE_0x400: u32 = 0x400;".into(),
            confidence: calxgloss_consts::types::Confidence::new(60),
            evidence: "0x400 used 5 times in FUN_18003ab00, FUN_zzz".into(),
        }
    }

    fn table_record(functions: &[&str]) -> calxgloss_consts::types::ConstFinding {
        calxgloss_consts::types::ConstFinding::DataTable(calxgloss_consts::types::DataTable {
            symbol: "DAT_1400a1b60".into(),
            address: 0x1400_a1b60,
            element_type: "u16".into(),
            count: 12,
            values: (1..=12).collect(),
            values_truncated: false,
            functions: functions.iter().map(|f| f.to_string()).collect(),
            suggestion: "const DAT_1400A1B60: [u16; 12];".into(),
            confidence: calxgloss_consts::types::Confidence::new(70),
            evidence: "12 bytes decode cleanly as 6 u16 entries at 0x1400a1b60".into(),
        })
    }

    fn persist_const_findings(dir: &TempDir, findings: Vec<calxgloss_consts::types::ConstFinding>) {
        let mut result = calxgloss_consts::types::ConstResult::new(ScanMetadata::new("eqmain.dll"));
        result.findings = findings;
        calxgloss_consts::persist::ConstPersistor::new(dir.path())
            .save(&result)
            .expect("the constant result should be saved");
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

    fn map_record(functions: &[&str]) -> calxgloss_serialize::types::SerializeFinding {
        calxgloss_serialize::types::SerializeFinding::EndiannessMap(
            calxgloss_serialize::types::EndiannessMap {
                function: String::new(),
                entries: vec![calxgloss_serialize::types::EndiannessEntry {
                    width: 32,
                    endianness: calxgloss_serialize::types::WireEndianness::BigEndian,
                    functions: functions.iter().map(|f| (*f).into()).collect(),
                }],
                suggestion: "program-wide BE wire order at u32 (byteorder BE types)".into(),
                confidence: calxgloss_serialize::types::Confidence::new(75),
                evidence: "uVar1 = ntohl(local_18);".into(),
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
                in_loop: false,
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

    fn branch_site_hint(function: &str) -> calxgloss_controlflow::types::ControlFlowFinding {
        calxgloss_controlflow::types::ControlFlowFinding::BranchSite(
            calxgloss_controlflow::types::BranchSite {
                function: function.into(),
                condition: "param_1 == 0".into(),
                params: vec!["param_1".into()],
                operator: Some("==".into()),
                immediate: Some("0".into()),
                guards: calxgloss_controlflow::types::GuardedTarget::EarlyReturn,
                suggestion: "keep the early return behind param_1 == 0".into(),
                confidence: calxgloss_controlflow::types::Confidence::new(80),
                evidence: "if (param_1 == 0) {".into(),
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
    fn the_loaded_findings_carry_the_function_s_branch_inventory() {
        // One load feeds the prompt context and the branch inventory that
        // targets baseline test generation (issue #261): the target
        // function's branch_site records in document order, and nothing
        // else — other finding kinds and other functions contribute no
        // records.
        let dir = TempDir::new().expect("temp dir should be created");
        persist_controlflow_findings(
            &dir,
            vec![
                switch_hint("FUN_18003ab00"),
                branch_site_hint("FUN_18003ab00"),
                branch_site_hint("FUN_zzz"),
            ],
        );

        let loaded = load_control_flow_result(Some(dir.path()), "eqmain.dll")
            .expect("the persisted document loads");
        let inventory = branch_inventory_of(Some(&loaded), "FUN_18003ab00");

        assert_eq!(inventory.len(), 1, "only the branch_site records");
        assert_eq!(inventory[0].function, "FUN_18003ab00");
        assert_eq!(inventory[0].condition, "param_1 == 0");
        assert_eq!(inventory[0].params, ["param_1"]);
        assert_eq!(inventory[0].operator.as_deref(), Some("=="));
        assert_eq!(inventory[0].immediate.as_deref(), Some("0"));
        assert_eq!(
            inventory[0].guards,
            calxgloss_controlflow::types::GuardedTarget::EarlyReturn
        );
        assert_eq!(u8::from(inventory[0].confidence), 80);
    }

    #[test]
    fn no_usable_document_yields_no_branch_inventory() {
        // No workspace, a missing document, or a corrupt one all load as
        // nothing: the inventory is empty and generation stays exactly
        // today's suite.
        assert!(
            branch_inventory_of(None, "FUN_18003ab00").is_empty(),
            "no loaded document means no inventory"
        );
        let dir = TempDir::new().expect("temp dir should be created");
        assert!(
            load_control_flow_result(Some(dir.path()), "eqmain.dll").is_none(),
            "a missing document loads as nothing"
        );
    }

    // ---- libmatch callee-hint extraction --------------------------------

    /// Test-only convenience wrapper over the read-plus-join route: load
    /// the per-binary document — degrading to nothing when no workspace
    /// is configured, none is persisted, or it is corrupt — and join it
    /// against the neighbors through [`libmatch_hints_from`]. The gather
    /// itself keeps the document to fill its coverage leg beside the
    /// hints (issue #347), so this pair only serves the pins.
    fn extract_libmatch_hints(
        workspace: Option<&std::path::Path>,
        binary: &str,
        function: &str,
        neighbors: &[String],
    ) -> Vec<calxgloss_prompts::LibmatchInfo> {
        libmatch_hints_from(
            load_libmatch_result(workspace, binary).as_ref(),
            function,
            neighbors,
        )
    }

    fn libmatch_finding(
        function: &str,
        symbol: &str,
        family: calxgloss_libmatch::types::LibraryFamily,
    ) -> calxgloss_libmatch::types::LibmatchFinding {
        calxgloss_libmatch::types::LibmatchFinding::BodySignature(
            calxgloss_libmatch::types::LibmatchMatch {
                function: function.to_string(),
                symbol: symbol.to_string(),
                family,
                suggestion: format!("rust equivalent of {symbol}"),
                confidence: Confidence::new(90),
                evidence:
                    "  *(undefined8 *)((long)puVar1 + -8) = *(undefined8 *)((long)lVar2 + -8);"
                        .to_string(),
                // Shaped as the engine writes them (P19-3): the note is
                // written into every match record a fresh scan files.
                admission: Some(calxgloss_libmatch::types::VERSION_UNKNOWN_ADMISSION.to_string()),
            },
        )
    }

    fn persist_libmatch_findings(
        dir: &TempDir,
        findings: Vec<calxgloss_libmatch::types::LibmatchFinding>,
    ) {
        let mut result =
            calxgloss_libmatch::types::LibmatchResult::new(ScanMetadata::new("eqmain.dll"));
        result.findings = findings;
        calxgloss_libmatch::persist::LibmatchPersistor::new(dir.path())
            .save(&result)
            .expect("the libmatch result should be saved");
    }

    #[test]
    fn no_workspace_configured_yields_no_libmatch_findings() {
        assert!(
            extract_libmatch_hints(None, "eqmain.dll", "FUN_18003ab00", &[]).is_empty(),
            "no workspace means no known-library context"
        );
    }

    #[test]
    fn a_missing_cache_yields_no_libmatch_findings() {
        let dir = TempDir::new().expect("temp dir should be created");
        assert!(
            extract_libmatch_hints(
                Some(dir.path()),
                "eqmain.dll",
                "FUN_18003ab00",
                &["FUN_1800412a0".to_string()],
            )
            .is_empty(),
            "a scan that has not run yet just means no known-library context"
        );
    }

    #[test]
    fn a_corrupt_cache_degrades_to_no_libmatch_findings() {
        let dir = TempDir::new().expect("temp dir should be created");
        let path = dir
            .path()
            .join("re")
            .join("analysis")
            .join("libmatch")
            .join("eqmain.dll.json");
        std::fs::create_dir_all(
            path.parent()
                .expect("the document path should have a parent"),
        )
        .expect("the cache directory should be creatable");
        std::fs::write(&path, "{ not json").expect("the corrupt document should be writable");

        assert!(
            extract_libmatch_hints(
                Some(dir.path()),
                "eqmain.dll",
                "FUN_18003ab00",
                &["FUN_1800412a0".to_string()],
            )
            .is_empty(),
            "one stale artifact never fails a translation run"
        );
    }

    #[test]
    fn libmatch_findings_join_the_callees_never_the_target() {
        // The join is against the target's call-graph neighbors: a
        // matched callee lands, the target's own match does not — a
        // matched target is stubbed at the call graph, not prompted —
        // even when the neighbor list names the target itself.
        let dir = TempDir::new().expect("temp dir should be created");
        persist_libmatch_findings(
            &dir,
            vec![
                libmatch_finding(
                    "FUN_18003ab00",
                    "memcpy",
                    calxgloss_libmatch::types::LibraryFamily::Crt,
                ),
                libmatch_finding(
                    "FUN_1800412a0",
                    "strlen",
                    calxgloss_libmatch::types::LibraryFamily::Crt,
                ),
            ],
        );

        let found = extract_libmatch_hints(
            Some(dir.path()),
            "eqmain.dll",
            "FUN_18003ab00",
            &["FUN_1800412a0".to_string(), "FUN_18003ab00".to_string()],
        );

        assert_eq!(found.len(), 1, "the callee's match, never the target's");
        assert_eq!(found[0].function, "FUN_1800412a0");
        assert_eq!(found[0].symbol, "strlen");
    }

    #[test]
    fn libmatch_findings_of_functions_the_target_does_not_call_are_dropped() {
        let dir = TempDir::new().expect("temp dir should be created");
        persist_libmatch_findings(
            &dir,
            vec![libmatch_finding(
                "FUN_zzz",
                "memcpy",
                calxgloss_libmatch::types::LibraryFamily::Crt,
            )],
        );

        let found = extract_libmatch_hints(
            Some(dir.path()),
            "eqmain.dll",
            "FUN_18003ab00",
            &["FUN_1800412a0".to_string()],
        );

        assert!(
            found.is_empty(),
            "a matched function the target does not call contributes nothing"
        );
    }

    #[test]
    fn every_libmatch_finding_of_a_callee_lands_in_the_prompt() {
        let dir = TempDir::new().expect("temp dir should be created");
        persist_libmatch_findings(
            &dir,
            vec![
                libmatch_finding(
                    "FUN_1800412a0",
                    "memcpy",
                    calxgloss_libmatch::types::LibraryFamily::Crt,
                ),
                libmatch_finding(
                    "FUN_180099999",
                    "_Tree_rot_right",
                    calxgloss_libmatch::types::LibraryFamily::Stl,
                ),
                libmatch_finding(
                    "FUN_zzz",
                    "strlen",
                    calxgloss_libmatch::types::LibraryFamily::Crt,
                ),
            ],
        );

        let found = extract_libmatch_hints(
            Some(dir.path()),
            "eqmain.dll",
            "FUN_18003ab00",
            &["FUN_180099999".to_string(), "FUN_1800412a0".to_string()],
        );

        // Document order, not neighbor order: the scan's sequence is
        // what makes two prompts over one document agree.
        let symbols: Vec<&str> = found.iter().map(|f| f.symbol.as_str()).collect();
        assert_eq!(symbols, vec!["memcpy", "_Tree_rot_right"]);
        assert_eq!(found[0].function, "FUN_1800412a0");
        assert_eq!(found[0].family, "crt");
        assert_eq!(found[0].suggestion, "rust equivalent of memcpy");
        assert_eq!(found[0].confidence, 90);
        assert!(found[0].evidence.contains("= *(undefined8"));
        assert_eq!(found[1].family, "stl");
    }

    #[test]
    fn a_libmatch_document_written_before_this_pass_still_loads() {
        // The prompt pass adds no fields to the persisted document: a
        // document exactly as the matcher wrote it before the prompt
        // section existed still loads and joins against the callees.
        let dir = TempDir::new().expect("temp dir should be created");
        let doc_dir = dir.path().join("re").join("analysis").join("libmatch");
        std::fs::create_dir_all(&doc_dir).expect("the document directory should be created");
        std::fs::write(
            doc_dir.join("eqmain.dll.json"),
            r#"{
                "metadata": {"binary": "eqmain.dll", "scanned_at": 1759488000},
                "findings": [{
                    "kind": "body_signature",
                    "function": "FUN_1800412a0",
                    "symbol": "memcpy",
                    "family": "crt",
                    "suggestion": "slice copy / std::ptr::copy_nonoverlapping",
                    "confidence": 90,
                    "evidence": "  *(undefined8 *)((long)puVar1 + -8);"
                }]
            }"#,
        )
        .expect("the pre-pass document should be writable");

        let found = extract_libmatch_hints(
            Some(dir.path()),
            "eqmain.dll",
            "FUN_18003ab00",
            &["FUN_1800412a0".to_string()],
        );

        assert_eq!(
            found.len(),
            1,
            "a pre-pass document joins like a current one"
        );
        assert_eq!(found[0].symbol, "memcpy");
        assert_eq!(found[0].family, "crt");
        assert_eq!(found[0].confidence, 90);
    }

    // ---- global-state hint extraction ---------------------------------

    fn global_read(
        function: &str,
        global: &str,
    ) -> calxgloss_globalstate::types::GlobalStateFinding {
        calxgloss_globalstate::types::GlobalStateFinding::GlobalRead(
            calxgloss_globalstate::types::GlobalAccess {
                function: function.into(),
                global: global.into(),
                evidence: format!("uVar1 = {global};"),
                confidence: calxgloss_types::Confidence::new(85),
                suggestion: "read the program global through shared state, not an invented local"
                    .into(),
            },
        )
    }

    fn global_write(
        function: &str,
        global: &str,
    ) -> calxgloss_globalstate::types::GlobalStateFinding {
        calxgloss_globalstate::types::GlobalStateFinding::GlobalWrite(
            calxgloss_globalstate::types::GlobalAccess {
                function: function.into(),
                global: global.into(),
                evidence: format!("{global} = param_1;"),
                confidence: calxgloss_types::Confidence::new(85),
                suggestion: "model the program global as shared struct state, not a Rust static"
                    .into(),
            },
        )
    }

    fn shared_index(
        global: &str,
        readers: &[&str],
        writers: &[&str],
    ) -> calxgloss_globalstate::types::GlobalStateFinding {
        calxgloss_globalstate::types::GlobalStateFinding::SharedGlobal(
            calxgloss_globalstate::types::SharedGlobalRecord {
                global: global.into(),
                readers: readers.iter().map(|f| f.to_string()).collect(),
                writers: writers.iter().map(|f| f.to_string()).collect(),
                confidence: calxgloss_types::Confidence::new(85),
            },
        )
    }

    fn persist_globalstate_findings(
        dir: &TempDir,
        findings: Vec<calxgloss_globalstate::types::GlobalStateFinding>,
    ) {
        let mut result =
            calxgloss_globalstate::types::GlobalStateResult::new(ScanMetadata::new("eqmain.dll"));
        result.findings = findings;
        calxgloss_globalstate::persist::GlobalStatePersistor::new(dir.path())
            .save(&result)
            .expect("the global-state result should be saved");
    }

    // ---- float/SIMD hint extraction ------------------------------------

    fn float_flag(function: &str) -> calxgloss_floatsimd::types::FloatsimdFinding {
        calxgloss_floatsimd::types::FloatsimdFinding::ScalarFloat(
            calxgloss_floatsimd::types::FloatsimdRecord {
                function: function.into(),
                evidence: "fVar1 = (float)uVar2 * 1.5f;".into(),
                confidence: calxgloss_types::Confidence::new(90),
                suggestion: "translate this body with f32/f64 scalars, not integer or pointer math"
                    .into(),
            },
        )
    }

    fn vector_flag(function: &str) -> calxgloss_floatsimd::types::FloatsimdFinding {
        calxgloss_floatsimd::types::FloatsimdFinding::VectorMatrix(
            calxgloss_floatsimd::types::FloatsimdRecord {
                function: function.into(),
                evidence: "uVar3 = CONCAT44(uVar2, uVar1);".into(),
                confidence: calxgloss_types::Confidence::new(60),
                suggestion: "translate this body as a small vector or component array, not scalar integer math"
                    .into(),
            },
        )
    }

    fn persist_floatsimd_findings(
        dir: &TempDir,
        findings: Vec<calxgloss_floatsimd::types::FloatsimdFinding>,
    ) {
        let mut result =
            calxgloss_floatsimd::types::FloatsimdResult::new(ScanMetadata::new("eqmain.dll"));
        result.findings = findings;
        calxgloss_floatsimd::persist::FloatsimdPersistor::new(dir.path())
            .save(&result)
            .expect("the float/SIMD result should be saved");
    }

    fn convention_inference(
        function: &str,
        callee: Option<&str>,
        convention: calxgloss_typeinfer::types::CallingConvention,
        method: InferenceMethod,
        confidence: u8,
        evidence: &str,
    ) -> InferredType {
        InferredType::Convention(InferredConvention {
            function: function.to_string(),
            callee: callee.map(str::to_string),
            convention,
            method,
            confidence: Confidence::new(confidence),
            evidence: evidence.to_string(),
        })
    }

    // --- error-handling findings (issue #293) ------------------------------

    fn seh_finding(function: &str) -> calxgloss_errhandling::types::ErrhandlingFinding {
        calxgloss_errhandling::types::ErrhandlingFinding::SehFrame(
            calxgloss_errhandling::types::SehFrame {
                function: function.to_string(),
                confidence: Confidence::new(80),
                evidence: "  catch(...){".to_string(),
                suggestion: calxgloss_errhandling::SEH_FRAME_SUGGESTION.to_string(),
            },
        )
    }

    fn ladder_finding(function: &str) -> calxgloss_errhandling::types::ErrhandlingFinding {
        calxgloss_errhandling::types::ErrhandlingFinding::GotoCleanup(
            calxgloss_errhandling::types::GotoCleanup {
                function: function.to_string(),
                confidence: Confidence::new(55),
                evidence: "  CloseHandle(hFile);".to_string(),
                join_label: "LAB_140001a2c".to_string(),
                suggestion: calxgloss_errhandling::GOTO_CLEANUP_SUGGESTION.to_string(),
            },
        )
    }

    fn code_finding(function: &str) -> calxgloss_errhandling::types::ErrhandlingFinding {
        calxgloss_errhandling::types::ErrhandlingFinding::ErrorCode(
            calxgloss_errhandling::types::ErrorCode {
                function: function.to_string(),
                confidence: Confidence::new(74),
                evidence: "  return 0x80070057;".to_string(),
                code: 0x8007_0057,
                site: calxgloss_errhandling::types::ErrorCodeSite::Return,
                suggestion: calxgloss_errhandling::ERROR_CODE_SUGGESTION.to_string(),
            },
        )
    }

    fn inherited_code_finding(function: &str) -> calxgloss_errhandling::types::ErrhandlingFinding {
        calxgloss_errhandling::types::ErrhandlingFinding::InheritedErrorCode(
            calxgloss_errhandling::types::InheritedErrorCode {
                function: function.to_string(),
                partner: "FUN_1800412a0".to_string(),
                confidence: Confidence::new(54),
                evidence: "  return FUN_1800412a0(param_1);".to_string(),
                code: 0xC000_0001,
                suggestion: calxgloss_errhandling::ERROR_CODE_SUGGESTION.to_string(),
            },
        )
    }

    fn persist_errhandling_findings(
        dir: &TempDir,
        findings: Vec<calxgloss_errhandling::types::ErrhandlingFinding>,
    ) {
        let mut result =
            calxgloss_errhandling::types::ErrhandlingResult::new(ScanMetadata::new("eqmain.dll"));
        result.findings = findings;
        calxgloss_errhandling::persist::ErrhandlingPersistor::new(dir.path())
            .save(&result)
            .expect("the error-handling result should be saved");
    }

    // --- the evidence gather (issue #268) ---------------------------------
    #[test]
    fn gather_function_evidence_reads_the_caches_into_one_bundle() {
        let dir = TempDir::new().unwrap();
        let mut db = TypeDatabase::new(ScanMetadata::new("eqmain.dll"));
        db.inferred_structs = vec![inferred_struct("Player", &["FUN_18003ab00"])];
        persist(&dir, db);
        persist_inferences(
            &dir,
            vec![
                param_inference("FUN_18003ab00", 0, "Widget *"),
                convention_inference(
                    "FUN_18003ab00",
                    None,
                    calxgloss_typeinfer::types::CallingConvention::Thiscall,
                    InferenceMethod::MangledConvention,
                    90,
                    "?paint@Widget@@QAEXXZ",
                ),
                direction_inference("FUN_18003ab00", 0, Direction::Out),
            ],
        );
        persist_hints(&dir, vec![algorithm_hint("FUN_18003ab00", "bubble sort")]);
        persist_const_findings(&dir, vec![table_record(&["FUN_18003ab00"])]);
        persist_errhandling_findings(
            &dir,
            vec![
                seh_finding("FUN_18003ab00"),
                code_finding("FUN_18003ab00"),
                seh_finding("FUN_zzz"),
            ],
        );

        let evidence =
            gather_function_evidence(Some(dir.path()), "eqmain.dll", "FUN_18003ab00", &[]);

        assert_eq!(evidence.data_structures.len(), 1);
        assert_eq!(evidence.data_structures[0].name, "Player");
        assert_eq!(
            evidence.type_info.len(),
            3,
            "every inference record for the function"
        );
        assert!(
            evidence.type_info.iter().any(|t| t.name == "param_1"),
            "the param inference lands in type_info"
        );
        assert_eq!(evidence.convention_findings.len(), 1);
        assert_eq!(evidence.convention_findings[0].convention, "thiscall");
        assert_eq!(evidence.recognized_algorithms.len(), 1);
        assert_eq!(
            evidence.parameter_direction_findings.len(),
            1,
            "the direction record also reaches the module-context bundle"
        );
        assert_eq!(evidence.parameter_direction_findings[0].direction, "out");
        assert_eq!(
            evidence.data_table_findings.len(),
            1,
            "the table the function reads reaches the module-context bundle"
        );
        assert_eq!(evidence.data_table_findings[0].name, "DAT_1400a1b60");
        assert_eq!(
            evidence.error_handling_findings.len(),
            2,
            "the function's idiom and failure code reach the module-context bundle"
        );
        assert_eq!(evidence.error_handling_findings[0].kind, "seh_frame");
        assert_eq!(
            evidence.error_handling_findings[1].code.as_deref(),
            Some("0x80070057")
        );
        assert_eq!(
            evidence
                .const_findings
                .iter()
                .filter(|f| f.kind == "data_table")
                .count(),
            1,
            "the same table also lands in the union findings for the escalate CONSTANTS section"
        );

        // The call-graph lists are the caller's to fill — the gather reads
        // only the persisted analyzer caches.
        assert!(evidence.call_graph_neighbors.is_empty());
        assert!(evidence.neighboring_functions.is_empty());
        assert!(evidence.call_graph_context.is_empty());

        // No workspace, no caches: every synchronous list degrades to empty.
        let none = gather_function_evidence(None, "eqmain.dll", "FUN_18003ab00", &[]);
        assert!(none.data_structures.is_empty());
        assert!(none.type_info.is_empty());
        assert!(none.recognized_algorithms.is_empty());
        assert!(none.memory_findings.is_empty());
        assert!(none.concurrency_findings.is_empty());
        assert!(none.callback_findings.is_empty());
        assert!(none.control_flow_findings.is_empty());
        assert!(none.convention_findings.is_empty());
        assert!(none.global_state_findings.is_empty());
        assert!(none.string_findings.is_empty());
        assert!(none.api_findings.is_empty());
        assert!(none.const_findings.is_empty());
        assert!(none.serialization_findings.is_empty());
        assert!(none.libmatch_findings.is_empty());
        assert!(none.parameter_direction_findings.is_empty());
        assert!(none.data_table_findings.is_empty());
        assert!(none.error_handling_findings.is_empty());
    }

    // --- the projection-row suite (issues #312, #313, and #314) ---------
    //
    // The parametrized suite replacing the per-engine trio tests: for
    // every row registered in `PROJECTION_ROWS`, driven through
    // `gather_function_evidence` exactly as the pipeline calls it — no
    // workspace configured, the field stays empty; the document missing,
    // the field stays empty rather than failing the gather; the document
    // corrupt, the field degrades to empty like a missing one; the
    // document persisted, exactly the records naming the function land
    // in the field, in scan order, with other functions' records and
    // program-level records not naming it (the API import entry) left
    // out. Each kit asserts record *identity and order*, never how an
    // adapter converts a record — conversion is pinned by the engine
    // crates' own `From` tests. A registered row without a kit here
    // panics: registering a row is what pulls an engine into this
    // suite, and the roster test in the adapters module pins the set of
    // registered rows.

    /// One row's test kit: how to place its document, how to corrupt it,
    /// which identities its bundle field(s) carry (in order), and what a
    /// persisted document must project — the target function's records
    /// only, in scan order, from a document that also names another
    /// function and, where the engine has them, program-level records.
    /// A multi-field row's kit (the shared consts and type-inference
    /// rows, #314) concatenates the identities of every field the row
    /// feeds, so one kit degrades or projects all of them together.
    struct RowKit {
        kind: &'static str,
        persist: fn(&TempDir),
        corrupt: fn(&TempDir),
        projected: fn(&EvidenceBundle) -> Vec<String>,
        expected: &'static [&'static str],
    }

    /// The shared row shape: each document carries two records naming
    /// the target function and one naming `FUN_zzz`, so the persisted
    /// case pins selection *and* order in one pass.
    const ROW_KITS: &[RowKit] = &[
        RowKit {
            kind: "algorithm recognition result",
            persist: |dir| {
                persist_hints(
                    dir,
                    vec![
                        algorithm_hint("FUN_18003ab00", "comparison_sort"),
                        algorithm_hint("FUN_zzz", "binary_search"),
                        algorithm_hint("FUN_18003ab00", "crc"),
                    ],
                );
            },
            corrupt: |dir| {
                corrupt_at(
                    calxgloss_algorithm::persist::AlgorithmPersistor::new(dir.path())
                        .path_for("eqmain.dll"),
                )
            },
            projected: |bundle| {
                bundle
                    .recognized_algorithms
                    .iter()
                    .map(|a| a.algorithm.clone())
                    .collect()
            },
            expected: &["comparison_sort", "crc"],
        },
        RowKit {
            kind: "memory lifecycle result",
            persist: |dir| {
                persist_findings(
                    dir,
                    vec![
                        calxgloss_memory::types::MemoryFinding::Allocation(allocation_hint(
                            "FUN_18003ab00",
                            "Box<T>",
                        )),
                        calxgloss_memory::types::MemoryFinding::Allocation(allocation_hint(
                            "FUN_zzz", "Box<T>",
                        )),
                        calxgloss_memory::types::MemoryFinding::Handle(handle_record(
                            "FUN_18003ab00",
                        )),
                    ],
                );
            },
            corrupt: |dir| {
                corrupt_at(
                    calxgloss_memory::persist::MemoryPersistor::new(dir.path())
                        .path_for("eqmain.dll"),
                )
            },
            projected: |bundle| {
                bundle
                    .memory_findings
                    .iter()
                    .map(|f| f.kind.clone())
                    .collect()
            },
            expected: &["allocation", "handle"],
        },
        RowKit {
            kind: "concurrency result",
            persist: |dir| {
                persist_sync_findings(
                    dir,
                    vec![
                        calxgloss_sync::types::SyncFinding::Mutex(mutex_hint(
                            "FUN_18003ab00",
                            "std::sync::Mutex<T>",
                        )),
                        calxgloss_sync::types::SyncFinding::Atomic(atomic_record("FUN_zzz")),
                        calxgloss_sync::types::SyncFinding::Atomic(atomic_record("FUN_18003ab00")),
                        calxgloss_sync::types::SyncFinding::Thread(thread_record("FUN_18003ab00")),
                    ],
                );
            },
            corrupt: |dir| {
                corrupt_at(
                    calxgloss_sync::persist::SyncPersistor::new(dir.path()).path_for("eqmain.dll"),
                )
            },
            projected: |bundle| {
                bundle
                    .concurrency_findings
                    .iter()
                    .map(|f| f.kind.clone())
                    .collect()
            },
            expected: &["mutex", "atomic", "thread"],
        },
        RowKit {
            kind: "string context result",
            persist: |dir| {
                let mut result = calxgloss_stringctx::types::StringContextResult::new(
                    ScanMetadata::new("eqmain.dll"),
                );
                result.findings = vec![
                    classified_string("FUN_18003ab00", "Journal.txt", "config file path"),
                    classified_string("FUN_zzz", "settings.ini", "config file path"),
                    classified_string("FUN_18003ab00", "Failed to open", "error message"),
                ];
                calxgloss_stringctx::persist::StringContextPersistor::new(dir.path())
                    .save(&result)
                    .expect("the string-context result should be saved");
            },
            corrupt: |dir| {
                corrupt_at(
                    calxgloss_stringctx::persist::StringContextPersistor::new(dir.path())
                        .path_for("eqmain.dll"),
                )
            },
            projected: |bundle| {
                bundle
                    .string_findings
                    .iter()
                    .map(|f| f.suggestion.clone())
                    .collect()
            },
            expected: &["config file path", "error message"],
        },
        RowKit {
            kind: "API result",
            persist: |dir| {
                persist_api_findings(
                    dir,
                    vec![
                        // A binary-level import entry: program-level, names
                        // no function, and must not project.
                        calxgloss_apidetect::types::ApiFinding::Import(
                            calxgloss_apidetect::types::ApiSignature {
                                api: "inflate".to_string(),
                                library: Some("zlib".to_string()),
                                rust_crate: Some("flate2".to_string()),
                                category: None,
                                features: Vec::new(),
                                confidence: calxgloss_apidetect::types::Confidence::new(90),
                            },
                        ),
                        api_usage("FUN_18003ab00", "inflate", "zlib", "flate2", true),
                        api_usage("FUN_zzz", "inflate", "zlib", "flate2", true),
                        api_usage(
                            "FUN_18003ab00",
                            "CreateFileA",
                            "Win32",
                            "windows / std::fs",
                            false,
                        ),
                    ],
                );
            },
            corrupt: |dir| {
                corrupt_at(
                    calxgloss_apidetect::persist::ApiPersistor::new(dir.path())
                        .path_for("eqmain.dll"),
                )
            },
            projected: |bundle| bundle.api_findings.iter().map(|f| f.api.clone()).collect(),
            expected: &["inflate", "CreateFileA"],
        },
        RowKit {
            // The float/SIMD document carries at most one flag per
            // function, so the shared shape shrinks to one other
            // function's flag before the target's.
            kind: "float/SIMD result",
            persist: |dir| {
                persist_floatsimd_findings(
                    dir,
                    vec![float_flag("FUN_zzz"), vector_flag("FUN_18003ab00")],
                );
            },
            corrupt: |dir| {
                corrupt_at(
                    calxgloss_floatsimd::persist::FloatsimdPersistor::new(dir.path())
                        .path_for("eqmain.dll"),
                )
            },
            projected: |bundle| {
                bundle
                    .floatsimd_findings
                    .iter()
                    .map(|f| f.kind.clone())
                    .collect()
            },
            expected: &["vector_matrix"],
        },
        RowKit {
            // The database row is the one selection spelled by the
            // adapter instead of an engine lookup: candidates whose
            // literals the function cross-references first, then the
            // named types of classes whose vtable lists the function
            // as a method.
            kind: "type database",
            persist: |dir| {
                let mut db = TypeDatabase::new(ScanMetadata::new("eqmain.dll"));
                db.inferred_structs = vec![
                    inferred_struct("Player", &["FUN_18003ab00"]),
                    inferred_struct("Other", &["FUN_zzz"]),
                ];
                db.vtables = vec![
                    vtable_for("Widget", "FUN_18003ab00"),
                    vtable_for("Unrelated", "FUN_zzz"),
                ];
                db.named_types = vec![named_struct("Widget"), named_struct("Unrelated")];
                persist(dir, db);
            },
            corrupt: |dir| {
                corrupt_at(
                    calxgloss_typesdb::persist::TypeDatabasePersistor::new(dir.path())
                        .path_for("eqmain.dll"),
                )
            },
            projected: |bundle| {
                bundle
                    .data_structures
                    .iter()
                    .map(|s| s.name.clone())
                    .collect()
            },
            expected: &["Player", "Widget"],
        },
        RowKit {
            // The endianness map is program-level, but it answers to
            // each of its contributing functions — a map naming only
            // the other function stays out.
            kind: "serialization result",
            persist: |dir| {
                persist_serialize_findings(
                    dir,
                    vec![
                        swap_record("FUN_18003ab00"),
                        swap_record("FUN_zzz"),
                        pack_record("FUN_18003ab00"),
                        magic_record("FUN_18003ab00"),
                        map_record(&["FUN_18003ab00", "FUN_zzz"]),
                    ],
                );
            },
            corrupt: |dir| {
                corrupt_at(
                    calxgloss_serialize::persist::SerializePersistor::new(dir.path())
                        .path_for("eqmain.dll"),
                )
            },
            projected: |bundle| {
                bundle
                    .serialization_findings
                    .iter()
                    .map(|f| f.kind.clone())
                    .collect()
            },
            expected: &["byteswap", "bitpack", "magic", "endianness_map"],
        },
        RowKit {
            kind: "callback result",
            persist: |dir| {
                persist_callback_findings(
                    dir,
                    vec![
                        fp_array_hint("FUN_18003ab00"),
                        registration_hint("FUN_zzz"),
                        registration_hint("FUN_18003ab00"),
                        jump_table_hint("FUN_18003ab00"),
                    ],
                );
            },
            corrupt: |dir| {
                corrupt_at(
                    calxgloss_callback::persist::CallbackPersistor::new(dir.path())
                        .path_for("eqmain.dll"),
                )
            },
            projected: |bundle| {
                bundle
                    .callback_findings
                    .iter()
                    .map(|f| f.kind.clone())
                    .collect()
            },
            expected: &["fp_array", "registration", "jump_table"],
        },
        RowKit {
            // The row projects the same findings the branch inventory
            // reads from the same document; the inventory's own shape
            // is pinned by its tests above, outside this seam.
            kind: "control-flow result",
            persist: |dir| {
                persist_controlflow_findings(
                    dir,
                    vec![
                        switch_hint("FUN_18003ab00"),
                        switch_hint("FUN_zzz"),
                        recursion_hint("FUN_18003ab00"),
                        state_machine_hint("FUN_18003ab00"),
                        branch_site_hint("FUN_18003ab00"),
                    ],
                );
            },
            corrupt: |dir| {
                corrupt_at(
                    calxgloss_controlflow::persist::ControlFlowPersistor::new(dir.path())
                        .path_for("eqmain.dll"),
                )
            },
            projected: |bundle| {
                bundle
                    .control_flow_findings
                    .iter()
                    .map(|f| f.kind.clone())
                    .collect()
            },
            expected: &["switch", "recursion", "state_machine", "branch_site"],
        },
        RowKit {
            kind: "error-handling result",
            persist: |dir| {
                persist_errhandling_findings(
                    dir,
                    vec![
                        seh_finding("FUN_18003ab00"),
                        seh_finding("FUN_zzz"),
                        ladder_finding("FUN_18003ab00"),
                        code_finding("FUN_18003ab00"),
                        inherited_code_finding("FUN_18003ab00"),
                    ],
                );
            },
            corrupt: |dir| {
                corrupt_at(
                    calxgloss_errhandling::persist::ErrhandlingPersistor::new(dir.path())
                        .path_for("eqmain.dll"),
                )
            },
            projected: |bundle| {
                bundle
                    .error_handling_findings
                    .iter()
                    .map(|f| f.kind.clone())
                    .collect()
            },
            expected: &[
                "seh_frame",
                "goto_cleanup",
                "error_code",
                "inherited_error_code",
            ],
        },
        RowKit {
            // The shared-globals index names the function among its
            // readers and writers but is a fact about a global, not a
            // function — the engine's by-function lookup keeps it out.
            kind: "global-state result",
            persist: |dir| {
                persist_globalstate_findings(
                    dir,
                    vec![
                        global_write("FUN_18003ab00", "DAT_180064e80"),
                        global_read("FUN_zzz", "DAT_180064e80"),
                        global_read("FUN_18003ab00", "g_counter"),
                        shared_index("DAT_180064e80", &["FUN_zzz"], &["FUN_18003ab00"]),
                    ],
                );
            },
            corrupt: |dir| {
                corrupt_at(
                    calxgloss_globalstate::persist::GlobalStatePersistor::new(dir.path())
                        .path_for("eqmain.dll"),
                )
            },
            projected: |bundle| {
                bundle
                    .global_state_findings
                    .iter()
                    .map(|f| format!("{}:{}", f.kind, f.global))
                    .collect()
            },
            expected: &["global_write:DAT_180064e80", "global_read:g_counter"],
        },
        RowKit {
            // The shared constant document is one load feeding two fields
            // (issue #314): every finding naming the function goes into the
            // union, and a table record *also* lands in the module-context
            // table field — the same record in both fields from the single
            // pass. Program-level findings answer to every function they
            // name; a table naming only the other function stays out of both
            // fields, and the union entry keeps the escalate CONSTANTS
            // section riding.
            kind: "constant result",
            persist: |dir| {
                persist_const_findings(
                    dir,
                    vec![
                        calxgloss_consts::types::ConstFinding::BitflagGroup(bitflag_record(
                            "FUN_18003ab00",
                        )),
                        calxgloss_consts::types::ConstFinding::EnumCandidate(enum_record(
                            "FUN_zzz",
                        )),
                        calxgloss_consts::types::ConstFinding::NamedConstant(named_record(&[
                            "FUN_18003ab00",
                            "FUN_zzz",
                        ])),
                        table_record(&["FUN_18003ab00", "FUN_zzz"]),
                        table_record(&["FUN_zzz"]),
                    ],
                );
            },
            corrupt: |dir| {
                corrupt_at(
                    calxgloss_consts::persist::ConstPersistor::new(dir.path())
                        .path_for("eqmain.dll"),
                )
            },
            projected: |bundle| {
                let mut ids: Vec<String> = bundle
                    .const_findings
                    .iter()
                    .map(|f| f.kind.clone())
                    .collect();
                ids.extend(
                    bundle
                        .data_table_findings
                        .iter()
                        .map(|t| format!("table:{}", t.name)),
                );
                ids
            },
            expected: &[
                "bitflag_group",
                "named_constant",
                "data_table",
                "table:DAT_1400a1b60",
            ],
        },
        RowKit {
            // The shared type-inference document is one load feeding three
            // fields (issue #314): every reading naming the function goes
            // into type_info — parameter, local, call-site, convention, and
            // direction alike — while the convention reading *also* fans out
            // to its module-context section and the direction reading to the
            // directions section. The collapsed convention re-read and the
            // per-field loads leave this one projection behind: other
            // functions' records stay out of all three fields.
            kind: "type inference result",
            persist: |dir| {
                persist_inferences(
                    dir,
                    vec![
                        param_inference("FUN_18003ab00", 0, "Widget *"),
                        param_inference("FUN_zzz", 0, "char *"),
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
                        convention_inference(
                            "FUN_18003ab00",
                            None,
                            calxgloss_typeinfer::types::CallingConvention::Thiscall,
                            InferenceMethod::MangledConvention,
                            90,
                            "?paint@Widget@@QAEXXZ",
                        ),
                        convention_inference(
                            "FUN_zzz",
                            None,
                            calxgloss_typeinfer::types::CallingConvention::Cdecl,
                            InferenceMethod::MangledConvention,
                            90,
                            "?draw@Canvas@@IAXXZ",
                        ),
                        direction_inference("FUN_18003ab00", 0, Direction::In),
                        direction_inference("FUN_18003ab00", 1, Direction::Out),
                        direction_inference("FUN_zzz", 0, Direction::Out),
                    ],
                );
            },
            corrupt: |dir| corrupt_at(TypeInferPersistor::new(dir.path()).path_for("eqmain.dll")),
            projected: |bundle| {
                let mut ids: Vec<String> = bundle
                    .type_info
                    .iter()
                    .map(|t| format!("type:{}", t.name))
                    .collect();
                ids.extend(
                    bundle
                        .convention_findings
                        .iter()
                        .map(|c| format!("conv:{}", c.convention)),
                );
                ids.extend(
                    bundle
                        .parameter_direction_findings
                        .iter()
                        .map(|d| format!("dir:{}:{}", d.parameter, d.direction)),
                );
                ids
            },
            expected: &[
                "type:param_1",
                "type:local_8",
                "type:CloseHandle arg 1",
                "type:convention",
                "type:param_1",
                "type:param_2",
                "conv:thiscall",
                "dir:param_1:in",
                "dir:param_2:out",
            ],
        },
    ];

    /// Write an unparseable document where `path` would hold the real one.
    fn corrupt_at(path: std::path::PathBuf) {
        std::fs::create_dir_all(
            path.parent()
                .expect("the document path should have a parent"),
        )
        .expect("the cache directory should be creatable");
        std::fs::write(&path, "{ not json").expect("the corrupt document should be writable");
    }

    /// A classified-string record for the string-context row's shared
    /// shape — the row's own engine record built the same way the engine
    /// persists it.
    fn classified_string(
        function: &str,
        value: &str,
        purpose: &str,
    ) -> calxgloss_stringctx::types::StringFinding {
        calxgloss_stringctx::types::StringFinding::Classified(
            calxgloss_stringctx::types::ClassifiedString {
                function: function.to_string(),
                string_address: 0x180127cd8,
                string_value: value.to_string(),
                classification: calxgloss_stringctx::types::StringClassification::FilePath,
                purpose: purpose.to_string(),
                source: calxgloss_stringctx::types::StringSource::BodyParse,
                confidence: calxgloss_stringctx::types::Confidence::new(60),
                evidence: "lpszVar1 = \"Journal.txt\";".into(),
            },
        )
    }

    #[test]
    fn every_registered_projection_row_gathers_the_document_quartet() {
        for row in crate::evidence_projector::adapters::PROJECTION_ROWS {
            let kit = ROW_KITS
                .iter()
                .find(|kit| kit.kind == row.kind)
                .unwrap_or_else(|| {
                    panic!(
                        "projection row '{}' has no test kit — every registered row is \
                         driven through the gather here, so add one",
                        row.kind
                    )
                });

            // No workspace configured: the field stays empty.
            let bundle = gather_function_evidence(None, "eqmain.dll", "FUN_18003ab00", &[]);
            assert!(
                (kit.projected)(&bundle).is_empty(),
                "no workspace leaves the `{}` field empty",
                row.kind
            );

            // Document missing: a scan that has not run yet is an empty
            // field, not a failed gather.
            let dir = TempDir::new().expect("temp workspace should be created");
            let bundle =
                gather_function_evidence(Some(dir.path()), "eqmain.dll", "FUN_18003ab00", &[]);
            assert!(
                (kit.projected)(&bundle).is_empty(),
                "no persisted `{}` means an empty field, not a failure",
                row.kind
            );

            // Document corrupt: degrades to empty exactly like a missing one.
            let dir = TempDir::new().expect("temp workspace should be created");
            (kit.corrupt)(&dir);
            let bundle =
                gather_function_evidence(Some(dir.path()), "eqmain.dll", "FUN_18003ab00", &[]);
            assert!(
                (kit.projected)(&bundle).is_empty(),
                "an unusable `{}` degrades to the empty field",
                row.kind
            );

            // Document persisted: only the function's own records, in
            // scan order.
            let dir = TempDir::new().expect("temp workspace should be created");
            (kit.persist)(&dir);
            let bundle =
                gather_function_evidence(Some(dir.path()), "eqmain.dll", "FUN_18003ab00", &[]);
            assert_eq!(
                (kit.projected)(&bundle),
                kit.expected,
                "`{}` projects only the function's records, in scan order",
                row.kind
            );
        }
    }

    /// Files an API document whose metadata carries `coverage` — the
    /// shape apidetect's own stamp takes — beside one usage record for
    /// the target function.
    fn persist_api_document_with_coverage(
        dir: &TempDir,
        coverage: Option<calxgloss_types::ScanCoverage>,
    ) {
        let mut metadata = ScanMetadata::new("eqmain.dll");
        metadata.coverage = coverage;
        let mut result = calxgloss_apidetect::types::ApiDetectionResult::new(metadata);
        result.findings = vec![api_usage(
            "FUN_18003ab00",
            "inflate",
            "zlib",
            "flate2",
            true,
        )];
        calxgloss_apidetect::persist::ApiPersistor::new(dir.path())
            .save(&result)
            .expect("the stamped API result should be saved");
    }

    /// The API row's coverage leg end to end (issue #346): the record
    /// apidetect stamps into its filed document is carried through one gather
    /// into the bundle's coverage field beside the findings, word for word; a
    /// document filed before coverage stamping fills nothing; and a missing
    /// or corrupt document fills nothing and degrades exactly as its findings
    /// do.
    #[test]
    fn the_api_row_gathers_the_documents_coverage_beside_its_findings() {
        // The engine's own stamp beside a complete call graph: partial
        // overall, with delay imports the one facet admitting short.
        let stamp = calxgloss_types::ScanCoverage {
            status: calxgloss_types::CoverageStatus::Partial,
            facets: vec![
                calxgloss_types::FacetCoverage {
                    id: "import-table".to_string(),
                    status: calxgloss_types::CoverageStatus::Complete,
                    limitation: None,
                },
                calxgloss_types::FacetCoverage {
                    id: "api-usage".to_string(),
                    status: calxgloss_types::CoverageStatus::Complete,
                    limitation: None,
                },
                calxgloss_types::FacetCoverage {
                    id: "delay-imports".to_string(),
                    status: calxgloss_types::CoverageStatus::Unexamined,
                    limitation: Some("delay imports unexamined".to_string()),
                },
            ],
        };

        let dir = TempDir::new().expect("temp workspace should be created");
        persist_api_document_with_coverage(&dir, Some(stamp));
        let bundle = gather_function_evidence(Some(dir.path()), "eqmain.dll", "FUN_18003ab00", &[]);
        assert_eq!(
            bundle
                .api_findings
                .iter()
                .map(|f| f.api.clone())
                .collect::<Vec<_>>(),
            vec!["inflate".to_string()],
            "the findings still land in their ordinary row"
        );
        assert_eq!(bundle.api_coverage.status, "partial");
        assert_eq!(
            bundle.api_coverage.admission, "partial — delay imports unexamined",
            "the admission reaches the bundle exactly as the shared type words it"
        );

        // A document filed before the coverage record shipped (the
        // standing kit's shape): the field stays default-empty.
        let dir = TempDir::new().expect("temp workspace should be created");
        persist_api_findings(
            &dir,
            vec![api_usage(
                "FUN_18003ab00",
                "inflate",
                "zlib",
                "flate2",
                true,
            )],
        );
        let bundle = gather_function_evidence(Some(dir.path()), "eqmain.dll", "FUN_18003ab00", &[]);
        assert!(
            !bundle.api_findings.is_empty()
                && bundle.api_coverage.status.is_empty()
                && bundle.api_coverage.admission.is_empty(),
            "a pre-P19 document fills findings but no coverage — the old render stands"
        );

        // Missing: nothing gathered, nothing filled.
        let dir = TempDir::new().expect("temp workspace should be created");
        let bundle = gather_function_evidence(Some(dir.path()), "eqmain.dll", "FUN_18003ab00", &[]);
        assert!(
            bundle.api_findings.is_empty() && bundle.api_coverage.admission.is_empty(),
            "a missing API document fills neither findings nor coverage"
        );

        // Corrupt: degrades alike, fills neither.
        let dir = TempDir::new().expect("temp workspace should be created");
        corrupt_at(
            calxgloss_apidetect::persist::ApiPersistor::new(dir.path()).path_for("eqmain.dll"),
        );
        let bundle = gather_function_evidence(Some(dir.path()), "eqmain.dll", "FUN_18003ab00", &[]);
        assert!(
            bundle.api_findings.is_empty() && bundle.api_coverage.admission.is_empty(),
            "a corrupt API document fills neither findings nor coverage"
        );
    }

    /// The float/SIMD row's coverage leg end to end (issue #347): the record
    /// floatsimd stamps into its filed document is carried through one gather
    /// into the bundle beside the flag, word for word; a document filed
    /// before coverage stamping fills nothing; and a missing or corrupt
    /// document fills nothing and degrades exactly as its flag does.
    #[test]
    fn the_floatsimd_row_gathers_the_documents_coverage_beside_its_flag() {
        // The engine's own stamp: its one bodies facet fell short, naming
        // the bodies the decompiler never produced.
        let stamp = calxgloss_types::ScanCoverage {
            status: calxgloss_types::CoverageStatus::Partial,
            facets: vec![calxgloss_types::FacetCoverage {
                id: "function-bodies".to_string(),
                status: calxgloss_types::CoverageStatus::Partial,
                limitation: Some(
                    "2 function bodies unreached: FUN_1800412a0, FUN_180049abc".to_string(),
                ),
            }],
        };

        let dir = TempDir::new().expect("temp workspace should be created");
        let mut metadata = ScanMetadata::new("eqmain.dll");
        metadata.coverage = Some(stamp);
        let mut result = calxgloss_floatsimd::types::FloatsimdResult::new(metadata);
        result.findings = vec![float_flag("FUN_18003ab00")];
        calxgloss_floatsimd::persist::FloatsimdPersistor::new(dir.path())
            .save(&result)
            .expect("the stamped float/SIMD result should be saved");

        let bundle = gather_function_evidence(Some(dir.path()), "eqmain.dll", "FUN_18003ab00", &[]);
        assert_eq!(
            bundle.floatsimd_findings.len(),
            1,
            "the flag still lands in its ordinary row"
        );
        assert_eq!(bundle.floatsimd_coverage.status, "partial");
        assert_eq!(
            bundle.floatsimd_coverage.admission,
            "partial — 2 function bodies unreached: FUN_1800412a0, FUN_180049abc",
            "the admission reaches the bundle exactly as the shared type words it"
        );

        // A document filed before the coverage record shipped (the
        // standing kit's shape): the field stays default-empty.
        let dir = TempDir::new().expect("temp workspace should be created");
        persist_floatsimd_findings(&dir, vec![float_flag("FUN_18003ab00")]);
        let bundle = gather_function_evidence(Some(dir.path()), "eqmain.dll", "FUN_18003ab00", &[]);
        assert!(
            !bundle.floatsimd_findings.is_empty()
                && bundle.floatsimd_coverage.status.is_empty()
                && bundle.floatsimd_coverage.admission.is_empty(),
            "a pre-P19 document fills the flag but no coverage — the old render stands"
        );

        // Missing and corrupt: neither flag nor coverage.
        let dir = TempDir::new().expect("temp workspace should be created");
        let bundle = gather_function_evidence(Some(dir.path()), "eqmain.dll", "FUN_18003ab00", &[]);
        assert!(
            bundle.floatsimd_findings.is_empty() && bundle.floatsimd_coverage.admission.is_empty(),
            "a missing float/SIMD document fills neither flag nor coverage"
        );
        let dir = TempDir::new().expect("temp workspace should be created");
        corrupt_at(
            calxgloss_floatsimd::persist::FloatsimdPersistor::new(dir.path())
                .path_for("eqmain.dll"),
        );
        let bundle = gather_function_evidence(Some(dir.path()), "eqmain.dll", "FUN_18003ab00", &[]);
        assert!(
            bundle.floatsimd_findings.is_empty() && bundle.floatsimd_coverage.admission.is_empty(),
            "a corrupt float/SIMD document fills neither flag nor coverage"
        );
    }

    /// The type database row's coverage leg end to end (issue #348): the
    /// record typesdb stamps into its filed document is carried through one
    /// gather into the bundle beside the structures, word for word; a
    /// document filed before coverage stamping fills nothing; and a missing
    /// or corrupt document fills nothing and degrades exactly as its
    /// structures do.
    #[test]
    fn the_typesdb_row_gathers_the_documents_coverage_beside_its_structures() {
        // The engine's own stamp over a target that yielded no vtable
        // evidence: the single facet unavailable beside its reason, while the
        // string-inferred candidates this function references still land in
        // the row.
        let stamp = calxgloss_types::ScanCoverage {
            status: calxgloss_types::CoverageStatus::Unavailable,
            facets: vec![calxgloss_types::FacetCoverage {
                id: "vtables".to_string(),
                status: calxgloss_types::CoverageStatus::Unavailable,
                limitation: Some("no vtable evidence on this target".to_string()),
            }],
        };

        let dir = TempDir::new().expect("temp workspace should be created");
        let mut metadata = ScanMetadata::new("eqmain.dll");
        metadata.coverage = Some(stamp);
        let mut db = TypeDatabase::new(metadata);
        db.inferred_structs = vec![inferred_struct("Player", &["FUN_18003ab00"])];
        persist(&dir, db);
        let bundle = gather_function_evidence(Some(dir.path()), "eqmain.dll", "FUN_18003ab00", &[]);
        assert_eq!(
            bundle
                .data_structures
                .iter()
                .map(|s| s.name.as_str())
                .collect::<Vec<_>>(),
            ["Player"],
            "the structures still land in their ordinary row"
        );
        assert_eq!(bundle.type_database_coverage.status, "unavailable");
        assert_eq!(
            bundle.type_database_coverage.admission,
            "unavailable — no vtable evidence on this target",
            "the admission reaches the bundle exactly as the shared type words it"
        );

        // A document filed before the coverage record shipped (the
        // standing kit's shape): the field stays default-empty.
        let dir = TempDir::new().expect("temp workspace should be created");
        let mut db = TypeDatabase::new(ScanMetadata::new("eqmain.dll"));
        db.inferred_structs = vec![inferred_struct("Player", &["FUN_18003ab00"])];
        persist(&dir, db);
        let bundle = gather_function_evidence(Some(dir.path()), "eqmain.dll", "FUN_18003ab00", &[]);
        assert!(
            !bundle.data_structures.is_empty()
                && bundle.type_database_coverage.status.is_empty()
                && bundle.type_database_coverage.admission.is_empty(),
            "a pre-P19 document fills structures but no coverage — the old render stands"
        );

        // Missing: nothing gathered, nothing filled.
        let dir = TempDir::new().expect("temp workspace should be created");
        let bundle = gather_function_evidence(Some(dir.path()), "eqmain.dll", "FUN_18003ab00", &[]);
        assert!(
            bundle.data_structures.is_empty() && bundle.type_database_coverage.admission.is_empty(),
            "a missing type database fills neither structures nor coverage"
        );

        // Corrupt: degrades alike, fills neither.
        let dir = TempDir::new().expect("temp workspace should be created");
        corrupt_at(
            calxgloss_typesdb::persist::TypeDatabasePersistor::new(dir.path())
                .path_for("eqmain.dll"),
        );
        let bundle = gather_function_evidence(Some(dir.path()), "eqmain.dll", "FUN_18003ab00", &[]);
        assert!(
            bundle.data_structures.is_empty() && bundle.type_database_coverage.admission.is_empty(),
            "a corrupt type database fills neither structures nor coverage"
        );
    }

    /// The constant row's coverage leg end to end (issue #348): the record
    /// consts stamps into its filed document is carried through one gather
    /// into the bundle beside the findings, word for word — and one load
    /// feeds both fields it populates, so the same admission qualifies the
    /// constants union and the data-tables list. A document filed before
    /// coverage stamping fills nothing; a missing or corrupt document fills
    /// nothing and degrades exactly as its findings do.
    #[test]
    fn the_consts_row_gathers_the_documents_coverage_beside_its_findings() {
        // The engine's own stamp over a region-limited scan: both facets
        // partial, one naming the bodies it never reached and one the
        // memory window it never read.
        let stamp = calxgloss_types::ScanCoverage {
            status: calxgloss_types::CoverageStatus::Partial,
            facets: vec![
                calxgloss_types::FacetCoverage {
                    id: "function-bodies".to_string(),
                    status: calxgloss_types::CoverageStatus::Partial,
                    limitation: Some(
                        "2 function bodies unreached: FUN_18003e750, +1 more".to_string(),
                    ),
                },
                calxgloss_types::FacetCoverage {
                    id: "data-objects".to_string(),
                    status: calxgloss_types::CoverageStatus::Partial,
                    limitation: Some(
                        "1 data-object memory window unreadable: DAT_1400a1c00".to_string(),
                    ),
                },
            ],
        };

        let dir = TempDir::new().expect("temp workspace should be created");
        let mut metadata = ScanMetadata::new("eqmain.dll");
        metadata.coverage = Some(stamp);
        let mut result = calxgloss_consts::types::ConstResult::new(metadata);
        result.findings = vec![
            calxgloss_consts::types::ConstFinding::BitflagGroup(bitflag_record("FUN_18003ab00")),
            table_record(&["FUN_18003ab00"]),
        ];
        calxgloss_consts::persist::ConstPersistor::new(dir.path())
            .save(&result)
            .expect("the stamped constant result should be saved");
        let bundle = gather_function_evidence(Some(dir.path()), "eqmain.dll", "FUN_18003ab00", &[]);
        assert_eq!(
            bundle.const_findings.len(),
            2,
            "both findings still land in the union row"
        );
        assert_eq!(
            bundle.data_table_findings.len(),
            1,
            "and the table record still lands in its own field"
        );
        assert_eq!(bundle.consts_coverage.status, "partial");
        assert_eq!(
            bundle.consts_coverage.admission,
            "partial — 2 function bodies unreached: FUN_18003e750, +1 more; \
             1 data-object memory window unreadable: DAT_1400a1c00",
            "one admission reaches the bundle, and it is the whole picture's"
        );

        // A document filed before the coverage record shipped (the
        // standing kit's shape): the field stays default-empty.
        let dir = TempDir::new().expect("temp workspace should be created");
        persist_const_findings(
            &dir,
            vec![calxgloss_consts::types::ConstFinding::BitflagGroup(
                bitflag_record("FUN_18003ab00"),
            )],
        );
        let bundle = gather_function_evidence(Some(dir.path()), "eqmain.dll", "FUN_18003ab00", &[]);
        assert!(
            !bundle.const_findings.is_empty()
                && bundle.consts_coverage.status.is_empty()
                && bundle.consts_coverage.admission.is_empty(),
            "a pre-P19 document fills findings but no coverage — the old render stands"
        );

        // Missing: nothing gathered, nothing filled.
        let dir = TempDir::new().expect("temp workspace should be created");
        let bundle = gather_function_evidence(Some(dir.path()), "eqmain.dll", "FUN_18003ab00", &[]);
        assert!(
            bundle.const_findings.is_empty() && bundle.consts_coverage.admission.is_empty(),
            "a missing constant document fills neither findings nor coverage"
        );

        // Corrupt: degrades alike, fills neither.
        let dir = TempDir::new().expect("temp workspace should be created");
        corrupt_at(
            calxgloss_consts::persist::ConstPersistor::new(dir.path()).path_for("eqmain.dll"),
        );
        let bundle = gather_function_evidence(Some(dir.path()), "eqmain.dll", "FUN_18003ab00", &[]);
        assert!(
            bundle.const_findings.is_empty() && bundle.consts_coverage.admission.is_empty(),
            "a corrupt constant document fills neither findings nor coverage"
        );
    }

    /// The libmatch gather's coverage leg end to end (issue #347): the
    /// libmatch document is read outside the projection fold — its findings
    /// join the live call-graph neighbor list — so its coverage record is
    /// carried through the gather, beside those joined findings, word for
    /// word; a document filed before coverage stamping fills nothing; and a
    /// missing or corrupt document fills neither findings nor coverage.
    #[test]
    fn the_libmatch_gather_carries_the_documents_coverage_beside_its_hints() {
        let stamp = calxgloss_types::ScanCoverage {
            status: calxgloss_types::CoverageStatus::Partial,
            facets: vec![calxgloss_types::FacetCoverage {
                id: "function-bodies".to_string(),
                status: calxgloss_types::CoverageStatus::Partial,
                limitation: Some("1 function body unreached: FUN_18003e999".to_string()),
            }],
        };

        let dir = TempDir::new().expect("temp workspace should be created");
        let mut metadata = ScanMetadata::new("eqmain.dll");
        metadata.coverage = Some(stamp);
        let mut result = calxgloss_libmatch::types::LibmatchResult::new(metadata);
        result.findings = vec![libmatch_finding(
            "FUN_18003e750",
            "memcpy",
            calxgloss_libmatch::types::LibraryFamily::Crt,
        )];
        calxgloss_libmatch::persist::LibmatchPersistor::new(dir.path())
            .save(&result)
            .expect("the stamped libmatch result should be saved");

        let bundle = gather_function_evidence(
            Some(dir.path()),
            "eqmain.dll",
            "FUN_18003ab00",
            &["FUN_18003e750".to_string()],
        );
        assert_eq!(
            bundle
                .libmatch_findings
                .iter()
                .map(|hint| hint.symbol.as_str())
                .collect::<Vec<_>>(),
            vec!["memcpy"],
            "the callee hint still joins against the neighbor list"
        );
        assert_eq!(
            bundle.libmatch_findings[0].admission,
            calxgloss_libmatch::types::VERSION_UNKNOWN_ADMISSION,
            "the match record's own version-authority note reaches the prompt \
             with the hint"
        );
        assert_eq!(bundle.libmatch_coverage.status, "partial");
        assert_eq!(
            bundle.libmatch_coverage.admission,
            "partial — 1 function body unreached: FUN_18003e999",
            "the admission reaches the bundle exactly as the shared type words it"
        );

        // A document filed before the coverage record shipped (the
        // standing kit's shape): hints without a coverage field.
        let dir = TempDir::new().expect("temp workspace should be created");
        persist_libmatch_findings(
            &dir,
            vec![libmatch_finding(
                "FUN_18003e750",
                "memcpy",
                calxgloss_libmatch::types::LibraryFamily::Crt,
            )],
        );
        let bundle = gather_function_evidence(
            Some(dir.path()),
            "eqmain.dll",
            "FUN_18003ab00",
            &["FUN_18003e750".to_string()],
        );
        assert!(
            !bundle.libmatch_findings.is_empty()
                && bundle.libmatch_coverage.status.is_empty()
                && bundle.libmatch_coverage.admission.is_empty(),
            "a pre-P19 document fills hints but no coverage — the old render stands"
        );

        // Missing and corrupt: neither hint nor coverage.
        let dir = TempDir::new().expect("temp workspace should be created");
        let bundle = gather_function_evidence(
            Some(dir.path()),
            "eqmain.dll",
            "FUN_18003ab00",
            &["FUN_18003e750".to_string()],
        );
        assert!(
            bundle.libmatch_findings.is_empty() && bundle.libmatch_coverage.admission.is_empty(),
            "a missing libmatch document fills neither hints nor coverage"
        );
        let dir = TempDir::new().expect("temp workspace should be created");
        corrupt_at(
            calxgloss_libmatch::persist::LibmatchPersistor::new(dir.path()).path_for("eqmain.dll"),
        );
        let bundle = gather_function_evidence(
            Some(dir.path()),
            "eqmain.dll",
            "FUN_18003ab00",
            &["FUN_18003e750".to_string()],
        );
        assert!(
            bundle.libmatch_findings.is_empty() && bundle.libmatch_coverage.admission.is_empty(),
            "a corrupt libmatch document fills neither hints nor coverage"
        );
    }

    /// The memory row's coverage leg end to end (issue #349): the record the
    /// memory scan stamps into its filed document is carried through one
    /// gather into the bundle beside the findings, word for word; a document
    /// filed before coverage stamping fills nothing; and a missing or corrupt
    /// document fills nothing and degrades exactly as its findings do.
    #[test]
    fn the_memory_row_gathers_the_documents_coverage_beside_its_findings() {
        // The engine's own stamp: its one bodies facet fell short, naming
        // the bodies the decompiler never produced.
        let stamp = calxgloss_types::ScanCoverage {
            status: calxgloss_types::CoverageStatus::Partial,
            facets: vec![calxgloss_types::FacetCoverage {
                id: "function-bodies".to_string(),
                status: calxgloss_types::CoverageStatus::Partial,
                limitation: Some(
                    "2 function bodies unreached: FUN_1800412a0, FUN_180049abc".to_string(),
                ),
            }],
        };

        let dir = TempDir::new().expect("temp workspace should be created");
        let mut metadata = ScanMetadata::new("eqmain.dll");
        metadata.coverage = Some(stamp);
        let mut result = calxgloss_memory::types::MemoryResult::new(metadata);
        result.findings = vec![calxgloss_memory::types::MemoryFinding::Allocation(
            allocation_hint("FUN_18003ab00", "Box<T>"),
        )];
        calxgloss_memory::persist::MemoryPersistor::new(dir.path())
            .save(&result)
            .expect("the stamped memory result should be saved");

        let bundle = gather_function_evidence(Some(dir.path()), "eqmain.dll", "FUN_18003ab00", &[]);
        assert_eq!(
            bundle.memory_findings.len(),
            1,
            "the findings still land in their ordinary row"
        );
        assert_eq!(bundle.memory_coverage.status, "partial");
        assert_eq!(
            bundle.memory_coverage.admission,
            "partial — 2 function bodies unreached: FUN_1800412a0, FUN_180049abc",
            "the admission reaches the bundle exactly as the shared type words it"
        );

        // A document filed before the coverage record shipped (the
        // standing kit's shape): the field stays default-empty.
        let dir = TempDir::new().expect("temp workspace should be created");
        persist_findings(
            &dir,
            vec![calxgloss_memory::types::MemoryFinding::Allocation(
                allocation_hint("FUN_18003ab00", "Box<T>"),
            )],
        );
        let bundle = gather_function_evidence(Some(dir.path()), "eqmain.dll", "FUN_18003ab00", &[]);
        assert!(
            !bundle.memory_findings.is_empty()
                && bundle.memory_coverage.status.is_empty()
                && bundle.memory_coverage.admission.is_empty(),
            "a pre-P19 document fills findings but no coverage — the old render stands"
        );

        // Missing and corrupt: neither findings nor coverage.
        let dir = TempDir::new().expect("temp workspace should be created");
        let bundle = gather_function_evidence(Some(dir.path()), "eqmain.dll", "FUN_18003ab00", &[]);
        assert!(
            bundle.memory_findings.is_empty() && bundle.memory_coverage.admission.is_empty(),
            "a missing memory document fills neither findings nor coverage"
        );
        let dir = TempDir::new().expect("temp workspace should be created");
        corrupt_at(
            calxgloss_memory::persist::MemoryPersistor::new(dir.path()).path_for("eqmain.dll"),
        );
        let bundle = gather_function_evidence(Some(dir.path()), "eqmain.dll", "FUN_18003ab00", &[]);
        assert!(
            bundle.memory_findings.is_empty() && bundle.memory_coverage.admission.is_empty(),
            "a corrupt memory document fills neither findings nor coverage"
        );
    }

    /// The concurrency row's coverage leg end to end (issue #349): the record
    /// the sync scan stamps into its filed document is carried through one
    /// gather into the bundle beside the findings, word for word; a document
    /// filed before coverage stamping fills nothing; and a missing or corrupt
    /// document fills nothing and degrades exactly as its findings do.
    #[test]
    fn the_sync_row_gathers_the_documents_coverage_beside_its_findings() {
        // The engine's own stamp: its one bodies facet fell short, naming
        // the bodies the decompiler never produced.
        let stamp = calxgloss_types::ScanCoverage {
            status: calxgloss_types::CoverageStatus::Partial,
            facets: vec![calxgloss_types::FacetCoverage {
                id: "function-bodies".to_string(),
                status: calxgloss_types::CoverageStatus::Partial,
                limitation: Some(
                    "2 function bodies unreached: FUN_1800412a0, FUN_180049abc".to_string(),
                ),
            }],
        };

        let dir = TempDir::new().expect("temp workspace should be created");
        let mut metadata = ScanMetadata::new("eqmain.dll");
        metadata.coverage = Some(stamp);
        let mut result = calxgloss_sync::types::SyncResult::new(metadata);
        result.findings = vec![calxgloss_sync::types::SyncFinding::Mutex(mutex_hint(
            "FUN_18003ab00",
            "std::sync::Mutex",
        ))];
        calxgloss_sync::persist::SyncPersistor::new(dir.path())
            .save(&result)
            .expect("the stamped concurrency result should be saved");

        let bundle = gather_function_evidence(Some(dir.path()), "eqmain.dll", "FUN_18003ab00", &[]);
        assert_eq!(
            bundle.concurrency_findings.len(),
            1,
            "the findings still land in their ordinary row"
        );
        assert_eq!(bundle.sync_coverage.status, "partial");
        assert_eq!(
            bundle.sync_coverage.admission,
            "partial — 2 function bodies unreached: FUN_1800412a0, FUN_180049abc",
            "the admission reaches the bundle exactly as the shared type words it"
        );

        // A document filed before the coverage record shipped (the
        // standing kit's shape): the field stays default-empty.
        let dir = TempDir::new().expect("temp workspace should be created");
        persist_sync_findings(
            &dir,
            vec![calxgloss_sync::types::SyncFinding::Mutex(mutex_hint(
                "FUN_18003ab00",
                "std::sync::Mutex",
            ))],
        );
        let bundle = gather_function_evidence(Some(dir.path()), "eqmain.dll", "FUN_18003ab00", &[]);
        assert!(
            !bundle.concurrency_findings.is_empty()
                && bundle.sync_coverage.status.is_empty()
                && bundle.sync_coverage.admission.is_empty(),
            "a pre-P19 document fills findings but no coverage — the old render stands"
        );

        // Missing and corrupt: neither findings nor coverage.
        let dir = TempDir::new().expect("temp workspace should be created");
        let bundle = gather_function_evidence(Some(dir.path()), "eqmain.dll", "FUN_18003ab00", &[]);
        assert!(
            bundle.concurrency_findings.is_empty() && bundle.sync_coverage.admission.is_empty(),
            "a missing concurrency document fills neither findings nor coverage"
        );
        let dir = TempDir::new().expect("temp workspace should be created");
        corrupt_at(calxgloss_sync::persist::SyncPersistor::new(dir.path()).path_for("eqmain.dll"));
        let bundle = gather_function_evidence(Some(dir.path()), "eqmain.dll", "FUN_18003ab00", &[]);
        assert!(
            bundle.concurrency_findings.is_empty() && bundle.sync_coverage.admission.is_empty(),
            "a corrupt concurrency document fills neither findings nor coverage"
        );
    }

    /// The control-flow row's coverage leg end to end (issue #349): the
    /// record the control-flow scan stamps into its filed document is carried
    /// through one gather into the bundle beside the findings, word for word;
    /// a document filed before coverage stamping fills nothing; and a missing
    /// or corrupt document fills nothing and degrades exactly as its findings
    /// do.
    #[test]
    fn the_control_flow_row_gathers_the_documents_coverage_beside_its_findings() {
        // The engine's own stamp: its one bodies facet fell short, naming
        // the bodies the decompiler never produced.
        let stamp = calxgloss_types::ScanCoverage {
            status: calxgloss_types::CoverageStatus::Partial,
            facets: vec![calxgloss_types::FacetCoverage {
                id: "function-bodies".to_string(),
                status: calxgloss_types::CoverageStatus::Partial,
                limitation: Some(
                    "2 function bodies unreached: FUN_1800412a0, FUN_180049abc".to_string(),
                ),
            }],
        };

        let dir = TempDir::new().expect("temp workspace should be created");
        let mut metadata = ScanMetadata::new("eqmain.dll");
        metadata.coverage = Some(stamp);
        let mut result = calxgloss_controlflow::types::ControlFlowResult::new(metadata);
        result.findings = vec![switch_hint("FUN_18003ab00")];
        calxgloss_controlflow::persist::ControlFlowPersistor::new(dir.path())
            .save(&result)
            .expect("the stamped control-flow result should be saved");

        let bundle = gather_function_evidence(Some(dir.path()), "eqmain.dll", "FUN_18003ab00", &[]);
        assert_eq!(
            bundle.control_flow_findings.len(),
            1,
            "the findings still land in their ordinary row"
        );
        assert_eq!(bundle.control_flow_coverage.status, "partial");
        assert_eq!(
            bundle.control_flow_coverage.admission,
            "partial — 2 function bodies unreached: FUN_1800412a0, FUN_180049abc",
            "the admission reaches the bundle exactly as the shared type words it"
        );

        // A document filed before the coverage record shipped (the
        // standing kit's shape): the field stays default-empty.
        let dir = TempDir::new().expect("temp workspace should be created");
        persist_controlflow_findings(&dir, vec![switch_hint("FUN_18003ab00")]);
        let bundle = gather_function_evidence(Some(dir.path()), "eqmain.dll", "FUN_18003ab00", &[]);
        assert!(
            !bundle.control_flow_findings.is_empty()
                && bundle.control_flow_coverage.status.is_empty()
                && bundle.control_flow_coverage.admission.is_empty(),
            "a pre-P19 document fills findings but no coverage — the old render stands"
        );

        // Missing and corrupt: neither findings nor coverage.
        let dir = TempDir::new().expect("temp workspace should be created");
        let bundle = gather_function_evidence(Some(dir.path()), "eqmain.dll", "FUN_18003ab00", &[]);
        assert!(
            bundle.control_flow_findings.is_empty()
                && bundle.control_flow_coverage.admission.is_empty(),
            "a missing control-flow document fills neither findings nor coverage"
        );
        let dir = TempDir::new().expect("temp workspace should be created");
        corrupt_at(
            calxgloss_controlflow::persist::ControlFlowPersistor::new(dir.path())
                .path_for("eqmain.dll"),
        );
        let bundle = gather_function_evidence(Some(dir.path()), "eqmain.dll", "FUN_18003ab00", &[]);
        assert!(
            bundle.control_flow_findings.is_empty()
                && bundle.control_flow_coverage.admission.is_empty(),
            "a corrupt control-flow document fills neither findings nor coverage"
        );
    }

    /// The global-state row's coverage leg end to end (issue #350): the
    /// record the global-state scan stamps into its filed document is carried
    /// through one gather into the bundle beside the access records, word for
    /// word; a document filed before coverage stamping fills nothing; and a
    /// missing or corrupt document fills nothing and degrades exactly as its
    /// findings do.
    #[test]
    fn the_global_state_row_gathers_the_documents_coverage_beside_its_records() {
        // The engine's own stamp: its one bodies facet fell short, naming
        // the bodies the decompiler never produced.
        let stamp = calxgloss_types::ScanCoverage {
            status: calxgloss_types::CoverageStatus::Partial,
            facets: vec![calxgloss_types::FacetCoverage {
                id: "function-bodies".to_string(),
                status: calxgloss_types::CoverageStatus::Partial,
                limitation: Some("1 function body unreached: FUN_180045670".to_string()),
            }],
        };

        let dir = TempDir::new().expect("temp workspace should be created");
        let mut metadata = ScanMetadata::new("eqmain.dll");
        metadata.coverage = Some(stamp);
        let mut result = calxgloss_globalstate::types::GlobalStateResult::new(metadata);
        result.findings = vec![global_write("FUN_18003ab00", "DAT_180064e80")];
        calxgloss_globalstate::persist::GlobalStatePersistor::new(dir.path())
            .save(&result)
            .expect("the stamped global-state result should be saved");

        let bundle = gather_function_evidence(Some(dir.path()), "eqmain.dll", "FUN_18003ab00", &[]);
        assert_eq!(
            bundle.global_state_findings.len(),
            1,
            "the access records still land in their ordinary row"
        );
        assert_eq!(bundle.global_state_coverage.status, "partial");
        assert_eq!(
            bundle.global_state_coverage.admission,
            "partial — 1 function body unreached: FUN_180045670",
            "the admission reaches the bundle exactly as the shared type words it"
        );

        // A document filed before the coverage record shipped (the
        // standing kit's shape): the field stays default-empty.
        let dir = TempDir::new().expect("temp workspace should be created");
        persist_globalstate_findings(&dir, vec![global_write("FUN_18003ab00", "DAT_180064e80")]);
        let bundle = gather_function_evidence(Some(dir.path()), "eqmain.dll", "FUN_18003ab00", &[]);
        assert!(
            !bundle.global_state_findings.is_empty()
                && bundle.global_state_coverage.status.is_empty()
                && bundle.global_state_coverage.admission.is_empty(),
            "a pre-P19 document fills findings but no coverage — the old render stands"
        );

        // Missing and corrupt: neither findings nor coverage.
        let dir = TempDir::new().expect("temp workspace should be created");
        let bundle = gather_function_evidence(Some(dir.path()), "eqmain.dll", "FUN_18003ab00", &[]);
        assert!(
            bundle.global_state_findings.is_empty()
                && bundle.global_state_coverage.admission.is_empty(),
            "a missing global-state document fills neither findings nor coverage"
        );
        let dir = TempDir::new().expect("temp workspace should be created");
        corrupt_at(
            calxgloss_globalstate::persist::GlobalStatePersistor::new(dir.path())
                .path_for("eqmain.dll"),
        );
        let bundle = gather_function_evidence(Some(dir.path()), "eqmain.dll", "FUN_18003ab00", &[]);
        assert!(
            bundle.global_state_findings.is_empty()
                && bundle.global_state_coverage.admission.is_empty(),
            "a corrupt global-state document fills neither findings nor coverage"
        );
    }

    /// The error-handling row's coverage leg end to end (issue #350): the
    /// record the error-handling scan stamps into its filed document is
    /// carried through one gather into the bundle beside the idiom and code
    /// findings, word for word; a document filed before coverage stamping
    /// fills nothing; and a missing or corrupt document fills nothing and
    /// degrades exactly as its findings do.
    #[test]
    fn the_error_handling_row_gathers_the_documents_coverage_beside_its_findings() {
        let stamp = calxgloss_types::ScanCoverage {
            status: calxgloss_types::CoverageStatus::Partial,
            facets: vec![calxgloss_types::FacetCoverage {
                id: "function-bodies".to_string(),
                status: calxgloss_types::CoverageStatus::Partial,
                limitation: Some(
                    "2 function bodies unreached: FUN_18004abcd, FUN_18006beef".to_string(),
                ),
            }],
        };

        let dir = TempDir::new().expect("temp workspace should be created");
        let mut metadata = ScanMetadata::new("eqmain.dll");
        metadata.coverage = Some(stamp);
        let mut result = calxgloss_errhandling::types::ErrhandlingResult::new(metadata);
        result.findings = vec![seh_finding("FUN_18003ab00")];
        calxgloss_errhandling::persist::ErrhandlingPersistor::new(dir.path())
            .save(&result)
            .expect("the stamped error-handling result should be saved");

        let bundle = gather_function_evidence(Some(dir.path()), "eqmain.dll", "FUN_18003ab00", &[]);
        assert_eq!(
            bundle.error_handling_findings.len(),
            1,
            "the findings still land in their ordinary row"
        );
        assert_eq!(bundle.error_handling_coverage.status, "partial");
        assert_eq!(
            bundle.error_handling_coverage.admission,
            "partial — 2 function bodies unreached: FUN_18004abcd, FUN_18006beef",
            "the admission reaches the bundle exactly as the shared type words it"
        );

        // A document filed before the coverage record shipped (the
        // standing kit's shape): the field stays default-empty.
        let dir = TempDir::new().expect("temp workspace should be created");
        persist_errhandling_findings(&dir, vec![seh_finding("FUN_18003ab00")]);
        let bundle = gather_function_evidence(Some(dir.path()), "eqmain.dll", "FUN_18003ab00", &[]);
        assert!(
            !bundle.error_handling_findings.is_empty()
                && bundle.error_handling_coverage.status.is_empty()
                && bundle.error_handling_coverage.admission.is_empty(),
            "a pre-P19 document fills findings but no coverage — the old render stands"
        );

        // Missing and corrupt: neither findings nor coverage.
        let dir = TempDir::new().expect("temp workspace should be created");
        let bundle = gather_function_evidence(Some(dir.path()), "eqmain.dll", "FUN_18003ab00", &[]);
        assert!(
            bundle.error_handling_findings.is_empty()
                && bundle.error_handling_coverage.admission.is_empty(),
            "a missing error-handling document fills neither findings nor coverage"
        );
        let dir = TempDir::new().expect("temp workspace should be created");
        corrupt_at(
            calxgloss_errhandling::persist::ErrhandlingPersistor::new(dir.path())
                .path_for("eqmain.dll"),
        );
        let bundle = gather_function_evidence(Some(dir.path()), "eqmain.dll", "FUN_18003ab00", &[]);
        assert!(
            bundle.error_handling_findings.is_empty()
                && bundle.error_handling_coverage.admission.is_empty(),
            "a corrupt error-handling document fills neither findings nor coverage"
        );
    }

    /// The callback row's coverage leg end to end (issue #350): the record
    /// the callback-detection scan stamps into its filed document is carried
    /// through one gather into the bundle beside the findings, word for word;
    /// a document filed before coverage stamping fills nothing; and a missing
    /// or corrupt document fills nothing and degrades exactly as its findings
    /// do.
    #[test]
    fn the_callback_row_gathers_the_documents_coverage_beside_its_findings() {
        let stamp = calxgloss_types::ScanCoverage {
            status: calxgloss_types::CoverageStatus::Partial,
            facets: vec![calxgloss_types::FacetCoverage {
                id: "function-bodies".to_string(),
                status: calxgloss_types::CoverageStatus::Partial,
                limitation: Some("1 function body unreached: FUN_180050001".to_string()),
            }],
        };

        let dir = TempDir::new().expect("temp workspace should be created");
        let mut metadata = ScanMetadata::new("eqmain.dll");
        metadata.coverage = Some(stamp);
        let mut result = calxgloss_callback::types::CallbackResult::new(metadata);
        result.findings = vec![fp_array_hint("FUN_18003ab00")];
        calxgloss_callback::persist::CallbackPersistor::new(dir.path())
            .save(&result)
            .expect("the stamped callback result should be saved");

        let bundle = gather_function_evidence(Some(dir.path()), "eqmain.dll", "FUN_18003ab00", &[]);
        assert_eq!(
            bundle.callback_findings.len(),
            1,
            "the findings still land in their ordinary row"
        );
        assert_eq!(bundle.callback_coverage.status, "partial");
        assert_eq!(
            bundle.callback_coverage.admission,
            "partial — 1 function body unreached: FUN_180050001",
            "the admission reaches the bundle exactly as the shared type words it"
        );

        // A document filed before the coverage record shipped (the
        // standing kit's shape): the field stays default-empty.
        let dir = TempDir::new().expect("temp workspace should be created");
        persist_callback_findings(&dir, vec![fp_array_hint("FUN_18003ab00")]);
        let bundle = gather_function_evidence(Some(dir.path()), "eqmain.dll", "FUN_18003ab00", &[]);
        assert!(
            !bundle.callback_findings.is_empty()
                && bundle.callback_coverage.status.is_empty()
                && bundle.callback_coverage.admission.is_empty(),
            "a pre-P19 document fills findings but no coverage — the old render stands"
        );

        // Missing and corrupt: neither findings nor coverage.
        let dir = TempDir::new().expect("temp workspace should be created");
        let bundle = gather_function_evidence(Some(dir.path()), "eqmain.dll", "FUN_18003ab00", &[]);
        assert!(
            bundle.callback_findings.is_empty() && bundle.callback_coverage.admission.is_empty(),
            "a missing callback document fills neither findings nor coverage"
        );
        let dir = TempDir::new().expect("temp workspace should be created");
        corrupt_at(
            calxgloss_callback::persist::CallbackPersistor::new(dir.path()).path_for("eqmain.dll"),
        );
        let bundle = gather_function_evidence(Some(dir.path()), "eqmain.dll", "FUN_18003ab00", &[]);
        assert!(
            bundle.callback_findings.is_empty() && bundle.callback_coverage.admission.is_empty(),
            "a corrupt callback document fills neither findings nor coverage"
        );
    }

    /// The algorithm-recognition row's coverage leg end to end (issue #351):
    /// the two-facet record the scan stamps into its filed document — bodies
    /// it never read and caller edges it could not pull — is carried through
    /// one gather into the bundle beside the hints, word for word; a document
    /// filed before coverage stamping fills nothing; and a missing or corrupt
    /// document fills nothing and degrades exactly as its findings do.
    #[test]
    fn the_algorithm_row_gathers_the_documents_coverage_beside_its_hints() {
        // The engine's own stamp: its bodies facet fell short, naming the
        // body the decompiler never produced, and its caller-edge facet
        // could read no edge for the function it tried.
        let stamp = calxgloss_types::ScanCoverage {
            status: calxgloss_types::CoverageStatus::Partial,
            facets: vec![
                calxgloss_types::FacetCoverage {
                    id: "function-bodies".to_string(),
                    status: calxgloss_types::CoverageStatus::Partial,
                    limitation: Some("1 function body unreached: FUN_180070010".to_string()),
                },
                calxgloss_types::FacetCoverage {
                    id: "caller-edges".to_string(),
                    status: calxgloss_types::CoverageStatus::Unavailable,
                    limitation: Some("1 caller edge unreadable: FUN_180070020".to_string()),
                },
            ],
        };

        let dir = TempDir::new().expect("temp workspace should be created");
        let mut metadata = ScanMetadata::new("eqmain.dll");
        metadata.coverage = Some(stamp);
        let mut result = calxgloss_algorithm::types::AlgorithmRecognitionResult::new(metadata);
        result.hints = vec![algorithm_hint("FUN_18003ab00", "CRC-32")];
        calxgloss_algorithm::persist::AlgorithmPersistor::new(dir.path())
            .save(&result)
            .expect("the stamped algorithm result should be saved");

        let bundle = gather_function_evidence(Some(dir.path()), "eqmain.dll", "FUN_18003ab00", &[]);
        assert_eq!(
            bundle.recognized_algorithms.len(),
            1,
            "the hints still land in their ordinary row"
        );
        assert_eq!(bundle.algorithm_coverage.status, "partial");
        assert_eq!(
            bundle.algorithm_coverage.admission,
            "partial — 1 function body unreached: FUN_180070010; \
             1 caller edge unreadable: FUN_180070020",
            "both short facets admit in the record's own order, word for word"
        );

        // A document filed before the coverage record shipped (the
        // standing kit's shape): the field stays default-empty.
        let dir = TempDir::new().expect("temp workspace should be created");
        persist_hints(&dir, vec![algorithm_hint("FUN_18003ab00", "CRC-32")]);
        let bundle = gather_function_evidence(Some(dir.path()), "eqmain.dll", "FUN_18003ab00", &[]);
        assert!(
            !bundle.recognized_algorithms.is_empty()
                && bundle.algorithm_coverage.status.is_empty()
                && bundle.algorithm_coverage.admission.is_empty(),
            "a pre-P19 document fills hints but no coverage — the old render stands"
        );

        // Missing and corrupt: neither hints nor coverage.
        let dir = TempDir::new().expect("temp workspace should be created");
        let bundle = gather_function_evidence(Some(dir.path()), "eqmain.dll", "FUN_18003ab00", &[]);
        assert!(
            bundle.recognized_algorithms.is_empty()
                && bundle.algorithm_coverage.admission.is_empty(),
            "a missing algorithm document fills neither hints nor coverage"
        );
        let dir = TempDir::new().expect("temp workspace should be created");
        corrupt_at(
            calxgloss_algorithm::persist::AlgorithmPersistor::new(dir.path())
                .path_for("eqmain.dll"),
        );
        let bundle = gather_function_evidence(Some(dir.path()), "eqmain.dll", "FUN_18003ab00", &[]);
        assert!(
            bundle.recognized_algorithms.is_empty()
                && bundle.algorithm_coverage.admission.is_empty(),
            "a corrupt algorithm document fills neither hints nor coverage"
        );
    }

    /// The gather's residue leg (issue #369): documents admitted `partial`
    /// and `unavailable` facets for this unit become one unknown record
    /// each, returned in the fold's scan order — the libmatch document read
    /// outside the seam first, then the folded rows — while the bundle
    /// itself is exactly what the plain gather assembles. A complete facet
    /// and a pre-P19 document derive nothing.
    #[test]
    fn the_gather_returns_coverage_residue_for_every_admitted_shortfall() {
        let dir = TempDir::new().expect("temp workspace should be created");

        // The algorithm document, stamped exactly as the #347 pin stamps
        // it: one `partial` facet with a limitation line and one
        // `unavailable` facet beside a `complete` one.
        let mut metadata = ScanMetadata::new("eqmain.dll");
        metadata.coverage = Some(calxgloss_types::ScanCoverage {
            status: calxgloss_types::CoverageStatus::Partial,
            facets: vec![
                calxgloss_types::FacetCoverage {
                    id: "function-bodies".to_string(),
                    status: calxgloss_types::CoverageStatus::Partial,
                    limitation: Some("1 function body unreached: FUN_180070010".to_string()),
                },
                calxgloss_types::FacetCoverage {
                    id: "caller-edges".to_string(),
                    status: calxgloss_types::CoverageStatus::Unavailable,
                    limitation: None,
                },
                calxgloss_types::FacetCoverage {
                    id: "constant-signatures".to_string(),
                    status: calxgloss_types::CoverageStatus::Complete,
                    limitation: None,
                },
            ],
        });
        let mut result = calxgloss_algorithm::types::AlgorithmRecognitionResult::new(metadata);
        result.hints = vec![algorithm_hint("FUN_18003ab00", "CRC-32")];
        calxgloss_algorithm::persist::AlgorithmPersistor::new(dir.path())
            .save(&result)
            .expect("the stamped algorithm result should be saved");

        // The libmatch document, read outside the fold but admitted by
        // the same gather: one facet it could not examine at all.
        let mut metadata = ScanMetadata::new("eqmain.dll");
        metadata.coverage = Some(calxgloss_types::ScanCoverage {
            status: calxgloss_types::CoverageStatus::Partial,
            facets: vec![
                calxgloss_types::FacetCoverage {
                    id: "function-bodies".to_string(),
                    status: calxgloss_types::CoverageStatus::Unavailable,
                    limitation: Some("the matcher read no body".to_string()),
                },
                calxgloss_types::FacetCoverage {
                    id: "callee-signatures".to_string(),
                    status: calxgloss_types::CoverageStatus::Complete,
                    limitation: None,
                },
            ],
        });
        let libmatch = calxgloss_libmatch::types::LibmatchResult::new(metadata);
        calxgloss_libmatch::persist::LibmatchPersistor::new(dir.path())
            .save(&libmatch)
            .expect("the stamped libmatch result should be saved");

        let (bundle, residue) =
            gather_function_evidence_residue(Some(dir.path()), "eqmain.dll", "FUN_18003ab00", &[]);
        assert_eq!(
            bundle.recognized_algorithms.len(),
            1,
            "the residue leg never disturbs the bundle"
        );
        assert_eq!(bundle.algorithm_coverage.status, "partial");

        let slots: Vec<String> = residue.iter().map(|r| r.source_slot()).collect();
        assert_eq!(
            slots,
            vec![
                // libmatch reads first, outside the seam — hence first.
                "known-library result#function-bodies",
                // Then the folded rows in table order, and each coverage
                // record's own facet order.
                "algorithm recognition result#function-bodies",
                "algorithm recognition result#caller-edges",
            ],
            "the admitted shortfalls derive in the fold's scan order"
        );
        assert_eq!(
            residue[0].id,
            "eqmain.dll/FUN_18003ab00/coverage_facet/known-library result#function-bodies",
            "the function-scoped id names the document and the facet"
        );
        assert_eq!(
            residue[1].severity,
            calxgloss_types::UnknownSeverity::Material,
            "partial by its own admission"
        );
        assert_eq!(
            residue[2].severity,
            calxgloss_types::UnknownSeverity::Blocking,
            "unavailable: the evidence never arrived at all"
        );

        // The plain gather sees the same bundle and keeps no residue of
        // its own — the caller that does not want the records loses
        // nothing.
        let plain = gather_function_evidence(Some(dir.path()), "eqmain.dll", "FUN_18003ab00", &[]);
        assert_eq!(plain.libmatch_coverage, bundle.libmatch_coverage);
        assert_eq!(plain.algorithm_coverage, bundle.algorithm_coverage);
    }

    /// A pre-P19 document — no coverage entry at all — contributes no
    /// residue: absence never produces a gap record (issue #369), at the
    /// gather exactly as at the fold.
    #[test]
    fn a_gather_over_pre_p19_documents_derives_no_residue() {
        let dir = TempDir::new().expect("temp workspace should be created");
        persist_hints(&dir, vec![algorithm_hint("FUN_18003ab00", "CRC-32")]);
        persist_libmatch_findings(
            &dir,
            vec![libmatch_finding(
                "malloc",
                "free",
                calxgloss_libmatch::types::LibraryFamily::Crt,
            )],
        );

        let (_, residue) =
            gather_function_evidence_residue(Some(dir.path()), "eqmain.dll", "FUN_18003ab00", &[]);
        assert!(
            residue.is_empty(),
            "documents stating no coverage leave nothing for the ledger to derive: {residue:?}"
        );
    }

    /// The string-context row's coverage leg end to end (issue #351): the
    /// three-facet record the scan stamps — bodies it never read, a string
    /// listing that never arrived, and cross-reference lookups that refused —
    /// is carried through one gather into the bundle beside the strings, word
    /// for word; a pre-P19 document fills nothing; and a missing or corrupt
    /// document fills nothing and degrades exactly as its findings do.
    #[test]
    fn the_string_context_row_gathers_the_documents_coverage_beside_its_findings() {
        let stamp = calxgloss_types::ScanCoverage {
            status: calxgloss_types::CoverageStatus::Partial,
            facets: vec![
                calxgloss_types::FacetCoverage {
                    id: "function-bodies".to_string(),
                    status: calxgloss_types::CoverageStatus::Partial,
                    limitation: Some("1 function body unreached: FUN_180061000".to_string()),
                },
                calxgloss_types::FacetCoverage {
                    id: "program-strings".to_string(),
                    status: calxgloss_types::CoverageStatus::Unavailable,
                    limitation: Some("program string listing unreadable".to_string()),
                },
                calxgloss_types::FacetCoverage {
                    id: "string-xrefs".to_string(),
                    status: calxgloss_types::CoverageStatus::Unavailable,
                    limitation: Some("no string cross-reference could be read".to_string()),
                },
            ],
        };

        let dir = TempDir::new().expect("temp workspace should be created");
        let mut metadata = ScanMetadata::new("eqmain.dll");
        metadata.coverage = Some(stamp);
        let mut result = calxgloss_stringctx::types::StringContextResult::new(metadata);
        result.findings = vec![classified_string(
            "FUN_18003ab00",
            "Journal.txt",
            "config file path",
        )];
        calxgloss_stringctx::persist::StringContextPersistor::new(dir.path())
            .save(&result)
            .expect("the stamped string-context result should be saved");

        let bundle = gather_function_evidence(Some(dir.path()), "eqmain.dll", "FUN_18003ab00", &[]);
        assert_eq!(
            bundle.string_findings.len(),
            1,
            "the strings still land in their ordinary row"
        );
        assert_eq!(bundle.string_context_coverage.status, "partial");
        assert_eq!(
            bundle.string_context_coverage.admission,
            "partial — 1 function body unreached: FUN_180061000; \
             program string listing unreadable; \
             no string cross-reference could be read",
            "all three short facets admit in the record's own order, word for word"
        );

        // A document filed before the coverage record shipped (the
        // standing kit's shape): the field stays default-empty.
        let dir = TempDir::new().expect("temp workspace should be created");
        let mut result =
            calxgloss_stringctx::types::StringContextResult::new(ScanMetadata::new("eqmain.dll"));
        result.findings = vec![classified_string(
            "FUN_18003ab00",
            "Journal.txt",
            "config file path",
        )];
        calxgloss_stringctx::persist::StringContextPersistor::new(dir.path())
            .save(&result)
            .expect("the pre-P19 string-context result should be saved");
        let bundle = gather_function_evidence(Some(dir.path()), "eqmain.dll", "FUN_18003ab00", &[]);
        assert!(
            !bundle.string_findings.is_empty()
                && bundle.string_context_coverage.status.is_empty()
                && bundle.string_context_coverage.admission.is_empty(),
            "a pre-P19 document fills findings but no coverage — the old render stands"
        );

        // Missing and corrupt: neither findings nor coverage.
        let dir = TempDir::new().expect("temp workspace should be created");
        let bundle = gather_function_evidence(Some(dir.path()), "eqmain.dll", "FUN_18003ab00", &[]);
        assert!(
            bundle.string_findings.is_empty()
                && bundle.string_context_coverage.admission.is_empty(),
            "a missing string-context document fills neither findings nor coverage"
        );
        let dir = TempDir::new().expect("temp workspace should be created");
        corrupt_at(
            calxgloss_stringctx::persist::StringContextPersistor::new(dir.path())
                .path_for("eqmain.dll"),
        );
        let bundle = gather_function_evidence(Some(dir.path()), "eqmain.dll", "FUN_18003ab00", &[]);
        assert!(
            bundle.string_findings.is_empty()
                && bundle.string_context_coverage.admission.is_empty(),
            "a corrupt string-context document fills neither findings nor coverage"
        );
    }

    /// The serialization row's coverage leg end to end (issue #351): the
    /// record the scan stamps into its filed document is carried through one
    /// gather into the bundle beside the findings, word for word; a document
    /// filed before coverage stamping fills nothing; and a missing or corrupt
    /// document fills nothing and degrades exactly as its findings do.
    #[test]
    fn the_serialization_row_gathers_the_documents_coverage_beside_its_findings() {
        let stamp = calxgloss_types::ScanCoverage {
            status: calxgloss_types::CoverageStatus::Partial,
            facets: vec![calxgloss_types::FacetCoverage {
                id: "function-bodies".to_string(),
                status: calxgloss_types::CoverageStatus::Partial,
                limitation: Some("1 function body unreached: FUN_180099900".to_string()),
            }],
        };

        let dir = TempDir::new().expect("temp workspace should be created");
        let mut metadata = ScanMetadata::new("eqmain.dll");
        metadata.coverage = Some(stamp);
        let mut result = calxgloss_serialize::types::SerializeResult::new(metadata);
        result.findings = vec![swap_record("FUN_18003ab00")];
        calxgloss_serialize::persist::SerializePersistor::new(dir.path())
            .save(&result)
            .expect("the stamped serialization result should be saved");

        let bundle = gather_function_evidence(Some(dir.path()), "eqmain.dll", "FUN_18003ab00", &[]);
        assert_eq!(
            bundle.serialization_findings.len(),
            1,
            "the findings still land in their ordinary row"
        );
        assert_eq!(bundle.serialization_coverage.status, "partial");
        assert_eq!(
            bundle.serialization_coverage.admission,
            "partial — 1 function body unreached: FUN_180099900",
            "the admission reaches the bundle exactly as the shared type words it"
        );

        // A document filed before the coverage record shipped (the
        // standing kit's shape): the field stays default-empty.
        let dir = TempDir::new().expect("temp workspace should be created");
        persist_serialize_findings(&dir, vec![swap_record("FUN_18003ab00")]);
        let bundle = gather_function_evidence(Some(dir.path()), "eqmain.dll", "FUN_18003ab00", &[]);
        assert!(
            !bundle.serialization_findings.is_empty()
                && bundle.serialization_coverage.status.is_empty()
                && bundle.serialization_coverage.admission.is_empty(),
            "a pre-P19 document fills findings but no coverage — the old render stands"
        );

        // Missing and corrupt: neither findings nor coverage.
        let dir = TempDir::new().expect("temp workspace should be created");
        let bundle = gather_function_evidence(Some(dir.path()), "eqmain.dll", "FUN_18003ab00", &[]);
        assert!(
            bundle.serialization_findings.is_empty()
                && bundle.serialization_coverage.admission.is_empty(),
            "a missing serialization document fills neither findings nor coverage"
        );
        let dir = TempDir::new().expect("temp workspace should be created");
        corrupt_at(
            calxgloss_serialize::persist::SerializePersistor::new(dir.path())
                .path_for("eqmain.dll"),
        );
        let bundle = gather_function_evidence(Some(dir.path()), "eqmain.dll", "FUN_18003ab00", &[]);
        assert!(
            bundle.serialization_findings.is_empty()
                && bundle.serialization_coverage.admission.is_empty(),
            "a corrupt serialization document fills neither findings nor coverage"
        );
    }

    /// The type-inference row's coverage leg end to end (issue #351): the
    /// four-facet record the scan stamps — with its complete bodies facet
    /// dropping out of the admission — is carried through one gather into the
    /// bundle, and the ONE record qualifies all THREE surfaces the row feeds:
    /// the type-information list, the calling-convention list, and the
    /// parameter-direction list all stand beside the same admission line,
    /// word for word; a pre-P19 document fills nothing; and a missing or
    /// corrupt document fills nothing and degrades exactly as its findings
    /// do.
    #[test]
    fn the_type_inference_row_gathers_the_documents_coverage_beside_its_three_surfaces() {
        let stamp = calxgloss_types::ScanCoverage {
            status: calxgloss_types::CoverageStatus::Partial,
            facets: vec![
                calxgloss_types::FacetCoverage {
                    id: "function-bodies".to_string(),
                    status: calxgloss_types::CoverageStatus::Complete,
                    limitation: None,
                },
                calxgloss_types::FacetCoverage {
                    id: "machine-listings".to_string(),
                    status: calxgloss_types::CoverageStatus::Partial,
                    limitation: Some("1 machine listing unreadable: FUN_180088000".to_string()),
                },
                calxgloss_types::FacetCoverage {
                    id: "import-names".to_string(),
                    status: calxgloss_types::CoverageStatus::Unavailable,
                    limitation: Some("import listing unreadable".to_string()),
                },
                calxgloss_types::FacetCoverage {
                    id: "caller-edges".to_string(),
                    status: calxgloss_types::CoverageStatus::Unavailable,
                    limitation: Some("1 caller edge unreadable: FUN_180088010".to_string()),
                },
            ],
        };

        let dir = TempDir::new().expect("temp workspace should be created");
        let mut metadata = ScanMetadata::new("eqmain.dll");
        metadata.coverage = Some(stamp);
        let mut result = calxgloss_typeinfer::types::TypeInferenceResult::new(metadata);
        result.inferences = vec![
            calxgloss_typeinfer::types::InferredType::Param(
                calxgloss_typeinfer::types::InferredParamType {
                    function: "FUN_18003ab00".to_string(),
                    param_index: 0,
                    param_name: Some("param_1".to_string()),
                    inferred_type: "char *".to_string(),
                    method: calxgloss_typeinfer::types::InferenceMethod::StringFunction,
                    scope: calxgloss_typeinfer::types::InferenceScope::Function,
                    confidence: calxgloss_typeinfer::types::Confidence::new(80),
                    evidence: "lstrlenA(param_1)".to_string(),
                },
            ),
            direction_inference(
                "FUN_18003ab00",
                0,
                calxgloss_typeinfer::types::Direction::In,
            ),
        ];
        calxgloss_typeinfer::persist::TypeInferPersistor::new(dir.path())
            .save(&result)
            .expect("the stamped type-inference result should be saved");

        let bundle = gather_function_evidence(Some(dir.path()), "eqmain.dll", "FUN_18003ab00", &[]);
        assert_eq!(
            bundle.type_info.len(),
            2,
            "both readings still land in their ordinary row"
        );
        assert_eq!(
            bundle.parameter_direction_findings.len(),
            1,
            "the direction reading still fans out to its own surface"
        );
        assert_eq!(bundle.type_inference_coverage.status, "partial");
        assert_eq!(
            bundle.type_inference_coverage.admission,
            "partial — 1 machine listing unreadable: FUN_180088000; \
             import listing unreadable; \
             1 caller edge unreadable: FUN_180088010",
            "the complete bodies facet names nothing; the three short \
             facets admit in the record's own order, word for word"
        );

        // A document filed before the coverage record shipped (the
        // standing kit's shape): the field stays default-empty.
        let dir = TempDir::new().expect("temp workspace should be created");
        persist_inferences(
            &dir,
            vec![calxgloss_typeinfer::types::InferredType::Param(
                calxgloss_typeinfer::types::InferredParamType {
                    function: "FUN_18003ab00".to_string(),
                    param_index: 0,
                    param_name: Some("param_1".to_string()),
                    inferred_type: "char *".to_string(),
                    method: calxgloss_typeinfer::types::InferenceMethod::StringFunction,
                    scope: calxgloss_typeinfer::types::InferenceScope::Function,
                    confidence: calxgloss_typeinfer::types::Confidence::new(80),
                    evidence: "lstrlenA(param_1)".to_string(),
                },
            )],
        );
        let bundle = gather_function_evidence(Some(dir.path()), "eqmain.dll", "FUN_18003ab00", &[]);
        assert!(
            !bundle.type_info.is_empty()
                && bundle.type_inference_coverage.status.is_empty()
                && bundle.type_inference_coverage.admission.is_empty(),
            "a pre-P19 document fills inferences but no coverage — the old render stands"
        );

        // Missing and corrupt: neither readings nor coverage.
        let dir = TempDir::new().expect("temp workspace should be created");
        let bundle = gather_function_evidence(Some(dir.path()), "eqmain.dll", "FUN_18003ab00", &[]);
        assert!(
            bundle.type_info.is_empty() && bundle.type_inference_coverage.admission.is_empty(),
            "a missing type-inference document fills neither readings nor coverage"
        );
        let dir = TempDir::new().expect("temp workspace should be created");
        corrupt_at(
            calxgloss_typeinfer::persist::TypeInferPersistor::new(dir.path())
                .path_for("eqmain.dll"),
        );
        let bundle = gather_function_evidence(Some(dir.path()), "eqmain.dll", "FUN_18003ab00", &[]);
        assert!(
            bundle.type_info.is_empty() && bundle.type_inference_coverage.admission.is_empty(),
            "a corrupt type-inference document fills neither readings nor coverage"
        );
    }

    // ---- #355: the seam fold beside the gathered documents --------------

    #[test]
    fn the_fold_carries_one_unavailable_familys_own_line_into_the_bundle() {
        // The fake: a hand-declared report with the imported-APIs family
        // unavailable and its own bounded reason. The fold puts exactly
        // that one admission line on the bundle, beside — never merged
        // with — the document's own api_coverage half.
        let report = calxgloss_types::CapabilityReport {
            families: vec![calxgloss_types::FamilyCapability {
                id: super::IMPORTS_FAMILY.to_string(),
                status: calxgloss_types::AvailabilityStatus::Unavailable,
                reason: Some("Quincunx sessions never open the import table".to_string()),
            }],
        };
        let mut bundle = gather_function_evidence(None, "game_logic.dll", "DrawSprite", &[]);
        super::fold_seam_capability(&report, &mut bundle);
        assert_eq!(
            bundle.api_capability.admission,
            "unavailable — Quincunx sessions never open the import table",
            "the fold carries the seam's own wording, word for word"
        );
        assert!(
            bundle.api_coverage.admission.is_empty(),
            "the seam's word never touches the document's coverage half"
        );
    }

    #[test]
    fn the_fold_leaves_the_bundle_empty_under_answerable_and_undeclared() {
        // Answerable: declared, nothing to admit. Undeclared: reads as
        // unknown, nothing to render. Both leave the bundle exactly as
        // gather left it — the empty view the include renders silently.
        let answerable = calxgloss_types::CapabilityReport {
            families: vec![calxgloss_types::FamilyCapability {
                id: super::IMPORTS_FAMILY.to_string(),
                status: calxgloss_types::AvailabilityStatus::Answerable,
                reason: None,
            }],
        };
        let mut bundle = gather_function_evidence(None, "game_logic.dll", "DrawSprite", &[]);
        super::fold_seam_capability(&answerable, &mut bundle);
        assert!(
            bundle.api_capability.admission.is_empty(),
            "answerable admits nothing"
        );
        assert_eq!(
            bundle.api_capability.status, "answerable",
            "the fold carries the declaration's own word, and the include \
             renders an empty admission as pure silence"
        );

        let undeclared = calxgloss_types::CapabilityReport::default();
        super::fold_seam_capability(&undeclared, &mut bundle);
        assert_eq!(
            bundle.api_capability,
            calxgloss_prompts::CapabilityInfo::default(),
            "an undeclared family folds to silence, never to absence"
        );
    }

    // ---- #357: the capability fan-out to every prompt-fed family --------

    /// The fold's half of the #357 both-ends wording pin: a hand-declared
    /// report unavailable across the roster — including the two families
    /// that feed no prompt surface — puts each family's own admission
    /// into exactly its own bundle field, with the same reason wording
    /// the prompts crate pins at the rendered end, and never a
    /// neighbor's.
    #[test]
    fn the_fanout_fold_carries_each_fed_familys_own_line_to_its_own_field() {
        let reasons = [
            ("decompilation", "Cascara sessions never produce a body"),
            ("disassembly", "Yarrow listings never surface an opcode"),
            ("strings", "Juniper builds carry no string data"),
            ("caller-edges", "Kelp walks never follow a call edge"),
            ("xrefs", "Lovage sessions leave xrefs dark"),
            ("type-database", "Mallow sessions open no type database"),
            ("data-items", "Nettle bins hold no data objects"),
            ("function-inventory", "Olive rosters stay sealed"),
            ("image-base", "Pimento sessions expose no base"),
        ];
        let report = calxgloss_types::CapabilityReport {
            families: reasons
                .iter()
                .map(|(id, reason)| calxgloss_types::FamilyCapability {
                    id: (*id).to_string(),
                    status: calxgloss_types::AvailabilityStatus::Unavailable,
                    reason: Some((*reason).to_string()),
                })
                .collect(),
        };
        let mut bundle = gather_function_evidence(None, "game_logic.dll", "DrawSprite", &[]);
        super::fold_seam_capability(&report, &mut bundle);
        let fields = [
            (
                &bundle.decompilation_cap_line,
                "Cascara sessions never produce a body",
            ),
            (
                &bundle.disassembly_cap_line,
                "Yarrow listings never surface an opcode",
            ),
            (
                &bundle.strings_cap_line,
                "Juniper builds carry no string data",
            ),
            (
                &bundle.caller_edges_cap_line,
                "Kelp walks never follow a call edge",
            ),
            (&bundle.xrefs_cap_line, "Lovage sessions leave xrefs dark"),
            (
                &bundle.type_database_cap_line,
                "Mallow sessions open no type database",
            ),
            (
                &bundle.data_items_cap_line,
                "Nettle bins hold no data objects",
            ),
        ];
        for (field, reason) in fields {
            assert_eq!(
                field.as_str(),
                format!("unavailable — {reason}"),
                "the fold carries this family's own wording, word for word",
            );
        }
        // The declaration-only families stop at the seam report: no field
        // carried them, and their names appear nowhere the fold wrote.
        let written: Vec<&str> = vec![
            bundle.decompilation_cap_line.as_str(),
            bundle.disassembly_cap_line.as_str(),
            bundle.strings_cap_line.as_str(),
            bundle.caller_edges_cap_line.as_str(),
            bundle.xrefs_cap_line.as_str(),
            bundle.type_database_cap_line.as_str(),
            bundle.data_items_cap_line.as_str(),
            bundle.api_capability.admission.as_str(),
        ];
        assert!(
            written
                .iter()
                .all(|text| !text.contains("Olive") && !text.contains("Pimento")),
            "a family that feeds no prompt surface never leaks its reason into a field"
        );
    }

    /// The fold's silence half across the fan-out: answerable and
    /// undeclared families fill no field — the bundle stays exactly as
    /// gather left it, and the hosts' identity pins on the prompts side
    /// start from these empty fields (issue #357).
    #[test]
    fn the_fanout_fold_stays_silent_for_answerable_and_undeclared_families() {
        let answerable = calxgloss_types::CapabilityReport {
            families: super::FED_CAP_FAMILIES
                .iter()
                .map(|id| calxgloss_types::FamilyCapability {
                    id: (*id).to_string(),
                    status: calxgloss_types::AvailabilityStatus::Answerable,
                    reason: None,
                })
                .collect(),
        };
        let mut bundle = gather_function_evidence(None, "game_logic.dll", "DrawSprite", &[]);
        super::fold_seam_capability(&answerable, &mut bundle);
        assert!(
            bundle.decompilation_cap_line.is_empty()
                && bundle.disassembly_cap_line.is_empty()
                && bundle.strings_cap_line.is_empty()
                && bundle.caller_edges_cap_line.is_empty()
                && bundle.xrefs_cap_line.is_empty()
                && bundle.type_database_cap_line.is_empty()
                && bundle.data_items_cap_line.is_empty(),
            "answerable families admit nothing into any field"
        );

        let undeclared = calxgloss_types::CapabilityReport::default();
        super::fold_seam_capability(&undeclared, &mut bundle);
        assert!(
            bundle.decompilation_cap_line.is_empty()
                && bundle.data_items_cap_line.is_empty()
                && bundle.caller_edges_cap_line.is_empty(),
            "an undeclared roster folds to silence, never to absence"
        );
    }

    /// The tier-escalated ModuleContext and FullModule prompts grow the
    /// fold with the held report riding the gather (issue #357): a
    /// hand-declared unavailable report renders its one line per fed
    /// section — heading-plus-line over the empty context the re-ask
    /// could not fill — and an all-answerable report renders no
    /// `Analysis engine:` line anywhere.
    #[tokio::test]
    async fn the_tier_escalation_folds_the_held_report_into_module_and_full_prompts() {
        let translation = Translation {
            binary: "game_logic.dll".to_string().into(),
            function: "DrawSprite".to_string(),
            function_address: None,
            rust_code: "fn draw_sprite(x: i32) -> i32 { x }".to_string(),
            prompt_used: "prompt".to_string(),
            model: "test-model".to_string(),
            tokens_used: Some(10),
            baseline_tests: Vec::new(),
            call_graph: Vec::new(),
            disassembly_hints: Vec::new(),
            context_tier: calxgloss_types::ContextTier::Signature,
            call_graph_context: Vec::new(),
        };
        let target = calxgloss_testfixtures::load_target().expect("fixture target");
        let kuna = calxgloss_kuna::KunaSource::load(target.path())
            .expect("the fixture must load for scanning with Kuna");
        let source = calxgloss_decomp::PipelineSource::Kuna(kuna);

        let report = calxgloss_types::CapabilityReport {
            families: vec![
                calxgloss_types::FamilyCapability {
                    id: "data-items".to_string(),
                    status: calxgloss_types::AvailabilityStatus::Unavailable,
                    reason: Some("Nettle bins hold no data objects".to_string()),
                },
                calxgloss_types::FamilyCapability {
                    id: "caller-edges".to_string(),
                    status: calxgloss_types::AvailabilityStatus::Unavailable,
                    reason: Some("Kelp walks never follow a call edge".to_string()),
                },
            ],
        };

        let module_prompt = build_escalated_prompt(
            &translation,
            calxgloss_types::ContextTier::ModuleContext,
            &source,
            None,
            &report,
        )
        .await
        .expect("the module-context escalation should build");
        assert!(
            module_prompt
                .contains("## DATA TABLES\n\nAnalysis engine: unavailable — Nettle bins hold no data objects\n\n"),
            "the data-tables surface filed nothing, so the seam's line sits under its heading"
        );
        assert!(
            module_prompt
                .contains("## CALL GRAPH NEIGHBORS\n\nAnalysis engine: unavailable — Kelp walks never follow a call edge\n\n"),
            "the call-graph trio produced no entries, and the seam says why"
        );
        assert_eq!(
            module_prompt
                .matches("Analysis engine: unavailable — Nettle bins hold no data objects")
                .count(),
            2,
            "data-items feeds the module host's data-structures and data-tables surfaces"
        );

        let full_prompt = build_escalated_prompt(
            &translation,
            calxgloss_types::ContextTier::FullModule,
            &source,
            None,
            &report,
        )
        .await
        .expect("the full-module escalation should build");
        assert_eq!(
            full_prompt
                .matches("Analysis engine: unavailable — Nettle bins hold no data objects")
                .count(),
            1,
            "the full-module host grows only its own fed surfaces"
        );
        assert_eq!(
            full_prompt
                .matches("Analysis engine: unavailable — Kelp walks never follow a call edge")
                .count(),
            3,
            "the full-module host's three call-graph surfaces admit the caller-edges family"
        );

        let answerable = calxgloss_types::CapabilityReport {
            families: calxgloss_decomp::QUERY_FAMILIES
                .iter()
                .map(|(id, _)| calxgloss_types::FamilyCapability {
                    id: (*id).to_string(),
                    status: calxgloss_types::AvailabilityStatus::Answerable,
                    reason: None,
                })
                .collect(),
        };
        for tier in [
            calxgloss_types::ContextTier::ModuleContext,
            calxgloss_types::ContextTier::FullModule,
        ] {
            let prompt = build_escalated_prompt(&translation, tier, &source, None, &answerable)
                .await
                .expect("the answerable escalation should build");
            assert!(
                !prompt.contains("Analysis engine:"),
                "an all-answerable report adds no admission line to the {tier}-tier prompt"
            );
        }
    }
}
