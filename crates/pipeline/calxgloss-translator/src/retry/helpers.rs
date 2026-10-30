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
mod tests;
