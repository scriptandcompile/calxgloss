//! The [`Analyzer`] struct, [`Strategy`] enum, [`DllClassification`],
//! and [`FunctionAnalysis`] — the core analysis types.

use crate::classify::{
    classification_reason, classify_dll_name, crate_replacement_for, pe_is_managed,
};
use crate::error::AnalysisError as Error;
use crate::error::Result;
use calxgloss_decomp::{PipelineSource, ScanSource};
use calxgloss_pal::ApiMappings;
use calxgloss_types::{
    ClassificationOverrideControl, DllCategory, DllInfo, FunctionInfo, WindowsApiCall,
};
use calxgloss_types::{FunctionComplexity, PromptVariant};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, instrument, warn};

// ============================================================
// Public types
// ============================================================

/// The strategy determined for a DLL during classification.
///
/// This drives what the translation pipeline does with each DLL:
/// - [`PalMapping`] — map Windows APIs to PAL trait methods
/// - [`CrateReplacement`] — find a Rust crate and write a shim layer
/// - [`ReverseEngineer`] — reverse engineer from disassembly
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Strategy {
    /// Use PAL mapping to replace Windows APIs with cross-platform Rust equivalents.
    PalMapping,

    /// Replace with a Rust crate; the value is the recommended crate name.
    CrateReplacement {
        /// The name of the Rust crate that provides equivalent functionality.
        crate_name: String,
    },

    /// Reverse engineer from disassembly — no crate equivalent exists.
    ReverseEngineer,

    /// Parked: the binary is a .NET managed assembly and the pipeline has
    /// nothing to translate from disassembly — we do not yet decompile
    /// managed code (issue #235). Adding a managed decompiler later is a
    /// one-branch change here, at this single dispatch point.
    DoNotTranslate,
}

/// The strategy a category routes to — the single dispatch every
/// classification path (heuristic or overridden) shares. The crate name
/// rides along in the crate-replacement modes.
fn strategy_for_category(category: &DllCategory, crate_replacement: Option<&str>) -> Strategy {
    match category {
        DllCategory::WindowsOs => Strategy::PalMapping,
        DllCategory::MicrosoftSdk | DllCategory::KnownThirdParty => Strategy::CrateReplacement {
            crate_name: crate_replacement.unwrap_or_default().to_string(),
        },
        DllCategory::ProjectSpecific
        | DllCategory::UnknownThirdParty
        | DllCategory::RuntimeLibrary => Strategy::ReverseEngineer,
        DllCategory::DotNetManaged => Strategy::DoNotTranslate,
    }
}

/// Classification result for a single DLL.
///
/// Produced by [`Analyzer::classify_dll`] or [`Analyzer::classify_target`].
/// Contains the DLL's category, the recommended strategy, symbol counts,
/// and any crate replacement name.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DllClassification {
    /// The DLL filename (e.g., `game_logic.dll`).
    pub binary: String,

    /// Classification category.
    pub category: DllCategory,

    /// Recommended strategy based on classification.
    pub strategy: Strategy,

    /// Number of exported symbols in the DLL.
    pub exports_count: usize,

    /// Number of imported symbols from the DLL.
    pub imports_count: usize,

    /// If `category` is `MicrosoftSdk` or `KnownThirdParty`, the recommended
    /// Rust crate name. `None` for `WindowsOs` and `ProjectSpecific` DLLs.
    pub crate_replacement: Option<String>,

    /// Whether this binary is a known runtime library — never a translation
    /// target (the Evidence glossary rule: consumers must check this flag
    /// alongside `category`, never the category alone). A `RuntimeLibrary`
    /// category always implies it; an operator override can set it for any
    /// category, or clear it when overriding a runtime-named binary back to
    /// a translated one.
    #[serde(default)]
    pub known_runtime: bool,

    /// Why this classification was chosen — the table or pattern the
    /// heuristics matched (or the operator's override). Displayed next to
    /// the classification override control; older records carry none.
    #[serde(default)]
    pub reason: String,
}

/// Complete analysis result for a single function.
///
/// Produced by [`Analyzer::analyze_function`]. Aggregates decompiler function data
/// with tagged Windows API calls and call graph information.
#[derive(Debug, Clone)]
pub struct FunctionAnalysis {
    /// The function's basic information (name, address, DLL).
    pub function_info: FunctionInfo,

    /// Windows API calls identified within this function, tagged with their
    /// PAL mappings. Derived from cross-referencing disassembly/imports against
    /// the PAL mapping table.
    pub tagged_apis: Vec<WindowsApiCall>,

    /// Call graph neighbors from the scan.
    pub call_graph: Vec<String>,
}

// ============================================================
// Analyzer
// ============================================================

/// Analyzes target DLLs: classifies them, extracts function metadata,
/// and tags Windows API calls with their cross-platform mappings.
///
/// The analyzer combines data from the analysis seam (imports, exports,
/// decompiler output, call graphs) with the static PAL mapping table to
/// produce structured analysis results.
///
/// # Construction
///
/// ```no_run
/// use calxgloss_analysis::Analyzer;
/// use calxgloss_pal::ApiMappings;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let source = calxgloss_decomp::PipelineSource::from(
///     calxgloss_kuna::KunaSource::load("eqmain.dll".as_ref())?,
/// );
/// let mappings = ApiMappings::default();
/// let analyzer = Analyzer::new(source, mappings);
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct Analyzer {
    /// The program facts, pulled through the analysis seam.
    source: PipelineSource,

    /// Windows API → Rust equivalent mapping table.
    api_mappings: ApiMappings,

    /// The shared classification-override handle (issue #97, W2.8) — when
    /// attached, every classification consults it before strategy dispatch,
    /// so an operator's correction from the dashboard routes the binary
    /// without a CLI re-run.
    classification_overrides: Option<ClassificationOverrideControl>,
}

impl Analyzer {
    /// Creates a new analyzer over the pipeline's scan source and API
    /// mappings.
    ///
    /// The analyzer pulls DLL/function metadata through the scan source and
    /// uses the API mappings to tag Windows API calls with their PAL
    /// replacements.
    pub fn new(source: PipelineSource, api_mappings: ApiMappings) -> Self {
        Self {
            source,
            api_mappings,
            classification_overrides: None,
        }
    }

    /// Attach the shared [`ClassificationOverrideControl`] handle the web
    /// router's classification endpoints drive. Every classification this
    /// analyzer builds then consults it before strategy dispatch.
    pub fn with_classification_overrides(
        mut self,
        overrides: ClassificationOverrideControl,
    ) -> Self {
        self.classification_overrides = Some(overrides);
        self
    }

    /// Classifies a single DLL by fetching its metadata from the loaded
    /// program and applying classification heuristics based on the DLL
    /// filename.
    ///
    /// # Arguments
    ///
    /// * `binary` — The DLL filename to classify (e.g., `game_logic.dll`).
    ///
    /// # A note on the symbol counts
    ///
    /// The engine holds one program at a time and exposes no per-DLL routing,
    /// so `exports_count` and `imports_count` are the counts for the loaded
    /// program — not necessarily for the DLL named in `binary`. The category
    /// itself comes from the filename and is unaffected. Call this when the
    /// loaded program is the DLL you mean; otherwise the counts describe
    /// something else while still being attached to `binary`.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use calxgloss_analysis::Analyzer;
    /// use calxgloss_pal::ApiMappings;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let source = calxgloss_decomp::PipelineSource::from(
    ///     calxgloss_kuna::KunaSource::load("game_logic.dll".as_ref())?,
    /// );
    /// let analyzer = Analyzer::new(source, ApiMappings::default());
    ///
    /// let classification = analyzer.classify_dll("game_logic.dll").await?;
    /// println!("Strategy: {:?}", classification.strategy);
    /// # Ok(())
    /// # }
    /// ```
    #[instrument(skip(self), fields(binary))]
    pub async fn classify_dll(&self, binary: &str) -> Result<DllClassification> {
        debug!(binary, "Classifying DLL");

        // Symbol counts come from the loaded program; see the note on this
        // method about what that means for a named DLL.
        let imports = ScanSource::imports(&self.source).await.unwrap_or_else(|e| {
            warn!(binary, error = %e, "Could not read imports; counting none");
            Vec::new()
        });
        let exports = ScanSource::exports(&self.source).await.unwrap_or_else(|e| {
            warn!(binary, error = %e, "Could not read exports; counting none");
            Vec::new()
        });

        Ok(self.build_classification(binary, exports.len(), imports.len(), false))
    }

    /// Build a classification from filename, symbol counts, and the PE
    /// managed marker. `is_managed` is the COM-descriptor fact from the
    /// binary's PE headers (issue #235); callers without a file to parse
    /// pass `false` and get the name-only heuristics.
    fn build_classification(
        &self,
        binary: &str,
        exports_count: usize,
        imports_count: usize,
        is_managed: bool,
    ) -> DllClassification {
        let (category, crate_replacement, known_runtime, reason) =
            self.classify_decision(binary, is_managed);

        let strategy = strategy_for_category(&category, crate_replacement.as_deref());

        let classification = DllClassification {
            binary: binary.to_string(),
            category,
            strategy,
            exports_count,
            imports_count,
            crate_replacement,
            known_runtime,
            reason,
        };

        info!(
            binary,
            category = ?classification.category,
            strategy = ?classification.strategy,
            exports = classification.exports_count,
            imports = classification.imports_count,
            "Classified DLL"
        );

        classification
    }

    /// The classification decision for one binary: the operator's override
    /// if one is recorded (issue #97, W2.8), then the PE managed fact
    /// (issue #235), then the filename heuristics. Both the category and
    /// the `known_runtime` flag come out of this one decision — per the
    /// Evidence glossary rule a runtime-library classification is never a
    /// translation target, so an override to `RuntimeLibrary` always
    /// carries the flag, and overriding a runtime-named binary to another
    /// category clears it. A managed assembly is a parked target, not a
    /// runtime library, so `DotNetManaged` keeps the flag false.
    ///
    /// Precedence: operator override > PE .NET check > name-table
    /// heuristics — a managed binary whose name happens to match a known
    /// table is still parked honestly, and the operator's word outranks
    /// the PE fact.
    ///
    /// Returns `(category, crate_replacement, known_runtime, reason)`.
    fn classify_decision(
        &self,
        binary: &str,
        is_managed: bool,
    ) -> (DllCategory, Option<String>, bool, String) {
        if let Some(override_record) = self
            .classification_overrides
            .as_ref()
            .and_then(|control| control.get(binary))
        {
            let known_runtime = override_record.is_runtime();
            let reason = override_record.override_reason();
            let category = override_record.category;
            let crate_replacement = match &category {
                DllCategory::MicrosoftSdk | DllCategory::KnownThirdParty => override_record
                    .crate_replacement
                    .clone()
                    .or_else(|| crate_replacement_for(binary, &category)),
                _ => None,
            };
            return (category, crate_replacement, known_runtime, reason);
        }

        if is_managed {
            // The PE fact outranks the name tables (issue #235): a managed
            // binary whose name matches a known table is still parked.
            let category = DllCategory::DotNetManaged;
            let reason = classification_reason(binary, &category);
            return (category, None, false, reason);
        }

        let category = classify_dll_name(binary);
        let crate_replacement = crate_replacement_for(binary, &category);
        let known_runtime = category == DllCategory::RuntimeLibrary;
        let reason = classification_reason(binary, &category);
        (category, crate_replacement, known_runtime, reason)
    }

    /// Classifies each of the named DLLs.
    ///
    /// Symbol counts are read from the PE header on disk (via `goblin`), which
    /// gives accurate per-DLL export/import counts. If a DLL file is missing
    /// from `target_dir` the call falls back to the currently-loaded
    /// program.
    ///
    /// The DLL names are supplied by the caller because the engine has no way to
    /// enumerate them: it serves a single open program and exposes no listing of
    /// what else a target links against. Where the list comes from — a
    /// directory scan, a manifest, a hand-written list — is the caller's
    /// decision.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use calxgloss_analysis::Analyzer;
    /// use calxgloss_pal::ApiMappings;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let source = calxgloss_decomp::PipelineSource::from(
    ///     calxgloss_kuna::KunaSource::load("eqmain.dll".as_ref())?,
    /// );
    /// let analyzer = Analyzer::new(source, ApiMappings::default());
    ///
    /// let names = vec!["eqmain.dll".to_string(), "eqgui.dll".to_string()];
    /// let target_dir = std::path::Path::new("/path/to/targets");
    /// for c in analyzer.classify_dlls(&names, target_dir).await? {
    ///     println!("{}: {:?}", c.binary, c.strategy);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    #[instrument(skip(self, dlls, target_dir), fields(count = dlls.len()))]
    pub async fn classify_dlls(
        &self,
        dlls: &[String],
        target_dir: &std::path::Path,
    ) -> Result<Vec<DllClassification>> {
        let mut classifications = Vec::with_capacity(dlls.len());
        for binary in dlls {
            let classification = self.classify_dll_with_target(binary, target_dir).await?;
            classifications.push(classification);
        }

        info!(count = classifications.len(), "Classified all DLLs");
        Ok(classifications)
    }

    /// Classify one DLL, reading symbol counts from the PE header on disk.
    async fn classify_dll_with_target(
        &self,
        binary: &str,
        target_dir: &std::path::Path,
    ) -> Result<DllClassification> {
        use anyhow::Context;

        let dll_path = target_dir.join(binary);

        // Try PE header parse first — gives accurate per-DLL counts.
        let bytes = std::fs::read(&dll_path)
            .with_context(|| format!("Failed to read {}", dll_path.display()))?;
        let pe = goblin::pe::PE::parse(&bytes)
            .with_context(|| format!("Failed to parse PE headers for {}", dll_path.display()))?;

        let exports_count = pe.exports.len();
        let imports_count = pe.imports.len();
        // The managed marker rides on the same PE parse the counts come
        // from — no extra file read (issue #235).
        let is_managed = pe_is_managed(&pe);

        Ok(self.build_classification(
            binary,
            exports_count,
            imports_count,
            is_managed,
        ))
    }

    /// Performs complete analysis on a single function.
    ///
    /// Resolves `function` to an address in the loaded program, fetches its
    /// decompilation and cross-references, then tags the Windows API calls
    /// among its callees using [`tag_windows_apis`].
    ///
    /// # Arguments
    ///
    /// * `binary` — The DLL the function belongs to. Recorded on the result; the
    ///   lookup itself is against the loaded program, which must be this DLL.
    /// * `function` — The function name, as the engine lists it.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use calxgloss_analysis::Analyzer;
    /// use calxgloss_pal::ApiMappings;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let source = calxgloss_decomp::PipelineSource::from(
    ///     calxgloss_kuna::KunaSource::load("game_logic.dll".as_ref())?,
    /// );
    /// let analyzer = Analyzer::new(source, ApiMappings::default());
    ///
    /// let analysis = analyzer.analyze_function("game_logic.dll", "DrawSprite").await?;
    /// println!("Found {} tagged Windows API calls", analysis.tagged_apis.len());
    /// # Ok(())
    /// # }
    /// ```
    #[instrument(skip(self), fields(binary, function))]
    pub async fn analyze_function(&self, binary: &str, function: &str) -> Result<FunctionAnalysis> {
        debug!(binary, function, "Analyzing function");

        // The seam has no lookup that returns a function without an address,
        // so the name is resolved through the function listing first. A
        // partial match is refused rather than guessed at, since silently
        // analysing the wrong function would produce a plausible but
        // irrelevant translation.
        let listing = ScanSource::functions(&self.source).await?;
        let found = listing
            .into_iter()
            .find(|m| m.name == function)
            .ok_or_else(|| Error::FunctionAnalysisFailed {
                binary: binary.to_string(),
                function: function.to_string(),
                reason: "no function by that exact name in the loaded program; if the name \
                         is a substring of the real one, pass the full name."
                    .to_string(),
            })?;
        let decompiled = ScanSource::decompile(&self.source, &found.name).await?;

        // Imports of the loaded program, used to spot Windows API calls.
        let import_names: Vec<String> = ScanSource::imports(&self.source)
            .await
            .unwrap_or_else(|e| {
                warn!(error = %e, "Could not read imports; tagging no API calls");
                Vec::new()
            })
            .into_iter()
            .map(|s| s.name)
            .collect();

        // Tag Windows API calls among the names the decompiled body calls,
        // intersected with the program's imports — the calls the engine can
        // see are the ones worth tagging.
        let callees = calxgloss_decomp::parse::callees_from_decompiled(&decompiled.body);
        let called_imports: Vec<String> = callees
            .iter()
            .filter(|callee| import_names.iter().any(|i| i == *callee))
            .cloned()
            .collect();
        let tagged_apis = self.tag_windows_apis("", &called_imports)?;

        // The seam has no call-graph endpoint. Callers come from the
        // cross-references to the entry; callees are scraped from the
        // decompiled body, which cannot see calls made through a function
        // pointer.
        let callers = ScanSource::callers(&self.source, found.address)
            .await
            .unwrap_or_default();
        let call_graph: Vec<String> = callers.iter().chain(callees.iter()).cloned().collect();

        let analysis = FunctionAnalysis {
            function_info: FunctionInfo {
                name: decompiled.name.clone(),
                address: found.address,
                binary: binary.to_string().into(),
                // The seam carries no disassembly read — the engine answers
                // pseudo-C — so the record keeps the field empty.
                disassembly: String::new(),
                decompiler_output: decompiled.body,
                windows_apis: Vec::new(),
                call_graph: call_graph.clone(),
                disassembly_hints: Vec::new(),
            },
            tagged_apis: tagged_apis.clone(),
            call_graph,
        };

        info!(
            binary,
            function,
            address = format_args!("{:#x}", found.address),
            neighbors = analysis.call_graph.len(),
            "Function analysis complete"
        );

        Ok(analysis)
    }

    /// Tags Windows API calls found in disassembly and imports.
    ///
    /// Cross-references the function's imports and the DLL's import list against
    /// the PAL mapping table. For each import that matches a known Windows API,
    /// records the API name, its category, and the PAL mapping target.
    ///
    /// This is a pure analysis function that reaches no engine at all —
    /// it works with the text and import list provided.
    ///
    /// # Arguments
    ///
    /// * `disassembly` — The function's listing text; an import is tagged
    ///   when its name appears in it (an empty string tags every import).
    /// * `imports` — The list of imports for the DLL containing the function.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use calxgloss_analysis::Analyzer;
    /// use calxgloss_pal::ApiMappings;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let source = calxgloss_decomp::PipelineSource::from(
    ///     calxgloss_kuna::KunaSource::load("game_logic.dll".as_ref())?,
    /// );
    /// let analyzer = Analyzer::new(source, ApiMappings::default());
    ///
    /// let imports = vec!["CreateFileA".to_string(), "ReadFile".to_string()];
    ///
    /// let tagged = analyzer.tag_windows_apis("", &imports).unwrap();
    /// assert_eq!(tagged.len(), 2);
    /// assert_eq!(tagged[0].name, "CreateFileA");
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Arguments
    ///
    /// * `imports` — Imported symbol names. Ghidra reports an import as a name
    ///   and an external slot with no module attached, so these are names rather
    ///   than [`Import`] values; the module a symbol came from is not available
    ///   from the analysis side and is not needed to look up a mapping.
    pub fn tag_windows_apis(
        &self,
        disassembly: &str,
        imports: &[String],
    ) -> Result<Vec<WindowsApiCall>> {
        debug!(imports_count = imports.len(), "Tagging Windows APIs");

        // Collect function names from disassembly to check for direct API references
        let mut tagged = Vec::new();
        let mut seen = std::collections::HashSet::new();

        // Tag APIs found in the imports
        for api_name in imports {
            // Skip if we've already tagged this API
            if seen.contains(api_name.as_str()) {
                continue;
            }

            // Look up the API in the PAL mapping table
            if let Some(mapping) = self.api_mappings.lookup(api_name) {
                tagged.push(WindowsApiCall {
                    name: api_name.clone(),
                    category: mapping.category.clone(),
                    pal_mapping: mapping.rust_equivalent.to_string(),
                });
                seen.insert(api_name.clone());
            }
        }

        // Also scan the disassembly for known API names that might not be in imports
        // (e.g., dynamically loaded via LoadLibrary/GetProcAddress)
        if !disassembly.is_empty() {
            let dis_lower = disassembly.to_lowercase();
            for mapping in self.api_mappings.iter() {
                let api_lower = mapping.windows_api.to_lowercase();
                if dis_lower.contains(&api_lower) && seen.insert(mapping.windows_api.to_string()) {
                    tagged.push(WindowsApiCall {
                        name: mapping.windows_api.to_string(),
                        category: mapping.category.clone(),
                        pal_mapping: mapping.rust_equivalent.to_string(),
                    });
                }
            }
        }

        info!(tagged_count = tagged.len(), "Tagged Windows APIs");
        Ok(tagged)
    }

    /// Classifies a `DllInfo` struct directly, without needing engine reads.
    ///
    /// Useful when you already have DLL metadata (e.g., from a cached analysis
    /// or manual inspection) and just need to determine the classification
    /// and strategy.
    ///
    /// # Arguments
    ///
    /// * `dll_info` — The DLL metadata to classify.
    pub fn classify_dll_info(&self, dll_info: &DllInfo) -> DllClassification {
        let (category, crate_replacement, known_runtime, reason) =
            self.classify_decision(&dll_info.name, false);

        let strategy = strategy_for_category(&category, crate_replacement.as_deref());

        DllClassification {
            binary: dll_info.name.clone(),
            category,
            strategy,
            exports_count: dll_info.exports.len(),
            imports_count: dll_info.imports.len(),
            crate_replacement,
            known_runtime,
            reason,
        }
    }

    /// Returns a reference to the API mappings used by this analyzer.
    pub fn api_mappings(&self) -> &ApiMappings {
        &self.api_mappings
    }

    /// Returns a reference to the scan source this analyzer reads through.
    pub fn source(&self) -> &PipelineSource {
        &self.source
    }

    /// Builds, classifies, and persists a call graph for a single DLL.
    ///
    /// This is the primary integration point between the call graph analysis
    /// pipeline and the rest of the system. It:
    ///
    /// 1. Fetches all function metadata from the engine.
    /// 2. Classifies each function as [`Root`](calxgloss_types::NodeCategory::Root),
    ///    [`Leaf`](calxgloss_types::NodeCategory::Leaf), or
    ///    [`Middle`](calxgloss_types::NodeCategory::Middle).
    /// 3. Persists the enriched graph to `re/analysis/{binary}_call_graph.json`.
    ///
    /// # Arguments
    ///
    /// * `dll_name` — The DLL filename (e.g., `"eqmain.dll"`).
    /// * `workspace` — The workspace root directory for persistence.
    ///
    /// # Returns
    ///
    /// A fully classified call graph, or an error if engine data cannot
    /// be fetched or the graph cannot be persisted.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use calxgloss_analysis::Analyzer;
    /// use calxgloss_pal::ApiMappings;
    /// use std::path::Path;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let source = calxgloss_decomp::PipelineSource::from(
    ///     calxgloss_kuna::KunaSource::load("eqmain.dll".as_ref())?,
    /// );
    /// let analyzer = Analyzer::new(source, ApiMappings::default());
    ///
    /// let graph = analyzer.build_call_graph("eqmain.dll", Path::new("/workspace"), None).await?;
    /// for func in &graph.functions {
    ///     println!("{}: {:?}", func.name, func.node_category);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # TODOs
    ///
    /// ```text
    /// TODO: Cache CallGraphBuilder results to avoid rebuilding on every analysis run
    /// TODO: Add call graph analysis as a separate pipeline phase (Phase 1.5)
    /// TODO: Make call graph analysis optional via config flag
    /// TODO: Integrate with dependency tracker: use NodeCategory for translation ordering
    /// ```
    pub async fn build_call_graph(
        &self,
        dll_name: &str,
        workspace: &std::path::Path,
        cache_dir: Option<&std::path::Path>,
    ) -> anyhow::Result<calxgloss_callgraph::CallGraph> {
        crate::callgraph::build_enriched_call_graph(&self.source, dll_name, workspace, cache_dir)
            .await
    }

    /// Generate shim layer suggestions for all crate-replacement DLLs.
    ///
    /// After classification, this function estimates the expected shim complexity
    /// for each DLL whose strategy is `CrateReplacement`. The estimation is based
    /// on export/import symbol counts and known crate patterns — no LLM call is needed.
    ///
    /// # Arguments
    ///
    /// * `classifications` — The full classification results to filter.
    ///
    /// # Returns
    ///
    /// A [`calxgloss_types::ShimSuggestionReport`] containing one suggestion per
    /// crate-replacement DLL, or an empty report if no DLLs need shim layers.
    pub fn suggest_shim_layers(
        &self,
        classifications: &[DllClassification],
    ) -> calxgloss_types::ShimSuggestionReport {
        let suggestions: Vec<calxgloss_types::ShimSuggestion> = classifications
            .iter()
            .filter_map(|c| {
                if matches!(c.strategy, Strategy::CrateReplacement { .. }) {
                    Some(suggest_shim(c))
                } else {
                    None
                }
            })
            .collect();

        calxgloss_types::ShimSuggestionReport { suggestions }
    }

    /// Detect the complexity of a function from its disassembly and API usage.
    ///
    /// This is the primary mechanism for deciding how much context to
    /// inject into the LLM prompt. Simple functions get minimal context;
    /// complex functions get rich contextual information.
    ///
    /// # Arguments
    ///
    /// * `disassembly` — The raw disassembly text from the engine.
    /// * `tagged_apis` — The Windows API calls identified in the function,
    ///   used to determine API-category diversity.
    ///
    /// # Returns
    ///
    /// A [`FunctionComplexity`] classification.
    pub fn detect_complexity(
        &self,
        disassembly: &str,
        tagged_apis: &[WindowsApiCall],
    ) -> FunctionComplexity {
        let api_categories: Vec<String> = tagged_apis
            .iter()
            .map(|api| api.category.to_string())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();
        calxgloss_types::detect_complexity(disassembly, &api_categories)
    }

    /// Build a [`PromptVariant`] for the given function analysis.
    ///
    /// This determines which prompt template and what level of context
    /// the translation pipeline should use. The default is API-aware,
    /// including mapping table rows for detected API categories.
    ///
    /// # Arguments
    ///
    /// * `analysis` — The complete function analysis including disassembly
    ///   and tagged APIs.
    ///
    /// # Returns
    ///
    /// A [`PromptVariant`] describing the optimal prompt configuration.
    pub fn build_prompt_variant(&self, analysis: &FunctionAnalysis) -> PromptVariant {
        let complexity =
            self.detect_complexity(&analysis.function_info.disassembly, &analysis.tagged_apis);
        PromptVariant::new(complexity).with_api_aware(true)
    }
}

/// Generate a shim suggestion for a single crate-replacement DLL.
///
/// Estimates complexity from the DLL's export/import symbol counts and
/// known crate characteristics. Well-known crates (wgpu, cpal) receive
/// higher confidence scores because their API patterns are better understood.
pub fn suggest_shim(classification: &DllClassification) -> calxgloss_types::ShimSuggestion {
    let estimated_mappings = classification.exports_count;

    let (estimated_complexity, confidence) = estimate_complexity(
        classification,
        estimated_mappings,
        classification.imports_count,
    );

    calxgloss_types::ShimSuggestion {
        source_dll: classification.binary.clone(),
        target_crate: classification.crate_replacement.clone().unwrap_or_default(),
        estimated_mappings,
        estimated_complexity,
        estimated_confidence: confidence,
    }
}

/// Estimates the shim complexity and confidence for a single DLL.
///
/// The complexity heuristic uses:
/// - Export count as the primary complexity driver
/// - Import count as a secondary factor (more imports → more interop)
/// - Known crate patterns for confidence calibration
fn estimate_complexity(
    classification: &DllClassification,
    exports: usize,
    imports: usize,
) -> (calxgloss_types::ComplexityScore, f64) {
    // Score = exports * 5 + imports * 3, weighted by crate familiarity
    let raw_score = (exports as f64) * 5.0 + (imports as f64) * 3.0;

    // Known crates get higher base confidence because their API patterns
    // are well-documented and the translation is more predictable.
    let crate_name = classification.crate_replacement.as_deref().unwrap_or("");
    let crate_familiarity: f64 = match crate_name {
        "wgpu" | "cpal" | "fmod-rs" => 0.9,
        "vb6runtime" => 0.85,
        "tiny-skia" => 0.8,
        _ => 0.6,
    };

    // Confidence decreases slightly with very high export counts
    // (harder to predict accurately) and increases with low counts.
    let count_factor: f64 = if exports == 0 {
        0.7
    } else if exports <= 10 {
        0.95
    } else if exports <= 50 {
        0.85
    } else if exports <= 100 {
        0.75
    } else {
        0.6
    };

    let confidence = (crate_familiarity * 0.6_f64 + count_factor * 0.4_f64).min(1.0_f64);

    // Determine complexity tier from weighted score
    let weighted_score = raw_score * (1.0 + (imports as f64) / 100.0);

    let complexity = if weighted_score < 50.0 {
        calxgloss_types::ComplexityScore::Low
    } else if weighted_score < 200.0 {
        calxgloss_types::ComplexityScore::Medium
    } else {
        calxgloss_types::ComplexityScore::High
    };

    (complexity, confidence)
}

#[cfg(test)]
mod tests {
    use super::*;
    use calxgloss_pal::ApiMappings;
    use calxgloss_types::{Export, Import};

    fn test_analyzer() -> Analyzer {
        let fixture = calxgloss_testfixtures::load_target().expect("fixture target");
        let source = calxgloss_decomp::PipelineSource::from(
            calxgloss_kuna::KunaSource::load(fixture.path()).expect("fixture loads"),
        );
        let api_mappings = ApiMappings::default();
        Analyzer::new(source, api_mappings)
    }

    #[test]
    fn test_analyzer_creation() {
        let analyzer = test_analyzer();
        assert!(!analyzer.api_mappings().is_empty());
    }

    #[test]
    fn test_tag_windows_apis_kernel32() {
        let analyzer = test_analyzer();
        let imports = vec!["CreateFileA".to_string(), "ReadFile".to_string()];

        let tagged = analyzer.tag_windows_apis("", &imports).unwrap();
        assert_eq!(tagged.len(), 2);
        assert_eq!(tagged[0].name, "CreateFileA");
        assert_eq!(tagged[1].name, "ReadFile");
    }

    #[test]
    fn test_tag_windows_apis_deduplication() {
        let analyzer = test_analyzer();
        let imports = vec!["CreateFileA".to_string(), "CreateFileA".to_string()];

        let tagged = analyzer.tag_windows_apis("", &imports).unwrap();
        assert_eq!(tagged.len(), 1);
    }

    #[test]
    fn test_tag_windows_apis_unrecognized() {
        let analyzer = test_analyzer();
        let imports = vec!["UnknownFunction".to_string()];

        let tagged = analyzer.tag_windows_apis("", &imports).unwrap();
        assert!(tagged.is_empty());
    }

    #[test]
    fn test_tag_windows_apis_empty() {
        let analyzer = test_analyzer();
        let tagged = analyzer.tag_windows_apis("", &[]).unwrap();
        assert!(tagged.is_empty());
    }

    #[test]
    fn test_tag_windows_apis_disassembly_scan() {
        let analyzer = test_analyzer();
        let imports: Vec<String> = vec![];

        // Disassembly contains a known API name that's not in imports
        let disassembly = r"
            0x00401000: call LoadLibraryA
            0x00401005: mov eax, [esp+0x4]
        ";

        let tagged = analyzer.tag_windows_apis(disassembly, &imports).unwrap();
        assert!(!tagged.is_empty());
        assert!(tagged.iter().any(|api| api.name == "LoadLibraryA"));
    }

    #[test]
    fn test_classify_dll_info_kernel32() {
        let analyzer = test_analyzer();
        let dll_info = DllInfo {
            name: "kernel32.dll".to_string(),
            version: None,
            category: DllCategory::WindowsOs,
            known_runtime: false,
            exports: vec![],
            imports: vec![],
        };

        let classification = analyzer.classify_dll_info(&dll_info);
        assert_eq!(classification.category, DllCategory::WindowsOs);
        assert!(matches!(classification.strategy, Strategy::PalMapping));
        assert!(classification.crate_replacement.is_none());
    }

    #[test]
    fn test_classify_dll_info_d3d9() {
        let analyzer = test_analyzer();
        let dll_info = DllInfo {
            name: "d3d9.dll".to_string(),
            version: None,
            category: DllCategory::MicrosoftSdk,
            known_runtime: false,
            exports: vec![],
            imports: vec![],
        };

        let classification = analyzer.classify_dll_info(&dll_info);
        assert_eq!(classification.category, DllCategory::MicrosoftSdk);
        assert!(matches!(
            classification.strategy,
            Strategy::CrateReplacement { ref crate_name } if crate_name == "wgpu"
        ));
        assert_eq!(classification.crate_replacement, Some("wgpu".to_string()));
    }

    #[test]
    fn test_classify_dll_info_fmod() {
        let analyzer = test_analyzer();
        let dll_info = DllInfo {
            name: "fmod.dll".to_string(),
            version: None,
            category: DllCategory::KnownThirdParty,
            known_runtime: false,
            exports: vec![],
            imports: vec![],
        };

        let classification = analyzer.classify_dll_info(&dll_info);
        assert_eq!(classification.category, DllCategory::KnownThirdParty);
        assert!(matches!(
            classification.strategy,
            Strategy::CrateReplacement { ref crate_name } if crate_name == "fmod-rs"
        ));
        assert_eq!(
            classification.crate_replacement,
            Some("fmod-rs".to_string())
        );
    }

    #[test]
    fn test_classify_dll_info_project_specific() {
        let analyzer = test_analyzer();
        let dll_info = DllInfo {
            name: "game_logic.dll".to_string(),
            version: None,
            category: DllCategory::ProjectSpecific,
            known_runtime: false,
            exports: vec![],
            imports: vec![],
        };

        let classification = analyzer.classify_dll_info(&dll_info);
        assert_eq!(classification.category, DllCategory::ProjectSpecific);
        assert!(matches!(classification.strategy, Strategy::ReverseEngineer));
        assert!(classification.crate_replacement.is_none());
    }

    #[test]
    fn test_classify_dll_info_preserves_counts() {
        let analyzer = test_analyzer();
        let dll_info = DllInfo {
            name: "my_app.dll".to_string(),
            version: None,
            category: DllCategory::ProjectSpecific,
            known_runtime: false,
            exports: vec![
                Export {
                    name: "Func1".to_string(),
                    address: 0x1000,
                    signature: "int __stdcall Func1()".to_string(),
                },
                Export {
                    name: "Func2".to_string(),
                    address: 0x2000,
                    signature: "void __stdcall Func2()".to_string(),
                },
            ],
            imports: vec![
                Import {
                    binary: "kernel32.dll".to_string().into(),
                    function: "CreateFileA".to_string(),
                },
                Import {
                    binary: "user32.dll".to_string().into(),
                    function: "MessageBoxA".to_string(),
                },
                Import {
                    binary: "user32.dll".to_string().into(),
                    function: "DestroyWindow".to_string(),
                },
            ],
        };

        let classification = analyzer.classify_dll_info(&dll_info);
        assert_eq!(classification.exports_count, 2);
        assert_eq!(classification.imports_count, 3);
    }

    #[test]
    fn test_detect_complexity_simple_function() {
        let analyzer = test_analyzer();
        let tagged_apis: Vec<WindowsApiCall> = vec![];
        let complexity = analyzer.detect_complexity(
            "0x00401000: mov eax, [esp+4]\n0x00401004: add eax, ebx\n0x00401007: ret",
            &tagged_apis,
        );
        assert_eq!(complexity, calxgloss_types::FunctionComplexity::Minimal);
    }

    #[test]
    fn test_detect_complexity_with_multiple_apis() {
        let analyzer = test_analyzer();
        let tagged_apis = vec![
            WindowsApiCall {
                name: "CreateFileA".to_string(),
                category: calxgloss_types::ApiCategory::Win32Core,
                pal_mapping: "std::fs::File::open".to_string(),
            },
            WindowsApiCall {
                name: "DirectDrawCreate".to_string(),
                category: calxgloss_types::ApiCategory::DirectX,
                pal_mapping: "wgpu".to_string(),
            },
            WindowsApiCall {
                name: "MessageBoxA".to_string(),
                category: calxgloss_types::ApiCategory::Win32Gui,
                pal_mapping: "dialog".to_string(),
            },
        ];
        let complexity =
            analyzer.detect_complexity("0x00401000: mov eax, 0\n0x00401004: ret", &tagged_apis);
        // 3 different API categories → Standard (bumped from Minimal)
        assert_eq!(complexity, calxgloss_types::FunctionComplexity::Standard);
    }

    #[test]
    fn test_build_prompt_variant() {
        let analyzer = test_analyzer();
        let analysis = FunctionAnalysis {
            function_info: FunctionInfo {
                name: "SimpleFunc".to_string(),
                address: 0x1000,
                binary: "test.dll".to_string().into(),
                disassembly: "0x00401000: mov eax, 0\n0x00401004: ret".to_string(),
                decompiler_output: "int SimpleFunc() { return 0; }".to_string(),
                windows_apis: Vec::new(),
                call_graph: Vec::new(),
                disassembly_hints: Vec::new(),
            },
            tagged_apis: Vec::new(),
            call_graph: Vec::new(),
        };

        let variant = analyzer.build_prompt_variant(&analysis);
        assert_eq!(
            variant.complexity,
            calxgloss_types::FunctionComplexity::Minimal
        );
        assert!(variant.api_aware);
    }

    #[test]
    fn test_suggest_shim_d3d9() {
        let classification = DllClassification {
            binary: "d3d9.dll".to_string(),
            category: DllCategory::MicrosoftSdk,
            strategy: Strategy::CrateReplacement {
                crate_name: "wgpu".to_string(),
            },
            exports_count: 200,
            imports_count: 5,
            crate_replacement: Some("wgpu".to_string()),
            known_runtime: false,
            reason: String::new(),
        };

        let suggestion = suggest_shim(&classification);
        assert_eq!(suggestion.source_dll, "d3d9.dll");
        assert_eq!(suggestion.target_crate, "wgpu");
        assert_eq!(suggestion.estimated_mappings, 200);
        assert!(matches!(
            suggestion.estimated_complexity,
            calxgloss_types::ComplexityScore::High
        ));
        assert!(suggestion.estimated_confidence > 0.0);
    }

    #[test]
    fn test_suggest_shim_kernel32_no_filtering() {
        // suggest_shim generates a suggestion regardless of strategy;
        // filtering to CrateReplacement only happens in suggest_shim_layers.
        let classification = DllClassification {
            binary: "kernel32.dll".to_string(),
            category: DllCategory::WindowsOs,
            strategy: Strategy::PalMapping,
            exports_count: 500,
            imports_count: 0,
            crate_replacement: None,
            known_runtime: false,
            reason: String::new(),
        };

        let suggestion = suggest_shim(&classification);
        // No filtering here — suggestion is still generated
        assert_eq!(suggestion.estimated_mappings, 500);
        assert!(suggestion.target_crate.is_empty());
    }

    #[test]
    fn test_suggest_shim_fmod() {
        let classification = DllClassification {
            binary: "fmod.dll".to_string(),
            category: DllCategory::KnownThirdParty,
            strategy: Strategy::CrateReplacement {
                crate_name: "fmod-rs".to_string(),
            },
            exports_count: 80,
            imports_count: 2,
            crate_replacement: Some("fmod-rs".to_string()),
            known_runtime: false,
            reason: String::new(),
        };

        let suggestion = suggest_shim(&classification);
        assert_eq!(suggestion.source_dll, "fmod.dll");
        assert_eq!(suggestion.target_crate, "fmod-rs");
        assert_eq!(suggestion.estimated_mappings, 80);
        assert!(suggestion.estimated_confidence > 0.8);
    }

    #[test]
    fn test_suggest_shim_small_dll() {
        let classification = DllClassification {
            binary: "tiny_lib.dll".to_string(),
            category: DllCategory::KnownThirdParty,
            strategy: Strategy::CrateReplacement {
                crate_name: "lz4".to_string(),
            },
            exports_count: 3,
            imports_count: 1,
            crate_replacement: Some("lz4".to_string()),
            known_runtime: false,
            reason: String::new(),
        };

        let suggestion = suggest_shim(&classification);
        assert_eq!(suggestion.estimated_mappings, 3);
        assert!(matches!(
            suggestion.estimated_complexity,
            calxgloss_types::ComplexityScore::Low
        ));
    }

    #[test]
    fn test_suggest_shim_layers_filters_correctly() {
        let analyzer = test_analyzer();
        let classifications = vec![
            DllClassification {
                binary: "d3d9.dll".to_string(),
                category: DllCategory::MicrosoftSdk,
                strategy: Strategy::CrateReplacement {
                    crate_name: "wgpu".to_string(),
                },
                exports_count: 50,
                imports_count: 10,
                crate_replacement: Some("wgpu".to_string()),
                known_runtime: false,
                reason: String::new(),
            },
            DllClassification {
                binary: "kernel32.dll".to_string(),
                category: DllCategory::WindowsOs,
                strategy: Strategy::PalMapping,
                exports_count: 500,
                imports_count: 0,
                crate_replacement: None,
                known_runtime: false,
                reason: String::new(),
            },
            DllClassification {
                binary: "game_logic.dll".to_string(),
                category: DllCategory::ProjectSpecific,
                strategy: Strategy::ReverseEngineer,
                exports_count: 100,
                imports_count: 5,
                crate_replacement: None,
                known_runtime: false,
                reason: String::new(),
            },
            DllClassification {
                binary: "fmod.dll".to_string(),
                category: DllCategory::KnownThirdParty,
                strategy: Strategy::CrateReplacement {
                    crate_name: "fmod-rs".to_string(),
                },
                exports_count: 80,
                imports_count: 2,
                crate_replacement: Some("fmod-rs".to_string()),
                known_runtime: false,
                reason: String::new(),
            },
        ];

        let report = analyzer.suggest_shim_layers(&classifications);
        assert_eq!(report.total_dlls(), 2);
        assert_eq!(report.low_complexity_count(), 0);
        // fmod (80*5 + 2*3 = 406) → High, d3d9 (50*5 + 10*3 = 280) → High
        assert_eq!(report.high_complexity_count(), 2);
        assert!(!report.is_empty());
    }

    #[test]
    fn test_suggest_shim_layers_empty() {
        let analyzer = test_analyzer();
        let classifications = vec![
            DllClassification {
                binary: "kernel32.dll".to_string(),
                category: DllCategory::WindowsOs,
                strategy: Strategy::PalMapping,
                exports_count: 500,
                imports_count: 0,
                crate_replacement: None,
                known_runtime: false,
                reason: String::new(),
            },
            DllClassification {
                binary: "game_logic.dll".to_string(),
                category: DllCategory::ProjectSpecific,
                strategy: Strategy::ReverseEngineer,
                exports_count: 100,
                imports_count: 5,
                crate_replacement: None,
                known_runtime: false,
                reason: String::new(),
            },
        ];

        let report = analyzer.suggest_shim_layers(&classifications);
        assert!(report.is_empty());
        assert_eq!(report.total_dlls(), 0);
        assert_eq!(report.average_confidence(), 0.0);
    }

    #[test]
    fn test_estimate_complexity_zero_exports() {
        let classification = DllClassification {
            binary: "empty.dll".to_string(),
            category: DllCategory::MicrosoftSdk,
            strategy: Strategy::CrateReplacement {
                crate_name: "wgpu".to_string(),
            },
            exports_count: 0,
            imports_count: 0,
            crate_replacement: Some("wgpu".to_string()),
            known_runtime: false,
            reason: String::new(),
        };

        let suggestion = suggest_shim(&classification);
        assert_eq!(suggestion.estimated_mappings, 0);
        assert!(matches!(
            suggestion.estimated_complexity,
            calxgloss_types::ComplexityScore::Low
        ));
        assert!(suggestion.estimated_confidence >= 0.0 && suggestion.estimated_confidence <= 1.0);
    }

    // ── Binary classification overrides (issue #97, W2.8) ──

    fn dll_info(name: &str) -> DllInfo {
        DllInfo {
            name: name.to_string(),
            version: None,
            category: DllCategory::ProjectSpecific,
            known_runtime: false,
            exports: Vec::new(),
            imports: Vec::new(),
        }
    }

    fn analyzer_with_override(
        binary: &str,
        record: calxgloss_types::BinaryClassificationOverride,
    ) -> Analyzer {
        let control = calxgloss_types::ClassificationOverrideControl::new();
        control.set(binary, record).expect("in-memory override");
        test_analyzer().with_classification_overrides(control)
    }

    fn override_record(
        category: DllCategory,
        crate_replacement: Option<&str>,
        known_runtime: bool,
    ) -> calxgloss_types::BinaryClassificationOverride {
        calxgloss_types::BinaryClassificationOverride {
            category,
            crate_replacement: crate_replacement.map(str::to_string),
            known_runtime,
        }
    }

    #[test]
    fn test_classification_override_routes_away_from_heuristic_strategy() {
        // fmod.dll heuristically routes to crate replacement; an override
        // to WindowsOs routes it to PAL mapping instead — observable in
        // which strategy the binary lands on.
        let analyzer = analyzer_with_override(
            "fmod.dll",
            override_record(DllCategory::WindowsOs, None, false),
        );
        let classification = analyzer.classify_dll_info(&dll_info("fmod.dll"));
        assert_eq!(classification.category, DllCategory::WindowsOs);
        assert_eq!(classification.strategy, Strategy::PalMapping);
        assert!(!classification.known_runtime);
        assert!(classification.reason.contains("operator override"));
    }

    #[test]
    fn test_classification_override_crate_replacement_mode_carries_the_target_crate() {
        // Overriding to crate-replacement mode with a target crate: the
        // shim layer lands where the operator pointed it.
        let analyzer = analyzer_with_override(
            "game_logic.dll",
            override_record(DllCategory::KnownThirdParty, Some("mlua"), false),
        );
        let classification = analyzer.classify_dll_info(&dll_info("game_logic.dll"));
        assert_eq!(classification.category, DllCategory::KnownThirdParty);
        assert_eq!(
            classification.strategy,
            Strategy::CrateReplacement {
                crate_name: "mlua".to_string()
            }
        );
        assert_eq!(
            classification.crate_replacement.as_deref(),
            Some("mlua"),
            "the operator's target crate rides into the record"
        );
    }

    #[test]
    fn test_classification_override_to_runtime_library_sets_known_runtime() {
        // The Evidence glossary rule: a runtime-library classification is
        // never a translation target — the flag must follow the category
        // even when the record left it false.
        let analyzer = analyzer_with_override(
            "game_logic.dll",
            override_record(DllCategory::RuntimeLibrary, None, false),
        );
        let classification = analyzer.classify_dll_info(&dll_info("game_logic.dll"));
        assert_eq!(classification.category, DllCategory::RuntimeLibrary);
        assert!(
            classification.known_runtime,
            "a RuntimeLibrary classification is never a translation target"
        );
    }

    #[test]
    fn test_classification_override_clears_the_runtime_flag_for_other_categories() {
        // msvcr100.dll heuristically reads as a runtime library; overriding
        // it to ProjectSpecific must clear the flag — the operator is
        // making it a translation target on purpose.
        let heuristic = test_analyzer().classify_dll_info(&dll_info("msvcr100.dll"));
        assert_eq!(heuristic.category, DllCategory::RuntimeLibrary);
        assert!(heuristic.known_runtime);

        let analyzer = analyzer_with_override(
            "msvcr100.dll",
            override_record(DllCategory::ProjectSpecific, None, false),
        );
        let classification = analyzer.classify_dll_info(&dll_info("msvcr100.dll"));
        assert_eq!(classification.category, DllCategory::ProjectSpecific);
        assert!(
            !classification.known_runtime,
            "the override's category and flag are both honored, not the heuristic's"
        );
    }

    #[test]
    fn test_classification_override_keyed_verbatim() {
        // The override is keyed by binary identity — a differently spelled
        // filename keeps its heuristic classification.
        let analyzer = analyzer_with_override(
            "Fmod.dll",
            override_record(DllCategory::WindowsOs, None, false),
        );
        let classification = analyzer.classify_dll_info(&dll_info("fmod.dll"));
        assert_eq!(
            classification.category,
            DllCategory::KnownThirdParty,
            "fmod.dll (lowercase) is a different binary than Fmod.dll"
        );
    }

    #[test]
    fn test_classification_without_override_records_reason_and_runtime_flag() {
        // Un-overridden classifications stay honest: the reason names the
        // table that matched, and the runtime flag follows the category.
        let analyzer = test_analyzer();
        let fmod = analyzer.classify_dll_info(&dll_info("fmod.dll"));
        assert!(
            fmod.reason.contains("known third-party") && fmod.reason.contains("fmod-rs"),
            "reason should name the matched table, got: {}",
            fmod.reason
        );
        assert!(!fmod.known_runtime);

        let runtime = analyzer.classify_dll_info(&dll_info("msvbvm60.dll"));
        assert!(runtime.known_runtime);
        assert!(runtime.reason.contains("runtime-library"));
    }

    // ── .NET managed assembly detection (issue #235) ──

    /// A minimal PE32+ image, byte-assembled: DOS header → PE signature →
    /// COFF header → optional header with 16 data directories → one section.
    /// `managed` fills the COM descriptor directory (#14) and backs it with
    /// the full chain goblin walks for a real .NET binary — a section mapping
    /// the directory's RVA, a COR20 header, and a metadata root carrying the
    /// `BSJB` signature; a native image leaves every directory zero (goblin
    /// reads those as absent).
    fn minimal_pe_bytes(managed: bool) -> Vec<u8> {
        let mut pe = vec![0u8; 0x400];
        pe[0..2].copy_from_slice(b"MZ");
        pe[0x3C..0x40].copy_from_slice(&0x40u32.to_le_bytes()); // e_lfanew
        pe[0x40..0x44].copy_from_slice(b"PE\0\0");
        let coff = 0x44;
        pe[coff..coff + 2].copy_from_slice(&0x8664u16.to_le_bytes()); // AMD64
        pe[coff + 2..coff + 4].copy_from_slice(&1u16.to_le_bytes()); // one section
        pe[coff + 16..coff + 18].copy_from_slice(&240u16.to_le_bytes()); // opt header size
        pe[coff + 18..coff + 20].copy_from_slice(&0x2002u16.to_le_bytes()); // DLL, executable
        let opt = coff + 20;
        pe[opt..opt + 2].copy_from_slice(&0x20Bu16.to_le_bytes()); // PE32+ magic
        pe[opt + 32..opt + 36].copy_from_slice(&0x1000u32.to_le_bytes()); // section alignment
        pe[opt + 36..opt + 40].copy_from_slice(&0x200u32.to_le_bytes()); // file alignment
        pe[opt + 56..opt + 60].copy_from_slice(&0x1200u32.to_le_bytes()); // size of image
        pe[opt + 60..opt + 64].copy_from_slice(&0x200u32.to_le_bytes()); // size of headers
        pe[opt + 68..opt + 70].copy_from_slice(&3u16.to_le_bytes()); // subsystem: console
        pe[opt + 108..opt + 112].copy_from_slice(&16u32.to_le_bytes()); // data directory count
        // The section table follows the 240-byte optional header: one .text
        // section mapping RVA 0x1000 to file offset 0x300.
        let sec = opt + 240;
        pe[sec..sec + 5].copy_from_slice(b".text");
        pe[sec + 8..sec + 12].copy_from_slice(&0x100u32.to_le_bytes()); // virtual size
        pe[sec + 12..sec + 16].copy_from_slice(&0x1000u32.to_le_bytes()); // virtual address
        pe[sec + 16..sec + 20].copy_from_slice(&0x100u32.to_le_bytes()); // raw data size
        pe[sec + 20..sec + 24].copy_from_slice(&0x300u32.to_le_bytes()); // raw data pointer
        pe[sec + 36..sec + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes()); // characteristics
        if managed {
            let dd14 = opt + 112 + 14 * 8;
            pe[dd14..dd14 + 4].copy_from_slice(&0x1000u32.to_le_bytes()); // COM descriptor RVA
            pe[dd14 + 4..dd14 + 8].copy_from_slice(&0x48u32.to_le_bytes()); // and size
            // The COR20 header at file 0x300 (RVA 0x1000), pointing at metadata.
            pe[0x300..0x304].copy_from_slice(&0x48u32.to_le_bytes()); // size of this header
            pe[0x304..0x306].copy_from_slice(&2u16.to_le_bytes()); // major runtime version
            pe[0x306..0x308].copy_from_slice(&5u16.to_le_bytes()); // minor runtime version
            pe[0x308..0x30C].copy_from_slice(&0x1048u32.to_le_bytes()); // metadata RVA
            pe[0x30C..0x310].copy_from_slice(&0x40u32.to_le_bytes()); // metadata size
            // The metadata root at file 0x348 (RVA 0x1048).
            pe[0x348..0x34C].copy_from_slice(b"BSJB");
            pe[0x34C..0x350].copy_from_slice(&1u32.to_le_bytes()); // major=1, minor=0
            pe[0x354..0x358].copy_from_slice(&4u32.to_le_bytes()); // version string length
            pe[0x358..0x35C].copy_from_slice(b"v4.0");
        }
        pe
    }

    /// Classifies fixture PEs written into a temp target dir through the
    /// analyzer's classification seam — the same seam the `classify`
    /// command drives.
    async fn classify_fixtures(
        analyzer: &Analyzer,
        fixtures: &[(&str, Vec<u8>)],
    ) -> Result<Vec<DllClassification>> {
        let dir = tempfile::tempdir().expect("temp target dir");
        let mut names = Vec::new();
        for (name, bytes) in fixtures {
            std::fs::write(dir.path().join(name), bytes).expect("write fixture PE");
            names.push(name.to_string());
        }
        analyzer.classify_dlls(&names, dir.path()).await
    }

    #[tokio::test]
    async fn classify_dlls_detects_managed_pe_and_parks_it() {
        let analyzer = test_analyzer();
        let classifications =
            classify_fixtures(&analyzer, &[("managed_app.dll", minimal_pe_bytes(true))])
                .await
                .expect("fixture PE classifies");
        let c = &classifications[0];
        assert_eq!(c.category, DllCategory::DotNetManaged);
        assert_eq!(c.strategy, Strategy::DoNotTranslate);
        assert!(
            c.reason.contains("we do not yet decompile .NET programs"),
            "the record documents the gap, got: {}",
            c.reason
        );
        assert!(
            !c.known_runtime,
            "a parked managed assembly is not a runtime library — the flag stays false"
        );
    }

    #[tokio::test]
    async fn managed_pe_fact_outranks_the_name_tables() {
        // fmod.dll heuristically reads as known third-party; a managed
        // fmod.dll is still parked honestly (story 25).
        let analyzer = test_analyzer();
        let classifications =
            classify_fixtures(&analyzer, &[("fmod.dll", minimal_pe_bytes(true))])
                .await
                .expect("fixture PE classifies");
        assert_eq!(classifications[0].category, DllCategory::DotNetManaged);
        assert_eq!(classifications[0].strategy, Strategy::DoNotTranslate);
    }

    #[tokio::test]
    async fn native_pe_classifies_by_name_exactly_as_before() {
        let analyzer = test_analyzer();
        let classifications =
            classify_fixtures(&analyzer, &[("game_logic.dll", minimal_pe_bytes(false))])
                .await
                .expect("fixture PE classifies");
        let c = &classifications[0];
        assert_eq!(c.category, DllCategory::ProjectSpecific);
        assert_eq!(c.strategy, Strategy::ReverseEngineer);
    }

    #[tokio::test]
    async fn operator_override_wins_over_managed_detection() {
        // The escape hatch is real: overriding a managed-detected binary
        // to a normal strategy routes it back to translation (story 21).
        let analyzer = analyzer_with_override(
            "managed_app.dll",
            override_record(DllCategory::ProjectSpecific, None, false),
        );
        let classifications =
            classify_fixtures(&analyzer, &[("managed_app.dll", minimal_pe_bytes(true))])
                .await
                .expect("fixture PE classifies");
        let c = &classifications[0];
        assert_eq!(c.category, DllCategory::ProjectSpecific);
        assert_eq!(c.strategy, Strategy::ReverseEngineer);
        assert!(c.reason.contains("operator override"));
    }

    #[tokio::test]
    async fn corrupt_pe_fails_classification_exactly_as_today() {
        // The .NET check rides the existing parse — it does not change
        // what a corrupt binary does (story 26).
        let analyzer = test_analyzer();
        let result = classify_fixtures(&analyzer, &[("broken.dll", b"MZnot-a-real-pe".to_vec())])
            .await;
        assert!(result.is_err(), "a corrupt PE still fails classification");
    }
}
