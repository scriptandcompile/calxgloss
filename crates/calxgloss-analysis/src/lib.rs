//! DLL classification, call graph analysis, and Windows API tagging.
//!
//! This crate provides the [`Analyzer`] struct, which orchestrates the analysis
//! of target DLLs by combining data from a GhidraMCP server with the PAL mapping
//! table from `calxgloss-pal`.
//!
//! # Main Capabilities
//!
//! - **DLL Classification** — categorize each DLL as `WindowsOs`, `MicrosoftSdk`,
//!   `KnownThirdParty`, `ProjectSpecific`, or `UnknownThirdParty`, and determine
//!   the appropriate reverse-engineering strategy.
//! - **Function Analysis** — extract complete function metadata including
//!   disassembly, decompiler output, Windows API calls, and call graph neighbors.
//! - **Windows API Tagging** — cross-reference disassembly and imports against the
//!   PAL mapping table to identify and tag every Windows API call with its
//!   category and cross-platform replacement.
//!
//! # Example
//!
//! ```no_run
//! use calxgloss_analysis::Analyzer;
//! use calxgloss_pal::ApiMappings;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let ghidra = calxgloss_ghidra::GhidraClient::new("http://localhost:8080")?;
//! let api_mappings = ApiMappings::default();
//! let analyzer = Analyzer::new(ghidra, api_mappings);
//!
//! // Classify the DLLs you care about
//! let names = vec!["eqmain.dll".to_string()];
//! let classifications = analyzer.classify_dlls(&names).await?;
//! for classification in &classifications {
//!     println!(
//!         "{:20} → {:?} ({:?})",
//!         classification.dll, classification.category, classification.strategy
//!     );
//! }
//! # Ok(())
//! # }
//! ```

mod classify;
pub mod benchmark;
pub mod error;

pub use benchmark::*;
pub use classify::*;
pub use error::{AnalysisError, Result};

use calxgloss_ghidra::GhidraClient;
use calxgloss_pal::ApiMappings;
use calxgloss_types::{DllCategory, DllInfo, FunctionInfo, WindowsApiCall};
use calxgloss_types::{FunctionComplexity, PromptVariant};
use error::AnalysisError as Error;
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
#[derive(Debug, Clone, PartialEq, Eq)]
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
}

/// Classification result for a single DLL.
///
/// Produced by [`Analyzer::classify_dll`] or [`Analyzer::classify_target`].
/// Contains the DLL's category, the recommended strategy, symbol counts,
/// and any crate replacement name.
#[derive(Debug, Clone)]
pub struct DllClassification {
    /// The DLL filename (e.g., `game_logic.dll`).
    pub dll: String,

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
}

/// Complete analysis result for a single function.
///
/// Produced by [`Analyzer::analyze_function`]. Aggregates Ghidra function data
/// with tagged Windows API calls and call graph information.
#[derive(Debug, Clone)]
pub struct FunctionAnalysis {
    /// The function's basic information (name, address, DLL).
    pub function_info: FunctionInfo,

    /// Windows API calls identified within this function, tagged with their
    /// PAL mappings. Derived from cross-referencing disassembly/imports against
    /// the PAL mapping table.
    pub tagged_apis: Vec<WindowsApiCall>,

    /// Call graph neighbors from Ghidra analysis.
    pub call_graph: Vec<String>,
}

// ============================================================
// Analyzer
// ============================================================

/// Analyzes target DLLs: classifies them, extracts function metadata,
/// and tags Windows API calls with their cross-platform mappings.
///
/// The analyzer combines data from a GhidraMCP server (imports, exports,
/// disassembly, decompiler output, call graphs) with the static PAL mapping
/// table to produce structured analysis results.
///
/// # Construction
///
/// ```
/// use calxgloss_analysis::Analyzer;
/// use calxgloss_pal::ApiMappings;
///
/// let ghidra = calxgloss_ghidra::GhidraClient::new("http://localhost:8080").unwrap();
/// let mappings = ApiMappings::default();
/// let analyzer = Analyzer::new(ghidra, mappings);
/// ```
#[derive(Debug, Clone)]
pub struct Analyzer {
    /// Client for querying the GhidraMCP server.
    ghidra: GhidraClient,

    /// Windows API → Rust equivalent mapping table.
    api_mappings: ApiMappings,
}

impl Analyzer {
    /// Creates a new analyzer with the given Ghidra client and API mappings.
    ///
    /// The analyzer uses the Ghidra client to fetch DLL/function metadata and
    /// the API mappings to tag Windows API calls with their PAL replacements.
    pub fn new(ghidra: GhidraClient, api_mappings: ApiMappings) -> Self {
        Self {
            ghidra,
            api_mappings,
        }
    }

    /// Classifies a single DLL by fetching its metadata from Ghidra and
    /// applying classification heuristics based on the DLL filename.
    ///
    /// # Arguments
    ///
    /// * `dll` — The DLL filename to classify (e.g., `game_logic.dll`).
    ///
    /// # A note on the symbol counts
    ///
    /// Ghidra serves one program at a time and exposes no per-DLL routing, so
    /// `exports_count` and `imports_count` are the counts for whichever program
    /// is open in Ghidra — not for the DLL named in `dll`. The category itself
    /// comes from the filename and is unaffected. Call this when the open
    /// program is the DLL you mean; otherwise the counts describe something
    /// else while still being attached to `dll`.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use calxgloss_analysis::Analyzer;
    /// use calxgloss_pal::ApiMappings;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let ghidra = calxgloss_ghidra::GhidraClient::new("http://localhost:8080")?;
    /// let analyzer = Analyzer::new(ghidra, ApiMappings::default());
    ///
    /// let classification = analyzer.classify_dll("game_logic.dll").await?;
    /// println!("Strategy: {:?}", classification.strategy);
    /// # Ok(())
    /// # }
    /// ```
    #[instrument(skip(self), fields(dll, base_url = %self.ghidra.base_url()))]
    pub async fn classify_dll(&self, dll: &str) -> Result<DllClassification> {
        debug!(dll, "Classifying DLL");

        // Symbol counts come from the program currently open in Ghidra; see the
        // note on this method about what that means for a named DLL.
        let imports = self.ghidra.imports(None).await.unwrap_or_else(|e| {
            warn!(dll, error = %e, "Could not read imports; counting none");
            Vec::new()
        });
        let exports = self.ghidra.exports(None).await.unwrap_or_else(|e| {
            warn!(dll, error = %e, "Could not read exports; counting none");
            Vec::new()
        });

        // Classify based on DLL filename
        let category = classify_dll_name(dll);
        let crate_replacement = crate_replacement_for(dll, &category);

        let strategy = match &category {
            DllCategory::WindowsOs => Strategy::PalMapping,
            DllCategory::MicrosoftSdk | DllCategory::KnownThirdParty => {
                Strategy::CrateReplacement {
                    crate_name: crate_replacement.clone().unwrap_or_default(),
                }
            }
            DllCategory::ProjectSpecific | DllCategory::UnknownThirdParty => {
                Strategy::ReverseEngineer
            }
        };

        let classification = DllClassification {
            dll: dll.to_string(),
            category,
            strategy,
            exports_count: exports.len(),
            imports_count: imports.len(),
            crate_replacement,
        };

        info!(
            dll,
            category = ?classification.category,
            strategy = ?classification.strategy,
            exports = classification.exports_count,
            imports = classification.imports_count,
            "Classified DLL"
        );

        Ok(classification)
    }

    /// Classifies each of the named DLLs using [`classify_dll`].
    ///
    /// The names are supplied by the caller because Ghidra has no way to
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
    /// let ghidra = calxgloss_ghidra::GhidraClient::new("http://localhost:8080")?;
    /// let analyzer = Analyzer::new(ghidra, ApiMappings::default());
    ///
    /// let names = vec!["eqmain.dll".to_string(), "eqgui.dll".to_string()];
    /// for c in analyzer.classify_dlls(&names).await? {
    ///     println!("{}: {:?}", c.dll, c.strategy);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    #[instrument(skip(self, dlls), fields(count = dlls.len(), base_url = %self.ghidra.base_url()))]
    pub async fn classify_dlls(&self, dlls: &[String]) -> Result<Vec<DllClassification>> {
        let mut classifications = Vec::with_capacity(dlls.len());
        for dll in dlls {
            classifications.push(self.classify_dll(dll).await?);
        }

        info!(count = classifications.len(), "Classified all DLLs");
        Ok(classifications)
    }

    /// Performs complete analysis on a single function.
    ///
    /// Resolves `function` to an address in the program open in Ghidra, fetches
    /// its decompilation, disassembly and cross-references, then tags any
    /// Windows API calls found in the program's imports using
    /// [`tag_windows_apis`].
    ///
    /// # Arguments
    ///
    /// * `dll` — The DLL the function belongs to. Recorded on the result; the
    ///   lookup itself is against the program Ghidra has open, which must be
    ///   this DLL.
    /// * `function` — The function name, as Ghidra knows it.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use calxgloss_analysis::Analyzer;
    /// use calxgloss_pal::ApiMappings;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let ghidra = calxgloss_ghidra::GhidraClient::new("http://localhost:8080")?;
    /// let analyzer = Analyzer::new(ghidra, ApiMappings::default());
    ///
    /// let analysis = analyzer.analyze_function("game_logic.dll", "DrawSprite").await?;
    /// println!("Found {} tagged Windows API calls", analysis.tagged_apis.len());
    /// # Ok(())
    /// # }
    /// ```
    #[instrument(skip(self), fields(dll, function, base_url = %self.ghidra.base_url()))]
    pub async fn analyze_function(&self, dll: &str, function: &str) -> Result<FunctionAnalysis> {
        debug!(dll, function, "Analyzing function");

        // Ghidra has no lookup that returns a function without an address, so
        // the name is resolved first. A partial match is refused rather than
        // guessed at, since silently analysing the wrong function would produce
        // a plausible but irrelevant translation.
        let matches = self.ghidra.search_functions(function, Some(1)).await?;
        let found = matches.iter().find(|m| m.name == function).ok_or_else(|| {
            Error::FunctionAnalysisFailed {
                dll: dll.to_string(),
                function: function.to_string(),
                reason: format!(
                    "no function by that exact name in the program Ghidra has open; the \
                         search matched {:?}. If the name is a substring of the real one, pass \
                         the full name.",
                    matches.iter().map(|m| &m.name).collect::<Vec<_>>()
                ),
            }
        })?;
        let report = self.ghidra.function_report(found.address).await?;

        // Imports of the open program, used to spot Windows API calls.
        let import_names: Vec<String> = self
            .ghidra
            .imports(None)
            .await
            .unwrap_or_else(|e| {
                warn!(error = %e, "Could not read imports; tagging no API calls");
                Vec::new()
            })
            .into_iter()
            .map(|s| s.name)
            .collect();

        // Tag Windows API calls in the function's disassembly
        let tagged_apis = self.tag_windows_apis(&report.disassembly, &import_names)?;

        // Ghidra has no call-graph endpoint. Callers come from the
        // cross-references to the entry; callees are scraped from the
        // decompiled body, which cannot see calls made through a function
        // pointer.
        let call_graph: Vec<String> = report
            .callers
            .iter()
            .chain(report.callees.iter())
            .cloned()
            .collect();

        let analysis = FunctionAnalysis {
            function_info: FunctionInfo {
                name: report.name.clone(),
                address: report.address,
                dll: dll.to_string(),
                disassembly: report.disassembly,
                decompiler_output: report.decompiled.body,
                windows_apis: Vec::new(),
                call_graph: call_graph.clone(),
            },
            tagged_apis: tagged_apis.clone(),
            call_graph,
        };

        info!(
            dll,
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
    /// This is a pure analysis function that doesn't require Ghidra network calls —
    /// it works with the disassembly text and import list provided.
    ///
    /// # Arguments
    ///
    /// * `disassembly` — The raw disassembly text for the function.
    /// * `imports` — The list of imports for the DLL containing the function.
    ///
    /// # Example
    ///
    /// ```
    /// use calxgloss_analysis::Analyzer;
    /// use calxgloss_types::Import;
    /// use calxgloss_pal::ApiMappings;
    /// use calxgloss_ghidra::GhidraClient;
    ///
    /// let ghidra = GhidraClient::new("http://localhost:8080").unwrap();
    /// let analyzer = Analyzer::new(ghidra, ApiMappings::default());
    ///
    /// let imports = vec!["CreateFileA".to_string(), "ReadFile".to_string()];
    ///
    /// let tagged = analyzer.tag_windows_apis("", &imports).unwrap();
    /// assert_eq!(tagged.len(), 2);
    /// assert_eq!(tagged[0].name, "CreateFileA");
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

    /// Classifies a `DllInfo` struct directly, without needing Ghidra network calls.
    ///
    /// Useful when you already have DLL metadata (e.g., from a cached analysis
    /// or manual inspection) and just need to determine the classification
    /// and strategy.
    ///
    /// # Arguments
    ///
    /// * `dll_info` — The DLL metadata to classify.
    pub fn classify_dll_info(&self, dll_info: &DllInfo) -> DllClassification {
        let category = classify_dll_name(&dll_info.name);
        let crate_replacement = crate_replacement_for(&dll_info.name, &category);

        let strategy = match &category {
            DllCategory::WindowsOs => Strategy::PalMapping,
            DllCategory::MicrosoftSdk | DllCategory::KnownThirdParty => {
                Strategy::CrateReplacement {
                    crate_name: crate_replacement.clone().unwrap_or_default(),
                }
            }
            DllCategory::ProjectSpecific | DllCategory::UnknownThirdParty => {
                Strategy::ReverseEngineer
            }
        };

        DllClassification {
            dll: dll_info.name.clone(),
            category,
            strategy,
            exports_count: dll_info.exports.len(),
            imports_count: dll_info.imports.len(),
            crate_replacement,
        }
    }

    /// Returns a reference to the API mappings used by this analyzer.
    pub fn api_mappings(&self) -> &ApiMappings {
        &self.api_mappings
    }

    /// Returns a reference to the Ghidra client used by this analyzer.
    pub fn ghidra_client(&self) -> &GhidraClient {
        &self.ghidra
    }

    /// Detect the complexity of a function from its disassembly and API usage.
    ///
    /// This is the primary mechanism for deciding how much context to
    /// inject into the LLM prompt. Simple functions get minimal context;
    /// complex functions get rich contextual information.
    ///
    /// # Arguments
    ///
    /// * `disassembly` — The raw disassembly text from Ghidra.
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
    /// the translation pipeline should use. The default is API-aware
    /// (step 2.2 of Phase 2).
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

#[cfg(test)]
mod tests {
    use super::*;
    use calxgloss_ghidra::GhidraClient;
    use calxgloss_pal::ApiMappings;
    use calxgloss_types::{Export, Import};

    fn test_analyzer() -> Analyzer {
        let ghidra = GhidraClient::new("http://localhost:8080").unwrap();
        let api_mappings = ApiMappings::default();
        Analyzer::new(ghidra, api_mappings)
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
                    dll: "kernel32.dll".to_string(),
                    function: "CreateFileA".to_string(),
                },
                Import {
                    dll: "user32.dll".to_string(),
                    function: "MessageBoxA".to_string(),
                },
                Import {
                    dll: "user32.dll".to_string(),
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
                dll: "test.dll".to_string(),
                disassembly: "0x00401000: mov eax, 0\n0x00401004: ret".to_string(),
                decompiler_output: "int SimpleFunc() { return 0; }".to_string(),
                windows_apis: Vec::new(),
                call_graph: Vec::new(),
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
}
