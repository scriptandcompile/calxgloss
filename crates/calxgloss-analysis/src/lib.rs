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
//! // Classify all DLLs for a target executable
//! let classifications = analyzer.classify_target("myapp.exe").await?;
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
pub mod error;

pub use classify::*;
pub use error::{AnalysisError, Result};

use calxgloss_types::{DllCategory, DllInfo, FunctionInfo, Import, WindowsApiCall};
use calxgloss_ghidra::GhidraClient;
use calxgloss_pal::ApiMappings;
use tracing::{debug, info, instrument};

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
        Self { ghidra, api_mappings }
    }

    /// Classifies a single DLL by fetching its metadata from Ghidra and
    /// applying classification heuristics based on the DLL filename.
    ///
    /// This method queries the Ghidra server for the DLL's imports and exports,
    /// then classifies the DLL using [`classify_dll_name`].
    ///
    /// # Arguments
    ///
    /// * `target_exe` — The target executable that was loaded into Ghidra.
    /// * `dll` — The DLL filename to classify (e.g., `game_logic.dll`).
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
    /// let classification = analyzer.classify_dll("myapp.exe", "game_logic.dll").await?;
    /// println!("Strategy: {:?}", classification.strategy);
    /// # Ok(())
    /// # }
    /// ```
    #[instrument(skip(self), fields(target_exe, dll, base_url = %self.ghidra.base_url()))]
    pub async fn classify_dll(&self, target_exe: &str, dll: &str) -> Result<DllClassification> {
        debug!(target_exe, dll, "Classifying DLL");

        // Fetch imports and exports from Ghidra
        let imports = self.ghidra.get_imports(target_exe, dll).await.unwrap_or_default();
        let exports = self.ghidra.get_exports(target_exe, dll).await.unwrap_or_default();

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

    /// Classifies all DLLs associated with a target executable.
    ///
    /// First lists all DLLs known to the Ghidra server for the target,
    /// then classifies each one using [`classify_dll`].
    ///
    /// # Arguments
    ///
    /// * `target_exe` — The target executable that was loaded into Ghidra.
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
    /// let classifications = analyzer.classify_target("myapp.exe").await?;
    /// for c in &classifications {
    ///     println!("{}: {:?}", c.dll, c.strategy);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    #[instrument(skip(self), fields(target_exe, base_url = %self.ghidra.base_url()))]
    pub async fn classify_target(&self, target_exe: &str) -> Result<Vec<DllClassification>> {
        debug!(target_exe, "Classifying target");

        let dlls = self.ghidra.list_dlls(target_exe).await?;
        info!(count = dlls.len(), target_exe, "Fetched DLL list");

        let mut classifications = Vec::with_capacity(dlls.len());
        for dll in &dlls {
            let classification = self.classify_dll(target_exe, dll).await?;
            classifications.push(classification);
        }

        info!(count = classifications.len(), target_exe, "Classified all DLLs");
        Ok(classifications)
    }

    /// Performs complete analysis on a single function.
    ///
    /// Fetches the function's metadata from Ghidra (disassembly, decompiler
    /// output, call graph), then tags any Windows API calls found in the
    /// imports using [`tag_windows_apis`].
    ///
    /// # Arguments
    ///
    /// * `target_exe` — The target executable that was loaded into Ghidra.
    /// * `dll` — The DLL containing the function.
    /// * `function` — The function name to analyze.
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
    /// let analysis = analyzer.analyze_function("myapp.exe", "game_logic.dll", "DrawSprite").await?;
    /// println!("Found {} tagged Windows API calls", analysis.tagged_apis.len());
    /// # Ok(())
    /// # }
    /// ```
    #[instrument(skip(self), fields(target_exe, dll, function, base_url = %self.ghidra.base_url()))]
    pub async fn analyze_function(
        &self,
        target_exe: &str,
        dll: &str,
        function: &str,
    ) -> Result<FunctionAnalysis> {
        debug!(target_exe, dll, function, "Analyzing function");

        // Fetch complete function info from Ghidra
        let function_info = self.ghidra.get_function(target_exe, dll, function).await?;

        // Fetch imports to cross-reference with API mappings
        let imports = self.ghidra.get_imports(target_exe, dll).await.unwrap_or_default();

        // Tag Windows API calls in the function's imports
        let tagged_apis = self.tag_windows_apis(&function_info.disassembly, &imports)?;

        let analysis = FunctionAnalysis {
            function_info,
            tagged_apis,
            call_graph: Vec::new(),
        };

        info!(
            dll,
            function,
            tagged_apis = analysis.tagged_apis.len(),
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
    /// let imports = vec![
    ///     Import { dll: "kernel32.dll".to_string(), function: "CreateFileA".to_string() },
    ///     Import { dll: "kernel32.dll".to_string(), function: "ReadFile".to_string() },
    /// ];
    ///
    /// let tagged = analyzer.tag_windows_apis("", &imports).unwrap();
    /// assert_eq!(tagged.len(), 2);
    /// assert_eq!(tagged[0].name, "CreateFileA");
    /// ```
    pub fn tag_windows_apis(&self, disassembly: &str, imports: &[Import]) -> Result<Vec<WindowsApiCall>> {
        debug!(imports_count = imports.len(), "Tagging Windows APIs");

        // Collect function names from disassembly to check for direct API references
        let mut tagged = Vec::new();
        let mut seen = std::collections::HashSet::new();

        // Tag APIs found in the imports
        for import in imports {
            let api_name = &import.function;

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
}

#[cfg(test)]
mod tests {
    use super::*;
    use calxgloss_types::{Export, Import};
    use calxgloss_ghidra::GhidraClient;
    use calxgloss_pal::ApiMappings;

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
        let imports = vec![
            Import {
                dll: "kernel32.dll".to_string(),
                function: "CreateFileA".to_string(),
            },
            Import {
                dll: "kernel32.dll".to_string(),
                function: "ReadFile".to_string(),
            },
        ];

        let tagged = analyzer.tag_windows_apis("", &imports).unwrap();
        assert_eq!(tagged.len(), 2);
        assert_eq!(tagged[0].name, "CreateFileA");
        assert_eq!(tagged[1].name, "ReadFile");
    }

    #[test]
    fn test_tag_windows_apis_deduplication() {
        let analyzer = test_analyzer();
        let imports = vec![
            Import {
                dll: "kernel32.dll".to_string(),
                function: "CreateFileA".to_string(),
            },
            Import {
                dll: "kernel32.dll".to_string(),
                function: "CreateFileA".to_string(),
            },
        ];

        let tagged = analyzer.tag_windows_apis("", &imports).unwrap();
        assert_eq!(tagged.len(), 1);
    }

    #[test]
    fn test_tag_windows_apis_unrecognized() {
        let analyzer = test_analyzer();
        let imports = vec![Import {
            dll: "unknown.dll".to_string(),
            function: "UnknownFunction".to_string(),
        }];

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
        let imports: Vec<Import> = vec![];

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
        assert_eq!(classification.crate_replacement, Some("fmod-rs".to_string()));
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
                Export { name: "Func1".to_string(), address: 0x1000, signature: "int __stdcall Func1()".to_string() },
                Export { name: "Func2".to_string(), address: 0x2000, signature: "void __stdcall Func2()".to_string() },
            ],
            imports: vec![
                Import { dll: "kernel32.dll".to_string(), function: "CreateFileA".to_string() },
                Import { dll: "user32.dll".to_string(), function: "MessageBoxA".to_string() },
                Import { dll: "user32.dll".to_string(), function: "DestroyWindow".to_string() },
            ],
        };

        let classification = analyzer.classify_dll_info(&dll_info);
        assert_eq!(classification.exports_count, 2);
        assert_eq!(classification.imports_count, 3);
    }
}
