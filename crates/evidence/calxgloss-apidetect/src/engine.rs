//! The API-identification evidence engine: import table plus per-function
//! summaries.
//!
//! [`ApiEngine`] runs the two detectors over one binary. The
//! [`ImportTableScanner`] identifies the binary's imports, and the
//! [`ApiSummaryDetector`] reads the built call graph for the APIs each
//! function reaches. Then the [divergence](crate::divergence) and
//! [com](crate::com) passes read the classified import listing and the
//! graph names for the platform-divergence and COM claims. Everything
//! is collected into one [`ApiDetectionResult`].
//!
//! The evidence engine is generic over the shared [`ScanSource`] plus
//! a [`CallGraphSource`] for the built graph, so tests can run the
//! whole orchestration over canned data. [`new`](Self::new) builds one
//! over a loaded [`KunaSource`].

use std::time::Instant;

use calxgloss_callgraph::{CallGraphBuilder, FunctionCallGraph};
use calxgloss_kuna::KunaSource;
use calxgloss_types::{CoverageStatus, FacetCoverage, ScanCoverage};
use tracing::{info, warn};

use crate::api_summary::ApiSummaryDetector;
use crate::com::detect_com;
use crate::divergence::detect_divergence;
use crate::error::{ApiError, Result};
use crate::import_table::ImportTableScanner;
use crate::types::{ApiDetectionResult, ScanMetadata};

/// The program facts an API scan reads.
///
/// This is the shared trait from the decompiler seam crate, re-exported
/// here so the evidence engine's generic bounds name it directly.
/// [`KunaSource`] implements it over the in-process analysis engine,
/// and tests implement it over canned listings so the orchestration
/// runs without a server. The futures are `Send` so an orchestrating
/// task can drive a scan.
pub use calxgloss_decomp::ScanSource;

/// The built call graph an API scan reads.
///
/// This trait is deliberately separate from [`ScanSource`]. The call
/// graph is not one seam read — it is a composite of many, assembled
/// by the call-graph builder, which reads through the shared seam
/// itself. So [`ScanSource`] stays a listing of raw program facts, and
/// this small trait supplies the one composite value the summary
/// detector needs.
pub trait CallGraphSource {
    /// The built call graph: one node per function, with its call edges.
    fn call_graph(
        &self,
        binary: &str,
    ) -> impl std::future::Future<Output = Result<Vec<FunctionCallGraph>>> + Send;
}

impl CallGraphSource for KunaSource {
    async fn call_graph(&self, binary: &str) -> Result<Vec<FunctionCallGraph>> {
        let graph =
            CallGraphBuilder::new(calxgloss_decomp::PipelineSource::from(self.clone()), binary)
                .build()
                .await
                .map_err(|error| ApiError::CallGraph {
                    reason: error.to_string(),
                })?;
        Ok(graph.functions)
    }
}

impl CallGraphSource for calxgloss_decomp::PipelineSource {
    async fn call_graph(&self, binary: &str) -> Result<Vec<FunctionCallGraph>> {
        // The builder reads through the shared seam itself, so a cached
        // pipeline source assembles the graph from cached reads.
        let graph = CallGraphBuilder::with_source(self.clone(), binary)
            .build()
            .await
            .map_err(|error| ApiError::CallGraph {
                reason: error.to_string(),
            })?;
        Ok(graph.functions)
    }
}

/// The facet ids apidetect declares — the roster, spelled once here
/// the way the CLI pairing pin (#342) spells its roster. The pin below
/// reads every facet a freshly written coverage record names against
/// this list, and every drift direction is a fault: a declared facet
/// the scan stopped stamping, a facet stamped twice, and an id the
/// scan invented outside the roster all fail loudly. `delay-imports`
/// belongs on the roster precisely because the evidence engine parses
/// no delay-import table — the roster records what the evidence engine
/// knows about, not only what it reads.
pub const DECLARED_FACETS: &[&str] = &["import-table", "api-usage", "delay-imports"];

/// The coverage record every apidetect scan stamps about itself (issue
/// #346), beside the provenance and the timing.
///
/// The import table is always `complete`: a failed import listing
/// aborts the run, so a finished scan read the listing end to end. The
/// per-function API reading is `complete` when the call graph built,
/// and `unavailable` with its reason when the scan degraded to the
/// import table alone — the warning the run already logs lands in the
/// document as well. `delay-imports` is always `unexamined`: parsing
/// the delay-import table is outside what this evidence engine was
/// ever built to examine, and the admission is the point — the API
/// picture states its own border. The whole picture is therefore
/// `partial`: the border stays until an evidence engine change moves
/// it, never because the scan quietly skipped part of what it could
/// read.
fn coverage_stamp(call_graph_available: bool) -> ScanCoverage {
    let api_usage = if call_graph_available {
        FacetCoverage {
            id: "api-usage".to_string(),
            status: CoverageStatus::Complete,
            limitation: None,
        }
    } else {
        FacetCoverage {
            id: "api-usage".to_string(),
            status: CoverageStatus::Unavailable,
            limitation: Some("call graph unavailable".to_string()),
        }
    };
    ScanCoverage {
        status: CoverageStatus::Partial,
        facets: vec![
            FacetCoverage {
                id: "import-table".to_string(),
                status: CoverageStatus::Complete,
                limitation: None,
            },
            api_usage,
            FacetCoverage {
                id: "delay-imports".to_string(),
                status: CoverageStatus::Unexamined,
                limitation: Some("delay imports unexamined".to_string()),
            },
        ],
    }
}

/// Orchestrates the import scanner and the summary detector into one
/// [`ApiDetectionResult`].
///
/// Each detector holds no state and starts configured with the builtin
/// library mappings. [`with_import_scanner`](Self::with_import_scanner)
/// and [`with_summary_detector`](Self::with_summary_detector) swap a
/// detector whole, so one instance of each serves the whole scan.
#[derive(Debug, Clone)]
pub struct ApiEngine<S = KunaSource> {
    source: S,
    scanner: ImportTableScanner,
    detector: ApiSummaryDetector,
}

impl ApiEngine<KunaSource> {
    /// An evidence engine over a loaded Kuna program, scanning with the
    /// builtin library mappings.
    pub fn new(source: &KunaSource) -> ApiEngine<KunaSource> {
        ApiEngine {
            source: source.clone(),
            scanner: ImportTableScanner::new(),
            detector: ApiSummaryDetector::new(),
        }
    }
}

impl<S> ApiEngine<S> {
    /// An evidence engine whose imports and call graph come from
    /// `source`, scanning with the builtin library mappings.
    pub fn with_source(source: S) -> Self {
        ApiEngine {
            source,
            scanner: ImportTableScanner::new(),
            detector: ApiSummaryDetector::new(),
        }
    }

    /// Identify imports against `scanner`'s mappings instead of the
    /// standard ones.
    pub fn with_import_scanner(mut self, scanner: ImportTableScanner) -> Self {
        self.scanner = scanner;
        self
    }

    /// Read API usages with `detector`'s mappings instead of the
    /// standard ones.
    pub fn with_summary_detector(mut self, detector: ApiSummaryDetector) -> Self {
        self.detector = detector;
        self
    }

    /// Identify the libraries and APIs of `binary`.
    ///
    /// `binary` names the program the scan reads (e.g. `eqmain.dll`)
    /// and becomes the key a persisted result is filed under. The
    /// findings follow the import listing: every import entry, in
    /// listing order, then the platform-divergence claim when the
    /// imports mix Win32 and POSIX/stdio families, then the COM claims
    /// when the import and call-graph names show COM signals. Then
    /// come the call-graph findings, function by function, direct
    /// calls before transitive paths. Two scans of the same program
    /// therefore diff cleanly.
    ///
    /// A failure of the import listing — the server being down, for
    /// example — aborts the run, since then nothing was scanned. A
    /// call graph that cannot be built degrades the run to the import
    /// table alone, with a warning: the binary-level identifications
    /// stand on their own, and the COM reading runs off the import
    /// listing without the graph names. The scan also stamps a
    /// coverage record admitting what it did not examine — including
    /// the delay imports it never attempts — so the filed document
    /// says what the scan examined and what it could not (issue #346).
    pub async fn scan(&self, binary: impl Into<String>) -> Result<ApiDetectionResult>
    where
        S: ScanSource + CallGraphSource,
    {
        let started = Instant::now();
        let binary = binary.into();
        let mut findings = self.scanner.scan(&self.source, &binary).await?;
        let imports = findings.len();
        // The divergence reading comes from the classified import
        // listing the scan already holds — no new ScanSource reads —
        // and is placed between the import entries and the usages so
        // the scan-order contract stays diffable.
        if let Some(divergence) = detect_divergence(&findings) {
            findings.push(divergence);
        }

        let graph = match self.source.call_graph(&binary).await {
            Ok(graph) => Some(graph),
            Err(error) => {
                warn!(
                    binary = %binary,
                    error = %error,
                    "Call graph unavailable: reporting the import table alone"
                );
                None
            }
        };

        // The COM reading comes from the classified import listing and
        // the node and callee names the built graph already holds —
        // no new ScanSource reads — and is placed after the import
        // entries (and any divergence claim) and before the usages so
        // the scan-order contract stays diffable.
        let graph_names: Vec<String> = graph
            .iter()
            .flatten()
            .flat_map(|node| {
                std::iter::once(node.name.clone())
                    .chain(node.callees.iter().map(|edge| edge.callee_name.clone()))
            })
            .collect();
        findings.extend(detect_com(&findings, &graph_names));

        if let Some(graph) = &graph {
            findings.extend(self.detector.detect(graph));
        }

        let mut metadata = ScanMetadata::new(binary);
        // The source names its analysis engine and pin under `kuna`
        // (issue #208).
        metadata.engine = self.source.engine_provenance();
        // The evidence engine admits its own coverage inside its own
        // scan, where the truth lives — not the registry row and not
        // the CLI (issue #346). The import table was parsed end to end
        // (a failed listing aborts the run above). The per-function
        // API reading used the graph when one built, and says so when
        // it did not. Delay imports sit outside what this evidence engine
        // was built to examine. The batch scan phase and the CLI's
        // force-rescan therefore file the same admission through the
        // same single definition.
        metadata.coverage = Some(coverage_stamp(graph.is_some()));
        metadata.duration_secs = started.elapsed().as_secs();
        info!(
            binary = %metadata.binary,
            imports,
            findings = findings.len(),
            duration_secs = metadata.duration_secs,
            "Identified libraries and APIs"
        );
        Ok(ApiDetectionResult { metadata, findings })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lib_mapping::{LibraryMapping, MappingDatabase};
    use crate::types::Confidence;
    use calxgloss_callgraph::CallGraphEdge;
    use calxgloss_decomp::{
        DataItem, DataTypeEntry, DecompiledFunction, EngineError, EnumDefinition, FunctionSummary,
        StringLiteral, StructLayout, Symbol, Xref,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct FakeProgram {
        imports: Vec<Symbol>,
        graph: Vec<FunctionCallGraph>,
        fail_imports: bool,
        fail_graph: bool,
        graph_calls: AtomicUsize,
    }

    impl FakeProgram {
        fn new(imports: Vec<&str>, graph: Vec<FunctionCallGraph>) -> Self {
            Self {
                imports: imports
                    .into_iter()
                    .map(|name| Symbol {
                        name: name.into(),
                        address: 0,
                        imported: true,
                    })
                    .collect(),
                graph,
                fail_imports: false,
                fail_graph: false,
                graph_calls: AtomicUsize::new(0),
            }
        }
    }

    impl ScanSource for FakeProgram {
        async fn functions(&self) -> calxgloss_decomp::Result<Vec<FunctionSummary>> {
            Ok(Vec::new())
        }

        async fn decompile(&self, name: &str) -> calxgloss_decomp::Result<DecompiledFunction> {
            Err(EngineError::NotFound {
                kind: "function",
                query: name.to_string(),
            })
        }

        async fn strings(&self) -> calxgloss_decomp::Result<Vec<StringLiteral>> {
            Ok(Vec::new())
        }

        async fn callers(&self, _address: u64) -> calxgloss_decomp::Result<Vec<String>> {
            Ok(Vec::new())
        }

        async fn xrefs_to(&self, _address: u64) -> calxgloss_decomp::Result<Vec<Xref>> {
            Ok(Vec::new())
        }

        async fn data_types(
            &self,
            _category: Option<&str>,
        ) -> calxgloss_decomp::Result<Vec<DataTypeEntry>> {
            Ok(Vec::new())
        }

        async fn struct_layout(&self, name: &str) -> calxgloss_decomp::Result<StructLayout> {
            Err(EngineError::NotFound {
                kind: "struct",
                query: name.to_string(),
            })
        }

        async fn enum_values(&self, name: &str) -> calxgloss_decomp::Result<EnumDefinition> {
            Err(EngineError::NotFound {
                kind: "enum",
                query: name.to_string(),
            })
        }

        async fn data_items(&self) -> calxgloss_decomp::Result<Vec<DataItem>> {
            Ok(Vec::new())
        }

        async fn imports(&self) -> calxgloss_decomp::Result<Vec<Symbol>> {
            if self.fail_imports {
                return Err(EngineError::Reported {
                    message: "the engine is busy".into(),
                });
            }
            Ok(self.imports.clone())
        }

        async fn exports(&self) -> calxgloss_decomp::Result<Vec<Symbol>> {
            Ok(Vec::new())
        }

        async fn image_base(&self) -> calxgloss_decomp::Result<u64> {
            Ok(0)
        }

        async fn read_memory(
            &self,
            _address: u64,
            _length: usize,
        ) -> calxgloss_decomp::Result<Vec<u8>> {
            Ok(Vec::new())
        }
        // Story 9 (#203): the fake source names itself, so the tests can pin
        // that scan() stamps the source's provenance onto the record (#208).
        fn engine_provenance(&self) -> Option<calxgloss_types::EngineProvenance> {
            Some(calxgloss_types::EngineProvenance {
                name: "fake-engine".into(),
                version: Some("9.9".into()),
                fingerprint: Some("0123456".into()),
            })
        }
    }

    impl CallGraphSource for FakeProgram {
        async fn call_graph(&self, _binary: &str) -> Result<Vec<FunctionCallGraph>> {
            self.graph_calls.fetch_add(1, Ordering::SeqCst);
            if self.fail_graph {
                return Err(ApiError::CallGraph {
                    reason: "decompiler unavailable".into(),
                });
            }
            Ok(self.graph.clone())
        }
    }

    fn node(name: &str, address: u64, callees: Vec<(&str, u64)>) -> FunctionCallGraph {
        FunctionCallGraph {
            name: name.into(),
            address,
            callers: Vec::new(),
            callees: callees
                .into_iter()
                .map(|(callee_name, target)| CallGraphEdge {
                    source: address,
                    target,
                    call_site: 0,
                    call_type: calxgloss_callgraph::CallType::Direct,
                    callee_name: callee_name.into(),
                })
                .collect(),
            node_category: calxgloss_types::NodeCategory::Middle,
        }
    }

    async fn scan(program: FakeProgram) -> ApiDetectionResult {
        ApiEngine::with_source(program)
            .scan("game.exe")
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn scan_collects_findings_from_both_detectors() {
        let result = scan(FakeProgram::new(
            vec!["inflate", "VendorSpecialFunction"],
            vec![node("FUN_a", 0x1000, vec![("inflate", 0)])],
        ))
        .await;
        assert_eq!(result.findings.len(), 3);
        assert_eq!(result.findings[0].kind(), "import");
        assert_eq!(result.findings[0].target(), "inflate");
        assert_eq!(result.findings[1].kind(), "import");
        assert_eq!(result.findings[2].kind(), "api_usage");
        assert_eq!(result.findings[2].function(), "FUN_a");
    }

    #[tokio::test]
    async fn import_findings_come_before_usage_findings() {
        let result = scan(FakeProgram::new(
            vec!["malloc"],
            vec![node("FUN_a", 0x1000, vec![("inflate", 0)])],
        ))
        .await;
        assert_eq!(result.findings[0].kind(), "import");
        assert_eq!(result.findings[1].kind(), "api_usage");
    }

    #[tokio::test]
    async fn a_binary_mixing_win32_and_posix_imports_claims_platform_divergence() {
        // The fake-program scan surfaces the claim whole: binary-level,
        // naming both families, listing the triggering imports from both
        // sides, at the fixed confidence, and suggesting cfg gates.
        let result = scan(FakeProgram::new(
            vec!["CreateFileA", "inflate", "fopen"],
            vec![node("FUN_a", 0x1000, vec![("inflate", 0)])],
        ))
        .await;
        let divergences: Vec<&crate::types::ApiFinding> = result
            .findings
            .iter()
            .filter(|finding| finding.kind() == "platform_divergence")
            .collect();
        assert_eq!(divergences.len(), 1, "one claim per binary");
        let finding = divergences[0];
        assert_eq!(finding.function(), "");
        assert_eq!(finding.target(), "Win32Core + POSIX");
        assert_eq!(finding.evidence(), "CreateFileA (Win32Core), fopen (POSIX)");
        assert_eq!(finding.confidence(), Confidence::new(70));
        assert!(finding.suggestion().contains("cfg"));
    }

    #[tokio::test]
    async fn the_divergence_finding_lands_after_import_entries_and_before_usages() {
        let result = scan(FakeProgram::new(
            vec!["CreateFileA", "malloc"],
            vec![node("FUN_a", 0x1000, vec![("malloc", 0)])],
        ))
        .await;
        let kinds: Vec<&str> = result
            .findings
            .iter()
            .map(|finding| finding.kind())
            .collect();
        assert_eq!(
            kinds,
            vec!["import", "import", "platform_divergence", "api_usage"]
        );
    }

    #[tokio::test]
    async fn a_single_family_binary_claims_no_divergence() {
        // Purely Win32 imports through the scan: the gate stays shut.
        let result = scan(FakeProgram::new(
            vec!["CreateFileA", "GetLastError"],
            vec![node("FUN_a", 0x1000, vec![("CreateFileA", 0)])],
        ))
        .await;
        assert!(
            result
                .findings
                .iter()
                .all(|finding| matches!(finding.kind(), "import" | "api_usage")),
            "no platform_divergence finding for a purely Win32 binary"
        );
    }

    #[tokio::test]
    async fn a_binary_with_decorated_com_imports_claims_a_named_interface() {
        // The fake-program scan surfaces the named claim whole:
        // binary-level, naming the recovered interface, keeping the
        // decorated names as evidence, at the named confidence,
        // and suggesting the trait shape.
        let result = scan(FakeProgram::new(
            vec![
                "CoCreateInstance",
                "?QueryInterface@IDataSource@@UEAAJPEAXPEAPEAX@Z",
                "?Release@IDataSource@@UEAAKXZ",
            ],
            vec![node("FUN_a", 0x1000, vec![("CoCreateInstance", 0)])],
        ))
        .await;
        let coms: Vec<&crate::types::ApiFinding> = result
            .findings
            .iter()
            .filter(|finding| finding.kind() == "com_interface")
            .collect();
        assert_eq!(coms.len(), 1, "one claim per interface");
        let finding = coms[0];
        assert_eq!(finding.function(), "");
        assert_eq!(finding.target(), "IDataSource");
        assert_eq!(
            finding.evidence(),
            "?QueryInterface@IDataSource@@UEAAJPEAXPEAPEAX@Z, ?Release@IDataSource@@UEAAKXZ"
        );
        assert_eq!(finding.confidence(), Confidence::new(70));
        assert!(finding.suggestion().contains("trait"));
        assert!(
            result
                .findings
                .iter()
                .any(|finding| finding.kind() == "import"
                    && finding.target() == "CoCreateInstance"),
            "the individual import entries stay beside the structural claim"
        );
    }

    #[tokio::test]
    async fn runtime_only_com_imports_claim_one_lower_confidence_finding() {
        // No name to recover: one binary-level claim naming the COM
        // runtime imports seen, at the visibly lower runtime confidence.
        let result = scan(FakeProgram::new(
            vec!["CoCreateInstance", "CoTaskMemAlloc", "inflate"],
            vec![node("FUN_a", 0x1000, vec![("inflate", 0)])],
        ))
        .await;
        let coms: Vec<&crate::types::ApiFinding> = result
            .findings
            .iter()
            .filter(|finding| finding.kind() == "com_interface")
            .collect();
        assert_eq!(coms.len(), 1, "one claim per binary");
        assert_eq!(coms[0].target(), "COM runtime");
        assert_eq!(
            coms[0].evidence(),
            "CoCreateInstance, CoTaskMemAlloc",
            "the graph adds no COM names here, and the cap holds"
        );
        assert_eq!(coms[0].confidence(), Confidence::new(50));
    }

    #[tokio::test]
    async fn the_com_finding_lands_after_import_entries_and_before_usages() {
        // With both structural readings open, the COM claim is placed
        // after the import entries and the divergence claim, before
        // the usages.
        let result = scan(FakeProgram::new(
            vec!["CreateFileA", "malloc", "CoCreateInstance"],
            vec![node("FUN_a", 0x1000, vec![("malloc", 0)])],
        ))
        .await;
        let kinds: Vec<&str> = result
            .findings
            .iter()
            .map(|finding| finding.kind())
            .collect();
        assert_eq!(
            kinds,
            vec![
                "import",
                "import",
                "import",
                "platform_divergence",
                "com_interface",
                "api_usage",
            ]
        );
    }

    #[tokio::test]
    async fn call_graph_names_carry_the_com_reading_through_the_scan() {
        // A decorated thunk name only in the call graph, with no COM
        // import at all, still produces the named claim — using the
        // names the scan already holds.
        let result = scan(FakeProgram::new(
            vec!["inflate"],
            vec![node(
                "FUN_a",
                0x1000,
                vec![("?QueryInterface@IDataSource@@UEAAJPEAXPEAPEAX@Z", 0)],
            )],
        ))
        .await;
        let coms: Vec<&crate::types::ApiFinding> = result
            .findings
            .iter()
            .filter(|finding| finding.kind() == "com_interface")
            .collect();
        assert_eq!(coms.len(), 1);
        assert_eq!(coms[0].target(), "IDataSource");
    }

    #[tokio::test]
    async fn a_no_com_signal_binary_claims_no_com_interface() {
        // Ordinary imports through the scan: the COM gate stays shut.
        let result = scan(FakeProgram::new(
            vec!["inflate", "CreateFileA"],
            vec![node("FUN_a", 0x1000, vec![("inflate", 0)])],
        ))
        .await;
        assert!(
            result
                .findings
                .iter()
                .all(|finding| finding.kind() != "com_interface"),
            "an ordinary binary is not over-read as COM"
        );
    }

    #[tokio::test]
    async fn a_failing_import_listing_fails_the_whole_run() {
        let source = FakeProgram {
            fail_imports: true,
            ..FakeProgram::new(vec![], Vec::new())
        };
        let error = ApiEngine::with_source(source)
            .scan("game.exe")
            .await
            .unwrap_err();
        assert!(matches!(error, ApiError::Engine(_)));
    }

    #[tokio::test]
    async fn a_failing_call_graph_degrades_to_the_import_table() {
        let source = FakeProgram {
            fail_graph: true,
            ..FakeProgram::new(
                vec!["inflate"],
                vec![node("FUN_a", 0x1000, vec![("inflate", 0)])],
            )
        };
        let result = ApiEngine::with_source(source)
            .scan("game.exe")
            .await
            .unwrap();
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].kind(), "import");
    }

    #[tokio::test]
    async fn scan_carries_category_and_features_onto_identified_findings() {
        // The enrichment survives the fake-program scan whole: an identified
        // import entry and its usage both record the builtin entry's
        // category and feature flags, and the suggestion renders the
        // crate[feature] form; the unidentified import stays category-less.
        let result = scan(FakeProgram::new(
            vec!["inflate", "VendorSpecialFunction"],
            vec![node("FUN_a", 0x1000, vec![("inflate", 0)])],
        ))
        .await;
        assert_eq!(result.findings.len(), 3);

        assert_eq!(result.findings[0].category(), Some("zlib"));
        assert_eq!(result.findings[0].features(), ["zlib".to_string()]);
        assert_eq!(result.findings[0].suggestion(), "flate2[zlib]");

        assert_eq!(result.findings[1].category(), None);
        assert!(result.findings[1].features().is_empty());
        assert_eq!(result.findings[1].suggestion(), "");

        assert_eq!(result.findings[2].category(), Some("zlib"));
        assert_eq!(result.findings[2].features(), ["zlib".to_string()]);
        assert_eq!(result.findings[2].suggestion(), "flate2[zlib]");
    }

    #[tokio::test]
    async fn custom_mappings_reach_both_detectors() {
        let mappings = MappingDatabase::builtin().with_library(LibraryMapping {
            library: "CustomEngine".into(),
            imports: vec!["Engine_LoadAsset".into()],
            rust_crate: "custom_engine".into(),
            category: Some("SDL2".into()),
            features: vec!["bundled".into()],
        });
        let engine = ApiEngine::with_source(FakeProgram::new(
            vec!["Engine_LoadAsset"],
            vec![node("FUN_a", 0x1000, vec![("Engine_LoadAsset", 0)])],
        ))
        .with_import_scanner(ImportTableScanner::with_mappings(mappings.clone()))
        .with_summary_detector(ApiSummaryDetector::with_mappings(mappings));
        let result = engine.scan("game.exe").await.unwrap();
        assert_eq!(result.findings.len(), 2);
        for finding in &result.findings {
            assert_eq!(finding.library(), Some("CustomEngine"));
            assert_eq!(finding.category(), Some("SDL2"));
            assert_eq!(finding.features(), ["bundled".to_string()]);
            assert_eq!(finding.suggestion(), "custom_engine[bundled]");
        }
    }

    #[tokio::test]
    async fn scan_stamps_the_scan_provenance() {
        let result = scan(FakeProgram::new(vec!["inflate"], Vec::new())).await;
        assert_eq!(result.metadata.binary, "game.exe");
        assert!(result.metadata.scanned_at > 0);
        // Story 9 (#203): the record also names the analysis engine that
        // produced it — scan() copies the source's provenance through (#208).
        let engine = result
            .metadata
            .engine
            .expect("scan record names its engine");
        assert_eq!(engine.name, "fake-engine");
        assert_eq!(engine.version.as_deref(), Some("9.9"));
        assert_eq!(engine.fingerprint.as_deref(), Some("0123456"));
    }

    #[tokio::test]
    async fn an_empty_program_yields_an_empty_result() {
        let result = scan(FakeProgram::new(Vec::new(), Vec::new())).await;
        assert!(result.findings.is_empty());
    }

    // -- admitted coverage (P19 tracer bullet, issue #346) ---------------

    /// The data-level verdict of the roster pin: empty means the record
    /// names every declared facet exactly once, and each fault spells one
    /// drift.
    fn roster_faults(coverage: &ScanCoverage) -> Vec<String> {
        coverage.roster_faults(DECLARED_FACETS)
    }

    #[tokio::test]
    async fn scan_stamps_coverage_naming_every_declared_facet_once() {
        // The stamp comes from the evidence engine's own scan, not from
        // the registry row and not from the CLI — the batch scan phase
        // and the CLI's force-rescan file the same admission through
        // this one definition.
        let result = scan(FakeProgram::new(
            vec!["inflate"],
            vec![node("FUN_a", 0x1000, vec![("inflate", 0)])],
        ))
        .await;
        let coverage = result
            .metadata
            .coverage
            .expect("a fresh apidetect scan states its coverage");
        assert_eq!(coverage.status, CoverageStatus::Partial);
        assert!(
            roster_faults(&coverage).is_empty(),
            "a fresh document must name every declared facet exactly once"
        );
        let by_id = |id: &str| {
            coverage
                .facets
                .iter()
                .find(|facet| facet.id == id)
                .unwrap_or_else(|| panic!("`{id}` is named"))
        };
        assert_eq!(by_id("import-table").status, CoverageStatus::Complete);
        assert_eq!(by_id("api-usage").status, CoverageStatus::Complete);
        assert_eq!(
            by_id("delay-imports").status,
            CoverageStatus::Unexamined,
            "the engine parses no delay-import table and says so end to end"
        );
        assert_eq!(
            by_id("delay-imports").limitation.as_deref(),
            Some("delay imports unexamined")
        );
    }

    #[tokio::test]
    async fn a_degraded_call_graph_lands_api_usage_unavailable_with_its_reason() {
        // The warning the run already logs ("Call graph unavailable:
        // reporting the import table alone") also lands in the
        // document: the facet that could not be read says why, beside
        // the permanent delay-imports border that stands either way.
        let result = ApiEngine::with_source(FakeProgram {
            fail_graph: true,
            ..FakeProgram::new(vec!["inflate"], Vec::new())
        })
        .scan("game.exe")
        .await
        .expect("a missing call graph degrades, it does not fail the run");
        let coverage = result
            .metadata
            .coverage
            .expect("a fresh apidetect scan states its coverage");
        assert!(
            roster_faults(&coverage).is_empty(),
            "a degraded scan still names every declared facet exactly once"
        );
        let api_usage = coverage
            .facets
            .iter()
            .find(|facet| facet.id == "api-usage")
            .expect("api-usage is named");
        assert_eq!(api_usage.status, CoverageStatus::Unavailable);
        assert_eq!(
            api_usage.limitation.as_deref(),
            Some("call graph unavailable"),
            "the facet that fell short names its reason"
        );
        assert_eq!(
            coverage
                .facets
                .iter()
                .find(|facet| facet.id == "delay-imports")
                .expect("delay-imports is named")
                .status,
            CoverageStatus::Unexamined
        );
    }

    #[tokio::test]
    async fn the_roster_pin_fails_when_a_declared_facet_goes_missing() {
        let mut coverage = coverage_stamp(true);
        coverage.facets.retain(|facet| facet.id != "delay-imports");
        assert_eq!(
            roster_faults(&coverage),
            ["declared facet `delay-imports` is missing from the record"],
            "an engine quietly skipping a declared facet fails loudly"
        );
    }

    #[tokio::test]
    async fn the_roster_pin_fails_when_a_facet_is_doubled() {
        let mut coverage = coverage_stamp(true);
        coverage.facets.push(coverage.facets[0].clone());
        assert_eq!(
            roster_faults(&coverage),
            ["declared facet `import-table` appears 2 times in the record"],
            "a facet crowded into two entries fails loudly"
        );
    }

    #[tokio::test]
    async fn the_roster_pin_fails_when_coverage_names_an_orphan_facet() {
        let mut coverage = coverage_stamp(true);
        coverage.facets.push(FacetCoverage {
            id: "vtables".to_string(),
            status: CoverageStatus::Unexamined,
            limitation: None,
        });
        assert_eq!(
            roster_faults(&coverage),
            ["record names `vtables`, a facet the engine never declared"],
            "an id invented outside the declared roster fails loudly"
        );
    }
}
