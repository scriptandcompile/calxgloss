//! The API-identification engine: import table plus per-function summaries.
//!
//! [`ApiEngine`] runs the two detectors over one binary — the
//! [`ImportTableScanner`] identifies the binary's imports, the
//! [`ApiSummaryDetector`] reads the built call graph for the APIs each
//! function reaches — and the [divergence](crate::divergence) and
//! [com](crate::com) passes read the classified import listing and the
//! graph names for the platform-divergence and COM claims, collecting
//! everything into one [`ApiDetectionResult`]. The engine is generic
//! over the shared [`ScanSource`] plus a [`CallGraphSource`] for the
//! built graph, so tests can run the whole orchestration over canned
//! data; [`new`](Self::new) builds one over a live [`GhidraClient`].

use std::time::Instant;

use calxgloss_callgraph::{CallGraphBuilder, FunctionCallGraph};
use calxgloss_ghidra::GhidraClient;
use tracing::{info, warn};

use crate::api_summary::ApiSummaryDetector;
use crate::com::detect_com;
use crate::divergence::detect_divergence;
use crate::error::{ApiError, Result};
use crate::import_table::ImportTableScanner;
use crate::types::{ApiDetectionResult, ScanMetadata};

/// The program facts an API scan reads.
///
/// The shared trait from the Ghidra integration crate, re-exported here
/// so the engine's generic shape names it where it always has;
/// [`GhidraClient`] implements it over the live HTTP API, and tests
/// implement it over canned listings so the orchestration runs without
/// a server. The futures are `Send` so a scan can be driven from an
/// orchestrating task.
pub use calxgloss_ghidra::ScanSource;

/// The built call graph an API scan reads.
///
/// Deliberately outside [`ScanSource`]: the graph is not a single Ghidra
/// read but a composite of them, assembled by the call-graph builder —
/// which reads through the shared seam itself — so the shared trait
/// stays a listing of raw program facts and this small trait carries
/// the one composite the summary detector needs.
pub trait CallGraphSource {
    /// The built call graph: one node per function, with its call edges.
    fn call_graph(
        &self,
        binary: &str,
    ) -> impl std::future::Future<Output = Result<Vec<FunctionCallGraph>>> + Send;
}

impl CallGraphSource for GhidraClient {
    async fn call_graph(&self, binary: &str) -> Result<Vec<FunctionCallGraph>> {
        let graph = CallGraphBuilder::new(self.clone(), binary)
            .build()
            .await
            .map_err(|error| ApiError::CallGraph {
                reason: error.to_string(),
            })?;
        Ok(graph.functions)
    }
}

impl CallGraphSource for calxgloss_ghidra::PipelineSource {
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

/// Orchestrates the import scanner and the summary detector into one
/// [`ApiDetectionResult`].
///
/// Each detector carries no state and starts configured with the builtin
/// library mappings — [`with_import_scanner`](Self::with_import_scanner)
/// and [`with_summary_detector`](Self::with_summary_detector) swap a
/// detector whole — so one instance of each serves the whole scan.
#[derive(Debug, Clone)]
pub struct ApiEngine<S = GhidraClient> {
    source: S,
    scanner: ImportTableScanner,
    detector: ApiSummaryDetector,
}

impl ApiEngine<GhidraClient> {
    /// An engine over a live GhidraMCP client, scanning with the
    /// builtin library mappings.
    pub fn new(client: &GhidraClient) -> ApiEngine<GhidraClient> {
        ApiEngine {
            source: client.clone(),
            scanner: ImportTableScanner::new(),
            detector: ApiSummaryDetector::new(),
        }
    }
}

impl<S> ApiEngine<S> {
    /// An engine whose imports and call graph come from `source`,
    /// scanning with the builtin library mappings.
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
    /// findings follow the import listing — every import entry, in
    /// listing order, then the platform-divergence claim when the
    /// imports mix Win32 and POSIX/stdio families, then the COM claims
    /// when the import and call-graph names carry COM signals — and
    /// then the call graph, function by function, direct calls before
    /// transitive paths, so two scans of the same program diff cleanly.
    ///
    /// A failure of the import listing — the server being down —
    /// aborts the run, since then nothing was scanned. A call graph
    /// that cannot be built degrades the run to the import table
    /// alone, with a warning: the binary-level identifications stand
    /// on their own, and the COM reading runs off the import listing
    /// without the graph names.
    pub async fn scan(&self, binary: impl Into<String>) -> Result<ApiDetectionResult>
    where
        S: ScanSource + CallGraphSource,
    {
        let started = Instant::now();
        let binary = binary.into();
        let mut findings = self.scanner.scan(&self.source, &binary).await?;
        let imports = findings.len();
        // The divergence reading comes off the classified import
        // listing the scan already holds — no new ScanSource reads —
        // and slots between the import entries and the usages so the
        // scan-order contract stays diffable.
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

        // The COM reading comes off the classified import listing and
        // the node and callee names the built graph already carries —
        // no new ScanSource reads — and slots after the import entries
        // (and any divergence claim) and before the usages so the
        // scan-order contract stays diffable.
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
        // The source names its engine and pin under `kuna`; the Ghidra
        // path names nothing and the record stays exactly as it was
        // (issue #208).
        metadata.engine = self.source.engine_provenance();
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
    use calxgloss_ghidra::{
        DataItem, DataTypeEntry, DecompiledFunction, EnumDefinition, FunctionSummary, GhidraError,
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
        async fn functions(&self) -> calxgloss_ghidra::Result<Vec<FunctionSummary>> {
            Ok(Vec::new())
        }

        async fn decompile(&self, name: &str) -> calxgloss_ghidra::Result<DecompiledFunction> {
            Err(GhidraError::NotFound {
                kind: "function",
                query: name.to_string(),
            })
        }

        async fn strings(&self) -> calxgloss_ghidra::Result<Vec<StringLiteral>> {
            Ok(Vec::new())
        }

        async fn callers(&self, _address: u64) -> calxgloss_ghidra::Result<Vec<String>> {
            Ok(Vec::new())
        }

        async fn xrefs_to(&self, _address: u64) -> calxgloss_ghidra::Result<Vec<Xref>> {
            Ok(Vec::new())
        }

        async fn data_types(
            &self,
            _category: Option<&str>,
        ) -> calxgloss_ghidra::Result<Vec<DataTypeEntry>> {
            Ok(Vec::new())
        }

        async fn struct_layout(&self, name: &str) -> calxgloss_ghidra::Result<StructLayout> {
            Err(GhidraError::NotFound {
                kind: "struct",
                query: name.to_string(),
            })
        }

        async fn enum_values(&self, name: &str) -> calxgloss_ghidra::Result<EnumDefinition> {
            Err(GhidraError::NotFound {
                kind: "enum",
                query: name.to_string(),
            })
        }

        async fn data_items(&self) -> calxgloss_ghidra::Result<Vec<DataItem>> {
            Ok(Vec::new())
        }

        async fn imports(&self) -> calxgloss_ghidra::Result<Vec<Symbol>> {
            if self.fail_imports {
                return Err(GhidraError::Reported {
                    status: Some(200),
                    message: "Ghidra is busy".into(),
                });
            }
            Ok(self.imports.clone())
        }

        async fn exports(&self) -> calxgloss_ghidra::Result<Vec<Symbol>> {
            Ok(Vec::new())
        }

        async fn image_base(&self) -> calxgloss_ghidra::Result<u64> {
            Ok(0)
        }

        async fn read_memory(
            &self,
            _address: u64,
            _length: usize,
        ) -> calxgloss_ghidra::Result<Vec<u8>> {
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
        // sides, at the fixed confidence, suggesting cfg gates.
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
        // binary-level, naming the recovered interface, carrying the
        // decorated names as evidence, at the named confidence,
        // suggesting the trait shape.
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
        // runtime imports seen, at the visibly lower runtime tier.
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
        // With both structural readings open, the COM claim slots after
        // the import entries and the divergence claim, before usages.
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
        // A decorated thunk name only in the call graph — no COM
        // import — still lands the named claim, off the names the
        // scan already holds.
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
        assert!(matches!(error, ApiError::Ghidra(_)));
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
        // The enrichment rides the fake-program scan whole: an identified
        // import entry and its usage both carry the builtin entry's
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
        // Story 9 (#203): the record also names the engine that produced it —
        // scan() copies the source's provenance through (#208).
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
}
