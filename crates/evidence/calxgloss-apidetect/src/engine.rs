//! The API-identification engine: import table plus per-function summaries.
//!
//! [`ApiEngine`] runs the two detectors over one binary — the
//! [`ImportTableScanner`] identifies the binary's imports, the
//! [`ApiSummaryDetector`] reads the built call graph for the APIs each
//! function reaches — and collects everything into one
//! [`ApiDetectionResult`]. The engine is generic over its [`ApiSource`],
//! so tests can run the whole orchestration over canned data;
//! [`new`](Self::new) builds one over a live [`GhidraClient`].

use std::time::Instant;

use calxgloss_callgraph::{CallGraphBuilder, FunctionCallGraph};
use calxgloss_ghidra::{GhidraClient, Symbol};
use tracing::{info, warn};

use crate::api_summary::ApiSummaryDetector;
use crate::error::{ApiError, Result};
use crate::import_table::ImportTableScanner;
use crate::types::{ApiDetectionResult, ScanMetadata};

/// The program an API scan reads.
///
/// [`GhidraClient`] implements it directly; tests implement it over
/// canned import lists and call graphs so the orchestration runs
/// without a server. The futures are `Send` so a scan can be driven
/// from an orchestrating task.
pub trait ApiSource {
    /// Every import in the program, in listing order.
    fn imports(&self) -> impl std::future::Future<Output = Result<Vec<Symbol>>> + Send;

    /// The built call graph: one node per function, with its call edges.
    fn call_graph(
        &self,
        binary: &str,
    ) -> impl std::future::Future<Output = Result<Vec<FunctionCallGraph>>> + Send;
}

impl ApiSource for GhidraClient {
    async fn imports(&self) -> Result<Vec<Symbol>> {
        Ok(self.imports(None).await?)
    }

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
    /// listing order — and then the call graph, function by function,
    /// direct calls before transitive paths, so two scans of the same
    /// program diff cleanly.
    ///
    /// A failure of the import listing — the server being down —
    /// aborts the run, since then nothing was scanned. A call graph
    /// that cannot be built degrades the run to the import table
    /// alone, with a warning: the binary-level identifications stand
    /// on their own.
    pub async fn scan(&self, binary: impl Into<String>) -> Result<ApiDetectionResult>
    where
        S: ApiSource,
    {
        let started = Instant::now();
        let binary = binary.into();
        let mut findings = self.scanner.scan(&self.source, &binary).await?;
        let imports = findings.len();

        match self.source.call_graph(&binary).await {
            Ok(graph) => {
                findings.extend(self.detector.detect(&graph));
            }
            Err(error) => {
                warn!(
                    binary = %binary,
                    error = %error,
                    "Call graph unavailable: reporting the import table alone"
                );
            }
        }

        let mut metadata = ScanMetadata::new(binary);
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
    use calxgloss_callgraph::CallGraphEdge;
    use calxgloss_ghidra::GhidraError;
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

    impl ApiSource for FakeProgram {
        async fn imports(&self) -> Result<Vec<Symbol>> {
            if self.fail_imports {
                return Err(GhidraError::Reported {
                    status: Some(200),
                    message: "Ghidra is busy".into(),
                }
                .into());
            }
            Ok(self.imports.clone())
        }

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
    async fn custom_mappings_reach_both_detectors() {
        let mappings = MappingDatabase::builtin().with_library(LibraryMapping {
            library: "CustomEngine".into(),
            imports: vec!["Engine_LoadAsset".into()],
            rust_crate: "custom_engine".into(),
        });
        let engine = ApiEngine::with_source(FakeProgram::new(
            vec!["Engine_LoadAsset"],
            vec![node("FUN_a", 0x1000, vec![("Engine_LoadAsset", 0)])],
        ))
        .with_import_scanner(ImportTableScanner::with_mappings(mappings.clone()))
        .with_summary_detector(ApiSummaryDetector::with_mappings(mappings));
        let result = engine.scan("game.exe").await.unwrap();
        assert_eq!(result.findings.len(), 2);
        assert_eq!(result.findings[0].library(), Some("CustomEngine"));
        assert_eq!(result.findings[1].library(), Some("CustomEngine"));
    }

    #[tokio::test]
    async fn scan_stamps_the_scan_provenance() {
        let result = scan(FakeProgram::new(vec!["inflate"], Vec::new())).await;
        assert_eq!(result.metadata.binary, "game.exe");
        assert!(result.metadata.scanned_at > 0);
    }

    #[tokio::test]
    async fn an_empty_program_yields_an_empty_result() {
        let result = scan(FakeProgram::new(Vec::new(), Vec::new())).await;
        assert!(result.findings.is_empty());
    }
}
