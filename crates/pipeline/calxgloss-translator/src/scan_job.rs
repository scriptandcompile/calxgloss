//! One pre-batch evidence scan as an owned job (issue #237).
//!
//! The eleven `ensure_*` entry points on [`TranslationPipeline`](crate::TranslationPipeline)
//! keep their signatures and their cached-document short-circuits, but the
//! scan itself — the engine call under the pass heartbeat, the document
//! persist, and the warn-and-continue degradation — runs through [`ScanJob`],
//! a handle that owns clones of everything a scan reads. The handle is the
//! prefactor for the parallel scan-phase fan-out (spec #234): the runtime
//! cannot spawn a scan that borrows the batch, so each scan has to own what
//! it reads before any of them can move onto a task.

use std::future::Future;
use std::path::{Path, PathBuf};

use calxgloss_algorithm::engine::AlgorithmEngine;
use calxgloss_algorithm::persist::AlgorithmPersistor;
use calxgloss_apidetect::engine::ApiEngine;
use calxgloss_apidetect::persist::ApiPersistor;
use calxgloss_callback::engine::CallbackEngine;
use calxgloss_callback::persist::CallbackPersistor;
use calxgloss_consts::engine::ConstEngine;
use calxgloss_consts::persist::ConstPersistor;
use calxgloss_controlflow::engine::ControlFlowEngine;
use calxgloss_controlflow::persist::ControlFlowPersistor;
use calxgloss_decomp::PipelineSource;
use calxgloss_kuna::KunaSource;
use calxgloss_memory::engine::MemoryEngine;
use calxgloss_memory::persist::MemoryPersistor;
use calxgloss_serialize::engine::SerializeEngine;
use calxgloss_serialize::persist::SerializePersistor;
use calxgloss_stringctx::engine::StringContextEngine;
use calxgloss_stringctx::persist::StringContextPersistor;
use calxgloss_sync::engine::SyncEngine;
use calxgloss_sync::persist::SyncPersistor;
use calxgloss_typeinfer::engine::TypeInferEngine;
use calxgloss_typeinfer::persist::TypeInferPersistor;
use calxgloss_types::TranslationEvents;
use calxgloss_typesdb::engine::TypesDBEngine;
use calxgloss_typesdb::persist::TypeDatabasePersistor;
use tracing::{debug, info, warn};

use crate::pipeline::callback_signature_map;

/// Everything one pre-batch evidence scan reads, owned by the scan itself.
///
/// The job holds clones of the four reads a scan makes — the workspace the
/// document is filed under, the batch's shared read source as armed by
/// [`begin_cached_source`](crate::TranslationPipeline::begin_cached_source),
/// the engine source the pass heartbeat is armed on, and the progress-event
/// channel — so it borrows nothing from the batch. Cloning is cheap (every
/// read is an `Arc`-backed handle or a small path) and the handle is
/// `Send + Sync`, so a caller can move a job onto a task — exactly what the
/// scan-phase fan-out (#240) needs.
///
/// Each scan method is today's scan shape end to end: the cached-document
/// short-circuit first, then the engine call wrapped by the per-scan
/// heartbeat arm/disarm, then the persist; a failed scan or save only warns
/// and reports `false`.
#[derive(Clone)]
pub(crate) struct ScanJob {
    /// The binary the scan reads and the document is named after.
    binary: String,

    /// The workspace root the scan's document is filed under.
    workspace: PathBuf,

    /// The batch's shared read source at the moment the job was built: the
    /// armed [`CachedScanSource`](calxgloss_decomp::CachedScanSource) or the
    /// loaded engine. Every engine read goes through this clone.
    source: PipelineSource,

    /// The loaded engine behind the reads — the handle the pass heartbeat
    /// arms and disarms (the heartbeat state is shared by clones).
    kuna: KunaSource,

    /// The progress-event channel the heartbeat beats into; `None` means
    /// there is nothing to beat to and the scan runs unchanged.
    events: Option<TranslationEvents>,
}

impl ScanJob {
    /// Assemble the job for one scan of `binary` in `workspace`, reading
    /// through `source` and beating the pass heartbeat on `kuna` into
    /// `events` when there is a channel.
    pub(crate) fn new(
        binary: &str,
        workspace: &Path,
        source: PipelineSource,
        kuna: KunaSource,
        events: Option<TranslationEvents>,
    ) -> Self {
        Self {
            binary: binary.to_string(),
            workspace: workspace.to_path_buf(),
            source,
            kuna,
            events,
        }
    }

    /// Run one scan's engine call under the pass heartbeat, persist its
    /// document, and degrade to a warning when either step fails — the
    /// shape every evidence scan shares. Returns whether the document is
    /// in place afterwards.
    ///
    /// The heartbeat arm/disarm stays per scan at this stage; the
    /// phase-scoped heartbeat is a separate ticket (#239).
    async fn run_scan<T, ScanError, SaveError>(
        &self,
        pass: &str,
        scan: impl Future<Output = std::result::Result<T, ScanError>>,
        persist: impl FnOnce(&T) -> std::result::Result<(), SaveError>,
        scan_failed: &str,
        save_failed: &str,
        on_saved: impl FnOnce(&T),
    ) -> bool
    where
        ScanError: std::fmt::Display,
        SaveError: std::fmt::Display,
    {
        if let Some(ref ev) = self.events {
            self.kuna.begin_pass(&self.binary, pass, ev);
        }
        let outcome = scan.await;
        self.kuna.end_pass();
        match outcome {
            Ok(result) => match persist(&result) {
                Ok(()) => {
                    on_saved(&result);
                    true
                }
                Err(e) => {
                    warn!(binary = %self.binary, error = %e, "{save_failed}");
                    false
                }
            },
            Err(e) => {
                warn!(binary = %self.binary, error = %e, "{scan_failed}");
                false
            }
        }
    }

    /// The type-database recovery scan, unless its document is already filed.
    pub(crate) async fn type_database(&self) -> bool {
        let persistor = TypeDatabasePersistor::new(&self.workspace);
        if persistor.exists(&self.binary) {
            debug!(
                binary = %self.binary,
                path = %persistor.path_for(&self.binary).display(),
                "Type database already cached; skipping recovery"
            );
            return true;
        }

        info!(binary = %self.binary, "Recovering type database before batch translation");
        let engine = TypesDBEngine::with_source(self.source.clone());
        self.run_scan(
            "type database",
            engine.scan(self.binary.as_str()),
            |db| persistor.save(db),
            "Type database recovery failed; continuing without data structure context",
            "Failed to persist recovered type database; continuing without data structure context",
            |db| {
                info!(
                    binary = %self.binary,
                    named_types = db.named_types.len(),
                    vtables = db.vtables.len(),
                    inferred_structs = db.inferred_structs.len(),
                    "Type database recovered"
                );
            },
        )
        .await
    }

    /// The parameter-type inference scan, unless its document is already filed.
    pub(crate) async fn type_inference(&self) -> bool {
        let persistor = TypeInferPersistor::new(&self.workspace);
        if persistor.exists(&self.binary) {
            debug!(
                binary = %self.binary,
                path = %persistor.path_for(&self.binary).display(),
                "Type inference result already cached; skipping scan"
            );
            return true;
        }

        info!(binary = %self.binary, "Inferring parameter types before batch translation");
        let engine = TypeInferEngine::with_source(self.source.clone());
        self.run_scan(
            "type inference",
            engine.scan(self.binary.as_str()),
            |result| persistor.save(result),
            "Type inference failed; continuing without type context",
            "Failed to persist type inference result; continuing without type context",
            |result| {
                info!(
                    binary = %self.binary,
                    inferences = result.inferences.len(),
                    "Type inference complete"
                );
            },
        )
        .await
    }

    /// The algorithm recognition scan, unless its document is already filed.
    pub(crate) async fn algorithm_recognition(&self) -> bool {
        let persistor = AlgorithmPersistor::new(&self.workspace);
        if persistor.exists(&self.binary) {
            debug!(
                binary = %self.binary,
                path = %persistor.path_for(&self.binary).display(),
                "Algorithm recognition result already cached; skipping scan"
            );
            return true;
        }

        info!(binary = %self.binary, "Recognizing algorithms before batch translation");
        let engine = AlgorithmEngine::with_source(self.source.clone());
        self.run_scan(
            "algorithm recognition",
            engine.scan(self.binary.as_str()),
            |result| persistor.save(result),
            "Algorithm recognition failed; continuing without algorithm context",
            "Failed to persist algorithm recognition result; continuing without algorithm context",
            |result| {
                info!(
                    binary = %self.binary,
                    hints = result.hints.len(),
                    "Algorithm recognition complete"
                );
            },
        )
        .await
    }

    /// The memory lifecycle detection scan, unless its document is already filed.
    pub(crate) async fn memory_detection(&self) -> bool {
        let persistor = MemoryPersistor::new(&self.workspace);
        if persistor.exists(&self.binary) {
            debug!(
                binary = %self.binary,
                path = %persistor.path_for(&self.binary).display(),
                "Memory lifecycle result already cached; skipping scan"
            );
            return true;
        }

        info!(binary = %self.binary, "Detecting memory lifecycles before batch translation");
        let engine = MemoryEngine::with_source(self.source.clone());
        self.run_scan(
            "memory detection",
            engine.scan(self.binary.as_str()),
            |result| persistor.save(result),
            "Memory lifecycle detection failed; continuing without memory context",
            "Failed to persist memory lifecycle result; continuing without memory context",
            |result| {
                info!(
                    binary = %self.binary,
                    findings = result.findings.len(),
                    "Memory lifecycle detection complete"
                );
            },
        )
        .await
    }

    /// The concurrency detection scan, unless its document is already filed.
    pub(crate) async fn sync_detection(&self) -> bool {
        let persistor = SyncPersistor::new(&self.workspace);
        if persistor.exists(&self.binary) {
            debug!(
                binary = %self.binary,
                path = %persistor.path_for(&self.binary).display(),
                "Concurrency result already cached; skipping scan"
            );
            return true;
        }

        info!(binary = %self.binary, "Detecting concurrency constructs before batch translation");
        let engine = SyncEngine::with_source(self.source.clone());
        self.run_scan(
            "sync detection",
            engine.scan(self.binary.as_str()),
            |result| persistor.save(result),
            "Concurrency detection failed; continuing without concurrency context",
            "Failed to persist concurrency result; continuing without concurrency context",
            |result| {
                info!(
                    binary = %self.binary,
                    findings = result.findings.len(),
                    "Concurrency detection complete"
                );
            },
        )
        .await
    }

    /// The constant structure detection scan, unless its document is already filed.
    pub(crate) async fn const_detection(&self) -> bool {
        let persistor = ConstPersistor::new(&self.workspace);
        if persistor.exists(&self.binary) {
            debug!(
                binary = %self.binary,
                path = %persistor.path_for(&self.binary).display(),
                "Constant result already cached; skipping scan"
            );
            return true;
        }

        info!(binary = %self.binary, "Detecting constant structures before batch translation");
        let engine = ConstEngine::with_source(self.source.clone());
        self.run_scan(
            "constant detection",
            engine.scan(self.binary.as_str()),
            |result| persistor.save(result),
            "Constant detection failed; continuing without constant context",
            "Failed to persist constant result; continuing without constant context",
            |result| {
                info!(
                    binary = %self.binary,
                    findings = result.findings.len(),
                    "Constant detection complete"
                );
            },
        )
        .await
    }

    /// The callback table detection scan, unless its document is already
    /// filed. When a type-inference document is filed too, its records are
    /// composed into a signature map and injected, so the persisted
    /// suggestions carry real closure contracts (see
    /// [`callback_signature_map`]).
    pub(crate) async fn callback_detection(&self) -> bool {
        let persistor = CallbackPersistor::new(&self.workspace);
        if persistor.exists(&self.binary) {
            debug!(
                binary = %self.binary,
                path = %persistor.path_for(&self.binary).display(),
                "Callback result already cached; skipping scan"
            );
            return true;
        }

        info!(binary = %self.binary, "Detecting callback tables before batch translation");
        // The type-inference scan runs before this one in the batch
        // pre-analysis, so its cached document is usually in place:
        // its records deepen the registration and chain suggestions
        // into real closure contracts. No document, no enrichment —
        // the scan degrades silently (issue #173).
        let signatures = callback_signature_map(&self.workspace, &self.binary);
        let engine = CallbackEngine::with_source(self.source.clone()).with_signatures(signatures);
        self.run_scan(
            "callback detection",
            engine.scan(self.binary.as_str()),
            |result| persistor.save(result),
            "Callback detection failed; continuing without callback context",
            "Failed to persist callback result; continuing without callback context",
            |result| {
                info!(
                    binary = %self.binary,
                    findings = result.findings.len(),
                    "Callback detection complete"
                );
            },
        )
        .await
    }

    /// The control-flow pattern detection scan, unless its document is
    /// already filed.
    pub(crate) async fn controlflow_detection(&self) -> bool {
        let persistor = ControlFlowPersistor::new(&self.workspace);
        if persistor.exists(&self.binary) {
            debug!(
                binary = %self.binary,
                path = %persistor.path_for(&self.binary).display(),
                "Control-flow result already cached; skipping scan"
            );
            return true;
        }

        info!(binary = %self.binary, "Detecting control-flow patterns before batch translation");
        let engine = ControlFlowEngine::with_source(self.source.clone());
        self.run_scan(
            "control flow detection",
            engine.scan(self.binary.as_str()),
            |result| persistor.save(result),
            "Control-flow detection failed; continuing without control-flow context",
            "Failed to persist control-flow result; continuing without control-flow context",
            |result| {
                info!(
                    binary = %self.binary,
                    findings = result.findings.len(),
                    "Control-flow detection complete"
                );
            },
        )
        .await
    }

    /// The string context scan, unless its document is already filed.
    pub(crate) async fn string_context(&self) -> bool {
        let persistor = StringContextPersistor::new(&self.workspace);
        if persistor.exists(&self.binary) {
            debug!(
                binary = %self.binary,
                path = %persistor.path_for(&self.binary).display(),
                "String context result already cached; skipping scan"
            );
            return true;
        }

        info!(binary = %self.binary, "Mapping program strings before batch translation");
        let engine = StringContextEngine::with_source(self.source.clone());
        self.run_scan(
            "string context",
            engine.scan(self.binary.as_str()),
            |result| persistor.save(result),
            "String context scan failed; continuing without string context",
            "Failed to persist string context result; continuing without string context",
            |result| {
                info!(
                    binary = %self.binary,
                    findings = result.findings.len(),
                    "String context scan complete"
                );
            },
        )
        .await
    }

    /// The library/API detection scan, unless its document is already filed.
    pub(crate) async fn api_detection(&self) -> bool {
        let persistor = ApiPersistor::new(&self.workspace);
        if persistor.exists(&self.binary) {
            debug!(
                binary = %self.binary,
                path = %persistor.path_for(&self.binary).display(),
                "API result already cached; skipping scan"
            );
            return true;
        }

        info!(binary = %self.binary, "Identifying libraries and APIs before batch translation");
        let engine = ApiEngine::with_source(self.source.clone());
        self.run_scan(
            "API detection",
            engine.scan(self.binary.as_str()),
            |result| persistor.save(result),
            "API detection failed; continuing without API context",
            "Failed to persist API result; continuing without API context",
            |result| {
                info!(
                    binary = %self.binary,
                    findings = result.findings.len(),
                    "API detection complete"
                );
            },
        )
        .await
    }

    /// The serialization pattern detection scan, unless its document is
    /// already filed.
    pub(crate) async fn serialize_detection(&self) -> bool {
        let persistor = SerializePersistor::new(&self.workspace);
        if persistor.exists(&self.binary) {
            debug!(
                binary = %self.binary,
                path = %persistor.path_for(&self.binary).display(),
                "Serialization result already cached; skipping scan"
            );
            return true;
        }

        info!(binary = %self.binary, "Detecting serialization patterns before batch translation");
        let engine = SerializeEngine::with_source(self.source.clone());
        self.run_scan(
            "serialization detection",
            engine.scan(self.binary.as_str()),
            |result| persistor.save(result),
            "Serialization detection failed; continuing without serialization context",
            "Failed to persist serialization result; continuing without serialization context",
            |result| {
                info!(
                    binary = %self.binary,
                    findings = result.findings.len(),
                    "Serialization detection complete"
                );
            },
        )
        .await
    }
}
