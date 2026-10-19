//! One pre-batch evidence scan as an owned job (issue #237).
//!
//! The eleven `ensure_*` entry points on [`TranslationPipeline`](crate::TranslationPipeline)
//! keep their signatures and their cached-document short-circuits, but the
//! scan itself — the engine call, the document
//! persist, and the warn-and-continue degradation — runs through [`ScanJob`],
//! a handle that owns clones of everything a scan reads. The handle is the
//! prefactor for the parallel scan-phase fan-out (spec #234): the runtime
//! cannot spawn a scan that borrows the batch, so each scan has to own what
//! it reads before any of them can move onto a task. The pass heartbeat is
//! the scan phase's — armed once around the whole group by
//! [`run_prebatch_scans`](crate::TranslationPipeline::run_prebatch_scans),
//! not per scan (issue #239) — so no scan method arms or disarms it.
//!
//! The one real ordering edge between the scans rides the handle too:
//! [`TypeInferenceLatch`] is the completion latch the type-inference scan
//! publishes and callback detection awaits before composing its closure
//! contracts from the type-inference document (issue #238).

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
use calxgloss_typesdb::engine::TypesDBEngine;
use calxgloss_typesdb::persist::TypeDatabasePersistor;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::pipeline::callback_signature_map;

/// The type-inference scan's completion latch (issue #238).
///
/// The scan phase arms one latch; the type-inference job publishes it
/// whether its scan succeeds or fails, and the callback job awaits it
/// before composing its closure contracts from the type-inference
/// document (issue #173). What made callback detection read inference's
/// output only after inference had run — today a positional accident of
/// the preamble's call order — becomes explicit data, so the edge
/// survives the scan-phase fan-out (#240) where the scans no longer run
/// in a fixed order.
///
/// A shared one-shot: every clone of the handle sees the same
/// completion flag. `wait` answers immediately once the flag is set, so
/// a waiter that arrives after the publish never blocks and one that
/// arrived before is released by it. Because the publish happens on
/// failure too, a failing inference scan can never strand the callback
/// job — it just finds no document and degrades exactly as today.
#[derive(Clone)]
pub(crate) struct TypeInferenceLatch {
    /// The completion flag, kept alive across clones of the handle by
    /// the same `Arc<watch::Sender>` shape the progress bus uses.
    completed: std::sync::Arc<watch::Sender<bool>>,

    /// The half a reader waits on; cheap to clone along with the handle.
    waiter: watch::Receiver<bool>,
}

impl TypeInferenceLatch {
    /// A fresh, unpublished latch.
    pub(crate) fn new() -> Self {
        let (completed, waiter) = watch::channel(false);
        Self {
            completed: std::sync::Arc::new(completed),
            waiter,
        }
    }

    /// Publish completion — the inference scan is done, succeeded or
    /// failed. Idempotent: a second publish changes nothing.
    pub(crate) fn publish(&self) {
        self.completed.send_replace(true);
    }

    /// Whether the inference scan has published its completion.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn is_set(&self) -> bool {
        *self.waiter.borrow()
    }

    /// Wait for the inference scan to finish. Returns immediately when
    /// the latch is already published; a channel closed with no
    /// publisher left also releases, so the reader is never stranded —
    /// only degraded.
    pub(crate) async fn wait(&self) {
        let mut waiter = self.waiter.clone();
        // `wait_for` re-checks the current value before each poll, so a
        // publish landing between the check and the wait is never missed.
        let _ = waiter.wait_for(|completed| *completed).await;
    }
}

/// Everything one pre-batch evidence scan reads, owned by the scan itself.
///
/// The job holds clones of the two reads a scan makes — the workspace the
/// document is filed under and the batch's shared read source as armed by
/// [`begin_cached_source`](crate::TranslationPipeline::begin_cached_source)
/// — so it borrows nothing from the batch, plus the scan phase's
/// [`TypeInferenceLatch`] when one is armed (issue #238). Cloning is cheap
/// (every read is an `Arc`-backed handle or a small path) and the handle is
/// `Send + Sync`, so a caller can move a job onto a task — exactly what the
/// scan-phase fan-out (#240) needs.
///
/// Each scan method is today's scan shape end to end: the cached-document
/// short-circuit first, then the engine call, then the persist; a failed
/// scan or save only warns and reports `false`. The pass heartbeat belongs
/// to the scan phase, armed once around the whole group by
/// [`run_prebatch_scans`](crate::TranslationPipeline::run_prebatch_scans)
/// and disarmed when the group ends — no scan method arms or disarms it
/// (issue #239).
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

    /// The scan phase's type-inference completion latch, present when
    /// the job was built inside an armed scan phase (issue #238): the
    /// [`type_inference`](Self::type_inference) job publishes it, the
    /// [`callback_detection`](Self::callback_detection) job awaits it.
    /// `None` for a job built outside a scan phase — a single scan
    /// asked for directly has no phase to order within.
    type_inference: Option<TypeInferenceLatch>,
}

impl ScanJob {
    /// Assemble the job for one scan of `binary` in `workspace`, reading
    /// through `source` and carrying the scan phase's `type_inference`
    /// completion latch when the phase armed one.
    pub(crate) fn new(
        binary: &str,
        workspace: &Path,
        source: PipelineSource,
        type_inference: Option<TypeInferenceLatch>,
    ) -> Self {
        Self {
            binary: binary.to_string(),
            workspace: workspace.to_path_buf(),
            source,
            type_inference,
        }
    }

    /// Run one scan's engine call, persist its document, and degrade to a
    /// warning when either step fails — the shape every evidence scan
    /// shares. Returns whether the document is in place afterwards.
    ///
    /// The heartbeat is the scan phase's — armed once around the group by
    /// [`run_prebatch_scans`](crate::TranslationPipeline::run_prebatch_scans)
    /// (issue #239) — so the scan itself neither arms nor disarms it.
    async fn run_scan<T, ScanError, SaveError>(
        &self,
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
        let outcome = scan.await;
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
    ///
    /// Publishes the scan phase's completion latch on every exit —
    /// cached hit, successful scan, or failure (issue #238) — so the
    /// callback job waiting on it is released either way.
    pub(crate) async fn type_inference(&self) -> bool {
        let persistor = TypeInferPersistor::new(&self.workspace);
        if persistor.exists(&self.binary) {
            debug!(
                binary = %self.binary,
                path = %persistor.path_for(&self.binary).display(),
                "Type inference result already cached; skipping scan"
            );
            self.publish_type_inference();
            return true;
        }

        info!(binary = %self.binary, "Inferring parameter types before batch translation");
        let engine = TypeInferEngine::with_source(self.source.clone());
        let scanned = self
            .run_scan(
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
            .await;
        self.publish_type_inference();
        scanned
    }

    /// Publish the scan phase's completion latch, when this job carries
    /// one — called on every exit of [`type_inference`](Self::type_inference)
    /// so a failing inference scan can never strand the callback job
    /// (issue #238).
    fn publish_type_inference(&self) {
        if let Some(ref latch) = self.type_inference {
            latch.publish();
        }
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
        // The scan future owns the engine and the binary name rather than
        // borrowing them from this frame: the algorithm scan's future is
        // deeply nested (its own concurrent pass inside), and rustc cannot
        // prove a borrowed nested future `'static` (rust#100013) — which
        // the scan-phase fan-out needs to move this scan onto a task
        // (issue #240).
        let engine = AlgorithmEngine::with_source(self.source.clone());
        let binary = self.binary.clone();
        self.run_scan(
            async move { engine.scan(binary).await },
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
        // The one real ordering edge between the scans: this scan's
        // closure contracts are composed from the type-inference
        // document (issue #173), so the job awaits inference's
        // completion latch instead of trusting the preamble's call
        // order (issue #238). The latch is published whether inference
        // succeeded or failed, so the wait releases either way —
        // enrichment when the document is in place, degraded silence
        // when it is not.
        if let Some(ref latch) = self.type_inference {
            latch.wait().await;
        }
        let signatures = callback_signature_map(&self.workspace, &self.binary);
        let engine = CallbackEngine::with_source(self.source.clone()).with_signatures(signatures);
        self.run_scan(
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
