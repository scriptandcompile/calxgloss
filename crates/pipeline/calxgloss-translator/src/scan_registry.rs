//! The evidence-scan registry — one descriptor behind the pre-batch scan
//! phase (issue #302, spec #301).
//!
//! The contract, in both directions:
//!
//! * **What the phase owns** (and no row restates): the fan-out window and
//!   its named cap, the measured high-water mark, the single scan-phase
//!   heartbeat row armed around the whole group, the completion latch that
//!   orders dependent scans, the cached-document short-circuit ahead of any
//!   engine read, the persist-or-skip decision with its warn-and-continue
//!   degradation, and the join-everything / cancel-nothing rule. That
//!   machinery lives in
//!   [`run_prebatch_scans`](crate::TranslationPipeline::run_prebatch_scans)
//!   and its helpers; a row never arms, joins, or latches anything.
//! * **What a row supplies** (the whole of its per-engine knowledge): the
//!   scan's name — carried as identity so a later engine-digest cache key
//!   has one home; where its document is filed, named through that
//!   engine's own persistor; how to build its engine from the batch's
//!   shared read source; the scan-failed and save-failed warning wording;
//!   the scan-started and cached-hit wording (operator-visible today, so
//!   the generic pass keeps it byte-for-byte); what the success log
//!   reports; and optional pre-scan / post-scan hooks.
//!
//! [`ScanDescriptor::new`] is the single generic constructor: it is the
//! only place the scan's shape — short-circuit, engine call, persist,
//! degrade, completion log — is written down. Rows are stored type-erased
//! in the table because each engine's result is its own type and the
//! fourteen (soon more) cannot sit in one list unboxed.
//!
//! The table is `pub` on purpose: the later generic CLI scan command
//! (P39) iterates these same rows. The descriptor is a pipeline-side
//! description of an engine, not a trait the evidence crates implement —
//! no evidence crate gains a dependency on, or implements, a
//! pipeline-owned abstraction, and there is no shared persistor interface:
//! each row names its location through its own concrete `JsonStore`-based
//! persistor, exactly as the legacy path does.
//!
//! Both mechanisms coexist while migration runs: the phase runs the
//! registered rows first, then the legacy scans that have not migrated
//! yet, joining every one of them. Control-flow detection was the first
//! scan to run from its row end to end (issue #302); the six body-reading
//! scans — memory lifecycle, concurrency, global state, constants,
//! error handling, and float/SIMD — followed (issue #303); then the five
//! that read whole-binary structure rather than per-function bodies —
//! type-database recovery, algorithm recognition, string-context
//! mapping, library/API identification, and serialization-pattern
//! detection (issue #304). Only the two latch-coupled scans — parameter-
//! type inference and callback detection — stay on the legacy path until
//! the ordering edge becomes a declared row dependency (issue #305).

use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;

use calxgloss_algorithm::engine::AlgorithmEngine;
use calxgloss_algorithm::persist::AlgorithmPersistor;
use calxgloss_apidetect::engine::ApiEngine;
use calxgloss_apidetect::persist::ApiPersistor;
use calxgloss_consts::engine::ConstEngine;
use calxgloss_consts::persist::ConstPersistor;
use calxgloss_controlflow::engine::ControlFlowEngine;
use calxgloss_controlflow::persist::ControlFlowPersistor;
use calxgloss_decomp::PipelineSource;
use calxgloss_errhandling::engine::ErrhandlingEngine;
use calxgloss_errhandling::persist::ErrhandlingPersistor;
use calxgloss_floatsimd::engine::FloatsimdEngine;
use calxgloss_floatsimd::persist::FloatsimdPersistor;
use calxgloss_globalstate::engine::GlobalStateEngine;
use calxgloss_globalstate::persist::GlobalStatePersistor;
use calxgloss_memory::engine::MemoryEngine;
use calxgloss_memory::persist::MemoryPersistor;
use calxgloss_serialize::engine::SerializeEngine;
use calxgloss_serialize::persist::SerializePersistor;
use calxgloss_stringctx::engine::StringContextEngine;
use calxgloss_stringctx::persist::StringContextPersistor;
use calxgloss_sync::engine::SyncEngine;
use calxgloss_sync::persist::SyncPersistor;
use calxgloss_typesdb::engine::TypesDBEngine;
use calxgloss_typesdb::persist::TypeDatabasePersistor;
use tracing::{debug, info, warn};

/// A future with nothing borrowed from its caller, ready to cross onto a
/// scan task — the shape the scan-phase fan-out moves every scan in.
type OwnedFuture<T> = Pin<Box<dyn Future<Output = T> + Send>>;

/// The row's persistor step: builds the engine's persistor over a
/// workspace root.
type PersistorStep<P> = Arc<dyn Fn(&Path) -> P + Send + Sync + 'static>;

/// The row's short-circuit probe: whether the document is already filed.
type ExistsStep<P> = Arc<dyn Fn(&P, &str) -> bool + Send + Sync + 'static>;

/// The row's location namer: where its document is filed, through the
/// engine's own persistor.
type LocationStep = Arc<dyn Fn(&Path, &str) -> PathBuf + Send + Sync + 'static>;

/// The row's persist step.
type SaveStep<T, P, SaveError> =
    Arc<dyn Fn(&P, &T) -> std::result::Result<(), SaveError> + Send + Sync + 'static>;

/// The row's engine step: build the engine from the batch's shared read
/// source and run its scan over the binary.
type EngineStep<T, ScanError> = Arc<
    dyn Fn(PipelineSource, String) -> OwnedFuture<std::result::Result<T, ScanError>>
        + Send
        + Sync
        + 'static,
>;

/// The row's success-log step: the counts worth reporting.
type SuccessStep<T> = Arc<dyn Fn(&ScanContext, &T) + Send + Sync + 'static>;

/// An optional per-row step the phase runs around the scan: a pre-scan
/// step runs after the short-circuit decided to scan and before the engine
/// is built (callback detection will await its dependency and compose its
/// signature map there), and a post-scan step runs on every exit — cached
/// hit, success, and both failures alike (the type-inference row will
/// publish its completion latch there). Control-flow detection uses
/// neither; the shape is here so the later rows need no new mechanism.
pub type ScanHook = Arc<dyn Fn(&ScanContext) -> OwnedFuture<()> + Send + Sync + 'static>;

/// The phase's run of one erased row: short-circuit, engine call,
/// persist, degrade, completion log — composed from the row's steps by
/// [`ScanDescriptor::new`]. Answers whether the document is in place.
type RunStep = Box<dyn Fn(ScanContext) -> OwnedFuture<bool> + Send + Sync + 'static>;

/// Everything one registered scan reads, owned by the scan itself: the
/// binary it reads and its document is named after, the workspace root the
/// document is filed under, and the batch's shared read source at the
/// moment the phase armed it. A row borrows nothing from the batch.
#[derive(Debug, Clone)]
pub struct ScanContext {
    /// The binary the scan reads and the document is named after.
    pub binary: String,

    /// The workspace root the scan's document is filed under.
    pub workspace: PathBuf,

    /// The batch's shared read source: the armed cached source or the
    /// loaded engine, exactly as [`ScanJob`](crate::scan_job::ScanJob)
    /// carries it.
    pub source: PipelineSource,
}

/// The operator-visible wording a row carries so degradation and progress
/// read exactly as they do in the legacy path. Each message matches the
/// tracing fields the generic pass logs around it: the cached-hit debug
/// carries `binary` and `path`, the started info carries `binary`, and
/// both failures warn with `binary` and `error`.
#[derive(Debug, Clone, Copy)]
pub struct ScanMessages {
    /// The info line logged just before the engine read begins.
    pub scan_started: &'static str,

    /// The debug line logged when the filed document short-circuits the scan.
    pub cached_hit: &'static str,

    /// The warning logged when the engine scan itself fails.
    pub scan_failed: &'static str,

    /// The warning logged when the scan succeeded but the save failed.
    pub save_failed: &'static str,
}

/// One scan row in its still-typed shape: the row's steps over one
/// engine's concrete result, persistor, and error types.
/// [`ScanDescriptor::new`] erases it into the table.
pub struct ScanRow<T, P, ScanError, SaveError>
where
    T: Send + 'static,
    P: Send + Sync + 'static,
    ScanError: std::fmt::Display + Send + 'static,
    SaveError: std::fmt::Display + Send + 'static,
{
    /// The scan's name, used in logs and carried as the scan's identity.
    pub name: &'static str,

    /// The row's operator-visible wording.
    pub messages: ScanMessages,

    /// Builds the engine's persistor over a workspace root.
    pub persistor: PersistorStep<P>,

    /// Whether the document is already filed — the phase's short-circuit
    /// reads through this, ahead of any engine read.
    pub exists: ExistsStep<P>,

    /// Where the document is filed, named through the engine's own
    /// persistor; also what the cached-hit debug names.
    pub document_path: LocationStep,

    /// Persists the scan's document through the persistor.
    pub save: SaveStep<T, P, SaveError>,

    /// Builds the engine from the batch's shared read source and runs its
    /// scan over the binary.
    pub build_and_scan: EngineStep<T, ScanError>,

    /// What the success log reports — genuinely per-engine (the type-
    /// database scan reports named types, vtables, and inferred structs;
    /// a single-finding-count scan reports one).
    pub on_saved: SuccessStep<T>,

    /// Optional step run before the engine is built.
    pub pre_scan: Option<ScanHook>,

    /// Optional step run on every exit of the scan.
    pub post_scan: Option<ScanHook>,
}

/// One registered scan as the phase's table holds it: the row's shape,
/// type-erased, plus the identity and document location the table and its
/// consumers read without running the scan.
pub struct ScanDescriptor {
    name: &'static str,
    run: RunStep,
    document_path: LocationStep,
}

impl ScanDescriptor {
    /// Erase one typed row into the table — the single generic
    /// constructor, and the only place the scan's shape is written. The
    /// shape it applies: short-circuit on the filed document ahead of any
    /// engine read; otherwise log the start, run the pre-scan hook, build
    /// the engine from the batch's shared read source, persist the
    /// document, and degrade to a warning (leaving no document) when the
    /// scan or the save fails — answering `false` either way, `true` on a
    /// cached hit or a saved document. The post-scan hook runs on every
    /// exit. The heartbeat, the window, and the joins stay the phase's;
    /// the row never sees them.
    pub fn new<T, P, ScanError, SaveError>(row: ScanRow<T, P, ScanError, SaveError>) -> Self
    where
        T: Send + 'static,
        P: Send + Sync + 'static,
        ScanError: std::fmt::Display + Send + 'static,
        SaveError: std::fmt::Display + Send + 'static,
    {
        let name = row.name;
        let messages = row.messages;
        // The run thunk is an `Fn` closure handing back a boxed future,
        // and each step is already an `Arc`, so the future takes cheap
        // clones of the captures rather than moving them out.
        let persistor = row.persistor;
        let exists = row.exists;
        let document_path = row.document_path;
        let save = row.save;
        let build_and_scan = row.build_and_scan;
        let on_saved = row.on_saved;
        let pre_scan = row.pre_scan;
        let post_scan = row.post_scan;

        // One Arc of the location namer stays with the descriptor for its
        // `document_path` accessor; the run thunk takes its own clone.
        let table_path = Arc::clone(&document_path);
        let run: RunStep = Box::new(move |ctx: ScanContext| {
            let persistor = Arc::clone(&persistor);
            let exists = Arc::clone(&exists);
            let document_path = Arc::clone(&document_path);
            let save = Arc::clone(&save);
            let build_and_scan = Arc::clone(&build_and_scan);
            let on_saved = Arc::clone(&on_saved);
            let pre_scan = pre_scan.clone();
            let post_scan = post_scan.clone();
            Box::pin(async move {
                let persistor = persistor(&ctx.workspace);
                let scanned = if exists(&persistor, &ctx.binary) {
                    debug!(
                        binary = %ctx.binary,
                        path = %document_path(&ctx.workspace, &ctx.binary).display(),
                        "{}", messages.cached_hit
                    );
                    true
                } else {
                    info!(binary = %ctx.binary, "{}", messages.scan_started);
                    if let Some(pre) = &pre_scan {
                        pre(&ctx).await;
                    }
                    let outcome = build_and_scan(ctx.source.clone(), ctx.binary.clone()).await;
                    match outcome {
                        Ok(result) => match save(&persistor, &result) {
                            Ok(()) => {
                                on_saved(&ctx, &result);
                                true
                            }
                            Err(e) => {
                                warn!(binary = %ctx.binary, error = %e, "{}", messages.save_failed);
                                false
                            }
                        },
                        Err(e) => {
                            warn!(binary = %ctx.binary, error = %e, "{}", messages.scan_failed);
                            false
                        }
                    }
                };
                if let Some(post) = &post_scan {
                    post(&ctx).await;
                }
                scanned
            })
        });

        Self {
            name,
            run,
            document_path: table_path,
        }
    }

    /// The scan's name — its identity in logs and in the registry's
    /// completeness roster.
    pub fn name(&self) -> &'static str {
        self.name
    }

    /// Where this scan's document is filed under a workspace root, named
    /// through the engine's own persistor — the documented location the
    /// scan-phase tests assert.
    pub fn document_path(&self, workspace: &Path, binary: &str) -> PathBuf {
        (self.document_path)(workspace, binary)
    }

    /// Run the scan over the batch's context and report whether its
    /// document is in place afterwards — filed by this run, or already
    /// filed and short-circuited. A failure warns and answers `false`;
    /// it never aborts the group around it.
    pub async fn run(&self, ctx: ScanContext) -> bool {
        (self.run)(ctx).await
    }
}

/// Control-flow pattern detection, the first scan to run from a row
/// (issue #302). The wording matches the legacy
/// [`controlflow_detection`](crate::scan_job::ScanJob) scan method
/// byte-for-byte, and the document lands where that method filed it:
/// `re/analysis/controlflow/<binary>.json` through the engine's own
/// persistor. No hooks — control-flow detection orders with nothing.
fn controlflow_row() -> ScanDescriptor {
    ScanDescriptor::new(ScanRow {
        name: "control-flow",
        messages: ScanMessages {
            scan_started: "Detecting control-flow patterns before batch translation",
            cached_hit: "Control-flow result already cached; skipping scan",
            scan_failed: "Control-flow detection failed; continuing without control-flow context",
            save_failed: "Failed to persist control-flow result; continuing without control-flow context",
        },
        persistor: Arc::new(|workspace| ControlFlowPersistor::new(workspace)),
        exists: Arc::new(|persistor, binary| persistor.exists(binary)),
        document_path: Arc::new(|workspace, binary| {
            ControlFlowPersistor::new(workspace).path_for(binary)
        }),
        save: Arc::new(|persistor, result| persistor.save(result)),
        // The engine and the binary name are moved into the scan future
        // rather than borrowed from this frame — the fan-out needs a
        // `'static` boxed future (rust#100013), the same shape the legacy
        // algorithm scan already runs.
        build_and_scan: Arc::new(|source, binary| {
            let engine = ControlFlowEngine::with_source(source);
            Box::pin(async move { engine.scan(binary).await })
        }),
        on_saved: Arc::new(|ctx, result| {
            info!(
                binary = %ctx.binary,
                findings = result.findings.len(),
                "Control-flow detection complete"
            );
        }),
        pre_scan: None,
        post_scan: None,
    })
}

/// The registered scan rows: the scans the phase runs from their
/// descriptor, run first ahead of the legacy scans that have not migrated
/// yet. Adding a scan to (or dropping one from) the phase means editing
/// this table — and the translator suite's roster test names the rows
/// explicitly, so the edit is deliberate, never an accident of a list
/// someone forgot (the `libmatch` drift, spec #301).
pub fn scan_rows() -> Vec<ScanDescriptor> {
    vec![
        controlflow_row(),
        memory_row(),
        concurrency_row(),
        global_state_row(),
        constants_row(),
        error_handling_row(),
        floatsimd_row(),
        type_database_row(),
        algorithm_row(),
        string_context_row(),
        library_api_row(),
        serialization_row(),
    ]
}

/// Memory lifecycle detection, running from its row (issue #303). The
/// wording matches the legacy [`memory_detection`](crate::scan_job::ScanJob)
/// scan method byte-for-byte, and the document lands where that method
/// filed it: `re/analysis/memory/<binary>.json` through the engine's own
/// persistor. No hooks — the scan orders with nothing.
fn memory_row() -> ScanDescriptor {
    ScanDescriptor::new(ScanRow {
        name: "memory-lifecycle",
        messages: ScanMessages {
            scan_started: "Detecting memory lifecycles before batch translation",
            cached_hit: "Memory lifecycle result already cached; skipping scan",
            scan_failed: "Memory lifecycle detection failed; continuing without memory context",
            save_failed: "Failed to persist memory lifecycle result; continuing without memory context",
        },
        persistor: Arc::new(|workspace| MemoryPersistor::new(workspace)),
        exists: Arc::new(|persistor, binary| persistor.exists(binary)),
        document_path: Arc::new(|workspace, binary| {
            MemoryPersistor::new(workspace).path_for(binary)
        }),
        save: Arc::new(|persistor, result| persistor.save(result)),
        build_and_scan: Arc::new(|source, binary| {
            let engine = MemoryEngine::with_source(source);
            Box::pin(async move { engine.scan(binary).await })
        }),
        on_saved: Arc::new(|ctx, result| {
            info!(
                binary = %ctx.binary,
                findings = result.findings.len(),
                "Memory lifecycle detection complete"
            );
        }),
        pre_scan: None,
        post_scan: None,
    })
}

/// Concurrency detection, running from its row (issue #303). The wording
/// matches the legacy [`sync_detection`](crate::scan_job::ScanJob) scan
/// method byte-for-byte, and the document lands at
/// `re/analysis/sync/<binary>.json` through the engine's own persistor.
/// No hooks — the scan orders with nothing.
fn concurrency_row() -> ScanDescriptor {
    ScanDescriptor::new(ScanRow {
        name: "concurrency",
        messages: ScanMessages {
            scan_started: "Detecting concurrency constructs before batch translation",
            cached_hit: "Concurrency result already cached; skipping scan",
            scan_failed: "Concurrency detection failed; continuing without concurrency context",
            save_failed: "Failed to persist concurrency result; continuing without concurrency context",
        },
        persistor: Arc::new(|workspace| SyncPersistor::new(workspace)),
        exists: Arc::new(|persistor, binary| persistor.exists(binary)),
        document_path: Arc::new(|workspace, binary| SyncPersistor::new(workspace).path_for(binary)),
        save: Arc::new(|persistor, result| persistor.save(result)),
        build_and_scan: Arc::new(|source, binary| {
            let engine = SyncEngine::with_source(source);
            Box::pin(async move { engine.scan(binary).await })
        }),
        on_saved: Arc::new(|ctx, result| {
            info!(
                binary = %ctx.binary,
                findings = result.findings.len(),
                "Concurrency detection complete"
            );
        }),
        pre_scan: None,
        post_scan: None,
    })
}

/// Global-state reference-set detection, running from its row
/// (issue #303). The wording matches the legacy
/// [`global_state_detection`](crate::scan_job::ScanJob) scan method
/// byte-for-byte, and the document lands at
/// `re/analysis/globalstate/<binary>.json` through the engine's own
/// persistor. No hooks — the scan orders with nothing.
fn global_state_row() -> ScanDescriptor {
    ScanDescriptor::new(ScanRow {
        name: "global-state",
        messages: ScanMessages {
            scan_started: "Detecting global-state accesses before batch translation",
            cached_hit: "Global-state result already cached; skipping scan",
            scan_failed: "Global-state detection failed; continuing without global-state context",
            save_failed: "Failed to persist global-state result; continuing without global-state context",
        },
        persistor: Arc::new(|workspace| GlobalStatePersistor::new(workspace)),
        exists: Arc::new(|persistor, binary| persistor.exists(binary)),
        document_path: Arc::new(|workspace, binary| {
            GlobalStatePersistor::new(workspace).path_for(binary)
        }),
        save: Arc::new(|persistor, result| persistor.save(result)),
        build_and_scan: Arc::new(|source, binary| {
            let engine = GlobalStateEngine::with_source(source);
            Box::pin(async move { engine.scan(binary).await })
        }),
        on_saved: Arc::new(|ctx, result| {
            info!(
                binary = %ctx.binary,
                findings = result.findings.len(),
                "Global-state detection complete"
            );
        }),
        pre_scan: None,
        post_scan: None,
    })
}

/// Constant structure detection, running from its row (issue #303). The
/// wording matches the legacy [`const_detection`](crate::scan_job::ScanJob)
/// scan method byte-for-byte, and the document lands at
/// `re/analysis/consts/<binary>.json` through the engine's own persistor.
/// No hooks — the scan orders with nothing.
fn constants_row() -> ScanDescriptor {
    ScanDescriptor::new(ScanRow {
        name: "constants",
        messages: ScanMessages {
            scan_started: "Detecting constant structures before batch translation",
            cached_hit: "Constant result already cached; skipping scan",
            scan_failed: "Constant detection failed; continuing without constant context",
            save_failed: "Failed to persist constant result; continuing without constant context",
        },
        persistor: Arc::new(|workspace| ConstPersistor::new(workspace)),
        exists: Arc::new(|persistor, binary| persistor.exists(binary)),
        document_path: Arc::new(|workspace, binary| {
            ConstPersistor::new(workspace).path_for(binary)
        }),
        save: Arc::new(|persistor, result| persistor.save(result)),
        build_and_scan: Arc::new(|source, binary| {
            let engine = ConstEngine::with_source(source);
            Box::pin(async move { engine.scan(binary).await })
        }),
        on_saved: Arc::new(|ctx, result| {
            info!(
                binary = %ctx.binary,
                findings = result.findings.len(),
                "Constant detection complete"
            );
        }),
        pre_scan: None,
        post_scan: None,
    })
}

/// Error-handling idiom detection, running from its row (issue #303). The
/// wording matches the legacy
/// [`error_handling_detection`](crate::scan_job::ScanJob) scan method
/// byte-for-byte, and the document lands at
/// `re/analysis/errhandling/<binary>.json` through the engine's own
/// persistor. No hooks — the scan orders with nothing.
fn error_handling_row() -> ScanDescriptor {
    ScanDescriptor::new(ScanRow {
        name: "error-handling",
        messages: ScanMessages {
            scan_started: "Detecting error-handling idioms before batch translation",
            cached_hit: "Error-handling result already cached; skipping scan",
            scan_failed: "Error-handling idiom detection failed; continuing without error-handling context",
            save_failed: "Failed to persist error-handling result; continuing without error-handling context",
        },
        persistor: Arc::new(|workspace| ErrhandlingPersistor::new(workspace)),
        exists: Arc::new(|persistor, binary| persistor.exists(binary)),
        document_path: Arc::new(|workspace, binary| {
            ErrhandlingPersistor::new(workspace).path_for(binary)
        }),
        save: Arc::new(|persistor, result| persistor.save(result)),
        build_and_scan: Arc::new(|source, binary| {
            let engine = ErrhandlingEngine::with_source(source);
            Box::pin(async move { engine.scan(binary).await })
        }),
        on_saved: Arc::new(|ctx, result| {
            info!(
                binary = %ctx.binary,
                findings = result.findings.len(),
                "Error-handling idiom detection complete"
            );
        }),
        pre_scan: None,
        post_scan: None,
    })
}

/// Float/SIMD usage detection, running from its row (issue #303). The
/// wording matches the legacy [`floatsimd_detection`](crate::scan_job::ScanJob)
/// scan method byte-for-byte, and the document lands at
/// `re/analysis/floatsimd/<binary>.json` through the engine's own
/// persistor. No hooks — the scan orders with nothing.
fn floatsimd_row() -> ScanDescriptor {
    ScanDescriptor::new(ScanRow {
        name: "float-simd",
        messages: ScanMessages {
            scan_started: "Detecting float/SIMD usage before batch translation",
            cached_hit: "Float/SIMD result already cached; skipping scan",
            scan_failed: "Float/SIMD usage detection failed; continuing without float/SIMD context",
            save_failed: "Failed to persist float/SIMD result; continuing without float/SIMD context",
        },
        persistor: Arc::new(|workspace| FloatsimdPersistor::new(workspace)),
        exists: Arc::new(|persistor, binary| persistor.exists(binary)),
        document_path: Arc::new(|workspace, binary| {
            FloatsimdPersistor::new(workspace).path_for(binary)
        }),
        save: Arc::new(|persistor, result| persistor.save(result)),
        build_and_scan: Arc::new(|source, binary| {
            let engine = FloatsimdEngine::with_source(source);
            Box::pin(async move { engine.scan(binary).await })
        }),
        on_saved: Arc::new(|ctx, result| {
            info!(
                binary = %ctx.binary,
                findings = result.findings.len(),
                "Float/SIMD usage detection complete"
            );
        }),
        pre_scan: None,
        post_scan: None,
    })
}

/// Type-database recovery, running from its row (issue #304). The wording
/// matches the legacy [`type_database`](crate::scan_job::ScanJob) scan
/// method byte-for-byte, and the document lands at
/// `re/analysis/typesdb/<binary>.json` through the engine's own
/// persistor. This row is the proof that no engine needs its own scan
/// body for a richer success log: it reports named types, vtables, and
/// inferred structs as three separate counts, and `on_saved` is the row's
/// own closure over the engine's result type — the module holds no
/// engine-specific code. No hooks — the scan orders with nothing.
fn type_database_row() -> ScanDescriptor {
    ScanDescriptor::new(ScanRow {
        name: "type-database",
        messages: ScanMessages {
            scan_started: "Recovering type database before batch translation",
            cached_hit: "Type database already cached; skipping recovery",
            scan_failed: "Type database recovery failed; continuing without data structure context",
            save_failed: "Failed to persist recovered type database; continuing without data structure context",
        },
        persistor: Arc::new(|workspace| TypeDatabasePersistor::new(workspace)),
        exists: Arc::new(|persistor, binary| persistor.exists(binary)),
        document_path: Arc::new(|workspace, binary| {
            TypeDatabasePersistor::new(workspace).path_for(binary)
        }),
        save: Arc::new(|persistor, db| persistor.save(db)),
        build_and_scan: Arc::new(|source, binary| {
            let engine = TypesDBEngine::with_source(source);
            Box::pin(async move { engine.scan(binary).await })
        }),
        on_saved: Arc::new(|ctx, db| {
            info!(
                binary = %ctx.binary,
                named_types = db.named_types.len(),
                vtables = db.vtables.len(),
                inferred_structs = db.inferred_structs.len(),
                "Type database recovered"
            );
        }),
        pre_scan: None,
        post_scan: None,
    })
}

/// Algorithm recognition, running from its row (issue #304). The wording
/// matches the legacy [`algorithm_recognition`](crate::scan_job::ScanJob)
/// scan method byte-for-byte, and the document lands at
/// `re/analysis/algorithm/<binary>.json` through the engine's own
/// persistor. The engine and the binary name move into the scan future —
/// the recognition pass is deeply nested (its own concurrent pass inside)
/// and rustc cannot prove a borrowed nested future `'static`
/// (rust#100013), the same shape the legacy method ran. No hooks — the
/// scan orders with nothing.
fn algorithm_row() -> ScanDescriptor {
    ScanDescriptor::new(ScanRow {
        name: "algorithm-recognition",
        messages: ScanMessages {
            scan_started: "Recognizing algorithms before batch translation",
            cached_hit: "Algorithm recognition result already cached; skipping scan",
            scan_failed: "Algorithm recognition failed; continuing without algorithm context",
            save_failed: "Failed to persist algorithm recognition result; continuing without algorithm context",
        },
        persistor: Arc::new(|workspace| AlgorithmPersistor::new(workspace)),
        exists: Arc::new(|persistor, binary| persistor.exists(binary)),
        document_path: Arc::new(|workspace, binary| {
            AlgorithmPersistor::new(workspace).path_for(binary)
        }),
        save: Arc::new(|persistor, result| persistor.save(result)),
        build_and_scan: Arc::new(|source, binary| {
            let engine = AlgorithmEngine::with_source(source);
            Box::pin(async move { engine.scan(binary).await })
        }),
        on_saved: Arc::new(|ctx, result| {
            info!(
                binary = %ctx.binary,
                hints = result.hints.len(),
                "Algorithm recognition complete"
            );
        }),
        pre_scan: None,
        post_scan: None,
    })
}

/// String-context mapping, running from its row (issue #304). The wording
/// matches the legacy [`string_context`](crate::scan_job::ScanJob) scan
/// method byte-for-byte, and the document lands at
/// `re/analysis/stringctx/<binary>.json` through the engine's own
/// persistor. No hooks — the scan orders with nothing.
fn string_context_row() -> ScanDescriptor {
    ScanDescriptor::new(ScanRow {
        name: "string-context",
        messages: ScanMessages {
            scan_started: "Mapping program strings before batch translation",
            cached_hit: "String context result already cached; skipping scan",
            scan_failed: "String context scan failed; continuing without string context",
            save_failed: "Failed to persist string context result; continuing without string context",
        },
        persistor: Arc::new(|workspace| StringContextPersistor::new(workspace)),
        exists: Arc::new(|persistor, binary| persistor.exists(binary)),
        document_path: Arc::new(|workspace, binary| {
            StringContextPersistor::new(workspace).path_for(binary)
        }),
        save: Arc::new(|persistor, result| persistor.save(result)),
        build_and_scan: Arc::new(|source, binary| {
            let engine = StringContextEngine::with_source(source);
            Box::pin(async move { engine.scan(binary).await })
        }),
        on_saved: Arc::new(|ctx, result| {
            info!(
                binary = %ctx.binary,
                findings = result.findings.len(),
                "String context scan complete"
            );
        }),
        pre_scan: None,
        post_scan: None,
    })
}

/// Library/API identification, running from its row (issue #304). The
/// wording matches the legacy [`api_detection`](crate::scan_job::ScanJob)
/// scan method byte-for-byte, and the document lands at
/// `re/analysis/apidetect/<binary>.json` through the engine's own
/// persistor. No hooks — the scan orders with nothing.
fn library_api_row() -> ScanDescriptor {
    ScanDescriptor::new(ScanRow {
        name: "library-api",
        messages: ScanMessages {
            scan_started: "Identifying libraries and APIs before batch translation",
            cached_hit: "API result already cached; skipping scan",
            scan_failed: "API detection failed; continuing without API context",
            save_failed: "Failed to persist API result; continuing without API context",
        },
        persistor: Arc::new(|workspace| ApiPersistor::new(workspace)),
        exists: Arc::new(|persistor, binary| persistor.exists(binary)),
        document_path: Arc::new(|workspace, binary| ApiPersistor::new(workspace).path_for(binary)),
        save: Arc::new(|persistor, result| persistor.save(result)),
        build_and_scan: Arc::new(|source, binary| {
            let engine = ApiEngine::with_source(source);
            Box::pin(async move { engine.scan(binary).await })
        }),
        on_saved: Arc::new(|ctx, result| {
            info!(
                binary = %ctx.binary,
                findings = result.findings.len(),
                "API detection complete"
            );
        }),
        pre_scan: None,
        post_scan: None,
    })
}

/// Serialization-pattern detection, running from its row (issue #304).
/// The wording matches the legacy
/// [`serialize_detection`](crate::scan_job::ScanJob) scan method
/// byte-for-byte, and the document lands at
/// `re/analysis/serialize/<binary>.json` through the engine's own
/// persistor. No hooks — the scan orders with nothing.
fn serialization_row() -> ScanDescriptor {
    ScanDescriptor::new(ScanRow {
        name: "serialization",
        messages: ScanMessages {
            scan_started: "Detecting serialization patterns before batch translation",
            cached_hit: "Serialization result already cached; skipping scan",
            scan_failed: "Serialization detection failed; continuing without serialization context",
            save_failed: "Failed to persist serialization result; continuing without serialization context",
        },
        persistor: Arc::new(|workspace| SerializePersistor::new(workspace)),
        exists: Arc::new(|persistor, binary| persistor.exists(binary)),
        document_path: Arc::new(|workspace, binary| {
            SerializePersistor::new(workspace).path_for(binary)
        }),
        save: Arc::new(|persistor, result| persistor.save(result)),
        build_and_scan: Arc::new(|source, binary| {
            let engine = SerializeEngine::with_source(source);
            Box::pin(async move { engine.scan(binary).await })
        }),
        on_saved: Arc::new(|ctx, result| {
            info!(
                binary = %ctx.binary,
                findings = result.findings.len(),
                "Serialization detection complete"
            );
        }),
        pre_scan: None,
        post_scan: None,
    })
}
