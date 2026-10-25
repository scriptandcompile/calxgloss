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
//! fifteen cannot sit in one list unboxed.
//!
//! The table is `pub` on purpose: the later generic CLI scan command
//! (P39) iterates these same rows. The descriptor is a pipeline-side
//! description of an engine, not a trait the evidence crates implement —
//! no evidence crate gains a dependency on, or implements, a
//! pipeline-owned abstraction, and there is no shared persistor interface:
//! each row names its location through its own concrete `JsonStore`-based
//! persistor, exactly as the deleted legacy path did.
//!
//! Every scan now runs from its row (issue #305): the ordering edge that
//! once kept parameter-type inference and callback detection on the
//! legacy path is table data too — the callback row names the inference
//! row in its [`ScanRow::waits_for`], and the module owns the completion
//! latch generically ([`CompletionLatch`]): [`arm_completion_latches`]
//! arms one latch per producer the rows declare, and the run shape
//! hands it to the producer, publishing it on every exit whatever the
//! outcome, and to the waiter, whose pre-scan hook awaits it before
//! composing from the producer's document. No named latch field sits on
//! the handle or the module, and a second ordering edge added later is
//! one more pair of rows, not new mechanism.
//!
//! The legacy scan plumbing — the fourteen scan methods on `ScanJob`,
//! their pipeline wrappers, the table thunks, and the fourteen `ensure_*`
//! entry points — was deleted by issue #308: the registry is the only way
//! a scan enters the phase, and the operator-visible wording and document
//! locations the legacy path produced are pinned by the registry's own
//! tests, not by keeping dead code compiling. A new Evidence engine joins
//! with exactly one row: a `fn x_row() -> ScanDescriptor` built through
//! [`ScanDescriptor::new`], added to [`scan_rows`]' table — and the
//! roster test names every row, so joining or leaving the phase is always
//! a deliberate, reviewed edit (the `libmatch` drift, spec #301).

use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use calxgloss_algorithm::engine::AlgorithmEngine;
use calxgloss_algorithm::persist::AlgorithmPersistor;
use calxgloss_apidetect::engine::ApiEngine;
use calxgloss_apidetect::persist::ApiPersistor;
use calxgloss_callback::engine::CallbackEngine;
use calxgloss_callback::persist::CallbackPersistor;
use calxgloss_callback::signatures::SignatureMap;
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
use calxgloss_libmatch::engine::LibmatchEngine;
use calxgloss_libmatch::persist::LibmatchPersistor;
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
/// is built (the callback row awaits its declared dependency and composes
/// its signature map there), and a post-scan step runs on every exit —
/// cached hit, success, and both failures alike. Completion latches are
/// not a row hook: the run shape itself publishes the latch a row's
/// producer arm carries, on every exit (see [`ScanLatches`]). Rows use
/// neither hook today beyond callback detection's pre-scan step; the
/// shape is here so later rows need no new mechanism.
pub type ScanHook = Arc<dyn Fn(&ScanContext) -> OwnedFuture<()> + Send + Sync + 'static>;

/// A declared dependency's completion latch — the phase's one ordering
/// edge between rows, named only by the producer's scan name in the
/// declaring rows (issue #305, generalizing issue #238's named field).
///
/// The phase arms one latch per scan a row declares it waits for; the
/// producer's run publishes it on every exit — cached-document hit,
/// successful scan, and failure alike — and the waiter's run awaits it
/// in its pre-scan hook before composing from the producer's document.
/// What made callback detection read inference's output only after
/// inference had run — once a positional accident of the preamble's
/// call order — is data on the rows that depend on it.
///
/// A shared one-shot: every clone of the latch sees the same completion
/// flag. [`wait`](Self::wait) answers immediately once the flag is set,
/// so a waiter that arrives after the publish never blocks and one that
/// arrived before is released by it. Because the publish happens on
/// failure too — and a latch whose producer never ran closes with it —
/// a waiter is never stranded: it releases and degrades to composing
/// nothing when no document is in place.
#[derive(Debug, Clone)]
pub struct CompletionLatch {
    /// The completion flag, kept alive across clones of the latch by
    /// the same `Arc<watch::Sender>` shape the progress bus uses.
    completed: Arc<watch::Sender<bool>>,

    /// The half a reader waits on; cheap to clone along with the latch.
    waiter: watch::Receiver<bool>,
}

impl CompletionLatch {
    /// A fresh, unpublished latch.
    pub fn new() -> Self {
        let (completed, waiter) = watch::channel(false);
        Self {
            completed: Arc::new(completed),
            waiter,
        }
    }

    /// Publish completion — the producing scan is done, succeeded or
    /// failed. Idempotent: a second publish changes nothing.
    pub fn publish(&self) {
        self.completed.send_replace(true);
    }

    /// Whether the producer has published its completion.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn is_set(&self) -> bool {
        *self.waiter.borrow()
    }

    /// Wait for the producing scan to finish. Returns immediately when
    /// the latch is already published; a channel closed with no
    /// publisher left also releases, so the waiter is never stranded —
    /// only degraded.
    pub async fn wait(&self) {
        let mut waiter = self.waiter.clone();
        // `wait_for` re-checks the current value before each poll, so a
        // publish landing between the check and the wait is never missed.
        let _ = waiter.wait_for(|completed| *completed).await;
    }
}

impl Default for CompletionLatch {
    fn default() -> Self {
        Self::new()
    }
}

/// The completion latches the phase hands to one row's run, wired from
/// the table's declarations rather than from anything the row builds
/// itself (issue #305): a row never arms or publishes a latch through a
/// field of its own — the phase arms one [`CompletionLatch`] per declared
/// producer ([`arm_completion_latches`]) and hands it here. Adding an
/// ordering edge is therefore one more `waits_for` on a row, never a new
/// field on the handle or the module.
#[derive(Debug, Clone, Default)]
pub struct ScanLatches {
    /// The latch this row's run publishes on every exit — set when some
    /// row declares this row's name as the scan it depends on.
    pub publish: Option<CompletionLatch>,

    /// The latch this row's pre-scan hook waits on — set when this row
    /// declared the scan it depends on and that producer's latch armed.
    pub wait: Option<CompletionLatch>,
}

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
    /// loaded engine, exactly as `ScanJob`
    /// carries it.
    pub source: PipelineSource,

    /// The completion latches the phase armed for this row's declared
    /// dependency edge (issue #305) — empty when the row orders with
    /// nothing, and never built by the row itself.
    pub latches: ScanLatches,
}

/// The operator-visible wording a row carries so degradation and progress
/// read exactly as the deleted legacy scan methods logged them (issue
/// #308 keeps the wording, drops the plumbing). Each message matches the
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

    /// The name of the scan this row's pre-scan work waits for, if any
    /// (issue #305). The phase arms one [`CompletionLatch`] for every
    /// producer name declared in the table and hands the same latch to
    /// the producer's run — published on every exit, whatever the
    /// outcome — and to this row's run, awaited before the pre-scan
    /// hook composes from the producer's document. A declared producer
    /// missing from the table closes its latch's channel, so the waiter
    /// releases degraded rather than stranded.
    pub waits_for: Option<&'static str>,

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
    waits_for: Option<&'static str>,
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
    /// exit, and so does the publish of a producer arm's completion
    /// latch: cached hit, success, and both failures release the waiter
    /// alike (issue #305). The heartbeat, the window, and the joins stay
    /// the phase's; the row never sees them.
    pub fn new<T, P, ScanError, SaveError>(row: ScanRow<T, P, ScanError, SaveError>) -> Self
    where
        T: Send + 'static,
        P: Send + Sync + 'static,
        ScanError: std::fmt::Display + Send + 'static,
        SaveError: std::fmt::Display + Send + 'static,
    {
        let name = row.name;
        let waits_for = row.waits_for;
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
                // The producer arm of a declared edge publishes on every
                // exit — cached hit, success, and both failures alike —
                // so a waiter is released whatever the outcome (issue
                // #305). The latch is the phase's wiring, never a field
                // this row built or named.
                if let Some(latch) = &ctx.latches.publish {
                    latch.publish();
                }
                scanned
            })
        });

        Self {
            name,
            waits_for,
            run,
            document_path: table_path,
        }
    }

    /// The scan's name — its identity in logs and in the registry's
    /// completeness roster.
    pub fn name(&self) -> &'static str {
        self.name
    }

    /// The scan this row declared it depends on (issue #305) — read by
    /// [`arm_completion_latches`] to wire the ordering edge generically.
    pub fn waits_for(&self) -> Option<&'static str> {
        self.waits_for
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
/// `controlflow_detection` scan method
/// byte-for-byte, and the document lands where that method filed it:
/// `re/analysis/controlflow/<binary>.json` through the engine's own
/// persistor. No hooks — control-flow detection orders with nothing.
fn controlflow_row() -> ScanDescriptor {
    ScanDescriptor::new(ScanRow {
        name: "control-flow",
        waits_for: None,
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

/// The registered scan rows: every scan the phase runs, and the only way
/// a scan reaches the phase (issue #308). Adding a
/// scan to (or dropping one from) the phase means editing this table —
/// and the translator suite's roster test names the rows explicitly, so
/// the edit is deliberate, never an accident of a list someone forgot
/// (the `libmatch` drift, spec #301).
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
        type_inference_row(),
        callback_row(),
        known_library_row(),
    ]
}

/// Arm one completion latch per scan name the table declares a
/// dependency on (issue #305): one latch per declared producer for the
/// phase, a name declared by several waiters gets the one latch, and a
/// producer no row waits for gets none. The scan phase wires the result
/// into each row's [`ScanContext`] — the producer's run publishes the
/// latch on every exit, its waiters' runs await it — so an ordering
/// edge is a row declaration and nothing else: a second edge added
/// later needs no new field on the handle or the module. A declared
/// producer missing from the table leaves its latch with no publisher:
/// the watch channel closes and its waiters release degraded rather
/// than stranded.
pub fn arm_completion_latches(rows: &[ScanDescriptor]) -> Vec<(&'static str, CompletionLatch)> {
    let mut latches: Vec<(&'static str, CompletionLatch)> = Vec::new();
    for producer in rows.iter().filter_map(ScanDescriptor::waits_for) {
        if !latches.iter().any(|(name, _)| *name == producer) {
            latches.push((producer, CompletionLatch::new()));
        }
    }
    latches
}

/// Memory lifecycle detection, running from its row (issue #303). The
/// wording matches the legacy `memory_detection`
/// scan method byte-for-byte, and the document lands where that method
/// filed it: `re/analysis/memory/<binary>.json` through the engine's own
/// persistor. No hooks — the scan orders with nothing.
fn memory_row() -> ScanDescriptor {
    ScanDescriptor::new(ScanRow {
        name: "memory-lifecycle",
        waits_for: None,
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
/// matches the legacy `sync_detection` scan
/// method byte-for-byte, and the document lands at
/// `re/analysis/sync/<binary>.json` through the engine's own persistor.
/// No hooks — the scan orders with nothing.
fn concurrency_row() -> ScanDescriptor {
    ScanDescriptor::new(ScanRow {
        name: "concurrency",
        waits_for: None,
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
/// `global_state_detection` scan method
/// byte-for-byte, and the document lands at
/// `re/analysis/globalstate/<binary>.json` through the engine's own
/// persistor. No hooks — the scan orders with nothing.
fn global_state_row() -> ScanDescriptor {
    ScanDescriptor::new(ScanRow {
        name: "global-state",
        waits_for: None,
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
/// wording matches the legacy `const_detection`
/// scan method byte-for-byte, and the document lands at
/// `re/analysis/consts/<binary>.json` through the engine's own persistor.
/// No hooks — the scan orders with nothing.
fn constants_row() -> ScanDescriptor {
    ScanDescriptor::new(ScanRow {
        name: "constants",
        waits_for: None,
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
/// `error_handling_detection` scan method
/// byte-for-byte, and the document lands at
/// `re/analysis/errhandling/<binary>.json` through the engine's own
/// persistor. No hooks — the scan orders with nothing.
fn error_handling_row() -> ScanDescriptor {
    ScanDescriptor::new(ScanRow {
        name: "error-handling",
        waits_for: None,
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
/// wording matches the legacy `floatsimd_detection`
/// scan method byte-for-byte, and the document lands at
/// `re/analysis/floatsimd/<binary>.json` through the engine's own
/// persistor. No hooks — the scan orders with nothing.
fn floatsimd_row() -> ScanDescriptor {
    ScanDescriptor::new(ScanRow {
        name: "float-simd",
        waits_for: None,
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
/// matches the legacy `type_database` scan
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
        waits_for: None,
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
/// matches the legacy `algorithm_recognition`
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
        waits_for: None,
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
/// matches the legacy `string_context` scan
/// method byte-for-byte, and the document lands at
/// `re/analysis/stringctx/<binary>.json` through the engine's own
/// persistor. No hooks — the scan orders with nothing.
fn string_context_row() -> ScanDescriptor {
    ScanDescriptor::new(ScanRow {
        name: "string-context",
        waits_for: None,
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
/// wording matches the legacy `api_detection`
/// scan method byte-for-byte, and the document lands at
/// `re/analysis/apidetect/<binary>.json` through the engine's own
/// persistor. No hooks — the scan orders with nothing.
fn library_api_row() -> ScanDescriptor {
    ScanDescriptor::new(ScanRow {
        name: "library-api",
        waits_for: None,
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
/// `serialize_detection` scan method
/// byte-for-byte, and the document lands at
/// `re/analysis/serialize/<binary>.json` through the engine's own
/// persistor. No hooks — the scan orders with nothing.
fn serialization_row() -> ScanDescriptor {
    ScanDescriptor::new(ScanRow {
        name: "serialization",
        waits_for: None,
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

/// Parameter-type inference, running from its row (issue #305). The
/// wording matches the legacy `type_inference`
/// scan method byte-for-byte, and the document lands where that method
/// filed it: `re/analysis/typeinfer/<binary>.json` through the engine's
/// own persistor. No hooks: publishing the completion latch its waiter
/// declared is the run shape's own every-exit step, not a row hook —
/// the row names no latch, it only *is* the producer the callback row's
/// `waits_for` names.
fn type_inference_row() -> ScanDescriptor {
    ScanDescriptor::new(ScanRow {
        name: "type-inference",
        waits_for: None,
        messages: ScanMessages {
            scan_started: "Inferring parameter types before batch translation",
            cached_hit: "Type inference result already cached; skipping scan",
            scan_failed: "Type inference failed; continuing without type context",
            save_failed: "Failed to persist type inference result; continuing without type context",
        },
        persistor: Arc::new(|workspace| TypeInferPersistor::new(workspace)),
        exists: Arc::new(|persistor, binary| persistor.exists(binary)),
        document_path: Arc::new(|workspace, binary| {
            TypeInferPersistor::new(workspace).path_for(binary)
        }),
        save: Arc::new(|persistor, result| persistor.save(result)),
        build_and_scan: Arc::new(|source, binary| {
            let engine = TypeInferEngine::with_source(source);
            Box::pin(async move { engine.scan(binary).await })
        }),
        on_saved: Arc::new(|ctx, result| {
            info!(
                binary = %ctx.binary,
                inferences = result.inferences.len(),
                "Type inference complete"
            );
        }),
        pre_scan: None,
        post_scan: None,
    })
}

/// Callback and function-pointer table detection, running from its row
/// (issue #305) — and the table's one declared ordering edge: its
/// `waits_for` names the inference row, so the phase arms the completion
/// latch that orders them. Its pre-scan hook is the whole of the scan's
/// pre-scan work: await the producer's latch (released on every exit,
/// so a failing inference scan degrades this one, never strands it),
/// then compose the closure-contract signatures from the filed
/// type-inference document into the cell the engine step reads back.
/// The wording matches the legacy
/// `callback_detection` scan method
/// byte-for-byte, and the document lands where that method filed it:
/// `re/analysis/callback/<binary>.json` through the engine's own
/// persistor.
fn callback_row() -> ScanDescriptor {
    // The composed signature map crosses from the pre-scan hook to the
    // engine step through this cell: the hook fills it after the wait
    // releases, and the engine step reads it when building the engine.
    // One row runs once per phase and `scan_rows` builds a fresh table
    // every phase, so the cell never spans two runs. With no producer
    // document the composition yields an empty map — the un-enriched
    // scan, degraded exactly as the legacy path left it.
    let composed: Arc<Mutex<SignatureMap>> = Arc::new(Mutex::new(SignatureMap::new()));

    ScanDescriptor::new(ScanRow {
        name: "callback-detection",
        waits_for: Some("type-inference"),
        messages: ScanMessages {
            scan_started: "Detecting callback tables before batch translation",
            cached_hit: "Callback result already cached; skipping scan",
            scan_failed: "Callback detection failed; continuing without callback context",
            save_failed: "Failed to persist callback result; continuing without callback context",
        },
        persistor: Arc::new(|workspace| CallbackPersistor::new(workspace)),
        exists: Arc::new(|persistor, binary| persistor.exists(binary)),
        document_path: Arc::new(|workspace, binary| {
            CallbackPersistor::new(workspace).path_for(binary)
        }),
        save: Arc::new(|persistor, result| persistor.save(result)),
        build_and_scan: {
            let composed = Arc::clone(&composed);
            Arc::new(move |source, binary| {
                let signatures = composed
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .clone();
                let engine = CallbackEngine::with_source(source).with_signatures(signatures);
                Box::pin(async move { engine.scan(binary).await })
            })
        },
        on_saved: Arc::new(|ctx, result| {
            info!(
                binary = %ctx.binary,
                findings = result.findings.len(),
                "Callback detection complete"
            );
        }),
        pre_scan: {
            let composed = Arc::clone(&composed);
            Some(Arc::new(move |ctx| {
                let composed = Arc::clone(&composed);
                // The boxed future outlives the borrowed context, so the
                // fields it reads are taken out of `ctx` before boxing.
                let latch = ctx.latches.wait.clone();
                let workspace = ctx.workspace.clone();
                let binary = ctx.binary.clone();
                Box::pin(async move {
                    // The declared edge, released by the phase's arm:
                    // the inference row publishes its latch on every
                    // exit — cached hit, success, or failure — and a
                    // wait on an unclaimed latch closes with the
                    // channel, so this scan is never stranded, only
                    // ever degraded to an empty signature map.
                    if let Some(latch) = &latch {
                        latch.wait().await;
                    }
                    let signatures = callback_signature_map(&workspace, &binary);
                    *composed
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner) = signatures;
                })
            }))
        },
        post_scan: None,
    })
}

/// Known-library identification, joining the phase as the fifteenth row
/// (issue #306, the drift spec #301 records: the engine, its persistor,
/// and its CLI existed while nothing in a run ever filed its document).
/// The document lands where its two readers already look —
/// `re/analysis/libmatch/<binary>.json` through the engine's own
/// persistor — so the escalation prompt path finally finds a document
/// on a cold run, and a call graph built after the phase finds it for
/// Skip classification. No hooks — the scan orders with nothing.
///
/// The batch's engine is built with the built-in starter signature set;
/// the operator-supplied signature database, the cached-report view, and
/// the console report stay command-only — a batch never guesses at a
/// curated set, and `calxgloss libmatch` behaves exactly as before.
///
/// Two limitations are recorded here rather than hidden:
///
/// * The call-graph *batch* path receives a pre-built graph, so its
///   Skip classification still benefits only when a document already
///   existed from an earlier run; re-ordering the graph build ahead of
///   the batch is out of scope for this track (spec #301).
/// * The built-in starter signatures are hand-authored against Ghidra
///   pseudo-C spellings, and the shapes Kuna emits (the only engine) do
///   not fold onto those wildcards — a cold run today therefore files a
///   metadata-carrying, findings-empty document, and the readers see
///   real identifications only once signatures can speak Kuna's dialect
///   (issue #309). The wiring this row adds is what makes that payoff
///   land without another pipeline change.
fn known_library_row() -> ScanDescriptor {
    ScanDescriptor::new(ScanRow {
        name: "known-library",
        waits_for: None,
        messages: ScanMessages {
            scan_started: "Identifying known-library functions before batch translation",
            cached_hit: "Known-library result already cached; skipping scan",
            scan_failed: "Known-library identification failed; continuing without known-library context",
            save_failed: "Failed to persist known-library result; continuing without known-library context",
        },
        persistor: Arc::new(|workspace| LibmatchPersistor::new(workspace)),
        exists: Arc::new(|persistor, binary| persistor.exists(binary)),
        document_path: Arc::new(|workspace, binary| {
            LibmatchPersistor::new(workspace).path_for(binary)
        }),
        save: Arc::new(|persistor, result| persistor.save(result)),
        build_and_scan: Arc::new(|source, binary| {
            let engine = LibmatchEngine::with_source(source);
            Box::pin(async move { engine.scan(binary).await })
        }),
        on_saved: Arc::new(|ctx, result| {
            info!(
                binary = %ctx.binary,
                findings = result.findings.len(),
                "Known-library identification complete"
            );
        }),
        pre_scan: None,
        post_scan: None,
    })
}
