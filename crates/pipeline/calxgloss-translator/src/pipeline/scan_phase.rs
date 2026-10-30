//! The pre-batch scan phase end to end: the descriptor-driven scan rows and
//! their fan-out window, the scan pass and the cached-source door, and the
//! seam capability report read.

use super::*;

/// The scan phase's name in progress reporting: one row carrying
/// "n of m functions consumed" for the whole group of fifteen pre-batch
/// evidence scans, instead of a separate row per scan that restarts with
/// each scan (issue #239).
pub(super) const SCAN_PHASE: &str = "evidence scans";

/// At most four evidence scans run at a time — the scan phase's fan-out
/// window (issue #240).
///
/// The cap does not protect the analysis engine. The engine handles one
/// request at a time either way, and the scan read cache already turns
/// simultaneous requests for one function body into a single engine request.
///
/// The cap exists to limit peak memory (each running scan keeps its own
/// copies of function bodies, while the shared cache stores each body
/// once) and to keep the scan phase's single dashboard row readable.
///
/// Four was chosen by measurement (issue #241). On eqmain.dll (4,076
/// functions), raising the cap from four to eleven changed warm-cache
/// speed almost nothing (56.6 s → 57.3 s), was slower on cold reads
/// (113.9 s → 153.8 s, because more scans in flight stack up waiting work
/// on the same listing data the engine is processing), and added about a
/// seventh more kept decompilation copies. So four stands. Raising it
/// later is a one-line change, guarded by
/// `the_scan_phase_window_never_runs_more_than_the_named_cap_at_a_time`,
/// which pins the phase at or under this constant and never at one scan.
pub(super) const MAX_CONCURRENT_EVIDENCE_SCANS: usize = 4;

/// One evidence scan as the fan-out's unit of work: takes its owned
/// [`ScanJob`] and hands back the scan's boxed future. Each scan's future
/// is a distinct type, so the window boxes them to move them onto tasks
/// (issue #240). Registered rows arrive as closures that capture their row,
/// hence the boxed `FnOnce` rather than the plain `fn` pointer (issue #302).
pub(super) type EvidenceScanTask =
    Box<dyn FnOnce(ScanJob) -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + 'static>;

/// One evidence scan as it passes through the fan-out window: it counts
/// itself in, runs, and counts itself out. The phase records the highest
/// count it ever reached, so the window's cap is a tested contract rather
/// than only a comment (issue #241). A named async fn again, so that the
/// spawned future is `'static` (issue #240).
pub(super) async fn run_scan_in_window(
    scan: EvidenceScanTask,
    job: ScanJob,
    in_flight: Arc<AtomicUsize>,
    high_water: Arc<AtomicUsize>,
) {
    let entered = in_flight.fetch_add(1, Ordering::SeqCst) + 1;
    high_water.fetch_max(entered, Ordering::SeqCst);
    scan(job).await;
    in_flight.fetch_sub(1, Ordering::SeqCst);
}

/// One registered row as the phase runs it: the row reads the batch
/// through the job's owned context, carries the completion latches the
/// phase armed for its declared dependency edge, and reports its own
/// outcome; the phase's window, progress reporting, and joins wrap it
/// from outside (issues #302, #305).
pub(super) async fn run_registered_scan(row: ScanDescriptor, job: ScanJob, latches: ScanLatches) {
    let mut ctx = job.scan_context();
    ctx.latches = latches;
    row.run(ctx).await;
}

/// The registered rows as ready-to-run tasks: each row moves into its own
/// closure, boxed so the window can move it onto a task (issue #240). The
/// completion latches are attached to each row's context from the table's
/// own declarations — the latch armed for this row's name is the one its
/// run publishes on every exit, and the latch named by its `waits_for` is
/// the one its pre-scan hook waits on (issue #305). No row carries its own
/// latch field; the ordering edge is table data, and this is the only way
/// a scan enters the phase (issue #308).
pub(super) fn registered_scan_tasks() -> Vec<EvidenceScanTask> {
    let rows = scan_rows();
    let armed = arm_completion_latches(&rows);
    rows.into_iter()
        .map(|row| -> EvidenceScanTask {
            let publish = armed
                .iter()
                .find(|(name, _)| *name == row.name())
                .map(|(_, latch)| latch.clone());
            let wait = row.waits_for().and_then(|producer| {
                armed
                    .iter()
                    .find(|(name, _)| *name == producer)
                    .map(|(_, latch)| latch.clone())
            });
            Box::new(move |job: ScanJob| {
                Box::pin(run_registered_scan(row, job, ScanLatches { publish, wait }))
            })
        })
        .collect()
}

impl TranslationPipeline {
    // =========================================================
    // Batch translation
    // =========================================================

    /// Open the batch's shared read cache over Kuna for `binary` (issue #105).
    ///
    /// Both batch entry points call this at their start. With a workspace and a
    /// `binary_path` set, it builds one [`CachedScanSource`] for the target
    /// binary — the binary's file bytes are hashed once — and every later read
    /// made through [`scan_source`](Self::scan_source) then tries the memo, then
    /// the disk tier, then the engine, saving what it reads as it goes.
    ///
    /// It degrades instead of failing: with no workspace or binary path the batch
    /// reads straight from the engine, exactly as before the cache existed, and an
    /// unreadable binary file also leaves the cache in pass-through mode, so the
    /// batch runs on either way.
    pub(super) async fn begin_cached_source(&self, binary: &str) {
        let (Some(workspace), Some(binary_path)) =
            (self.workspace.as_deref(), self.binary_path.as_deref())
        else {
            // No cache to open: the batch's reads go to the live engine, so
            // its declaration is the one the prompts hold (issue #355) —
            // fetched once, right here, beside this decision.
            *self
                .seam_report
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = self.kuna.capability_report();
            return;
        };

        let opened = if self.refresh_cache {
            CachedScanSource::new_refresh(self.kuna.clone(), workspace, binary, binary_path)
        } else {
            CachedScanSource::new(self.kuna.clone(), workspace, binary, binary_path)
        };
        match opened {
            Ok(source) => {
                debug!(
                    binary,
                    refresh = self.refresh_cache,
                    cache_dir = source
                        .cache_dir()
                        .map_or_else(|| "(memo only)".to_string(), |d| d.display().to_string()),
                    "Batch engine reads will go through the shared cache"
                );
                // The declaration travels with the source it describes: it is
                // fetched right here, as the source opens, and reading a
                // capability costs no extra engine read (issue #355). Every
                // later prompt reads this stored copy.
                *self
                    .seam_report
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) =
                    source.capability_report();
                *self
                    .cached_source
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(source);
            }
            Err(e) => {
                warn!(
                    binary,
                    error = %e,
                    "Could not open the batch read cache — reads will pass through to the engine"
                );
                // Same rule on the fallback path: the declaration belongs to
                // whichever source the batch's reads go through.
                *self
                    .seam_report
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) =
                    self.kuna.capability_report();
            }
        }
    }

    /// The stored capability declaration (issue #355): fetched once by
    /// [`begin_cached_source`](Self::begin_cached_source), and read by the
    /// escalate step of the retry loop for every fix prompt in the batch.
    pub(crate) fn seam_report(&self) -> calxgloss_types::CapabilityReport {
        self.seam_report
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// The source that every batch user — the [`ScanJob`]s the fifteen
    /// registered scans build, the call-graph build, and the
    /// retry/escalation helpers — reads program facts from: the batch's
    /// [`CachedScanSource`] once
    /// [`begin_cached_source`](Self::begin_cached_source) has opened it, and
    /// the loaded Kuna program otherwise.
    pub(super) fn scan_source(&self) -> PipelineSource {
        let guard = self
            .cached_source
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match guard.as_ref() {
            Some(cache) => PipelineSource::Cached(cache.clone()),
            None => PipelineSource::Kuna(self.kuna.clone()),
        }
    }

    /// Start the analysis engine's progress reporting for one pass, so the
    /// dashboard can show which function the pass is on. Without an event
    /// channel there is nothing to report to — the scan runs unchanged.
    pub(super) fn begin_scan_pass(&self, binary: &str, pass: &str) {
        if let Some(ref ev) = self.events {
            self.kuna.begin_pass(binary, pass, ev);
        }
    }

    /// Stop the engine's progress reporting — the pass is finished.
    pub(super) fn end_scan_pass(&self) {
        self.kuna.end_pass();
    }

    /// Build the owned handle that one evidence scan runs as (issue #237):
    /// copies of everything the scan reads — the workspace, the batch's
    /// shared read source as it stands now — so the scan borrows nothing
    /// from the batch and a caller can move the job onto a task. `None`
    /// when no workspace is configured, which is every scan's skip
    /// condition. The pass's progress reporting belongs to the phase, not
    /// to the job (issue #239), and the scan phase's ordering lives on the
    /// registry's rows, not on the job (issue #305).
    pub(super) fn scan_job(&self, binary: &str) -> Option<ScanJob> {
        let workspace = self.workspace.as_deref()?;
        Some(ScanJob::new(binary, workspace, self.scan_source()))
    }

    /// Run the fifteen pre-batch evidence scans: the shared scan phase that
    /// both batch entry points call — the function-list path
    /// ([`batch_translate`](Self::batch_translate)) and the call-graph path
    /// ([`batch_translate_from_callgraph`](Self::batch_translate_from_callgraph))
    /// — so neither keeps its own copy of the sequence and the CLI and web
    /// paths cannot drift apart (issue #234).
    ///
    /// The scans run concurrently on a [`JoinSet`], at most
    /// [`MAX_CONCURRENT_EVIDENCE_SCANS`] at a time, each on its own owned
    /// [`ScanJob`] (issues #237, #240): the engine thread is handed the next
    /// body as soon as it frees the last one, so parse work overlaps engine
    /// work, and a cold scan phase costs about the engine's own decompile
    /// time rather than that plus every scan's parse time. Scans enter the
    /// window in [`scan_rows`] order, but that is the order they enter, not
    /// the order they finish. Each body is decompiled exactly once by
    /// construction, with no new locking: the read cache's per-key cell turns
    /// concurrent requests for one body into a single engine request, so the
    /// engine stays the serial resource that the scans share safely.
    ///
    /// Each scan keeps its own shape: a cached-hit short-circuit ends it
    /// before any engine read, and a failed scan or save only warns and
    /// continues, so one detector's failure never takes down the batch. The
    /// group joins all fifteen and never cancels its siblings.
    ///
    /// The one real ordering edge between the scans — callback detection
    /// building its closure contracts from the type-inference document — is
    /// a declared row dependency: the phase arms a fresh completion latch for
    /// each declared producer ([`arm_completion_latches`]), the inference row
    /// publishes its latch on every exit, and the callback row waits on it,
    /// so the edge is explicit table data rather than a call order (issues
    /// #238, #305).
    ///
    /// The phase also starts the engine's progress reporting once for the
    /// whole group, under the phase name, and stops it when the group ends:
    /// the dashboard shows one honest "n of m functions consumed" row for the
    /// scan phase instead of fifteen rows that restart with each scan. The
    /// counts are of unique functions consumed — a body pulled cold from the
    /// engine and replayed warm by the read cache counts once — so a warm run
    /// still shows life, and the row stays honest while the scans interleave
    /// (issue #239, preserving #121). The phase skips itself when there is no
    /// workspace to file its documents under.
    pub(super) async fn run_prebatch_scans(&self, binary: &str) {
        self.begin_scan_pass(binary, SCAN_PHASE);
        let Some(job) = self.scan_job(binary) else {
            debug!(
                binary,
                "No workspace configured; skipping the pre-batch evidence scans"
            );
            self.end_scan_pass();
            return;
        };
        let mut scans = registered_scan_tasks().into_iter();
        let mut set = JoinSet::new();
        self.scan_window_high_water.store(0, Ordering::SeqCst);
        let in_flight = Arc::new(AtomicUsize::new(0));
        let high_water = Arc::clone(&self.scan_window_high_water);
        for scan in scans.by_ref().take(MAX_CONCURRENT_EVIDENCE_SCANS) {
            set.spawn(run_scan_in_window(
                scan,
                job.clone(),
                Arc::clone(&in_flight),
                Arc::clone(&high_water),
            ));
        }
        // Sliding window: every completion frees a slot for the next scan,
        // and the group joins all fifteen — a failing or panicking scan
        // never cancels its siblings (issue #240).
        while let Some(outcome) = set.join_next().await {
            if let Err(e) = outcome {
                warn!(
                    binary,
                    error = %e,
                    "An evidence scan task did not complete; continuing without its context"
                );
            }
            if let Some(scan) = scans.next() {
                set.spawn(run_scan_in_window(
                    scan,
                    job.clone(),
                    Arc::clone(&in_flight),
                    Arc::clone(&high_water),
                ));
            }
        }
        self.end_scan_pass();

        // P18's version-change trigger (issue #298): the scan step has just
        // written this version's scan documents. Compare this scan against
        // any surviving scan of the same identity — the sibling hash
        // directories under `re/cache/{identity}/` — exactly once per
        // (old, new) hash pair; a later run reuses the saved document.
        // Documents only: no engine reads (ADR-0026), no LLM, milliseconds.
        // With no sibling directory it writes nothing, leaving the queue's
        // behavior exactly as it is today.
        if let (Some(workspace), Some(binary_path)) =
            (self.workspace.as_deref(), self.binary_path.as_deref())
        {
            crate::version_pairing::pair_previous_versions(workspace, binary, binary_path);
        }
    }

    /// The most evidence scans that ran at the same time during the latest
    /// scan phase (issue #241) — the fan-out window's high-water mark,
    /// recorded by `run_scan_in_window` as each scan enters the window. Zero
    /// when no phase has run, or when it skipped for want of a workspace.
    pub fn scan_window_high_water(&self) -> usize {
        self.scan_window_high_water.load(Ordering::SeqCst)
    }
}
