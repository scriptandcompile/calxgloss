//! The live store holds the records the `calxgloss live` view shows
//! (issue #452). The store updates them as each `ProgressEvent` arrives
//! through [`ProgressState::apply`], and hands out the shared live
//! records — the [`calxgloss_types`] records the live view, the queue
//! rows, and the WebSocket push already serve. Handlers receive those
//! finished records and project nothing themselves.
//!
//! The store keeps a record for each unit being translated and for
//! the evidence scans of the pass in flight. It also keeps the run's
//! per-binary readings: classification results, batch summaries, the
//! processing binary, the queue plan, the heartbeat, and the ingestion
//! state. Every reading is guarded by one lock, so a snapshot names
//! one pass's state throughout — no field of a payload can come from a
//! different pass than the rest of it. A running scan's or unit's
//! elapsed measurement is taken when the snapshot is served, so the
//! live view's ticking clocks keep working.
//!
//! The per-unit entry and the scan row are private to this module.
//! Nothing outside the store keeps a second shape for a live unit.

use super::{BatchInfo, ClassificationInfo};
use calxgloss_types::{
    BinaryActivity, BinaryIdentity, LiveScanProgress, LiveTranslationState, LiveUnitProgress,
    PassStatus, PhaseRecord, ProgressEvent, TranslationPhase, UnitKey, derive_unit_confidence,
};
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use tokio::sync::RwLock;

/// A single DLL classification result, tracked during live translation.
#[derive(Debug)]
struct ClassificationResult {
    binary: BinaryIdentity,
    category: String,
    classification_strategy: String,
    crate_replacement: Option<String>,
    exported_symbols: usize,
    imported_symbols: usize,
}

/// Batch summary for a DLL after all functions are translated.
#[derive(Debug)]
struct BatchResult {
    binary: BinaryIdentity,
    total_functions: usize,
    success_count: usize,
    failure_count: usize,
    total_attempts: usize,
    total_tokens: usize,
}

/// One registered evidence scan as the store holds it (issue #428). A
/// running record has `elapsed_secs: None`, and the snapshot measures
/// its elapsed time from `started_at` when the payload is served. A
/// finished record keeps the run's wall-clock seconds, and keeps the
/// row's finding count only when the evidence engine reported a single
/// one.
///
/// `error` carries the failure's own words from the completed event: a
/// failed scan is finished with its error set and its finding count left
/// unknown, so a failure never reads as a completed scan with zero
/// findings (issue #429).
#[derive(Debug, Clone)]
struct ScanRow {
    /// The registry row's name.
    scan: String,
    /// The binary whose scan pass this record belongs to.
    binary: BinaryIdentity,
    /// When the started event landed — the running clock's anchor.
    started_at: std::time::Instant,
    /// Whether the completed event has landed.
    finished: bool,
    /// The completed event's wall-clock seconds; `None` while running.
    elapsed_secs: Option<f64>,
    /// The count the evidence engine reported; `None` means the row
    /// files no single count, never a zero.
    findings: Option<usize>,
    /// The completed event's error words; `None` when the scan did not
    /// fail.
    error: Option<String>,
}

/// Startup ingestion state (issue #124): whether startup ingestion has
/// begun and which binaries' analysis has landed. Its producers were
/// retired (issue #214), so it stays empty; the pipeline view still
/// derives this phase from classification counts.
#[derive(Debug, Default, Clone)]
pub struct IngestionState {
    pub started: bool,
    pub analyzed: Vec<BinaryIdentity>,
}

/// The store's per-unit record. It keeps the time anchors the shared
/// record needs — when the unit started and when its last event landed —
/// so the elapsed clock is measured at each snapshot rather than frozen
/// into an event.
#[derive(Debug, Clone)]
struct ProgressEntry {
    binary: BinaryIdentity,
    function: String,
    attempt: u32,
    /// Retry strategy the current LLM-call attempt used — Pipeline's word,
    /// never a batch outcome (issue #363). See [`outcome`](Self::outcome).
    retry_strategy: String,
    /// The outcome the batch recorded for this finished unit — `"batch_ok"`,
    /// `"batch_failed"` or `"cancelled"`. It is a separate field from the
    /// retry strategy, so the two names never take on each other's meaning.
    outcome: Option<String>,
    started_at: std::time::Instant,
    /// The pipeline step this unit is currently in, derived from the latest
    /// phase-bearing `ProgressEvent`.
    phase: TranslationPhase,
    /// Phases entered, in event order (the first entry is the starting phase).
    /// Re-entering a phase (e.g. `ContextTier` on tier escalation) appends a
    /// new entry, so the retry history stays visible.
    phase_history: Vec<PhaseRecord>,
    /// Set once a terminal event (completed / failed / function-completed)
    /// has been observed for this unit.
    finished: bool,
    /// Whether the unit's translation ultimately succeeded — `None` until a
    /// terminal event (`TranslationCompleted` / `TranslationFailed` /
    /// `FunctionCompleted`) says so, so an unfinished unit never looks failed.
    succeeded: Option<bool>,
    /// Context tier the current attempt runs at — `None` until a
    /// `ContextTierSelected` event records one (re-emitted on tier escalation).
    context_tier: Option<String>,
    /// Human-readable tier label from the same event.
    tier_label: Option<String>,
    /// Baseline tests that passed in the latest verified attempt — `None` until
    /// a `TranslationAttemptCompleted` reports a run.
    baseline_tests_passed: Option<usize>,
    /// Baseline tests for the unit — from `TestsGenerated`, then from the
    /// verified attempt's own count, whichever landed last.
    baseline_tests_total: Option<usize>,
    /// Edge-case (verification) tests that passed — `None` until the
    /// behavior-divergence detector runs them.
    verification_tests_passed: Option<usize>,
    /// Edge-case (verification) tests the detector ran.
    verification_tests_total: Option<usize>,
    /// Whether the latest verified attempt compiled — `None` until an attempt
    /// has been verified.
    compiled: Option<bool>,
    last_event_at: std::time::Instant,
}

/// The store keeps all of this behind one lock, so every read sees one
/// consistent pass.
#[derive(Debug, Default)]
struct StoreData {
    /// Map of unit key (`{binary}/{function}`) → current progress info for a
    /// live translation.
    entries: HashMap<String, ProgressEntry>,
    /// Classification results keyed by binary identity.
    classifications: HashMap<BinaryIdentity, ClassificationResult>,
    /// Batch summary results keyed by binary identity.
    batch_summaries: HashMap<BinaryIdentity, BatchResult>,
    /// The DLL whose batch pass is currently in flight — set by
    /// `BatchStarted`, cleared by that DLL's `BatchSummary`. The live loop
    /// works one binary at a time, so one slot is enough; a new
    /// `BatchStarted` replaces the old value if a pass ended without a
    /// summary (an error path).
    processing: Option<BinaryIdentity>,
    /// The run's ordered plan — `QueuePlanned` records the binaries the
    /// live loop will process, in that order. Empty until a plan lands;
    /// a later plan replaces the earlier one.
    queue: Vec<String>,
    /// The working pass's latest heartbeat — `(binary, activity)`. Set by
    /// `BatchProgress`, cleared when a new `BatchStarted` replaces the
    /// pass or that DLL's `BatchSummary` lands.
    activity: Option<(BinaryIdentity, BinaryActivity)>,
    /// Startup ingestion state (issue #124). The Ghidra preflight events
    /// that used to set it were retired along with the Ghidra analysis
    /// engine (issue #214), so this stays empty and the pipeline view
    /// derives `project_ingestion` from classification counts alone.
    ingestion: IngestionState,
    /// The pre-batch evidence scans of the binary whose pass is in flight,
    /// keyed by scan name so the latest event for a name wins
    /// (issue #428). The map holds one binary at a time: the first scan
    /// event for a different binary, or a `BatchStarted` naming one,
    /// clears the previous binary's rows — they no longer describe the
    /// live pass.
    scans: BTreeMap<String, ScanRow>,
}

/// One whole answer from the store, taken under a single lock
/// (issue #455). A handler serving the pipeline payload or a read of the
/// run's binary names takes one of these per request. The store copies
/// every field at the same moment, so no field the handler serves can
/// name a different pass than the rest.
#[derive(Debug)]
pub struct StoreReading {
    /// The shared record for every tracked unit, keyed by unit key
    /// (`{binary}/{function}`) — as [`ProgressState::snapshot`] hands them out.
    pub units: HashMap<String, LiveUnitProgress>,
    /// The shared scan records of the binary whose pass is in flight,
    /// in scan-name order (issue #428).
    pub scans: Vec<LiveScanProgress>,
    /// The run's classification results, one per classified binary.
    pub classifications: Vec<ClassificationInfo>,
    /// The batch summaries filed for passes that have ended.
    pub batch_summaries: Vec<BatchInfo>,
    /// The binary whose batch pass is currently in flight, if any.
    pub processing: Option<BinaryIdentity>,
    /// The run's ordered queue plan — empty until a plan lands.
    pub queue: Vec<String>,
    /// The working pass's latest heartbeat — `(binary, activity)`.
    pub activity: Option<(BinaryIdentity, BinaryActivity)>,
    /// Startup ingestion state (issue #124).
    pub ingestion: IngestionState,
}

/// Tracks translation units currently in progress.
///
/// Created when `handle_live` starts the server with an event channel,
/// updated by [`apply`](Self::apply) for each `ProgressEvent`, and served
/// by the live-view endpoints as the shared live records.
#[derive(Debug, Clone, Default)]
pub struct ProgressState {
    state: Arc<RwLock<StoreData>>,
}

impl ProgressState {
    pub fn new() -> Self {
        Self {
            state: Arc::new(RwLock::new(StoreData::default())),
        }
    }

    /// Apply one translation progress event to the store.
    pub async fn apply(&self, event: &ProgressEvent) {
        let mut data = self.state.write().await;
        match event {
            ProgressEvent::TranslationStarted { .. }
            | ProgressEvent::ScanFetchComplete { .. }
            | ProgressEvent::ApiTaggingComplete { .. }
            | ProgressEvent::TestsGenerated { .. }
            | ProgressEvent::ContextTierSelected { .. }
            | ProgressEvent::LlmCallStart { .. }
            | ProgressEvent::LlmCallComplete { .. }
            | ProgressEvent::LlmCallFailed { .. }
            | ProgressEvent::LlmCallInProgress { .. }
            | ProgressEvent::LlmRequest { .. }
            | ProgressEvent::LlmResponse { .. }
            | ProgressEvent::TranslationAttemptCompleted { .. }
            | ProgressEvent::TranslationCompleted { .. }
            | ProgressEvent::TranslationFailed { .. }
            | ProgressEvent::FunctionCompleted { .. }
            | ProgressEvent::HallucinationDetected { .. }
            | ProgressEvent::InfiniteLoopDetected { .. }
            | ProgressEvent::BehaviorDivergenceDetected { .. }
            | ProgressEvent::ResourceExhaustionDetected { .. }
            | ProgressEvent::UnitCancelled { .. } => {
                apply_translation_event(&mut data, event);
            }
            ProgressEvent::ClassificationComplete {
                binary,
                category,
                classification_strategy,
                crate_replacement,
                exported_symbols,
                imported_symbols,
            } => {
                data.classifications.insert(
                    binary.clone(),
                    ClassificationResult {
                        binary: binary.clone(),
                        category: category.clone(),
                        classification_strategy: classification_strategy.clone(),
                        crate_replacement: crate_replacement.clone(),
                        exported_symbols: *exported_symbols,
                        imported_symbols: *imported_symbols,
                    },
                );
            }
            ProgressEvent::BatchStarted { binary } => {
                // The live loop works one binary at a time; the newest
                // started pass is the one in flight. Any heartbeat from the
                // previous pass is stale the moment a new one begins.
                data.processing = Some(binary.clone());
                data.activity = None;
                // The same rule for the scan panel (issue #428): records
                // belong to the binary whose pass they witnessed. Another
                // pass over the same binary keeps them until that row's
                // next started event replaces the record. A pass for a
                // different binary retires the previous binary's rows.
                if data.scans.values().any(|record| record.binary != *binary) {
                    data.scans.clear();
                }
            }
            ProgressEvent::QueuePlanned { binaries } => {
                // The plan is the run's intent, replaced wholesale if a
                // later run plans differently.
                data.queue = binaries.clone();
            }
            ProgressEvent::BatchProgress {
                binary,
                pass,
                function,
                index,
                total,
            } => {
                // The latest heartbeat wins: it records the live position,
                // not a history log. Position fields that are not known
                // stay `None`.
                let activity = BinaryActivity {
                    pass: pass.clone(),
                    function: (!function.is_empty()).then(|| function.clone()),
                    index: (*index > 0).then_some(*index),
                    total: (*total > 0).then_some(*total),
                };
                data.activity = Some((binary.clone(), activity));
            }
            ProgressEvent::BatchSummary {
                binary,
                total_functions,
                success_count,
                failure_count,
                total_attempts,
                total_tokens,
            } => {
                data.batch_summaries.insert(
                    binary.clone(),
                    BatchResult {
                        binary: binary.clone(),
                        total_functions: *total_functions,
                        success_count: *success_count,
                        failure_count: *failure_count,
                        total_attempts: *total_attempts,
                        total_tokens: *total_tokens,
                    },
                );
                // The pass in flight is done — no binary is being worked on.
                if data.processing.as_deref() == Some(binary.as_str()) {
                    data.processing = None;
                }
                if data.activity.as_ref().is_some_and(|(d, _)| d == binary) {
                    data.activity = None;
                }
            }
            ProgressEvent::EvidenceScanStarted { binary, scan } => {
                // The scan traffic itself also marks the pass boundary:
                // the live pipeline emits no `BatchStarted`, so the first
                // scan event naming a new binary retires the previous
                // binary's rows (issue #428).
                if data.scans.values().any(|record| record.binary != *binary) {
                    data.scans.clear();
                }
                // A re-run pass over the same binary replaces the row's
                // old record the moment its new pass starts.
                data.scans.insert(
                    scan.clone(),
                    ScanRow {
                        scan: scan.clone(),
                        binary: binary.clone(),
                        started_at: std::time::Instant::now(),
                        finished: false,
                        elapsed_secs: None,
                        findings: None,
                        error: None,
                    },
                );
            }
            ProgressEvent::EvidenceScanCompleted {
                binary,
                scan,
                elapsed_secs,
                findings,
                error,
            } => {
                if data.scans.values().any(|record| record.binary != *binary) {
                    data.scans.clear();
                }
                // The phase emits the started event before this one, so a
                // running record is normally already here. A completed
                // with no running record for the current binary is a
                // dropped event, and an incomplete story stays out of the
                // panel rather than inventing one row.
                if let Some(record) = data.scans.get_mut(scan)
                    && record.binary == *binary
                {
                    record.finished = true;
                    record.elapsed_secs = Some(*elapsed_secs);
                    record.findings = *findings;
                    // The completed event's error words mark the row
                    // failed, its finding count left unknown — the panel
                    // must never read the missing count as zero
                    // (issue #429).
                    record.error = error.clone();
                }
            }
            ProgressEvent::PipelineStateChanged { .. } => {
                // Run-level lifecycle change (issue #90). ProgressState
                // tracks per-unit and per-binary state, not the run's own
                // state — the control handle is the source of truth, read
                // by `/api/server/status` and echoed to WS clients by the
                // broadcast. There is nothing to add to the per-unit view.
            }
            ProgressEvent::BinaryPauseChanged { .. } => {
                // Per-binary pause (issue #221). ProgressState does not
                // mirror the paused set — the scope handle is the source of
                // truth, and `GET /api/pipeline` fills each row's `paused`
                // flag from it. WS clients get the raw event from the
                // broadcast and re-render the row. There is nothing to add
                // here.
            }
        }
    }

    /// The live view's whole reading as one atomic snapshot: the shared
    /// per-unit records sorted by binary and function, the shared scan
    /// rows in scan-name order, the counts, and the working pass's
    /// heartbeat (issue #452). A running unit's or scan's elapsed
    /// measurement is taken now, so the live view's clocks tick between
    /// snapshots.
    pub async fn view(&self) -> LiveTranslationState {
        let data = self.state.read().await;
        let mut units: Vec<LiveUnitProgress> =
            data.entries.values().map(shared_unit_record).collect();
        sort_unit_rows(&mut units);

        // The scan rows of the binary whose pass is in flight (issue #428),
        // in scan-name order — already stable from the store's keyed map.
        let scans = data.scans.values().map(shared_scan_record).collect();

        // The working pass's latest heartbeat, beside the scan rows (issue
        // #430): pass name, the function Kuna is on, and its position in the
        // pass's work list. The store clears the record at every pass
        // boundary, so it never outlives the pass it describes.
        let activity = data.activity.clone().map(|(_binary, heartbeat)| heartbeat);

        let count = units.len();
        let in_flight = units.iter().filter(|u| !u.finished).count();
        LiveTranslationState {
            units,
            count,
            in_flight,
            scans,
            activity,
        }
    }

    /// The shared scan records of the binary whose pass is in flight, in
    /// scan-name order — the live view's stable row order (issue #428).
    /// Test-only: the store's honesty-rule tests read it (issue #453);
    /// handlers take the whole reading instead (issue #455).
    #[cfg(test)]
    async fn scan_view(&self) -> Vec<LiveScanProgress> {
        self.state
            .read()
            .await
            .scans
            .values()
            .map(shared_scan_record)
            .collect()
    }

    /// The shared record for every tracked unit, keyed by unit key
    /// (`{binary}/{function}`). Handlers merge these readings beside
    /// persisted rows. The per-unit entry itself stays private.
    pub async fn snapshot(&self) -> HashMap<String, LiveUnitProgress> {
        let data = self.state.read().await;
        data.entries
            .iter()
            .map(|(key, entry)| (key.clone(), shared_unit_record(entry)))
            .collect()
    }

    /// Read the whole store once (issue #455). A handler serving the
    /// pipeline payload or a read of the run's binary names calls this one
    /// time per request. The store copies every field of the
    /// [`StoreReading`] under a single lock acquisition, so a field from
    /// one pass cannot be stitched onto rows from another. A running
    /// unit's or scan's elapsed measurement is taken now, as in
    /// [`view`](Self::view).
    pub async fn full_read(&self) -> StoreReading {
        let data = self.state.read().await;
        StoreReading {
            units: data
                .entries
                .iter()
                .map(|(key, entry)| (key.clone(), shared_unit_record(entry)))
                .collect(),
            scans: data.scans.values().map(shared_scan_record).collect(),
            classifications: data
                .classifications
                .values()
                .map(classification_record)
                .collect(),
            batch_summaries: data.batch_summaries.values().map(batch_record).collect(),
            processing: data.processing.clone(),
            queue: data.queue.clone(),
            activity: data.activity.clone(),
            ingestion: data.ingestion.clone(),
        }
    }

    /// The current shared record for one unit, keyed by binary and
    /// function name. The event pump reads it to push the applied unit's
    /// record over the WebSocket.
    pub async fn entry(&self, binary: &str, function: &str) -> Option<LiveUnitProgress> {
        let key = UnitKey::new(&BinaryIdentity::from(binary), function).to_string();
        self.state
            .read()
            .await
            .entries
            .get(&key)
            .map(shared_unit_record)
    }

    /// The binary whose batch pass is currently in flight, if any —
    /// `BatchStarted` records it, and that binary's `BatchSummary` clears it.
    /// Test-only: the store's honesty-rule tests read it (issue #453);
    /// handlers take the whole reading instead (issue #455).
    #[cfg(test)]
    async fn processing_binary(&self) -> Option<BinaryIdentity> {
        self.state.read().await.processing.clone()
    }

    /// The run's ordered queue plan — the binaries the live loop will
    /// process, in that order. Empty when no plan has been announced.
    /// Test-only: the store's honesty-rule tests read it (issue #453);
    /// handlers take the whole reading instead (issue #455).
    #[cfg(test)]
    async fn queue(&self) -> Vec<String> {
        self.state.read().await.queue.clone()
    }

    /// The working pass's latest heartbeat — `(binary, activity)`, `None`
    /// while no pass is running to report one.
    /// Test-only: the store's honesty-rule tests read it (issue #453);
    /// handlers take the whole reading instead (issue #455).
    #[cfg(test)]
    async fn activity(&self) -> Option<(BinaryIdentity, BinaryActivity)> {
        self.state.read().await.activity.clone()
    }

    /// Returns the number of currently in-flight units.
    /// Test-only: the store's honesty-rule tests read it (issue #453).
    #[cfg(test)]
    async fn len(&self) -> usize {
        self.state.read().await.entries.len()
    }

    /// Returns the number of units still in flight (not yet finished).
    ///
    /// Finished units stay in the map for the dashboard's benefit, so the
    /// server status endpoint counts only the unfinished ones.
    pub async fn in_flight_count(&self) -> usize {
        self.state
            .read()
            .await
            .entries
            .values()
            .filter(|entry| !entry.finished)
            .count()
    }

    /// Returns whether there are any currently in-flight units.
    /// Test-only: the store's honesty-rule tests read it (issue #453).
    #[cfg(test)]
    async fn is_empty(&self) -> bool {
        self.state.read().await.entries.is_empty()
    }
}

/// Update the per-unit records from a unit-scoped event. Batch-level
/// events (ClassificationComplete, BatchSummary) are handled in `apply`
/// and never reach here.
fn apply_translation_event(data: &mut StoreData, event: &ProgressEvent) {
    // Unit-scoped events include the binary/function pair that identifies
    // the unit.
    let Some(unit) = event.unit_key() else {
        return;
    };
    let key = unit.to_string();

    // The unit's record begins with the first event that identifies it.
    // That is normally `TranslationStarted`, but the store never assumes
    // which event names a unit first — whichever one lands opens the
    // record. Dropping that first event (as `get_mut` did) loses real
    // evidence, so create the record instead. `TranslationStarted` then
    // finds the record already there and never overwrites it.
    let entry = data.entries.entry(key).or_insert_with(|| {
        // A started unit begins in the phase its first event derives.
        // `TranslationStarted` always derives ScanFetch (unit-tested);
        // fall back to it rather than panic if that ever changes.
        let phase = TranslationPhase::from_event(event).unwrap_or(TranslationPhase::ScanFetch);
        ProgressEntry {
            binary: unit.binary().clone(),
            function: unit.function().to_string(),
            attempt: 1,
            retry_strategy: String::new(),
            outcome: None,
            started_at: std::time::Instant::now(),
            phase,
            phase_history: vec![PhaseRecord {
                phase,
                elapsed_secs: 0.0,
            }],
            finished: false,
            succeeded: None,
            context_tier: None,
            tier_label: None,
            baseline_tests_passed: None,
            baseline_tests_total: None,
            verification_tests_passed: None,
            verification_tests_total: None,
            compiled: None,
            last_event_at: std::time::Instant::now(),
        }
    });

    entry.last_event_at = std::time::Instant::now();

    // Record the phase the event moves the unit into; re-entering the
    // same phase (e.g. a second LLM call without tier escalation) is
    // not a transition, but a re-derived *different* phase (e.g.
    // ContextTier on tier escalation) appends to the history.
    if let Some(phase) = TranslationPhase::from_event(event) {
        if phase != entry.phase {
            entry.phase_history.push(PhaseRecord {
                phase,
                elapsed_secs: entry.started_at.elapsed().as_secs_f64(),
            });
        }
        entry.phase = phase;
    }

    match event {
        ProgressEvent::LlmCallStart {
            attempt,
            retry_strategy,
            ..
        } => {
            entry.attempt = *attempt;
            entry.retry_strategy = retry_strategy.clone();
        }
        // The tier the current attempt runs at; re-emitted on tier
        // escalation, so the latest one wins.
        ProgressEvent::ContextTierSelected {
            tier, tier_label, ..
        } => {
            entry.context_tier = Some(tier.clone());
            entry.tier_label = Some(tier_label.clone());
        }
        // Baseline tests exist once they are generated; the verified
        // attempt then reports how many of them passed.
        ProgressEvent::TestsGenerated { test_count, .. } => {
            entry.baseline_tests_total = Some(*test_count);
        }
        ProgressEvent::TranslationAttemptCompleted {
            compiled,
            tests_passed,
            tests_total,
            ..
        } => {
            entry.compiled = Some(*compiled);
            entry.baseline_tests_passed = Some(*tests_passed);
            entry.baseline_tests_total = Some(*tests_total);
        }
        // The behavior-divergence detector re-runs the baseline plus
        // generated edge-case tests; its counts are the only live
        // source for the verification class.
        ProgressEvent::BehaviorDivergenceDetected {
            baseline_passed,
            baseline_total,
            edge_tests_passed,
            edge_tests_total,
            ..
        } => {
            entry.baseline_tests_passed = Some(*baseline_passed);
            entry.baseline_tests_total = Some(*baseline_total);
            entry.verification_tests_passed = Some(*edge_tests_passed);
            entry.verification_tests_total = Some(*edge_tests_total);
        }
        ProgressEvent::TranslationCompleted { .. } => {
            entry.finished = true;
            entry.succeeded = Some(true);
        }
        ProgressEvent::TranslationFailed { .. } => {
            entry.finished = true;
            entry.succeeded = Some(false);
        }
        ProgressEvent::FunctionCompleted { success, .. } => {
            // Batch-level completion marks the unit as done. The
            // outcome field records the result for the dashboard,
            // while retry_strategy still records the last attempt
            // that ran (issue #363).
            entry.finished = true;
            entry.succeeded = Some(*success);
            entry.outcome = Some(if *success {
                "batch_ok".to_string()
            } else {
                "batch_failed".to_string()
            });
        }
        ProgressEvent::UnitCancelled { .. } => {
            // The operator cancelled the in-flight unit (issue #91):
            // terminal and failed like any other unfinished attempt,
            // but the outcome field records why — the dashboard can
            // tell a cancelled unit from one that simply failed.
            entry.finished = true;
            entry.succeeded = Some(false);
            entry.outcome = Some("cancelled".to_string());
        }
        _ => {}
    }
}

/// The order every live unit row is served in: by binary identity, then
/// function name, so rows do not shuffle between refreshes. The enhanced
/// payload and the `/api/progress` rows both use it.
pub(crate) fn sort_unit_rows(rows: &mut [LiveUnitProgress]) {
    rows.sort_by(|a, b| {
        a.binary
            .cmp(&b.binary)
            .then_with(|| a.function.cmp(&b.function))
    });
}

/// Project one [`ProgressEntry`] into the shared [`LiveUnitProgress`]
/// record the live view consumes.
///
/// The live view's endpoints, the queue rows, and the WebSocket
/// `unit_phase` push all take this one finished record, so every surface
/// reports the unit the same way. Unmeasured test classes stay
/// [`PassState::NotRun`](calxgloss_types::PassState::NotRun), an unnamed
/// retry strategy is `None` rather than a blank, and confidence is
/// derived from evidence rather than guessed. The elapsed measurement is
/// taken now, at the snapshot, so a running unit's clock ticks.
fn shared_unit_record(e: &ProgressEntry) -> LiveUnitProgress {
    let elapsed = e.started_at.elapsed().as_secs_f64();
    let baseline =
        PassStatus::from_optional_counts(e.baseline_tests_passed, e.baseline_tests_total);
    let verification =
        PassStatus::from_optional_counts(e.verification_tests_passed, e.verification_tests_total);
    LiveUnitProgress {
        binary: e.binary.clone(),
        function: e.function.clone(),
        phase: e.phase,
        phase_history: e.phase_history.clone(),
        elapsed_secs: (elapsed * 1000.0).round() / 1000.0,
        attempt: e.attempt,
        // An entry starts with an empty retry strategy; none named yet
        // means none to report, not a blank one.
        retry_strategy: (!e.retry_strategy.is_empty()).then(|| e.retry_strategy.clone()),
        context_tier: e.context_tier.clone(),
        tier_label: e.tier_label.clone(),
        baseline: baseline.clone(),
        verification,
        compiled: e.compiled,
        unit_confidence: derive_unit_confidence(e.compiled, &baseline),
        finished: e.finished,
        succeeded: e.succeeded,
        outcome: e.outcome.clone(),
    }
}

/// Project one [`ScanRow`] into the shared [`LiveScanProgress`] the live
/// view consumes (issue #428). A running scan's elapsed is measured now,
/// at the snapshot, from its own start. A finished scan reports the
/// seconds recorded by its completed event. A scan that filed no single
/// count keeps `findings` as `None`, and the payload then carries no
/// count. A failed scan keeps its error words beside that unknown count
/// (issue #429).
fn shared_scan_record(r: &ScanRow) -> LiveScanProgress {
    let elapsed = match r.elapsed_secs {
        Some(secs) => secs,
        None => r.started_at.elapsed().as_secs_f64(),
    };
    LiveScanProgress {
        scan: r.scan.clone(),
        binary: r.binary.clone(),
        finished: r.finished,
        elapsed_secs: (elapsed * 1000.0).round() / 1000.0,
        findings: r.findings,
        error: r.error.clone(),
    }
}

/// The shared classification record for one stored result — the shape
/// `/api/pipeline` renders, projected the one way the store reports it.
fn classification_record(v: &ClassificationResult) -> ClassificationInfo {
    ClassificationInfo {
        binary: v.binary.clone(),
        category: v.category.clone(),
        classification_strategy: v.classification_strategy.clone(),
        crate_replacement: v.crate_replacement.clone(),
        exported_symbols: v.exported_symbols,
        imported_symbols: v.imported_symbols,
    }
}

/// The shared batch-summary record for one stored result.
fn batch_record(v: &BatchResult) -> BatchInfo {
    BatchInfo {
        binary: v.binary.clone(),
        total_functions: v.total_functions,
        success_count: v.success_count,
        failure_count: v.failure_count,
        total_attempts: v.total_attempts,
        total_tokens: v.total_tokens,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // These tests pin down what ADR-0061 decided the store must report
    // (issue #453). Each test feeds progress events through `apply` and
    // asserts on the records the store hands back. No router, no port, no
    // sleeps, no store internals — only the public interface above.

    fn scan_started(binary: &str, scan: &str) -> ProgressEvent {
        ProgressEvent::EvidenceScanStarted {
            binary: binary.into(),
            scan: scan.to_string(),
        }
    }

    fn scan_completed(
        binary: &str,
        scan: &str,
        findings: Option<usize>,
        error: Option<&str>,
    ) -> ProgressEvent {
        ProgressEvent::EvidenceScanCompleted {
            binary: binary.into(),
            scan: scan.to_string(),
            elapsed_secs: 2.5,
            findings,
            error: error.map(str::to_string),
        }
    }

    fn unit_started(binary: &str, function: &str) -> ProgressEvent {
        ProgressEvent::TranslationStarted {
            binary: binary.into(),
            function: function.to_string(),
        }
    }

    fn llm_call_started(
        binary: &str,
        function: &str,
        attempt: u32,
        strategy: &str,
    ) -> ProgressEvent {
        ProgressEvent::LlmCallStart {
            binary: binary.into(),
            function: function.to_string(),
            attempt,
            retry_strategy: strategy.to_string(),
        }
    }

    fn batch_started(binary: &str) -> ProgressEvent {
        ProgressEvent::BatchStarted {
            binary: binary.into(),
        }
    }

    fn batch_progress(binary: &str, pass: &str, function: &str) -> ProgressEvent {
        ProgressEvent::BatchProgress {
            binary: binary.into(),
            pass: pass.to_string(),
            function: function.to_string(),
            index: 1200,
            total: 7267,
        }
    }

    fn batch_summary(binary: &str) -> ProgressEvent {
        ProgressEvent::BatchSummary {
            binary: binary.into(),
            total_functions: 10,
            success_count: 9,
            failure_count: 1,
            total_attempts: 12,
            total_tokens: 40_000,
        }
    }

    // ── the single store reading (issue #455) ─────────────────────────

    /// One store reading answers every pipeline field at once (issue
    /// #455). The units, scan rows, classification results, batch
    /// summaries, the binary in flight, the queue plan, the heartbeat, and
    /// the ingestion state all come back in one answer.
    #[tokio::test]
    async fn one_store_reading_answers_every_pipeline_field_at_once() {
        let store = ProgressState::new();
        store.apply(&unit_started("game_logic.dll", "FUN_1")).await;
        store
            .apply(&scan_started("game_logic.dll", "type-database"))
            .await;
        store.apply(&batch_started("game_logic.dll")).await;
        store
            .apply(&batch_progress("game_logic.dll", "translating", "FUN_1"))
            .await;
        store
            .apply(&ProgressEvent::QueuePlanned {
                binaries: vec!["game_logic.dll".into(), "LaunchPad.exe".into()],
            })
            .await;
        store
            .apply(&ProgressEvent::ClassificationComplete {
                binary: "game_logic.dll".into(),
                category: "engine".into(),
                classification_strategy: "translate".into(),
                crate_replacement: None,
                exported_symbols: 4,
                imported_symbols: 2,
            })
            .await;
        store.apply(&batch_summary("LaunchPad.exe")).await;

        let reading = store.full_read().await;

        assert_eq!(reading.units.len(), 1, "the in-flight unit is a row");
        let unit = reading.units.values().next().expect("the one unit row");
        assert_eq!(unit.function, "FUN_1");
        assert_eq!(reading.scans.len(), 1, "the running scan is a row");
        assert_eq!(reading.scans[0].scan, "type-database");
        assert!(
            !reading.scans[0].finished,
            "its completed event has not landed"
        );
        assert_eq!(reading.classifications.len(), 1);
        assert_eq!(reading.classifications[0].category, "engine");
        assert_eq!(reading.batch_summaries.len(), 1);
        assert_eq!(
            reading.batch_summaries[0].binary,
            BinaryIdentity::new("LaunchPad.exe")
        );
        assert_eq!(
            reading.processing.as_deref(),
            Some("game_logic.dll"),
            "the batch pass is in flight"
        );
        let (heartbeat_binary, heartbeat) = reading.activity.expect("the pass is beating");
        assert_eq!(heartbeat_binary, BinaryIdentity::new("game_logic.dll"));
        assert_eq!(heartbeat.pass, "translating");
        assert_eq!(reading.queue, ["game_logic.dll", "LaunchPad.exe"]);
        assert!(
            !reading.ingestion.started,
            "no ingestion event landed, so the reading says ingestion never began"
        );
    }

    /// A taken store reading names one pass throughout, and it never
    /// moves (issue #455). Once it answers, a later pass cannot change any
    /// of its fields. A fresh reading names the new pass from its first
    /// field to its last.
    #[tokio::test]
    async fn a_taken_store_reading_names_one_pass_throughout_and_never_moves() {
        let store = ProgressState::new();
        store.apply(&batch_started("game_logic.dll")).await;
        store
            .apply(&batch_progress("game_logic.dll", "call graph", "FUN_1"))
            .await;
        store
            .apply(&ProgressEvent::QueuePlanned {
                binaries: vec!["game_logic.dll".into()],
            })
            .await;

        let first = store.full_read().await;

        // The second pass lands after the first reading was answered.
        store.apply(&batch_started("LaunchPad.exe")).await;
        store
            .apply(&batch_progress("LaunchPad.exe", "translating", "FUN_9"))
            .await;
        store
            .apply(&ProgressEvent::QueuePlanned {
                binaries: vec!["LaunchPad.exe".into()],
            })
            .await;

        assert_eq!(
            first.processing.as_deref(),
            Some("game_logic.dll"),
            "the answered reading still names the pass it witnessed"
        );
        let (heartbeat_binary, heartbeat) = first.activity.expect("the witnessed pass's heartbeat");
        assert_eq!(heartbeat_binary, BinaryIdentity::new("game_logic.dll"));
        assert_eq!(heartbeat.pass, "call graph");
        assert_eq!(first.queue, ["game_logic.dll"]);

        let second = store.full_read().await;
        assert_eq!(second.processing.as_deref(), Some("LaunchPad.exe"));
        let (heartbeat_binary, heartbeat) = second.activity.expect("the new pass's heartbeat");
        assert_eq!(heartbeat_binary, BinaryIdentity::new("LaunchPad.exe"));
        assert_eq!(heartbeat.pass, "translating");
        assert_eq!(second.queue, ["LaunchPad.exe"]);
    }

    // ── scan-record honesty (ADR-0061, issues #428/#429) ──────────────

    /// The evidence engine reported no single count, so the record carries
    /// none (issue #429). An unknown count stays unknown, never a zero.
    #[tokio::test]
    async fn a_scan_whose_evidence_engine_reported_no_count_keeps_its_findings_unknown_never_zero()
    {
        let store = ProgressState::new();
        store.apply(&scan_started("LaunchPad.exe", "sync")).await;
        store
            .apply(&scan_completed("LaunchPad.exe", "sync", None, None))
            .await;

        let rows = store.scan_view().await;
        assert_eq!(rows.len(), 1, "the started/completed pair leaves one row");
        assert!(rows[0].finished, "the completed event landed");
        assert_eq!(
            rows[0].findings, None,
            "an unreported count is absent, never Some(0): {rows:?}"
        );
        assert_eq!(
            rows[0].error, None,
            "a scan that did not fail names no error"
        );
    }

    /// A failed scan is finished *with* its error words and *without* its
    /// count, so it never reads as a completed scan that found nothing
    /// (issue #429).
    #[tokio::test]
    async fn a_failed_scan_keeps_its_error_words_and_leaves_the_count_unknown() {
        let store = ProgressState::new();
        store.apply(&scan_started("LaunchPad.exe", "sync")).await;
        store
            .apply(&scan_completed(
                "LaunchPad.exe",
                "sync",
                None,
                Some("the sync evidence engine refused the scan"),
            ))
            .await;

        let rows = store.scan_view().await;
        assert_eq!(rows.len(), 1);
        assert!(
            rows[0].finished,
            "the completed event lands even on a failure"
        );
        assert_eq!(
            rows[0].error.as_deref(),
            Some("the sync evidence engine refused the scan"),
            "the failure keeps its own words"
        );
        assert_eq!(
            rows[0].findings, None,
            "a failed scan files no count, so the failure cannot read as zero findings: {rows:?}"
        );
    }

    /// Scan records describe the pass in flight: the first scan event for
    /// a different binary retires the previous binary's rows (issue #428).
    #[tokio::test]
    async fn the_first_scan_event_for_a_new_binary_clears_the_previous_binaries_rows() {
        let store = ProgressState::new();
        store.apply(&scan_started("LaunchPad.exe", "sync")).await;
        store
            .apply(&scan_completed("LaunchPad.exe", "sync", Some(43), None))
            .await;
        store
            .apply(&scan_started("LaunchPad.exe", "call-graph"))
            .await;
        store.apply(&scan_started("game_logic.dll", "sync")).await;

        let rows = store.scan_view().await;
        assert_eq!(rows.len(), 1, "only the new binary's rows remain: {rows:?}");
        assert_eq!(rows[0].binary.as_str(), "game_logic.dll");
        assert!(
            !rows[0].finished,
            "the new binary's scan is the one running"
        );
    }

    /// A re-pass over the same binary keeps each finished row until that
    /// scan's own started event lands and replaces the record — no earlier
    /// scan event wipes it (issue #428).
    #[tokio::test]
    async fn a_repass_over_the_same_binary_replaces_a_row_only_when_its_started_event_lands() {
        let store = ProgressState::new();
        store.apply(&scan_started("LaunchPad.exe", "sync")).await;
        store
            .apply(&scan_completed("LaunchPad.exe", "sync", Some(3), None))
            .await;
        // Another scan of the same binary starting does not wipe the
        // finished sync row — its findings stay on the panel.
        store
            .apply(&scan_started("LaunchPad.exe", "call-graph"))
            .await;
        let rows = store.scan_view().await;
        assert_eq!(rows.len(), 2);
        let sync = rows
            .iter()
            .find(|r| r.scan == "sync")
            .expect("sync row kept");
        assert!(sync.finished, "the previous pass's finished row survives");
        assert_eq!(sync.findings, Some(3));

        // The sync scan's own started event opens the fresh record.
        store.apply(&scan_started("LaunchPad.exe", "sync")).await;
        let rows = store.scan_view().await;
        let sync = rows
            .iter()
            .find(|r| r.scan == "sync")
            .expect("sync row replaced");
        assert!(!sync.finished, "the re-pass's row is the running one");
        assert_eq!(sync.findings, None, "the fresh record files no count yet");
    }

    /// A completed event with no running record for the current binary is
    /// a dropped event — the panel loses that one story rather than
    /// inventing a row (issue #428).
    #[tokio::test]
    async fn a_completed_scan_with_no_running_record_is_dropped_not_given_a_fabricated_row() {
        let store = ProgressState::new();
        store
            .apply(&scan_completed("LaunchPad.exe", "sync", Some(9), None))
            .await;
        assert!(
            store.scan_view().await.is_empty(),
            "a completed with no started event fabricates no row"
        );

        // Even beside another scan's records, a lone completed for a scan
        // that never started stays out.
        store
            .apply(&scan_started("LaunchPad.exe", "call-graph"))
            .await;
        store
            .apply(&scan_completed("LaunchPad.exe", "sync", Some(9), None))
            .await;
        let rows = store.scan_view().await;
        assert_eq!(
            rows.len(),
            1,
            "only the started call-graph row is on the panel"
        );
        assert_eq!(rows[0].scan, "call-graph");
    }

    /// Scan events name no unit: they never open a unit record and never
    /// touch a phase history (ADR-0061, first decision).
    #[tokio::test]
    async fn a_scan_event_never_opens_a_unit_record_or_touches_a_phase_history() {
        let store = ProgressState::new();
        store.apply(&scan_started("LaunchPad.exe", "sync")).await;
        store
            .apply(&scan_completed("LaunchPad.exe", "sync", Some(1), None))
            .await;
        assert!(store.is_empty().await, "scan traffic names no unit");
        assert_eq!(store.len().await, 0);
        assert!(store.view().await.units.is_empty());
    }

    // ── heartbeat and processing-binary honesty ───────────────────────

    /// The heartbeat records where the working pass stands — and a new
    /// started pass makes any earlier heartbeat stale (issue #430).
    #[tokio::test]
    async fn a_batch_progress_event_sets_the_heartbeat_and_a_new_started_pass_clears_it() {
        let store = ProgressState::new();
        store
            .apply(&batch_progress(
                "LaunchPad.exe",
                "evidence scans",
                "FUN_1800412a0",
            ))
            .await;
        let (binary, beat) = store.activity().await.expect("the pass is beating");
        assert_eq!(binary.as_str(), "LaunchPad.exe");
        assert_eq!(beat.pass, "evidence scans");
        assert_eq!(beat.function.as_deref(), Some("FUN_1800412a0"));
        assert_eq!(beat.index, Some(1200));
        assert_eq!(beat.total, Some(7267));
        assert!(
            store.view().await.activity.is_some(),
            "the heartbeat rides beside the scan rows in the payload"
        );

        store.apply(&batch_started("game_logic.dll")).await;
        assert!(
            store.activity().await.is_none(),
            "a new pass retires the previous pass's heartbeat"
        );
        assert!(store.view().await.activity.is_none());
    }

    /// A batch summary closes the pass its binary was working, and that
    /// binary's heartbeat goes with it. A different binary's summary leaves
    /// the heartbeat alone.
    #[tokio::test]
    async fn a_batch_summary_clears_that_binaries_heartbeat_but_leaves_another_binaries() {
        let store = ProgressState::new();
        store.apply(&batch_started("LaunchPad.exe")).await;
        store
            .apply(&batch_progress("LaunchPad.exe", "call graph", "FUN_1"))
            .await;
        store.apply(&batch_summary("game_logic.dll")).await;
        assert!(
            store.activity().await.is_some(),
            "another binary's summary does not close this pass"
        );

        store.apply(&batch_summary("LaunchPad.exe")).await;
        assert!(
            store.activity().await.is_none(),
            "the working binary's summary ends the heartbeat"
        );
    }

    /// One binary's pass is in flight at a time. The started event names
    /// it, and that binary's summary clears it.
    #[tokio::test]
    async fn a_batch_start_names_the_processing_binary_and_that_binaries_summary_clears_it() {
        let store = ProgressState::new();
        store.apply(&batch_started("LaunchPad.exe")).await;
        assert_eq!(
            store.processing_binary().await.as_deref(),
            Some("LaunchPad.exe")
        );

        store.apply(&batch_summary("game_logic.dll")).await;
        assert_eq!(
            store.processing_binary().await.as_deref(),
            Some("LaunchPad.exe"),
            "another binary's summary does not end this pass"
        );

        store.apply(&batch_summary("LaunchPad.exe")).await;
        assert_eq!(
            store.processing_binary().await,
            None,
            "the pass in flight is done once its summary lands"
        );
    }

    // ── queue-plan honesty ────────────────────────────────────────────

    /// The plan is the run's intent: a later plan replaces the earlier
    /// one wholesale, not merged into it.
    #[tokio::test]
    async fn a_new_queue_plan_replaces_the_runs_plan_wholesale() {
        let store = ProgressState::new();
        store
            .apply(&ProgressEvent::QueuePlanned {
                binaries: vec!["LaunchPad.exe".into(), "game_logic.dll".into()],
            })
            .await;
        assert_eq!(store.queue().await, ["LaunchPad.exe", "game_logic.dll"]);

        store
            .apply(&ProgressEvent::QueuePlanned {
                binaries: vec!["game_logic.dll".into()],
            })
            .await;
        assert_eq!(
            store.queue().await,
            ["game_logic.dll"],
            "the new plan stands on its own, not appended to the old"
        );
    }

    // ── unit-record honesty ───────────────────────────────────────────

    /// Whichever event names a unit first opens its record — dropping that
    /// event would lose real evidence. A later `TranslationStarted` finds
    /// the record and never resets it.
    #[tokio::test]
    async fn the_first_event_naming_a_unit_opens_its_record_and_a_later_started_event_never_overwrites_it()
     {
        let store = ProgressState::new();
        store
            .apply(&ProgressEvent::TestsGenerated {
                binary: "LaunchPad.exe".into(),
                function: "FUN_1".into(),
                test_count: 5,
            })
            .await;
        let opened = store
            .entry("LaunchPad.exe", "FUN_1")
            .await
            .expect("the tests-generated event opened the record");
        assert_eq!(
            opened.baseline,
            PassStatus::pending(5),
            "the first event's evidence is kept, not dropped"
        );

        store
            .apply(&llm_call_started(
                "LaunchPad.exe",
                "FUN_1",
                3,
                "tier_escalation",
            ))
            .await;
        store.apply(&unit_started("LaunchPad.exe", "FUN_1")).await;

        let record = store
            .entry("LaunchPad.exe", "FUN_1")
            .await
            .expect("the record survives");
        assert_eq!(
            record.attempt, 3,
            "the late started event does not reset the attempt"
        );
        assert_eq!(
            record.retry_strategy.as_deref(),
            Some("tier_escalation"),
            "nor the strategy the third attempt named"
        );
        assert_eq!(
            record.baseline,
            PassStatus::pending(5),
            "nor the earlier evidence"
        );
        assert!(!record.finished, "a started event is not a terminal event");
        assert_eq!(store.len().await, 1, "one record per unit, not two");
    }

    /// The phase history records transitions, not dwell time. More events
    /// inside the same phase append nothing. A re-entered different phase,
    /// like a tier escalation landing `ContextTier` again, appends its entry.
    #[tokio::test]
    async fn the_phase_history_appends_only_when_the_derived_phase_changes() {
        let store = ProgressState::new();
        store.apply(&unit_started("LaunchPad.exe", "FUN_1")).await;
        store
            .apply(&ProgressEvent::ScanFetchComplete {
                binary: "LaunchPad.exe".into(),
                function: "FUN_1".into(),
                address: None,
                disassembly_lines: 10,
            })
            .await;
        store
            .apply(&llm_call_started("LaunchPad.exe", "FUN_1", 1, "direct"))
            .await;
        let phases: Vec<TranslationPhase> = store
            .entry("LaunchPad.exe", "FUN_1")
            .await
            .expect("the record exists")
            .phase_history
            .iter()
            .map(|entry| entry.phase)
            .collect();
        assert_eq!(
            phases,
            vec![
                TranslationPhase::ScanFetch,
                TranslationPhase::ApiTagging,
                TranslationPhase::LlmCall,
            ]
        );

        // More events inside the LLM-call phase: the same phase re-derived
        // is not a transition.
        store
            .apply(&ProgressEvent::LlmRequest {
                binary: "LaunchPad.exe".into(),
                function: "FUN_1".into(),
                attempt: 1,
                retry_strategy: "direct".into(),
                prompt: "…".into(),
            })
            .await;
        store
            .apply(&ProgressEvent::LlmCallInProgress {
                binary: "LaunchPad.exe".into(),
                function: "FUN_1".into(),
                attempt: 1,
                retry_strategy: "direct".into(),
                elapsed_secs: 5,
            })
            .await;
        let record = store
            .entry("LaunchPad.exe", "FUN_1")
            .await
            .expect("the record exists");
        assert_eq!(
            record.phase_history.len(),
            3,
            "staying in LlmCall appends nothing"
        );
        assert_eq!(record.phase, TranslationPhase::LlmCall);

        // A tier escalation re-derives a *different* phase — the history
        // records the re-entry so the escalation stays visible.
        store
            .apply(&ProgressEvent::ContextTierSelected {
                binary: "LaunchPad.exe".into(),
                function: "FUN_1".into(),
                tier: "T2".into(),
                tier_label: "with_tests".into(),
                complexity: "High".into(),
                api_call_count: 3,
            })
            .await;
        let record = store
            .entry("LaunchPad.exe", "FUN_1")
            .await
            .expect("the record exists");
        assert_eq!(
            record
                .phase_history
                .last()
                .expect("history is never empty")
                .phase,
            TranslationPhase::ContextTier,
            "a re-entered different phase appends"
        );
    }

    /// A cancelled unit and a failed unit are both finished and failed —
    /// their outcome words tell the dashboard which is which (issue #91).
    #[tokio::test]
    async fn a_cancelled_unit_and_a_failed_unit_read_apart_by_their_outcome_words() {
        let store = ProgressState::new();
        store
            .apply(&unit_started("LaunchPad.exe", "FUN_cancelled"))
            .await;
        store
            .apply(&llm_call_started(
                "LaunchPad.exe",
                "FUN_cancelled",
                1,
                "direct",
            ))
            .await;
        store
            .apply(&ProgressEvent::UnitCancelled {
                binary: "LaunchPad.exe".into(),
                function: "FUN_cancelled".into(),
            })
            .await;

        store
            .apply(&unit_started("LaunchPad.exe", "FUN_failed"))
            .await;
        store
            .apply(&ProgressEvent::FunctionCompleted {
                binary: "LaunchPad.exe".into(),
                function: "FUN_failed".into(),
                success: false,
                attempts: 3,
                branch: None,
            })
            .await;

        let cancelled = store
            .entry("LaunchPad.exe", "FUN_cancelled")
            .await
            .expect("the cancelled record exists");
        let failed = store
            .entry("LaunchPad.exe", "FUN_failed")
            .await
            .expect("the failed record exists");
        assert!(cancelled.finished && failed.finished, "both are terminal");
        assert_eq!(cancelled.succeeded, Some(false));
        assert_eq!(failed.succeeded, Some(false));
        assert_eq!(
            cancelled.outcome.as_deref(),
            Some("cancelled"),
            "the operator cancellation names itself"
        );
        assert_eq!(
            failed.outcome.as_deref(),
            Some("batch_failed"),
            "a failed unit names the batch outcome"
        );
        assert_ne!(cancelled.outcome, failed.outcome, "the two read apart");
    }

    /// The two completed events read apart. `TranslationCompleted` records
    /// that the unit succeeded, with no batch outcome word until the batch
    /// records one. `FunctionCompleted` records `batch_ok` in the outcome
    /// field — never in the retry strategy (issue #363).
    #[tokio::test]
    async fn a_completed_unit_sets_succeeded_and_its_terminal_word_lands_in_the_outcome_field() {
        let store = ProgressState::new();
        store.apply(&unit_started("LaunchPad.exe", "FUN_ok")).await;
        store
            .apply(&llm_call_started("LaunchPad.exe", "FUN_ok", 1, "direct"))
            .await;
        store
            .apply(&ProgressEvent::TranslationCompleted {
                binary: "LaunchPad.exe".into(),
                function: "FUN_ok".into(),
                total_attempts: 1,
                success_strategy: Some("direct".into()),
            })
            .await;
        let record = store
            .entry("LaunchPad.exe", "FUN_ok")
            .await
            .expect("the record exists");
        assert!(record.finished, "the completed event is terminal");
        assert_eq!(record.succeeded, Some(true));
        assert_eq!(
            record.outcome, None,
            "the unit-level completion files no batch outcome word"
        );
        assert_eq!(
            record.retry_strategy.as_deref(),
            Some("direct"),
            "the attempt's strategy keeps its own name after the unit is done"
        );

        store
            .apply(&ProgressEvent::FunctionCompleted {
                binary: "LaunchPad.exe".into(),
                function: "FUN_ok".into(),
                success: true,
                attempts: 1,
                branch: None,
            })
            .await;
        let record = store
            .entry("LaunchPad.exe", "FUN_ok")
            .await
            .expect("the record exists");
        assert_eq!(record.succeeded, Some(true));
        assert_eq!(record.outcome.as_deref(), Some("batch_ok"));
        assert_eq!(
            record.retry_strategy.as_deref(),
            Some("direct"),
            "the batch outcome never lands under the retry-strategy name"
        );
    }

    /// No LLM call has named a strategy yet, so the record hands out none
    /// — not a blank string that would render as a strategy.
    #[tokio::test]
    async fn a_unit_with_no_llm_call_yet_omits_the_retry_strategy() {
        let store = ProgressState::new();
        store.apply(&unit_started("LaunchPad.exe", "FUN_1")).await;
        let record = store
            .entry("LaunchPad.exe", "FUN_1")
            .await
            .expect("the started event opened the record");
        assert_eq!(
            record.retry_strategy, None,
            "an unnamed strategy is absent, not blank"
        );

        store
            .apply(&llm_call_started("LaunchPad.exe", "FUN_1", 1, "direct"))
            .await;
        let record = store
            .entry("LaunchPad.exe", "FUN_1")
            .await
            .expect("the record exists");
        assert_eq!(record.retry_strategy.as_deref(), Some("direct"));
    }

    /// The payload's counts describe the served rows. `count` names every
    /// tracked unit and `in_flight` only the unfinished ones, and the
    /// status getters agree with both.
    #[tokio::test]
    async fn the_unit_count_and_in_flight_count_agree_with_the_served_rows() {
        let store = ProgressState::new();
        store
            .apply(&unit_started("LaunchPad.exe", "FUN_done"))
            .await;
        store
            .apply(&unit_started("LaunchPad.exe", "FUN_running"))
            .await;
        store
            .apply(&ProgressEvent::TranslationCompleted {
                binary: "LaunchPad.exe".into(),
                function: "FUN_done".into(),
                total_attempts: 1,
                success_strategy: None,
            })
            .await;

        let view = store.view().await;
        assert_eq!(view.units.len(), 2, "both units are served");
        assert_eq!(view.count, 2, "the count names every tracked unit");
        assert_eq!(view.in_flight, 1, "only the unfinished unit is in flight");
        assert_eq!(
            view.units.iter().filter(|unit| !unit.finished).count(),
            view.in_flight,
            "in_flight agrees with the served rows"
        );
        assert_eq!(
            store.len().await,
            view.count,
            "the status count matches the payload"
        );
        assert_eq!(
            store.in_flight_count().await,
            view.in_flight,
            "the status in-flight count matches the payload"
        );
    }
}
