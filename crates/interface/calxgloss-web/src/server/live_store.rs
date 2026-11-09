//! The live store holds the records the `calxgloss live` view shows
//! (issue #451). The store updates them as each `ProgressEvent`
//! arrives. Handlers read them through this module's snapshot
//! methods.
//!
//! The store keeps a record for each unit being translated and for
//! the evidence scans of the pass in flight. It also keeps the run's
//! per-binary readings: classification results, batch summaries, the
//! processing binary, the queue plan, the heartbeat, and the
//! ingestion state. The locks that guard these records stay private
//! to this module, so no other module reaches into them.

use super::{BatchInfo, ClassificationInfo};
use calxgloss_types::{
    BinaryActivity, BinaryIdentity, PhaseRecord, ProgressEvent, TranslationPhase, UnitKey,
};
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

/// Tracks translation units currently in progress.
///
/// Created when `handle_live` starts the server with an event channel,
/// updated by processing `ProgressEvent` messages, and served by the
/// `/api/progress` endpoint so the dashboard can merge live status
/// with the git-backed state.
#[derive(Debug, Clone, Default)]
pub struct ProgressState {
    /// Map of unit key (`{binary}/{function}`) → current progress info for a
    /// live translation.
    entries: Arc<RwLock<std::collections::HashMap<String, ProgressEntry>>>,
    /// Classification results keyed by binary identity.
    classifications: Arc<RwLock<std::collections::HashMap<BinaryIdentity, ClassificationResult>>>,
    /// Batch summary results keyed by binary identity.
    batch_summaries: Arc<RwLock<std::collections::HashMap<BinaryIdentity, BatchResult>>>,
    /// The DLL whose batch pass is currently in flight — set by
    /// `BatchStarted`, cleared by that DLL's `BatchSummary`. The live loop
    /// works one binary at a time, so one slot is enough; a new
    /// `BatchStarted` replaces the old value if a pass ended without a
    /// summary (an error path).
    processing: Arc<RwLock<Option<BinaryIdentity>>>,
    /// The run's ordered plan — `QueuePlanned` records the binaries the
    /// live loop will process, in that order. Empty until a plan lands;
    /// a later plan replaces the earlier one.
    queue: Arc<RwLock<Vec<String>>>,
    /// The working pass's latest heartbeat — `(binary, activity)`. Set by
    /// `BatchProgress`, cleared when a new `BatchStarted` replaces the
    /// pass or that DLL's `BatchSummary` lands.
    activity: Arc<RwLock<Option<(BinaryIdentity, BinaryActivity)>>>,
    /// Startup ingestion state (issue #124). The Ghidra preflight events
    /// that used to set it were retired along with the Ghidra analysis
    /// engine (issue #214), so this stays empty and the pipeline view
    /// derives `project_ingestion` from classification counts alone.
    ingestion: Arc<RwLock<IngestionState>>,
    /// The pre-batch evidence scans of the binary whose pass is in flight,
    /// keyed by scan name so the latest event for a name wins
    /// (issue #428). The map holds one binary at a time: the first scan
    /// event for a different binary, or a `BatchStarted` naming one,
    /// clears the previous binary's rows — they no longer describe the
    /// live pass.
    scans: Arc<RwLock<std::collections::BTreeMap<String, ScanRecord>>>,
}

/// One registered evidence scan as the live store currently holds it
/// (issue #428). A running record has `elapsed_secs: None`, and the
/// payload measures its elapsed time from `started_at` at serve time. A
/// finished record keeps the run's wall-clock seconds, and keeps the
/// row's finding count only when the evidence engine reported a single
/// one.
///
/// `error` carries the failure's own words from the completed event: a
/// failed scan is finished with its error set and its finding count left
/// unknown, so a failure never reads as a completed scan with zero
/// findings (issue #429).
#[derive(Debug, Clone)]
pub struct ScanRecord {
    /// The registry row's name.
    pub scan: String,
    /// The binary whose scan pass this record belongs to.
    pub binary: BinaryIdentity,
    /// When the started event landed — the running clock's anchor.
    pub started_at: std::time::Instant,
    /// Whether the completed event has landed.
    pub finished: bool,
    /// The completed event's wall-clock seconds; `None` while running.
    pub elapsed_secs: Option<f64>,
    /// The count the evidence engine reported; `None` means the row
    /// files no single count, never a zero.
    pub findings: Option<usize>,
    /// The completed event's error words; `None` when the scan did not
    /// fail.
    pub error: Option<String>,
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

#[derive(Debug, Clone)]
pub struct ProgressEntry {
    pub binary: BinaryIdentity,
    pub function: String,
    pub attempt: u32,
    /// Retry strategy the current LLM-call attempt used — Pipeline's word,
    /// never a batch outcome (issue #363). See [`outcome`](Self::outcome).
    pub retry_strategy: String,
    /// The outcome the batch recorded for this finished unit — `"batch_ok"`,
    /// `"batch_failed"` or `"cancelled"`. It is a separate field from the
    /// retry strategy, so the two names never take on each other's meaning.
    pub outcome: Option<String>,
    pub started_at: std::time::Instant,
    /// The pipeline step this unit is currently in, derived from the latest
    /// phase-bearing `ProgressEvent`.
    pub phase: TranslationPhase,
    /// Phases entered, in event order (the first entry is the starting phase).
    /// Re-entering a phase (e.g. `ContextTier` on tier escalation) appends a
    /// new entry, so the retry history stays visible.
    pub phase_history: Vec<PhaseRecord>,
    /// Set once a terminal event (completed / failed / function-completed)
    /// has been observed for this unit.
    pub finished: bool,
    /// Whether the unit's translation ultimately succeeded — `None` until a
    /// terminal event (`TranslationCompleted` / `TranslationFailed` /
    /// `FunctionCompleted`) says so, so an unfinished unit never looks failed.
    pub succeeded: Option<bool>,
    /// Context tier the current attempt runs at — `None` until a
    /// `ContextTierSelected` event records one (re-emitted on tier escalation).
    pub context_tier: Option<String>,
    /// Human-readable tier label from the same event.
    pub tier_label: Option<String>,
    /// Baseline tests that passed in the latest verified attempt — `None` until
    /// a `TranslationAttemptCompleted` reports a run.
    pub baseline_tests_passed: Option<usize>,
    /// Baseline tests for the unit — from `TestsGenerated`, then from the
    /// verified attempt's own count, whichever landed last.
    pub baseline_tests_total: Option<usize>,
    /// Edge-case (verification) tests that passed — `None` until the
    /// behavior-divergence detector runs them.
    pub verification_tests_passed: Option<usize>,
    /// Edge-case (verification) tests the detector ran.
    pub verification_tests_total: Option<usize>,
    /// Whether the latest verified attempt compiled — `None` until an attempt
    /// has been verified.
    pub compiled: Option<bool>,
    pub last_event_at: std::time::Instant,
}

impl ProgressState {
    pub fn new() -> Self {
        Self {
            entries: Arc::new(RwLock::new(std::collections::HashMap::new())),
            classifications: Arc::new(RwLock::new(std::collections::HashMap::new())),
            batch_summaries: Arc::new(RwLock::new(std::collections::HashMap::new())),
            processing: Arc::new(RwLock::new(None)),
            queue: Arc::new(RwLock::new(Vec::new())),
            activity: Arc::new(RwLock::new(None)),
            ingestion: Arc::new(RwLock::new(IngestionState::default())),
            scans: Arc::new(RwLock::new(std::collections::BTreeMap::new())),
        }
    }

    /// Update progress state from a translation progress event.
    pub async fn on_event(&self, event: &ProgressEvent) {
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
                self.on_translation_event(event).await;
            }
            ProgressEvent::ClassificationComplete {
                binary,
                category,
                classification_strategy,
                crate_replacement,
                exported_symbols,
                imported_symbols,
            } => {
                let mut classifications = self.classifications.write().await;
                classifications.insert(
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
                *self.processing.write().await = Some(binary.clone());
                *self.activity.write().await = None;
                // The same rule for the scan panel (issue #428): records
                // belong to the binary whose pass they witnessed. Another
                // pass over the same binary keeps them until that row's
                // next started event replaces the record. A pass for a
                // different binary retires the previous binary's rows.
                let mut scans = self.scans.write().await;
                if scans.values().any(|record| record.binary != *binary) {
                    scans.clear();
                }
            }
            ProgressEvent::QueuePlanned { binaries } => {
                // The plan is the run's intent, replaced wholesale if a
                // later run plans differently.
                *self.queue.write().await = binaries.clone();
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
                *self.activity.write().await = Some((binary.clone(), activity));
            }
            ProgressEvent::BatchSummary {
                binary,
                total_functions,
                success_count,
                failure_count,
                total_attempts,
                total_tokens,
            } => {
                let mut batch_summaries = self.batch_summaries.write().await;
                batch_summaries.insert(
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
                let mut processing = self.processing.write().await;
                if processing.as_deref() == Some(binary.as_str()) {
                    *processing = None;
                }
                let mut activity = self.activity.write().await;
                if activity.as_ref().is_some_and(|(d, _)| d == binary) {
                    *activity = None;
                }
            }
            ProgressEvent::EvidenceScanStarted { binary, scan } => {
                // The scan traffic itself also marks the pass boundary:
                // the live pipeline emits no `BatchStarted`, so the first
                // scan event naming a new binary retires the previous
                // binary's rows (issue #428).
                let mut scans = self.scans.write().await;
                if scans.values().any(|record| record.binary != *binary) {
                    scans.clear();
                }
                // A re-run pass over the same binary replaces the row's
                // old record the moment its new pass starts.
                scans.insert(
                    scan.clone(),
                    ScanRecord {
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
                let mut scans = self.scans.write().await;
                if scans.values().any(|record| record.binary != *binary) {
                    scans.clear();
                }
                // The phase emits the started event before this one, so a
                // running record is normally already here. A completed
                // with no running record for the current binary is a
                // dropped event, and an incomplete story stays out of the
                // panel rather than inventing one row.
                if let Some(record) = scans.get_mut(scan)
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

    /// Handle translation-specific events (updates entries HashMap).
    async fn on_translation_event(&self, event: &ProgressEvent) {
        let mut entries = self.entries.write().await;

        // Unit-scoped events include the binary/function pair that identifies
        // the unit; batch-level events (ClassificationComplete, BatchSummary)
        // are handled in `on_event` and never reach here.
        let Some(unit) = event.unit_key() else {
            return;
        };
        let key = unit.to_string();

        // The unit's record begins with the first event that identifies it.
        // That is normally `TranslationStarted`, but the event callback
        // spawns one task per event and they race for the write lock, so any
        // unit-scoped event may legitimately arrive first. Dropping that
        // first event (as `get_mut` did) loses real evidence, so create the
        // record instead. `TranslationStarted` then finds the record already
        // there and never overwrites it.
        let entry = entries.entry(key).or_insert_with(|| {
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

        {
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
    }

    /// Returns a snapshot of all progress entries.
    pub async fn snapshot(&self) -> std::collections::HashMap<String, ProgressEntry> {
        self.entries.read().await.clone()
    }

    /// The current record for one unit, keyed by binary and function name.
    pub async fn entry(&self, binary: &str, function: &str) -> Option<ProgressEntry> {
        let key = UnitKey::new(&BinaryIdentity::from(binary), function).to_string();
        self.entries.read().await.get(&key).cloned()
    }

    /// The scan records of the binary whose pass is in flight, in scan-name
    /// order — the live view's stable row order (issue #428).
    pub async fn scan_snapshot(&self) -> Vec<ScanRecord> {
        self.scans.read().await.values().cloned().collect()
    }

    /// Returns a snapshot of classification results as serializable info.
    pub async fn classifications(&self) -> Vec<ClassificationInfo> {
        let map = self.classifications.read().await;
        map.values()
            .map(|v| ClassificationInfo {
                binary: v.binary.clone(),
                category: v.category.clone(),
                classification_strategy: v.classification_strategy.clone(),
                crate_replacement: v.crate_replacement.clone(),
                exported_symbols: v.exported_symbols,
                imported_symbols: v.imported_symbols,
            })
            .collect()
    }

    /// Returns a snapshot of batch summary results as serializable info.
    pub async fn batch_summaries(&self) -> Vec<BatchInfo> {
        let map = self.batch_summaries.read().await;
        map.values()
            .map(|v| BatchInfo {
                binary: v.binary.clone(),
                total_functions: v.total_functions,
                success_count: v.success_count,
                failure_count: v.failure_count,
                total_attempts: v.total_attempts,
                total_tokens: v.total_tokens,
            })
            .collect()
    }

    /// The binary whose batch pass is currently in flight, if any —
    /// `BatchStarted` records it, and that binary's `BatchSummary` clears it.
    pub async fn processing_binary(&self) -> Option<BinaryIdentity> {
        self.processing.read().await.clone()
    }

    /// The run's ordered queue plan — the binaries the live loop will
    /// process, in that order. Empty when no plan has been announced.
    pub async fn queue(&self) -> Vec<String> {
        self.queue.read().await.clone()
    }

    /// The working pass's latest heartbeat — `(binary, activity)`, `None`
    /// while no pass is running to report one.
    pub async fn activity(&self) -> Option<(BinaryIdentity, BinaryActivity)> {
        self.activity.read().await.clone()
    }

    /// Startup ingestion state (issue #124) — whether the startup preflight
    /// scan has begun, and which binaries' auto-analysis has landed.
    pub async fn ingestion(&self) -> IngestionState {
        self.ingestion.read().await.clone()
    }

    /// Returns the number of currently in-flight units.
    pub async fn len(&self) -> usize {
        self.entries.read().await.len()
    }

    /// Returns the number of units still in flight (not yet finished).
    ///
    /// Finished units stay in the map for the dashboard's benefit, so the
    /// server status endpoint counts only the unfinished ones.
    pub async fn in_flight_count(&self) -> usize {
        self.entries
            .read()
            .await
            .values()
            .filter(|entry| !entry.finished)
            .count()
    }

    /// Returns whether there are any currently in-flight units.
    pub async fn is_empty(&self) -> bool {
        self.entries.read().await.is_empty()
    }
}
