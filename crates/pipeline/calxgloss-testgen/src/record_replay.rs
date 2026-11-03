//! Record-and-replay fold (P23.2, issue #396): a captured event log,
//! replayed, mines filed baseline cases.
//!
//! The trace side ([`calxgloss_types::CaptureEventLog`]) records what the
//! original binary did at a hook or in a crash minidump. This module folds
//! such a log into the filed baseline suite: every captured call entry
//! whose argument vector the export's signature can hold is replayed
//! against the original binary, and what the replay observed is filed as a
//! baseline case under `re/baseline/{binary}/{function}/baseline.json`.
//!
//! Authority rests on the replay, not the capture: the capture only names
//! the inputs — the filed expectation is what the original returned when
//! those inputs were replayed now. A captured entry that cannot be replayed
//! is refused with a named reason and names a `capture_refused` unknown
//! record; a replay that faults names a `crash_reproduction` record naming
//! the event and files no case for that entry. The capture is trusted to
//! name inputs, never to promise the target survived.
//!
//! The fold is the `ExportUncovered` closure mechanism: a standing export
//! gap closes at the next ledger write once a mined replay has filed a
//! suite for that export — the residue writer skips exports that already
//! hold a baseline.
//!
//! # Doctrine
//!
//! - A mined case's origin comes from its entry's own evidence: a run
//!   event stamps the `mined-hook` origin naming that capture id and event
//!   sequence; a dump thread stamps `mined-minidump` naming the dump's
//!   digest and the faulting thread — every field the origin carries is a
//!   field the capture really recorded, never a repurposed stand-in.
//! - A mined case dedups against the generated suite on exact input-vector
//!   equality; a collision keeps the stronger origin — the mined one — and
//!   the mined row files no duplicate and is not replayed again.
//! - Mined cases are exempt from the per-function generation cap: the cap
//!   bounds what generation invents, and captured events are evidence, not
//!   invention.
//! - Filed order is stable — generated cases first, then mined cases in
//!   first-seen capture order — so a repeated ingest is byte-stable.
//! - Truncation is stated, never silent: a log that dropped events because
//!   its budget ran out names one capture-level refusal and says so, and a
//!   pointer descriptor over the *capture bound* — or short of its own
//!   stated size — refuses with the truncation named in its detail.
//! - Pointer arguments replay as fresh allocations holding the captured
//!   bytes ([`calxgloss_types::POINTER_CAPTURE_BOUND`] caps what capture
//!   may record); a pointer with no captured bytes to materialize is
//!   refused, never pointed at an address the harness cannot honor.

use std::collections::HashSet;

use anyhow::Result;
use calxgloss_types::{
    ArgumentDescriptor, CaptureEvidence, CapturedCallEntry, CaseOrigin, Export, ScalarTag,
    TestCase, TestResult, UnknownKind, UnknownLedger, UnknownOrigin, UnknownRecord,
    UnknownResolutions, UnknownSeverity,
};
use serde::Deserialize;
use serde_json::{Map, Value};

use crate::ffi::{ParsedSignature, parse_signature};
use crate::generator::TestGenerator;
use crate::wine::encode::ALLOC_KEY;

/// A capture event log as stored on disk, staged raw: entries stay raw
/// JSON values so a single unshaped entry refuses itself by name instead
/// of poisoning the whole log's parse, and the float scan happens at the
/// raw level, before any typed decode could hide the `float-argument`
/// reason behind a parse error. The shaped entries decode as the shared
/// [`CapturedCallEntry`]; the log as a whole is the glossary's *capture
/// event log* ([`calxgloss_types::CaptureEventLog`]).
#[derive(Debug, Clone, Deserialize)]
struct RawCaptureLog {
    /// Identifier of the capture session or minidump the log was read from.
    capture_id: String,
    /// Captured call events, in capture order, still raw.
    #[serde(default)]
    entries: Vec<Value>,
    /// Events the capture dropped once its budget was exhausted — stated,
    /// never silent.
    #[serde(default)]
    events_dropped: Option<u64>,
}

/// What a replay of one input vector observed at the original binary.
#[derive(Debug, Clone)]
pub enum ReplayOutcome {
    /// The call completed; the replay saw this return value, side-effect
    /// trace, and API-call trace.
    Observed {
        returned: Value,
        side_effects: Vec<calxgloss_types::SideEffect>,
        api_calls: Vec<String>,
    },
    /// The replay faulted at the target — the captured inputs reproduce it.
    Faulted { detail: String },
}

/// The replay seam the fold calls per mined candidate.
///
/// A closed enum rather than a trait: production replays through the Wine
/// baseline harness; tests pin the whole walk with a fake that decides
/// outcomes per case, with no Wine in sight.
pub enum Replay<'a> {
    /// Replay through the baseline harness against the given DLL.
    Harness {
        /// Path to the original DLL on the current system.
        dll_path: &'a std::path::Path,
    },
    /// Fake seam: `f(function, case)` decides each outcome.
    Fake(&'a dyn Fn(&str, &TestCase) -> ReplayOutcome),
}

/// The closed vocabulary of named refusal reasons (issue #396): every
/// entry the fold cannot replay is refused by exactly one of these, and
/// the same spelling rides the report line and the unknown record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefusalReason {
    /// A float argument — outside the capture vocabulary and the scalar
    /// replay, scanned at the raw level before any typed parse.
    FloatArgument,
    /// The named export is not in the listing, or its signature does not
    /// parse — the vector cannot be named against anything.
    NoParseableSignature,
    /// The vector carries a pointer with no captured bytes to materialize;
    /// the replay cannot honor an address the capture never recorded.
    UnmaterializablePointer,
    /// The capture truncated an argument, dropped events at its budget, or
    /// carries a pointer descriptor the capture bound says cannot be whole;
    /// the vector it describes is incomplete, not small.
    TruncatedCapture,
    /// The entry is not a shaped vector, or the vector does not fit the
    /// declared signature — wrong arity, or a value that cannot feed the
    /// parameter at its position.
    ArgumentShapeNotInSignature,
}

impl RefusalReason {
    /// The shared spelling, the one the report and the records speak.
    pub fn as_str(&self) -> &'static str {
        match self {
            RefusalReason::FloatArgument => "float-argument",
            RefusalReason::NoParseableSignature => "no-parseable-signature",
            RefusalReason::UnmaterializablePointer => "unmaterializable-pointer",
            RefusalReason::TruncatedCapture => "truncated-capture",
            RefusalReason::ArgumentShapeNotInSignature => "argument-shape-not-in-signature",
        }
    }
}

impl std::fmt::Display for RefusalReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A refusal the fold named for one captured entry (or the log as a whole).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    /// Capture id the entry came from.
    pub capture_id: String,
    /// Event sequence naming the entry, or `None` for the log as a whole —
    /// a truncation names the capture, not one event.
    pub sequence: Option<u64>,
    /// Export the entry named, when it named one.
    pub export: Option<String>,
    /// Named reason, one of the closed vocabulary.
    pub reason: RefusalReason,
}

/// The counts one ingest reports: events seen, cases mined, twins
/// deduplicated, refusals named, truncations stated.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MineReport {
    /// Entries the log carried.
    pub events_seen: usize,
    /// Entries the capture dropped under its budget, when it stated them.
    pub events_dropped: Option<u64>,
    /// Replay observations filed as baseline cases.
    pub cases_mined: usize,
    /// Mined candidates deduplicated into an already-filed suite row.
    pub cases_deduplicated: usize,
    /// Refusals the fold named, each naming its reason.
    pub refusals: Vec<Refusal>,
}

impl MineReport {
    /// The one-line count report.
    pub fn summary(&self) -> String {
        let refusals = self.refusals.len();
        let truncations = self.truncations_stated();
        format!(
            "{} events seen, {} cases mined, {} twin{} deduplicated, {refusals} refusal{} \
             named, {truncations} truncation{} stated",
            self.events_seen,
            self.cases_mined,
            self.cases_deduplicated,
            if self.cases_deduplicated == 1 {
                ""
            } else {
                "s"
            },
            if refusals == 1 { "" } else { "s" },
            if truncations == 1 { "" } else { "s" },
        )
    }

    fn truncations_stated(&self) -> usize {
        usize::from(self.events_dropped.is_some_and(|n| n > 0))
            + self
                .refusals
                .iter()
                .filter(|r| r.reason == RefusalReason::TruncatedCapture && r.sequence.is_some())
                .count()
    }
}

impl std::fmt::Display for MineReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "{}", self.summary())?;
        for refusal in &self.refusals {
            let event = match refusal.sequence {
                Some(seq) => format!("#{seq}"),
                None => "capture".to_string(),
            };
            let export = refusal.export.as_deref().unwrap_or("<no export>");
            writeln!(f, "  refused {export} {event}: {}", refusal.reason)?;
        }
        if let Some(dropped) = self.events_dropped
            && dropped > 0
        {
            writeln!(f, "  capture truncated: {dropped} events dropped")?;
        }
        Ok(())
    }
}

/// What one ingest produced: the count report and the unknown records the
/// refusals and replay faults named, in fold order, ready to be filed into
/// the binary's unknown ledger with [`file_capture_records`].
#[derive(Debug, Clone)]
pub struct Folded {
    /// The count report the ingest prints.
    pub report: MineReport,
    /// The `capture_refused`/`crash_reproduction` records the fold named.
    pub unknown_records: Vec<UnknownRecord>,
    /// The filed suites, `(binary, function, rows)` for every baseline
    /// document the fold wrote.
    pub filed: Vec<(String, String, Vec<TestResult>)>,
}

/// The per-ingest sink the fold pushes its named facts into: the count
/// report and the unknown records, one refuse call per named refusal.
struct Ingest {
    binary: String,
    capture_id: String,
    report: MineReport,
    unknown_records: Vec<UnknownRecord>,
}

impl Ingest {
    /// Name one refusal: the report line and its `capture_refused` record,
    /// both spelling the same reason.
    fn refuse(
        &mut self,
        sequence: Option<u64>,
        export: Option<&str>,
        reason: RefusalReason,
        detail: &str,
    ) {
        self.report.refusals.push(Refusal {
            capture_id: self.capture_id.clone(),
            sequence,
            export: export.map(str::to_string),
            reason,
        });
        self.unknown_records.push(refusal_record(
            &self.binary,
            &self.capture_id,
            sequence,
            export,
            reason,
            detail,
        ));
    }
}

/// One mined candidate: a decoded input vector plus the capture facts that
/// name its origin, its dedup key, and its crash record.
struct Candidate {
    sequence: u64,
    case: TestCase,
    key: String,
}

/// Fold one capture event log into the filed baseline suites.
///
/// For each entry in capture order: decode it as a [`CapturedCallEntry`],
/// name its argument vector against the export's signature, replay it
/// through `replay`, and file what the replay observed. Suites are
/// appended to the rows already filed on disk — generated first, then
/// mined in first-seen capture order — and rewritten only for exports the
/// fold changed. The report counts every entry; the unknown records carry
/// the same named reasons as the refusals and faults.
pub async fn fold_capture_event_log(
    generator: &TestGenerator,
    binary: &str,
    exports: &[Export],
    log: &Value,
    replay: &Replay<'_>,
) -> Result<Folded> {
    let log: RawCaptureLog = serde_json::from_value(log.clone())
        .map_err(|e| anyhow::anyhow!("capture event log is malformed: {e}"))?;
    let mut ingest = Ingest {
        binary: binary.to_string(),
        capture_id: log.capture_id.clone(),
        report: MineReport {
            events_seen: log.entries.len(),
            events_dropped: log.events_dropped,
            ..MineReport::default()
        },
        unknown_records: Vec::new(),
    };

    // A stated truncation of the log as a whole names one capture-level
    // refusal — never silent.
    if log.events_dropped.is_some_and(|n| n > 0) {
        ingest.refuse(
            None,
            None,
            RefusalReason::TruncatedCapture,
            "the capture stopped at its event budget",
        );
    }

    // Decode entries in capture order, grouping mined candidates by export.
    let mut mined: Vec<(&Export, Vec<Candidate>)> = Vec::new();
    for raw in &log.entries {
        let export_name = raw.get("export").and_then(Value::as_str);
        let event = raw_event(raw);

        // Float tags live at the raw level: a typed decode would refuse
        // them at parse time and name no reason.
        if raw_has_float(raw) {
            ingest.refuse(
                event,
                export_name,
                RefusalReason::FloatArgument,
                "the capture recorded a float value the scalar replay cannot carry",
            );
            continue;
        }
        let entry: CapturedCallEntry = match serde_json::from_value(raw.clone()) {
            Ok(entry) => entry,
            Err(_) => {
                ingest.refuse(
                    event,
                    export_name,
                    RefusalReason::ArgumentShapeNotInSignature,
                    "the captured entry is not a shaped argument vector",
                );
                continue;
            }
        };

        // This fold files one binary's suites: an entry naming a different
        // target belongs to that binary's own ingest, never to this one.
        if entry.binary != binary {
            continue;
        }

        // A stated truncation refuses by name before anything else: the
        // vector it describes is incomplete, not small. The record says
        // how much really arrived against the capture bound.
        if let Some((observed, captured)) =
            entry.arguments.iter().find_map(|argument| match argument {
                ArgumentDescriptor::Pointer {
                    bytes,
                    captured_size,
                    truncated: true,
                } => Some((*captured_size, bytes.len())),
                _ => None,
            })
        {
            let bound = calxgloss_types::POINTER_CAPTURE_BOUND;
            ingest.refuse(
                event,
                Some(&entry.export),
                RefusalReason::TruncatedCapture,
                &format!(
                    "the capture truncated an argument of this event — {observed} bytes \
                     observed, {captured} captured at the {bound}-byte capture bound"
                ),
            );
            continue;
        }
        // A pointer with no captured bytes is the one pointer shape the
        // replay can never honor: there is nothing to materialize.
        if entry
            .arguments
            .iter()
            .any(|argument| matches!(argument, ArgumentDescriptor::Pointer { bytes, .. } if bytes.is_empty()))
        {
            ingest.refuse(
                event,
                Some(&entry.export),
                RefusalReason::UnmaterializablePointer,
                "the descriptor names a pointer with no captured bytes to materialize",
            );
            continue;
        }
        // A record-time capture can never carry more than the capture
        // bound, and an untruncated descriptor must carry exactly the size
        // it observed. Either half failing means the record states a full
        // buffer the capture cannot have delivered — the truncation gets
        // named here rather than silently reconstructed whole at replay.
        if let Some((observed, captured)) =
            entry.arguments.iter().find_map(|argument| match argument {
                ArgumentDescriptor::Pointer {
                    bytes,
                    captured_size,
                    ..
                } if u64::max(*captured_size, bytes.len() as u64)
                    > calxgloss_types::POINTER_CAPTURE_BOUND
                    || bytes.len() as u64 != *captured_size =>
                {
                    Some((*captured_size, bytes.len()))
                }
                _ => None,
            })
        {
            let bound = calxgloss_types::POINTER_CAPTURE_BOUND;
            ingest.refuse(
                event,
                Some(&entry.export),
                RefusalReason::TruncatedCapture,
                &format!(
                    "the descriptor claims {captured} captured bytes against {observed} \
                     observed — the {bound}-byte capture bound cannot deliver that whole, \
                     a truncation the record left unstated"
                ),
            );
            continue;
        }

        let Some(export) = exports.iter().find(|e| e.name == entry.export) else {
            ingest.refuse(
                event,
                Some(&entry.export),
                RefusalReason::NoParseableSignature,
                "the named export is not in the listing with a parseable signature",
            );
            continue;
        };
        let parsed = match parse_signature(&export.signature) {
            Ok(parsed) => parsed,
            Err(_) => {
                ingest.refuse(
                    event,
                    Some(&entry.export),
                    RefusalReason::NoParseableSignature,
                    &format!(
                        "the export's signature `{}` does not parse",
                        export.signature
                    ),
                );
                continue;
            }
        };
        let sequence = event_sequence(&entry.evidence);
        let Some(case) = decode_case(&entry, &parsed) else {
            ingest.refuse(
                event,
                Some(&entry.export),
                RefusalReason::ArgumentShapeNotInSignature,
                "the captured argument vector does not fit the declared signature",
            );
            continue;
        };
        let candidate = Candidate {
            key: positional_key(&case.inputs, &parsed),
            sequence,
            case,
        };
        if let Some((_, group)) = mined.iter_mut().find(|(e, _)| e.name == export.name) {
            group.push(candidate);
        } else {
            mined.push((export, vec![candidate]));
        }
    }

    // Replay each export's group and file: the harness seam runs once per
    // export, and filed order is generated-first then capture order.
    let mut filed = Vec::new();
    for (export, candidates) in mined {
        let parsed = parse_signature(&export.signature)
            .map_err(|e| anyhow::anyhow!("signature for `{}` stopped parsing: {e}", export.name))?;
        let existing = generator
            .load_baseline(binary, &export.name)
            .unwrap_or_default();
        let mut rows: Vec<TestResult> = existing.clone();
        let mut seen: HashSet<String> = rows
            .iter()
            .map(|row| positional_key(&row.test_case.inputs, &parsed))
            .collect();

        // Collisions upgrade the filed row's origin before anything
        // replays: the twin files no duplicate and is never replayed.
        // Twins inside this same log dedup on the first-seen copy too —
        // first capture order wins.
        let mut replayable: Vec<&Candidate> = Vec::new();
        let mut pending: HashSet<String> = HashSet::new();
        for candidate in &candidates {
            if seen.contains(&candidate.key) || !pending.insert(candidate.key.clone()) {
                ingest.report.cases_deduplicated += 1;
                if let Some(row) = rows.iter_mut().find(|row| {
                    positional_key(&row.test_case.inputs, &parsed) == candidate.key
                        && row.test_case.origin == CaseOrigin::Generated
                }) {
                    row.test_case.origin = candidate.case.origin.clone();
                }
            } else {
                replayable.push(candidate);
            }
        }

        let batch: Vec<TestCase> = replayable.iter().map(|c| c.case.clone()).collect();
        let outcomes = match replay {
            Replay::Fake(f) => batch
                .iter()
                .map(|case| f(&export.name, case))
                .collect::<Vec<_>>(),
            Replay::Harness { dll_path } => {
                let results = generator
                    .run_baseline_tests(binary, &export.name, &export.signature, &batch, dll_path)
                    .await?;
                results
                    .into_iter()
                    .map(|result| match result.error {
                        Some(detail) => ReplayOutcome::Faulted { detail },
                        None => ReplayOutcome::Observed {
                            returned: result.actual_return,
                            side_effects: result.actual_side_effects,
                            api_calls: result.actual_api_calls,
                        },
                    })
                    .collect()
            }
        };

        for (candidate, outcome) in replayable.iter().zip(outcomes) {
            match outcome {
                ReplayOutcome::Observed {
                    returned,
                    side_effects,
                    api_calls,
                } => {
                    let mut case = candidate.case.clone();
                    if !side_effects.is_empty() {
                        case.expected_side_effects = side_effects.clone();
                    }
                    if !api_calls.is_empty() {
                        case.expected_api_calls = api_calls.clone();
                    }
                    seen.insert(candidate.key.clone());
                    rows.push(TestResult {
                        test_case: case,
                        actual_return: returned,
                        actual_side_effects: side_effects,
                        actual_api_calls: api_calls,
                        passed: true,
                        error: None,
                    });
                    ingest.report.cases_mined += 1;
                }
                ReplayOutcome::Faulted { detail } => {
                    let record = crash_record(
                        &ingest.binary,
                        &ingest.capture_id,
                        candidate.sequence,
                        &export.name,
                        &detail,
                    );
                    ingest.unknown_records.push(record);
                }
            }
        }

        if rows != existing {
            generator.save_baseline(binary, &export.name, &rows)?;
            filed.push((binary.to_string(), export.name.clone(), rows));
        }
    }

    Ok(Folded {
        report: ingest.report,
        unknown_records: ingest.unknown_records,
        filed,
    })
}

/// File the fold's named records into the binary's unknown ledger,
/// `re/unknowns/<binary>.json`.
///
/// The records join the landed set under the same merge doctrine the
/// pipeline's ledger write uses ([`UnknownLedger::file`]): a re-ingest of
/// the same capture re-derives each record's id instead of duplicating it,
/// the reviewer's reopen marks fire exactly once, and batch-filed records
/// survive the merge — the write replaces the document with the landed set
/// folded with the new records, never the new records alone. Returns the
/// number of records landed.
pub fn file_capture_records(
    workspace: &std::path::Path,
    binary: &str,
    records: &[UnknownRecord],
) -> Result<usize> {
    if records.is_empty() {
        return Ok(0);
    }
    let identity = calxgloss_types::BinaryIdentity::new(binary);
    let ledger_path = calxgloss_types::unknown_ledger_path(workspace, &identity);
    let landed = match calxgloss_types::load_json::<UnknownLedger>(&ledger_path) {
        Ok(ledger) => Some(ledger),
        Err(calxgloss_types::PersistError::NotFound { .. }) => None,
        Err(source) => {
            return Err(anyhow::anyhow!(
                "the unknown ledger is unreadable: {source}"
            ));
        }
    };
    let reopened = match calxgloss_types::load_json::<UnknownResolutions>(
        &calxgloss_types::unknown_resolutions_path(workspace),
    ) {
        Ok(resolutions) => resolutions.reopened,
        Err(_) => Default::default(),
    };
    let mut derived: Vec<UnknownRecord> = Vec::new();
    for record in records {
        if !derived.iter().any(|landed| landed.id == record.id) {
            derived.push(record.clone());
        }
    }
    if let Some(landed_doc) = landed.as_ref() {
        for record in landed_doc.records.iter().flatten() {
            if !derived.iter().any(|mine| mine.id == record.id) {
                derived.push(record.clone());
            }
        }
    }
    let ledger = UnknownLedger::file(
        identity.clone(),
        landed.as_ref(),
        &derived,
        &reopened,
        calxgloss_types::scan::now_unix_secs(),
    );
    let landed_count = ledger.records.as_ref().map_or(0, |records| records.len());
    calxgloss_types::save_json(&ledger_path, &ledger)
        .map_err(|source| anyhow::anyhow!("could not file the unknown ledger: {source}"))?;
    Ok(landed_count)
}

// ============================================================
// internals
// ============================================================

/// The event one raw entry names, read off its evidence at the raw level:
/// a run event's position within its capture, or a dump thread's id.
/// Absent or unshaped evidence leaves the entry nameable only against the
/// capture as a whole.
fn raw_event(raw: &Value) -> Option<u64> {
    let evidence = raw.get("evidence")?;
    evidence
        .get("run_event")
        .and_then(|run| run.get("event_sequence"))
        .and_then(Value::as_u64)
        .or_else(|| {
            evidence
                .get("dump_thread")
                .and_then(|dump| dump.get("thread_id"))
                .and_then(Value::as_u64)
        })
}

/// The event an entry's shaped evidence names: the same position the raw
/// scan reads, from the decoded [`CaptureEvidence`].
fn event_sequence(evidence: &CaptureEvidence) -> u64 {
    match evidence {
        CaptureEvidence::RunEvent { event_sequence, .. } => *event_sequence,
        CaptureEvidence::DumpThread { thread_id, .. } => u64::from(*thread_id),
    }
}

fn refusal_record(
    binary: &str,
    capture_id: &str,
    sequence: Option<u64>,
    export: Option<&str>,
    reason: RefusalReason,
    detail: &str,
) -> UnknownRecord {
    let event = match sequence {
        Some(seq) => format!("#{seq}"),
        None => "capture".to_string(),
    };
    UnknownRecord::derive(
        binary,
        export.map(str::to_string),
        UnknownKind::CaptureRefused,
        UnknownSeverity::Material,
        format!(
            "Why was capture `{capture_id}` event {event} refused by the record-and-replay \
             fold — {reason}: {detail}?"
        ),
        match export {
            Some(export) => format!("A replayable argument vector for `{export}`"),
            None => "A capture event the fold can name against a listed export".to_string(),
        },
        UnknownOrigin::Capture {
            capture_id: capture_id.to_string(),
            event_sequence: sequence,
        },
        calxgloss_types::scan::now_unix_secs(),
    )
}

fn crash_record(
    binary: &str,
    capture_id: &str,
    sequence: u64,
    export: &str,
    detail: &str,
) -> UnknownRecord {
    UnknownRecord::derive(
        binary,
        Some(export.to_string()),
        UnknownKind::CrashReproduction,
        UnknownSeverity::Material,
        format!(
            "What faults at `{export}` under replay — capture `{capture_id}` event #{sequence} \
             replayed to a fault: {detail}?"
        ),
        format!(
            "A baseline expectation that admits the fault at `{export}` on the captured inputs"
        ),
        UnknownOrigin::Capture {
            capture_id: capture_id.to_string(),
            event_sequence: Some(sequence),
        },
        calxgloss_types::scan::now_unix_secs(),
    )
}

/// Raw JSON float scan: any `f32`/`f64` tag under an `arguments` array
/// marks the entry as carrying float values the scalar replay cannot
/// carry — the closed [`ScalarTag`] vocabulary would drop the entry at
/// typed parse time, so the reason is named at the raw level first.
fn raw_has_float(raw: &Value) -> bool {
    fn walk(value: &Value) -> bool {
        match value {
            Value::Object(object) => {
                object
                    .get("tag")
                    .and_then(Value::as_str)
                    .is_some_and(|tag| tag == "f32" || tag == "f64")
                    || object.values().any(walk)
            }
            Value::Array(items) => items.iter().any(walk),
            _ => false,
        }
    }
    raw.get("arguments").is_some_and(walk)
}

/// Decode one captured entry into a [`TestCase`] the signature can hold,
/// its input keys spelled the way the harness consumes them — the
/// signature's own parameter names, `param_1`-style where the signature
/// leaves a parameter unnamed. Its origin is stamped from the entry's own
/// evidence: a run event mines the hook origin naming that capture and
/// position, a dump thread mines the minidump origin naming that digest
/// and thread — the capture's recorded facts, never repurposed stand-ins.
///
/// `None` names `argument-shape-not-in-signature`: wrong arity, or a vector
/// position the signature cannot hold — an integer that does not fit the
/// declared width or signedness, or a tag the parameter type does not speak.
fn decode_case(entry: &CapturedCallEntry, parsed: &ParsedSignature) -> Option<TestCase> {
    if parsed.parameters.len() != entry.arguments.len() {
        return None;
    }
    let mut inputs = Map::new();
    for (index, (argument, parameter)) in entry.arguments.iter().zip(&parsed.parameters).enumerate()
    {
        let name = parameter
            .name
            .clone()
            .filter(|name| !name.is_empty())
            .unwrap_or_else(|| format!("param_{}", index + 1));
        match argument {
            ArgumentDescriptor::Scalar { tag, value } => {
                if !tag_feeds_parameter(*tag, value, parameter) {
                    return None;
                }
                inputs.insert(name, value.clone());
            }
            // A captured pointer becomes a request for a fresh harness
            // allocation holding exactly the captured bytes — the replay
            // never points the target at an address from the captured
            // process. Only a pointer parameter can hold the request.
            ArgumentDescriptor::Pointer {
                bytes,
                captured_size,
                ..
            } => {
                if !parameter.is_pointer {
                    return None;
                }
                let hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
                inputs.insert(
                    name,
                    serde_json::json!({ALLOC_KEY: {"size": captured_size, "bytes": hex}}),
                );
            }
        }
    }
    let origin = match &entry.evidence {
        CaptureEvidence::RunEvent {
            capture_id,
            event_sequence,
        } => CaseOrigin::MinedHook {
            capture_id: capture_id.clone(),
            event_sequence: *event_sequence,
        },
        CaptureEvidence::DumpThread {
            dump_digest,
            thread_id,
        } => CaseOrigin::MinedMinidump {
            dump_digest: dump_digest.clone(),
            thread_id: *thread_id,
        },
    };
    Some(TestCase {
        inputs: Value::Object(inputs),
        expected_return: Value::Null,
        expected_side_effects: Vec::new(),
        expected_api_calls: Vec::new(),
        origin,
    })
}

/// Whether a captured scalar tag can feed the declared parameter: the tag
/// names the parameter's width and signedness directly.
fn tag_feeds_parameter(
    tag: ScalarTag,
    slot: &Value,
    parameter: &crate::ffi::ParameterTypeInfo,
) -> bool {
    if parameter.is_pointer {
        return false;
    }
    let width = match tag {
        ScalarTag::I8 | ScalarTag::U8 => 8,
        ScalarTag::I16 | ScalarTag::U16 => 16,
        ScalarTag::I32 | ScalarTag::U32 => 32,
        ScalarTag::I64 | ScalarTag::U64 => 64,
    };
    let declared = parameter.bit_width.unwrap_or(32);
    if width != declared {
        return false;
    }
    match slot.as_i64() {
        Some(v) => {
            if !parameter.is_signed && v < 0 {
                return false;
            }
            match declared {
                8 => {
                    v >= if parameter.is_signed {
                        i8::MIN as i64
                    } else {
                        0
                    } && v
                        <= if parameter.is_signed {
                            i8::MAX as i64
                        } else {
                            u8::MAX as i64
                        }
                }
                16 => {
                    v >= if parameter.is_signed {
                        i16::MIN as i64
                    } else {
                        0
                    } && v
                        <= if parameter.is_signed {
                            i16::MAX as i64
                        } else {
                            u16::MAX as i64
                        }
                }
                32 => {
                    v >= if parameter.is_signed {
                        i32::MIN as i64
                    } else {
                        0
                    } && v
                        <= if parameter.is_signed {
                            i32::MAX as i64
                        } else {
                            u32::MAX as i64
                        }
                }
                64 => true,
                _ => false,
            }
        }
        None => slot
            .as_u64()
            .is_some_and(|_| declared == 64 && !parameter.is_signed),
    }
}

/// Canonical dedup key: the inputs as a positional value vector in
/// signature order, each parameter resolved through the key spellings its
/// row may carry — the signature's name, the generation's `param_0`-style
/// spelling, the harness's `param_1`-style spelling. Two rows carry one
/// call's inputs; the key spells the values, not the key names.
fn positional_key(inputs: &Value, parsed: &ParsedSignature) -> String {
    let mut vector: Vec<&Value> = Vec::new();
    if let Value::Object(object) = inputs {
        for (index, parameter) in parsed.parameters.iter().enumerate() {
            let spelled = [
                parameter.name.clone().unwrap_or_default(),
                format!("param_{index}"),
                format!("param_{}", index + 1),
            ];
            let value = spelled
                .iter()
                .find_map(|key| object.get(key.as_str()))
                .unwrap_or(&Value::Null);
            vector.push(value);
        }
    }
    serde_json::to_string(&vector).unwrap_or_default()
}

#[cfg(test)]
mod tests;
