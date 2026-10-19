//! Core data model for global-state reference sets.
//!
//! The scan's reading is a per-function list of **access records**: one
//! [`GlobalAccess`] per sighting of a program global in a function's
//! body, naming the global, the evidence statement that carried the
//! reading, and the confidence band it scored on the Evidence scale.
//! [`GlobalStateFinding`] is the tagged union over the two access
//! kinds and the cross-function rollup's index record — the serde
//! `kind` tag spells the distinction in the persisted JSON — and
//! [`GlobalStateResult`] is the whole per-binary document: the
//! findings in scan order (per-function records grouped by function
//! in listing order, the shared-globals index records last) plus the
//! derived per-function [`FunctionPurity`] summary, so consumers
//! never recompute whether a function touches globals.

use calxgloss_types::{Confidence, ScanMetadata};
use serde::{Deserialize, Serialize};
use std::fmt;

// ============================================================
// Access kinds
// ============================================================

/// Whether an access reads the global's value or stores through it.
///
/// The distinction is the whole point of the artifact: a consumer
/// deciding translation order or side-effect expectations needs to know
/// which functions *mutate* shared state, not just which mention it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessKind {
    /// The body reads the global's value — a test, a return, a copy.
    Read,
    /// The body stores through the global — an assignment, a compound
    /// `+=`-style store, or an `++`/`--` bump.
    Write,
}

impl AccessKind {
    /// The lowercase label the kind serializes as.
    pub fn label(self) -> &'static str {
        match self {
            AccessKind::Read => "read",
            AccessKind::Write => "write",
        }
    }
}

impl fmt::Display for AccessKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

// ============================================================
// The access record
// ============================================================

/// One access to a program global in one function's body.
///
/// The record is the artifact's atom: it names the function that made
/// the access and the global it touched, quotes the access statement
/// itself as the evidence, and carries the confidence band the reading
/// scored on — an exact `DAT_*` store/load spelling above a shape-only
/// sighting. The read/write distinction lives in the [`GlobalStateFinding`]
/// tag wrapping the record, not in a field, so a persisted record can
/// never disagree with its own tag.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GlobalAccess {
    /// The function whose body makes the access.
    pub function: String,
    /// The global accessed, spelled exactly as the decompiler names it.
    pub global: String,
    /// The access statement quoted from the body — the claim's evidence.
    pub evidence: String,
    /// Confidence in the reading, on the shared 0–100 Evidence scale.
    pub confidence: Confidence,
    /// The Rust pattern the access steers a translation toward.
    pub suggestion: String,
}

// ============================================================
// The finding union
// ============================================================

/// One global-state finding, whichever kind it records.
///
/// The union is what the persisted document carries, so one list holds
/// every access for a binary and a consumer reads the shared shape —
/// function, global, evidence, confidence — through the accessors
/// without naming the access kind first. The serde `kind` tag names the
/// kind in the persisted JSON: `global_read`, `global_write`, or
/// `shared_global` for the rollup's index record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum GlobalStateFinding {
    /// The function reads the global's value.
    GlobalRead(GlobalAccess),
    /// The function stores through the global.
    GlobalWrite(GlobalAccess),
    /// One entry of the shared-globals index: every function that
    /// reads or writes one global, appended after the per-function
    /// records the rollup grouped them from.
    SharedGlobal(SharedGlobalRecord),
}

// ============================================================
// The shared-globals index record
// ============================================================

/// One entry of the shared-globals index: one global, and the
/// functions that read it and write it, separated by access kind.
///
/// The record is the rollup's atom — a cross-function reading derived
/// from the per-function access records over the same kept bodies
/// (the ADR-0027 precedent), not a sighting of its own. It is what
/// the reviewer and the DAG consumer see: who mutates one piece of
/// shared state, and which units touch the same global so ordering
/// can tie them. A global only one function touches still gets an
/// entry — the index is the per-global picture of the binary's
/// shared state; consumers that pair functions skip the degenerate
/// entries themselves.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SharedGlobalRecord {
    /// The global the entry indexes, spelled as the decompiler names it.
    pub global: String,
    /// The functions whose bodies read the global, in listing order,
    /// each named once however often it loaded the value.
    pub readers: Vec<String>,
    /// The functions whose bodies stored through the global, in
    /// listing order, each named once however often it wrote.
    pub writers: Vec<String>,
    /// The highest confidence among the accesses behind the entry —
    /// the rollup adds no reading of its own, so it never scores
    /// above the best access it groups.
    pub confidence: Confidence,
}

impl GlobalStateFinding {
    /// The function the finding is about.
    ///
    /// A rollup record is about a global, not a function, so it names
    /// no single function and answers with the empty string — which
    /// no listing entry ever spells, keeping rollup records out of
    /// every by-function lookup.
    pub fn function(&self) -> &str {
        match self {
            GlobalStateFinding::GlobalRead(record) => &record.function,
            GlobalStateFinding::GlobalWrite(record) => &record.function,
            GlobalStateFinding::SharedGlobal(_) => "",
        }
    }

    /// The global the function accessed.
    pub fn global(&self) -> &str {
        match self {
            GlobalStateFinding::GlobalRead(record) => &record.global,
            GlobalStateFinding::GlobalWrite(record) => &record.global,
            GlobalStateFinding::SharedGlobal(record) => &record.global,
        }
    }

    /// The access statement quoted from the body.
    ///
    /// A rollup record quotes no single statement — its evidence is
    /// the per-function records it groups, which ride in the same
    /// document — so it answers with the empty string.
    pub fn evidence(&self) -> &str {
        match self {
            GlobalStateFinding::GlobalRead(record) => &record.evidence,
            GlobalStateFinding::GlobalWrite(record) => &record.evidence,
            GlobalStateFinding::SharedGlobal(_) => "",
        }
    }

    /// Confidence in the reading, on the Evidence scale.
    pub fn confidence(&self) -> Confidence {
        match self {
            GlobalStateFinding::GlobalRead(record) => record.confidence,
            GlobalStateFinding::GlobalWrite(record) => record.confidence,
            GlobalStateFinding::SharedGlobal(record) => record.confidence,
        }
    }

    /// The Rust pattern the access suggests.
    ///
    /// A rollup record suggests no pattern of its own — the steering
    /// rides on the access records — so it answers with the empty
    /// string.
    pub fn suggestion(&self) -> &str {
        match self {
            GlobalStateFinding::GlobalRead(record) => &record.suggestion,
            GlobalStateFinding::GlobalWrite(record) => &record.suggestion,
            GlobalStateFinding::SharedGlobal(_) => "",
        }
    }

    /// The serde `kind` tag — `global_read`, `global_write`, or
    /// `shared_global` — naming the kind the finding records.
    pub fn kind(&self) -> &'static str {
        match self {
            GlobalStateFinding::GlobalRead(_) => "global_read",
            GlobalStateFinding::GlobalWrite(_) => "global_write",
            GlobalStateFinding::SharedGlobal(_) => "shared_global",
        }
    }

    /// The access kind the finding records, as the domain enum.
    ///
    /// `None` for a rollup record: the entry spans both kinds — its
    /// readers read and its writers write — so it names no single
    /// access kind.
    pub fn access_kind(&self) -> Option<AccessKind> {
        match self {
            GlobalStateFinding::GlobalRead(_) => Some(AccessKind::Read),
            GlobalStateFinding::GlobalWrite(_) => Some(AccessKind::Write),
            GlobalStateFinding::SharedGlobal(_) => None,
        }
    }

    /// The shared-globals index record, when this finding is one.
    ///
    /// The seam for consumers of the rollup — the reviewer's index
    /// section and the DAG's state-sharing edges — who reach the
    /// readers and writers without matching the union by hand.
    pub fn shared_global(&self) -> Option<&SharedGlobalRecord> {
        match self {
            GlobalStateFinding::SharedGlobal(record) => Some(record),
            _ => None,
        }
    }

    /// What the finding names, spelled for a report row: the global.
    pub fn target(&self) -> String {
        self.global().to_string()
    }
}

/// Render an access record as prompt data: the function that made the
/// access, the access kind, the global it touched, the Rust pattern the
/// access steers a translation toward, and the confidence and evidence
/// behind the claim — so the module-context and escalate prompts show
/// the shared state a function touches and how strongly each reading
/// was made, and the translator stops inventing locals for globals.
/// A rollup record renders through the same accessors; its empty
/// function name keeps it out of every by-function lookup, so it never
/// reaches a prompt.
impl From<&GlobalStateFinding> for calxgloss_prompts::GlobalStateInfo {
    fn from(finding: &GlobalStateFinding) -> Self {
        Self {
            function: finding.function().to_string(),
            kind: finding.kind().to_string(),
            global: finding.global().to_string(),
            suggestion: finding.suggestion().to_string(),
            confidence: finding.confidence().value(),
            evidence: finding.evidence().to_string(),
        }
    }
}

// ============================================================
// The derived purity summary
// ============================================================

/// The derived per-function purity summary: what the scan already knows
/// about one function's global traffic, stated so consumers never
/// recompute it.
///
/// A *pure* function touches no program global at all — its reading is
/// the absence of access records for it, made explicit. The flag is
/// what steers a translator holding a function that *does* touch
/// globals to model that state in a struct rather than a Rust
/// `static`; a pure function needs no such steering.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionPurity {
    /// The function the summary describes.
    pub function: String,
    /// Whether the function touches no program global.
    pub is_pure: bool,
    /// How many global reads the function's body recorded.
    pub reads: usize,
    /// How many global writes the function's body recorded.
    pub writes: usize,
}

// ============================================================
// Persisted result
// ============================================================

/// The global-state reference sets for one binary — the document
/// persisted to `re/analysis/globalstate/{binary}.json`.
///
/// The findings follow the function listing — grouped by function in
/// listing order, and within one function in body order — with the
/// shared-globals index records appended after them, in first-sighting
/// order, so two scans of the same program diff cleanly. The purity
/// summary covers every function whose body the scan kept, in listing
/// order; a function the decompiler never produced stays absent,
/// because absence of a body is not evidence of purity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GlobalStateResult {
    /// Provenance of the scan that produced these records.
    pub metadata: ScanMetadata,
    /// Every access record the scan made, grouped by function in
    /// listing order, followed by the shared-globals index records
    /// the rollup derived from them.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub findings: Vec<GlobalStateFinding>,
    /// The derived per-function purity summary, in listing order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub purity: Vec<FunctionPurity>,
}

impl GlobalStateResult {
    /// An empty result for the binary described by `metadata`.
    pub fn new(metadata: ScanMetadata) -> Self {
        Self {
            metadata,
            findings: Vec::new(),
            purity: Vec::new(),
        }
    }

    /// The access records made for one function, e.g. `FUN_18003ab00`.
    ///
    /// The shared-globals index records name no single function, so
    /// they never answer a by-function lookup — a prompt consumer
    /// asking for one function's records reads only its own accesses.
    pub fn for_function(&self, function: &str) -> impl Iterator<Item = &GlobalStateFinding> {
        self.findings
            .iter()
            .filter(move |finding| finding.function() == function)
    }

    /// Whether the scan recorded no global access at all.
    pub fn is_empty(&self) -> bool {
        self.findings.is_empty()
    }
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn access(function: &str, global: &str) -> GlobalAccess {
        GlobalAccess {
            function: function.to_string(),
            global: global.to_string(),
            evidence: "DAT_180064e80 = param_1".to_string(),
            confidence: 85.into(),
            suggestion: "model the global as shared struct state, not a Rust static".to_string(),
        }
    }

    fn shared_index(global: &str, readers: &[&str], writers: &[&str]) -> GlobalStateFinding {
        GlobalStateFinding::SharedGlobal(SharedGlobalRecord {
            global: global.to_string(),
            readers: readers.iter().map(|f| f.to_string()).collect(),
            writers: writers.iter().map(|f| f.to_string()).collect(),
            confidence: 85.into(),
        })
    }

    #[test]
    fn a_global_read_finding_serde_round_trips_under_its_kind_tag() {
        let finding = GlobalStateFinding::GlobalRead(access("FUN_18003ab00", "DAT_180064e80"));
        let json = serde_json::to_string(&finding).expect("a finding serializes");
        assert!(
            json.contains("\"kind\":\"global_read\""),
            "the read tag is spelled in the document: {json}"
        );
        let back: GlobalStateFinding = serde_json::from_str(&json).expect("the tag reads back");
        assert_eq!(back, finding);
    }

    #[test]
    fn a_global_write_finding_serde_round_trips_under_its_kind_tag() {
        let finding = GlobalStateFinding::GlobalWrite(access("FUN_18003ab00", "DAT_180064e80"));
        let json = serde_json::to_string(&finding).expect("a finding serializes");
        assert!(
            json.contains("\"kind\":\"global_write\""),
            "the write tag is spelled in the document: {json}"
        );
        let back: GlobalStateFinding = serde_json::from_str(&json).expect("the tag reads back");
        assert_eq!(back, finding);
    }

    #[test]
    fn a_shared_global_record_serde_round_trips_under_its_kind_tag() {
        let finding = GlobalStateFinding::SharedGlobal(SharedGlobalRecord {
            global: "DAT_180064e80".to_string(),
            readers: vec!["FUN_18003ab00".to_string()],
            writers: vec!["FUN_18003e750".to_string()],
            confidence: 85.into(),
        });
        let json = serde_json::to_string(&finding).expect("an index record serializes");
        assert!(
            json.contains("\"kind\":\"shared_global\""),
            "the rollup tag is spelled in the document: {json}"
        );
        let back: GlobalStateFinding = serde_json::from_str(&json).expect("the tag reads back");
        assert_eq!(back, finding);
    }

    #[test]
    fn the_union_accessors_reach_through_every_variant() {
        for finding in [
            GlobalStateFinding::GlobalRead(access("FUN_18003ab00", "DAT_180064e80")),
            GlobalStateFinding::GlobalWrite(access("FUN_18003ab00", "DAT_180064e80")),
        ] {
            assert_eq!(finding.function(), "FUN_18003ab00");
            assert_eq!(finding.global(), "DAT_180064e80");
            assert_eq!(finding.evidence(), "DAT_180064e80 = param_1");
            assert_eq!(finding.confidence().value(), 85);
            assert!(finding.suggestion().contains("static"));
            assert_eq!(finding.target(), "DAT_180064e80");
        }
        let read = GlobalStateFinding::GlobalRead(access("FUN_1", "g"));
        let write = GlobalStateFinding::GlobalWrite(access("FUN_1", "g"));
        assert_eq!(read.kind(), "global_read");
        assert_eq!(write.kind(), "global_write");
        assert_eq!(read.access_kind(), Some(AccessKind::Read));
        assert_eq!(write.access_kind(), Some(AccessKind::Write));
    }

    #[test]
    fn the_rollup_variant_answers_as_an_index_record_not_an_access() {
        // The rollup record is about a global, not a function: it
        // names no single function, quotes no single statement,
        // suggests no single pattern, and spans both access kinds —
        // so it claims no one kind. The seam accessor hands the entry
        // itself to the consumers that read readers and writers.
        let finding = shared_index("DAT_180064e80", &["FUN_18003ab00"], &["FUN_18003e750"]);
        assert_eq!(finding.function(), "");
        assert_eq!(finding.global(), "DAT_180064e80");
        assert_eq!(finding.evidence(), "");
        assert_eq!(finding.suggestion(), "");
        assert_eq!(finding.confidence().value(), 85);
        assert_eq!(finding.target(), "DAT_180064e80");
        assert_eq!(finding.kind(), "shared_global");
        assert_eq!(finding.access_kind(), None);
        let record = finding.shared_global().expect("the seam reaches the entry");
        assert_eq!(record.readers, vec!["FUN_18003ab00"]);
        assert_eq!(record.writers, vec!["FUN_18003e750"]);
        assert!(
            GlobalStateFinding::GlobalRead(access("FUN_1", "g"))
                .shared_global()
                .is_none()
        );
    }

    #[test]
    fn an_access_record_renders_into_prompt_data() {
        // The prompt seam: an access record carries its whole claim
        // into `GlobalStateInfo` — function, kind tag, global, the
        // steering suggestion the detector wrote, and the confidence
        // and evidence behind it.
        let write = GlobalStateFinding::GlobalWrite(access("FUN_18003ab00", "DAT_180064e80"));
        let info = calxgloss_prompts::GlobalStateInfo::from(&write);
        assert_eq!(info.function, "FUN_18003ab00");
        assert_eq!(info.kind, "global_write");
        assert_eq!(info.global, "DAT_180064e80");
        assert_eq!(
            info.suggestion,
            "model the global as shared struct state, not a Rust static"
        );
        assert_eq!(info.confidence, 85);
        assert_eq!(info.evidence, "DAT_180064e80 = param_1");
    }

    #[test]
    fn access_kinds_display_their_serde_labels() {
        assert_eq!(AccessKind::Read.to_string(), "read");
        assert_eq!(AccessKind::Write.to_string(), "write");
    }

    #[test]
    fn a_purity_record_serde_round_trips() {
        let purity = FunctionPurity {
            function: "FUN_18003ab00".to_string(),
            is_pure: false,
            reads: 2,
            writes: 1,
        };
        let json = serde_json::to_string(&purity).expect("a purity record serializes");
        let back: FunctionPurity = serde_json::from_str(&json).expect("it reads back");
        assert_eq!(back, purity);
    }

    #[test]
    fn a_global_state_result_serde_round_trips() {
        let mut result = GlobalStateResult::new(ScanMetadata::new("eqmain.dll"));
        result.findings.push(GlobalStateFinding::GlobalRead(access(
            "FUN_18003ab00",
            "DAT_180064e80",
        )));
        result.findings.push(GlobalStateFinding::GlobalWrite(access(
            "FUN_18003e750",
            "g_counter",
        )));
        result.findings.push(shared_index(
            "g_counter",
            &["FUN_18003ab00"],
            &["FUN_18003e750"],
        ));
        result.purity.push(FunctionPurity {
            function: "FUN_18003ab00".to_string(),
            is_pure: false,
            reads: 1,
            writes: 0,
        });
        result.purity.push(FunctionPurity {
            function: "FUN_18003e750".to_string(),
            is_pure: false,
            reads: 0,
            writes: 1,
        });
        let json = serde_json::to_string(&result).expect("the document serializes");
        let back: GlobalStateResult = serde_json::from_str(&json).expect("it reads back");
        assert_eq!(back, result);
    }

    #[test]
    fn a_result_without_records_omits_them_and_reads_back_empty() {
        let result = GlobalStateResult::new(ScanMetadata::new("eqmain.dll"));
        let json = serde_json::to_string(&result).expect("an empty document serializes");
        assert!(
            !json.contains("findings") && !json.contains("purity"),
            "empty sections are omitted, not spelled as empty arrays: {json}"
        );
        let back: GlobalStateResult = serde_json::from_str(&json).expect("it reads back");
        assert!(back.is_empty());
        assert!(back.purity.is_empty());
    }

    #[test]
    fn for_function_yields_only_that_function_s_records_in_order() {
        let mut result = GlobalStateResult::new(ScanMetadata::new("eqmain.dll"));
        result.findings.push(GlobalStateFinding::GlobalRead(access(
            "FUN_18003ab00",
            "DAT_180064e80",
        )));
        result.findings.push(GlobalStateFinding::GlobalWrite(access(
            "FUN_18003e750",
            "g_counter",
        )));
        result.findings.push(GlobalStateFinding::GlobalRead(access(
            "FUN_18003ab00",
            "g_counter",
        )));
        result.findings.push(shared_index(
            "g_counter",
            &["FUN_18003ab00"],
            &["FUN_18003e750"],
        ));
        let globals: Vec<&str> = result
            .for_function("FUN_18003ab00")
            .map(|finding| finding.global())
            .collect();
        assert_eq!(
            globals,
            vec!["DAT_180064e80", "g_counter"],
            "only the function's own records, in document order"
        );
        assert!(
            result
                .for_function("FUN_18003ab00")
                .all(|finding| finding.shared_global().is_none()),
            "the rollup record names no single function, so no by-function lookup answers it"
        );
    }
}
