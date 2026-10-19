//! Core data model for global-state reference sets.
//!
//! The scan's reading is a per-function list of **access records**: one
//! [`GlobalAccess`] per sighting of a program global in a function's
//! body, naming the global, the evidence statement that carried the
//! reading, and the confidence band it scored on the Evidence scale.
//! [`GlobalStateFinding`] is the tagged union over the two access
//! kinds — the serde `kind` tag spells the read/write distinction in
//! the persisted JSON — and [`GlobalStateResult`] is the whole per-
//! binary document: the findings in scan order plus the derived
//! per-function [`FunctionPurity`] summary, so consumers never
//! recompute whether a function touches globals.

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

/// One global-state finding, whichever access kind it records.
///
/// The union is what the persisted document carries, so one list holds
/// every access for a binary and a consumer reads the shared shape —
/// function, global, evidence, confidence — through the accessors
/// without naming the access kind first. The serde `kind` tag names the
/// kind in the persisted JSON: `global_read` or `global_write`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum GlobalStateFinding {
    /// The function reads the global's value.
    GlobalRead(GlobalAccess),
    /// The function stores through the global.
    GlobalWrite(GlobalAccess),
}

impl GlobalStateFinding {
    /// The function the finding is about.
    pub fn function(&self) -> &str {
        match self {
            GlobalStateFinding::GlobalRead(record) => &record.function,
            GlobalStateFinding::GlobalWrite(record) => &record.function,
        }
    }

    /// The global the function accessed.
    pub fn global(&self) -> &str {
        match self {
            GlobalStateFinding::GlobalRead(record) => &record.global,
            GlobalStateFinding::GlobalWrite(record) => &record.global,
        }
    }

    /// The access statement quoted from the body.
    pub fn evidence(&self) -> &str {
        match self {
            GlobalStateFinding::GlobalRead(record) => &record.evidence,
            GlobalStateFinding::GlobalWrite(record) => &record.evidence,
        }
    }

    /// Confidence in the reading, on the Evidence scale.
    pub fn confidence(&self) -> Confidence {
        match self {
            GlobalStateFinding::GlobalRead(record) => record.confidence,
            GlobalStateFinding::GlobalWrite(record) => record.confidence,
        }
    }

    /// The Rust pattern the access suggests.
    pub fn suggestion(&self) -> &str {
        match self {
            GlobalStateFinding::GlobalRead(record) => &record.suggestion,
            GlobalStateFinding::GlobalWrite(record) => &record.suggestion,
        }
    }

    /// The serde `kind` tag — `global_read` or `global_write` — naming
    /// the access kind the finding records.
    pub fn kind(&self) -> &'static str {
        match self {
            GlobalStateFinding::GlobalRead(_) => "global_read",
            GlobalStateFinding::GlobalWrite(_) => "global_write",
        }
    }

    /// The access kind the finding records, as the domain enum.
    pub fn access_kind(&self) -> AccessKind {
        match self {
            GlobalStateFinding::GlobalRead(_) => AccessKind::Read,
            GlobalStateFinding::GlobalWrite(_) => AccessKind::Write,
        }
    }

    /// What the finding names, spelled for a report row: the global.
    pub fn target(&self) -> String {
        self.global().to_string()
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
/// listing order, and within one function in body order — so two scans
/// of the same program diff cleanly. The purity summary covers every
/// function whose body the scan kept, in listing order; a function the
/// decompiler never produced stays absent, because absence of a body
/// is not evidence of purity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GlobalStateResult {
    /// Provenance of the scan that produced these records.
    pub metadata: ScanMetadata,
    /// Every access record the scan made, grouped by function in
    /// listing order.
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
        assert_eq!(read.access_kind(), AccessKind::Read);
        assert_eq!(write.access_kind(), AccessKind::Write);
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
        let globals: Vec<&str> = result
            .for_function("FUN_18003ab00")
            .map(|finding| finding.global())
            .collect();
        assert_eq!(
            globals,
            vec!["DAT_180064e80", "g_counter"],
            "only the function's own records, in document order"
        );
    }
}
