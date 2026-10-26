//! Core data types for known-library identification.
//!
//! This module holds the serialized shape of everything the body-signature
//! matcher produces:
//!
//! - `LibmatchMatch`, `LibraryFamily`: the per-function detection record —
//!   the matched library symbol and its family (CRT/STL), the Rust
//!   equivalent the match suggests, and the confidence and evidence behind
//!   the claim.
//! - `LibmatchFinding`: the finding union — the per-function
//!   body-signature match and the cross-function propagation kinds
//!   (identical-body inheritance, tail-call thunks) — serde-tagged by
//!   `kind`.
//! - `LibmatchResult`, `ScanMetadata`: the persisted per-binary result
//!   and its scan provenance.
//!
//! All types derive `Serialize`/`Deserialize`.

// `ScanMetadata` is the shared per-binary scan provenance and `Confidence`
// the shared 0–100 evidence score; both are re-exported so consumers name
// them through this crate, matching the typesdb, typeinfer, and algorithm
// convention.
pub use calxgloss_types::{Confidence, ScanMetadata};
use serde::{Deserialize, Serialize};

// ============================================================
// Library family
// ============================================================

/// The library family a matched symbol belongs to.
///
/// The family says which body of standard code the matched function came
/// from — the C runtime the compiler statically links, or the C++
/// standard library's template instantiations — so a reviewer (and, later,
/// a translation prompt) knows which Rust equivalent to reach for: CRT
/// memory and string routines map to `std` slices and intrinsics, STL
/// container idioms map to `Vec`/`BTreeMap`/`Rc`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LibraryFamily {
    /// The C runtime: memory and string routines, allocator wrappers,
    /// and their thunks, statically linked from the compiler's CRT.
    Crt,
    /// The C++ standard library: template instantiations — container
    /// tree helpers, allocation adapters — statically linked from the
    /// STL.
    Stl,
}

calxgloss_types::display_serde_label!(LibraryFamily {
    Crt => "crt",
    Stl => "stl",
});

// ============================================================
// Libmatch matches
// ============================================================

/// One known-library identification of one function, with the evidence
/// behind it.
///
/// A match is a hypothesis, not a fact applied to the program (ADR-0020):
/// it says the decompiled body *reads like* the statically linked body of
/// [`symbol`](Self::symbol) from the [`family`](Self::family) library, at
/// the given confidence, with the matched normalized shape kept as
/// [`evidence`](Self::evidence) so a reviewer can check the reasoning.
/// [`suggestion`](Self::suggestion) names the Rust equivalent a
/// translation should map calls onto rather than re-implement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LibmatchMatch {
    /// The function the match is about, e.g. `FUN_18003ab00`.
    pub function: String,
    /// The matched library symbol, e.g. `memcpy`.
    pub symbol: String,
    /// The library family the symbol belongs to.
    pub family: LibraryFamily,
    /// The Rust equivalent the match suggests, e.g. a `std` slice copy
    /// for `memcpy`.
    pub suggestion: String,
    /// Confidence that the match is right, 0–100.
    pub confidence: Confidence,
    /// The decompiled line whose normalized shape carried the signature's
    /// first required pattern — kept so a reviewer can check the
    /// reasoning.
    pub evidence: String,
}

// ============================================================
// Finding union
// ============================================================

/// One known-library finding, whichever pass made it.
///
/// The union is what the persisted result carries: the per-function
/// body-signature match and the cross-function propagation kinds — an
/// identical-body duplicate inheriting a match, a tail-call thunk
/// inheriting at a penalty — all riding the same [`LibmatchMatch`]
/// record, so consumers reading the shared shape (function, kind,
/// target, confidence, evidence) are unaffected by which pass made the
/// finding. The serde `kind` tag names the record shape in the
/// persisted JSON.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum LibmatchFinding {
    /// A built-in or supplied body signature matched the decompiled body.
    BodySignature(LibmatchMatch),
    /// A body whose normalized shape is identical to a matched body —
    /// a linker-folded (COMDAT/ICF) copy of the same routine — which
    /// inherits the match whole, at the matched body's confidence.
    IdenticalBody(LibmatchMatch),
    /// A body whose only statement is a tail call to a matched
    /// function — a thunk or wrapper — which inherits the match at a
    /// confidence penalty.
    TailCallThunk(LibmatchMatch),
}

impl LibmatchFinding {
    /// The match record every variant carries — the finding's shared
    /// shape, whichever pass made it.
    fn record(&self) -> &LibmatchMatch {
        match self {
            LibmatchFinding::BodySignature(record)
            | LibmatchFinding::IdenticalBody(record)
            | LibmatchFinding::TailCallThunk(record) => record,
        }
    }

    /// The function the finding is about.
    pub fn function(&self) -> &str {
        &self.record().function
    }

    /// The matched library symbol, e.g. `memcpy` — what the finding
    /// names, spelled for a report row.
    pub fn target(&self) -> &str {
        &self.record().symbol
    }

    /// The library family the matched symbol belongs to.
    pub fn family(&self) -> LibraryFamily {
        self.record().family
    }

    /// The Rust equivalent the match suggests.
    pub fn suggestion(&self) -> &str {
        &self.record().suggestion
    }

    /// Confidence that the finding is right.
    pub fn confidence(&self) -> Confidence {
        self.record().confidence
    }

    /// The decompiled lines that support the finding.
    pub fn evidence(&self) -> &str {
        &self.record().evidence
    }

    /// The serde `kind` tag — `body_signature`, `identical_body`, or
    /// `tail_call_thunk` — naming the pass behind the finding.
    pub fn kind(&self) -> &'static str {
        match self {
            LibmatchFinding::BodySignature(_) => "body_signature",
            LibmatchFinding::IdenticalBody(_) => "identical_body",
            LibmatchFinding::TailCallThunk(_) => "tail_call_thunk",
        }
    }
}

/// Render a finding as prompt data: the function it identifies, the
/// library symbol it matched, the family that symbol belongs to, the
/// Rust equivalent the match suggests, and the confidence and evidence
/// behind the claim — so a translation prompt naming this function's
/// callees can show the translator what a call is really calling and
/// how strongly that was read.
impl From<&LibmatchFinding> for calxgloss_prompts::LibmatchInfo {
    fn from(finding: &LibmatchFinding) -> Self {
        Self {
            function: finding.function().to_string(),
            symbol: finding.target().to_string(),
            family: finding.family().to_string(),
            suggestion: finding.suggestion().to_string(),
            confidence: finding.confidence().value(),
            evidence: finding.evidence().to_string(),
        }
    }
}

// ============================================================
// Persisted result
// ============================================================

/// The known-library identification result for one binary — the document
/// persisted to `re/analysis/libmatch/{binary}.json`.
///
/// The findings follow the function listing — function by function, and
/// within one function the signature matches in configuration order — so
/// two scans of the same program diff cleanly. Where two signatures claim
/// one function, the scan reports the strongest claim only, standing
/// where that function first appeared.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LibmatchResult {
    /// Provenance of the scan that produced these findings.
    pub metadata: ScanMetadata,
    /// Every finding the scan made, in scan order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub findings: Vec<LibmatchFinding>,
}

impl LibmatchResult {
    /// An empty result for the binary described by `metadata`.
    pub fn new(metadata: ScanMetadata) -> Self {
        Self {
            metadata,
            findings: Vec::new(),
        }
    }

    /// The findings recorded for one function, e.g. `FUN_18003ab00`.
    pub fn for_function(&self, function: &str) -> impl Iterator<Item = &LibmatchFinding> {
        self.findings
            .iter()
            .filter(move |finding| finding.function() == function)
    }

    /// Whether the scan identified nothing at all.
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

    fn matched() -> LibmatchMatch {
        LibmatchMatch {
            function: "FUN_18003ab00".into(),
            symbol: "memcpy".into(),
            family: LibraryFamily::Crt,
            suggestion: "slice copy / std::ptr::copy_nonoverlapping".into(),
            confidence: Confidence::new(60),
            evidence: "  *(undefined8 *)((long)puVar1 + -8) = *(undefined8 *)((long)lVar2 + -8);"
                .into(),
        }
    }

    #[test]
    fn a_libmatch_match_serde_round_trips() {
        let record = matched();
        let json = serde_json::to_string(&record).unwrap();
        // The family serializes snake_case, matching the workspace's
        // serde convention.
        assert!(json.contains("\"family\":\"crt\""));
        assert!(json.contains("\"confidence\":60"));
        let back: LibmatchMatch = serde_json::from_str(&json).unwrap();
        assert_eq!(back, record);
    }

    #[test]
    fn families_display_their_serde_labels() {
        for family in [LibraryFamily::Crt, LibraryFamily::Stl] {
            let label = serde_json::to_value(family).unwrap();
            assert_eq!(family.to_string(), label.as_str().unwrap());
        }
    }

    #[test]
    fn a_finding_serde_round_trips_tagged_by_kind() {
        let finding = LibmatchFinding::BodySignature(matched());
        let json = serde_json::to_string(&finding).unwrap();
        assert!(json.contains("\"kind\":\"body_signature\""));
        let back: LibmatchFinding = serde_json::from_str(&json).unwrap();
        assert_eq!(back, finding);
    }

    #[test]
    fn propagated_findings_serde_round_trip_tagged_by_kind() {
        for (finding, kind) in [
            (LibmatchFinding::IdenticalBody(matched()), "identical_body"),
            (LibmatchFinding::TailCallThunk(matched()), "tail_call_thunk"),
        ] {
            let json = serde_json::to_string(&finding).unwrap();
            assert!(json.contains(&format!("\"kind\":\"{kind}\"")));
            let back: LibmatchFinding = serde_json::from_str(&json).unwrap();
            assert_eq!(back, finding);
        }
    }

    #[test]
    fn finding_accessors_read_the_shared_shape() {
        let finding = LibmatchFinding::BodySignature(matched());
        assert_eq!(finding.function(), "FUN_18003ab00");
        assert_eq!(finding.target(), "memcpy");
        assert_eq!(finding.family(), LibraryFamily::Crt);
        assert_eq!(finding.confidence(), Confidence::new(60));
        assert_eq!(finding.kind(), "body_signature");
        assert!(finding.evidence().contains("= *(undefined8"));
    }

    #[test]
    fn a_finding_renders_as_prompt_data_with_its_evidence() {
        let info =
            calxgloss_prompts::LibmatchInfo::from(&LibmatchFinding::BodySignature(matched()));
        assert_eq!(info.function, "FUN_18003ab00");
        assert_eq!(info.symbol, "memcpy");
        // The family reaches the prompt as its serde label — the same
        // spelling the persisted document carries.
        assert_eq!(info.family, "crt");
        assert_eq!(
            info.suggestion,
            "slice copy / std::ptr::copy_nonoverlapping"
        );
        assert_eq!(info.confidence, 60);
        assert!(info.evidence.contains("= *(undefined8"));
    }

    #[test]
    fn a_libmatch_result_serde_round_trips() {
        let result = LibmatchResult {
            metadata: ScanMetadata {
                binary: "eqmain.dll".into(),
                scanned_at: 1_759_488_000,
                duration_secs: 12,
                engine: None,
                coverage: None,
            },
            findings: vec![LibmatchFinding::BodySignature(matched())],
        };
        let json = serde_json::to_string(&result).unwrap();
        let back: LibmatchResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back, result);
    }

    #[test]
    fn a_result_without_findings_omits_them_and_reads_back_empty() {
        // Documents persisted before a match landed still load, and an
        // empty scan stays small on disk.
        let result = LibmatchResult::new(ScanMetadata::new("eqmain.dll"));
        let json = serde_json::to_string(&result).unwrap();
        assert!(!json.contains("\"findings\""));
        let back: LibmatchResult = serde_json::from_str(&json).unwrap();
        assert!(back.is_empty());
        assert_eq!(back.metadata.binary, "eqmain.dll");
    }

    #[test]
    fn for_function_yields_only_that_function_s_findings_in_order() {
        let other = LibmatchMatch {
            function: "FUN_18003e750".into(),
            ..matched()
        };
        let result = LibmatchResult {
            metadata: ScanMetadata::new("eqmain.dll"),
            findings: vec![
                LibmatchFinding::BodySignature(matched()),
                LibmatchFinding::BodySignature(other.clone()),
            ],
        };
        let found: Vec<&LibmatchFinding> = result.for_function("FUN_18003e750").collect();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].function(), "FUN_18003e750");
        assert!(result.for_function("FUN_180099999").next().is_none());
        assert!(!result.is_empty());
    }
}
