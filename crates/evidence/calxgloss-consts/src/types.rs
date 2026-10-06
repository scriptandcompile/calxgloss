//! Core data types for constant and enum information.
//!
//! This module holds the serialized shape of everything the constant
//! detectors produce:
//!
//! - `BitflagGroup`: the per-function flag-group record — the distinct
//!   bits a function combines through bitwise operations, and the
//!   bitflags-style struct they suggest.
//! - `EnumCandidate`: the per-function enumerated-dispatch record — a
//!   run of contiguous switch case values, and the Rust `enum` it
//!   suggests.
//! - `NamedConstant`: the program-level repeated-value record — an
//!   integer literal used across several functions often enough to
//!   deserve a name, and the `const` it suggests.
//! - `ConstFinding`: the union over the three record kinds — one
//!   finding whichever detector made it — serde-tagged by `kind`.
//! - `ConstResult`, `ScanMetadata`: the persisted per-binary result and
//!   its scan provenance.
//!
//! All types derive `Serialize`/`Deserialize`.

// `ScanMetadata` is the shared per-binary scan provenance and `Confidence`
// the shared 0–100 evidence score; both are re-exported so consumers name
// them through this crate, matching the typesdb, typeinfer, algorithm, and
// memory convention.
pub use calxgloss_types::{Confidence, ScanMetadata};
use serde::{Deserialize, Serialize};

// ============================================================
// Bitflag groups
// ============================================================

/// One bitflag-group observation about one function, with the evidence
/// behind it.
///
/// A group says the function combines a set of distinct single-bit
/// values — [`bits`](Self::bits), the bit positions seen — through
/// bitwise operations, the shape a flags field takes. The bits are
/// what a `bitflags!`-style struct would name, and
/// [`suggestion`](Self::suggestion) spells the struct out at the
/// integer width the highest bit fits; [`mask`](Self::mask) is the
/// union of the bits and [`bit_width`](Self::bit_width) the position
/// count they span. The bitwise lines are kept as
/// [`evidence`](Self::evidence) so a reviewer (or a translation
/// prompt) can check the reasoning.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BitflagGroup {
    /// The function the record is about, e.g. `FUN_18003ab00`.
    pub function: String,
    /// The distinct bit positions combined in the function, ascending.
    pub bits: Vec<u32>,
    /// The union of the bits, e.g. `0x500` for bits 8 and 10.
    pub mask: u64,
    /// The bit count the highest observed bit spans, e.g. 11.
    pub bit_width: u32,
    /// The Rust shape the group suggests, e.g. a `bitflags!` struct.
    pub suggestion: String,
    /// Confidence that the record is right, 0–100.
    pub confidence: Confidence,
    /// The decompiled lines that support the record — the bitwise
    /// operations — kept so a reviewer (or a translation prompt) can
    /// check the reasoning.
    pub evidence: String,
}

// ============================================================
// Enum candidates
// ============================================================

/// One enumerated-dispatch observation about one function, with the
/// evidence behind it.
///
/// A candidate says the function dispatches on a `switch` whose case
/// values include a contiguous ascending run —
/// [`values`](Self::values), the run, and [`count`](Self::count) its
/// length — the shape an enumerated state takes when the compiler
/// lowers it to a jump table. A run reads like
/// [`suggestion`](Self::suggestion) — a Rust `enum` with one variant
/// per value. The case lines are kept as [`evidence`](Self::evidence)
/// so a reviewer (or a translation prompt) can check the reasoning.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnumCandidate {
    /// The function the record is about, e.g. `FUN_18003ab00`.
    pub function: String,
    /// The contiguous ascending case values of the run, ascending.
    pub values: Vec<i64>,
    /// The length of the run.
    pub count: usize,
    /// The Rust shape the run suggests, e.g. an `enum`.
    pub suggestion: String,
    /// Confidence that the record is right, 0–100.
    pub confidence: Confidence,
    /// The decompiled lines that support the record — the case labels
    /// of the run — kept so a reviewer (or a translation prompt) can
    /// check the reasoning.
    pub evidence: String,
}

// ============================================================
// Named constants
// ============================================================

/// One repeated-value observation about the whole program, with the
/// evidence behind it.
///
/// A record says one integer literal — [`value`](Self::value) — is
/// used [`count`](Self::count) times across the program, in the
/// functions listed in [`functions`](Self::functions), often enough
/// and spread wide enough that the value is a named constant rather
/// than a situational literal. It reads like
/// [`suggestion`](Self::suggestion) — a named `const` standing in for
/// the repeated literal. The usage summary is kept as
/// [`evidence`](Self::evidence) so a reviewer (or a translation
/// prompt) can check the reasoning.
///
/// Unlike the other two records this one is program-level: it belongs
/// to every function that uses the value, not to a single one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NamedConstant {
    /// The repeated literal's value, e.g. `0x400`.
    pub value: u64,
    /// How many times the value is used across the program.
    pub count: usize,
    /// The functions that use the value, ascending.
    pub functions: Vec<String>,
    /// The Rust shape the value suggests, e.g. a named `const`.
    pub suggestion: String,
    /// Confidence that the record is right, 0–100.
    pub confidence: Confidence,
    /// The usage summary that supports the record — the value's count
    /// and the functions it appears in — kept so a reviewer (or a
    /// translation prompt) can check the reasoning.
    pub evidence: String,
}

// ============================================================
// Finding union
// ============================================================

/// One constant finding, whichever detector made it.
///
/// The detectors emit the concrete records; the union is what the
/// persisted result carries, so one list can hold every finding for a
/// binary and a consumer reads the shared shape — function,
/// suggestion, confidence, evidence — without naming which detector
/// produced it. Like sync's disjoint families, the three detectors
/// read different shapes and make no competing claims, so nothing is
/// resolved between variants. The serde `kind` tag names the record
/// shape in the persisted JSON.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ConstFinding {
    /// A set of distinct bits combined through bitwise operations.
    BitflagGroup(BitflagGroup),
    /// A contiguous run of switch case values.
    EnumCandidate(EnumCandidate),
    /// A literal repeated across the program.
    NamedConstant(NamedConstant),
}

impl ConstFinding {
    /// The function the finding is about — empty for a program-level
    /// named constant, which belongs to every function that uses the
    /// value (see [`ConstResult::for_function`]).
    pub fn function(&self) -> &str {
        match self {
            ConstFinding::BitflagGroup(record) => &record.function,
            ConstFinding::EnumCandidate(record) => &record.function,
            ConstFinding::NamedConstant(_) => "",
        }
    }

    /// The Rust shape the finding suggests.
    pub fn suggestion(&self) -> &str {
        match self {
            ConstFinding::BitflagGroup(record) => &record.suggestion,
            ConstFinding::EnumCandidate(record) => &record.suggestion,
            ConstFinding::NamedConstant(record) => &record.suggestion,
        }
    }

    /// Confidence that the finding is right.
    pub fn confidence(&self) -> Confidence {
        match self {
            ConstFinding::BitflagGroup(record) => record.confidence,
            ConstFinding::EnumCandidate(record) => record.confidence,
            ConstFinding::NamedConstant(record) => record.confidence,
        }
    }

    /// The decompiled lines (or usage summary) that support the finding.
    pub fn evidence(&self) -> &str {
        match self {
            ConstFinding::BitflagGroup(record) => &record.evidence,
            ConstFinding::EnumCandidate(record) => &record.evidence,
            ConstFinding::NamedConstant(record) => &record.evidence,
        }
    }

    /// The serde `kind` tag — `bitflag_group`, `enum_candidate`, or
    /// `named_constant` — naming the detector behind the finding.
    pub fn kind(&self) -> &'static str {
        match self {
            ConstFinding::BitflagGroup(_) => "bitflag_group",
            ConstFinding::EnumCandidate(_) => "enum_candidate",
            ConstFinding::NamedConstant(_) => "named_constant",
        }
    }

    /// What the finding names, spelled for a report row: the group's
    /// bit mask, the run's value range, or the repeated value.
    pub fn target(&self) -> String {
        match self {
            ConstFinding::BitflagGroup(record) => format!("{:#x}", record.mask),
            ConstFinding::EnumCandidate(record) => {
                format!("{}..={}", record.values[0], record.values[record.count - 1])
            }
            ConstFinding::NamedConstant(record) => format!("{:#x}", record.value),
        }
    }
}

// ============================================================
// Prompt conversions
// ============================================================

/// Render a finding as prompt data: the function it is about, the kind
/// of constant structure the detector read, the Rust shape the finding
/// suggests, and the confidence and evidence behind the claim — so the
/// escalate prompt shows the hypothesis and how strongly it was made,
/// whichever detector produced it.
impl From<&ConstFinding> for calxgloss_prompts::ConstInfo {
    fn from(finding: &ConstFinding) -> Self {
        Self {
            function: finding.function().to_string(),
            kind: finding.kind().to_string(),
            suggestion: finding.suggestion().to_string(),
            confidence: finding.confidence().value(),
            evidence: finding.evidence().to_string(),
        }
    }
}

// ============================================================
// Persisted result
// ============================================================

/// The constant result for one binary — the document persisted to
/// `re/analysis/consts/{dll}.json`.
///
/// The findings are the three detectors' outputs in scan order:
/// function by function the bitmask groups then the enum candidates,
/// and after the per-function findings the program-level named
/// constants the frequency analyzer tallied across the whole pass. The
/// stable order means two scans of the same program diff cleanly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConstResult {
    /// Provenance of the scan that produced these findings.
    pub metadata: ScanMetadata,
    /// Every finding the detectors made, in scan order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub findings: Vec<ConstFinding>,
}

impl ConstResult {
    /// An empty result for the binary described by `metadata`.
    pub fn new(metadata: ScanMetadata) -> Self {
        Self {
            metadata,
            findings: Vec::new(),
        }
    }

    /// The findings recorded for one function, e.g. `FUN_18003ab00`.
    ///
    /// A program-level named constant belongs to every function that
    /// uses its value, so it is yielded for each of them — the
    /// per-function view a translation prompt reads.
    pub fn for_function(&self, function: &str) -> impl Iterator<Item = &ConstFinding> {
        self.findings
            .iter()
            .filter(move |finding| match &**finding {
                ConstFinding::BitflagGroup(record) => record.function == function,
                ConstFinding::EnumCandidate(record) => record.function == function,
                ConstFinding::NamedConstant(record) => {
                    record.functions.iter().any(|f| f == function)
                }
            })
    }

    /// Whether the scan found nothing at all.
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

    fn bitflag_group() -> BitflagGroup {
        BitflagGroup {
            function: "FUN_18003ab00".into(),
            bits: vec![8, 10],
            mask: 0x500,
            bit_width: 11,
            suggestion: "bitflags! struct Flags: u32 { /* bits: 0x100, 0x400 */ }".into(),
            confidence: Confidence::new(70),
            evidence: "if ((uVar1 & 0x400) != 0) { uVar1 |= 0x100; }".into(),
        }
    }

    fn enum_candidate() -> EnumCandidate {
        EnumCandidate {
            function: "FUN_18003ab00".into(),
            values: vec![0, 1, 2, 3],
            count: 4,
            suggestion: "enum State { /* variants for 0..=3 */ }".into(),
            confidence: Confidence::new(70),
            evidence: "case 0: case 1: case 2: case 3:".into(),
        }
    }

    fn named_constant() -> NamedConstant {
        NamedConstant {
            value: 0x400,
            count: 5,
            functions: vec!["FUN_18003ab00".into(), "FUN_18003e750".into()],
            suggestion: "const VALUE_0x400: u32 = 0x400;".into(),
            confidence: Confidence::new(60),
            evidence: "0x400 used 5 times in FUN_18003ab00, FUN_18003e750".into(),
        }
    }

    #[test]
    fn a_bitflag_group_serde_round_trips() {
        let record = bitflag_group();
        let json = serde_json::to_string(&record).unwrap();
        assert!(json.contains("\"bits\":[8,10]"));
        assert!(json.contains("\"confidence\":70"));
        let back: BitflagGroup = serde_json::from_str(&json).unwrap();
        assert_eq!(back, record);
    }

    #[test]
    fn an_enum_candidate_serde_round_trips() {
        let record = enum_candidate();
        let json = serde_json::to_string(&record).unwrap();
        assert!(json.contains("\"values\":[0,1,2,3]"));
        let back: EnumCandidate = serde_json::from_str(&json).unwrap();
        assert_eq!(back, record);
    }

    #[test]
    fn a_named_constant_serde_round_trips() {
        let record = named_constant();
        let json = serde_json::to_string(&record).unwrap();
        assert!(json.contains("\"value\":1024"));
        assert!(json.contains("\"confidence\":60"));
        let back: NamedConstant = serde_json::from_str(&json).unwrap();
        assert_eq!(back, record);
    }

    #[test]
    fn a_bitflag_finding_serde_round_trips_under_its_kind_tag() {
        let finding = ConstFinding::BitflagGroup(bitflag_group());
        let json = serde_json::to_string(&finding).expect("bitflag finding should serialize");
        assert!(json.contains("\"kind\":\"bitflag_group\""));
        assert!(json.contains("\"mask\":1280"));
        let back: ConstFinding =
            serde_json::from_str(&json).expect("bitflag finding should read back");
        assert_eq!(back, finding);
    }

    #[test]
    fn an_enum_finding_serde_round_trips_under_its_kind_tag() {
        let finding = ConstFinding::EnumCandidate(enum_candidate());
        let json = serde_json::to_string(&finding).expect("enum finding should serialize");
        assert!(json.contains("\"kind\":\"enum_candidate\""));
        let back: ConstFinding =
            serde_json::from_str(&json).expect("enum finding should read back");
        assert_eq!(back, finding);
    }

    #[test]
    fn a_named_constant_finding_serde_round_trips_under_its_kind_tag() {
        let finding = ConstFinding::NamedConstant(named_constant());
        let json =
            serde_json::to_string(&finding).expect("named-constant finding should serialize");
        assert!(json.contains("\"kind\":\"named_constant\""));
        let back: ConstFinding =
            serde_json::from_str(&json).expect("named-constant finding should read back");
        assert_eq!(back, finding);
    }

    #[test]
    fn the_union_accessors_reach_through_every_variant() {
        let findings = [
            ConstFinding::BitflagGroup(bitflag_group()),
            ConstFinding::EnumCandidate(enum_candidate()),
            ConstFinding::NamedConstant(named_constant()),
        ];
        let kinds: Vec<&str> = findings.iter().map(|f| f.kind()).collect();
        assert_eq!(
            kinds,
            vec!["bitflag_group", "enum_candidate", "named_constant"]
        );
        let targets: Vec<String> = findings.iter().map(|f| f.target()).collect();
        assert_eq!(targets, vec!["0x500", "0..=3", "0x400"]);
        for finding in &findings {
            assert!(!finding.suggestion().is_empty());
            assert!(!finding.evidence().is_empty());
        }
        assert_eq!(findings[0].function(), "FUN_18003ab00");
        assert_eq!(findings[1].function(), "FUN_18003ab00");
        assert_eq!(findings[2].function(), "");
        assert_eq!(findings[2].confidence(), Confidence::new(60));
    }

    #[test]
    fn a_const_result_serde_round_trips() {
        let result = ConstResult {
            metadata: ScanMetadata {
                binary: "eqmain.dll".into(),
                scanned_at: 1_759_488_000,
                duration_secs: 12,
            },
            findings: vec![
                ConstFinding::BitflagGroup(bitflag_group()),
                ConstFinding::EnumCandidate(enum_candidate()),
                ConstFinding::NamedConstant(named_constant()),
            ],
        };
        let json = serde_json::to_string(&result).expect("const result should serialize");
        let back: ConstResult = serde_json::from_str(&json).expect("const result should read back");
        assert_eq!(back, result);
    }

    #[test]
    fn a_result_without_findings_omits_them_and_reads_back_empty() {
        let result = ConstResult::new(ScanMetadata::new("eqmain.dll"));
        let json = serde_json::to_string(&result).expect("empty const result should serialize");
        assert!(!json.contains("\"findings\""));
        let back: ConstResult =
            serde_json::from_str(&json).expect("empty const result should read back");
        assert!(back.is_empty());
        assert_eq!(back.metadata.binary, "eqmain.dll");
    }

    #[test]
    fn for_function_yields_per_function_findings_and_named_constants_that_use_it() {
        let other = ConstFinding::BitflagGroup(BitflagGroup {
            function: "FUN_18003e750".into(),
            ..bitflag_group()
        });
        let named = ConstFinding::NamedConstant(NamedConstant {
            functions: vec!["FUN_18003e750".into()],
            ..named_constant()
        });
        let unrelated = ConstFinding::EnumCandidate(EnumCandidate {
            function: "FUN_180099999".into(),
            ..enum_candidate()
        });
        let result = ConstResult {
            metadata: ScanMetadata::new("eqmain.dll"),
            findings: vec![other.clone(), named.clone(), unrelated],
        };
        let found: Vec<&ConstFinding> = result.for_function("FUN_18003e750").collect();
        assert_eq!(found, vec![&other, &named]);
        assert!(result.for_function("FUN_180099998").next().is_none());
        assert!(!result.is_empty());
    }

    #[test]
    fn a_finding_renders_into_prompt_data_whichever_kind_it_is() {
        let bitflag = ConstFinding::BitflagGroup(bitflag_group());
        let info = calxgloss_prompts::ConstInfo::from(&bitflag);
        assert_eq!(info.function, "FUN_18003ab00");
        assert_eq!(info.kind, "bitflag_group");
        assert_eq!(info.confidence, 70);

        let enum_candidate = ConstFinding::EnumCandidate(enum_candidate());
        let info = calxgloss_prompts::ConstInfo::from(&enum_candidate);
        assert_eq!(info.kind, "enum_candidate");
        assert_eq!(info.confidence, 70);

        let named = ConstFinding::NamedConstant(named_constant());
        let info = calxgloss_prompts::ConstInfo::from(&named);
        assert_eq!(info.kind, "named_constant");
        assert_eq!(info.confidence, 60);
        assert_eq!(info.suggestion, "const VALUE_0x400: u32 = 0x400;");
    }
}
