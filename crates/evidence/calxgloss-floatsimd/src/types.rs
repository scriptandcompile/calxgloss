//! Core data model for float/SIMD usage flags.
//!
//! The scan's reading is a per-function list of **flag records**: one
//! [`FloatsimdRecord`] per function whose kept body carries float
//! evidence, naming the shape that evidence spells — scalar float math,
//! vector/matrix idioms, or both — the strongest evidence line the
//! reading rested on, and the confidence band that family scored on the
//! Evidence scale. [`FloatsimdFinding`] is the tagged union over the
//! three shapes — the serde `kind` tag spells the distinction in the
//! persisted JSON — and [`FloatsimdResult`] is the whole per-binary
//! document: the flags in scan order, one per flagged function in
//! listing order, so consumers never re-derive which functions do
//! float math.

use calxgloss_types::{Confidence, ScanMetadata};
use serde::{Deserialize, Serialize};
use std::fmt;

// ============================================================
// Shapes
// ============================================================

/// The float shape a function's body evidence spells.
///
/// The distinction is the whole point of the artifact: a translator
/// reading a mangled body has to know which Rust shape to reach for —
/// plain `f32`/`f64` operations for scalar float math, component
/// arrays or small vector structs for vector/matrix idioms — and a
/// reviewer triaging mistranslations wants to know which bodies the
/// decompiler mangled worst.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShapeKind {
    /// Scalar float math: explicit `float`/`double` evidence or CRT
    /// math calls over ordinary scalars.
    ScalarFloat,
    /// Vector/matrix idioms: `CONCAT44`/`SUB4`-style assembly shapes
    /// or parallel component (x/y/z) reads.
    VectorMatrix,
    /// Both shapes in one body — scalar and vector float evidence
    /// side by side, reported as one flag naming both.
    Mixed,
}

impl ShapeKind {
    /// The spelled-out label the flag carries into reports.
    pub fn label(self) -> &'static str {
        match self {
            ShapeKind::ScalarFloat => "scalar float",
            ShapeKind::VectorMatrix => "vector/matrix",
            ShapeKind::Mixed => "mixed",
        }
    }
}

impl fmt::Display for ShapeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

// ============================================================
// The flag record
// ============================================================

/// One function's float/SIMD usage flag.
///
/// The record is the artifact's atom: it names the flagged function,
/// quotes the strongest evidence line the reading rested on, and
/// carries the confidence band that evidence family scored on — an
/// explicit `float` token above a CRT math call above a vector
/// assembly idiom above a component triplet. The shape distinction
/// lives in the [`FloatsimdFinding`] tag wrapping the record, not in a
/// field, so a persisted record can never disagree with its own tag.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FloatsimdRecord {
    /// The function whose body carries the float evidence.
    pub function: String,
    /// The strongest evidence line quoted from the body — the claim's
    /// evidence.
    pub evidence: String,
    /// Confidence in the reading, on the shared 0–100 Evidence scale.
    pub confidence: Confidence,
    /// The Rust shape the flag steers a translation toward.
    pub suggestion: String,
}

// ============================================================
// The finding union
// ============================================================

/// One float/SIMD usage finding, whichever shape it records.
///
/// The union is what the persisted document carries, so one list holds
/// every flag for a binary and a consumer reads the shared shape —
/// function, evidence, confidence — through the accessors without
/// naming the shape first. The serde `kind` tag names the shape in
/// the persisted JSON: `scalar_float`, `vector_matrix`, or `mixed`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FloatsimdFinding {
    /// The body's float evidence spells scalar float math.
    ScalarFloat(FloatsimdRecord),
    /// The body's float evidence spells vector/matrix idioms.
    VectorMatrix(FloatsimdRecord),
    /// The body carries both shapes — one flag naming both, not two
    /// flags the consumer has to fold back together.
    Mixed(FloatsimdRecord),
}

impl FloatsimdFinding {
    /// The function the finding is about.
    pub fn function(&self) -> &str {
        match self {
            FloatsimdFinding::ScalarFloat(record)
            | FloatsimdFinding::VectorMatrix(record)
            | FloatsimdFinding::Mixed(record) => &record.function,
        }
    }

    /// The strongest evidence line quoted from the body.
    pub fn evidence(&self) -> &str {
        match self {
            FloatsimdFinding::ScalarFloat(record)
            | FloatsimdFinding::VectorMatrix(record)
            | FloatsimdFinding::Mixed(record) => &record.evidence,
        }
    }

    /// Confidence in the reading, on the Evidence scale — the band of
    /// the strongest evidence family the body fired.
    pub fn confidence(&self) -> Confidence {
        match self {
            FloatsimdFinding::ScalarFloat(record)
            | FloatsimdFinding::VectorMatrix(record)
            | FloatsimdFinding::Mixed(record) => record.confidence,
        }
    }

    /// The Rust shape the flag suggests.
    pub fn suggestion(&self) -> &str {
        match self {
            FloatsimdFinding::ScalarFloat(record)
            | FloatsimdFinding::VectorMatrix(record)
            | FloatsimdFinding::Mixed(record) => &record.suggestion,
        }
    }

    /// The serde `kind` tag — `scalar_float`, `vector_matrix`, or
    /// `mixed` — naming the shape the finding records.
    pub fn kind(&self) -> &'static str {
        match self {
            FloatsimdFinding::ScalarFloat(_) => "scalar_float",
            FloatsimdFinding::VectorMatrix(_) => "vector_matrix",
            FloatsimdFinding::Mixed(_) => "mixed",
        }
    }

    /// The shape the finding records, as the domain enum.
    pub fn shape(&self) -> ShapeKind {
        match self {
            FloatsimdFinding::ScalarFloat(_) => ShapeKind::ScalarFloat,
            FloatsimdFinding::VectorMatrix(_) => ShapeKind::VectorMatrix,
            FloatsimdFinding::Mixed(_) => ShapeKind::Mixed,
        }
    }

    /// What the finding names, spelled for a report row: the shape.
    pub fn target(&self) -> String {
        self.shape().label().to_string()
    }
}

/// Render a flag record as prompt data: the flagged function, the
/// shape kind, the Rust shape the flag steers a translation toward,
/// and the confidence and evidence behind the claim — so the
/// module-context and escalate prompts show that mangled pseudo-C in
/// that body likely represents float math, and the translator stops
/// reading it as integer or pointer logic.
impl From<&FloatsimdFinding> for calxgloss_prompts::FloatsimdInfo {
    fn from(finding: &FloatsimdFinding) -> Self {
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

/// The float/SIMD usage flags for one binary — the document persisted
/// to `re/analysis/floatsimd/{binary}.json`.
///
/// The flags follow the function listing — one record per flagged
/// function in listing order — so two scans of the same program diff
/// cleanly. A function the decompiler never produced stays absent,
/// because absence of a body is not evidence of integer-only math.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FloatsimdResult {
    /// Provenance of the scan that produced these flags.
    pub metadata: ScanMetadata,
    /// Every flag the scan made, one per flagged function, in listing
    /// order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub findings: Vec<FloatsimdFinding>,
}

impl FloatsimdResult {
    /// An empty result for the binary described by `metadata`.
    pub fn new(metadata: ScanMetadata) -> Self {
        Self {
            metadata,
            findings: Vec::new(),
        }
    }

    /// The flag made for one function, e.g. `FUN_18003ab00`.
    ///
    /// The scan makes at most one flag per function, so the lookup
    /// answers zero or one.
    pub fn for_function(&self, function: &str) -> impl Iterator<Item = &FloatsimdFinding> {
        self.findings
            .iter()
            .filter(move |finding| finding.function() == function)
    }

    /// Whether the scan flagged no function at all.
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

    fn record(function: &str) -> FloatsimdRecord {
        FloatsimdRecord {
            function: function.to_string(),
            evidence: "local_10 = CONCAT44(uVar2 >> 4, uVar2 & 0xfffffff);".to_string(),
            confidence: 60.into(),
            suggestion: "translate as a small vector struct or component array, not integer or \
                         pointer arithmetic"
                .to_string(),
        }
    }

    #[test]
    fn a_scalar_float_finding_serde_round_trips_under_its_kind_tag() {
        let finding = FloatsimdFinding::ScalarFloat(record("FUN_18003ab00"));
        let json = serde_json::to_string(&finding).expect("a finding serializes");
        assert!(
            json.contains("\"kind\":\"scalar_float\""),
            "the scalar shape tag is spelled in the document: {json}"
        );
        let back: FloatsimdFinding = serde_json::from_str(&json).expect("the tag reads back");
        assert_eq!(back, finding);
    }

    #[test]
    fn a_vector_matrix_finding_serde_round_trips_under_its_kind_tag() {
        let finding = FloatsimdFinding::VectorMatrix(record("FUN_18003ab00"));
        let json = serde_json::to_string(&finding).expect("a finding serializes");
        assert!(
            json.contains("\"kind\":\"vector_matrix\""),
            "the vector shape tag is spelled in the document: {json}"
        );
        let back: FloatsimdFinding = serde_json::from_str(&json).expect("the tag reads back");
        assert_eq!(back, finding);
    }

    #[test]
    fn a_mixed_finding_serde_round_trips_under_its_kind_tag() {
        let finding = FloatsimdFinding::Mixed(record("FUN_18003ab00"));
        let json = serde_json::to_string(&finding).expect("a finding serializes");
        assert!(
            json.contains("\"kind\":\"mixed\""),
            "the mixed shape tag is spelled in the document: {json}"
        );
        let back: FloatsimdFinding = serde_json::from_str(&json).expect("the tag reads back");
        assert_eq!(back, finding);
    }

    #[test]
    fn the_union_accessors_reach_through_every_variant() {
        for finding in [
            FloatsimdFinding::ScalarFloat(record("FUN_18003ab00")),
            FloatsimdFinding::VectorMatrix(record("FUN_18003ab00")),
            FloatsimdFinding::Mixed(record("FUN_18003ab00")),
        ] {
            assert_eq!(finding.function(), "FUN_18003ab00");
            assert_eq!(
                finding.evidence(),
                "local_10 = CONCAT44(uVar2 >> 4, uVar2 & 0xfffffff);"
            );
            assert_eq!(finding.confidence().value(), 60);
            assert!(finding.suggestion().contains("component array"));
        }
        let scalar = FloatsimdFinding::ScalarFloat(record("FUN_1"));
        let vector = FloatsimdFinding::VectorMatrix(record("FUN_1"));
        let mixed = FloatsimdFinding::Mixed(record("FUN_1"));
        assert_eq!(scalar.kind(), "scalar_float");
        assert_eq!(vector.kind(), "vector_matrix");
        assert_eq!(mixed.kind(), "mixed");
        assert_eq!(scalar.shape(), ShapeKind::ScalarFloat);
        assert_eq!(vector.shape(), ShapeKind::VectorMatrix);
        assert_eq!(mixed.shape(), ShapeKind::Mixed);
    }

    #[test]
    fn the_shape_names_what_a_report_row_is_about() {
        assert_eq!(
            FloatsimdFinding::ScalarFloat(record("FUN_1")).target(),
            "scalar float"
        );
        assert_eq!(
            FloatsimdFinding::VectorMatrix(record("FUN_1")).target(),
            "vector/matrix"
        );
        assert_eq!(FloatsimdFinding::Mixed(record("FUN_1")).target(), "mixed");
    }

    #[test]
    fn shapes_display_their_report_labels() {
        assert_eq!(ShapeKind::ScalarFloat.to_string(), "scalar float");
        assert_eq!(ShapeKind::VectorMatrix.to_string(), "vector/matrix");
        assert_eq!(ShapeKind::Mixed.to_string(), "mixed");
    }

    #[test]
    fn a_flag_record_renders_into_prompt_data() {
        // The prompt seam: a flag record carries its whole claim into
        // `FloatsimdInfo` — function, shape tag, the steering
        // suggestion the detector wrote, and the confidence and
        // evidence behind it.
        let flag = FloatsimdFinding::VectorMatrix(record("FUN_18003ab00"));
        let info = calxgloss_prompts::FloatsimdInfo::from(&flag);
        assert_eq!(info.function, "FUN_18003ab00");
        assert_eq!(info.kind, "vector_matrix");
        assert_eq!(
            info.suggestion,
            "translate as a small vector struct or component array, not integer or pointer \
             arithmetic"
        );
        assert_eq!(info.confidence, 60);
        assert_eq!(
            info.evidence,
            "local_10 = CONCAT44(uVar2 >> 4, uVar2 & 0xfffffff);"
        );
    }

    #[test]
    fn a_floatsimd_result_serde_round_trips() {
        let mut result = FloatsimdResult::new(ScanMetadata::new("game_logic.dll"));
        result
            .findings
            .push(FloatsimdFinding::ScalarFloat(record("FUN_18003ab00")));
        result
            .findings
            .push(FloatsimdFinding::Mixed(record("FUN_18003e750")));
        let json = serde_json::to_string(&result).expect("the document serializes");
        let back: FloatsimdResult = serde_json::from_str(&json).expect("it reads back");
        assert_eq!(back, result);
    }

    #[test]
    fn a_result_without_flags_omits_the_section_and_reads_back_empty() {
        let result = FloatsimdResult::new(ScanMetadata::new("game_logic.dll"));
        let json = serde_json::to_string(&result).expect("an empty document serializes");
        assert!(
            !json.contains("findings"),
            "an empty findings section is omitted, not spelled as an empty array: {json}"
        );
        let back: FloatsimdResult = serde_json::from_str(&json).expect("it reads back");
        assert!(back.is_empty());
    }

    #[test]
    fn for_function_yields_only_that_function_s_flag() {
        let mut result = FloatsimdResult::new(ScanMetadata::new("game_logic.dll"));
        result
            .findings
            .push(FloatsimdFinding::ScalarFloat(record("FUN_18003ab00")));
        result
            .findings
            .push(FloatsimdFinding::VectorMatrix(record("FUN_18003e750")));
        let shapes: Vec<&str> = result
            .for_function("FUN_18003ab00")
            .map(|finding| finding.kind())
            .collect();
        assert_eq!(shapes, vec!["scalar_float"], "only the function's own flag");
        assert!(result.for_function("FUN_1800412a0").next().is_none());
    }
}
