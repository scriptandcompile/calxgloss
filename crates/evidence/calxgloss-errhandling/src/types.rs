//! Core data model for error-handling evidence findings.
//!
//! The scan's reading is a per-function list of findings: one record
//! per function whose kept body shows a shape the idiom catalog names,
//! naming the function, the body line that carries the claim, the
//! confidence band it scored on the Evidence scale, and the Rust
//! pattern it steers translation toward. [`ErrhandlingFinding`] is the
//! tagged union over the finding kinds — the serde `kind` tag spells
//! the distinction in the persisted JSON, and it is what a consumer
//! switches on — and [`ErrhandlingResult`] is the whole per-binary
//! document, metadata-stamped like every other evidence artifact so
//! consumers can tell when the reading was taken and against which
//! decompiler engine.

use calxgloss_types::{Confidence, ScanMetadata};
use serde::{Deserialize, Serialize};

/// A function body that spells a whole SEH `try`/`catch` frame — a
/// `try {` line and a later `catch` clause — the body text that
/// carries the frame claim (ADR-0046).
///
/// The record quotes the `catch` line: the `catch (...)` clause is
/// what marks the block as a frame *handler* rather than some other
/// block structure, and it sits at the end of the frame the
/// decompiler spelled, so one quoted line witnesses the whole shape.
/// It also carries the Rust pattern the finding steers a translation
/// toward, naming the suggested shape up front. The frame shape
/// itself lives in the [`ErrhandlingFinding::SehFrame`] tag wrapping
/// the record, not in a field, so a persisted record can never
/// disagree with its own kind.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SehFrame {
    /// The function whose body spells the frame.
    pub function: String,
    /// Confidence that the body really holds an SEH `try`/`catch`
    /// frame, on the shared 0–100 Evidence scale.
    pub confidence: Confidence,
    /// The `catch` line quoted from the body — the claim's evidence.
    pub evidence: String,
    /// The Rust pattern the finding steers a translation toward.
    pub suggestion: String,
}

/// One error-handling evidence finding about one function.
///
/// The union is what the persisted document carries, so the follow-up
/// families (named handlers, API calls, the RAII shape, failure codes)
/// land as new variants without reshaping the artifact. The serde
/// `kind` tag names the finding kind in the persisted JSON; the tag
/// *is* the idiom kind, so a record can never disagree with its own
/// kind by carrying a redundant label.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ErrhandlingFinding {
    /// The body spells a whole SEH `try`/`catch` frame.
    SehFrame(SehFrame),
}

impl ErrhandlingFinding {
    /// The function the finding is about.
    pub fn function(&self) -> &str {
        match self {
            ErrhandlingFinding::SehFrame(record) => &record.function,
        }
    }

    /// The body line quoted as the claim's evidence.
    pub fn evidence(&self) -> &str {
        match self {
            ErrhandlingFinding::SehFrame(record) => &record.evidence,
        }
    }

    /// Confidence in the finding, on the Evidence scale.
    pub fn confidence(&self) -> Confidence {
        match self {
            ErrhandlingFinding::SehFrame(record) => record.confidence,
        }
    }

    /// The Rust pattern the finding suggests.
    pub fn suggestion(&self) -> &str {
        match self {
            ErrhandlingFinding::SehFrame(record) => &record.suggestion,
        }
    }

    /// What the finding identifies about the function, as the report's
    /// row label: the idiom shape the kind stands for, named once
    /// here so the tag and the report can never drift apart.
    pub fn target(&self) -> &'static str {
        match self {
            ErrhandlingFinding::SehFrame(_) => "try/catch frame",
        }
    }

    /// The serde `kind` tag — `seh_frame` — naming the finding kind.
    pub fn kind(&self) -> &'static str {
        match self {
            ErrhandlingFinding::SehFrame(_) => "seh_frame",
        }
    }
}

/// The whole scan of one binary: the findings plus the metadata stamp
/// every evidence artifact carries.
///
/// The findings ride in listing order, one function's findings
/// grouped together, so two scans of the same program diff cleanly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrhandlingResult {
    /// When and against which engine the reading was taken.
    pub metadata: ScanMetadata,
    /// Every finding the scan made, in listing order. Omitted from
    /// the persisted document when the scan claimed nothing — an
    /// empty scan stays small on disk, and a document written before
    /// a family landed still loads with the field read back empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub findings: Vec<ErrhandlingFinding>,
}

impl ErrhandlingResult {
    /// An empty result for `binary`: the shape a scan starts from,
    /// and the shape a caller persists when it scanned a program with
    /// nothing to report.
    pub fn new(metadata: ScanMetadata) -> Self {
        Self {
            metadata,
            findings: Vec::new(),
        }
    }

    /// Whether the scan made no finding at all.
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
    use crate::seh_frame::{SEH_FRAME_SUGGESTION, SPELLED_FRAME_CONFIDENCE};

    fn framed() -> SehFrame {
        SehFrame {
            function: "FUN_1800014a0".into(),
            confidence: Confidence::new(SPELLED_FRAME_CONFIDENCE),
            evidence: "  catch(...){".into(),
            suggestion: SEH_FRAME_SUGGESTION.into(),
        }
    }

    #[test]
    fn a_seh_frame_record_serde_round_trips() {
        let record = framed();
        let json = serde_json::to_string(&record).unwrap();
        // Confidence serializes as its bare score, matching the
        // workspace's serde convention.
        assert!(json.contains(&format!("\"confidence\":{}", SPELLED_FRAME_CONFIDENCE)));
        let back: SehFrame = serde_json::from_str(&json).unwrap();
        assert_eq!(back, record);
    }

    #[test]
    fn a_finding_serde_round_trips_tagged_by_kind() {
        let finding = ErrhandlingFinding::SehFrame(framed());
        let json = serde_json::to_string(&finding).unwrap();
        assert!(json.contains("\"kind\":\"seh_frame\""));
        let back: ErrhandlingFinding = serde_json::from_str(&json).unwrap();
        assert_eq!(back, finding);
    }

    #[test]
    fn finding_accessors_read_the_shared_shape() {
        let finding = ErrhandlingFinding::SehFrame(framed());
        assert_eq!(finding.function(), "FUN_1800014a0");
        assert_eq!(finding.kind(), "seh_frame");
        assert_eq!(finding.target(), "try/catch frame");
        assert_eq!(
            finding.confidence(),
            Confidence::new(SPELLED_FRAME_CONFIDENCE)
        );
        assert_eq!(finding.evidence(), "  catch(...){");
        assert!(finding.suggestion().contains("error-handling frame"));
    }

    #[test]
    fn an_errhandling_result_serde_round_trips() {
        let result = ErrhandlingResult {
            metadata: ScanMetadata::new("eqmain.dll"),
            findings: vec![ErrhandlingFinding::SehFrame(framed())],
        };
        let json = serde_json::to_string(&result).unwrap();
        let back: ErrhandlingResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back, result);
    }

    #[test]
    fn a_result_without_findings_omits_them_and_reads_back_empty() {
        // The findings-free document every no-idiom binary persists,
        // and a document written before a family landed: the field is
        // absent on disk and reads back as an empty scan.
        let result = ErrhandlingResult::new(ScanMetadata::new("eqmain.dll"));
        let json = serde_json::to_string(&result).unwrap();
        assert!(!json.contains("\"findings\""));
        let back: ErrhandlingResult = serde_json::from_str(&json).unwrap();
        assert!(back.is_empty());
        assert_eq!(back.metadata.binary, "eqmain.dll");
    }
}
