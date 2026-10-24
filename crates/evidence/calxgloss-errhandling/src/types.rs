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

/// A function body whose text names a personality-handler thunk —
/// `__except_handler3`, `_except_handler4`, or `_CxxFrameHandler3` —
/// an SEH frame the decompiler did not draw into a spelled block
/// (issue #288, ADR-0046's named-handler rung).
///
/// The record quotes the line carrying the registration: the thunk's
/// spelled name in body text is the registration itself, so one
/// quoted line witnesses the frame. The Rust mapping is the spelled
/// frame's — the finding is the same frame read through weaker
/// evidence — and the confidence carries the difference.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NamedHandler {
    /// The function whose body names the thunk.
    pub function: String,
    /// Confidence that the body really sits inside an SEH frame, on
    /// the shared 0–100 Evidence scale.
    pub confidence: Confidence,
    /// The body line naming the registration — the claim's evidence.
    pub evidence: String,
    /// The Rust pattern the finding steers a translation toward.
    pub suggestion: String,
}

/// A function body that calls an exception-handling API —
/// `GetExceptionCode`/`__exception_code`, `SetUnhandledExceptionFilter`,
/// or `AddVectoredExceptionHandler` — SEH participation witnessed by
/// the API alone, with no spelled block and no named registration
/// (issue #288, ADR-0046's exception-API rung).
///
/// The record quotes the line carrying the call. This is the weakest
/// SEH rung: the call names an exception facility the function talks
/// to, and only that — a function querying the code its own filter
/// was handed is not proven to guard its work.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExceptionApiCall {
    /// The function whose body calls the API.
    pub function: String,
    /// Confidence that the body really participates in SEH, on the
    /// shared 0–100 Evidence scale.
    pub confidence: Confidence,
    /// The body line carrying the call — the claim's evidence.
    pub evidence: String,
    /// The Rust pattern the finding steers a translation toward.
    pub suggestion: String,
}

/// A function body that calls `RaiseException` directly — the
/// function is the *source* of an exception, and the raised code is
/// the handler contract its callers must survive (issue #288).
///
/// `code` carries the raised exception code when the call's first
/// argument is a numeric literal, and stays absent (`None`, omitted
/// from the persisted document) when the argument is an identifier,
/// a cast, or otherwise unreadable — the raise is a fact, the code is
/// only as certain as the body spells it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RaiseException {
    /// The function whose body makes the call.
    pub function: String,
    /// Confidence that the body really raises an exception, on the
    /// shared 0–100 Evidence scale.
    pub confidence: Confidence,
    /// The body line carrying the call — the claim's evidence.
    pub evidence: String,
    /// The raised exception code, when the first argument names it
    /// as a 32-bit numeric literal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<u32>,
    /// The Rust pattern the finding steers a translation toward.
    pub suggestion: String,
}

/// A function body whose guarded forward gotos converge on one
/// shared cleanup block — the C cleanup-on-failure ladder, kept as
/// pure control flow where the decompiler never drew a frame
/// (issue #289).
///
/// The record names the join label — the label whose block the
/// rungs converge on *is* the ladder's shared cleanup — and quotes
/// the line inside that block that decides the claim: the release
/// call witnessing the cleanup, or the shared constant return the
/// ladder fails to. The suggestion steers the translation to early
/// returns plus RAII or scope guards, the shape the ladder already
/// is, instead of the nested conditionals a re-implementation
/// tends to produce.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GotoCleanup {
    /// The function whose body converges on the shared block.
    pub function: String,
    /// Confidence that the body really runs a cleanup ladder, on
    /// the shared 0–100 Evidence scale.
    pub confidence: Confidence,
    /// The join block line carrying the claim — the claim's evidence.
    pub evidence: String,
    /// The label whose block the guarded gotos converge on, as the
    /// body spells it (`LAB_*`, `joined_r0x*`, or a hand-named one).
    pub join_label: String,
    /// The Rust pattern the finding steers a translation toward.
    pub suggestion: String,
}

/// One error-handling evidence finding about one function.
///
/// The union is what the persisted document carries, so the follow-up
/// families (the per-code failure codes) land as new variants without
/// reshaping the artifact. The serde `kind` tag names the finding
/// kind in the persisted JSON; the tag *is* the idiom kind, so a
/// record can never disagree with its own kind by carrying a redundant
/// label. The three SEH kinds — spelled frame, named handler,
/// exception-API call — stand one per function at most, the strongest
/// family winning the one claim (the engine takes the first family
/// that fires, in ADR-0046's rung order); a `RaiseException` finding
/// and a `GotoCleanup` finding each ride beside them, different facts
/// about the same function.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ErrhandlingFinding {
    /// The body spells a whole SEH `try`/`catch` frame.
    SehFrame(SehFrame),
    /// The body names a personality-handler thunk registration.
    NamedHandler(NamedHandler),
    /// The body calls an exception-handling API.
    ExceptionApiCall(ExceptionApiCall),
    /// The body calls `RaiseException` directly.
    RaiseException(RaiseException),
    /// The body's guarded forward gotos converge on one shared
    /// cleanup block — the C cleanup-on-failure ladder.
    GotoCleanup(GotoCleanup),
}

impl ErrhandlingFinding {
    /// The function the finding is about.
    pub fn function(&self) -> &str {
        match self {
            ErrhandlingFinding::SehFrame(record) => &record.function,
            ErrhandlingFinding::NamedHandler(record) => &record.function,
            ErrhandlingFinding::ExceptionApiCall(record) => &record.function,
            ErrhandlingFinding::RaiseException(record) => &record.function,
            ErrhandlingFinding::GotoCleanup(record) => &record.function,
        }
    }

    /// The body line quoted as the claim's evidence.
    pub fn evidence(&self) -> &str {
        match self {
            ErrhandlingFinding::SehFrame(record) => &record.evidence,
            ErrhandlingFinding::NamedHandler(record) => &record.evidence,
            ErrhandlingFinding::ExceptionApiCall(record) => &record.evidence,
            ErrhandlingFinding::RaiseException(record) => &record.evidence,
            ErrhandlingFinding::GotoCleanup(record) => &record.evidence,
        }
    }

    /// Confidence in the finding, on the Evidence scale.
    pub fn confidence(&self) -> Confidence {
        match self {
            ErrhandlingFinding::SehFrame(record) => record.confidence,
            ErrhandlingFinding::NamedHandler(record) => record.confidence,
            ErrhandlingFinding::ExceptionApiCall(record) => record.confidence,
            ErrhandlingFinding::RaiseException(record) => record.confidence,
            ErrhandlingFinding::GotoCleanup(record) => record.confidence,
        }
    }

    /// The Rust pattern the finding suggests.
    pub fn suggestion(&self) -> &str {
        match self {
            ErrhandlingFinding::SehFrame(record) => &record.suggestion,
            ErrhandlingFinding::NamedHandler(record) => &record.suggestion,
            ErrhandlingFinding::ExceptionApiCall(record) => &record.suggestion,
            ErrhandlingFinding::RaiseException(record) => &record.suggestion,
            ErrhandlingFinding::GotoCleanup(record) => &record.suggestion,
        }
    }

    /// What the finding identifies about the function, as the report's
    /// row label: the idiom shape the kind stands for, named once
    /// here so the tag and the report can never drift apart.
    pub fn target(&self) -> &'static str {
        match self {
            ErrhandlingFinding::SehFrame(_) => "try/catch frame",
            ErrhandlingFinding::NamedHandler(_) => "named handler",
            ErrhandlingFinding::ExceptionApiCall(_) => "exception-API call",
            ErrhandlingFinding::RaiseException(_) => "RaiseException call",
            ErrhandlingFinding::GotoCleanup(_) => "goto-cleanup ladder",
        }
    }

    /// The serde `kind` tag — `seh_frame`, `named_handler`,
    /// `exception_api_call`, `raise_exception`, or `goto_cleanup` —
    /// naming the finding kind.
    pub fn kind(&self) -> &'static str {
        match self {
            ErrhandlingFinding::SehFrame(_) => "seh_frame",
            ErrhandlingFinding::NamedHandler(_) => "named_handler",
            ErrhandlingFinding::ExceptionApiCall(_) => "exception_api_call",
            ErrhandlingFinding::RaiseException(_) => "raise_exception",
            ErrhandlingFinding::GotoCleanup(_) => "goto_cleanup",
        }
    }

    /// Stamp the function the finding is about, the field every
    /// record carries and the detectors — which never see a name —
    /// leave empty for the engine to fill.
    pub(crate) fn set_function(&mut self, function: &str) {
        match self {
            ErrhandlingFinding::SehFrame(record) => record.function = function.to_string(),
            ErrhandlingFinding::NamedHandler(record) => record.function = function.to_string(),
            ErrhandlingFinding::ExceptionApiCall(record) => record.function = function.to_string(),
            ErrhandlingFinding::RaiseException(record) => record.function = function.to_string(),
            ErrhandlingFinding::GotoCleanup(record) => record.function = function.to_string(),
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
    use crate::exception_api::EXCEPTION_API_CONFIDENCE;
    use crate::goto_cleanup::{
        GOTO_CLEANUP_RELEASE_CONFIDENCE, GOTO_CLEANUP_RETURN_CONFIDENCE, GOTO_CLEANUP_SUGGESTION,
    };
    use crate::named_handler::NAMED_HANDLER_CONFIDENCE;
    use crate::raise_exception::{RAISE_EXCEPTION_CONFIDENCE, RAISE_EXCEPTION_SUGGESTION};
    use crate::seh_frame::{SEH_FRAME_SUGGESTION, SPELLED_FRAME_CONFIDENCE};

    fn framed() -> SehFrame {
        SehFrame {
            function: "FUN_1800014a0".into(),
            confidence: Confidence::new(SPELLED_FRAME_CONFIDENCE),
            evidence: "  catch(...){".into(),
            suggestion: SEH_FRAME_SUGGESTION.into(),
        }
    }

    fn named() -> NamedHandler {
        NamedHandler {
            function: "FUN_1800014a0".into(),
            confidence: Confidence::new(NAMED_HANDLER_CONFIDENCE),
            evidence: "  _CxxFrameHandler3(1, 0, lookup, this_ptr, frame);".into(),
            suggestion: SEH_FRAME_SUGGESTION.into(),
        }
    }

    fn api_call() -> ExceptionApiCall {
        ExceptionApiCall {
            function: "FUN_1800014a0".into(),
            confidence: Confidence::new(EXCEPTION_API_CONFIDENCE),
            evidence: "  code = GetExceptionCode();".into(),
            suggestion: SEH_FRAME_SUGGESTION.into(),
        }
    }

    fn raised(code: Option<u32>) -> RaiseException {
        RaiseException {
            function: "FUN_1800014a0".into(),
            confidence: Confidence::new(RAISE_EXCEPTION_CONFIDENCE),
            evidence: "  RaiseException(0xe06d7363, 0, 0, NULL);".into(),
            code,
            suggestion: RAISE_EXCEPTION_SUGGESTION.into(),
        }
    }

    fn laddered(band: u8) -> GotoCleanup {
        GotoCleanup {
            function: "FUN_1800014a0".into(),
            confidence: Confidence::new(band),
            evidence: "  CloseHandle(hFile);".into(),
            join_label: "LAB_140001a2c".into(),
            suggestion: GOTO_CLEANUP_SUGGESTION.into(),
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
    fn each_new_record_serde_round_trips_under_its_kind_tag() {
        // Documents written before a kind existed keep loading
        // because each kind is its own tag — the union's standing
        // guarantee, asserted for the three kinds issue #288 adds.
        let cases = [
            (
                ErrhandlingFinding::NamedHandler(named()),
                "\"kind\":\"named_handler\"",
            ),
            (
                ErrhandlingFinding::ExceptionApiCall(api_call()),
                "\"kind\":\"exception_api_call\"",
            ),
            (
                ErrhandlingFinding::RaiseException(raised(Some(0xe06d_7363))),
                "\"kind\":\"raise_exception\"",
            ),
            (
                ErrhandlingFinding::GotoCleanup(laddered(GOTO_CLEANUP_RELEASE_CONFIDENCE)),
                "\"kind\":\"goto_cleanup\"",
            ),
        ];
        for (finding, tag) in cases {
            let json = serde_json::to_string(&finding).unwrap();
            assert!(json.contains(tag), "the {tag} tag rides the document");
            let back: ErrhandlingFinding = serde_json::from_str(&json).unwrap();
            assert_eq!(back, finding);
        }
    }

    #[test]
    fn a_raise_without_a_code_omits_it_and_reads_back_empty() {
        // "a non-literal argument still lands the finding with no
        // code claimed" — the absence is on disk, not a sentinel 0.
        let finding = ErrhandlingFinding::RaiseException(raised(None));
        let json = serde_json::to_string(&finding).unwrap();
        assert!(!json.contains("\"code\""));
        let back: ErrhandlingFinding = serde_json::from_str(&json).unwrap();
        assert_eq!(back, finding);
    }

    #[test]
    fn a_raise_code_round_trips_as_a_number() {
        let finding = ErrhandlingFinding::RaiseException(raised(Some(0xe06d_7363)));
        let json = serde_json::to_string(&finding).unwrap();
        assert!(json.contains(&format!("\"code\":{}", 0xe06d_7363u32)));
        let back: ErrhandlingFinding = serde_json::from_str(&json).unwrap();
        match &back {
            ErrhandlingFinding::RaiseException(record) => {
                assert_eq!(record.code, Some(0xe06d_7363));
            }
            other => panic!("expected the raise kind back, got {other:?}"),
        }
    }

    #[test]
    fn new_finding_accessors_read_the_shared_shape() {
        // The shared accessors every consumer switches on, for each
        // kind #288 grows.
        let finding = ErrhandlingFinding::NamedHandler(named());
        assert_eq!(finding.kind(), "named_handler");
        assert_eq!(finding.target(), "named handler");
        assert_eq!(
            finding.confidence(),
            Confidence::new(NAMED_HANDLER_CONFIDENCE)
        );
        assert!(finding.evidence().contains("_CxxFrameHandler3"));

        let finding = ErrhandlingFinding::ExceptionApiCall(api_call());
        assert_eq!(finding.kind(), "exception_api_call");
        assert_eq!(finding.target(), "exception-API call");
        assert_eq!(
            finding.confidence(),
            Confidence::new(EXCEPTION_API_CONFIDENCE)
        );
        assert!(finding.evidence().contains("GetExceptionCode"));

        let finding = ErrhandlingFinding::RaiseException(raised(Some(0xe06d_7363)));
        assert_eq!(finding.kind(), "raise_exception");
        assert_eq!(finding.target(), "RaiseException call");
        assert_eq!(
            finding.confidence(),
            Confidence::new(RAISE_EXCEPTION_CONFIDENCE)
        );
        assert!(finding.suggestion().contains("error value"));

        let finding = ErrhandlingFinding::GotoCleanup(laddered(GOTO_CLEANUP_RETURN_CONFIDENCE));
        assert_eq!(finding.kind(), "goto_cleanup");
        assert_eq!(finding.target(), "goto-cleanup ladder");
        assert_eq!(
            finding.confidence(),
            Confidence::new(GOTO_CLEANUP_RETURN_CONFIDENCE)
        );
        assert!(finding.evidence().contains("CloseHandle"));
        assert!(finding.suggestion().contains("scope guard"));
    }

    #[test]
    fn a_ladder_record_names_its_join_label_through_the_round_trip() {
        // The join label is part of the claim on disk: a consumer
        // reading the document can point at the shared cleanup block
        // without re-reading the body.
        let finding = ErrhandlingFinding::GotoCleanup(laddered(GOTO_CLEANUP_RELEASE_CONFIDENCE));
        let json = serde_json::to_string(&finding).unwrap();
        assert!(json.contains("\"join_label\":\"LAB_140001a2c\""));
        assert!(json.contains(&format!(
            "\"confidence\":{}",
            GOTO_CLEANUP_RELEASE_CONFIDENCE
        )));
        let back: ErrhandlingFinding = serde_json::from_str(&json).unwrap();
        match &back {
            ErrhandlingFinding::GotoCleanup(record) => {
                assert_eq!(record.join_label, "LAB_140001a2c");
            }
            other => panic!("expected the ladder kind back, got {other:?}"),
        }
        assert_eq!(back.confidence(), finding.confidence());
    }

    #[test]
    fn the_seh_bands_and_the_raise_persist_ranked() {
        // The three SEH bands and the raise band, observable through
        // the persisted confidence: spelled block above named handler
        // above API call, the raise in high between, and every round
        // trip preserving the score the scan wrote.
        // ADR-0046's ladder: each follow-up anchors its own band as
        // it lands, strictly below the family above it — issue #289
        // adds the ladder's two rungs at the bottom, so neither can
        // outrank a spelled SEH block.
        const {
            assert!(
                SPELLED_FRAME_CONFIDENCE > RAISE_EXCEPTION_CONFIDENCE
                    && RAISE_EXCEPTION_CONFIDENCE > NAMED_HANDLER_CONFIDENCE
                    && NAMED_HANDLER_CONFIDENCE > EXCEPTION_API_CONFIDENCE
                    && EXCEPTION_API_CONFIDENCE > GOTO_CLEANUP_RELEASE_CONFIDENCE
                    && GOTO_CLEANUP_RELEASE_CONFIDENCE > GOTO_CLEANUP_RETURN_CONFIDENCE
            )
        };
        let finding = ErrhandlingFinding::ExceptionApiCall(api_call());
        let json = serde_json::to_string(&finding).unwrap();
        assert!(json.contains(&format!("\"confidence\":{}", EXCEPTION_API_CONFIDENCE)));
        let back: ErrhandlingFinding = serde_json::from_str(&json).unwrap();
        assert_eq!(back.confidence(), finding.confidence());
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
