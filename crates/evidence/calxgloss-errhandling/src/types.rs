//! Core data model for error-handling evidence findings.
//!
//! The scan's reading is a per-function list of findings. One record
//! stands for each function whose kept body shows a shape the idiom
//! catalog names. It names the function, quotes the body line that
//! carries the claim, scores the reading in a confidence band on the
//! shared Evidence scale, and names the Rust pattern it steers
//! translation toward.
//!
//! [`ErrhandlingFinding`] is the tagged union over the finding kinds.
//! The serde `kind` tag spells the distinction in the persisted JSON,
//! and it is what a consumer switches on. [`ErrhandlingResult`] is the
//! whole per-binary document. Like every other evidence artifact it is
//! metadata-stamped, so consumers can tell when the reading was taken
//! and against which analysis engine.

use calxgloss_types::{Confidence, ScanMetadata};
use serde::{Deserialize, Serialize};

/// A function body that spells a whole SEH `try`/`catch` frame — a
/// `try {` line and a later `catch` clause. The body text carries the
/// frame claim (ADR-0046).
///
/// The record quotes the `catch` line. The `catch (...)` clause is what
/// marks the block as a frame *handler* rather than some other block
/// structure, and it sits at the end of the frame the decompiler
/// spelled, so one quoted line witnesses the whole shape. The record
/// also carries the Rust pattern the finding steers a translation
/// toward, naming the suggested shape up front. The frame shape itself
/// lives in the [`ErrhandlingFinding::SehFrame`] tag wrapping the
/// record, not in a field, so a persisted record can never disagree
/// with its own kind.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SehFrame {
    /// The function whose body spells the frame.
    pub function: String,
    /// Evidence confidence that the body really holds an SEH
    /// `try`/`catch` frame, on the shared 0–100 scale.
    pub confidence: Confidence,
    /// The `catch` line quoted from the body — the claim's evidence.
    pub evidence: String,
    /// The Rust pattern the finding steers a translation toward.
    pub suggestion: String,
}

/// A function body whose text names a personality-handler thunk —
/// `__except_handler3`, `_except_handler4`, or `_CxxFrameHandler3`.
/// The name records an SEH frame the decompiler did not draw into a
/// spelled block (issue #288, ADR-0046's named-handler band).
///
/// The record quotes the line carrying the registration. The thunk's
/// spelled name in body text is the registration itself, so one
/// quoted line witnesses the frame. The Rust mapping is the spelled
/// frame's — the finding is the same frame read through weaker
/// evidence — and the evidence confidence carries the difference.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NamedHandler {
    /// The function whose body names the thunk.
    pub function: String,
    /// Evidence confidence that the body really sits inside an SEH
    /// frame, on the shared 0–100 scale.
    pub confidence: Confidence,
    /// The body line naming the registration — the claim's evidence.
    pub evidence: String,
    /// The Rust pattern the finding steers a translation toward.
    pub suggestion: String,
}

/// A function body that calls an exception-handling API —
/// `GetExceptionCode`/`__exception_code`, `SetUnhandledExceptionFilter`,
/// or `AddVectoredExceptionHandler`. This is SEH participation
/// witnessed by the API call alone: no spelled block, no named
/// registration (issue #288, ADR-0046's exception-API band).
///
/// The record quotes the line carrying the call. This is the weakest
/// SEH band: the call names an exception facility the function talks
/// to, and only that. A function querying the code its own filter was
/// handed is not proven to guard its work.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExceptionApiCall {
    /// The function whose body calls the API.
    pub function: String,
    /// Evidence confidence that the body really participates in SEH,
    /// on the shared 0–100 scale.
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
/// argument is a numeric literal. It stays absent (`None`, omitted
/// from the persisted document) when the argument is an identifier,
/// a cast, or otherwise unreadable: the raise is a fact, and the code
/// is only as certain as the body spells it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RaiseException {
    /// The function whose body makes the call.
    pub function: String,
    /// Evidence confidence that the body really raises an exception,
    /// on the shared 0–100 scale.
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

/// A function body whose guarded forward gotos converge on one shared
/// cleanup block — the C cleanup-on-failure ladder, kept as pure
/// control flow where the decompiler never drew a frame (issue #289).
///
/// The record names the join label: the label whose block the rungs
/// converge on is the ladder's shared cleanup. It quotes the line
/// inside that block that decides the claim — the release call
/// witnessing the cleanup, or, when the block releases nothing, the
/// shared constant return. The suggestion steers the translation to
/// early returns plus RAII or scope guards, the shape the ladder
/// already is, instead of the nested conditionals a re-implementation
/// tends to produce.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GotoCleanup {
    /// The function whose body converges on the shared block.
    pub function: String,
    /// Evidence confidence that the body really runs a cleanup
    /// ladder, on the shared 0–100 scale.
    pub confidence: Confidence,
    /// The join block line carrying the claim — the claim's evidence.
    pub evidence: String,
    /// The label whose block the guarded gotos converge on, as the
    /// body spells it (`LAB_*`, `joined_r0x*`, or a hand-named one).
    pub join_label: String,
    /// The Rust pattern the finding steers a translation toward.
    pub suggestion: String,
}

/// The site shape a failure-code literal was read from: the closed
/// set of statement kinds the failure-code reading treats as the
/// function stating its failure contract (issue #290). The persisted
/// record names which one it was, so a consumer can tell a code the
/// function hands its caller from a code it merely tests for. The
/// baseline-test follow-up pins only the returned and raised ones as
/// expected outcomes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCodeSite {
    /// The literal stands in the function's `return` statement —
    /// the value goes to the caller, the most direct statement of
    /// the failure contract the reading takes.
    Return,
    /// The literal stands as the first argument of a
    /// `RaiseException` call — the code leaves through the exception
    /// mechanism the function invokes, not through its return value.
    Raise,
    /// The literal stands in a guard comparison — the function
    /// tests for the code; whether it also emits it is inference,
    /// and the band says so.
    Guard,
}

/// A failure-code literal one function's body spells — the HRESULT-
/// or NTSTATUS-shaped value it returns, compares a guard against, or
/// raises, one record per distinct code per function (issue #290,
/// the artifact the baseline-test follow-up consumes: the expected
/// outcomes recorded, not re-derived).
///
/// The record carries the code value as the literal spells it, the
/// site kind it was read from, and the line that carries the claim
/// as its evidence; the confidence band follows the site kind (the
/// bands live in [`error_code`](crate::error_code)). A function
/// carrying codes and no idiom shape still carries its code records
/// — the failure contract and the idiom are different facts. The
/// same code sighted at several sites in one function stands as one
/// record at its strongest site, so per-function lookup stays direct
/// and two scans of one program keep diffing cleanly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorCode {
    /// The function whose body spells the code.
    pub function: String,
    /// Evidence confidence that the code really belongs to this
    /// function's failure contract, on the shared 0–100 scale,
    /// banded by the site kind.
    pub confidence: Confidence,
    /// The body line carrying the literal — the claim's evidence.
    pub evidence: String,
    /// The code value, as the literal spells it: an HRESULT-shaped
    /// (`0x8xxx_xxxx`) or NTSTATUS-shaped (`0xCxxx_xxxx`) 32-bit value.
    pub code: u32,
    /// The statement kind the literal was read from.
    pub site: ErrorCodeSite,
    /// The Rust pattern the finding steers a translation toward.
    pub suggestion: String,
}

/// A failure code one function inherits along the call map. The
/// callee's recorded code reaches the caller because the caller
/// compares the callee's return against that literal, or hands the
/// callee's return straight back to its own caller (issue #291,
/// ADR-0047: propagation carries codes, never idioms).
///
/// The record names the *caller* as its function — the finding is
/// about the caller's contract, which now includes a code the caller
/// never spelled itself. It names the callee as its `partner`, beside
/// the same code value the callee's own record carries. Its evidence
/// is the caller's own line: the call site where the comparison
/// guards the callee's value, or where the callee's value is handed
/// back. The band is propagation's own penalty, taken off the guard
/// reading's band ( [`INHERITED_ERROR_CODE_CONFIDENCE`](crate::cross_function)),
/// so a second-hand contract never outranks a first-hand one. One
/// (function, code) pair stands once — the first claim in scan order
/// wins, per ADR-0028's precedent. The caller's own [`ErrorCode`]
/// records sit beside the inherited one, different readings of
/// different facts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InheritedErrorCode {
    /// The caller inheriting the code — the function the finding is about.
    pub function: String,
    /// The callee the code travels from, named as the call map spells it.
    pub partner: String,
    /// Evidence confidence that the code really belongs to this
    /// caller's failure contract — propagation's own band, below
    /// every site reading that saw the literal in the body itself.
    pub confidence: Confidence,
    /// The caller's call-site line carrying the comparison or the
    /// hand-back — the claim's evidence.
    pub evidence: String,
    /// The code value, the same number the callee's own record carries.
    pub code: u32,
    /// The Rust pattern the finding steers a translation toward — the
    /// code's contract reads the same inherited as spelled.
    pub suggestion: String,
}

/// One error-handling evidence finding about one function.
///
/// The union is what the persisted document carries, so the follow-up
/// families (the cross-function propagation readings) land as new
/// variants without reshaping the artifact. The serde `kind` tag names
/// the finding kind in the persisted JSON. The tag *is* the idiom kind,
/// so a record can never disagree with its own kind by carrying a
/// redundant label.
///
/// The three SEH kinds — spelled frame, named handler, exception-API
/// call — stand one per function at most: the strongest family wins
/// the one claim, because the scan takes the first family that fires,
/// in ADR-0046's band order. A `RaiseException` finding and a
/// `GotoCleanup` finding each sit beside the SEH claim — different
/// facts about the same function. So do as many `ErrorCode` records
/// as the function spells distinct codes (issue #290).
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
    /// The body spells a failure-code literal — returned, compared
    /// in a guard, or raised — one record per distinct code per
    /// function.
    ErrorCode(ErrorCode),
    /// The function inherits a failure code along the call map — a
    /// callee's recorded code, reaching the caller through a
    /// comparison of the callee's return or a hand-back of it
    /// (issue #291, ADR-0047). Codes travel; idioms never do.
    InheritedErrorCode(InheritedErrorCode),
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
            ErrhandlingFinding::ErrorCode(record) => &record.function,
            ErrhandlingFinding::InheritedErrorCode(record) => &record.function,
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
            ErrhandlingFinding::ErrorCode(record) => &record.evidence,
            ErrhandlingFinding::InheritedErrorCode(record) => &record.evidence,
        }
    }

    /// Evidence confidence in the finding, on the shared 0–100 scale.
    pub fn confidence(&self) -> Confidence {
        match self {
            ErrhandlingFinding::SehFrame(record) => record.confidence,
            ErrhandlingFinding::NamedHandler(record) => record.confidence,
            ErrhandlingFinding::ExceptionApiCall(record) => record.confidence,
            ErrhandlingFinding::RaiseException(record) => record.confidence,
            ErrhandlingFinding::GotoCleanup(record) => record.confidence,
            ErrhandlingFinding::ErrorCode(record) => record.confidence,
            ErrhandlingFinding::InheritedErrorCode(record) => record.confidence,
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
            ErrhandlingFinding::ErrorCode(record) => &record.suggestion,
            ErrhandlingFinding::InheritedErrorCode(record) => &record.suggestion,
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
            ErrhandlingFinding::ErrorCode(_) => "failure code",
            ErrhandlingFinding::InheritedErrorCode(_) => "inherited failure code",
        }
    }

    /// The serde `kind` tag — `seh_frame`, `named_handler`,
    /// `exception_api_call`, `raise_exception`, `goto_cleanup`,
    /// `error_code`, or `inherited_error_code` — naming the finding kind.
    pub fn kind(&self) -> &'static str {
        match self {
            ErrhandlingFinding::SehFrame(_) => "seh_frame",
            ErrhandlingFinding::NamedHandler(_) => "named_handler",
            ErrhandlingFinding::ExceptionApiCall(_) => "exception_api_call",
            ErrhandlingFinding::RaiseException(_) => "raise_exception",
            ErrhandlingFinding::GotoCleanup(_) => "goto_cleanup",
            ErrhandlingFinding::ErrorCode(_) => "error_code",
            ErrhandlingFinding::InheritedErrorCode(_) => "inherited_error_code",
        }
    }

    /// Stamp the function the finding is about. Every record carries
    /// this field; the detectors never see a name, so they leave it
    /// empty for the scan to fill.
    pub(crate) fn set_function(&mut self, function: &str) {
        match self {
            ErrhandlingFinding::SehFrame(record) => record.function = function.to_string(),
            ErrhandlingFinding::NamedHandler(record) => record.function = function.to_string(),
            ErrhandlingFinding::ExceptionApiCall(record) => record.function = function.to_string(),
            ErrhandlingFinding::RaiseException(record) => record.function = function.to_string(),
            ErrhandlingFinding::GotoCleanup(record) => record.function = function.to_string(),
            ErrhandlingFinding::ErrorCode(record) => record.function = function.to_string(),
            ErrhandlingFinding::InheritedErrorCode(record) => {
                record.function = function.to_string()
            }
        }
    }
}

/// Render a finding as prompt data: the function it is about, the kind
/// tag, the reading spelled for a reader, the Rust pattern the finding
/// steers a translation toward, and the evidence confidence and body
/// line behind the claim (issue #293). The module-context and escalate
/// prompts then show the error-handling contract the body carries and
/// how strongly each reading was made, and the translator stops
/// guessing at error shapes.
///
/// Code-bearing records carry the code in its spelled `0x…` form. A
/// failure-code record names the site kind the literal was read from;
/// an inherited record names the callee the code came from; and a
/// `RaiseException` idiom names the code it raises beside its
/// suggestion without becoming a failure-code record itself.
impl From<&ErrhandlingFinding> for calxgloss_prompts::ErrhandlingInfo {
    fn from(finding: &ErrhandlingFinding) -> Self {
        let code = match finding {
            ErrhandlingFinding::RaiseException(record) => {
                record.code.map(|code| format!("{code:#010x}"))
            }
            ErrhandlingFinding::ErrorCode(record) => Some(format!("{:#010x}", record.code)),
            ErrhandlingFinding::InheritedErrorCode(record) => {
                Some(format!("{:#010x}", record.code))
            }
            _ => None,
        };
        let site = match finding {
            ErrhandlingFinding::ErrorCode(record) => Some(match record.site {
                ErrorCodeSite::Return => "return".to_string(),
                ErrorCodeSite::Raise => "raise".to_string(),
                ErrorCodeSite::Guard => "guard".to_string(),
            }),
            _ => None,
        };
        let partner = match finding {
            ErrhandlingFinding::InheritedErrorCode(record) => Some(record.partner.clone()),
            _ => None,
        };
        Self {
            function: finding.function().to_string(),
            kind: finding.kind().to_string(),
            target: finding.target().to_string(),
            suggestion: finding.suggestion().to_string(),
            confidence: finding.confidence().value(),
            evidence: finding.evidence().to_string(),
            code,
            site,
            partner,
        }
    }
}

/// The whole scan of one binary: the findings plus the metadata stamp
/// every evidence artifact carries.
///
/// The findings stay in listing order, one function's findings grouped
/// together, so two scans of the same program diff cleanly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrhandlingResult {
    /// When the reading was taken and against which analysis engine.
    pub metadata: ScanMetadata,
    /// Every finding the scan made, in listing order. Omitted from
    /// the persisted document when the scan claimed nothing — an
    /// empty scan stays small on disk, and a document written before
    /// a family landed still loads with the field read back empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub findings: Vec<ErrhandlingFinding>,
}

impl ErrhandlingResult {
    /// An empty result for the program `binary` names: the shape a
    /// scan starts from, and the shape a caller persists when it
    /// scanned a program with nothing to report.
    pub fn new(metadata: ScanMetadata) -> Self {
        Self {
            metadata,
            findings: Vec::new(),
        }
    }

    /// Every finding the scan made about one function, e.g.
    /// `FUN_18003ab00`, in listing order. Within one function's
    /// per-function block the idiom readings come first, then that
    /// function's failure-code records; the scan appends inherited
    /// codes at the end of the document, after every function's
    /// per-function block. A by-function lookup is what the prompt seam
    /// reads, so the same lookup answers idiom and codes at once.
    pub fn for_function(&self, function: &str) -> impl Iterator<Item = &ErrhandlingFinding> {
        self.findings
            .iter()
            .filter(move |finding| finding.function() == function)
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

    fn coded(site: ErrorCodeSite, band: u8) -> ErrorCode {
        ErrorCode {
            function: "FUN_1800014a0".into(),
            confidence: Confidence::new(band),
            evidence: "  return 0x80070057;".into(),
            code: 0x8007_0057,
            site,
            suggestion: crate::error_code::ERROR_CODE_SUGGESTION.into(),
        }
    }

    fn inherited() -> InheritedErrorCode {
        InheritedErrorCode {
            function: "FUN_1800014a0".into(),
            partner: "FUN_1800412a0".into(),
            confidence: Confidence::new(crate::cross_function::INHERITED_ERROR_CODE_CONFIDENCE),
            evidence: "  iVar1 = FUN_1800412a0(param_1);".into(),
            code: 0x8007_0057,
            suggestion: crate::error_code::ERROR_CODE_SUGGESTION.into(),
        }
    }

    #[test]
    fn a_seh_frame_record_serde_round_trips() {
        let record = framed();
        let json = serde_json::to_string(&record).unwrap();
        // Evidence confidence serializes as its bare score, matching
        // the workspace's serde convention.
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
        // Each kind is its own tag, so documents written before a kind
        // existed keep loading. That is the union's standing guarantee,
        // asserted here for every kind the track has grown.
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
            (
                ErrhandlingFinding::ErrorCode(coded(
                    ErrorCodeSite::Return,
                    crate::error_code::ERROR_CODE_RETURN_CONFIDENCE,
                )),
                "\"kind\":\"error_code\"",
            ),
            (
                ErrhandlingFinding::InheritedErrorCode(inherited()),
                "\"kind\":\"inherited_error_code\"",
            ),
        ];
        for (finding, tag) in cases {
            let json = serde_json::to_string(&finding).unwrap();
            assert!(json.contains(tag), "the {tag} tag is kept in the document");
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

        let finding = ErrhandlingFinding::ErrorCode(coded(
            ErrorCodeSite::Return,
            crate::error_code::ERROR_CODE_RETURN_CONFIDENCE,
        ));
        assert_eq!(finding.kind(), "error_code");
        assert_eq!(finding.target(), "failure code");
        assert_eq!(
            finding.confidence(),
            Confidence::new(crate::error_code::ERROR_CODE_RETURN_CONFIDENCE)
        );
        assert!(finding.evidence().contains("0x80070057"));
        assert!(finding.suggestion().contains("failure contract"));
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
    fn a_code_record_round_trips_with_its_value_and_site_kind() {
        // The code value is stored in the document as a number, and
        // the site kind as its spelled tag. A consumer reading the
        // document can pin the expected outcome and tell a returned
        // code from a compared one without opening the body.
        for (site, tag) in [
            (ErrorCodeSite::Return, "\"site\":\"return\""),
            (ErrorCodeSite::Raise, "\"site\":\"raise\""),
            (ErrorCodeSite::Guard, "\"site\":\"guard\""),
        ] {
            let finding = ErrhandlingFinding::ErrorCode(coded(
                site,
                crate::error_code::ERROR_CODE_GUARD_CONFIDENCE,
            ));
            let json = serde_json::to_string(&finding).unwrap();
            assert!(json.contains(tag), "the {tag} tag is kept in the document");
            assert!(json.contains(&format!("\"code\":{}", 0x8007_0057u32)));
            let back: ErrhandlingFinding = serde_json::from_str(&json).unwrap();
            match &back {
                ErrhandlingFinding::ErrorCode(record) => {
                    assert_eq!(record.code, 0x8007_0057);
                    assert_eq!(record.site, site);
                }
                other => panic!("expected the code kind back, got {other:?}"),
            }
            assert_eq!(back, finding);
        }
    }

    #[test]
    fn an_inherited_record_names_its_partner_and_round_trips() {
        // The callee is part of the claim on disk. A consumer reading
        // the document can see which function's contract the code came
        // from, without re-deriving the call map.
        let finding = ErrhandlingFinding::InheritedErrorCode(inherited());
        let json = serde_json::to_string(&finding).unwrap();
        assert!(json.contains("\"partner\":\"FUN_1800412a0\""));
        assert!(json.contains(&format!(
            "\"confidence\":{}",
            crate::cross_function::INHERITED_ERROR_CODE_CONFIDENCE
        )));
        let back: ErrhandlingFinding = serde_json::from_str(&json).unwrap();
        match &back {
            ErrhandlingFinding::InheritedErrorCode(record) => {
                assert_eq!(record.partner, "FUN_1800412a0");
                assert_eq!(record.code, 0x8007_0057);
            }
            other => panic!("expected the inherited kind back, got {other:?}"),
        }
        assert_eq!(back, finding);
        assert_eq!(finding.target(), "inherited failure code");
        assert!(finding.suggestion().contains("failure contract"));
    }

    #[test]
    fn the_seh_bands_and_the_raise_persist_ranked() {
        // The three SEH bands and the raise band, observable through
        // the evidence confidence in the persisted document: spelled
        // frame above raise, raise above named handler, named handler
        // above API call. Every round trip preserves the score the
        // scan wrote.
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
        // and documents written before a family landed: the field is
        // absent on disk, and it reads back as an empty scan.
        let result = ErrhandlingResult::new(ScanMetadata::new("eqmain.dll"));
        let json = serde_json::to_string(&result).unwrap();
        assert!(!json.contains("\"findings\""));
        let back: ErrhandlingResult = serde_json::from_str(&json).unwrap();
        assert!(back.is_empty());
        assert_eq!(back.metadata.binary, "eqmain.dll");
    }

    #[test]
    fn for_function_yields_only_that_function_s_findings_in_order() {
        // The prompt seam's lookup: only the target function's records,
        // idioms and codes together, in listing order.
        let mut result = ErrhandlingResult::new(ScanMetadata::new("eqmain.dll"));
        result.findings = vec![
            ErrhandlingFinding::SehFrame(framed()),
            ErrhandlingFinding::ErrorCode(coded(ErrorCodeSite::Return, 74)),
            ErrhandlingFinding::SehFrame(SehFrame {
                function: "FUN_zzz".into(),
                ..framed()
            }),
            ErrhandlingFinding::InheritedErrorCode(inherited()),
        ];

        let kinds: Vec<&str> = result
            .for_function("FUN_1800014a0")
            .map(|finding| finding.kind())
            .collect();
        assert_eq!(
            kinds,
            vec!["seh_frame", "error_code", "inherited_error_code"]
        );
    }

    #[test]
    fn an_idiom_finding_converts_to_prompt_data() {
        // The module-context and escalate ERROR HANDLING sections read
        // the finding's own shape — kind, target, suggestion, band, and
        // evidence — with no code, site, or partner to spell.
        let finding = ErrhandlingFinding::SehFrame(framed());
        let info = calxgloss_prompts::ErrhandlingInfo::from(&finding);
        assert_eq!(info.function, "FUN_1800014a0");
        assert_eq!(info.kind, "seh_frame");
        assert_eq!(info.target, "try/catch frame");
        assert_eq!(info.suggestion, SEH_FRAME_SUGGESTION);
        assert_eq!(info.confidence, SPELLED_FRAME_CONFIDENCE);
        assert_eq!(info.evidence, "  catch(...){");
        assert!(info.code.is_none());
        assert!(info.site.is_none());
        assert!(info.partner.is_none());
    }

    #[test]
    fn a_failure_code_finding_converts_with_its_code_and_site_spelled() {
        let finding = ErrhandlingFinding::ErrorCode(coded(ErrorCodeSite::Guard, 64));
        let info = calxgloss_prompts::ErrhandlingInfo::from(&finding);
        assert_eq!(info.target, "failure code");
        assert_eq!(info.code.as_deref(), Some("0x80070057"));
        assert_eq!(info.site.as_deref(), Some("guard"));
        assert!(info.partner.is_none());
    }

    #[test]
    fn an_inherited_code_finding_converts_naming_its_partner() {
        let finding = ErrhandlingFinding::InheritedErrorCode(inherited());
        let info = calxgloss_prompts::ErrhandlingInfo::from(&finding);
        assert_eq!(info.target, "inherited failure code");
        assert_eq!(info.code.as_deref(), Some("0x80070057"));
        assert_eq!(info.partner.as_deref(), Some("FUN_1800412a0"));
        assert!(info.site.is_none());
    }

    #[test]
    fn a_raise_finding_names_its_code_without_becoming_a_code_record() {
        let with = calxgloss_prompts::ErrhandlingInfo::from(&ErrhandlingFinding::RaiseException(
            raised(Some(0xe06d_7363)),
        ));
        assert_eq!(with.code.as_deref(), Some("0xe06d7363"));
        assert!(with.site.is_none());
        assert!(with.partner.is_none());
        // A raise whose argument did not spell a code stays code-less.
        let without = calxgloss_prompts::ErrhandlingInfo::from(
            &ErrhandlingFinding::RaiseException(raised(None)),
        );
        assert!(without.code.is_none());
    }
}
