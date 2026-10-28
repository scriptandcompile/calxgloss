//! The exception-API call detector.
//!
//! Some programs call the exception-handling APIs directly: reading
//! the current filter's code, installing a top-level filter, or
//! registering a vectored handler. Such a call shows SEH
//! participation without spelling any frame. A body that calls
//! `GetExceptionCode`/`__exception_code` (the public macro name and
//! the intrinsic behind it), `SetUnhandledExceptionFilter`, or
//! `AddVectoredExceptionHandler` is a function that lives inside or
//! beside an exception mechanism, even where the decompiler left no
//! frame in the body text (issue #288, ADR-0046's exception-API
//! band). The claim needs the call shape — the name in call position
//! with its `(` after it — so an API name merely stored in a pointer
//! or compared claims nothing. A GS stack-canary check names none of
//! these APIs and claims nothing. That is the canary guard rail: the
//! shipped noise filter strips canary bodies, and this rule is the
//! insurance against a filter miss.

use crate::identifier::{named_token, starts_call};
use crate::seh_frame::SEH_FRAME_SUGGESTION;
use crate::types::{ErrhandlingFinding, ExceptionApiCall};
use calxgloss_types::Confidence;

/// Evidence confidence for an SEH reading taken from an
/// exception-API call (ADR-0046's confidence ladder).
///
/// The mid band, below the named handler's 70. The call names an
/// exception facility the function talks to, but the API alone does
/// not prove a frame *in this function* the way a spelled block or a
/// handler registration does: the function might only be asking for
/// the code its own filter was handed. It is still more than noise,
/// and it is the strongest SEH band that rests on a call alone.
pub const EXCEPTION_API_CONFIDENCE: u8 = 60;

/// The exception-API names that show SEH participation when they
/// stand in call position: the current filter's code reader under
/// both its spellings (the intrinsic `__exception_code` and the
/// public macro name `GetExceptionCode`), the top-level filter
/// installer, and the vectored-handler registrar.
pub const EXCEPTION_API_NAMES: [&str; 4] = [
    "GetExceptionCode",
    "__exception_code",
    "SetUnhandledExceptionFilter",
    "AddVectoredExceptionHandler",
];

/// Detect an exception-API call in one function body.
///
/// The detector answers with at most one finding per function — the
/// reading is the function-level fact "this function talks to the
/// exception mechanism" — and fills no function name; the scan
/// stamps it. The scan only runs this detector when neither the
/// spelled frame nor a named handler fired, so one function never
/// collects duplicate SEH claims for one frame.
#[derive(Debug, Clone, Copy, Default)]
pub struct ExceptionApiDetector;

impl ExceptionApiDetector {
    /// Detect an exception-API call in one decompiled body.
    ///
    /// The shape is an API name from [`EXCEPTION_API_NAMES`] standing
    /// as a whole identifier with its `(` after it (spaces and tabs
    /// allowed between — a spaced call is still the call). The first
    /// such line in body order is the evidence.
    pub fn detect(&self, body: &str) -> Option<ErrhandlingFinding> {
        for line in body.lines() {
            if EXCEPTION_API_NAMES
                .iter()
                .any(|api| named_token(line, api).is_some_and(starts_call))
            {
                return Some(ErrhandlingFinding::ExceptionApiCall(ExceptionApiCall {
                    function: String::new(),
                    confidence: Confidence::new(EXCEPTION_API_CONFIDENCE),
                    evidence: line.trim_end().to_string(),
                    // The reading's Rust mapping is the spelled
                    // frame's: an error type mapped from the
                    // exception, rather than straight-line code that
                    // loses the exception meaning.
                    suggestion: SEH_FRAME_SUGGESTION.to_string(),
                }));
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::named_handler::NAMED_HANDLER_CONFIDENCE;

    fn body_of(lines: &[&str]) -> String {
        format!("{}\n", lines.join("\n"))
    }

    #[test]
    fn each_api_call_lands_the_finding_naming_the_api() {
        let bodies = [
            body_of(&["  code = GetExceptionCode();", "  return code;"]),
            body_of(&[
                "  if (__exception_code() == 0x80000003) {",
                "    return 1;",
                "  }",
            ]),
            body_of(&["  SetUnhandledExceptionFilter(my_filter);"]),
            body_of(&["  AddVectoredExceptionHandler(1, handler);"]),
        ];
        for body in &bodies {
            let finding = ExceptionApiDetector
                .detect(body)
                .expect("the exception-API call must be detected");
            assert_eq!(finding.confidence().value(), EXCEPTION_API_CONFIDENCE);
            assert_eq!(finding.kind(), "exception_api_call");
            assert!(
                EXCEPTION_API_NAMES
                    .iter()
                    .any(|api| finding.evidence().contains(api)),
                "the evidence line names the API: {:?}",
                finding.evidence()
            );
        }
    }

    #[test]
    fn spaced_call_spelling_still_counts() {
        // `Name (` with whitespace before the paren is still the
        // call shape; only a sighting without a call anywhere on the
        // line claims nothing.
        let body = body_of(&["  AddVectoredExceptionHandler (1, handler);"]);
        assert!(ExceptionApiDetector.detect(&body).is_some());
    }

    #[test]
    fn name_sightings_without_a_call_claim_nothing() {
        // A filter pointer stored, compared, or returned is not the
        // function talking to the exception mechanism in call shape.
        let body = body_of(&[
            "  pfn = SetUnhandledExceptionFilter;",
            "  if (GetExceptionCode == NULL) { return; }",
            "  return AddVectoredExceptionHandler;",
        ]);
        assert!(ExceptionApiDetector.detect(&body).is_none());
    }

    #[test]
    fn look_alike_names_claim_nothing() {
        // Identifier boundaries again: `GetExceptionCodeEx` and a
        // hand-named `my_GetExceptionCode` are the program's own.
        let body = body_of(&[
            "  code = GetExceptionCodeEx(0);",
            "  x = my_AddVectoredExceptionHandler(1);",
        ]);
        assert!(ExceptionApiDetector.detect(&body).is_none());
    }

    #[test]
    fn gs_canary_noise_claims_nothing() {
        // The guard rail (issue #288): cookie save, cookie
        // comparison, and the guard-runtime call name no exception
        // API; a canary check never reads as SEH participation,
        // alone or beside other noise.
        let body = body_of(&[
            "  uVar = __security_cookie ^ (ulonglong)&stack0xfffffffffffffff4;",
            "  if (uStack_8 == __security_cookie) {",
            "    goto joined_r0x140001337;",
            "  }",
            "  x = __security_check_cookie(local_8);",
            "  thunk = _guard_check_icall_fptr;",
        ]);
        assert!(ExceptionApiDetector.detect(&body).is_none());
    }

    #[test]
    fn an_ordinary_body_claims_nothing() {
        let body = body_of(&["  handle = CreateFileW(path, access);", "  return handle;"]);
        assert!(ExceptionApiDetector.detect(&body).is_none());
    }

    #[test]
    fn the_api_rung_sits_below_the_named_handler() {
        // ADR-0046's ladder, continued: spelled 80 > named 70 > API.
        const { assert!(EXCEPTION_API_CONFIDENCE < NAMED_HANDLER_CONFIDENCE) };
    }

    #[test]
    fn detector_never_claims_a_function_itself() {
        let body = body_of(&["  code = GetExceptionCode();"]);
        let finding = ExceptionApiDetector.detect(&body).unwrap();
        assert_eq!(finding.function(), "");
    }
}
