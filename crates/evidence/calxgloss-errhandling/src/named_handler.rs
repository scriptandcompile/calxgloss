//! The named personality-handler thunk detector.
//!
//! Where the decompiler does *not* reconstruct an SEH frame into a
//! spelled `try`/`catch` block, the frame still leaves its handler in
//! the body text: MSVC registers one of a handful of named
//! personality-handler thunks — `__except_handler3`,
//! `_except_handler4`, `_CxxFrameHandler3` — and where one of those
//! names stands as a whole identifier in a kept body, the function is
//! guarded by an exception frame whether or not the decompiler drew
//! it (issue #288, ADR-0046's named-handler rung). The reading claims
//! exactly that sighting and nothing else: a body merely *resembling*
//! an SEH frame, or naming a decorated variant of one of these
//! routines, stays silence, and a GS stack-canary check — cookie
//! comparison or cookie save — names none of these thunks and claims
//! nothing (issue #288's guard rail: shipped noise-filter strips the
//! canary family, and this is the insurance against a filter miss).

use crate::identifier::named_token;
use crate::seh_frame::SEH_FRAME_SUGGESTION;
use crate::types::{ErrhandlingFinding, NamedHandler};
use calxgloss_types::Confidence;

/// Confidence for a frame seen through a named personality-handler
/// thunk (ADR-0046's rung ladder).
///
/// The high-mid band, a rung below the spelled block's 80 and above
/// the exception-API call's 60: the thunk name witnesses a real frame
/// registration, but the decompiler never read the frame's structure,
/// so the claim is thinner than a spelled block's and thicker than an
/// API call's. `ErrhandlingEngine` keeps the ranking honest by taking
/// the strongest family that fires, whatever the numbers say.
pub const NAMED_HANDLER_CONFIDENCE: u8 = 70;

/// The personality-handler thunks whose spelled registration names a
/// frame: the SEH2 (`__except_handler3`) and SEH4 (`_except_handler4`)
/// C-runtime handlers and the C++ frame handler. The spellings are
/// MSVC's own; the identifier boundary also admits the engine's
/// deeper-underscore decorations, and refuses longer or prefixed
/// variants like `_except_handler4_common`.
pub const PERSONALITY_HANDLER_THUNKS: [&str; 3] =
    ["__except_handler3", "_except_handler4", "_CxxFrameHandler3"];

/// Detect a named personality-handler thunk in one function body.
///
/// The detector answers with at most one finding per function — a
/// frame is a function-level shape, and one function never carries a
/// stack of duplicate SEH claims — and fills no function name; the
/// engine stamps it. The evidence is the body line carrying the
/// registration, the thunk's name visible inside it.
#[derive(Debug, Clone, Copy, Default)]
pub struct NamedHandlerDetector;

impl NamedHandlerDetector {
    /// Detect a named-handler frame in one decompiled body.
    ///
    /// Any line naming one of [`PERSONALITY_HANDLER_THUNKS`] as a
    /// whole identifier carries the claim — a registration call, a
    /// handler pointer argument, or the name standing alone all
    /// witness the registration; only the identifier boundary is
    /// load-bearing. The first such line in body order is the
    /// evidence.
    pub fn detect(&self, body: &str) -> Option<ErrhandlingFinding> {
        for line in body.lines() {
            if PERSONALITY_HANDLER_THUNKS
                .iter()
                .any(|thunk| named_token(line, thunk).is_some())
            {
                return Some(ErrhandlingFinding::NamedHandler(NamedHandler {
                    function: String::new(),
                    confidence: Confidence::new(NAMED_HANDLER_CONFIDENCE),
                    evidence: line.trim_end().to_string(),
                    // The same Rust mapping the spelled frame steers
                    // toward: this is the same frame, read through
                    // weaker evidence.
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
    use crate::seh_frame::SPELLED_FRAME_CONFIDENCE;

    fn body_of(lines: &[&str]) -> String {
        format!("{}\n", lines.join("\n"))
    }

    #[test]
    fn each_named_thunk_lands_the_finding_with_its_line_as_evidence() {
        // The three spelled registrations the issue names, each on a
        // body line of its own shape.
        let bodies = [
            body_of(&["  pExc = __except_handler3;", "  work();"]),
            body_of(&["  _except_handler4(&frame, 0xFFFFFFFF);", "  work();"]),
            body_of(&[
                "  _CxxFrameHandler3(1, 0, lookup, this_ptr, frame);",
                "  work();",
            ]),
        ];
        for body in &bodies {
            let finding = NamedHandlerDetector
                .detect(body)
                .expect("the named thunk must be detected");
            assert_eq!(finding.confidence().value(), NAMED_HANDLER_CONFIDENCE);
            assert_eq!(finding.kind(), "named_handler");
            let thunk_names = ["__except_handler3", "_except_handler4", "_CxxFrameHandler3"];
            assert!(
                thunk_names.iter().any(|n| finding.evidence().contains(n)),
                "the evidence line names the thunk: {:?}",
                finding.evidence()
            );
        }
    }

    #[test]
    fn decorated_underscore_spellings_still_count() {
        // The engine's decoration of `_except_handler4` adds
        // underscores; the frame registration is the same fact.
        let body = body_of(&["  __except_handler4(a, b);"]);
        let finding = NamedHandlerDetector
            .detect(&body)
            .expect("the decorated spelling is the same registration");
        assert!(finding.evidence().contains("__except_handler4"));
    }

    #[test]
    fn first_sighting_in_body_order_is_the_evidence() {
        let body = body_of(&[
            "  work();",
            "  _except_handler4(&frame, -1);",
            "  _CxxFrameHandler3(1, 0, lookup, this_ptr, frame);",
        ]);
        let finding = NamedHandlerDetector.detect(&body).unwrap();
        assert_eq!(finding.evidence(), "  _except_handler4(&frame, -1);");
    }

    #[test]
    fn one_finding_per_function_however_many_registrations() {
        // The frame is a function-level reading; two named handlers
        // are still the one claim.
        let body = body_of(&[
            "  _except_handler4(&f1, -1);",
            "  _CxxFrameHandler3(1, 0, l, t, f2);",
        ]);
        assert_eq!(
            NamedHandlerDetector.detect(&body).unwrap().kind(),
            "named_handler"
        );
        assert_eq!(
            NamedHandlerDetector
                .detect(&body)
                .unwrap()
                .confidence()
                .value(),
            70
        );
    }

    #[test]
    fn decorated_variant_names_claim_nothing() {
        // `_except_handler4_common` is a different routine;
        // `my_except_handler3` is the program's own function. The
        // identifier boundary is what keeps these out.
        let body = body_of(&[
            "  _except_handler4_common(a, b, c);",
            "  my_except_handler3(x);",
            "  imp__CxxFrameHandler3(y);",
        ]);
        assert!(NamedHandlerDetector.detect(&body).is_none());
    }

    #[test]
    fn gs_canary_noise_claims_nothing() {
        // The guard rail (issue #288): a GS stack-canary check —
        // cookie save, cookie comparison, and the guard-runtime call,
        // beside the engine's join-label noise — reads as compiler
        // noise, not as exception handling. The shipped noise filter
        // strips these bodies; this is the insurance against a
        // filter miss.
        let body = body_of(&[
            "  uVar = __security_cookie ^ (ulonglong)&stack0xfffffffffffffff4;",
            "  if (uStack_8 == __security_cookie) {",
            "    goto joined_r0x140001337;",
            "  }",
            "  x = __security_check_cookie(local_8);",
        ]);
        assert!(NamedHandlerDetector.detect(&body).is_none());
    }

    #[test]
    fn an_ordinary_body_claims_nothing() {
        let body = body_of(&["  handle = CreateFileW(path, access);", "  return handle;"]);
        assert!(NamedHandlerDetector.detect(&body).is_none());
    }

    #[test]
    fn the_named_handler_rung_sits_below_the_spelled_block() {
        // ADR-0046's ladder: every family scores strictly below the
        // family above it, so a report can rank what it is shown.
        const { assert!(NAMED_HANDLER_CONFIDENCE < SPELLED_FRAME_CONFIDENCE) };
    }

    #[test]
    fn detector_never_claims_a_function_itself() {
        let body = body_of(&["  _CxxFrameHandler3(1, 0, l, t, f);"]);
        let finding = NamedHandlerDetector.detect(&body).unwrap();
        assert_eq!(finding.function(), "");
    }
}
