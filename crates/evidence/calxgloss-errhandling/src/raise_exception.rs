//! The direct `RaiseException` call detector.
//!
//! A function that calls `RaiseException` itself is the *source* of an
//! exception, not a guarded victim of one — the raised code is the
//! handler contract every caller up the chain must survive, and where
//! the first argument is a literal the record names that code so the
//! contract is visible without opening the body (issue #288, ADR-0046:
//! `RaiseException` joins the union as its own kind, beside the SEH
//! frame families rather than inside them). A named-constant or
//! computed first argument still lands the finding with no code
//! claimed — the raise is a fact, the code is only as certain as the
//! text shows it.

use crate::identifier::named_token;
use crate::types::{ErrhandlingFinding, RaiseException};
use calxgloss_types::Confidence;

/// Confidence for a direct `RaiseException` call (ADR-0046's family
/// ladder).
///
/// The high band, between the spelled frame's 80 and the named
/// handler's 70: the call is spelled in kept body text by name, which
/// is as literal as body evidence gets, but unlike a spelled frame it
/// shows the function *raising* into a mechanism rather than the
/// decompiler reading the frame's whole structure. The engine takes
/// this finding beside the function's one SEH finding, not instead of
/// it — the raise and the frame are different facts.
pub const RAISE_EXCEPTION_CONFIDENCE: u8 = 75;

/// The API whose call position names the raise. The undecorated
/// kernel32 spelling only: `__raise_exception` (the compiler
/// intrinsic) is a different facility, and case- and
/// identifier-boundary matching keeps `RaiseExceptionFilter` and a
/// hand-named `MyRaiseException` out.
pub const RAISE_EXCEPTION_API: &str = "RaiseException";

/// The Rust pattern a direct raise steers a translation toward.
///
/// Emulating `RaiseException` in a Rust translation recreates the
/// SEH mechanism in code that has no SEH mechanism; the honest shape
/// is an error value that carries the raised code, so the caller set
/// the function raises into can keep the contract (ADR-0029's
/// caller-set decision belongs to the translator, and this suggestion
/// only names the shape the evidence points at).
pub const RAISE_EXCEPTION_SUGGESTION: &str = "surface the exception the function raises as a Rust error value carrying the exception code, rather than emulating RaiseException";

/// Detect a direct `RaiseException` call in one function body.
///
/// The detector answers with at most one finding per function — the
/// reading is the function-level fact "this function raises
/// exceptions" — and fills no function name; the engine stamps it.
/// When the call's first argument is a numeric literal, the record
/// names the raised exception code; any other first argument (an
/// identifier, a cast, a wrapped call) lands the finding with no code
/// claimed.
#[derive(Debug, Clone, Copy, Default)]
pub struct RaiseExceptionDetector;

impl RaiseExceptionDetector {
    /// Detect a direct `RaiseException` call in one decompiled body.
    ///
    /// The shape is the name as a whole identifier with its `(` after
    /// it (spaces and tabs allowed between). The first such line in
    /// body order is the evidence; the code is read from that line's
    /// first argument, so a call wrapped across lines lands with no
    /// code claimed rather than reaching into other lines.
    pub fn detect(&self, body: &str) -> Option<ErrhandlingFinding> {
        for line in body.lines() {
            let Some(after_name) = named_token(line, RAISE_EXCEPTION_API) else {
                continue;
            };
            let args = after_name.trim_start_matches([' ', '\t', '\r']);
            let Some(args) = args.strip_prefix('(') else {
                // A name sighting that is not a call — a function
                // pointer stored, say — is not a raise.
                continue;
            };
            let code = literal_code(first_argument(args));
            return Some(ErrhandlingFinding::RaiseException(RaiseException {
                function: String::new(),
                confidence: Confidence::new(RAISE_EXCEPTION_CONFIDENCE),
                evidence: line.trim_end().to_string(),
                code,
                suggestion: RAISE_EXCEPTION_SUGGESTION.to_string(),
            }));
        }
        None
    }
}

/// The call's first argument: the text from the open paren to the
/// first top-level comma (or the close paren, or the line's end).
/// Parenthesised and bracketed runs nest, so a cast or a nested call
/// stays one argument.
fn first_argument(args: &str) -> &str {
    let mut depth = 0usize;
    for (idx, ch) in args.char_indices() {
        match ch {
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => {
                if depth == 0 {
                    return &args[..idx];
                }
                depth -= 1;
            }
            ',' if depth == 0 => return &args[..idx],
            _ => {}
        }
    }
    args
}

/// The raised code, when the first argument is a bare numeric
/// literal — a `0x`-prefixed hex or a plain decimal that fits a
/// `u32` (exception codes are 32-bit values). A named constant, a
/// cast, an expression, or a literal that does not fit claims no
/// code: the finding never invents a contract the body does not
/// spell.
fn literal_code(argument: &str) -> Option<u32> {
    let argument = argument.trim();
    if argument.is_empty() {
        return None;
    }
    if let Some(hex) = argument
        .strip_prefix("0x")
        .or_else(|| argument.strip_prefix("0X"))
    {
        // A `0x` spelling is only a literal if what follows is hex
        // digits; a malformed form claims nothing.
        if hex.chars().all(|c| c.is_ascii_hexdigit()) && !hex.is_empty() {
            return u32::from_str_radix(hex, 16).ok();
        }
        return None;
    }
    // Decimal spelling — Ghidra prints some values that way; still a
    // literal, still the contract.
    if argument.chars().all(|c| c.is_ascii_digit()) {
        return argument.parse().ok();
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seh_frame::SPELLED_FRAME_CONFIDENCE;

    fn body_of(lines: &[&str]) -> String {
        format!("{}\n", lines.join("\n"))
    }

    #[test]
    fn a_raise_with_a_hex_literal_names_the_raised_code() {
        // The C++ eh code, the shape that matters most: the handler
        // contract visible without opening the body.
        let body = body_of(&["  RaiseException(0xe06d7363, 0, 0, NULL);", "  return 0;"]);
        let finding = RaiseExceptionDetector
            .detect(&body)
            .expect("the direct raise must be detected");
        assert_eq!(finding.kind(), "raise_exception");
        assert_eq!(finding.confidence().value(), RAISE_EXCEPTION_CONFIDENCE);
        assert_eq!(
            finding.evidence(),
            "  RaiseException(0xe06d7363, 0, 0, NULL);"
        );
        match &finding {
            ErrhandlingFinding::RaiseException(record) => {
                assert_eq!(record.code, Some(0xe06d_7363));
            }
            other => panic!("expected the raise kind, got {other:?}"),
        }
    }

    #[test]
    fn a_raise_with_a_decimal_literal_names_the_code_too() {
        let body = body_of(&["  RaiseException(1073741824, 0, 0, NULL);"]);
        let finding = RaiseExceptionDetector.detect(&body).unwrap();
        match &finding {
            ErrhandlingFinding::RaiseException(record) => {
                assert_eq!(record.code, Some(0x4000_0000));
            }
            other => panic!("expected the raise kind, got {other:?}"),
        }
    }

    #[test]
    fn a_non_literal_first_argument_lands_the_finding_with_no_code() {
        // The raise is the fact; the code is only as certain as the
        // text shows it. Identifier, cast, and nested-call arguments
        // all claim no code.
        for arg in ["code", "(DWORD)0xe06d7363", "GetExceptionCode()"] {
            let body = body_of(&[&format!("  RaiseException({arg}, 0, 0, NULL);")]);
            let finding = RaiseExceptionDetector
                .detect(&body)
                .unwrap_or_else(|| panic!("`RaiseException({arg}, ...)` must land the finding"));
            match &finding {
                ErrhandlingFinding::RaiseException(record) => {
                    assert_eq!(record.code, None, "no code for argument `{arg}`");
                }
                other => panic!("expected the raise kind, got {other:?}"),
            }
        }
    }

    #[test]
    fn a_literal_beyond_the_32_bit_code_width_claims_no_code() {
        // Exception codes are 32-bit; an oversized literal is not a
        // code, and the record refuses to invent one.
        let body = body_of(&["  RaiseException(0x1ffffffff, 0, 0, NULL);"]);
        let finding = RaiseExceptionDetector.detect(&body).unwrap();
        match &finding {
            ErrhandlingFinding::RaiseException(record) => assert_eq!(record.code, None),
            other => panic!("expected the raise kind, got {other:?}"),
        }
    }

    #[test]
    fn a_call_wrapped_across_lines_lands_with_no_code_claimed() {
        // The line-local reading takes the raise from the line that
        // spells `RaiseException(`; the code on a later line stays
        // unclaimed rather than the detector reaching for it.
        let body = body_of(&["  RaiseException(", "    0xe06d7363, 0, 0, NULL);"]);
        let finding = RaiseExceptionDetector
            .detect(&body)
            .expect("the raise is spelled even when wrapped");
        assert_eq!(finding.evidence(), "  RaiseException(");
        match &finding {
            ErrhandlingFinding::RaiseException(record) => assert_eq!(record.code, None),
            other => panic!("expected the raise kind, got {other:?}"),
        }
    }

    #[test]
    fn one_finding_per_function_however_many_raises() {
        // The function-level reading stands once however many codes
        // the body raises; per-code records are #290's ErrorCode
        // family, not a stack of duplicates here.
        let body = body_of(&[
            "  RaiseException(0xe06d7363, 0, 0, NULL);",
            "  RaiseException(0x80070057, 0, 0, NULL);",
        ]);
        let finding = RaiseExceptionDetector.detect(&body).unwrap();
        assert_eq!(finding.kind(), "raise_exception");
        assert_eq!(
            finding.evidence(),
            "  RaiseException(0xe06d7363, 0, 0, NULL);"
        );
    }

    #[test]
    fn look_alike_names_and_intrinsics_claim_nothing() {
        // `RaiseExceptionFilter` and `MyRaiseException` are not the
        // API; the `__raise_exception` intrinsic is a different
        // facility, and case-sensitive matching keeps `raiseexception`
        // out too.
        let body = body_of(&[
            "  old = RaiseExceptionFilter(0);",
            "  MyRaiseException(0);",
            "  __raise_exception();",
            "  raiseexception(0);",
        ]);
        assert!(RaiseExceptionDetector.detect(&body).is_none());
    }

    #[test]
    fn a_bare_name_sighting_without_a_call_claims_nothing() {
        let body = body_of(&["  pRaise = RaiseException;"]);
        assert!(RaiseExceptionDetector.detect(&body).is_none());
    }

    #[test]
    fn gs_canary_noise_claims_nothing() {
        // The guard rail (issue #288): a GS stack-canary check —
        // cookie comparison and cookie save, alone beside other
        // compiler noise — names no exception API and claims no SEH
        // finding.
        let body = body_of(&[
            "  uVar = __security_cookie ^ (ulonglong)&stack0xfffffffffffffff4;",
            "  if (uStack_8 == __security_cookie) {",
            "    goto joined_r0x140001337;",
            "  }",
            "  x = __security_check_cookie(local_8);",
        ]);
        assert!(RaiseExceptionDetector.detect(&body).is_none());
    }

    #[test]
    fn the_raise_band_sits_below_the_spelled_block() {
        // ADR-0046: no reading outranks the spelled block's 80.
        const { assert!(RAISE_EXCEPTION_CONFIDENCE < SPELLED_FRAME_CONFIDENCE) };
    }

    #[test]
    fn detector_never_claims_a_function_itself() {
        let body = body_of(&["  RaiseException(0x1, 0, 0, NULL);"]);
        let finding = RaiseExceptionDetector.detect(&body).unwrap();
        assert_eq!(finding.function(), "");
    }

    #[test]
    fn first_argument_stops_at_the_top_level_comma_through_nesting() {
        // A cast and a nested call stay one argument; the comma that
        // ends it is the outermost one.
        assert_eq!(first_argument("(DWORD)(0x1), 0);"), "(DWORD)(0x1)");
        assert_eq!(first_argument("foo(a, b), c);"), "foo(a, b)");
        assert_eq!(first_argument("0x1"), "0x1");
        assert_eq!(first_argument("0x1, 0"), "0x1");
    }
}
