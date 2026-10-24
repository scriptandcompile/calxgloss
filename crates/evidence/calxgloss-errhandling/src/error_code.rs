//! The failure-code records detector.
//!
//! The failure contract a function keeps is spelled in the kept body
//! itself: the literal it returns on its error path, the literal it
//! compares a callee's return against, and the literal it hands
//! `RaiseException` are the codes its callers branch on and its
//! baseline tests must pin, and one record per distinct code per
//! function keeps that set readable without re-deriving it from the
//! body (issue #290 — the artifact the baseline-test follow-up
//! consumes as the expected outcomes).
//!
//! The literal's shape is the false-positive floor: only values that
//! spell as an HRESULT (`0x8xxx_xxxx`) or an NTSTATUS
//! (`0xCxxx_xxxx`) claim, which is what keeps a BOOL-shaped `0`/`1`
//! return, an ordinary small-integer comparison, and a wide address
//! literal outside those bands silent. A hex or decimal spelling of
//! an in-band value claims alike — the same parse the `RaiseException`
//! reading takes — and a literal too wide for the 32-bit code width
//! claims nothing, as does the C++ eh code (`0xE06D7363`), which is
//! neither shape.
//!
//! The reading is line-local like its siblings: string literals and
//! comments are blanked first, and a paren opened by a call, an
//! index-close, or a dereference `*(` cuts its contents — an argument
//! is not an operand the function returns or compares. A code that
//! only stands in an assignment or a call argument claims nothing.
//! The same code at several sites in one function is one record,
//! carried at its strongest site — a return outranks a raise, a raise
//! outranks a guard comparison — and the record names that site kind
//! with its evidence line, so the artifact can tell "returns this"
//! from "raises this" from "compares for this" and the band rides the
//! kind. A function carrying codes and no idiom shape still carries
//! its code records: the contract and the idiom are different facts.

use crate::goto_cleanup::blank_literals;
use crate::identifier::{find_word, named_token, starts_word};
use crate::raise_exception::{RAISE_EXCEPTION_API, first_argument};
use crate::types::{ErrhandlingFinding, ErrorCode, ErrorCodeSite};
use calxgloss_types::Confidence;

/// Confidence for a code literal standing in a `return` statement —
/// the value goes straight to the caller (issue #290's top band).
///
/// The high band, a notch under the raise call's 75: the literal is
/// spelled outright, which is the most literal body evidence there
/// is, and it is the most direct statement of the failure contract
/// the reading can take — but it names one value the function hands
/// over, not a mechanism the function participates in, so it rides
/// below the raise call's claim of the mechanism itself. This is the
/// band the baseline-test follow-up pins its expected return values
/// from.
pub const ERROR_CODE_RETURN_CONFIDENCE: u8 = 74;

/// Confidence for a code literal standing as a `RaiseException` call's
/// first argument — the code rides the exception path, not the return
/// value (issue #290's raise band).
///
/// A notch under the raise *finding*'s 75, deliberately: the finding
/// claims the function raises at all, spelled by the call's own name;
/// this record claims the one value handed to that mechanism, so it
/// sits below the claim whose argument it is.
pub const ERROR_CODE_RAISE_CONFIDENCE: u8 = 72;

/// Confidence for a code literal compared in a guard — the function
/// tests for the code; whether it also emits it is inference
/// (issue #290's guard band).
///
/// The mid band, between the named handler's 70 and the exception-API
/// call's 60: unlike the API rung, which names only a facility the
/// function talks to, the comparison names the exact contract value —
/// but a guard witnesses a code the function *recognises*, and the
/// #292 propagation reading is what turns a caller's comparison into
/// an inherited contract, at that reading's own penalty off this band.
pub const ERROR_CODE_GUARD_CONFIDENCE: u8 = 64;

/// The Rust pattern a failure-code record steers a translation toward.
///
/// The translation failure mode the spec names is the code dissolving
/// into an ad-hoc Rust error value callers cannot branch on; the
/// honest shape keeps the numeric contract. (ADR-0029's exact mapping
/// belongs to the translator, and this suggestion only names the
/// shape the evidence points at.)
pub const ERROR_CODE_SUGGESTION: &str = "keep this failure code as the numeric code of the Rust error value the function surfaces, preserving the failure contract callers branch on, rather than collapsing it into an ad-hoc error variant";

/// Detect the failure-code literals one function body spells, one
/// record per distinct code.
///
/// The detector answers with every distinct code the body carries —
/// this family is per-code, not per-function, unlike its idiom
/// siblings — and fills no function name; the engine stamps it.
/// Records emerge in body order (the first sighted code first), and a
/// code sighted at several sites stands once, at the strongest
/// sighted kind: a return outranks a raise, a raise outranks a guard
/// comparison.
#[derive(Debug, Clone, Copy, Default)]
pub struct ErrorCodeDetector;

/// One distinct code sighted so far in one body: the winning site
/// kind, its evidence line, and the band that kind carries.
struct Sighting {
    code: u32,
    site: ErrorCodeSite,
    evidence: String,
}

impl ErrorCodeDetector {
    /// Detect the failure-code records in one decompiled body.
    ///
    /// For each line, strings and comments blanked first: a
    /// `RaiseException` call's first argument claims the raise site;
    /// a literal outside call, index, and dereference parens claims
    /// the return site when it stands after the line's `return`
    /// keyword with no comparison in the returned expression, and the
    /// guard site when the line is an `if`/`else`/`while` guard
    /// carrying a comparison. A returned expression that is itself a
    /// comparison (`return (hr == 0xc0000022);`) hands back a 0/1,
    /// not the code, so its literal is carried honestly as a guard
    /// sighting. Everything else — assignments, arguments,
    /// out-of-shape values, BOOL-shaped returns — stays silence.
    pub fn detect(&self, body: &str) -> Vec<ErrhandlingFinding> {
        let mut seen: Vec<Sighting> = Vec::new();
        let mut in_block_comment = false;
        for line in body.lines() {
            let code = blank_literals(line, &mut in_block_comment);
            if code.trim().is_empty() {
                continue;
            }

            // The raise site: only the call's first argument names a
            // code — the flags and parameter-array arguments behind
            // it never do — read through the same cut the raise
            // finding takes.
            if let Some(after) = named_token(&code, RAISE_EXCEPTION_API)
                && let Some(args) = after
                    .trim_start_matches([' ', '\t', '\r'])
                    .strip_prefix('(')
                && let Some(value) = shaped_code(first_argument(args))
            {
                record(&mut seen, value, ErrorCodeSite::Raise, line);
            }

            // The return and guard sites, over the literals that
            // stand outside cut parens. The guard head is read past
            // any peeled closing braces, the decompiler's `} else {`
            // tail spelling.
            let head = code.trim().trim_start_matches('}').trim_start();
            let guard_head =
                starts_word(head, "if") || starts_word(head, "else") || starts_word(head, "while");
            let return_at = find_word(&code, "return");
            for (at, value) in shaped_literals_outside_cuts(&code) {
                let site = match return_at {
                    Some(ret) if at > ret => {
                        // A returned expression that is a comparison
                        // hands back a 0/1, not the code: the honest
                        // reading carries the literal as a guard
                        // sighting even though the line is a return.
                        if has_comparison(&code[ret + "return".len()..]) {
                            ErrorCodeSite::Guard
                        } else {
                            ErrorCodeSite::Return
                        }
                    }
                    _ if guard_head && has_comparison(&code) => ErrorCodeSite::Guard,
                    _ => continue,
                };
                record(&mut seen, value, site, line);
            }
        }

        seen.into_iter()
            .map(|sighting| {
                ErrhandlingFinding::ErrorCode(ErrorCode {
                    function: String::new(),
                    confidence: Confidence::new(match sighting.site {
                        ErrorCodeSite::Return => ERROR_CODE_RETURN_CONFIDENCE,
                        ErrorCodeSite::Raise => ERROR_CODE_RAISE_CONFIDENCE,
                        ErrorCodeSite::Guard => ERROR_CODE_GUARD_CONFIDENCE,
                    }),
                    evidence: sighting.evidence,
                    code: sighting.code,
                    site: sighting.site,
                    suggestion: ERROR_CODE_SUGGESTION.to_string(),
                })
            })
            .collect()
    }
}

/// Suggest a sighting of `code` at `site` into the body-order record
/// list: the first sighting of a code fixes its position, and a later
/// sighting at a stronger site kind replaces the kind and evidence —
/// the one-record-per-code guarantee, kept by construction.
fn record(seen: &mut Vec<Sighting>, code: u32, site: ErrorCodeSite, evidence: &str) {
    match seen.iter_mut().find(|sighting| sighting.code == code) {
        Some(existing) => {
            if site_rank(site) > site_rank(existing.site) {
                existing.site = site;
                existing.evidence = evidence.trim_end().to_string();
            }
        }
        None => seen.push(Sighting {
            code,
            site,
            evidence: evidence.trim_end().to_string(),
        }),
    }
}

/// The contract strength of one site kind, for the one-record-per-code
/// carry: the caller is handed a returned code outright, survives a
/// raised one through the exception path, and merely recognises a
/// compared one.
fn site_rank(site: ErrorCodeSite) -> u8 {
    match site {
        ErrorCodeSite::Return => 2,
        ErrorCodeSite::Raise => 1,
        ErrorCodeSite::Guard => 0,
    }
}

/// Whether `value` spells a failure code: an HRESULT-shaped
/// (`0x8000_0000..=0x8FFF_FFFF`) or NTSTATUS-shaped
/// (`0xC000_0000..=0xCFFF_FFFF`) 32-bit value. A value in neither
/// band — a BOOL flag, a small integer, a wide address spill, the
/// C++ eh code `0xE06D7363` — claims nothing: the shape, not the
/// intent, is the false-positive floor.
fn is_shaped(value: u32) -> bool {
    matches!(value, 0x8000_0000..=0x8fff_ffff | 0xc000_0000..=0xcfff_ffff)
}

/// A bare `0x`-hex or decimal literal standing in `argument`, when it
/// spells an in-band failure code — the parse the raise site reads
/// its first argument through, the code shape gate on top of the
/// raise finding's own literal reading.
fn shaped_code(argument: &str) -> Option<u32> {
    let argument = argument.trim();
    let value = match argument
        .strip_prefix("0x")
        .or_else(|| argument.strip_prefix("0X"))
    {
        Some(hex) if !hex.is_empty() && hex.chars().all(|c| c.is_ascii_hexdigit()) => {
            u32::from_str_radix(hex, 16).ok()?
        }
        None if !argument.is_empty() && argument.chars().all(|c| c.is_ascii_digit()) => {
            argument.parse().ok()?
        }
        _ => return None,
    };
    is_shaped(value).then_some(value)
}

/// The byte offsets and values of every clean `0x`-hex or decimal
/// literal in `s` standing outside cut parens — a paren is cut when
/// an identifier, an index-close, or a dereference `*(` opens it, so
/// a call argument, an indexed address, and a dereferenced load are
/// never operands the function returns or compares; a statement
/// keyword's paren (`if (`, `return (`) and a cast or grouping paren
/// are not. A digit continuing an identifier (`stack0x1234`) or
/// running on into one (`0x80h`) names no clean literal token and
/// claims nothing.
fn shaped_literals_outside_cuts(s: &str) -> Vec<(usize, u32)> {
    let bytes = s.as_bytes();
    let mut out: Vec<(usize, u32)> = Vec::new();
    let mut open: Vec<bool> = Vec::new();
    let mut inside_cut = 0usize;
    let mut i = 0usize;
    while i < bytes.len() {
        match bytes[i] {
            b'(' => {
                // Whitespace before the paren is the decompiler's
                // own spacing (`RaiseException (`); an identifier
                // before it is a call — unless the identifier is a
                // statement keyword, whose paren the reading must
                // see through.
                let mut word_end = i;
                while word_end > 0 && matches!(bytes[word_end - 1], b' ' | b'\t') {
                    word_end -= 1;
                }
                let cut = match bytes.get(word_end.wrapping_sub(1)) {
                    None => false,
                    Some(prev) if prev.is_ascii_alphanumeric() || *prev == b'_' => {
                        let mut word_start = word_end - 1;
                        while word_start > 0
                            && (bytes[word_start - 1].is_ascii_alphanumeric()
                                || bytes[word_start - 1] == b'_')
                        {
                            word_start -= 1;
                        }
                        !matches!(
                            &s[word_start..word_end],
                            "if" | "else" | "while" | "for" | "switch" | "return"
                        )
                    }
                    Some(b')' | b']' | b'*') => true,
                    Some(_) => false,
                };
                open.push(cut);
                if cut {
                    inside_cut += 1;
                }
                i += 1;
            }
            b')' => {
                if let Some(cut) = open.pop()
                    && cut
                {
                    inside_cut -= 1;
                }
                i += 1;
            }
            digit if digit.is_ascii_digit() => {
                let prev_clear =
                    i == 0 || !(bytes[i - 1].is_ascii_alphanumeric() || bytes[i - 1] == b'_');
                let (end, value) = literal_token(bytes, i);
                if prev_clear
                    && inside_cut == 0
                    && let Some(value) = value.filter(|v| is_shaped(*v))
                {
                    out.push((i, value));
                }
                i = end;
                let _ = digit;
            }
            _ => i += 1,
        }
    }
    out
}

/// The end offset of the numeric literal token at `at` — `0x`-hex or
/// decimal, digits continuing to the first character that is not part
/// of the token — and its value, `None` when the spelling is
/// malformed, the token runs on into a longer name (`0x80h`), or the
/// value does not fit the 32-bit code width. Consuming the token is
/// the point even when no value comes back: the digits behind a
/// refusal claim nothing either.
fn literal_token(bytes: &[u8], at: usize) -> (usize, Option<u32>) {
    let hex = bytes[at] == b'0'
        && at + 2 < bytes.len()
        && (bytes[at + 1] == b'x' || bytes[at + 1] == b'X')
        && (bytes[at + 2].is_ascii_hexdigit());
    let (digits_start, radix) = if hex { (at + 2, 16) } else { (at, 10) };
    let mut end = digits_start;
    while end < bytes.len()
        && (if radix == 16 {
            bytes[end].is_ascii_hexdigit()
        } else {
            bytes[end].is_ascii_digit()
        })
    {
        end += 1;
    }
    // The token runs on into a longer name — a suffix, a digit-led
    // identifier tail — when what follows is identifier material.
    if bytes
        .get(end)
        .is_some_and(|next| next.is_ascii_alphanumeric() || *next == b'_')
    {
        return (end, None);
    }
    let value = u32::from_str_radix(
        std::str::from_utf8(&bytes[digits_start..end]).unwrap_or(""),
        radix,
    )
    .ok();
    (end, value)
}

/// Whether the line carries a comparison operator — `==`, `!=`, `<`,
/// `<=`, `>`, `>=` — the gate that keeps a guard reading honest:
/// without an operator the line is a condition of another shape, and
/// a code literal in it witnesses no comparison. The member-access
/// arrow is skipped: `->` is a field read, not a `>` test.
fn has_comparison(s: &str) -> bool {
    let bytes = s.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        match bytes[i] {
            b'=' if i + 1 < bytes.len() && bytes[i + 1] == b'=' => return true,
            b'!' if i + 1 < bytes.len() && bytes[i + 1] == b'=' => return true,
            b'<' => return true,
            b'>' if !(i > 0 && bytes[i - 1] == b'-') => return true,
            _ => {}
        }
        i += 1;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exception_api::EXCEPTION_API_CONFIDENCE;
    use crate::named_handler::NAMED_HANDLER_CONFIDENCE;
    use crate::raise_exception::RAISE_EXCEPTION_CONFIDENCE;
    use crate::seh_frame::SPELLED_FRAME_CONFIDENCE;

    fn body_of(lines: &[&str]) -> String {
        format!("{}\n", lines.join("\n"))
    }

    /// The records of one body, with the code, site, and evidence of
    /// each read straight out — the external behaviour, never the
    /// detector's internals.
    fn codes(body: &str) -> Vec<(u32, ErrorCodeSite, String)> {
        ErrorCodeDetector
            .detect(body)
            .into_iter()
            .map(|finding| match finding {
                ErrhandlingFinding::ErrorCode(record) => {
                    (record.code, record.site, record.evidence.clone())
                }
                other => panic!("expected the code kind, got {other:?}"),
            })
            .collect()
    }

    #[test]
    fn a_returned_hresult_lands_a_code_record_at_its_band() {
        // The shape the whole artifact exists for: the failure value
        // the function hands its caller, named without opening the
        // body.
        let body = body_of(&[
            "  hr = ReadThing(h);",
            "  if (hr) {",
            "    return 0x80070057;",
            "  }",
            "  return 0;",
        ]);
        let findings = ErrorCodeDetector.detect(&body);
        assert_eq!(
            findings.len(),
            1,
            "the BOOL-shaped `return 0;` claims nothing but the shaped code stands"
        );
        match &findings[0] {
            ErrhandlingFinding::ErrorCode(record) => {
                assert_eq!(record.code, 0x8007_0057);
                assert_eq!(record.site, ErrorCodeSite::Return);
                assert_eq!(record.confidence.value(), ERROR_CODE_RETURN_CONFIDENCE);
                assert_eq!(record.evidence, "    return 0x80070057;");
            }
            other => panic!("expected the code kind, got {other:?}"),
        }
        assert_eq!(findings[0].kind(), "error_code");
        assert_eq!(findings[0].target(), "failure code");
    }

    #[test]
    fn a_returned_ntstatus_lands_too() {
        let body = body_of(&["  return 0xc0000022;"]);
        let found = codes(&body);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].0, 0xc000_0022);
        assert_eq!(found[0].1, ErrorCodeSite::Return);
    }

    #[test]
    fn a_guard_comparison_lands_the_code_at_its_band() {
        let body = body_of(&[
            "  hr = Call(a);",
            "  if (hr == 0xc0000022) {",
            "    work();",
            "  }",
        ]);
        let findings = ErrorCodeDetector.detect(&body);
        assert_eq!(findings.len(), 1);
        match &findings[0] {
            ErrhandlingFinding::ErrorCode(record) => {
                assert_eq!(record.code, 0xc000_0022);
                assert_eq!(record.site, ErrorCodeSite::Guard);
                assert_eq!(record.confidence.value(), ERROR_CODE_GUARD_CONFIDENCE);
                assert_eq!(record.evidence, "  if (hr == 0xc0000022) {");
            }
            other => panic!("expected the code kind, got {other:?}"),
        }
    }

    #[test]
    fn a_raise_argument_code_lands_the_code_at_its_band_and_the_eh_code_does_not() {
        // The raise site reads the first argument only; and the C++
        // eh code the raise finding loves (0xE…) is neither shape —
        // the raise finding stands, the code record stays quiet.
        let body = body_of(&["  RaiseException(0x80070057, 0, 0, NULL);"]);
        let found = codes(&body);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].0, 0x8007_0057);
        assert_eq!(found[0].1, ErrorCodeSite::Raise);

        let body = body_of(&["  RaiseException(0xe06d7363, 0, 0, NULL);"]);
        assert!(
            codes(&body).is_empty(),
            "the eh code is no HRESULT and no NTSTATUS"
        );
    }

    #[test]
    fn bool_shaped_returns_and_small_integer_comparisons_claim_nothing() {
        // The issue's false-positive floor, spelled out whole.
        let body = body_of(&[
            "  return 0;",
            "  return 1;",
            "  return -1;",
            "  if (local_4 == 2) {",
            "  return uVar;",
            "  x = 0x80070057;",
            "  puts(\"0x80070057\");",
            "  // return 0x80070057",
            "  printf(\"%x\", 0x80070057);",
            "  if (SetBreak(0x80070057)) {",
            "  Setup(0x80070057);",
        ]);
        assert!(
            codes(&body).is_empty(),
            "BOOL-shaped returns, small-int comparisons, assignments, strings, comments, and call arguments all stay silence: {:?}",
            codes(&body)
        );
    }

    #[test]
    fn a_wide_literal_and_an_out_of_band_value_claim_nothing() {
        // Too wide for the code width, and in neither shape band:
        // the address-spill and flag shapes stay under the floor.
        for line in [
            "  return 0x1ffffffff;",
            "  return 2684354560;",
            "  return 0xffffffff;",
            "  return 0x7fffffff;",
        ] {
            let body = body_of(&[line]);
            assert!(codes(&body).is_empty(), "`{line}` names no shaped code");
        }
    }

    #[test]
    fn a_decimal_spelling_in_band_lands_and_is_recorded_as_the_code_value() {
        // The same contract value, spelled the way Ghidra prints some
        // of them: 0x80070057 = 2147942487.
        let body = body_of(&["  return 2147942487;"]);
        let found = codes(&body);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].0, 0x8007_0057);
    }

    #[test]
    fn the_same_code_at_several_sites_lands_one_record_at_its_strongest_site() {
        // Compared twice, returned once: one record, carried as the
        // return with the return line as its evidence — the
        // per-code guarantee the follow-up baseline test reads
        // without re-deriving the set.
        let body = body_of(&[
            "  if (hr == 0x80070057) {",
            "    work();",
            "  }",
            "  if (hr != 0x80070057) {",
            "    return 0x80070057;",
            "  }",
        ]);
        let found = codes(&body);
        assert_eq!(found.len(), 1, "one code, one record");
        assert_eq!(found[0].0, 0x8007_0057);
        assert_eq!(found[0].1, ErrorCodeSite::Return);
        assert_eq!(found[0].2, "    return 0x80070057;");
    }

    #[test]
    fn two_distinct_codes_lands_two_records_in_body_order() {
        let body = body_of(&[
            "  if (hr == 0xc0000022) {",
            "    return 0x80070057;",
            "  }",
            "  return 0xc0000022;",
        ]);
        let found = codes(&body);
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].0, 0xc000_0022, "the first-sighted code leads");
        assert_eq!(
            found[0].1,
            ErrorCodeSite::Return,
            "…carried at its strongest site"
        );
        assert_eq!(found[1].0, 0x8007_0057);
    }

    #[test]
    fn one_line_comparing_and_returning_splits_its_codes() {
        // The one-line `if (cond) return CODE;` spelling: a literal
        // before the return keyword is the guard's operand, one
        // after it is the returned value.
        let body = body_of(&["  if (hr == 0xc0000022) return 0x80070057;"]);
        let found = codes(&body);
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].0, 0xc000_0022);
        assert_eq!(found[0].1, ErrorCodeSite::Guard);
        assert_eq!(found[0].2, "  if (hr == 0xc0000022) return 0x80070057;");
        assert_eq!(found[1].0, 0x8007_0057);
        assert_eq!(found[1].1, ErrorCodeSite::Return);
    }

    #[test]
    fn a_returned_comparison_carries_its_code_as_a_guard_not_a_return() {
        // `return (hr == 0xc0000022);` hands back a 0/1, not the
        // code: the literal is honestly carried as a guard sighting,
        // so the baseline-test follow-up never pins a code the
        // function only compares for.
        let body = body_of(&["  return (uVar == 0xc0000022);"]);
        let found = codes(&body);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].1, ErrorCodeSite::Guard);
    }

    #[test]
    fn a_cast_returned_code_still_lands() {
        // A grouping or cast paren is not a cut: `(LONG)0x…` is how
        // the decompiler dresses the returned value, not an argument.
        let body = body_of(&["  return (LONG)0x80070057;"]);
        let found = codes(&body);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].1, ErrorCodeSite::Return);
    }

    #[test]
    fn a_dereferenced_address_literal_claims_nothing() {
        // The address-spill shape: `*(base + 0x8…)` dereferences a
        // far offset, it does not return or compare a code.
        let body = body_of(&["  if (*(_image_base_ + 0x80070057) == 1) {"]);
        assert!(codes(&body).is_empty());
    }

    #[test]
    fn while_and_else_tails_are_guard_heads_too() {
        let body = body_of(&[
            "  while (hr != 0xc0000022) {",
            "    work();",
            "  }",
            "} else if (hr == 0x80070057) {",
        ]);
        let found = codes(&body);
        assert_eq!(found.len(), 2);
        assert!(
            found
                .iter()
                .all(|(_, site, _)| *site == ErrorCodeSite::Guard)
        );
    }

    #[test]
    fn a_block_comment_across_lines_names_no_code() {
        // Ghidra sprinkles label decoration; a commented-out return
        // inside a block comment names no contract, exactly as the
        // ladder reading's blanking keeps it from being a statement.
        let body = body_of(&["  /*", "  return 0x80070057;", "  */"]);
        assert!(codes(&body).is_empty());
        let body = body_of(&["  return 0x80070057; /* was 0xc0000022 */"]);
        let found = codes(&body);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].0, 0x8007_0057);
    }

    #[test]
    fn detector_never_claims_a_function_itself() {
        let body = body_of(&["  return 0x80070057;"]);
        let finding = &ErrorCodeDetector.detect(&body)[0];
        assert_eq!(finding.function(), "");
    }

    #[test]
    fn the_code_bands_interleave_the_ladder_and_stay_below_the_spelled_frame() {
        // ADR-0046: each family anchors its own bands, and every
        // code band scores the literal's directness — the returned
        // value near the raise call's own claim, the raised value a
        // notch under it, the compared value mid — with the spelled
        // frame still on top of the whole ladder.
        const {
            assert!(
                SPELLED_FRAME_CONFIDENCE > RAISE_EXCEPTION_CONFIDENCE
                    && RAISE_EXCEPTION_CONFIDENCE > ERROR_CODE_RETURN_CONFIDENCE
                    && ERROR_CODE_RETURN_CONFIDENCE > ERROR_CODE_RAISE_CONFIDENCE
                    && ERROR_CODE_RAISE_CONFIDENCE > NAMED_HANDLER_CONFIDENCE
                    && NAMED_HANDLER_CONFIDENCE > ERROR_CODE_GUARD_CONFIDENCE
                    && ERROR_CODE_GUARD_CONFIDENCE > EXCEPTION_API_CONFIDENCE
            )
        };
    }
}
