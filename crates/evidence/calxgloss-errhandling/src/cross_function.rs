//! Cross-function propagation of the failure-code records.
//!
//! The per-function code reading stops at a body's closing brace. A
//! caller that never spells a literal itself reads clean, even when
//! the value it branches on or hands back is its callee's failure
//! code. This module closes that gap over the bodies one scan already
//! holds. It derives the call map from those bodies — no extra reads
//! from the analysis engine. Each callee's code set comes from the
//! same configured [`ErrorCodeDetector`] re-run on text the scan
//! already has. The pass then copies the callee's recorded codes onto
//! the caller (issue #291, ADR-0047).
//!
//! Two caller shapes inherit. The first is a guard comparing a
//! callee's return against a code literal. The call sits straight
//! inside the comparison (`if (FUN_140006b40(param_1) == 0xc0000001)`),
//! or a local the call just assigned is the one
//! guarded — `iVar1 = FUN_140006b40(param_1);` and a later `if`,
//! `else`, or `while` head comparing it. That guard inherits each
//! compared code the callee's own records name. The second is a whole
//! hand-back of a callee's return to the caller's own caller —
//! `return FUN_140006b40(param_1);`, spelled casts and all, or
//! `return iVar1;` where the assignment names the call. A hand-back
//! carries the callee's *whole* recorded set, raise-site and
//! guard-site codes included: re-returning makes the callee's
//! contract the caller's return value too. A returned comparison
//! (`return iVar1 ==
//! 0xc0000022;`) hands back a 0/1, not a code, and inherits nothing.
//!
//! Only codes travel. A callee's spelled frame, `RaiseException`
//! claim, named handler, or cleanup shape never joins its caller:
//! propagation copies the records a contract is made of, not the
//! reading that found them. One (function, code) pair claims once —
//! the first claim in scan order wins and a second path stays quiet,
//! per ADR-0028's precedent. A callee outside the scanned set, one
//! the scan could not decompile, or one that records no codes
//! contributes nothing: the per-function picture stays exactly as it
//! was. Each pair inherits at most one hop per scan — the callee's
//! per-function records travel, not records that were themselves
//! inherited. A chain resolves scan by scan, not in one pass. An
//! inherited record sits below every band that saw the literal in the
//! body it claims: a second-hand contract is a weaker claim than a
//! first-hand one, and [`INHERITED_ERROR_CODE_CONFIDENCE`] pays the
//! penalty off the guard reading's band.

use crate::error_code::{ERROR_CODE_SUGGESTION, ErrorCodeDetector, shaped_code};
use crate::goto_cleanup::blank_literals;
use crate::identifier::{find_word, starts_word};
use crate::types::{ErrhandlingFinding, InheritedErrorCode};
use calxgloss_decomp::DecompiledFunction;
use calxgloss_types::CallSite;
use calxgloss_types::{
    Confidence, NON_CALL_KEYWORDS, NameContinuation, ScanOptions, call_sites, cast_group,
    is_ident_byte, skip_ws,
};
use std::collections::HashMap;

/// Evidence confidence of a code inherited along one call edge. The
/// callee's record is explicit and the caller's use of the value is a
/// spelled comparison or hand-back, but the caller never spelled the
/// literal itself — the link from the caller's value to the callee's
/// contract is read, not seen (issue #291). The band is the guard
/// reading's 64 with the propagation penalty paid: it sits under the
/// exception-API band's 60 and under the cleanup ladder's 55 as well,
/// so an inherited code never outranks any reading that saw the
/// literal in the body it claims.
pub const INHERITED_ERROR_CODE_CONFIDENCE: u8 = 54;

/// The call-name lookup settings: plain identifier callee names,
/// member and pointer access skipped, C statement keywords are not
/// calls. The call map the propagation walks comes off exactly this
/// configuration.
const CALL_SCAN: ScanOptions = ScanOptions {
    continuation: NameContinuation::Ident,
    reject_preceding: b".>",
    skip_keywords: &NON_CALL_KEYWORDS,
};

/// Cross-function code-propagation readings over the bodies one scan
/// holds.
///
/// The analyzer is stateless: every reading comes from the bodies it
/// is handed and the configured [`ErrorCodeDetector`] it is given, so
/// one analyzer serves an entire scan. It fetches nothing itself. The
/// scan hands it the same [`DecompiledFunction`] values the
/// per-function pass already decompiled, keeping the scan at one
/// decompile per function (ADR-0024's rails: no new analysis-engine
/// reads).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CrossFunctionAnalyzer;

impl CrossFunctionAnalyzer {
    /// An analyzer with no state — the code detector arrives at call
    /// time, so callee sets come from exactly the configured reading.
    pub fn new() -> Self {
        Self
    }

    /// The inherited-code findings the program carries. Callers come
    /// in the order the scan kept their bodies; within one caller,
    /// findings come in line order (a guard comparison ahead of a
    /// hand-back on the same line); a whole hand-back carries the
    /// callee's codes in the callee's own body-record order.
    ///
    /// For every body, each line is read with strings and comments
    /// blanked — the same blanking the failure-code reading does, so
    /// a comparison spelled inside a comment names no guard — and
    /// the call map comes off [`call_sites`] over the blanked line.
    /// A guard head (`if`, `else`, or `while`, past any peeled
    /// closing brace) whose comparison stands a known callee's call
    /// or a just-assigned local against a shaped literal inherits
    /// every compared code that callee records. A `return` handing a
    /// call's value — or a just-assigned local's — back whole
    /// inherits the callee's whole set. One (function, code) pair
    /// claims once, first in this scan order wins. A callee whose
    /// name is the caller's own (recursion) claims nothing.
    pub fn analyze(
        &self,
        functions: &[DecompiledFunction],
        codes: &ErrorCodeDetector,
    ) -> Vec<ErrhandlingFinding> {
        // The callee sets: the configured detector re-run over the
        // bodies the scan already holds — no extra decompile, and
        // every code spelled exactly as the per-function reading
        // names it.
        let mut code_sets: HashMap<&str, Vec<u32>> = HashMap::new();
        for func in functions {
            let set: Vec<u32> = codes
                .detect(&func.body)
                .into_iter()
                .filter_map(|finding| match finding {
                    ErrhandlingFinding::ErrorCode(record) => Some(record.code),
                    _ => None,
                })
                .collect();
            if !set.is_empty() {
                code_sets.insert(func.name.as_str(), set);
            }
        }

        let mut findings: Vec<ErrhandlingFinding> = Vec::new();
        // The one-claim gate, across every inheritance path: the
        // (function, code) pairs already claimed in scan order.
        let mut claimed: Vec<(&str, u32)> = Vec::new();
        for func in functions {
            // Locals the body assigned straight from a call, with
            // the callee and the call-site line each hand-off came
            // from — a guard on the local inherits at the call's
            // line, and a re-return of the local names the callee.
            let mut handed_off: Vec<(String, String, String)> = Vec::new();
            let mut in_block_comment = false;
            for line in func.body.lines() {
                let code = blank_literals(line, &mut in_block_comment);
                if code.trim().is_empty() {
                    continue;
                }
                let evidence_line = line.trim();
                let sites = call_sites(&code, &CALL_SCAN);

                // Remember a whole assignment of a call's value to a
                // plain local before reading the line's own shapes:
                // the one-line `iVar1 = K(x); if (iVar1 == code)`
                // spelling already holds the hand-off.
                if let Some((name, callee)) = assigned_from_call(&code, &sites) {
                    handed_off.retain(|(local, _, _)| local != name);
                    handed_off.push((
                        name.to_string(),
                        callee.to_string(),
                        evidence_line.to_string(),
                    ));
                }

                // The guard-compare path: the line is a statement
                // guard, and the comparison stands a callee's call or
                // a just-assigned local against a shaped literal.
                let head = code.trim().trim_start_matches('}').trim_start();
                let guard_head = starts_word(head, "if")
                    || starts_word(head, "else")
                    || starts_word(head, "while");
                if guard_head {
                    for (op_start, op_end) in comparison_operators(&code) {
                        for (callee, evidence) in [
                            callee_before(
                                &code,
                                op_start,
                                &sites,
                                &handed_off,
                                &func.name,
                                evidence_line,
                            ),
                            callee_after(
                                &code,
                                op_end,
                                &sites,
                                &handed_off,
                                &func.name,
                                evidence_line,
                            ),
                        ]
                        .into_iter()
                        .flatten()
                        {
                            let literal_side = if callee_is_before(&code, op_start) {
                                literal_after(&code, op_end)
                            } else {
                                literal_before(&code, op_start)
                            };
                            if let Some(literal) = literal_side
                                && code_sets
                                    .get(callee.as_str())
                                    .is_some_and(|set| set.contains(&literal))
                                && !claimed
                                    .iter()
                                    .any(|(f, c)| *f == func.name.as_str() && *c == literal)
                            {
                                claimed.push((func.name.as_str(), literal));
                                findings.push(inherited(&func.name, &callee, literal, evidence));
                            }
                        }
                    }
                }

                // The whole hand-back path: a return whose value is a
                // call or a just-assigned local, with the callee's
                // entire recorded set carried back to the caller.
                if let Some((callee, evidence)) =
                    returned_whole(&code, &sites, &handed_off, &func.name, evidence_line)
                    && let Some(set) = code_sets.get(callee.as_str())
                {
                    for &code_value in set {
                        if claimed
                            .iter()
                            .any(|(f, c)| *f == func.name.as_str() && *c == code_value)
                        {
                            continue;
                        }
                        claimed.push((func.name.as_str(), code_value));
                        findings.push(inherited(&func.name, &callee, code_value, evidence));
                    }
                }
            }
        }
        findings
    }
}

/// One inherited-code finding: the caller as its function, the
/// callee as its partner, propagation's own band, the caller's own
/// line as its evidence, and the code's contract suggestion — the
/// same shape the spelled record steers toward.
fn inherited(function: &str, partner: &str, code: u32, evidence: &str) -> ErrhandlingFinding {
    ErrhandlingFinding::InheritedErrorCode(InheritedErrorCode {
        function: function.to_string(),
        partner: partner.to_string(),
        confidence: Confidence::new(INHERITED_ERROR_CODE_CONFIDENCE),
        evidence: evidence.to_string(),
        code,
        suggestion: ERROR_CODE_SUGGESTION.to_string(),
    })
}

/// The comparison operators standing in `code` as `(start, end)` byte
/// spans: `==`, `!=`, `<`, `<=`, `>`, `>=`. The member-access arrow is
/// skipped — `->` reads no test. The shift spellings `<<` and `>>` are
/// consumed as a unit and claim nothing: shifting a callee's value
/// names no comparison against a code. A plain assignment `=` names
/// nothing either; only comparison operators make an operand pair.
fn comparison_operators(code: &str) -> Vec<(usize, usize)> {
    let bytes = code.as_bytes();
    let mut ops: Vec<(usize, usize)> = Vec::new();
    let mut i = 0usize;
    while i < bytes.len() {
        match bytes[i] {
            b'=' if bytes.get(i + 1) == Some(&b'=') => {
                ops.push((i, i + 2));
                i += 2;
            }
            b'!' if bytes.get(i + 1) == Some(&b'=') => {
                ops.push((i, i + 2));
                i += 2;
            }
            b'<' if bytes.get(i + 1) == Some(&b'<') => i += 2,
            b'<' if bytes.get(i + 1) == Some(&b'=') => {
                ops.push((i, i + 2));
                i += 2;
            }
            b'<' => {
                ops.push((i, i + 1));
                i += 1;
            }
            // The arrow: what precedes a `>` is already its `-`.
            b'>' if i > 0 && bytes[i - 1] == b'-' => i += 1,
            b'>' if bytes.get(i + 1) == Some(&b'>') => i += 2,
            b'>' if bytes.get(i + 1) == Some(&b'=') => {
                ops.push((i, i + 2));
                i += 2;
            }
            b'>' => {
                ops.push((i, i + 1));
                i += 1;
            }
            _ => i += 1,
        }
    }
    ops
}

/// The callee standing as the operand before the operator opening at
/// `op_start`, with the line its inheritance evidences at. A call's
/// closing paren at the operand's end resolves to that call's callee,
/// evidenced at this line. A plain local the body assigned straight
/// from a call resolves to that callee, evidenced at the hand-off's
/// own line. A recursion — the callee spelled as the caller's own
/// name — resolves to nothing.
fn callee_before<'a>(
    code: &'a str,
    op_start: usize,
    sites: &[CallSite<'a>],
    handed_off: &'a [(String, String, String)],
    caller: &str,
    evidence_line: &'a str,
) -> Option<(String, &'a str)> {
    let bytes = code.as_bytes();
    let mut i = op_start;
    while i > 0 && bytes[i - 1].is_ascii_whitespace() {
        i -= 1;
    }
    if i == 0 {
        return None;
    }
    if bytes[i - 1] == b')' {
        let callee = sites.iter().find(|site| site.close == i - 1)?.callee;
        return (callee != caller).then(|| (callee.to_string(), evidence_line));
    }
    if is_ident_byte(bytes[i - 1]) {
        let mut start = i - 1;
        while start > 0 && is_ident_byte(bytes[start - 1]) {
            start -= 1;
        }
        let name = &code[start..i];
        return handed_off
            .iter()
            .find(|(local, _, _)| local == name)
            .map(|(_, callee, line)| (callee.clone(), line.as_str()));
    }
    None
}

/// The callee standing as the operand after the operator closing at
/// `op_end` — the mirrored comparison (`if (0xc0000022 == iVar1)`) —
/// seen through any spelled cast, resolving exactly as
/// [`callee_before`] does.
fn callee_after<'a>(
    code: &'a str,
    op_end: usize,
    sites: &[CallSite<'a>],
    handed_off: &'a [(String, String, String)],
    caller: &str,
    evidence_line: &'a str,
) -> Option<(String, &'a str)> {
    let bytes = code.as_bytes();
    let mut i = skip_ws(bytes, op_end);
    while bytes.get(i) == Some(&b'(') {
        let close = cast_group(bytes, i, is_type_word)?;
        i = skip_ws(bytes, close + 1);
    }
    if let Some(site) = sites.iter().find(|s| s.offset == i) {
        return (site.callee != caller).then(|| (site.callee.to_string(), evidence_line));
    }
    if bytes
        .get(i)
        .is_some_and(|b| b.is_ascii_alphabetic() || *b == b'_')
    {
        let mut end = i;
        while end < bytes.len() && is_ident_byte(bytes[end]) {
            end += 1;
        }
        let name = &code[i..end];
        return handed_off
            .iter()
            .find(|(local, _, _)| local == name)
            .map(|(_, callee, line)| (callee.clone(), line.as_str()));
    }
    None
}

/// Whether the operand before the operator at `op_start` is a call
/// or a known local — the side test that decides which side of the
/// operator to parse the literal from. Mirrors [`callee_before`]'s
/// shape test without resolving the name.
fn callee_is_before(code: &str, op_start: usize) -> bool {
    let bytes = code.as_bytes();
    let mut i = op_start;
    while i > 0 && bytes[i - 1].is_ascii_whitespace() {
        i -= 1;
    }
    i > 0 && (bytes[i - 1] == b')' || is_ident_byte(bytes[i - 1]))
}

/// The shaped failure code standing as a literal operand right
/// before the operator opening at `op_start`: a hex or decimal token
/// bounded on its left by anything that does not continue an
/// identifier, parsed through the same shaped gate the failure-code
/// reading takes. `stack0x1234` names no clean literal token and
/// claims nothing.
fn literal_before(code: &str, op_start: usize) -> Option<u32> {
    let bytes = code.as_bytes();
    let mut i = op_start;
    while i > 0 && bytes[i - 1].is_ascii_whitespace() {
        i -= 1;
    }
    if i == 0 || !bytes[i - 1].is_ascii_digit() {
        return None;
    }
    let mut start = i - 1;
    while start > 0 && is_ident_byte(bytes[start - 1]) {
        start -= 1;
    }
    shaped_code(&code[start..i])
}

/// The shaped failure code standing as a literal operand right after
/// the operator closing at `op_end` — [`literal_before`]'s mirror.
fn literal_after(code: &str, op_end: usize) -> Option<u32> {
    let bytes = code.as_bytes();
    let i = skip_ws(bytes, op_end);
    if !bytes.get(i).is_some_and(|b| b.is_ascii_digit()) {
        return None;
    }
    let mut end = i;
    while end < bytes.len() && is_ident_byte(bytes[end]) {
        end += 1;
    }
    shaped_code(&code[i..end])
}

/// The local and callee of a whole assignment of a call's value to a
/// plain local — `iVar1 = FUN_140006b40(param_1);`, seen through any
/// spelled cast on the right side. A store through a dereference,
/// field, or index assigns no hand-off, and neither does a compound
/// assignment. A right side that is more than the call
/// (`iVar1 = K(x) + 1;`), or a right side that is not a call at all,
/// assigns none either: only the bare value the callee returns stands
/// as the callee's value under the decompiler's own naming.
fn assigned_from_call<'a>(code: &'a str, sites: &[CallSite<'a>]) -> Option<(&'a str, &'a str)> {
    let bytes = code.as_bytes();
    let name_start = skip_ws(bytes, 0);
    if !bytes
        .get(name_start)
        .is_some_and(|b| b.is_ascii_alphabetic() || *b == b'_')
    {
        return None;
    }
    let mut name_end = name_start;
    while name_end < bytes.len() && is_ident_byte(bytes[name_end]) {
        name_end += 1;
    }
    let mut at = skip_ws(bytes, name_end);
    if bytes.get(at) != Some(&b'=') || bytes.get(at + 1) == Some(&b'=') {
        return None;
    }
    at = skip_ws(bytes, at + 1);
    while bytes.get(at) == Some(&b'(') {
        let close = cast_group(bytes, at, is_type_word)?;
        at = skip_ws(bytes, close + 1);
    }
    let site = sites.iter().find(|s| s.offset == at)?;
    let after = skip_ws(bytes, site.close + 1);
    matches!(bytes.get(after), None | Some(b';'))
        .then(|| (&code[name_start..name_end], site.callee))
}

/// The callee whose value a `return` hands whole back to the caller,
/// with the line the hand-back evidences at. `return K(x);` (seen
/// through any spelled cast) resolves to `K` at this line, and
/// `return iVar1;` resolves to the callee `iVar1` was assigned from
/// at that hand-off's line. A bare `return;`, a returned literal, a
/// returned expression that is more than the call or local
/// (`return K(x) == 0x80070057;`, `return *K(x);`), and a recursion
/// all hand nothing back.
fn returned_whole<'a>(
    code: &'a str,
    sites: &[CallSite<'a>],
    handed_off: &'a [(String, String, String)],
    caller: &str,
    evidence_line: &'a str,
) -> Option<(String, &'a str)> {
    let at = find_word(code, "return")?;
    let bytes = code.as_bytes();
    let mut i = skip_ws(bytes, at + "return".len());
    while bytes.get(i) == Some(&b'(') {
        let close = cast_group(bytes, i, is_type_word)?;
        i = skip_ws(bytes, close + 1);
    }
    let (tail, callee) = match sites.iter().find(|s| s.offset == i) {
        Some(site) => (skip_ws(bytes, site.close + 1), site.callee.to_string()),
        None => {
            if !bytes
                .get(i)
                .is_some_and(|b| b.is_ascii_alphabetic() || *b == b'_')
            {
                return None;
            }
            let mut end = i;
            while end < bytes.len() && is_ident_byte(bytes[end]) {
                end += 1;
            }
            let name = &code[i..end];
            match handed_off.iter().find(|(local, _, _)| local == name) {
                Some((_, callee, _)) => (skip_ws(bytes, end), callee.clone()),
                None => return None,
            }
        }
    };
    if !matches!(bytes.get(tail), None | Some(b';')) {
        return None;
    }
    (callee != caller).then(|| {
        let evidence = if sites.iter().any(|s| s.offset == i) {
            evidence_line
        } else {
            // The local hand-back evidences at the hand-off line,
            // where the callee's value entered the caller.
            handed_off
                .iter()
                .find(|(local, _, _)| {
                    local
                        == &code[i..{
                            let mut end = i;
                            while end < bytes.len() && is_ident_byte(bytes[end]) {
                                end += 1;
                            }
                            end
                        }]
                })
                .map_or(evidence_line, |(_, _, line)| line.as_str())
        };
        (callee, evidence)
    })
}

/// The type words a decompiler cast may spell. This is the same
/// vocabulary the shared [`cast_group`] scan strips everywhere else in
/// the workspace, restated for this crate so the propagation reads a
/// caller's spelled cast without reaching into a sibling crate's
/// internals for one word list.
fn is_type_word(word: &str) -> bool {
    matches!(
        word,
        "undefined"
            | "undefined1"
            | "undefined2"
            | "undefined3"
            | "undefined4"
            | "undefined5"
            | "undefined6"
            | "undefined7"
            | "undefined8"
            | "ushort"
            | "uint"
            | "ulong"
            | "ulonglong"
            | "longlong"
            | "short"
            | "uchar"
            | "char"
            | "byte"
            | "word"
            | "dword"
            | "qword"
            | "void"
            | "code"
            | "size_t"
            | "wchar_t"
            | "bool"
            | "int"
            | "float"
            | "double"
    )
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error_code::{ERROR_CODE_GUARD_CONFIDENCE, ERROR_CODE_RETURN_CONFIDENCE};
    use crate::exception_api::EXCEPTION_API_CONFIDENCE;
    use crate::goto_cleanup::GOTO_CLEANUP_RELEASE_CONFIDENCE;

    fn function(name: &str, body: &str) -> DecompiledFunction {
        DecompiledFunction {
            name: name.to_string(),
            signature: format!("undefined {name}(void)"),
            body: format!("undefined {name}(void)\n\n{{\n{body}}}\n"),
        }
    }

    /// The pass over canned bodies, as the scan keeps them.
    fn analyze(bodies: &[(&str, &str)]) -> Vec<ErrhandlingFinding> {
        let functions: Vec<DecompiledFunction> = bodies
            .iter()
            .map(|(name, body)| function(name, body))
            .collect();
        CrossFunctionAnalyzer::new().analyze(&functions, &ErrorCodeDetector)
    }

    /// The external behaviour, read straight out: caller, callee,
    /// code, and evidence of every inherited record.
    fn inherited(findings: &[ErrhandlingFinding]) -> Vec<(String, String, u32, String)> {
        findings
            .iter()
            .map(|finding| match finding {
                ErrhandlingFinding::InheritedErrorCode(record) => (
                    record.function.clone(),
                    record.partner.clone(),
                    record.code,
                    record.evidence.clone(),
                ),
                other => panic!("propagation emits inherited records only, got {other:?}"),
            })
            .collect()
    }

    /// A callee recording two codes: an access-denied guard and an
    /// invalid-argument return.
    const CODED_CALLEE: &str =
        "  hr = NtQuery(handle);\n  if (hr == 0xc0000022) return hr;\n  return 0x80070057;\n";

    #[test]
    fn a_guard_comparing_a_callees_return_inherits_the_compared_code() {
        // The shape the issue opens with: the call straight inside
        // the comparison, the compared code the callee records.
        let findings = analyze(&[
            ("callee", CODED_CALLEE),
            (
                "caller",
                "  if (callee(param_1) == 0x80070057) {\n    fail();\n  }\n  return 0;\n",
            ),
        ]);
        assert_eq!(
            inherited(&findings),
            vec![(
                "caller".to_string(),
                "callee".to_string(),
                0x8007_0057,
                "if (callee(param_1) == 0x80070057) {".to_string(),
            )],
            "the compared code the callee records, evidenced at the guard's own line"
        );
        assert_eq!(
            findings[0].confidence().value(),
            INHERITED_ERROR_CODE_CONFIDENCE
        );
    }

    #[test]
    fn a_guard_on_a_local_the_call_assigned_inherits_at_the_call_line() {
        // The decompiler's own spelling — assign, then test. The
        // guard claims only the code it compares; the callee's other
        // recorded codes are not handed to this caller.
        let findings = analyze(&[
            ("callee", CODED_CALLEE),
            (
                "caller",
                "  iVar1 = callee(param_1);\n  if (iVar1 == 0xc0000022) {\n    fail();\n  }\n",
            ),
        ]);
        assert_eq!(
            inherited(&findings),
            vec![(
                "caller".to_string(),
                "callee".to_string(),
                0xc000_0022,
                "iVar1 = callee(param_1);".to_string(),
            )],
            "only the compared code, evidenced where the callee's value entered"
        );
    }

    #[test]
    fn a_while_guard_reads_as_a_comparison_too() {
        let findings = analyze(&[
            ("callee", CODED_CALLEE),
            (
                "caller",
                "  while (callee(param_1) != 0x80070057) {\n    retry();\n  }\n",
            ),
        ]);
        assert_eq!(inherited(&findings).len(), 1);
    }

    #[test]
    fn a_callee_recording_no_codes_inherits_nothing() {
        // The caller spelled a shaped comparison — the per-function
        // reading records it there — but the callee hands back no
        // recorded code, so propagation claims nothing.
        let findings = analyze(&[
            ("callee", "  work();\n  return 0;\n"),
            (
                "caller",
                "  if (callee(param_1) == 0x80070057) {\n    fail();\n  }\n",
            ),
        ]);
        assert!(findings.is_empty(), "nothing travelled, nothing claimed");
    }

    #[test]
    fn a_compared_literal_outside_the_callees_set_claims_nothing() {
        // The callee records the invalid-argument code, and the
        // caller compares for the access-denied one. The sets never
        // meet, and no contract connects these two functions.
        let findings = analyze(&[
            ("callee", "  if (bad) return 0x80070057;\n  return 0;\n"),
            (
                "caller",
                "  if (callee(param_1) == 0xc0000022) {\n    fail();\n  }\n",
            ),
        ]);
        assert!(findings.is_empty());
    }

    #[test]
    fn a_returned_call_carries_the_callees_whole_recorded_set() {
        // The second inheritance path: a hand-back makes the
        // callee's contract the caller's return value, raise-site
        // and guard-site codes included — the caller's caller sees
        // them whether or not this caller ever compared for one.
        let callee = "  RaiseException(0x80070005, 0, NULL, 0);\n  if (hr == 0xc0000022) \
                      return 1;\n  return 0x80070057;\n";
        let findings = analyze(&[
            ("callee", callee),
            ("caller", "  return callee(param_1);\n"),
        ]);
        assert_eq!(
            inherited(&findings),
            vec![
                (
                    "caller".to_string(),
                    "callee".to_string(),
                    0x8007_0005,
                    "return callee(param_1);".to_string(),
                ),
                (
                    "caller".to_string(),
                    "callee".to_string(),
                    0xc000_0022,
                    "return callee(param_1);".to_string(),
                ),
                (
                    "caller".to_string(),
                    "callee".to_string(),
                    0x8007_0057,
                    "return callee(param_1);".to_string(),
                ),
            ],
            "the callee's own body order, all its codes, none of its idioms"
        );
    }

    #[test]
    fn a_returned_local_carries_the_set_and_evidences_at_the_hand_off_line() {
        let findings = analyze(&[
            ("callee", CODED_CALLEE),
            ("caller", "  iVar1 = callee(param_1);\n  return iVar1;\n"),
        ]);
        let rows = inherited(&findings);
        assert_eq!(rows.len(), 2);
        assert!(
            rows.iter()
                .all(|(_, partner, _, evidence)| partner == "callee"
                    && evidence == "iVar1 = callee(param_1);"),
            "the hand-back names the callee and evidences where the value entered: {rows:?}"
        );
    }

    #[test]
    fn a_returned_cast_hand_back_still_carries_the_set() {
        let findings = analyze(&[
            ("callee", CODED_CALLEE),
            ("caller", "  return (ulong)callee(param_1);\n"),
        ]);
        assert_eq!(inherited(&findings).len(), 2, "spelled casts hide nothing");
    }

    #[test]
    fn a_returned_comparison_hands_back_a_flag_not_a_code() {
        // `return iVar1 == 0xc0000022;` gives the caller's caller a
        // 0/1 — the callee's code stays inside the comparison, and
        // neither inheritance path fires.
        let findings = analyze(&[
            ("callee", CODED_CALLEE),
            (
                "caller",
                "  iVar1 = callee(param_1);\n  return iVar1 == 0xc0000022;\n",
            ),
        ]);
        assert!(
            findings.is_empty(),
            "a returned flag propagates no failure code"
        );
    }

    #[test]
    fn the_first_claim_of_one_function_and_code_wins() {
        // Both inheritance paths reach the same code from different
        // callees; scan order takes the one record and the second
        // path stays quiet.
        let callee = "  return 0x80070057;\n";
        let findings = analyze(&[
            ("first", callee),
            ("second", callee),
            (
                "caller",
                "  if (first(param_1) == 0x80070057) {\n    fail();\n  }\n  return second(param_1);\n",
            ),
        ]);
        assert_eq!(
            inherited(&findings),
            vec![(
                "caller".to_string(),
                "first".to_string(),
                0x8007_0057,
                "if (first(param_1) == 0x80070057) {".to_string(),
            )],
            "the guard claim came first in line order and holds the one record"
        );
    }

    #[test]
    fn two_comparisons_on_one_line_resolve_to_their_own_callees() {
        let findings = analyze(&[
            ("first", "  return 0x80070005;\n"),
            ("second", "  return 0xc0000022;\n"),
            (
                "caller",
                "  if (first(a) == 0x80070005 || second(b) == 0xc0000022) {\n    fail();\n  }\n",
            ),
        ]);
        let mut rows = inherited(&findings);
        rows.sort();
        assert_eq!(
            rows,
            vec![
                (
                    "caller".to_string(),
                    "first".to_string(),
                    0x8007_0005,
                    "if (first(a) == 0x80070005 || second(b) == 0xc0000022) {".to_string(),
                ),
                (
                    "caller".to_string(),
                    "second".to_string(),
                    0xc000_0022,
                    "if (first(a) == 0x80070005 || second(b) == 0xc0000022) {".to_string(),
                ),
            ],
            "each comparison claims its own call's set, not the other's"
        );
    }

    #[test]
    fn an_unscanned_callee_carries_nothing() {
        // A library routine or a thunk the scan could not read holds
        // no records this scan could name, so no claim is made.
        let findings = analyze(&[(
            "caller",
            "  if (LoadLibraryExW(name) == 0x80070057) {\n    fail();\n  }\n",
        )]);
        assert!(findings.is_empty());
    }

    #[test]
    fn propagation_hops_one_edge_per_scan() {
        // The leaf's code reaches the middle (a whole hand-back);
        // the middle spells no literal itself, so its own recorded
        // set is empty and the caller above inherits nothing this
        // scan — the chain resolves scan by scan, never in one pass.
        let findings = analyze(&[
            ("leaf", "  if (bad) return 0x80070057;\n  return 0;\n"),
            ("middle", "  return leaf(param_1);\n"),
            ("caller", "  return middle(param_1);\n"),
        ]);
        assert_eq!(
            inherited(&findings),
            vec![(
                "middle".to_string(),
                "leaf".to_string(),
                0x8007_0057,
                "return leaf(param_1);".to_string(),
            )],
            "one hop, and only the direct caller's contract moves"
        );
    }

    #[test]
    fn recursion_inherits_nothing_from_itself() {
        let findings = analyze(&[(
            "recursive",
            "  if (recursive(n - 1) == 0x80070057) return 0x80070057;\n  return 0;\n",
        )]);
        assert!(findings.is_empty(), "a function is not its own partner");
    }

    #[test]
    fn a_comparison_spelled_inside_a_comment_inherits_nothing() {
        // The blanking is the point: a commented-out guard names no
        // comparison, exactly as the same blanking names no failure
        // code in the per-function reading (issue #290's rule carried
        // onto the pair).
        let findings = analyze(&[
            ("callee", CODED_CALLEE),
            (
                "caller",
                "  iVar1 = callee(param_1);\n  // if (iVar1 == 0xc0000022) fail();\n  work();\n",
            ),
        ]);
        assert!(findings.is_empty());
    }

    #[test]
    fn shifts_and_arrows_are_not_comparisons() {
        let findings = analyze(&[
            ("callee", CODED_CALLEE),
            (
                "caller",
                "  iVar1 = callee(param_1);\n  iVar1 >> 0xc0000022;\n  obj->field == 0x80070057;\n",
            ),
        ]);
        assert!(
            findings.is_empty(),
            "a shift by a shaped constant and an arrow-separated line name no guard"
        );
    }

    #[test]
    fn a_hand_back_of_a_computed_call_result_names_no_whole_return() {
        // `return callee(param_1) + 1;` hands back an arithmetic
        // result, not the callee's value — the contract did not move
        // whole, so nothing travels.
        let findings = analyze(&[
            ("callee", CODED_CALLEE),
            ("caller", "  return callee(param_1) + 1;\n"),
        ]);
        assert!(findings.is_empty());
    }

    #[test]
    fn an_inherited_record_names_its_caller_partner_and_band() {
        let findings = analyze(&[
            ("callee", CODED_CALLEE),
            ("caller", "  return callee(param_1);\n"),
        ]);
        let finding = &findings[0];
        assert_eq!(finding.kind(), "inherited_error_code");
        assert_eq!(finding.target(), "inherited failure code");
        assert_eq!(finding.function(), "caller");
        assert_eq!(
            finding.confidence().value(),
            INHERITED_ERROR_CODE_CONFIDENCE
        );
        assert!(finding.suggestion().contains("failure contract"));
        match finding {
            ErrhandlingFinding::InheritedErrorCode(record) => {
                assert_eq!(record.partner, "callee");
            }
            other => panic!("expected the inherited kind, got {other:?}"),
        }
    }

    #[test]
    fn the_inherited_band_sits_below_every_first_hand_reading() {
        // ADR-0047's ranking, pinned by construction: the guard's
        // 64, the exception-API band's 60, and the cleanup ladder's
        // 55 all outrank a code read across one call edge.
        const {
            assert!(
                ERROR_CODE_RETURN_CONFIDENCE > ERROR_CODE_GUARD_CONFIDENCE
                    && ERROR_CODE_GUARD_CONFIDENCE > EXCEPTION_API_CONFIDENCE
                    && EXCEPTION_API_CONFIDENCE > GOTO_CLEANUP_RELEASE_CONFIDENCE
                    && GOTO_CLEANUP_RELEASE_CONFIDENCE > INHERITED_ERROR_CODE_CONFIDENCE
            )
        };
    }

    #[test]
    fn the_analyzer_carries_no_state_across_scans() {
        let analyzer = CrossFunctionAnalyzer::new();
        let bodies = [
            ("callee", CODED_CALLEE),
            ("caller", "  return callee(param_1);\n"),
        ];
        let functions: Vec<DecompiledFunction> = bodies
            .iter()
            .map(|(name, body)| function(name, body))
            .collect();
        let first = analyzer.analyze(&functions, &ErrorCodeDetector);
        let second = analyzer.analyze(&functions, &ErrorCodeDetector);
        assert_eq!(first, second, "the same bodies read the same both times");
    }
}
