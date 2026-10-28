//! Return-type inference from how callers use the returned value.
//!
//! No body reads its own return, so a function whose callers all treat
//! its result as a `char *` still decompiles as `undefined FUN_x`.
//! [`ReturnUsageDetector`] reads each caller's call sites of the function
//! and types the return from the shape the value is used in:
//!
//! - **assigned to a typed local** — `local_8 = FUN_x();` where the
//!   caller's own scan reading already stands `local_8` as `char *`
//!   lends the function that return type;
//! - **passed at a known-signature position** — `strlen(FUN_x());` reads
//!   the result as the contract types that argument position
//!   ([`KnownTypePropagationEngine::match_signature`]);
//! - **dereferenced or field-accessed** — `*FUN_x()` or `FUN_x()->field`
//!   says the result is a pointer, though not to what.
//!
//! The evidence is the caller's line, so the record is the return kind
//! the vocabulary has for exactly this reading — [`InferredReturnType`]
//! at `RETURN_USAGE_CONFIDENCE`, keyed by the function whose return it
//! reads. Every call site contributes its candidate, and the scan's
//! conflict resolution keeps the strongest, first-seen one, so one
//! function never shows two return types. The detector fetches nothing
//! itself: the scan hands it the caller bodies the caller→callee pass
//! already fetched, keeping the scan at one decompile per function.
//!
//! [`KnownTypePropagationEngine::match_signature`]: crate::known_type::KnownTypePropagationEngine::match_signature
//! [`InferredReturnType`]: crate::types::InferredReturnType

use std::collections::HashMap;

use crate::cross_function::is_bare_identifier;
use crate::known_type::{BYTE_BUFFER, KnownTypePropagationEngine};
use crate::types::{InferenceMethod, InferenceScope, InferredReturnType, InferredType};
use calxgloss_decomp::DecompiledFunction;

use calxgloss_types::{
    CallSite, NON_CALL_KEYWORDS, NameContinuation, ScanOptions, call_sites, line_at, skip_char,
    skip_string, skip_ws,
};

/// How the pseudo-C call scan reads: plain-identifier callees, member
/// accesses skipped, and C keywords — `if (x)` — not calls. The same
/// shape the cross-function pass uses: this pass reads the same direct
/// call sites, just for the *use* of the value rather than the value of
/// the arguments.
const CALL_SCAN: ScanOptions = ScanOptions {
    continuation: NameContinuation::Ident,
    reject_preceding: b".>",
    skip_keywords: &NON_CALL_KEYWORDS,
};

/// Every direct call `name(args)` in the body — the shared pseudo-C
/// scan configured by [`CALL_SCAN`], nested calls included.
fn direct_calls(body: &str) -> Vec<CallSite<'_>> {
    call_sites(body, &CALL_SCAN)
}

/// Evidence confidence of a return reading inferred from caller usage.
/// The usage is concrete — this call, this expression — but the type is
/// only as good as the reading behind the usage shape: an inferred
/// local, a library contract, or the bare fact of a dereference. The
/// reading therefore sits at the bottom of the confidence ladder, level
/// with the assignment-chain family, below every inline and
/// known-signature reading.
const RETURN_USAGE_CONFIDENCE: u8 = 60;

/// The surviving local readings of a scan, grouped by the function they
/// belong to and keyed by decompiled name. These are the types an
/// assignment of the return value can be read against. A function or a
/// name absent from the map was never typed and lends nothing.
pub type LocalReadings<'a> = HashMap<&'a str, HashMap<&'a str, &'a str>>;

/// Return-type inference over one function's callers.
///
/// The detector is stateless: every reading comes from the caller bodies
/// and the surviving local readings it is handed, so one detector serves
/// an entire scan. It fetches nothing itself: the scan hands it the same
/// [`DecompiledFunction`] values the caller→callee pass already fetched,
/// keeping the scan at one decompile per function.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReturnUsageDetector {
    known: KnownTypePropagationEngine,
}

impl ReturnUsageDetector {
    /// A detector whose only contract source is the shared known-
    /// signature database; the caller bodies and local readings come in
    /// through [`infer_returns`](Self::infer_returns) at call time.
    pub fn new() -> Self {
        Self {
            known: KnownTypePropagationEngine::new(),
        }
    }

    /// The return records `callers` produce for `callee`, in caller
    /// order and, within one caller, call-site order: one
    /// [`InferredType::Return`] per call site whose use of the value
    /// gives a reading, keyed by the callee's name, with the caller's
    /// line as evidence.
    ///
    /// A call site contributes only when the returned value sits in a
    /// shape that names a type: the plain assignment target of a local
    /// the scan typed in that same caller, an argument at a position a
    /// known signature reads, or a dereference / `->` field access (a
    /// pointer, pointee unknown). A bare statement call, a comparison,
    /// an assignment to an untyped or non-local target, a call nested
    /// in a callee the database does not know, and a multiplication say
    /// nothing. The callee's own body is never read: a function returns
    /// what its callers take it to return.
    ///
    /// Where several callers read the return differently, every reading
    /// is emitted and the scan's conflict resolution keeps the
    /// strongest, first-seen one for the function.
    pub fn infer_returns(
        &self,
        callee: &DecompiledFunction,
        callers: &[&DecompiledFunction],
        local_readings: &LocalReadings,
    ) -> Vec<InferredType> {
        let mut records = Vec::new();
        for caller in callers {
            let calls = direct_calls(&caller.body);
            let locals = local_readings.get(caller.name.as_str());
            for call in &calls {
                if call.callee != callee.name {
                    continue;
                }
                let evidence = line_at(&caller.body, call.offset);
                let inferred_type = self
                    .assigned_local_type(call, &caller.body, locals)
                    .or_else(|| self.known_position_type(call, &calls, &caller.body))
                    .or_else(|| self.dereference_type(call, &caller.body));
                if let Some(inferred_type) = inferred_type {
                    records.push(self.record(callee, &inferred_type, &evidence));
                }
            }
        }
        records
    }

    /// The caller's own reading of a local the result is assigned to:
    /// `local_8 = FUN_x();` where `local_8` stands typed in this
    /// caller. The assignment must be plain (not `==`, not `+=`), the
    /// target a bare identifier, and the call the whole source. A cast
    /// around it (`(char *)FUN_x()`) names a type the scan does not
    /// read here, and an untyped or non-local target says nothing.
    fn assigned_local_type(
        &self,
        call: &CallSite,
        body: &str,
        locals: Option<&HashMap<&str, &str>>,
    ) -> Option<String> {
        let target = assignment_target(body, call.offset)?;
        let locals = locals?;
        locals.get(target).map(|text| (*text).to_string())
    }

    /// The contract reading at the position of a known-signature call
    /// the result is passed into: `strlen(FUN_x());` reads the result as
    /// `strlen` reads its first argument. Only the *innermost* enclosing
    /// call counts — the one the result is a direct argument of. The
    /// call must be the whole argument (a cast or expression around it
    /// names no value the contract reads). An enclosing callee the
    /// database does not know, or a position the contract does not read,
    /// says nothing.
    fn known_position_type(
        &self,
        call: &CallSite,
        calls: &[CallSite],
        body: &str,
    ) -> Option<String> {
        let enclosing = calls
            .iter()
            .filter(|outer| outer.offset < call.offset && call.offset < outer.close)
            .max_by_key(|outer| outer.offset)?;
        let matched = self.known.match_signature(enclosing.callee)?;
        let open = skip_ws(body.as_bytes(), enclosing.offset + enclosing.callee.len());
        let position = argument_position(body, open, call.offset);
        // The call must be the whole argument: a cast or expression
        // around it (`(char *)FUN_x()`, `FUN_x() + 1`) names no value
        // the contract reads, exactly as the assignment shape refuses
        // a cast around the call.
        let call_text = &body[call.offset..call.close + 1];
        enclosing
            .args
            .get(position)
            .filter(|arg| arg.trim() == call_text)?;
        matched
            .resolved_args()
            .into_iter()
            .find(|arg| arg.position == position)
            .map(|arg| arg.inferred_type.to_string())
    }

    /// The pointer reading a dereference or field access gives the
    /// result: `*FUN_x()` or `FUN_x()->field` says the value is a
    /// pointer, though not to what — the byte-buffer reading the
    /// database's buffer contracts use. A `*` in a multiplication
    /// (`uVar2 * FUN_x()`) is not a dereference.
    fn dereference_type(&self, call: &CallSite, body: &str) -> Option<String> {
        (is_dereferenced(body, call.offset) || is_field_accessed(body, call.close))
            .then(|| BYTE_BUFFER.to_string())
    }

    /// Assemble one reading into its record: the return-usage method,
    /// function scope — the reading is about this function's return,
    /// nothing beyond it — and the caller's line as evidence.
    fn record(
        &self,
        callee: &DecompiledFunction,
        inferred_type: &str,
        evidence: &str,
    ) -> InferredType {
        InferredType::Return(InferredReturnType {
            function: callee.name.clone(),
            inferred_type: inferred_type.to_string(),
            method: InferenceMethod::ReturnUsage,
            scope: InferenceScope::Function,
            confidence: RETURN_USAGE_CONFIDENCE.into(),
            evidence: evidence.to_string(),
        })
    }
}

/// The target of a plain `target = ` prefix ending just before a call
/// at `offset`, or nothing when the call does not sit at the start of a
/// plain assignment's source. `==` comparisons, compound assignments
/// (`+=`, `<<=`), control headers (`for (uVar2 = 0; …)`), and targets
/// that are not a bare identifier (`*puVar5`, `local_8[0]`) name no
/// assignable local.
fn assignment_target(body: &str, offset: usize) -> Option<&str> {
    let line_start = body[..offset].rfind('\n').map_or(0, |i| i + 1);
    let prefix = body[line_start..offset].trim_end();
    let before = prefix.strip_suffix('=')?;
    let last = before.as_bytes().last().copied();
    if matches!(
        last,
        Some(b'=' | b'<' | b'>' | b'!' | b'+' | b'-' | b'*' | b'/' | b'%' | b'&' | b'|' | b'^')
    ) {
        return None;
    }
    let target = before.trim();
    is_bare_identifier(target).then_some(target)
}

/// The top-level argument position containing `offset` within the
/// argument list opened at `open`: the number of depth-0 commas between
/// the opening paren and the offset.
fn argument_position(body: &str, open: usize, offset: usize) -> usize {
    let bytes = body.as_bytes();
    let mut depth = 0usize;
    let mut commas = 0usize;
    let mut i = open + 1;
    while i < offset && i < bytes.len() {
        match bytes[i] {
            b'"' => i = skip_string(bytes, i + 1),
            b'\'' => i = skip_char(bytes, i + 1),
            b'(' | b'[' | b'{' => {
                depth += 1;
                i += 1;
            }
            b')' | b']' | b'}' => {
                depth = depth.saturating_sub(1);
                i += 1;
            }
            b',' if depth == 0 => {
                commas += 1;
                i += 1;
            }
            _ => i += 1,
        }
    }
    commas
}

/// Whether the call at `offset` is dereferenced: a `*` immediately
/// before the callee, in unary position. A `*` after a value — `uVar2 *
/// FUN_x()` — is multiplication, not a dereference, unless the word
/// before it is `return`.
fn is_dereferenced(body: &str, offset: usize) -> bool {
    let bytes = body.as_bytes();
    let mut i = offset;
    while i > 0 && (bytes[i - 1] as char).is_ascii_whitespace() {
        i -= 1;
    }
    if i == 0 || bytes[i - 1] != b'*' {
        return false;
    }
    let mut k = i - 1;
    while k > 0 && (bytes[k - 1] as char).is_ascii_whitespace() {
        k -= 1;
    }
    if k == 0 {
        return true;
    }
    let before_star = bytes[k - 1];
    if before_star.is_ascii_alphanumeric() || matches!(before_star, b'_' | b')' | b']') {
        return word_before(bytes, k - 1) == "return";
    }
    true
}

/// The identifier ending at `end` (inclusive), used to tell a unary
/// `return *p` from a multiplication `x * p`.
fn word_before(bytes: &[u8], end: usize) -> &str {
    let mut start = end;
    while start > 0 {
        let prev = bytes[start - 1];
        if prev.is_ascii_alphanumeric() || prev == b'_' {
            start -= 1;
        } else {
            break;
        }
    }
    std::str::from_utf8(&bytes[start..=end]).unwrap_or("")
}

/// Whether the call closed at `close` is field-accessed: `->` follows
/// the closing parenthesis.
fn is_field_accessed(body: &str, close: usize) -> bool {
    let bytes = body.as_bytes();
    let i = skip_ws(bytes, close + 1);
    bytes.get(i..).is_some_and(|rest| rest.starts_with(b"->"))
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Confidence;

    fn callee() -> DecompiledFunction {
        DecompiledFunction {
            name: "FUN_180051c00".into(),
            signature: "undefined FUN_180051c00(void)".into(),
            body: "\nundefined FUN_180051c00(void)\n\n{\n  return;\n}\n".into(),
        }
    }

    fn caller(name: &str, body: &str) -> DecompiledFunction {
        DecompiledFunction {
            name: name.into(),
            signature: format!("undefined {name}(void)"),
            body: format!("\nundefined {name}(void)\n\n{{\n{body}}}\n"),
        }
    }

    fn local_readings<'a>(entries: &[(&'a str, &'a str, &'a str)]) -> LocalReadings<'a> {
        let mut readings = LocalReadings::new();
        for (function, name, inferred_type) in entries {
            readings
                .entry(function)
                .or_default()
                .insert(name, *inferred_type);
        }
        readings
    }

    fn returned(caller_body: &str, readings: &LocalReadings) -> Vec<InferredType> {
        let caller = caller("FUN_18003ab00", caller_body);
        ReturnUsageDetector::new().infer_returns(&callee(), &[&caller], readings)
    }

    #[test]
    fn a_detector_carries_no_state() {
        assert_eq!(ReturnUsageDetector::new(), ReturnUsageDetector::new());
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<ReturnUsageDetector>();
    }

    #[test]
    fn a_result_assigned_to_a_typed_local_lends_its_reading() {
        let records = returned(
            "  local_8 = FUN_180051c00();\n",
            &local_readings(&[("FUN_18003ab00", "local_8", "char *")]),
        );

        assert_eq!(records.len(), 1);
        let InferredType::Return(record) = &records[0] else {
            unreachable!("the pass emits return records");
        };
        assert_eq!(record.function, "FUN_180051c00");
        assert_eq!(record.inferred_type, "char *");
        assert_eq!(record.method, InferenceMethod::ReturnUsage);
        assert_eq!(record.scope, InferenceScope::Function);
        assert_eq!(record.confidence, Confidence::new(60));
        assert_eq!(record.evidence, "local_8 = FUN_180051c00();");
    }

    #[test]
    fn a_result_assigned_to_an_untyped_local_types_nothing() {
        // The name has no surviving reading in this caller, and a
        // reading stored under another function's name never applies
        // to this one.
        let records = returned(
            "  local_8 = FUN_180051c00();\n",
            &local_readings(&[("FUN_18003ab00", "local_10", "char *")]),
        );
        assert!(records.is_empty());
    }

    #[test]
    fn a_result_passed_at_a_known_position_lends_the_contract() {
        // `strlen` reads its first argument as a character string.
        let records = returned("  strlen(FUN_180051c00());\n", &LocalReadings::new());
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].inferred_type(), "char *");
        assert_eq!(records[0].confidence(), Confidence::new(60));
        let InferredType::Return(record) = &records[0] else {
            unreachable!("the pass emits return records");
        };
        assert_eq!(record.evidence, "strlen(FUN_180051c00());");

        // The position decides: `malloc` reads position 0 as a count,
        // and a position past its contract says nothing.
        let records = returned("  malloc(FUN_180051c00());\n", &LocalReadings::new());
        assert_eq!(records[0].inferred_type(), "size_t");
        let records = returned("  malloc(0x10, FUN_180051c00());\n", &LocalReadings::new());
        assert!(records.is_empty(), "position 1 is not read");

        // A cast around the call names no value the contract reads.
        let records = returned(
            "  strlen((char *)FUN_180051c00());\n",
            &LocalReadings::new(),
        );
        assert!(
            records.is_empty(),
            "a cast-wrapped result is not passed as-is"
        );
    }

    #[test]
    fn a_result_nested_in_an_unknown_call_types_nothing() {
        // The innermost enclosing callee is not in the database, and
        // the pass does not reach further out.
        let records = returned(
            "  FUN_18004b210(FUN_180051c00(), 0x10);\n",
            &LocalReadings::new(),
        );
        assert!(records.is_empty());
    }

    #[test]
    fn a_dereferenced_or_field_accessed_result_reads_a_pointer() {
        let records = returned("  iVar1 = *FUN_180051c00();\n", &LocalReadings::new());
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].inferred_type(), "void *");
        let InferredType::Return(record) = &records[0] else {
            unreachable!("the pass emits return records");
        };
        assert_eq!(record.evidence, "iVar1 = *FUN_180051c00();");

        let records = returned("  FUN_180051c00()->field = 3;\n", &LocalReadings::new());
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].inferred_type(), "void *");

        let records = returned("  return *FUN_180051c00();\n", &LocalReadings::new());
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].inferred_type(), "void *");
    }

    #[test]
    fn a_bare_call_comparison_or_multiplication_types_nothing() {
        let records = returned(
            "  FUN_180051c00();\n\
             \x20 if (FUN_180051c00() == 0) {\n\
             \x20 uVar1 = uVar2 * FUN_180051c00();\n",
            &LocalReadings::new(),
        );
        assert!(
            records.is_empty(),
            "a discarded result, a comparison, and a multiplication name no type"
        );
    }

    #[test]
    fn assignment_shapes_that_name_no_local_type_nothing() {
        let readings = local_readings(&[("FUN_18003ab00", "local_8", "char *")]);
        let records = returned(
            "  local_8[0] = FUN_180051c00();\n\
             \x20 *puVar5 = FUN_180051c00();\n\
             \x20 local_8 += FUN_180051c00();\n\
             \x20 local_8 = (char *)FUN_180051c00();\n",
            &readings,
        );
        assert!(
            records.is_empty(),
            "an indexed or dereferenced target, a compound assignment, \
             and a cast around the call name no typed local"
        );
    }

    #[test]
    fn every_caller_contributes_and_resolution_picks_the_winner() {
        // Two callers, two readings: the detector emits both candidates
        // in caller order and the scan's conflict resolution keeps one.
        let first = caller("FUN_18003ab00", "  local_8 = FUN_180051c00();\n");
        let second = caller("FUN_1800412a0", "  strlen(FUN_180051c00());\n");
        let readings = local_readings(&[("FUN_18003ab00", "local_8", "wchar_t *")]);
        let records =
            ReturnUsageDetector::new().infer_returns(&callee(), &[&first, &second], &readings);

        assert_eq!(records.len(), 2);
        assert_eq!(records[0].inferred_type(), "wchar_t *");
        assert_eq!(records[1].inferred_type(), "char *");
        let winners = crate::confidence::resolve_conflicts(records);
        assert_eq!(
            winners.len(),
            1,
            "one function never shows two return types"
        );
        assert_eq!(winners[0].inferred_type(), "wchar_t *");
    }

    #[test]
    fn a_call_to_another_function_is_not_a_use_of_the_return() {
        let records = returned(
            "  FUN_18004b210();\n  strlen(FUN_18004b210());\n",
            &local_readings(&[("FUN_18003ab00", "local_8", "char *")]),
        );
        assert!(records.is_empty());
    }
}
