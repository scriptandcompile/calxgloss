//! Parameter direction detection.
//!
//! [`ParamDirectionDetector`] reads from a function's own body which way
//! data flows through each of its pointer parameters: a body that writes
//! through the pointer before returning makes the parameter an *out*
//! parameter, one a known string function reads makes it an *in* one,
//! and a parameter both read and written reads as *inout*. The reading
//! rides the body the scan already keeps — the same kept bodies the
//! assignment-chain and return-usage passes ride, no extra engine reads —
//! and every record's evidence line names the deciding write or read.
//! A direct write (issue #274's families: plain `*param_1 = x` and its
//! double-pointer hand-back form `*param_2 = &local_8`) claims the
//! solid-high band the ADR anchors, and a string-function read the
//! modest band; field and indexed writes and bare reads join the
//! families in the follow-up at the bands that ADR fixes below the
//! direct write. Where the body shows no deciding shape the detector
//! records nothing: absence is unknown, never silently *in* — passing a
//! parameter to an unknown callee is no evidence either way, the
//! reading never guesses about a callee it has not read, and a value
//! parameter written only at its own name is no write *through* a
//! pointer.

use crate::known_type::is_type_word;
use crate::param_size::STRING_FUNCTIONS;
use crate::types::{
    Confidence, Direction, InferenceMethod, InferenceScope, InferredParamDirection,
};
use calxgloss_decomp::DecompiledFunction;
use calxgloss_types::{
    CallSite, NON_CALL_KEYWORDS, NameContinuation, ScanOptions, call_sites, is_ident_byte, line_at,
    skip_string, strip_casts,
};

// ============================================================
// Reading confidences
// ============================================================

/// Confidence of a direction reading decided by a direct write through
/// the pointer: the body spells the store out — `*param_1 = x`, or the
/// allocate-and-hand-back spelling `*param_2 = &local_8` — so the side
/// effect on the caller's storage is visible in one line. This is the
/// solid-high band ADR-0045 anchors for the direct-write family; an
/// inout reading rides it too, the out half of the claim standing on
/// the same write.
const DIRECT_WRITE_CONFIDENCE: u8 = 75;

/// Confidence of a direction reading from a body that only reads the
/// parameter through — a known string function taking it at a
/// character-pointer position: the read is explicit, but it rules out
/// no write elsewhere in a body this pass has not weighed, so the claim
/// that the parameter is *in* only reaches the modest band ADR-0045
/// anchors for read-only bodies.
const READ_CONFIDENCE: u8 = 60;

// ============================================================
// Call scan
// ============================================================

/// The scan the read family uses: plain-identifier callees, member
/// accesses skipped, and C keywords — `if (x)` — not calls. The callee
/// is then checked against the shared [`STRING_FUNCTIONS`] table the
/// size detector reads, so a string function means one thing to both
/// readings.
const CALL_SCAN: ScanOptions = ScanOptions {
    continuation: NameContinuation::Ident,
    reject_preceding: b".>",
    skip_keywords: &NON_CALL_KEYWORDS,
};

/// Every direct call `name(args)` in the body — the shared pseudo-C
/// scan configured by [`CALL_SCAN`].
fn direct_calls(body: &str) -> Vec<CallSite<'_>> {
    call_sites(body, &CALL_SCAN)
}

// ============================================================
// Usage occurrences
// ============================================================

/// One whole-word occurrence of a parameter in the body, with the byte
/// offsets of the nearest non-space bytes on each side.
struct Occurrence {
    /// Byte offset of the name itself.
    start: usize,
    /// The first non-space byte before the name.
    before: Option<usize>,
    /// The first non-space byte at or after the name's end.
    after: Option<usize>,
}

/// Every whole-word occurrence of `name` in the body. An occurrence
/// glued to a longer identifier (`param_1x`) is not the parameter
/// standing on its own.
fn occurrences(body: &str, name: &str) -> Vec<Occurrence> {
    let bytes = body.as_bytes();
    let mut found = Vec::new();
    let mut from = 0;
    while let Some(rel) = body[from..].find(name) {
        let start = from + rel;
        let end = start + name.len();
        from = end;
        let whole_word = (start == 0 || !is_ident_byte(bytes[start - 1]))
            && (end == bytes.len() || !is_ident_byte(bytes[end]));
        if !whole_word {
            continue;
        }
        found.push(Occurrence {
            start,
            before: prev_non_ws(bytes, start),
            after: next_non_ws(bytes, end),
        });
    }
    found
}

/// Whether the occurrence sits inside a string literal. The scan walks
/// the body's literals in order; a literal that never closes runs to
/// the end of the body.
fn inside_string(body: &str, offset: usize) -> bool {
    let bytes = body.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'"' {
            let open = i;
            i = skip_string(bytes, i + 1);
            if open < offset && offset < i.saturating_sub(1) {
                return true;
            }
        } else {
            i += 1;
        }
    }
    false
}

/// Whether an occurrence sits at a direct write through the pointer: a
/// `*` on the near side of the name and an `=` beginning an assignment
/// right after it — the `*param_1 = x` spelling and its double-pointer
/// hand-back form `*param_2 = &local_8`.
///
/// The shape can only be a dereference assignment: a multiplication
/// cannot take an assignment on its left, so a `*` standing beside a
/// name the body assigns through is the decompiler reading through the
/// parameter. A comparison reads `==`, not `=`, and `!=`, `<=`, and
/// `>=` never put the `=` right at the name's side, so
/// `*param_1 == 3` is silence, not a write. A field write
/// (`param_1->count = 0`) keeps no `*` beside the name and no `=` right
/// after it — the field family joins at its own band in the follow-up.
fn is_direct_write(bytes: &[u8], occ: &Occurrence) -> bool {
    let written_through = matches!(occ.before, Some(i) if bytes[i] == b'*');
    let assigned =
        matches!(occ.after, Some(i) if bytes[i] == b'=' && bytes.get(i + 1) != Some(&b'='));
    written_through && assigned
}

/// The index of the last non-space byte before `at`.
fn prev_non_ws(bytes: &[u8], at: usize) -> Option<usize> {
    let mut i = at;
    while i > 0 {
        i -= 1;
        if !bytes[i].is_ascii_whitespace() {
            return Some(i);
        }
    }
    None
}

/// The index of the first non-space byte at or after `at`.
fn next_non_ws(bytes: &[u8], at: usize) -> Option<usize> {
    let mut i = at;
    while i < bytes.len() && bytes[i].is_ascii_whitespace() {
        i += 1;
    }
    (i < bytes.len()).then_some(i)
}

// ============================================================
// Detector
// ============================================================

/// Parameter direction detection over decompiled functions.
///
/// The detector is stateless: every reading comes from the decompiled
/// function it is handed, so one detector serves an entire scan. It
/// holds no engine client of its own — the [`DecompiledFunction`] text
/// is fetched once per function and read by every detector — and it
/// never writes back to the program: a direction is not a program type
/// (ADR-0020 keeps the write trait for types), only a reading reported
/// for the translator and the baseline tests to use.
///
/// [`DecompiledFunction`]: calxgloss_decomp::DecompiledFunction
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ParamDirectionDetector;

impl ParamDirectionDetector {
    /// A detector with the tracer bullet's reading set (issue #274):
    /// direct writes through the pointer against string-function reads.
    pub fn new() -> Self {
        Self
    }

    /// Read the parameter directions the body shows, at most one record
    /// per parameter, in parameter order.
    ///
    /// A parameter gets a record only when the body carries deciding
    /// evidence for it:
    ///
    /// - A direct write through the pointer — `*param_1 = x`, or the
    ///   double-pointer hand-back `*param_2 = &local_8` — reads the
    ///   parameter *out* at [`DIRECT_WRITE_CONFIDENCE`], evidenced by
    ///   the line carrying the write.
    /// - A known string function ([`STRING_FUNCTIONS`]) with the
    ///   parameter at a character-pointer position, and no write, reads
    ///   it *in* at [`READ_CONFIDENCE`], evidenced by the call's line.
    /// - Both families non-empty reads it *inout*, riding the write's
    ///   confidence and naming the write's line — the out half of the
    ///   claim is the stronger one.
    /// - Neither family, and the parameter gets no record at all:
    ///   absence is unknown, never silently *in*. A parameter merely
    ///   passed to a callee this pass has not read is no evidence, and
    ///   an assignment to the parameter's own name is no write *through*
    ///   a pointer.
    pub fn detect_directions(&self, func: &DecompiledFunction) -> Vec<InferredParamDirection> {
        let params = func.parameter_names();
        if params.is_empty() {
            return Vec::new();
        }
        let bytes = func.body.as_bytes();

        // The read family: a known string function — the same table the
        // size detector reads — with the parameter sitting at one of
        // its character-pointer positions. The first such call in
        // source order is the parameter's evidence.
        let mut read_at: Vec<Option<usize>> = vec![None; params.len()];
        for call in direct_calls(&func.body) {
            let Some(spec) = STRING_FUNCTIONS.iter().find(|f| f.name == call.callee) else {
                continue;
            };
            for &position in spec.string_args {
                let Some(arg) = call.args.get(position) else {
                    continue;
                };
                let value = strip_casts(arg, is_type_word);
                if let Some(index) = params.iter().position(|p| *p == value)
                    && read_at[index].is_none()
                {
                    read_at[index] = Some(call.offset);
                }
            }
        }

        let mut records = Vec::new();
        for (index, name) in params.iter().enumerate() {
            // The write family: the first direct write through the
            // pointer in source order.
            let written = occurrences(&func.body, name)
                .into_iter()
                .find(|occ| !inside_string(&func.body, occ.start) && is_direct_write(bytes, occ));
            let (direction, confidence, at) = match (written, read_at[index]) {
                (Some(occ), Some(_)) => (Direction::InOut, DIRECT_WRITE_CONFIDENCE, occ.start),
                (Some(occ), None) => (Direction::Out, DIRECT_WRITE_CONFIDENCE, occ.start),
                (None, Some(offset)) => (Direction::In, READ_CONFIDENCE, offset),
                (None, None) => continue,
            };
            records.push(InferredParamDirection {
                function: func.name.clone(),
                param_index: index,
                param_name: Some(name.clone()),
                direction,
                method: InferenceMethod::ParamDirection,
                scope: InferenceScope::Function,
                confidence: Confidence::new(confidence),
                evidence: line_at(&func.body, at),
            });
        }
        records
    }
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn function(signature: &str, body: &str) -> DecompiledFunction {
        DecompiledFunction {
            name: "FUN_18003ab00".into(),
            signature: signature.into(),
            body: format!("\n{signature}\n\n{{\n{body}}}\n"),
        }
    }

    fn directions(func: &DecompiledFunction) -> Vec<InferredParamDirection> {
        ParamDirectionDetector::new().detect_directions(func)
    }

    #[test]
    fn a_direct_write_through_a_parameter_reads_it_out() {
        let func = function(
            "undefined FUN_18003ab00(undefined *param_1,undefined8 param_2)",
            "  *param_1 = 0;\n  return;\n",
        );
        let records = directions(&func);
        assert_eq!(records.len(), 1);
        let record = &records[0];
        assert_eq!(record.function, "FUN_18003ab00");
        assert_eq!(record.param_index, 0);
        assert_eq!(record.param_name.as_deref(), Some("param_1"));
        assert_eq!(record.direction, Direction::Out);
        assert_eq!(record.method, InferenceMethod::ParamDirection);
        assert_eq!(record.scope, InferenceScope::Function);
        assert_eq!(record.confidence, Confidence::new(75));
        // The evidence names the deciding write.
        assert_eq!(record.evidence, "*param_1 = 0;");
    }

    #[test]
    fn a_double_pointer_hand_back_reads_out() {
        // The allocate-and-hand-back idiom: the callee stores the
        // address of its local through the caller's pointer — a direct
        // write, the same family and band.
        let func = function(
            "undefined FUN_18003ab00(undefined8 param_1,undefined **param_2)",
            "  undefined local_8;\n  *param_2 = &local_8;\n  return;\n",
        );
        let records = directions(&func);
        assert_eq!(records.len(), 1);
        let record = &records[0];
        assert_eq!(record.param_index, 1);
        assert_eq!(record.param_name.as_deref(), Some("param_2"));
        assert_eq!(record.direction, Direction::Out);
        assert_eq!(record.confidence, Confidence::new(75));
        assert_eq!(record.evidence, "*param_2 = &local_8;");
    }

    #[test]
    fn a_string_function_read_of_a_parameter_reads_it_in() {
        let func = function(
            "undefined FUN_18003ab00(char *param_1)",
            "  uVar3 = strlen(param_1);\n  return uVar3;\n",
        );
        let records = directions(&func);
        assert_eq!(records.len(), 1);
        let record = &records[0];
        assert_eq!(record.param_index, 0);
        assert_eq!(record.direction, Direction::In);
        assert_eq!(record.confidence, Confidence::new(60));
        // The evidence names the deciding read.
        assert_eq!(record.evidence, "uVar3 = strlen(param_1);");
    }

    #[test]
    fn a_write_and_a_string_read_of_one_parameter_read_it_inout() {
        let func = function(
            "undefined FUN_18003ab00(char *param_1)",
            "  uVar3 = strlen(param_1);\n  *param_1 = 0;\n  return;\n",
        );
        let records = directions(&func);
        assert_eq!(records.len(), 1);
        let record = &records[0];
        assert_eq!(record.direction, Direction::InOut);
        // The inout reading rides the write's band and names the write —
        // the out half of the claim is the stronger one.
        assert_eq!(record.confidence, Confidence::new(75));
        assert_eq!(record.evidence, "*param_1 = 0;");
    }

    #[test]
    fn each_parameter_of_a_body_gets_its_own_record_in_position_order() {
        let func = function(
            "undefined FUN_18003ab00(undefined *param_1,char *param_2,undefined8 param_3)",
            "  uVar3 = strlen(param_2);\n  *param_1 = 0;\n  param_3 = 4;\n",
        );
        let records = directions(&func);
        // param_3 is written at its own name only — no pointer, no
        // record — and the two that do get records keep parameter order.
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].param_index, 0);
        assert_eq!(records[0].direction, Direction::Out);
        assert_eq!(records[1].param_index, 1);
        assert_eq!(records[1].direction, Direction::In);
    }

    #[test]
    fn a_body_with_no_deciding_shape_records_nothing() {
        // Absence is unknown, never silently in: passing the parameter
        // to a callee the pass has not read is no evidence either way.
        let func = function(
            "undefined FUN_18003ab00(undefined *param_1)",
            "  FUN_1800412a0(param_1);\n  return;\n",
        );
        assert!(directions(&func).is_empty());
    }

    #[test]
    fn an_assignment_to_a_parameter_s_own_name_is_no_write_through_it() {
        let func = function(
            "undefined FUN_18003ab00(undefined8 param_1)",
            "  param_1 = 4;\n  return param_1;\n",
        );
        assert!(directions(&func).is_empty());
    }

    #[test]
    fn a_read_through_a_pointer_records_nothing_yet() {
        // The dereference read is a read shape, but the read-only body
        // family — comparisons and rvalue use — arrives with its own
        // band in the follow-up; the tracer bullet reads only
        // string-function calls.
        let func = function(
            "undefined FUN_18003ab00(undefined *param_1)",
            "  uVar2 = *param_1;\n  return uVar2;\n",
        );
        assert!(directions(&func).is_empty());
    }

    #[test]
    fn a_comparison_through_a_pointer_is_not_a_write() {
        // `==` is a comparison, not an assignment: the `=` test must not
        // read it as a store.
        let func = function(
            "undefined FUN_18003ab00(undefined *param_1)",
            "  if (*param_1 == 3) { uVar2 = 1; }\n  return;\n",
        );
        assert!(directions(&func).is_empty());
    }

    #[test]
    fn a_field_write_is_silence_until_its_family_arrives() {
        // `param_1->count = 0` is a write through the pointer too, but
        // the field family lands at its own band below the direct write
        // in the follow-up; the tracer bullet claims nothing for it.
        let func = function(
            "undefined FUN_18003ab00(undefined *param_1)",
            "  param_1->count = 0;\n  return;\n",
        );
        assert!(directions(&func).is_empty());
    }

    #[test]
    fn a_multiplication_beside_a_parameter_is_no_evidence() {
        let func = function(
            "undefined FUN_18003ab00(undefined8 param_1)",
            "  uVar4 = count * param_1 + 2;\n  return uVar4;\n",
        );
        assert!(directions(&func).is_empty());
    }

    #[test]
    fn a_parameter_named_inside_a_string_literal_is_no_evidence() {
        let func = function(
            "undefined FUN_18003ab00(char *param_1)",
            "  OutputDebugStringA(\"param_1 = 0;\");\n  return;\n",
        );
        assert!(directions(&func).is_empty());
    }

    #[test]
    fn a_parameter_without_usable_evidence_keeps_its_position_quiet() {
        // A write to one parameter says nothing about its neighbours:
        // only the written parameter gets a record.
        let func = function(
            "undefined FUN_18003ab00(undefined *param_1,undefined *param_2)",
            "  *param_1 = 0;\n  return;\n",
        );
        let records = directions(&func);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].param_index, 0);
    }
}
