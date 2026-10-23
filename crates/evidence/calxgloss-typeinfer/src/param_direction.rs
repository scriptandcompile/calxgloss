//! Parameter direction detection.
//!
//! [`ParamDirectionDetector`] reads from a function's own body which way
//! data flows through each of its pointer parameters: a body that writes
//! through the pointer before returning makes the parameter an *out*
//! parameter, one that only reads through it makes it an *in* one, and a
//! parameter both read and written reads as *inout*. The reading rides the
//! body the scan already keeps — the same kept bodies the assignment-chain
//! and return-usage passes ride, no extra engine reads — and every
//! record's evidence line names the deciding write or read.
//!
//! The evidence families and their bands are the ones ADR-0045 anchors.
//! The write family: a direct write — `*param_1 = x` and its
//! double-pointer hand-back form `*param_2 = &local_8` — claims the
//! solid-high band, and a write through a member or subscript chain, in
//! any of the decompiler's cast spellings (`param_1->count = x`,
//! `param_2[i] = x`, `((Data *)param_1)->count = x`), claims the solid
//! band below it. The read family — the modest band — is a known
//! string-function call, a comparison or rvalue use through the pointer
//! (`if (*param_1 == 3)`, `uVar2 = param_1[i]`), or a field read behind a
//! cast. An *inout* reading rides the band of the write that carried the
//! out half and keeps the write's line as evidence.
//!
//! Where the body shows no deciding shape the detector records nothing:
//! absence is unknown, never silently *in* — passing a parameter to an
//! unknown callee is no evidence either way, the reading never guesses
//! about a callee it has not read. And every claimed shape carries an
//! explicit traversal through the pointer — a `*`, a `->` or subscript
//! chain, or a pointer cast dereferenced at the use — which is also what
//! proves the parameter is a pointer in the first place: a value
//! parameter touched only at its own name (`param_3 = 4`, a null test on
//! the pointer value itself) is silence without trusting the declared
//! types, and a this-pointer written through before return reads inout
//! like any other written pointer, its direction record standing beside
//! the this-pointer type record for the same parameter.

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
/// inout reading riding a direct write stands here too, the out half of
/// the claim resting on the same write.
const DIRECT_WRITE_CONFIDENCE: u8 = 75;

/// Confidence of a direction reading decided by a write through a
/// member or subscript chain — `param_1->count = x`, `param_2[i] = x`,
/// or either spelled behind a cast. The write is plain, but it sits one
/// inference step away from the pointer itself: the decompiler's member
/// and index spellings can name a rebase this pass has not read. This is
/// the solid band ADR-0045 anchors for the field and indexed writes,
/// below the direct write; an inout reading riding one of these writes
/// stands here.
const FIELD_INDEXED_WRITE_CONFIDENCE: u8 = 70;

/// Confidence of a direction reading from a body that only reads through
/// the parameter: the read is explicit, but it rules out no write
/// elsewhere in a body this pass has not weighed, so the claim that the
/// parameter is *in* only reaches the modest band ADR-0045 anchors for
/// read-only bodies.
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

/// Every direct call `name(args)` in the body block — the shared
/// pseudo-C scan configured by [`CALL_SCAN`].
fn direct_calls(body: &str) -> Vec<CallSite<'_>> {
    call_sites(body, &CALL_SCAN)
}

// ============================================================
// Body block
// ============================================================

/// The offset of the `{` that opens the body block. Readings look inside
/// the block only, never at the signature's parameter list:
/// `char param_1[10]` there is an array declarator, not a subscript
/// read through the parameter. A body with no opening brace (it should
/// have one, but decompiler text is what it is) scans whole.
fn body_open(body: &str) -> usize {
    let bytes = body.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'"' => i = skip_string(bytes, i + 1),
            b'{' => return i,
            _ => i += 1,
        }
    }
    0
}

// ============================================================
// Usage occurrences
// ============================================================

/// One whole-word occurrence of a parameter in the body block, with the
/// byte offsets of the name itself and its nearest non-space neighbor
/// ahead of it.
struct Occurrence {
    /// Byte offset of the name itself.
    start: usize,
    /// Byte offset just past the name.
    end: usize,
    /// The first non-space byte before the name.
    before: Option<usize>,
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
            end,
            before: prev_non_ws(bytes, start),
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

/// What one whole-word occurrence of a parameter does through the
/// parameter. A bare occurrence is no use at all — an assignment to the
/// parameter's own name is a write to a local, an argument to a call the
/// pass has not read says nothing, and a use of the pointer's own value
/// (`local_8 = param_1`, a null test `param_1 == NULL`) never reaches
/// through the pointer — so every claimed shape carries an explicit
/// traversal: a `*` at the name's near side, a member or subscript
/// chain behind it, or a pointer cast dereferenced at the use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Use {
    /// A store straight through the pointer — `*param_1 = x` and its
    /// double-pointer hand-back form — spelled out in one line.
    DirectWrite,
    /// A store through a member or subscript chain, in any spelling that
    /// reaches through the pointer: `param_1->count = x`,
    /// `param_2[i] = x`, `(*param_1).count = x`, or either behind a
    /// cast like `((Data *)param_1)->count = x`.
    ChainWrite,
    /// A read through the pointer, with no store at the end of the
    /// path: a dereferenced rvalue or comparison operand (`uVar2 =
    /// *param_1`, `*param_1 == 3`), a member or subscript read, or a
    /// field behind a dereferenced cast.
    Read,
}

/// Classify one occurrence of a parameter's name by its shape.
///
/// The near side tells the two pointer spellings apart: a `*` at the
/// name's near side is the decompiler reading or writing through the
/// parameter, and a `)` whose own near side is a `*` means the name sits
/// at the end of a pointer cast — `(Data *)param_1`. The chain of
/// member and subscript links behind the name is then walked, and the
/// byte the chain ends on decides store from read. A store is claimed
/// only where the path reaches through the pointer: a `*` on the near
/// side, a traversed chain, or a cast with a dereference in front of it
/// (`*(Data *)param_1 = x`). The direct-write shape is decided soundly
/// without parsing, as ADR-0045 records: a multiplication cannot take an
/// assignment on its left, so a `*` beside a name the body assigns
/// through can only be a dereference; `==`, `!=`, `<=`, and `>=` never
/// put an `=` at the name's side, so a comparison stays a read. A
/// dereference *read* needs the star proven unary — `count * param_1`
/// multiplies — and a bare chain (`param_1.field`, no pointer spelling
/// at all) reaches nothing, which is what keeps a value parameter silent
/// without reading its declared type.
fn classify_use(bytes: &[u8], occ: &Occurrence) -> Option<Use> {
    let star = matches!(occ.before, Some(i) if bytes[i] == b'*');
    let cast = matches!(occ.before, Some(close) if bytes[close] == b')')
        && occ
            .before
            .is_some_and(|close| prev_non_ws(bytes, close).is_some_and(|p| bytes[p] == b'*'));
    let (terminator, traversed) = walk_chain(bytes, occ.end, star || cast);
    // The cast reaches through the parameter only when a dereference
    // stands outside the cast group — `*(Data *)param_1`.
    let through_cast = cast
        && occ
            .before
            .is_some_and(|close| deref_outside_cast(bytes, close));

    if terminator.is_some_and(|at| ends_in_store(bytes, at)) {
        if traversed || through_cast {
            Some(Use::ChainWrite)
        } else if star {
            Some(Use::DirectWrite)
        } else {
            None
        }
    } else if traversed
        || through_cast
        || star && occ.before.is_some_and(|i| is_deref_star(bytes, i))
    {
        Some(Use::Read)
    } else {
        None
    }
}

/// Walk the member and subscript chain behind an occurrence —
/// `->field` and `[subscript]` links, repeated (`param_1->next->next`,
/// `param_2[i][j]`) — from the byte just past the name.
///
/// `parenthesized` says the name sits inside a dereference or cast
/// parenthetical — `(*param_1).count`, `((Data *)param_1)->count` — and
/// where it does, one closing paren directly ahead of a continuing link
/// closes the wrapping group and the chain reaches through it. A paren
/// with no link behind it (`Foo(param_1) == x`, `(Data *)param_1 + 1`)
/// ends the walk, so a chain never reaches through into a call's or a
/// group's result. A `.` link continues only a chain the parenthetical
/// has already pointed: a plain `param_1.field` reads a value member,
/// not the pointer.
///
/// Returns the first byte after the chain and whether any link went
/// through the parameter.
fn walk_chain(bytes: &[u8], from: usize, parenthesized: bool) -> (Option<usize>, bool) {
    let mut i = from;
    let mut traversed = false;
    let mut group_open = parenthesized;
    loop {
        let Some(at) = next_non_ws(bytes, i) else {
            return (None, traversed);
        };
        match bytes[at] {
            b'-' if bytes.get(at + 1) == Some(&b'>') => {
                traversed = true;
                i = skip_word(bytes, at + 2);
            }
            b'.' if parenthesized => {
                traversed = true;
                i = skip_word(bytes, at + 1);
            }
            b'[' => match close_bracket(bytes, at) {
                Some(after) => {
                    traversed = true;
                    i = after;
                }
                None => return (Some(at), traversed),
            },
            b')' if group_open && chain_continues(bytes, at + 1) => {
                group_open = false;
                i = at + 1;
            }
            _ => return (Some(at), traversed),
        }
    }
}

/// Whether the first non-space byte at or after `from` opens a chain
/// link: `->`, `.`, or `[`.
fn chain_continues(bytes: &[u8], from: usize) -> bool {
    match next_non_ws(bytes, from) {
        Some(i) if bytes[i] == b'[' || bytes[i] == b'.' => true,
        Some(i) if bytes[i] == b'-' => bytes.get(i + 1) == Some(&b'>'),
        _ => false,
    }
}

/// The offset just past the `]` matching the `[` at `open`, counting
/// nested brackets and stepping over string literals; [`None`] when the
/// bracket never closes.
fn close_bracket(bytes: &[u8], open: usize) -> Option<usize> {
    let mut depth = 0usize;
    let mut i = open;
    while i < bytes.len() {
        match bytes[i] {
            b'[' => depth += 1,
            b']' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i + 1);
                }
            }
            b'"' => i = skip_string(bytes, i + 1).saturating_sub(1),
            _ => {}
        }
        i += 1;
    }
    None
}

/// Whether the chain ends in a store: a plain `=`, or a compound
/// assignment like `+=` that reads and stores through in one statement.
/// `==` is a comparison, and `!=`, `<=`, and `>=` never hold the `=` at
/// the chain's end alone.
fn ends_in_store(bytes: &[u8], at: usize) -> bool {
    match bytes[at] {
        b'=' => bytes.get(at + 1) != Some(&b'='),
        b'+' | b'-' | b'*' | b'/' | b'%' | b'&' | b'|' | b'^' => bytes.get(at + 1) == Some(&b'='),
        _ => false,
    }
}

/// Whether the `*` at `at` dereferences rather than multiplies: a star
/// standing after an operand — a name, a number, `)`, `]` — is binary,
/// while a keyword like `return` or `sizeof` takes an operand, so
/// `return *param_1;` reads through the parameter. A `)` whose own near
/// side is a `*` closes a cast, not an operand: `(code **) *param_1`
/// dereferences what the cast describes.
fn is_deref_star(bytes: &[u8], at: usize) -> bool {
    let Some(prev) = prev_non_ws(bytes, at) else {
        return true;
    };
    match bytes[prev] {
        b if is_ident_byte(b) => {
            let mut start = prev;
            while start > 0 && is_ident_byte(bytes[start - 1]) {
                start -= 1;
            }
            NON_CALL_KEYWORDS
                .iter()
                .any(|keyword| &bytes[start..=prev] == keyword.as_bytes())
        }
        b')' => prev_non_ws(bytes, prev).is_some_and(|p| bytes[p] == b'*'),
        b']' => false,
        _ => true,
    }
}

/// When a parameter name follows a pointer cast's closing paren —
/// `(Data *)param_1` — a `*` outside the cast dereferences it, so
/// `*(Data *)param_1 = x` writes through the parameter while the bare
/// `(Data *)param_1` is only a value cast. The cast's opening paren is
/// found by walking back from `close`; the star ahead of it counts only
/// as a dereference, which `count * (Data *)param_1` — a multiplication
/// — is not.
fn deref_outside_cast(bytes: &[u8], close: usize) -> bool {
    let Some(open) = matching_open(bytes, close) else {
        return false;
    };
    prev_non_ws(bytes, open).is_some_and(|i| bytes[i] == b'*' && is_deref_star(bytes, i))
}

/// The offset of the `(` matching the `)` at `close`, or [`None`] when
/// the paren never opens.
fn matching_open(bytes: &[u8], close: usize) -> Option<usize> {
    let mut depth = 0usize;
    let mut i = close + 1;
    while i > 0 {
        i -= 1;
        match bytes[i] {
            b')' => depth += 1,
            b'(' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
    }
    None
}

/// Skip spaces and then any identifier bytes, from `at`.
fn skip_word(bytes: &[u8], mut i: usize) -> usize {
    while i < bytes.len() && bytes[i].is_ascii_whitespace() {
        i += 1;
    }
    while i < bytes.len() && is_ident_byte(bytes[i]) {
        i += 1;
    }
    i
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
    /// A detector with the full evidence families (issue #275): the
    /// direct, field, and indexed write families against the string-call
    /// and through-the-pointer read families, at the bands ADR-0045
    /// anchors.
    pub fn new() -> Self {
        Self
    }

    /// Read the parameter directions the body shows, at most one record
    /// per parameter, in parameter order.
    ///
    /// A parameter gets a record only when the body carries deciding
    /// evidence for it:
    ///
    /// - The first direct write through the pointer — `*param_1 = x`, or
    ///   the double-pointer hand-back `*param_2 = &local_8` — reads the
    ///   parameter *out* at [`DIRECT_WRITE_CONFIDENCE`], evidenced by
    ///   the line carrying the write.
    /// - A write through a member or subscript chain — `param_1->count =
    ///   x`, `param_2[i] = x`, `*(Data *)param_1 = x`, or either spelled
    ///   behind a cast — reads it *out* at [`FIELD_INDEXED_WRITE_CONFIDENCE`],
    ///   the band ADR-0045 anchors below the direct write. Where both
    ///   write shapes appear on one parameter, the direct write decides.
    /// - A read through the pointer — a known string function
    ///   ([`STRING_FUNCTIONS`]) with the parameter at a character-pointer
    ///   position, a comparison or rvalue use through the pointer, a
    ///   field or subscript read — and no write reads it *in* at
    ///   [`READ_CONFIDENCE`], evidenced by the earliest deciding line.
    /// - Both families non-empty reads it *inout*, riding the write's
    ///   band and naming the write's line — the out half of the claim is
    ///   the stronger one.
    /// - Neither family, and the parameter gets no record at all:
    ///   absence is unknown, never silently *in*. A parameter merely
    ///   passed to a callee this pass has not read is no evidence, an
    ///   assignment to the parameter's own name is no write *through* a
    ///   pointer, and a use of the pointer's own value never reaches
    ///   through it. A this-pointer written through before return takes
    ///   the same reading as any other parameter; its direction record
    ///   coexists with the this-pointer type record because the conflict
    ///   model keys the two apart (issue #274).
    pub fn detect_directions(&self, func: &DecompiledFunction) -> Vec<InferredParamDirection> {
        let params = func.parameter_names();
        if params.is_empty() {
            return Vec::new();
        }
        // Inside the body block only: the signature's parameter list is
        // declarators, not uses — `char param_1[10]` there reads nothing.
        let open = body_open(&func.body);
        let block = &func.body[open..];
        let bytes = block.as_bytes();

        // The read family's call half: a known string function — the
        // same table the size detector reads — with the parameter
        // sitting at one of its character-pointer positions. The first
        // such call in source order is a parameter's read evidence.
        let mut read_at: Vec<Option<usize>> = vec![None; params.len()];
        for call in direct_calls(block) {
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
            // pointer and the first chain write through it, in source
            // order; the reads join the call-half findings with the
            // earliest deciding occurrence.
            let mut direct = None;
            let mut chain = None;
            for occ in occurrences(block, name) {
                if inside_string(block, occ.start) {
                    continue;
                }
                match classify_use(bytes, &occ) {
                    Some(Use::DirectWrite) => {
                        direct = direct.or(Some(occ.start));
                    }
                    Some(Use::ChainWrite) => {
                        chain = chain.or(Some(occ.start));
                    }
                    Some(Use::Read) => {
                        read_at[index] =
                            Some(read_at[index].map_or(occ.start, |at| at.min(occ.start)));
                    }
                    None => {}
                }
            }
            // The out half decides the band and the evidence: a direct
            // write outranks a chain write, and an inout reading rides
            // whichever write carried it.
            let (write, band) = match (direct, chain) {
                (Some(at), _) => (Some(at), DIRECT_WRITE_CONFIDENCE),
                (None, Some(at)) => (Some(at), FIELD_INDEXED_WRITE_CONFIDENCE),
                (None, None) => (None, 0),
            };
            let (direction, confidence, at) = match (write, read_at[index]) {
                (Some(at), Some(_)) => (Direction::InOut, band, at),
                (Some(at), None) => (Direction::Out, band, at),
                (None, Some(at)) => (Direction::In, READ_CONFIDENCE, at),
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
                evidence: line_at(&func.body, at + open),
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
    fn a_field_write_through_a_parameter_reads_it_out() {
        // ADR-0045's field family: the write reaches through the
        // pointer's member — solid band, below the direct write.
        let func = function(
            "undefined FUN_18003ab00(undefined *param_1)",
            "  param_1->count = 0;\n  return;\n",
        );
        let records = directions(&func);
        assert_eq!(records.len(), 1);
        let record = &records[0];
        assert_eq!(record.param_index, 0);
        assert_eq!(record.direction, Direction::Out);
        assert_eq!(record.confidence, Confidence::new(70));
        assert_eq!(record.evidence, "param_1->count = 0;");
    }

    #[test]
    fn an_indexed_write_through_a_parameter_reads_it_out() {
        // The indexed family shares the field's band: `param_2[i] = x`
        // is a write through the pointer as plain as a member store.
        let func = function(
            "undefined FUN_18003ab00(char *param_1,undefined *param_2)",
            "  param_2[0] = 3;\n  return;\n",
        );
        let records = directions(&func);
        assert_eq!(records.len(), 1);
        let record = &records[0];
        assert_eq!(record.param_index, 1);
        assert_eq!(record.param_name.as_deref(), Some("param_2"));
        assert_eq!(record.direction, Direction::Out);
        assert_eq!(record.confidence, Confidence::new(70));
        assert_eq!(record.evidence, "param_2[0] = 3;");
    }

    #[test]
    fn a_field_write_behind_a_pointer_cast_reads_it_out() {
        // The decompiler's cast spelling of a member store reaches
        // through the same pointer and joins the field family — a step
        // below the direct write in the ranking reviewers read.
        let func = function(
            "undefined FUN_18003ab00(undefined *param_1)",
            "  ((Data *)param_1)->count = 0;\n  return;\n",
        );
        let records = directions(&func);
        assert_eq!(records.len(), 1);
        let record = &records[0];
        assert_eq!(record.direction, Direction::Out);
        assert_eq!(record.confidence, Confidence::new(70));
        assert_eq!(record.evidence, "((Data *)param_1)->count = 0;");
    }

    #[test]
    fn a_dereference_write_through_a_pointer_cast_reads_it_out() {
        // `*(Data *)param_1 = 5` — a cast dereference and a store: the
        // cast names a rebase this pass has not read, so the write sits
        // at the cast band, not the direct-write band.
        let func = function(
            "undefined FUN_18003ab00(undefined *param_1)",
            "  *(Data *)param_1 = 5;\n  return;\n",
        );
        let records = directions(&func);
        assert_eq!(records.len(), 1);
        let record = &records[0];
        assert_eq!(record.direction, Direction::Out);
        assert_eq!(record.confidence, Confidence::new(70));
        assert_eq!(record.evidence, "*(Data *)param_1 = 5;");
    }

    #[test]
    fn a_compound_store_through_a_member_reads_it_out() {
        // `+=` stores through the chain as surely as `=`, with the read
        // folded into the same statement.
        let func = function(
            "undefined FUN_18003ab00(undefined *param_1)",
            "  param_1->count += 1;\n  return;\n",
        );
        let records = directions(&func);
        assert_eq!(records.len(), 1);
        let record = &records[0];
        assert_eq!(record.direction, Direction::Out);
        assert_eq!(record.confidence, Confidence::new(70));
        assert_eq!(record.evidence, "param_1->count += 1;");
    }

    #[test]
    fn a_direct_write_outranks_a_field_write_on_one_parameter() {
        // One parameter, two write shapes: the direct write decides the
        // band and names the evidence — one record, never two.
        let func = function(
            "undefined FUN_18003ab00(undefined *param_1)",
            "  param_1->count = 0;\n  *param_1 = 0;\n  return;\n",
        );
        let records = directions(&func);
        assert_eq!(records.len(), 1);
        let record = &records[0];
        assert_eq!(record.direction, Direction::Out);
        assert_eq!(record.confidence, Confidence::new(75));
        assert_eq!(record.evidence, "*param_1 = 0;");
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
    fn a_dereference_read_of_a_parameter_reads_it_in() {
        // The rvalue use the tracer left for this family: the body
        // loads through the pointer and hands the value to a local.
        let func = function(
            "undefined FUN_18003ab00(undefined *param_1)",
            "  uVar2 = *param_1;\n  return uVar2;\n",
        );
        let records = directions(&func);
        assert_eq!(records.len(), 1);
        let record = &records[0];
        assert_eq!(record.direction, Direction::In);
        assert_eq!(record.confidence, Confidence::new(60));
        assert_eq!(record.evidence, "uVar2 = *param_1;");
    }

    #[test]
    fn a_comparison_through_a_pointer_reads_it_in() {
        // `==` is a comparison, not an assignment — the `=` test must
        // not read it as a store — but the test still reads through the
        // pointer, which is the read family's modest band.
        let func = function(
            "undefined FUN_18003ab00(undefined *param_1)",
            "  if (*param_1 == 3) { uVar2 = 1; }\n  return;\n",
        );
        let records = directions(&func);
        assert_eq!(records.len(), 1);
        let record = &records[0];
        assert_eq!(record.direction, Direction::In);
        assert_eq!(record.confidence, Confidence::new(60));
        assert_eq!(record.evidence, "if (*param_1 == 3) { uVar2 = 1; }");
    }

    #[test]
    fn a_member_read_in_a_comparison_reads_it_in() {
        let func = function(
            "undefined FUN_18003ab00(undefined *param_1)",
            "  if (param_1->count == 3) { uVar2 = 1; }\n  return;\n",
        );
        let records = directions(&func);
        assert_eq!(records.len(), 1);
        let record = &records[0];
        assert_eq!(record.direction, Direction::In);
        assert_eq!(record.confidence, Confidence::new(60));
        assert_eq!(record.evidence, "if (param_1->count == 3) { uVar2 = 1; }");
    }

    #[test]
    fn an_indexed_read_of_a_parameter_reads_it_in() {
        let func = function(
            "undefined FUN_18003ab00(undefined *param_1)",
            "  uVar2 = param_1[i];\n  return uVar2;\n",
        );
        let records = directions(&func);
        assert_eq!(records.len(), 1);
        let record = &records[0];
        assert_eq!(record.direction, Direction::In);
        assert_eq!(record.confidence, Confidence::new(60));
        assert_eq!(record.evidence, "uVar2 = param_1[i];");
    }

    #[test]
    fn a_read_through_a_dereferenced_cast_reads_it_in() {
        // The read spelled behind a cast and a dereference reaches
        // through the pointer like the bare spellings do.
        let func = function(
            "undefined FUN_18003ab00(undefined *param_1)",
            "  uVar2 = *(Data *)param_1;\n  return uVar2;\n",
        );
        let records = directions(&func);
        assert_eq!(records.len(), 1);
        let record = &records[0];
        assert_eq!(record.direction, Direction::In);
        assert_eq!(record.confidence, Confidence::new(60));
        assert_eq!(record.evidence, "uVar2 = *(Data *)param_1;");
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
    fn a_field_write_with_a_read_composes_inout_at_the_write_band() {
        // Both families non-empty on a chain write: inout, riding the
        // solid band the ADR anchors for field writes.
        let func = function(
            "undefined FUN_18003ab00(undefined *param_1)",
            "  if (param_1->count == 0) { return; }\n  param_1->count = 1;\n  return;\n",
        );
        let records = directions(&func);
        assert_eq!(records.len(), 1);
        let record = &records[0];
        assert_eq!(record.direction, Direction::InOut);
        assert_eq!(record.confidence, Confidence::new(70));
        assert_eq!(record.evidence, "param_1->count = 1;");
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
    fn a_use_of_the_pointer_s_own_value_is_no_read_through_it() {
        // Copying the pointer and testing it against NULL touch the
        // pointer's value, not what it points through: with nothing
        // reaching through, the parameter stays unrecorded.
        let func = function(
            "undefined FUN_18003ab00(undefined *param_1)",
            "  local_8 = param_1;\n  if (param_1 == NULL) { return; }\n\
             \x20 FUN_1800412a0(local_8);\n",
        );
        assert!(directions(&func).is_empty());
    }

    #[test]
    fn an_array_declarator_in_the_signature_reads_nothing() {
        // The signature's parameter list is declarators, not uses:
        // `char param_1[10]` there is no subscript read through the
        // parameter, and readings look inside the body block only.
        let func = function(
            "undefined FUN_18003ab00(char param_1[10],char *param_2)",
            "  return;\n",
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
