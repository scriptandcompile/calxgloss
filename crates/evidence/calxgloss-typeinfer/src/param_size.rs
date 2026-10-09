//! Parameter size detection.
//!
//! [`ParameterSizeDetector`] scans decompiled functions for the usage
//! shapes that pin a parameter's size: string-function calls (`strlen`,
//! `strcpy`, `strcmp`, ...) that read a parameter as a character pointer,
//! integer bit patterns (shifts, bitwise AND) that suggest a particular
//! width, and pointer arithmetic (offsets, dereferences, field access)
//! that says the parameter points at something. Each reading is emitted
//! as an [`InferredParamType`] record whose method is one of
//! [`StringFunction`], [`IntegerBitPattern`], or [`PointerArithmetic`] —
//! the size readings beside the this-pointer detector's — and when
//! several readings compete for one parameter, the highest-confidence
//! one wins.
//!
//! [`InferredParamType`]: crate::types::InferredParamType
//! [`StringFunction`]: crate::types::InferenceMethod::StringFunction
//! [`IntegerBitPattern`]: crate::types::InferenceMethod::IntegerBitPattern
//! [`PointerArithmetic`]: crate::types::InferenceMethod::PointerArithmetic

use crate::reading::Reading;
use crate::types::{InferenceMethod, InferenceScope, InferredParamType};
use calxgloss_ghidra::DecompiledFunction;
use calxgloss_types::{
    CallSite, NameContinuation, ScanOptions, call_sites, cast_group, is_ident_byte, line_at,
    skip_string, skip_ws, strip_casts,
};
use std::collections::HashMap;

// ============================================================
// Reading confidences
// ============================================================

/// Confidence of a character-pointer reading from a string-function call:
/// the callee's contract says the argument is a NUL-terminated string, so
/// the narrowing is concrete, but the call site alone cannot rule out a
/// buffer of another element type.
const STRING_CONFIDENCE: u8 = 70;

/// Confidence of a pointer reading from dereference, offset, field access,
/// or indexing: the body reads or writes through the parameter, which
/// proves it points at something, but not at what — the pointee stays
/// unnamed.
const POINTER_CONFIDENCE: u8 = 65;

/// Confidence of an integer reading from shift and mask usage: the bit
/// operations say the parameter is an integer, and the constants beside
/// them still fit the decompiler's default word, so the reading stays
/// there.
const INTEGER_CONFIDENCE: u8 = 55;

/// Confidence of an integer reading whose constants outrun the default
/// word: a mask wider than the word, or a shift count the word cannot
/// hold, proves the parameter spans more than the decompiler's default
/// — a pinned width, stronger evidence than the bare operation shape.
const WIDE_INTEGRAL_CONFIDENCE: u8 = 60;

/// The type text for a parameter the body reads through: the arithmetic
/// proves the parameter is a pointer, not what it points at. Readings
/// that recover a pointee type or a class name narrow this further.
const UNNAMED_POINTEE: &str = "void *";

/// The type text for a parameter the body shifts and masks: the bit
/// operations prove an integer, and the default word stands until a
/// constant beside one of the operations outruns it.
const DEFAULT_WORD: &str = "u32";

/// The type text for a parameter whose bit operations carry constants
/// the default word cannot hold: the parameter spans wider than one
/// word, and the constants say so directly.
const WIDE_WORD: &str = "u64";

/// Bits in the decompiler's default word: a mask spanning more bits, or
/// a shift count reaching past it, forces the reading to the wide word.
const WORD_BITS: u32 = 32;

// ============================================================
// String-function calls
// ============================================================

/// A known string function and the argument positions its contract reads
/// as character pointers. Everything else it takes — a count for the
/// `strn*` family, the character for `strchr`, the buffer size for
/// `snprintf` — is not a string, and a parameter sitting there gets no
/// character-pointer reading.
struct StringFunction {
    name: &'static str,
    string_args: &'static [usize],
}

/// The C string-function family: the routines whose `char *` arguments
/// sit at known positions of the call. The positions are explicit rather
/// than a leading count because the `sprintf` line hides its format
/// string behind a size argument — `snprintf(buf, size, fmt, ...)` reads
/// positions 0 and 2 — and a variadic tail argument is not necessarily a
/// string at all.
const STRING_FUNCTIONS: [StringFunction; 23] = [
    StringFunction {
        name: "strlen",
        string_args: &[0],
    },
    StringFunction {
        name: "strnlen",
        string_args: &[0],
    },
    StringFunction {
        name: "strcpy",
        string_args: &[0, 1],
    },
    StringFunction {
        name: "strncpy",
        string_args: &[0, 1],
    },
    StringFunction {
        name: "strcat",
        string_args: &[0, 1],
    },
    StringFunction {
        name: "strncat",
        string_args: &[0, 1],
    },
    StringFunction {
        name: "strcmp",
        string_args: &[0, 1],
    },
    StringFunction {
        name: "strncmp",
        string_args: &[0, 1],
    },
    StringFunction {
        name: "strcasecmp",
        string_args: &[0, 1],
    },
    StringFunction {
        name: "strncasecmp",
        string_args: &[0, 1],
    },
    StringFunction {
        name: "strchr",
        string_args: &[0],
    },
    StringFunction {
        name: "strrchr",
        string_args: &[0],
    },
    StringFunction {
        name: "strstr",
        string_args: &[0, 1],
    },
    StringFunction {
        name: "strpbrk",
        string_args: &[0, 1],
    },
    StringFunction {
        name: "strspn",
        string_args: &[0, 1],
    },
    StringFunction {
        name: "strcspn",
        string_args: &[0, 1],
    },
    StringFunction {
        name: "strtok",
        string_args: &[0, 1],
    },
    StringFunction {
        name: "strdup",
        string_args: &[0],
    },
    StringFunction {
        name: "strndup",
        string_args: &[0],
    },
    StringFunction {
        name: "sprintf",
        string_args: &[0, 1],
    },
    StringFunction {
        name: "snprintf",
        string_args: &[0, 2],
    },
    StringFunction {
        name: "vsprintf",
        string_args: &[0, 1],
    },
    StringFunction {
        name: "vsnprintf",
        string_args: &[0, 2],
    },
];

/// The scan this reader uses: every balanced `name(` counts, keyword
/// shapes included — `if (param_1 & 1)` still reads the parameter's
/// width. A name preceded by an identifier byte is the tail of a
/// longer identifier, and one preceded by a `.` is a member access;
/// neither is a plain call.
const CALL_SCAN: ScanOptions = ScanOptions {
    continuation: NameContinuation::Ident,
    reject_preceding: b".",
    skip_keywords: &[],
};

/// Every direct call `name(args)` in the body — the shared pseudo-C
/// scan configured by [`CALL_SCAN`].
fn direct_calls(body: &str) -> Vec<CallSite<'_>> {
    call_sites(body, &CALL_SCAN)
}

/// The type words a Ghidra cast may spell, matching the decompiler's
/// vocabulary the this-pointer scan already strips.
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
            | "long"
    )
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
/// standing on its own; a field access (`param_1->count`) is the
/// parameter plus a member, and its own reading shape decides it.
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

/// A shift or bitwise-AND operation sitting beside an occurrence, with
/// what the constants beside it say about the parameter's width.
struct BitOperation {
    /// The smallest width, in bits, the constants beside the operation
    /// force on the parameter: a mask needs its own bit length, and a
    /// shift the parameter is the operand of needs one bit more than
    /// its count. `None` when the operation carries no constant that
    /// bounds the parameter — a bare `param_1 & param_2`, a shift
    /// whose count the parameter itself supplies, or a parameter
    /// behind a cast, which types the expression rather than the
    /// parameter.
    width_bound: Option<u32>,
}

/// The shift or bitwise-AND operation at the occurrence, if any: the
/// bytes after the name open with `<<`, `>>`, or a lone `&` (a
/// compound `<<=`, `>>=`, `&=` included, the logical `&&` excluded),
/// or the name closes a `<<`/`>>` or follows a binary `&` — one whose
/// left side is an operand, not the unary address-of spelling.
fn bit_operation(bytes: &[u8], occ: &Occurrence) -> Option<BitOperation> {
    if let Some(a) = occ.after {
        let shift = bytes[a..].starts_with(b"<<") || bytes[a..].starts_with(b">>");
        let and = bytes[a] == b'&' && bytes.get(a + 1) != Some(&b'&');
        if shift || and {
            let constant = constant_after(bytes, if shift { a + 2 } else { a + 1 });
            let bound = (!behind_cast(bytes, occ))
                .then(|| constant.and_then(|n| if shift { shift_bound(n) } else { mask_bound(n) }));
            return Some(BitOperation {
                width_bound: bound.flatten(),
            });
        }
    }
    if let Some(p) = occ.before {
        match bytes[p] {
            b'<' if p > 0 && bytes[p - 1] == b'<' => {
                // The parameter supplies the shift count; the constant
                // before the operator is the shifted value, which says
                // nothing about the parameter's width.
                return Some(BitOperation { width_bound: None });
            }
            b'>' if p > 0 && bytes[p - 1] == b'>' => {
                return Some(BitOperation { width_bound: None });
            }
            b'&' if bytes.get(p.wrapping_sub(1)) != Some(&b'&') && operand_before(bytes, p) => {
                // `0xff & param_1`: the mask sits on the operator's left.
                let mask = constant_before(bytes, p);
                let bound = (!behind_cast(bytes, occ)).then(|| mask.and_then(mask_bound));
                return Some(BitOperation {
                    width_bound: bound.flatten(),
                });
            }
            _ => {}
        }
    }
    None
}

/// The width a mask forces: the number of bits the mask itself spans.
fn mask_bound(mask: u64) -> Option<u32> {
    Some(64 - mask.leading_zeros())
}

/// The width a shift forces: one bit more than its count, since a
/// count at or past the operand's width empties it.
fn shift_bound(count: u64) -> Option<u32> {
    Some(count.min(64) as u32 + 1)
}

/// Whether the occurrence sits directly behind a type cast —
/// `(ulonglong)param_1 << 0x20` — where the cast, not the parameter,
/// carries the width the constants speak of.
fn behind_cast(bytes: &[u8], occ: &Occurrence) -> bool {
    matches!(
        occ.before,
        Some(p) if bytes[p] == b')'
            && matching_open(bytes, p).is_some_and(|o| cast_group(bytes, o, is_type_word).is_some())
    )
}

/// The numeric constant following the operator ending at `at` — past a
/// compound assignment's `=` — when a number follows it.
fn constant_after(bytes: &[u8], at: usize) -> Option<u64> {
    let mut i = at;
    if bytes.get(i) == Some(&b'=') {
        i += 1;
    }
    let start = skip_ws(bytes, i);
    let end = number_end(bytes, start)?;
    parse_number(std::str::from_utf8(&bytes[start..end]).ok()?)
}

/// The numeric constant ending just before `at`: the identifier token
/// there when it is a number rather than a name — the left-hand mask
/// of `0xff & param_1`.
fn constant_before(bytes: &[u8], at: usize) -> Option<u64> {
    let end = prev_non_ws(bytes, at)?;
    let mut start = end;
    while start > 0 && is_ident_byte(bytes[start - 1]) {
        start -= 1;
    }
    parse_number(std::str::from_utf8(&bytes[start..=end]).ok()?)
}

/// The index just past the numeric literal starting at `at` — decimal
/// or `0x` hex, with an optional integer suffix like `u` or `ull` — or
/// `None` when no number starts there.
fn number_end(bytes: &[u8], at: usize) -> Option<usize> {
    if !is_number_at(bytes, at) {
        return None;
    }
    let mut i = at;
    if bytes[i] == b'0' && matches!(bytes.get(i + 1), Some(&b'x') | Some(&b'X')) {
        i += 2;
        while i < bytes.len() && bytes[i].is_ascii_hexdigit() {
            i += 1;
        }
    } else {
        while i < bytes.len() && bytes[i].is_ascii_digit() {
            i += 1;
        }
    }
    while i < bytes.len() && bytes[i].is_ascii_alphabetic() {
        i += 1;
    }
    Some(i)
}

/// A numeric literal's value, saturating at `u64::MAX`: decimal or
/// `0x` hex with an optional alphabetic integer suffix.
fn parse_number(text: &str) -> Option<u64> {
    if !text.starts_with(|c: char| c.is_ascii_digit()) {
        return None;
    }
    let (radix, digits) = if text.starts_with("0x") || text.starts_with("0X") {
        (16, &text[2..])
    } else {
        (10, text)
    };
    let digits = digits.trim_end_matches(|c: char| c.is_ascii_alphabetic());
    let mut value: u64 = 0;
    for digit in digits.chars() {
        value = value
            .saturating_mul(u64::from(radix))
            .saturating_add(u64::from(digit.to_digit(radix)?));
    }
    Some(value)
}

/// Whether the body points through the parameter: the byte before the
/// name is a `*` that dereferences rather than multiplies (`*param_1`,
/// `**(code **)*param_1`), the name is offset by a number inside a
/// parenthesized group that a `*` reads through (`*(undefined4 *)
/// (param_2 + 4)`), the name is followed by an arrow into a field
/// (`param_1->count`, chained `param_1->next->value` — the arrow only
/// exists on a pointer), or the name is indexed (`param_1[2]` — the
/// decompiler indexes what it types as a pointer). A multiply
/// (`count * param_1`) and a bare offset that nothing reads through
/// (`uVar = param_1 + 4`) say nothing about pointer-ness.
fn is_pointer_operand(bytes: &[u8], occ: &Occurrence) -> bool {
    if let Some(p) = occ.before
        && bytes[p] == b'*'
        && dereferences(bytes, p)
    {
        return true;
    }
    if let Some(a) = occ.after {
        if bytes[a] == b'-' && bytes.get(a + 1) == Some(&b'>') {
            return true;
        }
        if bytes[a] == b'[' {
            return true;
        }
        if matches!(bytes[a], b'+' | b'-')
            && is_number_at(bytes, skip_ws(bytes, a + 1))
            && offset_is_read_through(bytes, occ.start)
        {
            return true;
        }
    }
    false
}

/// Whether the `*` at `star` dereferences its operand rather than
/// multiplying: nothing operand-shaped ends before it, or the operand
/// it follows is a type cast — `(code *)*param_1` reads through the
/// parameter even though a `)` stands beside the star.
fn dereferences(bytes: &[u8], star: usize) -> bool {
    if !operand_before(bytes, star) {
        return true;
    }
    let p = match prev_non_ws(bytes, star) {
        Some(p) => p,
        None => return true,
    };
    if bytes[p] == b')'
        && let Some(open) = matching_open(bytes, p)
    {
        return cast_group(bytes, open, is_type_word).is_some();
    }
    false
}

/// Whether an operand ends just before `at` (skipping spaces): an
/// identifier that is not a control keyword, a number, or a closing
/// bracket. `x & param_1` is a binary AND; `return &param_1` takes the
/// parameter's address, and `return *param_1` reads through it.
fn operand_before(bytes: &[u8], at: usize) -> bool {
    let p = match prev_non_ws(bytes, at) {
        Some(p) => p,
        None => return false,
    };
    match bytes[p] {
        b')' | b']' => true,
        b if b.is_ascii_digit() => true,
        b if is_ident_byte(b) => {
            let mut start = p;
            while start > 0 && is_ident_byte(bytes[start - 1]) {
                start -= 1;
            }
            !matches!(
                std::str::from_utf8(&bytes[start..=p]).unwrap_or(""),
                "return" | "case" | "sizeof"
            )
        }
        _ => false,
    }
}

/// Whether the number at `at` — decimal or `0x` hex — is the offset
/// side of pointer arithmetic, rather than an identifier making the
/// expression a pointer difference or an indexed offset.
fn is_number_at(bytes: &[u8], at: usize) -> bool {
    match bytes.get(at) {
        Some(b'0') => match bytes.get(at + 1) {
            Some(&b'x') | Some(&b'X') => bytes.get(at + 2).is_some_and(|b| b.is_ascii_hexdigit()),
            other => other.is_some_and(|b| b.is_ascii_digit()),
        },
        Some(b) => b.is_ascii_digit(),
        None => false,
    }
}

/// Whether the group enclosing the occurrence at `at` is read through
/// a `*`: the non-space byte before the group's `(` is a star, or a
/// `)` closing a type cast that a star precedes — the
/// `*(undefined4 *)(param_2 + 4)` spelling.
fn offset_is_read_through(bytes: &[u8], at: usize) -> bool {
    let open = match enclosing_group(bytes, at) {
        Some(open) => open,
        None => return false,
    };
    let p = match prev_non_ws(bytes, open) {
        Some(p) => p,
        None => return false,
    };
    if bytes[p] == b'*' {
        return true;
    }
    if bytes[p] == b')'
        && let Some(cast_open) = matching_open(bytes, p)
        && cast_group(bytes, cast_open, is_type_word).is_some()
    {
        return matches!(prev_non_ws(bytes, cast_open), Some(q) if bytes[q] == b'*');
    }
    false
}

/// The innermost `(` whose group encloses `at`, scanning backward past
/// balanced groups. `None` when no group reaches that far.
fn enclosing_group(bytes: &[u8], at: usize) -> Option<usize> {
    let mut depth = 0usize;
    let mut i = at;
    while i > 0 {
        i -= 1;
        match bytes[i] {
            b')' => depth += 1,
            b'(' => {
                if depth == 0 {
                    return Some(i);
                }
                depth -= 1;
            }
            _ => {}
        }
    }
    None
}

/// The `(` matching the `)` at `close`, scanning backward.
fn matching_open(bytes: &[u8], close: usize) -> Option<usize> {
    let mut depth = 0usize;
    let mut i = close;
    while i > 0 {
        i -= 1;
        match bytes[i] {
            b'(' => {
                if depth == 0 {
                    return Some(i);
                }
                depth -= 1;
            }
            b')' => depth += 1,
            _ => {}
        }
    }
    None
}

// ============================================================
// Detector
// ============================================================

/// Parameter size detection over decompiled functions.
///
/// The detector is stateless: every reading comes from the decompiled
/// function it is handed, so one detector serves an entire scan and can
/// be shared across concurrent per-function passes. It holds no Ghidra
/// client of its own — the [`DecompiledFunction`] text is fetched once
/// per function and read by every detector — and it never writes back to
/// the program, only reporting what the body's usage implies.
///
/// [`DecompiledFunction`]: calxgloss_ghidra::DecompiledFunction
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ParameterSizeDetector;

impl ParameterSizeDetector {
    /// A detector with the full standard detection set: string-function
    /// calls, integer bit patterns, and pointer arithmetic, resolved by
    /// confidence when they compete for one parameter.
    pub fn new() -> Self {
        Self
    }

    /// Read the parameter sizes implied by a decompiled body's usage.
    ///
    /// A parameter gets a reading from each usage family the body shows
    /// for it, at most one per family, carrying that family's first
    /// matching shape in source order:
    ///
    /// - A call to a known string function ([`STRING_FUNCTIONS`]) with
    ///   the parameter in a string argument position narrows it to
    ///   `char *` through [`InferenceMethod::StringFunction`]. An
    ///   argument behind a cast still names the value; a parameter in a
    ///   count, character, or buffer-size position gets no reading.
    /// - A shift or bitwise-AND operation on the parameter reads it as
    ///   an integer through [`InferenceMethod::IntegerBitPattern`]. The
    ///   constants beside the operations are weighed: while every mask
    ///   fits the word and every shift count the parameter is the
    ///   operand of stays inside it, the reading is the default word
    ///   ([`DEFAULT_WORD`]); a mask spanning more than [`WORD_BITS`] or
    ///   a count reaching past it widens the reading to [`WIDE_WORD`],
    ///   backed by the line carrying that constant. A logical `&&` and
    ///   a unary address-of are not bit operations, a field's bit
    ///   operations (`param_1->flags & 0xff`) are not the parameter's,
    ///   a shift whose count the parameter supplies bounds no width,
    ///   and a parameter behind a cast (`(ulonglong)param_1 << 0x20`)
    ///   keeps the default word — the cast types the expression.
    /// - A dereference (`*param_1`, `**(code **)*param_1`), a numeric
    ///   offset inside a dereferenced group (`*(undefined4 *)(param_2 +
    ///   4)`), a field access (`param_1->count`, chained
    ///   `param_1->next->value`), or an array index (`param_1[2]`) reads
    ///   it as a pointer to an unnamed pointee ([`UNNAMED_POINTEE`])
    ///   through [`InferenceMethod::PointerArithmetic`]. A multiply and a
    ///   bare offset nothing reads through are not dereferences.
    ///
    /// Every reading is scoped to the function it was made in — the
    /// evidence lives in this body and reaches nowhere else. When
    /// several families read one parameter differently, the detector
    /// resolves the ambiguity itself: the highest-confidence reading
    /// wins and the rest are dropped — a parameter both copied by
    /// `strcpy` and dereferenced reads as `char *`, not `void *` — and
    /// a tie keeps the reading the body showed first.
    ///
    /// [`InferenceMethod::StringFunction`]: crate::types::InferenceMethod::StringFunction
    /// [`InferenceMethod::IntegerBitPattern`]: crate::types::InferenceMethod::IntegerBitPattern
    /// [`InferenceMethod::PointerArithmetic`]: crate::types::InferenceMethod::PointerArithmetic
    pub fn detect_parameter_sizes(&self, func: &DecompiledFunction) -> Vec<InferredParamType> {
        let params = func.parameter_names();
        if params.is_empty() {
            return Vec::new();
        }
        let bytes = func.body.as_bytes();

        let mut readings: Vec<Reading> = Vec::new();

        // The string family: a known string function called with the
        // parameter in one of its character-pointer positions.
        for call in direct_calls(&func.body) {
            let Some(spec) = STRING_FUNCTIONS.iter().find(|f| f.name == call.callee) else {
                continue;
            };
            for &position in spec.string_args {
                let Some(arg) = call.args.get(position) else {
                    continue;
                };
                let value = strip_casts(arg, is_type_word);
                if let Some(index) = params.iter().position(|p| *p == value) {
                    readings.push(Reading {
                        param_index: index,
                        method: InferenceMethod::StringFunction,
                        inferred_type: "char *",
                        confidence: STRING_CONFIDENCE,
                        evidence: line_at(&func.body, call.offset),
                    });
                }
            }
        }

        // The integer and pointer families: the first bit-operation and
        // the first read-through shape each parameter shows, with the
        // widest constant beside the bit operations pinning the width.
        for (index, name) in params.iter().enumerate() {
            let mut integer: Option<usize> = None;
            let mut widest: Option<(usize, u32)> = None;
            let mut pointer: Option<usize> = None;
            for occ in occurrences(&func.body, name) {
                if inside_string(&func.body, occ.start) {
                    continue;
                }
                if let Some(op) = bit_operation(bytes, &occ) {
                    if integer.is_none() {
                        integer = Some(occ.start);
                    }
                    if let Some(bound) = op.width_bound
                        && widest.is_none_or(|(_, best)| bound > best)
                    {
                        widest = Some((occ.start, bound));
                    }
                }
                if pointer.is_none() && is_pointer_operand(bytes, &occ) {
                    pointer = Some(occ.start);
                }
                if integer.is_some()
                    && pointer.is_some()
                    && widest.is_some_and(|(_, bound)| bound > WORD_BITS)
                {
                    break;
                }
            }
            if let Some(offset) = integer {
                let (inferred_type, confidence, offset) = match widest {
                    Some((wide_at, bound)) if bound > WORD_BITS => {
                        (WIDE_WORD, WIDE_INTEGRAL_CONFIDENCE, wide_at)
                    }
                    _ => (DEFAULT_WORD, INTEGER_CONFIDENCE, offset),
                };
                readings.push(Reading {
                    param_index: index,
                    method: InferenceMethod::IntegerBitPattern,
                    inferred_type,
                    confidence,
                    evidence: line_at(&func.body, offset),
                });
            }
            if let Some(offset) = pointer {
                readings.push(Reading {
                    param_index: index,
                    method: InferenceMethod::PointerArithmetic,
                    inferred_type: UNNAMED_POINTEE,
                    confidence: POINTER_CONFIDENCE,
                    evidence: line_at(&func.body, offset),
                });
            }
        }

        // At most one record per (parameter, family): the first reading
        // the family produced in source order is the one kept.
        let mut first: HashMap<(usize, InferenceMethod), usize> = HashMap::new();
        for (slot, reading) in readings.iter().enumerate() {
            first
                .entry((reading.param_index, reading.method))
                .or_insert(slot);
        }
        let kept: Vec<Reading> = readings
            .into_iter()
            .enumerate()
            .filter(|(slot, reading)| {
                first.get(&(reading.param_index, reading.method)) == Some(slot)
            })
            .map(|(_, reading)| reading)
            .collect();
        // Ambiguity handling: when families read one parameter
        // differently, the highest-confidence reading wins and the rest
        // are dropped; a tie keeps the reading the body showed first.
        let winners = Reading::resolve(kept);
        winners
            .into_iter()
            .map(|reading| {
                let param_name = params[reading.param_index].clone();
                reading.into_record(func.name.clone(), param_name, InferenceScope::Function)
            })
            .collect()
    }
}

// ============================================================
// Scanning helpers
// ============================================================

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

    fn readings(func: &DecompiledFunction) -> Vec<InferredParamType> {
        ParameterSizeDetector::new().detect_parameter_sizes(func)
    }

    #[test]
    fn a_detector_carries_no_state() {
        // One detector serves a whole scan: construction is free, equal
        // however it is made, and clones are interchangeable.
        let detector = ParameterSizeDetector::new();
        assert_eq!(detector, ParameterSizeDetector);
        assert_eq!(detector.clone(), detector);
    }

    #[test]
    fn a_detector_can_be_shared_across_scans() {
        // The detector is driven concurrently over a program's functions,
        // so sharing one by reference across tasks must stay sound.
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<ParameterSizeDetector>();
    }

    #[test]
    fn a_string_function_call_narrows_the_parameter_to_a_character_pointer() {
        let func = function(
            "undefined FUN_18003ab00(undefined4 param_1,undefined8 param_2)",
            "  uVar3 = strlen(param_2);\n",
        );
        let records = readings(&func);
        assert_eq!(records.len(), 1);
        let record = &records[0];
        assert_eq!(record.function, "FUN_18003ab00");
        assert_eq!(record.param_index, 1);
        assert_eq!(record.param_name.as_deref(), Some("param_2"));
        assert_eq!(record.inferred_type, "char *");
        assert_eq!(record.method, InferenceMethod::StringFunction);
        assert_eq!(record.scope, InferenceScope::Function);
        assert_eq!(record.confidence, STRING_CONFIDENCE);
        assert_eq!(record.evidence, "uVar3 = strlen(param_2);");
        assert!(record.is_pointer());
        assert!(!record.is_this_pointer());
    }

    #[test]
    fn both_arguments_of_a_string_copy_are_read_as_strings() {
        let func = function(
            "undefined FUN_18003ab00(undefined8 param_1,undefined8 param_2)",
            "  strcpy(param_1, param_2);\n",
        );
        let records = readings(&func);
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].param_index, 0);
        assert_eq!(records[1].param_index, 1);
        assert!(records
            .iter()
            .all(|r| r.inferred_type == "char *" && r.method == InferenceMethod::StringFunction));
    }

    #[test]
    fn a_cast_argument_still_names_the_value() {
        let func = function(
            "undefined FUN_18003ab00(undefined8 param_1)",
            "  strcmp((char *)param_1, (char *)s2);\n",
        );
        let records = readings(&func);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].param_index, 0);
        assert_eq!(records[0].inferred_type, "char *");
    }

    #[test]
    fn the_bounded_family_reads_string_positions_not_counts() {
        // `strncat(dest, src, n)`: the bound sits past the two strings and
        // says nothing about its argument's type.
        let func = function(
            "undefined FUN_18003ab00(undefined8 param_1,undefined8 param_2,undefined8 param_3)",
            "  strncat(param_1, param_2, param_3);\n",
        );
        let records = readings(&func);
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].param_index, 0);
        assert_eq!(records[1].param_index, 1);
        assert!(records
            .iter()
            .all(|r| r.inferred_type == "char *" && r.method == InferenceMethod::StringFunction));
    }

    #[test]
    fn a_character_argument_gets_no_string_reading() {
        // `strchr(s, c)` reads its first argument as a string; the second
        // is the character sought.
        let func = function(
            "undefined FUN_18003ab00(undefined8 param_1,undefined4 param_2)",
            "  pcVar3 = strchr(param_1, param_2);\n",
        );
        let records = readings(&func);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].param_index, 0);
        assert_eq!(records[0].inferred_type, "char *");
    }

    #[test]
    fn a_search_call_reads_haystack_and_needle() {
        let func = function(
            "undefined FUN_18003ab00(undefined8 param_1,undefined8 param_2)",
            "  pcVar3 = strstr(param_1, param_2);\n",
        );
        let records = readings(&func);
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].param_index, 0);
        assert_eq!(records[1].param_index, 1);
    }

    #[test]
    fn the_format_string_sits_behind_the_buffer_size() {
        // `snprintf(buf, size, fmt, ...)`: the format is the third
        // argument, and the size between them gets no reading.
        let func = function(
            "undefined FUN_18003ab00(undefined8 param_1,undefined8 param_2,undefined8 param_3)",
            "  snprintf(param_1, uVar2, param_3);\n",
        );
        let records = readings(&func);
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].param_index, 0);
        assert_eq!(records[1].param_index, 2);
        assert!(records.iter().all(|r| r.inferred_type == "char *"));
    }

    #[test]
    fn a_variadic_tail_argument_is_not_read_as_a_string() {
        // `sprintf(buf, "%d", param_2)` may pass any value through the
        // ellipsis; only the buffer position is known to be a string.
        let func = function(
            "undefined FUN_18003ab00(undefined8 param_1,undefined4 param_2)",
            "  sprintf(param_1, \"%d\", param_2);\n",
        );
        let records = readings(&func);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].param_index, 0);
    }

    #[test]
    fn shift_and_mask_usage_reads_the_parameter_as_an_integer() {
        let func = function(
            "undefined FUN_18003ab00(undefined4 param_1,undefined4 param_2)",
            "  uVar3 = (param_1 >> 8) & 0xff;\n\
             \x20 param_2 <<= 2;\n",
        );
        let records = readings(&func);
        assert_eq!(records.len(), 2);
        for record in &records {
            assert_eq!(record.inferred_type, "u32");
            assert_eq!(record.method, InferenceMethod::IntegerBitPattern);
            assert_eq!(record.confidence, INTEGER_CONFIDENCE);
        }
        assert_eq!(records[0].evidence, "uVar3 = (param_1 >> 8) & 0xff;");
        assert_eq!(records[1].evidence, "param_2 <<= 2;");
    }

    #[test]
    fn a_mask_wider_than_the_word_widens_the_reading_to_u64() {
        let func = function(
            "undefined FUN_18003ab00(undefined8 param_1)",
            "  uVar2 = param_1 & 0xffffffff00;\n",
        );
        let records = readings(&func);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].inferred_type, "u64");
        assert_eq!(records[0].method, InferenceMethod::IntegerBitPattern);
        assert_eq!(records[0].confidence, WIDE_INTEGRAL_CONFIDENCE);
        assert_eq!(records[0].evidence, "uVar2 = param_1 & 0xffffffff00;");
    }

    #[test]
    fn a_shift_count_beyond_the_word_widens_the_reading_to_u64() {
        let func = function(
            "undefined FUN_18003ab00(undefined8 param_1)",
            "  uVar2 = param_1 >> 0x20;\n",
        );
        let records = readings(&func);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].inferred_type, "u64");
        assert_eq!(records[0].confidence, WIDE_INTEGRAL_CONFIDENCE);
    }

    #[test]
    fn constants_the_default_word_covers_keep_the_default_word() {
        // `0xff000000` spans exactly the word and `>> 0x18` stays inside
        // it: the reading has no reason to move.
        let func = function(
            "undefined FUN_18003ab00(undefined4 param_1)",
            "  uVar2 = param_1 & 0xff000000;\n\
             \x20 uVar3 = param_1 >> 0x18;\n",
        );
        let records = readings(&func);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].inferred_type, "u32");
        assert_eq!(records[0].confidence, INTEGER_CONFIDENCE);
        assert_eq!(records[0].evidence, "uVar2 = param_1 & 0xff000000;");
    }

    #[test]
    fn the_widest_constant_across_a_function_s_operations_pins_the_width() {
        // A byte mask first, a beyond-the-word shift later: the reading
        // follows the constant that proves the width, not the first shape.
        let func = function(
            "undefined FUN_18003ab00(undefined4 param_1)",
            "  uVar2 = param_1 & 0xff;\n\
             \x20 uVar3 = param_1 >> 0x28;\n",
        );
        let records = readings(&func);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].inferred_type, "u64");
        assert_eq!(records[0].evidence, "uVar3 = param_1 >> 0x28;");
    }

    #[test]
    fn a_left_hand_mask_bounds_the_width() {
        let func = function(
            "undefined FUN_18003ab00(undefined8 param_1)",
            "  uVar2 = 0x100000000 & param_1;\n",
        );
        let records = readings(&func);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].inferred_type, "u64");
        assert_eq!(records[0].evidence, "uVar2 = 0x100000000 & param_1;");
    }

    #[test]
    fn a_compound_and_assignment_mask_bounds_the_width() {
        let func = function(
            "undefined FUN_18003ab00(undefined8 param_1)",
            "  param_1 &= 0x100000000;\n",
        );
        let records = readings(&func);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].inferred_type, "u64");
        assert_eq!(records[0].evidence, "param_1 &= 0x100000000;");
    }

    #[test]
    fn a_parameter_supplying_the_shift_count_gets_no_width_bound() {
        // `0x20 << param_1` shifts a constant by the parameter; the
        // constant says nothing about the parameter's width.
        let func = function(
            "undefined FUN_18003ab00(undefined4 param_1)",
            "  uVar2 = 0x20 << param_1;\n",
        );
        let records = readings(&func);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].inferred_type, "u32");
        assert_eq!(records[0].confidence, INTEGER_CONFIDENCE);
    }

    #[test]
    fn a_parameter_behind_a_cast_keeps_the_default_word() {
        // The cast promotes the expression, not the parameter: the
        // beyond-the-word count belongs to the cast's type.
        let func = function(
            "undefined FUN_18003ab00(undefined4 param_1)",
            "  lVar2 = (ulonglong)param_1 << 0x20;\n",
        );
        let records = readings(&func);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].inferred_type, "u32");
        assert_eq!(records[0].confidence, INTEGER_CONFIDENCE);
    }

    #[test]
    fn a_non_constant_operand_bounds_nothing() {
        let func = function(
            "undefined FUN_18003ab00(undefined4 param_1,undefined4 param_2)",
            "  uVar3 = param_1 & param_2;\n",
        );
        let records = readings(&func);
        assert_eq!(records.len(), 2);
        assert!(
            records
                .iter()
                .all(|r| r.inferred_type == "u32" && r.confidence == INTEGER_CONFIDENCE)
        );
    }

    #[test]
    fn an_integer_suffix_on_a_mask_constant_does_not_change_the_width() {
        // `0xffffffffu` is the full word, not a wide mask.
        let func = function(
            "undefined FUN_18003ab00(undefined4 param_1)",
            "  uVar2 = param_1 & 0xffffffffu;\n",
        );
        let records = readings(&func);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].inferred_type, "u32");
    }

    #[test]
    fn dereference_and_offset_arithmetic_read_the_parameter_as_a_pointer() {
        let func = function(
            "undefined FUN_18003ab00(undefined8 param_1,undefined8 param_2)",
            "  *param_1 = 0;\n\
             \x20 *(undefined4 *)(param_2 + 4) = uVar3;\n",
        );
        let records = readings(&func);
        assert_eq!(records.len(), 2);
        for record in &records {
            assert_eq!(record.inferred_type, "void *");
            assert_eq!(record.method, InferenceMethod::PointerArithmetic);
            assert_eq!(record.confidence, POINTER_CONFIDENCE);
        }
        assert_eq!(records[0].evidence, "*param_1 = 0;");
        assert_eq!(records[1].evidence, "*(undefined4 *)(param_2 + 4) = uVar3;");
    }

    #[test]
    fn a_logical_and_and_an_address_of_are_not_bit_operations() {
        // `&&` short-circuits, and `&p` takes the parameter's address —
        // neither says anything about an integer width.
        let func = function(
            "undefined FUN_18003ab00(undefined4 param_1)",
            "  if (param_1 != 0 && bVar2 != 0) {\n\
             \x20 FUN_18001234(&param_1);\n\
             }\n",
        );
        assert!(readings(&func).is_empty());
    }

    #[test]
    fn a_field_s_bit_operations_are_not_the_parameter_s() {
        // The whole-word guard keeps `param_1->flags & 0xff` from
        // reading the parameter itself as an integer operand; the arrow
        // still reads the parameter as a pointer.
        let func = function(
            "undefined FUN_18003ab00(undefined8 param_1)",
            "  uVar2 = param_1->flags & 0xff;\n",
        );
        let records = readings(&func);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].method, InferenceMethod::PointerArithmetic);
        assert_eq!(records[0].inferred_type, "void *");
    }

    #[test]
    fn field_access_reads_the_parameter_as_a_pointer() {
        let func = function(
            "undefined FUN_18003ab00(undefined8 param_1)",
            "  uVar2 = param_1->count;\n",
        );
        let records = readings(&func);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].inferred_type, "void *");
        assert_eq!(records[0].method, InferenceMethod::PointerArithmetic);
        assert_eq!(records[0].confidence, POINTER_CONFIDENCE);
        assert_eq!(records[0].evidence, "uVar2 = param_1->count;");
    }

    #[test]
    fn a_chained_arrow_and_an_array_index_read_the_parameter_as_a_pointer() {
        let func = function(
            "undefined FUN_18003ab00(undefined8 param_1,undefined8 param_2)",
            "  uVar3 = param_1->next->value;\n\
             \x20 uVar4 = param_2[2];\n",
        );
        let records = readings(&func);
        assert_eq!(records.len(), 2);
        assert!(records.iter().all(|r| {
            r.inferred_type == "void *" && r.method == InferenceMethod::PointerArithmetic
        }));
        assert_eq!(records[0].param_index, 0);
        assert_eq!(records[1].param_index, 1);
    }

    #[test]
    fn a_multiply_is_not_a_dereference() {
        // `count * param_1` and `param_1 * 2` are arithmetic on the
        // value; only a star that reads through the parameter points.
        let func = function(
            "undefined FUN_18003ab00(undefined4 param_1)",
            "  uVar2 = count * param_1;\n\
             \x20 uVar3 = param_1 * 2;\n",
        );
        assert!(readings(&func).is_empty());
    }

    #[test]
    fn a_bare_offset_nothing_reads_through_is_not_a_pointer_reading() {
        let func = function(
            "undefined FUN_18003ab00(undefined4 param_1)",
            "  uVar2 = param_1 + 4;\n",
        );
        assert!(readings(&func).is_empty());
    }

    #[test]
    fn a_parameter_used_two_ways_gets_one_reading_per_family() {
        // Masked in one line, shifted in the next: the integer family
        // contributes one record, backed by the first matching shape.
        let func = function(
            "undefined FUN_18003ab00(undefined4 param_1)",
            "  uVar2 = param_1 & 0xff;\n\
             \x20 uVar3 = param_1 >> 4;\n",
        );
        let records = readings(&func);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].method, InferenceMethod::IntegerBitPattern);
        assert_eq!(records[0].evidence, "uVar2 = param_1 & 0xff;");
    }

    #[test]
    fn a_string_reading_beats_a_pointer_reading_for_one_parameter() {
        // `strcpy` says character pointer, the bare dereference only
        // says pointer: the stronger reading wins and the other drops.
        let func = function(
            "undefined FUN_18003ab00(undefined8 param_1)",
            "  strcpy(param_1, s2);\n\
             \x20 *param_1 = 0;\n",
        );
        let records = readings(&func);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].inferred_type, "char *");
        assert_eq!(records[0].method, InferenceMethod::StringFunction);
        assert_eq!(records[0].confidence, STRING_CONFIDENCE);
        assert_eq!(records[0].evidence, "strcpy(param_1, s2);");
    }

    #[test]
    fn a_pointer_reading_beats_an_integer_reading_for_one_parameter() {
        // Shifted in one line, read through in the next: the pointer
        // reading carries more certainty than the bare default word.
        let func = function(
            "undefined FUN_18003ab00(undefined4 param_1)",
            "  uVar2 = param_1 >> 2;\n\
             \x20 *param_1 = 0;\n",
        );
        let records = readings(&func);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].inferred_type, "void *");
        assert_eq!(records[0].method, InferenceMethod::PointerArithmetic);
        assert_eq!(records[0].evidence, "*param_1 = 0;");
    }

    #[test]
    fn the_widest_integer_reading_still_loses_to_a_pointer_reading() {
        // A pinned `u64` (60) is stronger evidence than a bare word,
        // but a read-through offset (65) still outranks it.
        let func = function(
            "undefined FUN_18003ab00(undefined8 param_1)",
            "  uVar2 = param_1 & 0xffffffff00;\n\
             \x20 *(undefined4 *)(param_1 + 4) = 0;\n",
        );
        let records = readings(&func);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].inferred_type, "void *");
        assert_eq!(records[0].method, InferenceMethod::PointerArithmetic);
    }

    #[test]
    fn a_parameter_read_three_ways_keeps_only_the_string_reading() {
        // Called through `strlen`, indexed, and shifted: the character
        // pointer reading carries the body's strongest claim.
        let func = function(
            "undefined FUN_18003ab00(undefined8 param_1)",
            "  uVar2 = strlen(param_1);\n\
             \x20 uVar3 = param_1[0];\n\
             \x20 uVar4 = param_1 >> 8;\n",
        );
        let records = readings(&func);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].inferred_type, "char *");
        assert_eq!(records[0].method, InferenceMethod::StringFunction);
    }

    #[test]
    fn string_literals_do_not_produce_readings() {
        // A format string naming a string function, or spelling a
        // parameter's name, says nothing about the parameter.
        let func = function(
            "undefined FUN_18003ab00(undefined8 param_1)",
            "  FUN_1800412a0(\"strlen(param_1) >> 8\", uVar2);\n",
        );
        assert!(readings(&func).is_empty());
    }

    #[test]
    fn a_function_without_parameters_yields_no_readings() {
        let func = function("undefined FUN_18003ab00(void)", "  return;\n");
        assert!(readings(&func).is_empty());
    }

    #[test]
    fn a_local_variable_s_usage_is_not_a_parameter_reading() {
        // Shifts and dereferences on locals say nothing about the
        // signature.
        let func = function(
            "undefined FUN_18003ab00(undefined8 param_1)",
            "  uVar4 = uVar7 >> 2;\n\
             \x20 *puVar5 = 0;\n",
        );
        assert!(readings(&func).is_empty());
    }
}
