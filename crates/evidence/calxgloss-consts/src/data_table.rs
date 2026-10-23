//! Data-table detection.
//!
//! A read-only data table — game stats, an opcode table, a damage
//! curve — survives decompilation as scattered `DAT_x[idx]` reads and
//! an untyped blob in the engine's data listing. This module reads
//! that shape back: for each object the listing defines (`data_items`),
//! the bytes the engine exposes (`read_memory`) decode coherently at a
//! stride, the kept bodies' indexed reads corroborate a read and its
//! width (`DAT_x[idx]` under a bounds guard `if (idx < N)`, the same
//! shape callback's jump-table reading sizes its tables from), and the
//! engine's cross-references (`xrefs_to`) name the referencing
//! functions. All three reads are existing `ScanSource` seam methods,
//! cached under ADR-0043; nothing is written back to the program
//! (ADR-0020).
//!
//! A stride claims only when the object's whole byte run decodes into
//! one coherent family for that type: at least two entries, none zero
//! or equal to all the rest, magnitudes within one bounded spread
//! (finite, ordinary-magnitude values for the float strides at 4 and
//! 8, bounded spread for the integer strides) — an object whose bytes
//! decode incoherently at every stride, unstructured `.rdata` padding,
//! claims nothing. Strides 4 and 8 spell two families each and both
//! readings can be coherent at once; the integer family claims the
//! stride and the float family claims it only where the integer
//! reading fails or where the listing's applied type names a float, so
//! a claim never reports floats the bytes do not say are floats. When
//! several strides decode coherently the engine's applied listing type
//! (`type_name`, e.g. `uint` or `float [3]`) resolves the claim when
//! its stride is a viable one; failing that, the widths implied by
//! indexing bodies' bounds guards narrow the strides to one, and it
//! claims nothing unless they do — as does a guard that contradicts
//! the bytes or the applied type, or bytes that contradict the applied
//! type. The Evidence scale scores each claim by what stands behind
//! it: the engine-applied type is the highest tier (90); a clean
//! decode corroborated by an indexed read in a kept body high-mid
//! (70); a clean decode that cross-references name readers for but no
//! kept body visibly indexes mid (50); and raw bytes only,
//! unreferenced, low (30) — an honest low score, not silence.
//!
//! Two shapes still claim nothing outright: a kept body that stores
//! through the symbol makes the object mutable global state, the
//! global-state track's territory, and never a constant table; and any
//! entry resolving to a function start the function listing names is
//! either a dispatch table — the callback crate's jump-table reading
//! owns that outright — or a half-decoded mix that never lands as a
//! false const array. The claim stays inside what bytes, reads, and
//! the function listing agree on.
//!
//! The engine calls [`data_tables`] once per scan with the data
//! listing and, parallel to it, what the bodies the walk kept do with
//! each object — its indexed reads and whether anything stores
//! through its symbol — plus the addresses the function listing
//! names; the reading lands one record per qualifying object, in
//! listing order.

use std::collections::BTreeSet;

use calxgloss_decomp::{DataItem, DecompiledFunction, ScanSource};
use calxgloss_types::{is_ident_byte, skip_char, skip_string, skip_ws};
use tracing::{debug, warn};

use crate::types::{Confidence, DataTable, MAX_INLINE_TABLE_VALUES};

/// Confidence of a table the engine's own listing typed: the applied
/// array or element type is the decompiler's own declaration about the
/// object, the spec's highest table tier, above every decode-only
/// family below it.
const APPLIED_TYPE_CONFIDENCE: u8 = 90;

/// Confidence of a table the bytes decode coherently at and an indexed
/// read in a kept body corroborates — the spec's high-mid band, beside
/// the corroborated jump-table reading's 70.
const CORROBORATED_CONFIDENCE: u8 = 70;

/// Confidence of a clean decode the cross-references name readers for
/// but no kept body visibly indexes — the spec's mid tier: real use,
/// but no body read to corroborate the shape against.
const REFERENCED_CONFIDENCE: u8 = 50;

/// Confidence of a raw-bytes-only claim: bytes that decode coherently
/// with nothing referencing the object at all — the spec's low tier,
/// kept on the record at an honestly low score rather than hidden.
const UNREFERENCED_CONFIDENCE: u8 = 30;

/// The largest ratio between a table's biggest and smallest entry
/// magnitude that still reads as one coherent family of values. Entries
/// further apart than this look like unstructured padding, or like a
/// wide stride accidentally reading a small table's bytes as huge
/// scalars, and claim nothing.
const MAGNITUDE_SPREAD: u64 = 1_000_000;

/// The same gate in the float families' space, as a `f32` so it reaches
/// `f64` through an exact `From` rather than a lossy cast.
const MAGNITUDE_SPREAD_F: f32 = 1_000_000.0;

/// The float magnitudes an entry has to stay inside for a float decode
/// to be sane: below [`MAGNITUDE_SPREAD`]-spaced, but also ordinary —
/// subnormal-scale and astronomically large bit patterns are what
/// integer-looking bytes misread as floats look like, and they claim
/// nothing.
const FLOAT_MAGNITUDE_MIN: f64 = 1e-30;

/// The upper bound of the ordinary float magnitude band; see
/// [`FLOAT_MAGNITUDE_MIN`].
const FLOAT_MAGNITUDE_MAX: f64 = 1e30;

/// The byte widths a table entry can occupy, as widths and as the
/// Rust element type each spells.
const ELEMENT_WIDTHS: [(u64, &str); 4] = [(1, "u8"), (2, "u16"), (4, "u32"), (8, "u64")];

/// One element family a stride can decode into: a width in bytes, the
/// Rust element type it spells, and whether entries read as IEEE-754
/// floats rather than unsigned integers. Strides 4 and 8 each spell
/// two families — the widths where `.rdata` scalars are as likely to
/// be floats as integers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Family {
    width: u64,
    name: &'static str,
    float: bool,
}

/// The element families a table can claim: an integer decode at every
/// stride in {1, 2, 4, 8}, plus the float decodes at the strides whose
/// bytes could be floats. The order is the tie-break at the strides
/// that spell two families: the integer family stands first, so it
/// claims the stride wherever its own reading is coherent.
const FAMILIES: &[Family] = &[
    Family {
        width: 1,
        name: "u8",
        float: false,
    },
    Family {
        width: 2,
        name: "u16",
        float: false,
    },
    Family {
        width: 4,
        name: "u32",
        float: false,
    },
    Family {
        width: 4,
        name: "f32",
        float: true,
    },
    Family {
        width: 8,
        name: "u64",
        float: false,
    },
    Family {
        width: 8,
        name: "f64",
        float: true,
    },
];

/// One indexed read of a data object found in a kept body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct IndexedRead {
    /// The function whose body carries the read.
    pub function: String,
    /// The decompiled line, trimmed — the evidence the claim quotes.
    pub line: String,
    /// The entry width the read's bounds guard implies: the guard's
    /// bound is the entry count, so width = length / bound. Absent
    /// when the read carries no readable bounds check.
    pub width: Option<u64>,
}

/// Whether `line` indexes the data object `label` — `label[` —
/// returning one [`IndexedRead`] per such line.
///
/// The object's byte `length` turns a bounds guard's bound into the
/// width it implies. A bracketed index that is a compound expression
/// (`i * 4`, `i + 1`) proves the reference but names no bound, so it
/// carries no width; only a simple identifier index is read for a
/// guard. The read is found textually, so it reads the shape, not the
/// direction — a write (`label[i] = v`) is the same text — and the
/// engine asks [`stores_through`] first, calling this only for a line
/// that stores nothing, so a claim's evidence is always a read.
pub(crate) fn indexed_read(
    body: &DecompiledFunction,
    label: &str,
    line: &str,
    length: u64,
) -> Option<IndexedRead> {
    let marker = format!("{label}[");
    let at = line.find(&marker)?;
    let index = bracketed_index(&line[at + marker.len()..]);
    let width = if is_simple_ident(index) {
        body.body
            .lines()
            .find_map(|guard| bounds_check(guard, index))
            .and_then(|bound| bound_width(length, bound))
    } else {
        None
    };
    Some(IndexedRead {
        function: body.name.clone(),
        line: line.trim().to_string(),
        width,
    })
}

/// What the bodies the walk kept do with one data object, collected as
/// the engine reads them: the indexed reads a table claim rests on,
/// and the mutation gate's signal.
#[derive(Debug, Default)]
pub(crate) struct ObjectUsage {
    /// The indexed reads found in the kept bodies, in body order.
    pub reads: Vec<IndexedRead>,
    /// Whether any kept body stores through the symbol. Such an
    /// object is mutable global state — the global-state track's
    /// territory — so it never reads as a constant table.
    pub written: bool,
}

/// Whether a kept body's `line` stores through the data object
/// `label`: an assignment to the symbol (`DAT_x = v`, `DAT_x += v`),
/// a store through an index into it (`DAT_x[i] = v`, `DAT_x[i]++`),
/// or a store through it another way (`*(&DAT_x)[i] = v`,
/// `*(int *)(DAT_x + 4) = 0`).
///
/// The rule reads forward from the name, the way the global-state
/// crate's access kind does, so a dereference, cast, or address-of
/// wrapped around the symbol needs no case of its own: the reference's
/// tail — subscript groups, a `)` closing the wrapper the body opened
/// before the name, a `+ 4` offset, a `.field` selection — has to open
/// with an assignment (`=`, never `==`, and the compound `+=`-style
/// stores) or a `++`/`--` bump for the name to be a store target. A
/// test, a plain copy, and the name spelled inside a string or char
/// literal store nothing, and a longer label that merely starts with
/// this one (`DAT_1400a1b600`) is never this object.
pub(crate) fn stores_through(line: &str, label: &str) -> bool {
    let bytes = line.as_bytes();
    let mut at = 0;
    while at < bytes.len() {
        match bytes[at] {
            b'"' => at = skip_string(bytes, at + 1),
            b'\'' => at = skip_char(bytes, at + 1),
            b if b.is_ascii_alphabetic() || b == b'_' => {
                let end = name_end(bytes, at);
                if &line[at..end] == label && stores_after(line, end) {
                    return true;
                }
                at = end;
            }
            _ => at += 1,
        }
    }
    false
}

/// The end of the identifier run starting at `start` — letters,
/// digits, and underscores — so a name is only ever matched whole.
fn name_end(bytes: &[u8], start: usize) -> usize {
    let mut end = start;
    while end < bytes.len() && is_ident_byte(bytes[end]) {
        end += 1;
    }
    end
}

/// Whether what follows the symbol reference ending at `at` is a
/// store, past the reference's tail. `if (DAT_x[i] == 3) uVar1 = 4;`
/// reads as a read because the reference's tail stops at the `==`,
/// which is a comparison: the assignment further along the line never
/// becomes this object's store target.
fn stores_after(line: &str, mut at: usize) -> bool {
    let bytes = line.as_bytes();
    loop {
        at = skip_ws(bytes, at);
        if store_operator(line, at).is_some() {
            return true;
        }
        match bytes.get(at) {
            // A subscript group belongs to the reference, index
            // expression and all — `DAT_x[i]`, `(&DAT_x)[uVar2]`,
            // `DAT_x[i][j]`.
            Some(b'[') => match closing_bracket(line, at) {
                Some(close) => at = close + 1,
                None => return false,
            },
            // A closer belongs to the wrapper the body opened before
            // the name: `*(int *)(DAT_x + 4)`, `*(&DAT_x)[i]`.
            Some(b')') => at += 1,
            // A field selection: `DAT_x.count = 3`.
            Some(b'.') => match member_at(bytes, at + 1) {
                Some(end) => at = end,
                None => return false,
            },
            Some(b'-') if bytes.get(at + 1) == Some(&b'>') => match member_at(bytes, at + 2) {
                Some(end) => at = end,
                None => return false,
            },
            // A byte offset out of the symbol's own storage: the
            // `+ 4` of `*(int *)(DAT_x + 4) = 0`.
            Some(b'+' | b'-') => match number_end(bytes, at + 1) {
                Some(end) => at = end,
                None => return false,
            },
            _ => return false,
        }
    }
}

/// The assignment and bump operators, longest spelling first so
/// `<<=` never reads as a comparison. `==` is excluded: a test stores
/// nothing. The index just past the operator, when `line` opens with
/// one at `at`.
fn store_operator(line: &str, at: usize) -> Option<usize> {
    const OPERATORS: [&str; 13] = [
        "<<=", ">>=", "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", "++", "--", "=",
    ];
    let rest = &line[at..];
    OPERATORS
        .iter()
        .find(|op| rest.starts_with(**op) && !rest.starts_with("=="))
        .map(|op| at + op.len())
}

/// The member name a `.` or `->` selects at `at`, as the end of that
/// name — `None` when nothing name-like follows, which ends the
/// reference's tail rather than letting the scan stall.
fn member_at(bytes: &[u8], at: usize) -> Option<usize> {
    let start = skip_ws(bytes, at);
    if !bytes
        .get(start)
        .is_some_and(|b| b.is_ascii_alphabetic() || *b == b'_')
    {
        return None;
    }
    Some(name_end(bytes, start))
}

/// The index of the `]` matching the `[` at `open`, skipping string
/// and char literals so a `]` inside one cannot close the subscript
/// early — [`calxgloss_types::closing_paren`]'s rule for brackets.
fn closing_bracket(body: &str, open: usize) -> Option<usize> {
    let bytes = body.as_bytes();
    let mut depth = 0usize;
    let mut at = open;
    while at < bytes.len() {
        match bytes[at] {
            b'"' => at = skip_string(bytes, at + 1),
            b'\'' => at = skip_char(bytes, at + 1),
            b'[' => {
                depth += 1;
                at += 1;
            }
            b']' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Some(at);
                }
                at += 1;
            }
            _ => at += 1,
        }
    }
    None
}

/// The end of the integer literal starting at or after `at`, as the
/// index just past its digits — the `4` of `DAT_x + 4`, hex spelled
/// too — `None` when no digits are there at all.
fn number_end(bytes: &[u8], at: usize) -> Option<usize> {
    let start = skip_ws(bytes, at);
    let hex = bytes.get(start) == Some(&b'0')
        && matches!(bytes.get(start + 1), Some(&b'x') | Some(&b'X'));
    let digits = if hex { start + 2 } else { start };
    let mut end = digits;
    while end < bytes.len()
        && bytes[end].is_ascii_hexdigit()
        && (hex || bytes[end].is_ascii_digit())
    {
        end += 1;
    }
    (end > digits).then_some(end)
}

/// The text between an opening bracket already consumed and its
/// closing `]` — empty when the bracket never closes or the index is
/// compound.
fn bracketed_index(after: &str) -> &str {
    let Some(close) = after.find(']') else {
        return "";
    };
    let index = &after[..close];
    if index.contains('[') { "" } else { index }
}

/// Whether `s` is a plain decompiler identifier — letters, digits and
/// underscores, not starting with a digit.
fn is_simple_ident(s: &str) -> bool {
    !s.is_empty()
        && !s.starts_with(|c: char| c.is_ascii_digit())
        && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// A `bound` guarding the entry count of a `length`-byte object, as
/// the entry width it implies — only when the bound names at least
/// two entries and divides the object exactly into one of the four
/// element widths.
fn bound_width(length: u64, bound: usize) -> Option<u64> {
    let bound = bound as u64;
    if bound < 2 || !length.is_multiple_of(bound) {
        return None;
    }
    let width = length / bound;
    ELEMENT_WIDTHS
        .iter()
        .any(|(w, _)| *w == width)
        .then_some(width)
}

/// A bounds check on `index` in one body line, as the exclusive upper
/// bound it states: `idx < N` and `N > idx` name `N`, `idx <= N` and
/// `N >= idx` name `N + 1`. Hex bounds (`0xc`) read as hex; anything
/// else — other variables, unparseable counts — names nothing.
fn bounds_check(line: &str, index: &str) -> Option<usize> {
    // `idx <op> N`: the index on the left.
    for (cmp, incl) in [("<=", true), ("<", false)] {
        let pattern = format!("{index} {cmp} ");
        if let Some(rest) = line.split_once(&pattern).map(|(_, r)| r.trim())
            && let Some(n) = parse_count(rest)
        {
            return Some(if incl { n + 1 } else { n });
        }
    }
    // `N <op> idx`: the index on the right, mirrored.
    for (cmp, incl) in [(">=", true), (">", false)] {
        let pattern = format!(" {cmp} {index}");
        if let Some((left, _)) = line.rsplit_once(&pattern) {
            let token = left.split_whitespace().next_back()?;
            if let Some(n) = parse_count(token) {
                return Some(if incl { n + 1 } else { n });
            }
        }
    }
    None
}

/// One integer literal, decimal or `0x`-hex, at the start of `s` —
/// leading punctuation (an `if (` paren) and trailing punctuation (a
/// closing paren or semicolon) trimmed off.
fn parse_count(s: &str) -> Option<usize> {
    let token = s.split_whitespace().next()?;
    let token = token.trim_start_matches(|c: char| !(c.is_ascii_hexdigit() || c == 'x'));
    let digits = token.trim_end_matches(|c: char| !(c.is_ascii_alphanumeric() || c == 'x'));
    if let Some(hex) = digits.strip_prefix("0x") {
        usize::from_str_radix(hex, 16).ok()
    } else {
        digits.parse().ok()
    }
}

/// The element families the object's bytes decode coherently at. Each
/// family survives only when the width divides the length into at
/// least two entries and every entry decodes into a coherent family
/// for that type: no zero entries (a gap or terminator is not a
/// uniform array), not all equal (a fill is a fill, not a table), and
/// magnitudes within [`MAGNITUDE_SPREAD`] of each other — the float
/// families additionally require every bit pattern to be a finite,
/// nonzero, ordinary-magnitude number, the shape integer-looking bytes
/// never accidentally spell. An object that fails every family is
/// unstructured padding and claims nothing.
fn viable_families(bytes: &[u8]) -> Vec<Family> {
    FAMILIES
        .iter()
        .copied()
        .filter(|family| coherent_family(bytes, family))
        .collect()
}

/// The family to claim one stride with, out of the coherent families
/// the guards left standing. Families are the tie-break order, so the
/// integer reading of a stride claims it wherever both readings hold;
/// no family surviving the guards contradicts them, and several
/// surviving strides is a decode nothing sized — both claim nothing.
fn one_stride(families: &[Family]) -> Option<Family> {
    let widths: BTreeSet<u64> = families.iter().map(|family| family.width).collect();
    match widths.len() {
        1 => families.first().copied(),
        _ => None,
    }
}

/// Whether `bytes` decode into one coherent family of `family`'s type.
fn coherent_family(bytes: &[u8], family: &Family) -> bool {
    let width = family.width as usize;
    if !bytes.len().is_multiple_of(width) || bytes.len() / width < 2 {
        return false;
    }
    if family.float {
        let values: Vec<f64> = bytes
            .chunks(width)
            .map(|chunk| {
                let bits = le_u64(chunk);
                if width == 4 {
                    f32::from_bits(bits as u32) as f64
                } else {
                    f64::from_bits(bits)
                }
            })
            .collect();
        let (mut min, mut max) = (f64::INFINITY, 0.0f64);
        values.iter().all(|value| {
            min = min.min(value.abs());
            max = max.max(value.abs());
            value.is_finite()
                && *value != 0.0
                && value.abs() >= FLOAT_MAGNITUDE_MIN
                && value.abs() <= FLOAT_MAGNITUDE_MAX
        }) && values.iter().any(|value| *value != values[0])
            && max <= min * f64::from(MAGNITUDE_SPREAD_F)
    } else {
        let entries: Vec<u64> = bytes.chunks(width).map(le_u64).collect();
        let (mut min, mut max) = (u64::MAX, 0u64);
        entries.iter().all(|entry| {
            min = min.min(*entry);
            max = max.max(*entry);
            *entry != 0
        }) && entries.iter().any(|entry| *entry != entries[0])
            && max / min <= MAGNITUDE_SPREAD
    }
}

/// The element family the engine's applied listing type names, when it
/// names one. The type is the listing's own declaration about the
/// object — `uint`, `float [3]`, `undefined4` — and names a stride only
/// for the uniform element types: `undefined`, pointers, struct and
/// typedef names name nothing. An applied array type states a count
/// too, and an array whose count disagrees with the object's length is
/// a mislabeled object — it resolves no stride either.
fn applied_family(type_name: &str, length: u64) -> Option<Family> {
    let (base, count) = match type_name.split_once('[') {
        Some((base, rest)) => (
            base.trim(),
            rest.trim().trim_end_matches(']').trim().parse::<u64>().ok(),
        ),
        None => (type_name.trim(), None),
    };
    let name = match base.to_ascii_lowercase().as_str() {
        "char" | "uchar" | "byte" | "uint8" | "undefined1" => "u8",
        "short" | "ushort" | "word" | "uint16" | "undefined2" => "u16",
        "int" | "uint" | "dword" | "uint32" | "undefined4" => "u32",
        "float" => "f32",
        "qword" | "longlong" | "ulonglong" | "uint64" | "undefined8" => "u64",
        "double" => "f64",
        _ => return None,
    };
    let family = FAMILIES.iter().copied().find(|f| f.name == name)?;
    if let Some(count) = count
        && count.checked_mul(family.width) != Some(length)
    {
        return None;
    }
    Some(family)
}

/// One little-endian chunk as an integer.
fn le_u64(bytes: &[u8]) -> u64 {
    let mut value = 0u64;
    for (i, byte) in bytes.iter().enumerate() {
        value |= (*byte as u64) << (i * 8);
    }
    value
}

/// The table reading for one data object: no kept body may store
/// through its symbol, its bytes must be readable in full and decode
/// coherently, one family must survive the resolution — the engine's
/// applied listing type when it names a viable family, otherwise the
/// families the bounds guards of indexing bodies narrow to exactly one,
/// otherwise a single coherent family standing alone — and none of its
/// entries may resolve to one of the `function_starts` the listing
/// names. `None` silently for a disqualifying or unresolved shape, with
/// a warning for a read that failed. A kept body's indexed read is no
/// longer required to claim: it decides which Evidence tier the claim
/// lands at, from applied type at the top to raw bytes only at the
/// bottom.
async fn read_object<S: ScanSource>(
    source: &S,
    item: &DataItem,
    usage: &ObjectUsage,
    function_starts: &BTreeSet<u64>,
) -> Option<DataTable> {
    if usage.written {
        // The mutation gate: a body that stores through the symbol
        // makes it mutable global state, the global-state track's
        // territory, so it never reads as a constant table.
        debug!(
            object = %item.label,
            address = format_args!("{:#x}", item.address),
            "Skipping data object: a kept body stores through the symbol"
        );
        return None;
    }
    let reads = &usage.reads;
    if item.label.is_empty() || item.length < 2 {
        // No stride divides a shorter object into the two entries the
        // candidate gate asks for.
        return None;
    }
    let bytes = match source.read_memory(item.address, item.length as usize).await {
        Ok(bytes) => bytes,
        Err(error) => {
            warn!(
                object = %item.label,
                address = format_args!("{:#x}", item.address),
                error = %error,
                "Skipping data object: read_memory failed"
            );
            return None;
        }
    };
    if bytes.len() as u64 != item.length {
        warn!(
            object = %item.label,
            address = format_args!("{:#x}", item.address),
            "Skipping data object: short memory window"
        );
        return None;
    }

    let viable = viable_families(&bytes);
    if viable.is_empty() {
        debug!(
            object = %item.label,
            address = format_args!("{:#x}", item.address),
            "Skipping data object: bytes decode incoherently at every stride"
        );
        return None;
    }
    // The widths the indexing bodies' guards imply; guards naming no
    // width do not narrow.
    let implied: BTreeSet<u64> = reads.iter().filter_map(|read| read.width).collect();
    // Resolution in the spec's order, over strides: the listing's
    // applied type claims its stride, and claims nothing when the
    // bytes or a guard contradict it; failing the applied type, the
    // guards narrow the viable strides to one; and several strides
    // nothing resolves claim nothing.
    let applied = applied_family(&item.type_name, item.length);
    let mut confidence = None;
    let family = if let Some(applied) = applied {
        if !viable.contains(&applied) {
            debug!(
                object = %item.label,
                address = format_args!("{:#x}", item.address),
                applied_type = %item.type_name,
                "Skipping data object: the bytes decode incoherently at the applied type's stride"
            );
            return None;
        }
        if !implied.is_empty() && !implied.contains(&applied.width) {
            debug!(
                object = %item.label,
                address = format_args!("{:#x}", item.address),
                applied_type = %item.type_name,
                "Skipping data object: the reads' bounds guards contradict the applied type"
            );
            return None;
        }
        confidence = Some(APPLIED_TYPE_CONFIDENCE);
        applied
    } else if !implied.is_empty() {
        let narrowed: Vec<Family> = viable
            .into_iter()
            .filter(|family| implied.contains(&family.width))
            .collect();
        let Some(family) = one_stride(&narrowed) else {
            // Zero surviving strides is a contradiction between the
            // guards and the bytes; several is an unresolved
            // multi-stride decode — both claim nothing.
            return None;
        };
        confidence = Some(CORROBORATED_CONFIDENCE);
        family
    } else {
        let Some(family) = one_stride(&viable) else {
            debug!(
                object = %item.label,
                address = format_args!("{:#x}", item.address),
                "Skipping data object: several strides decode coherently with nothing to resolve them"
            );
            return None;
        };
        family
    };

    // The entries the claim reports and vetoes against: the raw
    // little-endian chunk at the chosen width — for the float
    // families, the entries' IEEE-754 bit patterns, kept whole for
    // codegen to re-spell.
    let entries: Vec<u64> = bytes.chunks(family.width as usize).map(le_u64).collect();
    let count = entries.len();
    // The pointer gates: an entry equal to one of the addresses the
    // function listing names is a pointer to a function start. Every
    // entry resolving is a dispatch table — the callback crate's
    // jump-table reading is that owner outright — and some entries
    // resolving is a half-decoded mix that never lands as a false
    // const array, so one resolving entry claims nothing. A value the
    // listing does not name is an ordinary scalar: the veto is
    // resolution, not magnitude.
    let pointers = entries
        .iter()
        .filter(|entry| function_starts.contains(entry))
        .count();
    if pointers > 0 {
        debug!(
            object = %item.label,
            address = format_args!("{:#x}", item.address),
            resolving = format_args!("{pointers}/{count} entries resolve to function starts"),
            "Skipping data object: function-pointer table, the callback crate's jump-table reading owns it"
        );
        return None;
    }
    let values_truncated = count > MAX_INLINE_TABLE_VALUES;
    let mut values = entries;
    values.truncate(MAX_INLINE_TABLE_VALUES);

    // The referencing functions come from the engine's
    // cross-references — ascending, deduped. A failed xref read is
    // logged and left empty: the claim rests on the bytes and the
    // body read; the functions only widen the per-function view and
    // settle the tier.
    let functions: Vec<String> = match source.xrefs_to(item.address).await {
        Ok(xrefs) => xrefs
            .iter()
            .filter_map(|xref| xref.function.clone())
            .collect::<BTreeSet<String>>()
            .into_iter()
            .collect(),
        Err(error) => {
            warn!(
                object = %item.label,
                address = format_args!("{:#x}", item.address),
                error = %error,
                "Data table landed without referencing functions: xrefs_to failed"
            );
            Vec::new()
        }
    };

    // The tier, last settled against what actually stands behind the
    // claim: applied type and guard-corroborated claims scored during
    // resolution; an open claim at indexed read (high-mid), named
    // cross-references (mid), or nothing at all (low).
    let confidence = confidence.unwrap_or(if !reads.is_empty() {
        CORROBORATED_CONFIDENCE
    } else if !functions.is_empty() {
        REFERENCED_CONFIDENCE
    } else {
        UNREFERENCED_CONFIDENCE
    });

    // The evidence a reviewer checks: the resolution's strongest
    // backing first — the applied listing type when it decided the
    // claim — then the indexed-read lines, and for a decode-only
    // claim the decode itself with what referencing it amounts to.
    let mut evidence: Vec<String> = Vec::new();
    if confidence == APPLIED_TYPE_CONFIDENCE {
        evidence.push(format!(
            "data listing applies type `{}`",
            item.type_name.trim()
        ));
    }
    if !reads.is_empty() {
        // The read lines already end in the decompiler's semicolon:
        // one line per corroborating body, spaced apart.
        evidence.push(
            reads
                .iter()
                .map(|read| format!("{}: {}", read.function, read.line))
                .collect::<Vec<String>>()
                .join(" "),
        );
    }
    if evidence.is_empty() {
        let decode = format!(
            "{} bytes decode cleanly as {count} {} entries at {:#x}",
            item.length, family.name, item.address
        );
        if functions.is_empty() {
            evidence.push(format!("{decode}; nothing references the object"));
        } else {
            let readers = match functions.len() {
                1 => "one function".to_string(),
                count => format!("{count} functions"),
            };
            evidence.push(format!(
                "{decode}; the cross-references name {readers}, no kept body indexes it"
            ));
        }
    }

    Some(DataTable {
        symbol: item.label.clone(),
        address: item.address,
        element_type: family.name.to_string(),
        count,
        values,
        values_truncated,
        functions,
        suggestion: DataTable::render_suggestion(&item.label, family.name, count),
        confidence: Confidence::new(confidence),
        evidence: evidence.join("; "),
    })
}

/// The program's data tables: every object the engine's data listing
/// defines whose bytes decode coherently at exactly one resolved
/// stride, that no kept body stores through, and whose entries none of
/// which resolves to a listed function start, in listing order.
/// `table_usage` is parallel to `items` — what the walk collected from
/// the bodies it kept, per object — and `function_starts` is the
/// address set the function listing names, which the pointer gates
/// resolve entries against. A failed listing fails the run like the
/// function listing's failure (the engine reads it before calling
/// this); a failing per-object read skips that object with a warning,
/// and a disqualified or unresolved shape skips it silently.
pub(crate) async fn data_tables<S: ScanSource>(
    source: &S,
    items: &[DataItem],
    table_usage: &[ObjectUsage],
    function_starts: &BTreeSet<u64>,
) -> Vec<DataTable> {
    let mut tables = Vec::new();
    for (item, usage) in items.iter().zip(table_usage) {
        if let Some(record) = read_object(source, item, usage, function_starts).await {
            tables.push(record);
        }
    }
    tables
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn body(name: &str, text: &str) -> DecompiledFunction {
        DecompiledFunction {
            name: name.to_string(),
            signature: format!("undefined {name}(void)"),
            body: format!("\nundefined {name}(void)\n\n{{\n{text}}}\n"),
        }
    }

    /// The element type names of a viability result, for readable
    /// assertions.
    fn families_at(bytes: &[u8]) -> Vec<&'static str> {
        viable_families(bytes)
            .iter()
            .map(|family| family.name)
            .collect()
    }

    #[test]
    fn an_indexed_simple_read_carries_no_width_without_a_guard() {
        let program = body("FUN_18003ab00", "  uVar3 = DAT_1400a1b60[uVar2];\n");
        let read = indexed_read(
            &program,
            "DAT_1400a1b60",
            "  uVar3 = DAT_1400a1b60[uVar2];",
            24,
        )
        .expect("the indexed read is found");
        assert_eq!(read.function, "FUN_18003ab00");
        assert_eq!(read.line, "uVar3 = DAT_1400a1b60[uVar2];");
        assert_eq!(read.width, None);
    }

    #[test]
    fn a_bounds_guard_on_the_index_implies_the_width() {
        let program = body(
            "FUN_18003ab00",
            "  if (uVar2 < 0xc) {\n    uVar3 = DAT_1400a1b60[uVar2];\n  }\n",
        );
        let read = indexed_read(
            &program,
            "DAT_1400a1b60",
            "    uVar3 = DAT_1400a1b60[uVar2];",
            24,
        )
        .expect("the indexed read is found");
        // 24 bytes / 12 entries = u16 entries.
        assert_eq!(read.width, Some(2));
    }

    #[test]
    fn a_compound_index_proves_the_read_but_names_no_width() {
        let program = body(
            "FUN_18003ab00",
            "  if (uVar2 < 0xc) {\n    uVar3 = DAT_1400a1b60[uVar2 * 2];\n  }\n",
        );
        let read = indexed_read(
            &program,
            "DAT_1400a1b60",
            "    uVar3 = DAT_1400a1b60[uVar2 * 2];",
            24,
        )
        .expect("the bracketed reference is found");
        assert_eq!(read.width, None);
    }

    #[test]
    fn a_store_through_the_symbol_spells_itself_three_ways() {
        // Assignment to the symbol itself.
        assert!(stores_through("  DAT_1400a1b60 = 0;", "DAT_1400a1b60"));
        assert!(stores_through("  DAT_1400a1b60 += 2;", "DAT_1400a1b60"));
        // A store through an index into it.
        assert!(stores_through(
            "  DAT_1400a1b60[uVar2] = uVar3;",
            "DAT_1400a1b60"
        ));
        assert!(stores_through("  DAT_1400a1b60[uVar2]++;", "DAT_1400a1b60"));
        // A store through it another way, wrapper and offset included.
        assert!(stores_through(
            "  *(int *)(&DAT_1400a1b60)[uVar2] = uVar3;",
            "DAT_1400a1b60"
        ));
        assert!(stores_through(
            "  *(int *)(DAT_1400a1b60 + 4) = 0;",
            "DAT_1400a1b60"
        ));
    }

    #[test]
    fn reading_and_comparing_through_the_symbol_stores_nothing() {
        // The gate takes a store spelled outright: the reference's
        // tail has to open with one, so the reads a table claim lives
        // on all stay claims.
        assert!(!stores_through(
            "  uVar3 = DAT_1400a1b60[uVar2];",
            "DAT_1400a1b60"
        ));
        assert!(!stores_through(
            "  if (DAT_1400a1b60[uVar2] == 3) { uVar1 = 4; }",
            "DAT_1400a1b60"
        ));
        assert!(!stores_through(
            "  if (DAT_1400a1b60[uVar2] < 3) { uVar1 = 4; }",
            "DAT_1400a1b60"
        ));
        assert!(!stores_through(
            "  uVar4 = (uint)(&DAT_1400a1b60)[uVar2];",
            "DAT_1400a1b60"
        ));
        // A call through the table dispatches; it stores nothing.
        assert!(!stores_through(
            "  (*(code *)(&switchD_1800412a0)[uVar2])();",
            "switchD_1800412a0"
        ));
        // The scan reads code, not prose: a store inside a string
        // literal is not a store.
        assert!(!stores_through(
            "  printf(\"DAT_1400a1b60 = 1\\n\");",
            "DAT_1400a1b60"
        ));
        // A longer label that starts with this one names another object.
        assert!(!stores_through("  DAT_1400a1b600 = 1;", "DAT_1400a1b60"));
        assert!(!stores_through(
            "  uVar1 = sDAT_1400a1b60[0];",
            "DAT_1400a1b60"
        ));
    }

    #[test]
    fn one_label_cannot_match_inside_a_longer_one() {
        let program = body("FUN_18003ab00", "  uVar3 = DAT_1400a1b600[uVar2];\n");
        assert!(
            indexed_read(
                &program,
                "DAT_1400a1b60",
                "  uVar3 = DAT_1400a1b600[uVar2];",
                24
            )
            .is_none()
        );
    }

    #[test]
    fn bounds_checks_name_their_exclusive_bound_in_either_order() {
        assert_eq!(bounds_check("if (uVar2 < 0xc) {", "uVar2"), Some(12));
        assert_eq!(bounds_check("if (uVar2 <= 11) {", "uVar2"), Some(12));
        assert_eq!(bounds_check("if (0xc > uVar2) {", "uVar2"), Some(12));
        assert_eq!(bounds_check("if (11 >= uVar2) {", "uVar2"), Some(12));
        assert_eq!(bounds_check("if (uVar2 < uVar3) {", "uVar2"), None);
        // A lower bound guards nothing above — no entry count to size.
        assert_eq!(bounds_check("if (uVar2 >= 3) {", "uVar2"), None);
        assert_eq!(bounds_check("uVar20 = 0xc;", "uVar2"), None);
    }

    #[test]
    fn a_bound_sizes_a_width_only_when_it_divides_the_object_exactly() {
        assert_eq!(bound_width(24, 12), Some(2));
        assert_eq!(bound_width(24, 7), None);
        assert_eq!(bound_width(24, 3), Some(8));
        assert_eq!(bound_width(24, 24), Some(1));
        // A one-entry "array" is a scalar, not a table.
        assert_eq!(bound_width(24, 1), None);
    }

    #[test]
    fn a_fill_or_gapped_object_is_not_coherent_at_any_stride() {
        // 0xCCCC padding: uniform-looking but a fill, not a table.
        assert!(viable_families(&[0xcc; 24]).is_empty());
        // Zero runs kill every stride the length admits at all.
        assert!(viable_families(&[1, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0]).is_empty());
        // u16 values with no gaps decode coherently at 2 (and, paired,
        // at 4 and 8 — the float misreads stay out of the sane band).
        let bytes: Vec<u8> = (1u16..=12).flat_map(u16::to_le_bytes).collect();
        assert_eq!(families_at(&bytes), ["u16", "u32", "u64"]);
        // Too few entries to be a table at any width.
        assert!(viable_families(&[7, 0]).is_empty());
    }

    #[test]
    fn a_wide_magnitude_spread_reads_as_padding_not_a_table() {
        // Nonzero and distinct, but the entry magnitudes run a billion
        // fold apart — scattered flags and masks, not one coherent run
        // of values. The float misreads join the verdict: a NaN entry
        // and subnormal-scale bit patterns are never a sane decode.
        let bytes: Vec<u8> = [1u32, 2, 0xFFFF_FFF0]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect();
        assert!(families_at(&bytes).is_empty());
    }

    #[test]
    fn sane_float_entries_form_a_family_and_insane_ones_never_do() {
        // 0.5, 1.0, 2.0: finite, ordinary-magnitude floats — the f32
        // family decodes, and the integer misread of the same bits
        // (magnitudes within the spread, none zero) decodes beside it.
        let bytes: Vec<u8> = [0.5f32, 1.0, 2.0]
            .into_iter()
            .flat_map(f32::to_le_bytes)
            .collect();
        assert_eq!(families_at(&bytes), ["u32", "f32"]);
        // A NaN entry puts the whole stride out of the coherent band.
        let with_nan: Vec<u8> = [0.5f32, f32::NAN, 2.0]
            .into_iter()
            .flat_map(f32::to_le_bytes)
            .collect();
        assert_eq!(families_at(&with_nan), ["u32"]);
        // 1 as a bit pattern is a subnormal near-zero float: the
        // misread of integer-looking bytes, not a sane decode.
        let integer_bytes: Vec<u8> = [1u32, 2, 3]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect();
        assert_eq!(families_at(&integer_bytes), ["u32"]);
    }

    #[test]
    fn the_listing_type_names_its_family_only_when_it_names_one() {
        assert_eq!(applied_family("uint", 24).unwrap().name, "u32");
        assert_eq!(applied_family("float [3]", 12).unwrap().name, "f32");
        // The array count has to square with the object's length.
        assert!(applied_family("float [4]", 12).is_none());
        // A bare object with no listing type, and everything the
        // engine spells as opaque, names no stride.
        assert!(applied_family("undefined", 24).is_none());
        assert!(applied_family("IMAGE_DOS_HEADER", 24).is_none());
        assert!(applied_family("undefined8 *", 24).is_none());
    }
}
