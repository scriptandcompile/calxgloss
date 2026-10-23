//! Data-table detection.
//!
//! A read-only data table — game stats, an opcode table, a damage
//! curve — survives decompilation as scattered `DAT_x[idx]` reads and
//! an untyped blob in the engine's data listing. This module reads
//! that shape back: for each object the listing defines
//! (`data_items`), the kept bodies' indexed reads corroborate it
//! (`DAT_x[idx]` under a bounds guard `if (idx < N)`, the same shape
//! callback's jump-table reading sizes its tables from), the bytes
//! the engine exposes (`read_memory`) decode cleanly, and the engine's
//! cross-references (`xrefs_to`) name the referencing functions. All
//! three reads are existing `ScanSource` seam methods, cached under
//! ADR-0043; nothing is written back to the program (ADR-0020).
//!
//! The reading claims the corroborated happy path only — the tracer
//! bullet. An object lands a [`DataTable`] record when a kept body
//! indexes it, its bytes decode uniformly at a single stride —
//! every entry nonzero, entries not all equal (a fill is a fill, not
//! a table) — and, when more than one stride decodes uniformly, a
//! bounds guard in an indexing body names the entry count that picks
//! exactly one. The disqualification gates (a body storing through
//! the symbol, pointer-wide entries) and the general stride
//! viability and multi-stride resolution land in sibling tickets —
//! so a guard and a byte decode that disagree, or two guards naming
//! different widths, or a uniform decode at two widths with no guard
//! to pick one, all claim nothing. The claim stays inside what bytes
//! and reads agree on.
//!
//! The engine calls [`data_tables`] once per scan with the data
//! listing and, parallel to it, the indexed reads it collected from
//! the bodies the walk kept; the reading lands one record per
//! qualifying object, in listing order.

use std::collections::BTreeSet;

use calxgloss_decomp::{DataItem, DecompiledFunction, ScanSource};
use tracing::warn;

use crate::types::{Confidence, DataTable, MAX_INLINE_TABLE_VALUES};

/// Confidence of a table the bytes decode uniformly and an indexed
/// read corroborates — the spec's high-mid band, beside the
/// corroborated jump-table reading's 70. The engine-applied-type tier
/// above it lands with the stride-viability ticket.
const DATA_TABLE_CONFIDENCE: u8 = 70;

/// The byte widths a table entry can occupy, as widths and as the
/// Rust element type each spells.
const ELEMENT_WIDTHS: [(u64, &str); 4] = [(1, "u8"), (2, "u16"), (4, "u32"), (8, "u64")];

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
/// guard. The read is found textually — a write (`label[i] = v`) is
/// the same text, and the mutation gate belongs to the
/// disqualification ticket, so this reads the shape, not the
/// direction.
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

/// The element widths the object's bytes decode uniformly at: the
/// width divides the length into at least two little-endian entries,
/// every entry is nonzero (a zero entry is a gap or terminator, not a
/// uniform array), and the entries are not all equal (a fill claims
/// no table).
///
/// This is the tracer bullet's viability bar — the general
/// viability rules and multi-stride resolution are the stride
/// ticket's; here, anything but a single width passing this bar
/// claims nothing.
fn viable_widths(bytes: &[u8]) -> Vec<u64> {
    ELEMENT_WIDTHS
        .iter()
        .map(|(width, _)| *width)
        .filter(|&width| {
            let length = bytes.len() as u64;
            if !length.is_multiple_of(width) || length / width < 2 {
                return false;
            }
            let entries: Vec<u64> = bytes.chunks(width as usize).map(le_u64).collect();
            entries.iter().all(|entry| *entry != 0)
                && entries.iter().any(|entry| *entry != entries[0])
        })
        .collect()
}

/// One little-endian chunk as an integer.
fn le_u64(bytes: &[u8]) -> u64 {
    let mut value = 0u64;
    for (i, byte) in bytes.iter().enumerate() {
        value |= (*byte as u64) << (i * 8);
    }
    value
}

/// The table reading for one data object: a kept body must index it,
/// its bytes must be readable in full and decode uniformly, and a
/// single stride must survive — the only uniform width, or a width a
/// bounds guard in an indexing body picks out of several. `None` with
/// a warning for anything else.
async fn read_object<S: ScanSource>(
    source: &S,
    item: &DataItem,
    reads: &[IndexedRead],
) -> Option<DataTable> {
    if reads.is_empty() {
        // The tracer claims only the corroborated path: an object no
        // kept body indexes is a raw-bytes-only claim, a lower tier
        // the unreferenced-families ticket will land.
        return None;
    }
    if item.label.is_empty() || item.length < 2 {
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

    // The strides the bytes decode cleanly at, narrowed by the widths
    // the guards imply (guards naming no width do not narrow). A
    // guard that contradicts the bytes empties the intersection.
    let viable = viable_widths(&bytes);
    let implied: BTreeSet<u64> = reads.iter().filter_map(|read| read.width).collect();
    let narrowed: Vec<u64> = if implied.is_empty() {
        viable
    } else {
        viable
            .into_iter()
            .filter(|width| implied.contains(width))
            .collect()
    };
    let Ok([width]) = <[u64; 1]>::try_from(narrowed) else {
        // Zero widths surviving is a contradiction; more than one is
        // an unresolved multi-stride decode — both claim nothing.
        return None;
    };
    let element_type = ELEMENT_WIDTHS
        .iter()
        .find(|(w, _)| *w == width)
        .map(|(_, name)| *name)?;

    let entries: Vec<u64> = bytes.chunks(width as usize).map(le_u64).collect();
    let count = entries.len();
    let values_truncated = count > MAX_INLINE_TABLE_VALUES;
    let mut values = entries;
    values.truncate(MAX_INLINE_TABLE_VALUES);

    // The referencing functions come from the engine's
    // cross-references — ascending, deduped. A failed xref read is
    // logged and left empty: the claim rests on the bytes and the
    // body read; the functions only widen the per-function view.
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

    Some(DataTable {
        symbol: item.label.clone(),
        address: item.address,
        element_type: element_type.to_string(),
        count,
        values,
        values_truncated,
        functions,
        suggestion: DataTable::render_suggestion(&item.label, element_type, count),
        confidence: Confidence::new(DATA_TABLE_CONFIDENCE),
        evidence: reads
            .iter()
            .map(|read| format!("{}: {}", read.function, read.line))
            .collect::<Vec<String>>()
            .join("; "),
    })
}

/// The program's data tables: every object the engine's data listing
/// defines that a kept body indexes and whose bytes decode uniformly
/// at exactly one corroborated stride, in listing order. `table_reads`
/// is parallel to `items` — the indexed reads the walk collected from
/// the bodies it kept, per object. A failed listing fails the run
/// like the function listing's failure (the engine reads it before
/// calling this); a failing per-object read skips that object with a
/// warning.
pub(crate) async fn data_tables<S: ScanSource>(
    source: &S,
    items: &[DataItem],
    table_reads: &[Vec<IndexedRead>],
) -> Vec<DataTable> {
    let mut tables = Vec::new();
    for (item, reads) in items.iter().zip(table_reads) {
        if let Some(record) = read_object(source, item, reads).await {
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
            "  if (uVar2 < 0xc) {\n    DAT_1400a1b60[uVar2 * 2] = uVar3;\n  }\n",
        );
        let read = indexed_read(
            &program,
            "DAT_1400a1b60",
            "    DAT_1400a1b60[uVar2 * 2] = uVar3;",
            24,
        )
        .expect("the bracketed reference is found");
        assert_eq!(read.width, None);
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
    fn a_fill_or_gapped_object_is_not_uniform_at_any_width() {
        // 0xCCCC padding: uniform-looking but a fill, not a table.
        assert!(viable_widths(&[0xcc; 24]).is_empty());
        // Zero runs kill every stride the length admits at all.
        assert!(viable_widths(&[1, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0]).is_empty());
        // u16 values with no gaps decode cleanly at 2 (and, paired, at 4 and 8).
        let bytes: Vec<u8> = (1u16..=12).flat_map(u16::to_le_bytes).collect();
        assert_eq!(viable_widths(&bytes), vec![2, 4, 8]);
        // Too few entries to be a table at any width.
        assert!(viable_widths(&[7, 0]).is_empty());
    }
}
