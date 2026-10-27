//! Rendered Rust codegen derived from the persisted constant result.
//!
//! [`render_codegen`] turns a [`ConstResult`] into one Rust source
//! string — the reconstructed constants spelled out as code a reviewer
//! reads side by side with the JSON: a `bitflags!`-style block per flag
//! family with its bits named by position, an `enum` block per enum
//! candidate with its variants named by value, `const` items for
//! the named, protocol, and color constants using each record's name,
//! and a `pub const` array per data table with its element type and
//! decoded entries.
//! The renderer is pure: data in, string out, no analysis engine
//! call and no clock reading. It is deterministic: it stamps no
//! timestamp and sorts every section, so two renders of the same
//! document are byte-identical and a rescan produces a reviewable
//! diff, not churn.
//!
//! The rendering rules (ADR-0013's derived-rendered-artifact pattern,
//! applied to constant findings):
//!
//! - **No record, no declaration.** Only findings the document carries
//!   become code: a flag family renders a `bitflags!` block (the
//!   per-function groups it merged stay evidence, not code), an enum
//!   candidate renders an `enum`, and named, protocol, and color
//!   records render `const` items. A finding kind with no block in
//!   this file — a lone per-function bitflag group that merged into no
//!   family — contributes nothing.
//! - **Names come from the records.** A named constant renders its
//!   context name when it carries one and the mechanical `VALUE_0x…`
//!   spelling when not; a protocol constant renders its table name; a
//!   color renders `COLOR_<hex>`. The renderer invents no name the
//!   findings do not already hold.
//! - **Sanitized identifiers, collision suffixes.** Function- and
//!   mask-derived declaration names become valid Rust identifiers
//!   (non-identifier characters collapse to `_`), and a name already
//!   taken gains `_2`, `_3`, … in render order — so two same-named
//!   records still get distinct, stable declarations.
//! - **Everything sorted.** Families by mask, enums by function then
//!   run start, constants by value, tables by address — so the same
//!   document always renders the same blocks in the same order.
//! - **The header always stands; declarations only where findings
//!   back them.** An empty result renders a header-only file: the
//!   header names the binary and nothing else, never the scan time.
//!
//! The output is a *derived artifact*: regenerated from the loaded
//! document beside the JSON it came from, and never read back — the
//! JSON stays the single source of truth. It is a review artifact, not
//! a compile target: the `bitflags!` blocks name the shape the family
//! suggests, not a macro call the file guarantees to resolve.

use std::collections::HashSet;

use crate::bitmask::flags_type;
use crate::types::{ConstFinding, ConstResult, DataTable, FlagFamily, int_const_type};

/// Rust keywords and reserved words a sanitized identifier must not spell
/// verbatim; a declaration named one gets a trailing `_` instead.
const RUST_KEYWORDS: &[&str] = &[
    "as", "async", "await", "box", "break", "const", "continue", "crate", "do", "dyn", "else",
    "enum", "extern", "false", "final", "fn", "for", "if", "impl", "in", "let", "loop", "macro",
    "match", "mod", "move", "mut", "override", "pub", "ref", "return", "self", "Self", "static",
    "struct", "super", "trait", "true", "try", "type", "typeof", "union", "unsafe", "use",
    "virtual", "where", "while", "yield",
];

/// Render the result's findings as one Rust source string.
///
/// Declarations appear sorted by record: families by mask, enums by
/// function then run start, constants by value, tables by address.
/// Nothing volatile (timestamps, counts) is written, so the same
/// document always renders to the same bytes. An empty result
/// renders a header-only file: the header names the binary and
/// stands on its own.
pub fn render_codegen(result: &ConstResult) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "// Constant reconstruction for {}, rendered by `calxgloss consts`.\n\
         // Derived artifact: regenerated from the constant result on\n\
         // every scan — edit the result, never this file.\n\n\
         #![allow(dead_code, unused_imports)]\n",
        result.metadata.binary
    ));

    // Collision suffixes are handed out across the whole file, in
    // render order, so two records sanitizing to the same name — a
    // context name and a color, say — still get distinct, stable
    // declarations.
    let mut taken: HashSet<String> = HashSet::new();

    render_families(result, &mut taken, &mut out);
    render_enums(result, &mut taken, &mut out);
    render_constants(result, &mut taken, &mut out);
    render_tables(result, &mut taken, &mut out);
    out
}

/// The flag-family blocks: one `bitflags!`-style block per family,
/// families sorted by mask, each bit named by its position. The block
/// is preceded by a comment naming the contributing functions — the
/// record's own list, so the code claims nothing the family does not
/// already say.
fn render_families(result: &ConstResult, taken: &mut HashSet<String>, out: &mut String) {
    let mut families: Vec<&FlagFamily> = result
        .findings
        .iter()
        .filter_map(|finding| match finding {
            ConstFinding::FlagFamily(record) => Some(record),
            _ => None,
        })
        .collect();
    families.sort_by_key(|record| record.mask);

    for record in families {
        out.push('\n');
        out.push_str(&format!("// {}\n", record.functions.join(", ")));
        let name = unique_name(
            &sanitize_identifier(&format!("Flags_{:#x}", record.mask)),
            taken,
        );
        out.push_str(&format!(
            "bitflags! {{\n    struct {name}: {} {{\n",
            flags_type(record.bit_width)
        ));
        for bit in &record.bits {
            let bit_name = unique_name(&format!("BIT_{bit}"), taken);
            out.push_str(&format!("        const {bit_name} = 1 << {bit};\n"));
        }
        out.push_str("    }\n}\n");
    }
}

/// The enum-candidate blocks: one `pub enum` per candidate, sorted by
/// function then run start, named after the function the run was read
/// in, with one variant per case value spelled by that value.
fn render_enums(result: &ConstResult, taken: &mut HashSet<String>, out: &mut String) {
    let mut candidates: Vec<(&str, &[i64])> = result
        .findings
        .iter()
        .filter_map(|finding| match finding {
            ConstFinding::EnumCandidate(record) => {
                Some((record.function.as_str(), record.values.as_slice()))
            }
            _ => None,
        })
        .collect();
    candidates.sort();

    for (function, values) in candidates {
        out.push('\n');
        let name = unique_name(&sanitize_identifier(&format!("{function}_State")), taken);
        out.push_str(&format!("#[repr(i64)]\npub enum {name} {{\n"));
        for value in values {
            out.push_str(&format!("    {} = {value},\n", value_variant(*value)));
        }
        out.push_str("}\n");
    }
}

/// The `const` items: named constants (context name when the record
/// carries one, mechanical `VALUE_0x…` when not), protocol constants
/// (named after the table entry), and the color palette
/// (`COLOR_<hex>`), each group sorted by value and rendered in that
/// group order.
fn render_constants(result: &ConstResult, taken: &mut HashSet<String>, out: &mut String) {
    let mut named: Vec<(Option<&str>, u64)> = result
        .findings
        .iter()
        .filter_map(|finding| match finding {
            ConstFinding::NamedConstant(record) => Some((record.name.as_deref(), record.value)),
            _ => None,
        })
        .collect();
    named.sort_by_key(|(_, value)| *value);

    let mut protocol: Vec<(&str, u64)> = result
        .findings
        .iter()
        .filter_map(|finding| match finding {
            ConstFinding::ProtocolConstant(record) => Some((record.name.as_str(), record.value)),
            _ => None,
        })
        .collect();
    protocol.sort_by_key(|(_, value)| *value);

    let mut colors: Vec<u64> = result
        .findings
        .iter()
        .filter_map(|finding| match finding {
            ConstFinding::ColorConstant(record) => Some(record.values.iter().copied()),
            _ => None,
        })
        .flatten()
        .collect();
    colors.sort_unstable();
    colors.dedup();

    // The constants are one section: a single blank line opens it and
    // the items stand contiguous, sorted within each group.
    let mut opened = false;
    let mut open = |out: &mut String| {
        if !opened {
            opened = true;
            out.push('\n');
        }
    };
    for (name, value) in named {
        open(out);
        let base = match name {
            Some(name) => name.to_string(),
            None => format!("VALUE_{value:#x}"),
        };
        let name = unique_name(&sanitize_identifier(&base), taken);
        out.push_str(&format!(
            "const {name}: {} = {value:#x};\n",
            int_const_type(value)
        ));
    }
    for (table_name, value) in protocol {
        open(out);
        let name = unique_name(&sanitize_identifier(table_name), taken);
        out.push_str(&format!(
            "const {name}: {} = {value:#x};\n",
            int_const_type(value)
        ));
    }
    for value in &colors {
        open(out);
        let name = unique_name(&sanitize_identifier(&format!("COLOR_{value:#x}")), taken);
        // Palette values fit in 24 bits by the reading's own gate,
        // so u32 always holds one — the same width the palette's
        // suggestion spells.
        out.push_str(&format!("const {name}: u32 = {value:#x};\n"));
    }
}

/// The data-table blocks: one `pub const` array per table finding,
/// sorted by address, named by the label's Rust form (the mechanical
/// uppercase spelling for a bare `DAT_*`/`switchD_*` label, the
/// meaningful label verbatim). The declared length is the number of
/// entries actually spelled, so the file always compiles. A truncated
/// record gets a comment above the declaration stating the full entry
/// count, rather than pretending the prefix is the whole table. Float
/// entries are the raw bit patterns the record carries, re-spelled as
/// the float literals their element type names.
fn render_tables(result: &ConstResult, taken: &mut HashSet<String>, out: &mut String) {
    let mut tables: Vec<&DataTable> = result
        .findings
        .iter()
        .filter_map(|finding| match finding {
            ConstFinding::DataTable(record) => Some(record),
            _ => None,
        })
        .collect();
    tables.sort_by_key(|record| (record.address, record.symbol.as_str()));

    for record in tables {
        out.push('\n');
        if record.values_truncated {
            out.push_str(&format!(
                "// values truncated — {} entries total, first {} shown\n",
                record.count,
                record.values.len(),
            ));
        }
        let name = unique_name(
            &sanitize_identifier(&DataTable::rust_name(&record.symbol)),
            taken,
        );
        let values: Vec<String> = record
            .values
            .iter()
            .map(|value| table_value(&record.element_type, *value))
            .collect();
        out.push_str(&format!(
            "pub const {name}: [{type}; {len}] = [\n",
            type = record.element_type,
            len = values.len(),
        ));
        for chunk in values.chunks(VALUES_PER_LINE) {
            out.push_str(&format!("    {},\n", chunk.join(", ")));
        }
        out.push_str("];\n");
    }
}

/// Table entries spelled per line before the value list wraps — wide
/// enough to read as a row, narrow enough to keep the file diffable.
const VALUES_PER_LINE: usize = 12;

/// The literal one decoded entry spells. Integers spell in hex, as
/// the rest of the file spells values. A float entry is the record's
/// raw IEEE-754 bit pattern, formatted back through its element type
/// to the shortest decimal that reads as the same float. A non-finite
/// bit pattern — one the data-table reading's decode gate refuses,
/// but a hand-edited document can carry — spells the type's `NAN`,
/// `INFINITY`, or `NEG_INFINITY` path so the emitted array stays
/// valid Rust whatever the record holds.
fn table_value(element_type: &str, value: u64) -> String {
    match element_type {
        "f32" => {
            let v = f32::from_bits(value as u32);
            if v.is_finite() {
                format!("{v}")
            } else {
                format!("f32::{}", non_finite_name(v.is_nan(), v.is_sign_negative()))
            }
        }
        "f64" => {
            let v = f64::from_bits(value);
            if v.is_finite() {
                format!("{v}")
            } else {
                format!("f64::{}", non_finite_name(v.is_nan(), v.is_sign_negative()))
            }
        }
        _ => format!("{value:#x}"),
    }
}

/// The associated-constant name a non-finite float spells: `NAN`,
/// `INFINITY`, or `NEG_INFINITY` — all valid paths in a `const`
/// expression, unlike the `NaN`/`inf` its `Display` would emit.
fn non_finite_name(is_nan: bool, is_negative: bool) -> &'static str {
    match (is_nan, is_negative) {
        (true, _) => "NAN",
        (false, false) => "INFINITY",
        (false, true) => "NEG_INFINITY",
    }
}

/// The variant spelling one case value suggests: `VALUE_3`, and a
/// negative run's value spelled `VALUE_NEG_3` — a Rust identifier
/// cannot carry the minus sign, and the name still says the value.
fn value_variant(value: i64) -> String {
    if value < 0 {
        format!("VALUE_NEG_{}", value.unsigned_abs())
    } else {
        format!("VALUE_{value}")
    }
}

/// Sanitize a record-derived name into a valid Rust identifier:
/// non-identifier characters collapse to `_` (runs collapsed), a
/// leading digit is prefixed, a Rust keyword gains a trailing `_`, and
/// a name left with nothing falls back to `anonymous`. Case is
/// preserved — context names and function names are spelled as the
/// scan spelled them.
fn sanitize_identifier(name: &str) -> String {
    let mut out = String::new();
    for c in name.chars() {
        if c.is_ascii_alphanumeric() || c == '_' {
            out.push(c);
        } else {
            out.push('_');
        }
    }
    while out.contains("__") {
        out = out.replace("__", "_");
    }
    let out = out.trim_end_matches('_').to_string();
    if out.is_empty() {
        return "anonymous".to_string();
    }
    if out.starts_with(|c: char| c.is_ascii_digit()) {
        return format!("_{out}");
    }
    if RUST_KEYWORDS.contains(&out.as_str()) {
        return format!("{out}_");
    }
    out
}

/// The first free name: two records can sanitize to the same
/// spelling, so a collision gains `_2`, `_3`, … in render order —
/// deterministic, so re-renders never churn.
fn unique_name(base: &str, taken: &mut HashSet<String>) -> String {
    if taken.insert(base.to_string()) {
        return base.to_string();
    }
    let mut nth = 2;
    loop {
        let candidate = format!("{base}_{nth}");
        if taken.insert(candidate.clone()) {
            return candidate;
        }
        nth += 1;
    }
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{
        BitflagGroup, ColorConstant, Confidence, DataTable, EnumCandidate, NamedConstant,
        ProtocolConstant, ScanMetadata,
    };

    fn result_with(binary: &str, findings: Vec<ConstFinding>) -> ConstResult {
        let mut result = ConstResult::new(ScanMetadata::new(binary));
        result.findings = findings;
        result
    }

    fn family(mask: u64, bits: &[u32], functions: &[&str]) -> ConstFinding {
        ConstFinding::FlagFamily(FlagFamily {
            bits: bits.to_vec(),
            mask,
            bit_width: bits[bits.len() - 1] + 1,
            functions: functions.iter().map(|f| f.to_string()).collect(),
            suggestion: "bitflags! struct Flags: u32 { /* bits */ }".to_string(),
            confidence: Confidence::new(80),
            evidence: "FUN_a: bits 0x100; FUN_b: bits 0x400".to_string(),
        })
    }

    fn enum_candidate(function: &str, values: &[i64]) -> ConstFinding {
        ConstFinding::EnumCandidate(EnumCandidate {
            function: function.to_string(),
            values: values.to_vec(),
            count: values.len(),
            suggestion: format!(
                "enum State {{ /* variants for {}..={} */ }}",
                values[0],
                values[values.len() - 1]
            ),
            confidence: Confidence::new(70),
            evidence: "case 0: | case 1: | case 2:".to_string(),
        })
    }

    fn named(value: u64, name: Option<&str>) -> ConstFinding {
        ConstFinding::NamedConstant(NamedConstant {
            value,
            count: 3,
            functions: vec!["FUN_a".to_string(), "FUN_b".to_string()],
            name: name.map(str::to_string),
            suggestion: NamedConstant::render_suggestion(name, value),
            confidence: Confidence::new(60),
            evidence: format!("{value:#x} used 3 times in FUN_a and FUN_b"),
        })
    }

    fn protocol(value: u64, name: &str) -> ConstFinding {
        ConstFinding::ProtocolConstant(ProtocolConstant {
            value,
            name: name.to_string(),
            protocol: "PNG image format".to_string(),
            count: 1,
            functions: vec!["FUN_a".to_string()],
            suggestion: format!("const {name}: u32 = {value:#x};"),
            confidence: Confidence::new(75),
            evidence: format!("{value:#x} used 1 times in FUN_a — matches PNG_MAGIC"),
        })
    }

    fn palette(values: &[u64]) -> ConstFinding {
        ConstFinding::ColorConstant(ColorConstant {
            values: values.to_vec(),
            functions: vec!["FUN_a".to_string(), "FUN_b".to_string()],
            suggestion: "one named const per color".to_string(),
            confidence: Confidence::new(60),
            evidence: "0x123456 used 1 times in FUN_a".to_string(),
        })
    }

    /// A table finding with the given label and entries; a `truncated`
    /// record keeps the entries shown plus 88 more that the count
    /// states but the list drops.
    fn table(
        symbol: &str,
        address: u64,
        element_type: &str,
        values: Vec<u64>,
        truncated: bool,
    ) -> ConstFinding {
        let count = if truncated {
            values.len() + 88
        } else {
            values.len()
        };
        ConstFinding::DataTable(DataTable {
            symbol: symbol.to_string(),
            address,
            element_type: element_type.to_string(),
            count,
            values,
            values_truncated: truncated,
            functions: vec!["FUN_a".to_string(), "FUN_b".to_string()],
            suggestion: DataTable::render_suggestion(symbol, element_type, count),
            confidence: Confidence::new(70),
            evidence: format!("{symbol} decoded as {count} {element_type} entries"),
        })
    }

    fn bitflag_group(function: &str, bits: &[u32], mask: u64) -> ConstFinding {
        ConstFinding::BitflagGroup(BitflagGroup {
            function: function.to_string(),
            bits: bits.to_vec(),
            mask,
            bit_width: bits[bits.len() - 1] + 1,
            suggestion: "bitflags! struct Flags: u32 { /* bits */ }".to_string(),
            confidence: Confidence::new(70),
            evidence: "if ((uVar1 & 0x400) != 0)".to_string(),
        })
    }

    #[test]
    fn a_flag_family_renders_a_bitflags_block_with_position_named_bits() {
        let rendered = render_codegen(&result_with(
            "eqmain.dll",
            vec![family(0xd00, &[8, 10, 11], &["FUN_a", "FUN_b"])],
        ));

        assert!(
            rendered.contains("// FUN_a, FUN_b\nbitflags! {\n    struct Flags_0xd00: u16 {\n"),
            "{rendered}"
        );
        assert!(
            rendered.contains("        const BIT_8 = 1 << 8;\n"),
            "{rendered}"
        );
        assert!(
            rendered.contains("        const BIT_10 = 1 << 10;\n"),
            "{rendered}"
        );
        assert!(
            rendered.contains("        const BIT_11 = 1 << 11;\n"),
            "{rendered}"
        );
        assert!(rendered.ends_with("    }\n}\n"), "{rendered}");
    }

    #[test]
    fn an_enum_candidate_renders_a_block_with_value_named_variants() {
        let rendered = render_codegen(&result_with(
            "eqmain.dll",
            vec![enum_candidate("FUN_18003ab00", &[0, 1, 2, 3])],
        ));

        assert!(
            rendered.contains("#[repr(i64)]\npub enum FUN_18003ab00_State {\n"),
            "{rendered}"
        );
        assert!(rendered.contains("    VALUE_0 = 0,\n"), "{rendered}");
        assert!(rendered.contains("    VALUE_3 = 3,\n"), "{rendered}");
    }

    #[test]
    fn a_negative_run_still_names_its_variants_by_value() {
        let rendered = render_codegen(&result_with(
            "eqmain.dll",
            vec![enum_candidate("FUN_a", &[-1, 0, 1])],
        ));

        assert!(rendered.contains("    VALUE_NEG_1 = -1,\n"), "{rendered}");
        assert!(rendered.contains("    VALUE_0 = 0,\n"), "{rendered}");
        assert!(rendered.contains("    VALUE_1 = 1,\n"), "{rendered}");
    }

    #[test]
    fn named_protocol_and_color_records_render_consts_using_their_names() {
        let rendered = render_codegen(&result_with(
            "eqmain.dll",
            vec![
                named(0x280, Some("SIZE_0x280")),
                named(0x400, None),
                protocol(0x89504e47, "PNG_MAGIC"),
                palette(&[0x123456, 0xff00ff]),
            ],
        ));

        assert!(
            rendered.contains("const SIZE_0x280: u32 = 0x280;\n"),
            "{rendered}"
        );
        assert!(
            rendered.contains("const VALUE_0x400: u32 = 0x400;\n"),
            "{rendered}"
        );
        assert!(
            rendered.contains("const PNG_MAGIC: u32 = 0x89504e47;\n"),
            "{rendered}"
        );
        assert!(
            rendered.contains("const COLOR_0x123456: u32 = 0x123456;\n"),
            "{rendered}"
        );
        assert!(
            rendered.contains("const COLOR_0xff00ff: u32 = 0xff00ff;\n"),
            "{rendered}"
        );
    }

    #[test]
    fn a_wide_named_constant_renders_at_u64_width() {
        let rendered = render_codegen(&result_with("eqmain.dll", vec![named(0x1_0000_0000, None)]));

        assert!(
            rendered.contains("const VALUE_0x100000000: u64 = 0x100000000;\n"),
            "{rendered}"
        );
    }

    #[test]
    fn a_data_table_renders_a_pub_const_array_with_its_type_count_and_values() {
        let values = (1u64..=12).collect();
        let rendered = render_codegen(&result_with(
            "eqmain.dll",
            vec![table("DAT_1400a1b60", 0x1400_a1b60, "u16", values, false)],
        ));

        assert!(
            rendered.contains("pub const DAT_1400A1B60: [u16; 12] = [\n"),
            "{rendered}"
        );
        assert!(
            rendered.contains("    0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc,\n"),
            "{rendered}"
        );
        assert!(rendered.ends_with("];\n"), "{rendered}");
    }

    #[test]
    fn a_meaningful_label_names_its_table_verbatim() {
        let rendered = render_codegen(&result_with(
            "eqmain.dll",
            vec![table(
                "gDamageCurve",
                0x1400_a1b60,
                "u32",
                vec![10, 20, 30],
                false,
            )],
        ));

        assert!(
            rendered.contains("pub const gDamageCurve: [u32; 3] = [\n    0xa, 0x14, 0x1e,\n];\n"),
            "{rendered}"
        );
    }

    #[test]
    fn a_float_table_renders_its_bit_patterns_as_float_literals() {
        let f32s = |vs: &[f32]| vs.iter().map(|v| v.to_bits() as u64).collect();
        let rendered = render_codegen(&result_with(
            "eqmain.dll",
            vec![
                table(
                    "DAT_1400a1b60",
                    0x1400_a1b60,
                    "f32",
                    f32s(&[1.5, -2.25]),
                    false,
                ),
                table(
                    "gScaleFactors",
                    0x1400_a1c00,
                    "f64",
                    vec![0.25f64.to_bits()],
                    false,
                ),
            ],
        ));

        assert!(
            rendered.contains("pub const DAT_1400A1B60: [f32; 2] = [\n    1.5, -2.25,\n];\n"),
            "{rendered}"
        );
        assert!(
            rendered.contains("pub const gScaleFactors: [f64; 1] = [\n    0.25,\n];\n"),
            "{rendered}"
        );
    }

    #[test]
    fn a_non_finite_bit_pattern_still_renders_a_compiling_literal() {
        // The record is data a hand-edited document can carry anything
        // in: the data-table reading's decode gate refuses non-finite
        // floats, but a stray bit pattern still has to spell valid
        // Rust.
        let rendered = render_codegen(&result_with(
            "eqmain.dll",
            vec![table(
                "DAT_1400a1b60",
                0x1400_a1b60,
                "f32",
                vec![0x7f80_0000, 0xff80_0000, 0x7fc0_0000],
                false,
            )],
        ));

        assert!(
            rendered.contains(
                "pub const DAT_1400A1B60: [f32; 3] = [\n    f32::INFINITY, f32::NEG_INFINITY, f32::NAN,\n];\n"
            ),
            "{rendered}"
        );
    }

    #[test]
    fn a_table_colliding_with_an_earlier_declaration_gains_a_suffix() {
        // The collision machinery is file-wide: a named constant
        // already holds the name the bare label's mechanical form
        // spells, so the table gains the next suffix.
        let rendered = render_codegen(&result_with(
            "eqmain.dll",
            vec![
                named(0x5, Some("DAT_1400A1B60")),
                table("DAT_1400a1b60", 0x1400_a1b60, "u16", vec![1, 2], false),
            ],
        ));

        assert!(
            rendered.contains("const DAT_1400A1B60: u32 = 0x5;\n"),
            "{rendered}"
        );
        assert!(
            rendered.contains("pub const DAT_1400A1B60_2: [u16; 2] = [\n"),
            "{rendered}"
        );
    }

    #[test]
    fn a_truncated_value_list_renders_a_truncation_comment_stating_the_full_count() {
        let values = (0..512).collect();
        let rendered = render_codegen(&result_with(
            "eqmain.dll",
            vec![table("DAT_1400a1b60", 0x1400_a1b60, "u16", values, true)],
        ));

        assert!(
            rendered.contains("// values truncated — 600 entries total, first 512 shown\n"),
            "{rendered}"
        );
        assert!(
            rendered.contains("pub const DAT_1400A1B60: [u16; 512] = [\n"),
            "the declared length matches the values actually spelled: {rendered}"
        );
    }

    #[test]
    fn tables_render_sorted_by_address() {
        let rendered = render_codegen(&result_with(
            "eqmain.dll",
            vec![
                table("DAT_1400a1b60", 0x1400_a1b60, "u16", vec![1, 2], false),
                table("DAT_1400a1000", 0x1400_a1000, "u16", vec![3, 4], false),
            ],
        ));

        let low = rendered.find("DAT_1400A1000").unwrap_or(usize::MAX);
        let high = rendered.find("DAT_1400A1B60").unwrap_or(usize::MAX);
        assert!(
            low < high,
            "tables render at ascending addresses: {rendered}"
        );
    }

    #[test]
    fn identifiers_are_sanitized_and_collisions_gain_suffixes_in_render_order() {
        let rendered = render_codegen(&result_with(
            "eqmain.dll",
            vec![
                enum_candidate("weird/name!", &[0, 1, 2]),
                enum_candidate("weird/name!", &[3, 4, 5]),
                // A context name spelled exactly like the name a
                // palette color would get: the collision gains a suffix.
                named(0x280, Some("COLOR_0x280")),
                palette(&[0x280]),
            ],
        ));

        assert!(
            rendered.contains("pub enum weird_name_State {"),
            "{rendered}"
        );
        assert!(
            rendered.contains("pub enum weird_name_State_2 {"),
            "{rendered}"
        );
        assert!(
            rendered.contains("const COLOR_0x280: u32 = 0x280;\n"),
            "{rendered}"
        );
        assert!(
            rendered.contains("const COLOR_0x280_2: u32 = 0x280;\n"),
            "{rendered}"
        );
    }

    #[test]
    fn every_section_is_sorted_by_its_record() {
        let rendered = render_codegen(&result_with(
            "eqmain.dll",
            vec![
                family(0xd00, &[8, 10, 11], &["FUN_a", "FUN_b"]),
                family(0x3, &[0, 1], &["FUN_c"]),
                enum_candidate("FUN_b", &[0, 1, 2]),
                enum_candidate("FUN_a", &[4, 5, 6]),
                named(0x400, None),
                named(0x280, None),
                palette(&[0xff00ff, 0x123456]),
            ],
        ));

        let order: Vec<usize> = [
            rendered.find("struct Flags_0x3").unwrap_or(usize::MAX),
            rendered.find("struct Flags_0xd00").unwrap_or(usize::MAX),
            rendered.find("pub enum FUN_a_State").unwrap_or(usize::MAX),
            rendered.find("pub enum FUN_b_State").unwrap_or(usize::MAX),
            rendered.find("const VALUE_0x280").unwrap_or(usize::MAX),
            rendered.find("const VALUE_0x400").unwrap_or(usize::MAX),
            rendered.find("const COLOR_0x123456").unwrap_or(usize::MAX),
            rendered.find("const COLOR_0xff00ff").unwrap_or(usize::MAX),
        ]
        .into_iter()
        .collect();
        let mut sorted = order.clone();
        sorted.sort_unstable();
        assert_eq!(
            order, sorted,
            "sections render in sorted order:\n{rendered}"
        );
    }

    #[test]
    fn two_renders_of_the_same_result_are_byte_identical() {
        let result = result_with(
            "eqmain.dll",
            vec![
                family(0xd00, &[8, 10, 11], &["FUN_a", "FUN_b"]),
                enum_candidate("FUN_a", &[0, 1, 2]),
                named(0x280, Some("SIZE_0x280")),
                protocol(0xdeadbeef, "DEAD_BEEF_MARKER"),
                palette(&[0x123456, 0xff00ff]),
                table(
                    "DAT_1400a1b60",
                    0x1400_a1b60,
                    "u16",
                    (1..=12).collect(),
                    false,
                ),
            ],
        );
        assert_eq!(render_codegen(&result), render_codegen(&result));
    }

    #[test]
    fn the_header_names_only_the_binary_never_the_scan_time() {
        let mut result = result_with("eqmain.dll", Vec::new());
        result.metadata.scanned_at = 1_730_000_000;

        let rendered = render_codegen(&result);
        assert!(
            rendered.starts_with(
                "// Constant reconstruction for eqmain.dll, rendered by `calxgloss consts`.\n"
            ),
            "{rendered}"
        );
        assert!(
            !rendered.contains("1730000000"),
            "the header stamps no scan time: {rendered}"
        );
    }

    #[test]
    fn an_empty_result_renders_a_header_only_file() {
        let rendered = render_codegen(&result_with("eqmain.dll", Vec::new()));
        assert_eq!(
            rendered,
            "// Constant reconstruction for eqmain.dll, rendered by `calxgloss consts`.\n\
             // Derived artifact: regenerated from the constant result on\n\
             // every scan — edit the result, never this file.\n\n\
             #![allow(dead_code, unused_imports)]\n"
        );
    }

    #[test]
    fn a_lone_bitflag_group_with_no_family_renders_no_declaration() {
        // The per-function group is a finding, but the file spells the
        // program-level reconstruction: a group that merged into no
        // family has no family record, so it contributes no block.
        let rendered = render_codegen(&result_with(
            "eqmain.dll",
            vec![bitflag_group("FUN_a", &[8, 10], 0x500)],
        ));
        assert!(
            !rendered.contains("bitflags!"),
            "no family record, no block: {rendered}"
        );
        assert_eq!(rendered.lines().count(), 5, "header only: {rendered}");
    }

    #[test]
    fn a_small_result_renders_the_whole_file_verbatim() {
        let rendered = render_codegen(&result_with(
            "eqmain.dll",
            vec![
                family(0x500, &[8, 10], &["FUN_a", "FUN_b"]),
                enum_candidate("FUN_c", &[0, 1, 2]),
                named(0x280, Some("SIZE_0x280")),
                protocol(0x89504e47, "PNG_MAGIC"),
                palette(&[0x123456]),
                table("DAT_1400a1b60", 0x1400_a1b60, "u16", vec![1, 2, 3], false),
            ],
        ));
        let expected = "\
// Constant reconstruction for eqmain.dll, rendered by `calxgloss consts`.
// Derived artifact: regenerated from the constant result on
// every scan — edit the result, never this file.

#![allow(dead_code, unused_imports)]

// FUN_a, FUN_b
bitflags! {
    struct Flags_0x500: u16 {
        const BIT_8 = 1 << 8;
        const BIT_10 = 1 << 10;
    }
}

#[repr(i64)]
pub enum FUN_c_State {
    VALUE_0 = 0,
    VALUE_1 = 1,
    VALUE_2 = 2,
}

const SIZE_0x280: u32 = 0x280;
const PNG_MAGIC: u32 = 0x89504e47;
const COLOR_0x123456: u32 = 0x123456;

pub const DAT_1400A1B60: [u16; 3] = [
    0x1, 0x2, 0x3,
];
";
        assert_eq!(rendered, expected);
    }
}
