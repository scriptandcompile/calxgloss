//! Cross-field validation (message integrity) detection.
//!
//! This module provides [`ValidationDetector`], which reads each
//! decompiled body for the comparisons that define message
//! validation: a stored field checked against a value computed from
//! other fields — `if (checksum == computed_sum)`, the checksum
//! shape — and a read length checked against a buffer size or
//! remaining count, the framing shape that keeps a parser inside its
//! buffer. Each qualifying check lands as its own
//! [`CrossFieldValidation`] record naming the compared field, the
//! computed-side expression, and the [`ValidationShape`] it was read
//! from, with the comparison line as evidence.
//!
//! The silence gates keep the claim honest: constant-vs-constant
//! comparisons, variable-vs-literal comparisons (that is magic and
//! constant territory, read by the other detectors), and comparisons
//! the magic detector already reported claim nothing here — the
//! engine hands the scan's [`MagicFormat`] records to
//! [`detect`](ValidationDetector::detect) so a signature check never
//! double-lands as validation.

use std::collections::HashSet;

use crate::scan;
use crate::types::{CrossFieldValidation, MagicFormat, ValidationShape};
use calxgloss_ghidra::DecompiledFunction;

// ============================================================
// Detector
// ============================================================

/// Cross-field validation detection over decompiled functions.
///
/// The detector holds no configuration — the reading is a fixed shape
/// rule over comparison lines — and no Ghidra client of its own; one
/// detector serves an entire scan and can be shared by reference
/// across concurrent per-function passes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ValidationDetector {}

impl ValidationDetector {
    /// A detector reading the standard validation shapes.
    pub fn new() -> Self {
        Self::default()
    }

    /// The message-integrity comparisons one function's body carries.
    ///
    /// The reading walks the body line by line and reports every
    /// `==`/`!=` comparison whose sides fit a validation shape as one
    /// [`CrossFieldValidation`]: a plain field against an arithmetic
    /// expression over variables (the checksum shape), or a length
    /// against a size or remaining count (the framing shape — read
    /// from a subtraction on the computed side, e.g. Ghidra's
    /// `size + -N` spelling of `size - N`, or from a length-, size-,
    /// or count-flavoured name on either side). A comparison against
    /// a bare literal, a constant-vs-constant comparison, and a plain
    /// variable pair with nothing naming a length claim nothing;
    /// neither side being a plain field claims nothing either — the
    /// check must validate a *stored* field. Lines the magic detector
    /// already reported — matched by their evidence text, so a custom
    /// signature table gates exactly what the scan actually reported
    /// — are skipped, so a signature check lands exactly once.
    /// Findings come back in body order, so two scans of one body
    /// diff cleanly.
    pub fn detect(
        &self,
        func: &DecompiledFunction,
        magic_findings: &[MagicFormat],
    ) -> Vec<CrossFieldValidation> {
        let magic_lines: HashSet<&str> = magic_findings
            .iter()
            .map(|finding| finding.evidence.as_str())
            .collect();

        let mut records = Vec::new();

        for raw in func.body.lines() {
            let line = raw.trim();
            // Integrity checking is a comparison; the same shapes
            // anywhere else are just arithmetic.
            if line.is_empty() || !(line.contains("==") || line.contains("!=")) {
                continue;
            }
            // A comparison the magic detector already named is that
            // check's one landing — validation claims nothing on it.
            if magic_lines.contains(line) {
                continue;
            }

            let chars: Vec<char> = line.chars().collect();
            let quoted = quoted_mask(&chars);
            for (left, right) in comparisons(&chars, &quoted) {
                let (field, computed) = match (classify(&left), classify(&right)) {
                    (Side::Plain, Side::Computed) => (left.clone(), right.clone()),
                    (Side::Computed, Side::Plain) => (right.clone(), left.clone()),
                    // Framing by name alone: a length compared against
                    // a size or remaining count, both plain — the
                    // names are what make the pair a framing check.
                    (Side::Plain, Side::Plain)
                        if names_a_length(&left) || names_a_length(&right) =>
                    {
                        (left.clone(), right.clone())
                    }
                    _ => continue,
                };
                let shape = if names_a_length(&field)
                    || names_a_length(&computed)
                    || has_subtraction(&computed)
                {
                    ValidationShape::Length
                } else {
                    ValidationShape::Checksum
                };
                records.push(CrossFieldValidation {
                    function: func.name.clone(),
                    field,
                    computed,
                    shape,
                    suggestion: VALIDATION_SUGGESTION.to_string(),
                    confidence: VALIDATION_CONFIDENCE.into(),
                    evidence: line.to_string(),
                });
            }
        }

        records
    }
}

// ============================================================
// The reading
// ============================================================

/// Confidence of a validation reading from the comparison shape: the
/// check is explicit body evidence, but which side is the stored
/// field and which the computed one is a reading of the shape, not a
/// name that carries the intent outright — so the claim sits above
/// the shape-read bit packs and below the swap calls.
const VALIDATION_CONFIDENCE: u8 = 65;

/// The Rust pattern a validation check reads as: the integrity logic
/// modelled on the type, so translation keeps the check instead of
/// dropping the comparison.
const VALIDATION_SUGGESTION: &str = "checked parse or validate step on the Rust type";

/// Identifier words that name a type or a literal, never a variable:
/// the decompiler's cast and keyword spellings, filtered out wherever
/// a reading asks whether a side actually mentions a field.
const NON_VARIABLE_WORDS: &[&str] = &[
    "uint",
    "int",
    "uchar",
    "ushort",
    "ulong",
    "long",
    "short",
    "char",
    "byte",
    "bool",
    "void",
    "float",
    "double",
    "size_t",
    "dword",
    "qword",
    "word",
    "undefined",
    "true",
    "false",
    "NULL",
];

/// Name fragments that say a variable holds a length, a size, or a
/// remaining count: the framing shape's only textual signal when both
/// compared sides are plain. A marker must open an underscore-
/// separated segment of the name — `read_len`, `bytes_remaining` —
/// so a name that merely ends inside a marker (`discount`) says
/// nothing. Ghidra's minted names (`uVar1`, `local_18`, `param_2`)
/// carry none of them, so a default-named pair claims nothing.
const LENGTH_NAME_MARKERS: &[&str] = &[
    "len", "size", "count", "remain", "avail", "bytes", "capacity", "left",
];

/// One side of a comparison, classified by what it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Side {
    /// A bare integer literal.
    Literal,
    /// A plain field: an identifier (through casts, derefs, and
    /// indexing), with no arithmetic of its own.
    Plain,
    /// An arithmetic expression over variables.
    Computed,
    /// Anything else — claims nothing.
    Other,
}

/// Which characters of a line sit inside a string literal, so the
/// reading stays blind to comparisons spelled inside text.
fn quoted_mask(chars: &[char]) -> Vec<bool> {
    let mut mask = vec![false; chars.len()];
    let mut i = 0;
    let mut in_string = false;
    while i < chars.len() {
        if in_string {
            mask[i] = true;
            if chars[i] == '\\' {
                if i + 1 < chars.len() {
                    mask[i + 1] = true;
                }
                i += 2;
                continue;
            }
            if chars[i] == '"' {
                in_string = false;
            }
        } else if chars[i] == '"' {
            in_string = true;
            mask[i] = true;
        }
        i += 1;
    }
    mask
}

/// The `(left, right)` operand pairs of every `==`/`!=` comparison on
/// the line, quote-blind. Operands are read outward from the operator
/// through balanced parens (so a cast like `*(ushort *)pvVar2` stays
/// one side) and stop at statement and logical-operator boundaries, so
/// `if (a == b && c == d)` yields both comparisons.
fn comparisons(chars: &[char], quoted: &[bool]) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut i = 0;
    while i + 1 < chars.len() {
        if quoted[i] {
            i += 1;
            continue;
        }
        let is_eq = chars[i] == '=' && chars[i + 1] == '=';
        let is_ne = chars[i] == '!' && chars[i + 1] == '=';
        if !(is_eq || is_ne) {
            i += 1;
            continue;
        }
        let left = take_left(chars, quoted, i);
        let (right, stop) = take_right(chars, quoted, i + 2);
        let left = left
            .trim()
            .trim_matches(|c: char| c == '&' || c == '|' || c == '!');
        let right = right
            .trim()
            .trim_matches(|c: char| c == '&' || c == '|' || c == '!');
        if !left.is_empty() && !right.is_empty() {
            out.push((left.to_string(), right.to_string()));
        }
        i = stop.max(i + 2);
    }
    out
}

/// The left operand of the comparison whose operator starts at
/// `op_start`: walk left through balanced parens, stopping at an
/// unbalanced `(`, a statement boundary, an `=`, or a `&&`/`||`.
fn take_left(chars: &[char], quoted: &[bool], op_start: usize) -> String {
    let mut depth = 0usize;
    let mut j = op_start;
    while j > 0 {
        let c = chars[j - 1];
        if quoted[j - 1] {
            j -= 1;
            continue;
        }
        match c {
            '(' => {
                if depth == 0 {
                    break;
                }
                depth -= 1;
            }
            ')' => depth += 1,
            ';' | ',' | '{' | '}' | '=' => break,
            '&' if chars.get(j - 2) == Some(&'&') => break,
            '|' if chars.get(j - 2) == Some(&'|') => break,
            _ => {}
        }
        j -= 1;
    }
    chars[j..op_start].iter().collect()
}

/// The right operand of the comparison whose operator ends at
/// `op_end`, and the index where the walk stopped: walk right through
/// balanced parens, stopping at an unbalanced `)`, a statement
/// boundary, an `=`, or a `&&`/`||`.
fn take_right(chars: &[char], quoted: &[bool], op_end: usize) -> (String, usize) {
    let mut depth = 0usize;
    let mut j = op_end;
    while j < chars.len() {
        let c = chars[j];
        if quoted[j] {
            j += 1;
            continue;
        }
        match c {
            '(' => depth += 1,
            ')' => {
                if depth == 0 {
                    break;
                }
                depth -= 1;
            }
            ';' | ',' | '{' | '}' | '=' => break,
            '&' if chars.get(j + 1) == Some(&'&') => break,
            '|' if chars.get(j + 1) == Some(&'|') => break,
            _ => {}
        }
        j += 1;
    }
    (chars[op_end..j].iter().collect(), j)
}

/// Classify one comparison side: a bare literal, a plain field, an
/// arithmetic expression over variables, or something that claims
/// nothing.
fn classify(side: &str) -> Side {
    let side = side.trim();
    if side.is_empty() {
        return Side::Other;
    }
    if scan::parse_uint(side).is_some() {
        return Side::Literal;
    }
    let stripped = strip_casts(side);
    let arithmetic = has_binary_operator(&stripped);
    let mentions_a_variable = identifiers(&stripped)
        .iter()
        .any(|id| !is_non_variable_word(id));
    if !mentions_a_variable {
        return Side::Other;
    }
    if arithmetic {
        Side::Computed
    } else {
        Side::Plain
    }
}

/// The identifier runs in a side, in order.
fn identifiers(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    for c in s.chars() {
        if c.is_alphanumeric() || c == '_' {
            current.push(c);
        } else {
            if !current.is_empty() {
                out.push(std::mem::take(&mut current));
            }
        }
    }
    if !current.is_empty() {
        out.push(current);
    }
    out
}

/// Whether a word is one of the decompiler's type and literal
/// spellings rather than a variable name. `undefined8` and its kin
/// count as the `undefined` family.
fn is_non_variable_word(word: &str) -> bool {
    NON_VARIABLE_WORDS.contains(&word) || word.starts_with("undefined")
}

/// Drop `(type)` and `(type *)` cast spellings, so a cast names no
/// arithmetic and its type word names no variable.
fn strip_casts(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    let mut out = String::new();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '(' {
            let mut depth = 1usize;
            let mut j = i + 1;
            while j < chars.len() && depth > 0 {
                if chars[j] == '(' {
                    depth += 1;
                } else if chars[j] == ')' {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                }
                j += 1;
            }
            if j < chars.len() {
                let inner: String = chars[i + 1..j].iter().collect();
                let inner = inner.trim().trim_end_matches('*').trim();
                if !inner.is_empty() && identifiers(inner).iter().all(|w| is_non_variable_word(w)) {
                    i = j + 1;
                    continue;
                }
            }
        }
        out.push(chars[i]);
        i += 1;
    }
    out
}

/// Whether a side carries arithmetic of its own: an operator with an
/// operand in front of it, so a leading deref or unary minus stays
/// part of a plain field's spelling and `->` names no subtraction.
fn has_binary_operator(s: &str) -> bool {
    let chars: Vec<char> = s.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        let two_char_shift = (c == '<' && chars.get(i + 1) == Some(&'<'))
            || (c == '>' && chars.get(i + 1) == Some(&'>'));
        if matches!(c, '+' | '-' | '*' | '/' | '%' | '^' | '|' | '&') || two_char_shift {
            if c == '-' && chars.get(i + 1) == Some(&'>') {
                i += 2;
                continue;
            }
            if (c == '&' && chars.get(i + 1) == Some(&'&'))
                || (c == '|' && chars.get(i + 1) == Some(&'|'))
            {
                i += 2;
                continue;
            }
            let prev = (0..i).rev().find(|&k| !chars[k].is_whitespace());
            let operand_in_front = prev
                .map(|k| {
                    chars[k].is_alphanumeric()
                        || chars[k] == '_'
                        || chars[k] == ')'
                        || chars[k] == ']'
                })
                .unwrap_or(false);
            if operand_in_front {
                return true;
            }
            if two_char_shift {
                i += 2;
                continue;
            }
        }
        i += 1;
    }
    false
}

/// Whether a side spells a subtraction — the remaining-count signal
/// that reads as framing (`size - 4`, and Ghidra's `size + -4`). A
/// `-` that is really the `->` of a member access subtracts nothing,
/// so a checksum read through struct fields stays a checksum.
fn has_subtraction(s: &str) -> bool {
    let chars: Vec<char> = s.chars().collect();
    (0..chars.len()).any(|i| chars[i] == '-' && chars.get(i + 1) != Some(&'>'))
}

/// Whether any identifier in a side is spelled like a length, size,
/// or remaining count — the framing shape's name signal. The marker
/// must open an underscore-separated segment of the name, so
/// `read_len` and `bytes_remaining` say framing while `discount`
/// (which merely ends in "count") says nothing.
fn names_a_length(s: &str) -> bool {
    identifiers(s).iter().any(|id| {
        let lowered = id.to_lowercase();
        lowered.split('_').any(|segment| {
            LENGTH_NAME_MARKERS
                .iter()
                .any(|marker| segment.starts_with(marker))
        })
    })
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn function(body: &str) -> DecompiledFunction {
        DecompiledFunction {
            name: "FUN_18003ab00".into(),
            signature: "undefined FUN_18003ab00(void)".into(),
            body: format!("undefined FUN_18003ab00(void)\n\n{{\n{body}\n}}\n"),
        }
    }

    fn detect(body: &str) -> Vec<CrossFieldValidation> {
        ValidationDetector::new().detect(&function(body), &[])
    }

    fn magic(evidence: &str) -> Vec<MagicFormat> {
        vec![MagicFormat {
            function: "FUN_18003ab00".into(),
            magic: 0x8950_4E47,
            format: "PNG".into(),
            suggestion: "png::Decoder".into(),
            confidence: 80.into(),
            evidence: evidence.into(),
        }]
    }

    #[test]
    fn a_checksum_comparison_lands_a_checksum_validation() {
        let records = detect("  if (uVar7 == uVar5 + uVar6) {");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].shape, ValidationShape::Checksum);
        assert_eq!(records[0].field, "uVar7");
        assert_eq!(records[0].computed, "uVar5 + uVar6");
        assert_eq!(
            records[0].suggestion,
            "checked parse or validate step on the Rust type"
        );
        assert_eq!(records[0].confidence, VALIDATION_CONFIDENCE);
        // The evidence carries the comparison line itself.
        assert_eq!(records[0].evidence, "if (uVar7 == uVar5 + uVar6) {");
    }

    #[test]
    fn a_checksum_written_the_other_way_names_the_plain_side_as_the_field() {
        let records = detect("  if (uVar5 + uVar6 == uVar7) {");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].field, "uVar7");
        assert_eq!(records[0].computed, "uVar5 + uVar6");
        assert_eq!(records[0].shape, ValidationShape::Checksum);
    }

    #[test]
    fn a_xor_and_mask_checksum_lands_too() {
        let records = detect("  if (iVar2 == (uVar3 ^ uVar4) & 0xffff) {");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].shape, ValidationShape::Checksum);
        assert_eq!(records[0].field, "iVar2");
    }

    #[test]
    fn a_field_verified_against_another_field_plus_a_constant_reads_as_a_checksum() {
        // A stored field checked against a global plus a fixed offset
        // is a computed comparison — the checksum shape. Nothing says
        // framing: no subtraction on the computed side and no
        // length-ish name on either.
        let records = detect("  if (iVar1 == DAT_14004a0b0 + 0x10) {");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].shape, ValidationShape::Checksum);
        assert_eq!(records[0].field, "iVar1");
        assert_eq!(records[0].computed, "DAT_14004a0b0 + 0x10");
    }

    #[test]
    fn a_remaining_count_comparison_lands_a_length_validation() {
        // Ghidra spells `size - 4` as `size + -4`; the subtraction on
        // the computed side is what reads as a remaining count.
        let records = detect("  if (uVar4 == local_18 + -4) {");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].shape, ValidationShape::Length);
        assert_eq!(records[0].field, "uVar4");
        assert_eq!(records[0].computed, "local_18 + -4");
    }

    #[test]
    fn a_checksum_read_through_struct_fields_stays_a_checksum() {
        // `->` carries a `-`, but it names a member, not a
        // subtraction: a stored field verified against fields of the
        // same object is the checksum shape, not framing.
        let records = detect("  if (obj->crc == obj->a + obj->b) {");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].shape, ValidationShape::Checksum);
        assert_eq!(records[0].field, "obj->crc");
        assert_eq!(records[0].computed, "obj->a + obj->b");
    }

    #[test]
    fn a_name_that_merely_ends_inside_a_length_marker_claims_nothing() {
        // The length markers read as name segments, not substrings:
        // `discount` ends in "count" but holds no length, so a plain
        // pair of ordinary fields stays silent.
        let records = detect("  if (discount == price) {");
        assert!(
            records.is_empty(),
            "a name that only contains a marker claims nothing"
        );
    }

    #[test]
    fn a_named_length_versus_size_comparison_lands_a_length_validation() {
        // Both sides plain, but the names say framing: a read length
        // checked against a buffer size.
        let records = detect("  if (read_len == buffer_size) {");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].shape, ValidationShape::Length);
        assert_eq!(records[0].field, "read_len");
        assert_eq!(records[0].computed, "buffer_size");
    }

    #[test]
    fn a_stored_field_read_through_a_pointer_still_reads_as_the_field() {
        let records = detect("  if (*(uint *)pvVar2 == uVar3 + uVar4) {");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].field, "*(uint *)pvVar2");
        assert_eq!(records[0].shape, ValidationShape::Checksum);
    }

    #[test]
    fn constant_versus_constant_claims_nothing() {
        let records = detect("  if (0x10 == 0x20) {");
        assert!(records.is_empty());
    }

    #[test]
    fn a_variable_versus_literal_comparison_claims_nothing() {
        // Magic and constant territory: the other detectors read it.
        let records = detect("  if (iVar1 == 0x1234) {");
        assert!(records.is_empty());
    }

    #[test]
    fn a_computed_versus_literal_comparison_claims_nothing() {
        // No plain stored field on either side, so no field is being
        // validated — the shape does not fit either reading.
        let records = detect("  if (uVar5 + uVar6 == 0) {");
        assert!(records.is_empty());
    }

    #[test]
    fn a_plain_variable_pair_claims_nothing() {
        // Two default-named variables: nothing says which is a length
        // and which a size, so the comparison claims no framing.
        let records = detect("  if (uVar1 == uVar2) {");
        assert!(records.is_empty());
    }

    #[test]
    fn a_comparison_already_reported_as_a_magic_hit_claims_nothing() {
        // The magic detector reports this line (it carries the PNG
        // literal); validation must not double-report it even though
        // the sides fit the checksum shape.
        let line = "if (uVar1 == 0x89504e47 + uVar2) {";
        let detector = ValidationDetector::new();
        let records = detector.detect(&function(&format!("  {line}")), &magic(line));
        assert!(
            records.is_empty(),
            "a magic hit claims no validation finding"
        );
        // Without the magic finding on record the same line does
        // read as validation — the gate is what silences it.
        let unguarded = detector.detect(&function(&format!("  {line}")), &[]);
        assert_eq!(unguarded.len(), 1);
    }

    #[test]
    fn multiple_checks_in_one_body_each_land_their_own_finding_in_body_order() {
        let records = detect(
            "\
  if (uVar7 == uVar5 + uVar6) {
  if (uVar4 == local_18 + -4) {
  if (iVar9 == iVar10 ^ iVar11) {
",
        );
        let shapes: Vec<ValidationShape> = records.iter().map(|r| r.shape).collect();
        assert_eq!(
            shapes,
            vec![
                ValidationShape::Checksum,
                ValidationShape::Length,
                ValidationShape::Checksum
            ]
        );
        let fields: Vec<&str> = records.iter().map(|r| r.field.as_str()).collect();
        assert_eq!(fields, vec!["uVar7", "uVar4", "iVar9"]);
    }

    #[test]
    fn two_comparisons_on_one_line_each_get_their_own_finding() {
        let records = detect("  if (uVar7 == uVar5 + uVar6 && read_len == buffer_size) {");
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].shape, ValidationShape::Checksum);
        assert_eq!(records[1].shape, ValidationShape::Length);
    }

    #[test]
    fn an_assignment_is_not_a_comparison() {
        let records = detect("  uVar1 = uVar2 + uVar3;");
        assert!(records.is_empty());
    }

    #[test]
    fn a_comparison_spelled_inside_a_string_literal_claims_nothing() {
        let records = detect("  printf(\"uVar7 == uVar5 + uVar6\");");
        assert!(records.is_empty());
    }

    #[test]
    fn inequality_comparisons_read_like_equality_ones() {
        let records = detect("  if (uVar7 != uVar5 + uVar6) goto LAB_18003ab50;");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].shape, ValidationShape::Checksum);
        assert_eq!(
            records[0].evidence,
            "if (uVar7 != uVar5 + uVar6) goto LAB_18003ab50;"
        );
    }
}
