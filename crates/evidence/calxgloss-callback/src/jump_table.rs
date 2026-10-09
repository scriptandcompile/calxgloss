//! Jump-table dispatch detection.
//!
//! This module provides [`JumpTableDetector`], which carries the
//! data-symbol prefixes that mark an unnamed dispatch table — Ghidra's
//! `DAT_`, `LAB_` and `switchD` spellings — and reads each indexed
//! indirect call through one as a jump-table dispatch.
//!
//! A jump table is the implicit half of callback dispatch: where the
//! fp-array detector reads a *named* table being called, this one reads
//! a table the decompiler could not name — the callee is a minted data
//! symbol indexed by a variable and called through a code cast:
//!
//! ```c
//! if (index < 4) {
//!     (*(code *)(&switchD_1800015a0)[index])();
//! }
//! (*(code *)(DAT_18011711c + index * 8))(a, b);
//! ```
//!
//! [`JumpTableDetector::detect`] runs the reading: it reports each such
//! call (and the `switch(&switchD_*)[index]` header form) once per table
//! symbol, sizing the table from a bounds check on the index
//! (`idx < N` → N entries, `idx <= N` → N + 1) or from the number of
//! `SYM_caseD_*` labels the decompiler emitted. A table with a known
//! size below [`MIN_TARGETS`] is an ordinary small branch, not a
//! dispatch, and passes unrecorded.

use crate::types::JumpTable;
use calxgloss_ghidra::DecompiledFunction;
use calxgloss_types::skip_literal;

// ============================================================
// Detector
// ============================================================

/// Jump-table dispatch detection over decompiled functions.
///
/// The detector owns the data-symbol prefix set a scan reads bodies
/// against: a table symbol counts when it starts with one of the
/// configured prefixes. The set is configurable — supply it whole
/// through [`with_prefixes`](Self::with_prefixes) or grow it one prefix
/// at a time with [`add_prefix`](Self::add_prefix) — and
/// [`prefixes`](Self::prefixes) reports it in configuration order. The
/// standard set ([`default_table_prefixes`]) covers Ghidra's minted
/// spellings; a binary whose tables carry project names configures
/// those instead. The detector holds no Ghidra client of its own and
/// never writes back to the program; one detector serves an entire
/// scan.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct JumpTableDetector {
    prefixes: Vec<String>,
}

impl JumpTableDetector {
    /// A detector with no prefixes configured: every body it is handed
    /// reads nothing until the standard set arrives through
    /// [`with_default_prefixes`](Self::with_default_prefixes) or
    /// prefixes join one at a time through [`add_prefix`](Self::add_prefix).
    pub fn new() -> Self {
        Self::default()
    }

    /// A detector that scans against the standard prefix set —
    /// [`default_table_prefixes`] — in its configuration order.
    pub fn with_default_prefixes() -> Self {
        Self::with_prefixes(default_table_prefixes())
    }

    /// A detector that scans against exactly `prefixes`, each kept in
    /// the order it is given.
    pub fn with_prefixes(prefixes: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self {
            prefixes: prefixes.into_iter().map(Into::into).collect(),
        }
    }

    /// Add one prefix to the set this detector scans against.
    pub fn add_prefix(&mut self, prefix: impl Into<String>) {
        self.prefixes.push(prefix.into());
    }

    /// The prefixes this detector scans against, in configuration order.
    pub fn prefixes(&self) -> &[String] {
        &self.prefixes
    }

    /// The jump-table dispatches one function's body carries.
    ///
    /// The reading walks the body line by line and reports each
    /// indexed indirect call whose callee starts with `*` and names a
    /// configured-prefix data symbol — plus the
    /// `switch(&SYM)[index]` header form — once per table symbol, in
    /// first-call order. The table is sized from a bounds check on the
    /// index or from `SYM_caseD_*` label counts; a sized table below
    /// [`MIN_TARGETS`] entries is a branch, not a dispatch, and passes
    /// unrecorded. A sized table reads at [`JUMP_TABLE_CONFIDENCE`]
    /// with an exact-size suggestion; an unsized one still reports, at
    /// [`UNSIZED_TABLE_CONFIDENCE`], because the indexed code call itself is
    /// the evidence.
    pub fn detect(&self, func: &DecompiledFunction) -> Vec<JumpTable> {
        let mut tables = Vec::new();
        let mut seen: Vec<&str> = Vec::new();
        for line in func.body.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with("//") {
                continue;
            }
            let Some((symbol, index)) = self.call_site(trimmed) else {
                continue;
            };
            if seen.contains(&symbol) {
                continue;
            }
            seen.push(symbol);
            let count = target_count(&func.body, symbol, &index);
            if let Some(n) = count
                && n < MIN_TARGETS
            {
                continue;
            }
            tables.push(build_table(func, symbol, index, count, trimmed));
        }
        tables
    }

    /// The table symbol and index expression if this line dispatches
    /// through an unnamed table: an indirect call whose callee starts
    /// with `*` and contains a configured-prefix data symbol, or a
    /// `switch(&SYM)[i]` header.
    fn call_site<'a>(&self, line: &'a str) -> Option<(&'a str, String)> {
        if let Some((operand, index)) = switch_header(line) {
            let symbol = self.prefixed_symbol(operand)?;
            return Some((symbol, index?));
        }
        let bytes = line.as_bytes();
        let mut i = 0usize;
        while i < bytes.len() {
            if bytes[i] == b'"' || bytes[i] == b'\'' {
                // A dispatch shape inside a string literal is prose,
                // not a call.
                i = skip_literal(bytes, i);
                continue;
            }
            if bytes[i] != b'(' {
                i += 1;
                continue;
            }
            // A call through a computed callee: the `(` follows a `)`.
            let before = line[..i].trim_end();
            if before.as_bytes().last().copied() != Some(b')') {
                i += 1;
                continue;
            }
            let Some(callee) = callee_expr(line, before.len() - 1) else {
                i += 1;
                continue;
            };
            if !callee.trim_start().starts_with('*') {
                i += 1;
                continue;
            }
            let Some(symbol) = self.prefixed_symbol(callee) else {
                i += 1;
                continue;
            };
            let Some(index) = index_expr(callee) else {
                i += 1;
                continue;
            };
            return Some((symbol, index));
        }
        None
    }

    /// The first configured-prefix identifier inside the callee
    /// expression, as a slice of the line it came from.
    fn prefixed_symbol<'a>(&self, expr: &'a str) -> Option<&'a str> {
        let bytes = expr.as_bytes();
        let mut start = 0usize;
        while start < bytes.len() {
            if bytes[start].is_ascii_alphanumeric() || bytes[start] == b'_' {
                let mut end = start;
                while end < bytes.len()
                    && (bytes[end].is_ascii_alphanumeric() || bytes[end] == b'_')
                {
                    end += 1;
                }
                let word = &expr[start..end];
                if self.prefixes.iter().any(|p| word.starts_with(p.as_str())) {
                    return Some(word);
                }
                start = end;
            } else {
                start += 1;
            }
        }
        None
    }
}

// ============================================================
// The reading
// ============================================================

/// Confidence of a dispatch whose table size was read from a bounds
/// check or switch labels beside it: the indexed code call plus its
/// bound is strong evidence of a dispatch table.
const JUMP_TABLE_CONFIDENCE: u8 = 70;

/// Confidence of a dispatch seen without a visible bound: the indexed
/// code call is the whole evidence, and the table's extent — and
/// whether it is a dispatch at all — is inferred.
const UNSIZED_TABLE_CONFIDENCE: u8 = 60;

/// A table this small is a branch, not a dispatch.
const MIN_TARGETS: usize = 3;

/// For `switch(&switchD_1400a3270)[uVar2];`, return the switch operand
/// and the index expression. Only indexed switch operands are jump
/// tables.
fn switch_header(line: &str) -> Option<(&str, Option<String>)> {
    let open = line.find("switch(")?;
    let inner = &line[open + "switch(".len()..];
    // `inner` starts just after the opening paren, so depth starts at 1.
    let close = matching_close_paren(inner)?;
    let operand = inner[..close].trim();
    let rest = inner[close + 1..].trim_start();
    if !rest.starts_with('[') {
        return None;
    }
    Some((operand, bracket_index_at(rest, 0)))
}

/// The callee expression inside the balanced group whose `)` sits at
/// `close`.
fn callee_expr(line: &str, close: usize) -> Option<&str> {
    let open = matching_paren_back(line, close)?;
    Some(&line[open + 1..close])
}

/// The index inside a callee: the last `[...]` group's contents, else
/// the identifier in the `SYM + idx * size` arithmetic form.
fn index_expr(callee: &str) -> Option<String> {
    if let Some(open) = callee.rfind('[') {
        return bracket_index_at(callee, open);
    }
    let plus = callee.find('+')?;
    let star = callee[plus..].find('*')?;
    let term = callee[plus + 1..plus + star].trim();
    is_simple_ident(term).then(|| term.to_string())
}

/// The contents of the `[...]` group opening at `open`.
fn bracket_index_at(haystack: &str, open: usize) -> Option<String> {
    let bytes = haystack.as_bytes();
    let mut depth = 0usize;
    let mut i = open;
    while i < bytes.len() {
        if bytes[i] == b'"' || bytes[i] == b'\'' {
            i = skip_literal(bytes, i);
            continue;
        }
        match bytes[i] {
            b'[' => depth += 1,
            b']' => {
                depth -= 1;
                if depth == 0 {
                    let inner = haystack[open + 1..i].trim();
                    return (!inner.is_empty()).then(|| inner.to_string());
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
}

/// Size the table: the count of distinct `SYM_caseD_*` labels the
/// decompiler emitted, else a bounds check on the index variable.
fn target_count(body: &str, symbol: &str, index: &str) -> Option<usize> {
    // Switch tables: the decompiler emits one `SYM_caseD_x` label per
    // entry.
    let marker = format!("{symbol}_caseD_");
    let mut labels: Vec<&str> = body
        .lines()
        .filter_map(|l| {
            let at = l.find(&marker)?;
            let mut end = at + marker.len();
            let bytes = l.as_bytes();
            while end < bytes.len() && (bytes[end].is_ascii_alphanumeric() || bytes[end] == b'_') {
                end += 1;
            }
            Some(&l[at..end])
        })
        .collect();
    labels.sort();
    labels.dedup();
    if !labels.is_empty() {
        // The labels are the ground truth for a switch's arms: even
        // when fewer than the threshold are visible, reporting the
        // count lets the caller's threshold skip a small switch.
        return Some(labels.len());
    }
    // Bounds check: `idx < N` → N, `idx <= N` → N + 1 (mirrored forms
    // too).
    if !is_simple_ident(index) {
        return None;
    }
    for line in body.lines() {
        if let Some(n) = bounds_check(line, index) {
            return Some(n);
        }
    }
    None
}

/// Parse `idx < N` / `idx <= N` / `N > idx` / `N >= idx` out of one
/// line, whole identifier matches only.
fn bounds_check(line: &str, idx: &str) -> Option<usize> {
    let ident_byte = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
    let mut search = line;
    while let Some(at) = search.find(idx) {
        let after_at = at + idx.len();
        let before_ok = at == 0 || !ident_byte(search.as_bytes()[at - 1]);
        let after_ok = after_at >= search.len() || !ident_byte(search.as_bytes()[after_at]);
        if before_ok && after_ok {
            let after = search[after_at..].trim_start();
            if let Some(rest) = after.strip_prefix("<=") {
                if let Some(n) = leading_number(rest) {
                    return Some(n + 1);
                }
            } else if let Some(rest) = after.strip_prefix('<') {
                if let Some(n) = leading_number(rest) {
                    return Some(n);
                }
            } else if let Some(rest) = after.strip_prefix(">=") {
                if let Some(n) = leading_number(rest) {
                    return Some(n);
                }
            } else if let Some(rest) = after.strip_prefix('>')
                && let Some(n) = leading_number(rest)
            {
                return Some(n + 1);
            }
            let before = search[..at].trim_end();
            if let Some(rest) = before.strip_suffix("<=") {
                if let Some(n) = trailing_number(rest) {
                    return Some(n + 1);
                }
            } else if let Some(rest) = before.strip_suffix('<') {
                if let Some(n) = trailing_number(rest) {
                    return Some(n);
                }
            } else if let Some(rest) = before.strip_suffix(">=") {
                if let Some(n) = trailing_number(rest) {
                    return Some(n);
                }
            } else if let Some(rest) = before.strip_suffix('>')
                && let Some(n) = trailing_number(rest)
            {
                return Some(n + 1);
            }
        }
        search = &search[after_at..];
    }
    None
}

/// Parse the number token at the start of `s` (decimal or `0x` hex).
fn leading_number(s: &str) -> Option<usize> {
    let s = s.trim_start();
    let mut end = 0usize;
    while end < s.len() && (s.as_bytes()[end].is_ascii_alphanumeric() || s.as_bytes()[end] == b'_')
    {
        end += 1;
    }
    parse_int(&s[..end])
}

/// Parse the number token at the end of `s` (decimal or `0x` hex).
fn trailing_number(s: &str) -> Option<usize> {
    let s = s.trim_end();
    let bytes = s.as_bytes();
    let mut start = bytes.len();
    while start > 0 && (bytes[start - 1].is_ascii_alphanumeric() || bytes[start - 1] == b'_') {
        start -= 1;
    }
    parse_int(&s[start..])
}

fn parse_int(token: &str) -> Option<usize> {
    if let Some(hex) = token
        .strip_prefix("0x")
        .or_else(|| token.strip_prefix("0X"))
    {
        if hex.is_empty() {
            return None;
        }
        usize::from_str_radix(hex, 16).ok()
    } else if !token.is_empty() && token.chars().all(|c| c.is_ascii_digit()) {
        token.parse().ok()
    } else {
        None
    }
}

fn is_simple_ident(s: &str) -> bool {
    !s.is_empty()
        && (s.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_'))
        && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// The record for one dispatch: a `switchD` table reads as `match`
/// arms, any other as a fixed-size array of `fn` pointers; the size,
/// when one was read, lands in both the suggestion and the record.
fn build_table(
    func: &DecompiledFunction,
    symbol: &str,
    index: String,
    count: Option<usize>,
    call_line: &str,
) -> JumpTable {
    let is_switch = symbol.starts_with("switchD") || symbol.starts_with("switchdataD");
    let suggestion = match (is_switch, count) {
        (true, Some(n)) => format!("match index {{ /* {n} arms */ }}"),
        (true, None) => "match index { ... }".to_string(),
        (false, Some(n)) => format!("[fn(...); {n}]"),
        (false, None) => "[fn(...)]".to_string(),
    };
    JumpTable {
        function: func.name.clone(),
        table: symbol.to_string(),
        index,
        target_count: count,
        suggestion,
        confidence: if count.is_some() {
            JUMP_TABLE_CONFIDENCE
        } else {
            UNSIZED_TABLE_CONFIDENCE
        }
        .into(),
        evidence: call_line.to_string(),
    }
}

// ============================================================
// Scanning helpers
// ============================================================
/// Scan a slice that starts just after an opening `(`; return the
/// index of the `)` that closes it.
fn matching_close_paren(s: &str) -> Option<usize> {
    let bytes = s.as_bytes();
    let mut depth = 1usize;
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'"' || bytes[i] == b'\'' {
            i = skip_literal(bytes, i);
            continue;
        }
        match bytes[i] {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
}

/// Given the index of a `)`, return the index of the `(` that closes
/// at it: the group that is open across the whole scan and whose
/// closing paren sits exactly at `close`.
fn matching_paren_back(line: &str, close: usize) -> Option<usize> {
    let bytes = line.as_bytes();
    let mut depth = 0usize;
    let mut open: Option<usize> = None;
    let mut i = 0usize;
    while i <= close {
        if bytes[i] == b'"' || bytes[i] == b'\'' {
            i = skip_literal(bytes, i);
            continue;
        }
        match bytes[i] {
            b'(' => {
                depth += 1;
                if depth == 1 {
                    open = Some(i);
                }
            }
            b')' => {
                if depth == 0 {
                    return None;
                }
                depth -= 1;
                if depth == 0 {
                    if i == close {
                        return open;
                    }
                    open = None;
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
}

// ============================================================
// The standard prefix set
// ============================================================

/// Ghidra's spellings for the unnamed data symbols that back jump
/// tables: `DAT_` for unnamed globals, `LAB_` for unnamed labels, and
/// the `switchD`/`switchdataD` families for compiler-generated switch
/// address tables. These are the decompiler's own mintings, not
/// project names: a binary whose tables carry names configures them
/// through [`JumpTableDetector::with_prefixes`].
pub fn default_table_prefixes() -> Vec<String> {
    ["DAT_", "LAB_", "switchD", "switchdataD"]
        .iter()
        .map(|s| (*s).to_string())
        .collect()
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn function(body: &str) -> DecompiledFunction {
        DecompiledFunction {
            name: "FUN_180001560".into(),
            signature: "undefined FUN_180001560(void)".into(),
            body: format!("\nundefined FUN_180001560(void)\n\n{{\n{body}}}\n"),
        }
    }

    fn detect(body: &str) -> Vec<JumpTable> {
        JumpTableDetector::with_default_prefixes().detect(&function(body))
    }

    fn one(body: &str) -> JumpTable {
        let found = detect(body);
        assert_eq!(found.len(), 1, "body: {body}");
        found.into_iter().next().unwrap()
    }

    #[test]
    fn the_default_prefix_set_names_ghidras_minted_spellings() {
        let detector = JumpTableDetector::with_default_prefixes();
        assert_eq!(
            detector.prefixes(),
            ["DAT_", "LAB_", "switchD", "switchdataD"]
        );
        assert!(JumpTableDetector::new().prefixes().is_empty());
    }

    #[test]
    fn detects_switch_table_call_with_bounds_check() {
        let record =
            one("  if (index < 4) {\n    (*(code *)(&switchD_1800015a0)[index])();\n  }\n");
        assert_eq!(record.table, "switchD_1800015a0");
        assert_eq!(record.index, "index");
        assert_eq!(record.target_count, Some(4));
        assert_eq!(record.suggestion, "match index { /* 4 arms */ }");
        assert_eq!(record.confidence, 70);
    }

    #[test]
    fn detects_dat_arithmetic_table_with_inclusive_bound() {
        let record =
            one("  if (index <= 2) {\n    (*(code *)(DAT_18011711c + index * 8))(a, b);\n  }\n");
        assert_eq!(record.table, "DAT_18011711c");
        assert_eq!(record.index, "index");
        // `<= 2` means 3 entries.
        assert_eq!(record.target_count, Some(3));
        assert_eq!(record.suggestion, "[fn(...); 3]");
        assert_eq!(record.confidence, 70);
    }

    #[test]
    fn hex_bounds_are_parsed() {
        let record = one("  if (uVar2 < 0x1a) {\n    (*(&DAT_18011711c)[uVar2])();\n  }\n");
        assert_eq!(record.target_count, Some(26));
        assert_eq!(record.suggestion, "[fn(...); 26]");
    }

    #[test]
    fn mirrored_bounds_are_parsed() {
        let record = one("  if (0x10 < uVar2) { return; }\n  (*(&DAT_18011711c)[uVar2])();\n");
        assert_eq!(record.target_count, Some(16));
    }

    #[test]
    fn switch_case_labels_size_the_table() {
        let record = one("\
  (*(code *)(&switchD_1800a3270)[uVar2])();
  switchD_1800a3270_caseD_0:
  switchD_1800a3270_caseD_1:
  switchD_1800a3270_caseD_2:
  goto switchD_1800a3270_caseD_1;
");
        assert_eq!(record.target_count, Some(3));
        assert_eq!(record.suggestion, "match index { /* 3 arms */ }");
    }

    #[test]
    fn switch_header_form_is_detected() {
        let record = one("  switch(&switchD_1400a3270)[uVar2];\n");
        assert_eq!(record.table, "switchD_1400a3270");
        assert_eq!(record.index, "uVar2");
    }

    #[test]
    fn lab_symbols_are_detected_at_pattern_confidence() {
        let record = one("  (*(&LAB_1800015a0)[index])();\n");
        assert_eq!(record.table, "LAB_1800015a0");
        // No bounds, no labels: pattern-only, lower confidence.
        assert_eq!(record.target_count, None);
        assert_eq!(record.confidence, 60);
        assert_eq!(record.suggestion, "[fn(...)]");
    }

    #[test]
    fn tiny_tables_are_ordinary_branches() {
        // A bounds check of 2 is a branch, not a dispatch.
        assert!(
            detect("  if (index < 2) {\n    (*(code *)(&switchD_1)[index])();\n  }\n").is_empty()
        );
    }

    #[test]
    fn a_switch_with_too_few_visible_arms_reports_nothing() {
        // Two visible `caseD` arms and no bounds check: below the
        // target threshold, so nothing is reported even though the
        // dispatch shape itself matches.
        assert!(
            detect(
                "\
  (*(code *)(&switchD_1800a3270)[uVar2])();
  switchD_1800a3270_caseD_0:
  switchD_1800a3270_caseD_1:
"
            )
            .is_empty()
        );
    }

    #[test]
    fn a_symbol_inside_a_string_literal_invents_no_table() {
        // The scan reads code, not prose: a full dispatch shape inside
        // a string literal is not a dispatch.
        assert!(detect("  printf(\"(*(&DAT_1800a3270)[uVar2])();\");\n").is_empty());
    }

    #[test]
    fn named_symbols_are_not_jump_tables() {
        // `handlers` is the fp-array detector's territory.
        assert!(detect("  (*handlers[i])(buf);").is_empty());
    }

    #[test]
    fn vtable_calls_are_not_jump_tables() {
        // The eqmain shape: calls through locals, not data symbols.
        assert!(detect(
            "  (*(code *)(*pppplVar3)[6])(pppplVar3);\n  (*(code *)local_1078[1])(&local_1078);\n"
        )
        .is_empty());
    }

    #[test]
    fn one_finding_per_table_symbol() {
        let found = detect("  (*(&DAT_1)[a])();\n  (*(&DAT_1)[b])();\n");
        assert_eq!(found.len(), 1);
    }

    #[test]
    fn configured_prefixes_replace_the_defaults() {
        let detector = JumpTableDetector::with_prefixes(["tbl_"]);
        let found = detector.detect(&function("  (*(&tbl_events)[i])();"));
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].table, "tbl_events");
        assert!(detector.detect(&function("  (*(&DAT_1)[i])();")).is_empty());
    }

    #[test]
    fn evidence_quotes_the_call_line() {
        let record = one("  (*(code *)(DAT_18011711c + index * 8))(a, b);\n");
        assert_eq!(
            record.evidence,
            "(*(code *)(DAT_18011711c + index * 8))(a, b);"
        );
    }
}
