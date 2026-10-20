//! Branch inventory: one record per branch site in one decompiled body.
//!
//! Where the branch-density detector counts the branching of a body as
//! a whole, this detector walks the same per-body control flow graph and
//! inventories the individual branch sites: each site's condition as
//! written, the parameter and local names it reads, and — where the
//! comparison is readable — the operator and the constant immediate
//! compared against them. A site is only recorded when the branch
//! guards something in the [`GuardedTarget`] vocabulary: a taken arm
//! that returns (an early return) or reports an error (an error path), a
//! loop header (the loop exit), a trailing `else` arm, a `case` arm, or
//! a `default:` arm. A plain guarded body that guards nothing in that
//! vocabulary is not a site worth a record — the branch-density and
//! switch findings already tell that story, and this detector stays out
//! of their way.
//!
//! Confidence rides how much of the comparison was actually read: 80
//! when the operator and a numeric or char immediate both came out —
//! the exact boundary — 70 when the operator was read but the other
//! side is a name rather than a constant, and 50 for a shape-only
//! reading, which names no operator or immediate at all. A `case` arm
//! always names its probe value, so it reads 80 for a numeric or char
//! constant and 70 for a named one.
//!
//! The site enumeration reuses the graph's block cuts and the chain
//! walker's string-literal blindness, so keywords and braces spelled
//! inside string literals invent no sites. A truncated body (the
//! decompiler cutting a decompile off mid-brace) inventories only what
//! is visible: the headers whose text is readable still record, and the
//! edges the missing brace would have carried are simply absent.

use calxgloss_types::Confidence;

use crate::cfg::{Cfg, Terminator, starts_word};
use crate::chain::{net_braces, outside_strings};
use crate::types::{BranchSite, GuardedTarget};

/// The name fragments that read as an error path when a taken arm
/// calls through them, matched case-insensitively anywhere in the
/// callee's name — Ghidra's `report_error`/`__fail`/`assert` spellings
/// all read as failure reporting.
const ERROR_NAME_MARKERS: [&str; 5] = ["err", "fail", "abort", "assert", "exception"];

/// Words that look like call sites but are not — the keywords whose
/// `(` opens a condition, not a call.
const NON_CALL_WORDS: [&str; 8] = [
    "if", "while", "for", "switch", "return", "sizeof", "do", "else",
];

/// Comparison operators the predicate reader looks for, longest first
/// so `<=` never reads as `<`.
const COMPARISON_OPERATORS: [&str; 6] = ["==", "!=", "<=", ">=", "<", ">"];

/// Detector for the branch sites of one decompiled body: what each
/// branch tests and what it guards.
#[derive(Debug, Clone, Default)]
pub struct BranchInventoryDetector {
    /// Records below this confidence are dropped; 0 keeps every site.
    min_confidence: u8,
}

impl BranchInventoryDetector {
    /// Create a detector with the default settings: every readable
    /// site records, at whatever confidence the reading earned.
    pub fn new() -> Self {
        Self::default()
    }

    /// Drop records whose confidence sits below `min_confidence` —
    /// raising it to 80 keeps only the sites whose exact boundary was
    /// read, and silences the shape-only readings.
    pub fn with_min_confidence(mut self, min_confidence: u8) -> Self {
        self.min_confidence = min_confidence;
        self
    }

    /// Inventory the branch sites of one decompiled function body, in
    /// body order: each site names its condition, the names it reads,
    /// the operator and immediate where readable, and what it guards.
    /// A body with no readable branch site reports nothing.
    pub(crate) fn detect(&self, name: &str, code: &str) -> Vec<BranchSite> {
        let cfg = Cfg::build(code);
        // Structure reads the string-blanked lines (the graph's own
        // discipline); evidence quotes the real ones.
        let blanked: Vec<String> = code.lines().map(outside_strings).collect();
        let trimmed: Vec<&str> = blanked.iter().map(String::as_str).map(str::trim).collect();
        let raw: Vec<&str> = code.lines().map(str::trim).collect();

        let mut sites: Vec<(usize, BranchSite)> = Vec::new();

        for block in cfg.blocks() {
            let head = block.end - 1;
            match block.terminator {
                Terminator::Branch => {
                    if let Some(site) = self.branch_site(name, &trimmed, &raw, head) {
                        sites.push((head, site));
                    }
                }
                Terminator::Loop => {
                    if let Some(site) = self.loop_site(name, &trimmed, &raw, head) {
                        sites.push((head, site));
                    }
                }
                Terminator::DoWhileTail => {
                    if let Some(site) = self.do_while_site(name, &trimmed, &raw, head) {
                        sites.push((head, site));
                    }
                }
                Terminator::FallThrough | Terminator::Return | Terminator::Goto => {}
            }

            // A case or default label opens its own block; the site
            // sits on the label line, not the block's exit.
            let opening = trimmed[block.start];
            if starts_word(opening, "case") && opening.contains(':') {
                sites.push((block.start, self.case_site(name, opening, raw[block.start])));
            } else if starts_word(opening, "default") && opening.contains(':') {
                sites.push((block.start, self.default_site(name, raw[block.start])));
            }
        }

        // A plain `else` line belongs to no block — the graph cut
        // around it — so the else arms are read straight off the text.
        for (line, text) in trimmed.iter().enumerate() {
            let core = text.strip_prefix('}').map(str::trim_start).unwrap_or(text);
            if starts_word(core, "else") && !starts_word(core[4..].trim_start(), "if") {
                sites.push((line, self.else_site(name, raw[line])));
            }
        }

        sites.sort_by_key(|(line, _)| *line);
        sites
            .into_iter()
            .filter(|(_, site)| site.confidence.value() >= self.min_confidence)
            .map(|(_, site)| site)
            .collect()
    }

    /// The site at an `if`/`else if` head: recorded only when the
    /// taken arm guards a return or an error path.
    fn branch_site(
        &self,
        name: &str,
        trimmed: &[&str],
        raw: &[&str],
        head: usize,
    ) -> Option<BranchSite> {
        let condition = paren_inner(trimmed[head])?;
        let guards = self.taken_guards(trimmed, head)?;
        Some(self.site(name, &condition, guards, raw[head]))
    }

    /// The site at a `for`/`while` head — the loop exit. A `do` head
    /// carries no predicate; its condition is read at the tail. A
    /// `for` with an empty middle clause (`for (;;)`) tests nothing,
    /// so it names no site.
    fn loop_site(
        &self,
        name: &str,
        trimmed: &[&str],
        raw: &[&str],
        head: usize,
    ) -> Option<BranchSite> {
        let line = trimmed[head];
        if starts_word(line, "do") {
            return None;
        }
        let inner = paren_inner(line)?;
        let condition = if starts_word(line, "for") {
            let predicate = inner
                .split(';')
                .nth(1)
                .map(str::trim)
                .filter(|p| !p.is_empty())?;
            predicate.to_string()
        } else {
            inner.to_string()
        };
        Some(self.site(name, &condition, GuardedTarget::LoopExit, raw[head]))
    }

    /// The site at a `} while (...);` tail — the condition a `do` body
    /// re-tests, read where the graph says it sits.
    fn do_while_site(
        &self,
        name: &str,
        trimmed: &[&str],
        raw: &[&str],
        head: usize,
    ) -> Option<BranchSite> {
        let condition = paren_inner(trimmed[head])?;
        Some(self.site(name, &condition, GuardedTarget::LoopExit, raw[head]))
    }

    /// The site at a `case ...:` label: the probe value is always
    /// visible, so the record names it as the immediate — 80 for a
    /// numeric or char constant, 70 for a name — and never invents an
    /// operator the label does not spell.
    fn case_site(&self, name: &str, label: &str, evidence: &str) -> BranchSite {
        let value = label["case".len()..].split(':').next().unwrap_or("").trim();
        let confidence = if is_literal(value) { 80 } else { 70 };
        BranchSite {
            function: name.to_string(),
            condition: label.to_string(),
            params: ident_list(value),
            operator: None,
            immediate: Some(value.to_string()),
            guards: GuardedTarget::SwitchArm,
            suggestion: "express the switch arm as a match arm".to_string(),
            confidence: Confidence::new(confidence),
            evidence: evidence.to_string(),
        }
    }

    /// The site at a `default:` label — the switch's else arm, a
    /// shape-only reading: there is no condition to read.
    fn default_site(&self, name: &str, evidence: &str) -> BranchSite {
        BranchSite {
            function: name.to_string(),
            condition: "default:".to_string(),
            params: Vec::new(),
            operator: None,
            immediate: None,
            guards: GuardedTarget::ElseArm,
            suggestion: "express the else arm as the match default".to_string(),
            confidence: Confidence::new(50),
            evidence: evidence.to_string(),
        }
    }

    /// The site at a plain `else` line — a shape-only reading of the
    /// arm with no condition of its own.
    fn else_site(&self, name: &str, evidence: &str) -> BranchSite {
        BranchSite {
            function: name.to_string(),
            condition: "else".to_string(),
            params: Vec::new(),
            operator: None,
            immediate: None,
            guards: GuardedTarget::ElseArm,
            suggestion: "express the else arm as the match default".to_string(),
            confidence: Confidence::new(50),
            evidence: evidence.to_string(),
        }
    }

    /// What the taken arm of the branch at `head` guards, brace-walked
    /// through the arm body: a bare `return;` reads as an early
    /// return; a value return or an error-ish call reads as an error
    /// path (the failure-return shape Ghidra leaves behind); anything
    /// else guards nothing in the vocabulary and records nothing.
    fn taken_guards(&self, trimmed: &[&str], head: usize) -> Option<GuardedTarget> {
        let mut bare_return = false;
        let mut value_return = false;
        let mut error_call = false;
        for line in self.arm_body(trimmed, head) {
            if starts_word(line, "return") {
                let rest = line[6..].trim().trim_end_matches(';').trim();
                if rest.is_empty() {
                    bare_return = true;
                } else {
                    value_return = true;
                }
            } else if call_names(line).iter().any(|callee| {
                let lower = callee.to_lowercase();
                ERROR_NAME_MARKERS
                    .iter()
                    .any(|marker| lower.contains(marker))
            }) {
                error_call = true;
            }
        }
        if error_call || value_return {
            Some(GuardedTarget::ErrorPath)
        } else if bare_return {
            Some(GuardedTarget::EarlyReturn)
        } else {
            None
        }
    }

    /// The string-blanked trimmed lines of the arm body the head at
    /// `head` opens, on the chain walker's brace discipline: the walk
    /// stops at the line that closes the arm — including the `} else`
    /// line the taken branch routes around. A head with no brace on
    /// its line has a single-statement body instead (the braceless
    /// form a hand-written or truncated body leaves).
    fn arm_body<'a>(&self, trimmed: &'a [&'a str], head: usize) -> Vec<&'a str> {
        if !trimmed[head].contains('{') {
            return trimmed.get(head + 1).copied().into_iter().collect();
        }
        let mut depth = 0i32;
        let mut body = Vec::new();
        for line in trimmed[head + 1..].iter().copied() {
            if depth == 0 && (line.starts_with('}') || net_braces(line) < 0) {
                break;
            }
            body.push(line);
            depth += net_braces(line);
        }
        body
    }

    /// Build one site record from the condition text: the names it
    /// reads, the operator and immediate where the comparison is
    /// readable, and the confidence the reading earned — 80 with both
    /// read, 70 with the operator alone, 50 shape-only.
    fn site(
        &self,
        name: &str,
        condition: &str,
        guards: GuardedTarget,
        evidence: &str,
    ) -> BranchSite {
        let (operator, immediate) = read_comparison(condition);
        let confidence = match (&operator, &immediate) {
            (Some(_), Some(_)) => 80,
            (Some(_), None) => 70,
            _ => 50,
        };
        let suggestion = match guards {
            GuardedTarget::EarlyReturn => format!("keep the early return behind {condition}"),
            GuardedTarget::ErrorPath => format!("keep the error path behind {condition} explicit"),
            GuardedTarget::LoopExit => {
                format!("express the loop exit for {condition} at the boundary")
            }
            GuardedTarget::ElseArm => "express the else arm as the match default".to_string(),
            GuardedTarget::SwitchArm => "express the switch arm as a match arm".to_string(),
        };
        BranchSite {
            function: name.to_string(),
            condition: condition.to_string(),
            params: ident_list(condition),
            operator,
            immediate,
            guards,
            suggestion,
            confidence: Confidence::new(confidence),
            evidence: evidence.to_string(),
        }
    }
}

/// The text inside the first balanced paren pair of `line`, from just
/// after the first `(` to its match — the condition a head line
/// carries. A truncated line with no closing paren still yields what
/// is visible.
fn paren_inner(line: &str) -> Option<String> {
    let open = line.find('(')?;
    let mut depth = 0usize;
    for (i, c) in line[open..].char_indices() {
        match c {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(line[open + 1..open + i].trim().to_string());
                }
            }
            _ => {}
        }
    }
    Some(line[open + 1..].trim().to_string())
}

/// Read the comparison out of a condition: the first top-level
/// operator among `== != <= >= < >` and the constant immediate
/// compared against the other side. A compound condition (a top-level
/// `&&` or `||`) is a shape-only reading — naming one arm's operator
/// would misreport the whole test — and so is a condition with no
/// comparison at all. Ghidra's cast prefixes (`(char *)0x0`) are
/// stripped from the operands before the immediate is judged.
fn read_comparison(condition: &str) -> (Option<String>, Option<String>) {
    let bytes = condition.as_bytes();
    // A compound condition is shape-only: naming one arm's operator
    // would misreport the whole test.
    let mut depth = 0i32;
    for i in 0..bytes.len() {
        match bytes[i] {
            b'(' => depth += 1,
            b')' => depth -= 1,
            b'&' if depth == 0 && bytes.get(i + 1) == Some(&b'&') => return (None, None),
            b'|' if depth == 0 && bytes.get(i + 1) == Some(&b'|') => return (None, None),
            _ => {}
        }
    }
    depth = 0;
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'(' => depth += 1,
            b')' => depth -= 1,
            _ => {}
        }
        if depth == 0 {
            // All operator lead bytes are ASCII, so a match position is
            // always a char boundary and the slices below are safe.
            if matches!(bytes[i], b'=' | b'!' | b'<' | b'>') {
                for op in COMPARISON_OPERATORS {
                    if bytes[i..].starts_with(op.as_bytes()) {
                        let lhs = strip_casts(&condition[..i]);
                        let rhs = strip_casts(&condition[i + op.len()..]);
                        let immediate = if is_literal(rhs) {
                            Some(rhs.to_string())
                        } else if is_literal(lhs) {
                            Some(lhs.to_string())
                        } else {
                            None
                        };
                        return (Some(op.to_string()), immediate);
                    }
                }
            }
        }
        i += 1;
    }
    (None, None)
}

/// Strip Ghidra's cast prefixes from an operand: a leading paren
/// group whose content is only names, spaces, and `*` is a cast, and
/// the operand is what follows it.
fn strip_casts(operand: &str) -> &str {
    let mut s = operand.trim();
    while let Some(rest) = s.strip_prefix('(') {
        let mut depth = 1usize;
        let mut close = None;
        for (i, c) in rest.char_indices() {
            match c {
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if depth == 0 {
                        close = Some(i);
                        break;
                    }
                }
                _ => {}
            }
        }
        let Some(close) = close else { return s };
        let inner = &rest[..close];
        let cast_like = inner
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == ' ' || c == '*');
        if !cast_like {
            return s;
        }
        s = rest[close + 1..].trim();
    }
    s
}

/// Whether `s` is a constant the record can name as an immediate: a
/// char literal, a decimal or hex number, optionally signed.
fn is_literal(s: &str) -> bool {
    let s = s.trim();
    if s.len() >= 3 && s.starts_with('\'') && s.ends_with('\'') {
        return true;
    }
    let digits = s.strip_prefix(['-', '+']).unwrap_or(s);
    if digits.is_empty() {
        return false;
    }
    if let Some(hex) = digits
        .strip_prefix("0x")
        .or_else(|| digits.strip_prefix("0X"))
    {
        return !hex.is_empty() && hex.chars().all(|c| c.is_ascii_hexdigit());
    }
    let mut seen_digit = false;
    let mut seen_dot = false;
    for c in digits.chars() {
        match c {
            '0'..='9' => seen_digit = true,
            '.' if !seen_dot => seen_dot = true,
            _ => return false,
        }
    }
    seen_digit
}

/// The identifier runs a condition reads, in first-seen order,
/// deduped — the parameters and locals the site tests, with the
/// shape's own keywords left out.
fn ident_list(condition: &str) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    let chars: Vec<char> = condition.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i].is_ascii_alphabetic() || chars[i] == '_' {
            let start = i;
            while i < chars.len() && (chars[i].is_ascii_alphanumeric() || chars[i] == '_') {
                i += 1;
            }
            let word: String = chars[start..i].iter().collect();
            if word != "case" && word != "default" && word != "else" && !names.contains(&word) {
                names.push(word);
            }
        } else {
            i += 1;
        }
    }
    names
}

/// The callee names a (string-blanked, trimmed) line calls: identifier
/// runs followed by `(`, with the condition keywords left out.
fn call_names(line: &str) -> Vec<&str> {
    let mut names = Vec::new();
    let chars: Vec<char> = line.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i].is_ascii_alphabetic() || chars[i] == '_' {
            let start = i;
            while i < chars.len() && (chars[i].is_ascii_alphanumeric() || chars[i] == '_') {
                i += 1;
            }
            let mut j = i;
            while j < chars.len() && chars[j] == ' ' {
                j += 1;
            }
            if j < chars.len() && chars[j] == '(' {
                let word = &line[start..i];
                if !NON_CALL_WORDS.contains(&word) {
                    names.push(word);
                }
            }
            i = j;
        } else {
            i += 1;
        }
    }
    names
}

#[cfg(test)]
mod tests {
    use super::*;

    fn detect(code: &str) -> Vec<BranchSite> {
        BranchInventoryDetector::default().detect("fun", code)
    }

    fn guards_loop_and_switch() -> Vec<BranchSite> {
        detect(
            "\
if (param_1 == 0) {
    return;
}
if (param_1 < 0) {
    return 0xffffffff;
}
while (param_1 < 10) {
    param_1 = param_1 + 1;
}
switch (param_1) {
    case 1:
        a();
        break;
    case 2:
        b();
        break;
    default:
        c();
}",
        )
    }

    #[test]
    fn a_body_with_guards_a_loop_and_a_switch_yields_one_record_per_site() {
        let sites = guards_loop_and_switch();
        let guards: Vec<GuardedTarget> = sites.iter().map(|site| site.guards).collect();
        assert_eq!(
            guards,
            vec![
                GuardedTarget::EarlyReturn,
                GuardedTarget::ErrorPath,
                GuardedTarget::LoopExit,
                GuardedTarget::SwitchArm,
                GuardedTarget::SwitchArm,
                GuardedTarget::ElseArm,
            ]
        );

        let early = &sites[0];
        assert_eq!(early.function, "fun");
        assert_eq!(early.condition, "param_1 == 0");
        assert_eq!(early.params, ["param_1"]);
        assert_eq!(early.operator.as_deref(), Some("=="));
        assert_eq!(early.immediate.as_deref(), Some("0"));
        assert_eq!(
            early.suggestion,
            "keep the early return behind param_1 == 0"
        );
        assert_eq!(u8::from(early.confidence), 80);
        assert_eq!(early.evidence, "if (param_1 == 0) {");

        let error = &sites[1];
        assert_eq!(error.condition, "param_1 < 0");
        assert_eq!(error.operator.as_deref(), Some("<"));
        assert_eq!(error.immediate.as_deref(), Some("0"));
        assert_eq!(
            error.suggestion,
            "keep the error path behind param_1 < 0 explicit"
        );
        assert_eq!(u8::from(error.confidence), 80);

        let exit = &sites[2];
        assert_eq!(exit.condition, "param_1 < 10");
        assert_eq!(exit.operator.as_deref(), Some("<"));
        assert_eq!(exit.immediate.as_deref(), Some("10"));
        assert_eq!(
            exit.suggestion,
            "express the loop exit for param_1 < 10 at the boundary"
        );
        assert_eq!(u8::from(exit.confidence), 80);

        let arm = &sites[3];
        assert_eq!(arm.condition, "case 1:");
        assert_eq!(arm.immediate.as_deref(), Some("1"));
        assert_eq!(arm.operator, None, "a case label spells no operator");
        assert_eq!(arm.suggestion, "express the switch arm as a match arm");
        assert_eq!(u8::from(arm.confidence), 80);

        let default = &sites[5];
        assert_eq!(default.condition, "default:");
        assert_eq!(u8::from(default.confidence), 50);
    }

    #[test]
    fn an_exact_boundary_scores_higher_than_a_shape_only_reading() {
        // Operator and immediate both read: the exact boundary.
        let sites = detect(
            "\
if (param_1 == 0) {
    return;
}",
        );
        assert_eq!(sites.len(), 1);
        assert_eq!(u8::from(sites[0].confidence), 80);

        // Operator read, other side a name: the named-constant rung.
        let sites = detect(
            "\
if (local_4 == STATE_IDLE) {
    return;
}",
        );
        assert_eq!(sites[0].operator.as_deref(), Some("=="));
        assert_eq!(sites[0].immediate, None);
        assert_eq!(u8::from(sites[0].confidence), 70);

        // A shape-only reading names no operator or immediate.
        let sites = detect(
            "\
if (local_4) {
    return;
}",
        );
        assert_eq!(sites[0].operator, None);
        assert_eq!(sites[0].immediate, None);
        assert_eq!(u8::from(sites[0].confidence), 50);
    }

    #[test]
    fn a_compound_condition_reads_shape_only() {
        // Naming one arm's operator would misreport the whole test.
        let sites = detect(
            "\
if (param_1 == 0 && param_2 == 1) {
    return;
}",
        );
        assert_eq!(sites.len(), 1);
        assert_eq!(sites[0].condition, "param_1 == 0 && param_2 == 1");
        assert_eq!(sites[0].params, ["param_1", "param_2"]);
        assert_eq!(sites[0].operator, None);
        assert_eq!(sites[0].immediate, None);
        assert_eq!(u8::from(sites[0].confidence), 50);
    }

    #[test]
    fn a_for_header_records_its_test_clause_and_a_do_while_its_tail() {
        let sites = detect(
            "\
for (local_9 = 0; local_9 < 3; local_9 = local_9 + 1) {
    f();
}
do {
    g();
} while (param_1 != 0);",
        );
        assert_eq!(sites.len(), 2);
        assert_eq!(sites[0].condition, "local_9 < 3");
        assert_eq!(sites[0].guards, GuardedTarget::LoopExit);
        assert_eq!(
            sites[0].evidence,
            "for (local_9 = 0; local_9 < 3; local_9 = local_9 + 1) {"
        );
        assert_eq!(sites[1].condition, "param_1 != 0");
        assert_eq!(sites[1].evidence, "} while (param_1 != 0);");
        assert_eq!(u8::from(sites[1].confidence), 80);

        // An endless for tests nothing: no predicate, no record.
        assert!(detect("for (;;) {\n    f();\n}").is_empty());
    }

    #[test]
    fn a_goto_loop_names_no_site() {
        // The flattened-loop shape carries no readable predicate.
        let sites = detect(
            "\
LAB_top:
    x = x + 1;
    goto LAB_top;
return;",
        );
        assert!(sites.is_empty());
    }

    #[test]
    fn a_plain_guarded_body_records_nothing() {
        // The branch-density and switch findings already tell the
        // plain-chain story: a guarded body with no return and no
        // error call guards nothing in the vocabulary.
        assert!(
            detect(
                "\
if (local_4 == 1) {
    a();
}
else if (local_4 == 2) {
    b();
}"
            )
            .is_empty()
        );
    }

    #[test]
    fn a_trailing_else_and_a_named_case_arm_record_at_their_own_lines() {
        let sites = detect(
            "\
if (local_4 == STATE_IDLE) {
    a();
}
else {
    b();
}
switch (local_4) {
    case STATE_RUN:
        c();
}",
        );
        let guards: Vec<GuardedTarget> = sites.iter().map(|site| site.guards).collect();
        assert_eq!(
            guards,
            vec![GuardedTarget::ElseArm, GuardedTarget::SwitchArm]
        );
        assert_eq!(sites[0].condition, "else");
        assert_eq!(sites[0].evidence, "else {");
        assert_eq!(u8::from(sites[0].confidence), 50);
        assert_eq!(sites[1].condition, "case STATE_RUN:");
        assert_eq!(sites[1].immediate.as_deref(), Some("STATE_RUN"));
        assert_eq!(u8::from(sites[1].confidence), 70, "a named case constant");
    }

    #[test]
    fn a_ghidra_cast_does_not_hide_the_immediate() {
        // Kuna renders Ghidra's casts; the operand under the cast is
        // what the comparison reads.
        let sites = detect(
            "\
if (scratch == (char *)0x0) {
    return (char *)0x0;
}",
        );
        assert_eq!(sites.len(), 1);
        assert_eq!(sites[0].guards, GuardedTarget::ErrorPath);
        assert_eq!(sites[0].operator.as_deref(), Some("=="));
        assert_eq!(sites[0].immediate.as_deref(), Some("0x0"));
        assert_eq!(u8::from(sites[0].confidence), 80);
    }

    #[test]
    fn an_error_shaped_call_in_the_taken_arm_reads_as_an_error_path() {
        let sites = detect(
            "\
if (param_1 == 0) {
    report_error(1);
}
else {
    f();
}",
        );
        assert_eq!(sites[0].guards, GuardedTarget::ErrorPath);
        assert_eq!(
            sites[0].suggestion,
            "keep the error path behind param_1 == 0 explicit"
        );
    }

    #[test]
    fn a_truncated_body_inventories_only_what_is_visible() {
        // The while header is readable even though its closing brace
        // never arrived; the truncated plain guard guards nothing
        // visible, so it records nothing.
        let sites = detect(
            "\
while (local_9 < 3) {
    local_9 = local_9 + 1;
if (local_4 == 1) {",
        );
        assert_eq!(sites.len(), 1);
        assert_eq!(sites[0].condition, "local_9 < 3");
        assert_eq!(sites[0].guards, GuardedTarget::LoopExit);
    }

    #[test]
    fn branch_keywords_in_string_literals_invent_no_sites() {
        assert!(
            detect(
                "\
puts(\"if (a) { return; }\");
puts(\"} else {\");
puts(\"while (b) { }\");
puts(\"case 1:\");"
            )
            .is_empty(),
            "branching spelled inside strings invents no sites"
        );
    }

    #[test]
    fn a_body_with_no_readable_branches_records_nothing() {
        assert!(detect("return;").is_empty());
        assert!(detect("a();\nb();\nreturn;").is_empty());
    }

    #[test]
    fn the_minimum_confidence_knob_drops_the_shape_only_readings() {
        let body = "\
if (param_1 == 0) {
    return;
}
if (param_1 < 0) {
    return 0xffffffff;
}
while (param_1 < 10) {
    param_1 = param_1 + 1;
}
switch (param_1) {
    case 1:
        a();
        break;
    case 2:
        b();
        break;
    default:
        c();
}";
        assert_eq!(detect(body).len(), 6);

        let kept = BranchInventoryDetector::default()
            .with_min_confidence(80)
            .detect("fun", body);
        assert_eq!(
            kept.len(),
            5,
            "the shape-only default arm drops out at the raised floor"
        );
        assert!(kept.iter().all(|site| u8::from(site.confidence) >= 80));
    }

    #[test]
    fn the_detector_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<BranchInventoryDetector>();
    }
}
