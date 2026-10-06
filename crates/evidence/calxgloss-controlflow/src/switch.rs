//! Switch-shaped if/else-if chain detection.
//!
//! Ghidra renders C `switch` statements as `if (var == CONST) { ... } else if
//! (var == CONST) { ... }` chains. A chain with at least `min_cases` arms is
//! reported as a switch-shaped construct; very wide chains (>=
//! `wide_threshold`) get a dispatch-table suggestion instead of a `match`.

use calxgloss_types::Confidence;

use crate::chain::find_chains;
use crate::types::SwitchChain;

/// Detector for switch-shaped if/else-if chains.
#[derive(Debug, Clone)]
pub struct SwitchChainDetector {
    /// Minimum number of `==` arms for a chain to look like a switch.
    min_cases: usize,
    /// Chain width at which a dispatch table beats a `match`.
    wide_threshold: usize,
}

impl Default for SwitchChainDetector {
    fn default() -> Self {
        Self {
            min_cases: 3,
            wide_threshold: 10,
        }
    }
}

impl SwitchChainDetector {
    /// Create a detector with the default thresholds (3 cases, wide at 10).
    pub fn new() -> Self {
        Self::default()
    }

    /// Lower or raise the arm count a chain needs to read as a switch.
    pub fn with_min_cases(mut self, min_cases: usize) -> Self {
        self.min_cases = min_cases;
        self
    }

    /// Lower or raise the chain width at which a dispatch table is
    /// suggested instead of a `match`.
    pub fn with_wide_threshold(mut self, wide_threshold: usize) -> Self {
        self.wide_threshold = wide_threshold;
        self
    }

    /// Detect switch-shaped chains in one decompiled function body.
    pub(crate) fn detect(&self, name: &str, code: &str) -> Vec<SwitchChain> {
        let lines: Vec<&str> = code.lines().collect();
        find_chains(&lines)
            .into_iter()
            .filter(|chain| chain.cases.len() >= self.min_cases)
            .map(|chain| {
                let n = chain.cases.len();
                let suggestion = if n >= self.wide_threshold {
                    format!("use a &[fn(...); {}] dispatch table for {}", n, chain.var)
                } else {
                    let default = if chain.has_default { " + _" } else { "" };
                    format!("match {} {{ /* {} arms */ }}{}", chain.var, n, default)
                };
                let last = chain
                    .cases
                    .last()
                    .map(|c| c.konst.as_str())
                    .unwrap_or_default();
                let mut evidence = format!(
                    "if ({} == {}) ... else if ({} == {})",
                    chain.var, chain.cases[0].konst, chain.var, last
                );
                if chain.has_default {
                    evidence.push_str(" + default");
                }
                SwitchChain {
                    function: name.to_string(),
                    variable: chain.var.clone(),
                    cases: chain.cases.iter().map(|c| c.konst.clone()).collect(),
                    has_default: chain.has_default,
                    suggestion,
                    confidence: Confidence::new(70),
                    evidence,
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chain_body(arms: usize, default: bool) -> String {
        let mut src = String::new();
        for i in 0..arms {
            if i == 0 {
                src.push_str(&format!(
                    "if (local_4 == {}) {{\n    f{}();\n}}\n",
                    i + 1,
                    i
                ));
            } else {
                src.push_str(&format!(
                    "else if (local_4 == {}) {{\n    f{}();\n}}\n",
                    i + 1,
                    i
                ));
            }
        }
        if default {
            src.push_str("else {\n    g();\n}\n");
        }
        src
    }

    #[test]
    fn detects_three_case_chain() {
        let findings = SwitchChainDetector::default().detect("dispatch", &chain_body(3, false));
        assert_eq!(findings.len(), 1);
        let f = &findings[0];
        assert_eq!(f.function, "dispatch");
        assert_eq!(f.variable, "local_4");
        assert_eq!(f.cases, ["1", "2", "3"]);
        assert!(!f.has_default);
        assert_eq!(f.suggestion, "match local_4 { /* 3 arms */ }");
        assert_eq!(u8::from(f.confidence), 70);
    }

    #[test]
    fn trailing_else_marks_default() {
        let findings = SwitchChainDetector::default().detect("dispatch", &chain_body(3, true));
        assert_eq!(findings.len(), 1);
        let f = &findings[0];
        assert!(f.has_default);
        assert_eq!(f.suggestion, "match local_4 { /* 3 arms */ } + _");
        assert!(f.evidence.ends_with("+ default"));
    }

    #[test]
    fn two_case_chain_is_below_threshold() {
        let findings = SwitchChainDetector::default().detect("dispatch", &chain_body(2, false));
        assert!(findings.is_empty());
    }

    #[test]
    fn threshold_is_configurable() {
        let findings = SwitchChainDetector::default()
            .with_min_cases(2)
            .detect("dispatch", &chain_body(2, false));
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn wide_chain_suggests_dispatch_table() {
        let findings = SwitchChainDetector::default().detect("dispatch", &chain_body(10, true));
        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].suggestion,
            "use a &[fn(...); 10] dispatch table for local_4"
        );
    }

    #[test]
    fn wide_threshold_is_configurable() {
        let findings = SwitchChainDetector::default()
            .with_wide_threshold(3)
            .detect("dispatch", &chain_body(3, false));
        assert_eq!(
            findings[0].suggestion,
            "use a &[fn(...); 3] dispatch table for local_4"
        );
    }

    #[test]
    fn string_literals_do_not_form_chains() {
        let code = "\
puts(\"if (x == 1) {\");
puts(\"else if (x == 2) {\");
puts(\"else if (x == 3) {\");
";
        let findings = SwitchChainDetector::default().detect("printer", code);
        assert!(findings.is_empty());
    }

    #[test]
    fn nested_ifs_do_not_join_outer_chain() {
        let code = "\
if (x == 1) {
    if (y == 5) {
        a();
    }
    if (y == 6) {
        b();
    }
    if (y == 7) {
        c();
    }
}
else if (x == 2) {
    d();
}
else if (x == 3) {
    e();
}
";
        let findings = SwitchChainDetector::default().detect("fn", code);
        // Only the outer x-chain qualifies; the y-ifs are separate statements.
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].variable, "x");
    }
}
