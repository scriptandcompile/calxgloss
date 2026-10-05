//! Control flow signature matching.
//!
//! This module provides [`CfgPatternMatcher`], which carries the control
//! flow signatures — comparison sort, binary search, linear search, hash
//! table lookup, state machine, recursion, linked list traversal — that
//! decompiled function bodies are scanned against. Each signature is an
//! [`AlgorithmPattern`]: a named bundle of regexes (configurable match
//! and exclude patterns) with a minimum line-count floor that keeps tiny
//! functions from accidentally fitting a broad shape.
//!
//! [`default_patterns`] carries the standard signature set — comparison
//! sort, binary search, linear search, hash table lookup, state machine,
//! recursion, linked list traversal — and
//! [`CfgPatternMatcher::with_default_patterns`] builds a matcher that
//! scans against it.
//!
//! [`AlgorithmPattern`]: crate::types::AlgorithmPattern

use crate::types::{AlgorithmCategory, AlgorithmHint, AlgorithmPattern, DetectionMethod};
use calxgloss_ghidra::DecompiledFunction;
use calxgloss_types::Confidence;
use regex::Regex;

// ============================================================
// Match confidence
// ============================================================

/// Confidence of a control flow match: the body carries every shape the
/// signature requires and clears its line floor, which is real
/// evidence, but regexes over decompiled pseudo-C approximate the
/// algorithm rather than prove it — the hint stays a hypothesis for
/// the translation prompt, not a fact applied to the program.
const CFG_CONFIDENCE: u8 = 60;

// ============================================================
// Matcher
// ============================================================

/// Control flow signature matching over decompiled functions.
///
/// The matcher owns the signature set a scan reads bodies against:
/// [`AlgorithmPattern`] records, each a named bundle of regexes with a
/// minimum line-count floor. The set is configurable — supply it whole
/// through [`with_patterns`](Self::with_patterns) or grow it one
/// signature at a time with [`add_pattern`](Self::add_pattern) — and
/// [`patterns`](Self::patterns) reports it in configuration order, so
/// two matchers built the same way scan identically and results diff
/// cleanly. The matcher holds no Ghidra client of its own and never
/// writes back to the program; one matcher serves an entire scan and can
/// be shared by reference across concurrent per-function passes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CfgPatternMatcher {
    patterns: Vec<AlgorithmPattern>,
}

impl CfgPatternMatcher {
    /// A matcher with no signatures configured: every body it is handed
    /// matches nothing until the standard set arrives through
    /// [`with_default_patterns`](Self::with_default_patterns) or
    /// signatures join one at a time through
    /// [`add_pattern`](Self::add_pattern).
    pub fn new() -> Self {
        Self::default()
    }

    /// A matcher that scans against the standard signature set —
    /// [`default_patterns`] — in its configuration order.
    pub fn with_default_patterns() -> Self {
        Self::with_patterns(default_patterns())
    }

    /// A matcher that scans against exactly `patterns`, kept in the
    /// order they are given.
    pub fn with_patterns(patterns: impl IntoIterator<Item = AlgorithmPattern>) -> Self {
        Self {
            patterns: patterns.into_iter().collect(),
        }
    }

    /// Add one signature to the set this matcher scans against.
    pub fn add_pattern(&mut self, pattern: AlgorithmPattern) {
        self.patterns.push(pattern);
    }

    /// The signatures this matcher scans against, in configuration
    /// order.
    pub fn patterns(&self) -> &[AlgorithmPattern] {
        &self.patterns
    }

    /// Scan a decompiled body against every configured signature, in
    /// configuration order, and report a hint for each signature the
    /// body fits.
    ///
    /// A signature fits when the body spans at least its
    /// [`min_lines`](AlgorithmPattern::min_lines) lines and carries a
    /// match for every regex in
    /// [`match_patterns`](AlgorithmPattern::match_patterns) and none in
    /// [`exclude_patterns`](AlgorithmPattern::exclude_patterns). The
    /// floor runs before any regex: a body shorter than it is too
    /// small to carry a real control flow shape — tiny functions
    /// accidentally fit broad signatures — so it is refused outright.
    ///
    /// Each hint names the pattern and its category, is marked
    /// [`CfgPattern`](DetectionMethod::CfgPattern) at
    /// [`CFG_CONFIDENCE`], and carries as its evidence the body line
    /// holding the first match of the signature's first required
    /// regex. A signature that asserts nothing — no required regexes —
    /// fits nothing, and a signature carrying a regex that will not
    /// compile can make no claim: it matches nothing, and an
    /// uncompilable exclusion rejects nothing.
    ///
    /// A regex source may carry the `{name}` placeholder: the matcher
    /// replaces it with the scanned function's name, escaped for literal
    /// matching, so a signature can speak of the function itself — the
    /// shape recursion needs, since a self-call is only recognizable
    /// against the function's own name.
    pub fn match_patterns(&self, func: &DecompiledFunction) -> Vec<AlgorithmHint> {
        let lines = func.body.lines().count();
        let name = regex::escape(&func.name);
        let mut hints = Vec::new();
        for pattern in &self.patterns {
            if lines < pattern.min_lines || pattern.match_patterns.is_empty() {
                continue;
            }

            // Every required shape must appear; the first one's first
            // match supplies the hint's evidence line.
            let mut evidence: Option<String> = None;
            let mut fits = true;
            for source in &pattern.match_patterns {
                let source = source.replace("{name}", &name);
                let Ok(shape) = Regex::new(&source) else {
                    fits = false;
                    break;
                };
                match shape.find(&func.body) {
                    Some(found) => {
                        if evidence.is_none() {
                            evidence = Some(line_at(&func.body, found.start()));
                        }
                    }
                    None => {
                        fits = false;
                        break;
                    }
                }
            }
            if !fits {
                continue;
            }

            // Any exclusion present in the body makes the matched
            // shapes read differently, so the signature refuses the
            // body.
            let excluded = pattern.exclude_patterns.iter().any(|source| {
                let source = source.replace("{name}", &name);
                Regex::new(&source).is_ok_and(|shape| shape.is_match(&func.body))
            });
            if excluded {
                continue;
            }

            hints.push(AlgorithmHint {
                function: func.name.clone(),
                algorithm: pattern.name.clone(),
                category: pattern.category,
                method: DetectionMethod::CfgPattern,
                confidence: Confidence::new(CFG_CONFIDENCE),
                evidence: evidence.unwrap_or_default(),
            });
        }
        hints
    }
}

// ============================================================
// The standard signature set
// ============================================================

/// The standard control flow signatures: the algorithms a scan
/// recognizes out of the box — comparison sort, binary search, linear
/// search, hash table lookup, state machine, recursion, and linked
/// list traversal.
///
/// Each signature reads the shapes Ghidra's decompiler actually emits
/// for its algorithm: the nested loop and temporary-mediated swap of a
/// sort, the halved range of a binary search, the equality test and
/// early exit of a linear scan, the modulo-folded bucket probe of a
/// hash lookup, the else-if or switch chain over a state-named
/// variable, a call carrying the scanned function's own name, and the
/// walk of a cursor through `->` fields. The shapes overlap — a probe
/// loop over buckets is also a linear scan — so exclusions keep each
/// signature to the reading it means, and the line floor keeps tiny
/// functions from fitting a broad shape.
pub fn default_patterns() -> Vec<AlgorithmPattern> {
    let comparison_sort = AlgorithmPattern {
        exclude_patterns: vec![r"\bqsort\b".into()],
        ..AlgorithmPattern::new(
            "comparison_sort",
            AlgorithmCategory::Sorting,
            [
                // A loop inside a loop: the outer pass and the inner
                // sweep that walks the range.
                r"\b(for|while) \([^)]*\)[^{}]*\{[^{}]*\b(for|while) \(",
                // The ordering comparison that drives the swap.
                "<",
                // The swap: three consecutive assignments — a
                // temporary takes a value, the slot is overwritten,
                // and the temporary reappears bare as the last
                // rvalue — the shape the decompiler emits for an
                // element exchange.
                r"(?m)^\s*\w+ = [^;\n]+;\n\s*[^;\n]+ = [^;\n]+;\n\s*[^;\n]+ = \w+;",
            ],
        )
    };

    let binary_search = AlgorithmPattern::new(
        "binary_search",
        AlgorithmCategory::Searching,
        [
            // The probe loop...
            r"\b(for|while) \(",
            // ...halving its range each pass.
            r"(?:/ 2\b|>> 1)",
            // The midpoint comparison that picks the half.
            r"if \(",
            r"[<>]",
        ],
    );

    let linear_search = AlgorithmPattern {
        exclude_patterns: vec![r"(?:/ 2\b|>> 1)".into(), "% ".into()],
        ..AlgorithmPattern::new(
            "linear_search",
            AlgorithmCategory::Searching,
            [
                // The scan loop...
                r"\b(for|while) \(",
                // ...testing each element against the target.
                "==",
                // A hit leaves the scan early.
                r"\b(return|break)\b",
            ],
        )
    };

    let hash_table_lookup = AlgorithmPattern::new(
        "hash_table_lookup",
        AlgorithmCategory::Hashing,
        [
            // The digest folded into a bucket index.
            "% ",
            // The bucket array access.
            r"\[",
            // The probe or bucket check around it.
            r"\b(if|while|for) \(",
        ],
    );

    let state_machine = AlgorithmPattern::new(
        "state_machine",
        AlgorithmCategory::StateMachine,
        [
            // A variable named for the role it plays.
            r"(?i)(state|status|mode)",
            // The dispatch across states...
            r"\b(if|switch) \(",
            // ...carried by an else-if or switch chain.
            r"\belse\b|\bcase\b",
        ],
    );

    // A self-call is precise evidence even in a short body, so the
    // floor only keeps one-line wrappers out. `{name}` names the
    // scanned function, and the `);` tail keeps the signature line —
    // where the name also appears, but never call-shaped — from
    // reading as a call.
    let recursion = AlgorithmPattern {
        min_lines: 6,
        ..AlgorithmPattern::new(
            "recursion",
            AlgorithmCategory::Recursion,
            [r"\b{name}\s*\([^;{]*\);"],
        )
    };

    let linked_list_traversal = AlgorithmPattern::new(
        "linked_list_traversal",
        AlgorithmCategory::Traversal,
        [
            // The walk loop...
            r"\b(for|while) \(",
            // ...reading through pointer fields...
            r"->\w+",
            // ...advancing the cursor to the next node.
            r"= \w+->",
        ],
    );

    vec![
        comparison_sort,
        binary_search,
        linear_search,
        hash_table_lookup,
        state_machine,
        recursion,
        linked_list_traversal,
    ]
}

// ============================================================
// Scanning helpers
// ============================================================

/// The trimmed source line containing `offset`.
pub(crate) fn line_at(body: &str, offset: usize) -> String {
    let line = body[..offset].matches('\n').count();
    body.lines().nth(line).unwrap_or("").trim().to_string()
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::AlgorithmCategory;

    fn pattern(name: &str) -> AlgorithmPattern {
        AlgorithmPattern::new(name, AlgorithmCategory::Sorting, ["<", "="])
    }

    #[test]
    fn a_new_matcher_starts_with_no_signatures() {
        // Construction is free: empty, equal however it is made, and
        // clones interchangeable.
        let matcher = CfgPatternMatcher::new();
        assert!(matcher.patterns().is_empty());
        assert_eq!(matcher, CfgPatternMatcher::default());
        assert_eq!(matcher.clone(), matcher);
    }

    #[test]
    fn a_matcher_keeps_the_signatures_it_is_configured_with() {
        let matcher = CfgPatternMatcher::with_patterns([
            pattern("comparison_sort"),
            pattern("insertion_sort"),
        ]);
        let patterns = matcher.patterns();
        assert_eq!(patterns.len(), 2);
        // Configuration order is scan order: two matchers built the
        // same way see the same signatures in the same order.
        assert_eq!(patterns[0].name, "comparison_sort");
        assert_eq!(patterns[1].name, "insertion_sort");
        assert_eq!(patterns[0].match_patterns, vec!["<", "="]);
    }

    #[test]
    fn an_added_signature_joins_the_set_in_order() {
        let mut matcher = CfgPatternMatcher::with_patterns([pattern("comparison_sort")]);
        matcher.add_pattern(pattern("shell_sort"));
        matcher.add_pattern(pattern("insertion_sort"));
        let names: Vec<&str> = matcher.patterns().iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, ["comparison_sort", "shell_sort", "insertion_sort"]);
    }

    #[test]
    fn a_matcher_can_be_shared_across_scans() {
        // One matcher is driven concurrently over a program's functions,
        // so sharing one by reference across tasks must stay sound.
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<CfgPatternMatcher>();
    }

    fn function(body: &str) -> DecompiledFunction {
        DecompiledFunction {
            name: "FUN_18003ab00".into(),
            signature: "void FUN_18003ab00(void)".into(),
            body: body.into(),
        }
    }

    /// A body that clears the default line floor and carries both of
    /// `pattern`'s required shapes: the `<` on the `while` line and the
    /// `=` inside the swap.
    fn fitting_body() -> String {
        [
            "void FUN_18003ab00(void) {",
            "  int local_10 = 0;",
            "  while (local_10 < 10) {",
            "    if (uVar1 < uVar2) {",
            "      uVar3 = uVar1;",
            "      uVar1 = uVar2;",
            "      uVar2 = uVar3;",
            "    }",
            "    local_10 = local_10 + 1;",
            "  }",
            "}",
        ]
        .join("\n")
    }

    #[test]
    fn a_body_fitting_a_signature_yields_a_hint() {
        let matcher = CfgPatternMatcher::with_patterns([pattern("comparison_sort")]);
        let hints = matcher.match_patterns(&function(&fitting_body()));
        assert_eq!(hints.len(), 1);
        let hint = &hints[0];
        assert_eq!(hint.function, "FUN_18003ab00");
        assert_eq!(hint.algorithm, "comparison_sort");
        assert_eq!(hint.category, AlgorithmCategory::Sorting);
        assert_eq!(hint.method, DetectionMethod::CfgPattern);
        assert_eq!(hint.confidence, Confidence::new(CFG_CONFIDENCE));
    }

    #[test]
    fn the_evidence_is_the_line_carrying_the_first_required_shape() {
        // The first required regex is `<`; its first match sits on the
        // `while` line, and the evidence is that whole trimmed line.
        let matcher = CfgPatternMatcher::with_patterns([pattern("comparison_sort")]);
        let hints = matcher.match_patterns(&function(&fitting_body()));
        assert_eq!(hints[0].evidence, "while (local_10 < 10) {");
    }

    #[test]
    fn a_body_missing_one_required_shape_matches_nothing() {
        // Every required regex must match: this body has `<` but no `=`.
        let matcher = CfgPatternMatcher::with_patterns([pattern("comparison_sort")]);
        let body = [
            "void FUN_18003ab00(int param_1) {",
            "  while (param_1 < 10) {",
            "    puts(\"tick\");",
            "    puts(\"tick\");",
            "    puts(\"tick\");",
            "    puts(\"tick\");",
            "    puts(\"tick\");",
            "    puts(\"tick\");",
            "    puts(\"tick\");",
            "  }",
            "}",
        ]
        .join("\n");
        assert!(matcher.match_patterns(&function(&body)).is_empty());
    }

    #[test]
    fn an_exclusion_in_the_body_rejects_the_match() {
        let mut signature = pattern("comparison_sort");
        signature.exclude_patterns = vec!["\\bqsort\\b".into()];
        let matcher = CfgPatternMatcher::with_patterns([signature]);

        // Without the exclusion the body fits; with a `qsort` call
        // beside the shapes the signature refuses it.
        assert_eq!(matcher.match_patterns(&function(&fitting_body())).len(), 1);
        let calling = format!("{}\n  qsort(local_10, 10, 4, local_11);", fitting_body());
        assert!(matcher.match_patterns(&function(&calling)).is_empty());
    }

    #[test]
    fn a_body_below_the_line_floor_matches_nothing() {
        let signature = AlgorithmPattern {
            min_lines: 20,
            ..pattern("comparison_sort")
        };
        let matcher = CfgPatternMatcher::with_patterns([signature]);
        assert!(
            matcher
                .match_patterns(&function(&fitting_body()))
                .is_empty()
        );
    }

    #[test]
    fn the_line_floor_is_inclusive() {
        // A body spanning exactly `min_lines` lines clears the floor.
        let signature = AlgorithmPattern {
            min_lines: 11,
            ..pattern("comparison_sort")
        };
        let matcher = CfgPatternMatcher::with_patterns([signature]);
        assert_eq!(matcher.match_patterns(&function(&fitting_body())).len(), 1);
    }

    #[test]
    fn a_matcher_with_no_signatures_yields_no_hints() {
        let matcher = CfgPatternMatcher::new();
        assert!(
            matcher
                .match_patterns(&function(&fitting_body()))
                .is_empty()
        );
    }

    #[test]
    fn each_fitting_signature_yields_its_own_hint_in_order() {
        let matcher = CfgPatternMatcher::with_patterns([
            pattern("insertion_sort"),
            pattern("comparison_sort"),
        ]);
        let hints = matcher.match_patterns(&function(&fitting_body()));
        let names: Vec<&str> = hints.iter().map(|h| h.algorithm.as_str()).collect();
        assert_eq!(names, ["insertion_sort", "comparison_sort"]);
    }

    #[test]
    fn a_signature_with_an_uncompilable_regex_matches_nothing() {
        // A signature that cannot evaluate its own shape can make no
        // claim about the body.
        let broken = AlgorithmPattern::new("broken", AlgorithmCategory::Sorting, ["("]);
        let matcher = CfgPatternMatcher::with_patterns([broken]);
        assert!(
            matcher
                .match_patterns(&function(&fitting_body()))
                .is_empty()
        );
    }

    #[test]
    fn an_uncompilable_exclusion_rejects_nothing() {
        let mut signature = pattern("comparison_sort");
        signature.exclude_patterns = vec!["(".into()];
        let matcher = CfgPatternMatcher::with_patterns([signature]);
        assert_eq!(matcher.match_patterns(&function(&fitting_body())).len(), 1);
    }

    #[test]
    fn a_signature_that_asserts_nothing_matches_nothing() {
        // A bundle of zero required regexes would vacuously fit every
        // body, so it fits none.
        let empty = AlgorithmPattern {
            match_patterns: Vec::new(),
            ..pattern("comparison_sort")
        };
        let matcher = CfgPatternMatcher::with_patterns([empty]);
        assert!(
            matcher
                .match_patterns(&function(&fitting_body()))
                .is_empty()
        );
    }

    // --------------------------------------------------------
    // The standard signature set
    // --------------------------------------------------------

    /// The names of the algorithms the standard set reports for `body`.
    fn algorithms(body: &str) -> Vec<String> {
        CfgPatternMatcher::with_default_patterns()
            .match_patterns(&function(body))
            .into_iter()
            .map(|hint| hint.algorithm)
            .collect()
    }

    /// A decompiled bubble sort: the outer pass, the inner sweep, the
    /// ordering comparison, and the swap through `iVar4`.
    fn sort_body() -> String {
        [
            "void FUN_18003ab00(int *param_1,int param_2)",
            "",
            "{",
            "  int iVar2;",
            "  uint uVar3;",
            "  int iVar4;",
            "  ",
            "  uVar3 = 0;",
            "  while (uVar3 < (uint)param_2) {",
            "    iVar2 = 0;",
            "    while (iVar2 < param_2 - 1) {",
            "      if (param_1[iVar2] < param_1[iVar2 + 1]) {",
            "        iVar4 = param_1[iVar2];",
            "        param_1[iVar2] = param_1[iVar2 + 1];",
            "        param_1[iVar2 + 1] = iVar4;",
            "      }",
            "      iVar2 = iVar2 + 1;",
            "    }",
            "    uVar3 = uVar3 + 1;",
            "  }",
            "  return;",
            "}",
        ]
        .join("\n")
    }

    /// A decompiled binary search: the probe loop, the halved range,
    /// and the midpoint comparisons.
    fn binary_search_body() -> String {
        [
            "int FUN_18003ab00(int *param_1,int param_2,int param_3)",
            "",
            "{",
            "  int iVar1;",
            "  int iVar2;",
            "  int iVar3;",
            "  ",
            "  iVar1 = 0;",
            "  iVar2 = param_2 + -1;",
            "  while (iVar1 <= iVar2) {",
            "    iVar3 = (iVar1 + iVar2) / 2;",
            "    if (param_1[iVar3] < param_3) {",
            "      iVar1 = iVar3 + 1;",
            "    }",
            "    else if (param_3 < param_1[iVar3]) {",
            "      iVar2 = iVar3 + -1;",
            "    }",
            "    else {",
            "      return param_1[iVar3];",
            "    }",
            "  }",
            "  return -1;",
            "}",
        ]
        .join("\n")
    }

    /// A decompiled linear scan: the loop, the equality test against
    /// the target, and the early return on a hit.
    fn linear_search_body() -> String {
        [
            "int FUN_18003ab00(int *param_1,int param_2,int param_3)",
            "",
            "{",
            "  int iVar1;",
            "  ",
            "  iVar1 = 0;",
            "  while (iVar1 < param_2) {",
            "    if (param_1[iVar1] == param_3) {",
            "      return iVar1;",
            "    }",
            "    iVar1 = iVar1 + 1;",
            "  }",
            "  return -1;",
            "}",
        ]
        .join("\n")
    }

    /// A decompiled hash lookup: the digest loop, the modulo-folded
    /// bucket index, and the probe over the bucket array.
    fn hash_lookup_body() -> String {
        [
            "undefined8 FUN_18003ab00(char *param_1)",
            "",
            "{",
            "  ulong uVar2;",
            "  ulong uVar3;",
            "  ",
            "  uVar2 = 0;",
            "  while (*param_1 != '\\0') {",
            "    uVar2 = (ulong)((uint)uVar2 * 0x1f) + (ulong)(byte)*param_1;",
            "    param_1 = param_1 + 1;",
            "  }",
            "  uVar3 = (ulong)(uVar2 % 0x40);",
            "  while (hash_table[uVar3] != 0) {",
            "    if (hash_table[uVar3].field_0 == uVar2) {",
            "      return hash_table[uVar3].field_8;",
            "    }",
            "    uVar3 = (uVar3 + 1) % 0x40;",
            "  }",
            "  return 0;",
            "}",
        ]
        .join("\n")
    }

    /// A decompiled state machine: the else-if chain dispatching on a
    /// state-named variable and assigning its transitions.
    fn state_machine_body() -> String {
        [
            "void FUN_18003ab00(int param_1)",
            "",
            "{",
            "  int local_state;",
            "  ",
            "  if (local_state == 0) {",
            "    if (param_1 == 1) {",
            "      local_state = 1;",
            "    }",
            "  }",
            "  else if (local_state == 1) {",
            "    if (param_1 == 2) {",
            "      local_state = 2;",
            "    }",
            "  }",
            "  else if (local_state == 2) {",
            "    local_state = 0;",
            "  }",
            "  return;",
            "}",
        ]
        .join("\n")
    }

    /// A decompiled fibonacci: two calls carrying the function's own
    /// name.
    fn recursion_body() -> String {
        [
            "longlong FUN_18003ab00(longlong param_1)",
            "",
            "{",
            "  longlong iVar1;",
            "  longlong iVar2;",
            "  ",
            "  if (param_1 < 2) {",
            "    return param_1;",
            "  }",
            "  iVar1 = FUN_18003ab00(param_1 + -1);",
            "  iVar2 = FUN_18003ab00(param_1 + -2);",
            "  return iVar1 + iVar2;",
            "}",
        ]
        .join("\n")
    }

    /// A decompiled list walk: the loop, the cursor reading through
    /// `->` fields, and the advance to the next node.
    fn list_traversal_body() -> String {
        [
            "void FUN_18003ab00(node *param_1)",
            "",
            "{",
            "  node *pnVar1;",
            "  uint uVar2;",
            "  ",
            "  pnVar1 = param_1;",
            "  uVar2 = 0;",
            "  while (pnVar1 != (node *)0x0) {",
            "    uVar2 = uVar2 + pnVar1->data;",
            "    pnVar1 = pnVar1->next;",
            "  }",
            "  printf(\"sum: %d\\n\",uVar2);",
            "  return;",
            "}",
        ]
        .join("\n")
    }

    #[test]
    fn the_standard_set_carries_the_planned_signatures() {
        let patterns = default_patterns();
        let names: Vec<&str> = patterns.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(
            names,
            [
                "comparison_sort",
                "binary_search",
                "linear_search",
                "hash_table_lookup",
                "state_machine",
                "recursion",
                "linked_list_traversal",
            ]
        );
        let categories: Vec<AlgorithmCategory> = patterns.iter().map(|p| p.category).collect();
        assert_eq!(
            categories,
            [
                AlgorithmCategory::Sorting,
                AlgorithmCategory::Searching,
                AlgorithmCategory::Searching,
                AlgorithmCategory::Hashing,
                AlgorithmCategory::StateMachine,
                AlgorithmCategory::Recursion,
                AlgorithmCategory::Traversal,
            ]
        );
    }

    #[test]
    fn a_matcher_built_with_the_standard_set_scans_against_it() {
        let matcher = CfgPatternMatcher::with_default_patterns();
        assert_eq!(matcher.patterns(), default_patterns());
        assert_ne!(matcher, CfgPatternMatcher::new());
    }

    #[test]
    fn a_nested_loop_with_a_swap_reads_as_a_comparison_sort() {
        assert_eq!(algorithms(&sort_body()), ["comparison_sort"]);
    }

    #[test]
    fn a_halving_probe_reads_as_a_binary_search() {
        assert_eq!(algorithms(&binary_search_body()), ["binary_search"]);
    }

    #[test]
    fn an_equality_scan_reads_as_a_linear_search() {
        assert_eq!(algorithms(&linear_search_body()), ["linear_search"]);
    }

    #[test]
    fn a_modulo_folded_probe_reads_as_a_hash_table_lookup() {
        // The probe loop is also an equality scan, but the modulo
        // folding says the scan walks buckets, not a plain range.
        assert_eq!(algorithms(&hash_lookup_body()), ["hash_table_lookup"]);
    }

    #[test]
    fn an_else_if_chain_on_a_state_variable_reads_as_a_state_machine() {
        assert_eq!(algorithms(&state_machine_body()), ["state_machine"]);
    }

    #[test]
    fn a_self_call_reads_as_recursion() {
        assert_eq!(algorithms(&recursion_body()), ["recursion"]);
    }

    #[test]
    fn a_signature_line_is_not_a_self_call() {
        // The body names the function only in its own signature line,
        // and calls a different function: no self-call, no recursion.
        let body = [
            "longlong FUN_18003ab00(longlong param_1)",
            "",
            "{",
            "  longlong iVar1;",
            "  uint uVar2;",
            "  int iVar3;",
            "  ",
            "  iVar1 = 0;",
            "  uVar2 = 0;",
            "  while (iVar1 < 4) {",
            "    iVar3 = (int)(uVar2 % 0x10);",
            "    iVar1 = FUN_180001900(iVar3);",
            "    iVar1 = iVar1 + 1;",
            "  }",
            "  return iVar1;",
            "}",
        ]
        .join("\n");
        assert!(!algorithms(&body).contains(&"recursion".into()));
    }

    #[test]
    fn a_next_pointer_walk_reads_as_a_linked_list_traversal() {
        assert_eq!(
            algorithms(&list_traversal_body()),
            ["linked_list_traversal"]
        );
    }

    #[test]
    fn the_standard_set_stays_quiet_on_a_tiny_body() {
        // Every shape a tiny function could accidentally carry is
        // refused by the line floors.
        let body = "void FUN_18003ab00(void)\n\n{\n  return;\n}";
        assert!(algorithms(body).is_empty());
    }
}
