//! Multi-function correlation: recognizing algorithms that span a call
//! relationship.
//!
//! The other three detectors read one function at a time. An algorithm
//! spelled out across two bodies — a sort routine driving a comparator
//! callback, or a divide-and-conquer that splits its range and recurses —
//! is invisible to each of them. [`CrossFunctionDetector`] is the fourth
//! detector. It derives the program's call map from the scan's kept
//! bodies: the program-function names that appear in each fetched body.
//! It then matches [`CorrelationRelationship`] records against that call
//! map, so the whole pass costs no extra analysis engine reads. This
//! follows the same idea as typeinfer's shared caller-body cache. The
//! detector's standard score lives in the
//! [`confidence`](crate::confidence) module, beside the other
//! detectors' standard scores.
//!
//! [`default_relationships`] carries the small, honest built-in set:
//! recursive divide-and-conquer (a self-call plus a halving/split shape)
//! and a sort driven by a comparator callback (a host call like `qsort`
//! plus a comparator-shaped callee). A correlated detection is an
//! ordinary [`AlgorithmHint`] record marked [`CrossFunction`](DetectionMethod::CrossFunction)
//! whose evidence names the partner function. It therefore goes through
//! the same resolution, the same confidence floor, and the same prompt
//! rendering as every other hint.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::confidence::CROSS_FUNCTION_CONFIDENCE;
use crate::types::{AlgorithmCategory, AlgorithmHint, DetectionMethod};
use calxgloss_decomp::DecompiledFunction;
use calxgloss_types::Confidence;
use regex::Regex;

// ============================================================
// Relationships
// ============================================================

/// One cross-function relationship the correlation detector matches: a
/// named bundle of shapes the hinted function's own body must carry,
/// beside the shapes its partner callee's body must carry.
///
/// A relationship recognizes exactly one algorithm: its
/// [`name`](Self::name) and [`category`](Self::category) are what a hint
/// records when the relationship fits. The hinted function's body must
/// match every regex in [`body_patterns`](Self::body_patterns) — the
/// call shape that ties it to a partner, spelled with the `{name}`
/// placeholder when the partner is the function itself. When
/// [`partner_patterns`](Self::partner_patterns) is not empty, one of the
/// program functions the body names must also match every partner
/// shape. An empty partner set means the body patterns already prove
/// everything the relationship needs from a partner: a self-call is its
/// own partner. Like the other pattern types, an entry may carry its own
/// [`confidence`](Self::confidence) overriding the detector's standard
/// score, and a [`min_lines`](Self::min_lines) floor rejects bodies too
/// small to carry a real relationship.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CorrelationRelationship {
    /// The algorithm this relationship recognizes, e.g.
    /// `divide_and_conquer`.
    pub name: String,
    /// The family the recognized algorithm belongs to.
    pub category: AlgorithmCategory,
    /// Regex sources the hinted function's own body must all match. A
    /// source may carry the `{name}` placeholder, which the detector
    /// replaces with the scanned function's name, escaped for literal
    /// matching — the shape a self-call needs.
    pub body_patterns: Vec<String>,
    /// Regex sources the partner callee's body must all match — the
    /// behavior the relationship demands of the partner, e.g. a
    /// comparator comparing two pointer touches. An empty set means the
    /// hinted body alone proves the relationship.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub partner_patterns: Vec<String>,
    /// Minimum number of body lines for the relationship to be
    /// considered.
    #[serde(default)]
    pub min_lines: usize,
    /// Optional per-entry confidence (0–100) overriding the detector's
    /// standard score ([`CROSS_FUNCTION_CONFIDENCE`]) for the hints this
    /// relationship makes. Absent means the standard score.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence: Option<u8>,
}

impl CorrelationRelationship {
    /// The default line-count floor, matching the control flow
    /// matcher's: a body shorter than this is too small to carry a real
    /// relationship.
    pub const DEFAULT_MIN_LINES: usize = crate::types::AlgorithmPattern::DEFAULT_MIN_LINES;

    /// A relationship named `name` in `category`, requiring every regex
    /// in `body_patterns` of the hinted body — no partner shapes, the
    /// standard line floor, and the standard score.
    pub fn new(
        name: impl Into<String>,
        category: AlgorithmCategory,
        body_patterns: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        CorrelationRelationship {
            name: name.into(),
            category,
            body_patterns: body_patterns.into_iter().map(Into::into).collect(),
            partner_patterns: Vec::new(),
            min_lines: Self::DEFAULT_MIN_LINES,
            confidence: None,
        }
    }

    /// Require the partner callee's body to carry every regex in
    /// `patterns`.
    pub fn with_partner_patterns(
        mut self,
        patterns: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        self.partner_patterns = patterns.into_iter().map(Into::into).collect();
        self
    }

    /// Refuse hinted bodies shorter than `lines`.
    pub fn with_min_lines(mut self, lines: usize) -> Self {
        self.min_lines = lines;
        self
    }

    /// Override the standard score with `confidence` for the hints this
    /// relationship makes.
    pub fn with_confidence(mut self, confidence: u8) -> Self {
        self.confidence = Some(confidence);
        self
    }
}

// ============================================================
// Detector
// ============================================================

/// Multi-function correlation over the call map built from the scan's
/// own bodies.
///
/// The detector owns the relationship set a scan matches against:
/// [`CorrelationRelationship`] records, configurable whole through
/// [`with_relationships`](Self::with_relationships) or grown one at a
/// time with [`add_relationship`](Self::add_relationship).
/// [`with_default_relationships`](Self::with_default_relationships)
/// builds a detector over [`default_relationships`].
///
/// The set's configuration order is the scan order, as with every other
/// detector: a function fitting two relationships reports both, first
/// the one configured first.
///
/// The detector holds no scan source and never reads the program
/// itself: [`detect_correlations`](Self::detect_correlations) is handed
/// the bodies the scan already fetched. It adds no analysis engine
/// round trips, and one detector serves a whole scan.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CrossFunctionDetector {
    relationships: Vec<CorrelationRelationship>,
}

impl CrossFunctionDetector {
    /// A detector with no relationships configured: every program it is
    /// handed stays quiet until the standard set arrives through
    /// [`with_default_relationships`](Self::with_default_relationships)
    /// or relationships join one at a time through
    /// [`add_relationship`](Self::add_relationship).
    pub fn new() -> Self {
        Self::default()
    }

    /// A detector that matches against the standard relationship set —
    /// [`default_relationships`] — in its configuration order.
    pub fn with_default_relationships() -> Self {
        Self::with_relationships(default_relationships())
    }

    /// A detector that matches against exactly `relationships`, kept in
    /// the order they are given.
    pub fn with_relationships(
        relationships: impl IntoIterator<Item = CorrelationRelationship>,
    ) -> Self {
        Self {
            relationships: relationships.into_iter().collect(),
        }
    }

    /// Add one relationship to the set this detector matches against.
    pub fn add_relationship(&mut self, relationship: CorrelationRelationship) {
        self.relationships.push(relationship);
    }

    /// The relationships this detector matches against, in configuration
    /// order.
    pub fn relationships(&self) -> &[CorrelationRelationship] {
        &self.relationships
    }

    /// Recognize the relationships spanning `functions`, the decompiled
    /// bodies in listing order, and report a hint for each function each
    /// relationship fits.
    ///
    /// The call map is derived here, from these bodies alone: a program
    /// function counts as called by another when its name appears in
    /// that body — as the callee of a call or as a callback handed to a
    /// host. So the pass reads nothing from the analysis engine and
    /// costs no extra round trips.
    ///
    /// A relationship fits a function when the function's body spans at
    /// least its [`min_lines`](CorrelationRelationship::min_lines) and
    /// carries every [`body_patterns`](CorrelationRelationship::body_patterns)
    /// shape, with `{name}` standing for the function's own name. Where
    /// the relationship demands partner shapes, one of the program
    /// functions its body names must also carry every
    /// [`partner_patterns`](CorrelationRelationship::partner_patterns)
    /// shape in its own body. That partner must itself be in `functions`
    /// and must not be the function itself. The first such partner in
    /// listing order is the partner; a relationship reports once per
    /// function however many partners would fit.
    ///
    /// Each hint is marked [`CrossFunction`](DetectionMethod::CrossFunction)
    /// at [`CROSS_FUNCTION_CONFIDENCE`] — or at the relationship's own
    /// [`confidence`](CorrelationRelationship::confidence) when it
    /// carries one. Its evidence is the hinted body's first line naming
    /// the partner function after the signature line, so the claim
    /// always names the function it was made with. A relationship that
    /// asserts nothing — no body shapes — fits nothing, and a regex that
    /// will not compile can make no claim: it matches nothing.
    ///
    /// Hints follow `functions` order, and within one function the
    /// relationships' configuration order, so two scans of the same
    /// program diff cleanly.
    pub fn detect_correlations(&self, functions: &[DecompiledFunction]) -> Vec<AlgorithmHint> {
        if self.relationships.is_empty() {
            return Vec::new();
        }

        // The call map, derived from the bodies the scan already holds:
        // which program functions each body names.
        let program: HashSet<&str> = functions.iter().map(|f| f.name.as_str()).collect();
        let mentions: HashMap<&str, HashSet<&str>> = functions
            .iter()
            .map(|f| (f.name.as_str(), named_functions(&f.body, &program)))
            .collect();

        let mut hints = Vec::new();
        for func in functions {
            let lines = func.body.lines().count();
            let name = regex::escape(&func.name);
            for relationship in &self.relationships {
                if lines < relationship.min_lines || relationship.body_patterns.is_empty() {
                    continue;
                }
                let fits = relationship.body_patterns.iter().all(|source| {
                    let source = source.replace("{name}", &name);
                    Regex::new(&source).is_ok_and(|shape| shape.is_match(&func.body))
                });
                if !fits {
                    continue;
                }

                // The partner: the relationship's own body shapes prove
                // a self-carried relationship; otherwise a program
                // function the body names must carry the partner shapes
                // in its own body.
                let partner = if relationship.partner_patterns.is_empty() {
                    Some(func.name.as_str())
                } else {
                    let mentioned = mentions.get(func.name.as_str());
                    functions
                        .iter()
                        .find(|candidate| {
                            candidate.name != func.name
                                && mentioned
                                    .is_some_and(|names| names.contains(candidate.name.as_str()))
                                && relationship.partner_patterns.iter().all(|source| {
                                    Regex::new(source)
                                        .is_ok_and(|shape| shape.is_match(&candidate.body))
                                })
                        })
                        .map(|candidate| candidate.name.as_str())
                };
                let Some(partner) = partner else {
                    continue;
                };

                hints.push(AlgorithmHint {
                    function: func.name.clone(),
                    algorithm: relationship.name.clone(),
                    category: relationship.category,
                    method: DetectionMethod::CrossFunction,
                    confidence: Confidence::new(
                        relationship.confidence.unwrap_or(CROSS_FUNCTION_CONFIDENCE),
                    ),
                    evidence: naming_line(&func.body, partner),
                });
            }
        }
        hints
    }
}

// ============================================================
// The standard relationship set
// ============================================================

/// The standard relationships: the cross-function algorithms a scan
/// recognizes out of the box — recursive divide-and-conquer and a sort
/// driven by a comparator callback.
///
/// The set starts small and honest: only relationships the derived call
/// map can actually see.
///
/// The divide-and-conquer relationship demands both halves of the
/// shape: the self-call, spelled with `{name}` — the call shape the
/// recursion signature already reads — and the halving that splits the
/// problem. A plain recursion without those halves stays the control
/// flow set's claim alone.
///
/// The sort relationship demands a call to `qsort` — the host call the
/// C standard library sorts through. That call must name a callee the
/// program itself carries, and the callee's body must compare two
/// pointer touches the way the library demands of its comparator. This
/// is the same comparison shape the callback contracts read, seen from
/// the caller's side.
pub fn default_relationships() -> Vec<CorrelationRelationship> {
    // The comparison between two touched elements the library demands
    // of its comparator. It is the callback contracts' own shape, here
    // read from the callee's body. The `[^-]` guard keeps a field-access
    // arrow from reading as a comparison.
    let element_comparison = r"[*&][^;]*[^-](?:[<>]|==|!=)[^;]*[*&]";

    let divide_and_conquer = CorrelationRelationship::new(
        "divide_and_conquer",
        AlgorithmCategory::Recursion,
        [
            // The self-call — the same call shape the recursion
            // signature reads, `);` keeping the signature line out.
            r"\b{name}\s*\([^;{]*\);",
            // The halving that splits the problem in two. The `\b`
            // guards keep `>> 12` from reading as a halving.
            r"(?:/ 2\b|>> 1\b)",
        ],
    )
    .with_min_lines(8);

    let sort_via_comparator = CorrelationRelationship::new(
        "comparison_sort",
        AlgorithmCategory::Sorting,
        [r"\bqsort\s*\("],
    )
    .with_partner_patterns([element_comparison])
    .with_min_lines(4);

    vec![divide_and_conquer, sort_via_comparator]
}

// ============================================================
// Scanning helpers
// ============================================================

/// Whether `byte` continues an identifier token.
fn is_ident_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

/// The program function names appearing in `body` as whole identifier
/// tokens — called directly or handed to a host as a callback.
fn named_functions<'b>(body: &'b str, program: &HashSet<&str>) -> HashSet<&'b str> {
    let mut found = HashSet::new();
    let bytes = body.as_bytes();
    let mut cursor = 0;
    while cursor < bytes.len() {
        if !is_ident_byte(bytes[cursor]) {
            cursor += 1;
            continue;
        }
        let start = cursor;
        while cursor < bytes.len() && is_ident_byte(bytes[cursor]) {
            cursor += 1;
        }
        let token = &body[start..cursor];
        if program.contains(token) {
            found.insert(token);
        }
    }
    found
}

/// The trimmed body line first naming `partner` as a whole word,
/// searching only past the opening brace. The signature line always
/// carries the function's own name, but never call-shaped, so it must
/// not stand as the evidence of a self-call. If no line past the brace
/// names the partner, this falls back to the first line naming the
/// partner anywhere in the body.
fn naming_line(body: &str, partner: &str) -> String {
    let shape = Regex::new(&format!(r"\b{}\b", regex::escape(partner)));
    let Ok(shape) = shape else {
        return String::new();
    };
    let mut past_brace = false;
    let mut fallback: Option<String> = None;
    for line in body.lines() {
        if !past_brace && line.trim().starts_with('{') {
            past_brace = true;
        }
        if shape.is_match(line) {
            let line = line.trim().to_string();
            if past_brace {
                return line;
            }
            fallback.get_or_insert(line);
        }
    }
    fallback.unwrap_or_default()
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn function(name: &str, signature: &str, body: &str) -> DecompiledFunction {
        DecompiledFunction {
            name: name.to_string(),
            signature: signature.to_string(),
            body: format!("{signature}\n\n{{\n{body}}}\n"),
        }
    }

    /// A recursive halving split: the self-call and the halved range.
    fn recursive(name: &str) -> DecompiledFunction {
        function(
            name,
            "void FUN_180050000(int *param_1,int param_2)",
            &[
                "  int local_14;",
                "  ",
                "  if (param_2 < 2) {",
                "    return;",
                "  }",
                "  local_14 = param_2 / 2;",
                "  FUN_180050000(param_1,local_14);",
                "  FUN_180050000(param_1 + local_14,param_2 - local_14);",
                "  return;",
            ]
            .join("\n"),
        )
    }

    /// A sort driven through `qsort`, naming the comparator it hands the
    /// host.
    fn qsort_caller(comparator: &str) -> DecompiledFunction {
        function(
            "FUN_180050100",
            "void FUN_180050100(int *param_1,int param_2)",
            &format!(
                "  uint uVar2;\n\
                 \x20 \n\
                 \x20 uVar2 = (uint)param_2;\n\
                 \x20 qsort(param_1,uVar2,{comparator});\n\
                 \x20 return;\n"
            ),
        )
    }

    /// A compare callback: the two parameters compared against each
    /// other — the comparator shape.
    fn comparator() -> DecompiledFunction {
        function(
            "FUN_1800412a0",
            "int FUN_1800412a0(int *param_1,int *param_2)",
            &[
                "  if (*param_1 < *param_2) {",
                "    return -1;",
                "  }",
                "  if (*param_2 < *param_1) {",
                "    return 1;",
                "  }",
                "  return 0;",
            ]
            .join("\n"),
        )
    }

    fn relationship(name: &str) -> CorrelationRelationship {
        CorrelationRelationship::new(name, AlgorithmCategory::Sorting, ["qsort"])
    }

    #[test]
    fn a_new_detector_starts_with_no_relationships() {
        // Construction is free: the detector starts empty, compares
        // equal however it is built, and a clone works the same as the
        // original.
        let detector = CrossFunctionDetector::new();
        assert!(detector.relationships().is_empty());
        assert_eq!(detector, CrossFunctionDetector::default());
        assert_eq!(detector.clone(), detector);
    }

    #[test]
    fn a_detector_keeps_the_relationships_it_is_configured_with() {
        let detector = CrossFunctionDetector::with_relationships([
            relationship("divide_and_conquer"),
            relationship("comparison_sort"),
        ]);
        let relationships = detector.relationships();
        assert_eq!(relationships.len(), 2);
        // Configuration order is scan order.
        assert_eq!(relationships[0].name, "divide_and_conquer");
        assert_eq!(relationships[1].name, "comparison_sort");
    }

    #[test]
    fn an_added_relationship_joins_the_set_in_order() {
        let mut detector =
            CrossFunctionDetector::with_relationships([relationship("comparison_sort")]);
        detector.add_relationship(relationship("divide_and_conquer"));
        let names: Vec<&str> = detector
            .relationships()
            .iter()
            .map(|r| r.name.as_str())
            .collect();
        assert_eq!(names, ["comparison_sort", "divide_and_conquer"]);
    }

    #[test]
    fn a_detector_can_be_shared_across_scans() {
        // One detector is driven over a whole program's bodies, so
        // sharing one by reference must stay sound.
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<CrossFunctionDetector>();
    }

    #[test]
    fn a_relationship_serde_round_trips() {
        let relationship = CorrelationRelationship::new(
            "divide_and_conquer",
            AlgorithmCategory::Recursion,
            [r"\b{name}\s*\(", "/ 2"],
        )
        .with_partner_patterns(["if \\("])
        .with_min_lines(8)
        .with_confidence(80);
        let json = serde_json::to_string(&relationship).expect("the relationship serializes");
        let back: CorrelationRelationship =
            serde_json::from_str(&json).expect("the serialized relationship reads back");
        assert_eq!(back, relationship);
        assert_eq!(back.confidence, Some(80));
    }

    #[test]
    fn a_relationship_without_optional_fields_omits_them_and_reads_back_with_defaults() {
        let json = serde_json::to_string(&relationship("comparison_sort"))
            .expect("the relationship serializes");
        assert!(!json.contains("partner_patterns"));
        assert!(!json.contains("confidence"));
        let back: CorrelationRelationship =
            serde_json::from_str(&json).expect("the relationship reads back");
        assert!(back.partner_patterns.is_empty());
        assert_eq!(back.min_lines, CorrelationRelationship::DEFAULT_MIN_LINES);
        assert_eq!(back.confidence, None);
    }

    #[test]
    fn a_self_call_beside_a_split_yields_a_divide_and_conquer_hint() {
        let detector = CrossFunctionDetector::with_default_relationships();
        let hints = detector.detect_correlations(&[recursive("FUN_180050000")]);
        assert_eq!(hints.len(), 1);
        let hint = &hints[0];
        assert_eq!(hint.function, "FUN_180050000");
        assert_eq!(hint.algorithm, "divide_and_conquer");
        assert_eq!(hint.category, AlgorithmCategory::Recursion);
        assert_eq!(hint.method, DetectionMethod::CrossFunction);
        assert_eq!(hint.confidence, Confidence::new(CROSS_FUNCTION_CONFIDENCE));
        // The evidence is the self-call line — naming the partner,
        // which for a recursion is the function itself.
        assert_eq!(hint.evidence, "FUN_180050000(param_1,local_14);");
    }

    #[test]
    fn a_host_call_beside_a_comparator_callee_yields_a_sort_hint() {
        let detector = CrossFunctionDetector::with_default_relationships();
        let hints = detector.detect_correlations(&[qsort_caller("FUN_1800412a0"), comparator()]);
        let sort: Vec<&AlgorithmHint> = hints
            .iter()
            .filter(|hint| hint.function == "FUN_180050100")
            .collect();
        assert_eq!(sort.len(), 1);
        let hint = sort[0];
        assert_eq!(hint.algorithm, "comparison_sort");
        assert_eq!(hint.category, AlgorithmCategory::Sorting);
        assert_eq!(hint.method, DetectionMethod::CrossFunction);
        assert_eq!(hint.confidence, Confidence::new(CROSS_FUNCTION_CONFIDENCE));
        // The evidence names the partner function the claim rests on.
        assert_eq!(hint.evidence, "qsort(param_1,uVar2,FUN_1800412a0);");
    }

    #[test]
    fn a_self_call_without_a_split_claims_no_divide_and_conquer() {
        // Plain recursion stays the control flow set's claim alone:
        // without the halving shape, the correlation relationship
        // rejects the body.
        let plain = function(
            "FUN_180050000",
            "void FUN_180050000(int *param_1,int param_2)",
            &[
                "  if (param_2 < 2) {",
                "    return;",
                "  }",
                "  FUN_180050000(param_1 + 1,param_2 - 1);",
                "  return;",
            ]
            .join("\n"),
        );
        let detector = CrossFunctionDetector::with_default_relationships();
        assert!(detector.detect_correlations(&[plain]).is_empty());
    }

    #[test]
    fn a_shift_beyond_one_bit_is_no_halving() {
        // `>> 12` divides by 4096, not two: the word-boundary guard
        // keeps a wide shift from reading as the split shape.
        let wide = function(
            "FUN_180050000",
            "void FUN_180050000(int *param_1,int param_2)",
            &[
                "  if (param_2 < 2) {",
                "    return;",
                "  }",
                "  FUN_180050000(param_1,param_2 >> 12);",
                "  return;",
            ]
            .join("\n"),
        );
        let detector = CrossFunctionDetector::with_default_relationships();
        assert!(detector.detect_correlations(&[wide]).is_empty());
    }

    #[test]
    fn a_qsort_call_naming_no_comparator_callee_claims_no_sort() {
        // The comparator must be a program function the scan decompiled
        // with a comparator-shaped body — an unnamed or unread partner
        // lends nothing.
        let unnamed = qsort_caller("compare_fn");
        let detector = CrossFunctionDetector::with_default_relationships();
        assert!(
            detector
                .detect_correlations(&[unnamed, comparator()])
                .is_empty()
        );
    }

    #[test]
    fn a_callee_without_the_comparator_shape_claims_no_sort() {
        let not_a_comparator = function(
            "FUN_1800412a0",
            "void FUN_1800412a0(int *param_1,int *param_2)",
            &[
                "  *param_1 = *param_1 + 1;",
                "  *param_2 = *param_2 + 1;",
                "  return;",
            ]
            .join("\n"),
        );
        let detector = CrossFunctionDetector::with_default_relationships();
        let hints =
            detector.detect_correlations(&[qsort_caller("FUN_1800412a0"), not_a_comparator]);
        assert!(hints.is_empty());
    }

    #[test]
    fn the_standard_set_stays_quiet_about_unrelated_functions() {
        // Bodies that call nothing, and a comparator nobody calls
        // through a host, claim nothing.
        let detector = CrossFunctionDetector::with_default_relationships();
        let hints = detector.detect_correlations(&[comparator()]);
        assert!(hints.is_empty());
    }

    #[test]
    fn a_relationship_with_no_body_patterns_claims_nothing() {
        let detector = CrossFunctionDetector::with_relationships([CorrelationRelationship::new(
            "nothing",
            AlgorithmCategory::Sorting,
            Vec::<String>::new(),
        )]);
        assert!(
            detector
                .detect_correlations(&[recursive("FUN_180050000")])
                .is_empty()
        );
    }

    #[test]
    fn an_uncompilable_regex_claims_nothing() {
        let detector = CrossFunctionDetector::with_relationships([CorrelationRelationship::new(
            "broken",
            AlgorithmCategory::Sorting,
            ["qsort(", r"(?:/ 2\b|>> 1"],
        )]);
        assert!(
            detector
                .detect_correlations(&[qsort_caller("FUN_1800412a0"), comparator()])
                .is_empty()
        );
    }

    #[test]
    fn an_uncompilable_partner_pattern_claims_nothing() {
        // A broken partner shape matches nothing, so no partner fits
        // and the relationship makes no claim. The lenient rule cannot
        // fabricate a match in either direction.
        let detector = CrossFunctionDetector::with_relationships([CorrelationRelationship::new(
            "sort",
            AlgorithmCategory::Sorting,
            [r"\bqsort\s*\("],
        )
        .with_min_lines(4)
        .with_partner_patterns(["("])]);
        assert!(
            detector
                .detect_correlations(&[qsort_caller("FUN_1800412a0"), comparator()])
                .is_empty()
        );
    }

    #[test]
    fn the_name_placeholder_names_the_scanned_function() {
        let detector = CrossFunctionDetector::with_relationships([CorrelationRelationship::new(
            "self_starter",
            AlgorithmCategory::Recursion,
            [r"\b{name}\s*\("],
        )
        .with_min_lines(4)]);
        let hints = detector.detect_correlations(&[recursive("FUN_180050000")]);
        assert_eq!(hints.len(), 1);
        // The evidence skips the signature line — the name appears
        // there too, but never call-shaped.
        assert_eq!(hints[0].evidence, "FUN_180050000(param_1,local_14);");
    }

    #[test]
    fn a_relationship_reports_once_however_many_partners_fit() {
        // The caller names two comparator-shaped program functions; the
        // relationship still claims once, and the first fitting partner
        // in listing order is the one the evidence names.
        let caller = function(
            "FUN_180050100",
            "void FUN_180050100(int *param_1,int param_2)",
            &[
                "  uint uVar2;",
                "  ",
                "  uVar2 = (uint)param_2;",
                "  qsort(param_1,uVar2,FUN_1800412a0);",
                "  qsort(param_1,uVar2,FUN_180041300);",
                "  return;",
            ]
            .join("\n"),
        );
        let second = function(
            "FUN_180041300",
            "int FUN_180041300(int *param_1,int *param_2)",
            "  if (*param_1 < *param_2) {\n    return -1;\n  }\n  return 0;\n",
        );
        let detector = CrossFunctionDetector::with_default_relationships();
        let hints = detector.detect_correlations(&[caller, comparator(), second]);
        let sort: Vec<&AlgorithmHint> = hints
            .iter()
            .filter(|hint| hint.algorithm == "comparison_sort")
            .collect();
        assert_eq!(sort.len(), 1);
        assert_eq!(sort[0].evidence, "qsort(param_1,uVar2,FUN_1800412a0);");
    }

    #[test]
    fn hints_follow_function_and_relationship_order() {
        // One body fitting both built-in relationships reports them in
        // the relationships' configuration order.
        let both = function(
            "FUN_180050000",
            "void FUN_180050000(int *param_1,int param_2)",
            &[
                "  int local_14;",
                "  ",
                "  if (param_2 < 2) {",
                "    return;",
                "  }",
                "  local_14 = param_2 / 2;",
                "  FUN_180050000(param_1,local_14);",
                "  qsort(param_1,local_14,FUN_1800412a0);",
                "  return;",
            ]
            .join("\n"),
        );
        let detector = CrossFunctionDetector::with_default_relationships();
        let hints = detector.detect_correlations(&[both, comparator()]);
        let algorithms: Vec<&str> = hints.iter().map(|hint| hint.algorithm.as_str()).collect();
        assert_eq!(algorithms, ["divide_and_conquer", "comparison_sort"]);
    }

    #[test]
    fn the_line_floor_refuses_a_body_too_small_for_a_relationship() {
        let tiny = function(
            "FUN_180050000",
            "void FUN_180050000(int param_1)",
            "  param_1 = param_1 / 2;\n  FUN_180050000(param_1);\n",
        );
        let detector = CrossFunctionDetector::with_default_relationships();
        assert!(
            detector.detect_correlations(&[tiny]).is_empty(),
            "the divide-and-conquer floor is 8 lines"
        );
    }

    #[test]
    fn a_per_entry_confidence_is_paid_instead_of_the_standard_score() {
        let detector = CrossFunctionDetector::with_relationships([CorrelationRelationship::new(
            "divide_and_conquer",
            AlgorithmCategory::Recursion,
            [r"\b{name}\s*\([^;{]*\);", r"(?:/ 2\b|>> 1)"],
        )
        .with_min_lines(8)
        .with_confidence(90)]);
        let hints = detector.detect_correlations(&[recursive("FUN_180050000")]);
        assert_eq!(hints[0].confidence, Confidence::new(90));
    }

    #[test]
    fn the_standard_set_carries_the_two_built_in_relationships() {
        let relationships = default_relationships();
        let names: Vec<&str> = relationships.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(names, ["divide_and_conquer", "comparison_sort"]);
    }

    #[test]
    fn a_detector_built_with_the_standard_set_matches_against_it() {
        let detector = CrossFunctionDetector::with_default_relationships();
        assert_eq!(detector.relationships(), default_relationships());
    }
}
