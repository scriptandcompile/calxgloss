//! Core data types for recognized algorithm information.
//!
//! This module holds the serialized shape of everything the recognition
//! detectors produce:
//!
//! - `AlgorithmHint`, `AlgorithmCategory`, `DetectionMethod`,
//!   `AlgorithmPattern`: per-function detection records — the recognized
//!   algorithm and its category, which detector produced the hint, and
//!   the pattern behind the match.
//! - `AlgorithmRecognitionResult`, `ScanMetadata`: the persisted
//!   per-binary result and its scan provenance.
//!
//! All types derive `Serialize`/`Deserialize`.

// `ScanMetadata` is the shared per-binary scan provenance and `Confidence`
// the shared 0–100 evidence score; both are re-exported so consumers name
// them through this crate, matching the typesdb and typeinfer convention.
pub use calxgloss_types::{Confidence, ScanMetadata};
use serde::{Deserialize, Serialize};

// ============================================================
// Algorithm category
// ============================================================

/// The high-level family a recognized algorithm belongs to.
///
/// The category tells a translation prompt what kind of behavior the
/// function implements — a sort is rewritten differently than a hash
/// lookup or a state machine — and lets detectors reading different
/// evidence classes converge on the same family: a qsort-style compare
/// callback and a nested-loop swap both say `Sorting`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlgorithmCategory {
    /// Ordering elements by comparison — nested-loop and swap shapes,
    /// qsort-style compare callbacks.
    Sorting,
    /// Finding an element in a collection — binary search, linear scan,
    /// bsearch-style compare callbacks.
    Searching,
    /// Mixing data into a digest for lookup — hash table probes and
    /// comparators, md5/sha/hmac.
    Hashing,
    /// Error-detection digests — CRC and checksum loops.
    Checksum,
    /// Encoding data smaller — inflate, deflate, gzip, bz2, lzo.
    Compression,
    /// Converting structures to and from byte streams — serialize and
    /// deserialize shapes.
    Serialization,
    /// Reading structured text or binary input.
    Parsing,
    /// A variable tracking state with explicit transitions across an
    /// if-else or switch chain.
    StateMachine,
    /// Walking a linked or graph structure through next/child pointers.
    Traversal,
    /// A function calling itself — the translation should mirror the
    /// recursion or unroll it onto an explicit stack.
    Recursion,
    /// Protocol handling — http, tcp, udp string signatures.
    NetworkProtocol,
}

calxgloss_types::display_serde_label!(AlgorithmCategory {
    Sorting => "sorting",
    Searching => "searching",
    Hashing => "hashing",
    Checksum => "checksum",
    Compression => "compression",
    Serialization => "serialization",
    Parsing => "parsing",
    StateMachine => "state_machine",
    Traversal => "traversal",
    Recursion => "recursion",
    NetworkProtocol => "network_protocol",
});

// ============================================================
// Detection method
// ============================================================

/// The detector that produced a hint.
///
/// Each detector reads a different evidence class — control flow shapes,
/// string signatures, callback contracts — and the method says how a hint
/// was made, so confidence resolution and the prompt rendering can weigh
/// and explain hints by their evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectionMethod {
    /// A control flow signature matched the decompiled body.
    CfgPattern,
    /// A string signature appeared in the body or the binary's string
    /// listing — "CRC", "inflate", "md5".
    StringHint,
    /// The function's signature and usage match a known callback contract,
    /// e.g. a qsort compare function.
    CallbackPattern,
}

calxgloss_types::display_serde_label!(DetectionMethod {
    CfgPattern => "cfg_pattern",
    StringHint => "string_hint",
    CallbackPattern => "callback_pattern",
});

// ============================================================
// Control flow patterns
// ============================================================

/// One control flow signature the cfg matcher scans decompiled bodies
/// against — a named bundle of regexes with the line-count floor that
/// keeps it honest.
///
/// A pattern recognizes exactly one algorithm: its [`name`](Self::name)
/// and [`category`](Self::category) are what a hint records when the
/// pattern matches. The body must carry every regex in
/// [`match_patterns`](Self::match_patterns) and none in
/// [`exclude_patterns`](Self::exclude_patterns), and must span at least
/// [`min_lines`](Self::min_lines) lines — tiny functions accidentally fit
/// broad shapes, so the floor refuses them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AlgorithmPattern {
    /// The algorithm this pattern recognizes, e.g. `comparison_sort`.
    pub name: String,
    /// The family the recognized algorithm belongs to.
    pub category: AlgorithmCategory,
    /// Regex sources, all of which must match the decompiled body. A
    /// source may carry the `{name}` placeholder, which the matcher
    /// replaces with the scanned function's name, letting a signature
    /// speak of the function itself.
    pub match_patterns: Vec<String>,
    /// Regex sources, any of which rejects the match when it appears in
    /// the body — shapes that make the matched signature read differently.
    /// A source may carry the same `{name}` placeholder.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exclude_patterns: Vec<String>,
    /// Minimum number of body lines for the pattern to be considered.
    #[serde(default)]
    pub min_lines: usize,
}

impl AlgorithmPattern {
    /// The default line-count floor: a body shorter than this is too small
    /// to carry a real control flow signature.
    pub const DEFAULT_MIN_LINES: usize = 10;

    /// A pattern named `name` in `category` requiring every one of
    /// `match_patterns`, with no exclusions and the default line-count
    /// floor.
    pub fn new(
        name: impl Into<String>,
        category: AlgorithmCategory,
        match_patterns: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self {
            name: name.into(),
            category,
            match_patterns: match_patterns.into_iter().map(Into::into).collect(),
            exclude_patterns: Vec::new(),
            min_lines: Self::DEFAULT_MIN_LINES,
        }
    }
}

// ============================================================
// Algorithm hints
// ============================================================

/// One recognized algorithm in one function, with the evidence behind it.
///
/// A hint is a hypothesis, not a fact applied to the program: it says the
/// decompiled body *reads like* a known algorithm, and the method,
/// confidence, and evidence together say how strongly. Detectors emit
/// these records; confidence resolution keeps the strongest hints per
/// function, and the survivors are persisted and rendered into
/// translation prompts as the high-level specification to target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AlgorithmHint {
    /// The function the hint is about, e.g. `FUN_18003ab00`.
    pub function: String,
    /// The recognized algorithm, e.g. `comparison_sort`, `crc32` — for a
    /// cfg match, the name of the pattern that matched.
    pub algorithm: String,
    /// The family the recognized algorithm belongs to.
    pub category: AlgorithmCategory,
    /// The detector that produced the hint.
    pub method: DetectionMethod,
    /// Confidence that the hint is right, 0–100.
    pub confidence: Confidence,
    /// The decompiled line, string, or signature that supports the hint —
    /// kept so a reviewer (or a translation prompt) can check the
    /// reasoning.
    pub evidence: String,
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    const ALL_CATEGORIES: [AlgorithmCategory; 11] = [
        AlgorithmCategory::Sorting,
        AlgorithmCategory::Searching,
        AlgorithmCategory::Hashing,
        AlgorithmCategory::Checksum,
        AlgorithmCategory::Compression,
        AlgorithmCategory::Serialization,
        AlgorithmCategory::Parsing,
        AlgorithmCategory::StateMachine,
        AlgorithmCategory::Traversal,
        AlgorithmCategory::Recursion,
        AlgorithmCategory::NetworkProtocol,
    ];

    const ALL_METHODS: [DetectionMethod; 3] = [
        DetectionMethod::CfgPattern,
        DetectionMethod::StringHint,
        DetectionMethod::CallbackPattern,
    ];

    fn hint() -> AlgorithmHint {
        AlgorithmHint {
            function: "FUN_18003ab00".into(),
            algorithm: "comparison_sort".into(),
            category: AlgorithmCategory::Sorting,
            method: DetectionMethod::CfgPattern,
            confidence: Confidence::new(75),
            evidence: "for (local_10 = 0; local_10 < uVar2; local_10 = local_10 + 1)".into(),
        }
    }

    #[test]
    fn an_algorithm_hint_serde_round_trips() {
        let record = hint();
        let json = serde_json::to_string(&record).unwrap();
        // Categories and methods serialize snake_case, matching the
        // workspace's serde convention.
        assert!(json.contains("\"category\":\"sorting\""));
        assert!(json.contains("\"method\":\"cfg_pattern\""));
        assert!(json.contains("\"confidence\":75"));
        let back: AlgorithmHint = serde_json::from_str(&json).unwrap();
        assert_eq!(back, record);
    }

    #[test]
    fn categories_and_methods_display_their_serde_labels() {
        for category in ALL_CATEGORIES {
            let label = serde_json::to_value(category).unwrap();
            assert_eq!(category.to_string(), label.as_str().unwrap());
        }
        for method in ALL_METHODS {
            let label = serde_json::to_value(method).unwrap();
            assert_eq!(method.to_string(), label.as_str().unwrap());
        }
        assert_eq!(AlgorithmCategory::StateMachine.to_string(), "state_machine");
        assert_eq!(
            AlgorithmCategory::NetworkProtocol.to_string(),
            "network_protocol"
        );
        assert_eq!(DetectionMethod::StringHint.to_string(), "string_hint");
    }

    #[test]
    fn an_algorithm_pattern_serde_round_trips_and_omits_its_exclusions() {
        let pattern = AlgorithmPattern::new(
            "binary_search",
            AlgorithmCategory::Searching,
            ["/ 2", "if (", "<"],
        );
        let json = serde_json::to_string(&pattern).unwrap();
        assert!(!json.contains("\"exclude_patterns\""));
        let back: AlgorithmPattern = serde_json::from_str(&json).unwrap();
        assert_eq!(back, pattern);
    }

    #[test]
    fn a_pattern_without_optional_fields_reads_back_with_defaults() {
        // Documents persisted before a field existed still load.
        let json = r#"{
            "name": "linear_search",
            "category": "searching",
            "match_patterns": ["while (", "=="]
        }"#;
        let back: AlgorithmPattern = serde_json::from_str(json).unwrap();
        assert_eq!(back.category, AlgorithmCategory::Searching);
        assert!(back.exclude_patterns.is_empty());
        assert_eq!(back.min_lines, 0);
    }

    #[test]
    fn a_new_pattern_starts_with_no_exclusions_and_the_default_floor() {
        let pattern =
            AlgorithmPattern::new("hash_table_lookup", AlgorithmCategory::Hashing, ["% ", "["]);
        assert_eq!(pattern.name, "hash_table_lookup");
        assert_eq!(pattern.category, AlgorithmCategory::Hashing);
        assert_eq!(pattern.match_patterns, vec!["% ", "["]);
        assert!(pattern.exclude_patterns.is_empty());
        assert_eq!(pattern.min_lines, AlgorithmPattern::DEFAULT_MIN_LINES);
    }

    #[test]
    fn a_pattern_carries_its_exclusions_and_floor_through_json() {
        let pattern = AlgorithmPattern {
            exclude_patterns: vec!["\\bqsort\\b".into()],
            min_lines: 20,
            ..AlgorithmPattern::new("comparison_sort", AlgorithmCategory::Sorting, ["<", "swap"])
        };
        let json = serde_json::to_string(&pattern).unwrap();
        let back: AlgorithmPattern = serde_json::from_str(&json).unwrap();
        assert_eq!(back, pattern);
        assert_eq!(back.exclude_patterns, vec!["\\bqsort\\b"]);
        assert_eq!(back.min_lines, 20);
    }
}
