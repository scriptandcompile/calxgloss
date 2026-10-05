//! Callback pattern detection.
//!
//! This module provides [`CallbackPatternDb`], which carries the
//! callback contracts — a known host function and the shape of the
//! callback it takes — that analyzed functions are matched against,
//! recognizing the functions that serve as callbacks rather than
//! ordinary callees: qsort compare, bsearch compare, hash table
//! comparator.
//!
//! Each contract is a [`CallbackPattern`]: a named role, the host
//! names that take the callback (matched against caller names through
//! the call graph), the arity the contract expects, the body shapes
//! the callback must carry, and the [`TypeHint`]s the contract
//! implies for the callback's own signature — a qsort compare
//! callback's parameters are element pointers and its return an
//! ordering integer, so recognizing the role types the function
//! beside naming its algorithm.
//!
//! The contract set is configurable — supplied whole through
//! [`with_patterns`](CallbackPatternDb::with_patterns) or grown one at
//! a time with [`add_pattern`](CallbackPatternDb::add_pattern) — and
//! reported in configuration order, so two databases built the same
//! way scan identically and results diff cleanly.
//!
//! [`default_patterns`] carries the standard contract set — qsort
//! compare, bsearch compare, hash table comparator — and
//! [`CallbackPatternDb::with_default_patterns`] builds a database that
//! scans against it.
//!
//! The usage half of a detection runs through
//! [`match_callers`](CallbackPatternDb::match_callers): handed the
//! analyzed function's caller names — read from the call graph — it
//! reports the contracts whose hosts reach the function, the evidence
//! that it serves a callback role rather than an ordinary callee.
//!
//! The full detection runs through
//! [`detect_callback_patterns`](CallbackPatternDb::detect_callback_patterns):
//! handed the analyzed function beside its caller names, it reports
//! each contract the function fits on both halves at once — its own
//! signature (the contract's arity and body shapes) and its usage (a
//! host reaching it) — as a [`CallbackDetection`] pairing the
//! [`AlgorithmHint`] naming the role with the contract whose type
//! hints the fit carries over to the function's signature.

use crate::types::{AlgorithmCategory, AlgorithmHint, DetectionMethod};
use calxgloss_ghidra::DecompiledFunction;
use calxgloss_types::Confidence;
use regex::Regex;
use serde::{Deserialize, Serialize};

// ============================================================
// Detection confidence
// ============================================================

/// Confidence of a callback detection: two independent signals agree —
/// the call graph shows one of the contract's hosts reaching the
/// function, and the function's own signature fits the contract's
/// arity and body shapes. A call-graph edge from a host like `qsort`
/// is close to proof that the function is the callback that host was
/// handed, but the reading still rests on regexes over decompiled
/// pseudo-C rather than a resolved indirect-call target, so it stands
/// above a lone control flow or string match and below a direct
/// vtable dispatch.
const CALLBACK_CONFIDENCE: u8 = 75;

// ============================================================
// Type hints
// ============================================================

/// Which position of a callback's own signature a [`TypeHint`] types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TypeTarget {
    /// The callback's return value.
    Return,
    /// The callback's parameter at this index (0-based).
    Param(usize),
}

/// A type the callback contract implies for one position of the
/// callback's signature.
///
/// A contract states its callback's signature — a qsort compare
/// callback takes two element pointers and returns an ordering
/// integer — so recognizing the role types the analyzed function's
/// parameters and return beside naming its algorithm, without a
/// separate inference pass.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TypeHint {
    /// Which position of the callback's signature this types.
    pub target: TypeTarget,
    /// The suggested type in its C spelling, e.g. `const void *`.
    pub suggested_type: String,
}

impl TypeHint {
    /// A hint typing the callback's parameter at `index` (0-based) as
    /// `type_name`.
    pub fn param(index: usize, type_name: impl Into<String>) -> Self {
        Self {
            target: TypeTarget::Param(index),
            suggested_type: type_name.into(),
        }
    }

    /// A hint typing the callback's return value as `type_name`.
    pub fn return_value(type_name: impl Into<String>) -> Self {
        Self {
            target: TypeTarget::Return,
            suggested_type: type_name.into(),
        }
    }
}

// ============================================================
// Callback contracts
// ============================================================

/// One callback contract: a known host function and the shape of the
/// callback it takes.
///
/// A pattern recognizes exactly one callback role: its
/// [`name`](Self::name) and [`category`](Self::category) are what a
/// detection records when the pattern fits. A function serves the
/// role when its own signature fits the contract — it takes
/// [`param_count`](Self::param_count) parameters and its body carries
/// every shape in [`body_patterns`](Self::body_patterns) — and it is
/// used as a callback: a caller matching one of
/// [`host_patterns`](Self::host_patterns) reaches it through the call
/// graph. The [`type_hints`](Self::type_hints) are the types the
/// contract implies for the callback's signature, which a fit carries
/// over to the analyzed function.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallbackPattern {
    /// The callback role this pattern recognizes, e.g. `qsort_compare`.
    pub name: String,
    /// The family of the host algorithm — the family the detected
    /// callback participates in.
    pub category: AlgorithmCategory,
    /// Regex sources matched against caller names: the host functions
    /// that take this callback, e.g. `\bqsort\b`. A function reached
    /// by one of these hosts reads as its callback.
    pub host_patterns: Vec<String>,
    /// The number of parameters the contract expects — a compare
    /// callback takes the two elements being compared.
    pub param_count: usize,
    /// Regex sources the callback's body must carry — the behavior the
    /// contract demands of its callback, e.g. the two parameters
    /// compared against each other.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub body_patterns: Vec<String>,
    /// The types the contract implies for the callback's signature.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub type_hints: Vec<TypeHint>,
}

impl CallbackPattern {
    /// A contract named `name` in `category` for callbacks taken by
    /// hosts whose names match `host_patterns` and taking `param_count`
    /// parameters, with no required body shapes and no type hints.
    pub fn new(
        name: impl Into<String>,
        category: AlgorithmCategory,
        host_patterns: impl IntoIterator<Item = impl Into<String>>,
        param_count: usize,
    ) -> Self {
        Self {
            name: name.into(),
            category,
            host_patterns: host_patterns.into_iter().map(Into::into).collect(),
            param_count,
            body_patterns: Vec::new(),
            type_hints: Vec::new(),
        }
    }

    /// A contract whose callback's body must carry every one of
    /// `patterns` — the behavior the contract demands.
    pub fn body_patterns(mut self, patterns: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.body_patterns = patterns.into_iter().map(Into::into).collect();
        self
    }

    /// A contract carrying `hints` as the types it implies for the
    /// callback's signature.
    pub fn type_hints(mut self, hints: impl IntoIterator<Item = TypeHint>) -> Self {
        self.type_hints = hints.into_iter().collect();
        self
    }
}

// ============================================================
// Caller matching
// ============================================================

/// A contract the analyzed function is used as a callback for, and the
/// caller that uses it that way.
///
/// The pair is the usage half of a detection: the contract names the
/// role the function serves, and the caller name is the evidence — the
/// host that reaches the function through the call graph, kept so a
/// detection can report *why* the function reads as this callback's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostMatch<'a> {
    /// The contract the function's usage fits.
    pub pattern: &'a CallbackPattern,
    /// The caller name that matched one of the contract's
    /// [`host_patterns`](CallbackPattern::host_patterns).
    pub caller: String,
}

// ============================================================
// Detections
// ============================================================

/// A function recognized as a callback: the hint naming the role it
/// serves, and the contract it fits.
///
/// The pair is a full detection. The [`hint`](Self::hint) is the
/// shared record — the recognized role, its category, and the host
/// that reaches the function as its evidence — and the
/// [`pattern`](Self::pattern) is the contract behind it, whose
/// [`type_hints`](CallbackPattern::type_hints) the fit carries over to
/// the analyzed function's own signature: recognizing a qsort compare
/// callback types its parameters `const void *` and its return `int`
/// beside naming its algorithm.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallbackDetection<'a> {
    /// The recognized role, as the shared hint record a scan persists.
    pub hint: AlgorithmHint,
    /// The contract the function's signature and usage fit.
    pub pattern: &'a CallbackPattern,
}

// ============================================================
// Database
// ============================================================

/// Callback contract matching over analyzed functions.
///
/// The database owns the contract set a scan reads functions against:
/// [`CallbackPattern`] records supplied whole through
/// [`with_patterns`](Self::with_patterns) or grown one at a time with
/// [`add_pattern`](Self::add_pattern), and [`patterns`](Self::patterns)
/// reports the set in configuration order, so two databases built the
/// same way scan identically and results diff cleanly. The database
/// holds no Ghidra client of its own and never writes back to the
/// program; one database serves an entire scan and can be shared by
/// reference across concurrent per-function passes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CallbackPatternDb {
    patterns: Vec<CallbackPattern>,
}

impl CallbackPatternDb {
    /// A database with no contracts configured: nothing is recognized
    /// until a contract set arrives through
    /// [`with_patterns`](Self::with_patterns) or contracts join one at
    /// a time through [`add_pattern`](Self::add_pattern).
    pub fn new() -> Self {
        Self::default()
    }

    /// A database that scans against the standard contract set —
    /// [`default_patterns`] — in its configuration order.
    pub fn with_default_patterns() -> Self {
        Self::with_patterns(default_patterns())
    }

    /// A database that scans against exactly `patterns`, kept in the
    /// order they are given.
    pub fn with_patterns(patterns: impl IntoIterator<Item = CallbackPattern>) -> Self {
        Self {
            patterns: patterns.into_iter().collect(),
        }
    }

    /// Add one contract to the set this database scans against.
    pub fn add_pattern(&mut self, pattern: CallbackPattern) {
        self.patterns.push(pattern);
    }

    /// The contracts this database scans against, in configuration
    /// order.
    pub fn patterns(&self) -> &[CallbackPattern] {
        &self.patterns
    }

    /// Match the analyzed function's caller names against every
    /// configured contract's host patterns, in configuration order, and
    /// report each contract the function is used as a callback for.
    ///
    /// The caller names are read from the call graph — the functions
    /// that reach the analyzed one — and a contract matches when any
    /// caller name carries a match for any of its
    /// [`host_patterns`](CallbackPattern::host_patterns): being reached
    /// by one of the hosts that take this callback is what separates a
    /// callback from an ordinary callee. A contract reports once,
    /// however many callers fit it, and the first caller name that
    /// matched stands as the evidence. A contract with no host patterns
    /// claims nothing, and a host pattern that will not compile can
    /// make no claim: it matches nothing.
    pub fn match_callers(
        &self,
        caller_names: impl IntoIterator<Item = impl AsRef<str>>,
    ) -> Vec<HostMatch<'_>> {
        let callers: Vec<String> = caller_names
            .into_iter()
            .map(|name| name.as_ref().to_string())
            .collect();
        let mut matches = Vec::new();
        for pattern in &self.patterns {
            let shapes: Vec<Regex> = pattern
                .host_patterns
                .iter()
                .filter_map(|source| Regex::new(source).ok())
                .collect();
            for caller in &callers {
                if shapes.iter().any(|shape| shape.is_match(caller)) {
                    matches.push(HostMatch {
                        pattern,
                        caller: caller.clone(),
                    });
                    break;
                }
            }
        }
        matches
    }

    /// Detect the callback contracts the analyzed function serves,
    /// matching its own signature and its usage together.
    ///
    /// A contract fits when both halves agree. The signature half: the
    /// function takes exactly the contract's
    /// [`param_count`](CallbackPattern::param_count) parameters — the
    /// arity Ghidra's inferred signature carries — and its body
    /// carries a match for every
    /// [`body_patterns`](CallbackPattern::body_patterns) shape, the
    /// behavior the contract demands of its callback; a contract
    /// requiring no body shape fits on signature and usage alone. The
    /// usage half: a caller matching one of the contract's host
    /// patterns reaches the function through the call graph — the
    /// same reading [`match_callers`](Self::match_callers) reports,
    /// and the matched caller name stands as the hint's evidence.
    ///
    /// Each fit is reported in configuration order as a
    /// [`CallbackDetection`]: an [`AlgorithmHint`] marked
    /// [`CallbackPattern`](DetectionMethod::CallbackPattern) at
    /// [`CALLBACK_CONFIDENCE`], naming the contract and its category,
    /// beside the contract itself, whose
    /// [`type_hints`](CallbackPattern::type_hints) the fit carries
    /// over to the function's signature. A contract whose hosts never
    /// reach the function claims nothing, a function of the wrong
    /// arity fits no contract, and a body pattern that will not
    /// compile can make no claim: it matches nothing.
    pub fn detect_callback_patterns(
        &self,
        func: &DecompiledFunction,
        caller_names: impl IntoIterator<Item = impl AsRef<str>>,
    ) -> Vec<CallbackDetection<'_>> {
        let arity = func.parameter_names().len();
        let mut detections = Vec::new();
        for host in self.match_callers(caller_names) {
            let pattern = host.pattern;
            if arity != pattern.param_count {
                continue;
            }
            let fits = pattern
                .body_patterns
                .iter()
                .all(|source| Regex::new(source).is_ok_and(|shape| shape.is_match(&func.body)));
            if !fits {
                continue;
            }
            detections.push(CallbackDetection {
                hint: AlgorithmHint {
                    function: func.name.clone(),
                    algorithm: pattern.name.clone(),
                    category: pattern.category,
                    method: DetectionMethod::CallbackPattern,
                    confidence: Confidence::new(CALLBACK_CONFIDENCE),
                    evidence: host.caller,
                },
                pattern,
            });
        }
        detections
    }
}

// ============================================================
// The standard contract set
// ============================================================

/// The standard callback contracts: the roles a scan recognizes out of
/// the box — qsort compare, bsearch compare, and hash table
/// comparator.
///
/// Each contract reads what the host actually demands of its callback.
/// The C standard library hands its compare callbacks the two elements
/// being compared as opaque pointers and takes an ordering integer
/// back, so both compare contracts demand a comparison between two
/// pointer touches in the body; a hash table's comparator answers
/// equality rather than ordering, and is reached through the
/// insert/lookup helpers that probe a bucket. The host names are
/// word-anchored so the caller reads as the host itself — the import
/// symbol appearing in the call graph — and a name that merely
/// carries the host's letters stays outside: `qsort_s`'s callback
/// takes a context parameter the two-parameter contract does not
/// expect.
pub fn default_patterns() -> Vec<CallbackPattern> {
    // The comparison between the two compared elements: a pointer
    // touch, an ordering or equality operator inside the same
    // statement, another pointer touch. The `[^-]` guard keeps a
    // field-access arrow — `p->next`, whose `>` is no comparison —
    // from reading as one.
    let element_comparison = r"[*&][^;]*[^-](?:[<>]|==|!=)[^;]*[*&]";
    // The equality test a hash comparator answers with: the same
    // shape, narrowed to `==`.
    let element_equality = r"[*&][^;]*[^-]==[^;]*[*&]";

    let qsort_compare = CallbackPattern::new(
        "qsort_compare",
        AlgorithmCategory::Sorting,
        [r"\bqsort\b"],
        2,
    )
    .body_patterns([element_comparison])
    .type_hints([
        TypeHint::param(0, "const void *"),
        TypeHint::param(1, "const void *"),
        TypeHint::return_value("int"),
    ]);

    let bsearch_compare = CallbackPattern::new(
        "bsearch_compare",
        AlgorithmCategory::Searching,
        [r"\bbsearch\b"],
        2,
    )
    .body_patterns([element_comparison])
    .type_hints([
        TypeHint::param(0, "const void *"),
        TypeHint::param(1, "const void *"),
        TypeHint::return_value("int"),
    ]);

    let hash_comparator = CallbackPattern::new(
        "hash_comparator",
        AlgorithmCategory::Hashing,
        [r"\bhash_(?:insert|lookup|find|add)\b"],
        2,
    )
    .body_patterns([element_equality])
    .type_hints([
        TypeHint::param(0, "const void *"),
        TypeHint::param(1, "const void *"),
        TypeHint::return_value("int"),
    ]);

    vec![qsort_compare, bsearch_compare, hash_comparator]
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// The qsort compare contract, spelled the way a real one reads:
    /// the host names the callback, the arity and body shapes say what
    /// it does, and the type hints carry the contract's signature.
    fn qsort_compare() -> CallbackPattern {
        CallbackPattern::new(
            "qsort_compare",
            AlgorithmCategory::Sorting,
            [r"\bqsort\b"],
            2,
        )
        .body_patterns([r"[*&]\w+[^;]*[<=>][^;]*[*&]\w+"])
        .type_hints([
            TypeHint::param(0, "const void *"),
            TypeHint::param(1, "const void *"),
            TypeHint::return_value("int"),
        ])
    }

    fn bsearch_compare() -> CallbackPattern {
        CallbackPattern::new(
            "bsearch_compare",
            AlgorithmCategory::Searching,
            [r"\bbsearch\b"],
            2,
        )
    }

    #[test]
    fn a_new_database_starts_with_no_contracts() {
        // Construction is free: empty, equal however it is made, and
        // clones interchangeable.
        let db = CallbackPatternDb::new();
        assert!(db.patterns().is_empty());
        assert_eq!(db, CallbackPatternDb::default());
        assert_eq!(db.clone(), db);
    }

    #[test]
    fn a_database_keeps_the_contracts_it_is_configured_with() {
        let db = CallbackPatternDb::with_patterns([qsort_compare(), bsearch_compare()]);
        let patterns = db.patterns();
        assert_eq!(patterns.len(), 2);
        // Configuration order is scan order: two databases built the
        // same way see the same contracts in the same order.
        assert_eq!(patterns[0].name, "qsort_compare");
        assert_eq!(patterns[1].name, "bsearch_compare");
        assert_eq!(patterns[0].host_patterns, [r"\bqsort\b"]);
        assert_eq!(patterns[0].param_count, 2);
    }

    #[test]
    fn an_added_contract_joins_the_set_in_order() {
        let mut db = CallbackPatternDb::with_patterns([qsort_compare()]);
        db.add_pattern(bsearch_compare());
        db.add_pattern(CallbackPattern::new(
            "hash_comparator",
            AlgorithmCategory::Hashing,
            [r"\bhash_(?:insert|lookup)\b"],
            2,
        ));
        let names: Vec<&str> = db.patterns().iter().map(|p| p.name.as_str()).collect();
        assert_eq!(
            names,
            ["qsort_compare", "bsearch_compare", "hash_comparator"]
        );
    }

    #[test]
    fn a_database_can_be_shared_across_scans() {
        // One database is driven concurrently over a program's
        // functions, so sharing one by reference across tasks must
        // stay sound.
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<CallbackPatternDb>();
    }

    // --------------------------------------------------------
    // Contracts
    // --------------------------------------------------------

    #[test]
    fn a_new_contract_starts_with_no_body_shapes_or_type_hints() {
        let contract = CallbackPattern::new(
            "bsearch_compare",
            AlgorithmCategory::Searching,
            [r"\bbsearch\b"],
            2,
        );
        assert_eq!(contract.name, "bsearch_compare");
        assert_eq!(contract.category, AlgorithmCategory::Searching);
        assert_eq!(contract.host_patterns, [r"\bbsearch\b"]);
        assert_eq!(contract.param_count, 2);
        assert!(contract.body_patterns.is_empty());
        assert!(contract.type_hints.is_empty());
    }

    #[test]
    fn builders_attach_body_shapes_and_type_hints() {
        let contract = qsort_compare();
        assert_eq!(contract.body_patterns, [r"[*&]\w+[^;]*[<=>][^;]*[*&]\w+"]);
        assert_eq!(
            contract.type_hints,
            [
                TypeHint::param(0, "const void *"),
                TypeHint::param(1, "const void *"),
                TypeHint::return_value("int"),
            ]
        );
    }

    #[test]
    fn a_callback_pattern_serde_round_trips() {
        let contract = qsort_compare();
        let json = serde_json::to_string(&contract).unwrap();
        // Categories serialize snake_case, matching the workspace's
        // serde convention.
        assert!(json.contains("\"category\":\"sorting\""));
        let back: CallbackPattern = serde_json::from_str(&json).unwrap();
        assert_eq!(back, contract);
    }

    #[test]
    fn a_contract_without_optional_fields_omits_them_and_reads_back_with_defaults() {
        // Documents persisted before the optional fields existed
        // still load.
        let contract = bsearch_compare();
        let json = serde_json::to_string(&contract).unwrap();
        assert!(!json.contains("\"body_patterns\""));
        assert!(!json.contains("\"type_hints\""));
        let back: CallbackPattern = serde_json::from_str(&json).unwrap();
        assert_eq!(back, contract);
        assert!(back.body_patterns.is_empty());
        assert!(back.type_hints.is_empty());
    }

    // --------------------------------------------------------
    // Type hints
    // --------------------------------------------------------

    #[test]
    fn a_type_hint_serde_round_trips_for_parameters_and_return() {
        let param = TypeHint::param(1, "const void *");
        let json = serde_json::to_string(&param).unwrap();
        assert_eq!(
            json,
            r#"{"target":{"param":1},"suggested_type":"const void *"}"#
        );
        assert_eq!(serde_json::from_str::<TypeHint>(&json).unwrap(), param);

        let ret = TypeHint::return_value("int");
        let json = serde_json::to_string(&ret).unwrap();
        assert!(json.contains("\"target\":\"return\""));
        assert_eq!(serde_json::from_str::<TypeHint>(&json).unwrap(), ret);
    }

    #[test]
    fn type_targets_distinguish_parameters_from_the_return() {
        assert_ne!(TypeTarget::Param(0), TypeTarget::Return);
        assert_ne!(TypeTarget::Param(0), TypeTarget::Param(1));
        assert_eq!(TypeTarget::Param(1), TypeTarget::Param(1));
    }

    // --------------------------------------------------------
    // Caller matching
    // --------------------------------------------------------

    #[test]
    fn a_caller_matching_a_contract_yields_a_match() {
        // The analyzed function is reached by the host that takes this
        // callback: it reads as the host's callback.
        let db = CallbackPatternDb::with_patterns([qsort_compare()]);
        let matches = db.match_callers(["qsort"]);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].pattern.name, "qsort_compare");
        assert_eq!(matches[0].pattern.category, AlgorithmCategory::Sorting);
    }

    #[test]
    fn the_match_carries_the_caller_name_that_fitted() {
        // The caller name is the evidence a detection reports for why
        // the function reads as this callback's.
        let db = CallbackPatternDb::with_patterns([qsort_compare()]);
        let matches = db.match_callers(["main", "qsort"]);
        assert_eq!(matches[0].caller, "qsort");
    }

    #[test]
    fn a_contract_reports_once_however_many_callers_fit() {
        // Reached by the host twice over is still one role served: the
        // first caller name that matched stands as the evidence.
        let db = CallbackPatternDb::with_patterns([qsort_compare()]);
        let matches = db.match_callers(["qsort", "qsort"]);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].caller, "qsort");
    }

    #[test]
    fn callers_matching_no_contract_yield_nothing() {
        let db = CallbackPatternDb::with_patterns([qsort_compare()]);
        assert!(db.match_callers(["main", "FUN_180001900"]).is_empty());
    }

    #[test]
    fn a_name_merely_carrying_the_host_letters_matches_nothing() {
        // The host pattern is word-anchored: `qsort_s`'s callback
        // takes a context parameter the contract does not expect, so
        // the contract stays quiet about it.
        let db = CallbackPatternDb::with_patterns([qsort_compare()]);
        assert!(db.match_callers(["qsort_s", "my_qsort_helper"]).is_empty());
    }

    #[test]
    fn a_second_host_pattern_reaches_the_same_contract() {
        // Hosts are a set: any one of them reaching the function
        // serves the same single role.
        let contract = CallbackPattern::new(
            "qsort_compare",
            AlgorithmCategory::Sorting,
            [r"\bqsort\b", r"\bqsort_r\b"],
            2,
        );
        let db = CallbackPatternDb::with_patterns([contract]);
        let matches = db.match_callers(["qsort_r"]);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].caller, "qsort_r");
    }

    #[test]
    fn a_contract_with_no_host_patterns_claims_nothing() {
        // A contract that names no host can say no caller reaches the
        // function as its callback.
        let contract = CallbackPattern::new(
            "anonymous",
            AlgorithmCategory::Sorting,
            std::iter::empty::<String>(),
            2,
        );
        let db = CallbackPatternDb::with_patterns([contract]);
        assert!(db.match_callers(["qsort"]).is_empty());
    }

    #[test]
    fn an_uncompilable_host_pattern_matches_nothing() {
        // A contract that cannot evaluate its own host name can make
        // no claim about the function's usage.
        let contract = CallbackPattern::new("broken", AlgorithmCategory::Sorting, ["("], 2);
        let db = CallbackPatternDb::with_patterns([contract]);
        assert!(db.match_callers(["qsort"]).is_empty());
    }

    #[test]
    fn matches_follow_configuration_order() {
        // Callers arrive in one order; contracts report in theirs, so
        // two databases built alike report alike.
        let db = CallbackPatternDb::with_patterns([qsort_compare(), bsearch_compare()]);
        let matches = db.match_callers(["bsearch", "qsort"]);
        let names: Vec<&str> = matches.iter().map(|m| m.pattern.name.as_str()).collect();
        assert_eq!(names, ["qsort_compare", "bsearch_compare"]);
    }

    #[test]
    fn caller_names_arrive_in_whatever_shape_the_call_graph_hands_them() {
        // The call graph and Ghidra client spell names as `String` and
        // `&str` alike; the match reads them the same way.
        let db = CallbackPatternDb::with_default_patterns();
        let owned = "qsort".to_string();
        let matches = db.match_callers([&owned, "bsearch"]);
        let names: Vec<&str> = matches.iter().map(|m| m.pattern.name.as_str()).collect();
        assert_eq!(names, ["qsort_compare", "bsearch_compare"]);
    }

    // --------------------------------------------------------
    // Detection
    // --------------------------------------------------------

    /// A decompiled function whose inferred signature carries
    /// `param_count` parameters — the arity the contract reads.
    fn callback(name: &str, param_count: usize, body: &str) -> DecompiledFunction {
        let params: Vec<String> = (1..=param_count)
            .map(|i| format!("int param_{i}"))
            .collect();
        DecompiledFunction {
            name: name.into(),
            signature: format!("int {name}({})", params.join(", ")),
            body: body.into(),
        }
    }

    /// A body carrying the comparison the compare contracts demand: an
    /// ordering test between two pointer touches.
    fn compare_body() -> String {
        [
            "int compare_elements(int param_1, int param_2) {",
            "  int *piVar1;",
            "  int *piVar2;",
            "  if (*piVar1 < *piVar2) {",
            "    return -1;",
            "  }",
            "  if (*piVar1 == *piVar2) {",
            "    return 0;",
            "  }",
            "  return 1;",
            "}",
        ]
        .join("\n")
    }

    #[test]
    fn a_function_the_host_reaches_with_a_fitting_signature_is_detected() {
        // Both halves agree: `qsort` reaches the function, and the
        // function takes the two compared elements and compares them.
        let db = CallbackPatternDb::with_patterns([qsort_compare()]);
        let func = callback("FUN_18003ab00", 2, &compare_body());
        let detections = db.detect_callback_patterns(&func, ["qsort"]);
        assert_eq!(detections.len(), 1);
        let hint = &detections[0].hint;
        assert_eq!(hint.function, "FUN_18003ab00");
        assert_eq!(hint.algorithm, "qsort_compare");
        assert_eq!(hint.category, AlgorithmCategory::Sorting);
        assert_eq!(hint.method, DetectionMethod::CallbackPattern);
        assert_eq!(hint.confidence, Confidence::new(CALLBACK_CONFIDENCE));
    }

    #[test]
    fn the_evidence_is_the_host_that_reaches_the_function() {
        // The call-graph edge from the host is the usage evidence a
        // reviewer (or a prompt) can check.
        let db = CallbackPatternDb::with_patterns([qsort_compare()]);
        let func = callback("FUN_18003ab00", 2, &compare_body());
        let detections = db.detect_callback_patterns(&func, ["main", "qsort"]);
        assert_eq!(detections[0].hint.evidence, "qsort");
    }

    #[test]
    fn the_detection_carries_the_contract_and_its_type_hints() {
        // Recognizing the role types the function beside naming it:
        // the fit carries the contract's own signature over.
        let db = CallbackPatternDb::with_patterns([qsort_compare()]);
        let func = callback("FUN_18003ab00", 2, &compare_body());
        let detections = db.detect_callback_patterns(&func, ["qsort"]);
        assert_eq!(detections[0].pattern, &qsort_compare());
        assert_eq!(
            detections[0].pattern.type_hints,
            [
                TypeHint::param(0, "const void *"),
                TypeHint::param(1, "const void *"),
                TypeHint::return_value("int"),
            ]
        );
    }

    #[test]
    fn a_fitting_signature_reached_by_no_host_is_not_detected() {
        // A compare-shaped two-parameter function that no host reaches
        // is an ordinary callee, not this callback.
        let db = CallbackPatternDb::with_patterns([qsort_compare()]);
        let func = callback("FUN_18003ab00", 2, &compare_body());
        assert!(
            db.detect_callback_patterns(&func, ["main", "FUN_180001900"])
                .is_empty()
        );
    }

    #[test]
    fn a_wrong_arity_fits_no_contract() {
        // The contract expects exactly its arity: a three-parameter
        // function (a `qsort_s`-style callback with a context
        // parameter) and a one-parameter function both stand outside
        // the two-parameter contract even when the host reaches them.
        let db = CallbackPatternDb::with_patterns([qsort_compare()]);
        let three = callback("FUN_18003ab00", 3, &compare_body());
        let one = callback("FUN_18003ab01", 1, &compare_body());
        assert!(db.detect_callback_patterns(&three, ["qsort"]).is_empty());
        assert!(db.detect_callback_patterns(&one, ["qsort"]).is_empty());
    }

    #[test]
    fn a_body_missing_the_required_shape_is_not_detected() {
        // Reached by the host at the right arity, but the body carries
        // no comparison between pointer touches — the signature half
        // refuses what the usage half suggests.
        let db = CallbackPatternDb::with_patterns([qsort_compare()]);
        let body = [
            "void log_pair(int param_1, int param_2) {",
            "  printf(\"%d %d\", param_1, param_2);",
            "}",
        ]
        .join("\n");
        let func = callback("FUN_18003ab00", 2, &body);
        assert!(db.detect_callback_patterns(&func, ["qsort"]).is_empty());
    }

    #[test]
    fn a_contract_without_body_shapes_fits_on_usage_and_arity_alone() {
        // A contract that demands no behavior of its callback reads
        // the role from the host and the arity alone.
        let db = CallbackPatternDb::with_patterns([bsearch_compare()]);
        let body = [
            "int decide(int param_1, int param_2) {",
            "  return param_1 - param_2;",
            "}",
        ]
        .join("\n");
        let func = callback("FUN_18003ab00", 2, &body);
        let detections = db.detect_callback_patterns(&func, ["bsearch"]);
        assert_eq!(detections.len(), 1);
        assert_eq!(detections[0].hint.algorithm, "bsearch_compare");
    }

    #[test]
    fn an_uncompilable_body_pattern_claims_nothing() {
        // A contract that cannot evaluate its own demand can make no
        // claim about the function.
        let contract = qsort_compare().body_patterns(["("]);
        let db = CallbackPatternDb::with_patterns([contract]);
        let func = callback("FUN_18003ab00", 2, &compare_body());
        assert!(db.detect_callback_patterns(&func, ["qsort"]).is_empty());
    }

    #[test]
    fn a_function_serving_two_contracts_reports_both_in_configuration_order() {
        // One compare callback shape, two hosts that take it: each
        // contract the function serves reports once, in the order the
        // contracts were configured.
        let db = CallbackPatternDb::with_patterns([qsort_compare(), bsearch_compare()]);
        let func = callback("FUN_18003ab00", 2, &compare_body());
        let detections = db.detect_callback_patterns(&func, ["bsearch", "qsort"]);
        let names: Vec<&str> = detections
            .iter()
            .map(|d| d.hint.algorithm.as_str())
            .collect();
        assert_eq!(names, ["qsort_compare", "bsearch_compare"]);
    }

    #[test]
    fn a_contract_reports_once_however_many_hosts_reach_the_function() {
        let db = CallbackPatternDb::with_patterns([qsort_compare()]);
        let func = callback("FUN_18003ab00", 2, &compare_body());
        let detections = db.detect_callback_patterns(&func, ["qsort", "qsort"]);
        assert_eq!(detections.len(), 1);
        assert_eq!(detections[0].hint.evidence, "qsort");
    }

    #[test]
    fn the_standard_set_detects_a_realistic_qsort_compare_callback() {
        let db = CallbackPatternDb::with_default_patterns();
        let func = callback("compare_elements", 2, &compare_body());
        let detections = db.detect_callback_patterns(&func, ["qsort"]);
        assert_eq!(detections.len(), 1);
        assert_eq!(detections[0].hint.algorithm, "qsort_compare");
        assert_eq!(detections[0].hint.category, AlgorithmCategory::Sorting);
    }

    #[test]
    fn the_standard_set_detects_a_hash_comparator_through_its_host() {
        // A comparator answers equality, not ordering, and is reached
        // through the helper that probes a bucket.
        let db = CallbackPatternDb::with_default_patterns();
        let body = [
            "int same_element(int param_1, int param_2) {",
            "  int *piVar1;",
            "  int *piVar2;",
            "  return *piVar1 == *piVar2;",
            "}",
        ]
        .join("\n");
        let func = callback("same_element", 2, &body);
        let detections = db.detect_callback_patterns(&func, ["hash_insert", "main"]);
        assert_eq!(detections.len(), 1);
        assert_eq!(detections[0].hint.algorithm, "hash_comparator");
        assert_eq!(detections[0].hint.category, AlgorithmCategory::Hashing);
        assert_eq!(detections[0].hint.evidence, "hash_insert");
    }

    #[test]
    fn the_standard_set_stays_quiet_about_a_function_no_host_reaches() {
        // The compare shape alone, with no host reaching the function,
        // names no callback role.
        let db = CallbackPatternDb::with_default_patterns();
        let func = callback("FUN_18003ab00", 2, &compare_body());
        assert!(db.detect_callback_patterns(&func, ["main"]).is_empty());
    }

    // --------------------------------------------------------
    // The standard contract set
    // --------------------------------------------------------

    #[test]
    fn the_standard_set_carries_the_three_standard_contracts() {
        let contracts = default_patterns();
        let names: Vec<&str> = contracts.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(
            names,
            ["qsort_compare", "bsearch_compare", "hash_comparator"]
        );
        let categories: Vec<AlgorithmCategory> = contracts.iter().map(|p| p.category).collect();
        assert_eq!(
            categories,
            [
                AlgorithmCategory::Sorting,
                AlgorithmCategory::Searching,
                AlgorithmCategory::Hashing,
            ]
        );
        // Every standard contract is a two-parameter compare callback.
        assert!(contracts.iter().all(|p| p.param_count == 2));
    }

    #[test]
    fn a_database_built_with_the_standard_set_scans_against_it() {
        let db = CallbackPatternDb::with_default_patterns();
        assert_eq!(db.patterns(), default_patterns());
        assert_ne!(db, CallbackPatternDb::new());
    }

    #[test]
    fn each_standard_contract_states_its_callback_signature() {
        // The standard contracts carry everything a detection needs to
        // type the function it recognizes: the two element pointers,
        // the integer answer, and the body shape the host demands.
        for contract in default_patterns() {
            assert!(!contract.host_patterns.is_empty());
            assert!(!contract.body_patterns.is_empty());
            assert_eq!(
                contract.type_hints,
                [
                    TypeHint::param(0, "const void *"),
                    TypeHint::param(1, "const void *"),
                    TypeHint::return_value("int"),
                ]
            );
        }
    }
}
