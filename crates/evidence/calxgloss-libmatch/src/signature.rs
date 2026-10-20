//! Body signatures: the named shapes of statically linked library code.
//!
//! A [`LibmatchSignature`] is one entry of the set a scan reads bodies
//! against: a library symbol and its family, the per-line regex bundle
//! that its *normalized* body must carry, an optional exclusion bundle
//! that vetoes look-alike shapes, a minimum line-count floor that keeps
//! tiny functions from accidentally fitting a broad shape, and an
//! optional per-entry confidence that overrides the scan's standard
//! body-evidence score. The entry type is its own serde shape, per
//! ADR-0023's pattern-database precedent, so a supplied
//! [database file](crate::signature_db) carries these entries whole
//! without a format change.
//!
//! [`default_signatures`] is the built-in starter set — the
//! highest-frequency MSVC CRT and STL shapes, hand-authored against the
//! [normalize](crate::normalize) contract. The set is deliberately
//! small: every entry trades a false-positive risk against a missed
//! library function, and the operator-supplied
//! [signature database](crate::signature_db) is the growth path.

use serde::{Deserialize, Serialize};

use crate::types::LibraryFamily;

/// One known-library body signature — a named bundle of normalized-line
/// regexes with the line-count floor that keeps it honest.
///
/// A signature identifies exactly one library symbol: its
/// [`symbol`](Self::symbol) and [`family`](Self::family) are what a
/// finding records when the signature matches. The normalized body must
/// carry a line matching every regex in
/// [`match_patterns`](Self::match_patterns) and none matching any in
/// [`exclude_patterns`](Self::exclude_patterns), and the raw body must
/// span at least [`min_lines`](Self::min_lines) lines — tiny functions
/// accidentally fit broad shapes, so the floor refuses them. Each regex
/// is matched against a single normalized line; a source may carry the
/// `{name}` placeholder, which the matcher replaces with the scanned
/// function's name, escaped for literal matching.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LibmatchSignature {
    /// The library symbol this signature identifies, e.g. `memcpy`.
    pub symbol: String,
    /// The library family the symbol belongs to.
    pub family: LibraryFamily,
    /// Regex sources, each of which must match some normalized line of
    /// the body. A source may carry the `{name}` placeholder.
    pub match_patterns: Vec<String>,
    /// Regex sources, any of which rejects the match when it appears in
    /// a normalized line of the body — shapes that make the matched
    /// signature read differently (a guard branch turning `memcpy` into
    /// a `memmove` overlap check, say). A source may carry the same
    /// `{name}` placeholder.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exclude_patterns: Vec<String>,
    /// Minimum number of raw body lines for the signature to be
    /// considered.
    #[serde(default)]
    pub min_lines: usize,
    /// Optional per-entry confidence (0–100) overriding the scan's
    /// standard body-evidence score
    /// ([`BODY_MATCH_CONFIDENCE`](crate::confidence::BODY_MATCH_CONFIDENCE))
    /// for the findings this signature makes — a hand-tuned signature
    /// can claim more (or less) trust than the standard set pays.
    /// Absent means the standard score.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence: Option<u8>,
    /// The Rust equivalent the match suggests, spelled for a finding's
    /// suggestion — what a translation should map calls onto rather
    /// than re-implement.
    pub suggestion: String,
}

impl LibmatchSignature {
    /// The default line-count floor: a body shorter than this is too
    /// small to carry a real library routine.
    pub const DEFAULT_MIN_LINES: usize = 6;

    /// A signature named `symbol` in `family` requiring every one of
    /// `match_patterns` against the normalized body, with no
    /// exclusions, the default line-count floor, the scan's standard
    /// score, and `suggestion` as its suggestion.
    pub fn new(
        symbol: impl Into<String>,
        family: LibraryFamily,
        match_patterns: impl IntoIterator<Item = impl Into<String>>,
        suggestion: impl Into<String>,
    ) -> Self {
        Self {
            symbol: symbol.into(),
            family,
            match_patterns: match_patterns.into_iter().map(Into::into).collect(),
            exclude_patterns: Vec::new(),
            min_lines: Self::DEFAULT_MIN_LINES,
            confidence: None,
            suggestion: suggestion.into(),
        }
    }
}

/// The built-in starter set: the highest-frequency MSVC CRT and STL
/// shapes, hand-authored against the [normalize](crate::normalize)
/// contract.
///
/// The set is kept small on purpose — every entry is a standing
/// false-positive risk against the program's own routines — and covers
/// the routines a statically linked CRT puts in nearly every binary
/// plus the associative-container tree idioms the STL compiles to. The
/// exclusion bundles are what separate look-alike loop shapes: the copy
/// loop without a guard is `memcpy`, the fill loop that stores a cast
/// byte instead of a source read is `memset`, the one with an overlap
/// branch is neither. The allocator wrappers are the set's deliberately
/// sloppier entries: a `malloc`/`free` call with a null test is a thin
/// shape any allocation helper reads alike, so they claim a lower score
/// through the per-entry override.
pub fn default_signatures() -> Vec<LibmatchSignature> {
    vec![
        // The CRT byte/word copy loop: a countdown, a dereference
        // assignment, and a `!= 0` loop test, with no guard branch —
        // an overlap check would make it a memmove shape, and allocator
        // calls would make it something that allocates.
        LibmatchSignature::new(
            "memcpy",
            LibraryFamily::Crt,
            [
                r"\*\([^;]*\) = \*\(",
                r"VAR = VAR \+ -1",
                r"while \(VAR != 0\)",
            ],
            "slice copy — `copy_nonoverlapping` / `clone_from_slice`",
        )
        .with_exclusions([r"\bif \(", r"\bmalloc\b", r"\bfree\b"]),
        // The CRT byte-fill loop: the same countdown and loop test as
        // the copy loop, but the store carries a cast byte instead of a
        // source read — no `*(...) = *(...)` line fits the copy shape.
        LibmatchSignature::new(
            "memset",
            LibraryFamily::Crt,
            [
                r"\*VAR = \([a-z]+\)VAR",
                r"VAR = VAR \+ -1",
                r"while \(VAR != 0\)",
            ],
            "`[0u8; N]` fill / `slice::fill`",
        )
        .with_exclusions([r"\bif \(", r"\bmalloc\b", r"\bfree\b"]),
        // The CRT byte-compare loop: unsigned byte loads from two
        // pointers, the same countdown as the copy loop, and no store
        // line — the loads are `(uchar *)`-cast because the comparison
        // is unsigned.
        LibmatchSignature::new(
            "memcmp",
            LibraryFamily::Crt,
            [
                r"VAR = \*\(uchar \*\)VAR",
                r"VAR = VAR \+ -1",
                r"while \(VAR != 0\)",
            ],
            "slice compare — `slice::eq` / `Ord` on byte slices",
        )
        .with_exclusions([r"\bmalloc\b", r"\bfree\b"]),
        // The CRT string-length scan: walk the pointer itself until the
        // NUL byte, count as you go, return the count. The
        // `while (*VAR != '\0')` spelling is what separates the scan
        // from the compare and copy loops, which test a loaded byte
        // variable instead of the dereferenced pointer.
        LibmatchSignature::new(
            "strlen",
            LibraryFamily::Crt,
            [r"while \(\*VAR != '\\0'", r"VAR = VAR \+ 1"],
            "`str::len` / `CStr` count",
        )
        .with_exclusions([r"\bmalloc\b", r"\bfree\b"]),
        // The CRT string compare: byte loads from both strings, an
        // equality carry line, and the loop test that keeps going while
        // the bytes match and stop on the NUL byte.
        LibmatchSignature::new(
            "strcmp",
            LibraryFamily::Crt,
            [
                r"VAR = \*VAR;",
                r"VAR = VAR == VAR;",
                r"while \(VAR && \(VAR != '\\0'\)",
            ],
            "string compare — `str::cmp` / `Ord` on `CStr`",
        )
        .with_exclusions([r"\bmalloc\b", r"\bfree\b"]),
        // The CRT string copy: a byte load, a bare byte store, and the
        // NUL-terminated loop — the copy that carries the terminator,
        // with no guard branch.
        LibmatchSignature::new(
            "strcpy",
            LibraryFamily::Crt,
            [r"VAR = \*VAR;", r"\*VAR = VAR;", r"while \(VAR != '\\0'\)"],
            "string copy — `CStr` to `String` / `str` copy",
        )
        .with_exclusions([r"\bif \(", r"\bmalloc\b", r"\bfree\b"]),
        // The CRT allocator wrappers: `operator new` is a `malloc` call
        // with a null test, `operator delete` a guarded `free`. The
        // shapes are thin — any allocation helper reads alike — so both
        // entries deliberately claim a sloppier score than the standard
        // body-evidence one.
        LibmatchSignature::new(
            "operator new",
            LibraryFamily::Crt,
            [r"VAR = malloc\(VAR\)", r"if \(VAR == \(void \*\)0x0\)"],
            "heap allocation — `Box::new` / `Vec` growth",
        )
        .with_confidence(50),
        LibmatchSignature::new(
            "operator delete",
            LibraryFamily::Crt,
            [r"free\(VAR\);", r"if \(VAR != \(void \*\)0x0\)"],
            "heap deallocation — `drop` / `Box::from_raw`",
        )
        .with_confidence(50),
        // The STL associative-container tree idioms, spelled by the
        // MSVC node fields (`_Left`, `_Right`, `_Parent`, `_Isnil`) that
        // survive normalization: the red-black rotation the rebalancing
        // pass compiles to — the three-line child rehang — and the
        // search descent that walks `_Left`/`_Right` while testing
        // `_Isnil`.
        LibmatchSignature::new(
            "std::_Tree::_Rotate_left",
            LibraryFamily::Stl,
            [
                r"VAR = VAR->_Right;",
                r"VAR->_Right = VAR->_Left;",
                r"VAR->_Left = VAR;",
            ],
            "red-black tree rebalancing — `BTreeMap` internals",
        ),
        LibmatchSignature::new(
            "std::_Tree::_Lower_bound",
            LibraryFamily::Stl,
            [
                r"VAR = VAR->_Left;",
                r"VAR = VAR->_Right;",
                r"VAR = VAR->_Isnil;",
            ],
            "associative-container lookup — `BTreeMap` / `BTreeSet` search",
        ),
    ]
}

/// Chainable additions to a signature, mirroring the workspace's
/// builder convention.
impl LibmatchSignature {
    /// Vetoes the shapes `patterns` spells: any of them appearing in a
    /// normalized line rejects the match.
    pub fn with_exclusions(
        mut self,
        patterns: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        self.exclude_patterns = patterns.into_iter().map(Into::into).collect();
        self
    }

    /// Requires at least `lines` raw body lines before the signature is
    /// considered.
    pub fn with_min_lines(mut self, lines: usize) -> Self {
        self.min_lines = lines;
        self
    }

    /// Claims `confidence` (0–100) instead of the scan's standard
    /// body-evidence score.
    pub fn with_confidence(mut self, confidence: u8) -> Self {
        self.confidence = Some(confidence);
        self
    }
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use regex::Regex;

    #[test]
    fn a_signature_serde_round_trips_and_omits_its_absent_optionals() {
        let signature = LibmatchSignature::new(
            "memcpy",
            LibraryFamily::Crt,
            [r"VAR = VAR \+ -1"],
            "slice copy",
        );
        let json = serde_json::to_string(&signature).unwrap();
        assert!(!json.contains("\"exclude_patterns\""));
        assert!(!json.contains("\"confidence\""));
        let back: LibmatchSignature = serde_json::from_str(&json).unwrap();
        assert_eq!(back, signature);
    }

    #[test]
    fn a_signature_carries_its_exclusions_floor_and_confidence_through_json() {
        let signature =
            LibmatchSignature::new("wmemcpy", LibraryFamily::Crt, [r"while \("], "slice copy")
                .with_exclusions([r"\bif \("])
                .with_min_lines(10)
                .with_confidence(70);
        let json = serde_json::to_string(&signature).unwrap();
        let back: LibmatchSignature = serde_json::from_str(&json).unwrap();
        assert_eq!(back, signature);
        assert_eq!(back.exclude_patterns, vec![r"\bif \("]);
        assert_eq!(back.min_lines, 10);
        assert_eq!(back.confidence, Some(70));
    }

    #[test]
    fn a_new_signature_starts_with_no_exclusions_and_the_default_floor() {
        let signature =
            LibmatchSignature::new("memmove", LibraryFamily::Crt, ["while ("], "slice copy");
        assert_eq!(signature.symbol, "memmove");
        assert_eq!(signature.family, LibraryFamily::Crt);
        assert_eq!(signature.match_patterns, vec!["while ("]);
        assert!(signature.exclude_patterns.is_empty());
        assert_eq!(signature.min_lines, LibmatchSignature::DEFAULT_MIN_LINES);
        assert_eq!(signature.confidence, None);
    }

    #[test]
    fn the_built_in_set_names_crt_and_stl_symbols_with_suggestions() {
        // The starter set is pinned at this level; what it finds is
        // pinned through scan findings, not here.
        let signatures = default_signatures();
        assert!(!signatures.is_empty());
        for signature in &signatures {
            assert!(!signature.symbol.is_empty());
            assert!(!signature.suggestion.is_empty());
            assert!(!signature.match_patterns.is_empty());
            // Every built-in regex compiles: a hand-authored typo would
            // silently claim nothing in a scan.
            for source in signature
                .match_patterns
                .iter()
                .chain(signature.exclude_patterns.iter())
            {
                Regex::new(source)
                    .unwrap_or_else(|e| panic!("built-in regex {source} must compile: {e}"));
            }
        }
        // The set covers the CRT memory/string routines and allocator
        // wrappers and the STL tree idioms, each under its family.
        for (symbol, family) in [
            ("memcpy", LibraryFamily::Crt),
            ("memset", LibraryFamily::Crt),
            ("memcmp", LibraryFamily::Crt),
            ("strlen", LibraryFamily::Crt),
            ("strcmp", LibraryFamily::Crt),
            ("strcpy", LibraryFamily::Crt),
            ("operator new", LibraryFamily::Crt),
            ("operator delete", LibraryFamily::Crt),
            ("std::_Tree::_Rotate_left", LibraryFamily::Stl),
            ("std::_Tree::_Lower_bound", LibraryFamily::Stl),
        ] {
            assert!(
                signatures
                    .iter()
                    .any(|signature| signature.symbol == symbol && signature.family == family),
                "the starter set must carry {symbol} in {family:?}"
            );
        }
    }

    #[test]
    fn built_in_entries_score_at_the_standard_confidence_unless_deliberately_sloppier() {
        // An entry that overrides the standard score is one the set
        // deliberately reads sloppier — the thin allocator-wrapper
        // shapes — and it claims less trust than the standard
        // body-evidence score, never more.
        let signatures = default_signatures();
        let mut overridden = 0;
        for signature in &signatures {
            if let Some(confidence) = signature.confidence {
                overridden += 1;
                assert!(
                    confidence < crate::confidence::BODY_MATCH_CONFIDENCE,
                    "built-in entry {} overrides at {confidence}, below the standard score",
                    signature.symbol
                );
            }
        }
        assert!(
            overridden > 0,
            "the deliberately sloppier entries must carry their own override"
        );
    }
}
