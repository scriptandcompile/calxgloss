//! Body signatures: the named shapes of statically linked library code.
//!
//! A [`LibmatchSignature`] is one entry of the set a scan reads bodies
//! against: a library symbol and its family, the per-line regex bundle
//! that its *normalized* body must carry, an optional exclusion bundle
//! that vetoes look-alike shapes, a minimum line-count floor that keeps
//! tiny functions from accidentally fitting a broad shape, and an
//! optional per-entry confidence that overrides the scan's standard
//! body-evidence score. The entry type is its own serde shape, per
//! ADR-0023's pattern-database precedent, so a supplied database file
//! can carry these entries whole later without a format change.
//!
//! [`default_signatures`] is the built-in starter set — the
//! highest-frequency MSVC CRT shapes, hand-authored against the
//! [normalize](crate::normalize) contract. It is deliberately small:
//! every entry trades a false-positive risk against a missed library
//! function, and the operator-supplied database (a later ticket) is the
//! growth path.

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

/// The built-in starter set: the highest-frequency MSVC CRT shapes,
/// hand-authored against the [normalize](crate::normalize) contract.
///
/// The set is kept small on purpose — every entry is a standing
/// false-positive risk against the program's own routines — and covers
/// the routines a statically linked CRT puts in nearly every binary.
/// The exclusion bundles are what separate look-alike loop shapes: the
/// copy loop without a guard is `memcpy`, the one with an overlap
/// branch is not.
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
        // The CRT string-length scan: walk until the NUL byte, count as
        // you go, return the count.
        LibmatchSignature::new(
            "strlen",
            LibraryFamily::Crt,
            [r"while \(", r"!= '\\0'", r"VAR = VAR \+ 1"],
            "`str::len` / `CStr` count",
        )
        .with_exclusions([r"\bmalloc\b", r"\bfree\b"]),
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
    fn the_built_in_set_names_crt_symbols_with_suggestions() {
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
        assert!(
            signatures
                .iter()
                .any(|signature| signature.symbol == "memcpy"
                    && signature.family == LibraryFamily::Crt),
            "the starter set must carry the memcpy idiom"
        );
    }
}
