//! Body-signature matching over decompiled functions.
//!
//! [`LibmatchMatcher`] owns the signature set a scan reads bodies
//! against. Its records are [`LibmatchSignature`]s: each a named bundle
//! of normalized-line regexes with a minimum line-count floor. The set
//! is configurable — supply it whole through
//! [`with_signatures`](LibmatchMatcher::with_signatures) — and
//! [`default_signatures`](crate::signature::default_signatures) is the
//! built-in starter set this scan uses by default.
//!
//! Matching is body shape, not bytes. The body is normalized first
//! ([`normalize`](crate::normalize)) so Ghidra variable names, register
//! temporaries, and addresses that move between builds read as
//! wildcards, while calls, operators, constants, string literals, and
//! control-flow keywords stand. This is the body-based complement to
//! ADR-0012's name-shape flagging; the two never touch each other's
//! records.
//!
//! The matcher holds no scan source of its own and never writes back to
//! the program (ADR-0020); one matcher serves an entire scan.

use crate::confidence::BODY_MATCH_CONFIDENCE;
use crate::normalize::normalize_lines;
use crate::signature::LibmatchSignature;
use crate::types::{Confidence, LibmatchFinding, LibmatchMatch, VERSION_UNKNOWN_ADMISSION};
use calxgloss_decomp::DecompiledFunction;
use regex::Regex;

/// Body-signature matching over decompiled functions.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LibmatchMatcher {
    signatures: Vec<LibmatchSignature>,
}

impl LibmatchMatcher {
    /// A matcher with no signatures configured: every body it is handed
    /// matches nothing until the built-in starter set arrives through
    /// [`with_default_signatures`](Self::with_default_signatures) or a
    /// supplied set through [`with_signatures`](Self::with_signatures).
    pub fn new() -> Self {
        Self::default()
    }

    /// A matcher that scans against the built-in starter set —
    /// [`default_signatures`](crate::signature::default_signatures) —
    /// in its configuration order.
    pub fn with_default_signatures() -> Self {
        Self::with_signatures(crate::signature::default_signatures())
    }

    /// A matcher that scans against exactly `signatures`, kept in the
    /// order they are given.
    pub fn with_signatures(signatures: impl IntoIterator<Item = LibmatchSignature>) -> Self {
        Self {
            signatures: signatures.into_iter().collect(),
        }
    }

    /// The signatures this matcher scans against, in configuration
    /// order.
    pub fn signatures(&self) -> &[LibmatchSignature] {
        &self.signatures
    }

    /// Scan one decompiled body against every configured signature, in
    /// configuration order, and report a finding for each signature the
    /// body fits.
    ///
    /// The body is normalized once, and each signature's regexes are
    /// matched against the normalized lines. A signature fits when the
    /// raw body spans at least its
    /// [`min_lines`](LibmatchSignature::min_lines) lines, every regex
    /// in [`match_patterns`](LibmatchSignature::match_patterns) matches
    /// some normalized line, and no regex in
    /// [`exclude_patterns`](LibmatchSignature::exclude_patterns)
    /// matches any. The line-count floor runs before any regex: a body
    /// shorter than the floor is too small to hold a real library
    /// routine.
    ///
    /// Each finding names the matched symbol and its family. It is
    /// scored at the signature's own
    /// [`confidence`](LibmatchSignature::confidence) when it carries
    /// one, and at [`BODY_MATCH_CONFIDENCE`] otherwise. Its evidence is
    /// the decompiled line whose normalized form matched the
    /// signature's first required regex. A signature that requires
    /// nothing — no required regexes — fits nothing. A required regex
    /// that will not compile makes the signature claim nothing, and an
    /// uncompilable exclusion vetoes nothing.
    ///
    /// A regex source may carry the `{name}` placeholder: the matcher
    /// replaces it with the scanned function's name, escaped for
    /// literal matching, so a signature can speak of the function
    /// itself.
    pub fn match_function(&self, func: &DecompiledFunction) -> Vec<LibmatchFinding> {
        let lines = func.body.lines().count();
        let normalized = normalize_lines(&func.body);
        let name = regex::escape(&func.name);
        let mut findings = Vec::new();
        for signature in &self.signatures {
            if lines < signature.min_lines || signature.match_patterns.is_empty() {
                continue;
            }

            // Every required shape must appear on some normalized line;
            // the first one's first matching line supplies the finding's
            // evidence.
            let mut evidence: Option<String> = None;
            let mut fits = true;
            for (index, source) in signature.match_patterns.iter().enumerate() {
                let Some(regex) = compile(source, &name) else {
                    fits = false;
                    break;
                };
                let hit = normalized
                    .iter()
                    .find(|(_, line)| regex.is_match(line))
                    .map(|(original, _)| original.clone());
                match hit {
                    Some(line) if index == 0 => evidence = Some(line),
                    Some(_) => {}
                    None => {
                        fits = false;
                        break;
                    }
                }
            }

            // Any exclusion appearing in the body vetoes the match.
            if fits {
                for source in &signature.exclude_patterns {
                    if let Some(regex) = compile(source, &name)
                        && normalized.iter().any(|(_, line)| regex.is_match(line))
                    {
                        fits = false;
                        break;
                    }
                }
            }

            if let Some(evidence) = fits.then_some(evidence).flatten() {
                findings.push(LibmatchFinding::BodySignature(LibmatchMatch {
                    function: func.name.clone(),
                    symbol: signature.symbol.clone(),
                    family: signature.family,
                    suggestion: signature.suggestion.clone(),
                    confidence: Confidence::new(
                        signature.confidence.unwrap_or(BODY_MATCH_CONFIDENCE),
                    ),
                    evidence,
                    // P19-3: every match this scan makes states its
                    // own version authority — the signature proved a
                    // body shape, never WHICH release carried it.
                    admission: Some(VERSION_UNKNOWN_ADMISSION.into()),
                }));
            }
        }
        findings
    }
}

/// Compile one signature regex source, replacing the `{name}`
/// placeholder with the scanned function's name (already escaped for
/// literal matching). A source that will not compile answers `None` —
/// the lenient per-entry semantics: a broken regex can claim nothing
/// and veto nothing.
fn compile(source: &str, name: &str) -> Option<Regex> {
    Regex::new(&source.replace("{name}", name)).ok()
}
