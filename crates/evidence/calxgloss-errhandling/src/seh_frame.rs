//! The spelled `try`/`catch` SEH frame detector.
//!
//! The frame is the one error-handling shape the decompiler spells
//! outright: a body that opens a `try {` block and later carries a
//! `catch (...)` clause shows the whole frame in kept body text, and
//! this detector claims exactly that — and nothing else. A lone
//! `try {` without a `catch` clause, or a lone `catch` without a
//! `try`, is not a frame; neither is an identifier that merely
//! contains one of the words (`catch_count`, `entry_try_helper`). The
//! claim quotes the `catch` line, the clause that marks the block a
//! handler, and scores the reading in the high band — the ADR-0046
//! anchor for this family's confidences.

use crate::types::{ErrhandlingFinding, SehFrame};
use calxgloss_types::Confidence;

/// Confidence for a whole spelled `try`/`catch` frame (ADR-0046).
///
/// The band is high but not highest: the body text carries the whole
/// frame — open and handler — which is why the reading sits at 80.
/// It is not the catalog's top band, because the decompiler's C
/// spelling is its own normalization, and the exception-code paths
/// that hide in other bodies (issue #288) are the same construct
/// without the spelling; when those families land they score below
/// this anchor, so a report can rank what it is shown.
pub const SPELLED_FRAME_CONFIDENCE: u8 = 80;

/// The Rust pattern a spelled frame steers a translation toward.
///
/// The pattern keeps the frame's structure — a fallible body and a
/// handler — without pretending the SEH mechanism survives
/// translation: whether the Rust side uses `Result`, `catch_unwind`
/// or an explicit state machine is the translator's call, made with
/// the caller set in view (ADR-0029), and this suggestion only names
/// the shape the evidence points at.
pub const SEH_FRAME_SUGGESTION: &str = "wrap the guarded block and its handler in a Rust error-handling frame \
     (Result, or catch_unwind if the handler must survive FFI)";

/// Detect a spelled SEH `try`/`catch` frame in one function body.
///
/// The detector answers with at most one finding per function: the
/// frame is a function-level shape, so a body that spells it twice
/// (a second frame after the first) is still the one reading —
/// "this function handles exceptions in a frame" — and a second
/// finding would double-count the same claim. The detector fills no
/// function name — it never sees one; the engine stamps it.
#[derive(Debug, Clone, Copy, Default)]
pub struct SehFrameDetector;

impl SehFrameDetector {
    /// Detect the spelled frame in one decompiled body.
    ///
    /// The shape is read per line so the evidence is a real body line:
    /// a trimmed line that is exactly a `try {` opener, and a later
    /// line that opens a `catch` clause. Both must be block text —
    /// the words as whole lines or line openers, never as parts of
    /// identifiers.
    pub fn detect(&self, body: &str) -> Option<ErrhandlingFinding> {
        // Two passes, one cursor: find the opener, then look for a
        // catch clause *after* it, so a body that pairs a catch with
        // an earlier construct cannot claim a frame it doesn't have.
        let try_start = first_try_opener(body)?;
        let catch_line = first_catch_clause(body, try_start)?;
        Some(ErrhandlingFinding::SehFrame(SehFrame {
            function: String::new(),
            confidence: Confidence::new(SPELLED_FRAME_CONFIDENCE),
            evidence: catch_line.trim_end().to_string(),
            suggestion: SEH_FRAME_SUGGESTION.to_string(),
        }))
    }
}

/// The offset of the first line that opens a `try` block, or `None`
/// when no line does.
///
/// The line's trimmed text must begin with the word `try` followed
/// (after whitespace) by a block brace — the decompiler's spelling.
/// The word-boundary check is what keeps `try_it {` or a line merely
/// *containing* the word from counting as the opener.
fn first_try_opener(body: &str) -> Option<usize> {
    let mut offset = 0usize;
    for line in body.split_inclusive('\n') {
        let trimmed = line.trim_start();
        if let Some(rest) = trimmed.strip_prefix("try") {
            // The word boundary keeps `try_it {` from matching; the
            // brace check keeps `try (work());` from matching.
            if rest.starts_with(|c: char| c.is_whitespace()) && rest.trim_start().starts_with('{') {
                return Some(offset);
            }
        }
        offset += line.len();
    }
    None
}

/// The first `catch` clause line at or after `from`, as its full line,
/// or `None` when no line from there on opens a catch clause.
///
/// The line's trimmed text must begin with the whole word `catch`
/// followed (after optional whitespace, or on the next line) by a `(`
/// clause — the handler spelling — so an identifier containing the
/// word cannot match, and a bare `catch` claims nothing. The next-line
/// form is part of the decompiler's pinned spelling (`catch\r\n(\r\n`),
/// so CRLF-safe handling of the word boundary is load-bearing.
fn first_catch_clause(body: &str, from: usize) -> Option<&str> {
    let mut offset = 0usize;
    for line in body.split_inclusive('\n') {
        if offset > from {
            let trimmed = line.trim_start();
            if let Some(rest) = trimmed.strip_prefix("catch") {
                // `catch (`, `catch(` after any run of whitespace and
                // line endings — the clause may sit on the catch
                // word's own line or open the next line.
                let after = rest.trim_start_matches(|c: char| c.is_whitespace() || c == '\r');
                if after.starts_with('(') {
                    return Some(line);
                }
            }
        }
        offset += line.len();
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body_of(lines: &[&str]) -> String {
        format!("{}\n", lines.join("\n"))
    }

    #[test]
    fn spelled_frame_is_detected() {
        // The decompiler's own spelling of an SEH frame (the shape
        // pinned byte-for-byte by issue #286's tests): a `try {`
        // block and a `catch(...)` clause, both in kept body text.
        let body = body_of(&[
            "  try {",
            "    handle = CreateFileW(path, access);",
            "  }",
            "  catch(...){",
            "    handle = INVALID_HANDLE;",
            "  }",
        ]);
        let finding = SehFrameDetector
            .detect(&body)
            .expect("the spelled frame must be detected");
        assert_eq!(finding.confidence().value(), SPELLED_FRAME_CONFIDENCE);
        assert_eq!(
            finding.evidence(),
            "  catch(...){",
            "the catch line is the evidence"
        );
    }

    #[test]
    fn try_without_catch_claims_nothing() {
        // A lone `try {` is not a frame — the handler is the half
        // that makes the claim.
        let body = body_of(&["  try {", "    work();", "  }"]);
        assert!(SehFrameDetector.detect(&body).is_none());
    }

    #[test]
    fn catch_without_try_claims_nothing() {
        // The pair must both be present; and the catch must come
        // after the opener, as the frame's shape dictates.
        let body = body_of(&["  catch(...){", "    recover();", "  }"]);
        assert!(SehFrameDetector.detect(&body).is_none());
    }

    #[test]
    fn identifiers_holding_the_words_claim_nothing() {
        // The whole point of the line-shape rule: `catch_count`
        // references and `try_` helper names are body text, not
        // spelled frames.
        let body = body_of(&[
            "  catch_count++;",
            "  entry_try_helper(0);",
            "  if (code == try_code) { goto cleanup; }",
            "  cleanup: return catch_value;",
        ]);
        assert!(SehFrameDetector.detect(&body).is_none());
    }

    #[test]
    fn catch_without_a_clause_claims_nothing() {
        // `catch` as a bare word on its own — no `(` clause anywhere
        // near it — is not a handler spelling: a label or identifier
        // shaped like the word claims nothing.
        let body = body_of(&["  try {", "    work();", "  }", "  catch_all: goto done;"]);
        assert!(SehFrameDetector.detect(&body).is_none());
    }

    #[test]
    fn one_finding_per_function_even_with_two_frames() {
        // The frame is a function-level reading; spelling it twice
        // is still the one claim.
        let body = body_of(&[
            "  try {",
            "    a();",
            "  }",
            "  catch(...){",
            "    ha();",
            "  }",
            "  try {",
            "    b();",
            "  }",
            "  catch(DWORD code){",
            "    hb(code);",
            "  }",
        ]);
        let finding = SehFrameDetector
            .detect(&body)
            .expect("the first frame must be detected");
        assert_eq!(finding.evidence(), "  catch(...){");
    }

    #[test]
    fn try_opener_line_requires_the_block_brace() {
        // `try` at a line head without a block brace — e.g. a call —
        // is not the opener; the pairing must stay honest.
        let body = body_of(&["  try (work());", "  catch(...){", "  }"]);
        assert!(SehFrameDetector.detect(&body).is_none());
    }

    #[test]
    fn spaced_brace_spelling_also_counts() {
        // `try {` with the brace, and `catch (DWORD code) {` with a
        // typed clause and spaced brace: still the frame shape.
        let body = body_of(&[
            "  try {",
            "    work();",
            "  }",
            "  catch (DWORD code) {",
            "    handle(code);",
            "  }",
        ]);
        let finding = SehFrameDetector
            .detect(&body)
            .expect("the typed-clause spelling is still the frame");
        assert_eq!(finding.evidence(), "  catch (DWORD code) {");
    }

    #[test]
    fn detector_never_claims_a_function_itself() {
        // The detector fills no function name; the engine stamps it.
        let body = body_of(&["  try {", "  }", "  catch(...){", "  }"]);
        let finding = SehFrameDetector.detect(&body).unwrap();
        assert_eq!(finding.function(), "");
    }
}
