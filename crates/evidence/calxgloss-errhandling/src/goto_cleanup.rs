//! The goto-cleanup ladder detector.
//!
//! The C cleanup-on-failure idiom never reaches the decompiler's
//! spelled syntax — it survives as pure control flow: a ladder of
//! guarded early exits, each a `goto LAB_*` or `goto joined_r0x*`
//! standing in its guard's block, all converging on one shared tail
//! label whose block releases the function's resources and returns a
//! failure value. Where kept body text shows two or more such guarded
//! *forward* gotos landing on one label block that names a release
//! call, the function carries the ladder and this detector claims
//! exactly that — naming the join label and quoting the release line
//! as the evidence (issue #289, ADR-0046: the ladder joins the union
//! as its own kind, a different idiom from the SEH families). Where
//! the join block spells no release but ends in a shared constant
//! return, the same convergence lands a weaker claim.
//!
//! The silence is the load-bearing half: a lone goto — a loop's
//! back-edge, a single forward skip, a compiler join with no guard
//! behind it — claims nothing, and a convergence whose shared tail
//! releases nothing and returns no constant is ordinary control flow.
//! The reading is line-local like its siblings — string literals and
//! comments (which Ghidra sprinkles over label blocks) are blanked
//! before any shape is matched, so pseudo-C noise invents no rung.

use crate::identifier::{find_word, named_token, starts_call, starts_word};
use crate::types::{ErrhandlingFinding, GotoCleanup};
use calxgloss_types::Confidence;
use std::iter::Peekable;
use std::str::CharIndices;

/// Confidence for a ladder whose join block performs release calls
/// (issue #289's mid band).
///
/// The mid band, a rung below the exception-API call's 60 and every
/// SEH rung: the convergence is a real shape read off the gotos the
/// decompiler emitted, but unlike the SEH families nothing in the
/// body *names* the idiom — the claim is inferred from shape plus
/// release vocabulary, so it anchors at the bottom of ADR-0046's
/// family ladder and never outranks a spelled SEH block.
pub const GOTO_CLEANUP_RELEASE_CONFIDENCE: u8 = 55;

/// Confidence for a ladder whose join block only ends in a shared
/// constant return (issue #289's low band).
///
/// The low band: the convergence and the shared failure value are
/// there, but with no release call the block could be an ordinary
/// shared exit. The claim is honestly weak, and its score says so.
pub const GOTO_CLEANUP_RETURN_CONFIDENCE: u8 = 45;

/// The release-call vocabulary whose sighting in a join block
/// witnesses the cleanup: the deallocator and closer names the
/// memory crate pairs on (`free`, `VirtualFree`, `CloseHandle`,
/// `LocalFree`, `CoTaskMemFree`, `RegCloseKey`, `fclose`). The list
/// is hand-authored — a binary whose project owns its own allocator
/// grows the detector's set through
/// [`with_releases`](GotoCleanupDetector::with_releases).
pub const RELEASE_API_NAMES: [&str; 7] = [
    "free",
    "VirtualFree",
    "CloseHandle",
    "LocalFree",
    "CoTaskMemFree",
    "RegCloseKey",
    "fclose",
];

/// The Rust pattern a cleanup ladder steers a translation toward.
///
/// The ladder's translation failure mode is the nested-conditional
/// re-implementation that hides the shared cleanup; the honest shape
/// is the early return the guards already are, with the cleanup riding
/// RAII or a scope guard (ADR-0029's exact mapping belongs to the
/// translator, and this suggestion only names the shape the evidence
/// points at).
pub const GOTO_CLEANUP_SUGGESTION: &str = "return early from each guard and let RAII or a scope guard run the cleanup, rather than re-implementing the ladder as nested conditionals";

/// Detect a goto-cleanup ladder in one function body.
///
/// The detector answers with at most one finding per function — the
/// ladder is a function-level shape, and a body with two ladders is
/// still the one claim, taken at the join label whose line appears
/// first in body order — and fills no function name; the engine
/// stamps it. The detector owns the release-call vocabulary: the
/// standard [`RELEASE_API_NAMES`] set, grown by
/// [`with_releases`](Self::with_releases).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GotoCleanupDetector {
    releases: Vec<String>,
}

impl Default for GotoCleanupDetector {
    /// A detector carrying the standard release vocabulary.
    fn default() -> Self {
        Self {
            releases: RELEASE_API_NAMES
                .iter()
                .map(|name| (*name).to_string())
                .collect(),
        }
    }
}

impl GotoCleanupDetector {
    /// A detector carrying the standard release vocabulary —
    /// [`RELEASE_API_NAMES`].
    pub fn new() -> Self {
        Self::default()
    }

    /// A standard detector with `names` added to the release
    /// vocabulary — the seam a binary's project-owned release names
    /// plug into without replacing the standard set.
    pub fn with_releases(mut self, names: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.releases.extend(names.into_iter().map(Into::into));
        self
    }

    /// Detect the cleanup ladder in one decompiled body.
    ///
    /// The reading: label lines (the control-flow crate's `ident:`
    /// spelling) open jump-target blocks; a `goto` line is a rung
    /// when it stands in an enclosing guard block — an `if`/`else`
    /// arm, or the one-line `if (cond) goto LAB_x;` spelling — and
    /// its target label sits *later* in the body (a back-edge is a
    /// loop, not an exit). Two or more rungs landing on one label
    /// make that block the join: its first release-call line claims
    /// the [`GOTO_CLEANUP_RELEASE_CONFIDENCE`] band, failing that its
    /// last line being a constant return claims
    /// [`GOTO_CLEANUP_RETURN_CONFIDENCE`], and neither keeps the
    /// silence.
    pub fn detect(&self, body: &str) -> Option<ErrhandlingFinding> {
        // Pass one, one cursor: every label line, every goto line,
        // and whether the guard stack says the goto is guarded when
        // it runs. String literals and comments — Ghidra's own label
        // decoration among them — are blanked line by line first, so
        // no noise invents a rung, a label, or a release.
        let raw: Vec<&str> = body.lines().collect();
        let mut code: Vec<String> = Vec::with_capacity(raw.len());
        let mut in_block_comment = false;
        for line in &raw {
            code.push(blank_literals(line, &mut in_block_comment));
        }

        let mut labels: Vec<(&str, usize)> = Vec::new();
        let mut gotos: Vec<(&str, usize, bool)> = Vec::new();
        let mut guards: Vec<bool> = Vec::new();
        for (idx, line) in code.iter().enumerate() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            if let Some(name) = label_name(trimmed) {
                labels.push((name, idx));
            }
            if let Some((target, guarded)) = goto_target(trimmed, guards.last().copied()) {
                gotos.push((target, idx, guarded));
            }
            // Update the open-block stack from the line's blanked
            // braces. A brace opened on a line whose head word is
            // `if`/`else` marks a guard arm; every other opener —
            // loops, switch bodies, bare blocks — does not. The head
            // word is read past any peeled closing braces, so the
            // decompiler's `} else {` tail opens its guard arm. The
            // first-brace rule matches the one-head-per-line
            // spelling; a line opening two heads at once marks only
            // the first by its head word, which reads conservative.
            let head = trimmed.trim_start_matches('}').trim_start();
            let guard_opener = starts_word(head, "if") || starts_word(head, "else");
            let mut first_brace = true;
            for ch in trimmed.chars() {
                match ch {
                    '}' => {
                        guards.pop();
                    }
                    '{' => {
                        guards.push(guard_opener && first_brace);
                        first_brace = false;
                    }
                    _ => {}
                }
            }
        }

        // Pass two: the first join label (body order) with two or
        // more guarded forward rungs, then what its block spells.
        for (order, &(name, line)) in labels.iter().enumerate() {
            if labels[..order].iter().any(|(earlier, _)| *earlier == name) {
                continue; // a re-sighted label name is the same label
            }
            let rungs = gotos
                .iter()
                .filter(|(target, from, guarded)| *guarded && *target == name && *from < line)
                .count();
            if rungs < 2 {
                continue; // a lone goto — or a loop's back-edge — claims nothing
            }
            let end = labels
                .iter()
                .map(|&(_, at)| at)
                .find(|at| *at > line)
                .unwrap_or(code.len());
            if let Some(finding) = self.read_join_block(name, &raw, &code, line + 1..end) {
                return Some(finding);
            }
            // A convergence whose block claims neither release nor
            // shared constant return is ordinary control flow; a
            // later label may still hold a real ladder.
        }
        None
    }

    /// Read one join block for the ladder claim, over the code lines
    /// `range` (the lines *after* the label line): the first
    /// release-call line in body order lands the release band with
    /// that line as evidence; failing that, a block whose last
    /// meaningful line is a constant return lands the return band.
    /// Neither claim, and the block witnesses nothing.
    fn read_join_block(
        &self,
        label: &str,
        raw: &[&str],
        code: &[String],
        range: std::ops::Range<usize>,
    ) -> Option<ErrhandlingFinding> {
        for idx in range.clone() {
            if self
                .releases
                .iter()
                .any(|name| named_token(&code[idx], name).is_some_and(starts_call))
            {
                return Some(ladder_finding(
                    GOTO_CLEANUP_RELEASE_CONFIDENCE,
                    raw[idx].trim_end(),
                    label,
                ));
            }
        }
        let last = range
            .clone()
            .rev()
            .find(|idx| {
                let trimmed = code[*idx].trim();
                !trimmed.is_empty() && trimmed != "}"
            })
            .filter(|idx| constant_return(code[*idx].trim()))?;
        Some(ladder_finding(
            GOTO_CLEANUP_RETURN_CONFIDENCE,
            raw[last].trim_end(),
            label,
        ))
    }
}

/// A ladder finding at `band` with `evidence` and `label` as its
/// join label; the function name is the engine's to stamp.
fn ladder_finding(band: u8, evidence: &str, label: &str) -> ErrhandlingFinding {
    ErrhandlingFinding::GotoCleanup(GotoCleanup {
        function: String::new(),
        confidence: Confidence::new(band),
        evidence: evidence.to_string(),
        join_label: label.to_string(),
        suggestion: GOTO_CLEANUP_SUGGESTION.to_string(),
    })
}

/// The label name when `t` is a label line — `ident:` alone or
/// followed by `{` — as the control-flow crate reads label lines;
/// `default:` and `case` arms belong to a switch, not to a ladder.
fn label_name(t: &str) -> Option<&str> {
    let colon = t.find(':')?;
    let name = &t[..colon];
    if !label_ident(name) || name == "default" {
        return None;
    }
    let rest = t[colon + 1..].trim();
    (rest.is_empty() || rest == "{").then_some(name)
}

/// Whether `s` is a plain label identifier: alphanumerics and
/// underscores, not opening with a digit — the `LAB_*` and
/// `joined_r0x*` shapes and hand-named cleanup labels alike.
fn label_ident(s: &str) -> bool {
    !s.is_empty()
        && !s.starts_with(|c: char| c.is_ascii_digit())
        && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// The jump target and whether it stands behind a guard, when `t` is
/// a goto line: `goto ident;` inside the enclosing block the guard
/// stack reports, or the one-line `if (cond) goto ident;` spelling
/// whose guard is its own head word. A computed `goto *ptr;` or a
/// bare `goto` names no label and claims nothing.
fn goto_target(t: &str, enclosing_guard: Option<bool>) -> Option<(&str, bool)> {
    if starts_word(t, "goto") {
        let target = label_run(&t["goto".len()..])?;
        return Some((target, enclosing_guard == Some(true)));
    }
    if starts_word(t, "if") || starts_word(t, "else") {
        let at = find_word(t, "goto")?;
        let target = label_run(&t[at + "goto".len()..])?;
        return Some((target, true));
    }
    None
}

/// The label identifier opening `rest`, cut at its first
/// non-identifier character (the `;`, comment, or brace that ends it).
fn label_run(rest: &str) -> Option<&str> {
    let rest = rest.trim_start();
    let end = rest
        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .unwrap_or(rest.len());
    label_ident(&rest[..end]).then(|| &rest[..end])
}

/// Whether `t` is a `return` of a numeric constant — decimal or
/// `0x` hex, an optional sign — the shared failure value a cleanup
/// ladder converges on. A bare `return;`, a returned variable, or a
/// cast expression names no constant.
fn constant_return(t: &str) -> bool {
    if !starts_word(t, "return") {
        return false;
    }
    let value = t["return".len()..].trim().trim_end_matches(';').trim();
    let value = value.strip_prefix('-').unwrap_or(value);
    match value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        Some(hex) => !hex.is_empty() && hex.chars().all(|c| c.is_ascii_hexdigit()),
        None => !value.is_empty() && value.chars().all(|c| c.is_ascii_digit()),
    }
}

/// `line` with its string and character literals and its comments
/// blanked — `in_block_comment` carries an open `/* */` across
/// lines, exactly as the decompiler's own label decoration spells
/// it. The blanking, not the copy, is the point: a `puts("goto
/// LAB_100;")` invents no rung and a `/* free(pv) */` decoration
/// names no release call. The failure-code reading blanks the same
/// way, so a code spelled inside a string or a comment names no
/// contract.
pub(crate) fn blank_literals(line: &str, in_block_comment: &mut bool) -> String {
    let mut out = String::with_capacity(line.len());
    let mut chars = line.char_indices().peekable();
    while let Some((_, ch)) = chars.next() {
        if *in_block_comment {
            if ch == '*' && chars.peek().is_some_and(|&(_, next)| next == '/') {
                chars.next();
                *in_block_comment = false;
            }
            continue;
        }
        match ch {
            '"' | '\'' => skip_literal(&mut chars, ch),
            '/' => {
                let next = chars.peek().copied();
                if next.is_some_and(|(_, n)| n == '/') {
                    break; // to the end of the line
                } else if next.is_some_and(|(_, n)| n == '*') {
                    chars.next();
                    *in_block_comment = true;
                } else {
                    out.push('/');
                }
            }
            _ => out.push(ch),
        }
    }
    out
}

/// Advance past a string or character literal opened by its quote,
/// honouring backslash escapes; an unterminated literal runs to the
/// line's end, degrading with the truncated body rather than guessing.
fn skip_literal(chars: &mut Peekable<CharIndices<'_>>, quote: char) {
    while let Some((_, ch)) = chars.next() {
        if ch == '\\' {
            chars.next();
        } else if ch == quote {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exception_api::EXCEPTION_API_CONFIDENCE;
    use crate::seh_frame::SPELLED_FRAME_CONFIDENCE;

    fn body_of(lines: &[&str]) -> String {
        format!("{}\n", lines.join("\n"))
    }

    /// A body whose two guarded early exits both land on one cleanup
    /// label whose block closes the handle, frees the buffer, and
    /// returns the failure value.
    fn ladder_body(join: &str, cleanup: &[&str]) -> String {
        let rung = format!("    goto {join};");
        let label = format!("{join}:");
        let mut lines = vec![
            "  pvVar = LocalAlloc(flags, size);",
            "  if (pvVar == NULL) {",
            &rung,
            "  }",
            "  hFile = CreateFileW(path, access);",
            "  if (hFile == INVALID_HANDLE) {",
            &rung,
            "  }",
            "  do_work(pvVar, hFile);",
            "  return 0;",
            &label,
        ];
        lines.extend(cleanup.iter().copied());
        body_of(&lines)
    }

    #[test]
    fn a_ladder_converging_on_release_calls_lands_the_release_band() {
        let body = ladder_body(
            "LAB_140001a2c",
            &[
                "  CloseHandle(hFile);",
                "  LocalFree(pvVar);",
                "  return 0xffffffff;",
            ],
        );
        let finding = GotoCleanupDetector::new()
            .detect(&body)
            .expect("the convergence on a releasing block is the ladder");
        assert_eq!(finding.kind(), "goto_cleanup");
        assert_eq!(
            finding.confidence().value(),
            GOTO_CLEANUP_RELEASE_CONFIDENCE
        );
        match &finding {
            ErrhandlingFinding::GotoCleanup(record) => {
                assert_eq!(record.join_label, "LAB_140001a2c");
            }
            other => panic!("expected the ladder kind, got {other:?}"),
        }
        assert_eq!(finding.evidence(), "  CloseHandle(hFile);");
    }

    #[test]
    fn the_joined_r0x_spelling_is_a_join_label_too() {
        // The engine's own join spelling is as valid a convergence
        // point as a LAB_ label — the ladder shape is the same text
        // the control-flow crate reads.
        let body = ladder_body("joined_r0x140001f0", &["  free(pvVar);", "  return 0;"]);
        let finding = GotoCleanupDetector::new()
            .detect(&body)
            .expect("the joined-label convergence is the same ladder");
        match finding {
            ErrhandlingFinding::GotoCleanup(record) => {
                assert_eq!(record.join_label, "joined_r0x140001f0");
            }
            other => panic!("expected the ladder kind, got {other:?}"),
        }
    }

    #[test]
    fn each_seed_release_name_witnesses_the_join_block() {
        let bodies = RELEASE_API_NAMES.iter().map(|name| {
            ladder_body(
                "LAB_cleanup",
                &[&format!("  {name}(pvVar);"), "  return 0xffffffff;"],
            )
        });
        for body in bodies {
            let finding = GotoCleanupDetector::new()
                .detect(&body)
                .expect("the seeded release vocabulary witnesses the cleanup");
            assert_eq!(
                finding.confidence().value(),
                GOTO_CLEANUP_RELEASE_CONFIDENCE
            );
        }
    }

    #[test]
    fn a_builder_supplied_release_name_is_recognized() {
        // The vocabulary is extensible like every other name list:
        // the binary's project-owned release joins the standard set.
        let body = ladder_body("LAB_cleanup", &["  MyPoolFree(pvVar);", "  return iVar1;"]);
        assert!(
            GotoCleanupDetector::new().detect(&body).is_none(),
            "an unseeded name is not a release call"
        );
        let finding = GotoCleanupDetector::new()
            .with_releases(["MyPoolFree"])
            .detect(&body)
            .expect("the configured name witnesses the cleanup");
        assert_eq!(
            finding.confidence().value(),
            GOTO_CLEANUP_RELEASE_CONFIDENCE
        );
        assert_eq!(finding.evidence(), "  MyPoolFree(pvVar);");
    }

    #[test]
    fn a_builder_name_stands_in_call_shape_like_every_other_name() {
        // The identifier boundary is load-bearing: a configured name
        // merely stored or embedded in a longer name claims nothing.
        let body = ladder_body(
            "LAB_cleanup",
            &[
                "  pfFree = MyPoolFree;",
                "  ExtendedMyPoolFreeEx(pvVar);",
                "  return iVar1;",
            ],
        );
        assert!(
            GotoCleanupDetector::new()
                .with_releases(["MyPoolFree"])
                .detect(&body)
                .is_none()
        );
    }

    #[test]
    fn a_shared_constant_return_alone_lands_the_return_band() {
        let body = ladder_body("LAB_140001a2c", &["  return 0xffffffff;"]);
        let finding = GotoCleanupDetector::new()
            .detect(&body)
            .expect("the convergence on a shared failure value is a weak ladder");
        assert_eq!(finding.confidence().value(), GOTO_CLEANUP_RETURN_CONFIDENCE);
        assert_eq!(finding.evidence(), "  return 0xffffffff;");
    }

    #[test]
    fn a_lone_guarded_goto_claims_nothing() {
        // One early exit is one early exit — without the second rung
        // the shared tail is a shared tail, not a ladder.
        let body = body_of(&[
            "  if (pvVar == NULL) {",
            "    goto LAB_cleanup;",
            "  }",
            "  do_work(pvVar);",
            "LAB_cleanup:",
            "  free(pvVar);",
            "  return 0;",
        ]);
        assert!(GotoCleanupDetector::new().detect(&body).is_none());
    }

    #[test]
    fn a_loops_back_edge_to_its_own_label_claims_nothing() {
        // Backward gotos are loop control, never an early exit — even
        // beside a releasing block that follows.
        let body = body_of(&[
            "LAB_top:",
            "  do_work(pvVar);",
            "  if (again) {",
            "    goto LAB_top;",
            "  }",
            "  if (retry) {",
            "    goto LAB_top;",
            "  }",
            "  free(pvVar);",
            "  return 0;",
        ]);
        assert!(GotoCleanupDetector::new().detect(&body).is_none());
    }

    #[test]
    fn a_compiler_join_without_guards_claims_nothing() {
        // The engine's own fall-together `joined_r0x*` noise: guarded
        // once and unguarded once is one guard and a fall-through —
        // ordinary control flow, exactly the GS-canary body's shape.
        let body = body_of(&[
            "  if (uStack_8 == __security_cookie) {",
            "    goto joined_r0x140001337;",
            "  }",
            "  work();",
            "  goto joined_r0x140001337;",
            "joined_r0x140001337:",
            "  free(pvVar);",
            "  return uVar;",
        ]);
        assert!(GotoCleanupDetector::new().detect(&body).is_none());
    }

    #[test]
    fn a_shared_tail_that_claims_neither_release_nor_constant_return_is_ordinary_flow() {
        // Two guarded forward gotos do converge — but the shared
        // block merges the arms, it does not release or fail: the
        // ordinary goto-only body the silence exists for.
        let body = ladder_body("LAB_merge", &["  process(x);", "  return result;"]);
        assert!(GotoCleanupDetector::new().detect(&body).is_none());
    }

    #[test]
    fn release_calls_outside_the_join_block_claim_nothing() {
        // The release must stand in the block the rungs converge on;
        // cleanup scattered through the guarded body is not a shared
        // ladder, and here the one converging block returns a variable.
        let body = body_of(&[
            "  if (a == 0) {",
            "    free(pvVar);",
            "    goto LAB_exit;",
            "  }",
            "  if (b == 0) {",
            "    free(pvVar);",
            "    goto LAB_exit;",
            "  }",
            "LAB_exit:",
            "  return uVar;",
        ]);
        assert!(GotoCleanupDetector::new().detect(&body).is_none());
    }

    #[test]
    fn gotos_inside_string_literals_invent_no_rungs() {
        // A body that only *prints* the ladder text is a body that
        // prints: the blanking keeps the reading off Ghidra's own
        // string content.
        let body = body_of(&[
            "  puts(\"if (a) goto LAB_100;\");",
            "  puts(\"if (b) goto LAB_100;\");",
            "LAB_100:",
            "  free(pvVar);",
            "  return 0;",
        ]);
        assert!(GotoCleanupDetector::new().detect(&body).is_none());
    }

    #[test]
    fn a_comment_naming_a_release_is_not_the_release_call() {
        // Ghidra's label decoration comments (`/* free at LAB_100 */`)
        // sit over real cleanup blocks; the blanked reading takes the
        // call from the code line or not at all.
        let body = body_of(&[
            "  if (a == 0) {",
            "    goto LAB_100;",
            "  }",
            "  if (b == 0) {",
            "    goto LAB_100;",
            "  }",
            "LAB_100:  /* free(pvVar) already done at block#7 */",
            "  return uVar;",
        ]);
        assert!(GotoCleanupDetector::new().detect(&body).is_none());
    }

    #[test]
    fn the_one_line_guarded_goto_spelling_counts_as_a_rung() {
        // `if (cond) goto LAB_x;` carries its own guard on the line —
        // both rungs spelled that way still converge.
        let body = body_of(&[
            "  if (pvVar == NULL) goto LAB_cleanup;",
            "  work(pvVar);",
            "  if (h == 0) goto LAB_cleanup;",
            "LAB_cleanup:",
            "  free(pvVar);",
            "  return 0;",
        ]);
        let finding = GotoCleanupDetector::new()
            .detect(&body)
            .expect("both rungs stand behind their one-line guards");
        assert_eq!(
            finding.confidence().value(),
            GOTO_CLEANUP_RELEASE_CONFIDENCE
        );
    }

    #[test]
    fn a_rung_guarded_inside_a_loop_body_still_counts() {
        // An early exit from inside a loop is guarded by its `if`,
        // not by the loop around it — the innermost open block is the
        // guard, and the goto runs forward past the loop.
        let body = body_of(&[
            "  for (i = 0; i < 3; i = i + 1) {",
            "    if (bad(i)) {",
            "      goto LAB_cleanup;",
            "    }",
            "  }",
            "  if (worse) {",
            "    goto LAB_cleanup;",
            "  }",
            "LAB_cleanup:",
            "  fclose(f);",
            "  return 0;",
        ]);
        assert!(GotoCleanupDetector::new().detect(&body).is_some());
    }

    #[test]
    fn a_ladder_converging_on_a_variable_return_claims_nothing() {
        // `return 0;` is a spelled failure value; a returned variable
        // names no constant and witnesses no shared failure.
        let body = ladder_body("LAB_exit", &["  return uVar;"]);
        assert!(GotoCleanupDetector::new().detect(&body).is_none());
    }

    #[test]
    fn one_finding_per_function_however_many_ladders() {
        // The ladder is a function-level reading; two ladders claim
        // the first join label in body order once.
        let body = body_of(&[
            "  if (a) {",
            "    goto LAB_one;",
            "  }",
            "  if (b) {",
            "    goto LAB_two;",
            "  }",
            "  if (c) {",
            "    goto LAB_one;",
            "  }",
            "  if (d) {",
            "    goto LAB_two;",
            "  }",
            "LAB_one:",
            "  free(p1);",
            "  return 0;",
            "LAB_two:",
            "  free(p2);",
            "  return 0;",
        ]);
        let finding = GotoCleanupDetector::new()
            .detect(&body)
            .expect("the function holds a ladder");
        match finding {
            ErrhandlingFinding::GotoCleanup(record) => {
                assert_eq!(record.join_label, "LAB_one");
            }
            other => panic!("expected the ladder kind, got {other:?}"),
        }
    }

    #[test]
    fn identifiers_holding_the_goto_word_claim_no_rung() {
        // The word boundary again: `gotolink()` is a call, `goto_count`
        // is a variable, and `goto` as a head word never arrives.
        let body = body_of(&[
            "  gotolink(LAB_100);",
            "  goto_count = 2;",
            "  my_goto(LAB_100);",
            "LAB_100:",
            "  free(pvVar);",
            "  return 0;",
        ]);
        assert!(GotoCleanupDetector::new().detect(&body).is_none());
    }

    #[test]
    fn the_else_arm_of_a_guard_is_a_guard_too() {
        // The `} else {` tail opens a guard arm: two rungs behind
        // else arms of different guards still converge.
        let body = body_of(&[
            "  if (a != 0) {",
            "    work1();",
            "  } else {",
            "    goto LAB_cleanup;",
            "  }",
            "  if (b != 0) {",
            "    work2();",
            "  } else {",
            "    goto LAB_cleanup;",
            "  }",
            "LAB_cleanup:",
            "  free(pvVar);",
            "  return 0;",
        ]);
        assert!(GotoCleanupDetector::new().detect(&body).is_some());
    }

    #[test]
    fn the_ladder_bands_sit_at_the_bottom_of_the_family_ladder() {
        // ADR-0046's ladder, continued: the ladder's release band
        // lands below the exception-API rung, its return band below
        // that — and neither can ever outrank a spelled SEH block
        // (issue #289's ranking gate).
        const {
            assert!(
                EXCEPTION_API_CONFIDENCE > GOTO_CLEANUP_RELEASE_CONFIDENCE
                    && GOTO_CLEANUP_RELEASE_CONFIDENCE > GOTO_CLEANUP_RETURN_CONFIDENCE
                    && GOTO_CLEANUP_RELEASE_CONFIDENCE < SPELLED_FRAME_CONFIDENCE
            )
        };
    }

    #[test]
    fn detector_never_claims_a_function_itself() {
        let body = ladder_body("LAB_cleanup", &["  free(pvVar);", "  return 0;"]);
        let finding = GotoCleanupDetector::new().detect(&body).unwrap();
        assert_eq!(finding.function(), "");
    }
}
