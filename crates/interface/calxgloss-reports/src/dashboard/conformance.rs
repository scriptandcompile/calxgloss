//! The per-binary conformance verdict on the review surfaces (issue #419,
//! P26.3): whether a target binary's restitch work is honestly closed.
//!
//! One derived join serves every reader, the way
//! [`audit`](super::audit) does for the unknown ledger and
//! [`scenarios`](super::scenarios) does for the scenario status. Each
//! binary's *obligation ledger* is read through [`read_obligation_ledger`]
//! — which keeps a never-filed document apart from a tampered one — and
//! joins at read time with branch state, the attempt branch's committed
//! *verification receipt* pair, the Accept records, and the unknown
//! ledgers. The terminal dashboard and the model's JSON render from these
//! rows. Nothing here stores a verdict, so no second copy of the truth
//! can drift from the first. The layer reads only: it never accepts a
//! unit, touches a branch, or changes a review status.

use std::collections::BTreeSet;
use std::path::Path;

use calxgloss_git::GitManager;
use calxgloss_types::{
    BinaryConformance, BinaryIdentity, BinaryUnknownLedger, ConformanceOpenObligation,
    ConformanceTally, ConformanceUnknownCause, ConformanceVerdict, GitBranch,
    ObligationDisposition, ObligationEntry, PersistError, UnknownSeverity, VerificationReceipt,
    VerificationVerdict, obligation_ledger_dir, read_obligation_ledger, verification_receipt_path,
};

use super::render::{green_bold, yellow_bold};

/// Every binary the conformance rows must name: the binaries of the
/// model's translated units (supporting shim and classification work is
/// not a target binary and gets no verdict), plus every obligation
/// ledger filed under `re/obligations/`. The builder derives the rows
/// over this set so a binary with a filed ledger but no branch is still
/// named (issue #419).
pub fn conformance_binaries(
    workspace: &std::path::Path,
    model_binaries: impl IntoIterator<Item = String>,
) -> BTreeSet<String> {
    let mut binaries: BTreeSet<String> = model_binaries.into_iter().collect();
    if let Ok(entries) = std::fs::read_dir(obligation_ledger_dir(workspace)) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|ext| ext.to_str()) == Some("json")
                && let Some(stem) = path.file_stem().and_then(|stem| stem.to_str())
            {
                binaries.insert(stem.to_string());
            }
        }
    }
    binaries
}

/// Derive one conformance row per binary: the filed obligation ledger
/// joined with branch state, the receipt pairs committed on the attempt
/// branches, the Accept records, and the binary's open-unknown reading
/// from the dashboard model's unknown-ledger rows. A *complete* verdict
/// requires every obligation closed on checked evidence and an unknown
/// ledger proven open-free of blocking records — fail-closed aggregation,
/// so an unproven gate never reads as a clean run (issue #392).
pub fn derive_binary_conformance(
    git: &GitManager,
    binaries: &BTreeSet<String>,
    unknown_rows: &[BinaryUnknownLedger],
) -> Vec<BinaryConformance> {
    binaries
        .iter()
        .map(|binary| conformance_row(git, binary, unknown_rows))
        .collect()
}

/// How one green claim (a *claimed-verified* entry) reads when its
/// evidence is checked against the branch, the receipt pair, and the
/// review record.
enum ClaimReading {
    /// Every leg stands: the entry can close.
    Closed,
    /// A leg is honestly absent or negative — merged without an Accept,
    /// a receipt verdict that is not green, an owner digest that no
    /// longer names the branch tip. The obligation stays open. This is
    /// incompleteness, not an unreadable record.
    Open(String),
    /// A leg is an input error: the cited pair cannot be resolved on the
    /// attempt branch. Like a corrupt document, this fails loudly and
    /// lands a named unknown cause on the verdict.
    CitationFault(String),
}

fn conformance_row(
    git: &GitManager,
    binary: &str,
    unknown_rows: &[BinaryUnknownLedger],
) -> BinaryConformance {
    let identity = BinaryIdentity::from(binary);
    let ledger = match read_obligation_ledger(git.repo_path(), &identity) {
        Ok(ledger) => ledger,
        Err(PersistError::NotFound { .. }) => {
            // The never-filed ledger: unknown naming its cause, never a
            // clean run (issue #419).
            return BinaryConformance {
                binary: binary.to_string(),
                verdict: ConformanceVerdict::Unknown,
                causes: vec![ConformanceUnknownCause::NoLedgerFiled],
                closure_digest: None,
                tally: ConformanceTally::default(),
                first_open: None,
                blocking_unknowns: Vec::new(),
            };
        }
        Err(err) => {
            // Tampered, replaced, or invalid bytes: the reader names the
            // input error here, at the read, and the verdict falls to
            // unknown — never a pass (issue #419).
            eprintln!(
                "  [conformance] {binary}: obligation ledger read is an input error, \
                 verdict falls to unknown: {err}"
            );
            return BinaryConformance {
                binary: binary.to_string(),
                verdict: ConformanceVerdict::Unknown,
                causes: vec![ConformanceUnknownCause::DigestMismatch],
                closure_digest: None,
                tally: ConformanceTally::default(),
                first_open: None,
                blocking_unknowns: Vec::new(),
            };
        }
    };

    if ledger.entries.is_empty() {
        // A sealed roster naming nothing proves nothing: fail-closed means
        // an empty ledger never reads complete (issue #392's whole point).
        return BinaryConformance {
            binary: binary.to_string(),
            verdict: ConformanceVerdict::Unknown,
            causes: vec![ConformanceUnknownCause::NoObligationsFiled],
            closure_digest: None,
            tally: ConformanceTally::default(),
            first_open: None,
            blocking_unknowns: Vec::new(),
        };
    }
    let mut row = BinaryConformance {
        binary: binary.to_string(),
        verdict: ConformanceVerdict::Unknown,
        causes: Vec::new(),
        closure_digest: Some(ledger.digest.clone()),
        tally: ConformanceTally::default(),
        first_open: None,
        blocking_unknowns: Vec::new(),
    };
    let mut obligations_open = false;
    let mut first_open: Option<ConformanceOpenObligation> = None;
    for entry in &ledger.entries {
        match entry.disposition {
            ObligationDisposition::ClaimedVerified => match close_claim(git, &identity, entry) {
                ClaimReading::Closed => row.tally.verified += 1,
                ClaimReading::Open(reason) => {
                    obligations_open = true;
                    first_open.get_or_insert_with(|| ConformanceOpenObligation {
                        function: entry.function.clone(),
                        attempt: entry.attempt,
                        link: reason.clone(),
                    });
                    eprintln!(
                        "  [conformance] {binary}: obligation `{}` attempt {} stays open — {reason}",
                        entry.function, entry.attempt
                    );
                }
                ClaimReading::CitationFault(reason) => {
                    obligations_open = true;
                    push_cause(
                        &mut row,
                        ConformanceUnknownCause::UnresolvableReceiptCitation,
                    );
                    eprintln!(
                        "  [conformance] {binary}: `{}` attempt {} cites an unresolvable \
                         verifier receipt — {reason}",
                        entry.function, entry.attempt
                    );
                }
            },
            disposition => {
                // Honest dispositions never count toward closure (issue
                // #392): every one holds its obligation open and keeps its
                // own tally, counted apart from the verified (issue #419,
                // AC 4).
                obligations_open = true;
                match disposition {
                    ObligationDisposition::Skipped => row.tally.skipped += 1,
                    ObligationDisposition::Parked => row.tally.parked += 1,
                    ObligationDisposition::Overridden => row.tally.overridden += 1,
                    ObligationDisposition::UnReviewed => row.tally.un_reviewed += 1,
                    ObligationDisposition::NoBaseline => row.tally.no_baseline += 1,
                    ObligationDisposition::ClaimedVerified => {}
                }
            }
        }
    }

    if !row.causes.is_empty() {
        return row; // unknown: the records themselves failed to read.
    }
    row.blocking_unknowns = unknowns_gate_reasons(binary, unknown_rows);
    row.verdict = if !obligations_open && row.blocking_unknowns.is_empty() {
        ConformanceVerdict::Complete
    } else {
        // The first chain link that broke, named beside the counts, so
        // the operator has a first thing to fix (issue #419, AC 1).
        row.first_open = first_open;
        ConformanceVerdict::Incomplete
    };
    row
}

/// Push one named cause, keeping the cause list free of repeats.
fn push_cause(row: &mut BinaryConformance, cause: ConformanceUnknownCause) {
    if !row.causes.contains(&cause) {
        row.causes.push(cause);
    }
}

/// The blocking-unknown gate: *complete* requires the binary's open
/// unknown state proven free of blocking-severity records. A state that
/// cannot be proven — no unknown-ledger row, or a reading whose records
/// never arrived — keeps the gate shut. Every reason the gate refuses to
/// open comes back named (the severity ADR-0056 declared for this gate,
/// issue #392; issue #419 names the verdict's own reason).
fn unknowns_gate_reasons(binary: &str, unknown_rows: &[BinaryUnknownLedger]) -> Vec<String> {
    let Some(ledger_row) = unknown_rows
        .iter()
        .find(|row| row.binary.as_str() == binary)
    else {
        return vec![
            "no unknown-ledger row names this binary, so its open unknowns are unproven"
                .to_string(),
        ];
    };
    match ledger_row.unknowns.open.as_ref() {
        None => vec![
            "the binary's unknown ledger never reported its open set, so blocking records are unproven"
                .to_string(),
        ],
        Some(open) => open
            .iter()
            .filter(|unknown| unknown.severity == UnknownSeverity::Blocking)
            .map(|unknown| {
                format!(
                    "an open `{}` unknown record `{}` stands at blocking severity",
                    unknown.kind, unknown.id
                )
            })
            .collect(),
    }
}

/// Check one green claim against the evidence the entry pins: its owner
/// digest against the attempt branch's tip, its citation against the
/// receipt pair committed there, the Accept review action, and the
/// merged state.
fn close_claim(
    git: &GitManager,
    identity: &BinaryIdentity,
    entry: &ObligationEntry,
) -> ClaimReading {
    // The unit's attempt branch as every other writer spells it, from
    // the entry's own unit key (issue #68 naming).
    let branch = match GitBranch::new(identity.as_str(), &entry.function, entry.attempt) {
        Ok(branch) => branch,
        Err(_) => {
            return ClaimReading::CitationFault(
                "the entry's unit key does not spell an attempt branch".to_string(),
            );
        }
    };
    let Some(branch_ref) = git
        .repo()
        .find_branch(&branch.name, git2::BranchType::Local)
        .ok()
    else {
        return ClaimReading::CitationFault(format!(
            "no attempt branch `{}` stands to carry the receipt pair",
            branch.name
        ));
    };
    let tip = match branch_ref.get().peel_to_commit() {
        Ok(tip) => tip,
        Err(_) => {
            return ClaimReading::CitationFault(format!(
                "attempt branch `{}` cannot be read",
                branch.name
            ));
        }
    };

    // The owner pin: the entry speaks for the exact content its owner
    // digest names, and the branch tip is the only candidate (issue
    // #392, story 9).
    if entry.owner_commit != tip.id().to_string() {
        return ClaimReading::Open(format!(
            "branch `{}` tip {} no longer names the entry's owner {}",
            branch.name,
            tip.id(),
            entry.owner_commit
        ));
    }

    // The receipt pair, resolved on the attempt branch itself — not from
    // any workspace copy that a later checkout could have moved.
    let receipt = match branch_receipt(git, &tip, identity, &entry.function, entry.attempt) {
        Ok(receipt) => receipt,
        Err(reason) => return ClaimReading::CitationFault(reason),
    };

    // The citation must seal to the pair, and the pair must speak for
    // this exact unit and attempt — another attempt's green run can
    // never close this obligation (issue #392, stories 8 and 10).
    let Some(citation) = entry.receipt_digest.as_deref() else {
        return ClaimReading::CitationFault("the entry cites no verifier receipt".to_string());
    };
    match receipt.content_digest() {
        Err(err) => {
            return ClaimReading::CitationFault(format!("receipt digest unreadable: {err}"));
        }
        Ok(seal) if seal != citation => {
            return ClaimReading::CitationFault(format!(
                "cited {citation}, the pair on the branch seals {seal}"
            ));
        }
        Ok(_) => {}
    }
    if receipt.binary != *identity
        || receipt.function != entry.function
        || receipt.attempt != entry.attempt
    {
        return ClaimReading::CitationFault(format!(
            "the pair on `{}` speaks for {} / {} attempt {}, not this entry",
            branch.name, receipt.binary, receipt.function, receipt.attempt
        ));
    }
    if receipt.verdict != VerificationVerdict::Passed {
        return ClaimReading::Open(format!(
            "the cited receipt verdict is `{}`, never a green close",
            serde_json::to_value(receipt.verdict)
                .ok()
                .and_then(|value| value.as_str().map(str::to_string))
                .unwrap_or_else(|| format!("{:?}", receipt.verdict).to_lowercase())
        ));
    }

    // Review is the only door into verified: a merged branch with no
    // standing Accept action never closes an obligation (issue #392,
    // story 6).
    if !accept_record_stands(git.repo_path(), identity, &entry.function, entry.attempt) {
        return ClaimReading::Open("no Accept review action stands for this attempt".to_string());
    }
    if !git
        .is_branch_merged_into_main(&branch.name)
        .unwrap_or(false)
    {
        return ClaimReading::Open(format!("branch `{}` is not merged into main", branch.name));
    }
    ClaimReading::Closed
}

/// Read one attempt's *verification receipt* from the branch tip's own
/// tree: the JSON authority plus its Markdown twin, both committed. A
/// half pair verifies nothing, the same rule the commit sites state
/// (issue #413).
fn branch_receipt(
    git: &GitManager,
    tip: &git2::Commit,
    identity: &BinaryIdentity,
    function: &str,
    attempt: u32,
) -> Result<VerificationReceipt, String> {
    let json_path = verification_receipt_path(git.repo_path(), identity, function, attempt);
    let rel_json = json_path
        .strip_prefix(git.repo_path())
        .unwrap_or(json_path.as_path())
        .to_string_lossy()
        .into_owned();
    let rel_md_full = json_path.with_extension("md");
    let rel_md = rel_md_full
        .strip_prefix(git.repo_path())
        .unwrap_or(rel_md_full.as_path())
        .to_path_buf();
    let tree = tip
        .tree()
        .map_err(|_| format!("attempt branch `{}` has no readable tree", identity))?;
    let bytes = {
        let entry = tree
            .get_path(Path::new(&rel_json))
            .map_err(|_| format!("no receipt pair is committed on the branch at `{rel_json}`"))?;
        let object = git
            .repo()
            .find_object(entry.id(), None)
            .map_err(|_| format!("receipt blob at `{rel_json}` cannot be read"))?;
        object
            .peel_to_blob()
            .map_err(|_| format!("receipt blob at `{rel_json}` is not a file"))?
            .content()
            .to_vec()
    };
    tree.get_path(&rel_md).map_err(|_| {
        format!("the receipt pair at `{rel_json}` is half-committed — its Markdown twin is missing")
    })?;
    let receipt: VerificationReceipt = serde_json::from_slice(&bytes)
        .map_err(|err| format!("the receipt does not parse: {err}"))?;
    Ok(receipt)
}

/// Whether one Accept review action stands for the attempt: a record
/// under `re/accepts/{binary}/{function}/v{attempt}.json` whose merge
/// result is a landed merge, not a conflict report (issue #83 kept
/// conflicts honest in the record. This reads that).
fn accept_record_stands(
    workspace: &Path,
    branch_binary: &str,
    function: &str,
    attempt: u32,
) -> bool {
    let path = workspace
        .join("re")
        .join("accepts")
        .join(branch_binary)
        .join(function)
        .join(format!("v{attempt}.json"));
    let Ok(text) = std::fs::read_to_string(path) else {
        return false;
    };
    let Ok(record) = serde_json::from_str::<serde_json::Value>(&text) else {
        return false;
    };
    record
        .get("merge_result")
        .and_then(|result| result.as_str())
        .is_some_and(|result| result.starts_with("merged:") || result == "already_up_to_date")
}

/// The header the review surfaces print above the per-binary conformance
/// rows (issue #419).
pub fn conformance_header() -> String {
    "  Conformance — restitch closure per binary".to_string()
}

/// One binary's conformance lines, shared byte-for-byte by every reader
/// of the section (issue #419). An *unknown* verdict names its causes,
/// and a row broken mid-read shows the tallies it counted before the
/// fault. A *complete* verdict says what sealed it; an *incomplete*
/// verdict shows the verified count beside the honest dispositions held
/// apart from it, and names the first broken link and any blocking
/// unknown below the counts.
pub fn conformance_lines(row: &BinaryConformance) -> Vec<String> {
    match row.verdict {
        ConformanceVerdict::Complete => {
            let seal = row
                .closure_digest
                .as_deref()
                .map(|digest| {
                    digest
                        .trim_start_matches("sha256:")
                        .chars()
                        .take(8)
                        .collect::<String>()
                })
                .unwrap_or_else(|| "?".to_string());
            vec![green_bold(&format!(
                "  {} — complete ({} verified, sealed {seal})",
                row.binary, row.tally.verified
            ))]
        }
        ConformanceVerdict::Incomplete => {
            let mut lines = styled_wrapped(&format!(
                "  {} — incomplete ({})",
                row.binary,
                tally_words(row).join(", ")
            ));
            if let Some(open) = &row.first_open {
                lines.extend(wrapped(&format!(
                    "    ↳ first open: {} attempt {} — {}",
                    open.function, open.attempt, open.link
                )));
            }
            for reason in &row.blocking_unknowns {
                lines.extend(wrapped(&format!("    ↳ unknown gate: {reason}")));
            }
            lines
        }
        ConformanceVerdict::Unknown => {
            let causes: Vec<String> = row
                .causes
                .iter()
                .map(|cause| format!("{cause}").replace('_', " "))
                .collect();
            // The tallies of a row broken mid-read still ride the JSON,
            // so the terminal shows them too — the two surfaces state
            // the same facts (issue #419, AC 4).
            let tally = if row.tally == ConformanceTally::default() {
                String::new()
            } else {
                format!(" ({})", tally_words(row).join(", "))
            };
            styled_wrapped(&format!(
                "  {} — unknown: {} — never a clean run{tally}",
                row.binary,
                if causes.is_empty() {
                    "unnamed cause".to_string()
                } else {
                    causes.join(", ")
                }
            ))
        }
    }
}

/// The nonzero counts behind a verdict — verified first, each honest
/// disposition held apart from it — in the same words the JSON carries
/// (issue #419, AC 4).
fn tally_words(row: &BinaryConformance) -> Vec<String> {
    let mut counts = vec![format!("{} verified", row.tally.verified)];
    for (count, label) in [
        (row.tally.skipped, "skipped"),
        (row.tally.parked, "parked"),
        (row.tally.overridden, "overridden"),
        (row.tally.un_reviewed, "un-reviewed"),
        (row.tally.no_baseline, "no-baseline"),
    ] {
        if count > 0 {
            counts.push(format!("{count} {label}"));
        }
    }
    counts
}

/// The frame's visible width. The frame clips at this width, so a long
/// row wraps and no count hides (the rule, not a guess).
const VISIBLE_WIDTH: usize = super::render::SEP_WIDTH;

/// One logical line, wrapped to the frame width with continuation lines
/// indented two columns past the line's own indent — so a long cause
/// list or broken-link sentence never hides behind the clip.
fn wrapped(text: &str) -> Vec<String> {
    wrapped_within(text, VISIBLE_WIDTH)
}

fn wrapped_within(text: &str, limit: usize) -> Vec<String> {
    let indent = text.len() - text.trim_start().len();
    let cont = " ".repeat(indent + 2);
    let mut lines = Vec::new();
    let mut current = String::new();
    for word in text.split(' ') {
        let candidate = if current.is_empty() || current == cont {
            format!("{current}{word}")
        } else {
            format!("{current} {word}")
        };
        if current.is_empty() || candidate.chars().count() <= limit {
            current = candidate;
        } else {
            lines.push(current);
            current = format!("{cont}{word}");
        }
    }
    if !current.is_empty() {
        lines.push(current);
    }
    lines
}

/// The first line bold-colored, the continuations plain — same palette
/// decision the scenario and unknown sections keep. The frame counts the
/// escape's bracket bytes toward the line's width (only ESC itself is
/// free), so the colored line wraps ten characters early to never clip.
fn styled_wrapped(text: &str) -> Vec<String> {
    const ANSI_OVERHEAD: usize = 10; // "[1m" + "[33m" + "[0m"
    let mut lines = wrapped_within(text, VISIBLE_WIDTH - ANSI_OVERHEAD);
    if !lines.is_empty() {
        lines[0] = yellow_bold(&lines[0]);
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Drop the color escapes (ESC through `m`) so an assertion can read a
    /// wrapped, colored sentence as one line again.
    fn strip_ansi(text: &str) -> String {
        let mut out = String::new();
        let mut chars = text.chars().peekable();
        while let Some(c) = chars.next() {
            if c == '\u{1b}' {
                for next in chars.by_ref() {
                    if next == 'm' {
                        break;
                    }
                }
            } else {
                out.push(c);
            }
        }
        out
    }

    fn row(
        verdict: ConformanceVerdict,
        causes: Vec<ConformanceUnknownCause>,
        tally: ConformanceTally,
        closure_digest: Option<&str>,
    ) -> BinaryConformance {
        BinaryConformance {
            binary: "game_logic.dll".to_string(),
            verdict,
            causes,
            closure_digest: closure_digest.map(str::to_string),
            tally,
            first_open: None,
            blocking_unknowns: Vec::new(),
        }
    }

    #[test]
    fn complete_line_names_the_verified_count_and_the_seal() {
        let lines = conformance_lines(&row(
            ConformanceVerdict::Complete,
            Vec::new(),
            ConformanceTally {
                verified: 11,
                ..Default::default()
            },
            Some("sha256:deadbeeffeedface"),
        ));
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("game_logic.dll — complete (11 verified, sealed deadbeef)"));
    }

    #[test]
    fn incomplete_line_shows_each_nonzero_disposition_apart_from_verified() {
        let joined: String = conformance_lines(&row(
            ConformanceVerdict::Incomplete,
            Vec::new(),
            ConformanceTally {
                verified: 2,
                skipped: 3,
                parked: 1,
                overridden: 0,
                un_reviewed: 4,
                no_baseline: 0,
            },
            Some("sha256:seal"),
        ))
        .iter()
        .map(|line| strip_ansi(line).trim().to_string())
        .collect::<Vec<_>>()
        .join(" ");
        assert!(joined.contains("incomplete (2 verified, 3 skipped, 1 parked, 4 un-reviewed)"));
        assert!(
            !joined.contains("overridden") && !joined.contains("no-baseline"),
            "zero counts never clutter the line: {joined}"
        );
    }

    #[test]
    fn unknown_line_names_its_causes_in_words_never_zeros() {
        let lines = conformance_lines(&row(
            ConformanceVerdict::Unknown,
            vec![
                ConformanceUnknownCause::NoLedgerFiled,
                ConformanceUnknownCause::UnresolvableReceiptCitation,
            ],
            ConformanceTally::default(),
            None,
        ));
        let joined: String = lines
            .iter()
            .map(|line| strip_ansi(line).trim().to_string())
            .collect::<Vec<_>>()
            .join(" ");
        assert!(joined.contains(
            "unknown: no ledger filed, unresolvable receipt citation — never a clean run"
        ));
        assert!(
            !joined.contains("0 verified"),
            "absent tallies never render as zeros"
        );
    }

    #[test]
    fn unknown_line_shows_the_tally_counted_before_the_read_broke() {
        // The JSON carries the tallies of a row broken mid-read, so the
        // terminal states them too — the surfaces never disagree (AC 4).
        let joined: String = conformance_lines(&row(
            ConformanceVerdict::Unknown,
            vec![ConformanceUnknownCause::UnresolvableReceiptCitation],
            ConformanceTally {
                verified: 3,
                skipped: 2,
                ..Default::default()
            },
            Some("sha256:seal"),
        ))
        .iter()
        .map(|line| strip_ansi(line).trim().to_string())
        .collect::<Vec<_>>()
        .join(" ");
        assert!(joined.contains(&format!(
            "unknown: unresolvable receipt citation — never a clean run ({} verified, {} skipped)",
            3, 2
        )));
    }

    #[test]
    fn incomplete_line_names_the_unknown_gate_blocker_below_the_counts() {
        // A closed evidence chain held shut by a blocking unknown still
        // says what holds it (issue #419): the record is named, not the
        // counts alone.
        let mut row = row(
            ConformanceVerdict::Incomplete,
            Vec::new(),
            ConformanceTally {
                verified: 4,
                ..Default::default()
            },
            Some("sha256:seal"),
        );
        row.blocking_unknowns = vec![
            "an open `export_uncovered` unknown record `unknown-export-uncovered` stands at blocking severity"
                .to_string(),
        ];
        let joined: String = conformance_lines(&row)
            .iter()
            .map(|line| strip_ansi(line).trim().to_string())
            .collect::<Vec<_>>()
            .join(" ");
        assert!(joined.contains("incomplete (4 verified)"));
        assert!(joined.contains(
            "↳ unknown gate: an open `export_uncovered` unknown record `unknown-export-uncovered` stands at blocking severity"
        ));
    }

    #[test]
    fn incomplete_line_names_the_first_broken_link_below_the_counts() {
        let mut row = row(
            ConformanceVerdict::Incomplete,
            Vec::new(),
            ConformanceTally {
                verified: 10,
                ..Default::default()
            },
            Some("sha256:seal"),
        );
        row.first_open = Some(calxgloss_types::ConformanceOpenObligation {
            function: "claim v2".to_string(),
            attempt: 2,
            link: "no Accept review action stands for this attempt".to_string(),
        });
        let lines = conformance_lines(&row);
        assert!(lines[0].contains("incomplete (10 verified)"));
        let joined: String = lines
            .iter()
            .map(|line| strip_ansi(line).trim().to_string())
            .collect::<Vec<_>>()
            .join(" ");
        assert!(joined.contains(
            "↳ first open: claim v2 attempt 2 — no Accept review action stands for this attempt"
        ));
    }

    #[test]
    fn a_long_incomplete_line_wraps_within_the_frame_and_hides_no_count() {
        let lines = conformance_lines(&row(
            ConformanceVerdict::Incomplete,
            Vec::new(),
            ConformanceTally {
                verified: 1,
                skipped: 1,
                parked: 1,
                overridden: 1,
                un_reviewed: 1,
                no_baseline: 1,
            },
            Some("sha256:seal"),
        ));
        assert!(lines.len() > 1, "a wide tally continues, never clips");
        for line in &lines {
            let visible: String = line.chars().filter(|c| !c.is_control()).collect();
            assert!(
                visible.chars().count() <= VISIBLE_WIDTH,
                "line out of the frame ({})",
                visible.chars().count()
            );
        }
        let joined: String = lines
            .iter()
            .map(|line| strip_ansi(line).trim().to_string())
            .collect::<Vec<_>>()
            .join(" ");
        for label in [
            "1 verified",
            "1 skipped",
            "1 parked",
            "1 overridden",
            "1 un-reviewed",
            "1 no-baseline",
        ] {
            assert!(
                joined.contains(label),
                "{label} hidden by wrapping: {joined}"
            );
        }
    }
}
