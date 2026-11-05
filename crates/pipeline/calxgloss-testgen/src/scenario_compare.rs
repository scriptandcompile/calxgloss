//! The scenario-compare seam (P24.6, issue #407): two *scenario captures*
//! plus one *scenario contract* in, one digest-bearing *scenario verdict*
//! out — pure record logic, never a process launch. This is the one high
//! seam's external behavior, pinned by hand-built capture pairs that need
//! no Wine toolchain on any machine.
//!
//! The honesty line this slice carries (ADR-0057's line extended to
//! process behavior): the comparator never claims more than the two
//! captures support. Each of the five dimensions — terminal, interaction,
//! exit, filesystem, process — reads assessed pass, assessed fail, or
//! unassessed; an absent or empty side reads *unassessed*, so silence is
//! never mistaken for a pass and never fails by silence. Every failure
//! names its divergent fields with both sides beside them. Normalization
//! is declared, versioned, and never silent: only the contract's literal
//! replacements and port patterns ever touch the comparison, the verdict
//! states the version in force, and two captures stamped under different
//! normalization versions refuse to pair, by name. Caps, truncation marks,
//! and residual unknowns (every file outside the declared observation
//! paths, a mismatched Wine) block a complete-equivalence claim rather
//! than passing or failing by silence.
//!
//! The verdict files as its own digest-bearing document at
//! `re/scenarios/verdicts/<binary identity>-<scenario key>.json`, so
//! P25's receipts and P26's ledger can cite it by digest without P24
//! changing shape.

use anyhow::{Context as _, Result, bail};
use calxgloss_types::{
    BinaryIdentity, CapturePairing, DimensionDivergence, DimensionVerdict, NormalizationRules,
    ProcessSample, ScenarioCapture, ScenarioContract, ScenarioVerdict, ScenarioVerdictDocument,
};

#[cfg(test)]
mod tests;

/// Compare two *scenario captures* under one *scenario contract* and
/// return the *scenario verdict* document — filing is the interface's;
/// this seam answers the comparison and touches no process, no Wine, and
/// no filesystem. `now` is the filing clock's reading, stamped as
/// `filed_at` exactly as the capture seam takes it.
///
/// Refusals are named and change nothing: captures of different scenarios
/// never pair, captures whose *pairing rule* normalization stamps disagree
/// (or stand missing) refuse to pair across normalization versions, both
/// versions named, and a contract declaring a different normalization
/// version than the pair's stamps refuse the comparison by both names.
pub fn compare_captures(
    binary: &BinaryIdentity,
    contract: &ScenarioContract,
    left: &ScenarioCapture,
    right: &ScenarioCapture,
    now: u64,
) -> Result<ScenarioVerdictDocument> {
    if left.scenario != contract.name || right.scenario != contract.name {
        bail!(
            "refusing to compare: the contract declares scenario '{}', but the two \
             captures name '{}' and '{}' — a comparison judges one scenario's pair",
            contract.name,
            left.scenario,
            right.scenario
        );
    }
    let pair = PairingSides::check(left, right)?;

    // The gate reaches the governing contract too: its declared
    // normalization version must be the one the pair was stamped under.
    // A contract re-declared under new rules judging captures normalized
    // under the old ones is the silent bridge this lane never crosses.
    if contract.normalization.version != pair.left.normalization_version {
        bail!(
            "refusing to compare: the contract declares normalization version '{}' now, but \
             the pair was stamped under '{}' — the rules in force are not the rules that \
             normalized the pair, and the comparison never bridges versions silently",
            contract.normalization.version,
            pair.left.normalization_version,
        );
    }

    // Each dimension reads assessed only when both sides stand filled —
    // the equality reading is the pass case; the named-divergence case
    // grows dimension by dimension under its own pin.
    let port_patterns = compiled_port_patterns(&contract.normalization)?;
    let (terminal, mut divergences) =
        compare_terminal(left, right, &contract.normalization, &port_patterns);
    let (interaction, interaction_divergences) = compare_interaction(left, right);
    let (exit, exit_divergences) = compare_exit(left, right);
    divergences.extend(interaction_divergences);
    divergences.extend(exit_divergences);
    let (filesystem, filesystem_divergences) = compare_filesystem(left, right);
    let (process, process_divergences) = compare_process(left, right);
    divergences.extend(filesystem_divergences);
    divergences.extend(process_divergences);

    let verdict = ScenarioVerdict {
        terminal,
        interaction,
        exit,
        filesystem,
        process,
    };

    // The bounded-evidence statements, never silent and in dimension
    // order: a capped recording says what it withheld, and a weighed
    // filesystem knows only its declared observation paths — every other
    // file either run may have touched stays unknown, and says so.
    let mut residual_unknowns = Vec::new();
    for (side, capture) in [("left", left), ("right", right)] {
        if let Some(terminal) = capture.terminal.as_ref().filter(|t| t.output_capped) {
            let cap = match terminal.cap_bytes {
                Some(bytes) => format!("{bytes} bytes"),
                None => "a cap the capture never named".to_string(),
            };
            residual_unknowns.push(format!(
                "the {side} terminal output stopped at the cap of {cap}; everything the \
                     run printed after it was never recorded and stays unknown"
            ));
        }
    }
    // Same-binary captures taken under different Wine versions can differ
    // for reasons no scenario author caused — the environment moved. The
    // pair still compares (what the dimensions saw is real and worth
    // seeing), but the verdict names both versions and a clean reading
    // across them proves nothing about either environment.
    if pair.left.wine_version != pair.right.wine_version {
        residual_unknowns.push(format!(
            "the captures were taken under different Wine versions (left {}, right {}); \
             the environment difference may explain any divergence, so a clean verdict \
             across them proves nothing about either environment",
            pair.left.wine_version, pair.right.wine_version
        ));
    }
    if filesystem != DimensionVerdict::Unassessed {
        residual_unknowns.push(format!(
            "both captures weighed only the declared observation paths ({}); every file \
             outside them both runs may have created, changed, or deleted stays unknown",
            contract.observation_paths.join(", ")
        ));
    }

    let claims_complete_equivalence = verdict.terminal == DimensionVerdict::AssessedPass
        && verdict.interaction == DimensionVerdict::AssessedPass
        && verdict.exit == DimensionVerdict::AssessedPass
        && verdict.filesystem == DimensionVerdict::AssessedPass
        && verdict.process == DimensionVerdict::AssessedPass
        && residual_unknowns.is_empty();

    let mut document = ScenarioVerdictDocument {
        binary: binary.clone(),
        scenario: contract.name.clone(),
        filed_at: now,
        normalization_version: contract.normalization.version.clone(),
        left_capture_sha256: capture_digest(left)?,
        right_capture_sha256: capture_digest(right)?,
        left_pairing: left.pairing.clone(),
        right_pairing: right.pairing.clone(),
        verdict,
        divergences,
        residual_unknowns,
        claims_complete_equivalence,
        digest: String::new(),
    };
    document.digest = document.content_digest()?;
    Ok(document)
}

/// A dimension reads assessed pass or assessed fail only where both sides
/// stand filled; a dimension nobody observed — or observed on only one
/// side — reads *unassessed*. Silence is never a pass and never a fail.
fn assess(agrees: bool, both_sides_filled: bool) -> DimensionVerdict {
    if !both_sides_filled {
        DimensionVerdict::Unassessed
    } else if agrees {
        DimensionVerdict::AssessedPass
    } else {
        DimensionVerdict::AssessedFail
    }
}

/// The terminal dimension's reading: both sides' segments normalized under
/// the contract's declared rules — and only those rules ever touch the
/// comparison — then weighed in order, segment index against segment
/// index. Every disagreement is named with both sides beside it; a segment
/// one side never printed stands `None` on that side. The cap marks and
/// geometries grow their own readings under their own pins.
fn compare_terminal(
    left: &ScenarioCapture,
    right: &ScenarioCapture,
    rules: &NormalizationRules,
    patterns: &[regex::Regex],
) -> (DimensionVerdict, Vec<DimensionDivergence>) {
    let (Some(l), Some(r)) = (&left.terminal, &right.terminal) else {
        return (DimensionVerdict::Unassessed, Vec::new());
    };
    if l.chunks.is_empty() || r.chunks.is_empty() {
        return (DimensionVerdict::Unassessed, Vec::new());
    }
    let left_norm: Vec<String> = l
        .chunks
        .iter()
        .map(|segment| normalize_segment(segment, rules, patterns))
        .collect();
    let right_norm: Vec<String> = r
        .chunks
        .iter()
        .map(|segment| normalize_segment(segment, rules, patterns))
        .collect();
    let shared = left_norm.len().min(right_norm.len());
    let mut divergences: Vec<DimensionDivergence> = Vec::new();
    for index in 0..shared {
        if left_norm[index] != right_norm[index] {
            divergences.push(DimensionDivergence::TerminalSegment {
                index,
                left: Some(left_norm[index].clone()),
                right: Some(right_norm[index].clone()),
            });
        }
    }
    for (index, text) in left_norm.iter().enumerate().skip(shared) {
        divergences.push(DimensionDivergence::TerminalSegment {
            index,
            left: Some(text.clone()),
            right: None,
        });
    }
    for (index, text) in right_norm.iter().enumerate().skip(shared) {
        divergences.push(DimensionDivergence::TerminalSegment {
            index,
            left: None,
            right: Some(text.clone()),
        });
    }
    // The terminal dimension has content, not just bytes: the opening
    // geometry and the rendered states ride the comparison too, each
    // disagreement named with both sides — an unmeasured geometry stands
    // absent, never defaulted.
    if l.geometry != r.geometry {
        divergences.push(DimensionDivergence::TerminalGeometry {
            left: l.geometry,
            right: r.geometry,
        });
    }
    if l.rendered_states != r.rendered_states {
        divergences.push(DimensionDivergence::TerminalRenderedStates {
            left: l.rendered_states.clone(),
            right: r.rendered_states.clone(),
        });
    }
    (assess(divergences.is_empty(), true), divergences)
}

/// The interaction dimension's reading: the acknowledgements each run
/// filed, weighed by at-offset. An offset one run acknowledged and the
/// other never did is named at its offset, each side's state beside it.
fn compare_interaction(
    left: &ScenarioCapture,
    right: &ScenarioCapture,
) -> (DimensionVerdict, Vec<DimensionDivergence>) {
    let (Some(l), Some(r)) = (&left.interaction, &right.interaction) else {
        return (DimensionVerdict::Unassessed, Vec::new());
    };
    if l.acknowledged_at_ms.is_empty() || r.acknowledged_at_ms.is_empty() {
        return (DimensionVerdict::Unassessed, Vec::new());
    }
    let mut offsets: Vec<u64> = l
        .acknowledged_at_ms
        .iter()
        .chain(r.acknowledged_at_ms.iter())
        .copied()
        .collect();
    offsets.sort_unstable();
    offsets.dedup();
    let mut divergences = Vec::new();
    for at_ms in offsets {
        let left_ack = l.acknowledged_at_ms.contains(&at_ms);
        let right_ack = r.acknowledged_at_ms.contains(&at_ms);
        if left_ack != right_ack {
            divergences.push(DimensionDivergence::InteractionAcknowledgement {
                at_ms,
                left: left_ack,
                right: right_ack,
            });
        }
    }
    (assess(divergences.is_empty(), true), divergences)
}

/// The exit dimension's reading: how each run ended, with its code and —
/// when a window closed the run — its finalization outcome. Every field
/// that disagrees is named; a side that reported no code or was never
/// finalized stands absent beside the comparison, never defaulted.
fn compare_exit(
    left: &ScenarioCapture,
    right: &ScenarioCapture,
) -> (DimensionVerdict, Vec<DimensionDivergence>) {
    let (Some(l), Some(r)) = (&left.exit, &right.exit) else {
        return (DimensionVerdict::Unassessed, Vec::new());
    };
    let mut divergences = Vec::new();
    if l.disposition != r.disposition {
        divergences.push(DimensionDivergence::ExitDisposition {
            left: l.disposition,
            right: r.disposition,
        });
    }
    if l.exit_code != r.exit_code {
        divergences.push(DimensionDivergence::ExitCode {
            left: l.exit_code,
            right: r.exit_code,
        });
    }
    if l.finalization != r.finalization {
        divergences.push(DimensionDivergence::ExitFinalization {
            left: l.finalization,
            right: r.finalization,
        });
    }
    (assess(divergences.is_empty(), true), divergences)
}

/// The filesystem dimension's reading: the declared observation paths'
/// entries, weighed by path — change kind, size, whole-file digest, and
/// block digests all ride the comparison. A disagreeing path is named
/// with both sides' whole entries beside it; a path one side never
/// carried names the other side's entry with the silent side absent.
/// Paths are walked left's declared order first, then right-only paths in
/// right's order, so the filed verdict is deterministic.
fn compare_filesystem(
    left: &ScenarioCapture,
    right: &ScenarioCapture,
) -> (DimensionVerdict, Vec<DimensionDivergence>) {
    let (Some(l), Some(r)) = (&left.filesystem, &right.filesystem) else {
        return (DimensionVerdict::Unassessed, Vec::new());
    };
    if l.entries.is_empty() || r.entries.is_empty() {
        return (DimensionVerdict::Unassessed, Vec::new());
    }
    let mut paths: Vec<&str> = l.entries.iter().map(|e| e.path.as_str()).collect();
    for entry in &r.entries {
        if !paths.contains(&entry.path.as_str()) {
            paths.push(entry.path.as_str());
        }
    }
    let mut divergences = Vec::new();
    for path in paths {
        let left_entry = l.entries.iter().find(|e| e.path == path);
        let right_entry = r.entries.iter().find(|e| e.path == path);
        match (left_entry, right_entry) {
            (Some(a), Some(b)) if a == b => {}
            (Some(a), Some(b)) => divergences.push(DimensionDivergence::FileSystemPath {
                path: path.to_string(),
                left: Some(a.clone()),
                right: Some(b.clone()),
            }),
            (Some(a), None) => divergences.push(DimensionDivergence::FileSystemPath {
                path: path.to_string(),
                left: Some(a.clone()),
                right: None,
            }),
            (None, Some(b)) => divergences.push(DimensionDivergence::FileSystemPath {
                path: path.to_string(),
                left: None,
                right: Some(b.clone()),
            }),
            (None, None) => {}
        }
    }
    (assess(divergences.is_empty(), true), divergences)
}

/// The process dimension's reading: the *process-tree rows* each run
/// sighted, weighed by program name — pids are run accidents and never a
/// divergence by themselves. A row one tree had and the other never did
/// is named with that row beside the reader; the count of same-named rows
/// counts too, so one child more or less stands named.
fn compare_process(
    left: &ScenarioCapture,
    right: &ScenarioCapture,
) -> (DimensionVerdict, Vec<DimensionDivergence>) {
    let (Some(l), Some(r)) = (&left.process, &right.process) else {
        return (DimensionVerdict::Unassessed, Vec::new());
    };
    if l.samples.is_empty() || r.samples.is_empty() {
        return (DimensionVerdict::Unassessed, Vec::new());
    }
    let mut unmatched_right: Vec<&ProcessSample> = r.samples.iter().collect();
    let mut divergences = Vec::new();
    for row in &l.samples {
        if let Some(matched) = unmatched_right
            .iter()
            .position(|other| other.name == row.name)
        {
            unmatched_right.remove(matched);
        } else {
            divergences.push(DimensionDivergence::ProcessTreeRow {
                left: Some(row.clone()),
                right: None,
            });
        }
    }
    for row in unmatched_right {
        divergences.push(DimensionDivergence::ProcessTreeRow {
            left: None,
            right: Some(row.clone()),
        });
    }
    (assess(divergences.is_empty(), true), divergences)
}

/// Compile the contract's declared port patterns once; a pattern that
/// does not compile is refused by name — a declared rule that quietly
/// stopped applying would change the comparison in silence.
fn compiled_port_patterns(rules: &NormalizationRules) -> Result<Vec<regex::Regex>> {
    rules
        .port_patterns
        .iter()
        .map(|pattern| {
            regex::Regex::new(pattern).with_context(|| {
                format!(
                    "the contract declares port pattern `{pattern}` as a normalization rule, \
                     and it does not compile as a regex — refusing to compare rather than \
                     silently dropping a declared rule"
                )
            })
        })
        .collect()
}

/// Normalize one captured segment: only the contract's declared rules —
/// literal replacements in declaration order, then the port-pattern masks.
/// Nothing else ever touches captured text.
fn normalize_segment(text: &str, rules: &NormalizationRules, patterns: &[regex::Regex]) -> String {
    let mut out = text.to_string();
    for replacement in &rules.literal_replacements {
        out = out.replace(&replacement.from, &replacement.to);
    }
    for pattern in patterns {
        out = pattern.replace_all(&out, "<port>").into_owned();
    }
    out
}

/// The two captures' pairing blocks, once the *pairing rule* gate has
/// cleared them to be compared.
struct PairingSides {
    left: CapturePairing,
    right: CapturePairing,
}

impl PairingSides {
    /// The normalization gate: two captures pair only when both name the
    /// normalization version they were captured under and the versions
    /// agree. An unstamped capture proves nothing and the refusal says so;
    /// versions that disagree are both named, never silently bridged.
    fn check(left: &ScenarioCapture, right: &ScenarioCapture) -> Result<PairingSides> {
        let (Some(left_pair), Some(right_pair)) = (left.pairing.as_ref(), right.pairing.as_ref())
        else {
            let missing = match (left.pairing.as_ref(), right.pairing.as_ref()) {
                (None, None) => "both sides",
                (None, Some(_)) => "the left side",
                _ => "the right side",
            };
            bail!(
                "refusing to pair: {missing} carries no pairing stamp — the normalization \
                 version its capture ran under is not proven, and comparisons never pair across unproven versions"
            );
        };
        if left_pair.normalization_version.is_empty() || right_pair.normalization_version.is_empty()
        {
            let unstamped: Vec<&str> = match (
                left_pair.normalization_version.is_empty(),
                right_pair.normalization_version.is_empty(),
            ) {
                (true, true) => vec!["left", "right"],
                (true, false) => vec!["left"],
                (false, true) => vec!["right"],
                (false, false) => vec![],
            };
            bail!(
                "refusing to pair: the {} capture(s) were filed before normalization versions \
                 were stamped — the version they ran under is not proven, and pairing never \
                 assumes it",
                unstamped.join(" and ")
            );
        }
        if left_pair.normalization_version != right_pair.normalization_version {
            bail!(
                "refusing to pair: the two captures were normalized under different versions \
                 (left {}, right {}) — a pair across normalization versions is refused, never \
                 silently equalized",
                left_pair.normalization_version,
                right_pair.normalization_version
            );
        }
        Ok(PairingSides {
            left: left_pair.clone(),
            right: right_pair.clone(),
        })
    }
}

/// The digest of one capture's content: sha256 over its canonical JSON,
/// prefixed like every other content digest the record tree carries. The
/// verdict cites both captures it judged by this digest.
fn capture_digest(capture: &ScenarioCapture) -> Result<String> {
    use anyhow::Context as _;
    use sha2::{Digest as _, Sha256};
    let bytes = serde_json::to_vec(capture).context("the capture document serializes")?;
    let sum = Sha256::digest(&bytes);
    let hex: String = sum.iter().map(|byte| format!("{byte:02x}")).collect();
    Ok(format!("sha256:{hex}"))
}
