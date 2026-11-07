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
//! rows, and the live/auto run close prints the same section through
//! [`print_run_conformance_audit`], which derives its own rows from the
//! same documents (issue #423). The two readers print identical lines
//! because they run the same functions on the same shape, reading the
//! reviewer's live records through the same reader functions. Nothing
//! here stores a verdict, so no second copy of the truth can drift from
//! the first. The layer reads only: it never accepts a unit, touches a
//! branch, or changes a review status.
//!
//! The join also carries the reviewer's live records beside the ledger
//! (issue #420): the reviewer skip set, the Do Not Translate
//! classifications that park a binary's units, and the unit override
//! records — where one of those stands for a unit, it decides that unit's
//! disposition at the read.

use std::collections::{BTreeSet, HashMap};
use std::path::Path;

use calxgloss_git::GitManager;
use calxgloss_types::{
    BinaryConformance, BinaryIdentity, BinaryUnknownLedger, ConformanceOpenObligation,
    ConformanceTally, ConformanceUnknownCause, ConformanceVerdict, GitBranch,
    ObligationDisposition, ObligationEntry, OverrideControl, PersistError, ScenarioVerdictDocument,
    UnitObligation, UnitObligationEntry, UnknownSeverity, VerificationReceipt, VerificationVerdict,
    dashboard::ReviewSkips, obligation_ledger_dir, override_records_path, read_obligation_ledger,
    scenario_file_key, scenario_verdicts_dir, verification_receipt_path,
};

use super::render::{green_bold, println_content, yellow_bold};

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

/// What the read seam joins with the filed ledger (issue #420): the
/// reviewer skip-set keys, the parked binaries with their classification
/// reasons, and the unit-override handle over the workspace — the live
/// records the review surfaces already read, shared here rather than
/// reinterpreted.
#[derive(Default, Clone)]
pub struct ConformanceJoin<'a> {
    /// Skip-set keys spelling `{binary}/{function}/v{attempt}`, exactly
    /// as the review surfaces store them.
    pub skipped: BTreeSet<String>,
    /// Parked binaries — those whose in-force category is Do Not
    /// Translate — with the classification document's reason beside each.
    pub parked: HashMap<&'a str, Option<String>>,
    /// The unit-override handle over the workspace, opened once per
    /// build. A never-opened handle stands for no override records.
    pub overrides: Option<OverrideControl>,
}

impl ConformanceJoin<'_> {
    /// The reviewer override record standing for one unit, if any.
    fn override_for(&self, binary: &str, function: &str) -> bool {
        self.overrides
            .as_ref()
            .is_some_and(|control| control.get(binary, function).is_some())
    }
}

/// Derive one conformance row per binary: the filed obligation ledger
/// joined with branch state, the receipt pairs committed on the attempt
/// branches, the Accept records, and the binary's open-unknown reading
/// from the dashboard model's unknown-ledger rows. A *complete* verdict
/// requires every obligation closed on checked evidence and an unknown
/// ledger proven open-free of blocking records — fail-closed aggregation,
/// so an unproven gate never reads as a clean run (issue #392). The
/// `join` carries the reviewer's live records — the skip set, the Do Not
/// Translate parked binaries with their classification reasons, and the
/// unit override handle — and where one stands for a unit, that record
/// decides the unit's disposition at the read (issue #420).
pub fn derive_binary_conformance(
    git: &GitManager,
    binaries: &BTreeSet<String>,
    unknown_rows: &[BinaryUnknownLedger],
    join: &ConformanceJoin,
) -> Vec<BinaryConformance> {
    binaries
        .iter()
        .map(|binary| conformance_row(git.repo_path(), Some(git), binary, unknown_rows, join))
        .collect()
}

/// Derive the conformance rows for the named binaries straight from the
/// documents — the run close's entry point (issue #423). The close carries
/// no dashboard model, so it opens its own read-only git handle over the
/// workspace. Where no repository stands (a run with git skipped), green
/// claims resolve to their honest citation fault and the close still never
/// fails. Binaries are printed in the order named, deduplicated through
/// the same verbatim-unique walk as [`derive_binary_unknown_ledgers`], so
/// the two run-close sections key the same binaries by the same words.
pub fn derive_run_conformance(workspace: &Path, binaries: &[String]) -> Vec<BinaryConformance> {
    let git = calxgloss_git::GitManager::open(workspace).ok();
    let unknown_rows = super::audit::derive_binary_unknown_ledgers(workspace, binaries);
    // The join reads the reviewer's live records through the same reader
    // functions the dashboard builder calls — one skip set, one
    // classification park-list, one override handle — so the two readers
    // cannot decide a unit's disposition differently (issue #423).
    let classified = super::builder::read_classification_records(workspace);
    let class_overrides = super::builder::read_classification_overrides(workspace);
    let parked_map = super::builder::parked_classifications(&classified, &class_overrides);
    let join = ConformanceJoin {
        skipped: super::builder::read_review_skips(workspace)
            .into_iter()
            .collect(),
        parked: parked_map
            .iter()
            .map(|(binary, reason)| (binary.as_str(), reason.clone()))
            .collect(),
        overrides: Some(calxgloss_types::OverrideControl::open(workspace)),
    };
    let mut rows = Vec::new();
    for binary in super::audit::dedupe_verbatim(binaries) {
        rows.push(conformance_row(
            workspace,
            git.as_ref(),
            &binary,
            &unknown_rows,
            &join,
        ));
    }
    rows
}

/// The run-close conformance section as lines — the header, then every
/// named binary's row, derived from the same reading the dashboard builder
/// carries (issue #423). A run close with no target binaries produces no
/// lines at all — the same shape the audit-ledger section keeps.
pub fn run_conformance_lines(workspace: &Path, binaries: &[String]) -> Vec<String> {
    if binaries.is_empty() {
        return Vec::new();
    }
    let rows = derive_run_conformance(workspace, binaries);
    let mut lines = vec![conformance_header(), String::new()];
    for row in &rows {
        lines.extend(conformance_lines(row));
        lines.push(String::new());
    }
    lines
}

/// Print the run-close conformance section: the same lines
/// [`run_conformance_lines`] derives, content-padded like every other
/// dashboard surface (issue #423).
pub fn print_run_conformance_audit(workspace: &Path, binaries: &[String]) {
    for line in run_conformance_lines(workspace, binaries) {
        println_content(line);
    }
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
    /// The review door never opened: no Accept review action stands, so
    /// the unit reads *un-reviewed* — its own tally, never verified
    /// (issue #420, AC 5). A merged branch makes this the whole story;
    /// review, not the merge, is the only door into verified.
    UnReviewed(String),
    /// A leg is an input error: the cited pair cannot be resolved on the
    /// attempt branch. Like a corrupt document, this fails loudly and
    /// lands a named unknown cause on the verdict.
    CitationFault(String),
}

fn conformance_row(
    workspace: &Path,
    git: Option<&GitManager>,
    binary: &str,
    unknown_rows: &[BinaryUnknownLedger],
    join: &ConformanceJoin,
) -> BinaryConformance {
    let identity = BinaryIdentity::from(binary);
    let ledger = match read_obligation_ledger(workspace, &identity) {
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
        // The read seam joins the ledger with the live records (issue
        // #420): where a Do Not Translate classification, a reviewer
        // skip, or a reviewer override stands for this unit, that record
        // decides the unit's disposition. The entry's own filed
        // disposition only speaks when no live record stands for the
        // unit.
        if let Some(hold) = disposition_at_read(join, binary, entry) {
            tally_obligation(&mut row.tally, hold.disposition);
            obligations_open = true;
            first_open.get_or_insert_with(|| ConformanceOpenObligation {
                function: entry.function.clone(),
                attempt: entry.attempt,
                link: hold.reason.clone(),
            });
            eprintln!(
                "  [conformance] {binary}: obligation `{}` attempt {} reads {} — {}",
                entry.function,
                entry.attempt,
                disposition_words(&hold.disposition),
                hold.reason
            );
            continue;
        }
        match entry.disposition {
            ObligationDisposition::ClaimedVerified => {
                match close_claim(git, workspace, &identity, entry) {
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
                    ClaimReading::UnReviewed(reason) => {
                        // An attempt no review action ever acted on reads
                        // un-reviewed: its own tally, counted apart from the
                        // verified, and never a verified close (issue #420,
                        // AC 5).
                        obligations_open = true;
                        row.tally.un_reviewed += 1;
                        first_open.get_or_insert_with(|| ConformanceOpenObligation {
                            function: entry.function.clone(),
                            attempt: entry.attempt,
                            link: reason.clone(),
                        });
                        eprintln!(
                            "  [conformance] {binary}: obligation `{}` attempt {} reads un-reviewed — {reason}",
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
                }
            }
            disposition => {
                // Honest dispositions never count toward closure (issue
                // #392): every one holds its obligation open and keeps
                // its own tally, counted apart from the verified (issue
                // #419, AC 4). Where the filed ledger itself records the
                // disposition, the provenance says so plainly.
                obligations_open = true;
                tally_obligation(&mut row.tally, disposition);
                let words = disposition_words(&disposition);
                first_open.get_or_insert_with(|| ConformanceOpenObligation {
                    function: entry.function.clone(),
                    attempt: entry.attempt,
                    link: format!("the filed obligation ledger records it as {words}"),
                });
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

/// The live record standing for one unit at the read seam, and why (the
/// precedence, issue #420): a Do Not Translate classification parks
/// every unit under the binary; the reviewer skip set holds a unit out
/// attempt by attempt; a reviewer override record overrides the unit's
/// system judgment. Each names its own document as the provenance
/// beside the disposition. Where no live record speaks, the ledger's
/// own filed disposition stands.
fn disposition_at_read(
    join: &ConformanceJoin,
    binary: &str,
    entry: &ObligationEntry,
) -> Option<HeldDisposition> {
    if let Some(reason) = join.parked.get(binary) {
        let reason = reason
            .clone()
            .unwrap_or_else(|| "the classification records it as Do Not Translate".to_string());
        return Some(HeldDisposition {
            disposition: ObligationDisposition::Parked,
            reason: format!("the binary's Do Not Translate classification parks it: {reason}"),
        });
    }
    let unit_attempt = format!("{}/{}/v{}", binary, entry.function, entry.attempt);
    if join.skipped.contains(&unit_attempt) {
        return Some(HeldDisposition {
            disposition: ObligationDisposition::Skipped,
            reason: format!(
                "the reviewer's skip set names this unit at {}",
                ReviewSkips::path_in(Path::new("")).display()
            ),
        });
    }
    if join.override_for(binary, &entry.function) {
        return Some(HeldDisposition {
            disposition: ObligationDisposition::Overridden,
            reason: format!(
                "a reviewer unit override record in {} overrides this unit's system judgment",
                override_records_path(Path::new("")).display()
            ),
        });
    }
    None
}

/// One live record's honest reading of one unit: the disposition from
/// the closed roster, and the provenance sentence naming the record.
struct HeldDisposition {
    disposition: ObligationDisposition,
    reason: String,
}

/// The tally slot one disposition keeps, always apart from the verified
/// (issue #419, AC 4). A claimed-verified entry never lands here: it
/// either closes on checked evidence or names the leg that broke.
/// Unknowns carry no slot — they are verdict causes, not obligation
/// dispositions.
fn tally_obligation(tally: &mut ConformanceTally, disposition: ObligationDisposition) {
    match disposition {
        ObligationDisposition::Skipped => tally.skipped += 1,
        ObligationDisposition::Parked => tally.parked += 1,
        ObligationDisposition::Overridden => tally.overridden += 1,
        ObligationDisposition::UnReviewed => tally.un_reviewed += 1,
        ObligationDisposition::NoBaseline => tally.no_baseline += 1,
        ObligationDisposition::ClaimedVerified => {}
    }
}

/// The disposition words the terminal and the first-open sentence share:
/// the roster's own spelling of the disposition — the same label serde
/// writes into the JSON — with underscores spoken as spaces. Unknowns
/// spell their cause beside them, never a bare label.
fn disposition_words(disposition: &ObligationDisposition) -> String {
    disposition.to_string().replace('_', " ")
}

/// Check one green claim against the evidence the entry pins: its owner
/// digest against the attempt branch's tip, its citation against the
/// receipt pair committed there, the suite's coverage of the case kinds
/// the obligation requires, the Accept review action, and the merged
/// state. For an exe target a filed scenario verdict claiming complete
/// equivalence must also stand (issue #421).
fn close_claim(
    git: Option<&GitManager>,
    workspace: &Path,
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
    // A run closed over a workspace with no repository (a run with git
    // skipped) carries no branch, no receipt pair, and no merge state.
    // The claim's evidence cannot stand, so the reading names the missing
    // repository as the reason the citation cannot resolve — never a
    // pass, and the close keeps printing instead of failing (issue #423).
    let Some(git) = git else {
        return ClaimReading::CitationFault(format!(
            "no attempt branch `{}` stands to carry the receipt pair: the workspace holds no \
             git repository, so the citation was never consulted",
            branch.name
        ));
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

    // The coverage check (issue #421, AC 3): every case kind the
    // obligation requires must stand among the kinds the filed suite
    // exercised. The citation just sealed this exact document, so the
    // covered kinds stated on the receipt's face are the honest record
    // of what the run tried — a suite document re-resolved after filing
    // could decide coverage, and a case that declared no kind never
    // exercised one. A green run that never tried a required class keeps
    // the obligation open.
    let missing_kinds: Vec<String> = entry
        .required_case_kinds
        .iter()
        .filter(|kind| !receipt.covered_case_kinds.contains(kind))
        .map(|kind| kind.to_string())
        .collect();
    if !missing_kinds.is_empty() {
        return ClaimReading::Open(format!(
            "the filed suite never exercised the required case kinds: {}",
            missing_kinds.join(", ")
        ));
    }

    // For an exe target, unit evidence alone never closes the claim: the
    // scenario lane is what shows the translated unit actually runs and
    // behaves, and only a filed scenario verdict claiming complete
    // equivalence speaks for it. The FFI gate never closes an entry on its
    // own — the row says the lane lacks an assessment, naming
    // it as the first open link (issue #421, AC 6).
    if identity.as_str().to_ascii_lowercase().ends_with(".exe")
        && !scenario_verdict_claims_complete(workspace, identity)
    {
        return ClaimReading::Open(
            "no filed scenario verdict claims complete equivalence for this binary".to_string(),
        );
    }

    // Review is the only door into verified: a merged branch with no
    // standing Accept action never closes an obligation, and the unit
    // reads un-reviewed — its own tally, never verified (issue #392,
    // story 6; issue #420, AC 5).
    if !accept_record_stands(workspace, identity, &entry.function, entry.attempt) {
        return ClaimReading::UnReviewed(
            "no Accept review action stands for this attempt".to_string(),
        );
    }
    if !git
        .is_branch_merged_into_main(&branch.name)
        .unwrap_or(false)
    {
        return ClaimReading::Open(format!("branch `{}` is not merged into main", branch.name));
    }
    ClaimReading::Closed
}

/// Whether a filed *scenario verdict* document under
/// `re/scenarios/verdicts/` claims complete equivalence for this binary
/// (issue #421, AC 6): the file stem must spell `{binary}-{scenario key}`
/// the way the filing site spells it, the document must parse and name
/// this binary, and the complete-equivalence claim must stand on its
/// face. A missing directory, an unreadable document, or a stale
/// envelope claims nothing — fail-closed.
fn scenario_verdict_claims_complete(workspace: &Path, identity: &BinaryIdentity) -> bool {
    let Ok(entries) = std::fs::read_dir(scenario_verdicts_dir(workspace)) else {
        return false;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        let Ok(document) = serde_json::from_str::<ScenarioVerdictDocument>(&text) else {
            continue;
        };
        if document.binary != *identity {
            continue;
        }
        // the stamped digest must match the filed bytes: a document edited
        // after filing names no verdict at all, exactly like a receipt whose
        // citation digest no longer computes
        let Ok(recomputed) = document.content_digest() else {
            continue;
        };
        if recomputed != document.digest {
            continue;
        }
        if !document.claims_complete_equivalence {
            continue;
        }
        let stem = path
            .file_stem()
            .and_then(|stem| stem.to_str())
            .unwrap_or_default();
        if stem
            != format!(
                "{}-{}",
                identity.as_str(),
                scenario_file_key(&document.scenario)
            )
        {
            continue;
        }
        return true;
    }
    false
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

/// The unit's *obligation entry* riding the review model (issue #424,
/// P26.8): one map per binary from the ledger's function and attempt to
/// the entry as the read seam decides it — each attempt of a function
/// joins with its own entry, never the newest one. The fold runs the
/// same ledger read and the same live-record join as [`conformance_row`],
/// so the unit detail's entry and the per-binary *conformance verdict*
/// read one derivation and can never disagree. A binary whose ledger
/// was never filed or could not be read yields no map at all — every
/// unit of that binary keeps the honest unknown reading, never a closed
/// obligation. The row for the binary names the cause on the same build.
pub fn derive_unit_obligations(
    workspace: &Path,
    binaries: &BTreeSet<String>,
    join: &ConformanceJoin,
) -> HashMap<String, std::collections::BTreeMap<(String, u32), UnitObligation>> {
    let mut per_binary = HashMap::new();
    for binary in binaries {
        let Ok(ledger) = read_obligation_ledger(workspace, &BinaryIdentity::from(binary.as_str()))
        else {
            // Never filed or an input error: [`conformance_row`] already
            // named this cause on the same build, and the units below
            // ride the unknown reading from it.
            continue;
        };
        let by_attempt: std::collections::BTreeMap<(String, u32), UnitObligation> = ledger
            .entries
            .iter()
            .map(|entry| {
                (
                    (entry.function.clone(), entry.attempt),
                    unit_obligation_for(binary, entry, join),
                )
            })
            .collect();
        per_binary.insert(binary.clone(), by_attempt);
    }
    per_binary
}

/// The filed [`ObligationEntry`] as one unit's riding entry: what the
/// entry names rides through, and the *obligation disposition* is the
/// read seam's — the live reviewer record standing for the unit decides
/// it, otherwise the filed one speaks (issue #420, issue #424).
fn unit_obligation_for(
    binary: &str,
    entry: &ObligationEntry,
    join: &ConformanceJoin,
) -> UnitObligation {
    let (disposition, disposition_reason) = match disposition_at_read(join, binary, entry) {
        Some(held) => (held.disposition, Some(held.reason)),
        None => (entry.disposition, None),
    };
    UnitObligation {
        entry: Some(UnitObligationEntry {
            attempt: entry.attempt,
            owner_commit: entry.owner_commit.clone(),
            required_case_kinds: entry.required_case_kinds.clone(),
            disposition,
            disposition_reason,
            receipt_digest: entry.receipt_digest.clone(),
        }),
    }
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
    // The line's own leading indent rides the first physical line — the
    // word split would otherwise drop it and the key would not line up
    // with the other run-close sections (issue #423).
    let indent = text.len() - text.trim_start().len();
    let lead = &text[..indent];
    let cont = " ".repeat(indent + 2);
    let mut lines = Vec::new();
    let mut current = String::new();
    for word in text.trim_start().split(' ').filter(|word| !word.is_empty()) {
        let candidate = if current.is_empty() {
            format!("{lead}{word}")
        } else if current == cont {
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
    use calxgloss_types::ObligationLedger;

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
    fn the_run_close_section_prints_an_unfiled_ledger_as_unknown_never_a_clean_run() {
        // Issue #423, AC 3: the close derives its own rows from the filed
        // documents. A target with no filed obligation ledger degrades to
        // *unknown* in the section, and the close does not fail. This
        // workspace is not even a git repository, so the degradation is
        // total and quiet.
        let dir = tempfile::tempdir().expect("temp dir");
        let lines = run_conformance_lines(dir.path(), &["game_logic.dll".to_string()]);
        assert_eq!(lines[0], conformance_header());
        let joined = lines
            .iter()
            .map(|line| strip_ansi(line).trim().to_string())
            .collect::<Vec<_>>()
            .join(" ");
        assert!(
            joined.contains("game_logic.dll — unknown: no ledger filed — never a clean run"),
            "{joined}"
        );
        assert!(
            !joined.contains("complete"),
            "absence never reads as closure: {joined}"
        );
    }

    #[test]
    fn a_green_claim_read_without_a_git_repository_never_passes_and_never_fails_the_close() {
        // A run closed with git skipped has no attempt branch and no
        // receipt pair. The claim cannot close, so the section names the
        // receipt citation as unresolvable and reads the verdict as
        // unknown. The derivation still returns its row instead of failing
        // the close (issue #423, AC 3).
        let dir = tempfile::tempdir().expect("temp dir");
        let mut entry = ObligationEntry::new(
            "DrawPrimitive",
            1,
            "",
            ObligationDisposition::ClaimedVerified,
        );
        entry.receipt_digest = Some("sha256:cafe".to_string());
        let ledger = ObligationLedger::file("game_logic.dll", vec![entry], 1_700_000_000)
            .expect("the ledger seals");
        calxgloss_types::save_json(
            &calxgloss_types::obligation_ledger_path(
                dir.path(),
                &BinaryIdentity::from("game_logic.dll"),
            ),
            &ledger,
        )
        .expect("file the ledger");
        let rows = derive_run_conformance(dir.path(), &["game_logic.dll".to_string()]);
        assert_eq!(rows.len(), 1, "the close still derives its row");
        assert_eq!(rows[0].verdict, ConformanceVerdict::Unknown);
        assert_eq!(
            rows[0].causes,
            vec![ConformanceUnknownCause::UnresolvableReceiptCitation],
            "the missing repository lands as an unresolvable citation, never a pass"
        );
    }

    #[test]
    fn the_run_close_conformance_section_keys_targets_verbatim_like_the_unknown_section() {
        // Issue #423, AC 4: the two run-close sections key the same
        // binaries the same way. Each key is spelled exactly as handed, in
        // the named order, and a target named twice is named once.
        let dir = tempfile::tempdir().expect("temp dir");
        let targets = vec![
            "keyless_engine.dll".to_string(),
            "game_logic.dll".to_string(),
            "keyless_engine.dll".to_string(),
        ];
        let names = ["game_logic.dll", "keyless_engine.dll"];
        let keys_in = |lines: &[String]| -> Vec<String> {
            lines
                .iter()
                .map(|line| strip_ansi(line))
                .filter_map(|line| {
                    names
                        .iter()
                        .find(|name| line.starts_with(&format!("  {name} —")))
                        .map(|name| name.to_string())
                })
                .collect()
        };
        let unknown = super::super::audit::run_audit_ledger_lines(dir.path(), &targets);
        let conformance = run_conformance_lines(dir.path(), &targets);
        assert_eq!(
            keys_in(&conformance),
            keys_in(&unknown),
            "the two run-close sections must name the same binaries the same way"
        );
        assert_eq!(
            keys_in(&conformance),
            vec!["keyless_engine.dll", "game_logic.dll"],
            "named order, duplicate once"
        );
        assert!(run_conformance_lines(dir.path(), &[]).is_empty());
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
