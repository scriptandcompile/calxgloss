//! The `errhandling` command's CLI contribution — detect error-handling
//! idioms for a binary (issue #340, spec #337).
//!
//! The scan shape — engine build, scan, persist, degradation — lives in
//! the pipeline's `error-handling` registry row; this module contributes
//! only what is genuinely per-engine: the cached-document loader and the
//! report printer. The generic handler
//! ([`scan_command`](crate::commands::scan_command)) routes the command
//! end to end: it rebuilds the result on demand (the CLI's force-rescan
//! contract) and can print what a cached one holds, filing it where the
//! row files it — `re/analysis/errhandling/{binary}.json`. The run's
//! report and a later `--show` report are the same read of the same
//! document.

use std::path::Path;

use anyhow::{Context, Result};
use calxgloss_errhandling::persist::ErrhandlingPersistor;
use calxgloss_errhandling::types::ErrhandlingResult;
use calxgloss_translator::scan_registry::ScanRunOptions;
use chrono::DateTime;

use crate::commands::scan_command::{ScanContribution, ScanContributionSteps};
use crate::utils::*;

/// How many entries a detail section lists before collapsing the rest.
const DETAIL_LIMIT: usize = 10;

/// The `errhandling` entry in the CLI-side contribution table: it serves
/// the registry's `error-handling` row and supplies this command's loader
/// and printer. The command carries no flags beyond `--binary` and
/// `--show`, so its flag derivation hands over the plain default options —
/// the overwrite policy is the generic handler's to set.
pub(crate) fn contribution() -> ScanContribution {
    ScanContribution::new(ScanContributionSteps {
        row: "error-handling",
        load: load_filed_result,
        print: print_report,
        derive_options: |_flags| ScanRunOptions::default(),
        post_scan: None,
        show_loads_program: |_flags| false,
    })
}

/// Read the filed result through the engine's own persistor — the same
/// loader for the `--show` report and for reading the document a run
/// just filed. A missing one arrives with the remediation wording
/// naming the exact producing command.
fn load_filed_result(workspace: &Path, binary: &str) -> Result<ErrhandlingResult> {
    ErrhandlingPersistor::new(workspace)
        .load(binary)
        .with_context(|| {
            format!(
                "No cached error-handling detection result for {binary}; \
                 run `calxgloss errhandling --binary {binary}` to produce one"
            )
        })
}

/// Print the report over the loaded result, naming where the document is
/// filed. Both paths read the same on-disk state, so the run's report
/// and a later `--show` report are byte-identical over one document.
fn print_report(result: &ErrhandlingResult, workspace: &Path, binary: &str) -> Result<()> {
    print_errhandling_report(
        result,
        &ErrhandlingPersistor::new(workspace).path_for(binary),
    );
    Ok(())
}

/// Print a summary of a detection result: where it is filed, when it
/// was built, and what the findings say.
fn print_errhandling_report(result: &ErrhandlingResult, path: &Path) {
    println!();
    hsep_bold();
    println_content(format!(
        "  Error-Handling Idiom Detection — {}",
        result.metadata.binary
    ));
    hsep();
    println!();

    println_content(format!(
        "  {}{}",
        white_bold("File:      "),
        dim(&path.display().to_string())
    ));
    let scanned = DateTime::from_timestamp(result.metadata.scanned_at as i64, 0)
        .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
        .unwrap_or_else(|| format!("unix {}", result.metadata.scanned_at));
    println_content(format!(
        "  {}{} {}",
        white_bold("Scanned:   "),
        scanned,
        dim(&format!("({}s)", result.metadata.duration_secs))
    ));
    println!();

    // Findings, broken down by the idiom kind the readings name.
    let kind_breakdown: Vec<String> = [
        "seh_frame",
        "named_handler",
        "exception_api_call",
        "raise_exception",
        "goto_cleanup",
        "error_code",
        "inherited_error_code",
    ]
    .into_iter()
    .map(|kind| {
        (
            kind,
            result
                .findings
                .iter()
                .filter(|finding| finding.kind() == kind)
                .count(),
        )
    })
    .filter(|(_, count)| *count > 0)
    .map(|(kind, count)| format!("{kind} {count}"))
    .collect();
    println_content(format!(
        "  {}{:<5}{}",
        white_bold("Findings:  "),
        result.findings.len(),
        dim(&kind_breakdown.join(", "))
    ));

    let top_confidence = result
        .findings
        .iter()
        .map(|finding| finding.confidence().value())
        .max();
    println_content(format!(
        "  {}{}",
        white_bold("Top conf:  "),
        match top_confidence {
            Some(confidence) => confidence_color(confidence)(&confidence.to_string()),
            None => dim("(none)"),
        }
    ));
    println!();

    if !result.findings.is_empty() {
        hsep();
        println_content("  Findings:");
        hsep();
        for finding in result.findings.iter().take(DETAIL_LIMIT) {
            println_content(format!(
                "  ●  {:<14} {:<12} {:<70} {}",
                finding.function(),
                finding.target(),
                finding.suggestion(),
                confidence_color(finding.confidence().value())(&format!(
                    "{} {}",
                    finding.confidence(),
                    finding.kind()
                ))
            ));
            println_content(format!(
                "     {}{}",
                dim("evidence: "),
                dim(finding.evidence().trim())
            ));
        }
        print_hidden_count("finding", result.findings.len());
        println!();
    }

    hsep_bold();
    if result.is_empty() {
        println!(
            "  {} The scan found nothing — no decompiled body spelled an error-handling idiom.",
            yellow_bold("◉")
        );
    } else {
        println!(
            "  {} Error-handling detection ready — spelled frames and named handler sites are named in the record.",
            green_bold("✓")
        );
    }
    println!();
}

/// Color a 0–100 confidence score the way the other reports color pass rates.
fn confidence_color(confidence: u8) -> fn(&str) -> String {
    if confidence >= 70 {
        green_bold
    } else if confidence >= 50 {
        yellow_bold
    } else {
        red_bold
    }
}

/// The "…and N more" line a detail section ends with when it collapsed.
fn print_hidden_count(noun: &str, total: usize) {
    if total > DETAIL_LIMIT {
        println_content(format!(
            "  {} …and {} more {noun}",
            dim("●"),
            total - DETAIL_LIMIT
        ));
    }
}
