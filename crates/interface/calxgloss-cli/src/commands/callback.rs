//! The `callback` command's CLI contribution — detect callback tables
//! for a binary (issue #340, spec #337).
//!
//! The shape of this scan — how the evidence engine is built, how the
//! scan runs, how the result is persisted, and how degradation is
//! reported — lives in the pipeline's `callback-detection` registry
//! row. This module contributes only what is genuinely specific to
//! this evidence engine: the cached-document loader and the report
//! printer. The generic handler
//! ([`scan_command`](crate::commands::scan_command)) runs the whole
//! command: a run always rebuilds the result instead of reusing the
//! cached document (the CLI's refresh-cache contract), and `--show`
//! prints a cached document instead. The result is filed where the row
//! files it — `re/analysis/callback/{binary}.json` — the same file
//! batch translation reads as prompt context. The run's report and a
//! later `--show` report read the same document the same way.
//!
//! The enrichment belongs to the row, not to this module. Before the
//! scan, the `callback-detection` row's pre-scan hook reads the filed
//! type-inference document and composes its records into a signature
//! map, which the row's evidence-engine build then picks up. That is
//! what lets registration and chain suggestions carry real closure
//! contracts.
//! When no type-inference document exists, the map is empty and the
//! scan runs exactly as it did un-enriched (issue #173). This module
//! contributes no composition of its own: the row's pre-scan work runs
//! through the generic handler like any other row step.

use std::path::Path;

use anyhow::{Context, Result};
use calxgloss_callback::persist::CallbackPersistor;
use calxgloss_callback::types::CallbackResult;
use calxgloss_translator::scan_registry::ScanRunOptions;
use chrono::DateTime;

use crate::commands::scan_command::{ScanContribution, ScanContributionSteps};
use crate::utils::*;

/// How many entries a detail section lists before collapsing the rest.
const DETAIL_LIMIT: usize = 10;

/// The `callback` entry in the CLI-side contribution table: it serves
/// the registry's `callback-detection` row and supplies this command's
/// loader and printer. The command carries no flags beyond `--binary`
/// and `--show`, so its flag derivation hands over the plain default
/// options — the overwrite policy is the generic handler's to set, and
/// the signature enrichment is the row's pre-scan hook, not a CLI step.
pub(crate) fn contribution() -> ScanContribution {
    ScanContribution::new(ScanContributionSteps {
        row: "callback-detection",
        load: load_filed_result,
        print: print_report,
        derive_options: |_flags| ScanRunOptions::default(),
        post_scan: None,
        show_loads_program: |_flags| false,
    })
}

/// Read the filed result through the evidence engine's own persistor —
/// the same loader for the `--show` report and for reading the document
/// a run just filed. When the document is missing, the error names the
/// exact command that produces one.
fn load_filed_result(workspace: &Path, binary: &str) -> Result<CallbackResult> {
    CallbackPersistor::new(workspace)
        .load(binary)
        .with_context(|| {
            format!(
                "No cached callback result for {binary}; \
                 run `calxgloss callback --binary {binary}` to produce one"
            )
        })
}

/// Print the report over the loaded result, naming where the document is
/// filed. Both paths read the same on-disk state, so for one document
/// the run's report and a later `--show` report come out byte-identical.
fn print_report(result: &CallbackResult, workspace: &Path, binary: &str) -> Result<()> {
    print_callback_report(result, &CallbackPersistor::new(workspace).path_for(binary));
    Ok(())
}

/// Print a summary of a callback result: where it is filed, when it
/// was built, and what the findings say.
fn print_callback_report(result: &CallbackResult, path: &Path) {
    println!();
    hsep_bold();
    println_content(format!("  Callbacks — {}", result.metadata.binary));
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

    // Findings, broken down by the kind of each finding.
    let kind_breakdown: Vec<String> = [
        "fp_array",
        "registration",
        "jump_table",
        "plugin",
        "chain",
        "event_system",
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

    // The scan's own admission, beside the counts it qualifies (issue
    // #350): the shared type's bounded line, framed under `Coverage:` and
    // printed only when there is something to admit. The line names only
    // bodies the scan never reached — a function without findings under a
    // complete record is examined and clean.
    print_coverage(result.metadata.coverage.as_ref());
    println!();

    if !result.findings.is_empty() {
        hsep();
        println_content("  Findings:");
        hsep();
        for finding in result.findings.iter().take(DETAIL_LIMIT) {
            println_content(format!(
                "  ●  {:<14} {:<24} {:<30} {}",
                finding.function(),
                finding.target(),
                finding.suggestion(),
                confidence_color(finding.confidence().value())(&format!(
                    "{} {}",
                    finding.confidence(),
                    finding.kind()
                ))
            ));
        }
        print_hidden_count("finding", result.findings.len());
        println!();
    }

    hsep_bold();
    if result.is_empty() {
        println!(
            "  {} The scan found nothing — no function-pointer arrays, registration calls, jump tables, plugin shapes, cross-function callback chains or event systems were found in the decompiled bodies.",
            yellow_bold("◉")
        );
    } else {
        println!(
            "  {} Callback detection ready — batch translation reads it as prompt context.",
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

/// The "…and N more" line a detail section ends with when it hides some
/// entries.
fn print_hidden_count(noun: &str, total: usize) {
    if total > DETAIL_LIMIT {
        println_content(format!(
            "  {} …and {} more {noun}",
            dim("●"),
            total - DETAIL_LIMIT
        ));
    }
}
