//! The `libmatch` command's CLI contribution — identify known-library
//! functions for a binary (issue #341, spec #337).
//!
//! The scan shape — engine build, scan, persist, degradation — lives in
//! the pipeline's `known-library` registry row; this module contributes
//! only what is genuinely per-engine: the cached-document loader, the
//! report printer, and the `--signatures` derivation through the
//! registry's own set-override option, which the row interprets inside
//! its own engine build. The generic handler
//! ([`scan_command`](crate::commands::scan_command)) routes the command
//! end to end: it rebuilds the result on demand (the CLI's force-rescan
//! contract) and can print what a cached one holds, filing it where the
//! row files it — `re/analysis/libmatch/{binary}.json`. The run's
//! report and a later `--show` report are the same read of the same
//! document.
//!
//! With `--signatures <file>`, the scan reads its signature set from a
//! JSON [signature database](calxgloss_libmatch::signature_db) instead
//! of the built-in starter set — a malformed file fails the run naming
//! its path. The flag is ignored on the `--show` path, which prints a
//! cached result without scanning.

use std::path::Path;

use anyhow::{Context, Result};
use calxgloss_libmatch::persist::LibmatchPersistor;
use calxgloss_libmatch::types::LibmatchResult;
use calxgloss_translator::scan_registry::ScanRunOptions;
use chrono::DateTime;

use crate::commands::scan_command::{ScanContribution, ScanContributionSteps, ScanFlags};
use crate::utils::*;

/// How many entries a detail section lists before collapsing the rest.
const DETAIL_LIMIT: usize = 10;

/// The `libmatch` entry in the CLI-side contribution table: it serves
/// the registry's `known-library` row and supplies this command's
/// loader, printer, and flag derivation. `--signatures` reaches the row
/// build through the set-override option; the overwrite policy is the
/// generic handler's to set.
pub(crate) fn contribution() -> ScanContribution {
    ScanContribution::new(ScanContributionSteps {
        row: "known-library",
        load: load_filed_result,
        print: print_report,
        derive_options: derive_run_options,
        post_scan: None,
        show_loads_program: |_flags| false,
    })
}

/// Read the filed result through the engine's own persistor — the same
/// loader for the `--show` report and for reading the document a run
/// just filed. A missing one arrives with the remediation wording
/// naming the exact producing command.
fn load_filed_result(workspace: &Path, binary: &str) -> Result<LibmatchResult> {
    LibmatchPersistor::new(workspace)
        .load(binary)
        .with_context(|| {
            format!(
                "No cached known-library identification result for {binary}; \
             run `calxgloss libmatch --binary {binary}` to produce one"
            )
        })
}

/// Print the report over the loaded result, naming where the document
/// is filed. Both paths read the same on-disk state, so the run's
/// report and a later `--show` report are byte-identical over one
/// document.
fn print_report(result: &LibmatchResult, workspace: &Path, binary: &str) -> Result<()> {
    print_libmatch_report(result, &LibmatchPersistor::new(workspace).path_for(binary));
    Ok(())
}

/// The `--signatures` flag reaches the scan as the registry's
/// set-override option, which the known-library row interprets inside
/// its own engine build (issue #338); a malformed database fails the
/// row, whose warning the handler turns into a failed run. The
/// overwrite policy stays the generic handler's.
pub(crate) fn derive_run_options(flags: &ScanFlags) -> ScanRunOptions {
    ScanRunOptions {
        set_override_file: flags.set_override_file.clone(),
        ..ScanRunOptions::default()
    }
}

/// Print a summary of an identification result: where it is filed, when
/// it was built, and what the findings say.
fn print_libmatch_report(result: &LibmatchResult, path: &Path) {
    println!();
    hsep_bold();
    println_content(format!(
        "  Known-Library Identification — {}",
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

    // Findings, broken down by the library family the matches name.
    let family_breakdown: Vec<String> = ["crt", "stl"]
        .into_iter()
        .map(|family| {
            (
                family,
                result
                    .findings
                    .iter()
                    .filter(|finding| finding.family().to_string() == family)
                    .count(),
            )
        })
        .filter(|(_, count)| *count > 0)
        .map(|(family, count)| format!("{family} {count}"))
        .collect();
    println_content(format!(
        "  {}{:<5}{}",
        white_bold("Findings:  "),
        result.findings.len(),
        dim(&family_breakdown.join(", "))
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
    // #347): the shared type's bounded line, framed under `Coverage:` and
    // printed only when there is something to admit.
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
                    "{} {} {}",
                    finding.confidence(),
                    finding.family(),
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
            "  {} The scan found nothing — no decompiled body matched a known-library signature.",
            yellow_bold("◉")
        );
    } else {
        println!(
            "  {} Known-library identification ready — statically linked CRT/STL functions are named in the record.",
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
