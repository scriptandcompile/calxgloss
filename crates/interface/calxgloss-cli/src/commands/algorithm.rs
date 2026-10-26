//! The `algorithm` command's CLI contribution — recognize algorithms in
//! a binary (issue #341, spec #337).
//!
//! The scan shape — engine build, scan, persist, degradation — lives in
//! the pipeline's `algorithm-recognition` registry row; this module
//! contributes only what is genuinely per-engine: the cached-document
//! loader, the report printer, and the `--patterns` derivation through
//! the registry's own set-override option, which the row interprets
//! inside its own engine build. The generic handler
//! ([`scan_command`](crate::commands::scan_command)) routes the command
//! end to end: it rebuilds the result on demand (the CLI's force-rescan
//! contract) and can print what a cached one holds, filing it where the
//! row files it — `re/analysis/algorithm/{binary}.json` — the same file
//! batch translation reads as prompt context. The run's report and a
//! later `--show` report are the same read of the same document.
//!
//! With `--patterns <file>`, the scan reads its signature sets from a
//! JSON [pattern database](calxgloss_algorithm::pattern_db) instead of
//! the built-in standard sets — a malformed file fails the run naming
//! its path. The flag is ignored on the `--show` path, which prints a
//! cached result without scanning.

use std::path::Path;

use anyhow::{Context, Result};
use calxgloss_algorithm::persist::AlgorithmPersistor;
use calxgloss_algorithm::types::AlgorithmRecognitionResult;
use calxgloss_algorithm::types::DetectionMethod;
use calxgloss_translator::scan_registry::ScanRunOptions;
use chrono::DateTime;

use crate::commands::scan_command::{ScanContribution, ScanContributionSteps, ScanFlags};
use crate::utils::*;

/// How many entries a detail section lists before collapsing the rest.
const DETAIL_LIMIT: usize = 10;

/// The `algorithm` entry in the CLI-side contribution table: it serves
/// the registry's `algorithm-recognition` row and supplies this
/// command's loader, printer, and flag derivation. `--patterns` reaches
/// the row build through the set-override option; the overwrite policy
/// is the generic handler's to set.
pub(crate) fn contribution() -> ScanContribution {
    ScanContribution::new(ScanContributionSteps {
        row: "algorithm-recognition",
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
fn load_filed_result(workspace: &Path, binary: &str) -> Result<AlgorithmRecognitionResult> {
    AlgorithmPersistor::new(workspace)
        .load(binary)
        .with_context(|| {
            format!(
                "No cached algorithm recognition result for {binary}; \
                 run `calxgloss algorithm --binary {binary}` to produce one"
            )
        })
}

/// Print the report over the loaded result, naming where the document
/// is filed. Both paths read the same on-disk state, so the run's
/// report and a later `--show` report are byte-identical over one
/// document.
fn print_report(result: &AlgorithmRecognitionResult, workspace: &Path, binary: &str) -> Result<()> {
    print_algorithm_recognition_report(
        result,
        &AlgorithmPersistor::new(workspace).path_for(binary),
    );
    Ok(())
}

/// The `--patterns` flag reaches the scan as the registry's set-override
/// option, which the algorithm-recognition row interprets inside its
/// own engine build (issue #338); a malformed database fails the row,
/// whose warning the handler turns into a failed run. The overwrite
/// policy stays the generic handler's.
pub(crate) fn derive_run_options(flags: &ScanFlags) -> ScanRunOptions {
    ScanRunOptions {
        set_override_file: flags.set_override_file.clone(),
        ..ScanRunOptions::default()
    }
}

/// Print a summary of a recognition result: where it is filed, when it
/// was built, and what the surviving hints say.
fn print_algorithm_recognition_report(result: &AlgorithmRecognitionResult, path: &Path) {
    println!();
    hsep_bold();
    println_content(format!(
        "  Algorithm Recognition — {}",
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

    // Hints, broken down by the detector that made each one.
    let method_breakdown: Vec<String> = [
        DetectionMethod::CfgPattern,
        DetectionMethod::StringHint,
        DetectionMethod::CallbackPattern,
        DetectionMethod::CrossFunction,
    ]
    .into_iter()
    .map(|method| {
        (
            method,
            result
                .hints
                .iter()
                .filter(|hint| hint.method == method)
                .count(),
        )
    })
    .filter(|(_, count)| *count > 0)
    .map(|(method, count)| format!("{method} {count}"))
    .collect();
    println_content(format!(
        "  {}{:<5}{}",
        white_bold("Hints:     "),
        result.hints.len(),
        dim(&method_breakdown.join(", "))
    ));

    let top_confidence = result.hints.iter().map(|h| h.confidence.value()).max();
    println_content(format!(
        "  {}{}",
        white_bold("Top conf:  "),
        match top_confidence {
            Some(confidence) => confidence_color(confidence)(&confidence.to_string()),
            None => dim("(none)"),
        }
    ));
    println!();

    if !result.hints.is_empty() {
        hsep();
        println_content("  Hints:");
        hsep();
        for hint in result.hints.iter().take(DETAIL_LIMIT) {
            println_content(format!(
                "  ●  {:<14} {:<22} {:<14} {}",
                hint.function,
                hint.algorithm,
                hint.category,
                confidence_color(hint.confidence.value())(&format!(
                    "{} {}",
                    hint.confidence, hint.method
                ))
            ));
        }
        print_hidden_count("hint", result.hints.len());
        println!();
    }

    hsep_bold();
    if result.is_empty() {
        println!(
            "  {} The scan recognized nothing — no control flow, string, or callback signature matched the decompiled bodies.",
            yellow_bold("◉")
        );
    } else {
        println!(
            "  {} Algorithm recognition ready — batch translation reads it as prompt context.",
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
