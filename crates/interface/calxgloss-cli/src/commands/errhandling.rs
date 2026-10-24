//! The `errhandling` command — detect error-handling idioms for a binary.
//!
//! Runs the body-text detectors — reading each decompiled body for spelled
//! `try`/`catch` frames, named personality-handler thunks, exception-API
//! calls, direct `RaiseException` sites, and goto-cleanup ladders (guarded
//! forward gotos converging on one releasing join block), and records the
//! HRESULT- and NTSTATUS-shaped failure codes each body returns, raises, or
//! compares for — against the loaded program and
//! saves the result to `re/analysis/errhandling/{binary}.json` in the
//! workspace. `--show` prints a cached result without running the scan.

use std::path::Path;

use anyhow::{Context, Result};
use calxgloss_errhandling::engine::ErrhandlingEngine;
use calxgloss_errhandling::persist::ErrhandlingPersistor;
use calxgloss_errhandling::types::ErrhandlingResult;
use chrono::DateTime;
use tracing::info;

use crate::Settings;
use crate::utils::*;

/// How many entries a detail section lists before collapsing the rest.
const DETAIL_LIMIT: usize = 10;

/// Handle the `errhandling` subcommand: detect error-handling idioms
/// for `binary`, or print the cached result when `show` is set.
pub async fn handle_errhandling(
    binary: &str,
    workspace: &Path,
    show: bool,
    settings: &Settings,
) -> Result<()> {
    let persistor = ErrhandlingPersistor::new(workspace);

    if show {
        let result = persistor.load(binary).with_context(|| {
            format!(
                "No cached error-handling detection result for {binary}; \
                 run `calxgloss errhandling --binary {binary}` to produce one"
            )
        })?;
        print_errhandling_report(&result, &persistor.path_for(binary));
        return Ok(());
    }

    info!(binary, workspace = %workspace.display(), "Detecting error-handling idioms");

    let kuna = load_kuna_source(settings, binary)?;

    let engine = ErrhandlingEngine::new(&kuna);
    let result = engine
        .scan(binary)
        .await
        .with_context(|| format!("Error-handling detection failed for {binary}"))?;
    persistor
        .save(&result)
        .with_context(|| format!("Failed to save the error-handling result for {binary}"))?;

    print_errhandling_report(&result, &persistor.path_for(binary));
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
