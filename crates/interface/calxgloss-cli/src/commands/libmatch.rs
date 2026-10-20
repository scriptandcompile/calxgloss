//! The `libmatch` command — identify known-library functions for a binary.
//!
//! Runs the body-signature matcher — normalizing each decompiled body so
//! Ghidra variable names, register temporaries, and volatile addresses
//! read as wildcards, then matching the shape against the built-in
//! signature set of statically linked CRT/STL code — against the loaded
//! program and saves the result to `re/analysis/libmatch/{binary}.json`
//! in the workspace. `--show` prints a cached result without running the
//! scan.

use std::path::Path;

use anyhow::{Context, Result};
use calxgloss_libmatch::engine::LibmatchEngine;
use calxgloss_libmatch::persist::LibmatchPersistor;
use calxgloss_libmatch::types::LibmatchResult;
use chrono::DateTime;
use tracing::info;

use crate::Settings;
use crate::utils::*;

/// How many entries a detail section lists before collapsing the rest.
const DETAIL_LIMIT: usize = 10;

/// Handle the `libmatch` subcommand: identify known-library functions
/// for `binary`, or print the cached result when `show` is set.
pub async fn handle_libmatch(
    binary: &str,
    workspace: &Path,
    show: bool,
    settings: &Settings,
) -> Result<()> {
    let persistor = LibmatchPersistor::new(workspace);

    if show {
        let result = persistor.load(binary).with_context(|| {
            format!(
                "No cached known-library identification result for {binary}; \
                 run `calxgloss libmatch --binary {binary}` to produce one"
            )
        })?;
        print_libmatch_report(&result, &persistor.path_for(binary));
        return Ok(());
    }

    info!(binary, workspace = %workspace.display(), "Identifying known-library functions");

    let kuna = load_kuna_source(settings, binary)?;

    let engine = LibmatchEngine::new(&kuna);
    let result = engine
        .scan(binary)
        .await
        .with_context(|| format!("Known-library identification failed for {binary}"))?;
    persistor
        .save(&result)
        .with_context(|| format!("Failed to save the known-library result for {binary}"))?;

    print_libmatch_report(&result, &persistor.path_for(binary));
    Ok(())
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
