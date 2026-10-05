//! The `memory` command — inspect the cached memory lifecycle result.
//!
//! The three lifecycle detectors — allocation/release pair tracking,
//! handle lifetime detection, and reference-counting detection — file
//! their findings per binary at `re/analysis/memory/{dll}.json` in the
//! workspace, the same file batch translation will read as prompt
//! context. `--show` prints a cached document without connecting to
//! Ghidra; the on-demand scan that produces one arrives with the memory
//! engine, so running the command without `--show` reports that the
//! scan is not wired up yet.

use std::path::Path;

use anyhow::{Context, Result, anyhow};
use calxgloss_memory::persist::MemoryPersistor;
use calxgloss_memory::types::MemoryResult;
use chrono::DateTime;

use crate::utils::*;

/// How many entries a detail section lists before collapsing the rest.
const DETAIL_LIMIT: usize = 10;

/// Handle the `memory` subcommand: print the cached lifecycle result
/// for `dll` when `show` is set.
pub async fn handle_memory(dll: &str, workspace: &Path, show: bool) -> Result<()> {
    let persistor = MemoryPersistor::new(workspace);

    if show {
        let result = persistor.load(dll).with_context(|| {
            format!(
                "No cached memory lifecycle result for {dll}; \
                 the scan that produces one (`calxgloss memory --dll {dll}`) \
                 is not wired up yet"
            )
        })?;
        print_memory_lifecycle_report(&result, &persistor.path_for(dll));
        return Ok(());
    }

    // The scan against the open Ghidra program lands with `MemoryEngine`
    // (the next P4 step); until then the command is read-only.
    Err(anyhow!(
        "the memory lifecycle scan is not wired up yet; \
         `calxgloss memory --dll {dll} --show` prints a cached document"
    ))
}

/// Print a summary of a lifecycle result: where it is filed, when it
/// was built, and what the findings say.
fn print_memory_lifecycle_report(result: &MemoryResult, path: &Path) {
    println!();
    hsep_bold();
    println_content(format!("  Memory Lifecycle — {}", result.metadata.binary));
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

    // Findings, broken down by the record kind the union carries.
    let kind_breakdown: Vec<String> = ["allocation", "handle", "ref_count"]
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
            "  {} The scan found nothing — no allocation/release pairs, handle lifetimes, or reference-count pairs were found in the decompiled bodies.",
            yellow_bold("◉")
        );
    } else {
        println!(
            "  {} Memory lifecycle analysis ready — batch translation reads it as prompt context.",
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
