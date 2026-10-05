//! The `memory` command — detect memory lifecycles for the open binary.
//!
//! Runs the three lifecycle detectors — allocation/release pair tracking,
//! handle lifetime detection, and reference-counting detection — against
//! the program currently open in Ghidra and saves the result to
//! `re/analysis/memory/{dll}.json` in the workspace, the same file batch
//! translation will read as prompt context. Batch translation runs the
//! same scan before its first batch when no result is cached; this
//! command is the manual entry point: it rebuilds the result on demand
//! and can print what a cached one holds.

use std::path::Path;

use anyhow::{Context, Result};
use calxgloss_ghidra::{GhidraClient, GhidraConfig};
use calxgloss_memory::engine::MemoryEngine;
use calxgloss_memory::persist::MemoryPersistor;
use calxgloss_memory::types::MemoryResult;
use chrono::DateTime;
use tracing::info;

use crate::Settings;
use crate::utils::*;

/// How many entries a detail section lists before collapsing the rest.
const DETAIL_LIMIT: usize = 10;

/// Handle the `memory` subcommand: detect memory lifecycles for `dll`,
/// or print the cached result when `show` is set.
pub async fn handle_memory(
    dll: &str,
    workspace: &Path,
    show: bool,
    settings: &Settings,
) -> Result<()> {
    let persistor = MemoryPersistor::new(workspace);

    if show {
        let result = persistor.load(dll).with_context(|| {
            format!(
                "No cached memory lifecycle result for {dll}; \
                 run `calxgloss memory --dll {dll}` to produce one"
            )
        })?;
        print_memory_lifecycle_report(&result, &persistor.path_for(dll));
        return Ok(());
    }

    info!(dll, workspace = %workspace.display(), "Detecting memory lifecycles");

    let ghidra_url = &settings.ghidra_url.value;
    let mut config = GhidraConfig::new(ghidra_url)
        .with_context(|| format!("Failed to parse GhidraMCP URL: {}", ghidra_url))?;
    if let Some(key) = &settings.ghidra_api_key {
        config = config.with_api_key(key.value.clone());
    }
    let ghidra = GhidraClient::from_config(config)
        .with_context(|| format!("Failed to connect to GhidraMCP at {}", ghidra_url))?;

    let engine = MemoryEngine::new(&ghidra);
    let result = engine
        .scan(dll)
        .await
        .with_context(|| format!("Memory lifecycle detection failed for {dll}"))?;
    persistor
        .save(&result)
        .with_context(|| format!("Failed to save the memory lifecycle result for {dll}"))?;

    print_memory_lifecycle_report(&result, &persistor.path_for(dll));
    Ok(())
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
