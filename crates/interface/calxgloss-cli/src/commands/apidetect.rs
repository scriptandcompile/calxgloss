//! The `apidetect` command — identify the libraries and APIs of the open binary.
//!
//! Runs the two API detectors — the import-table scanner and the
//! per-function call-graph summary — against the program currently open
//! in Ghidra and saves the result to `re/analysis/apidetect/{dll}.json`
//! in the workspace, the same file batch translation will read as prompt
//! context. Batch translation runs the same scan before its first batch
//! when no result is cached; this command is the manual entry point: it
//! rebuilds the result on demand and can print what a cached one holds.

use std::path::Path;

use anyhow::{Context, Result};
use calxgloss_apidetect::engine::ApiEngine;
use calxgloss_apidetect::persist::ApiPersistor;
use calxgloss_apidetect::types::ApiDetectionResult;
use calxgloss_ghidra::{GhidraClient, GhidraConfig};
use chrono::DateTime;
use tracing::info;

use crate::Settings;
use crate::utils::*;

/// How many entries a detail section lists before collapsing the rest.
const DETAIL_LIMIT: usize = 10;

/// Handle the `apidetect` subcommand: identify the libraries and APIs of
/// `dll`, or print the cached result when `show` is set.
pub async fn handle_apidetect(
    dll: &str,
    workspace: &Path,
    show: bool,
    settings: &Settings,
) -> Result<()> {
    let persistor = ApiPersistor::new(workspace);

    if show {
        let result = persistor.load(dll).with_context(|| {
            format!(
                "No cached API result for {dll}; \
                 run `calxgloss apidetect --dll {dll}` to produce one"
            )
        })?;
        print_api_report(&result, &persistor.path_for(dll));
        return Ok(());
    }

    info!(dll, workspace = %workspace.display(), "Identifying libraries and APIs");

    let ghidra_url = &settings.ghidra_url.value;
    let mut config = GhidraConfig::new(ghidra_url)
        .with_context(|| format!("Failed to parse GhidraMCP URL: {}", ghidra_url))?;
    if let Some(key) = &settings.ghidra_api_key {
        config = config.with_api_key(key.value.clone());
    }
    let ghidra = GhidraClient::from_config(config)
        .with_context(|| format!("Failed to connect to GhidraMCP at {}", ghidra_url))?;

    let engine = ApiEngine::new(&ghidra);
    let result = engine
        .scan(dll)
        .await
        .with_context(|| format!("API detection failed for {dll}"))?;
    persistor
        .save(&result)
        .with_context(|| format!("Failed to save the API result for {dll}"))?;

    print_api_report(&result, &persistor.path_for(dll));
    Ok(())
}

/// Print a summary of an API result: where it is filed, when it was
/// built, and what the findings say.
fn print_api_report(result: &ApiDetectionResult, path: &Path) {
    println!();
    hsep_bold();
    println_content(format!("  Libraries & APIs — {}", result.metadata.binary));
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
    let kind_breakdown: Vec<String> = ["import", "api_usage"]
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

    let identified = result
        .findings
        .iter()
        .filter(|finding| finding.library().is_some())
        .count();
    println_content(format!(
        "  {}{} identified",
        white_bold("Identified:"),
        identified
    ));
    println!();

    if !result.findings.is_empty() {
        hsep();
        println_content("  Findings:");
        hsep();
        for finding in result.findings.iter().take(DETAIL_LIMIT) {
            let function = if finding.function().is_empty() {
                "(binary)"
            } else {
                finding.function()
            };
            println_content(format!(
                "  ●  {:<14} {:<24} {:<22} {}",
                function,
                finding.target(),
                finding.rust_crate().unwrap_or("(unidentified)"),
                confidence_color(finding.confidence().value())(&format!(
                    "{} {}",
                    finding.confidence().value(),
                    finding.kind()
                ))
            ));
        }
        print_hidden_count("finding", result.findings.len());
        println!();
    }

    hsep_bold();
    if result.findings.is_empty() {
        println!(
            "  {} The scan found nothing — the binary imports nothing the mapping database knows.",
            yellow_bold("◉")
        );
    } else {
        println!(
            "  {} API detection ready — batch translation reads it as prompt context.",
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
