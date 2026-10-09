//! The `controlflow` command — detect control-flow patterns for the open binary.
//!
//! Runs the control-flow detectors — switch-shaped if/else-if chains,
//! self-recursion, and state-machine patterns — against the program
//! currently open in Ghidra and saves the result to
//! `re/analysis/controlflow/{binary}.json` in the workspace, the same file
//! batch translation will read as prompt context. Batch translation runs
//! the same scan before its first batch when no result is cached; this
//! command is the manual entry point: it rebuilds the result on demand
//! and can print what a cached one holds.

use std::path::Path;

use anyhow::{Context, Result};
use calxgloss_controlflow::engine::ControlFlowEngine;
use calxgloss_controlflow::persist::ControlFlowPersistor;
use calxgloss_controlflow::types::ControlFlowResult;
use calxgloss_ghidra::{GhidraClient, GhidraConfig};
use chrono::DateTime;
use tracing::info;

use crate::Settings;
use crate::utils::*;

/// How many entries a detail section lists before collapsing the rest.
const DETAIL_LIMIT: usize = 10;

/// Handle the `controlflow` subcommand: detect control-flow patterns for
/// `binary`, or print the cached result when `show` is set.
pub async fn handle_controlflow(
    binary: &str,
    workspace: &Path,
    show: bool,
    settings: &Settings,
) -> Result<()> {
    let persistor = ControlFlowPersistor::new(workspace);

    if show {
        let result = persistor.load(binary).with_context(|| {
            format!(
                "No cached control-flow result for {binary}; \
                 run `calxgloss controlflow --binary {binary}` to produce one"
            )
        })?;
        print_controlflow_report(&result, &persistor.path_for(binary));
        return Ok(());
    }

    info!(binary, workspace = %workspace.display(), "Detecting control-flow patterns");

    let ghidra_url = &settings.ghidra_url.value;
    let mut config = GhidraConfig::new(ghidra_url)
        .with_context(|| format!("Failed to parse GhidraMCP URL: {}", ghidra_url))?;
    if let Some(key) = &settings.ghidra_api_key {
        config = config.with_api_key(key.value.clone());
    }
    let ghidra = GhidraClient::from_config(config)
        .with_context(|| format!("Failed to connect to GhidraMCP at {}", ghidra_url))?;

    let engine = ControlFlowEngine::new(&ghidra);
    let result = engine
        .scan(binary)
        .await
        .with_context(|| format!("Control-flow detection failed for {binary}"))?;
    persistor
        .save(&result)
        .with_context(|| format!("Failed to save the control-flow result for {binary}"))?;

    print_controlflow_report(&result, &persistor.path_for(binary));
    Ok(())
}

/// Print a summary of a control-flow result: where it is filed, when it
/// was built, and what the findings say.
fn print_controlflow_report(result: &ControlFlowResult, path: &Path) {
    println!();
    hsep_bold();
    println_content(format!("  Control flow — {}", result.metadata.binary));
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
    let kind_breakdown: Vec<String> = ["switch", "recursion", "state_machine"]
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
            "  {} The scan found nothing — no switch-shaped chains, self-recursive functions, or state-machine patterns were found in the decompiled bodies.",
            yellow_bold("◉")
        );
    } else {
        println!(
            "  {} Control-flow detection ready — batch translation reads it as prompt context.",
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
