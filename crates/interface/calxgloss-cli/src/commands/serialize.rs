//! The `serialize` command — detect endianness and serialization
//! patterns for the open binary.
//!
//! Runs the serialization detectors — byte-swap call matching, manual
//! bit-packing recognition, and magic-byte format sniffing — against the
//! program currently open in Ghidra and saves the result to
//! `re/analysis/serialize/{dll}.json` in the workspace, the same file
//! batch translation will read as prompt context. Batch translation runs
//! the same scan before its first batch when no result is cached; this
//! command is the manual entry point: it rebuilds the result on demand
//! and can print what a cached one holds.

use std::path::Path;

use anyhow::{Context, Result};
use calxgloss_serialize::persist::SerializePersistor;
use calxgloss_serialize::types::SerializeResult;
use chrono::DateTime;
use tracing::info;

use crate::Settings;
use crate::utils::*;

/// How many entries a detail section lists before collapsing the rest.
const DETAIL_LIMIT: usize = 10;

/// Handle the `serialize` subcommand: detect serialization patterns for
/// `dll`, or print the cached result when `show` is set.
pub async fn handle_serialize(
    dll: &str,
    workspace: &Path,
    show: bool,
    _settings: &Settings,
) -> Result<()> {
    let persistor = SerializePersistor::new(workspace);

    if show {
        let result = persistor.load(dll).with_context(|| {
            format!(
                "No cached serialization result for {dll}; \
                 run `calxgloss serialize --dll {dll}` to produce one"
            )
        })?;
        print_serialization_report(&result, &persistor.path_for(dll));
        return Ok(());
    }

    info!(dll, workspace = %workspace.display(), "Detecting serialization patterns");

    // The scan engine lands with the P11 detector tickets; until it is
    // wired in, only cached results can be shown.
    anyhow::bail!(
        "serialize detection is not wired up yet — \
         `calxgloss serialize --dll {dll} --show` prints a cached result"
    )
}

/// Print a summary of a serialization result: where it is filed, when it
/// was built, and what the findings say.
fn print_serialization_report(result: &SerializeResult, path: &Path) {
    println!();
    hsep_bold();
    println_content(format!("  Serialization — {}", result.metadata.binary));
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
    let kind_breakdown: Vec<String> = ["byteswap"]
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
            "  {} The scan found nothing — no byte-swap calls, bit-packing chains, or magic-byte comparisons were found in the decompiled bodies.",
            yellow_bold("◉")
        );
    } else {
        println!(
            "  {} Serialization detection ready — batch translation reads it as prompt context.",
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
