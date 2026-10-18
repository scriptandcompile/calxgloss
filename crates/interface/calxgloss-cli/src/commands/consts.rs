//! The `consts` command — detect constant structures for a binary.
//!
//! Runs the three constant detectors — bitflag group detection,
//! enumerated-dispatch detection, and repeated-magic-number frequency
//! analysis — against the loaded program and saves the
//! result to `re/analysis/consts/{binary}.json` in the workspace, the same
//! file batch translation will read as prompt context, together with a
//! rendered Rust codegen file spelling the reconstructed flag families,
//! enums, and constants out beside the JSON. Batch translation
//! runs the same scan before its first batch when no result is cached;
//! this command is the manual entry point: it rebuilds the result on
//! demand and can print what a cached one holds.

use std::path::Path;

use anyhow::{Context, Result};
use calxgloss_consts::codegen::render_codegen;
use calxgloss_consts::engine::ConstEngine;
use calxgloss_consts::persist::ConstPersistor;
use calxgloss_consts::types::ConstResult;
use chrono::DateTime;
use tracing::info;

use crate::Settings;
use crate::utils::*;

/// How many entries a detail section lists before collapsing the rest.
const DETAIL_LIMIT: usize = 10;

/// Handle the `consts` subcommand: detect constant structures for
/// `binary`, or print the cached result when `show` is set.
pub async fn handle_consts(
    binary: &str,
    workspace: &Path,
    show: bool,
    settings: &Settings,
) -> Result<()> {
    let persistor = ConstPersistor::new(workspace);

    if show {
        let result = persistor.load(binary).with_context(|| {
            format!(
                "No cached constant result for {binary}; \
                 run `calxgloss consts --binary {binary}` to produce one"
            )
        })?;
        print_constant_report(
            &result,
            &persistor.path_for(binary),
            persistor
                .codegen_exists(binary)
                .then(|| persistor.codegen_path_for(binary))
                .as_deref(),
        );
        return Ok(());
    }

    info!(binary, workspace = %workspace.display(), "Detecting constant structures");

    let kuna = load_kuna_source(settings, binary)?;

    let engine = ConstEngine::new(&kuna);
    let result = engine
        .scan(binary)
        .await
        .with_context(|| format!("Constant detection failed for {binary}"))?;
    persistor
        .save(&result)
        .with_context(|| format!("Failed to save the constant result for {binary}"))?;
    persistor
        .save_codegen(binary, &render_codegen(&result))
        .with_context(|| format!("Failed to write the constant codegen for {binary}"))?;

    print_constant_report(
        &result,
        &persistor.path_for(binary),
        Some(&persistor.codegen_path_for(binary)),
    );
    Ok(())
}

/// Print a summary of a constant result: where it is filed, where its
/// rendered Rust codegen is (when it exists), when it was built, and
/// what the findings say.
fn print_constant_report(result: &ConstResult, path: &Path, codegen_path: Option<&Path>) {
    println!();
    hsep_bold();
    println_content(format!("  Constants — {}", result.metadata.binary));
    hsep();
    println!();

    println_content(format!(
        "  {}{}",
        white_bold("File:      "),
        dim(&path.display().to_string())
    ));
    if let Some(codegen_path) = codegen_path {
        println_content(format!(
            "  {}{}",
            white_bold("Codegen:   "),
            dim(&codegen_path.display().to_string())
        ));
    }
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
    let kind_breakdown: Vec<String> = [
        "bitflag_group",
        "enum_candidate",
        "named_constant",
        "flag_family",
        "protocol_constant",
        "color_constant",
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
            // A program-level named constant belongs to every function
            // that uses its value; the report shows the usage count
            // where a per-function name would go.
            let subject = match finding.function().is_empty() {
                true => "(program)".to_string(),
                false => finding.function().to_string(),
            };
            println_content(format!(
                "  ●  {:<14} {:<24} {:<30} {}",
                subject,
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
            "  {} The scan found nothing — no bitflag groups, enum candidates, or repeated magic numbers were found in the decompiled bodies.",
            yellow_bold("◉")
        );
    } else {
        println!(
            "  {} Constant detection ready — batch translation reads it as prompt context.",
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
