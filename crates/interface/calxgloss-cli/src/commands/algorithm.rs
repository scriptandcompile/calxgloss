//! The `algorithm` command — recognize algorithms in the open binary.
//!
//! Runs the three recognition detectors — control flow signature
//! matching, string-guided hints, and callback pattern detection —
//! against the program currently open in Ghidra and saves the result to
//! `re/analysis/algorithm/{binary}.json` in the workspace. Batch
//! translation runs the same scan before its first batch when no result
//! is cached; this command is the manual entry point: it rebuilds the
//! result on demand and can print what a cached one holds.

use std::path::Path;

use anyhow::{Context, Result};
use calxgloss_algorithm::engine::AlgorithmEngine;
use calxgloss_algorithm::persist::AlgorithmPersistor;
use calxgloss_algorithm::types::AlgorithmRecognitionResult;
use calxgloss_algorithm::types::DetectionMethod;
use calxgloss_ghidra::{GhidraClient, GhidraConfig};
use chrono::DateTime;
use tracing::info;

use crate::Settings;
use crate::utils::*;

/// How many entries a detail section lists before collapsing the rest.
const DETAIL_LIMIT: usize = 10;

/// Handle the `algorithm` subcommand: recognize algorithms in `binary`,
/// or print the cached result when `show` is set.
pub async fn handle_algorithm(
    binary: &str,
    workspace: &Path,
    show: bool,
    settings: &Settings,
) -> Result<()> {
    let persistor = AlgorithmPersistor::new(workspace);

    if show {
        let result = persistor.load(binary).with_context(|| {
            format!(
                "No cached algorithm recognition result for {binary}; \
                 run `calxgloss algorithm --binary {binary}` to produce one"
            )
        })?;
        print_algorithm_recognition_report(&result, &persistor.path_for(binary));
        return Ok(());
    }

    info!(binary, workspace = %workspace.display(), "Recognizing algorithms");

    let ghidra_url = &settings.ghidra_url.value;
    let mut config = GhidraConfig::new(ghidra_url)
        .with_context(|| format!("Failed to parse GhidraMCP URL: {}", ghidra_url))?;
    if let Some(key) = &settings.ghidra_api_key {
        config = config.with_api_key(key.value.clone());
    }
    let ghidra = GhidraClient::from_config(config)
        .with_context(|| format!("Failed to connect to GhidraMCP at {}", ghidra_url))?;

    let engine = AlgorithmEngine::new(&ghidra);
    let result = engine
        .scan(binary)
        .await
        .with_context(|| format!("Algorithm recognition failed for {binary}"))?;
    persistor
        .save(&result)
        .with_context(|| format!("Failed to save the algorithm recognition result for {binary}"))?;

    print_algorithm_recognition_report(&result, &persistor.path_for(binary));
    Ok(())
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
