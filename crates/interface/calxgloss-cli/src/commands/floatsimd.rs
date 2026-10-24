//! The `floatsimd` command — flag float/SIMD usage for a binary.
//!
//! Runs the body-text detectors — reading each decompiled body for
//! explicit `float`/`double` tokens, casts, and float literals, CRT
//! math import calls, `CONCAT44`/`SUB4`-style vector assembly idioms,
//! and parallel `x`/`y`/`z` component reads — against the loaded
//! program and saves one flag per flagged function to
//! `re/analysis/floatsimd/{binary}.json` in the workspace, the same
//! file batch translation will read as prompt context. `--show` prints
//! a cached result without running the scan.

use std::path::Path;

use anyhow::{Context, Result};
use calxgloss_floatsimd::engine::FloatsimdEngine;
use calxgloss_floatsimd::persist::FloatsimdPersistor;
use calxgloss_floatsimd::types::FloatsimdResult;
use chrono::DateTime;
use tracing::info;

use crate::Settings;
use crate::utils::*;

/// How many entries a detail section lists before collapsing the rest.
const DETAIL_LIMIT: usize = 10;

/// Handle the `floatsimd` subcommand: flag float/SIMD usage for
/// `binary`, or print the cached result when `show` is set.
pub async fn handle_floatsimd(
    binary: &str,
    workspace: &Path,
    show: bool,
    settings: &Settings,
) -> Result<()> {
    let persistor = FloatsimdPersistor::new(workspace);

    if show {
        let result = persistor.load(binary).with_context(|| {
            format!(
                "No cached float/SIMD detection result for {binary}; \
                 run `calxgloss floatsimd --binary {binary}` to produce one"
            )
        })?;
        print_floatsimd_report(&result, &persistor.path_for(binary));
        return Ok(());
    }

    info!(binary, workspace = %workspace.display(), "Flagging float/SIMD usage");

    let kuna = load_kuna_source(settings, binary)?;

    let engine = FloatsimdEngine::new(&kuna);
    let result = engine
        .scan(binary)
        .await
        .with_context(|| format!("Float/SIMD usage detection failed for {binary}"))?;
    persistor
        .save(&result)
        .with_context(|| format!("Failed to save the float/SIMD result for {binary}"))?;

    print_floatsimd_report(&result, &persistor.path_for(binary));
    Ok(())
}

/// Print a summary of a detection result: where it is filed, when it
/// was built, and which functions the scan flagged.
fn print_floatsimd_report(result: &FloatsimdResult, path: &Path) {
    println!();
    hsep_bold();
    println_content(format!(
        "  Float/SIMD Usage Detection — {}",
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

    println_content(format!(
        "  {}{:<5}{}",
        white_bold("Findings:  "),
        result.findings.len(),
        dim(&kind_breakdown(result).join(", "))
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
        println_content("  Flagged functions:");
        hsep();
        for finding in result.findings.iter().take(DETAIL_LIMIT) {
            println_content(format!(
                "  ●  {:<14} {:<14} {:<70} {}",
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
        print_hidden_count("flag", result.findings.len());
        println!();
    }

    hsep_bold();
    if result.is_empty() {
        println!(
            "  {} The scan found nothing — no decompiled body carried float evidence.",
            yellow_bold("◉")
        );
    } else {
        println!(
            "  {} Float/SIMD detection ready — every flagged function names its shape in the record.",
            green_bold("✓")
        );
    }
    println!();
}

/// The shape breakdown the report prints: every shape tag the finding
/// union can carry — scalar float math, vector/matrix idioms, and the
/// both-shapes flag — with its count, in report order. The union is
/// closed, and the breakdown tests pin all three against the list.
fn kind_breakdown(result: &FloatsimdResult) -> Vec<String> {
    [
        (
            "scalar_float",
            result
                .findings
                .iter()
                .filter(|finding| finding.kind() == "scalar_float")
                .count(),
        ),
        (
            "vector_matrix",
            result
                .findings
                .iter()
                .filter(|finding| finding.kind() == "vector_matrix")
                .count(),
        ),
        (
            "mixed",
            result
                .findings
                .iter()
                .filter(|finding| finding.kind() == "mixed")
                .count(),
        ),
    ]
    .into_iter()
    .filter(|(_, count)| *count > 0)
    .map(|(kind, count)| format!("{kind} {count}"))
    .collect()
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

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use calxgloss_floatsimd::types::{FloatsimdFinding, FloatsimdRecord, ShapeKind};
    use calxgloss_types::{Confidence, ScanMetadata};

    fn flag(function: &str, shape: ShapeKind) -> FloatsimdFinding {
        let record = FloatsimdRecord {
            function: function.to_string(),
            evidence: "fVar1 = (float)uVar2 * 1.5f;".to_string(),
            confidence: Confidence::new(90),
            suggestion: "translate this body with f32/f64 scalars".to_string(),
        };
        match shape {
            ShapeKind::ScalarFloat => FloatsimdFinding::ScalarFloat(record),
            ShapeKind::VectorMatrix => FloatsimdFinding::VectorMatrix(record),
            ShapeKind::Mixed => FloatsimdFinding::Mixed(record),
        }
    }

    #[test]
    fn the_shape_breakdown_names_every_tag_the_union_carries() {
        let mut result = FloatsimdResult::new(ScanMetadata::new("eqmain.dll"));
        result
            .findings
            .push(flag("FUN_18003ab00", ShapeKind::ScalarFloat));
        result
            .findings
            .push(flag("FUN_18003e750", ShapeKind::VectorMatrix));
        result
            .findings
            .push(flag("FUN_1800412a0", ShapeKind::Mixed));
        assert_eq!(
            kind_breakdown(&result),
            ["scalar_float 1", "vector_matrix 1", "mixed 1"],
            "every shape the union carries shows up with its count"
        );
    }

    #[test]
    fn a_shape_with_no_flags_stays_out_of_the_breakdown() {
        let mut result = FloatsimdResult::new(ScanMetadata::new("eqmain.dll"));
        result
            .findings
            .push(flag("FUN_18003ab00", ShapeKind::ScalarFloat));
        assert_eq!(kind_breakdown(&result), ["scalar_float 1"]);
    }

    #[test]
    fn the_breakdown_counts_repeated_shapes_together() {
        let mut result = FloatsimdResult::new(ScanMetadata::new("eqmain.dll"));
        result
            .findings
            .push(flag("FUN_18003ab00", ShapeKind::VectorMatrix));
        result
            .findings
            .push(flag("FUN_18003e750", ShapeKind::VectorMatrix));
        assert_eq!(kind_breakdown(&result), ["vector_matrix 2"]);
    }
}
