//! The `globalstate` command — record the global-state reference sets
//! for a binary.
//!
//! Runs the global-state detector — which program globals each function
//! reads and writes, each access with its evidence statement and
//! confidence band, rolled up into a shared-globals index of who shares
//! what — against the loaded program and saves the result to
//! `re/analysis/globalstate/{binary}.json` in the workspace, the same
//! file batch translation will read as prompt context. Batch
//! translation runs the same scan before its first batch when no result
//! is cached; this command is the manual entry point: it rebuilds the
//! result on demand and can print what a cached one holds.

use std::path::Path;

use anyhow::{Context, Result};
use calxgloss_globalstate::engine::GlobalStateEngine;
use calxgloss_globalstate::persist::GlobalStatePersistor;
use calxgloss_globalstate::types::GlobalStateResult;
use chrono::DateTime;
use tracing::info;

use crate::Settings;
use crate::utils::*;

/// How many entries a detail section lists before collapsing the rest.
const DETAIL_LIMIT: usize = 10;

/// Handle the `globalstate` subcommand: record the global-state
/// reference sets for `binary`, or print the cached result when `show`
/// is set.
pub async fn handle_global_state(
    binary: &str,
    workspace: &Path,
    show: bool,
    settings: &Settings,
) -> Result<()> {
    let persistor = GlobalStatePersistor::new(workspace);

    if show {
        let result = persistor.load(binary).with_context(|| {
            format!(
                "No cached global-state result for {binary}; \
                 run `calxgloss globalstate --binary {binary}` to produce one"
            )
        })?;
        print_global_state_report(&result, &persistor.path_for(binary));
        return Ok(());
    }

    info!(binary, workspace = %workspace.display(), "Recording global-state reference sets");

    let kuna = load_kuna_source(settings, binary)?;

    let engine = GlobalStateEngine::new(&kuna);
    let result = engine
        .scan(binary)
        .await
        .with_context(|| format!("Global-state detection failed for {binary}"))?;
    persistor
        .save(&result)
        .with_context(|| format!("Failed to save the global-state result for {binary}"))?;

    print_global_state_report(&result, &persistor.path_for(binary));
    Ok(())
}

/// Print a summary of a global-state result: where it is filed, when it
/// was built, and what the access records say.
fn print_global_state_report(result: &GlobalStateResult, path: &Path) {
    println!();
    hsep_bold();
    println_content(format!("  Global state — {}", result.metadata.binary));
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

    let pure = result.purity.iter().filter(|entry| entry.is_pure).count();
    println_content(format!(
        "  {}{}{}",
        white_bold("Functions: "),
        result.purity.len(),
        dim(&format!("({pure} touch no global)"))
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
        let accesses: Vec<_> = result
            .findings
            .iter()
            .filter(|finding| finding.shared_global().is_none())
            .collect();
        for finding in accesses.iter().take(DETAIL_LIMIT) {
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
        print_hidden_count("finding", accesses.len());
        println!();
    }

    let index = index_rows(result);
    if !index.is_empty() {
        hsep();
        println_content("  Shared globals:");
        hsep();
        for row in index.iter().take(DETAIL_LIMIT) {
            println_content(row);
        }
        print_hidden_count("shared global", index.len());
        println!();
    }

    hsep_bold();
    if result.is_empty() {
        println!(
            "  {} The scan found nothing — no program global was read or written in the decompiled bodies.",
            yellow_bold("◉")
        );
    } else {
        println!(
            "  {} Global-state detection ready — the reference-set document is persisted for downstream analysis.",
            green_bold("✓")
        );
    }
    println!();
}

/// The shared-globals index rows the report prints: one per rollup
/// record, naming the global and the functions that read it and write
/// it, separated by kind — the reviewer's picture of who mutates one
/// piece of shared state.
fn index_rows(result: &GlobalStateResult) -> Vec<String> {
    result
        .findings
        .iter()
        .filter_map(|finding| finding.shared_global())
        .map(|entry| {
            format!(
                "  ●  {:<24} {:<44} {}",
                entry.global,
                format!(
                    "reads: {}  writes: {}",
                    functions_or_dash(&entry.readers),
                    functions_or_dash(&entry.writers)
                ),
                confidence_color(entry.confidence.value())(&format!(
                    "{} shared_global",
                    entry.confidence
                ))
            )
        })
        .collect()
}

/// A function list spelled for a report row; a dash when the list is
/// empty, so the kind separation stays visible either way.
fn functions_or_dash(functions: &[String]) -> String {
    if functions.is_empty() {
        "-".to_string()
    } else {
        functions.join(", ")
    }
}

/// The kind breakdown the report prints: every kind the finding union
/// can carry — the two access kinds and the rollup's index record —
/// with its count, in report order. The union is closed, and the
/// breakdown tests pin all three against the list.
fn kind_breakdown(result: &GlobalStateResult) -> Vec<String> {
    [
        (
            "global_read",
            result
                .findings
                .iter()
                .filter(|finding| finding.kind() == "global_read")
                .count(),
        ),
        (
            "global_write",
            result
                .findings
                .iter()
                .filter(|finding| finding.kind() == "global_write")
                .count(),
        ),
        (
            "shared_global",
            result
                .findings
                .iter()
                .filter(|finding| finding.kind() == "shared_global")
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
    use calxgloss_globalstate::types::{
        FunctionPurity, GlobalAccess, GlobalStateFinding, SharedGlobalRecord,
    };
    use calxgloss_types::ScanMetadata;

    fn access(function: &str, global: &str, write: bool) -> GlobalStateFinding {
        let record = GlobalAccess {
            function: function.to_string(),
            global: global.to_string(),
            evidence: format!("{global} = param_1"),
            confidence: 85.into(),
            suggestion: "model the program global as shared struct state, not a Rust static"
                .to_string(),
        };
        if write {
            GlobalStateFinding::GlobalWrite(record)
        } else {
            GlobalStateFinding::GlobalRead(record)
        }
    }

    fn shared_index(global: &str, readers: &[&str], writers: &[&str]) -> GlobalStateFinding {
        GlobalStateFinding::SharedGlobal(SharedGlobalRecord {
            global: global.to_string(),
            readers: readers.iter().map(|f| f.to_string()).collect(),
            writers: writers.iter().map(|f| f.to_string()).collect(),
            confidence: 85.into(),
        })
    }

    #[test]
    fn the_kind_breakdown_names_every_access_kind_the_union_carries() {
        let mut result = GlobalStateResult::new(ScanMetadata::new("eqmain.dll"));
        result
            .findings
            .push(access("FUN_18003ab00", "DAT_180064e80", true));
        result
            .findings
            .push(access("FUN_18003e750", "DAT_180064e80", false));
        result
            .findings
            .push(access("FUN_18003e750", "g_counter", false));
        result.findings.push(shared_index(
            "DAT_180064e80",
            &["FUN_18003e750"],
            &["FUN_18003ab00"],
        ));
        result.purity.push(FunctionPurity {
            function: "FUN_18003ab00".to_string(),
            is_pure: false,
            reads: 0,
            writes: 1,
        });
        assert_eq!(
            kind_breakdown(&result),
            ["global_read 2", "global_write 1", "shared_global 1"],
            "every kind the union carries shows up with its count"
        );
    }

    #[test]
    fn a_kind_with_no_records_stays_out_of_the_breakdown() {
        let mut result = GlobalStateResult::new(ScanMetadata::new("eqmain.dll"));
        result
            .findings
            .push(access("FUN_18003ab00", "DAT_180064e80", true));
        assert_eq!(kind_breakdown(&result), ["global_write 1"]);
    }

    #[test]
    fn the_index_rows_name_the_global_and_its_readers_and_writers() {
        // The report's index section: one row per entry, readers and
        // writers separated by kind, an empty list spelled as a dash.
        let mut result = GlobalStateResult::new(ScanMetadata::new("eqmain.dll"));
        result.findings.push(shared_index(
            "DAT_180064e80",
            &["FUN_18003e750"],
            &["FUN_18003ab00"],
        ));
        result
            .findings
            .push(shared_index("g_alone", &[], &["FUN_18003e750"]));
        let rows = index_rows(&result);
        assert_eq!(rows.len(), 2, "one row per index record");
        assert!(rows[0].contains("DAT_180064e80"));
        assert!(rows[0].contains("reads: FUN_18003e750"));
        assert!(rows[0].contains("writes: FUN_18003ab00"));
        assert!(rows[1].contains("reads: -"), "no readers, visibly");
        assert!(rows[1].contains("writes: FUN_18003e750"));
    }
}
