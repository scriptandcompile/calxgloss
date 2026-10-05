//! The `typesdb` command — recover the per-binary type database.
//!
//! Runs the three recovery scans — named types from Ghidra's Type Manager,
//! vtable detection, and string-guided struct inference — against the
//! program currently open in Ghidra and saves the result to
//! `re/analysis/typesdb/{dll}.json` in the workspace. Batch translation
//! runs the same recovery before its first batch when no database is
//! cached; this command is the manual entry point: it rebuilds the
//! database on demand and can print what a cached one holds.

use std::path::Path;

use anyhow::{Context, Result};
use calxgloss_ghidra::{GhidraClient, GhidraConfig};
use calxgloss_typesdb::engine::TypesDBEngine;
use calxgloss_typesdb::persist::TypeDatabasePersistor;
use calxgloss_typesdb::types::{TypeDatabase, TypeKind, Vtable};
use chrono::DateTime;
use tracing::info;

use crate::Settings;
use crate::utils::*;

/// How many entries a detail section lists before collapsing the rest.
const DETAIL_LIMIT: usize = 10;

/// Handle the `typesdb` subcommand: recover the type database for `dll`,
/// or print the cached one when `show` is set.
pub async fn handle_typesdb(
    dll: &str,
    workspace: &Path,
    show: bool,
    no_tag: bool,
    settings: &Settings,
) -> Result<()> {
    let persistor = TypeDatabasePersistor::new(workspace);

    if show {
        let db = persistor.load(dll).with_context(|| {
            format!(
                "No cached type database for {dll}; \
                 run `calxgloss typesdb --dll {dll}` to recover one"
            )
        })?;
        print_type_database_report(&db, &persistor.path_for(dll));
        return Ok(());
    }

    info!(dll, workspace = %workspace.display(), "Recovering type database");

    let ghidra_url = &settings.ghidra_url.value;
    let mut config = GhidraConfig::new(ghidra_url)
        .with_context(|| format!("Failed to parse GhidraMCP URL: {}", ghidra_url))?;
    if let Some(key) = &settings.ghidra_api_key {
        config = config.with_api_key(key.value.clone());
    }
    let ghidra = GhidraClient::from_config(config)
        .with_context(|| format!("Failed to connect to GhidraMCP at {}", ghidra_url))?;

    let mut engine = TypesDBEngine::new(&ghidra);
    if no_tag {
        engine = engine.without_tagging();
    }

    let db = engine
        .scan(dll)
        .await
        .with_context(|| format!("Type database recovery failed for {dll}"))?;
    persistor
        .save(&db)
        .with_context(|| format!("Failed to save the type database for {dll}"))?;

    print_type_database_report(&db, &persistor.path_for(dll));
    Ok(())
}

/// Print a summary of a recovered type database: where it is filed, when
/// it was built, and what each of the three recovered sections holds.
fn print_type_database_report(db: &TypeDatabase, path: &Path) {
    println!();
    hsep_bold();
    println_content(format!("  Type Database — {}", db.metadata.binary));
    hsep();
    println!();

    println_content(format!(
        "  {}{}",
        white_bold("File:       "),
        dim(&path.display().to_string())
    ));
    let scanned = DateTime::from_timestamp(db.metadata.scanned_at as i64, 0)
        .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
        .unwrap_or_else(|| format!("unix {}", db.metadata.scanned_at));
    println_content(format!(
        "  {}{} {}",
        white_bold("Scanned:    "),
        scanned,
        dim(&format!("({}s)", db.metadata.duration_secs))
    ));
    println!();

    // Named types, broken down by the kind the scan established.
    let breakdown: Vec<String> = [
        TypeKind::Struct,
        TypeKind::Class,
        TypeKind::Union,
        TypeKind::Enum,
        TypeKind::Typedef,
        TypeKind::Other,
    ]
    .into_iter()
    .map(|kind| {
        (
            kind,
            db.named_types.iter().filter(|t| t.kind == kind).count(),
        )
    })
    .filter(|(_, count)| *count > 0)
    .map(|(kind, count)| format!("{kind} {count}"))
    .collect();
    println_content(format!(
        "  {}{:<5}{}",
        white_bold("Named types:"),
        db.named_types.len(),
        dim(&breakdown.join(", "))
    ));

    let confirmed = db.vtables.iter().filter(|v| v.is_confirmed()).count();
    let com = db.vtables.iter().filter(|v| v.is_com_interface).count();
    println_content(format!(
        "  {}{:<5}{}",
        white_bold("Vtables:    "),
        db.vtables.len(),
        dim(&format!("{confirmed} RTTI-confirmed, {com} COM"))
    ));

    let top_confidence = db.inferred_structs.iter().map(|s| s.confidence).max();
    println_content(format!(
        "  {}{:<5}{}",
        white_bold("Inferred:   "),
        db.inferred_structs.len(),
        dim(&match top_confidence {
            Some(confidence) => format!("top confidence {confidence}"),
            None => String::new(),
        })
    ));
    println!();

    if !db.vtables.is_empty() {
        hsep();
        println_content("  Vtables:");
        hsep();
        for vtable in db.vtables.iter().take(DETAIL_LIMIT) {
            let owner = vtable.class_name.as_deref().unwrap_or("(unresolved)");
            println_content(format!(
                "  {}  {:#x}  {}  {} methods{}",
                dim("●"),
                vtable.address,
                white_bold(owner),
                vtable.methods.len(),
                dim(&vtable_notes(vtable))
            ));
        }
        print_hidden_count("vtable", db.vtables.len());
        println!();
    }

    if !db.inferred_structs.is_empty() {
        hsep();
        println_content("  Inferred struct candidates:");
        hsep();
        for candidate in db.inferred_structs.iter().take(DETAIL_LIMIT) {
            println_content(format!(
                "  {}  {:<24} {:>3} fields  confidence {}",
                dim("●"),
                white_bold(&candidate.name),
                candidate.fields.len(),
                confidence_color(candidate.confidence.value())(&candidate.confidence.to_string())
            ));
        }
        print_hidden_count("candidate", db.inferred_structs.len());
        println!();
    }

    hsep_bold();
    if db.is_empty() {
        println!(
            "  {} The scan recovered nothing — the program has no named types, vtables, or string clusters to infer from.",
            yellow_bold("◉")
        );
    } else {
        println!(
            "  {} Type database ready — batch translation reads it as prompt context.",
            green_bold("✓")
        );
    }
    println!();
}

/// The parenthetical flags for one vtable row: RTTI/COM confirmation and
/// base classes.
fn vtable_notes(vtable: &Vtable) -> String {
    let mut notes: Vec<String> = Vec::new();
    if vtable.is_confirmed() {
        notes.push("RTTI".to_string());
    }
    if vtable.is_com_interface {
        notes.push("COM".to_string());
    }
    match vtable.base_classes.len() {
        0 => {}
        1 => notes.push(format!("base: {}", vtable.base_classes[0])),
        count => notes.push(format!("{count} bases")),
    }
    if notes.is_empty() {
        String::new()
    } else {
        format!(" ({})", notes.join(", "))
    }
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
