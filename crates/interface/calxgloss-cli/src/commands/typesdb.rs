//! The `typesdb` command's CLI contribution — recover the per-binary
//! type database (issue #339, spec #337).
//!
//! The shape of a scan — build the analysis engine, scan, persist,
//! degrade — lives in the pipeline's `type-database` registry row. This
//! module contributes only what belongs to this evidence engine: the
//! cached-document loader, the report printer, the `--no-tag` derivation
//! through the write-suppression option, and the post-scan step that
//! writes the `re/analysis/typesdb/<binary>.rs` declarations from the
//! loaded document — the one side effect the registry row does not file.
//!
//! The generic handler ([`scan_command`](crate::commands::scan_command))
//! runs the command end to end. A scan run always rebuilds the database
//! — the CLI's refresh-cache contract — and `--show` prints what a
//! cached document holds. The run's report and a later `--show` report
//! read the same document the same way.

use std::path::Path;

use anyhow::{Context, Result};
use calxgloss_decomp::PipelineSource;
use calxgloss_translator::scan_registry::ScanRunOptions;
use calxgloss_typesdb::persist::TypeDatabasePersistor;
use calxgloss_typesdb::rust_decls::render_rust_decls;
use calxgloss_typesdb::types::{TypeDatabase, TypeKind, Vtable};
use chrono::DateTime;

use crate::commands::scan_command::{
    PostScanFuture, ScanContribution, ScanContributionSteps, ScanFlags,
};
use crate::utils::*;

/// How many entries a detail section lists before collapsing the rest.
const DETAIL_LIMIT: usize = 10;

/// The `typesdb` entry in the CLI-side contribution table: it serves the
/// registry's `type-database` row and supplies this command's loader,
/// printer, flag derivation, and post-scan step.
pub(crate) fn contribution() -> ScanContribution {
    ScanContribution::new(ScanContributionSteps {
        row: "type-database",
        load: load_filed_database,
        print: print_report,
        derive_options: derive_run_options,
        post_scan: Some(write_rust_decls),
        show_loads_program: |_flags| false,
    })
}

/// Read the filed database through the evidence engine's own persistor.
/// The same loader serves the `--show` report and reads back the
/// document a run just filed. When the document is missing, the error
/// carries the remediation wording naming the exact command that
/// recovers one.
fn load_filed_database(workspace: &Path, binary: &str) -> Result<TypeDatabase> {
    let persistor = TypeDatabasePersistor::new(workspace);
    persistor.load(binary).with_context(|| {
        format!(
            "No cached type database for {binary}; \
             run `calxgloss typesdb --binary {binary}` to recover one"
        )
    })
}

/// The report printer: renders the loaded database and names where the
/// document is filed, plus where its Rust declarations are when they
/// exist. The run report and a later `--show` report read the same
/// on-disk state, so over one document the two reports come out
/// byte-identical.
fn print_report(db: &TypeDatabase, workspace: &Path, binary: &str) -> Result<()> {
    let persistor = TypeDatabasePersistor::new(workspace);
    print_type_database_report(
        db,
        &persistor.path_for(binary),
        persistor
            .decls_exists(binary)
            .then(|| persistor.decls_path_for(binary))
            .as_deref(),
    );
    Ok(())
}

/// The `--no-tag` flag reaches the scan as the write-suppression option
/// (`suppress_write_back`). The type-database row interprets it while
/// constructing its own evidence engine (issue #338). The overwrite
/// policy stays the generic handler's.
pub(crate) fn derive_run_options(flags: &ScanFlags) -> ScanRunOptions {
    ScanRunOptions {
        suppress_write_back: flags.no_tag,
        ..ScanRunOptions::default()
    }
}

/// The post-scan step: render the loaded database into `#[repr(C)]`
/// Rust declarations and write them beside the document — the one side
/// effect the registry row does not file. This step uses neither the
/// retained Kuna engine source nor the command line's flags; the
/// source parameter stays because later entries — the type-inference
/// write-back — run their follow-on steps over it.
fn write_rust_decls<'a>(
    _source: &'a PipelineSource,
    workspace: &'a Path,
    binary: &'a str,
    _flags: &'a ScanFlags,
    db: &'a mut TypeDatabase,
) -> PostScanFuture<'a> {
    Box::pin(async move {
        TypeDatabasePersistor::new(workspace)
            .save_decls(binary, &render_rust_decls(db))
            .with_context(|| format!("Failed to write the Rust declarations for {binary}"))
    })
}

/// Print a summary of a recovered type database: where it is filed, where
/// its rendered Rust declarations are (when they exist), when it was
/// built, and what each of the three recovered sections holds.
fn print_type_database_report(db: &TypeDatabase, path: &Path, decls_path: Option<&Path>) {
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
    if let Some(decls_path) = decls_path {
        println_content(format!(
            "  {}{}",
            white_bold("Rust decls: "),
            dim(&decls_path.display().to_string())
        ));
    }
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
    let nested = db
        .named_types
        .iter()
        .flat_map(|t| t.fields.iter())
        .filter(|f| f.is_nested())
        .count();
    let stl_types = db.named_types.iter().filter(|t| t.is_stl()).count();
    let mut notes = breakdown;
    if nested > 0 {
        notes.push(format!("{nested} nested fields"));
    }
    if stl_types > 0 {
        notes.push(format!("{stl_types} STL-flagged"));
    }
    println_content(format!(
        "  {}{:<5}{}",
        white_bold("Named types:"),
        db.named_types.len(),
        dim(&notes.join(", "))
    ));

    let confirmed = db.vtables.iter().filter(|v| v.is_confirmed()).count();
    let com = db.vtables.iter().filter(|v| v.is_com_interface).count();
    let stl_vtables = db.vtables.iter().filter(|v| v.is_stl()).count();
    let stl_note = if stl_vtables > 0 {
        format!(", {stl_vtables} STL-flagged")
    } else {
        String::new()
    };
    println_content(format!(
        "  {}{:<5}{}",
        white_bold("Vtables:    "),
        db.vtables.len(),
        dim(&format!("{confirmed} RTTI-confirmed, {com} COM{stl_note}"))
    ));

    let top_confidence = db.inferred_structs.iter().map(|s| s.confidence).max();
    let linked = db.inferred_structs.iter().filter(|s| s.is_linked()).count();
    let merged = db
        .inferred_structs
        .iter()
        .filter(|s| s.merged_from.is_some())
        .count();
    let stl_fields = db
        .inferred_structs
        .iter()
        .flat_map(|s| s.fields.iter())
        .filter(|f| f.is_stl())
        .count();
    println_content(format!(
        "  {}{:<5}{}",
        white_bold("Inferred:   "),
        db.inferred_structs.len(),
        dim(&match top_confidence {
            Some(confidence) => {
                let mut notes: Vec<String> = Vec::new();
                if linked > 0 {
                    notes.push(format!("{linked} linked to vtables"));
                }
                if merged > 0 {
                    notes.push(format!("{merged} merged from half-candidates"));
                }
                if stl_fields > 0 {
                    notes.push(format!("{stl_fields} STL-flagged fields"));
                }
                notes.push(format!("top confidence {confidence}"));
                notes.join(", ")
            }
            None => String::new(),
        })
    ));

    // Print the scan's own admission next to the counts it qualifies
    // (issue #348): the shared type's one bounded admission line, shown
    // under `Coverage:` and printed only when there is something to
    // admit. A target that yielded no vtable evidence says so next to
    // the zero count — the reading a reviewer needs is "this binary
    // carries no RTTI", never "this program has no classes".
    print_coverage(db.metadata.coverage.as_ref());
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
            let link = candidate
                .linked_vtable
                .map(|address| format!(" {}", dim(&format!("(vtable {address:#x})"))))
                .unwrap_or_default();
            let merge = candidate
                .merged_from
                .map(|parts| format!(" {}", dim(&format!("(merged from {parts})"))))
                .unwrap_or_default();
            println_content(format!(
                "  {}  {:<24} {:>3} fields  confidence {}{link}{merge}",
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

/// The parenthetical flags for one vtable row: RTTI/COM confirmation, the
/// STL family when flagged, and base classes.
fn vtable_notes(vtable: &Vtable) -> String {
    let mut notes: Vec<String> = Vec::new();
    if vtable.is_confirmed() {
        notes.push("RTTI".to_string());
    }
    if vtable.is_com_interface {
        notes.push("COM".to_string());
    }
    if let Some(kind) = vtable.stl_kind {
        notes.push(format!("STL {kind}"));
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
