//! The `capture` command — mine the baseline from real calls (P23.2 + P23.6,
//! issues #396 and #400).
//!
//! Two shapes, one command. With `--app <EXE>` the command **runs** the
//! reference application against the target under Wine: it scaffolds an
//! instrumented run dir (the real target parked under its real module name,
//! the recording proxy wearing the target's identity in front of it),
//! launches the application with the run dir on the DLL search path, and
//! stops the run at the capture budgets — max events, duration, event-log
//! size — each one stating its truncation in the report. Stopping rides
//! owned-process discipline: the launched process is bound to an ownership
//! token at launch and rechecked before every signal. A finished or
//! interrupted run always leaves the run dir holding the real module under
//! its own identity beside the finished event log — never a recorder
//! standing over the target. With `--ingest <LOG>` the command folds an
//! event log taken earlier or on another machine without re-running
//! anything: `--ingest` stays a separate fold step.
//!
//! Both shapes then fold through the record-and-replay lane: every captured
//! argument vector a listed export's signature can hold is replayed against
//! the original binary through the baseline harness, and what the replay
//! observed is filed as a baseline case under
//! `re/baseline/{binary}/{function}/baseline.json`. Authority rests on the
//! replay, not the capture — a refused entry names its reason and files a
//! `capture_refused` record; a replay that faults files a
//! `crash_reproduction` record naming the event and files no case. The
//! command prints the count report — events seen, cases mined, twins
//! deduplicated, refusals named, truncations stated — and lands the named
//! records in the binary's unknown ledger, the same merge doctrine batch
//! writes use. The next batch run closes the standing `export_uncovered`
//! record for any export the fold filed a suite for.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use calxgloss_testgen::{
    CaptureBudgets, PeImage, Replay, TestGenerator, WineRunner, derive_proxy_slots,
    file_capture_records, fold_capture_event_log,
};
use calxgloss_types::Export;
use tracing::info;

use crate::Settings;
use crate::utils::*;

/// How long an unbudgeted reference-app run may go: a run nobody gave a
/// duration budget to still cannot run on forever.
const DEFAULT_CAPTURE_DURATION_SECS: u64 = 300;

/// The operator's `--app` shape: the reference application to run, and
/// the run-dir and budget choices that shape the run.
pub struct CaptureRunOptions {
    /// The reference application, relative to the target directory unless
    /// absolute.
    pub app: PathBuf,
    /// The instrumented run dir; `None` asks for the workspace default.
    pub run_dir: Option<PathBuf>,
    /// Capture budgets, each optional; see `calxgloss_testgen::CaptureBudgets`.
    pub max_events: Option<u64>,
    pub max_duration_secs: Option<u64>,
    pub max_log_bytes: Option<u64>,
}

/// Handle the `capture` subcommand for `binary`: run the reference
/// application (`run`) or fold the already-taken event log (`ingest`),
/// then fold whatever event log stands — the run's or the ingested one —
/// through the record-and-replay lane against the target directory's
/// current bytes.
pub async fn handle_capture(
    binary: &str,
    ingest: Option<&Path>,
    run: Option<CaptureRunOptions>,
    workspace: &Path,
    settings: &Settings,
) -> Result<()> {
    if run.is_some() == ingest.is_some() {
        bail!(
            "`capture` takes exactly one source: --app <EXE> runs the reference-app capture, \
             --ingest <LOG> folds a capture event log without re-running anything"
        );
    }
    // The replay runs against the target directory's current bytes — the
    // same file the scan commands load.
    let target_dir = settings
        .target_dir
        .as_ref()
        .map(|r| PathBuf::from(&r.value))
        .unwrap_or_else(|| std::env::current_dir().expect("Failed to read current directory"));
    let dll_path = target_dir.join(binary);

    // The listing the fold checks each event against — and, in the run
    // shape, the table the recording proxy's slots are read from: every
    // named export of the current bytes, with the prototype line Kuna's
    // decompiler renders for it. An export whose prototype Kuna will not
    // render enters the listing with no signature — the fold then refuses
    // any event naming it with the `no-parseable-signature` reason, and
    // the proxy just forwards it, naming the gap instead of guessing.
    let source = load_kuna_at(settings, &dll_path)?;
    let mut exports: Vec<Export> = Vec::new();
    for symbol in source
        .list_exports()
        .await
        .context("The export listing never came back from Kuna")?
    {
        if symbol.imported || symbol.name.is_empty() {
            continue;
        }
        let signature = source
            .decompile_function(&symbol.name)
            .await
            .map(|decompiled| decompiled.signature)
            .unwrap_or_default();
        exports.push(Export {
            name: symbol.name,
            address: symbol.address,
            signature,
        });
    }
    info!(binary, exports = exports.len(), "Capture listing loaded");

    let log = match (ingest, run) {
        (Some(ingest), None) => std::fs::read_to_string(ingest)
            .with_context(|| format!("Failed to read the capture event log: {}", ingest.display()))?
            .parse()
            .with_context(|| {
                format!(
                    "The capture event log at {} is not valid JSON — expected a \
                         `capture-log-v1` document",
                    ingest.display()
                )
            })?,
        (None, Some(run)) => {
            let app_path = if run.app.is_absolute() {
                run.app
            } else {
                target_dir.join(&run.app)
            };
            let run_dir = run.run_dir.unwrap_or_else(|| {
                let stem = Path::new(binary).file_stem().unwrap_or(binary.as_ref());
                workspace.join("re/capture").join(stem)
            });
            let budgets = CaptureBudgets {
                max_events: run.max_events,
                max_duration_secs: Some(
                    run.max_duration_secs
                        .unwrap_or(DEFAULT_CAPTURE_DURATION_SECS),
                ),
                max_log_bytes: run.max_log_bytes,
            };
            // The proxy build's work area stays outside the run dir: the
            // run dir is the operator's tree under instrument, and it ends
            // the run holding only the module and the finished log.
            let runner = WineRunner::new(&workspace.join("re/capture/work").join(binary));
            let capture = runner
                .capture_reference_app_run(
                    &derive_proxy_slots(&exports, PeImage::parse(&dll_path)?.machine()),
                    &dll_path,
                    &app_path,
                    &run_dir,
                    &budgets,
                )
                .with_context(|| {
                    format!(
                        "Failed to run the reference application {} against {binary}",
                        app_path.display()
                    )
                })?;
            // The run states its own account before the fold speaks:
            // what was seen, what was dropped, what stopped the run, and
            // every truncation the budgets took.
            println!(
                "capture run: {} events seen, {} event(s) dropped",
                capture.events_seen, capture.events_dropped
            );
            match capture.stop {
                Some(stop) => println!("  stopped at its {stop}"),
                None => println!("  the reference application ran to completion"),
            }
            for note in &capture.notes {
                println!("  note: {note}");
            }
            println!("  event log: {}", capture.log_path.display());
            capture.log
        }
        (Some(_), Some(_)) | (None, None) => {
            unreachable!("exactly one source was checked above")
        }
    };

    let generator = TestGenerator::new(workspace);
    let folded = fold_capture_event_log(
        &generator,
        binary,
        &exports,
        &log,
        &Replay::Harness {
            dll_path: &dll_path,
        },
    )
    .await
    .with_context(|| format!("Failed to fold the capture event log for {binary}"))?;

    // The count report the issue asks the command to print, refusal by
    // refusal.
    print!("{}", folded.report);
    for (binary, function, rows) in &folded.filed {
        println!("  filed {binary}/{function}: {} baseline cases", rows.len());
    }

    let landed = file_capture_records(workspace, binary, &folded.unknown_records)
        .context("Failed to file the capture fold's unknown records")?;
    if landed > 0 {
        println!(
            "  unknowns: {landed} record{} landed in re/unknowns/{binary}.json",
            if landed == 1 { "" } else { "s" }
        );
    }
    Ok(())
}
