//! The `sync` command's CLI contribution — detect concurrency constructs
//! for a binary (issue #340, spec #337).
//!
//! The shape of this scan — how the evidence engine is built, how the
//! scan runs, how the result is persisted, and how degradation is
//! reported — lives in the pipeline's `concurrency` registry row. This
//! module contributes only what is genuinely specific to this evidence
//! engine: the cached-document loader and the report printer. The
//! generic handler ([`scan_command`](crate::commands::scan_command))
//! runs the whole command: a run always rebuilds the result instead of
//! reusing the cached document (the CLI's refresh-cache contract), and
//! `--show` prints a cached document instead. The result is filed where
//! the row files it — `re/analysis/sync/{binary}.json` — the same file
//! batch translation reads as prompt context. The run's report and a
//! later `--show` report read the same document the same way.

use std::path::Path;

use anyhow::{Context, Result};
use calxgloss_sync::persist::SyncPersistor;
use calxgloss_sync::types::SyncResult;
use calxgloss_translator::scan_registry::ScanRunOptions;
use chrono::DateTime;

use crate::commands::scan_command::{ScanContribution, ScanContributionSteps};
use crate::utils::*;

/// How many entries a detail section lists before collapsing the rest.
const DETAIL_LIMIT: usize = 10;

/// The `sync` entry in the CLI-side contribution table: it serves the
/// registry's `concurrency` row and supplies this command's loader and
/// printer. The command carries no flags beyond `--binary` and `--show`,
/// so its flag derivation hands over the plain default options — the
/// overwrite policy is the generic handler's to set.
pub(crate) fn contribution() -> ScanContribution {
    ScanContribution::new(ScanContributionSteps {
        row: "concurrency",
        load: load_filed_result,
        print: print_report,
        derive_options: |_flags| ScanRunOptions::default(),
        post_scan: None,
        show_loads_program: |_flags| false,
    })
}

/// Read the filed result through the evidence engine's own persistor —
/// the same loader for the `--show` report and for reading the document
/// a run just filed. When the document is missing, the error names the
/// exact command that produces one.
fn load_filed_result(workspace: &Path, binary: &str) -> Result<SyncResult> {
    SyncPersistor::new(workspace).load(binary).with_context(|| {
        format!(
            "No cached concurrency result for {binary}; \
                 run `calxgloss sync --binary {binary}` to produce one"
        )
    })
}

/// Print the report over the loaded result, naming where the document is
/// filed. Both paths read the same on-disk state, so for one document
/// the run's report and a later `--show` report come out byte-identical.
fn print_report(result: &SyncResult, workspace: &Path, binary: &str) -> Result<()> {
    print_concurrency_report(result, &SyncPersistor::new(workspace).path_for(binary));
    Ok(())
}

/// Print a summary of a concurrency result: where it is filed, when it
/// was built, and what the findings say.
fn print_concurrency_report(result: &SyncResult, path: &Path) {
    println!();
    hsep_bold();
    println_content(format!("  Concurrency — {}", result.metadata.binary));
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

    // Findings, broken down by the kind of each finding.
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

    // The scan's own admission, beside the counts it qualifies (issue
    // #349): the shared type's bounded line, framed under `Coverage:` and
    // printed only when there is something to admit. The line names only
    // bodies the scan never reached — a function without findings under a
    // complete record is examined and clean.
    print_coverage(result.metadata.coverage.as_ref());
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
            "  {} The scan found nothing — no lock pairings, atomic calls, thread spawns, or thread-local keys were found in the decompiled bodies.",
            yellow_bold("◉")
        );
    } else {
        println!(
            "  {} Concurrency detection ready — batch translation reads it as prompt context.",
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

/// The findings-per-kind counts the report prints beside the total.
/// The helper counts this result and lists every kind with at least
/// one finding, in report order. Kinds with no findings drop out.
/// This list must hold
/// the finding type's full kind set — a kind missing from it would
/// print nothing no matter how many findings of it the scan made. An
/// aggregated data race is one finding of the `data_race` kind, so
/// the line counts globals, not accessor pairs (issue #434).
fn kind_breakdown(result: &SyncResult) -> Vec<String> {
    [
        "mutex",
        "atomic",
        "thread",
        "tls",
        "async_runtime",
        "futex",
        "lock_order",
        "data_race",
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
    .collect()
}

/// The "…and N more" line a detail section ends with when it hides some
/// entries.
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
    use calxgloss_sync::types::{
        AsyncRuntime, AtomicOperation, ConcurrencyHint, Confidence, DataRace, Futex, LockOrder,
        RaceSide, ScanMetadata, SyncFinding, SyncType, ThreadSpawn, TlsUsage,
    };

    fn result_of(findings: Vec<SyncFinding>) -> SyncResult {
        SyncResult {
            metadata: ScanMetadata::new("eqmain.dll"),
            findings,
        }
    }

    fn one_of_every_kind() -> Vec<SyncFinding> {
        vec![
            SyncFinding::Mutex(ConcurrencyHint {
                function: "FUN_a".into(),
                sync_type: SyncType::StdMutex,
                acquire: "EnterCriticalSection".into(),
                release: "LeaveCriticalSection".into(),
                suggestion: "std::sync::Mutex<T>".into(),
                confidence: Confidence::new(70),
                evidence: "EnterCriticalSection(&l);".into(),
            }),
            SyncFinding::Atomic(AtomicOperation {
                function: "FUN_a".into(),
                operation: "InterlockedIncrement".into(),
                suggestion: "std::sync::atomic::AtomicU32".into(),
                confidence: Confidence::new(70),
                evidence: "InterlockedIncrement(&l);".into(),
            }),
            SyncFinding::Thread(ThreadSpawn {
                function: "FUN_a".into(),
                spawn: "CreateThread".into(),
                join: None,
                suggestion: "std::thread::spawn".into(),
                confidence: Confidence::new(70),
                evidence: "CreateThread(...);".into(),
            }),
            SyncFinding::Tls(TlsUsage {
                function: "FUN_a".into(),
                creation: Some("TlsAlloc".into()),
                access: "TlsGetValue".into(),
                suggestion: "thread_local!".into(),
                confidence: Confidence::new(70),
                evidence: "local_4 = TlsAlloc();".into(),
            }),
            SyncFinding::AsyncRuntime(AsyncRuntime {
                function: "FUN_a".into(),
                operation: "GetQueuedCompletionStatus".into(),
                suggestion: "tokio".into(),
                confidence: Confidence::new(60),
                evidence: "GetQueuedCompletionStatus(...);".into(),
            }),
            SyncFinding::Futex(Futex {
                function: "FUN_a".into(),
                operation: "FUTEX_WAIT".into(),
                suggestion: "std::sync::Mutex/Condvar".into(),
                confidence: Confidence::new(60),
                evidence: "syscall(61, ...);".into(),
            }),
            SyncFinding::LockOrder(LockOrder {
                function: "FUN_a".into(),
                partner: "FUN_b".into(),
                first_lock: "local_20".into(),
                second_lock: "local_40".into(),
                suggestion: "pick one consistent lock acquisition order".into(),
                confidence: Confidence::new(70),
                evidence: "FUN_a: local_20 -> local_40; FUN_b: local_40 -> local_20".into(),
            }),
            SyncFinding::DataRace(DataRace {
                variable: "DAT_counter".into(),
                readers: vec!["FUN_b".into(), "FUN_c".into()],
                writers: vec!["FUN_a".into()],
                unguarded_reads: 2,
                unguarded_writes: 1,
                sides: vec![
                    RaceSide {
                        function: "FUN_a".into(),
                        statement: "DAT_counter = 1".into(),
                    },
                    RaceSide {
                        function: "FUN_b".into(),
                        statement: "uVar1 = DAT_counter".into(),
                    },
                    RaceSide {
                        function: "FUN_c".into(),
                        statement: "uVar2 = DAT_counter".into(),
                    },
                ],
                suggestion: "guard the shared global with one lock held by both functions".into(),
                confidence: Confidence::new(60),
                evidence: "FUN_a: DAT_counter = 1; FUN_b: uVar1 = DAT_counter;".into(),
            }),
        ]
    }

    #[test]
    fn the_report_breakdown_names_every_kind_the_union_can_carry() {
        // The breakdown line is the report's kind index: every kind
        // tag the finding union carries must show up with its count,
        // or a scan full of that kind prints as though it found
        // nothing of it.
        let result = result_of(one_of_every_kind());
        let breakdown = kind_breakdown(&result);
        assert_eq!(
            breakdown,
            vec![
                "mutex 1",
                "atomic 1",
                "thread 1",
                "tls 1",
                "async_runtime 1",
                "futex 1",
                "lock_order 1",
                "data_race 1",
            ],
            "every kind the union carries is named"
        );
        assert_eq!(
            breakdown.len(),
            result.findings.len(),
            "every finding is counted — a union variant missing from the breakdown list fails here"
        );
    }

    #[test]
    fn the_breakdown_counts_an_aggregated_race_as_one_data_race_whatever_its_accessor_count() {
        // A rescan of the case that used to print `data_race 3` — the
        // same global claimed once per function pair — now prints one
        // count, because the finding is per global (issue #434).
        let mut findings = one_of_every_kind();
        findings.retain(|finding| finding.kind() == "data_race");
        findings.push(SyncFinding::DataRace(DataRace {
            variable: "DAT_flag".into(),
            readers: vec!["FUN_d".into()],
            writers: vec!["FUN_e".into()],
            unguarded_reads: 1,
            unguarded_writes: 1,
            sides: vec![
                RaceSide {
                    function: "FUN_e".into(),
                    statement: "DAT_flag = 2".into(),
                },
                RaceSide {
                    function: "FUN_d".into(),
                    statement: "uVar3 = DAT_flag".into(),
                },
            ],
            suggestion: "guard the shared global with one lock held by both functions".into(),
            confidence: Confidence::new(60),
            evidence: "FUN_e: DAT_flag = 2; FUN_d: uVar3 = DAT_flag;".into(),
        }));
        assert_eq!(kind_breakdown(&result_of(findings)), vec!["data_race 2"]);
    }
}
