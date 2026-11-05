//! The primary P24.6 suite: the five-dimension comparator pinned as pure
//! record logic — two hand-built *scenario captures* plus one *scenario
//! contract* in, one digest-bearing *scenario verdict* out. Nothing here
//! launches a process or needs a Wine toolchain: these tests run on every
//! machine, and that is itself the pin that the comparator launches
//! nothing.

use calxgloss_types::{
    BinaryIdentity, CapturePairing, DimensionDivergence, DimensionVerdict, ExitDisposition,
    ExitObservation, FileChange, FileObservation, FilesystemObservation, FinalizationOutcome,
    InteractionObservation, LiteralReplacement, NormalizationRules, ProcessObservation,
    ProcessSample, ScenarioCapture, ScenarioContract, ScenarioVerdictDocument, TerminalGeometry,
    TerminalObservation,
};

use super::compare_captures;

fn contract(name: &str) -> ScenarioContract {
    ScenarioContract {
        name: name.into(),
        working_dir: ".".into(),
        env: Default::default(),
        argv: vec![],
        interactions: vec![],
        cols: 80,
        rows: 24,
        observation_paths: vec!["new.dat".into(), "old.dat".into()],
        idle_timeout_ms: 5_000,
        max_run_ms: 30_000,
        finalization_grace_ms: 5_000,
        max_output_bytes: 1_048_576,
        normalization: NormalizationRules {
            version: "norm-v1".into(),
            literal_replacements: vec![],
            port_patterns: vec![],
        },
    }
}

/// One capture that observed everything: all five dimension blocks stand
/// and filled, with its pairing stamped under norm-v1. `program` stands in
/// for the bytes that ran, so the two sides can differ where a real
/// original-vs-restitch pair would.
fn full_capture(scenario: &str, program: &str) -> ScenarioCapture {
    ScenarioCapture {
        scenario: scenario.into(),
        filed_at: 1,
        pairing: Some(CapturePairing {
            program_sha256: format!("sha256:{program}"),
            wine_version: "wine-9.0".into(),
            normalization_version: "norm-v1".into(),
        }),
        terminal: Some(TerminalObservation {
            chunks: vec!["hello-scene".into(), "goodbye".into()],
            output_capped: false,
            cap_bytes: None,
            geometry: Some(TerminalGeometry { cols: 80, rows: 24 }),
            rendered_states: vec![],
        }),
        interaction: Some(InteractionObservation {
            acknowledged_at_ms: vec![1_000, 2_000],
        }),
        exit: Some(ExitObservation {
            disposition: ExitDisposition::Exited,
            exit_code: Some(7),
            finalization: None,
        }),
        filesystem: Some(FilesystemObservation {
            entries: vec![
                FileObservation {
                    path: "new.dat".into(),
                    change: FileChange::Created,
                    size_bytes: Some(12),
                    sha256: Some("sha256-new".into()),
                    block_hashes: vec!["sha256-new".into()],
                },
                FileObservation {
                    path: "old.dat".into(),
                    change: FileChange::Deleted,
                    size_bytes: Some(9),
                    sha256: Some("sha256-old".into()),
                    block_hashes: vec!["sha256-old".into()],
                },
            ],
        }),
        process: Some(ProcessObservation {
            samples: vec![
                ProcessSample {
                    pid: 100,
                    name: "fixture_console.exe".into(),
                },
                ProcessSample {
                    pid: 110,
                    name: "child_helper.exe".into(),
                },
            ],
        }),
    }
}

fn compare_pair(
    contract: &ScenarioContract,
    left: &ScenarioCapture,
    right: &ScenarioCapture,
) -> ScenarioVerdictDocument {
    compare_captures(
        &BinaryIdentity::new("fixture_console.exe"),
        contract,
        left,
        right,
        42,
    )
    .expect("the pair compares")
}

#[test]
fn captures_normalized_under_different_versions_refuse_to_pair_and_are_named() {
    // Two captures, each stamped under its own normalization version: the
    // comparison refuses outright and names both versions — the pair is
    // never silently equalized across versions.
    let c = contract("boot-and-exit");
    let mut left = full_capture("boot-and-exit", "a");
    let mut right = full_capture("boot-and-exit", "b");
    left.pairing
        .as_mut()
        .expect("stamped")
        .normalization_version = "norm-v1".into();
    right
        .pairing
        .as_mut()
        .expect("stamped")
        .normalization_version = "norm-v2".into();
    let error = compare_captures(
        &BinaryIdentity::new("fixture_console.exe"),
        &c,
        &left,
        &right,
        42,
    )
    .expect_err("a cross-version pair is refused");
    let message = error.to_string();
    assert!(
        message.contains("norm-v1") && message.contains("norm-v2"),
        "both versions are named: {message}"
    );
}

#[test]
fn an_unstamped_capture_refuses_the_pair_naming_the_side_that_cannot_prove_its_version() {
    // A capture filed before version stamps existed proves nothing — the
    // refusal names the side that cannot prove its normalization version.
    let c = contract("boot-and-exit");
    let left = full_capture("boot-and-exit", "a");
    let mut right = full_capture("boot-and-exit", "b");
    right
        .pairing
        .as_mut()
        .expect("stamped")
        .normalization_version = String::new();
    let error = compare_captures(
        &BinaryIdentity::new("fixture_console.exe"),
        &c,
        &left,
        &right,
        42,
    )
    .expect_err("an unstamped side is refused");
    let message = error.to_string();
    assert!(
        message.contains("right"),
        "the unstamped side is named: {message}"
    );
    assert!(
        message.contains("not proven"),
        "the refusal says what is missing: {message}"
    );
}

#[test]
fn captures_of_different_scenarios_never_pair_and_all_three_names_are_stated() {
    // The pair and the contract must speak the same scenario; the refusal
    // states the contract's name and both captures' names.
    let c = contract("boot-and-exit");
    let left = full_capture("boot-and-exit", "a");
    let right = full_capture("other-flow", "b");
    let error = compare_captures(
        &BinaryIdentity::new("fixture_console.exe"),
        &c,
        &left,
        &right,
        42,
    )
    .expect_err("a cross-scenario pair is refused");
    let message = error.to_string();
    for name in ["boot-and-exit", "other-flow"] {
        assert!(
            message.contains(name),
            "the refusal names {name}: {message}"
        );
    }
}

#[test]
fn different_wine_versions_pair_and_compare_but_state_the_environment_difference() {
    // A wine move is an environment change, not a pairing refusal: the
    // dimensions still say what they saw, but the verdict names both
    // versions as a residual unknown and a clean reading claims nothing.
    let c = contract("boot-and-exit");
    let left = full_capture("boot-and-exit", "a");
    let mut right = full_capture("boot-and-exit", "b");
    right
        .pairing
        .as_mut()
        .expect("the pairing stands")
        .wine_version = "wine-10.0".into();
    let document = compare_pair(&c, &left, &right);

    assert_eq!(document.verdict.terminal, DimensionVerdict::AssessedPass);
    assert!(document.divergences.is_empty(), "the pair still compares");
    let stated = document
        .residual_unknowns
        .iter()
        .find(|unknown| unknown.contains("wine-9.0") && unknown.contains("wine-10.0"));
    assert!(
        stated.is_some(),
        "the wine mismatch must name both versions: {:?}",
        document.residual_unknowns
    );
    assert!(
        !document.claims_complete_equivalence,
        "a wine mismatch blocks the complete-equivalence claim: {document:?}"
    );
}

#[test]
fn a_contract_redeclared_under_newer_rules_refuses_captures_stamped_under_the_old_ones() {
    // The version in force is only in force if it was in force when the
    // captures ran: a pair stamped norm-v1 cannot be judged by a contract
    // since re-declared under norm-v2, and the refusal names both.
    let mut c = contract("boot-and-exit");
    c.normalization.version = "norm-v2".into();
    let left = full_capture("boot-and-exit", "a");
    let right = full_capture("boot-and-exit", "b");
    let error = compare_captures(
        &BinaryIdentity::new("fixture_console.exe"),
        &c,
        &left,
        &right,
        42,
    )
    .expect_err("a contract past its pair's version is refused");
    let message = error.to_string();
    for version in ["norm-v1", "norm-v2"] {
        assert!(
            message.contains(version),
            "the refusal names the version {version}: {message}"
        );
    }
}

#[test]
fn declared_literal_replacements_equalize_flaky_output_and_the_terminal_still_passes() {
    // The only equalization that ever happens is the contract's declared
    // one: two segments whose flaky spans both fold to the same
    // placeholder read equal — and the verdict says which version judged.
    let mut c = contract("boot-and-exit");
    c.normalization.literal_replacements = vec![
        LiteralReplacement {
            from: "0x7faaa".into(),
            to: "<address>".into(),
        },
        LiteralReplacement {
            from: "0x7fbbb".into(),
            to: "<address>".into(),
        },
    ];
    let mut left = full_capture("boot-and-exit", "a");
    let mut right = full_capture("boot-and-exit", "b");
    left.terminal.as_mut().expect("the block stands").chunks[0] = "loaded at 0x7faaa".into();
    right.terminal.as_mut().expect("the block stands").chunks[0] = "loaded at 0x7fbbb".into();
    let document = compare_pair(&c, &left, &right);

    assert_eq!(document.verdict.terminal, DimensionVerdict::AssessedPass);
    assert_eq!(
        document.normalization_version, "norm-v1",
        "the version in force is stated"
    );
}

#[test]
fn port_patterns_are_masked_out_of_comparison_as_declared() {
    // The contract declares the port pattern; the comparison masks it —
    // never anything else. Undeclared differences still fail.
    let mut c = contract("boot-and-exit");
    c.normalization.port_patterns = vec![":\\d{4,5}".into()];
    let mut left = full_capture("boot-and-exit", "a");
    let mut right = full_capture("boot-and-exit", "b");
    left.terminal.as_mut().expect("the block stands").chunks[1] = "listening on :1234".into();
    right.terminal.as_mut().expect("the block stands").chunks[1] = "listening on :9090".into();
    let document = compare_pair(&c, &left, &right);

    assert_eq!(
        document.verdict.terminal,
        DimensionVerdict::AssessedPass,
        "the declared pattern masks both sides' port spans"
    );
}

#[test]
fn a_difference_the_contract_declared_no_rule_for_still_fails_named() {
    // Normalization is never silent and never improvised: with no declared
    // rule touching it, the raw difference stands and fails the dimension.
    let c = contract("boot-and-exit");
    let mut left = full_capture("boot-and-exit", "a");
    let mut right = full_capture("boot-and-exit", "b");
    left.terminal.as_mut().expect("the block stands").chunks[1] = "listening on :1234".into();
    right.terminal.as_mut().expect("the block stands").chunks[1] = "listening on :9090".into();
    let document = compare_pair(&c, &left, &right);

    assert_eq!(document.verdict.terminal, DimensionVerdict::AssessedFail);
}

#[test]
fn a_terminal_segment_that_diverges_is_named_by_index_with_both_sides_beside_it() {
    // The reviewer never hand-diffs two raw captures: the failing terminal
    // dimension names the segment index and prints both sides beside it.
    let c = contract("boot-and-exit");
    let mut left = full_capture("boot-and-exit", "a");
    let mut right = full_capture("boot-and-exit", "b");
    left.terminal.as_mut().expect("the block stands").chunks[1] =
        "goodbye from the original".into();
    right.terminal.as_mut().expect("the block stands").chunks[1] =
        "goodbye from the restitch".into();
    let document = compare_pair(&c, &left, &right);

    assert_eq!(document.verdict.terminal, DimensionVerdict::AssessedFail);
    assert_eq!(
        document.divergences,
        vec![DimensionDivergence::TerminalSegment {
            index: 1,
            left: Some("goodbye from the original".into()),
            right: Some("goodbye from the restitch".into()),
        }],
        "the segment index and both normalized sides ride the divergence"
    );
}

#[test]
fn one_sides_extra_terminal_segment_is_named_with_the_other_side_standing_empty() {
    // A restitch that prints one segment more fails the dimension, and the
    // divergence names the index with the side that never printed it absent.
    let c = contract("boot-and-exit");
    let left = full_capture("boot-and-exit", "a");
    let mut right = full_capture("boot-and-exit", "b");
    right
        .terminal
        .as_mut()
        .expect("the block stands")
        .chunks
        .push("an extra trailing line".into());
    let document = compare_pair(&c, &left, &right);

    assert_eq!(document.verdict.terminal, DimensionVerdict::AssessedFail);
    assert_eq!(
        document.divergences,
        vec![DimensionDivergence::TerminalSegment {
            index: 2,
            left: None,
            right: Some("an extra trailing line".into()),
        }]
    );
}

#[test]
fn an_interaction_one_run_acknowledged_and_the_other_never_did_is_named_by_offset() {
    // "Which interaction" answered directly: the at-offset, and which of
    // the two runs acknowledged it.
    let c = contract("boot-and-exit");
    let left = full_capture("boot-and-exit", "a");
    let mut right = full_capture("boot-and-exit", "b");
    right
        .interaction
        .as_mut()
        .expect("the block stands")
        .acknowledged_at_ms = vec![1_000, 3_000];
    let document = compare_pair(&c, &left, &right);

    assert_eq!(document.verdict.interaction, DimensionVerdict::AssessedFail);
    assert_eq!(
        document.divergences,
        vec![
            DimensionDivergence::InteractionAcknowledgement {
                at_ms: 2_000,
                left: true,
                right: false,
            },
            DimensionDivergence::InteractionAcknowledgement {
                at_ms: 3_000,
                left: false,
                right: true,
            },
        ],
        "each offset stands with its acknowledgement state on both sides"
    );
}

#[test]
fn a_different_exit_is_named_in_disposition_and_code_and_finalization_with_both_sides_beside_them()
{
    // The exit dimension names all three of its fields when they diverge:
    // the dispositions, the codes (a silent side stands None), and the
    // finalization outcome — including one run having been finalized at
    // all while the other never was.
    let c = contract("boot-and-exit");
    let left = full_capture("boot-and-exit", "a");
    let mut right = full_capture("boot-and-exit", "b");
    right.exit = Some(ExitObservation {
        disposition: ExitDisposition::Timeout,
        exit_code: None,
        finalization: Some(FinalizationOutcome::Signaled),
    });
    let document = compare_pair(&c, &left, &right);

    assert_eq!(document.verdict.exit, DimensionVerdict::AssessedFail);
    assert_eq!(
        document.divergences,
        vec![
            DimensionDivergence::ExitDisposition {
                left: ExitDisposition::Exited,
                right: ExitDisposition::Timeout,
            },
            DimensionDivergence::ExitCode {
                left: Some(7),
                right: None,
            },
            DimensionDivergence::ExitFinalization {
                left: None,
                right: Some(FinalizationOutcome::Signaled),
            },
        ],
        "every exit field that disagrees stands with both sides beside it"
    );
}

#[test]
fn a_file_that_changed_differently_fails_named_by_path_with_both_entries_beside_them() {
    // "Which file, created/deleted/modified, by digest" answered in one
    // divergence: the path, and each side's whole entry — change kind,
    // size, digest, and block digests all beside the reader.
    let c = contract("boot-and-exit");
    let left = full_capture("boot-and-exit", "a");
    let mut right = full_capture("boot-and-exit", "b");
    right.filesystem.as_mut().expect("the block stands").entries[0] = FileObservation {
        path: "new.dat".into(),
        change: FileChange::Modified,
        size_bytes: Some(20),
        sha256: Some("sha256-restitched".into()),
        block_hashes: vec!["sha256-restitched".into()],
    };
    let document = compare_pair(&c, &left, &right);

    assert_eq!(document.verdict.filesystem, DimensionVerdict::AssessedFail);
    assert_eq!(
        document.divergences,
        vec![DimensionDivergence::FileSystemPath {
            path: "new.dat".into(),
            left: Some(FileObservation {
                path: "new.dat".into(),
                change: FileChange::Created,
                size_bytes: Some(12),
                sha256: Some("sha256-new".into()),
                block_hashes: vec!["sha256-new".into()],
            }),
            right: Some(FileObservation {
                path: "new.dat".into(),
                change: FileChange::Modified,
                size_bytes: Some(20),
                sha256: Some("sha256-restitched".into()),
                block_hashes: vec!["sha256-restitched".into()],
            }),
        }],
        "the unchanged old.dat stands unmentioned — only the disagreeing path is named"
    );
}

#[test]
fn an_observation_path_one_side_recorded_and_the_other_never_did_is_named_absent() {
    // One capture classified a path the other never carried an entry for:
    // the divergence names the path with the silent side absent.
    let c = contract("boot-and-exit");
    let left = full_capture("boot-and-exit", "a");
    let mut right = full_capture("boot-and-exit", "b");
    right
        .filesystem
        .as_mut()
        .expect("the block stands")
        .entries
        .retain(|e| e.path != "old.dat");
    let document = compare_pair(&c, &left, &right);

    assert_eq!(document.verdict.filesystem, DimensionVerdict::AssessedFail);
    assert_eq!(
        document.divergences,
        vec![DimensionDivergence::FileSystemPath {
            path: "old.dat".into(),
            left: Some(FileObservation {
                path: "old.dat".into(),
                change: FileChange::Deleted,
                size_bytes: Some(9),
                sha256: Some("sha256-old".into()),
                block_hashes: vec!["sha256-old".into()],
            }),
            right: None,
        }]
    );
}

#[test]
fn a_process_tree_row_one_run_sighted_and_the_other_never_did_is_named_by_row() {
    // The restitch that spawns a child the original never had (or loses
    // one) fails the process dimension, naming the row each side stands
    // or absently stands beside.
    let c = contract("boot-and-exit");
    let left = full_capture("boot-and-exit", "a");
    let mut right = full_capture("boot-and-exit", "b");
    right.process.as_mut().expect("the block stands").samples = vec![ProcessSample {
        pid: 200,
        name: "fixture_console.exe".into(),
    }];
    let document = compare_pair(&c, &left, &right);

    assert_eq!(document.verdict.process, DimensionVerdict::AssessedFail);
    assert_eq!(
        document.divergences,
        vec![DimensionDivergence::ProcessTreeRow {
            left: Some(ProcessSample {
                pid: 110,
                name: "child_helper.exe".into(),
            }),
            right: None,
        }],
        "the shared fixture_console.exe row is not a divergence — pid churn is not behavior"
    );
}

#[test]
fn different_pids_for_the_same_program_names_are_not_a_divergence() {
    // Pids are run accidents; the process dimension weighs the tree by
    // program names. Same names, different pids: assessed pass.
    let c = contract("boot-and-exit");
    let left = full_capture("boot-and-exit", "a");
    let mut right = full_capture("boot-and-exit", "b");
    right.process.as_mut().expect("the block stands").samples = vec![
        ProcessSample {
            pid: 200,
            name: "fixture_console.exe".into(),
        },
        ProcessSample {
            pid: 210,
            name: "child_helper.exe".into(),
        },
    ];
    let document = compare_pair(&c, &left, &right);

    assert_eq!(document.verdict.process, DimensionVerdict::AssessedPass);
    assert!(
        document.divergences.is_empty(),
        "pid churn alone names nothing: {:?}",
        document.divergences
    );
}

#[test]
fn a_mismatched_opening_geometry_fails_the_terminal_naming_both_sides_geometry() {
    // The terminal dimension has content, not just bytes: a restitch that
    // could not open the declared geometry fails, with both measured
    // geometries beside the reader.
    let c = contract("boot-and-exit");
    let left = full_capture("boot-and-exit", "a");
    let mut right = full_capture("boot-and-exit", "b");
    right.terminal.as_mut().expect("the block stands").geometry = Some(TerminalGeometry {
        cols: 100,
        rows: 30,
    });
    let document = compare_pair(&c, &left, &right);

    assert_eq!(document.verdict.terminal, DimensionVerdict::AssessedFail);
    assert_eq!(
        document.divergences,
        vec![DimensionDivergence::TerminalGeometry {
            left: Some(TerminalGeometry { cols: 80, rows: 24 }),
            right: Some(TerminalGeometry {
                cols: 100,
                rows: 30
            }),
        }]
    );
}

#[test]
fn a_geometry_one_side_never_measured_stands_absent_beside_the_side_that_did() {
    // One run read its geometry off the live terminal and the other never
    // got the reading — the divergence states the absence, never defaults.
    let c = contract("boot-and-exit");
    let mut left = full_capture("boot-and-exit", "a");
    left.terminal.as_mut().expect("the block stands").geometry = None;
    let right = full_capture("boot-and-exit", "b");
    let document = compare_pair(&c, &left, &right);

    assert_eq!(document.verdict.terminal, DimensionVerdict::AssessedFail);
    assert_eq!(
        document.divergences,
        vec![DimensionDivergence::TerminalGeometry {
            left: None,
            right: Some(TerminalGeometry { cols: 80, rows: 24 }),
        }]
    );
}

#[test]
fn disagreeing_rendered_states_are_named_with_both_lists_beside_each_other() {
    // A resize that landed on one rendering and not the other is visible
    // right here: the rendered states, both sides, in order.
    let c = contract("boot-and-exit");
    let mut left = full_capture("boot-and-exit", "a");
    left.terminal
        .as_mut()
        .expect("the block stands")
        .rendered_states = vec![TerminalGeometry {
        cols: 100,
        rows: 30,
    }];
    let right = full_capture("boot-and-exit", "b");
    let document = compare_pair(&c, &left, &right);

    assert_eq!(document.verdict.terminal, DimensionVerdict::AssessedFail);
    assert_eq!(
        document.divergences,
        vec![DimensionDivergence::TerminalRenderedStates {
            left: vec![TerminalGeometry {
                cols: 100,
                rows: 30
            }],
            right: vec![],
        }]
    );
}

#[test]
fn a_capped_side_blocks_the_equivalence_claim_and_states_its_cap_instead_of_failing_by_silence() {
    // The cap's truncation mark blocks a complete-equivalence claim — it
    // never fails the dimension by itself and is never silent: the verdict
    // names which side capped at how many bytes.
    let c = contract("boot-and-exit");
    let mut left = full_capture("boot-and-exit", "a");
    left.terminal
        .as_mut()
        .expect("the block stands")
        .output_capped = true;
    left.terminal.as_mut().expect("the block stands").cap_bytes = Some(1_048_576);
    let right = full_capture("boot-and-exit", "b");
    let document = compare_pair(&c, &left, &right);

    assert_eq!(
        document.verdict.terminal,
        DimensionVerdict::AssessedPass,
        "the truncation mark is not a divergence — what both sides recorded still agrees"
    );
    let stated = document.residual_unknowns.join(" | ");
    assert!(
        stated.contains("left"),
        "the capped side is named: {stated}"
    );
    assert!(
        stated.contains("1048576"),
        "the cap it stopped at is named: {stated}"
    );
    assert!(
        !document.claims_complete_equivalence,
        "a truncated capture never claims complete equivalence"
    );
}

#[test]
fn a_port_pattern_that_does_not_compile_is_refused_naming_the_pattern() {
    // A declared rule that cannot be applied is refused by name — never
    // quietly dropped, which would change the comparison silently.
    let mut c = contract("boot-and-exit");
    c.normalization.port_patterns = vec!["[unclosed".into()];
    let error = compare_captures(
        &BinaryIdentity::new("fixture_console.exe"),
        &c,
        &full_capture("boot-and-exit", "a"),
        &full_capture("boot-and-exit", "b"),
        42,
    )
    .expect_err("a declared rule that cannot apply is refused");
    assert!(
        error.to_string().contains("[unclosed"),
        "the refusal names the declared pattern: {error}"
    );
}

#[test]
fn a_dimension_left_blank_on_either_side_reads_unassessed_not_pass_and_not_fail() {
    // The honesty rule at the heart of the lane: a dimension one side
    // never spoke for reads *unassessed* — silence is never a pass, and
    // it never fails by silence either. An absent block and an empty one
    // read the same.
    let c = contract("boot-and-exit");
    let mut left = full_capture("boot-and-exit", "a");
    let mut right = full_capture("boot-and-exit", "b");
    left.terminal = None;
    right.interaction = Some(InteractionObservation {
        acknowledged_at_ms: vec![],
    });
    let document = compare_pair(&c, &left, &right);

    assert_eq!(
        document.verdict.terminal,
        DimensionVerdict::Unassessed,
        "the side that never observed the terminal cannot make it pass or fail"
    );
    assert_eq!(
        document.verdict.interaction,
        DimensionVerdict::Unassessed,
        "an empty block reads exactly as an absent one"
    );
    // The dimensions both sides spoke for still assess normally.
    assert_eq!(document.verdict.exit, DimensionVerdict::AssessedPass);
    assert_eq!(document.verdict.filesystem, DimensionVerdict::AssessedPass);
    assert_eq!(document.verdict.process, DimensionVerdict::AssessedPass);
}

#[test]
fn a_thin_pair_reads_every_dimension_unassessed_and_claims_nothing() {
    // Two captures that say nothing about any dimension: the verdict
    // states five unassessed readings, files no divergences, and makes no
    // equivalence claim — but never a failure out of pure silence.
    let c = contract("bare");
    let left: ScenarioCapture = serde_json::from_str(
        r#"{"scenario": "bare", "filed_at": 1,
            "pairing": {"program_sha256": "sha256:one", "wine_version": "wine-9.0",
                        "normalization_version": "norm-v1"}}"#,
    )
    .expect("a thin capture parses");
    let right: ScenarioCapture = serde_json::from_str(
        r#"{"scenario": "bare", "filed_at": 2,
            "pairing": {"program_sha256": "sha256:two", "wine_version": "wine-9.0",
                        "normalization_version": "norm-v1"}}"#,
    )
    .expect("a second thin capture parses");
    let document = compare_pair(&c, &left, &right);

    assert_eq!(
        document.verdict,
        calxgloss_types::ScenarioVerdict::default()
    );
    assert!(document.divergences.is_empty());
    assert!(
        !document.claims_complete_equivalence,
        "an unassessed pair claims no equivalence"
    );
    assert!(
        document.residual_unknowns.is_empty(),
        "nothing was weighed, so no filesystem unknown is stated — the unassessed \
         dimensions themselves are what the reader reads: {:?}",
        document.residual_unknowns
    );
}

#[test]
fn a_pair_that_agrees_on_every_dimension_reads_assessed_pass_on_all_five() {
    // The one high seam's external behavior, best case: two captures plus
    // the contract in, five assessed-pass dimension verdicts out.
    let c = contract("boot-and-exit");
    let left = full_capture("boot-and-exit", "bytes-original");
    let right = full_capture("boot-and-exit", "bytes-restitched");
    let document = compare_pair(&c, &left, &right);

    assert_eq!(document.binary, BinaryIdentity::new("fixture_console.exe"));
    assert_eq!(document.scenario, "boot-and-exit");
    assert_eq!(
        document.filed_at, 42,
        "the filing clock rides in from the caller"
    );
    assert_eq!(document.verdict.terminal, DimensionVerdict::AssessedPass);
    assert_eq!(document.verdict.interaction, DimensionVerdict::AssessedPass);
    assert_eq!(document.verdict.exit, DimensionVerdict::AssessedPass);
    assert_eq!(document.verdict.filesystem, DimensionVerdict::AssessedPass);
    assert_eq!(document.verdict.process, DimensionVerdict::AssessedPass);
    assert!(
        document.divergences.is_empty(),
        "a passing pair names nothing: {:?}",
        document.divergences
    );
}

#[test]
fn the_verdict_document_carries_its_digest_and_the_captures_it_judged() {
    // The document is digest-bearing in its own right: the digest re-derives
    // from the filed content, and each capture it judged is cited by digest.
    let c = contract("boot-and-exit");
    let left = full_capture("boot-and-exit", "bytes-original");
    let right = full_capture("boot-and-exit", "bytes-restitched");
    let document = compare_pair(&c, &left, &right);

    assert!(
        document.digest.starts_with("sha256:"),
        "the digest names its algorithm"
    );
    assert_eq!(
        document.content_digest().expect("the document serializes"),
        document.digest,
        "the digest reads back from the document alone"
    );
    assert_ne!(
        document.left_capture_sha256, document.right_capture_sha256,
        "different captures are cited by different digests"
    );
    assert!(
        document.left_capture_sha256.starts_with("sha256:")
            && document.right_capture_sha256.starts_with("sha256:"),
        "the capture citations name their algorithm too"
    );
    // What paired against what stays visible: both pairing blocks ride in.
    let left_pairing = document
        .left_pairing
        .as_ref()
        .expect("the left pairing rides in");
    assert_eq!(left_pairing.program_sha256, "sha256:bytes-original");
    let right_pairing = document
        .right_pairing
        .as_ref()
        .expect("the right pairing rides in");
    assert_eq!(right_pairing.program_sha256, "sha256:bytes-restitched");
}

#[test]
fn the_normalization_version_in_force_is_stated_in_the_verdict() {
    // Normalization is never silent: the verdict names the version it
    // judged the pair under.
    let c = contract("boot-and-exit");
    let document = compare_pair(
        &c,
        &full_capture("boot-and-exit", "a"),
        &full_capture("boot-and-exit", "b"),
    );
    assert_eq!(document.normalization_version, "norm-v1");
}

#[test]
fn a_bounded_pair_never_claims_complete_equivalence_the_filesystem_unknowns_stay_stated() {
    // The honesty rule over the best pair: observation-path files are
    // weighed, everything outside them is stated unknown — and a
    // complete-equivalence claim is blocked, never silently made.
    let c = contract("boot-and-exit");
    let document = compare_pair(
        &c,
        &full_capture("boot-and-exit", "a"),
        &full_capture("boot-and-exit", "b"),
    );

    assert!(
        !document.claims_complete_equivalence,
        "a bounded capture never silently claims complete equivalence"
    );
    let stated = document.residual_unknowns.join(" | ");
    assert!(
        stated.contains("new.dat") && stated.contains("old.dat"),
        "the unknown is specific about the observation paths it covers: {stated}"
    );
}
