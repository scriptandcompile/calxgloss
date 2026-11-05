//! Pure record tests for the scenario records (P24.1, issue #402).
//!
//! The honesty rule these pin: silence is readable, never a pass. A filed
//! verdict document that says nothing about a dimension reads *unassessed* —
//! never assessed pass, never assessed fail — and a capture block that is
//! absent reads the same way at compare time.

use super::*;

#[test]
fn comparison_verdicts_land_at_their_named_record_tree_location() {
    // Verdicts live in their own directory beside the captures, one
    // document per (binary, scenario name) like the capture keying — a
    // later reader (P25's receipts, P26's ledger) finds the current
    // verdict at this documented location and cites it by its digest.
    let path = scenario_verdict_path("/ws", &BinaryIdentity::new("eqgame.exe"), "boot-and-exit");
    assert_eq!(
        path,
        Path::new("/ws")
            .join("re")
            .join("scenarios")
            .join("verdicts")
            .join("eqgame.exe-boot-and-exit.json"),
        "the record tree names the verdicts directory beside the captures"
    );
    assert_eq!(
        scenario_verdicts_dir("/ws"),
        scenario_captures_dir("/ws")
            .parent()
            .expect("the captures dir has a parent")
            .join("verdicts"),
        "the verdicts directory stands inside the scenario directory, beside the captures"
    );
}

#[test]
fn an_empty_verdict_document_reads_every_dimension_unassessed() {
    let verdict: ScenarioVerdict = serde_json::from_str("{}").expect("an empty verdict parses");
    assert_eq!(verdict.terminal, DimensionVerdict::Unassessed);
    assert_eq!(verdict.interaction, DimensionVerdict::Unassessed);
    assert_eq!(verdict.exit, DimensionVerdict::Unassessed);
    assert_eq!(verdict.filesystem, DimensionVerdict::Unassessed);
    assert_eq!(verdict.process, DimensionVerdict::Unassessed);
}

#[test]
fn a_named_dimension_verdict_deserializes_and_the_rest_stay_unassessed() {
    let verdict: ScenarioVerdict =
        serde_json::from_str(r#"{"exit": "assessed_pass", "filesystem": "assessed_fail"}"#)
            .expect("a partial verdict parses");
    assert_eq!(verdict.exit, DimensionVerdict::AssessedPass);
    assert_eq!(verdict.filesystem, DimensionVerdict::AssessedFail);
    assert_eq!(verdict.terminal, DimensionVerdict::Unassessed);
    assert_eq!(verdict.interaction, DimensionVerdict::Unassessed);
    assert_eq!(verdict.process, DimensionVerdict::Unassessed);
}

#[test]
fn verdict_dimensions_round_trip_in_snake_case_wire_form() {
    let verdict = ScenarioVerdict {
        terminal: DimensionVerdict::AssessedPass,
        interaction: DimensionVerdict::AssessedFail,
        ..Default::default()
    };
    let json = serde_json::to_string(&verdict).expect("a verdict serializes");
    assert!(json.contains("\"assessed_pass\""), "wire form: {json}");
    assert!(json.contains("\"assessed_fail\""), "wire form: {json}");
    let back: ScenarioVerdict = serde_json::from_str(&json).expect("the verdict round-trips");
    assert_eq!(back, verdict);
}

#[test]
fn a_filed_verdict_document_reads_back_by_its_own_digest() {
    // The standing pin P25's receipts and P26's ledger lean on: a filed
    // verdict names its own digest, and a reader who loads the filed bytes
    // re-derives exactly that digest — the citation by digest is provable
    // from the document alone.
    let stage = tempfile::tempdir().expect("a staging dir");
    let document = sample_verdict_document();
    let path = stage.path().join("verdict.json");
    crate::persist::save_json(&path, &document).expect("the verdict files");
    let back: ScenarioVerdictDocument =
        crate::persist::load_json(&path).expect("the filed verdict loads back");
    assert_eq!(back, document, "the document round-trips through filing");
    assert!(
        document.digest.starts_with("sha256:"),
        "the digest names its own algorithm: {}",
        document.digest
    );
    assert_eq!(
        document.content_digest().expect("the document serializes"),
        back.digest,
        "the digest reads back from the filed bytes alone"
    );
}

#[test]
fn the_verdict_digest_digests_the_content_never_the_digest_field_itself() {
    // Same content under any stored digest string re-derives the same
    // digest, and different content never does — the digest is the
    // content's identity, so two verdicts that disagree cannot share one.
    let a = sample_verdict_document();
    let mut blanked = a.clone();
    blanked.digest = String::new();
    assert_eq!(
        a.content_digest().expect("serializes"),
        blanked.content_digest().expect("serializes"),
        "the digest field itself never rides its own digest"
    );
    let mut b = a.clone();
    b.verdict.terminal = DimensionVerdict::AssessedFail;
    assert_ne!(
        a.content_digest().expect("serializes"),
        b.content_digest().expect("serializes"),
        "a different verdict is a different digest"
    );
}

#[test]
fn a_pairing_stamp_carries_the_normalization_version_it_was_captured_under() {
    // The capture names not only which bytes ran and which Wine ran them,
    // but which normalization version governed it: pairing refuses across
    // versions, and that refusal can only name versions the captures
    // themselves carry.
    let capture: ScenarioCapture = serde_json::from_str(
        r#"{"scenario": "boot", "filed_at": 1,
            "pairing": {"program_sha256": "aa", "wine_version": "wine-9.0",
                        "normalization_version": "norm-v1"}}"#,
    )
    .expect("a stamped capture parses");
    let pairing = capture.pairing.expect("the pairing stamp stands");
    assert_eq!(pairing.normalization_version, "norm-v1");
    let json = serde_json::to_string(&pairing).expect("the pairing round-trips");
    assert!(
        json.contains("\"normalization_version\":\"norm-v1\""),
        "wire form: {json}"
    );
}

#[test]
fn a_pairing_from_before_the_version_stamp_reads_as_version_unstamped() {
    // A capture filed before this stamp existed carries no version — the
    // compare side reads that as *not proven*, never as agreement.
    let pairing: CapturePairing =
        serde_json::from_str(r#"{"program_sha256": "aa", "wine_version": "wine-9.0"}"#)
            .expect("an older pairing still parses");
    assert!(
        pairing.normalization_version.is_empty(),
        "the absent stamp reads as unstamped, never as a version"
    );
}

#[test]
fn an_absent_capture_dimension_block_reads_unassessed() {
    // A capture that says nothing about a dimension carries no block for it
    // at all — the compare side (P24.6) reads that absence as unassessed.
    let capture: ScenarioCapture =
        serde_json::from_str(r#"{"scenario": "boot-and-exit", "filed_at": 1234}"#)
            .expect("a thin capture parses");
    assert_eq!(capture.scenario, "boot-and-exit");
    assert!(capture.pairing.is_none(), "no pairing stamp filed yet");
    assert!(capture.terminal.is_none());
    assert!(capture.interaction.is_none());
    assert!(capture.exit.is_none());
    assert!(capture.filesystem.is_none());
    assert!(capture.process.is_none());
}

#[test]
fn the_exit_disposition_is_closed_and_snake_case_on_the_wire() {
    let capture: ScenarioCapture = serde_json::from_str(
        r#"{"scenario": "hang", "filed_at": 1234,
           "exit": {"disposition": "idle_timeout", "exit_code": null}}"#,
    )
    .expect("an exit block parses");
    let exit = capture.exit.expect("the exit block is present");
    assert_eq!(exit.disposition, ExitDisposition::IdleTimeout);
    assert_eq!(exit.exit_code, None);

    for (text, want) in [
        ("exited", ExitDisposition::Exited),
        ("timeout", ExitDisposition::Timeout),
        ("cancelled", ExitDisposition::Cancelled),
        ("failed", ExitDisposition::Failed),
    ] {
        let got: ExitDisposition =
            serde_json::from_str(&format!("\"{text}\"")).expect("closed-set name parses");
        assert_eq!(got, want);
    }
    // The set is closed: an invented disposition fails rather than landing
    // in some fallback.
    assert!(serde_json::from_str::<ExitDisposition>("\"shrugged\"").is_err());
}

/// A complete, well-formed contract for the validation tests to mutate.
/// The working dir is the literal name `wd`, expected to exist under the
/// validation root each test builds.
fn sample_contract(name: &str) -> ScenarioContract {
    ScenarioContract {
        name: name.into(),
        working_dir: "wd".into(),
        env: BTreeMap::from([("CALX_SCENARIO".to_string(), name.to_string())]),
        argv: vec!["--fast".into()],
        interactions: vec![
            ScriptedInteraction {
                at_ms: 500,
                kind: InteractionKind::Input {
                    text: ScriptedInput::Text("menu choice\n".into()),
                },
            },
            ScriptedInteraction {
                at_ms: 900,
                kind: InteractionKind::Input {
                    text: ScriptedInput::ByteCount { bytes: 13 },
                },
            },
            ScriptedInteraction {
                at_ms: 1_200,
                kind: InteractionKind::Resize {
                    cols: 120,
                    rows: 40,
                },
            },
            ScriptedInteraction {
                at_ms: 1_500,
                kind: InteractionKind::Signal {
                    signal: ScenarioSignal::Interrupt,
                },
            },
        ],
        cols: 80,
        rows: 24,
        observation_paths: vec!["save/out.dat".into(), "logs".into()],
        idle_timeout_ms: 5_000,
        max_run_ms: 30_000,
        finalization_grace_ms: 5_000,
        max_output_bytes: 1_048_576,
        normalization: NormalizationRules {
            version: "norm-v1".into(),
            literal_replacements: vec![LiteralReplacement {
                from: "Arthur".into(),
                to: "<user>".into(),
            }],
            port_patterns: vec![":\\d{4,5}".into()],
        },
    }
}

fn sample_verdict_document() -> ScenarioVerdictDocument {
    // A filed verdict as the comparator files one: a named divergence, a
    // stated unknown, and the digest the document stamps itself with.
    let mut document = ScenarioVerdictDocument {
        binary: BinaryIdentity::new("eqgame.exe"),
        scenario: "boot".into(),
        filed_at: 7,
        normalization_version: "norm-v1".into(),
        left_capture_sha256: "sha256:left-bytes".into(),
        right_capture_sha256: "sha256:right-bytes".into(),
        left_pairing: None,
        right_pairing: None,
        verdict: ScenarioVerdict {
            exit: DimensionVerdict::AssessedFail,
            ..ScenarioVerdict::default()
        },
        divergences: vec![DimensionDivergence::ExitCode {
            left: Some(7),
            right: Some(9),
        }],
        residual_unknowns: vec!["files outside the declared observation paths are unknown".into()],
        claims_complete_equivalence: false,
        digest: String::new(),
    };
    document.digest = document
        .content_digest()
        .expect("a sample verdict document serializes");
    document
}

#[test]
fn a_declared_contract_round_trips_over_the_wire() {
    let contract = sample_contract("boot");
    let json = serde_json::to_string(&contract).expect("a contract serializes");
    let back: ScenarioContract = serde_json::from_str(&json).expect("the contract round-trips");
    assert_eq!(back, contract);
}

#[test]
fn a_contract_with_absent_optional_fields_reads_as_declared_nothing() {
    // Silence in a filed contract is readable as nothing-declared, never a
    // guess: the closed-list optional fields default to empty.
    let contract: ScenarioContract = serde_json::from_str(
        r#"{"name": "bare", "working_dir": "wd", "cols": 80, "rows": 24,
           "idle_timeout_ms": 5000, "max_run_ms": 30000,
           "finalization_grace_ms": 5000, "max_output_bytes": 1048576,
           "normalization": {"version": "norm-v1"}}"#,
    )
    .expect("a contract with only required fields parses");
    assert!(contract.env.is_empty(), "absent env reads as nothing");
    assert!(contract.argv.is_empty(), "absent argv reads as nothing");
    assert!(
        contract.interactions.is_empty(),
        "absent interactions read as nothing"
    );
    assert!(
        contract.observation_paths.is_empty(),
        "absent observation paths read as nothing"
    );
    assert!(
        contract.normalization.literal_replacements.is_empty()
            && contract.normalization.port_patterns.is_empty(),
        "absent normalization rules read as declared-nothing"
    );
}

#[test]
fn a_sensitive_scripted_input_persists_only_as_a_byte_count_placeholder() {
    // The placeholder is the storage form: the contract document's own
    // bytes carry how many were typed, never which ones. (The end-to-end
    // prove-the-secret-absent pin rides the CLI slice, issue #402.)
    let contract = sample_contract("login");
    let json = serde_json::to_string(&contract).expect("a contract serializes");
    assert!(
        json.contains("\"byte_count\""),
        "the placeholder is filed: {json}"
    );
    let back: ScenarioContract = serde_json::from_str(&json).expect("round-trips");
    let typed: Vec<ScriptedInput> = back
        .interactions
        .iter()
        .filter_map(|i| match &i.kind {
            InteractionKind::Input { text } => Some(text.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(typed.len(), 2, "both scripted inputs round-trip");
    assert!(matches!(&typed[1], ScriptedInput::ByteCount { bytes: 13 }));
    assert!(matches!(&typed[0], ScriptedInput::Text(t) if t == "menu choice\n"));
}

// ============================================================
// Validation: a malformed declaration is refused naming its field
// ============================================================

/// Validation root holding the `wd` working dir the sample contract names.
fn validation_root() -> tempfile::TempDir {
    let dir = tempfile::TempDir::new().expect("a temp validation root");
    std::fs::create_dir(dir.path().join("wd")).expect("the working dir exists");
    dir
}

/// Assert the refusal names exactly this field.
fn refused_field(result: Result<(), TypesError>) -> String {
    match result {
        Ok(()) => panic!("the declaration should have been refused"),
        Err(TypesError::ScenarioFieldInvalid { field, .. }) => field,
        Err(other) => panic!("a different error surfaced: {other}"),
    }
}

#[test]
fn an_unresolvable_working_dir_is_refused_naming_the_field() {
    let dir = tempfile::TempDir::new().expect("a temp validation root");
    let mut contract = sample_contract("boot");
    contract.working_dir = "nowhere".into();
    assert_eq!(
        refused_field(contract.validate(dir.path())),
        "working_dir",
        "the refusal names the offending field"
    );
}

#[test]
fn an_observation_path_escaping_the_run_dir_is_refused_naming_the_field() {
    let root = validation_root();
    for escaping in ["../outside", "/etc/passwd", "save/../../x"] {
        let mut contract = sample_contract("boot");
        contract.observation_paths = vec![escaping.to_string()];
        assert_eq!(
            refused_field(contract.validate(root.path())),
            "observation_paths",
            "the escape `{escaping}` is refused naming its field"
        );
    }
}

#[test]
fn absurd_timing_values_are_refused_naming_the_field() {
    let root = validation_root();
    for (field, mutate) in [
        (
            "idle_timeout_ms",
            Box::new(|c: &mut ScenarioContract| c.idle_timeout_ms = 0)
                as Box<dyn Fn(&mut ScenarioContract)>,
        ),
        (
            "idle_timeout_ms",
            Box::new(|c| c.idle_timeout_ms = MAX_SCENARIO_WINDOW_MS + 1),
        ),
        ("max_run_ms", Box::new(|c| c.max_run_ms = 0)),
        (
            "max_run_ms",
            Box::new(|c| c.max_run_ms = MAX_SCENARIO_WINDOW_MS + 1),
        ),
        (
            "finalization_grace_ms",
            Box::new(|c| c.finalization_grace_ms = MAX_FINALIZATION_GRACE_MS + 1),
        ),
        ("max_output_bytes", Box::new(|c| c.max_output_bytes = 0)),
        (
            "max_output_bytes",
            Box::new(|c| c.max_output_bytes = MAX_SCENARIO_OUTPUT_BYTES + 1),
        ),
    ] {
        let mut contract = sample_contract("boot");
        mutate(&mut contract);
        assert_eq!(
            refused_field(contract.validate(root.path())),
            field,
            "the absurd timing value is refused naming `{field}`"
        );
    }
}

#[test]
fn an_interaction_scheduled_after_the_run_can_only_have_ended_is_refused() {
    let root = validation_root();
    let mut contract = sample_contract("boot");
    contract
        .interactions
        .get_mut(0)
        .expect("the sample contract has interactions")
        .at_ms = contract.max_run_ms;
    assert_eq!(
        refused_field(contract.validate(root.path())),
        "interactions",
        "a never-fireable interaction names its field"
    );
}

#[test]
fn an_unversioned_normalization_is_refused_naming_the_field() {
    let root = validation_root();
    let mut contract = sample_contract("boot");
    contract.normalization.version = String::new();
    assert_eq!(
        refused_field(contract.validate(root.path())),
        "normalization",
        "normalization must carry its version"
    );
}

// ============================================================
// Filing: one owned document per binary, replaced per scenario name
// ============================================================

#[test]
fn contract_documents_key_by_binary_identity_under_re_scenarios() {
    let path = scenario_contracts_path(Path::new("ws"), &BinaryIdentity::new("eqgame.exe"));
    assert_eq!(
        path,
        Path::new("ws")
            .join("re")
            .join("scenarios")
            .join("eqgame.exe.json"),
        "the record tree names the interface-owned scenario directory"
    );
}

#[test]
fn several_scenarios_coexist_and_re_declaring_replaces_by_name() {
    let root = validation_root();
    let mut docs = ScenarioContracts {
        binary: BinaryIdentity::new("eqgame.exe"),
        filed_at: 1,
        scenarios: BTreeMap::new(),
    };
    docs.declare(sample_contract("boot"), root.path(), 2)
        .expect("the first contract declares");
    docs.declare(sample_contract("login"), root.path(), 3)
        .expect("the second scenario coexists");
    assert_eq!(docs.scenarios.len(), 2);

    let mut re_declared = sample_contract("boot");
    re_declared.max_run_ms = 5_000;
    docs.declare(re_declared, root.path(), 4)
        .expect("re-declaring replaces by name");
    assert_eq!(
        docs.scenarios.len(),
        2,
        "exactly one current contract per scenario name"
    );
    assert_eq!(docs.scenarios["boot"].max_run_ms, 5_000);
    assert_eq!(docs.filed_at, 4, "the filing envelope refreshes");
}

#[test]
fn a_refused_declaration_changes_nothing_at_all() {
    let root = validation_root();
    let mut docs = ScenarioContracts {
        binary: BinaryIdentity::new("eqgame.exe"),
        filed_at: 7,
        scenarios: BTreeMap::from([("boot".to_string(), sample_contract("boot"))]),
    };
    let before = docs.clone();
    let mut bad = sample_contract("mismatched");
    bad.max_run_ms = 0;
    assert_eq!(
        refused_field(docs.declare(bad, root.path(), 9)),
        "max_run_ms",
        "nothing files on refusal"
    );
    assert_eq!(docs, before, "the refused declaration changed nothing");
}

// ============================================================
// The capture document's record-tree location (P24.3, issue #404)
// ============================================================

#[test]
fn captures_land_at_their_named_record_tree_location() {
    // The captures live in their own directory under the scenario
    // directory: one document per (binary, scenario name), so re-capture
    // replaces the previous document outright and exactly one current
    // capture stands per scenario name.
    let path = scenario_capture_path("/ws", &BinaryIdentity::new("eqgame.exe"), "boot-and-exit");
    assert_eq!(
        path,
        Path::new("/ws")
            .join("re")
            .join("scenarios")
            .join("captures")
            .join("eqgame.exe-boot-and-exit.json"),
        "the record tree names the capture directory under the scenario directory"
    );
    assert_eq!(
        scenario_captures_dir("/ws"),
        scenario_contracts_dir("/ws").join("captures"),
        "the captures directory stands inside the scenario directory"
    );
}

#[test]
fn a_scenario_name_folds_to_one_file_key() {
    // A filed capture can never escape the captures directory through a
    // scenario name: every character outside [A-Za-z0-9._-] folds to `-`,
    // so the name stays one file name whatever was declared.
    let path = scenario_capture_path(
        "/ws",
        &BinaryIdentity::new("eqgame.exe"),
        "run ../ deep/name",
    );
    let file_name = path.file_name().expect("one file name, not a climb");
    assert_eq!(
        file_name.to_str().expect("utf-8 file name"),
        "eqgame.exe-run-..--deep-name.json"
    );
    assert_eq!(
        path.parent().expect("the file sits in the captures dir"),
        scenario_captures_dir("/ws")
    );
}

// ============================================================
// File content identity: whole file + 4 KiB block hashes (P24.3)
// ============================================================

#[test]
fn a_pre_block_hash_capture_document_still_parses_with_empty_blocks() {
    // The block-hash detail grew with the capture slice: a capture
    // document written without it still reads, stating no blocks at all —
    // never an implied full-file single block.
    let capture: ScenarioCapture = serde_json::from_str(
        r#"{"scenario": "boot", "filed_at": 1, "filesystem": {"entries": [
            {"path": "out.dat", "change": "created", "size_bytes": 5, "sha256": "ab"}
        ]}}"#,
    )
    .expect("a pre-P24.3 capture document still parses");
    let entry = &capture
        .filesystem
        .expect("the filesystem block reads")
        .entries[0];
    assert!(
        entry.block_hashes.is_empty(),
        "a document that never carried block hashes states none, not an implied block"
    );
}

// ============================================================
// Terminal geometry and rendered states beside the chunks (P24.5, #406)
// ============================================================

#[test]
fn terminal_geometry_and_rendered_states_round_trip_beside_the_chunks() {
    // The terminal dimension carries content beyond bytes: the geometry the
    // console opened at, and every geometry the live terminal rendered after
    // a resize, in order.
    let observation = TerminalObservation {
        chunks: vec!["ready".into()],
        geometry: Some(TerminalGeometry { cols: 80, rows: 24 }),
        rendered_states: vec![
            TerminalGeometry {
                cols: 100,
                rows: 30,
            },
            TerminalGeometry {
                cols: 120,
                rows: 40,
            },
        ],
        ..Default::default()
    };
    let json = serde_json::to_string(&observation).expect("the observation serializes");
    assert!(
        json.contains(r#""geometry":{"cols":80,"rows":24}"#),
        "the geometry files its cells: {json}"
    );
    assert!(
        json.contains(r#""rendered_states":[{"cols":100,"rows":30},{"cols":120,"rows":40}]"#),
        "the rendered states file in order: {json}"
    );
    let back: TerminalObservation = serde_json::from_str(&json).expect("it round-trips");
    assert_eq!(back, observation);
}

#[test]
fn a_terminal_record_without_geometry_or_states_reads_absent() {
    // The honesty rule again: a capture written before P24.5 carries neither
    // field, and it reads *unassessed* — no geometry, no states — never a
    // defaulted 0x0 terminal.
    let observation: TerminalObservation =
        serde_json::from_str(r#"{"chunks": ["ready"]}"#).expect("an old terminal record parses");
    assert_eq!(observation.geometry, None);
    assert!(
        observation.rendered_states.is_empty(),
        "no states filed reads as none observed"
    );
    let json = serde_json::to_string(&observation).expect("it serializes");
    assert!(
        !json.contains("geometry") && !json.contains("rendered_states"),
        "unobserved fields stay out of the document: {json}"
    );
}

#[test]
fn block_hashes_round_trip_beside_the_whole_file_digest() {
    let entry = FileObservation {
        path: "out.dat".to_string(),
        change: FileChange::Created,
        size_bytes: Some(5),
        sha256: Some("whole-file".to_string()),
        block_hashes: vec!["block-0".to_string(), "block-1".to_string()],
    };
    let json = serde_json::to_string(&entry).expect("the observation serializes");
    assert!(json.contains("\"block_hashes\""), "wire form: {json}");
    let back: FileObservation = serde_json::from_str(&json).expect("it round-trips");
    assert_eq!(back, entry);
}
