//! Pure record tests for the scenario records (P24.1, issue #402).
//!
//! The honesty rule these pin: silence is readable, never a pass. A filed
//! verdict document that says nothing about a dimension reads *unassessed* —
//! never assessed pass, never assessed fail — and a capture block that is
//! absent reads the same way at compare time.

use super::*;

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
