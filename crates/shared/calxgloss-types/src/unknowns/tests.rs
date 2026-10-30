// Tests for the module above, split out of the file they test.
use super::*;
use crate::persist::{JsonStore, save_json};

/// One coverage-residue record: the fixture every test reaches for, in
/// the shape the batch's coverage fold (issue #369) will file.
fn coverage_record(binary: &str, function: &str, question: &str, now: u64) -> UnknownRecord {
    UnknownRecord::derive(
        binary,
        Some(function.to_string()),
        UnknownKind::CoverageFacet,
        UnknownSeverity::Blocking,
        question,
        "the decompiled body of the function",
        UnknownOrigin::Document {
            document: "typesdb".to_string(),
            facet: "function-bodies".to_string(),
        },
        now,
    )
}

/// A ledger document as the pipeline files it, holding the given records.
fn filed_ledger(binary: &str, records: Vec<UnknownRecord>) -> UnknownLedger {
    UnknownLedger {
        binary: BinaryIdentity::new(binary),
        filed_at: 1_760_000_000,
        records: Some(records),
    }
}

#[test]
fn the_round_trip_through_the_shared_json_store_passes_everything_through_untouched() {
    // A full round trip (issue #368): ids, kinds, severities, question
    // and required-evidence lines, origins, order, and revisions all
    // pass through the shared JSON store byte-faithfully.
    let dir = tempfile::TempDir::new().expect("temp workspace");
    let store = JsonStore::<UnknownLedger>::new(unknown_ledger_dir(dir.path()));
    let records = vec![
        coverage_record(
            "eqmain.dll",
            "DrawSprite",
            "what does DrawSprite do, given its body never decompiled?",
            100,
        ),
        UnknownRecord::derive(
            "eqmain.dll",
            None,
            UnknownKind::ExportUncovered,
            UnknownSeverity::Blocking,
            "what calls DrawSprite really do to its arguments?",
            "a filed baseline document calling DrawSprite",
            UnknownOrigin::CaseSet {
                case_set: "export-DrawSprite".to_string(),
            },
            101,
        ),
        UnknownRecord::derive(
            "eqmain.dll",
            Some("InitWorld".to_string()),
            UnknownKind::AnalysisFamily,
            UnknownSeverity::Material,
            "who calls InitWorld, given caller edges cannot be answered?",
            "caller-edge listings from the analysis engine",
            UnknownOrigin::Family {
                family: "caller-edges".to_string(),
            },
            102,
        ),
        UnknownRecord::derive(
            "eqmain.dll",
            Some("InitWorld".to_string()),
            UnknownKind::RetryPruned,
            UnknownSeverity::Notable,
            "what context the escalate would have re-asked is still missing?",
            "an analysis engine that can answer decompilation",
            UnknownOrigin::RetryDecision {
                decision: "escalate#decompilation".to_string(),
            },
            103,
        ),
    ];
    let ledger = filed_ledger("eqmain.dll", records);

    store.save("eqmain.dll", &ledger).expect("ledger files");

    let loaded = store.load("eqmain.dll").expect("ledger loads");
    assert_eq!(loaded, ledger, "every field passes through untouched");
    let loaded_records = loaded.records.expect("filed records key");
    assert_eq!(
        loaded_records
            .iter()
            .map(|r| r.id.as_str())
            .collect::<Vec<_>>(),
        ledger
            .records
            .as_ref()
            .expect("same records")
            .iter()
            .map(|r| r.id.as_str())
            .collect::<Vec<_>>(),
        "the filing order survives"
    );
    assert_eq!(loaded_records[1].kind, UnknownKind::ExportUncovered);
    assert_eq!(loaded_records[2].severity, UnknownSeverity::Material);
    assert_eq!(loaded_records[3].revision, 1);
    assert_eq!(
        loaded_records[0].question,
        ledger.records.as_ref().unwrap()[0].question,
        "the question line survives word for word"
    );
}

#[test]
fn the_three_free_text_fields_pass_through_their_documents_verbatim() {
    // The bounded-one-line discipline the P19 and P20 shapes already
    // share: each field's wording is owned once by the shared type, and
    // the store carries it unchanged — em dashes and all.
    let dir = tempfile::TempDir::new().expect("temp workspace");
    let record = coverage_record(
        "eqmain.dll",
        "F",
        "what does F do — its body never arrived?",
        100,
    );
    let ledger = filed_ledger("eqmain.dll", vec![record.clone()]);
    save_json(&unknown_ledger_path(dir.path(), &ledger.binary), &ledger).expect("ledger files");

    let resolutions = UnknownResolutions {
        resolutions: [(
            record.id.clone(),
            UnknownResolution {
                disposition: UnknownDisposition::Resolved,
                reason: "read the disassembly listing — it matches the shim".to_string(),
                expected_revision: 1,
                at: 200,
            },
        )]
        .into_iter()
        .collect(),
        reopened: BTreeMap::new(),
    };
    save_json(&unknown_resolutions_path(dir.path()), &resolutions).expect("resolutions file");

    let loaded_ledger = read_unknown_ledger(dir.path(), &ledger.binary).expect("ledger loads");
    let EffectiveLedger::Filed(records) = loaded_ledger else {
        panic!("a filed document reads as filed");
    };
    assert_eq!(records[0], record);
    let loaded: UnknownResolutions =
        load_json(&unknown_resolutions_path(dir.path())).expect("resolutions load");
    assert_eq!(loaded, resolutions);
    assert_eq!(
        loaded.resolutions[&record.id].reason,
        "read the disassembly listing — it matches the shim"
    );
}

// --- the three readings of a ledger, never collapsed ------------------

#[test]
fn an_unfiled_ledger_reads_as_unknown_never_as_no_gaps() {
    let dir = tempfile::TempDir::new().expect("temp workspace");
    let reading =
        read_unknown_ledger(dir.path(), &BinaryIdentity::new("eqmain.dll")).expect("absence reads");
    assert_eq!(reading, EffectiveLedger::Unknown);
    assert!(
        reading.records().is_none(),
        "an unfiled ledger carries no records to render — never a clean bill of health"
    );
}

#[test]
fn a_filed_document_without_a_records_key_reads_as_unknown() {
    // The absent-field rule ADR-0053 established, applied to this
    // track's own artifact: an absent key never means the list is empty.
    let dir = tempfile::TempDir::new().expect("temp workspace");
    let path = unknown_ledger_path(dir.path(), &BinaryIdentity::new("eqmain.dll"));
    std::fs::create_dir_all(path.parent().expect("ledger dir")).expect("create re/unknowns");
    std::fs::write(&path, r#"{"binary": "eqmain.dll", "filed_at": 1760000000}"#)
        .expect("file the keyless document");

    let reading = read_unknown_ledger(dir.path(), &BinaryIdentity::new("eqmain.dll"))
        .expect("the keyless document loads");
    assert_eq!(reading, EffectiveLedger::Unknown);
}

#[test]
fn a_filed_empty_list_is_the_only_known_and_none_reading() {
    let dir = tempfile::TempDir::new().expect("temp workspace");
    let ledger = filed_ledger("eqmain.dll", Vec::new());
    save_json(&unknown_ledger_path(dir.path(), &ledger.binary), &ledger).expect("file empty");

    let reading = read_unknown_ledger(dir.path(), &ledger.binary).expect("empty list loads");
    assert_eq!(reading, EffectiveLedger::Filed(Vec::new()));
    assert_eq!(
        reading.records().expect("a filed empty list"),
        &[] as &[UnknownRecord],
        "explicitly-empty is the one honest nothing-is-open-here"
    );
}

#[test]
fn a_corrupt_ledger_stays_corrupt_and_never_reads_as_unknown() {
    // The missing-versus-corrupt distinction (NotFound vs Json) stays.
    let dir = tempfile::TempDir::new().expect("temp workspace");
    let path = unknown_ledger_path(dir.path(), &BinaryIdentity::new("eqmain.dll"));
    std::fs::create_dir_all(path.parent().expect("ledger dir")).expect("create re/unknowns");
    std::fs::write(&path, "{ not json").expect("corrupt the document");

    let err = read_unknown_ledger(dir.path(), &BinaryIdentity::new("eqmain.dll"))
        .expect_err("a corrupt document fails loudly");
    assert!(
        matches!(err, PersistError::Json { .. }),
        "corrupt is corrupt: {err}"
    );
}

#[test]
fn a_document_without_its_filing_envelope_is_not_a_filed_ledger() {
    // The envelope — which binary it was filed for and when — is what
    // lets a reader tell a filed document from a stray one.
    let err = serde_json::from_str::<UnknownLedger>(r#"{"records": []}"#)
        .expect_err("an envelope-less document is refused");
    assert!(
        err.to_string().contains("binary"),
        "the refusal names the missing envelope field: {err}"
    );
}

// --- the id pins: the load-bearing ones --------------------------------

#[test]
fn the_same_inputs_re_derived_across_attempts_and_runs_lands_the_same_id() {
    let first_run = coverage_record(
        "game_logic.dll",
        "DrawSprite",
        "what does DrawSprite do, given its body never decompiled?",
        100,
    );
    let later_run = coverage_record(
        "game_logic.dll",
        "DrawSprite",
        "what does DrawSprite do, given its body never decompiled?",
        9_999,
    );
    assert_eq!(
        first_run.id, later_run.id,
        "re-derivation never duplicates a question"
    );
}

#[test]
fn re_worded_admission_text_keeps_the_id() {
    // The engine re-worded its limitation line; the gap is the same
    // facet of the same document for the same function.
    let before = coverage_record(
        "game_logic.dll",
        "DrawSprite",
        "what is DrawSprite doing?",
        100,
    );
    let after = coverage_record(
        "game_logic.dll",
        "DrawSprite",
        "what does the never-decompiled body of DrawSprite contain?",
        200,
    );
    assert_eq!(before.id, after.id, "the id excludes the wording lines");
    assert_ne!(
        before.question, after.question,
        "the wording lines did change"
    );
}

#[test]
fn the_id_excludes_the_question_and_required_evidence_wording() {
    let plain = coverage_record("a.dll", "F", "one question", 100);
    let reworded = UnknownRecord::derive(
        "a.dll",
        Some("F".to_string()),
        UnknownKind::CoverageFacet,
        UnknownSeverity::Notable,
        "an entirely different sentence about the same gap",
        "and a different evidence sentence too",
        UnknownOrigin::Document {
            document: "typesdb".to_string(),
            facet: "function-bodies".to_string(),
        },
        200,
    );
    assert_eq!(plain.id, reworded.id);
}

#[test]
fn a_different_facet_family_or_export_yields_a_different_id() {
    let bodies = coverage_record("a.dll", "F", "q", 100);
    let other_facet = UnknownRecord::derive(
        "a.dll",
        Some("F".to_string()),
        UnknownKind::CoverageFacet,
        UnknownSeverity::Blocking,
        "q",
        "e",
        UnknownOrigin::Document {
            document: "typesdb".to_string(),
            facet: "data-objects".to_string(),
        },
        100,
    );
    let other_document = UnknownRecord::derive(
        "a.dll",
        Some("F".to_string()),
        UnknownKind::CoverageFacet,
        UnknownSeverity::Blocking,
        "q",
        "e",
        UnknownOrigin::Document {
            document: "callback".to_string(),
            facet: "function-bodies".to_string(),
        },
        100,
    );
    let family = UnknownRecord::derive(
        "a.dll",
        Some("F".to_string()),
        UnknownKind::AnalysisFamily,
        UnknownSeverity::Material,
        "q",
        "e",
        UnknownOrigin::Family {
            family: "decompilation".to_string(),
        },
        100,
    );
    let export = UnknownRecord::derive(
        "a.dll",
        None,
        UnknownKind::ExportUncovered,
        UnknownSeverity::Blocking,
        "q",
        "e",
        UnknownOrigin::CaseSet {
            case_set: "export-F".to_string(),
        },
        100,
    );
    let other_export = UnknownRecord::derive(
        "a.dll",
        None,
        UnknownKind::ExportUncovered,
        UnknownSeverity::Blocking,
        "q",
        "e",
        UnknownOrigin::CaseSet {
            case_set: "export-G".to_string(),
        },
        100,
    );
    let ids = [
        bodies.id,
        other_facet.id,
        other_document.id,
        family.id,
        export.id,
        other_export.id,
    ];
    for (i, a) in ids.iter().enumerate() {
        for b in ids.iter().skip(i + 1) {
            assert_ne!(a, b, "genuinely different gaps are different ids: {a}");
        }
    }
}

#[test]
fn the_id_folds_the_binary_and_the_function_where_the_record_is_function_specific() {
    // Same kind and slot across two binaries, and across two functions
    // of one binary: four different records. And the binary-level
    // spelling differs from any function's.
    let one = coverage_record("a.dll", "F", "q", 100);
    let other_binary = coverage_record("b.dll", "F", "q", 100);
    let other_function = coverage_record("a.dll", "G", "q", 100);
    let binary_level = UnknownRecord::derive(
        "a.dll",
        None,
        UnknownKind::CoverageFacet,
        UnknownSeverity::Blocking,
        "q",
        "e",
        UnknownOrigin::Document {
            document: "typesdb".to_string(),
            facet: "function-bodies".to_string(),
        },
        100,
    );
    assert_ne!(one.id, other_binary.id);
    assert_ne!(one.id, other_function.id);
    assert_ne!(one.id, binary_level.id);
    assert!(
        !one.id.contains("game") && one.id.starts_with("a.dll/F/coverage_facet/"),
        "the id is readable and folds its subject, its kind, and its slot: {}",
        one.id
    );
}

// --- revisions guard writes --------------------------------------------

#[test]
fn re_deriving_an_unchanged_record_keeps_its_revision_and_first_seen() {
    // Diff-friendly across attempts and runs (issue #368): the landed
    // document re-derived whole keeps every record's revision and
    // first-seen, refreshing only last-seen.
    let landed = filed_ledger(
        "a.dll",
        UnknownLedger::file(
            "a.dll",
            None,
            &[coverage_record("a.dll", "F", "what is F doing?", 100)],
            &BTreeMap::new(),
            100,
        )
        .records
        .expect("filed"),
    );
    let re_derived = UnknownLedger::file(
        "a.dll",
        Some(&landed),
        &[coverage_record("a.dll", "F", "what is F doing?", 500)],
        &BTreeMap::new(),
        500,
    );
    let records = re_derived.records.expect("filed again");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].id, landed.records.as_ref().unwrap()[0].id);
    assert_eq!(
        records[0].revision, 1,
        "a stamp move is not a content change"
    );
    assert_eq!(records[0].first_seen, 100, "first-seen survives untouched");
    assert_eq!(
        records[0].last_seen, 500,
        "last-seen refreshes to this derivation"
    );
}

#[test]
fn a_changed_persisted_field_appends_a_new_revision_and_never_rewrites_the_old_one() {
    let first = UnknownLedger::file(
        "a.dll",
        None,
        &[coverage_record("a.dll", "F", "first wording", 100)],
        &BTreeMap::new(),
        100,
    );
    // Re-worded admission (the question changed): a new revision, one
    // above the landed. First-seen stays; nothing is rewritten.
    let second = UnknownLedger::file(
        "a.dll",
        Some(&first),
        &[coverage_record("a.dll", "F", "second wording", 200)],
        &BTreeMap::new(),
        200,
    );
    let second_records = second.records.as_ref().expect("filed");
    assert_eq!(second_records[0].revision, 2);
    assert_eq!(second_records[0].first_seen, 100);
    // A second change appends again — 3, and the landed 2 was never
    // rewritten in place.
    let third = UnknownLedger::file(
        "a.dll",
        Some(&second),
        &[UnknownRecord::derive(
            "a.dll",
            Some("F".to_string()),
            UnknownKind::CoverageFacet,
            UnknownSeverity::Material,
            "second wording",
            "e",
            UnknownOrigin::Document {
                document: "typesdb".to_string(),
                facet: "function-bodies".to_string(),
            },
            300,
        )],
        &BTreeMap::new(),
        300,
    );
    assert_eq!(third.records.expect("filed")[0].revision, 3);
}

#[test]
fn a_new_record_files_at_revision_one_and_a_disappeared_slot_stops_being_derivable() {
    let landed = UnknownLedger::file(
        "a.dll",
        None,
        &[
            coverage_record("a.dll", "F", "q", 100),
            coverage_record("a.dll", "G", "q", 100),
        ],
        &BTreeMap::new(),
        100,
    );
    // G's source slot disappeared from the filed documents: the next
    // derivation simply does not name it.
    let re_derived = UnknownLedger::file(
        "a.dll",
        Some(&landed),
        &[coverage_record("a.dll", "F", "q", 500)],
        &BTreeMap::new(),
        500,
    );
    let records = re_derived.records.expect("filed");
    assert_eq!(
        records.len(),
        1,
        "the stopped-derivable record stops landing"
    );
    assert_eq!(records[0].function.as_deref(), Some("F"));
}

#[test]
fn a_disappeared_slot_its_resolution_survives_as_a_durable_reviewer_record() {
    // The ledger replaces outright; the reviewer's document is a
    // different owner and this write never touches it.
    let dir = tempfile::TempDir::new().expect("temp workspace");
    let settled = coverage_record("a.dll", "G", "q", 100);
    let mut resolutions = UnknownResolutions::default();
    resolutions
        .resolve(&settled, "not relevant to this target", 1, 150)
        .expect("settle");
    save_json(&unknown_resolutions_path(dir.path()), &resolutions).expect("resolutions file");

    let landed = UnknownLedger::file(
        "a.dll",
        None,
        std::slice::from_ref(&settled),
        &BTreeMap::new(),
        100,
    );
    save_json(&unknown_ledger_path(dir.path(), &landed.binary), &landed).expect("file ledger");
    let re_derived = UnknownLedger::file("a.dll", Some(&landed), &[], &BTreeMap::new(), 500);
    save_json(
        &unknown_ledger_path(dir.path(), &re_derived.binary),
        &re_derived,
    )
    .expect("file again");

    assert!(
        re_derived.record(&settled.id).is_none(),
        "no longer derivable"
    );
    let durable: UnknownResolutions =
        load_json(&unknown_resolutions_path(dir.path())).expect("resolutions still load");
    assert!(
        durable.resolutions.contains_key(&settled.id),
        "the reviewer's answer is a durable reviewer record, never silently dropped"
    );
}

#[test]
fn a_stale_settle_write_fails_with_a_named_changed_underneath_conflict() {
    // A fresh batch re-derived the record (revision 9 landed) after the
    // reviewer read revision 8: the settle loses, naming the landed state.
    let record = UnknownRecord::derive(
        "a.dll",
        Some("F".to_string()),
        UnknownKind::BaselineNeverRun,
        UnknownSeverity::Blocking,
        "was F ever exercised?",
        "filed baseline cases calling F",
        UnknownOrigin::CaseSet {
            case_set: "cases-F".to_string(),
        },
        900,
    );
    let landed_at_9 = UnknownRecord {
        revision: 9,
        ..record.clone()
    };
    let mut resolutions = UnknownResolutions::default();
    let err = resolutions
        .resolve(&landed_at_9, "established by hand", 8, 1_000)
        .expect_err("a stale write must fail loudly");
    assert!(matches!(err, UnknownActionError::ChangedUnderneath { .. }));
    let message = err.to_string();
    assert!(
        message.contains(&record.id),
        "the conflict names the record: {message}"
    );
    assert!(
        message.contains("open at record revision 9"),
        "the conflict names the landed state: {message}"
    );
}

#[test]
fn a_two_action_race_lands_exactly_one_and_the_loser_names_the_landed_settlement() {
    let record = coverage_record("a.dll", "F", "q", 100);
    let mut resolutions = UnknownResolutions::default();
    resolutions
        .resolve(&record, "established by hand", 1, 200)
        .expect("first settle lands");
    let err = resolutions
        .dismiss(&record, "not relevant", 1, 300)
        .expect_err("the second settle loses to the first");
    assert!(matches!(err, UnknownActionError::ChangedUnderneath { .. }));
    let message = err.to_string();
    assert!(
        message.contains("resolved at record revision 1"),
        "the loser learns what already landed: {message}"
    );
    assert_eq!(resolutions.resolutions.len(), 1);
    assert_eq!(
        resolutions
            .resolution_for(&record.id)
            .expect("bound")
            .disposition,
        UnknownDisposition::Resolved,
        "exactly one settle landed"
    );
}

#[test]
fn reopening_appends_a_revision_and_deletes_nothing() {
    // A resolution is a revision, never a deletion (issue #368): the
    // reopen marks the revision it was taken back from, and the next
    // ledger write appends one revision above the landed one — once.
    let record = coverage_record("a.dll", "F", "q", 100);
    let landed = UnknownLedger::file(
        "a.dll",
        None,
        std::slice::from_ref(&record),
        &BTreeMap::new(),
        100,
    );
    let landed_record = landed.record(&record.id).expect("landed").clone();
    assert_eq!(
        landed_record.revision, 1,
        "a fresh record files at revision 1"
    );

    let mut resolutions = UnknownResolutions::default();
    resolutions
        .resolve(&landed_record, "established", 1, 150)
        .expect("settle at revision 1");
    resolutions
        .reopen(&landed_record)
        .expect("reopen at revision 1");
    assert!(
        resolutions.resolutions.is_empty(),
        "the reviewer took their intent back"
    );
    assert_eq!(
        resolutions.reopened.get(&record.id),
        Some(&1),
        "the reopen itself is a durable reviewer mark"
    );

    // The next batch re-derives the same content: the mark fires, and a
    // NEW revision lands above the old — the old was never rewritten.
    let after_reopen = UnknownLedger::file(
        "a.dll",
        Some(&landed),
        &[coverage_record("a.dll", "F", "q", 500)],
        &resolutions.reopened,
        500,
    );
    let reopened_record = after_reopen.record(&record.id).expect("still derivable");
    assert_eq!(
        reopened_record.revision, 2,
        "reopening appended a new revision"
    );
    assert_eq!(
        reopened_record.first_seen, 100,
        "nothing about the record was deleted"
    );
    assert_eq!(
        reopened_record.id, record.id,
        "the record kept its identity"
    );

    // A third derivation: the mark already fired at revision 1, and the
    // landed revision is now 2 — it fires exactly once.
    let third = UnknownLedger::file(
        "a.dll",
        Some(&after_reopen),
        &[coverage_record("a.dll", "F", "q", 600)],
        &resolutions.reopened,
        600,
    );
    assert_eq!(third.record(&record.id).expect("landed").revision, 2);
}

#[test]
fn reopening_without_a_settlement_loses_naming_the_landed_open_state() {
    let record = coverage_record("a.dll", "F", "q", 100);
    let mut resolutions = UnknownResolutions::default();
    let err = resolutions
        .reopen(&record)
        .expect_err("reopening an open record is refused");
    assert!(matches!(err, UnknownActionError::ChangedUnderneath { .. }));
    assert!(
        err.to_string().contains("open at record revision 1"),
        "the refusal names the landed state: {err}"
    );
}

#[test]
fn reopening_a_stale_settlement_loses_naming_the_landed_settlement() {
    let record = coverage_record("a.dll", "F", "q", 100);
    let mut resolutions = UnknownResolutions::default();
    resolutions
        .resolve(&record, "established", 1, 150)
        .expect("settle at revision 1");
    // A fresh batch moved the record to revision 2 under the reviewer.
    let landed_at_2 = UnknownRecord {
        revision: 2,
        ..record.clone()
    };
    let err = resolutions
        .reopen(&landed_at_2)
        .expect_err("the reopen is stale against the landed revision");
    assert!(matches!(err, UnknownActionError::ChangedUnderneath { .. }));
    assert!(
        err.to_string().contains("resolved at record revision 1"),
        "the refusal names what the reviewer settled at: {err}"
    );
}

#[test]
fn a_resolution_entry_is_keyed_by_id_and_carries_its_four_fields() {
    let dir = tempfile::TempDir::new().expect("temp workspace");
    let record = coverage_record("a.dll", "F", "q", 100);
    let mut resolutions = UnknownResolutions::default();
    resolutions
        .dismiss(&record, "the shim contract says it away", 1, 1_700_000_000)
        .expect("dismiss");
    save_json(&unknown_resolutions_path(dir.path()), &resolutions).expect("resolutions file");
    let loaded: UnknownResolutions =
        load_json(&unknown_resolutions_path(dir.path())).expect("resolutions load");
    let entry = loaded
        .resolutions
        .get(&record.id)
        .expect("keyed by unknown id");
    assert_eq!(entry.disposition, UnknownDisposition::Dismissed);
    assert_eq!(entry.reason, "the shim contract says it away");
    assert_eq!(entry.expected_revision, 1);
    assert_eq!(entry.at, 1_700_000_000);
}

#[test]
fn a_resolution_without_its_reason_is_refused() {
    // The reason is required: an answer that never says its grounds
    // cannot land, at the boundary of the document itself.
    let err = serde_json::from_str::<UnknownResolution>(
        r#"{"disposition": "resolved", "expected_revision": 1, "at": 10}"#,
    )
    .expect_err("a reason-less entry must not deserialize");
    assert!(
        err.to_string().contains("reason"),
        "the refusal names the missing field: {err}"
    );
}

#[test]
fn a_blank_reason_is_refused_as_strictly_as_a_missing_one() {
    // Required means required: a whitespace-only reason is an answer
    // that says its grounds no better than no reason at all.
    let record = coverage_record("a.dll", "F", "q", 100);
    let mut resolutions = UnknownResolutions::default();
    let err = resolutions
        .dismiss(&record, "   ", 1, 200)
        .expect_err("a whitespace-only reason is no grounds");
    assert!(matches!(err, UnknownActionError::EmptyReason { .. }));
    assert!(
        err.to_string().contains(&record.id),
        "the refusal names the record: {err}"
    );
    assert!(resolutions.resolutions.is_empty(), "nothing landed");
}

#[test]
fn the_severity_scale_is_closed_and_its_blocking_level_is_the_done_claim_gate() {
    // Three levels, none a catch-all (issue #368). `blocking` means the
    // establishing evidence never arrived at all — the level a done
    // claim gates on — and every level has a criterion a producer can
    // honestly apply today.
    for label in ["notable", "material", "blocking"] {
        let parsed: UnknownSeverity = serde_json::from_str(&format!("\"{label}\""))
            .unwrap_or_else(|err| panic!("severity label `{label}` must be declared: {err}"));
        assert_eq!(
            serde_json::to_value(parsed).expect("severity writes"),
            *label
        );
        assert_eq!(parsed.to_string(), *label, "Display emits the same label");
    }
    assert!(
        serde_json::from_str::<UnknownSeverity>("\"devastating\"").is_err(),
        "the scale is closed: no producer can invent a fourth level"
    );
}

// --- two documents, two owners: the writers never clobber ----------------

#[test]
fn the_two_writers_never_clobber_each_others_documents() {
    // The store's whole-document replace makes the split load-bearing
    // (issue #368): a ledger write never touches reviewer intent, and a
    // reviewer write never touches the ledger.
    let dir = tempfile::TempDir::new().expect("temp workspace");
    let record = coverage_record("a.dll", "F", "q", 100);
    let ledger = UnknownLedger::file(
        "a.dll",
        None,
        std::slice::from_ref(&record),
        &BTreeMap::new(),
        100,
    );
    save_json(&unknown_ledger_path(dir.path(), &record.binary), &ledger).expect("file ledger");

    let mut resolutions = UnknownResolutions::default();
    resolutions
        .resolve(&record, "established", 1, 200)
        .expect("settle lands in the reviewer's document");
    save_json(&unknown_resolutions_path(dir.path()), &resolutions).expect("resolutions file");
    let reviewer_bytes =
        std::fs::read_to_string(unknown_resolutions_path(dir.path())).expect("resolutions read");

    // The batch re-files the ledger outright, twice.
    let refiled = UnknownLedger::file(
        "a.dll",
        Some(&ledger),
        &[coverage_record("a.dll", "F", "q", 500)],
        &resolutions.reopened,
        500,
    );
    save_json(&unknown_ledger_path(dir.path(), &record.binary), &refiled).expect("re-file ledger");
    save_json(
        &unknown_ledger_path(dir.path(), &record.binary),
        &UnknownLedger::file("a.dll", Some(&refiled), &[], &resolutions.reopened, 600),
    )
    .expect("re-file again with nothing derived");
    assert_eq!(
        std::fs::read_to_string(unknown_resolutions_path(dir.path())).expect("resolutions read"),
        reviewer_bytes,
        "the pipeline's whole-document replace never touches reviewer intent"
    );
    let ledger_bytes = std::fs::read_to_string(unknown_ledger_path(dir.path(), &record.binary))
        .expect("ledger read");

    // A reviewer cycle (settle, reopen, re-settle) never touches the
    // ledger bytes: a reopen's revision rides the next pipeline write,
    // never a reviewer write — so the landed record still stands at
    // revision 1 and a fresh re-settle lands.
    resolutions
        .reopen(&record)
        .expect("reopen in the reviewer's document");
    resolutions
        .dismiss(
            refiled.record(&record.id).expect("landed"),
            "not relevant",
            1,
            800,
        )
        .expect("the landed revision never moved, so the re-settle is fresh");
    assert_eq!(
        resolutions
            .resolution_for(&record.id)
            .expect("re-settled")
            .disposition,
        UnknownDisposition::Dismissed
    );
    save_json(&unknown_resolutions_path(dir.path()), &resolutions).expect("resolutions re-file");
    assert_eq!(
        std::fs::read_to_string(unknown_ledger_path(dir.path(), &record.binary))
            .expect("ledger read"),
        ledger_bytes,
        "the reviewer's whole-document replace never touches the ledger"
    );
}

// --- the join: open / resolved / dismissed, recomputed every read -------

#[test]
fn re_worded_admission_text_keeps_the_resolution_bound() {
    // The spine of the feature (issue #368): the reviewer answered the
    // gap, the engine re-worded its admission, and the answer is still
    // attached — id-stability is what makes review's work outlive the
    // wording that revealed the question.
    let mut resolutions = UnknownResolutions::default();
    let settled = coverage_record("a.dll", "F", "what is F doing?", 100);
    resolutions
        .resolve(&settled, "established by hand", 1, 150)
        .expect("settle at revision 1");

    let landed = UnknownLedger::file(
        "a.dll",
        None,
        std::slice::from_ref(&settled),
        &BTreeMap::new(),
        100,
    );
    let re_derived = UnknownLedger::file(
        "a.dll",
        Some(&landed),
        &[coverage_record(
            "a.dll",
            "F",
            "what is the re-worded question about F?",
            500,
        )],
        &resolutions.reopened,
        500,
    );
    let records = re_derived.records.expect("filed");
    assert_eq!(
        records[0].id, settled.id,
        "the re-worded record is the same gap"
    );
    let joined = resolutions.join(&records);
    assert_eq!(joined.len(), 1);
    assert_eq!(joined[0].disposition, EffectiveDisposition::Resolved);
    assert_eq!(
        joined[0].resolution.as_ref().expect("still bound").reason,
        "established by hand"
    );
}

#[test]
fn the_join_reads_open_resolved_and_dismissed_from_the_two_documents() {
    let open = coverage_record("a.dll", "Open", "q", 100);
    let resolved = coverage_record("a.dll", "Resolved", "q", 100);
    let dismissed = coverage_record("a.dll", "Dismissed", "q", 100);
    let mut resolutions = UnknownResolutions::default();
    resolutions
        .resolve(&resolved, "established", 1, 150)
        .expect("resolve");
    resolutions
        .dismiss(&dismissed, "not relevant", 1, 160)
        .expect("dismiss");
    let joined = resolutions.join(&[open, resolved, dismissed]);
    assert_eq!(
        joined.iter().map(|j| j.disposition).collect::<Vec<_>>(),
        vec![
            EffectiveDisposition::Open,
            EffectiveDisposition::Resolved,
            EffectiveDisposition::Dismissed,
        ],
        "the join keeps the ledger's own order"
    );
    assert!(
        joined[0].resolution.is_none(),
        "open is the absence of intent, never written"
    );
}

// --- the closed kind roster and the shared checker ----------------------

#[test]
fn the_declared_roster_is_exactly_the_labels_the_kind_set_serde_writes() {
    // The roster's strings and the enum's persisted labels are one set,
    // in one order: grepping a roster entry finds the label it writes.
    for label in DECLARED_UNKNOWN_KINDS {
        let parsed: UnknownKind = serde_json::from_str(&format!("\"{label}\""))
            .unwrap_or_else(|err| panic!("roster label `{label}` must be a declared kind: {err}"));
        assert_eq!(serde_json::to_value(parsed).expect("kind writes"), *label);
        assert_eq!(parsed.to_string(), *label, "Display emits the same label");
    }
    assert_eq!(
        DECLARED_UNKNOWN_KINDS.len(),
        6,
        "one kind per gap family — grow the set with a producer, never ahead of one"
    );
}

#[test]
fn the_roster_pairs_clean_against_a_clean_producer_set() {
    let produced = [
        ("coverage_facet", "typesdb#function-bodies"),
        ("analysis_family", "decompilation"),
        ("baseline_never_run", "cases-F"),
        ("export_uncovered", "export-DrawSprite"),
        ("retry_pruned", "escalate#decompilation"),
        ("tier_refused", "tier#module_context"),
    ];
    assert_eq!(
        unknown_roster_faults(DECLARED_UNKNOWN_KINDS, &produced),
        Vec::<String>::new(),
        "every declared kind paired with exactly one producer, every producer with a declared kind"
    );
}

#[test]
fn a_declared_kind_with_no_producer_fails_naming_itself() {
    let produced = [("coverage_facet", "typesdb#function-bodies")];
    let faults = unknown_roster_faults(DECLARED_UNKNOWN_KINDS, &produced);
    assert_eq!(
        faults,
        [
            "declared kind `analysis_family` has no producer",
            "declared kind `baseline_never_run` has no producer",
            "declared kind `export_uncovered` has no producer",
            "declared kind `retry_pruned` has no producer",
            "declared kind `tier_refused` has no producer",
        ],
        "every dead kind appears, each naming itself"
    );
}

#[test]
fn a_producer_naming_an_undeclared_kind_fails_naming_itself() {
    let produced = [("smokewood", "some#slot")];
    let faults = unknown_roster_faults(DECLARED_UNKNOWN_KINDS, &produced);
    assert!(
        faults
            .iter()
            .any(|f| f == "producer files `smokewood`, a kind the roster never declared"),
        "an invented kind fails loudly, naming itself: {faults:?}"
    );
}

#[test]
fn a_kind_produced_twice_from_one_source_slot_fails_naming_itself() {
    let produced = [
        ("coverage_facet", "typesdb#function-bodies"),
        ("coverage_facet", "typesdb#function-bodies"),
    ];
    let faults = unknown_roster_faults(&["coverage_facet"], &produced);
    assert_eq!(
        faults,
        ["kind `coverage_facet` is produced twice from source slot `typesdb#function-bodies`"],
        "the same gap emitted twice is a duplicate question, and it is named once"
    );
}

#[test]
fn the_same_kind_from_two_different_slots_is_no_fault() {
    let produced = [
        ("coverage_facet", "typesdb#function-bodies"),
        ("coverage_facet", "callback#function-bodies"),
        ("coverage_facet", "typesdb#data-objects"),
    ];
    assert_eq!(
        unknown_roster_faults(&["coverage_facet"], &produced),
        Vec::<String>::new()
    );
}

// --- record-tree locations, named and pinned ----------------------------

#[test]
fn the_two_documents_land_at_their_named_record_tree_locations() {
    // The ledger beside the record tree's owner directories; the
    // reviewer's document beside the skip set and the queue overlay.
    assert_eq!(
        unknown_ledger_path("/ws", &BinaryIdentity::new("eqmain.dll")),
        PathBuf::from("/ws")
            .join("re")
            .join("unknowns")
            .join("eqmain.dll.json")
    );
    assert_eq!(
        unknown_resolutions_path("/ws"),
        PathBuf::from("/ws")
            .join("re")
            .join("review")
            .join("unknown_resolutions.json")
    );
    // The JsonStore default naming and the pinned path agree, so the
    // batch's per-binary writer can use either.
    let store = JsonStore::<UnknownLedger>::new(unknown_ledger_dir("/ws"));
    assert_eq!(
        store.path_for("eqmain.dll"),
        unknown_ledger_path("/ws", &BinaryIdentity::new("eqmain.dll"))
    );
}

#[test]
fn the_three_ledger_readings_stay_distinct_on_the_unit_model_wire() {
    // Issue #376 honesty rule, pinned at the wire: unknown serializes as
    // `open: null` and never as an empty list; only the honest
    // known-and-none serializes the empty list; and a payload with no
    // `open` field at all deserializes to unknown, never zero.
    let unknown = UnitUnknowns::unknown();
    let json = serde_json::to_value(&unknown).expect("serialize unknown");
    assert!(json["open"].is_null(), "unknown rides as null");
    assert_eq!(json["open_by_severity"], serde_json::json!({}));

    let known_none = UnitUnknowns {
        open: Some(vec![]),
        ..UnitUnknowns::unknown()
    };
    let json = serde_json::to_value(&known_none).expect("serialize known-none");
    assert_eq!(json["open"], serde_json::json!([]), "none open rides as []");

    let back: UnitUnknowns = serde_json::from_str("{}").expect("bare object deserializes");
    assert!(
        back.open.is_none(),
        "absent open field is unknown, not zero"
    );
    assert_eq!(back.open_count(), None);

    let back: UnitUnknowns = serde_json::from_str(r#"{"open": null}"#).expect("null reads");
    assert!(
        back.open.is_none(),
        "an explicit null is the same unknown reading"
    );
}
