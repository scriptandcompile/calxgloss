//! Record-seam pins for the obligation ledger (issue #417): the doctrine
//! lives at the document boundary — deserializers, the filing envelope, the
//! closure digest, and the missing-versus-corrupt readings.

use super::*;
use crate::persist::save_json;

#[test]
fn the_declared_case_kind_roster_is_exactly_the_labels_serde_writes() {
    // The roster's strings and the enum's persisted labels are one set,
    // in one order: grepping a roster entry finds the label it writes.
    for label in DECLARED_CASE_KINDS {
        let parsed: CaseKind = serde_json::from_str(&format!("\"{label}\""))
            .unwrap_or_else(|err| panic!("roster label `{label}` must be a declared kind: {err}"));
        assert_eq!(serde_json::to_value(parsed).expect("kind writes"), *label);
        assert_eq!(parsed.to_string(), *label, "Display emits the same label");
    }
    assert_eq!(
        DECLARED_CASE_KINDS.len(),
        3,
        "the case-kind roster is closed at three kinds"
    );
}

#[test]
fn an_invented_case_kind_refuses_at_the_deserializer() {
    // Closed means closed: no producer conjures a fourth kind of try.
    let err = serde_json::from_str::<CaseKind>("\"surprising\"")
        .expect_err("an undeclared case kind is refused");
    assert!(
        err.to_string().contains("surprising"),
        "the refusal names the invented kind: {err}"
    );
}

#[test]
fn the_declared_disposition_roster_is_exactly_the_labels_serde_writes() {
    // Same pairing as the case kinds: one set, one order, Display and
    // serde writing the identical label.
    for label in DECLARED_DISPOSITIONS {
        let parsed: ObligationDisposition = serde_json::from_str(&format!("\"{label}\""))
            .unwrap_or_else(|err| {
                panic!("roster label `{label}` must be a declared disposition: {err}")
            });
        assert_eq!(
            serde_json::to_value(parsed).expect("disposition writes"),
            *label
        );
        assert_eq!(parsed.to_string(), *label, "Display emits the same label");
    }
    assert_eq!(
        DECLARED_DISPOSITIONS.len(),
        6,
        "the disposition roster is closed at six names"
    );
}

#[test]
fn an_invented_disposition_refuses_at_the_deserializer() {
    // No free-text status exists anywhere: a fourth way of being "kind of
    // done" is refused, not folded in.
    let err = serde_json::from_str::<ObligationDisposition>("\"sort_of_done\"")
        .expect_err("an undeclared disposition is refused");
    assert!(
        err.to_string().contains("sort_of_done"),
        "the refusal names the invented disposition: {err}"
    );
}

#[test]
fn every_obligation_entry_requires_all_three_declared_case_kinds() {
    // Decided with the spec (issue #417): until a later track narrows
    // requirements by signature, each unit obligation demands the whole
    // closed roster — a suite that never tried a malformed input cannot
    // close it.
    let entry = ObligationEntry::new(
        "DrawSprite",
        2,
        "deadbeefcafe",
        ObligationDisposition::NoBaseline,
    );
    let written = serde_json::to_value(&entry).expect("entry writes");
    assert_eq!(
        written["required_case_kinds"],
        serde_json::json!(["positive", "negative", "malformed"]),
        "a fresh obligation names every declared case kind"
    );
}

#[test]
fn a_document_without_its_filing_envelope_is_not_a_filed_ledger() {
    // The envelope — which binary it was filed for and when — is what
    // lets a reader tell a filed document from a stray one.
    let err = serde_json::from_str::<ObligationLedger>(r#"{"entries": []}"#)
        .expect_err("an envelope-less document is refused");
    assert!(
        err.to_string().contains("binary"),
        "the refusal names the missing envelope field: {err}"
    );
    let err = serde_json::from_str::<ObligationLedger>(
        r#"{"binary": "game_logic.dll", "entries": [], "digest": "sha256:00"}"#,
    )
    .expect_err("a document missing its filing time is refused");
    assert!(
        err.to_string().contains("filed_at"),
        "the refusal names the missing filing time: {err}"
    );
}

/// Three obligations for one binary, in the writer's scan order, built
/// through the entry constructor so the fixture rides the real shape.
fn scan_order_entries() -> Vec<ObligationEntry> {
    let mut claimed = ObligationEntry::new(
        "DrawSprite",
        1,
        "aaaa1111",
        ObligationDisposition::ClaimedVerified,
    );
    claimed.receipt_digest = Some("sha256:9f0e12".to_string());
    vec![
        claimed,
        ObligationEntry::new(
            "DrawSprite",
            2,
            "bbbb2222",
            ObligationDisposition::UnReviewed,
        ),
        ObligationEntry::new(
            "UpdateHUD",
            1,
            "cccc3333",
            ObligationDisposition::NoBaseline,
        ),
    ]
}

/// The one filed ledger the digest tests read from — same binary, same
/// scan order, one filing time.
fn filed_obligation_ledger() -> ObligationLedger {
    ObligationLedger::file("game_logic.dll", scan_order_entries(), 1_730_000_000)
        .expect("plain records always serialize")
}

#[test]
fn the_closure_digest_ignores_write_order_and_changes_with_any_content_edit() {
    // The digest is the records' identity, not the writer's convenience:
    // handing the same entries in at another order seals the same digest,
    // and no content edit keeps it.
    let filed = filed_obligation_ledger();
    assert!(
        filed.digest.starts_with("sha256:"),
        "the digest names its algorithm"
    );

    let mut shuffled = scan_order_entries();
    shuffled.reverse();
    let refilled = ObligationLedger::file("game_logic.dll", shuffled, 1_730_000_000)
        .expect("plain records always serialize");
    assert_eq!(
        refilled.digest, filed.digest,
        "the same records in another write order seal the same digest"
    );

    let mut edited = scan_order_entries();
    edited[2].disposition = ObligationDisposition::Skipped;
    let edited_ledger = ObligationLedger::file("game_logic.dll", edited, 1_730_000_000)
        .expect("plain records always serialize");
    assert_ne!(
        edited_ledger.digest, filed.digest,
        "a changed disposition seals a different digest"
    );
}

#[test]
fn a_refiling_of_unchanged_records_at_a_later_time_seals_the_same_digest() {
    // Successive batches diff by digest to see what moved (issue #392,
    // story 25): the filing time never rides the digest, so unchanged
    // records keep their seal across rebuilds.
    let morning = filed_obligation_ledger();
    let evening = ObligationLedger::file("game_logic.dll", scan_order_entries(), 1_730_003_600)
        .expect("plain records always serialize");
    assert_eq!(
        evening.digest, morning.digest,
        "unchanged records refiled later seal the same digest"
    );
    assert_eq!(
        evening.binary,
        BinaryIdentity::new("game_logic.dll"),
        "the envelope still names its binary"
    );
    assert_eq!(
        evening.filed_at, 1_730_003_600,
        "the envelope still states when"
    );
}

#[test]
fn the_digest_field_never_rides_its_own_digest_and_a_reader_re_derives_it() {
    // Same content under any stored digest string re-derives the same
    // digest — the fold is the content's identity, not a stored label.
    let filed = filed_obligation_ledger();
    let mut blanked = filed.clone();
    blanked.digest = String::new();
    assert_eq!(
        filed.content_digest().expect("serializes"),
        blanked.content_digest().expect("serializes"),
        "the digest field itself never rides its own digest"
    );

    // The filed-bytes leg: a reader who never saw the writer parses the
    // written document and re-derives the same digest from it alone.
    let written = serde_json::to_string(&filed).expect("serializes");
    let read_back: ObligationLedger = serde_json::from_str(&written).expect("the filed bytes read");
    assert_eq!(
        read_back.content_digest().expect("folds"),
        filed.digest,
        "the digest re-derives from the filed bytes alone"
    );
}

#[test]
fn a_filed_ledger_round_trips_through_its_record_tree_path() {
    // The filing seam is the shared JSON store at the documented path:
    // what a writer files, a later reader loads whole — envelope,
    // entries, and stamped digest — and re-derives the digest from the
    // filed bytes.
    let workspace = tempfile::TempDir::new().expect("temp workspace");
    let binary = BinaryIdentity::new("game_logic.dll");
    let filed = filed_obligation_ledger();
    save_json(&obligation_ledger_path(workspace.path(), &binary), &filed).expect("files");

    let loaded =
        read_obligation_ledger(workspace.path(), &binary).expect("the filed document reads");
    assert_eq!(loaded, filed, "envelope, entries, and digest ride intact");
    assert_eq!(
        loaded.content_digest().expect("folds"),
        loaded.digest.clone(),
        "the reader's re-derived digest equals the stamped one"
    );
}

#[test]
fn a_missing_ledger_reads_as_recomputable_missing_and_corrupt_bytes_as_tampered() {
    // The established missing-versus-corrupt split (issue #417): no
    // document at all is a recompute-the-ledger state, while corrupt
    // bytes are a loud failure — never either way a reading of clean.
    let workspace = tempfile::TempDir::new().expect("temp workspace");
    let binary = BinaryIdentity::new("game_logic.dll");
    let err =
        read_obligation_ledger(workspace.path(), &binary).expect_err("nothing has been filed");
    assert!(
        matches!(err, PersistError::NotFound { .. }),
        "absence is recomputable-missing: {err}"
    );

    let path = obligation_ledger_path(workspace.path(), &binary);
    std::fs::create_dir_all(path.parent().expect("ledger dir")).expect("create re/obligations");
    std::fs::write(&path, "{ not json").expect("corrupt the document");
    let err = read_obligation_ledger(workspace.path(), &binary)
        .expect_err("a corrupt document fails loudly");
    assert!(
        matches!(err, PersistError::Json { .. }),
        "corrupt is corrupt: {err}"
    );
}

#[test]
fn a_content_edit_under_a_stale_digest_refuses_at_the_reader() {
    // "A tampered or replaced ledger reads as an input error, never as a
    // clean run": the reader re-derives the digest from the filed bytes
    // and refuses on mismatch, so editing the entries without resealing
    // cannot pass the reader holding the old seal.
    let workspace = tempfile::TempDir::new().expect("temp workspace");
    let binary = BinaryIdentity::new("game_logic.dll");
    let path = obligation_ledger_path(workspace.path(), &binary);
    save_json(&path, &filed_obligation_ledger()).expect("files");

    let mut tampered: ObligationLedger =
        serde_json::from_str(&std::fs::read_to_string(&path).expect("filed bytes"))
            .expect("parses");
    tampered.entries[0].disposition = ObligationDisposition::Skipped;
    save_json(&path, &tampered).expect("rewrite keeps the stale stamped digest");

    let err = read_obligation_ledger(workspace.path(), &binary)
        .expect_err("the re-derived digest refuses the edit");
    assert!(
        matches!(err, PersistError::Json { .. }),
        "a tampered ledger is corrupt, never a reading: {err}"
    );
}

#[test]
fn a_replaced_ledger_from_another_binary_refuses_at_the_reader() {
    // The envelope is the reader's replaced-document check: a validly
    // sealed ledger for one binary, filed under another binary's name,
    // refuses — its seal is intact but it speaks for the wrong binary.
    let workspace = tempfile::TempDir::new().expect("temp workspace");
    let binary = BinaryIdentity::new("game_logic.dll");
    let other = ObligationLedger::file("other.dll", scan_order_entries(), 1_730_000_000)
        .expect("plain records always serialize");
    save_json(&obligation_ledger_path(workspace.path(), &binary), &other).expect("misfiled");

    let err = read_obligation_ledger(workspace.path(), &binary)
        .expect_err("the envelope must name the asked-for binary");
    assert!(
        matches!(err, PersistError::Json { .. }) && err.to_string().contains("other.dll"),
        "the refusal names the binary the document actually speaks for: {err}"
    );
}

#[test]
fn an_entry_that_drops_a_declared_case_kind_refuses_at_the_deserializer() {
    // "Every unit obligation requires all three case kinds": closed at
    // the deserializer, so a suite cannot quietly close an obligation by
    // never requiring a malformed try. A later track narrowing by
    // signature extends this shape rather than relaxing it silently.
    let mut entry = serde_json::to_value(ObligationEntry::new(
        "DrawSprite",
        1,
        "aaaa1111",
        ObligationDisposition::NoBaseline,
    ))
    .expect("entry writes");
    entry["required_case_kinds"] = serde_json::json!(["positive", "negative"]);
    let err = serde_json::from_value::<ObligationEntry>(entry)
        .expect_err("an obligation requiring only part of the roster is refused");
    assert!(
        err.to_string().contains("malformed"),
        "the refusal names the dropped case kind: {err}"
    );
}

#[test]
fn a_claimed_verified_entry_with_no_receipt_citation_refuses_at_the_deserializer() {
    // "A verifier-receipt-digest citation wherever the unit claims
    // green": a green claim with no cited receipt is an invalid value,
    // refused at the deserializer like an invented one — never quietly
    // read as a pass.
    let entry = serde_json::to_value(ObligationEntry::new(
        "DrawSprite",
        1,
        "aaaa1111",
        ObligationDisposition::ClaimedVerified,
    ))
    .expect("entry writes");
    let err = serde_json::from_value::<ObligationEntry>(entry)
        .expect_err("a green claim with no cited receipt is refused");
    assert!(
        err.to_string().contains("receipt"),
        "the refusal names the missing citation: {err}"
    );
}
