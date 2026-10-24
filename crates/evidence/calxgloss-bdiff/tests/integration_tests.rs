//! Cross-module flow for the binary-version pairing crate (issue #295,
//! part of track #233): two in-memory scan snapshots go through the
//! pairing pass and the pairing document comes back through the shared
//! JSON persistor plumbing — documents in, pairing document out, with
//! no engine reads (ADR-0026), no program mutation (ADR-0020), and no
//! LLM anywhere in the crate.

use calxgloss_bdiff::{BdiffPersistor, FunctionEntry, MatchFamily, ScanSnapshot, pair_versions};
use calxgloss_types::BinaryIdentity;

/// One listed function, body naming itself so "unrelated bodies" reads
/// honestly in the fixtures.
fn function(name: &str, address: u64) -> FunctionEntry {
    FunctionEntry {
        name: name.into(),
        address,
        body: format!("// body of {name}"),
    }
}

/// One version's snapshot: the old build of the fixture DLL, exports
/// intact, internals renumbered by the rebuild.
fn old_snapshot() -> ScanSnapshot {
    ScanSnapshot {
        binary: BinaryIdentity::new("fixture.dll"),
        bytes_sha256: "a".repeat(64),
        functions: vec![
            function("fixture_init", 0x1000),
            function("Widget::render(void)", 0x1100),
            function("FUN_10001200", 0x1200),
        ],
        exports: vec!["fixture_init".into()],
    }
}

/// The new build: the same export at a new address, the same demangled
/// member at a new address, one moved internal whose `FUN_…` spelling
/// changed, and one genuinely new function.
fn new_snapshot() -> ScanSnapshot {
    ScanSnapshot {
        binary: BinaryIdentity::new("fixture.dll"),
        bytes_sha256: "b".repeat(64),
        functions: vec![
            function("FUN_10009000", 0x9000),
            function("fixture_init", 0x4000),
            function("Widget::render(void)", 0x4100),
            function("brand_new", 0x5000),
        ],
        exports: vec!["fixture_init".into(), "brand_new".into()],
    }
}

#[test]
fn the_pairing_pass_round_trips_one_document_through_the_shared_plumbing() {
    let document = pair_versions(&old_snapshot(), &new_snapshot()).expect("one binary identity");

    let workspace = tempfile::tempdir().expect("temp workspace");
    let persistor = BdiffPersistor::new(workspace.path());
    persistor.save(&document).expect("the save should work");

    let key = BdiffPersistor::key_for("fixture.dll", &"a".repeat(64), &"b".repeat(64));
    assert!(
        persistor.exists(&key),
        "the persisted document is the cache"
    );
    let loaded = persistor.load(&key).expect("the load should work");
    assert_eq!(loaded, document, "the document round-trips whole");
    assert_eq!(loaded.old_bytes_sha256, "a".repeat(64));
    assert_eq!(loaded.new_bytes_sha256, "b".repeat(64));
}

#[test]
fn name_identity_pairs_the_named_functions_and_silences_the_rest() {
    let document = pair_versions(&old_snapshot(), &new_snapshot()).expect("one binary identity");

    let paired: Vec<(&str, &str)> = document
        .pairings
        .iter()
        .map(|record| (record.old_function.as_str(), record.new_function.as_str()))
        .collect();
    assert_eq!(
        paired,
        [
            ("fixture_init", "fixture_init"),
            ("Widget::render(void)", "Widget::render(void)")
        ],
        "the export and the demangled member pair in old scan order; the \
         moved internal's FUN_ spelling and the new function claim nothing"
    );
    for record in &document.pairings {
        assert_eq!(record.family, MatchFamily::NameIdentity);
        assert_eq!(record.confidence.value(), 95);
        assert!(
            !record.evidence.is_empty(),
            "every pairing names its evidence"
        );
    }
}

#[test]
fn the_document_carries_both_listings_so_the_unpaired_sides_are_nameable() {
    // The CLI review command (#300) lists old-only and new-only
    // functions straight off the document: the listings minus paired.
    let document = pair_versions(&old_snapshot(), &new_snapshot()).expect("one binary identity");

    let paired_old: Vec<&str> = document
        .pairings
        .iter()
        .map(|r| r.old_function.as_str())
        .collect();
    let paired_new: Vec<&str> = document
        .pairings
        .iter()
        .map(|r| r.new_function.as_str())
        .collect();
    let old_only: Vec<&str> = document
        .old_functions
        .iter()
        .map(String::as_str)
        .filter(|name| !paired_old.contains(name))
        .collect();
    let new_only: Vec<&str> = document
        .new_functions
        .iter()
        .map(String::as_str)
        .filter(|name| !paired_new.contains(name))
        .collect();
    assert_eq!(old_only, ["FUN_10001200"]);
    assert_eq!(new_only, ["FUN_10009000", "brand_new"]);
}
