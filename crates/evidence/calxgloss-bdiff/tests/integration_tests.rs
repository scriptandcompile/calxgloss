//! Cross-module flow for the binary-version pairing crate (issues #295,
//! #296, and #297, part of track #233): two in-memory scan snapshots go
//! through the pairing pass, and the pairing document comes back
//! through the shared JSON store — documents in, pairing document out.
//! The crate makes no analysis-engine reads (ADR-0026), mutates no
//! program (ADR-0020), and runs no LLM anywhere.

use calxgloss_bdiff::{
    BdiffPersistor, CARRY_OVER_CONFIDENCE_FLOOR, FunctionEntry, MatchFamily, ScanSnapshot,
    TOPOLOGY_CONFIDENCE, pair_versions,
};
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
/// intact, internals renumbered by the rebuild in the new snapshot.
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
fn a_moved_internal_function_pairs_through_the_body_family() {
    // #296 end to end. The export and the demangled member still pair
    // through name identity. The moved internal — renamed FUN_
    // spelling, re-lettered variables, byte-equal normalized body —
    // pairs through the body family at 90 beside them, and the pairing
    // survives the persistor round trip.
    let mut old = old_snapshot();
    let mut new = new_snapshot();
    for entry in &mut old.functions {
        if entry.name == "FUN_10001200" {
            entry.body = "\
{
   uint uVar1;
   uVar1 = DAT_140045a68;
   if (uVar1 != 0) {
      FUN_10002200(uVar1);
   }
   return;
}"
            .into();
        }
    }
    for entry in &mut new.functions {
        if entry.name == "FUN_10009000" {
            entry.body = "\
{
   uint iVar4;
   iVar4 = DAT_140049a68;
   if (iVar4 != 0) {
      FUN_10002200(iVar4);
   }
   return;
}"
            .into();
        }
    }

    let document = pair_versions(&old, &new).expect("one binary identity");
    assert_eq!(document.pairings.len(), 3, "two name pairs, one body pair");
    let record = document
        .pairings
        .iter()
        .find(|record| record.old_function == "FUN_10001200")
        .expect("the moved internal pairs through the body family");
    assert_eq!(record.new_function, "FUN_10009000");
    assert_eq!(record.family, MatchFamily::NormalizedBody);
    assert_eq!(record.confidence.value(), 90);
    assert_eq!(
        record.evidence,
        ["normalized bodies are byte-equal (8 lines)"],
        "the body-family record carries its normalized-body evidence line"
    );

    let workspace = tempfile::tempdir().expect("temp workspace");
    let persistor = BdiffPersistor::new(workspace.path());
    persistor.save(&document).expect("the save should work");
    let loaded = persistor
        .load(&BdiffPersistor::key_for(
            "fixture.dll",
            &"a".repeat(64),
            &"b".repeat(64),
        ))
        .expect("the load should work");
    assert_eq!(loaded, document, "the body-family record round-trips whole");
}

#[test]
fn a_renamed_internal_pairs_through_the_call_graph_and_survives_the_round_trip() {
    // #297 end to end. The export and the demangled member still pair
    // by name, and this time the renamed internal pairs through the
    // call graph: both its callers are the name-paired functions, and
    // the call map built only from the snapshots' own bodies agrees on
    // the callee through them. The record sits below the carry-over
    // floor the consumer applies. The whole document round-trips
    // through the persistor, with the new family spelled
    // `call_topology`.
    let mut old = old_snapshot();
    let mut new = new_snapshot();
    for entry in &mut old.functions {
        match entry.name.as_str() {
            "fixture_init" | "Widget::render(void)" => {
                entry.body = "{\n\tFUN_10001200();\n}".into()
            }
            "FUN_10001200" => entry.body = "{\n\treturn;\n}".into(),
            _ => {}
        }
    }
    for entry in &mut new.functions {
        match entry.name.as_str() {
            "fixture_init" | "Widget::render(void)" => {
                entry.body = "{\n\tFUN_10009000();\n}".into()
            }
            "FUN_10009000" => {
                entry.body = "\
{
   uint uVar1;
   uVar1 = uVar1 + 1;
   uVar1 = uVar1 + 2;
   uVar1 = uVar1 + 3;
   uVar1 = uVar1 + 4;
   uVar1 = uVar1 + 5;
   uVar1 = uVar1 + 6;
   uVar1 = uVar1 + 7;
   uVar1 = uVar1 + 8;
   uVar1 = uVar1 + 9;
   return;
}"
                .into()
            }
            _ => {}
        }
    }

    let document = pair_versions(&old, &new).expect("one binary identity");
    assert_eq!(
        document
            .pairings
            .iter()
            .map(|record| (record.old_function.as_str(), record.new_function.as_str()))
            .collect::<Vec<_>>(),
        [
            ("fixture_init", "fixture_init"),
            ("Widget::render(void)", "Widget::render(void)"),
            ("FUN_10001200", "FUN_10009000"),
        ],
        "the renamed internal joins the two name pairs through the call graph"
    );
    let record = document
        .pairings
        .iter()
        .find(|record| record.family == MatchFamily::CallTopology)
        .expect("the topology record stands beside the name pairs");
    assert_eq!(record.confidence.value(), TOPOLOGY_CONFIDENCE);
    assert!(
        record.confidence.value() < CARRY_OVER_CONFIDENCE_FLOOR,
        "a topology claim on its own sits below the carry-over floor \
         the consumer applies"
    );
    assert_eq!(
        record.evidence,
        [
            "call-graph topology through 2 paired neighbors",
            "FUN_10001200 is called by paired neighbor fixture_init -> fixture_init",
            "FUN_10001200 is called by paired neighbor Widget::render(void) -> Widget::render(void)",
        ],
        "the record names the paired neighbors it stood on"
    );

    let workspace = tempfile::tempdir().expect("temp workspace");
    let persistor = BdiffPersistor::new(workspace.path());
    persistor.save(&document).expect("the save should work");
    let loaded = persistor
        .load(&BdiffPersistor::key_for(
            "fixture.dll",
            &"a".repeat(64),
            &"b".repeat(64),
        ))
        .expect("the load should work");
    assert_eq!(loaded, document, "the topology record round-trips whole");
    assert_eq!(loaded.pairings[2].family, MatchFamily::CallTopology);
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
