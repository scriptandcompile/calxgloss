//! The web harness's end-to-end scan under `engine = kuna` (issue #212,
//! part of epic #203). The spawn-server harness gets one scan run against
//! the checked-in fixture target. Its analysis engine is built the way an
//! `analysis.engine = kuna` run builds it — the `PipelineSource::Kuna`
//! arm, loaded in this process, with no Ghidra process behind it. The scan
//! record saved in the record-of-effort layout names its analysis engine.
//!
//! The seam itself is pinned in `calxgloss-decomp/tests/kuna_scan.rs`. This
//! test pins the contract the web's pipeline reads: one scan run through
//! the seam, one saved record, and the record naming the Kuna engine, the
//! release it is pinned to, and the pinned source fingerprint (issue #208's
//! provenance) — written to disk and read back.

use calxgloss_decomp::PipelineSource;
use calxgloss_kuna::{KUNA_PIN_REV, KUNA_RELEASE, KunaSource};
use calxgloss_testfixtures::TARGET_FILE_NAME;
use calxgloss_typesdb::engine::TypesDBEngine;
use calxgloss_typesdb::persist::TypeDatabasePersistor;

/// The analysis engine an `analysis.engine = kuna` run selects: the seam's
/// Kuna arm over the fixture target, loaded in this process — no server, no
/// JVM, no auto-analysis.
fn kuna_pipeline_source() -> PipelineSource {
    let fixture = calxgloss_testfixtures::load_target()
        .expect("fixture target should build and validate from the web harness");
    PipelineSource::Kuna(
        KunaSource::load(fixture.path()).expect("the fixture must load for scanning with Kuna"),
    )
}

#[tokio::test]
async fn a_kuna_scan_run_persists_a_record_naming_its_engine_provenance() {
    let source = kuna_pipeline_source();
    let workspace = tempfile::tempdir().expect("web workspace");

    // One scan run through the seam: the same type-database recovery the
    // live pipeline runs before its first batch. The Kuna arm refuses the
    // vtable-method tag write (issue #209's directive plane writes types,
    // not Ghidra-era program tags), and the scan tolerates that — tagging is
    // enrichment, not detection — so the run completes on seam reads alone.
    let db = TypesDBEngine::with_source(source)
        .scan(TARGET_FILE_NAME)
        .await
        .expect("the scan runs under engine = kuna");

    // The scan really did read through the Kuna engine: the fixture's
    // imports imply named structures, and the recovery pass adds them to
    // the database. An empty database would pass the provenance asserts
    // below while proving nothing about the seam.
    assert!(
        db.named_types.iter().any(|t| t.name == "_iobuf"),
        "the scan recovered the types the fixture implies, got {:?}",
        db.named_types.iter().map(|t| &t.name).collect::<Vec<_>>()
    );

    // Persist the way the pipeline does: the record-of-effort layout the
    // web server serves, `re/analysis/typesdb/{binary}.json`.
    let persistor = TypeDatabasePersistor::new(workspace.path());
    persistor.save(&db).expect("the scan record persists");

    // The acceptance check, read off disk as raw JSON: the saved scan
    // record names the analysis engine, the release it is pinned to, and
    // the pinned source fingerprint — the provenance issue #208 stamps.
    let raw = std::fs::read_to_string(persistor.path_for(TARGET_FILE_NAME))
        .expect("the scan record is on disk");
    let json: serde_json::Value = serde_json::from_str(&raw).expect("the scan record is JSON");
    let engine = &json["metadata"]["engine"];
    assert_eq!(engine["name"], "kuna", "the record names its engine: {raw}");
    assert_eq!(
        engine["version"], KUNA_RELEASE,
        "the record names the Kuna release it ran, derived from the lockfile pin"
    );
    assert_eq!(
        engine["fingerprint"], KUNA_PIN_REV,
        "the record names the pinned source fingerprint the engine was built from"
    );

    // And the record reads back whole through the production persistor —
    // the shape every consumer above the seam sees.
    let back = persistor
        .load(TARGET_FILE_NAME)
        .expect("the record reads back");
    assert_eq!(back.metadata.binary, TARGET_FILE_NAME);
    assert!(back.metadata.scanned_at > 0, "the record stamps its time");
    let provenance = back.metadata.engine.expect("the record names its engine");
    assert_eq!(provenance.name, "kuna");
    assert_eq!(provenance.version.as_deref(), Some(KUNA_RELEASE));
    assert_eq!(provenance.fingerprint.as_deref(), Some(KUNA_PIN_REV));
}
