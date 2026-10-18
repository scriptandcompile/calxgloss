//! The data-structure-recovery pass over the Kuna engine (issue #207, part
//! of epic #203).
//!
//! Kuna synthesizes each type's category from its own kind, so every bucket
//! membership the scanner sees is suspect and the layout probes must confirm
//! it — the fallback the scanner documents, engaged rather than assumed.
//! The probe answers and the probe misses arrive in the same vocabulary the
//! Ghidra bridge uses, so the scanner branches on one fact whichever engine
//! answers.

use calxgloss_decomp::{EngineError, ScanSource};
use calxgloss_kuna::KunaSource;
use calxgloss_typesdb::scanner::TypeLibraryScanner;
use calxgloss_typesdb::types::TypeKind;

fn fixture_source() -> KunaSource {
    let fixture = calxgloss_testfixtures::load_target()
        .expect("the fixture target builds and validates from the integration tests");
    KunaSource::load(fixture.path()).expect("the fixture must load for scanning with Kuna")
}

#[tokio::test]
async fn the_recovery_pass_recovers_probe_confirmed_types_under_kuna() {
    let scanner = TypeLibraryScanner::with_source(fixture_source());
    let recovered = scanner
        .scan_named_types()
        .await
        .expect("the recovery pass runs under kuna");

    // The engine's own analysis has interned the Windows and MSVCRT
    // structures the fixture's imports imply, so there is bucket
    // membership to recover — and because Kuna's category is the kind word
    // itself, every membership is suspect and the layout probe confirms it.
    assert!(
        !recovered.is_empty(),
        "the fixture implies named types to recover"
    );
    let found = |name: &str| recovered.iter().find(|entry| entry.name == name);

    // Confirmed by probe: the layout answered, so the kind is established
    // from the fields, not from the category.
    let iobuf = found("_iobuf").expect("the engine interns _iobuf for msvcrt's streams");
    assert_eq!(iobuf.kind, TypeKind::Struct);
    assert!(
        !iobuf.fields.is_empty(),
        "the layout probe should have carried the fields: {iobuf:?}"
    );

    // Graceful fallback: a union has no layout endpoint to confirm it, so
    // the scanner keeps the bucket's kind from the listing rather than
    // dropping the type or claiming a structure for it.
    let fpreg = found("__pformat_fpreg_t").expect("the engine interns the pformat union");
    assert_eq!(fpreg.kind, TypeKind::Union);
    assert!(
        fpreg.fields.is_empty(),
        "a recovered union carries no fields it did not answer: {fpreg:?}"
    );
}

#[tokio::test]
async fn probe_misses_arrive_in_the_engine_vocabulary_under_kuna() {
    let source = fixture_source();

    // An unknown name is a NotFound, the same fact the bridge reports for a
    // type its Type Manager does not know.
    // `KunaSource` carries inherent engine-native methods beside the trait
    // ones, so these calls name the trait to reach the seam — the path the
    // scanner itself takes — and its Ghidra-shaped errors.
    let missing = ScanSource::struct_layout(&source, "no_such_type_anywhere")
        .await
        .expect_err("an unknown type name is a named miss");
    assert!(
        matches!(
            &missing,
            EngineError::NotFound { kind, query }
                if *kind == "type" && query == "no_such_type_anywhere"
        ),
        "expected the bridge's NotFound, got {missing:?}"
    );

    // A kind mismatch is a Malformed, exactly as the bridge answers a
    // structure probe against a non-structure. Both shapes are the misses
    // the scanner's probe fallback branches on.
    let mismatch = ScanSource::struct_layout(&source, "int4")
        .await
        .expect_err("a builtin is not a structure");
    assert!(
        matches!(&mismatch, EngineError::Malformed { kind, .. } if *kind == "structure layout"),
        "expected the bridge's Malformed, got {mismatch:?}"
    );
    let enum_mismatch = ScanSource::enum_values(&source, "int4")
        .await
        .expect_err("a builtin is not an enumeration");
    assert!(
        matches!(&enum_mismatch, EngineError::Malformed { kind, .. } if *kind == "enumeration"),
        "expected the bridge's Malformed, got {enum_mismatch:?}"
    );
}
