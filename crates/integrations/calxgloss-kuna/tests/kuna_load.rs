//! The Kuna engine load path over the checked-in fixture target (issue #205).
//!
//! The fixture DLL is the shape contract the whole epic asserts against;
//! these tests pin that the pinned Kuna build can open it in-process, that
//! the identity the later scan tickets will key on is reported, and that an
//! unloadable target fails by name with the `--engine ghidra` fallback
//! spelled out rather than as an upstream backtrace.

use calxgloss_kuna::KunaError;

#[test]
fn the_fixture_target_loads_and_reports_its_identity() {
    let fixture = calxgloss_testfixtures::load_target()
        .expect("fixture target should build and validate from the integration tests");
    let program = calxgloss_kuna::load(fixture.path()).expect("the fixture must load with Kuna");
    let identity = program.identity().to_string();
    assert!(
        identity.contains("x86") && identity.contains("64"),
        "identity should name the x86-64 language, got {identity}"
    );
    assert!(
        program.entry().is_some(),
        "a PE entry point should be reported for {identity}"
    );
    assert!(
        program.num_symbols() > 0,
        "the loader should collect function symbols for {identity}"
    );
}

#[test]
fn an_unloadable_target_fails_by_name_naming_the_ghidra_fallback() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("not-a-binary.dll");
    std::fs::write(&path, b"just text, not a PE").expect("write the junk file");

    let error = calxgloss_kuna::load(&path).expect_err("text is not loadable");
    assert!(
        matches!(error, KunaError::LoadFailed { .. }),
        "expected a named load failure, got {error:?}"
    );
    let message = error.to_string();
    assert!(
        message.contains(&path.display().to_string()),
        "the failure should name the path: {message}"
    );
    assert!(
        message.contains("--engine ghidra"),
        "the failure should name the fallback: {message}"
    );
}
