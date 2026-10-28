//! The fixture target binary must be reachable from the Integrations
//! integration tests.
//!
//! The analysis engine tests drive the same `drive_all<S: ScanSource>`
//! seam harness over this fixture that `integration_tests.rs` runs over
//! canned and stand-in sources. So the fixture's dev-dependency wiring
//! and shape are pinned here: a later ticket asserts seam behavior
//! against `load_target()` without building the DLL by hand.

#[test]
fn fixture_target_is_reachable_and_valid() {
    let target = calxgloss_testfixtures::load_target()
        .expect("fixture target should build and validate from the integration tests");
    assert!(
        target
            .exports()
            .iter()
            .all(|export| export.starts_with("fixture_")),
        "every fixture export should be a fixture_ function"
    );
    assert!(
        target.jump_table().entries >= calxgloss_testfixtures::MIN_JUMP_TABLE_ENTRIES,
        "the fixture should carry the jump table the engine tests assert against"
    );
}
