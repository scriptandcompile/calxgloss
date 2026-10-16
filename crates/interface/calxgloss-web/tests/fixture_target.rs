//! The fixture target binary must be reachable from the web e2e harness.
//!
//! The spawn-server tests gain a scan run with `engine = kuna` against this
//! fixture, so the fixture's dev-dependency wiring into this crate is
//! pinned here: the built DLL and its validated shape must be reachable
//! from the web harness's own test binary.

#[test]
fn fixture_target_is_reachable_from_the_web_harness() {
    let target = calxgloss_testfixtures::load_target()
        .expect("fixture target should build and validate from the web harness");
    assert!(
        target
            .path()
            .ends_with(calxgloss_testfixtures::TARGET_FILE_NAME),
        "the fixture target should be a real file the scan pipeline can open"
    );
    assert!(
        target.image_base() != 0,
        "the fixture should declare an image base the scan can report"
    );
}
