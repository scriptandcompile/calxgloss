//! The Kuna engine behind the `TypeWriteSource` seam, end to end (issue
//! #209, part of epic #203).
//!
//! These tests drive the seam itself — `TypeWriteSource` over
//! `KunaSource`, read back through `ScanSource` — over the checked-in
//! fixture DLL: a write compiles to a directive that changes what the
//! seam's own reads answer, the directive file persists in the record of
//! effort and replays on a fresh load, and misses arrive in the Ghidra
//! path's error vocabulary. The engine-native API is pinned in
//! `calxgloss-kuna/tests/kuna_write_back.rs`.
//!
//! Both seams are RPITIT traits, not dyn-compatible, so the calls below
//! name the trait explicitly (`TypeWriteSource::…(&source, …)`) — that
//! also forces the seam's mapping rather than the source's inherent
//! method of the same name.

use calxgloss_ghidra::{GhidraError, NewStructField, ScanSource, TypeWriteSource};
use calxgloss_kuna::KunaSource;
use calxgloss_kuna::directives::directive_file_path;
use calxgloss_testfixtures::TARGET_FILE_NAME;

/// The loader's spelling of a fixture name: MinGW COFF symbols carry a
/// leading underscore, so the listing may report `_fixture_tick` where
/// the export table says `fixture_tick`.
fn loader_name(raw: &str) -> String {
    raw.trim_start_matches('_').to_string()
}

/// A Kuna source loaded with its directive plane at the canonical
/// record-of-effort location under `workspace`, replayed from any file
/// already there.
fn source_with_plane(workspace: &std::path::Path) -> KunaSource {
    let fixture = calxgloss_testfixtures::load_target()
        .expect("fixture target should build and validate from the integration tests");
    let file = directive_file_path(workspace, fixture.path());
    KunaSource::load_with_directives(fixture.path(), Some(&file))
        .expect("the fixture must load with Kuna")
}

/// The fixture export named `name`, through the seam's own listing.
async fn exported(source: &KunaSource, name: &str) -> calxgloss_ghidra::FunctionSummary {
    let listing = ScanSource::functions(source)
        .await
        .expect("the function listing should be readable");
    listing
        .into_iter()
        .find(|f| loader_name(&f.name) == name)
        .unwrap_or_else(|| panic!("`{name}` should be in the function listing"))
}

#[tokio::test]
async fn a_prototype_written_through_the_seam_round_trips_and_replays() {
    let dir = tempfile::tempdir().expect("temp dir");

    {
        let source = source_with_plane(dir.path());

        let tick = exported(&source, "fixture_tick").await;
        let before = ScanSource::decompile(&source, &tick.name)
            .await
            .expect("fixture_tick should decompile");
        assert!(
            !before.signature.contains("uint4"),
            "before the write the return should be undeclared:\n{}",
            before.signature
        );

        TypeWriteSource::set_function_prototype(
            &source,
            tick.address,
            "unsigned int fixture_tick(void)",
        )
        .await
        .expect("the seam should accept the prototype write");

        let after = ScanSource::decompile(&source, &tick.name)
            .await
            .expect("fixture_tick should decompile after the write");
        assert!(
            after.signature.contains("uint4"),
            "the seam's decompile should render the written prototype:\n{}",
            after.signature
        );
    }

    // The record of effort holds the directive, and a fresh load replays
    // it: the seam answers the round trip again with no write call.
    let fixture = calxgloss_testfixtures::load_target()
        .expect("fixture target should build and validate from the integration tests");
    let file = directive_file_path(dir.path(), fixture.path());
    assert!(file.ends_with(format!("{TARGET_FILE_NAME}.kuna")));
    let text = std::fs::read_to_string(&file).expect("the directive file should persist");
    assert!(
        text.contains("prototype 0x") && text.contains("unsigned int fixture_tick(void)"),
        "the write should be recorded in Kuna's directive syntax:\n{text}"
    );

    let source = source_with_plane(dir.path());
    let tick = exported(&source, "fixture_tick").await;
    let after = ScanSource::decompile(&source, &tick.name)
        .await
        .expect("fixture_tick should decompile after the replay");
    assert!(
        after.signature.contains("uint4"),
        "the replayed prototype should change the decompile:\n{}",
        after.signature
    );
}

#[tokio::test]
async fn a_struct_written_through_the_seam_survives_a_reload() {
    let dir = tempfile::tempdir().expect("temp dir");

    {
        let source = source_with_plane(dir.path());

        TypeWriteSource::create_struct(&source, "RECT", &[NewStructField::new("left", "long")])
            .await
            .expect("the seam should accept the struct create");
        TypeWriteSource::add_struct_field(&source, "RECT", "top", "long", None)
            .await
            .expect("the seam should accept the field addition");

        // The live session keeps the created body: Kuna refuses to re-body
        // a completed record, so the regenerated record waits for replay.
        let layout = ScanSource::struct_layout(&source, "RECT")
            .await
            .expect("the created struct should answer through the seam");
        let names: Vec<&str> = layout
            .fields
            .iter()
            .map(|f| f.field_name.as_str())
            .collect();
        assert_eq!(
            names,
            vec!["left"],
            "the live struct keeps its created body"
        );
    }

    // A fresh load replays the ONE regenerated record: the seam sees both
    // fields, in order, without any write call.
    let source = source_with_plane(dir.path());
    let layout = ScanSource::struct_layout(&source, "RECT")
        .await
        .expect("the replayed struct should answer through the seam");
    let names: Vec<&str> = layout
        .fields
        .iter()
        .map(|f| f.field_name.as_str())
        .collect();
    assert_eq!(
        names,
        vec!["left", "top"],
        "the replayed struct carries both fields"
    );
}

#[tokio::test]
async fn seam_refusals_arrive_in_the_ghidra_path_error_vocabulary() {
    let dir = tempfile::tempdir().expect("temp dir");
    let source = source_with_plane(dir.path());

    // A function that is not there is the same named NotFound the Ghidra
    // path reports — the Kuna fold, not a new error shape.
    let error =
        TypeWriteSource::set_function_prototype(&source, 0xdead_beef, "int no_such_function(void)")
            .await
            .expect_err("a prototype at a missing function's address must be refused");
    assert!(
        matches!(&error, GhidraError::NotFound { kind, query }
            if *kind == "function" && query == "0xdeadbeef"),
        "expected the seam's NotFound, got {error:?}"
    );

    let error = TypeWriteSource::add_struct_field(&source, "NO_SUCH", "x", "int", None)
        .await
        .expect_err("a field on a missing struct must be refused");
    assert!(
        matches!(&error, GhidraError::NotFound { kind, query }
            if *kind == "type" && query == "NO_SUCH"),
        "expected the seam's NotFound, got {error:?}"
    );

    // Nothing was recorded: every refusal happened before the plane.
    let fixture = calxgloss_testfixtures::load_target()
        .expect("fixture target should build and validate from the integration tests");
    let file = directive_file_path(dir.path(), fixture.path());
    assert!(
        !file.exists(),
        "refused writes must not reach the directive file"
    );

    // And the read side still answers — the refusals left the session clean.
    let tick = exported(&source, "fixture_tick").await;
    assert!(tick.address > 0);
}
