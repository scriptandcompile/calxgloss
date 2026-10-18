//! The Kuna source's write-back plane over the checked-in fixture target
//! (issue #209, part of epic #203).
//!
//! These tests drive `KunaSource`'s inherent write API against the fixture
//! DLL: each write compiles to a directive that takes effect in the live
//! session (the round trip: write, re-decompile, see the new signature),
//! the directive file persists in the record of effort and replays on a
//! fresh load, and a struct field addition regenerates the owning typedef
//! record rather than appending a patch. The seam itself
//! (`impl TypeWriteSource for KunaSource`) is exercised in
//! `calxgloss-decomp/tests/kuna_write_back.rs`, beside every other seam test.

use calxgloss_kuna::KunaError;
use calxgloss_kuna::KunaNewField;
use calxgloss_kuna::directives::directive_file_path;
use calxgloss_kuna::source::KunaSource;
use calxgloss_testfixtures::TARGET_FILE_NAME;

/// The loader's spelling of a fixture name: MinGW COFF symbols carry a
/// leading underscore, so the listing may report `_fixture_tick` where the
/// export table says `fixture_tick`.
fn loader_name(raw: &str) -> String {
    raw.trim_start_matches('_').to_string()
}

/// A source loaded with its directive plane at the canonical record-of-
/// effort location under `workspace`, replayed from any file already there.
async fn source_with_plane(workspace: &std::path::Path) -> KunaSource {
    let fixture = calxgloss_testfixtures::load_target()
        .expect("fixture target should build and validate from the integration tests");
    let file = directive_file_path(workspace, fixture.path());
    KunaSource::load_with_directives(fixture.path(), Some(&file))
        .expect("the fixture must load with Kuna")
}

/// The fixture export named `name`, by its loader spelling.
async fn exported(source: &KunaSource, name: &str) -> calxgloss_kuna::KunaFunction {
    let listing = source
        .list_functions()
        .await
        .expect("the function listing should be readable");
    listing
        .into_iter()
        .find(|f| loader_name(&f.name) == name)
        .unwrap_or_else(|| panic!("`{name}` should be in the function listing"))
}

#[tokio::test]
async fn a_prototype_write_round_trips_in_the_live_session() {
    let dir = tempfile::tempdir().expect("temp dir");
    let source = source_with_plane(dir.path()).await;

    // The fixture's tick takes nothing and returns nothing declared: the
    // decompiler's first answer is an `undefined` return.
    let tick = exported(&source, "fixture_tick").await;
    let before = source
        .decompile_function(&tick.name)
        .await
        .expect("fixture_tick should decompile");
    assert!(
        before.signature.contains("fixture_tick") && !before.signature.contains("uint4"),
        "before the write the return should be undeclared:\n{}",
        before.signature
    );

    source
        .set_function_prototype(tick.address, "unsigned int fixture_tick(void)")
        .await
        .expect("the prototype write should be accepted");

    let after = source
        .decompile_function(&tick.name)
        .await
        .expect("fixture_tick should decompile after the write");
    assert!(
        after.signature.contains("uint4") && after.signature.contains("fixture_tick"),
        "after the write the decompile signature should carry the new prototype:\n{}",
        after.signature
    );

    // The engine applied the directive rather than rejecting it.
    let fates = source
        .directive_fates()
        .await
        .expect("the directive fates should be readable");
    assert!(
        fates
            .iter()
            .any(|f| f.directive.contains("prototype") && f.status == "applied"),
        "the prototype directive should report as applied: {fates:?}"
    );
}

#[tokio::test]
async fn the_directive_file_persists_and_replays_on_a_fresh_load() {
    let dir = tempfile::tempdir().expect("temp dir");

    {
        let source = source_with_plane(dir.path()).await;
        let tick = exported(&source, "fixture_tick").await;
        source
            .set_function_prototype(tick.address, "unsigned int fixture_tick(void)")
            .await
            .expect("the prototype write should be accepted");
        source
            .create_typedef("ULONG", "unsigned long")
            .await
            .expect("the typedef write should be accepted");
    }

    // The record of effort holds the directives as Kuna's own line text.
    let fixture = calxgloss_testfixtures::load_target()
        .expect("fixture target should build and validate from the integration tests");
    let file = directive_file_path(dir.path(), fixture.path());
    assert!(file.ends_with(format!("{TARGET_FILE_NAME}.kuna")));
    let text = std::fs::read_to_string(&file).expect("the directive file should persist");
    assert!(
        text.contains("prototype 0x") && text.contains("unsigned int fixture_tick(void)"),
        "the prototype should be recorded in Kuna's directive syntax:\n{text}"
    );
    assert!(
        text.contains("typedef typedef unsigned long ULONG;"),
        "the typedef should be recorded in the doubled form the grammar wants:\n{text}"
    );

    // A fresh load replays the file: the prototype is visible again without
    // any write call, and the engine reports both directives as applied.
    let source = source_with_plane(dir.path()).await;
    let tick = exported(&source, "fixture_tick").await;
    let after = source
        .decompile_function(&tick.name)
        .await
        .expect("fixture_tick should decompile after the replay");
    assert!(
        after.signature.contains("uint4"),
        "the replayed prototype should change the decompile:\n{}",
        after.signature
    );
    let fates = source
        .directive_fates()
        .await
        .expect("the directive fates should be readable");
    assert_eq!(
        fates.len(),
        2,
        "both replayed directives should have a fate: {fates:?}"
    );
    assert!(
        fates.iter().all(|f| f.status == "applied"),
        "the replayed directives should apply cleanly: {fates:?}"
    );
}

#[tokio::test]
async fn a_struct_field_addition_regenerates_the_owning_record() {
    let dir = tempfile::tempdir().expect("temp dir");

    {
        let source = source_with_plane(dir.path()).await;
        source
            .create_struct("RECT", &[KunaNewField::new("left", "long")])
            .await
            .expect("the struct create should be accepted");
        source
            .add_struct_field("RECT", "top", "long", None)
            .await
            .expect("the field addition should be accepted");

        // The live session keeps the old body: Kuna refuses to re-body a
        // completed record, so the regenerated record waits for the replay.
        let layout = source
            .struct_layout("RECT")
            .await
            .expect("the struct layout should be readable");
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

    // The directive file holds ONE regenerated record, not a create plus
    // a field patch.
    let fixture = calxgloss_testfixtures::load_target()
        .expect("fixture target should build and validate from the integration tests");
    let file = directive_file_path(dir.path(), fixture.path());
    let text = std::fs::read_to_string(&file).expect("the directive file should persist");
    assert!(
        text.contains("typedef struct RECT { long left; long top; };"),
        "the record should be the regenerated whole-struct declaration:\n{text}"
    );
    assert_eq!(
        text.lines().filter(|line| line.contains("RECT")).count(),
        1,
        "one create plus one field add must leave exactly one RECT record:\n{text}"
    );

    // A fresh load replays the record: the struct is there with both fields.
    let source = source_with_plane(dir.path()).await;
    let layout = source
        .struct_layout("RECT")
        .await
        .expect("the replayed struct layout should be readable");
    let names: Vec<&str> = layout
        .fields
        .iter()
        .map(|f| f.field_name.as_str())
        .collect();
    assert_eq!(
        names,
        vec!["left", "top"],
        "the replayed struct should carry both fields"
    );
}

#[tokio::test]
async fn enum_and_typedef_writes_are_visible_and_a_local_type_reaches_the_decompile() {
    let dir = tempfile::tempdir().expect("temp dir");
    let source = source_with_plane(dir.path()).await;

    source
        .create_enum("COLOR", &[("RED", 0), ("GREEN", 1)], 2)
        .await
        .expect("the enum create should be accepted");
    source
        .create_typedef("HANDLE", "void *")
        .await
        .expect("the typedef write should be accepted");

    let found = source
        .enum_values("COLOR")
        .await
        .expect("the created enum should be interned and answer members");
    assert_eq!(
        found.size, 2,
        "the seam's width became the fixed underlying type"
    );
    let members: Vec<(&str, i64)> = found
        .members
        .iter()
        .map(|m| (m.name.as_str(), m.value))
        .collect();
    assert_eq!(members, vec![("RED", 0), ("GREEN", 1)]);

    // A local-type write may name the new typedef and validates against it.
    // The decompiler names fixture_status's recovered parameter `a0`, and the
    // engine refuses a retype that changes the parameter's width — so the
    // typedef aliases the 4-byte type the parameter already carries.
    let status = exported(&source, "fixture_status").await;
    source
        .create_typedef("STATUS_CODE", "unsigned int")
        .await
        .expect("the typedef write should be accepted");
    source
        .set_local_variable_type(status.address, "a0", "STATUS_CODE")
        .await
        .expect("the local type write should be accepted");
    let body = source
        .decompile_function(&status.name)
        .await
        .expect("fixture_status should decompile after the local write");
    assert!(
        body.signature.contains("STATUS_CODE") || body.body.contains("STATUS_CODE"),
        "the re-decompile should render the new local type:\n{}\n{}",
        body.signature,
        body.body
    );

    // The engine's own report shows the local directive was reached.
    let fates = source
        .directive_fates()
        .await
        .expect("the directive fates should be readable");
    let local = fates
        .iter()
        .find(|f| f.directive.starts_with("type "))
        .expect("the local-type directive should have a fate");
    assert_eq!(
        local.status, "applied",
        "the decompile loop should have applied the type directive: {fates:?}"
    );
}

#[tokio::test]
async fn writes_to_targets_that_are_not_there_are_refused_by_name() {
    let dir = tempfile::tempdir().expect("temp dir");
    let source = source_with_plane(dir.path()).await;
    let absent = 0xdead_beef_u64;

    let error = source
        .set_function_prototype(absent, "int no_such_function(void)")
        .await
        .expect_err("a prototype at a missing function's address must be refused");
    assert!(
        matches!(&error, KunaError::FunctionNotFound { name } if name == "0xdeadbeef"),
        "expected a named function refusal, got {error:?}"
    );

    let error = source
        .set_local_variable_type(absent, "param_1", "int")
        .await
        .expect_err("a local type in a missing function must be refused");
    assert!(
        matches!(&error, KunaError::FunctionNotFound { name } if name == "0xdeadbeef"),
        "expected a named function refusal, got {error:?}"
    );

    let tick = exported(&source, "fixture_tick").await;
    let error = source
        .set_function_prototype(tick.address, "int fixture_tick(")
        .await
        .expect_err("an unparseable declaration must be refused");
    assert!(
        matches!(&error, KunaError::DirectiveRejected { directive, .. }
            if directive.contains("int fixture_tick(")),
        "expected a named declaration refusal, got {error:?}"
    );

    let error = source
        .set_local_variable_type(tick.address, "param_1", "int missing(")
        .await
        .expect_err("an unparseable type must be refused");
    assert!(
        matches!(&error, KunaError::DirectiveRejected { directive, .. }
            if directive == "int missing("),
        "expected a named type refusal, got {error:?}"
    );

    // A struct the plane holds no record for cannot be re-bodied.
    let error = source
        .add_struct_field("NO_SUCH", "x", "int", None)
        .await
        .expect_err("a field on a missing struct must be refused");
    assert!(
        matches!(&error, KunaError::TypeNotFound { name } if name == "NO_SUCH"),
        "expected a named type miss, got {error:?}"
    );

    // Nothing was recorded: every refusal happened before the plane persisted.
    let fixture = calxgloss_testfixtures::load_target()
        .expect("fixture target should build and validate from the integration tests");
    let file = directive_file_path(dir.path(), fixture.path());
    assert!(
        !file.exists(),
        "refused writes must not reach the directive file"
    );
}
