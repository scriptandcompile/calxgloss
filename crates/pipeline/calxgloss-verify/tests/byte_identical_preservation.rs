//! What the verify stage preserves, byte for byte (the rebuilt pipeline
//! suite).
//!
//! The guarantee this suite pins: the scaffolded scratch project is
//! deterministic — two runs of one translation stand byte-identical — and
//! the translated function's source survives the scaffold unmodified, even
//! when the translation does not compile. The stub text that rides into
//! every scaffold is call-stable too.
//!
//! Three of these tests scaffold and `cargo check` a real scratch project;
//! they follow this crate's convention of hiding compile-backed tests
//! behind `#[ignore]`:
//!
//! ```text
//! cargo test -p calxgloss-verify --test byte_identical_preservation -- --ignored
//! ```

use std::path::{Path, PathBuf};

use calxgloss_verify::{Stubs, Verifier, sanitize_crate_name, sanitize_identifier};

/// The translation under test: comment alignment, unicode, and odd
/// whitespace all deliberate, because preservation means *these bytes*,
/// not an equivalent rendering.
const TRANSLATION: &str = concat!(
    "// Ünïcode comment —   aligned    oddly\n",
    "pub fn fixture_add(x: i32, y: i32) -> i32 {\n",
    "    //  nested   comment   spacing\n",
    "    x + y   // trailing spaces kept: ",
    "\t\n",
    "}\n",
);

/// The marker the scaffold writes immediately before the translated body.
const BODY_MARKER: &str = "// ===== Translated function =====\n\n";

/// The stub text rendered into every scaffold is byte-identical call to
/// call, and non-empty.
#[test]
fn the_stub_text_is_byte_identical_call_to_call() {
    let first = Stubs::all();
    let second = Stubs::all();
    assert_eq!(first, second, "two renders of the stub text match exactly");
    assert!(!first.is_empty(), "the stub text carries the stub content");
}

/// The name sanitizers are stable call to call and idempotent — feeding a
/// sanitized name back in changes nothing, so project names cannot drift
/// between runs.
#[test]
fn the_name_sanitizers_are_stable_and_idempotent() {
    for name in [
        "eqmain.dll",
        "Game_Logic.dll",
        "weird name!",
        "Fixture.Target-DLL",
    ] {
        let once = sanitize_crate_name(name);
        assert_eq!(
            once,
            sanitize_crate_name(name),
            "sanitize_crate_name is stable for {name}"
        );
        assert_eq!(
            once,
            sanitize_crate_name(&once),
            "sanitize_crate_name is idempotent for {name}"
        );
        let ident = sanitize_identifier(name);
        assert_eq!(
            ident,
            sanitize_identifier(&ident),
            "sanitize_identifier is idempotent for {name}"
        );
    }
}

/// The scaffolded lib.rs is exactly the fixed prologue plus the
/// translation's own bytes — the body survives unmodified, with no
/// reformatting between the marker and the end of file.
#[tokio::test]
#[ignore = "scaffolds and cargo-checks a scratch project"]
async fn the_translated_body_survives_the_scaffold_byte_for_byte() {
    let work = tempfile::tempdir().expect("temp work dir");
    let verifier = Verifier::new(work.path()).expect("verifier");
    verifier
        .compile("fixture_target.dll", "fixture_add", TRANSLATION)
        .await
        .expect("the compile check runs");

    let lib_rs = std::fs::read_to_string(scratch_project(work.path()).join("src/lib.rs"))
        .expect("the scaffolded lib.rs");
    let body = lib_rs
        .split_once(BODY_MARKER)
        .expect("the scaffold marks the translated function")
        .1;
    assert_eq!(body, TRANSLATION, "the body stands exactly as written");
}

/// Two separate runs of one translation scaffold byte-identical projects:
/// Cargo.toml and src/lib.rs match across the runs, so a verification
/// rerun never silently re-renders the code under review.
#[tokio::test]
#[ignore = "scaffolds and cargo-checks a scratch project"]
async fn two_scaffolds_of_one_translation_are_byte_identical() {
    let run_a = tempfile::tempdir().expect("first work dir");
    let run_b = tempfile::tempdir().expect("second work dir");

    for dir in [run_a.path(), run_b.path()] {
        Verifier::new(dir)
            .expect("verifier")
            .compile("fixture_target.dll", "fixture_add", TRANSLATION)
            .await
            .expect("the compile check runs");
    }

    for file in ["Cargo.toml", "src/lib.rs"] {
        let a = read_scratch_file(run_a.path(), file);
        let b = read_scratch_file(run_b.path(), file);
        assert_eq!(
            a, b,
            "{file} stands byte-identical across two scaffold runs"
        );
    }
}

/// A translation that does not compile is preserved just the same: the
/// scaffold carries its bytes unmodified even while the checker reports
/// failure, so review sees exactly what was sent, not what survived the
/// compiler.
#[tokio::test]
#[ignore = "scaffolds and cargo-checks a scratch project"]
async fn a_failing_translation_is_still_preserved_byte_for_byte() {
    const BROKEN: &str = "pub fn broken() -> i32 {\n    \"not an int\"   // kept verbatim\n}\n";

    let work = tempfile::tempdir().expect("temp work dir");
    let verifier = Verifier::new(work.path()).expect("verifier");
    let result = verifier
        .compile("fixture_target.dll", "broken", BROKEN)
        .await
        .expect("the compile check runs");
    assert!(
        !result.success,
        "the checker reports the broken translation as failing"
    );

    let lib_rs = std::fs::read_to_string(scratch_project(work.path()).join("src/lib.rs"))
        .expect("the scaffolded lib.rs");
    let body = lib_rs
        .split_once(BODY_MARKER)
        .expect("the scaffold marks the translated function")
        .1;
    assert_eq!(
        body, BROKEN,
        "the failing translation still stands verbatim"
    );
}

/// The one scaffolded scratch project under a verifier's work dir.
fn scratch_project(work: &Path) -> PathBuf {
    let scratch = work.join("scratch");
    let projects: Vec<PathBuf> = std::fs::read_dir(&scratch)
        .expect("the verifier created its scratch directory")
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| path.join("src/lib.rs").is_file())
        .filter(|path| path.file_name().map(|n| n != "pal").unwrap_or(false))
        .collect();
    assert!(
        projects.len() == 1,
        "one compile, one scratch project, got {projects:?}"
    );
    projects.into_iter().next().expect("the scaffolded project")
}

fn read_scratch_file(work: &Path, relative: &str) -> Vec<u8> {
    std::fs::read(scratch_project(work).join(relative)).expect("the scaffolded file exists")
}
