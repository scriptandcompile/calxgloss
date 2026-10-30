//! Smoke test for the fixture target binary.
//!
//! Asserts the built fixture has the shape every Kuna engine test relies
//! on — exports, imports, strings, and a jump table — so later tickets can
//! assert against the fixture without re-building it by hand. The fixture
//! crate's `load_target` already validates each element with a named error;
//! this test is the gate that fires when the fixture source or the compiler
//! stops producing that shape.

use calxgloss_testfixtures::{
    EXPORT_NAMES, IMPORT_DLL_NAMES, IMPORT_FUNCTIONS, MIN_JUMP_TABLE_ENTRIES,
    PLAIN_TARGET_FILE_NAME, STRING_LITERALS, TARGET_FILE_NAME, fixture_target_path, load_target,
    plain_target_path,
};

#[test]
fn fixture_target_is_built_and_reachable() {
    let path = fixture_target_path().expect("build script should have compiled the fixture target");
    assert!(path.ends_with(TARGET_FILE_NAME));
    let size = path
        .metadata()
        .expect("fixture target should be readable")
        .len();
    assert!(size > 0, "fixture target should not be empty");
}

#[test]
fn fixture_target_has_named_exports() {
    let target = load_target().expect("fixture target should load");
    let mut exports: Vec<&str> = target.exports().iter().map(String::as_str).collect();
    exports.sort_unstable();
    let mut expected = EXPORT_NAMES.to_vec();
    expected.sort_unstable();
    assert_eq!(
        exports, expected,
        "fixture target should export exactly the named functions"
    );
}

#[test]
fn fixture_target_imports_from_two_dlls() {
    let target = load_target().expect("fixture target should load");
    for dll in IMPORT_DLL_NAMES {
        assert!(
            target
                .imports()
                .iter()
                .any(|import| import.dll.eq_ignore_ascii_case(dll)),
            "fixture target should import from {dll}"
        );
    }
    for function in IMPORT_FUNCTIONS {
        assert!(
            target
                .imports()
                .iter()
                .any(|import| import.function == *function),
            "fixture target should import {function}"
        );
    }
}

#[test]
fn fixture_target_carries_string_literals() {
    let target = load_target().expect("fixture target should load");
    assert_eq!(
        target.strings().len(),
        STRING_LITERALS.len(),
        "every fixture string literal should be present in the image"
    );
}

#[test]
fn fixture_target_has_a_jump_table() {
    let target = load_target().expect("fixture target should load");
    let table = target.jump_table();
    assert_eq!(
        table.section, ".rdata",
        "the jump table should live in a read-only data section"
    );
    assert!(
        table.entries >= MIN_JUMP_TABLE_ENTRIES,
        "jump table should have at least {MIN_JUMP_TABLE_ENTRIES} entries, found {}",
        table.entries
    );
    assert!(table.rva > 0, "jump table should have a mapped RVA");
}

#[test]
fn plain_fixture_target_has_exports_but_no_import_table() {
    // The P22 trace gate needs a target with nothing to interpose on, to
    // prove an absent import table is a reported, survivable condition.
    let path = plain_target_path().expect("build script should have compiled the plain fixture");
    assert!(path.ends_with(PLAIN_TARGET_FILE_NAME));
    let bytes = std::fs::read(&path).expect("plain fixture should be readable");
    let pe = goblin::pe::PE::parse(&bytes).expect("plain fixture should be a PE");
    assert!(pe.is_lib, "plain fixture should be a DLL");
    assert!(
        pe.imports.is_empty(),
        "plain fixture must not import anything: {:?}",
        pe.imports.iter().map(|i| &i.name).collect::<Vec<_>>()
    );
    let exports: Vec<&str> = pe.exports.iter().filter_map(|e| e.name).collect();
    assert!(
        exports.contains(&"plain_add"),
        "plain fixture should export plain_add: {exports:?}"
    );
}
