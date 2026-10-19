//! The Kuna source's core scan reads over the checked-in fixture target
//! (issue #206, part of epic #203).
//!
//! These tests drive `KunaSource`'s inherent API — the Kuna-native answers
//! the seam maps — over the fixture DLL: the function listing, decompile by
//! name, the import and export tables, and the image base. The seam itself
//! (`impl ScanSource for KunaSource`) is exercised in
//! `calxgloss-decomp/tests/kuna_scan.rs`, beside every other seam test.

use calxgloss_kuna::KunaError;
use calxgloss_kuna::source::KunaSource;
use calxgloss_testfixtures::{EXPORT_NAMES, IMPORT_FUNCTIONS, TARGET_FILE_NAME};

/// The loader's spelling of a fixture name: MinGW COFF symbols carry a
/// leading underscore, so the listing may report `_fixture_init` where the
/// export table says `fixture_init`.
fn loader_name(raw: &str) -> String {
    raw.trim_start_matches('_').to_string()
}

/// The listing's entry whose loader name matches `want`, for a readable
/// failure that shows what the listing actually answered.
fn listed<'a>(
    listing: &'a [calxgloss_kuna::KunaFunction],
    want: &str,
) -> Option<&'a calxgloss_kuna::KunaFunction> {
    listing
        .iter()
        .find(|function| loader_name(&function.name) == want)
}

fn fixture_source() -> KunaSource {
    let fixture = calxgloss_testfixtures::load_target()
        .expect("fixture target should build and validate from the integration tests");
    KunaSource::load(fixture.path()).expect("the fixture must load for scanning with Kuna")
}

#[tokio::test]
async fn the_function_listing_answers_with_the_fixture_functions() {
    let source = fixture_source();
    let functions = source.list_functions().await.expect("functions read");

    for want in EXPORT_NAMES {
        assert!(
            listed(&functions, want).is_some(),
            "the listing should carry the fixture export {want}, got {:?}",
            functions.iter().map(|f| &f.name).collect::<Vec<_>>(),
        );
    }
    // Kuna's synthetic import placeholders (addresses invented for call
    // naming) are filtered out of the listing. What does legitimately
    // appear is a named import *thunk* — MinGW emits real `jmp [__imp_x]`
    // veneers in `.text`, and the engine names them for what they are:
    // defined code in the image, the same functions Ghidra lists as thunks.
    // Addresses are in-image virtual addresses, not synthetic slots.
    for function in &functions {
        assert!(
            function.address > 0,
            "every listed function has an entry address: {function:?}",
        );
    }
}

#[tokio::test]
async fn decompile_answers_with_a_signature_and_a_body_for_a_fixture_function() {
    let source = fixture_source();
    let functions = source.list_functions().await.expect("functions read");
    let tick = listed(&functions, "fixture_tick").expect("fixture_tick is listed");

    let decompiled = source
        .decompile_function(&tick.name)
        .await
        .expect("the listed name must decompile");
    assert_eq!(decompiled.name, tick.name, "the answer names its function");
    assert!(
        !decompiled.signature.is_empty(),
        "the prototype line is the signature"
    );
    assert!(
        !decompiled.signature.ends_with(';'),
        "the seam's signature carries no trailing semicolon: {}",
        decompiled.signature,
    );
    assert!(
        decompiled.signature.contains("fixture_tick"),
        "the signature names the function: {}",
        decompiled.signature,
    );
    assert!(
        !decompiled.body.trim().is_empty(),
        "the pseudo-C body is not empty"
    );
}

#[tokio::test]
async fn an_unknown_function_name_fails_by_name() {
    let source = fixture_source();
    let error = source
        .decompile_function("no_such_function_anywhere")
        .await
        .expect_err("an unknown name is a named miss, not an empty answer");
    assert!(
        matches!(error, KunaError::FunctionNotFound { .. }),
        "expected a named miss, got {error:?}"
    );
    assert!(
        error.to_string().contains("no_such_function_anywhere"),
        "the failure names the missing function: {error}"
    );
}

#[tokio::test]
async fn the_disassembly_listing_answers_real_listing_text_for_a_fixture_function() {
    // Issue #245: the engine-native disassembly read over the fixture DLL.
    // The rows are the engine's own listing — an address column, then the
    // lifter's uppercase SLEIGH mnemonics with `0x` hex operands — and a
    // miss is the same named failure a decompile answers with.
    let source = fixture_source();
    let functions = source.list_functions().await.expect("functions read");
    let tick = listed(&functions, "fixture_tick").expect("fixture_tick is listed");

    let text = source
        .disassemble_function(&tick.name)
        .await
        .expect("the listed name must disassemble");
    assert!(
        !text.trim().is_empty(),
        "a listed function body lists instructions"
    );
    for line in text.lines() {
        let (address, instruction) = line
            .split_once("  ")
            .unwrap_or_else(|| panic!("rows carry an address column: {line}"));
        assert!(
            !address.is_empty() && address.chars().all(|c| c.is_ascii_hexdigit()),
            "the address column is the vma in hex: {line}"
        );
        let mnemonic = instruction.split_whitespace().next().unwrap_or(instruction);
        assert!(
            !mnemonic.is_empty() && mnemonic.to_uppercase() == *mnemonic,
            "the mnemonic is the lifter's uppercase spelling: {line}"
        );
    }
    // The fixture is an x64 PE: the listing spells its registers the
    // 64-bit way and its constants in 0x hex.
    assert!(
        text.contains("RSP"),
        "an x64 body spells its stack register RSP: {text}"
    );
    assert!(text.contains("0x"), "constants carry 0x hex: {text}");

    let error = source
        .disassemble_function("no_such_function_anywhere")
        .await
        .expect_err("an unknown name is a named miss, not an empty listing");
    assert!(
        matches!(error, KunaError::FunctionNotFound { .. }),
        "expected a named miss, got {error:?}"
    );
}

#[tokio::test]
async fn the_import_and_export_tables_and_the_image_base_answer_from_the_fixture() {
    let source = fixture_source();

    let imports = source.list_imports().await.expect("imports read");
    for want in IMPORT_FUNCTIONS {
        assert!(
            imports.iter().any(|i| loader_name(&i.name) == *want),
            "the import table should carry {want}, got {:?}",
            imports.iter().map(|i| &i.name).collect::<Vec<_>>(),
        );
    }
    assert!(
        imports.iter().all(|i| i.imported),
        "every import-table entry is an import",
    );

    let exports = source.list_exports().await.expect("exports read");
    for want in EXPORT_NAMES {
        let export = exports
            .iter()
            .find(|e| loader_name(&e.name) == *want)
            .unwrap_or_else(|| {
                panic!(
                    "the export table should carry {want}, got {:?}",
                    exports.iter().map(|e| &e.name).collect::<Vec<_>>(),
                )
            });
        assert!(!export.imported, "an export-table entry is not an import");
        assert!(export.address > 0, "an export has an in-image address");
    }

    let base = source.image_base().await.expect("image base read");
    assert!(
        base > 0,
        "a PE image base is reported for {TARGET_FILE_NAME}"
    );
    for export in &exports {
        assert!(
            export.address >= base,
            "export {} at {:#x} sits at or above the base {base:#x}",
            export.name,
            export.address,
        );
    }
}

#[tokio::test]
async fn one_source_answers_from_exactly_one_target_binary() {
    // One handle loaded one path, and every read answers
    // from that one program — a wrong-program mix-up is structurally
    // impossible.
    let fixture = calxgloss_testfixtures::load_target()
        .expect("fixture target should build and validate from the integration tests");
    let source = fixture_source();
    assert_eq!(source.path(), fixture.path(), "the handle names its target");
    assert!(
        source.identity().contains("x86") && source.identity().contains("64"),
        "the identity is the loaded program's: {}",
        source.identity(),
    );

    // A clone shares the same program — not a second load of anything.
    let clone = source.clone();
    assert_eq!(clone.path(), source.path());
    assert_eq!(clone.identity(), source.identity());
    let base = clone.image_base().await.expect("clone reads");
    assert!(base > 0);
}

#[tokio::test]
async fn a_source_that_cannot_load_hands_back_no_handle() {
    // The engine thread exits with the load failure and no handle exists to
    // read through — the only way to ask a question is through a handle, so
    // a dead program is unreachable by construction. What is observable is
    // the failure itself: the same named load failure the plain loader
    // reports, naming the path and Kuna's own reason.
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("not-a-binary.dll");
    std::fs::write(&path, b"just text, not a PE").expect("write the junk file");
    let error = KunaSource::load(&path).expect_err("text is not loadable");
    assert!(
        matches!(error, KunaError::LoadFailed { .. }),
        "a failed scan-load is the same named load failure, got {error:?}"
    );
    assert!(
        error.to_string().contains(&path.display().to_string()),
        "the failure names the unloadable path: {error}"
    );
}
