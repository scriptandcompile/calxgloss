//! The Kuna engine behind the `ScanSource` seam, end to end (issue #206,
//! part of epic #203).
//!
//! These tests drive the seam itself — `ScanSource` through
//! `PipelineSource::Kuna` — over the checked-in fixture DLL: the five core
//! reads answer from the one in-process program, the eight reads Kuna does
//! not answer yet fail by name naming issue #207 and the `--engine ghidra`
//! fallback, and a scan assembled purely from seam reads persists
//! `FunctionInfo` and `DllInfo` records the web's artifact layout reads
//! back. The engine-native API is pinned in
//! `calxgloss-kuna/tests/kuna_scan.rs`.

use calxgloss_ghidra::{GhidraError, PipelineSource, ScanSource};
use calxgloss_kuna::KunaSource;
use calxgloss_testfixtures::{EXPORT_NAMES, IMPORT_DLL_NAMES, IMPORT_FUNCTIONS, TARGET_FILE_NAME};
use calxgloss_types::{
    BinaryIdentity, DllCategory, DllInfo, Export, FunctionInfo, Import, analysis_dir, load_json,
    save_json,
};

/// The loader's spelling of a fixture name: MinGW COFF symbols carry a
/// leading underscore, so the listing may report `_fixture_init` where the
/// export table says `fixture_init`.
fn loader_name(raw: &str) -> String {
    raw.trim_start_matches('_').to_string()
}

/// The fixture loaded for scanning, wrapped as the pipeline's Kuna source.
fn fixture_pipeline_source() -> PipelineSource {
    let fixture = calxgloss_testfixtures::load_target()
        .expect("fixture target should build and validate from the integration tests");
    PipelineSource::Kuna(
        KunaSource::load(fixture.path()).expect("the fixture must load for scanning with Kuna"),
    )
}

#[tokio::test]
async fn the_kuna_source_answers_the_core_seam_reads_over_the_fixture() {
    let source = fixture_pipeline_source();

    let functions = source.functions().await.expect("functions read");
    for want in EXPORT_NAMES {
        assert!(
            functions
                .iter()
                .any(|f| loader_name(&f.name) == *want && f.address > 0),
            "the seam listing should carry the fixture export {want}, got {:?}",
            functions.iter().map(|f| &f.name).collect::<Vec<_>>(),
        );
    }

    let listed = functions
        .iter()
        .find(|f| loader_name(&f.name) == "fixture_tick")
        .expect("fixture_tick is listed");
    let decompiled = source
        .decompile(&listed.name)
        .await
        .expect("the listed name decompiles through the seam");
    assert_eq!(decompiled.name, listed.name);
    assert!(
        !decompiled.signature.is_empty() && !decompiled.signature.ends_with(';'),
        "the seam signature is the prototype without its semicolon: {}",
        decompiled.signature,
    );
    assert!(
        !decompiled.body.trim().is_empty(),
        "the seam body is the rendered pseudo-C"
    );

    let imports = source.imports().await.expect("imports read");
    for want in IMPORT_FUNCTIONS {
        assert!(
            imports
                .iter()
                .any(|i| loader_name(&i.name) == *want && i.imported),
            "the seam import listing should carry {want}, got {:?}",
            imports.iter().map(|i| &i.name).collect::<Vec<_>>(),
        );
    }

    let base = source.image_base().await.expect("image base read");
    assert!(base > 0, "a PE image base is reported");
    let exports = source.exports().await.expect("exports read");
    for want in EXPORT_NAMES {
        assert!(
            exports
                .iter()
                .any(|e| loader_name(&e.name) == *want && !e.imported && e.address >= base),
            "the seam export listing should carry {want} at or above the base",
        );
    }
}

#[tokio::test]
async fn an_unknown_function_name_is_a_named_miss_at_the_seam() {
    let source = fixture_pipeline_source();
    let error = source
        .decompile("no_such_function_anywhere")
        .await
        .expect_err("an unknown name is a named miss");
    match &error {
        GhidraError::NotFound { kind, query } => {
            assert_eq!(*kind, "function");
            assert_eq!(query, "no_such_function_anywhere");
        }
        other => panic!("expected the same NotFound the Ghidra path reports, got {other:?}"),
    }
}

#[tokio::test]
async fn the_reads_kuna_does_not_answer_yet_fail_by_name_naming_207_and_the_fallback() {
    let source = fixture_pipeline_source();

    let refusals: Vec<(&str, String)> = vec![
        (
            "strings",
            expect_refused(source.strings().await).to_string(),
        ),
        (
            "callers",
            expect_refused(source.callers(0x1800_0000).await).to_string(),
        ),
        (
            "xrefs_to",
            expect_refused(source.xrefs_to(0x1800_0000).await).to_string(),
        ),
        (
            "data_types",
            expect_refused(source.data_types(None).await).to_string(),
        ),
        (
            "struct_layout",
            expect_refused(source.struct_layout("FOO").await).to_string(),
        ),
        (
            "enum_values",
            expect_refused(source.enum_values("FOO").await).to_string(),
        ),
        (
            "data_items",
            expect_refused(source.data_items().await).to_string(),
        ),
        (
            "read_memory",
            expect_refused(source.read_memory(0x1800_0000, 8).await).to_string(),
        ),
    ];

    for (read, message) in &refusals {
        assert!(
            message.contains(read)
                && message.contains("#207")
                && message.contains("--engine ghidra"),
            "the `{read}` refusal should name the read, issue #207, and the fallback: {message}",
        );
    }
}

/// Unwrap the expected refusal of a not-yet-wired read.
fn expect_refused<T>(outcome: calxgloss_ghidra::Result<T>) -> GhidraError {
    match outcome {
        Err(error) => error,
        Ok(_) => panic!("a read Kuna cannot answer must fail, never answer empty"),
    }
}

#[tokio::test]
async fn a_kuna_scan_persists_function_and_dll_records_the_web_reads_back() {
    // The issue's acceptance line: a scan of the fixture under engine=kuna
    // persists FunctionInfo and DllInfo records. Everything below is
    // assembled purely from seam reads, filed in the layout the web's
    // analysis handler reads (`re/analysis/{binary}/{function}.json`), and
    // read back whole.
    let source = fixture_pipeline_source();
    let workspace = tempfile::tempdir().expect("temp workspace");

    let functions = source.functions().await.expect("functions read");
    let base = source.image_base().await.expect("image base read");
    let exports = source.exports().await.expect("exports read");
    let imports = source.imports().await.expect("imports read");

    let binary = BinaryIdentity::new(TARGET_FILE_NAME);
    let mut persisted = 0;
    for want in EXPORT_NAMES {
        let listed = functions
            .iter()
            .find(|f| loader_name(&f.name) == *want)
            .unwrap_or_else(|| panic!("{want} should be listed for the scan"));
        let decompiled = source
            .decompile(&listed.name)
            .await
            .expect("fixture exports decompile");
        let info = FunctionInfo {
            name: listed.name.clone(),
            address: listed.address,
            binary: binary.clone(),
            // The Kuna seam answers no disassembly read yet (#207 wires the
            // remaining reads); the record carries what the engine knows.
            disassembly: String::new(),
            decompiler_output: decompiled.body,
            windows_apis: Vec::new(),
            call_graph: Vec::new(),
            disassembly_hints: Vec::new(),
        };
        let path = analysis_dir(workspace.path())
            .join(TARGET_FILE_NAME)
            .join(format!("{}.json", listed.name));
        save_json(&path, &info).expect("persist the function record");
        let back = load_json::<FunctionInfo>(&path).expect("read the function record back");
        assert_eq!(back.name, info.name);
        assert_eq!(back.address, info.address);
        assert_eq!(back.binary, binary);
        assert!(
            back.decompiler_output
                .contains(listed.name.trim_start_matches('_')),
            "the persisted decompilation is the function's own C"
        );
        persisted += 1;
    }
    assert_eq!(persisted, EXPORT_NAMES.len());

    // The DllInfo record, assembled from the seam's export and import
    // listings. The seam reports bare import names (as the Ghidra path
    // does); the owning DLL is the mapping the scan applies, exactly as
    // the API-detection mapping database does on the Ghidra path.
    let dll_exports = exports
        .iter()
        .filter(|e| {
            EXPORT_NAMES
                .iter()
                .any(|want| loader_name(&e.name) == *want)
        })
        .map(|e| Export {
            name: e.name.clone(),
            address: e.address,
            signature: String::new(),
        })
        .collect::<Vec<_>>();
    assert_eq!(dll_exports.len(), EXPORT_NAMES.len());

    let dll_imports = imports
        .iter()
        .filter(|i| {
            IMPORT_FUNCTIONS
                .iter()
                .any(|want| loader_name(&i.name) == *want)
        })
        .map(|i| Import {
            binary: BinaryIdentity::new(import_dll(&loader_name(&i.name))),
            function: loader_name(&i.name),
        })
        .collect::<Vec<_>>();
    assert_eq!(dll_imports.len(), IMPORT_FUNCTIONS.len());
    for dll in IMPORT_DLL_NAMES {
        assert!(
            dll_imports.iter().any(|i| i.binary.as_str() == *dll),
            "imports from {dll} should be recorded",
        );
    }

    let dll_info = DllInfo {
        name: TARGET_FILE_NAME.to_string(),
        version: None,
        category: DllCategory::ProjectSpecific,
        known_runtime: false,
        exports: dll_exports,
        imports: dll_imports,
    };
    let dll_path = analysis_dir(workspace.path()).join(format!("{TARGET_FILE_NAME}_dll_info.json"));
    save_json(&dll_path, &dll_info).expect("persist the DLL record");
    let back = load_json::<DllInfo>(&dll_path).expect("read the DLL record back");
    assert_eq!(back.name, TARGET_FILE_NAME);
    assert_eq!(back.exports.len(), EXPORT_NAMES.len());
    assert_eq!(back.imports.len(), IMPORT_FUNCTIONS.len());
    for export in &back.exports {
        assert!(export.address >= base, "recorded exports keep their VAs");
    }
}

/// The DLL a fixture import comes from — the mapping the scan applies over
/// the seam's bare import names.
fn import_dll(function: &str) -> &'static str {
    match function {
        "GetTickCount" | "OutputDebugStringA" => "KERNEL32.dll",
        "malloc" | "free" | "puts" => "msvcrt.dll",
        other => panic!("unmapped fixture import: {other}"),
    }
}
