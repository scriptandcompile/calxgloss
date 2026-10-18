//! The Kuna engine behind the `ScanSource` seam, end to end (issues #206,
//! #207, and #208, part of epic #203).
//!
//! These tests drive the seam itself — `ScanSource` through
//! `PipelineSource::Kuna` — over the checked-in fixture DLL: every read the
//! trait carries answers from the one in-process program, misses arrive in
//! the Ghidra path's error vocabulary, and a scan assembled purely from
//! seam reads persists `FunctionInfo` and `DllInfo` records the web's
//! artifact layout reads back. The engine-native API is pinned in
//! `calxgloss-kuna/tests/kuna_scan.rs`.

use calxgloss_ghidra::{GhidraClient, GhidraError, PipelineSource, ScanSource, Xref};
use calxgloss_kuna::{KUNA_PIN_REV, KUNA_RELEASE, KunaSource};
use calxgloss_testfixtures::{
    EXPORT_NAMES, IMPORT_DLL_NAMES, IMPORT_FUNCTIONS, STRING_LITERALS, TARGET_FILE_NAME,
};
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
async fn the_kuna_source_answers_every_read_the_seam_carries_over_the_fixture() {
    let source = fixture_pipeline_source();

    // The string listing: every literal the fixture promises.
    let strings = source.strings().await.expect("strings read");
    for want in STRING_LITERALS {
        assert!(
            strings.iter().any(|found| &found.value == want),
            "the seam's string listing should carry {want:?}, got {:?}",
            strings.iter().map(|found| &found.value).collect::<Vec<_>>(),
        );
    }

    // Raw memory answers from the program's own load image: the PE header
    // is the first thing mapped, and an unmapped range is a named miss in
    // the Ghidra path's vocabulary, never a zero-filled answer.
    let base = source.image_base().await.expect("image base read");
    let header = source
        .read_memory(base, 2)
        .await
        .expect("the header is mapped memory");
    assert_eq!(header, b"MZ");
    let unmapped = source
        .read_memory(1 << 48, 4)
        .await
        .expect_err("an unmapped range is a miss");
    assert!(
        matches!(&unmapped, GhidraError::NotFound { kind, .. } if *kind == "memory"),
        "expected the Ghidra path's NotFound, got {unmapped:?}"
    );

    // Xrefs and callers: some fixture literal is referenced by code, and
    // the xref shape is the Ghidra client's — a site address, an optional
    // referring function, and an optional kind.
    let mut referenced: Option<(u64, Vec<Xref>)> = None;
    for string in &strings {
        let xrefs = source
            .xrefs_to(string.address)
            .await
            .expect("xrefs read answers for every address");
        if !xrefs.is_empty() {
            referenced = Some((string.address, xrefs));
            break;
        }
    }
    let (address, xrefs) = referenced.expect("a fixture literal is referenced by code");
    for xref in &xrefs {
        assert!(
            xref.address >= base,
            "xref sites are in-image addresses: {xref:?}"
        );
    }
    assert!(
        xrefs
            .iter()
            .any(|xref| xref.function.is_some() && xref.kind.is_some()),
        "the walk names the referring function and the reference kind: {xrefs:?}"
    );

    // callers dedups the xref listing's function names in first-reference
    // order — the exact shape the Ghidra client answers with, which is why
    // the call-graph builder needs no engine special case.
    let callers = source.callers(address).await.expect("callers read");
    let mut expected: Vec<String> = Vec::new();
    for xref in &xrefs {
        if let Some(name) = &xref.function
            && !expected.contains(name)
        {
            expected.push(name.clone());
        }
    }
    assert_eq!(callers, expected, "callers should dedup the xref listing");

    // A function address answers too: the fixture's exports call nothing
    // inside the image, so the honest answer is empty, not an error.
    let functions = source.functions().await.expect("functions read");
    let tick = functions
        .iter()
        .find(|f| loader_name(&f.name) == "fixture_tick")
        .expect("fixture_tick is listed");
    let tick_callers = source
        .callers(tick.address)
        .await
        .expect("callers on a function address answer");
    assert!(
        tick_callers.is_empty(),
        "no fixture export calls fixture_tick: {tick_callers:?}"
    );

    // The type-library listing answers from the engine's interned factory:
    // every entry named, classified, and pathed from its category.
    let types = source.data_types(None).await.expect("data types read");
    assert!(!types.is_empty(), "the engine interns its core vocabulary");
    for entry in &types {
        assert!(
            !entry.name.is_empty(),
            "anonymous types are skipped: {entry:?}"
        );
        assert_eq!(entry.path, format!("/{}/{}", entry.category, entry.name));
    }
    // The category filter answers like the bridge's: a case-insensitive
    // substring of the category.
    let structs = source
        .data_types(Some("Struct"))
        .await
        .expect("filtered data types read");
    assert!(
        structs
            .iter()
            .all(|entry| entry.category.contains("struct")),
        "the filter matched outside its bucket: {structs:?}"
    );

    // The layout read answers for a structure the engine's own analysis
    // interned, and misses in the vocabulary the scanner's probes branch
    // on: an unknown name is NotFound, a kind mismatch is Malformed.
    let iobuf = source
        .struct_layout("_iobuf")
        .await
        .expect("the engine's analysis interns _iobuf");
    assert_eq!(iobuf.name, "_iobuf");
    assert!(
        !iobuf.fields.is_empty(),
        "the layout carries its fields: {iobuf:?}"
    );
    let missing = source
        .struct_layout("no_such_type_anywhere")
        .await
        .expect_err("an unknown type name is a named miss");
    assert!(
        matches!(
            &missing,
            GhidraError::NotFound { kind, query }
                if *kind == "type" && query == "no_such_type_anywhere"
        ),
        "expected the bridge's NotFound, got {missing:?}"
    );
    let kind_miss = source
        .struct_layout("int4")
        .await
        .expect_err("a builtin is not a structure");
    assert!(
        matches!(&kind_miss, GhidraError::Malformed { kind, .. } if *kind == "structure layout"),
        "expected the bridge's Malformed, got {kind_miss:?}"
    );
    let enum_miss = source
        .enum_values("int4")
        .await
        .expect_err("a builtin is not an enumeration");
    assert!(
        matches!(&enum_miss, GhidraError::Malformed { kind, .. } if *kind == "enumeration"),
        "expected the bridge's Malformed, got {enum_miss:?}"
    );

    // Data items answer from the engine's symbol table: labeled in-image
    // globals with their applied types.
    let items = source.data_items().await.expect("data items read");
    for item in &items {
        assert!(
            !item.label.is_empty() && item.address >= base,
            "a global is a labeled in-image object: {item:?}"
        );
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
            // The seam carries no disassembly read at all — disassembly
            // is a Ghidra-client read outside the seam — so the record
            // carries what the seam answers.
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

/// The seam's own provenance read (issue #208): a Kuna-powered pipeline
/// names its engine, release, and pinned source, so a scan record built
/// over it can carry them; the Ghidra arms name nothing, so their records
/// stay exactly as they were on disk.
#[test]
fn the_seam_names_its_engine_only_under_kuna() {
    let provenance = fixture_pipeline_source()
        .engine_provenance()
        .expect("the Kuna arm names its engine");
    assert_eq!(provenance.name, "kuna");
    assert_eq!(provenance.version.as_deref(), Some(KUNA_RELEASE));
    assert_eq!(provenance.fingerprint.as_deref(), Some(KUNA_PIN_REV));
    assert!(
        !KUNA_RELEASE.is_empty()
            && KUNA_PIN_REV.len() == 7
            && KUNA_PIN_REV.chars().all(|c| c.is_ascii_hexdigit()),
        "the pin names a short git commit: {KUNA_RELEASE} @ {KUNA_PIN_REV}"
    );

    let client =
        GhidraClient::new("http://127.0.0.1:1").expect("a client needs no server to build");
    assert!(
        PipelineSource::from(client).engine_provenance().is_none(),
        "the Ghidra path names no engine, so its scan records stay byte-for-byte as they were",
    );
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
