//! Live named-type, vtable, and string-inference scans against a running
//! GhidraMCP server.
//!
//! The engines' unit tests run over canned responses; these ask a real
//! bridge, so a change in the endpoints' output shows up here rather than as
//! silently wrong data in a persisted type database.
//!
//! They are `#[ignore]`d by default because they need a Ghidra instance with
//! a program open. To run them:
//!
//! ```text
//! CALXGLOSS_GHIDRA_URL=http://127.0.0.1:8089 \
//!     cargo test -p calxgloss-typesdb --test live -- --ignored --nocapture
//! ```
//!
//! Any type the assertions name must exist in the program that is open.
//! With `eqmain.dll` loaded, the default targets below do.

use calxgloss_ghidra::GhidraClient;
use calxgloss_typesdb::scanner::TypeLibraryScanner;
use calxgloss_typesdb::string_infer::StringInferenceEngine;
use calxgloss_typesdb::types::TypeKind;
use calxgloss_typesdb::vtable::VtableDetector;

fn client() -> Option<GhidraClient> {
    let url = std::env::var("CALXGLOSS_GHIDRA_URL").ok()?;
    match GhidraClient::new(&url) {
        Ok(c) => Some(c),
        Err(e) => {
            eprintln!("bad CALXGLOSS_GHIDRA_URL: {e}");
            None
        }
    }
}

#[tokio::test]
#[ignore = "needs a running GhidraMCP server with eqmain.dll open"]
async fn the_scan_recovers_pe_struct_layouts() {
    let Some(ghidra) = client() else {
        eprintln!("CALXGLOSS_GHIDRA_URL not set; skipping");
        return;
    };

    let types = TypeLibraryScanner::new(&ghidra)
        .scan_named_types()
        .await
        .expect("named type scan");
    assert!(types.len() > 100, "only {} recovered", types.len());

    let dos = types
        .iter()
        .find(|t| t.name == "IMAGE_DOS_HEADER")
        .expect("the PE headers should be in the Type Manager");
    assert_eq!(dos.kind, TypeKind::Struct);
    assert_eq!(dos.size, Some(128));
    assert!(dos.has_layout(), "the layout probe should have resolved");
    assert!(
        dos.fields
            .iter()
            .any(|f| f.name == "e_lfanew" && f.offset == 60),
        "e_lfanew should carry its offset: {:?}",
        dos.fields
    );
}

#[tokio::test]
#[ignore = "needs a running GhidraMCP server with eqmain.dll open"]
async fn the_scan_recovers_enum_members() {
    let Some(ghidra) = client() else {
        eprintln!("CALXGLOSS_GHIDRA_URL not set; skipping");
        return;
    };

    let types = TypeLibraryScanner::new(&ghidra)
        .scan_named_types()
        .await
        .expect("named type scan");

    let disposition = types
        .iter()
        .find(|t| t.name == "_EXCEPTION_DISPOSITION")
        .expect("the CRT exception enum should be in the Type Manager");
    assert_eq!(disposition.kind, TypeKind::Enum);
    assert_eq!(disposition.members.len(), 4);
    assert_eq!(disposition.members[0].name, "ExceptionContinueExecution");
}

#[tokio::test]
#[ignore = "needs a running GhidraMCP server with a program open"]
async fn the_scan_degrades_without_failing_and_skips_variant_entries() {
    let Some(ghidra) = client() else {
        eprintln!("CALXGLOSS_GHIDRA_URL not set; skipping");
        return;
    };

    // Thousands of Type Manager entries, many of them typedefs, function
    // signatures, and probe misses: the scan must finish and return them at
    // whatever fidelity it could establish.
    let types = TypeLibraryScanner::new(&ghidra)
        .scan_named_types()
        .await
        .expect("named type scan");
    assert!(
        types.iter().all(|t| t.path.starts_with('/')),
        "every record should carry its Type Manager path"
    );
    assert!(
        types.iter().all(|t| !t.name.ends_with('*')),
        "pointer variants are not recovered"
    );
    assert!(
        types.iter().all(|t| t.category != "builtin"),
        "builtin primitives are not recovered"
    );
    let recovered_layouts = types.iter().filter(|t| t.has_layout()).count();
    assert!(
        recovered_layouts > 50,
        "only {recovered_layouts} layouts resolved"
    );
}

#[tokio::test]
#[ignore = "needs a running GhidraMCP server with eqmain.dll open"]
async fn the_category_filter_narrows_the_scan() {
    let Some(ghidra) = client() else {
        eprintln!("CALXGLOSS_GHIDRA_URL not set; skipping");
        return;
    };

    // `excpt` names a Type Manager category and collides with no
    // classification word, so the filter's match is checkable. (`pe` would
    // not be: the bridge also matches the filter against the classification,
    // and `typedef` contains `pe`.)
    let types = TypeLibraryScanner::new(&ghidra)
        .with_category("excpt")
        .scan_named_types()
        .await
        .expect("filtered named type scan");
    assert!(
        !types.is_empty(),
        "the `excpt` filter should match something"
    );
    assert!(
        types.iter().all(|t| t.category.contains("excpt")),
        "filter leaked: {:?}",
        types.iter().map(|t| &t.category).collect::<Vec<_>>()
    );
}

#[tokio::test]
#[ignore = "needs a running GhidraMCP server with eqmain.dll open"]
async fn the_detector_finds_and_confirms_eqmain_vftables() {
    let Some(ghidra) = client() else {
        eprintln!("CALXGLOSS_GHIDRA_URL not set; skipping");
        return;
    };

    // Tagging writes back into the program, so the live scan runs read-only.
    let vtables = VtableDetector::new(&ghidra)
        .without_tagging()
        .detect_vtables()
        .await
        .expect("vtable detection");
    assert!(vtables.len() > 50, "only {} detected", vtables.len());

    // `vftable` names are not unique; the address is the key, and eqmain's
    // tables all carry the RTTI metadata pointer.
    let addresses: Vec<u64> = vtables.iter().map(|v| v.address).collect();
    assert!(
        addresses.windows(2).all(|w| w[0] < w[1]),
        "not sorted/unique"
    );
    assert!(
        vtables.iter().all(|v| v.is_confirmed()),
        "a vftable lacked its metadata pointer"
    );
}

#[tokio::test]
#[ignore = "needs a running GhidraMCP server with eqmain.dll open"]
async fn the_detector_resolves_methods_classes_and_bases() {
    let Some(ghidra) = client() else {
        eprintln!("CALXGLOSS_GHIDRA_URL not set; skipping");
        return;
    };

    let vtables = VtableDetector::new(&ghidra)
        .without_tagging()
        .detect_vtables()
        .await
        .expect("vtable detection");

    let with_methods = vtables.iter().filter(|v| !v.methods.is_empty()).count();
    assert!(with_methods > 50, "only {with_methods} resolved methods");
    assert!(
        vtables
            .iter()
            .all(|v| v.methods.iter().all(|m| m.slot < v.methods.len())),
        "slot indices should be table-order"
    );

    let with_classes = vtables.iter().filter(|v| v.class_name.is_some()).count();
    assert!(
        with_classes > 50,
        "only {with_classes} recovered a class name"
    );
    let with_bases = vtables
        .iter()
        .filter(|v| !v.base_classes.is_empty())
        .count();
    assert!(with_bases > 0, "no vtable recovered a base class");
}

#[tokio::test]
#[ignore = "needs a running GhidraMCP server with eqmain.dll open"]
async fn the_engine_infers_candidates_from_eqmain_literals() {
    let Some(ghidra) = client() else {
        eprintln!("CALXGLOSS_GHIDRA_URL not set; skipping");
        return;
    };

    let candidates = StringInferenceEngine::new(&ghidra)
        .infer_structures()
        .await
        .expect("string inference");
    assert!(!candidates.is_empty(), "no candidates inferred");
    assert!(
        candidates.windows(2).all(|w| w[0].confidence >= w[1].confidence),
        "not strongest-first"
    );
    assert!(
        candidates.iter().all(|c| c.fields.len() >= 2),
        "a candidate is below the field floor"
    );
    assert!(
        candidates
            .iter()
            .all(|c| c.fields.iter().all(|f| !f.name.is_empty())),
        "a field name is empty"
    );
}

#[tokio::test]
#[ignore = "needs a running GhidraMCP server with eqmain.dll open"]
async fn the_engine_recovers_the_startup_flow_field_list() {
    let Some(ghidra) = client() else {
        eprintln!("CALXGLOSS_GHIDRA_URL not set; skipping");
        return;
    };

    // eqmain's startup-flow keys are read together in one function; the
    // engine should group them into one candidate even though Ghidra named
    // nothing.
    let candidates = StringInferenceEngine::new(&ghidra)
        .infer_structures()
        .await
        .expect("string inference");
    let flow = candidates
        .iter()
        .find(|c| c.fields.iter().any(|f| f.name == "flowname"))
        .expect("a candidate should carry the `flowname` literal");
    let names: Vec<&str> = flow.fields.iter().map(|f| f.name.as_str()).collect();
    for key in ["startupflow", "screen", "nextflow", "action"] {
        assert!(names.contains(&key), "flow candidate missing {key}: {names:?}");
    }
    assert!(
        flow.referenced_by.iter().any(|f| f == "FUN_18000b620"),
        "the flow cluster should name its referencing function: {:?}",
        flow.referenced_by
    );
}

#[tokio::test]
#[ignore = "needs a running GhidraMCP server with eqmain.dll open"]
async fn the_string_filter_narrows_the_run() {
    let Some(ghidra) = client() else {
        eprintln!("CALXGLOSS_GHIDRA_URL not set; skipping");
        return;
    };

    let candidates = StringInferenceEngine::new(&ghidra)
        .with_string_filter("flow")
        .infer_structures()
        .await
        .expect("filtered string inference");
    assert!(
        candidates.iter().all(|c| c
            .fields
            .iter()
            .all(|f| f.source_value.to_ascii_lowercase().contains("flow"))),
        "filter leaked: {:?}",
        candidates
            .iter()
            .flat_map(|c| c.fields.iter())
            .map(|f| &f.source_value)
            .collect::<Vec<_>>()
    );
}
