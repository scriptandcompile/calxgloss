//! Live tests against a running GhidraMCP server.
//!
//! The parsers in this crate are written against captured response bodies, but
//! a captured body is only as good as the day it was captured. These tests ask a
//! real server, so a change in the server's output shows up here rather than as
//! silently wrong data in a pipeline.
//!
//! They are `#[ignore]`d by default because they need a Ghidra instance with a
//! program open. To run them:
//!
//! ```text
//! CALXGLOSS_GHIDRA_URL=http://127.0.0.1:8080 \
//!     cargo test -p calxgloss-ghidra --test live -- --ignored --nocapture
//! ```
//!
//! Any function the assertions name must exist in the program that is open.
//! With `eqmain.dll` loaded, the default targets below do.

use calxgloss_ghidra::{GhidraClient, GhidraError, rva_from_va};

/// A function in `eqmain.dll` whose decompiled body is
/// `return param_1 + ((longlong)param_2 + 4) * 8;`.
const KNOWN_NAME: &str = "FUN_18008ed50";
const KNOWN_VA: u64 = 0x18008ed50;
const KNOWN_IMAGE_BASE: u64 = 0x180000000;
const KNOWN_RVA: u32 = 0x8ed50;

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
#[ignore = "needs a running GhidraMCP server with a program open"]
async fn server_is_reachable_and_serving() {
    let Some(ghidra) = client() else {
        eprintln!("CALXGLOSS_GHIDRA_URL not set; skipping");
        return;
    };
    ghidra
        .probe()
        .await
        .expect("GhidraMCP should be serving a program");
}

#[tokio::test]
#[ignore = "needs a running GhidraMCP server with eqmain.dll open"]
async fn decompiled_signature_round_trips_into_the_pipeline() {
    let Some(ghidra) = client() else {
        eprintln!("CALXGLOSS_GHIDRA_URL not set; skipping");
        return;
    };

    let f = ghidra
        .decompile_function(KNOWN_VA)
        .await
        .expect("the known function should decompile");

    assert_eq!(f.name, KNOWN_NAME);
    // The parameter names are what test generation keys its inputs by, so a
    // mismatch here would misalign every generated test case.
    assert_eq!(f.parameter_names(), vec!["param_1", "param_2"]);
    assert!(
        f.signature.contains("longlong") && f.signature.contains("int param_2"),
        "unexpected signature: {}",
        f.signature
    );
}

#[tokio::test]
#[ignore = "needs a running GhidraMCP server with eqmain.dll open"]
async fn decompiling_by_name_matches_decompiling_by_address() {
    let Some(ghidra) = client() else {
        eprintln!("CALXGLOSS_GHIDRA_URL not set; skipping");
        return;
    };

    // The 6.x bridge dropped the POST-by-name endpoint, so by-name resolution
    // goes through a name search and then decompiles by address.
    let by_name = ghidra
        .decompile_function_by_name(KNOWN_NAME)
        .await
        .expect("decompile by name");
    let by_address = ghidra
        .decompile_function(KNOWN_VA)
        .await
        .expect("decompile by address");
    assert_eq!(by_name.signature, by_address.signature);
}

#[tokio::test]
#[ignore = "needs a running GhidraMCP server with a program open"]
async fn a_missing_function_is_an_error_not_an_empty_result() {
    let Some(ghidra) = client() else {
        eprintln!("CALXGLOSS_GHIDRA_URL not set; skipping");
        return;
    };

    // This is the case the old client got wrong: the server answers `200 OK`
    // with an explanation, so trusting the status code returns the error text as
    // if it were a result.
    match ghidra.decompile_function(0xdeadbeef).await {
        Err(GhidraError::Reported { message, .. }) => {
            assert!(
                message.contains("No function found"),
                "unhelpful message: {message}"
            );
        }
        other => panic!("expected a reported error, got {other:?}"),
    }
}

#[tokio::test]
#[ignore = "needs a running GhidraMCP server with a program open"]
async fn searching_for_nothing_is_reported_as_not_found() {
    let Some(ghidra) = client() else {
        eprintln!("CALXGLOSS_GHIDRA_URL not set; skipping");
        return;
    };

    // "No such function" and "the search matched nothing" are different claims,
    // and only the first is an error.
    assert!(matches!(
        ghidra
            .search_functions("zzz_definitely_not_a_function", None)
            .await,
        Err(GhidraError::Reported { .. }) | Err(GhidraError::NotFound { .. })
    ));
}

#[tokio::test]
#[ignore = "needs a running GhidraMCP server with eqmain.dll open"]
async fn metadata_and_disassembly_describe_the_same_function() {
    let Some(ghidra) = client() else {
        eprintln!("CALXGLOSS_GHIDRA_URL not set; skipping");
        return;
    };

    let body = ghidra
        .function_body(KNOWN_VA)
        .await
        .expect("function metadata");
    assert_eq!(body.entry, KNOWN_VA);
    assert!(body.end > body.entry, "a function must span some bytes");

    let disassembly = ghidra
        .disassemble_function(KNOWN_VA)
        .await
        .expect("disassembly");
    assert!(
        disassembly.contains("RET"),
        "expected a RET in the listing, got: {disassembly}"
    );
}

#[tokio::test]
#[ignore = "needs a running GhidraMCP server with eqmain.dll open"]
async fn the_image_base_turns_a_ghidra_address_into_an_rva() {
    let Some(ghidra) = client() else {
        eprintln!("CALXGLOSS_GHIDRA_URL not set; skipping");
        return;
    };

    // This is the join between what Ghidra reports and what the PE headers
    // index, so the two have to agree for the same binary.
    let base = ghidra.image_base().await.expect("image base");
    if base != KNOWN_IMAGE_BASE {
        eprintln!("skipping: the open program is based at {base:#x}, not eqmain.dll");
        return;
    }
    assert_eq!(rva_from_va(base, KNOWN_VA), Some(KNOWN_RVA));
}

#[tokio::test]
#[ignore = "needs a running GhidraMCP server with eqmain.dll open"]
async fn cross_references_name_the_calling_function() {
    let Some(ghidra) = client() else {
        eprintln!("CALXGLOSS_GHIDRA_URL not set; skipping");
        return;
    };

    // `eqmain.dll` calls this function from exactly one place, which makes it a
    // checkable expectation rather than a shape check.
    let callers = ghidra.callers(KNOWN_VA).await.expect("callers");
    assert_eq!(callers, vec!["FUN_18000a0d0".to_string()]);
}

#[tokio::test]
#[ignore = "needs a running GhidraMCP server with eqmain.dll open"]
async fn a_function_report_assembles_every_part() {
    let Some(ghidra) = client() else {
        eprintln!("CALXGLOSS_GHIDRA_URL not set; skipping");
        return;
    };

    let report = ghidra
        .function_report(KNOWN_VA)
        .await
        .expect("function report");
    assert_eq!(report.name, KNOWN_NAME);
    assert_eq!(report.address, KNOWN_VA);
    assert_eq!(report.signature(), report.decompiled.signature);
    assert!(report.disassembly.contains("RET"));
    assert!(report.body.is_some());
    assert!(report.callers.contains(&"FUN_18000a0d0".to_string()));
    // This function performs arithmetic only, so it calls nothing.
    assert!(report.callees.is_empty(), "{:?}", report.callees);
}

#[tokio::test]
#[ignore = "needs a running GhidraMCP server with a program open"]
async fn callees_are_recovered_from_the_decompiled_body() {
    let Some(ghidra) = client() else {
        eprintln!("CALXGLOSS_GHIDRA_URL not set; skipping");
        return;
    };

    // `FUN_18000a0d0` calls into eqmain heavily, which exercises the callee
    // extraction on a real body rather than a fixture.
    let report = ghidra
        .function_report(0x18000a0d0)
        .await
        .expect("function report");
    assert!(
        report.callees.len() > 5,
        "expected many callees, got {:?}",
        report.callees
    );
    // `FUN_18008ed50` is genuinely called here; a cast in front of the call
    // must not hide it.
    assert!(
        report.callees.contains(&KNOWN_NAME.to_string()),
        "{:?}",
        report.callees
    );
}

#[tokio::test]
#[ignore = "needs a running GhidraMCP server with eqmain.dll open"]
async fn exports_carry_real_addresses() {
    let Some(ghidra) = client() else {
        eprintln!("CALXGLOSS_GHIDRA_URL not set; skipping");
        return;
    };

    let exports = ghidra.exports(None).await.expect("exports");
    let main = exports
        .iter()
        .find(|s| s.name == "dll_main")
        .expect("eqmain.dll exports dll_main");
    assert!(main.address > 0, "export address should be resolved");
    assert!(!main.imported);
}

#[tokio::test]
#[ignore = "needs a running GhidraMCP server with a program open"]
async fn imports_are_marked_as_external() {
    let Some(ghidra) = client() else {
        eprintln!("CALXGLOSS_GHIDRA_URL not set; skipping");
        return;
    };

    let imports = ghidra.imports(None).await.expect("imports");
    assert!(!imports.is_empty());
    assert!(
        imports.iter().all(|s| s.imported),
        "every import should be marked as one"
    );
}

#[tokio::test]
#[ignore = "needs a running GhidraMCP server with a program open"]
async fn strings_decode_to_their_contents() {
    let Some(ghidra) = client() else {
        eprintln!("CALXGLOSS_GHIDRA_URL not set; skipping");
        return;
    };

    let strings = ghidra
        .strings(Some(500), Some("UIFiles"))
        .await
        .expect("strings");
    assert!(!strings.is_empty(), "the filter should match something");
    for s in &strings {
        assert!(s.value.contains("UIFiles"), "filter leaked: {:?}", s.value);
    }
}

#[tokio::test]
#[ignore = "needs a running GhidraMCP server with a program open"]
async fn open_programs_names_the_current_program() {
    let Some(ghidra) = client() else {
        eprintln!("CALXGLOSS_GHIDRA_URL not set; skipping");
        return;
    };

    // The 6.x bridge can hold several programs; exactly one is current, and
    // switching to it by name must succeed.
    let programs = ghidra.open_programs().await.expect("open programs");
    assert!(!programs.is_empty(), "at least one program should be open");
    let current = programs
        .iter()
        .find(|p| p.is_current)
        .expect("one program is current");
    ghidra
        .switch_program(&current.name)
        .await
        .expect("switching to the current program is a no-op that succeeds");
}

#[tokio::test]
#[ignore = "needs a running GhidraMCP server with a program open"]
async fn a_whole_program_listing_parses_completely() {
    let Some(ghidra) = client() else {
        eprintln!("CALXGLOSS_GHIDRA_URL not set; skipping");
        return;
    };

    // The parser has to survive every record in a 4000-function binary, not just
    // the hand-picked fixtures.
    let functions = ghidra.list_functions().await.expect("function listing");
    assert!(functions.len() > 100, "only {} parsed", functions.len());
    assert!(
        functions
            .iter()
            .all(|f| !f.name.is_empty() && f.address > 0),
        "every record should yield a name and an address"
    );
}

#[tokio::test]
#[ignore = "needs a running GhidraMCP server with eqmain.dll open"]
async fn the_type_manager_lists_named_types() {
    let Some(ghidra) = client() else {
        eprintln!("CALXGLOSS_GHIDRA_URL not set; skipping");
        return;
    };

    // The Type Manager holds types never applied to a symbol; eqmain.dll's
    // imported PE and CRT types make a checkable expectation.
    let types = ghidra.list_data_types(None).await.expect("data types");
    assert!(types.len() > 100, "only {} parsed", types.len());
    assert!(
        types
            .iter()
            .all(|t| !t.name.is_empty() && t.path.starts_with('/')),
        "every record should yield a name and a Type Manager path"
    );
    assert!(
        types.iter().any(|t| t.name == "IMAGE_DOS_HEADER"),
        "the PE headers should be in the Type Manager"
    );

    // The category filter narrows the listing without emptying it.
    let pe = ghidra
        .list_data_types(Some("pe"))
        .await
        .expect("filtered data types");
    assert!(!pe.is_empty(), "the `pe` filter should match something");
}

#[tokio::test]
#[ignore = "needs a running GhidraMCP server with eqmain.dll open"]
async fn a_known_struct_layout_round_trips() {
    let Some(ghidra) = client() else {
        eprintln!("CALXGLOSS_GHIDRA_URL not set; skipping");
        return;
    };

    let layout = ghidra
        .get_struct_layout("IMAGE_DOS_HEADER")
        .await
        .expect("struct layout");
    assert_eq!(layout.name, "IMAGE_DOS_HEADER");
    assert_eq!(layout.size, 128);
    assert_eq!(layout.fields[0].field_name, "e_magic");
    assert_eq!(layout.fields[0].type_name, "char[2]");
    // The field that locates the PE headers, which is why this struct matters
    // to the pipeline at all.
    let lfanew = layout
        .fields
        .iter()
        .find(|f| f.field_name == "e_lfanew")
        .expect("e_lfanew field");
    assert_eq!(lfanew.offset, 60);

    // A miss is an error, not the server's prose parsed as a layout.
    match ghidra.get_struct_layout("zzz_not_a_struct").await {
        Err(GhidraError::NotFound { query, .. }) => assert_eq!(query, "zzz_not_a_struct"),
        other => panic!("expected not-found, got {other:?}"),
    }
}

#[tokio::test]
#[ignore = "needs a running GhidraMCP server with eqmain.dll open"]
async fn a_known_enum_round_trips() {
    let Some(ghidra) = client() else {
        eprintln!("CALXGLOSS_GHIDRA_URL not set; skipping");
        return;
    };

    let definition = ghidra
        .get_enum_values("_EXCEPTION_DISPOSITION")
        .await
        .expect("enum values");
    assert_eq!(definition.name, "_EXCEPTION_DISPOSITION");
    assert_eq!(definition.size, 4);
    assert_eq!(definition.members.len(), 4);
    assert_eq!(definition.members[0].name, "ExceptionContinueExecution");
    assert_eq!(definition.members[0].value, 0);

    match ghidra.get_enum_values("zzz_not_an_enum").await {
        Err(GhidraError::NotFound { query, .. }) => assert_eq!(query, "zzz_not_an_enum"),
        other => panic!("expected not-found, got {other:?}"),
    }
}

#[tokio::test]
#[ignore = "needs a running GhidraMCP server with eqmain.dll open"]
async fn the_defined_data_listing_parses_completely() {
    let Some(ghidra) = client() else {
        eprintln!("CALXGLOSS_GHIDRA_URL not set; skipping");
        return;
    };

    // One page first: the windowing has to hold before the full collection.
    let page = ghidra
        .data_items_page(0, 10)
        .await
        .expect("data items page");
    assert_eq!(page.len(), 10);

    // eqmain.dll defines thousands of data items, so this exercises paging
    // across many server pages, not a single fixture.
    let items = ghidra.list_data_items().await.expect("data items");
    assert!(items.len() > 1000, "only {} parsed", items.len());
    assert!(
        items.iter().all(|i| !i.label.is_empty() && i.address > 0),
        "every record should yield a label and an address"
    );
    assert!(
        items
            .iter()
            .any(|i| i.label == "IMAGE_DOS_HEADER_180000000" && i.address == KNOWN_IMAGE_BASE),
        "the DOS header should be a defined data item"
    );
}

#[tokio::test]
#[ignore = "needs a running GhidraMCP server with eqmain.dll open"]
async fn read_memory_returns_the_raw_bytes() {
    let Some(ghidra) = client() else {
        eprintln!("CALXGLOSS_GHIDRA_URL not set; skipping");
        return;
    };

    // The image base of a PE always opens with the `MZ` signature, so the
    // expected bytes are known without depending on any symbol.
    let bytes = ghidra
        .read_memory(KNOWN_IMAGE_BASE, 2)
        .await
        .expect("read memory");
    assert_eq!(bytes, vec![b'M', b'Z']);
}
