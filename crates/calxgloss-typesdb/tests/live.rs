//! Live named-type scans against a running GhidraMCP server.
//!
//! The scanner's unit tests run over canned responses; these ask a real
//! bridge, so a change in the Type Manager endpoints' output shows up here
//! rather than as silently wrong data in a persisted type database.
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
use calxgloss_typesdb::types::TypeKind;

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
