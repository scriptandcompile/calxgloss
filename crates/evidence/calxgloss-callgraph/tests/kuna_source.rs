//! The call-graph builder over the Kuna engine (issue #207, part of epic #203).
//!
//! The builder is generic over `ScanSource` and carries no engine special
//! case: the function listing, callers, and decompile shapes the Kuna
//! source answers through the seam are the shapes it consumes, and the
//! fixture builds a graph from them.

use calxgloss_callgraph::CallGraphBuilder;
use calxgloss_ghidra::ScanSource;
use calxgloss_kuna::KunaSource;
use calxgloss_testfixtures::{EXPORT_NAMES, TARGET_FILE_NAME};

/// The loader's spelling of a fixture name: MinGW COFF symbols carry a
/// leading underscore, so the listing may report `_fixture_init` where the
/// export table says `fixture_init`.
fn loader_name(raw: &str) -> String {
    raw.trim_start_matches('_').to_string()
}

#[tokio::test]
async fn the_call_graph_builds_over_the_kuna_source_with_no_special_case() {
    let fixture = calxgloss_testfixtures::load_target()
        .expect("the fixture target builds and validates from the integration tests");
    let source =
        KunaSource::load(fixture.path()).expect("the fixture must load for scanning with Kuna");

    let graph = CallGraphBuilder::with_source(source.clone(), TARGET_FILE_NAME)
        .build()
        .await
        .expect("the builder reads the Kuna source unchanged");

    assert_eq!(graph.binary, TARGET_FILE_NAME);
    for want in EXPORT_NAMES {
        assert!(
            graph
                .functions
                .iter()
                .any(|f| loader_name(&f.name) == *want),
            "the graph should carry the fixture export {want}, got {:?}",
            graph.functions.iter().map(|f| &f.name).collect::<Vec<_>>(),
        );
    }

    // Shape parity: the graph's nodes are exactly the seam's listing, each
    // with its entry address — the same shape the scan source produces,
    // which is why the builder needs no engine special case.
    let listed = source
        .functions()
        .await
        .expect("functions read answers after the build");
    assert_eq!(
        graph.functions.len(),
        listed.len(),
        "every listed function is a graph node"
    );
    // Names repeat (MinGW emits one thunk per import call site), so pair
    // on (name, address) rather than on name alone.
    let mut graphed: Vec<(&str, u64)> = graph
        .functions
        .iter()
        .map(|f| (f.name.as_str(), f.address))
        .collect();
    let mut listed_pairs: Vec<(&str, u64)> = listed
        .iter()
        .map(|f| (f.name.as_str(), f.address))
        .collect();
    graphed.sort();
    listed_pairs.sort();
    assert_eq!(graphed, listed_pairs, "graph nodes mirror the seam listing");

    // The callee list comes from the shared decompiled-text parser, which
    // recognizes Ghidra's placeholder names (`FUN_…`) — the names Ghidra
    // gives functions it has no real name for. Kuna names every function
    // from the symbol table, so the parser honestly answers none, exactly
    // as it answers none for a program whose calls all carry real
    // names. The caller edges, by contrast, come from the seam's xrefs and
    // are richly populated: the statically linked MinGW CRT calls itself
    // throughout the image, and every caller resolves to a listed entry.
    let helper = graph
        .functions
        .iter()
        .find(|f| f.name == "__pformat_putc")
        .expect("the CRT's pformat helper is listed");
    assert!(
        !helper.callers.is_empty(),
        "the CRT calls its own helpers through the seam's xrefs: {helper:?}"
    );
    for caller in &helper.callers {
        assert!(
            listed_pairs.iter().any(|(_, address)| address == caller),
            "caller {caller:#x} of __pformat_putc is a listed function entry"
        );
    }
}
