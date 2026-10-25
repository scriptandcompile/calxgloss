//! The starter set against the only engine's real output (issue #309):
//! the built-in signatures used to speak Ghidra's spellings alone, and
//! Kuna — the only analysis engine (ADR-0041) — spells the same shapes
//! its own way, so a cold batch filed a findings-empty known-library
//! document. The fixture target is the corpus: every statically linked
//! CRT routine it carries is decompiled by Kuna itself, and the scan
//! here is the very engine the pipeline's known-library row builds —
//! built-in starter set, whole listing, no supplied database.

use calxgloss_kuna::source::KunaSource;
use calxgloss_libmatch::engine::LibmatchEngine;

/// The scan the pipeline's row builds, run over the whole fixture
/// listing with the built-in starter set and nothing supplied.
async fn fixture_claims() -> Vec<(String, String, u8)> {
    let fixture = calxgloss_testfixtures::load_target()
        .expect("fixture target should build and validate from the integration tests");
    let source = KunaSource::load(fixture.path()).expect("the fixture must load for Kuna");
    let engine = LibmatchEngine::with_source(source);
    let result = engine
        .scan(calxgloss_testfixtures::TARGET_FILE_NAME)
        .await
        .expect("the starter-set scan reads the fixture listing");
    result
        .findings
        .iter()
        .map(|finding| {
            (
                finding.function().to_string(),
                finding.target().to_string(),
                finding.confidence().value(),
            )
        })
        .collect()
}

#[tokio::test]
async fn the_starter_set_lands_real_identifications_on_kuna_bodies() {
    // The drift #306 recorded: over the same listing the Ghidra-spelled
    // starter set found nothing at all. With the normalizer's Kuna
    // dialect layer and the bundles' corpus-grounded alternatives, the
    // cold scan now claims the shapes the fixture really carries.
    let claims = fixture_claims().await;
    assert!(
        !claims.is_empty(),
        "a cold scan of the fixture with the built-in set files a document that says something"
    );

    // The NUL scan, Kuna-spelled: the fixture's `strnlen` walks the
    // pointer until the byte reads as false (`while (*v1) {` /
    // `v1 = &v1[1];`) — the length-scan shape, at the standard
    // body-evidence score.
    assert!(
        claims
            .iter()
            .any(|(function, target, confidence)| function == "strnlen"
                && target == "strlen"
                && *confidence == calxgloss_libmatch::confidence::BODY_MATCH_CONFIDENCE),
        "the strnlen body lands the strlen scan shape: {claims:?}"
    );

    // The guarded `free`, Kuna-spelled: bodies that release a heap
    // block behind a falseness test (`if (!v1)` … `free(v1);`) read as
    // the `operator delete` wrapper's thin shape — the entry's own
    // doctrine admits any allocation helper reads alike, which is why
    // it claims the deliberately sloppier 50, far under the 80 the
    // call graph's Skip classification demands.
    for helper in ["__Bfree_D2A", "_execute_onexit_table"] {
        assert!(
            claims
                .iter()
                .any(|(function, target, confidence)| function == helper
                    && target == "operator delete"
                    && *confidence == 50),
            "{helper} lands the guarded-free wrapper shape: {claims:?}"
        );
    }

    // The exclusions hold: the fixture's own `fixture_describe`
    // allocates *and* frees — a body calling `malloc` is not the
    // `delete` wrapper, and one calling `free` is not the `new`
    // wrapper — and the import thunks (`memcpy`, `memset`, `strlen`
    // as `return memcpy(a0,a1,a2); // jump-as-call`) are far under any
    // entry's line-count floor. Nothing else in the listing fits.
    assert!(
        !claims
            .iter()
            .any(|(function, _, _)| function == "fixture_describe"),
        "a routine that both allocates and frees claims neither wrapper: {claims:?}"
    );
    for thunk in ["memcpy", "memset", "memcmp", "strlen", "strcmp", "strcpy"] {
        assert!(
            !claims.iter().any(|(function, _, _)| function == thunk),
            "the {thunk} import thunk is a jump, not a body: {claims:?}"
        );
    }
    let unique: std::collections::HashSet<&String> =
        claims.iter().map(|(function, _, _)| function).collect();
    assert_eq!(
        unique.len(),
        claims.len(),
        "one claim per function — the set does not cross-claim: {claims:?}"
    );
}
