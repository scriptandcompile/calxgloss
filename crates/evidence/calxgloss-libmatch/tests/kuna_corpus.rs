//! The starter set tested against the analysis engine's real output
//! (issue #309). The built-in signatures once spoke Ghidra's spellings
//! alone. Kuna — the only analysis engine (ADR-0041) — spells the same
//! shapes its own way, so a cold batch filed a known-library document
//! with no findings. The fixture target is the corpus: every
//! statically linked CRT routine it carries is decompiled by Kuna
//! itself. The scan here is the very one the pipeline's known-library
//! row builds — built-in starter set, whole listing, no supplied
//! database.

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
    // Issue #306 recorded the drift: over this same listing, the
    // Ghidra-spelled starter set found nothing at all. With the
    // normalizer's Kuna dialect layer and the corpus-grounded
    // alternatives added to the bundles, the cold scan now claims the
    // shapes the fixture really carries.
    let claims = fixture_claims().await;
    assert!(
        !claims.is_empty(),
        "a cold scan of the fixture with the built-in set files a document that says something"
    );

    // The NUL-scan claim, in Kuna's spelling: the fixture's `strnlen`
    // walks the pointer until the byte reads as false (`while (*v1) {`
    // / `v1 = &v1[1];`). That is the length-scan shape, at the standard
    // body-evidence score.
    assert!(
        claims
            .iter()
            .any(|(function, target, confidence)| function == "strnlen"
                && target == "strlen"
                && *confidence == calxgloss_libmatch::confidence::BODY_MATCH_CONFIDENCE),
        "the strnlen body lands the strlen scan shape: {claims:?}"
    );

    // The guarded `free`, in Kuna's spelling: bodies that release a
    // heap block behind a falseness test (`if (!v1)` … `free(v1);`)
    // read as the `operator delete` wrapper's thin shape. The entry's
    // own note admits any allocation helper reads alike, which is why
    // it deliberately claims the sloppier 50 — far under the 80 that
    // the call graph's `Skip` classification demands.
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

    // The exclusions hold. The fixture's own `fixture_describe`
    // allocates *and* frees: a body calling `malloc` is not the
    // `delete` wrapper, and one calling `free` is not the `new`
    // wrapper. The import thunks (`memcpy`, `memset`, `strlen` as
    // `return memcpy(a0,a1,a2); // jump-as-call`) sit far under every
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
