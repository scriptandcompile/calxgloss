//! The decompile noise filter at the exits of the seam's `decompile`
//! reads (issues #271–#273).
//!
//! The tests that seed fake analysis-engine bodies drive the cached
//! source in the tampered-document style of `cache_tests.rs`: a body the
//! fixture's analysis engine could never answer — standalone guard calls
//! and the if-wrapped cookie compare sitting beside real statements — is
//! seeded into the disk tier. The replayed read comes back stripped,
//! while the document on disk keeps the raw text. That proves the shared
//! filter sits at the cached source's exit *above* the cache, with raw
//! staying raw (ADR-0043). The in-process Kuna source's exit is pinned
//! from the other side: the fixture's canary-free bodies come back
//! byte-identical to the analysis engine's own raw text, so the filter
//! at that exit changes exactly nothing it must not change. The filter's
//! behavior on fake bodies — the strips themselves, the conservative
//! gate, the never-empties rule, the debug log — is pinned in
//! `noise_filter`'s unit tests.

use calxgloss_decomp::{CachedScanSource, DecompiledFunction, PipelineSource, ScanSource};
use calxgloss_kuna::KunaSource;
use calxgloss_testfixtures::TARGET_FILE_NAME;
use std::path::{Path, PathBuf};

/// A temp workspace holding a copy of the fixture binary, returning the
/// workspace and the copy's path — the `cache_tests.rs` driver.
fn workspace_with_fixture() -> (tempfile::TempDir, PathBuf) {
    let fixture = calxgloss_testfixtures::load_target()
        .expect("fixture target should build and validate from the integration tests");
    let dir = tempfile::TempDir::new().expect("temp workspace");
    let binary = dir.path().join(TARGET_FILE_NAME);
    std::fs::copy(fixture.path(), &binary).expect("fixture copied into the workspace");
    (dir, binary)
}

fn cached_source(workspace: &Path, binary: &Path) -> CachedScanSource {
    let source = KunaSource::load(binary).expect("the fixture must load for scanning with Kuna");
    CachedScanSource::new(source, workspace, TARGET_FILE_NAME, binary).expect("cached source")
}

#[tokio::test]
async fn a_seeded_body_of_guard_calls_comes_back_stripped_and_stays_raw_on_disk() {
    let (workspace, binary) = workspace_with_fixture();
    let source = cached_source(workspace.path(), &binary);

    // Seed a fake analysis-engine body the fixture could never answer:
    // standalone calls to each guard name, at top level and inside a
    // block, beside the function's real statements.
    let fake = DecompiledFunction {
        name: "gs_theater".into(),
        signature: "void gs_theater(int param_1)".into(),
        body: concat!(
            "{\n",
            "  __security_init_cookie();\n",
            "  if (param_1 != 0) {\n",
            "    __security_check_cookie(local_8);\n",
            "  }\n",
            "  FUN_180045a00(param_1 + 1);\n",
            "  __report_gsfailure();\n",
            "  return;\n",
            "}\n",
        )
        .into(),
    };
    let document = source
        .cache_dir()
        .expect("the disk tier is on")
        .join("decompile/gs_theater.json");
    calxgloss_types::save_json(&document, &fake).expect("fake body seeded");

    // The seam read replays the seeded document and strips at the exit:
    // the standalone calls are gone, everything else is byte-identical.
    let read = ScanSource::decompile(&source, "gs_theater")
        .await
        .expect("disk-hit decompile");
    assert_eq!(read.name, fake.name, "the name survives byte-for-byte");
    assert_eq!(
        read.signature, fake.signature,
        "the signature line survives filtering byte-for-byte"
    );
    assert_eq!(
        read.body,
        concat!(
            "{\n",
            "  if (param_1 != 0) {\n",
            "  }\n",
            "  FUN_180045a00(param_1 + 1);\n",
            "  return;\n",
            "}\n",
        ),
        "every standalone guard call is gone and the real statements are byte-identical"
    );

    // The disk document still holds the raw text: the cache tiers never saw
    // the filtered body, so the filter is reversible by deleting the cache
    // (ADR-0043 unchanged).
    let on_disk: DecompiledFunction =
        calxgloss_types::load_json(&document).expect("the seeded document still parses");
    assert_eq!(
        on_disk.body, fake.body,
        "the cache file holds the raw engine text"
    );

    // A fresh instance's warm replay strips identically, through the
    // pipeline's dispatch enum — the same exit, not a second filter copy —
    // and the document on disk is still raw.
    let replayed = ScanSource::decompile(
        &PipelineSource::Cached(cached_source(workspace.path(), &binary)),
        "gs_theater",
    )
    .await
    .expect("warm replay through PipelineSource::Cached");
    assert_eq!(replayed, read, "a warm replay strips the same way");
    let on_disk: DecompiledFunction = calxgloss_types::load_json(&document).expect("still raw");
    assert_eq!(on_disk.body, fake.body, "the raw text is never rewritten");
}

#[tokio::test]
async fn a_seeded_full_canary_body_comes_back_stripped_and_stays_raw_on_disk() {
    // The prologue+epilogue idiom (issues #272–#273): the save line and
    // the if-wrapped comparison with its failure call come out whole.
    // The declaration stays, because the equality test and the return
    // still refer to the local. That equality test, with a real call in
    // its block, is the conservative gate's case, and it stands
    // byte-for-byte.
    let (workspace, binary) = workspace_with_fixture();
    let source = cached_source(workspace.path(), &binary);
    let fake = DecompiledFunction {
        name: "gs_epilogue".into(),
        signature: "undefined8 gs_epilogue(int param_1)".into(),
        body: concat!(
            "{\n",
            "  undefined8 local_8;\n",
            "  local_8 = DAT_18004a040 ^ (ulonglong)&stack0x00000008;\n",
            "  FUN_180045a00(param_1);\n",
            "  if (local_8 != DAT_18004a040) {\n",
            "    __report_gsfailure();\n",
            "  }\n",
            "  if (local_8 == DAT_18004a040) { FUN_180045a00(local_8); }\n",
            "  return (local_8 ^ 0x22);\n",
            "}\n",
        )
        .into(),
    };
    let document = source
        .cache_dir()
        .expect("the disk tier is on")
        .join("decompile/gs_epilogue.json");
    calxgloss_types::save_json(&document, &fake).expect("fake body seeded");

    let read = ScanSource::decompile(&source, "gs_epilogue")
        .await
        .expect("disk-hit decompile");
    assert_eq!(read.name, fake.name, "the name survives byte-for-byte");
    assert_eq!(
        read.signature, fake.signature,
        "the signature line survives filtering byte-for-byte"
    );
    assert_eq!(
        read.body,
        concat!(
            "{\n",
            "  undefined8 local_8;\n",
            "  FUN_180045a00(param_1);\n",
            "  if (local_8 == DAT_18004a040) { FUN_180045a00(local_8); }\n",
            "  return (local_8 ^ 0x22);\n",
            "}\n",
        ),
        "the save line, the wrapper, the comparison, and the failure call are gone \
         together, the still-referenced declaration stays, and everything else is \
         byte-identical"
    );

    let on_disk: DecompiledFunction =
        calxgloss_types::load_json(&document).expect("the seeded document still parses");
    assert_eq!(
        on_disk.body, fake.body,
        "the cache file holds the raw engine text"
    );
}

#[tokio::test]
async fn a_seeded_canary_body_loses_its_orphaned_cookie_declaration_too() {
    // Issue #273's sweep of orphaned locals at the seam: with the save
    // and the compare gone, nothing references local_8 anymore, so its
    // declaration goes with the idiom. The function's real statements
    // and return come back byte-identical.
    let (workspace, binary) = workspace_with_fixture();
    let source = cached_source(workspace.path(), &binary);
    let fake = DecompiledFunction {
        name: "gs_prologue".into(),
        signature: "void gs_prologue(int param_1)".into(),
        body: concat!(
            "{\n",
            "  undefined8 local_8;\n",
            "  local_8 = ___security_cookie ^ (ulonglong)&stack0x00000008;\n",
            "  FUN_180045a00(param_1);\n",
            "  if (local_8 != ___security_cookie) {\n",
            "    __report_gsfailure();\n",
            "  }\n",
            "  return;\n",
            "}\n",
        )
        .into(),
    };
    let document = source
        .cache_dir()
        .expect("the disk tier is on")
        .join("decompile/gs_prologue.json");
    calxgloss_types::save_json(&document, &fake).expect("fake body seeded");

    let read = ScanSource::decompile(&source, "gs_prologue")
        .await
        .expect("disk-hit decompile");
    assert_eq!(
        read.body,
        concat!("{\n", "  FUN_180045a00(param_1);\n", "  return;\n", "}\n",),
        "the whole idiom and the orphaned declaration are gone through the seam read"
    );
    let on_disk: DecompiledFunction =
        calxgloss_types::load_json(&document).expect("the seeded document still parses");
    assert_eq!(
        on_disk.body, fake.body,
        "the cache file holds the raw engine text, declaration and all"
    );
}

#[tokio::test]
async fn a_seeded_body_without_guard_calls_comes_back_byte_identical() {
    let (workspace, binary) = workspace_with_fixture();
    let source = cached_source(workspace.path(), &binary);
    let fake = DecompiledFunction {
        name: "gs_clean".into(),
        signature: "undefined8 gs_clean(int param_1)".into(),
        body: "{\n  int local_8;\n  local_8 = param_1 ^ 0x22;\n  return (ulong)(local_8 == DAT_18004a040);\n}\n"
            .into(),
    };
    let document = source
        .cache_dir()
        .expect("the disk tier is on")
        .join("decompile/gs_clean.json");
    calxgloss_types::save_json(&document, &fake).expect("fake body seeded");

    let read = ScanSource::decompile(&source, "gs_clean")
        .await
        .expect("disk-hit decompile");
    assert_eq!(read, fake, "a canary-free read comes back byte-identical");
    let on_disk: DecompiledFunction = calxgloss_types::load_json(&document).expect("intact");
    assert_eq!(on_disk.body, fake.body, "the document is untouched");
}

#[tokio::test]
async fn the_in_process_kuna_source_passes_canary_free_bodies_byte_identical() {
    // The Kuna arm's exit filter (issue #271), checked against the
    // analysis engine's own raw text: a body with no canary noise comes
    // back from the seam read byte-identical to the raw read. That is
    // the other direction of the proof — nothing at that exit changes
    // what it must not change.
    let fixture = calxgloss_testfixtures::load_target()
        .expect("fixture target should build and validate from the integration tests");
    let source =
        KunaSource::load(fixture.path()).expect("the fixture must load for scanning with Kuna");
    let seam = PipelineSource::Kuna(source.clone());

    let listed = ScanSource::functions(&seam)
        .await
        .expect("function listing");
    let tick = listed
        .iter()
        .find(|f| f.name.trim_start_matches('_') == "fixture_tick")
        .expect("fixture_tick is listed");

    let raw = KunaSource::decompile_function(&source, &tick.name)
        .await
        .expect("the engine's raw read");
    let read = ScanSource::decompile(&seam, &tick.name)
        .await
        .expect("the seam's Kuna-arm read");
    assert_eq!(
        read.body, raw.body,
        "a canary-free body passes the Kuna exit byte-identical"
    );
    assert_eq!(
        read.signature, raw.signature,
        "the signature line survives byte-for-byte"
    );
    assert_eq!(read.name, raw.name);
}
