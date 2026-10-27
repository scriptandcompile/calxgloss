//! `CachedScanSource` end-to-end, driven through the shared `ScanSource`
//! seam over the Kuna engine on the checked-in fixture DLL (issue #214).
//!
//! The cache's whole contract is observable from outside: a first instance
//! fetches live and writes through, a second instance over the same
//! workspace replays from disk, changed bytes or a mismatched manifest mean
//! cold, a corrupt document degrades to a live refetch, and heartbeats pass
//! straight through. With no server to count calls at, the instrumentation
//! is the documents themselves: a tampered document whose value comes back
//! proves a disk replay, and a corrupt document whose real value comes back
//! proves a live refetch. No cache internals are inspected.

use calxgloss_decomp::{CachedScanSource, EngineError, FunctionSummary, ScanSource};
use calxgloss_kuna::KunaSource;
use calxgloss_testfixtures::{EXPORT_NAMES, STRING_LITERALS, TARGET_FILE_NAME};
use std::path::{Path, PathBuf};

/// The fixture's own entry point, listed with MinGW's leading underscore.
fn fixture_export(functions: &[FunctionSummary], want: &str) -> FunctionSummary {
    functions
        .iter()
        .find(|f| f.name.trim_start_matches('_') == want)
        .unwrap_or_else(|| {
            panic!(
                "{want} should be listed, got {:?}",
                functions.iter().map(|f| &f.name).collect::<Vec<_>>()
            )
        })
        .clone()
}

// ============================================================
// Fixtures and drivers
// ============================================================

/// The ticket demands `Clone + Send + Sync`; the clones spawned in the
/// concurrency test prove `Send`, this pins `Sync` as well.
#[test]
fn cached_source_is_clone_send_and_sync() {
    fn assert_clone_send_sync<T: Clone + Send + Sync>() {}
    assert_clone_send_sync::<CachedScanSource>();
}

/// A temp workspace holding a copy of the fixture binary, returning the
/// workspace and the copy's path.
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

/// Drive every cached read once, asserting each answers with the fixture's
/// own values — cached or not, the answers must be the engine's.
async fn drive_reads<S: ScanSource>(source: &S) {
    let functions = source.functions().await.expect("function listing");
    let tick = fixture_export(&functions, "fixture_tick");
    let body = source
        .decompile(&tick.name)
        .await
        .expect("decompile by listed name");
    assert!(
        body.body.contains("fixture_tick"),
        "the decompiled body should name its own function: {body:?}"
    );
    let listing = source
        .disassembly(&tick.name)
        .await
        .expect("disassembly by listed name");
    assert!(
        !listing.trim().is_empty(),
        "the disassembly read lists instructions: {listing:?}"
    );
    let strings = source.strings().await.expect("strings");
    for want in STRING_LITERALS {
        assert!(
            strings.iter().any(|s| s.value == *want),
            "the string listing should carry {want:?}"
        );
    }
    let base = source.image_base().await.expect("image base");
    assert!(base > 0, "a PE image base is reported");
    let exports = source.exports().await.expect("exports");
    for want in EXPORT_NAMES {
        assert!(
            exports
                .iter()
                .any(|e| e.name.trim_start_matches('_') == *want),
            "the export listing should carry {want}"
        );
    }
    let imports = source.imports().await.expect("imports");
    assert!(
        imports.iter().any(|i| i.name.contains("puts")),
        "the import listing should carry puts, got {:?}",
        imports.iter().map(|i| &i.name).collect::<Vec<_>>()
    );
    assert!(
        !source.data_items().await.expect("data items").is_empty(),
        "the fixture carries in-image globals"
    );
    assert!(
        !source
            .data_types(None)
            .await
            .expect("data types")
            .is_empty(),
        "the engine interns its core vocabulary"
    );
    let iobuf = source
        .struct_layout("_iobuf")
        .await
        .expect("the engine's analysis interns _iobuf");
    assert_eq!(iobuf.name, "_iobuf");
    assert_eq!(
        source.read_memory(base, 2).await.expect("memory bytes"),
        b"MZ"
    );
    // A referenced literal answers xrefs and callers.
    let mut xref_site = None;
    for s in strings.iter().take(8) {
        let xrefs = source.xrefs_to(s.address).await.expect("xrefs read");
        if !xrefs.is_empty() {
            xref_site = Some(s.address);
            break;
        }
    }
    let address = xref_site.expect("a fixture literal is referenced by code");
    let callers = source.callers(address).await.expect("callers read");
    assert!(
        !callers.is_empty(),
        "the referring function is named for {address:x}"
    );
}

// ============================================================
// Write-through and replay
// ============================================================

#[tokio::test]
async fn a_first_instance_fetches_live_and_writes_each_item_through() {
    let (workspace, binary) = workspace_with_fixture();
    let source = cached_source(workspace.path(), &binary);

    drive_reads(&source).await;

    let functions = source.functions().await.expect("function listing");
    let tick = fixture_export(&functions, "fixture_tick");
    let dir = source.cache_dir().expect("the disk tier is on");
    for entry in [
        "manifest.json",
        "functions.json",
        "strings.json",
        "imports.json",
        "exports.json",
        "image_base.json",
        "data_items.json",
        "data_types/all.json",
        "struct_layout/_iobuf.json",
        &format!("decompile/{}.json", tick.name),
        &format!("disassembly/{}.json", tick.name),
    ] {
        assert!(
            dir.join(entry).is_file(),
            "{entry} should be written through as one document"
        );
    }
    // Address-keyed documents land under the fixture's own addresses.
    let base = source.image_base().await.expect("image base");
    assert!(
        dir.join(format!("memory/{base:x}-2.json")).is_file(),
        "the memory read is filed under its range"
    );
}

#[tokio::test]
async fn a_second_instance_over_the_same_workspace_replays_from_disk() {
    let (workspace, binary) = workspace_with_fixture();

    let first = cached_source(workspace.path(), &binary);
    drive_reads(&first).await;
    let dir = first
        .cache_dir()
        .expect("the disk tier is on")
        .to_path_buf();

    // Tamper the listing with a value the engine could never answer. If a
    // fresh instance returns it, that read came off disk — the only
    // possible replay source — with no engine round trip at all.
    let sentinel_functions = vec![FunctionSummary {
        name: "sentinel_function".into(),
        address: 1,
    }];
    calxgloss_types::save_json(&dir.join("functions.json"), &sentinel_functions)
        .expect("functions tampered");

    let second = cached_source(workspace.path(), &binary);
    let replayed = second.functions().await.expect("function listing");
    assert_eq!(
        replayed, sentinel_functions,
        "the second instance must replay the tampered document, proving a disk read"
    );

    // And the untouched documents replay the engine's own values: the
    // string listing still carries the fixture's literals.
    let strings = second.strings().await.expect("strings replay");
    for want in STRING_LITERALS {
        assert!(
            strings.iter().any(|s| s.value == *want),
            "the intact string document should replay {want:?}"
        );
    }
}

#[tokio::test]
async fn a_warm_disassembly_replays_from_disk_without_an_engine_round_trip() {
    // Issue #245: the listing text is cached like every other scan read.
    // A cold read files it under the scan-cache convention, and a warm
    // instance replays it with no engine round trip at all — a warm scan
    // never re-disassembles.
    let (workspace, binary) = workspace_with_fixture();
    let first = cached_source(workspace.path(), &binary);
    drive_reads(&first).await;
    let dir = first
        .cache_dir()
        .expect("the disk tier is on")
        .to_path_buf();
    let functions = first.functions().await.expect("function listing");
    let tick = fixture_export(&functions, "fixture_tick");

    // The cold read wrote its document beside the decompile documents.
    let document = dir.join(format!("disassembly/{}.json", tick.name));
    assert!(
        document.is_file(),
        "the cold listing is filed under disassembly/"
    );

    // Tamper it with a value the engine could never answer. A fresh
    // instance returning it proves the warm read came off disk.
    calxgloss_types::save_json(&document, &"sentinel listing text").expect("tampered");
    let second = cached_source(workspace.path(), &binary);
    let replayed = second
        .disassembly(&tick.name)
        .await
        .expect("disassembly replay");
    assert_eq!(
        replayed, "sentinel listing text",
        "the warm read must replay the tampered document, proving a disk read"
    );
}

#[tokio::test]
async fn a_refresh_instance_goes_cold_and_rewrites_the_cache() {
    let (workspace, binary) = workspace_with_fixture();

    let first = cached_source(workspace.path(), &binary);
    drive_reads(&first).await;
    let dir = first
        .cache_dir()
        .expect("the disk tier is on")
        .to_path_buf();

    // Tamper the listing, then take the refresh escape hatch (issue #106):
    // same workspace, same bytes, warm disk tier — a refreshing instance
    // ignores it and refetches from the engine.
    let sentinel = vec![FunctionSummary {
        name: "sentinel_function".into(),
        address: 1,
    }];
    calxgloss_types::save_json(&dir.join("functions.json"), &sentinel).expect("tampered");
    let source = KunaSource::load(&binary).expect("fixture loads");
    let refreshed = CachedScanSource::new_refresh(source, &workspace, TARGET_FILE_NAME, &binary)
        .expect("refreshing cached source");
    let functions = refreshed.functions().await.expect("refreshed listing");
    assert!(
        functions
            .iter()
            .any(|f| f.name.trim_start_matches('_') == "fixture_tick"),
        "a refresh refetches live instead of replaying the tampered document"
    );

    // And the refresh rewrote the cache: a third plain instance replays the
    // engine's values, not the sentinel.
    let third = cached_source(workspace.path(), &binary);
    let replayed = third.functions().await.expect("third listing");
    assert_ne!(
        replayed, sentinel,
        "the rewritten cache replays the engine's own listing"
    );
    assert!(
        replayed
            .iter()
            .any(|f| f.name.trim_start_matches('_') == "fixture_tick")
    );
}

#[tokio::test]
async fn concurrent_misses_of_one_item_share_one_fill() {
    let (workspace, binary) = workspace_with_fixture();
    let source = cached_source(workspace.path(), &binary);
    let functions = source.functions().await.expect("function listing");
    let tick = fixture_export(&functions, "fixture_tick");

    let clones: Vec<CachedScanSource> = (0..5).map(|_| source.clone()).collect::<Vec<_>>();
    let handles: Vec<_> = clones
        .into_iter()
        .map(|s| {
            let name = tick.name.clone();
            tokio::spawn(async move { s.decompile(&name).await })
        })
        .collect();
    let mut bodies = Vec::new();
    for handle in handles {
        let body = handle.await.expect("task ran").expect("decompile");
        bodies.push(body);
    }
    for body in &bodies[1..] {
        assert_eq!(
            body, &bodies[0],
            "five concurrent misses of one key share one fill"
        );
    }
}

#[tokio::test]
async fn a_failed_live_fetch_is_not_cached_and_does_not_poison_the_key() {
    let (workspace, binary) = workspace_with_fixture();
    let source = cached_source(workspace.path(), &binary);

    let err = source
        .decompile("no_such_function_anywhere")
        .await
        .expect_err("an unknown name is a named miss");
    assert!(
        matches!(&err, EngineError::NotFound { kind, query }
            if *kind == "function" && query == "no_such_function_anywhere"),
        "{err}"
    );

    // The failure was never written through — the key stays a plain miss.
    let dir = source.cache_dir().expect("the disk tier is on");
    assert!(
        !dir.join("decompile")
            .join("no_such_function_anywhere.json")
            .exists(),
        "a failed fetch writes nothing"
    );

    // A later read of the same key goes to the engine again, and a real
    // decompile still works around the failed key.
    let again = source
        .decompile("no_such_function_anywhere")
        .await
        .expect_err("the retry is a fresh miss, not a replayed failure");
    assert!(matches!(again, EngineError::NotFound { .. }));
    let functions = source.functions().await.expect("function listing");
    let tick = fixture_export(&functions, "fixture_tick");
    let body = source
        .decompile(&tick.name)
        .await
        .expect("a real decompile still works");
    assert!(body.body.contains("fixture_tick"));
}

// ============================================================
// Cold-cache conditions
// ============================================================

#[tokio::test]
async fn changed_binary_bytes_yield_a_cold_cache_under_a_new_directory() {
    let (workspace, binary) = workspace_with_fixture();

    let first = cached_source(workspace.path(), &binary);
    first.functions().await.expect("first listing");

    // A rebuilt binary: same identity, different bytes. Flipping the COFF
    // TimeDateStamp changes the file hash while keeping the image valid —
    // it sits four bytes past the Machine field, at signature + 8.
    let mut bytes = std::fs::read(&binary).expect("binary readable");
    let pe_sig = find_pe_signature(&bytes).expect("the fixture is a PE");
    bytes[pe_sig + 8] ^= 0xff; // TimeDateStamp
    std::fs::write(&binary, &bytes).expect("binary rewritten");

    let second = cached_source(workspace.path(), &binary);
    let functions = second.functions().await.expect("second listing");
    assert!(
        functions
            .iter()
            .any(|f| f.name.trim_start_matches('_') == "fixture_tick"),
        "the second instance reads its own build, not the old cache"
    );
    assert_ne!(
        first.cache_dir().expect("first dir"),
        second.cache_dir().expect("second dir"),
        "each byte-for-byte build gets its own hash directory"
    );
    let identity_dir = second
        .cache_dir()
        .expect("second dir")
        .parent()
        .expect("identity dir")
        .read_dir()
        .expect("identity dir readable");
    assert_eq!(identity_dir.count(), 2, "the old hash directory is kept");
}

fn find_pe_signature(bytes: &[u8]) -> Option<usize> {
    bytes.windows(4).position(|w| w == b"PE\0\0")
}

#[tokio::test]
async fn a_manifest_field_mismatch_yields_a_cold_cache() {
    for field in ["binary_sha256", "format_version", "program"] {
        let (workspace, binary) = workspace_with_fixture();
        let first = cached_source(workspace.path(), &binary);
        first.functions().await.expect("first listing");

        let dir = first
            .cache_dir()
            .expect("the disk tier is on")
            .to_path_buf();
        let manifest_path = dir.join("manifest.json");
        let mut manifest: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&manifest_path).expect("manifest"))
                .expect("manifest json");
        match field {
            "binary_sha256" => manifest["binary_sha256"] = serde_json::json!("stale-hash"),
            "format_version" => manifest["format_version"] = serde_json::json!(999),
            _ => manifest["program"] = serde_json::json!("SomeOther.exe"),
        }
        std::fs::write(&manifest_path, manifest.to_string()).expect("manifest tampered");

        let second = cached_source(workspace.path(), &binary);
        assert!(
            !dir.join("functions.json").is_file(),
            "a cold directory must be wiped at construction, before any refetch"
        );
        let functions = second.functions().await.expect("second listing");
        assert!(
            functions
                .iter()
                .any(|f| f.name.trim_start_matches('_') == "fixture_tick"),
            "a {field} mismatch must treat the directory as cold and refetch"
        );
    }
}

#[tokio::test]
async fn a_corrupt_cache_document_refetches_live_instead_of_failing() {
    let (workspace, binary) = workspace_with_fixture();

    let first = cached_source(workspace.path(), &binary);
    first.functions().await.expect("first listing");
    first.strings().await.expect("first strings");

    let dir = first
        .cache_dir()
        .expect("the disk tier is on")
        .to_path_buf();
    std::fs::write(dir.join("functions.json"), "{ not json").expect("document corrupted");

    let second = cached_source(workspace.path(), &binary);
    let functions = second
        .functions()
        .await
        .expect("corrupt entry refetched live");
    assert!(
        functions
            .iter()
            .any(|f| f.name.trim_start_matches('_') == "fixture_tick"),
        "the corrupt document fell back to a live engine read"
    );
    let strings = second.strings().await.expect("intact entry replayed");
    for want in STRING_LITERALS {
        assert!(
            strings.iter().any(|s| s.value == *want),
            "the intact string document should still replay {want:?}"
        );
    }
}

#[tokio::test]
async fn an_unreadable_binary_path_degrades_to_pass_through_engine_reads() {
    let (workspace, binary) = workspace_with_fixture();

    // The engine loaded the real fixture; the *hashing* path is missing,
    // which drops the disk tier but leaves the loaded engine answering.
    let source = KunaSource::load(&binary).expect("the fixture loads");
    let missing = workspace.path().join("absent.exe");
    let cached = CachedScanSource::new(source, workspace.path(), TARGET_FILE_NAME, &missing)
        .expect("a missing binary is not a construction error");

    assert!(cached.cache_dir().is_none(), "the disk tier is off");
    let functions = cached.functions().await.expect("pass-through listing");
    assert!(
        functions
            .iter()
            .any(|f| f.name.trim_start_matches('_') == "fixture_tick"),
        "reads pass straight through to the engine"
    );
    assert!(
        !workspace.path().join("re").exists(),
        "nothing is filed under the workspace"
    );
}

// ============================================================
// Never-cached writes, passed-through heartbeats, crash safety
// ============================================================

#[tokio::test]
async fn function_tagging_is_refused_by_name() {
    let (workspace, binary) = workspace_with_fixture();
    let source = cached_source(workspace.path(), &binary);
    let functions = source.functions().await.expect("function listing");
    let tick = fixture_export(&functions, "fixture_tick");

    let err = source
        .add_function_tag(&tick.name, "candidate")
        .await
        .expect_err("Kuna has no tag write-back");
    assert!(
        matches!(&err, EngineError::Reported { message } if message.contains("Kuna")),
        "the refusal must name the engine: {err}"
    );
}

#[tokio::test]
async fn heartbeats_pass_straight_through_and_beat_for_live_and_warm_work() {
    let (workspace, binary) = workspace_with_fixture();
    let source = cached_source(workspace.path(), &binary);

    let events = calxgloss_types::TranslationEvents::new(64);
    let mut rx = events.subscribe();
    source.begin_pass(TARGET_FILE_NAME, "evidence scans", &events);
    let functions = source.functions().await.expect("live listing");
    let tick = fixture_export(&functions, "fixture_tick");
    source.decompile(&tick.name).await.expect("live decompile");
    let beat = rx.try_recv().expect("the live decompile beat");
    assert!(
        matches!(&beat, calxgloss_types::ProgressEvent::BatchProgress { pass, .. } if pass == "evidence scans"),
        "expected a BatchProgress beat, got {beat:?}"
    );
    source.end_pass();
    source
        .decompile(&tick.name)
        .await
        .expect("memo-hit decompile, pass over");
    assert!(rx.try_recv().is_err(), "after end_pass nothing beats");
}

#[tokio::test]
async fn a_warm_replay_still_beats_the_heartbeat_per_decompile() {
    let (workspace, binary) = workspace_with_fixture();

    // A cold run fills the disk tier.
    let first = cached_source(workspace.path(), &binary);
    drive_reads(&first).await;

    // A warm instance armed for a pass consumes work items without an
    // engine round trip — the heartbeat must still count them, or the
    // dashboard's per-binary activity line goes silent on every warm run
    // (issue #121).
    let second = cached_source(workspace.path(), &binary);
    let events = calxgloss_types::TranslationEvents::new(64);
    let mut rx = events.subscribe();
    second.begin_pass(TARGET_FILE_NAME, "evidence scans", &events);
    let listed = second.functions().await.expect("warm function listing");
    let tick = fixture_export(&listed, "fixture_tick");
    second
        .decompile(&tick.name)
        .await
        .expect("disk-hit decompile");
    let beat = rx.try_recv().expect("a disk-hit decompile beats");
    match &beat {
        calxgloss_types::ProgressEvent::BatchProgress {
            binary,
            pass,
            function,
            index,
            total,
        } => {
            assert_eq!(binary, TARGET_FILE_NAME);
            assert_eq!(pass, "evidence scans", "the beat names the scan phase");
            assert_eq!(function, &tick.name, "the warm worklist names the item");
            assert_eq!(*index, 1);
            assert_eq!(*total, listed.len(), "the warm worklist carries the total");
        }
        other => panic!("expected BatchProgress, got {other:?}"),
    }

    // Re-armed, the next decompile is a memo hit — it beats too: a fresh
    // phase counts its consumed functions fresh.
    second.begin_pass(TARGET_FILE_NAME, "evidence scans", &events);
    second
        .decompile(&tick.name)
        .await
        .expect("memo-hit decompile");
    let memo_beat = rx.try_recv().expect("a memo-hit decompile beats");
    assert!(
        matches!(&memo_beat, calxgloss_types::ProgressEvent::BatchProgress { pass, function, .. }
            if pass == "evidence scans" && function == &tick.name),
        "the memo hit beats by name: {memo_beat:?}"
    );
    second.end_pass();
}

#[tokio::test]
async fn an_interrupted_run_leaves_every_written_entry_individually_valid() {
    let (workspace, binary) = workspace_with_fixture();

    // A run that fetched three items and stopped — what a crash or Ctrl-C
    // leaves behind.
    let first = cached_source(workspace.path(), &binary);
    first.functions().await.expect("functions");
    first.strings().await.expect("strings");
    let functions = first.functions().await.expect("listing");
    let tick = fixture_export(&functions, "fixture_tick");
    first.decompile(&tick.name).await.expect("one decompile");

    let dir = source_dir(&first);
    for entry in [
        "functions.json",
        "strings.json",
        &format!("decompile/{}.json", tick.name),
    ] {
        let document = std::fs::read_to_string(dir.join(entry)).expect("entry written");
        let parsed: Result<serde_json::Value, _> = serde_json::from_str(&document);
        assert!(
            parsed.is_ok(),
            "{entry} must be a valid JSON document on its own"
        );
    }
    assert!(
        !has_temp_residue(&dir),
        "atomic writes leave no partial files behind"
    );
    assert!(
        !dir.join("imports.json").exists(),
        "what was never fetched was never written"
    );

    // The restart resumes from where it stopped: the written entries
    // replay, the rest fetch normally. Tamper the replayed ones — the
    // restart must return the tampered values (proof they came from disk)
    // while the never-fetched ones arrive live from the engine.
    let dir2 = dir.clone();
    let sentinel = vec![FunctionSummary {
        name: "sentinel_function".into(),
        address: 1,
    }];
    calxgloss_types::save_json(&dir2.join("functions.json"), &sentinel).expect("tampered");
    let second = cached_source(workspace.path(), &binary);
    let replayed = second.functions().await.expect("replayed functions");
    assert_eq!(replayed, sentinel, "the partial cache resumes from disk");
    let imports = second.imports().await.expect("freshly fetched imports");
    assert!(
        imports.iter().any(|i| i.name.contains("puts")),
        "what was never written fetches live"
    );
}

fn source_dir(source: &CachedScanSource) -> PathBuf {
    source
        .cache_dir()
        .expect("the disk tier is on")
        .to_path_buf()
}

fn has_temp_residue(dir: &Path) -> bool {
    let mut stack = vec![dir.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).expect("dir readable") {
            let path = entry.expect("dir entry").path();
            if path.is_dir() {
                stack.push(path);
            } else if path
                .file_name()
                .map(|name| name.to_string_lossy().contains(".tmp"))
                .unwrap_or(false)
            {
                return true;
            }
        }
    }
    false
}

// ============================================================
// Provenance pass-through (issue #208)
// ============================================================

#[test]
fn the_cache_forwards_the_engine_provenance() {
    let (workspace, binary) = workspace_with_fixture();
    let source = cached_source(workspace.path(), &binary);
    let provenance = source
        .engine_provenance()
        .expect("the wrapped Kuna source names its engine");
    assert_eq!(provenance.name, "kuna");
}

// ============================================================
// Capability report pass-through (issue #354)
// ============================================================

/// A cache never changes capabilities, it only caches answers — so the
/// wrapped engine's declaration rides `CachedScanSource` and
/// `PipelineSource` byte-identically, and a source whose engine declares
/// nothing would propagate the same empty, fully-unknown declaration the
/// trait default hands up.
#[test]
fn the_cache_and_pipeline_wrappers_pass_the_capability_report_through_byte_identically() {
    let (workspace, binary) = workspace_with_fixture();
    let raw = KunaSource::load(&binary).expect("the fixture must load for scanning with Kuna");
    let raw_report = ScanSource::capability_report(&raw);
    let raw_bytes = serde_json::to_string(&raw_report).expect("the report serializes");
    assert!(
        !raw_report.families.is_empty(),
        "the wrapped Kuna source declares its full roster"
    );

    let cached = cached_source(workspace.path(), &binary);
    let cached_bytes =
        serde_json::to_string(&cached.capability_report()).expect("the report serializes");
    assert_eq!(
        cached_bytes, raw_bytes,
        "the cache passes the wrapped source's report through untouched"
    );

    let pipeline = calxgloss_decomp::PipelineSource::from(cached.clone());
    let pipeline_bytes =
        serde_json::to_string(&pipeline.capability_report()).expect("the report serializes");
    assert_eq!(
        pipeline_bytes, raw_bytes,
        "the pipeline wrapper forwards the wrapped source's report byte-for-byte"
    );
}
