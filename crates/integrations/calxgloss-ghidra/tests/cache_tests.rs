//! `CachedGhidraSource` end-to-end, driven through the shared `ScanSource`
//! seam against a stand-in GhidraMCP server that counts every call it serves.
//!
//! The cache's whole contract is observable from outside: a first instance
//! fetches live and writes through, a second instance over the same
//! workspace replays with zero live reads, changed bytes or a mismatched
//! manifest mean cold, a corrupt document degrades to a live refetch, and
//! writes and heartbeats pass straight through. Server-side call counts are
//! the only instrumentation — no cache internals are inspected.

use calxgloss_ghidra::{
    CachedGhidraSource, DataItem, DataTypeEntry, FunctionSummary, GhidraClient, ScanSource,
    StringLiteral, StructFieldLayout, StructLayout, Symbol, Xref,
};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

const KNOWN_FUNCTION: &str = "FUN_18003e750";
const PROGRAM: &str = "LaunchPad.exe";

/// The read endpoints `drive_reads` reaches the server through; the cache
/// must make the second instance's pass over them cost nothing.
const READ_ENDPOINTS: &[&str] = &[
    "list_functions",
    "search_functions",
    "decompile_function",
    "list_strings",
    "get_xrefs_to",
    "list_data_types",
    "get_struct_layout",
    "get_enum_values",
    "list_data_items",
    "list_imports",
    "list_exports",
    "list_segments",
    "read_memory",
];

// ============================================================
// A counting stand-in GhidraMCP server
// ============================================================

/// A stand-in server answering every endpoint the seam touches with one
/// canned record each (in the 6.x bridge's own text formats), counting how
/// many times it served each endpoint.
struct FakeServer {
    base_url: String,
    calls: Arc<Mutex<HashMap<String, usize>>>,
    /// When positive, the next N endpoint calls answer 500 instead of data.
    fail_next: Arc<AtomicUsize>,
}

impl FakeServer {
    async fn start() -> Self {
        Self::serving(PROGRAM).await
    }

    async fn serving(program: &str) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("fake server should bind");
        let addr = listener.local_addr().expect("fake server address");
        let calls: Arc<Mutex<HashMap<String, usize>>> = Arc::new(Mutex::new(HashMap::new()));
        let counted = Arc::clone(&calls);
        let failing = Arc::new(AtomicUsize::new(0));
        let failing_task = Arc::clone(&failing);
        let program = program.to_string();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let counted = Arc::clone(&counted);
                let failing = Arc::clone(&failing_task);
                let program = program.clone();
                tokio::spawn(async move {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    let mut request = [0u8; 2048];
                    let read = stream.read(&mut request).await.unwrap_or(0);
                    let path = String::from_utf8_lossy(&request[..read])
                        .split_whitespace()
                        .nth(1)
                        .unwrap_or_default()
                        .to_string();
                    let endpoint = path
                        .split('?')
                        .next()
                        .unwrap_or_default()
                        .trim_start_matches('/');
                    if endpoint != "favicon.ico" {
                        *counted
                            .lock()
                            .expect("counts lock")
                            .entry(endpoint.to_string())
                            .or_insert(0) += 1;
                    }
                    let body = if endpoint == "get_current_address"
                        || endpoint == "get_current_function"
                    {
                        format!(
                            "{{\"address\":\"180000000\",\"program\":\"{program}\",\"function_name\":\"{KNOWN_FUNCTION}\"}}"
                        )
                    } else if endpoint == "list_functions" {
                        "FUN_18003e750 at 18003e750".to_string()
                    } else if endpoint == "search_functions" {
                        "FUN_18003e750 @ 18003e750".to_string()
                    } else if endpoint == "decompile_function" {
                        "undefined FUN_18003e750(void)\n{\n  void *pv = malloc(0x10);\n  free(pv);\n}\n"
                            .to_string()
                    } else if endpoint == "list_strings" {
                        "180128d18: \"Journal.txt\"".to_string()
                    } else if endpoint == "get_xrefs_to" {
                        "From 18000a3be in FUN_caller [UNCONDITIONAL_CALL]".to_string()
                    } else if endpoint == "list_data_types" {
                        "_EXCEPTION_DISPOSITION | excpt.h | 4 bytes | /excpt.h/_EXCEPTION_DISPOSITION"
                            .to_string()
                    } else if endpoint == "get_struct_layout" {
                        "Structure: IMAGE_DOS_HEADER\nSize: 128 bytes\nAlignment: 1\n\nLayout:\nOffset | Size | Type | Name\n-------|------|------|-----\n     0 |    2 | char[2] | e_magic\n"
                            .to_string()
                    } else if endpoint == "get_enum_values" {
                        "Enumeration: _EXCEPTION_DISPOSITION\nSize: 4 bytes\n\nValues:\nName | Value\n-----|------\nExceptionContinueExecution | 0 (0x0)\n"
                            .to_string()
                    } else if endpoint == "list_data_items" {
                        "IMAGE_DOS_HEADER_180000000 @ 180000000 [IMAGE_DOS_HEADER] (128 bytes)"
                            .to_string()
                    } else if endpoint == "list_imports" {
                        "malloc -> EXTERNAL:00000123\nfree -> EXTERNAL:00000124".to_string()
                    } else if endpoint == "list_exports" {
                        "DllMain -> 18000c690".to_string()
                    } else if endpoint == "list_segments" {
                        ".text: 180000000 - 1801261ff".to_string()
                    } else if endpoint == "read_memory" {
                        "{\"address\":\"1801306f0\",\"length\":8,\"data\":[0,171,3,128,1,0,0,0],\"hex\":\"00ab038001000000\"}"
                            .to_string()
                    } else if endpoint == "add_function_tag" {
                        "Tag added".to_string()
                    } else {
                        "Error 404: No context found for request".to_string()
                    };
                    let fail = endpoint != "favicon.ico" && failing.load(Ordering::SeqCst) > 0;
                    if fail {
                        failing.fetch_sub(1, Ordering::SeqCst);
                    }
                    let (status, body) = if fail {
                        ("500 Internal Server Error", "boom".to_string())
                    } else {
                        ("200 OK", body)
                    };
                    let response = format!(
                        "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                });
            }
        });
        Self {
            base_url: format!("http://{addr}"),
            calls,
            fail_next: failing,
        }
    }

    fn count(&self, endpoint: &str) -> usize {
        *self
            .calls
            .lock()
            .expect("counts lock")
            .get(endpoint)
            .unwrap_or(&0)
    }

    /// Make the next `n` endpoint calls answer 500 instead of data.
    fn fail_next_calls(&self, n: usize) {
        self.fail_next.store(n, Ordering::SeqCst);
    }

    /// How many read-endpoint calls the server has served in total.
    fn read_calls(&self) -> usize {
        READ_ENDPOINTS.iter().map(|e| self.count(e)).sum()
    }
}

// ============================================================
// Fixtures and drivers
// ============================================================

/// The ticket demands `Clone + Send + Sync`; the clones spawned in the
/// concurrency test prove `Send`, this pins `Sync` as well.
#[test]
fn cached_source_is_clone_send_and_sync() {
    fn assert_clone_send_sync<T: Clone + Send + Sync>() {}
    assert_clone_send_sync::<CachedGhidraSource>();
}

fn sample_functions() -> Vec<FunctionSummary> {
    vec![FunctionSummary {
        name: KNOWN_FUNCTION.into(),
        address: 0x18003e750,
    }]
}

fn sample_strings() -> Vec<StringLiteral> {
    vec![StringLiteral {
        address: 0x180128d18,
        value: "Journal.txt".into(),
    }]
}

fn sample_xrefs() -> Vec<Xref> {
    vec![Xref {
        address: 0x18000a3be,
        function: Some("FUN_caller".into()),
        kind: Some("UNCONDITIONAL_CALL".into()),
    }]
}

fn sample_data_types() -> Vec<DataTypeEntry> {
    vec![DataTypeEntry {
        name: "_EXCEPTION_DISPOSITION".into(),
        category: "excpt.h".into(),
        size: Some(4),
        path: "/excpt.h/_EXCEPTION_DISPOSITION".into(),
    }]
}

fn sample_struct_layout() -> StructLayout {
    StructLayout {
        name: "IMAGE_DOS_HEADER".into(),
        size: 128,
        alignment: 1,
        fields: vec![StructFieldLayout {
            offset: 0,
            size: 2,
            type_name: "char[2]".into(),
            field_name: "e_magic".into(),
        }],
    }
}

fn sample_data_items() -> Vec<DataItem> {
    vec![DataItem {
        label: "IMAGE_DOS_HEADER_180000000".into(),
        address: 0x180000000,
        type_name: "IMAGE_DOS_HEADER".into(),
        length: 128,
    }]
}

fn sample_imports() -> Vec<Symbol> {
    vec![
        Symbol {
            name: "malloc".into(),
            address: 0x123,
            imported: true,
        },
        Symbol {
            name: "free".into(),
            address: 0x124,
            imported: true,
        },
    ]
}

fn sample_exports() -> Vec<Symbol> {
    vec![Symbol {
        name: "DllMain".into(),
        address: 0x18000c690,
        imported: false,
    }]
}

/// Drive every cached read once, asserting each answers with the canned
/// record — cached or not, the values must be the server's own.
async fn drive_reads<S: ScanSource>(source: &S) {
    assert_eq!(
        source.functions().await.expect("function listing"),
        sample_functions()
    );
    let body = source
        .decompile(KNOWN_FUNCTION)
        .await
        .expect("decompile by name");
    assert!(
        body.body.contains("malloc(0x10)"),
        "the decompiled body should come through: {body:?}"
    );
    assert_eq!(source.strings().await.expect("strings"), sample_strings());
    assert_eq!(
        source.callers(0x18003e750).await.expect("callers"),
        vec!["FUN_caller".to_string()]
    );
    assert_eq!(
        source.xrefs_to(0x18003e750).await.expect("xrefs"),
        sample_xrefs()
    );
    assert_eq!(
        source.data_types(None).await.expect("data types"),
        sample_data_types()
    );
    assert_eq!(
        source
            .struct_layout("IMAGE_DOS_HEADER")
            .await
            .expect("struct layout"),
        sample_struct_layout()
    );
    assert_eq!(
        source
            .enum_values("_EXCEPTION_DISPOSITION")
            .await
            .expect("enum values")
            .name,
        "_EXCEPTION_DISPOSITION"
    );
    assert_eq!(
        source.data_items().await.expect("data items"),
        sample_data_items()
    );
    assert_eq!(source.imports().await.expect("imports"), sample_imports());
    assert_eq!(source.exports().await.expect("exports"), sample_exports());
    assert_eq!(source.image_base().await.expect("image base"), 0x180000000);
    assert_eq!(
        source
            .read_memory(0x1801306f0, 8)
            .await
            .expect("memory bytes"),
        vec![0, 171, 3, 128, 1, 0, 0, 0]
    );
}

/// A workspace holding a target binary of `bytes`, returning its path.
fn workspace_with_binary(bytes: &[u8]) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::TempDir::new().expect("temp workspace");
    let binary = dir.path().join(PROGRAM);
    std::fs::write(&binary, bytes).expect("binary written");
    (dir, binary)
}

async fn cached_over(fake: &FakeServer, workspace: &Path, binary: &Path) -> CachedGhidraSource {
    let client = GhidraClient::new(&fake.base_url).expect("fake ghidra client");
    CachedGhidraSource::new(client, workspace, PROGRAM, binary)
        .await
        .expect("cached source")
}

// ============================================================
// Write-through and replay
// ============================================================

#[tokio::test]
async fn a_first_instance_fetches_live_and_writes_each_item_through() {
    let fake = FakeServer::start().await;
    let (workspace, binary) = workspace_with_binary(b"the program's bytes");
    let source = cached_over(&fake, workspace.path(), &binary).await;

    drive_reads(&source).await;

    for endpoint in READ_ENDPOINTS {
        // The client derives `callers` from `get_xrefs_to`, so a cold pass
        // hits that endpoint once per cache key.
        let expected = usize::from(*endpoint == "get_xrefs_to") + 1;
        assert_eq!(
            fake.count(endpoint),
            expected,
            "a cold cache fetches {endpoint} exactly once per key"
        );
    }
    let dir = source.cache_dir().expect("the disk tier is on");
    for entry in [
        "manifest.json",
        "functions.json",
        "strings.json",
        "imports.json",
        "exports.json",
        "image_base.json",
        "data_items.json",
        "decompile/FUN_18003e750.json",
        "callers/18003e750.json",
        "xrefs_to/18003e750.json",
        "data_types/all.json",
        "struct_layout/IMAGE_DOS_HEADER.json",
        "enum_values/_EXCEPTION_DISPOSITION.json",
        "memory/1801306f0-8.json",
    ] {
        assert!(
            dir.join(entry).is_file(),
            "{entry} should be written through as one document"
        );
    }
}

#[tokio::test]
async fn a_second_instance_over_the_same_workspace_replays_with_zero_live_reads() {
    let fake = FakeServer::start().await;
    let (workspace, binary) = workspace_with_binary(b"the program's bytes");

    let first = cached_over(&fake, workspace.path(), &binary).await;
    drive_reads(&first).await;
    let after_first_run = fake.read_calls();
    assert_eq!(
        after_first_run,
        READ_ENDPOINTS.len() + 1,
        "one live call per key (callers rides the xrefs endpoint)"
    );

    // A fresh instance (fresh client, fresh memo) over the same workspace
    // and the same bytes replays every read from disk.
    let second = cached_over(&fake, workspace.path(), &binary).await;
    drive_reads(&second).await;
    assert_eq!(
        fake.read_calls(),
        after_first_run,
        "the second instance must not touch the server for cached reads"
    );
}

#[tokio::test]
async fn concurrent_misses_of_one_item_fire_exactly_one_live_request() {
    let fake = FakeServer::start().await;
    let (workspace, binary) = workspace_with_binary(b"the program's bytes");
    let source = cached_over(&fake, workspace.path(), &binary).await;

    let clones: Vec<CachedGhidraSource> = (0..5).map(|_| source.clone()).collect::<Vec<_>>();
    let handles: Vec<_> = clones
        .into_iter()
        .map(|s| tokio::spawn(async move { s.decompile(KNOWN_FUNCTION).await }))
        .collect();
    for handle in handles {
        let body = handle.await.expect("task ran").expect("decompile");
        assert!(body.body.contains("malloc(0x10)"));
    }
    assert_eq!(
        fake.count("decompile_function"),
        1,
        "five concurrent misses of one key share one live decompile"
    );
    assert_eq!(fake.count("search_functions"), 1);
}

#[tokio::test]
async fn a_failed_live_fetch_is_not_cached_and_does_not_poison_the_key() {
    let fake = FakeServer::start().await;
    let (workspace, binary) = workspace_with_binary(b"fail once");
    let source = cached_over(&fake, workspace.path(), &binary).await;

    // The name-based decompile goes through search_functions first; force
    // that first live hop to fail.
    fake.fail_next_calls(1);
    let first = source.decompile(KNOWN_FUNCTION).await;
    assert!(first.is_err(), "the forced 500 should surface as an error");

    // A later read retries live rather than replaying the failure.
    let second = source
        .decompile(KNOWN_FUNCTION)
        .await
        .expect("the retry should go live again");
    assert!(second.body.contains("malloc(0x10)"));
    // And the successful fetch is now cached for further reads.
    let third = source
        .decompile(KNOWN_FUNCTION)
        .await
        .expect("the successful fetch should be cached");
    assert_eq!(third.body, second.body);

    // The failed search and the successful one both reached the server; the
    // replay did not.
    assert_eq!(fake.count("search_functions"), 2);
    assert_eq!(fake.count("decompile_function"), 1);
}

// ============================================================
// Cold-cache conditions
// ============================================================

#[tokio::test]
async fn changed_binary_bytes_yield_a_cold_cache_under_a_new_directory() {
    let fake = FakeServer::start().await;
    let (workspace, binary) = workspace_with_binary(b"the program's bytes");

    let first = cached_over(&fake, workspace.path(), &binary).await;
    first.functions().await.expect("first listing");

    // A rebuilt binary: same identity, different bytes.
    std::fs::write(&binary, b"a rebuilt program").expect("binary rewritten");
    let second = cached_over(&fake, workspace.path(), &binary).await;
    second.functions().await.expect("second listing");

    assert_eq!(
        fake.count("list_functions"),
        2,
        "changed bytes must not serve the old cache"
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

#[tokio::test]
async fn a_manifest_field_mismatch_yields_a_cold_cache() {
    for field in ["binary_sha256", "format_version", "program"] {
        let fake = FakeServer::start().await;
        let (workspace, binary) = workspace_with_binary(b"the program's bytes");
        let first = cached_over(&fake, workspace.path(), &binary).await;
        first.functions().await.expect("first listing");

        let dir = first.cache_dir().expect("the disk tier is on");
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

        let second = cached_over(&fake, workspace.path(), &binary).await;
        assert!(
            !dir.join("functions.json").is_file(),
            "a cold directory must be wiped at construction, before any refetch"
        );
        second.functions().await.expect("second listing");
        assert_eq!(
            fake.count("list_functions"),
            2,
            "a {field} mismatch must treat the directory as cold"
        );
    }
}

#[tokio::test]
async fn a_different_program_name_from_the_probe_yields_a_cold_cache() {
    let (workspace, binary) = workspace_with_binary(b"the program's bytes");

    let fake = FakeServer::serving(PROGRAM).await;
    let first = cached_over(&fake, workspace.path(), &binary).await;
    first.functions().await.expect("first listing");

    // The same bytes, but Ghidra now has a different program open.
    let other = FakeServer::serving("Rebuilt.exe").await;
    let second = cached_over(&other, workspace.path(), &binary).await;
    second.functions().await.expect("second listing");
    assert_eq!(
        other.count("list_functions"),
        1,
        "the program-name mismatch must force a cold read"
    );
}

#[tokio::test]
async fn a_corrupt_cache_document_refetches_live_instead_of_failing() {
    let fake = FakeServer::start().await;
    let (workspace, binary) = workspace_with_binary(b"the program's bytes");

    let first = cached_over(&fake, workspace.path(), &binary).await;
    first.functions().await.expect("first listing");
    first.strings().await.expect("first strings");

    let dir = first.cache_dir().expect("the disk tier is on");
    std::fs::write(dir.join("functions.json"), "{ not json").expect("document corrupted");

    let second = cached_over(&fake, workspace.path(), &binary).await;
    assert_eq!(
        second
            .functions()
            .await
            .expect("corrupt entry refetched live"),
        sample_functions()
    );
    assert_eq!(
        second.strings().await.expect("intact entry replayed"),
        sample_strings()
    );
    assert_eq!(
        fake.count("list_functions"),
        2,
        "the corrupt entry went live"
    );
    assert_eq!(fake.count("list_strings"), 1, "the intact entry did not");
}

#[tokio::test]
async fn a_missing_binary_file_degrades_to_pass_through_live_reads() {
    let fake = FakeServer::start().await;
    let workspace = tempfile::TempDir::new().expect("temp workspace");
    let missing = workspace.path().join("absent.exe");

    let client = GhidraClient::new(&fake.base_url).expect("fake ghidra client");
    let source = CachedGhidraSource::new(client, workspace.path(), "absent.exe", &missing)
        .await
        .expect("a missing binary is not a construction error");

    assert!(source.cache_dir().is_none(), "the disk tier is off");
    drive_reads(&source).await;
    assert_eq!(
        fake.count("list_functions"),
        1,
        "reads pass straight through to the live client"
    );
    assert_eq!(
        fake.count("get_current_address"),
        0,
        "no manifest, no probe"
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
async fn write_calls_are_never_cached_and_heartbeats_pass_straight_through() {
    let fake = FakeServer::start().await;
    let (workspace, binary) = workspace_with_binary(b"the program's bytes");
    let source = cached_over(&fake, workspace.path(), &binary).await;

    // Writes delegate every time — a cache that swallowed one would leave
    // Ghidra and the pipeline disagreeing about what was tagged.
    source
        .add_function_tag(KNOWN_FUNCTION, "candidate")
        .await
        .expect("tag 1");
    source
        .add_function_tag(KNOWN_FUNCTION, "candidate")
        .await
        .expect("tag 2");
    assert_eq!(fake.count("add_function_tag"), 2, "writes are never cached");

    // begin_pass/end_pass arm the wrapped client's heartbeat; beats fire
    // on live decompiles only — a cached hit is not work done.
    let events = calxgloss_types::TranslationEvents::new(64);
    let mut rx = events.subscribe();
    source.begin_pass(PROGRAM, "call graph", &events);
    source
        .decompile(KNOWN_FUNCTION)
        .await
        .expect("live decompile");
    let beat = rx.try_recv().expect("the live decompile beat");
    assert!(
        matches!(&beat, calxgloss_types::ProgressEvent::BatchProgress { pass, .. } if pass == "call graph"),
        "expected a BatchProgress beat, got {beat:?}"
    );
    source
        .decompile(KNOWN_FUNCTION)
        .await
        .expect("cached decompile");
    assert!(rx.try_recv().is_err(), "a cached hit beats nothing");
    source.end_pass();
    source
        .decompile("FUN_other")
        .await
        .expect("live decompile, pass over");
    assert!(rx.try_recv().is_err(), "after end_pass nothing beats");
}

#[tokio::test]
async fn an_interrupted_run_leaves_every_written_entry_individually_valid() {
    let fake = FakeServer::start().await;
    let (workspace, binary) = workspace_with_binary(b"the program's bytes");

    // A run that fetched three items and stopped — what a crash or Ctrl-C
    // leaves behind.
    let first = cached_over(&fake, workspace.path(), &binary).await;
    first.functions().await.expect("functions");
    first.strings().await.expect("strings");
    first
        .decompile(KNOWN_FUNCTION)
        .await
        .expect("one decompile");

    let dir = source_dir(&first);
    for entry in [
        "functions.json",
        "strings.json",
        "decompile/FUN_18003e750.json",
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

    // The restart resumes from where it stopped: the three written entries
    // replay with zero live calls, the rest fetch normally.
    let reads_before = fake.read_calls();
    let second = cached_over(&fake, workspace.path(), &binary).await;
    second.functions().await.expect("replayed functions");
    second.strings().await.expect("replayed strings");
    second
        .decompile(KNOWN_FUNCTION)
        .await
        .expect("replayed decompile");
    assert_eq!(
        fake.read_calls(),
        reads_before,
        "the partial cache resumes the run without refetching"
    );
}

fn source_dir(source: &CachedGhidraSource) -> PathBuf {
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
