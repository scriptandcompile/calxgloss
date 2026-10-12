//! The shared `ScanSource` seam, exercised from outside the crate.
//!
//! Two things must hold for the seam to serve the planned read cache, and
//! both are checked here rather than inside the crate:
//!
//! * [`GhidraClient`] implements it, driven against the same stand-in
//!   GhidraMCP server the pipeline tests use, so every trait method is
//!   proven to reach the right endpoint and parse the server's own answer.
//! * A test double defined outside this crate can implement it too — the
//!   cache and every engine's `FakeProgram` will be such implementors, so
//!   the trait must not leak implementation-only requirements.
//!
//! Both implementations are driven through one generic function against one
//! set of `sample_*` fixtures, so they are held to identical expectations.

use calxgloss_ghidra::{
    DataItem, DataTypeEntry, DecompiledFunction, EnumDefinition, EnumMember, FunctionSummary,
    GhidraClient, Result, ScanSource, StringLiteral, StructFieldLayout, StructLayout, Symbol, Xref,
};

// ============================================================
// The canned facts every implementation must answer with
// ============================================================

const KNOWN_FUNCTION: &str = "FUN_18003e750";

fn sample_functions() -> Vec<FunctionSummary> {
    vec![FunctionSummary {
        name: KNOWN_FUNCTION.into(),
        address: 0x18003e750,
    }]
}

fn sample_decompiled(name: &str) -> DecompiledFunction {
    DecompiledFunction {
        name: name.to_string(),
        signature: format!("undefined {name}(void)"),
        body: format!("{name}(void)\n{{\n  void *pv = malloc(0x10);\n  free(pv);\n}}\n"),
    }
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

fn sample_callers() -> Vec<String> {
    vec!["FUN_caller".to_string()]
}

fn sample_data_types() -> Vec<DataTypeEntry> {
    vec![DataTypeEntry {
        name: "_EXCEPTION_DISPOSITION".into(),
        category: "excpt.h".into(),
        size: Some(4),
        path: "/excpt.h/_EXCEPTION_DISPOSITION".into(),
    }]
}

fn sample_struct_layout(name: &str) -> StructLayout {
    StructLayout {
        name: name.to_string(),
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

fn sample_enum(name: &str) -> EnumDefinition {
    EnumDefinition {
        name: name.to_string(),
        size: 4,
        members: vec![EnumMember {
            name: "ExceptionContinueExecution".into(),
            value: 0,
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

fn sample_image_base() -> u64 {
    0x180000000
}

fn sample_memory_bytes() -> Vec<u8> {
    vec![0, 171, 3, 128, 1, 0, 0, 0]
}

// ============================================================
// One driver, held to the fixtures above
// ============================================================

/// Drive every read the trait carries through `source`, asserting each
/// answers with the sample fixture for it.
async fn drive_all<S: ScanSource>(source: &S) {
    assert_eq!(
        source.functions().await.expect("function listing"),
        sample_functions()
    );

    let body = source
        .decompile(KNOWN_FUNCTION)
        .await
        .expect("decompile by name");
    assert_eq!(body.name, KNOWN_FUNCTION);
    assert!(
        body.body.contains("malloc(0x10)"),
        "the decompiled body should come through: {body:?}"
    );

    assert_eq!(
        source.strings().await.expect("string listing"),
        sample_strings()
    );
    assert_eq!(
        source
            .xrefs_to(0x18003e750)
            .await
            .expect("xrefs to a function"),
        sample_xrefs()
    );
    assert_eq!(
        source.callers(0x18003e750).await.expect("callers"),
        sample_callers()
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
        sample_struct_layout("IMAGE_DOS_HEADER")
    );
    assert_eq!(
        source
            .enum_values("_EXCEPTION_DISPOSITION")
            .await
            .expect("enum values"),
        sample_enum("_EXCEPTION_DISPOSITION")
    );
    assert_eq!(
        source.data_items().await.expect("data items"),
        sample_data_items()
    );
    assert_eq!(source.imports().await.expect("imports"), sample_imports());
    assert_eq!(source.exports().await.expect("exports"), sample_exports());
    assert_eq!(
        source.image_base().await.expect("image base"),
        sample_image_base()
    );
    assert_eq!(
        source
            .read_memory(0x1801306f0, 8)
            .await
            .expect("memory bytes"),
        sample_memory_bytes()
    );
}

/// A stand-in GhidraMCP server answering every endpoint the trait touches
/// with one canned record each, in the 6.x bridge's own text formats.
/// Returns the base URL to point a client at.
async fn fake_ghidra() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("fake server should bind");
    let addr = listener.local_addr().expect("fake server address");
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut request = [0u8; 2048];
                let read = stream.read(&mut request).await.unwrap_or(0);
                let path = String::from_utf8_lossy(&request[..read])
                    .split_whitespace()
                    .nth(1)
                    .unwrap_or_default()
                    .to_string();
                let body = if path.starts_with("/list_functions") {
                    "FUN_18003e750 at 18003e750".to_string()
                } else if path.starts_with("/search_functions") {
                    "FUN_18003e750 @ 18003e750".to_string()
                } else if path.starts_with("/decompile_function") {
                    "undefined FUN_18003e750(void)\n{\n  void *pv = malloc(0x10);\n  free(pv);\n}\n"
                        .to_string()
                } else if path.starts_with("/list_strings") {
                    "180128d18: \"Journal.txt\"".to_string()
                } else if path.starts_with("/get_xrefs_to") {
                    "From 18000a3be in FUN_caller [UNCONDITIONAL_CALL]".to_string()
                } else if path.starts_with("/list_data_types") {
                    "_EXCEPTION_DISPOSITION | excpt.h | 4 bytes | /excpt.h/_EXCEPTION_DISPOSITION"
                        .to_string()
                } else if path.starts_with("/get_struct_layout") {
                    "Structure: IMAGE_DOS_HEADER\nSize: 128 bytes\nAlignment: 1\n\nLayout:\nOffset | Size | Type | Name\n-------|------|------|-----\n     0 |    2 | char[2] | e_magic\n"
                        .to_string()
                } else if path.starts_with("/get_enum_values") {
                    "Enumeration: _EXCEPTION_DISPOSITION\nSize: 4 bytes\n\nValues:\nName | Value\n-----|------\nExceptionContinueExecution | 0 (0x0)\n"
                        .to_string()
                } else if path.starts_with("/list_data_items") {
                    "IMAGE_DOS_HEADER_180000000 @ 180000000 [IMAGE_DOS_HEADER] (128 bytes)"
                        .to_string()
                } else if path.starts_with("/list_imports") {
                    "malloc -> EXTERNAL:00000123\nfree -> EXTERNAL:00000124".to_string()
                } else if path.starts_with("/list_exports") {
                    "DllMain -> 18000c690".to_string()
                } else if path.starts_with("/list_segments") {
                    ".text: 180000000 - 1801261ff".to_string()
                } else if path.starts_with("/read_memory") {
                    "{\"address\":\"1801306f0\",\"length\":8,\"data\":[0,171,3,128,1,0,0,0],\"hex\":\"00ab038001000000\"}"
                        .to_string()
                } else {
                    "Error 404: No context found for request".to_string()
                };
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
            });
        }
    });
    format!("http://{addr}")
}

#[tokio::test]
async fn ghidra_client_implements_the_trait_against_a_fake_server() {
    let client = GhidraClient::new(&fake_ghidra().await).expect("fake ghidra client");
    drive_all(&client).await;
}

/// The trait's futures are `Send`, so a scan driven through it can move
/// between tasks — what an orchestrating pipeline does.
#[tokio::test]
async fn a_scan_driven_through_the_trait_can_be_spawned() {
    let client = GhidraClient::new(&fake_ghidra().await).expect("fake ghidra client");
    tokio::spawn(async move { drive_all(&client).await })
        .await
        .expect("the spawned scan ran to completion");
}

/// A canned program standing in for a real Ghidra — exactly the shape every
/// engine's `FakeProgram` and the planned read cache will take. That it can
/// be written here, outside the defining crate, is the point of the test.
#[derive(Debug, Default)]
struct CannedProgram;

impl ScanSource for CannedProgram {
    async fn functions(&self) -> Result<Vec<FunctionSummary>> {
        Ok(sample_functions())
    }

    async fn decompile(&self, name: &str) -> Result<DecompiledFunction> {
        Ok(sample_decompiled(name))
    }

    async fn strings(&self) -> Result<Vec<StringLiteral>> {
        Ok(sample_strings())
    }

    async fn callers(&self, _address: u64) -> Result<Vec<String>> {
        Ok(sample_callers())
    }

    async fn xrefs_to(&self, _address: u64) -> Result<Vec<Xref>> {
        Ok(sample_xrefs())
    }

    async fn data_types(&self, _category: Option<&str>) -> Result<Vec<DataTypeEntry>> {
        Ok(sample_data_types())
    }

    async fn struct_layout(&self, name: &str) -> Result<StructLayout> {
        Ok(sample_struct_layout(name))
    }

    async fn enum_values(&self, name: &str) -> Result<EnumDefinition> {
        Ok(sample_enum(name))
    }

    async fn data_items(&self) -> Result<Vec<DataItem>> {
        Ok(sample_data_items())
    }

    async fn imports(&self) -> Result<Vec<Symbol>> {
        Ok(sample_imports())
    }

    async fn exports(&self) -> Result<Vec<Symbol>> {
        Ok(sample_exports())
    }

    async fn image_base(&self) -> Result<u64> {
        Ok(sample_image_base())
    }

    async fn read_memory(&self, _address: u64, _length: usize) -> Result<Vec<u8>> {
        Ok(sample_memory_bytes())
    }
}

#[tokio::test]
async fn a_test_double_outside_the_crate_can_implement_the_trait() {
    drive_all(&CannedProgram).await;
}

// ============================================================
// The GhidraMCP identity probe (issue #111)
// ============================================================

use calxgloss_ghidra::{GhidraError, ServerKind};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

const GUI_CONNECTION: &str = "Connected: GhidraMCP plugin running with program 'eqmain.dll'";
const HEADLESS_CONNECTION: &str = "Connection OK - GhidraMCP Headless Server v6.0.0";
const HEADLESS_METADATA: &str = "Program Name: eqmain.dll\nExecutable Path: /bin/eqmain.dll\nArchitecture: x86:LE:64:default\nFunction Count: 21847\n";

/// A stand-in server answering each named endpoint with a canned body and
/// counting requests per endpoint, so a test can prove which endpoints a
/// probe did — and did not — touch. Anything else gets the bridge's 404.
struct ProbeFake {
    base_url: String,
    calls: Arc<Mutex<HashMap<String, usize>>>,
}

impl ProbeFake {
    async fn serving(routes: &[(&'static str, &'static str)]) -> Self {
        Self::serving_status(
            &routes
                .iter()
                .map(|(p, b)| (*p, 200, *b))
                .collect::<Vec<_>>(),
        )
        .await
    }

    /// As [`serving`](Self::serving), but each route also carries the HTTP
    /// status to answer with — a foreign server's 404 is a different shape
    /// from GhidraMCP's `200`-with-an-error-body.
    async fn serving_status(routes: &[(&'static str, u16, &'static str)]) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("fake server should bind");
        let addr = listener.local_addr().expect("fake server address");
        let calls: Arc<Mutex<HashMap<String, usize>>> = Arc::new(Mutex::new(HashMap::new()));
        let counted = Arc::clone(&calls);
        let routes: Vec<(&'static str, u16, &'static str)> = routes.to_vec();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let counted = Arc::clone(&counted);
                let routes = routes.clone();
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
                        .trim_start_matches('/')
                        .to_string();
                    *counted
                        .lock()
                        .expect("counts lock")
                        .entry(endpoint.clone())
                        .or_insert(0) += 1;
                    let (status, body) = routes
                        .iter()
                        .find(|(name, _, _)| endpoint == *name)
                        .map(|(_, status, body)| (*status, (*body).to_string()))
                        .unwrap_or((404, "Error 404: No context found for request".to_string()));
                    let reason = if status == 404 { "Not Found" } else { "OK" };
                    let response = format!(
                        "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                });
            }
        });
        Self {
            base_url: format!("http://{addr}"),
            calls,
        }
    }

    fn count(&self, endpoint: &str) -> usize {
        self.calls
            .lock()
            .expect("counts lock")
            .get(endpoint)
            .copied()
            .unwrap_or(0)
    }
}

#[tokio::test]
async fn the_identity_probe_parses_the_gui_form() {
    let fake = ProbeFake::serving(&[("check_connection", GUI_CONNECTION)]).await;
    let client = GhidraClient::new(&fake.base_url).expect("client");
    let info = client.check_connection().await.expect("GUI identity");
    assert_eq!(info.kind, ServerKind::Gui);
    assert_eq!(info.program.as_deref(), Some("eqmain.dll"));
    assert_eq!(info.version, None, "the GUI form carries no version");
}

#[tokio::test]
async fn the_identity_probe_parses_the_headless_form() {
    let fake = ProbeFake::serving(&[("check_connection", HEADLESS_CONNECTION)]).await;
    let client = GhidraClient::new(&fake.base_url).expect("client");
    let info = client.check_connection().await.expect("headless identity");
    assert_eq!(info.kind, ServerKind::Headless);
    assert_eq!(info.version.as_deref(), Some("6.0.0"));
}

#[tokio::test]
async fn a_headless_probe_never_touches_the_cursor_endpoints() {
    // A headless server has no GUI cursor; its probe must verify via the
    // connection answer plus `get_metadata`'s current-program block.
    let fake = ProbeFake::serving(&[
        ("check_connection", HEADLESS_CONNECTION),
        ("get_metadata", HEADLESS_METADATA),
    ])
    .await;
    let client = GhidraClient::new(&fake.base_url).expect("client");
    let info = client.probe().await.expect("headless probe");
    assert_eq!(info.program, "eqmain.dll");
    assert_eq!(
        info.function, None,
        "a headless server has no cursor function"
    );
    assert_eq!(
        info.address, None,
        "a headless server has no cursor address"
    );
    assert_eq!(
        fake.count("get_current_address") + fake.count("get_current_function"),
        0,
        "the headless branch must not call GUI-only endpoints"
    );
}

#[tokio::test]
async fn a_gui_probe_still_reads_the_cursor() {
    let fake = ProbeFake::serving(&[
        ("check_connection", GUI_CONNECTION),
        (
            "get_current_address",
            "{\"address\":\"18008ed50\",\"program\":\"eqmain.dll\"}",
        ),
        (
            "get_current_function",
            "{\"function_name\":\"FUN_18008ed50\",\"address\":\"18008ed50\"}",
        ),
    ])
    .await;
    let client = GhidraClient::new(&fake.base_url).expect("client");
    let info = client.probe().await.expect("GUI probe");
    assert_eq!(info.program, "eqmain.dll");
    assert_eq!(info.function.as_deref(), Some("FUN_18008ed50"));
    assert_eq!(info.address, Some(0x18008ed50));
}

#[tokio::test]
async fn a_port_answering_with_an_error_fails_as_not_ghidra_mcp() {
    // The 8080-is-my-local-AI case: the port answers, but its answer is a
    // foreign error shape, not GhidraMCP's — a named failure, not a
    // malformed-response puzzle.
    let fake =
        ProbeFake::serving(&[("check_connection", "{\"error\":\"unknown endpoint\"}")]).await;
    let client = GhidraClient::new(&fake.base_url).expect("client");
    let err = client
        .probe()
        .await
        .expect_err("a foreign server must not pass as GhidraMCP");
    assert!(
        matches!(err, GhidraError::NotGhidraMcp { .. }),
        "expected NotGhidraMcp, got {err:?}"
    );
}

#[tokio::test]
async fn a_port_answering_with_foreign_content_fails_as_not_ghidra_mcp() {
    // Same failure through the other door: a 200 whose body simply is not
    // one of GhidraMCP's connection sentences.
    let fake = ProbeFake::serving(&[("check_connection", "<h1>404 Not Found</h1>")]).await;
    let client = GhidraClient::new(&fake.base_url).expect("client");
    let err = client
        .check_connection()
        .await
        .expect_err("HTML is not a GhidraMCP identity");
    assert!(
        matches!(err, GhidraError::NotGhidraMcp { .. }),
        "expected NotGhidraMcp, got {err:?}"
    );
}

#[tokio::test]
async fn a_port_answering_with_a_real_404_fails_as_not_ghidra_mcp() {
    // The realistic foreign-server shape: a plain HTTP server (the local AI
    // on 8080) answers the endpoint it does not have with a real 404.
    let fake =
        ProbeFake::serving_status(&[("check_connection", 404, "<h1>404 Not Found</h1>")]).await;
    let client = GhidraClient::new(&fake.base_url).expect("client");
    let err = client
        .probe()
        .await
        .expect_err("a 404 from a foreign server must not pass as GhidraMCP");
    assert!(
        matches!(err, GhidraError::NotGhidraMcp { .. }),
        "expected NotGhidraMcp, got {err:?}"
    );
}

#[tokio::test]
async fn an_unreachable_server_fails_as_server_unreachable() {
    // Bind, learn the address, drop the listener: nothing is home.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("port should bind");
    let addr = listener.local_addr().expect("fake server address");
    drop(listener);
    let client = GhidraClient::new(&format!("http://{addr}")).expect("client");
    let err = client
        .check_connection()
        .await
        .expect_err("nothing is listening");
    assert!(
        matches!(err, GhidraError::ServerUnreachable { .. }),
        "expected ServerUnreachable, got {err:?}"
    );
}

#[tokio::test]
async fn an_under_versioned_plugin_fails_as_version_mismatch() {
    let fake = ProbeFake::serving(&[(
        "check_connection",
        "Connection OK - GhidraMCP Headless Server v5.4.0",
    )])
    .await;
    let client = GhidraClient::new(&fake.base_url).expect("client");
    let err = client
        .check_connection()
        .await
        .expect_err("an old plugin must fail by name");
    match err {
        GhidraError::VersionMismatch { found, required } => {
            assert_eq!(found, "5.4.0");
            assert_eq!(required, "6.0.0");
        }
        other => panic!("expected VersionMismatch, got {other:?}"),
    }
}

// ============================================================
// The read-only stack check (`calxgloss doctor`'s engine)
// ============================================================

use calxgloss_ghidra::lifecycle::{
    ExtensionVerdict, InstallDiscovery, ServerDiscovery, StackRequest, check_stack,
};

/// A fake install `<home>/ghidra_<version>_PUBLIC` with a valid layout.
fn sample_install(home: &std::path::Path, version: &str) -> std::path::PathBuf {
    let path = home.join(format!("ghidra_{version}_PUBLIC"));
    std::fs::create_dir_all(path.join("Ghidra").join("Framework")).expect("create layout");
    path
}

/// A fake GhidraMCP extension under `<home>/.config/ghidra/ghidra_<state>_PUBLIC`.
fn sample_extension(
    home: &std::path::Path,
    state: &str,
    built_for: &str,
    plugin: &str,
) -> std::path::PathBuf {
    let dir = home
        .join(".config")
        .join("ghidra")
        .join(format!("ghidra_{state}_PUBLIC"))
        .join("Extensions")
        .join("GhidraMCP");
    std::fs::create_dir_all(dir.join("lib")).expect("create extension dirs");
    std::fs::write(
        dir.join("extension.properties"),
        format!("name=GhidraMCP\ndescription=Plugin version {plugin}.\nversion={built_for}\n"),
    )
    .expect("write manifest");
    std::fs::write(dir.join("lib").join(format!("GhidraMCP-{plugin}.jar")), b"")
        .expect("write jar");
    dir
}

#[tokio::test]
async fn the_stack_check_passes_against_a_complete_stack() {
    let home = tempfile::tempdir().expect("tempdir");
    let install = sample_install(home.path(), "12.1.2");
    sample_extension(home.path(), "12.1.2", "12.1.2", "6.0.0");
    let fake = ProbeFake::serving(&[("check_connection", HEADLESS_CONNECTION)]).await;
    let client = GhidraClient::new(&fake.base_url).expect("client");

    let request = StackRequest {
        env_install_dir: None,
        config_install_dir: None,
        home: Some(home.path()),
    };
    let report = check_stack(&client, &request).await;
    assert!(report.all_ok(), "report: {report:?}");
    match &report.install {
        InstallDiscovery::Found { install: found, .. } => assert_eq!(found.path, install),
        other => panic!("expected a found install, got {other:?}"),
    }
    assert_eq!(
        report.extension,
        Some(ExtensionVerdict::Ok {
            plugin_version: Some("6.0.0".into()),
            built_for: "12.1.2".into(),
        })
    );
    match &report.server {
        ServerDiscovery::Up { info, url } => {
            assert_eq!(info.kind, ServerKind::Headless);
            assert_eq!(info.version.as_deref(), Some("6.0.0"));
            assert_eq!(
                url,
                &format!("{}/", fake.base_url),
                "the probed URL, normalized"
            );
        }
        other => panic!("expected an up server, got {other:?}"),
    }
}

#[tokio::test]
async fn the_stack_check_reports_an_unreachable_server_as_none_not_a_crash() {
    // Bind and drop a listener so the port is almost certainly refused —
    // the doctor contract is that this reports `Unreachable`, never panics.
    let spare = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("spare port should bind");
    let url = format!("http://{}", spare.local_addr().expect("address"));
    drop(spare);
    let home = tempfile::tempdir().expect("tempdir");
    sample_install(home.path(), "12.1.2");
    sample_extension(home.path(), "12.1.2", "12.1.2", "6.0.0");
    let client = GhidraClient::new(&url).expect("client");

    let report = check_stack(
        &client,
        &StackRequest {
            env_install_dir: None,
            config_install_dir: None,
            home: Some(home.path()),
        },
    )
    .await;
    assert!(matches!(report.server, ServerDiscovery::Unreachable { .. }));
    assert!(
        !report.all_ok(),
        "a stack with no server must not pass the gate"
    );
}

#[tokio::test]
async fn the_stack_check_flags_an_extension_built_for_another_ghidra_build() {
    // The ADR-0001 failure: Ghidra was upgraded, the extension was not.
    let home = tempfile::tempdir().expect("tempdir");
    sample_install(home.path(), "12.1.2");
    sample_extension(home.path(), "12.1.2", "12.1.1", "6.0.0");
    let fake = ProbeFake::serving(&[("check_connection", HEADLESS_CONNECTION)]).await;
    let client = GhidraClient::new(&fake.base_url).expect("client");

    let report = check_stack(
        &client,
        &StackRequest {
            env_install_dir: None,
            config_install_dir: None,
            home: Some(home.path()),
        },
    )
    .await;
    match &report.extension {
        Some(ExtensionVerdict::WrongBuild {
            built_for,
            ghidra,
            extensions_dir,
        }) => {
            assert_eq!(built_for, "12.1.1");
            assert_eq!(ghidra, "12.1.2");
            assert!(
                extensions_dir.ends_with("ghidra_12.1.2_PUBLIC/Extensions"),
                "hint path: {}",
                extensions_dir.display()
            );
        }
        other => panic!("expected a wrong-build verdict, got {other:?}"),
    }
    assert!(!report.all_ok());
}

#[tokio::test]
async fn the_stack_check_names_a_foreign_port_as_not_ghidra_mcp() {
    // The 8080-is-my-local-AI class of error: the port answers HTTP, but the
    // answer is not GhidraMCP's.
    let fake =
        ProbeFake::serving_status(&[("check_connection", 404, "<h1>404 Not Found</h1>")]).await;
    let home = tempfile::tempdir().expect("tempdir");
    sample_install(home.path(), "12.1.2");
    sample_extension(home.path(), "12.1.2", "12.1.2", "6.0.0");
    let client = GhidraClient::new(&fake.base_url).expect("client");

    let report = check_stack(
        &client,
        &StackRequest {
            env_install_dir: None,
            config_install_dir: None,
            home: Some(home.path()),
        },
    )
    .await;
    assert!(matches!(
        report.server,
        ServerDiscovery::NotGhidraMcp { .. }
    ));
    assert!(!report.all_ok());
}

#[tokio::test]
async fn the_stack_check_skips_the_extension_when_no_install_validates() {
    // The extension lives per Ghidra build; with no install there is no
    // version to pair against, so the verdict is honestly absent rather
    // than a guess.
    let home = tempfile::tempdir().expect("tempdir");
    let fake = ProbeFake::serving(&[("check_connection", HEADLESS_CONNECTION)]).await;
    let client = GhidraClient::new(&fake.base_url).expect("client");

    let report = check_stack(
        &client,
        &StackRequest {
            env_install_dir: None,
            config_install_dir: None,
            home: Some(home.path()),
        },
    )
    .await;
    assert_eq!(report.install, InstallDiscovery::NotFound);
    assert_eq!(report.extension, None);
    assert!(!report.all_ok());
}

// ============================================================
// The wrong-program guard (issue #113, incident 2026-10-08)
// ============================================================

use calxgloss_ghidra::lifecycle::{ProgramMatch, ensure_current_program};

const OPEN_PROGRAMS_TARGET_CURRENT: &str = "{\"programs\":[{\"name\":\"eqmain.dll\",\"path\":\"/eqmain.dll\",\"is_current\":true,\"function_count\":21847}],\"count\":1,\"current_program\":\"eqmain.dll\"}";
const OPEN_PROGRAMS_TARGET_STALE: &str = "{\"programs\":[{\"name\":\"eqmain.dll\",\"path\":\"/eqmain.dll\",\"is_current\":false,\"function_count\":21847},{\"name\":\"shell32.dll\",\"path\":\"/shell32.dll\",\"is_current\":true,\"function_count\":1234}],\"count\":2,\"current_program\":\"shell32.dll\"}";
const OPEN_PROGRAMS_ONLY_OTHER: &str = "{\"programs\":[{\"name\":\"shell32.dll\",\"path\":\"/shell32.dll\",\"is_current\":true,\"function_count\":1234}],\"count\":1,\"current_program\":\"shell32.dll\"}";
const OPEN_PROGRAMS_NONE: &str = "{\"programs\":[],\"count\":0,\"current_program\":null}";
const SWITCHED_TO_EQMAIN: &str = "{\"switched_to\":\"eqmain.dll\"}";

#[tokio::test]
async fn the_guard_passes_when_the_target_is_already_current() {
    let fake = ProbeFake::serving(&[("list_open_programs", OPEN_PROGRAMS_TARGET_CURRENT)]).await;
    let client = GhidraClient::new(&fake.base_url).expect("client");

    let matched = ensure_current_program(&client, "eqmain.dll")
        .await
        .expect("the target is current");
    assert_eq!(matched, ProgramMatch::AlreadyCurrent);
    assert_eq!(
        fake.count("switch_program"),
        0,
        "a current target needs no switch"
    );
}

#[tokio::test]
async fn the_guard_switches_to_an_open_program_that_is_not_current() {
    // The incident's shape: several programs open, the scan target among
    // them but not the one answering queries. The guard switches and the
    // run proceeds against it.
    let fake = ProbeFake::serving(&[
        ("list_open_programs", OPEN_PROGRAMS_TARGET_STALE),
        ("switch_program", SWITCHED_TO_EQMAIN),
    ])
    .await;
    let client = GhidraClient::new(&fake.base_url).expect("client");

    let matched = ensure_current_program(&client, "eqmain.dll")
        .await
        .expect("the target is open and gets switched to");
    assert_eq!(matched, ProgramMatch::Switched);
    assert_eq!(
        fake.count("switch_program"),
        1,
        "the stale current program triggers exactly one switch"
    );
}

#[tokio::test]
async fn the_guard_fails_fast_naming_the_programs_that_are_open() {
    // Target not open at all: fail before any scan endpoint is touched,
    // and name the programs that *are* open so the operator can fix the
    // right window.
    let fake = ProbeFake::serving(&[("list_open_programs", OPEN_PROGRAMS_ONLY_OTHER)]).await;
    let client = GhidraClient::new(&fake.base_url).expect("client");

    let err = ensure_current_program(&client, "eqmain.dll")
        .await
        .expect_err("a target that is not open must fail the run");
    assert!(
        matches!(err, GhidraError::WrongProgram { .. }),
        "expected WrongProgram, got {err:?}"
    );
    let message = err.to_string();
    assert!(
        message.contains("eqmain.dll"),
        "the message names the target: {message}"
    );
    assert!(
        message.contains("shell32.dll"),
        "the message lists the open programs: {message}"
    );
    assert_eq!(
        fake.count("switch_program"),
        0,
        "a program that is not open cannot be switched to"
    );
    assert_eq!(
        fake.count("list_functions"),
        0,
        "the guard fails before any scan endpoint is touched"
    );
}

#[tokio::test]
async fn the_guard_says_none_when_no_program_is_open() {
    let fake = ProbeFake::serving(&[("list_open_programs", OPEN_PROGRAMS_NONE)]).await;
    let client = GhidraClient::new(&fake.base_url).expect("client");

    let err = ensure_current_program(&client, "eqmain.dll")
        .await
        .expect_err("nothing open means nothing to scan");
    let message = err.to_string();
    assert!(
        message.contains("none"),
        "the message says honestly that nothing is open: {message}"
    );
}

#[tokio::test]
async fn the_guard_surfaces_a_switch_the_server_refuses() {
    // The listing says the target is open, but the switch itself fails —
    // the server's own reason must reach the caller, not a false success.
    // The 6.x bridge reports switch failures as a JSON error body.
    let fake = ProbeFake::serving(&[
        ("list_open_programs", OPEN_PROGRAMS_TARGET_STALE),
        (
            "switch_program",
            "{\"error\":\"Program not found: eqmain.dll\"}",
        ),
    ])
    .await;
    let client = GhidraClient::new(&fake.base_url).expect("client");

    let err = ensure_current_program(&client, "eqmain.dll")
        .await
        .expect_err("a refused switch fails the guard");
    assert!(
        matches!(err, GhidraError::Reported { .. }),
        "the server's reason propagates: {err:?}"
    );
}

// ============================================================
// The session preflight: attach vs. start decisions (issue #114, G1-T4)
// ============================================================

use calxgloss_ghidra::lifecycle::{BRIDGE_DEFAULT_PORT, GhidraSession, Ownership, SessionRequest};

/// A session request pointed at `url` with a project beside a tempdir, so
/// log and pid files could land somewhere writable without polluting
/// anything, and no socket dir to discover through.
fn session_request<'a>(
    url: &'a str,
    project: &'a std::path::Path,
    home: &'a std::path::Path,
) -> SessionRequest<'a> {
    SessionRequest {
        url,
        api_key: None,
        project,
        socket_dir: None,
        fallback_port: BRIDGE_DEFAULT_PORT,
        stack: StackRequest {
            env_install_dir: None,
            config_install_dir: None,
            home: Some(home),
        },
        start_timeout: std::time::Duration::from_millis(200),
    }
}

#[tokio::test]
async fn a_running_gui_server_is_attached_and_never_owned() {
    let home = tempfile::tempdir().expect("tempdir");
    let fake = ProbeFake::serving(&[("check_connection", GUI_CONNECTION)]).await;

    let session = GhidraSession::ensure(
        &session_request(&fake.base_url, &home.path().join("eqmain.gpr"), home.path()),
        None,
    )
    .await
    .expect("a running server is attachable");
    assert_eq!(session.ownership(), Ownership::Attached);
    assert_eq!(session.server_info().kind, ServerKind::Gui);

    // Shutting down an attached session must not touch the server: its owner
    // is a human at a Ghidra window (design risk 5).
    session.shutdown().await;
    assert_eq!(
        fake.count("close_project"),
        0,
        "an attached project stays open"
    );
}

#[tokio::test]
async fn a_running_headless_server_is_attached_too() {
    // A manually started headless server is someone else's process too —
    // ownership follows who spawned it, never the server's kind.
    let home = tempfile::tempdir().expect("tempdir");
    let fake = ProbeFake::serving(&[("check_connection", HEADLESS_CONNECTION)]).await;

    let session = GhidraSession::ensure(
        &session_request(&fake.base_url, &home.path().join("eqmain.gpr"), home.path()),
        None,
    )
    .await
    .expect("a running headless server is attachable");
    assert_eq!(session.ownership(), Ownership::Attached);
    assert_eq!(session.server_info().kind, ServerKind::Headless);
    session.shutdown().await;
    assert_eq!(fake.count("close_project"), 0);
}

#[tokio::test]
async fn a_foreign_port_fails_fast_and_is_never_spawned_over() {
    // The 8080-is-my-local-AI class of error, even with a complete stack
    // fixture that *could* spawn: the probe's named error wins, and nothing
    // is started over a port something else is answering on.
    let home = tempfile::tempdir().expect("tempdir");
    sample_install(home.path(), "12.1.2");
    sample_extension(home.path(), "12.1.2", "12.1.2", "6.0.0");
    let fake =
        ProbeFake::serving_status(&[("check_connection", 404, "<h1>404 Not Found</h1>")]).await;

    let err = GhidraSession::ensure(
        &session_request(&fake.base_url, &home.path().join("eqmain.gpr"), home.path()),
        None,
    )
    .await
    .expect_err("a foreign port is a named failure, not a spawn trigger");
    assert!(
        matches!(err, GhidraError::NotGhidraMcp { .. }),
        "the probe's own verdict propagates: {err:?}"
    );
}

#[tokio::test]
async fn an_under_versioned_plugin_fails_fast_too() {
    let home = tempfile::tempdir().expect("tempdir");
    sample_install(home.path(), "12.1.2");
    sample_extension(home.path(), "12.1.2", "12.1.2", "6.0.0");
    let fake = ProbeFake::serving(&[(
        "check_connection",
        "Connection OK - GhidraMCP Headless Server v5.4.0",
    )])
    .await;

    let err = GhidraSession::ensure(
        &session_request(&fake.base_url, &home.path().join("eqmain.gpr"), home.path()),
        None,
    )
    .await
    .expect_err("an old plugin is a named failure");
    assert!(
        matches!(err, GhidraError::VersionMismatch { .. }),
        "ADR-0001's floor propagates: {err:?}"
    );
}

#[tokio::test]
async fn a_spawn_with_no_ghidra_install_names_what_is_missing() {
    // Nothing answers the probe, so a spawn is the only way forward — but
    // there is no install to spawn, and the error says so instead of trying.
    let spare = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("spare port should bind");
    let url = format!("http://{}", spare.local_addr().expect("address"));
    drop(spare);
    let home = tempfile::tempdir().expect("tempdir");

    let err = GhidraSession::ensure(
        &session_request(&url, &home.path().join("eqmain.gpr"), home.path()),
        None,
    )
    .await
    .expect_err("no install means no spawn");
    match err {
        GhidraError::CannotSpawn { reason } => {
            assert!(
                reason.contains("no Ghidra install was found"),
                "the reason names the missing piece: {reason}"
            );
        }
        other => panic!("expected CannotSpawn, got {other:?}"),
    }
}

#[tokio::test]
async fn a_spawn_with_no_extension_names_the_extensions_dir() {
    // The ADR-0001 pairing again: Ghidra is installed, the bridge is not —
    // the error must say where the zip belongs.
    let spare = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("spare port should bind");
    let url = format!("http://{}", spare.local_addr().expect("address"));
    drop(spare);
    let home = tempfile::tempdir().expect("tempdir");
    sample_install(home.path(), "12.1.2");

    let err = GhidraSession::ensure(
        &session_request(&url, &home.path().join("eqmain.gpr"), home.path()),
        None,
    )
    .await
    .expect_err("no extension means no spawn");
    match err {
        GhidraError::CannotSpawn { reason } => {
            assert!(
                reason.contains("extension is not installed")
                    && reason.contains("ghidra_12.1.2_PUBLIC/Extensions"),
                "the reason names the missing extension and where it goes: {reason}"
            );
        }
        other => panic!("expected CannotSpawn, got {other:?}"),
    }
}

#[tokio::test]
async fn a_busy_port_refuses_the_spawn_by_name() {
    // Design risk 4: never bind a busy port. Something holds the configured
    // port but does not answer as GhidraMCP (it hangs up on every request),
    // discovery finds no live server to attach to instead, and the fallback
    // is held too — so the free-port policy is what stops the spawn.
    let holder = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("port holder should bind");
    let url = format!("http://{}", holder.local_addr().expect("address"));
    tokio::spawn(async move {
        while let Ok((stream, _)) = holder.accept().await {
            drop(stream); // answer nothing, hang up
        }
    });
    let fallback_holder = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("fallback holder should bind");
    let fallback = fallback_holder.local_addr().expect("address").port();
    let home = tempfile::tempdir().expect("tempdir");
    sample_install(home.path(), "12.1.2");
    sample_extension(home.path(), "12.1.2", "12.1.2", "6.0.0");

    let project = home.path().join("eqmain.gpr");
    let request = SessionRequest {
        fallback_port: fallback,
        ..session_request(&url, &project, home.path())
    };
    let err = GhidraSession::ensure(&request, None)
        .await
        .expect_err("a held port must not be spawned onto");
    match err {
        GhidraError::PortBusy { url: named } => assert_eq!(named, format!("{url}/")),
        other => panic!("expected PortBusy, got {other:?}"),
    }
}

// ============================================================
// UDS port discovery + reconciliation (issue #115, G1-T5)
// ============================================================

/// A fake bridge registration: a UDS named `ghidra-<pid>.sock` answering
/// `GET /mcp/instance_info` with the bridge's own record shape, framed
/// exactly as the bridge's UDS server frames it. A plain thread, because
/// the session's scan is blocking and the test runtime must stay free.
fn fake_registration(dir: &std::path::Path, pid: u32, tcp_port: i64, project: &str) {
    let listener = std::os::unix::net::UnixListener::bind(dir.join(format!("ghidra-{pid}.sock")))
        .expect("bind fake registration");
    let body = format!(
        "{{\"pid\":{pid},\"project\":\"{project}\",\"project_path\":\"/eq/{project}\",\
         \"programs\":[],\"tcp_port\":{tcp_port},\"tools\":1}}"
    );
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    std::thread::spawn(move || {
        while let Ok((mut stream, _)) = listener.accept() {
            use std::io::{Read as _, Write as _};
            // Read the request before answering, as the bridge does —
            // closing over an unread request earns an RST.
            let mut request = [0u8; 1024];
            let _ = stream.read(&mut request);
            let _ = stream.write_all(response.as_bytes());
        }
    });
}

/// The port a `ProbeFake`'s base URL names.
fn port_of(base_url: &str) -> i64 {
    base_url
        .rsplit(':')
        .next()
        .and_then(|port| port.parse().ok())
        .expect("the fake's URL names a port")
}

/// A PID guaranteed dead: a short-lived child, reaped.
fn dead_pid() -> u32 {
    let mut child = std::process::Command::new("/bin/true")
        .spawn()
        .expect("spawn /bin/true");
    let pid = child.id();
    child.wait().expect("reap /bin/true");
    pid
}

/// A configured URL nothing answers: a bound-then-dropped spare port.
fn unreachable_url() -> String {
    let spare = std::net::TcpListener::bind("127.0.0.1:0").expect("spare port should bind");
    let url = format!("http://{}", spare.local_addr().expect("address"));
    drop(spare);
    url
}

#[tokio::test]
async fn a_stale_configured_port_attaches_to_a_discovered_server() {
    // The reboot case: the configured port answers nothing, but the bridge's
    // runtime-socket dir carries a live registration naming the port that
    // *does* answer. The session corrects the URL, attaches, and owns
    // nothing — no spawn, no install needed.
    let fake = ProbeFake::serving(&[("check_connection", GUI_CONNECTION)]).await;
    let sockets = tempfile::tempdir().expect("tempdir");
    fake_registration(
        sockets.path(),
        std::process::id(),
        port_of(&fake.base_url),
        "EQ_Ghidra",
    );
    let home = tempfile::tempdir().expect("tempdir");

    let url = unreachable_url();
    let project = home.path().join("eqmain.gpr");
    let request = SessionRequest {
        socket_dir: Some(sockets.path()),
        ..session_request(&url, &project, home.path())
    };
    let session = GhidraSession::ensure(&request, None)
        .await
        .expect("the stale port is corrected to the discovered server");
    assert_eq!(
        session.ownership(),
        Ownership::Attached,
        "a discovered server is someone else's process"
    );
    assert_eq!(session.server_info().kind, ServerKind::Gui);
    assert_eq!(
        fake.count("check_connection"),
        1,
        "the discovered port was probed"
    );

    session.shutdown().await;
    assert_eq!(
        fake.count("close_project"),
        0,
        "the attached server is left untouched"
    );
}

#[tokio::test]
async fn a_dead_registration_falls_through_to_the_spawn_decision() {
    // Dead sockets are ignored: with nothing live discovered and no Ghidra
    // install to spawn, the preflight fails exactly the way it did before
    // discovery existed.
    let sockets = tempfile::tempdir().expect("tempdir");
    std::fs::write(
        sockets.path().join(format!("ghidra-{}.sock", dead_pid())),
        "",
    )
    .expect("write stale registration");
    let home = tempfile::tempdir().expect("tempdir");

    let url = unreachable_url();
    let project = home.path().join("eqmain.gpr");
    let request = SessionRequest {
        socket_dir: Some(sockets.path()),
        ..session_request(&url, &project, home.path())
    };
    let err = GhidraSession::ensure(&request, None)
        .await
        .expect_err("a dead registration is not a server");
    assert!(
        matches!(err, GhidraError::CannotSpawn { .. }),
        "the scan ignored the dead socket and the spawn check failed as before: {err:?}"
    );
}

#[tokio::test]
async fn a_discovered_port_that_is_not_ghidramcp_is_skipped() {
    // A registration whose TCP port answers as something else (the probe's
    // 404 form) is not attachable: reconciliation verifies identity, does
    // not trust the socket alone, and falls through to the spawn decision.
    let foreign =
        ProbeFake::serving_status(&[("check_connection", 404, "<h1>404 Not Found</h1>")]).await;
    let sockets = tempfile::tempdir().expect("tempdir");
    fake_registration(
        sockets.path(),
        std::process::id(),
        port_of(&foreign.base_url),
        "EQ_Ghidra",
    );
    let home = tempfile::tempdir().expect("tempdir");

    let url = unreachable_url();
    let project = home.path().join("eqmain.gpr");
    let request = SessionRequest {
        socket_dir: Some(sockets.path()),
        ..session_request(&url, &project, home.path())
    };
    let err = GhidraSession::ensure(&request, None)
        .await
        .expect_err("a foreign discovered port is not attachable");
    assert!(
        matches!(err, GhidraError::CannotSpawn { .. }),
        "the session moved past the foreign port to the spawn decision: {err:?}"
    );
    assert_eq!(
        foreign.count("check_connection"),
        1,
        "the discovered port was probed and rejected"
    );
}

#[tokio::test]
async fn the_wrong_program_guard_rides_on_the_session() {
    // Commands reach the incident fix through the session, not by wiring the
    // guard by hand: the same routes as the standalone guard, through
    // `ensure_current_program`.
    let home = tempfile::tempdir().expect("tempdir");
    let fake = ProbeFake::serving(&[
        ("check_connection", HEADLESS_CONNECTION),
        ("list_open_programs", OPEN_PROGRAMS_TARGET_STALE),
        ("switch_program", SWITCHED_TO_EQMAIN),
    ])
    .await;

    let session = GhidraSession::ensure(
        &session_request(&fake.base_url, &home.path().join("eqmain.gpr"), home.path()),
        None,
    )
    .await
    .expect("attach to the fake");
    let matched = session
        .ensure_current_program("eqmain.dll")
        .await
        .expect("the target is open, if not current");
    assert_eq!(matched, ProgramMatch::Switched);
    assert_eq!(fake.count("switch_program"), 1);
    session.shutdown().await;
}
