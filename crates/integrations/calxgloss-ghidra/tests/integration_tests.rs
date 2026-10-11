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
