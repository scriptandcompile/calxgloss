//! End-to-end contract: scan a canned program, persist the document,
//! and read it back — the whole artifact path without a server.

use calxgloss_decomp::{
    DataItem, DataTypeEntry, DecompiledFunction, EngineError, EnumDefinition, FunctionSummary,
    Result, ScanSource, StringLiteral, StructLayout, Symbol, Xref,
};
use calxgloss_floatsimd::{FloatsimdEngine, FloatsimdFinding, FloatsimdPersistor};
use std::collections::HashMap;

struct CannedProgram {
    listing: Vec<FunctionSummary>,
    bodies: HashMap<String, DecompiledFunction>,
}

impl ScanSource for CannedProgram {
    async fn functions(&self) -> Result<Vec<FunctionSummary>> {
        Ok(self.listing.clone())
    }

    async fn decompile(&self, name: &str) -> Result<DecompiledFunction> {
        self.bodies
            .get(name)
            .cloned()
            .ok_or_else(|| EngineError::NotFound {
                kind: "function",
                query: name.to_string(),
            })
    }

    async fn strings(&self) -> Result<Vec<StringLiteral>> {
        Ok(Vec::new())
    }

    async fn callers(&self, _address: u64) -> Result<Vec<String>> {
        Ok(Vec::new())
    }

    async fn xrefs_to(&self, _address: u64) -> Result<Vec<Xref>> {
        Ok(Vec::new())
    }

    async fn data_types(&self, _category: Option<&str>) -> Result<Vec<DataTypeEntry>> {
        Ok(Vec::new())
    }

    async fn struct_layout(&self, name: &str) -> Result<StructLayout> {
        Err(EngineError::NotFound {
            kind: "struct",
            query: name.to_string(),
        })
    }

    async fn enum_values(&self, name: &str) -> Result<EnumDefinition> {
        Err(EngineError::NotFound {
            kind: "enum",
            query: name.to_string(),
        })
    }

    async fn data_items(&self) -> Result<Vec<DataItem>> {
        Ok(Vec::new())
    }

    async fn imports(&self) -> Result<Vec<Symbol>> {
        Ok(Vec::new())
    }

    async fn exports(&self) -> Result<Vec<Symbol>> {
        Ok(Vec::new())
    }

    async fn image_base(&self) -> Result<u64> {
        Ok(0)
    }

    async fn read_memory(&self, _address: u64, _length: usize) -> Result<Vec<u8>> {
        Ok(Vec::new())
    }
}

fn function(name: &str, body: &str) -> DecompiledFunction {
    DecompiledFunction {
        name: name.to_string(),
        signature: format!("undefined {name}(void)"),
        body: format!("undefined {name}(void)\n\n{{\n{body}}}\n"),
    }
}

/// A function-list entry for the canned listing.
fn summary(name: &str, address: u64) -> FunctionSummary {
    FunctionSummary {
        name: name.into(),
        address,
    }
}

#[tokio::test]
async fn a_scan_persists_and_reads_back_the_same_document() {
    let mut bodies = HashMap::new();
    bodies.insert(
        "FUN_18003ab00".into(),
        function(
            "FUN_18003ab00",
            "  fVar1 = (float)uVar2;\n  local_10 = CONCAT44(fVar1, fVar2);\n",
        ),
    );
    bodies.insert(
        "FUN_18003e750".into(),
        function("FUN_18003e750", "  return uVar1 + 4;\n"),
    );
    let program = CannedProgram {
        listing: vec![
            summary("FUN_18003ab00", 0x1800_3ab00),
            summary("FUN_18003e750", 0x1800_3e750),
        ],
        bodies,
    };

    let workspace = tempfile::tempdir().expect("a workspace");
    let result = FloatsimdEngine::with_source(program)
        .scan("game_logic.dll")
        .await
        .expect("the scan runs");
    assert_eq!(result.findings.len(), 1);
    assert_eq!(result.findings[0].kind(), "mixed");
    assert_eq!(
        result.findings[0].function(),
        "FUN_18003ab00",
        "the integer function stays unflagged"
    );

    let persistor = FloatsimdPersistor::new(workspace.path());
    persistor.save(&result).expect("the document saves");
    assert!(
        persistor
            .path_for("game_logic.dll")
            .to_string_lossy()
            .contains("re/analysis/floatsimd/"),
        "the document follows the analysis-directory convention"
    );

    let loaded = persistor
        .load("game_logic.dll")
        .expect("the document loads");
    assert_eq!(loaded, result, "the document reads back exactly as saved");
    let flag = loaded
        .for_function("FUN_18003ab00")
        .next()
        .expect("the flag reads back");
    match flag {
        FloatsimdFinding::Mixed(record) => {
            assert_eq!(record.confidence.value(), 90);
            assert_eq!(record.evidence, "fVar1 = (float)uVar2;");
        }
        other => panic!("the flag is the mixed one, got {other:?}"),
    }
}
