//! Import-table scanning: binary-level API identification.
//!
//! Reads the binary's import table via [`ScanSource::imports`], classifies
//! each entry against the [`MappingDatabase`], and produces [`ApiFinding`]s:
//! identified imports carry their library and Rust crate suggestion, while
//! unidentified and ordinal-only imports are kept as entries with no
//! library — the issue's "import table entries" output.

use tracing::debug;

use crate::engine::ScanSource;
use crate::error::Result;
use crate::lib_mapping::MappingDatabase;
use crate::types::{ApiFinding, ApiSignature, Confidence};

/// Scans a binary's import table and identifies known APIs.
#[derive(Debug, Clone, Default)]
pub struct ImportTableScanner {
    mappings: MappingDatabase,
}

/// Confidence that a mapping-recognized import really is that library's API.
const IDENTIFIED_CONFIDENCE: u8 = 90;
/// Confidence for an import the database doesn't recognize — kept for
/// completeness, identified by nothing.
const UNIDENTIFIED_CONFIDENCE: u8 = 0;

impl ImportTableScanner {
    /// Scanner with the builtin library mappings.
    pub fn new() -> Self {
        Self {
            mappings: MappingDatabase::builtin(),
        }
    }

    /// Scanner with custom library mappings.
    pub fn with_mappings(mappings: MappingDatabase) -> Self {
        Self { mappings }
    }

    /// The library mappings the scanner classifies with.
    pub fn mappings(&self) -> &MappingDatabase {
        &self.mappings
    }

    /// Scan `binary`'s import table.
    ///
    /// Every import entry becomes one finding, in listing order: identified
    /// entries with their library and crate suggestion, unidentified and
    /// ordinal-only entries as plain records.
    pub async fn scan<S: ScanSource>(&self, source: &S, _binary: &str) -> Result<Vec<ApiFinding>> {
        let imports = source.imports().await?;
        let mut findings = Vec::with_capacity(imports.len());
        for symbol in imports {
            let signature = self.classify(&symbol.name);
            debug!(
                "apidetect: import {} → {}",
                signature.api,
                signature.library.as_deref().unwrap_or("unidentified")
            );
            findings.push(ApiFinding::Import(signature));
        }
        Ok(findings)
    }

    /// Classify one import name against the mapping database.
    fn classify(&self, name: &str) -> ApiSignature {
        match self.mappings.lookup(name) {
            Some((library, rust_crate)) => ApiSignature {
                api: name.to_string(),
                library: Some(library),
                rust_crate: Some(rust_crate),
                confidence: Confidence::new(IDENTIFIED_CONFIDENCE),
            },
            None => ApiSignature {
                api: name.to_string(),
                library: None,
                rust_crate: None,
                confidence: Confidence::new(UNIDENTIFIED_CONFIDENCE),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lib_mapping::LibraryMapping;
    use calxgloss_ghidra::{
        DataItem, DataTypeEntry, DecompiledFunction, EnumDefinition, FunctionSummary, GhidraError,
        StringLiteral, StructLayout, Symbol, Xref,
    };

    struct FakeSource {
        imports: Vec<Symbol>,
    }

    impl ScanSource for FakeSource {
        async fn functions(&self) -> calxgloss_ghidra::Result<Vec<FunctionSummary>> {
            Ok(Vec::new())
        }

        async fn decompile(&self, name: &str) -> calxgloss_ghidra::Result<DecompiledFunction> {
            Err(GhidraError::NotFound {
                kind: "function",
                query: name.to_string(),
            })
        }

        async fn strings(&self) -> calxgloss_ghidra::Result<Vec<StringLiteral>> {
            Ok(Vec::new())
        }

        async fn callers(&self, _address: u64) -> calxgloss_ghidra::Result<Vec<String>> {
            Ok(Vec::new())
        }

        async fn xrefs_to(&self, _address: u64) -> calxgloss_ghidra::Result<Vec<Xref>> {
            Ok(Vec::new())
        }

        async fn data_types(
            &self,
            _category: Option<&str>,
        ) -> calxgloss_ghidra::Result<Vec<DataTypeEntry>> {
            Ok(Vec::new())
        }

        async fn struct_layout(&self, name: &str) -> calxgloss_ghidra::Result<StructLayout> {
            Err(GhidraError::NotFound {
                kind: "struct",
                query: name.to_string(),
            })
        }

        async fn enum_values(&self, name: &str) -> calxgloss_ghidra::Result<EnumDefinition> {
            Err(GhidraError::NotFound {
                kind: "enum",
                query: name.to_string(),
            })
        }

        async fn data_items(&self) -> calxgloss_ghidra::Result<Vec<DataItem>> {
            Ok(Vec::new())
        }

        async fn imports(&self) -> calxgloss_ghidra::Result<Vec<Symbol>> {
            Ok(self.imports.clone())
        }

        async fn exports(&self) -> calxgloss_ghidra::Result<Vec<Symbol>> {
            Ok(Vec::new())
        }

        async fn image_base(&self) -> calxgloss_ghidra::Result<u64> {
            Ok(0)
        }

        async fn read_memory(
            &self,
            _address: u64,
            _length: usize,
        ) -> calxgloss_ghidra::Result<Vec<u8>> {
            Ok(Vec::new())
        }
    }

    fn import(name: &str) -> Symbol {
        Symbol {
            name: name.into(),
            address: 0,
            imported: true,
        }
    }

    #[tokio::test]
    async fn identifies_known_imports_with_library_and_crate() {
        let source = FakeSource {
            imports: vec![import("inflate"), import("CreateFileA")],
        };
        let findings = ImportTableScanner::new()
            .scan(&source, "game.exe")
            .await
            .unwrap();
        assert_eq!(findings.len(), 2);

        assert_eq!(findings[0].target(), "inflate");
        assert_eq!(findings[0].library(), Some("zlib"));
        assert_eq!(findings[0].rust_crate(), Some("flate2"));
        assert_eq!(findings[0].confidence(), 90);

        assert_eq!(findings[1].target(), "CreateFileA");
        assert_eq!(findings[1].library(), Some("Win32"));
        assert_eq!(findings[1].rust_crate(), Some("windows / std::fs"));
    }

    #[tokio::test]
    async fn keeps_unidentified_imports_as_entries() {
        let source = FakeSource {
            imports: vec![import("VendorSpecialFunction")],
        };
        let findings = ImportTableScanner::new()
            .scan(&source, "game.exe")
            .await
            .unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].target(), "VendorSpecialFunction");
        assert_eq!(findings[0].library(), None);
        assert_eq!(findings[0].rust_crate(), None);
        assert_eq!(findings[0].confidence(), 0);
    }

    #[tokio::test]
    async fn keeps_ordinal_only_imports_as_entries() {
        // Ghidra names ordinal-only imports `EXTERNAL:<ordinal>`.
        let source = FakeSource {
            imports: vec![import("EXTERNAL:123")],
        };
        let findings = ImportTableScanner::new()
            .scan(&source, "game.exe")
            .await
            .unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].target(), "EXTERNAL:123");
        assert_eq!(findings[0].library(), None);
    }

    #[tokio::test]
    async fn custom_mappings_override_the_builtin_table() {
        let scanner = ImportTableScanner::with_mappings(MappingDatabase::builtin().with_library(
            LibraryMapping {
                library: "zlib".into(),
                imports: vec!["my_inflate".into()],
                rust_crate: "my_zlib".into(),
            },
        ));
        let source = FakeSource {
            imports: vec![import("inflate")],
        };
        let findings = scanner.scan(&source, "game.exe").await.unwrap();
        assert_eq!(findings[0].library(), None);
    }
}
