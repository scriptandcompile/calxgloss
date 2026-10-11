//! Type database recovery orchestration.
//!
//! [`TypesDBEngine`] runs the three recovery engines — named type recovery,
//! vtable detection, and string-guided inference — concurrently against one
//! open Ghidra program and assembles their results into a single
//! [`TypeDatabase`] with its scan provenance.
//!
//! The three scans read disjoint endpoint sets (`list_data_types`,
//! `list_data_items` + `read_memory`, and `list_strings` + `get_xrefs_to`),
//! so they run as concurrent tasks rather than one after another. Each engine
//! already degrades internally for missing or malformed data, so an error
//! surfacing here means the server itself failed mid-scan; the run aborts
//! with that error rather than returning a database whose sections were
//! built against different programs or different moments.

use crate::error::Result;
use crate::scanner::TypeLibraryScanner;
use crate::string_infer::StringInferenceEngine;
use crate::types::{ScanMetadata, TypeDatabase};
use crate::vtable::{TagSink, VtableDetector};
use calxgloss_ghidra::GhidraClient;
use std::time::Instant;
use tracing::info;

/// The shared trait from the Ghidra integration crate, re-exported here
/// so the engine's generic shape names it where it always has;
/// [`GhidraClient`] implements it over the live HTTP API, and tests
/// implement it over canned listings so the orchestration runs without
/// a server. The futures are `Send` so a scan can be driven from an
/// orchestrating task.
pub use calxgloss_ghidra::ScanSource;

/// Orchestrates the three recovery engines into one [`TypeDatabase`].
///
/// The engine is generic over the same source traits as the scanners it
/// drives, so tests can run the whole orchestration over canned responses;
/// [`new`](Self::new) builds one over a live [`GhidraClient`].
#[derive(Debug, Clone)]
pub struct TypesDBEngine<S = GhidraClient> {
    scanner: TypeLibraryScanner<S>,
    vtables: VtableDetector<S>,
    strings: StringInferenceEngine<S>,
}

impl TypesDBEngine<GhidraClient> {
    /// An engine over a live GhidraMCP client.
    pub fn new(client: &GhidraClient) -> TypesDBEngine<GhidraClient> {
        TypesDBEngine {
            scanner: TypeLibraryScanner::new(client),
            vtables: VtableDetector::new(client),
            strings: StringInferenceEngine::new(client),
        }
    }
}

impl<S> TypesDBEngine<S> {
    /// An engine whose three scanners share one source.
    pub fn with_source(source: S) -> Self
    where
        S: Clone,
    {
        TypesDBEngine {
            scanner: TypeLibraryScanner::with_source(source.clone()),
            vtables: VtableDetector::with_source(source.clone()),
            strings: StringInferenceEngine::with_source(source),
        }
    }

    /// Restrict the named-type scan to a Type Manager category.
    pub fn with_category(mut self, category: impl Into<String>) -> Self {
        self.scanner = self.scanner.with_category(category);
        self
    }

    /// Tag confirmed vtable methods with `tag` instead of the default.
    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.vtables = self.vtables.with_tag(tag);
        self
    }

    /// Detect vtables without writing anything back to the program.
    pub fn without_tagging(mut self) -> Self {
        self.vtables = self.vtables.without_tagging();
        self
    }

    /// Regex the string listing is filtered by.
    pub fn with_string_filter(mut self, pattern: impl Into<String>) -> Self {
        self.strings = self.strings.with_string_filter(pattern);
        self
    }

    /// Report inferred candidates scoring `threshold` or higher.
    pub fn with_min_confidence(mut self, threshold: u8) -> Self {
        self.strings = self.strings.with_min_confidence(threshold);
        self
    }

    /// Report inferred candidates with at least `count` fields.
    pub fn with_min_fields(mut self, count: usize) -> Self {
        self.strings = self.strings.with_min_fields(count);
        self
    }

    /// Assume `pointer_size` for vtable entries and text-typed fields —
    /// one program, one pointer size, so the knob reaches both scanners.
    pub fn with_pointer_size(mut self, pointer_size: usize) -> Self {
        self.vtables = self.vtables.with_pointer_size(pointer_size);
        self.strings = self.strings.with_pointer_size(pointer_size as u64);
        self
    }

    /// Recover the whole type database for `binary`, running the three
    /// scans concurrently.
    ///
    /// `binary` names the program the scans read (e.g. `eqmain.dll`) and
    /// becomes the key a persisted database is filed under. The metadata is
    /// stamped when the scans finish, so it records when the database was
    /// built and how long the concurrent run took.
    pub async fn scan(&self, binary: impl Into<String>) -> Result<TypeDatabase>
    where
        S: ScanSource + TagSink,
    {
        let started = Instant::now();
        let (named_types, vtables, inferred_structs) = tokio::try_join!(
            self.scanner.scan_named_types(),
            self.vtables.detect_vtables(),
            self.strings.infer_structures(),
        )?;

        let mut metadata = ScanMetadata::new(binary);
        metadata.duration_secs = started.elapsed().as_secs();
        info!(
            binary = %metadata.binary,
            named_types = named_types.len(),
            vtables = vtables.len(),
            inferred_structs = inferred_structs.len(),
            duration_secs = metadata.duration_secs,
            "Recovered type database"
        );
        Ok(TypeDatabase {
            metadata,
            named_types,
            vtables,
            inferred_structs,
        })
    }
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::TypesDbError;
    use calxgloss_ghidra::{
        DataItem, DataTypeEntry, DecompiledFunction, EnumDefinition, FunctionSummary, GhidraError,
        Result as GhidraResult, StringLiteral, StructFieldLayout, StructLayout, Symbol, Xref,
    };
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use tokio::task::yield_now;

    fn le32(value: u32) -> Vec<u8> {
        value.to_le_bytes().to_vec()
    }

    fn le64(value: u64) -> Vec<u8> {
        value.to_le_bytes().to_vec()
    }

    fn entry(name: &str, category: &str, size: Option<u64>) -> DataTypeEntry {
        DataTypeEntry {
            name: name.to_string(),
            category: category.to_string(),
            size,
            path: format!("/{category}/{name}"),
        }
    }

    fn item(label: &str, address: u64, type_name: &str, length: u64) -> DataItem {
        DataItem {
            label: label.to_string(),
            address,
            type_name: type_name.to_string(),
            length,
        }
    }

    fn reference(function: &str) -> Xref {
        Xref {
            address: 0x1800_0100,
            function: Some(function.to_string()),
            kind: Some("DATA".to_string()),
        }
    }

    /// A TypeDescriptor body: the header pair plus the mangled name.
    fn type_descriptor(name: &str) -> Vec<u8> {
        let mut bytes = vec![0u8; 16];
        bytes.extend_from_slice(name.as_bytes());
        bytes.push(0);
        bytes
    }

    /// State shared by every clone of a [`FakeProgram`], so a test can read
    /// what the scans did after the engine has consumed its source.
    #[derive(Debug, Default)]
    struct Stats {
        in_flight: AtomicUsize,
        max_in_flight: AtomicUsize,
        tags: Mutex<Vec<(u64, String)>>,
    }

    /// A canned program implementing [`ScanSource`] and [`TagSink`], so the
    /// whole orchestration runs without a server. Every source call yields,
    /// the way a real HTTP call pends, which is what lets the concurrency
    /// test observe the scans overlapping.
    #[derive(Clone)]
    struct FakeProgram {
        listing: Vec<DataTypeEntry>,
        buckets: HashMap<&'static str, Vec<DataTypeEntry>>,
        layouts: HashMap<String, StructLayout>,
        enums: HashMap<String, EnumDefinition>,
        items: Vec<DataItem>,
        functions: Vec<FunctionSummary>,
        image_base: u64,
        memory: HashMap<u64, Vec<u8>>,
        literals: Vec<StringLiteral>,
        xrefs: HashMap<u64, Vec<Xref>>,
        fail_items: bool,
        stats: Arc<Stats>,
    }

    impl FakeProgram {
        fn empty() -> Self {
            Self {
                listing: Vec::new(),
                buckets: HashMap::new(),
                layouts: HashMap::new(),
                enums: HashMap::new(),
                items: Vec::new(),
                functions: Vec::new(),
                image_base: 0x1800_00000,
                memory: HashMap::new(),
                literals: Vec::new(),
                xrefs: HashMap::new(),
                fail_items: false,
                stats: Arc::new(Stats::default()),
            }
        }

        fn enter(&self) {
            let now = self.stats.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
            self.stats.max_in_flight.fetch_max(now, Ordering::SeqCst);
        }

        fn exit(&self) {
            self.stats.in_flight.fetch_sub(1, Ordering::SeqCst);
        }

        fn tagged(&self) -> Vec<(u64, String)> {
            self.stats.tags.lock().unwrap().clone()
        }
    }

    /// The canned program: one PE struct and one enum in the Type Manager,
    /// one RTTI-confirmed vtable with two methods, and a two-literal cluster
    /// that infers to a `Player` candidate.
    fn program() -> FakeProgram {
        let mut program = FakeProgram::empty();

        program.listing = vec![
            entry("IMAGE_DOS_HEADER", "pe", Some(128)),
            entry("_EXCEPTION_DISPOSITION", "excpt.h", Some(4)),
        ];
        program
            .buckets
            .insert("struct", vec![entry("IMAGE_DOS_HEADER", "pe", Some(128))]);
        program.buckets.insert(
            "enum",
            vec![entry("_EXCEPTION_DISPOSITION", "excpt.h", Some(4))],
        );
        program.layouts.insert(
            "IMAGE_DOS_HEADER".into(),
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
            },
        );
        program.enums.insert(
            "_EXCEPTION_DISPOSITION".into(),
            EnumDefinition {
                name: "_EXCEPTION_DISPOSITION".into(),
                size: 4,
                members: vec![calxgloss_ghidra::EnumMember {
                    name: "ExceptionContinueExecution".into(),
                    value: 0,
                }],
            },
        );

        // vftable @ 1801306f0 preceded by its vftable_meta_ptr, whose COL
        // names the class Widget with base Base.
        program.items = vec![
            item("vftable_meta_ptr", 0x1801_306e8, "pointer", 8),
            item("vftable", 0x1801_306f0, "pointer[2]", 16),
        ];
        program.functions = vec![
            FunctionSummary {
                name: "FUN_18003ab00".into(),
                address: 0x1800_3ab00,
            },
            FunctionSummary {
                name: "FUN_18003e750".into(),
                address: 0x1800_3e750,
            },
        ];
        program.memory.insert(
            0x1801_306f0,
            [le64(0x1800_3ab00), le64(0x1800_3e750)].concat(),
        );
        program.memory.insert(0x1801_306e8, le64(0x1801_30700));
        program.memory.insert(
            0x1801_30700,
            [le32(1), le32(0), le32(0), le32(0x13_0800), le32(0x13_0900)].concat(),
        );
        program
            .memory
            .insert(0x1801_30800, type_descriptor(".?AVWidget@@"));
        program.memory.insert(
            0x1801_30900,
            [le32(0), le32(0), le32(1), le32(0x13_0a00)].concat(),
        );
        program.memory.insert(0x1801_30a00, le32(0x13_0b00));
        let mut bcd = vec![0u8; 24];
        bcd.extend_from_slice(&le32(0x13_0c00));
        bcd.extend_from_slice(&[0u8; 4]);
        program.memory.insert(0x1801_30b00, bcd);
        program
            .memory
            .insert(0x1801_30c00, type_descriptor(".?AVBase@@"));

        program.literals = vec![
            StringLiteral {
                address: 0x1801_29350,
                value: "player.x=1".into(),
            },
            StringLiteral {
                address: 0x1801_29360,
                value: "player.y=2".into(),
            },
        ];
        program
            .xrefs
            .insert(0x1801_29350, vec![reference("Player_update")]);
        program
            .xrefs
            .insert(0x1801_29360, vec![reference("Player_update")]);
        program
    }

    impl ScanSource for FakeProgram {
        async fn data_types(&self, category: Option<&str>) -> GhidraResult<Vec<DataTypeEntry>> {
            self.enter();
            yield_now().await;
            self.exit();
            match category {
                None => Ok(self.listing.clone()),
                Some(word) if self.buckets.contains_key(word) => Ok(self.buckets[word].clone()),
                Some(word) => Ok(self
                    .listing
                    .iter()
                    .filter(|e| e.category.contains(word))
                    .cloned()
                    .collect()),
            }
        }

        async fn struct_layout(&self, name: &str) -> GhidraResult<StructLayout> {
            self.enter();
            yield_now().await;
            self.exit();
            self.layouts
                .get(name)
                .cloned()
                .ok_or_else(|| GhidraError::NotFound {
                    kind: "structure",
                    query: name.to_string(),
                })
        }

        async fn enum_values(&self, name: &str) -> GhidraResult<EnumDefinition> {
            self.enter();
            yield_now().await;
            self.exit();
            self.enums
                .get(name)
                .cloned()
                .ok_or_else(|| GhidraError::NotFound {
                    kind: "enumeration",
                    query: name.to_string(),
                })
        }

        async fn data_items(&self) -> GhidraResult<Vec<DataItem>> {
            self.enter();
            yield_now().await;
            self.exit();
            if self.fail_items {
                return Err(GhidraError::Reported {
                    status: Some(200),
                    message: "Ghidra is busy".into(),
                });
            }
            Ok(self.items.clone())
        }

        async fn functions(&self) -> GhidraResult<Vec<FunctionSummary>> {
            self.enter();
            yield_now().await;
            self.exit();
            Ok(self.functions.clone())
        }

        async fn image_base(&self) -> GhidraResult<u64> {
            self.enter();
            yield_now().await;
            self.exit();
            Ok(self.image_base)
        }

        async fn read_memory(&self, address: u64, _length: usize) -> GhidraResult<Vec<u8>> {
            self.enter();
            yield_now().await;
            self.exit();
            self.memory
                .get(&address)
                .cloned()
                .ok_or_else(|| GhidraError::NotFound {
                    kind: "memory",
                    query: format!("{address:x}"),
                })
        }

        async fn strings(&self) -> GhidraResult<Vec<StringLiteral>> {
            self.enter();
            yield_now().await;
            self.exit();
            Ok(self.literals.clone())
        }

        async fn xrefs_to(&self, address: u64) -> GhidraResult<Vec<Xref>> {
            self.enter();
            yield_now().await;
            self.exit();
            Ok(self.xrefs.get(&address).cloned().unwrap_or_default())
        }

        async fn decompile(&self, name: &str) -> GhidraResult<DecompiledFunction> {
            Err(GhidraError::NotFound {
                kind: "function",
                query: name.to_string(),
            })
        }

        async fn callers(&self, _address: u64) -> GhidraResult<Vec<String>> {
            Ok(Vec::new())
        }

        async fn imports(&self) -> GhidraResult<Vec<Symbol>> {
            Ok(Vec::new())
        }

        async fn exports(&self) -> GhidraResult<Vec<Symbol>> {
            Ok(Vec::new())
        }
    }

    impl TagSink for FakeProgram {
        async fn add_function_tag(&self, address: u64, tag: &str) -> Result<()> {
            self.enter();
            yield_now().await;
            self.exit();
            self.stats
                .tags
                .lock()
                .unwrap()
                .push((address, tag.to_string()));
            Ok(())
        }
    }

    #[tokio::test]
    async fn scan_collects_all_three_sections() {
        let program = program();
        let db = TypesDBEngine::with_source(program.clone())
            .scan("eqmain.dll")
            .await
            .expect("scan");

        assert_eq!(db.metadata.binary, "eqmain.dll");
        assert!(db.metadata.scanned_at > 0);

        // Named types in Type Manager path order, layouts resolved.
        assert_eq!(db.named_types.len(), 2);
        assert_eq!(db.named_types[0].name, "_EXCEPTION_DISPOSITION");
        assert_eq!(
            db.named_types[0].members[0].name,
            "ExceptionContinueExecution"
        );
        assert_eq!(db.named_types[1].name, "IMAGE_DOS_HEADER");
        assert_eq!(db.named_types[1].fields[0].name, "e_magic");

        // The RTTI-confirmed vtable with its class chain and named methods.
        assert_eq!(db.vtables.len(), 1);
        let vtable = &db.vtables[0];
        assert!(vtable.is_confirmed());
        assert_eq!(vtable.class_name.as_deref(), Some("Widget"));
        assert_eq!(vtable.base_classes, vec!["Base"]);
        assert_eq!(vtable.methods.len(), 2);
        assert_eq!(vtable.methods[0].name.as_deref(), Some("FUN_18003ab00"));

        // The literal cluster as a candidate above the default threshold.
        assert_eq!(db.inferred_structs.len(), 1);
        let candidate = &db.inferred_structs[0];
        assert_eq!(candidate.name, "Player");
        assert_eq!(candidate.fields.len(), 2);
        assert!(candidate.confidence >= 40);

        // The default configuration tags confirmed vtable methods.
        let tags = program.tagged();
        assert_eq!(tags.len(), 2);
        assert!(tags.iter().all(|(_, tag)| tag == "vtable-method"));
    }

    #[tokio::test]
    async fn scan_runs_the_three_scans_concurrently() {
        // Every source call pends like an HTTP request, so a sequential
        // orchestration could never have two scans in flight at once.
        let program = program();
        TypesDBEngine::with_source(program.clone())
            .scan("eqmain.dll")
            .await
            .expect("scan");
        assert!(
            program.stats.max_in_flight.load(Ordering::SeqCst) >= 2,
            "the three scans should overlap, not run one after another"
        );
    }

    #[tokio::test]
    async fn a_failing_scan_fails_the_whole_run() {
        // Each engine degrades internally for missing data, so an error
        // here is a server failure: the run aborts rather than returning a
        // database with a silently missing section.
        let mut program = program();
        program.fail_items = true;
        let result = TypesDBEngine::with_source(program).scan("eqmain.dll").await;
        assert!(matches!(
            result,
            Err(TypesDbError::Ghidra(GhidraError::Reported { .. }))
        ));
    }

    #[tokio::test]
    async fn an_empty_program_yields_an_empty_database() {
        let db = TypesDBEngine::with_source(FakeProgram::empty())
            .scan("nothing.dll")
            .await
            .expect("scan");
        assert!(db.is_empty());
        assert_eq!(db.metadata.binary, "nothing.dll");
        assert!(db.metadata.scanned_at > 0);
    }

    #[tokio::test]
    async fn configuration_reaches_every_scanner() {
        let program = program();
        let db = TypesDBEngine::with_source(program.clone())
            .with_category("pe")
            .with_min_confidence(70)
            .without_tagging()
            .scan("eqmain.dll")
            .await
            .expect("scan");

        assert_eq!(
            db.named_types.len(),
            1,
            "the category filter reaches the scanner"
        );
        assert_eq!(db.named_types[0].name, "IMAGE_DOS_HEADER");
        assert!(
            db.inferred_structs.is_empty(),
            "the threshold reaches the inference engine"
        );
        assert!(program.tagged().is_empty(), "the detector stays read-only");
        assert_eq!(db.vtables.len(), 1, "detection itself still ran");
    }
}
