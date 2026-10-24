//! The shared read seam for everything an evidence engine pulls from the
//! analysis engine.
//!
//! Every evidence-engine crate once carried its own `ScanSource`-shaped
//! trait, and the copies had grown near-identical. This is their union — the
//! function listing, decompile-by-name, the per-function disassembly-text
//! read, the string listing, callers,
//! xrefs-to, the Type Manager reads (data types, struct layouts, enum values,
//! data items), the import and export listings, and the raw reads the vtable
//! scan makes (image base, memory bytes) — defined once so the read cache
//! implements it once instead of fourteen times. All fourteen scan-based
//! evidence engines — algorithm, callback, consts, control-flow,
//! error-handling, float-SIMD, memory, serialization, string-context, concurrency,
//! global-state, types-database, type-inference, and API-detection —
//! re-export this trait in place of their own.
//!
//! Kuna is the only analysis engine (issue #214, ADR-0041): the seam answers
//! through [`KunaSource`] directly or through
//! [`CachedScanSource`](crate::CachedScanSource), the two-tier read cache.
//!
//! Deliberately absent:
//!
//! * **Write-side calls** (function tags, type write-back) — the cache only
//!   ever serves read-only facts. `calxgloss-typesdb`'s vtable scan keeps a
//!   slim local `TagSink` trait for its one write; the type write-back seam
//!   lives beside this module as [`TypeWriteSource`](crate::TypeWriteSource),
//!   answered by the Kuna directive plane (issue #209).
//! * **The string-listing filter** — only `calxgloss-typesdb`'s string
//!   inference takes one, and no production caller sets it; the engine-facing
//!   shape carries an unfiltered listing, so this trait matches it and the
//!   inference engine filters the listing itself.
//! * **The built call graph** — `calxgloss-apidetect`'s `call_graph` read is
//!   a composite of these reads, assembled by the call-graph builder, which
//!   reads through this seam itself; the engine keeps a slim local
//!   `CallGraphSource` trait for it.

use crate::cache::CachedScanSource;
use crate::error::{EngineError, Result};
use crate::model::{
    DataItem, DataTypeEntry, DecompiledFunction, EnumDefinition, EnumMember, FunctionSummary,
    StringLiteral, StructFieldLayout, StructLayout, Symbol, Xref,
};
use calxgloss_kuna::KunaSource;
use calxgloss_types::EngineProvenance;

/// The read-only program facts every evidence engine pulls from the engine.
///
/// [`KunaSource`] implements the core reads over the in-process Kuna engine
/// (issue #206), [`CachedScanSource`](crate::CachedScanSource) implements it
/// as the read cache, and tests implement it over canned data. The futures
/// are `Send` so a scan can be driven from an orchestrating task.
pub trait ScanSource {
    /// Every function in the program, in listing order.
    ///
    /// A listed name is a name [`Self::decompile`] can answer: an engine's
    /// import pointer slots and other bodyless entries belong to the
    /// [`Self::imports`] read, and a name the engine cannot settle on one
    /// entry — two of its own entries sharing a name, say — is listable by
    /// nobody, so a consumer that decompiles every listed name spends no
    /// read that cannot succeed.
    fn functions(&self) -> impl std::future::Future<Output = Result<Vec<FunctionSummary>>> + Send;

    /// The pseudo-C for one function, by name.
    fn decompile(
        &self,
        name: &str,
    ) -> impl std::future::Future<Output = Result<DecompiledFunction>> + Send;

    /// The machine-instruction listing for one function, by name, as text.
    ///
    /// One row per instruction in address order, spelled by the engine's
    /// own listing — uppercase SLEIGH mnemonics, `0x` hex operands — the
    /// evidence a calling-convention detector reads epilogues (`ret N`)
    /// and caller stack cleanup from (issue #245). The default answers
    /// empty — the `engine_provenance` precedent: a source that has not
    /// opted in lists nothing, so every existing implementor, offline
    /// fake program, and scan keeps compiling and behaving byte-for-byte
    /// as it did — while the Kuna source answers from the engine's own
    /// instruction walker and the read cache files the text under the
    /// scan-cache convention.
    fn disassembly(&self, _name: &str) -> impl std::future::Future<Output = Result<String>> + Send {
        async { Ok(String::new()) }
    }

    /// Every string literal defined in the program.
    fn strings(&self) -> impl std::future::Future<Output = Result<Vec<StringLiteral>>> + Send;

    /// The names of the functions that call the function at `address`.
    fn callers(
        &self,
        address: u64,
    ) -> impl std::future::Future<Output = Result<Vec<String>>> + Send;

    /// The references pointing at `address`, as the client parsed them.
    fn xrefs_to(&self, address: u64)
    -> impl std::future::Future<Output = Result<Vec<Xref>>> + Send;

    /// Every named type in the Type Manager, optionally filtered by category
    /// or classification, collected across pages.
    fn data_types(
        &self,
        category: Option<&str>,
    ) -> impl std::future::Future<Output = Result<Vec<DataTypeEntry>>> + Send;

    /// Field layout of a structure from the Type Manager.
    fn struct_layout(
        &self,
        name: &str,
    ) -> impl std::future::Future<Output = Result<StructLayout>> + Send;

    /// Members and values of an enumeration from the Type Manager.
    fn enum_values(
        &self,
        name: &str,
    ) -> impl std::future::Future<Output = Result<EnumDefinition>> + Send;

    /// Every defined data object in the listing, collected across pages.
    fn data_items(&self) -> impl std::future::Future<Output = Result<Vec<DataItem>>> + Send;

    /// Every import in the program, in listing order.
    fn imports(&self) -> impl std::future::Future<Output = Result<Vec<Symbol>>> + Send;

    /// Every export in the program, in listing order.
    fn exports(&self) -> impl std::future::Future<Output = Result<Vec<Symbol>>> + Send;

    /// The base address the program is loaded at, for resolving RVAs.
    fn image_base(&self) -> impl std::future::Future<Output = Result<u64>> + Send;

    /// The raw bytes at `address` — a vtable's method pointers, an RTTI
    /// locator — which no listing endpoint reports.
    fn read_memory(
        &self,
        address: u64,
        length: usize,
    ) -> impl std::future::Future<Output = Result<Vec<u8>>> + Send;

    /// The decompiler engine answering these reads, when the source names one.
    ///
    /// Engine identity, not a program read: a scan record stamps this
    /// beside its timing so a reviewer can tell what produced any
    /// decompilation inside the record and re-create or blame it
    /// (issue #208). The default names nothing — a source that adds no
    /// identity of its own leaves scan records byte-for-byte what they
    /// were — while the Kuna source names its engine, pinned release,
    /// and source fingerprint.
    fn engine_provenance(&self) -> Option<EngineProvenance> {
        None
    }
}

/// The engine's decompile mapped to the seam's shape, raw — the text as the
/// engine rendered it, before the decompiler-noise pre-filter has seen it.
///
/// Both analysis sources read through this one function: the in-process arm
/// below filters the mapped record at its exit, and the read cache's live
/// tier fetches through here so its memo and disk documents hold the
/// engine's raw text, with the filter applied above the cache instead —
/// reversible by deleting the cache (ADR-0043, issue #271).
pub(crate) async fn raw_decompile(source: &KunaSource, name: &str) -> Result<DecompiledFunction> {
    KunaSource::decompile_function(source, name)
        .await
        .map(|function| DecompiledFunction {
            name: function.name,
            signature: function.signature,
            body: function.body,
        })
        .map_err(EngineError::from)
}

/// The core scan reads answered by the in-process Kuna engine (issue #206).
///
/// Every read the trait carries maps onto [`KunaSource`]'s inherent API,
/// with Kuna's named failures mapped onto the seam's error vocabulary: a
/// missing function, type, or byte range becomes [`EngineError::NotFound`]
/// and a kind mismatch [`EngineError::Malformed`] — the same facts the
/// retired Ghidra bridge reported, so layout probes branch on one
/// vocabulary. Every other Kuna failure arrives as
/// [`EngineError::Reported`] carrying the engine's own message.
impl ScanSource for KunaSource {
    async fn functions(&self) -> Result<Vec<FunctionSummary>> {
        KunaSource::list_functions(self)
            .await
            .map(|functions| {
                functions
                    .into_iter()
                    .map(|function| FunctionSummary {
                        name: function.name,
                        address: function.address,
                    })
                    .collect()
            })
            .map_err(EngineError::from)
    }

    async fn decompile(&self, name: &str) -> Result<DecompiledFunction> {
        // The exit filter (issue #271): every consumer of this arm's pseudo-C
        // sees bodies with the recognized compiler noise already stripped.
        raw_decompile(self, name)
            .await
            .map(crate::noise_filter::strip_decompiler_noise)
    }

    async fn disassembly(&self, name: &str) -> Result<String> {
        KunaSource::disassemble_function(self, name)
            .await
            .map_err(EngineError::from)
    }

    async fn strings(&self) -> Result<Vec<StringLiteral>> {
        KunaSource::strings(self)
            .await
            .map(|strings| {
                strings
                    .into_iter()
                    .map(|string| StringLiteral {
                        address: string.address,
                        value: string.value,
                    })
                    .collect()
            })
            .map_err(EngineError::from)
    }

    /// The names of the functions holding a reference to `address`, deduped
    /// in first-reference order — the shape the seam's `callers`
    /// read has always carried, so the call-graph builder needs no engine
    /// special case.
    async fn callers(&self, address: u64) -> Result<Vec<String>> {
        KunaSource::xrefs_to(self, address)
            .await
            .map(|xrefs| {
                let mut names: Vec<String> = Vec::new();
                for xref in xrefs {
                    if let Some(name) = xref.function
                        && !names.contains(&name)
                    {
                        names.push(name);
                    }
                }
                names
            })
            .map_err(EngineError::from)
    }

    async fn xrefs_to(&self, address: u64) -> Result<Vec<Xref>> {
        KunaSource::xrefs_to(self, address)
            .await
            .map(|xrefs| {
                xrefs
                    .into_iter()
                    .map(|xref| Xref {
                        address: xref.address,
                        function: xref.function,
                        kind: xref.kind,
                    })
                    .collect()
            })
            .map_err(EngineError::from)
    }

    async fn data_types(&self, category: Option<&str>) -> Result<Vec<DataTypeEntry>> {
        KunaSource::data_types(self, category)
            .await
            .map(|entries| {
                entries
                    .into_iter()
                    .map(|entry| DataTypeEntry {
                        name: entry.name,
                        category: entry.category,
                        size: entry.size,
                        path: entry.path,
                    })
                    .collect()
            })
            .map_err(EngineError::from)
    }

    async fn struct_layout(&self, name: &str) -> Result<StructLayout> {
        KunaSource::struct_layout(self, name)
            .await
            .map(|layout| StructLayout {
                name: layout.name,
                size: layout.size,
                alignment: layout.alignment,
                fields: layout
                    .fields
                    .into_iter()
                    .map(|field| StructFieldLayout {
                        offset: field.offset,
                        size: field.size,
                        type_name: field.type_name,
                        field_name: field.field_name,
                    })
                    .collect(),
            })
            .map_err(EngineError::from)
    }

    async fn enum_values(&self, name: &str) -> Result<EnumDefinition> {
        KunaSource::enum_values(self, name)
            .await
            .map(|definition| EnumDefinition {
                name: definition.name,
                size: definition.size,
                members: definition
                    .members
                    .into_iter()
                    .map(|member| EnumMember {
                        name: member.name,
                        value: member.value,
                    })
                    .collect(),
            })
            .map_err(EngineError::from)
    }

    async fn data_items(&self) -> Result<Vec<DataItem>> {
        KunaSource::data_items(self)
            .await
            .map(|items| {
                items
                    .into_iter()
                    .map(|item| DataItem {
                        label: item.label,
                        address: item.address,
                        type_name: item.type_name,
                        length: item.length,
                    })
                    .collect()
            })
            .map_err(EngineError::from)
    }

    async fn imports(&self) -> Result<Vec<Symbol>> {
        KunaSource::list_imports(self)
            .await
            .map(|imports| {
                imports
                    .into_iter()
                    .map(|import| Symbol {
                        name: import.name,
                        address: import.address,
                        imported: import.imported,
                    })
                    .collect()
            })
            .map_err(EngineError::from)
    }

    async fn exports(&self) -> Result<Vec<Symbol>> {
        KunaSource::list_exports(self)
            .await
            .map(|exports| {
                exports
                    .into_iter()
                    .map(|export| Symbol {
                        name: export.name,
                        address: export.address,
                        imported: export.imported,
                    })
                    .collect()
            })
            .map_err(EngineError::from)
    }

    async fn image_base(&self) -> Result<u64> {
        KunaSource::image_base(self)
            .await
            .map_err(EngineError::from)
    }

    async fn read_memory(&self, address: u64, length: usize) -> Result<Vec<u8>> {
        KunaSource::read_memory(self, address, length)
            .await
            .map_err(EngineError::from)
    }

    fn engine_provenance(&self) -> Option<EngineProvenance> {
        // The pin is the build: the release tag and the short commit of
        // the checkout the engine and its embedded specs came from are
        // the same facts `build.rs` read out of the lock file, so a scan
        // record names exactly the engine source that produced it
        // (issue #208).
        Some(EngineProvenance {
            name: "kuna".to_string(),
            version: Some(calxgloss_kuna::KUNA_RELEASE.to_string()),
            fingerprint: Some(calxgloss_kuna::KUNA_PIN_REV.to_string()),
        })
    }
}

/// The one concrete read source a translation batch hands to every consumer.
///
/// The pipeline builds a [`CachedScanSource`] for the target binary at the
/// top of a batch and every scan, the call-graph build, and the retry/escalation
/// helpers read through this enum afterwards — `Kuna` until that cache exists,
/// `Cached` once it does. Having one concrete type (rather than two call paths)
/// keeps the pipeline's plumbing generic-free: the same `PipelineSource` value
/// answers every consumer, and a warm second batch over the same workspace and
/// unchanged binary costs no engine reads at all.
#[derive(Debug, Clone)]
pub enum PipelineSource {
    /// The batch's shared two-tier cache, scoped to one target binary.
    Cached(CachedScanSource),
    /// The in-process Kuna engine, loaded with exactly one target binary.
    Kuna(KunaSource),
}

impl From<CachedScanSource> for PipelineSource {
    fn from(source: CachedScanSource) -> Self {
        Self::Cached(source)
    }
}

impl From<KunaSource> for PipelineSource {
    fn from(source: KunaSource) -> Self {
        Self::Kuna(source)
    }
}

impl ScanSource for PipelineSource {
    // Each arm delegates to its own `ScanSource` implementation; the cache
    // tier resolves memo → disk → engine. The calls are trait-qualified so
    // the engine's inherent methods (which answer Kuna-native shapes) never
    // shadow the seam's mapped reads.
    async fn functions(&self) -> Result<Vec<FunctionSummary>> {
        match self {
            Self::Cached(cache) => ScanSource::functions(cache).await,
            Self::Kuna(source) => ScanSource::functions(source).await,
        }
    }

    async fn decompile(&self, name: &str) -> Result<DecompiledFunction> {
        match self {
            Self::Cached(cache) => ScanSource::decompile(cache, name).await,
            Self::Kuna(source) => ScanSource::decompile(source, name).await,
        }
    }

    async fn disassembly(&self, name: &str) -> Result<String> {
        match self {
            Self::Cached(cache) => ScanSource::disassembly(cache, name).await,
            Self::Kuna(source) => ScanSource::disassembly(source, name).await,
        }
    }

    async fn strings(&self) -> Result<Vec<StringLiteral>> {
        match self {
            Self::Cached(cache) => ScanSource::strings(cache).await,
            Self::Kuna(source) => ScanSource::strings(source).await,
        }
    }

    async fn callers(&self, address: u64) -> Result<Vec<String>> {
        match self {
            Self::Cached(cache) => ScanSource::callers(cache, address).await,
            Self::Kuna(source) => ScanSource::callers(source, address).await,
        }
    }

    async fn xrefs_to(&self, address: u64) -> Result<Vec<Xref>> {
        match self {
            Self::Cached(cache) => ScanSource::xrefs_to(cache, address).await,
            Self::Kuna(source) => ScanSource::xrefs_to(source, address).await,
        }
    }

    async fn data_types(&self, category: Option<&str>) -> Result<Vec<DataTypeEntry>> {
        match self {
            Self::Cached(cache) => ScanSource::data_types(cache, category).await,
            Self::Kuna(source) => ScanSource::data_types(source, category).await,
        }
    }

    async fn struct_layout(&self, name: &str) -> Result<StructLayout> {
        match self {
            Self::Cached(cache) => ScanSource::struct_layout(cache, name).await,
            Self::Kuna(source) => ScanSource::struct_layout(source, name).await,
        }
    }

    async fn enum_values(&self, name: &str) -> Result<EnumDefinition> {
        match self {
            Self::Cached(cache) => ScanSource::enum_values(cache, name).await,
            Self::Kuna(source) => ScanSource::enum_values(source, name).await,
        }
    }

    async fn data_items(&self) -> Result<Vec<DataItem>> {
        match self {
            Self::Cached(cache) => ScanSource::data_items(cache).await,
            Self::Kuna(source) => ScanSource::data_items(source).await,
        }
    }

    async fn imports(&self) -> Result<Vec<Symbol>> {
        match self {
            Self::Cached(cache) => ScanSource::imports(cache).await,
            Self::Kuna(source) => ScanSource::imports(source).await,
        }
    }

    async fn exports(&self) -> Result<Vec<Symbol>> {
        match self {
            Self::Cached(cache) => ScanSource::exports(cache).await,
            Self::Kuna(source) => ScanSource::exports(source).await,
        }
    }

    async fn image_base(&self) -> Result<u64> {
        match self {
            Self::Cached(cache) => ScanSource::image_base(cache).await,
            Self::Kuna(source) => ScanSource::image_base(source).await,
        }
    }

    async fn read_memory(&self, address: u64, length: usize) -> Result<Vec<u8>> {
        match self {
            Self::Cached(cache) => ScanSource::read_memory(cache, address, length).await,
            Self::Kuna(source) => ScanSource::read_memory(source, address, length).await,
        }
    }

    fn engine_provenance(&self) -> Option<EngineProvenance> {
        // Identity forwards like the reads: both arms answer through the
        // Kuna engine, so a scan record built over this source names the
        // engine, its pinned release, and its source fingerprint (issue
        // #208).
        match self {
            Self::Cached(cache) => ScanSource::engine_provenance(cache),
            Self::Kuna(source) => ScanSource::engine_provenance(source),
        }
    }
}
