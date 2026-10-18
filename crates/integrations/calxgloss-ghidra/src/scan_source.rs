//! The shared read seam for everything an evidence engine pulls from Ghidra.
//!
//! Every evidence-engine crate once carried its own `ScanSource`-shaped
//! trait, and the copies had grown near-identical. This is their union — the
//! function listing, decompile-by-name, the string listing, callers,
//! xrefs-to, the Type Manager reads (data types, struct layouts, enum values,
//! data items), the import and export listings, and the raw reads the vtable
//! scan makes (image base, memory bytes) — defined once so the planned read
//! cache implements it once instead of eleven times. All eleven scan-based
//! evidence engines — algorithm, callback, consts, control-flow, memory,
//! serialization, string-context, concurrency, types-database,
//! type-inference, and API-detection — re-export this trait in place of
//! their own.
//!
//! Deliberately absent:
//!
//! * **Write-side calls** (function tags, type write-back) — the cache only
//!   ever serves read-only facts. `calxgloss-typesdb`'s vtable scan keeps a
//!   slim local `TagSink` trait for its one write; the type write-back seam
//!   lives beside this module as [`TypeWriteSource`](crate::TypeWriteSource),
//!   implemented by the raw client alone.
//! * **The string-listing filter** — only `calxgloss-typesdb`'s string
//!   inference takes one, and no production caller sets it; the engine-facing
//!   shape carries an unfiltered listing, so this trait matches it and the
//!   inference engine filters the listing itself.
//! * **The built call graph** — `calxgloss-apidetect`'s `call_graph` read is
//!   a composite of these reads, assembled by the call-graph builder, which
//!   will read through this seam itself; the engine keeps a slim local
//!   `CallGraphSource` trait for it.

use crate::cache::CachedGhidraSource;
use crate::client::{GhidraClient, GhidraError, Result};
use crate::model::{
    DataItem, DataTypeEntry, DecompiledFunction, EnumDefinition, EnumMember, FunctionSummary,
    StringLiteral, StructFieldLayout, StructLayout, Symbol, Xref,
};
use calxgloss_kuna::KunaSource;

/// The read-only program facts every evidence engine pulls from Ghidra.
///
/// [`GhidraClient`] implements it over the live HTTP API,
/// [`CachedGhidraSource`](crate::CachedGhidraSource) implements it as the
/// read cache, [`KunaSource`] implements the core reads over the in-process
/// Kuna engine (issue #206), and tests implement it over canned data. The
/// futures are `Send` so a scan can be driven from an orchestrating task.
pub trait ScanSource {
    /// Every function in the program, in listing order.
    fn functions(&self) -> impl std::future::Future<Output = Result<Vec<FunctionSummary>>> + Send;

    /// The pseudo-C for one function, by name.
    fn decompile(
        &self,
        name: &str,
    ) -> impl std::future::Future<Output = Result<DecompiledFunction>> + Send;

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
}

impl ScanSource for GhidraClient {
    // The trait's `Result` is the client's own, so each method delegates
    // straight through; the inherent methods (which take limits or page)
    // win over the trait's in method resolution.
    async fn functions(&self) -> Result<Vec<FunctionSummary>> {
        self.list_functions().await
    }

    async fn decompile(&self, name: &str) -> Result<DecompiledFunction> {
        self.decompile_function_by_name(name).await
    }

    async fn strings(&self) -> Result<Vec<StringLiteral>> {
        self.list_strings(None).await
    }

    async fn callers(&self, address: u64) -> Result<Vec<String>> {
        self.callers(address).await
    }

    async fn xrefs_to(&self, address: u64) -> Result<Vec<Xref>> {
        self.xrefs_to(address, None).await
    }

    async fn data_types(&self, category: Option<&str>) -> Result<Vec<DataTypeEntry>> {
        self.list_data_types(category).await
    }

    async fn struct_layout(&self, name: &str) -> Result<StructLayout> {
        self.get_struct_layout(name).await
    }

    async fn enum_values(&self, name: &str) -> Result<EnumDefinition> {
        self.get_enum_values(name).await
    }

    async fn data_items(&self) -> Result<Vec<DataItem>> {
        self.list_data_items().await
    }

    async fn imports(&self) -> Result<Vec<Symbol>> {
        self.imports(None).await
    }

    async fn exports(&self) -> Result<Vec<Symbol>> {
        self.exports(None).await
    }

    async fn image_base(&self) -> Result<u64> {
        self.image_base().await
    }

    async fn read_memory(&self, address: u64, length: usize) -> Result<Vec<u8>> {
        self.read_memory(address, length).await
    }
}

/// The core scan reads answered by the in-process Kuna engine (issue #206).
///
/// Every read the trait carries maps onto [`KunaSource`]'s inherent API,
/// with Kuna's named failures mapped onto the seam's error vocabulary: a
/// missing function, type, or byte range becomes [`GhidraError::NotFound`]
/// and a kind mismatch [`GhidraError::Malformed`] — the same facts the
/// Ghidra bridge reports, so layout probes branch on one vocabulary
/// whichever engine answers. Every other Kuna failure arrives as
/// [`GhidraError::Reported`] whose message already names the
/// `--engine ghidra` fallback.
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
            .map_err(GhidraError::from)
    }

    async fn decompile(&self, name: &str) -> Result<DecompiledFunction> {
        KunaSource::decompile_function(self, name)
            .await
            .map(|function| DecompiledFunction {
                name: function.name,
                signature: function.signature,
                body: function.body,
            })
            .map_err(GhidraError::from)
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
            .map_err(GhidraError::from)
    }

    /// The names of the functions holding a reference to `address`, deduped
    /// in first-reference order — the same shape the Ghidra client's
    /// `callers` answers with, so the call-graph builder needs no engine
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
            .map_err(GhidraError::from)
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
            .map_err(GhidraError::from)
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
            .map_err(GhidraError::from)
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
            .map_err(GhidraError::from)
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
            .map_err(GhidraError::from)
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
            .map_err(GhidraError::from)
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
            .map_err(GhidraError::from)
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
            .map_err(GhidraError::from)
    }

    async fn image_base(&self) -> Result<u64> {
        KunaSource::image_base(self)
            .await
            .map_err(GhidraError::from)
    }

    async fn read_memory(&self, address: u64, length: usize) -> Result<Vec<u8>> {
        KunaSource::read_memory(self, address, length)
            .await
            .map_err(GhidraError::from)
    }
}

/// The one concrete read source a translation batch hands to every consumer.
///
/// The pipeline builds a [`CachedGhidraSource`] for the target binary at the
/// top of a batch and every scan, the call-graph build, and the retry/escalation
/// helpers read through this enum afterwards — `Live` until that cache exists,
/// `Cached` once it does. Having one concrete type (rather than two call paths)
/// keeps the pipeline's plumbing generic-free: the same `PipelineSource` value
/// answers every consumer, and a warm second batch over the same workspace and
/// unchanged binary costs no live reads at all.
///
/// `Kuna` is the third path (issues #206 and #207): the in-process Kuna
/// engine, answering every scan read with no server at all. A Kuna batch
/// never silently falls back to the Ghidra server mid-scan — it answers
/// from one engine or fails by name.
#[derive(Debug, Clone)]
pub enum PipelineSource {
    /// No cache active — every read goes straight to the server.
    Live(GhidraClient),
    /// The batch's shared two-tier cache, scoped to one target binary.
    Cached(CachedGhidraSource),
    /// The in-process Kuna engine, loaded with exactly one target binary.
    Kuna(KunaSource),
}

impl From<GhidraClient> for PipelineSource {
    fn from(client: GhidraClient) -> Self {
        Self::Live(client)
    }
}

impl From<KunaSource> for PipelineSource {
    fn from(source: KunaSource) -> Self {
        Self::Kuna(source)
    }
}

impl ScanSource for PipelineSource {
    // Each arm delegates to its own `ScanSource` implementation; the cache
    // tier resolves memo → disk → live, the live tier is the raw client.
    // The calls are trait-qualified so the client's inherent methods (which
    // take limits and filters) never shadow the seam's unfiltered reads.
    async fn functions(&self) -> Result<Vec<FunctionSummary>> {
        match self {
            Self::Live(client) => ScanSource::functions(client).await,
            Self::Cached(cache) => ScanSource::functions(cache).await,
            Self::Kuna(source) => ScanSource::functions(source).await,
        }
    }

    async fn decompile(&self, name: &str) -> Result<DecompiledFunction> {
        match self {
            Self::Live(client) => ScanSource::decompile(client, name).await,
            Self::Cached(cache) => ScanSource::decompile(cache, name).await,
            Self::Kuna(source) => ScanSource::decompile(source, name).await,
        }
    }

    async fn strings(&self) -> Result<Vec<StringLiteral>> {
        match self {
            Self::Live(client) => ScanSource::strings(client).await,
            Self::Cached(cache) => ScanSource::strings(cache).await,
            Self::Kuna(source) => ScanSource::strings(source).await,
        }
    }

    async fn callers(&self, address: u64) -> Result<Vec<String>> {
        match self {
            Self::Live(client) => ScanSource::callers(client, address).await,
            Self::Cached(cache) => ScanSource::callers(cache, address).await,
            Self::Kuna(source) => ScanSource::callers(source, address).await,
        }
    }

    async fn xrefs_to(&self, address: u64) -> Result<Vec<Xref>> {
        match self {
            Self::Live(client) => ScanSource::xrefs_to(client, address).await,
            Self::Cached(cache) => ScanSource::xrefs_to(cache, address).await,
            Self::Kuna(source) => ScanSource::xrefs_to(source, address).await,
        }
    }

    async fn data_types(&self, category: Option<&str>) -> Result<Vec<DataTypeEntry>> {
        match self {
            Self::Live(client) => ScanSource::data_types(client, category).await,
            Self::Cached(cache) => ScanSource::data_types(cache, category).await,
            Self::Kuna(source) => ScanSource::data_types(source, category).await,
        }
    }

    async fn struct_layout(&self, name: &str) -> Result<StructLayout> {
        match self {
            Self::Live(client) => ScanSource::struct_layout(client, name).await,
            Self::Cached(cache) => ScanSource::struct_layout(cache, name).await,
            Self::Kuna(source) => ScanSource::struct_layout(source, name).await,
        }
    }

    async fn enum_values(&self, name: &str) -> Result<EnumDefinition> {
        match self {
            Self::Live(client) => ScanSource::enum_values(client, name).await,
            Self::Cached(cache) => ScanSource::enum_values(cache, name).await,
            Self::Kuna(source) => ScanSource::enum_values(source, name).await,
        }
    }

    async fn data_items(&self) -> Result<Vec<DataItem>> {
        match self {
            Self::Live(client) => ScanSource::data_items(client).await,
            Self::Cached(cache) => ScanSource::data_items(cache).await,
            Self::Kuna(source) => ScanSource::data_items(source).await,
        }
    }

    async fn imports(&self) -> Result<Vec<Symbol>> {
        match self {
            Self::Live(client) => ScanSource::imports(client).await,
            Self::Cached(cache) => ScanSource::imports(cache).await,
            Self::Kuna(source) => ScanSource::imports(source).await,
        }
    }

    async fn exports(&self) -> Result<Vec<Symbol>> {
        match self {
            Self::Live(client) => ScanSource::exports(client).await,
            Self::Cached(cache) => ScanSource::exports(cache).await,
            Self::Kuna(source) => ScanSource::exports(source).await,
        }
    }

    async fn image_base(&self) -> Result<u64> {
        match self {
            Self::Live(client) => ScanSource::image_base(client).await,
            Self::Cached(cache) => ScanSource::image_base(cache).await,
            Self::Kuna(source) => ScanSource::image_base(source).await,
        }
    }

    async fn read_memory(&self, address: u64, length: usize) -> Result<Vec<u8>> {
        match self {
            Self::Live(client) => ScanSource::read_memory(client, address, length).await,
            Self::Cached(cache) => ScanSource::read_memory(cache, address, length).await,
            Self::Kuna(source) => ScanSource::read_memory(source, address, length).await,
        }
    }
}
