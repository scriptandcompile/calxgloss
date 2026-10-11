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
//!   slim local `TagSink` trait for its one write.
//! * **The string-listing filter** — only `calxgloss-typesdb`'s string
//!   inference takes one, and no production caller sets it; the engine-facing
//!   shape carries an unfiltered listing, so this trait matches it and the
//!   inference engine filters the listing itself.
//! * **The built call graph** — `calxgloss-apidetect`'s `call_graph` read is
//!   a composite of these reads, assembled by the call-graph builder, which
//!   will read through this seam itself; the engine keeps a slim local
//!   `CallGraphSource` trait for it.

use crate::cache::CachedGhidraSource;
use crate::client::{GhidraClient, Result};
use crate::model::{
    DataItem, DataTypeEntry, DecompiledFunction, EnumDefinition, FunctionSummary, StringLiteral,
    StructLayout, Symbol, Xref,
};

/// The read-only program facts every evidence engine pulls from Ghidra.
///
/// [`GhidraClient`] implements it over the live HTTP API and
/// [`CachedGhidraSource`](crate::CachedGhidraSource) implements it as the
/// read cache; tests implement it over canned data. The futures are `Send`
/// so a scan can be driven from an orchestrating task.
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

/// The one concrete read source a translation batch hands to every consumer.
///
/// The pipeline builds a [`CachedGhidraSource`] for the target binary at the
/// top of a batch and every scan, the call-graph build, and the retry/escalation
/// helpers read through this enum afterwards — `Live` until that cache exists,
/// `Cached` once it does. Having one concrete type (rather than two call paths)
/// keeps the pipeline's plumbing generic-free: the same `PipelineSource` value
/// answers every consumer, and a warm second batch over the same workspace and
/// unchanged binary costs no live reads at all.
#[derive(Debug, Clone)]
pub enum PipelineSource {
    /// No cache active — every read goes straight to the server.
    Live(GhidraClient),
    /// The batch's shared two-tier cache, scoped to one target binary.
    Cached(CachedGhidraSource),
}

impl From<GhidraClient> for PipelineSource {
    fn from(client: GhidraClient) -> Self {
        Self::Live(client)
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
        }
    }

    async fn decompile(&self, name: &str) -> Result<DecompiledFunction> {
        match self {
            Self::Live(client) => ScanSource::decompile(client, name).await,
            Self::Cached(cache) => ScanSource::decompile(cache, name).await,
        }
    }

    async fn strings(&self) -> Result<Vec<StringLiteral>> {
        match self {
            Self::Live(client) => ScanSource::strings(client).await,
            Self::Cached(cache) => ScanSource::strings(cache).await,
        }
    }

    async fn callers(&self, address: u64) -> Result<Vec<String>> {
        match self {
            Self::Live(client) => ScanSource::callers(client, address).await,
            Self::Cached(cache) => ScanSource::callers(cache, address).await,
        }
    }

    async fn xrefs_to(&self, address: u64) -> Result<Vec<Xref>> {
        match self {
            Self::Live(client) => ScanSource::xrefs_to(client, address).await,
            Self::Cached(cache) => ScanSource::xrefs_to(cache, address).await,
        }
    }

    async fn data_types(&self, category: Option<&str>) -> Result<Vec<DataTypeEntry>> {
        match self {
            Self::Live(client) => ScanSource::data_types(client, category).await,
            Self::Cached(cache) => ScanSource::data_types(cache, category).await,
        }
    }

    async fn struct_layout(&self, name: &str) -> Result<StructLayout> {
        match self {
            Self::Live(client) => ScanSource::struct_layout(client, name).await,
            Self::Cached(cache) => ScanSource::struct_layout(cache, name).await,
        }
    }

    async fn enum_values(&self, name: &str) -> Result<EnumDefinition> {
        match self {
            Self::Live(client) => ScanSource::enum_values(client, name).await,
            Self::Cached(cache) => ScanSource::enum_values(cache, name).await,
        }
    }

    async fn data_items(&self) -> Result<Vec<DataItem>> {
        match self {
            Self::Live(client) => ScanSource::data_items(client).await,
            Self::Cached(cache) => ScanSource::data_items(cache).await,
        }
    }

    async fn imports(&self) -> Result<Vec<Symbol>> {
        match self {
            Self::Live(client) => ScanSource::imports(client).await,
            Self::Cached(cache) => ScanSource::imports(cache).await,
        }
    }

    async fn exports(&self) -> Result<Vec<Symbol>> {
        match self {
            Self::Live(client) => ScanSource::exports(client).await,
            Self::Cached(cache) => ScanSource::exports(cache).await,
        }
    }

    async fn image_base(&self) -> Result<u64> {
        match self {
            Self::Live(client) => ScanSource::image_base(client).await,
            Self::Cached(cache) => ScanSource::image_base(cache).await,
        }
    }

    async fn read_memory(&self, address: u64, length: usize) -> Result<Vec<u8>> {
        match self {
            Self::Live(client) => ScanSource::read_memory(client, address, length).await,
            Self::Cached(cache) => ScanSource::read_memory(cache, address, length).await,
        }
    }
}
