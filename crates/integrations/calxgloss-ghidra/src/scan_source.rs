//! The shared read seam for everything an evidence engine pulls from Ghidra.
//!
//! Each evidence-engine crate carries its own `ScanSource`-shaped trait today,
//! and the copies have grown near-identical. This is their union — the
//! function listing, decompile-by-name, the string listing, callers,
//! xrefs-to, the Type Manager reads (data types, struct layouts, enum values,
//! data items), the import and export listings, and the raw reads the vtable
//! scan makes (image base, memory bytes) — defined once so the planned read
//! cache implements it once instead of eight times. The algorithm, callback,
//! consts, and control-flow engines already re-export this trait in place of
//! their own; the remaining crates migrate onto it one batch at a time.
//!
//! Deliberately absent:
//!
//! * **Write-side calls** (function tags, type write-back) — the cache only
//!   ever serves read-only facts.
//! * **The string-listing filter** — only `calxgloss-typesdb`'s string
//!   inference takes one, and no production caller sets it; the eight
//!   engine-facing shapes carry an unfiltered listing, so this trait matches
//!   them and a filtered consumer can filter the listing itself.
//! * **The built call graph** — `calxgloss-apidetect`'s `call_graph` read is
//!   a composite of these reads, assembled by the call-graph builder, which
//!   will read through this seam itself.

use crate::client::{GhidraClient, Result};
use crate::model::{
    DataItem, DataTypeEntry, DecompiledFunction, EnumDefinition, FunctionSummary, StringLiteral,
    StructLayout, Symbol, Xref,
};

/// The read-only program facts every evidence engine pulls from Ghidra.
///
/// [`GhidraClient`] implements it over the live HTTP API; tests and the
/// planned read cache implement it over canned or memoized data. The futures
/// are `Send` so a scan can be driven from an orchestrating task.
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
