//! The shared read seam: the one way that evidence engines read facts out of
//! the analysis engine.
//!
//! Every evidence-engine crate once had its own `ScanSource`-shaped trait,
//! and the copies had grown near-identical. This trait is their union — the
//! function listing, decompile-by-name, the per-function disassembly-text
//! read, the string listing, callers, xrefs-to, the Type Manager reads
//! (data types, struct layouts, enum values, data items), the import and
//! export listings, and the raw reads the vtable scan makes (image base,
//! memory bytes). It is defined once so the scan read cache implements it
//! once instead of once for each of the fourteen copies. All fifteen
//! scan-based evidence engines — algorithm, callback, consts, control-flow,
//! error-handling, float-SIMD, memory, serialization, string-context,
//! concurrency, global-state, known-library, types-database, type-inference,
//! and API-detection — re-export this trait in place of their own.
//!
//! Kuna is the only analysis engine (issue #214, ADR-0041). The seam answers
//! either directly through [`KunaSource`] or through
//! [`CachedScanSource`](crate::CachedScanSource), the two-tier read cache.
//!
//! Deliberately absent:
//!
//! * **Write-side calls** (function tags, type write-back) — the scan read
//!   cache only ever answers read-only facts. `calxgloss-typesdb`'s vtable
//!   scan keeps its own small local `TagSink` trait for its one write; the
//!   type write-back seam lives beside this module as
//!   [`TypeWriteSource`](crate::TypeWriteSource), answered by the Kuna
//!   directive plane (issue #209).
//! * **The string-listing filter** — only `calxgloss-typesdb`'s string
//!   inference takes a filter, and no production caller sets one. The
//!   analysis engine returns an unfiltered listing, so this trait matches
//!   that shape and the string inference filters the listing itself.
//! * **The built call graph** — `calxgloss-apidetect`'s `call_graph` read
//!   is a composite of these reads, assembled by the call-graph builder,
//!   which reads through this seam itself; `calxgloss-apidetect` keeps its
//!   own small local `CallGraphSource` trait for it.

use crate::cache::CachedScanSource;
use crate::error::{EngineError, Result};
use crate::model::{
    DataItem, DataTypeEntry, DecompiledFunction, EnumDefinition, EnumMember, FunctionSummary,
    StringLiteral, StructFieldLayout, StructLayout, Symbol, Xref,
};
use calxgloss_kuna::KunaSource;
use calxgloss_types::{AvailabilityStatus, CapabilityReport, EngineProvenance, FamilyCapability};

/// The read-only program facts every evidence engine reads from the
/// analysis engine.
///
/// [`KunaSource`] implements the core reads over the in-process Kuna
/// analysis engine (issue #206),
/// [`CachedScanSource`](crate::CachedScanSource) implements it as the read
/// cache, and tests implement it over canned data. The futures are `Send`,
/// so a scan can be driven from an orchestrating task.
pub trait ScanSource {
    /// Every function in the program, in listing order.
    ///
    /// A name in this listing is a name [`Self::decompile`] can answer:
    /// the analysis engine's import pointer slots and other entries
    /// without a body belong to the [`Self::imports`] read, and a name the
    /// engine cannot settle on a single entry — two of its own entries
    /// sharing one name, say — is listable by nobody. So a consumer that
    /// decompiles every listed name spends no read that cannot succeed.
    fn functions(&self) -> impl std::future::Future<Output = Result<Vec<FunctionSummary>>> + Send;

    /// The pseudo-C for one function, by name.
    fn decompile(
        &self,
        name: &str,
    ) -> impl std::future::Future<Output = Result<DecompiledFunction>> + Send;

    /// The machine-instruction listing for one function, by name, as text.
    ///
    /// One row per instruction, in address order, spelled by the analysis
    /// engine's own listing — uppercase SLEIGH mnemonics, `0x` hex operands
    /// — the text a calling-convention detector reads epilogues (`ret N`)
    /// and caller stack cleanup from (issue #245). The default answers
    /// empty, following the `engine_provenance` precedent: a source that
    /// has not opted in lists nothing, so every existing implementor,
    /// offline fake program, and scan keeps compiling and behaving
    /// byte-for-byte as it did — while the Kuna source answers from the
    /// engine's own instruction walker and the scan read cache stores the
    /// text under the scan-cache convention.
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

    /// The cross-references (xrefs) pointing at `address`, as the analysis
    /// engine recorded them.
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
    /// locator — bytes that no listing read reports.
    fn read_memory(
        &self,
        address: u64,
        length: usize,
    ) -> impl std::future::Future<Output = Result<Vec<u8>>> + Send;

    /// The analysis engine's decompiler answering these reads, when the
    /// source names one.
    ///
    /// This is the engine's identity, not a program read: a scan record
    /// stores it beside its timing, so a reviewer can tell what produced
    /// any decompilation inside the record and re-create it or blame it
    /// (issue #208). The default names nothing — a source that adds no
    /// identity of its own leaves scan records byte-for-byte what they
    /// were — while the Kuna source names its engine, pinned release, and
    /// source fingerprint.
    fn engine_provenance(&self) -> Option<EngineProvenance> {
        None
    }

    /// What the analysis engine behind this source can answer right now,
    /// family by family.
    ///
    /// The seam's own answer surface, declared by the engine: one entry
    /// per query family — the families of [`QUERY_FAMILIES`], paired to
    /// this trait's own query methods — saying whether the engine can
    /// answer that family *right now*, with a bounded reason line when it
    /// cannot (issue #354, applying ADR-0053's honesty doctrine one level
    /// up). The report is live session state: read once when a source
    /// opens, then held for the run. It never persists into a scan
    /// document, whose admitted coverage stays the persisted half.
    ///
    /// The default declares nothing: every family then reads
    /// [`EffectiveAvailability::Unknown`](calxgloss_types::EffectiveAvailability)
    /// — never answerable, so an undeclared question can never be treated
    /// as an answer, and never unavailable, so unknown never reads absent.
    /// That leaves every existing implementor and offline fake program
    /// byte-for-byte as it behaved, exactly the `engine_provenance`
    /// precedent. [`KunaSource`] declares its full roster, and
    /// [`CachedScanSource`](crate::CachedScanSource) and [`PipelineSource`]
    /// pass on the wrapped source's report untouched: a cache never changes
    /// capabilities, it only caches answers.
    fn capability_report(&self) -> CapabilityReport {
        CapabilityReport::default()
    }
}

/// The seam's query families, paired one-for-one with its own query
/// methods: each entry gives one family's stable, machine-comparable id
/// and the trait methods that answer it.
///
/// The trait's fourteen program-query reads group into twelve question
/// families: the three Type Manager reads (`data_types`, `struct_layout`,
/// `enum_values`) ask as one family, and the rest one method each. The two
/// self-knowledge reads (`engine_provenance`, `capability_report`) answer
/// no program question and belong to no family. This roster is the
/// declared side of the seam crate's roster pin (issue #354). The pin
/// checks the roster against the trait's own methods — a method no family
/// claims, a family claiming a method the trait does not declare, and a
/// method claimed twice each fault loudly — and against the capability
/// report every source declares, where missing, doubled, and orphaned
/// entries fault through the shared `CapabilityReport::roster_faults`.
/// Every future seam-primitive track (P28's masked byte search, P29's call
/// paths) enters by growing this roster inside its own change — the pin is
/// what makes forgetting fault. Family ids are how consumers — prompts,
/// retry decisions, and P21's unknown records — name a family across the
/// whole track.
pub const QUERY_FAMILIES: &[(&str, &[&str])] = &[
    ("function-inventory", &["functions"]),
    ("decompilation", &["decompile"]),
    ("disassembly", &["disassembly"]),
    ("strings", &["strings"]),
    ("caller-edges", &["callers"]),
    ("xrefs", &["xrefs_to"]),
    (
        "type-database",
        &["data_types", "struct_layout", "enum_values"],
    ),
    ("data-items", &["data_items"]),
    ("imports", &["imports"]),
    ("exports", &["exports"]),
    ("image-base", &["image_base"]),
    ("memory-reads", &["read_memory"]),
];

/// The analysis engine's decompile mapped to the seam's shape, raw — the
/// text exactly as the engine rendered it, before the decompile noise
/// filter has seen it.
///
/// Both analysis sources read through this one function: the in-process
/// Kuna source below filters the mapped record as it returns it, and the
/// read cache's live tier fetches through here so its memo and disk
/// documents hold the engine's raw text, with the filter applied above the
/// cache instead — reversible by deleting the cache (ADR-0043, issue #271).
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

/// The compiled-in Kuna analysis engine's own provenance stamp, written
/// once.
///
/// The pin is the build: the release tag and the short commit of the
/// checkout the engine and its embedded specs came from are the same facts
/// `build.rs` reads out of the lock file, so a scan record names exactly
/// the engine source that produced it (issue #208). The trait's provenance
/// read below and the scan read cache's engine-identity manifest field
/// both answer through this one construction — bumping the pinned Kuna
/// crate moves every stamp at once, and no hand-maintained constant feeds
/// the cache's engine key (issue #358).
pub(crate) fn kuna_provenance() -> EngineProvenance {
    EngineProvenance {
        name: "kuna".to_string(),
        version: Some(calxgloss_kuna::KUNA_RELEASE.to_string()),
        fingerprint: Some(calxgloss_kuna::KUNA_PIN_REV.to_string()),
    }
}

/// The core scan reads, answered by the in-process Kuna analysis engine
/// (issue #206).
///
/// Every read the trait declares maps onto [`KunaSource`]'s own API, and
/// Kuna's named failures are mapped onto the seam's error vocabulary: a
/// missing function, type, or byte range becomes [`EngineError::NotFound`]
/// and a kind mismatch [`EngineError::Malformed`] — the same facts the
/// retired Ghidra bridge reported, so layout probes branch on one
/// vocabulary. Every other Kuna failure arrives as
/// [`EngineError::Reported`] with the analysis engine's own message.
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

    /// The names of the functions holding a reference to `address`, with
    /// duplicates removed in first-reference order — the shape the seam's
    /// `callers` read has always had, so the call-graph builder needs no
    /// special case for the analysis engine.
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
        // This engine's stamp is the one construction the seam writes —
        // the same stamp beside every scan record and beside the cache
        // manifest (#208, #358).
        Some(kuna_provenance())
    }

    fn capability_report(&self) -> CapabilityReport {
        // Today Kuna declares its full roster honestly: every query
        // family the seam exposes, all answerable, none needing a reason
        // to admit. The declaration is built from the seam's own family
        // roster, so it can never drift from the seam's shape — and if a
        // pinned Kuna ever cannot answer a family, that roster is exactly
        // where the admission appears, reasoned (issue #354).
        full_roster_report()
    }
}

/// Every family on the seam's own roster, each answerable and none
/// admitted — the declaration [`KunaSource`] makes today. The seam crate's
/// roster pin pairs this report one-for-one against [`QUERY_FAMILIES`] in
/// its own tests.
fn full_roster_report() -> CapabilityReport {
    CapabilityReport {
        families: QUERY_FAMILIES
            .iter()
            .map(|(family, _)| FamilyCapability {
                id: (*family).to_string(),
                status: AvailabilityStatus::Answerable,
                reason: None,
            })
            .collect(),
    }
}

/// The one concrete read source that a translation batch hands to every
/// consumer.
///
/// At the top of a batch the pipeline builds a [`CachedScanSource`] for
/// the target binary, and after that every scan, the call-graph build, and
/// the retry/escalation helpers read through this enum — `Kuna` until that
/// cache exists, `Cached` once it does. One concrete type, rather than two
/// call paths, keeps the pipeline free of generics: the same
/// `PipelineSource` value answers every consumer, and a warm second batch
/// over the same workspace and unchanged binary costs no analysis-engine
/// reads at all.
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
    // Each variant delegates to its own `ScanSource` implementation; the
    // cache tier resolves memo → disk → engine. The calls name the trait
    // explicitly, so the engine's own methods (which answer Kuna-native
    // shapes) can never hide the seam's mapped reads.
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
        // Identity forwards like the reads: both variants answer through
        // the Kuna analysis engine, so a scan record built over this
        // source names the engine, its pinned release, and its source
        // fingerprint (issue #208).
        match self {
            Self::Cached(cache) => ScanSource::engine_provenance(cache),
            Self::Kuna(source) => ScanSource::engine_provenance(source),
        }
    }

    fn capability_report(&self) -> CapabilityReport {
        // Capabilities forward like identity, untouched: the cache never
        // changes capabilities, it only caches answers, and both variants
        // stand behind the same analysis engine — so the report the
        // pipeline holds is exactly the report the engine declared, byte
        // for byte (issue #354). A source whose engine declares nothing
        // passes on the empty, fully-unknown declaration the trait
        // default provides.
        match self {
            Self::Cached(cache) => ScanSource::capability_report(cache),
            Self::Kuna(source) => ScanSource::capability_report(source),
        }
    }
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use calxgloss_types::EffectiveAvailability;

    /// Reads that answer a question about the source itself rather than a
    /// program question, so they stand outside every family by design. A
    /// new identity or self-describing read joins this list on purpose; a
    /// new program query never does — the roster pairing demands its
    /// family.
    const NON_QUERY_READS: &[&str] = &["engine_provenance", "capability_report"];

    /// The family ids the seam's roster declares.
    fn declared_families() -> Vec<&'static str> {
        QUERY_FAMILIES.iter().map(|(family, _)| *family).collect()
    }

    /// The query methods the seam trait itself declares, taken from this
    /// file's own source. The roster pairs against the trait this way so
    /// the pin stands on the seam's actual shape rather than a second
    /// hand-maintained list: a method added to the trait with no family
    /// entry in the roster faults, and so does a roster entry naming a
    /// method the trait does not declare.
    fn seam_query_methods() -> Vec<String> {
        let source = include_str!("scan_source.rs");
        let marker = "pub trait ScanSource {";
        let body = &source[source
            .find(marker)
            .expect("the seam declares its own trait")
            + marker.len()..];
        let mut depth = 1usize;
        let mut methods = Vec::new();
        let stripped = body
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n")
            .replace('{', " { ")
            .replace('}', " } ");
        let mut tokens = stripped.split_whitespace();
        while let Some(token) = tokens.next() {
            match token {
                "{" => depth += 1,
                "}" => {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                }
                "fn" if depth == 1 => {
                    let name = tokens.next().expect("a method name follows `fn`");
                    methods.push(
                        name.split('(')
                            .next()
                            .expect("a method name ends at its parameter list")
                            .to_string(),
                    );
                }
                _ => {}
            }
        }
        methods.retain(|name| !NON_QUERY_READS.contains(&name.as_str()));
        methods
    }

    /// The data-level check behind the roster pairing: does the roster
    /// give every query method of the trait exactly one family, and does
    /// every family entry name a method the trait actually declares? Each
    /// returned fault names one drift in its own words, so a drift can
    /// only ever fail loudly.
    fn roster_pairing_faults(methods: &[String], roster: &[(&str, &[&str])]) -> Vec<String> {
        let mut faults = Vec::new();
        for method in methods {
            let claims = roster
                .iter()
                .filter(|(_, family_methods)| family_methods.contains(&method.as_str()))
                .count();
            if claims == 0 {
                faults.push(format!("seam method `{method}` has no family entry"));
            } else if claims > 1 {
                faults.push(format!(
                    "seam method `{method}` is claimed by {claims} families"
                ));
            }
        }
        for (family, family_methods) in roster {
            for method in *family_methods {
                if !methods.iter().any(|m| m == *method) {
                    faults.push(format!(
                        "family `{family}` names `{method}`, a method the seam does not carry"
                    ));
                }
            }
        }
        faults
    }

    /// A source that answers the seam's queries and declares no capability
    /// at all — what every test fake and offline stand-in gets from the
    /// trait default without writing a line about itself.
    struct SilentSource;

    impl ScanSource for SilentSource {
        async fn functions(&self) -> Result<Vec<FunctionSummary>> {
            Ok(Vec::new())
        }

        async fn decompile(&self, _name: &str) -> Result<DecompiledFunction> {
            Ok(DecompiledFunction {
                name: String::new(),
                signature: String::new(),
                body: String::new(),
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

        async fn struct_layout(&self, _name: &str) -> Result<StructLayout> {
            Ok(StructLayout {
                name: String::new(),
                size: 0,
                alignment: 0,
                fields: Vec::new(),
            })
        }

        async fn enum_values(&self, _name: &str) -> Result<EnumDefinition> {
            Ok(EnumDefinition {
                name: String::new(),
                size: 0,
                members: Vec::new(),
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

    // -- the roster pin: report pairs the roster, roster pairs the trait --

    #[test]
    fn the_roster_pairs_the_seams_own_query_methods_one_for_one() {
        // ADR-0053's engine-stamps/roster-pins doctrine, applied one
        // level up (issue #354): the seam declares the families and pairs
        // them against its own trait — every query method of the trait
        // belongs to exactly one family, and every family names methods
        // the trait actually declares. A future seam-primitive track
        // (P28, P29) grows the trait and must grow this roster in the
        // same change, or this pin faults.
        let methods = seam_query_methods();
        assert_eq!(
            methods.len(),
            QUERY_FAMILIES.iter().map(|(_, m)| m.len()).sum::<usize>(),
            "the parsed trait and the roster agree on the query-method count"
        );
        assert!(
            roster_pairing_faults(&methods, QUERY_FAMILIES).is_empty(),
            "the roster must pair every seam method exactly once: {:?}",
            roster_pairing_faults(&methods, QUERY_FAMILIES)
        );
    }

    #[test]
    fn a_trait_method_with_no_family_entry_fails_the_roster_pairing_loudly() {
        // Proves the P28/P29 posture in a test: when the roster was never
        // grown to carry a new query method's family, that method names
        // itself in the fault.
        let mut methods = seam_query_methods();
        methods.push("masked_byte_search".into());
        assert_eq!(
            roster_pairing_faults(&methods, QUERY_FAMILIES),
            ["seam method `masked_byte_search` has no family entry"],
            "a seam method no family entry answers fails loudly"
        );
    }

    #[test]
    fn a_roster_entry_naming_no_method_fails_the_roster_pairing_loudly() {
        let mut roster: Vec<(&str, &[&str])> = QUERY_FAMILIES.to_vec();
        roster.push(("ghost-reads", &["no_such_read"]));
        assert_eq!(
            roster_pairing_faults(&seam_query_methods(), &roster),
            ["family `ghost-reads` names `no_such_read`, a method the seam does not carry"],
            "a family entry naming a method no seam query is fails loudly"
        );
    }

    #[test]
    fn one_method_claimed_by_two_families_fails_the_roster_pairing_loudly() {
        let mut roster: Vec<(&str, &[&str])> = QUERY_FAMILIES.to_vec();
        roster.push(("second-inventory", &["functions"]));
        assert_eq!(
            roster_pairing_faults(&seam_query_methods(), &roster),
            ["seam method `functions` is claimed by 2 families"],
            "a method two families both claim fails loudly"
        );
    }

    #[test]
    fn the_declared_report_pairs_the_roster_one_for_one() {
        // The report side of the same pin: Kuna's declaration names every
        // family on the roster exactly once and nothing the roster never
        // carried.
        assert!(
            full_roster_report()
                .roster_faults(&declared_families())
                .is_empty(),
            "a fresh Kuna declaration must pair one-for-one with the seam's families"
        );
    }

    #[test]
    fn a_seam_method_with_no_family_entry_in_the_report_fails_loudly() {
        // `decompile` answers through the `decompilation` family; remove
        // that entry and the seam's own read stands uncovered, naming
        // itself as the fault.
        let mut report = full_roster_report();
        report.families.retain(|entry| entry.id != "decompilation");
        assert_eq!(
            report.roster_faults(&declared_families()),
            ["declared family `decompilation` is missing from the report"],
            "a seam method whose family the engine stopped declaring fails loudly"
        );
    }

    #[test]
    fn a_family_entry_doubled_in_the_report_fails_loudly() {
        let mut report = full_roster_report();
        let doubled = report.families[0].clone();
        report.families.push(doubled);
        assert_eq!(
            report.roster_faults(&declared_families()),
            ["declared family `function-inventory` appears 2 times in the report"],
            "a family declared twice fails loudly"
        );
    }

    #[test]
    fn a_family_entry_naming_no_seam_method_fails_loudly() {
        let mut report = full_roster_report();
        report.families.push(FamilyCapability {
            id: "masked-byte-search".into(),
            status: AvailabilityStatus::Answerable,
            reason: None,
        });
        assert_eq!(
            report.roster_faults(&declared_families()),
            ["report names `masked-byte-search`, a family the seam's roster never carried"],
            "an entry no seam method stands behind fails loudly"
        );
    }

    // -- the honest default: declared-absent reads unknown, both ways -----

    #[test]
    fn a_source_that_declares_nothing_reads_every_family_as_unknown() {
        // The trait default is the honest default, and the pin the whole
        // track reads: a family never declared reads unknown — never
        // answerable, so an undeclared question can never be treated as
        // an answer, and never unavailable, so unknown never reads absent
        // (issue #354). The cache and pipeline wrappers pass on this same
        // empty declaration untouched.
        let report = SilentSource.capability_report();
        assert!(
            report.families.is_empty(),
            "the trait default declares nothing"
        );
        for (family, _) in QUERY_FAMILIES {
            let availability = report.availability_for(family);
            assert_eq!(
                availability,
                EffectiveAvailability::Unknown,
                "`{family}` was never declared, so it reads unknown"
            );
            assert_ne!(availability, EffectiveAvailability::Answerable);
            assert_ne!(availability, EffectiveAvailability::Unavailable);
        }
    }
}
