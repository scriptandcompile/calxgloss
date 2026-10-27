//! The two-tier read-through cache for engine reads (issue #103).
//!
//! [`CachedScanSource`] wraps a [`KunaSource`] and implements the shared
//! [`ScanSource`] seam, so every evidence engine pulls its program facts
//! through the cache without knowing it exists. Reads resolve in three
//! tiers: an in-memory memo first, then JSON documents on disk under the
//! record of effort, then the engine — and every engine result is written
//! through to disk immediately, so an interrupted run leaves a valid partial
//! cache and a second run over the same bytes replays with zero engine calls.
//! The `decompile` read is the one exception on the way out: the
//! decompiler-noise pre-filter runs above the cache, so every tier keeps the
//! engine's raw text and the filter re-applies on each read (issue #271).
//!
//! **Validity is the key.** The disk tier lives at
//! `re/cache/{binary identity}/{sha256}/`, where the hash is SHA-256
//! over the target binary's file bytes. Changed bytes mean a different
//! directory, so staleness needs no invalidation logic; old hash directories
//! are kept (for switching back to a previous build) until pruned by hand.
//! A `manifest.json` in the directory records the binary hash, the cache
//! format version, and the program name as the engine named it — a mismatch
//! on any field (or a corrupt manifest) treats the directory as cold: it is
//! wiped and rewritten, so a stale entry is never served. The format version
//! went to 2 when Kuna became the only engine (issue #214): documents
//! written by the retired Ghidra bridge are never replayed under Kuna. It
//! went to 3 when the function listing dropped the engine's import pointer
//! slots: a v2 `functions` document still names every IAT slot, and a
//! consumer that decompiles each listed name then spends one read per
//! import on an entry the engine refuses.
//!
//! **The directory has had three names** — `re/ghidra-cache` (ADR-0041's
//! deferral), `re/decomp-cache` (ADR-0042's uptake), and `re/cache` from
//! ADR-0043, which drops the engine-era qualifier entirely: the directory
//! holds the scan read cache and nothing else lives under it. Each rename
//! is a silent reset — a directory under an old name is never opened again,
//! so it stays in the workspace as dead weight for its owner to delete.
//!
//! **Kept out of the workspace repo:** opening the disk tier ensures
//! `re/cache/` is listed in the workspace's `.gitignore` — the cache is
//! tens of thousands of regenerable documents, and a workspace repo that
//! commits them carries that weight through every clone and checkout.
//!
//! **Forcing a cold cache:** the `--refresh-cache` CLI flag (on
//! `batch-translate`, `auto`, and `live`) routes the run through
//! [`CachedScanSource::new_refresh`] — the directory is wiped and
//! rewritten, so every read goes to the engine once and the next run
//! replays warm again. Deleting the cache directory (or the binary's whole
//! identity directory) does the same by hand. Bumping
//! [`CACHE_FORMAT_VERSION`] invalidates every cache at once when the record
//! shape changes.
//!
//! **Degradation, never failure:** a missing or unreadable binary file drops
//! the disk tier entirely and reads pass straight through to the engine; a
//! corrupt cache document is logged and refetched from the engine; a failed
//! cache write is logged and the read still succeeds. Only the engine
//! fetch's own errors reach the caller.
//!
//! **The surviving scans stay readable** (issue #298, track P18): when a
//! binary's bytes change, the previous version's scan document set is the
//! sibling hash directory this module keeps on disk. The binary-version
//! pairing pass reads exactly two such document sets and no engine, so
//! [`is_surviving_scan`] and the [`cached_functions`], [`cached_exports`],
//! and [`cached_body`] readers are that pass's public surface: read-only,
//! keyed by hash directory, answering the same shapes the seam answers.
//! Unlike [`open_manifest`] they never wipe a directory — a sibling scan
//! belongs to a different version's bytes, and this run's manifest has no
//! claim on it.
//!
//! **What is never cached:** write-side calls (function tags, type
//! write-back) never go through the cache, and `begin_pass`/`end_pass`
//! heartbeat control passes through to the wrapped engine. The heartbeat
//! counts *unique work items consumed*, not engine round trips: a cached
//! decompile beats through the wrapped engine's heartbeat just like a
//! live one, so a warm run's progress line keeps moving (issue #121),
//! and a function already counted cold is not counted again warm (issue
//! #239). Concurrent misses of one key share a single engine request.

use crate::error::{EngineError, Result};
use crate::model::{
    DataItem, DataTypeEntry, DecompiledFunction, EnumDefinition, FunctionSummary, StringLiteral,
    StructLayout, Symbol, Xref,
};
use crate::scan_source::{ScanSource, raw_decompile};
use calxgloss_kuna::KunaSource;
use calxgloss_types::BinaryIdentity;
use calxgloss_types::TranslationEvents;
use calxgloss_types::persist::{PersistError, load_json, save_json};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::OnceCell;
use tracing::{debug, warn};

/// Cache-format version, recorded in every manifest. Bump when a cached
/// document's shape changes: every existing directory then reads as cold
/// instead of serving records the new readers cannot interpret. Version 2
/// marks the Kuna-only engine (issue #214): the Ghidra bridge's documents
/// are never replayed under a different engine's decompiler. Version 3 marks
/// the function listing without import pointer slots — a v2 listing names
/// each IAT slot, and no `decompile` of one can succeed. Version 4 marks the
/// listing without ambiguous names either — a v3 listing names both thunk
/// veneers of an import an MSVC link emitted twice, and the engine settles
/// on neither, so no `decompile` of that name can succeed.
///
/// Public because the surviving-scan readers below answer only directories
/// written under the current version (#298), and a consumer assembling a
/// manifest for one needs the live value, not a hand-copy.
pub const CACHE_FORMAT_VERSION: u32 = 4;

/// The `manifest.json` beside a directory's cached documents. All three
/// fields must match this run's facts for the directory to be warm; the
/// binary hash duplicates the directory name on purpose, so a renamed or
/// moved directory is detected rather than trusted. The surviving-scan
/// readers expose the same record for reading (#298).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CacheManifest {
    /// SHA-256 (hex) of the target binary's file bytes.
    pub binary_sha256: String,
    /// The [`CACHE_FORMAT_VERSION`] this directory was written under.
    pub format_version: u32,
    /// The program name as the engine named it.
    pub program: String,
}

/// One cached read, identifying both its read and its argument.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum CacheKey {
    Functions,
    Strings,
    Imports,
    Exports,
    ImageBase,
    DataItems,
    DataTypes(Option<String>),
    Decompile(String),
    Disassembly(String),
    Callers(u64),
    XrefsTo(u64),
    StructLayout(String),
    EnumValues(String),
    Memory(u64, usize),
}

/// A cached view of one loaded program, safe to clone and hand to every
/// engine in a batch.
///
/// See the [module docs](crate::cache) for the tiers, the validity key, and
/// the degradation rules. The instance is scoped to one target binary: the
/// memo and the disk directory can never serve one program's data for
/// another.
#[derive(Debug, Clone)]
pub struct CachedScanSource {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    source: KunaSource,
    /// `re/cache/{identity}/{sha256}` — `None` when the binary file
    /// was missing or unreadable, which drops the disk tier and leaves
    /// pass-through engine reads.
    cache_dir: Option<PathBuf>,
    /// In-memory tier: one shared cell per key. The cell fills on the first
    /// miss (disk or engine), and concurrent misses of the same key await
    /// the one in-flight fill instead of stampeding the engine.
    memo: Mutex<HashMap<CacheKey, Arc<OnceCell<Value>>>>,
}

impl CachedScanSource {
    /// Wrap `source` with a cache for the binary `binary_path`, filed under
    /// the workspace's record of effort.
    ///
    /// The binary's file bytes are hashed once here; the program name the
    /// manifest records is the one the loaded engine already names, so
    /// construction never touches the engine. A missing or unreadable
    /// `binary_path` is not an error: the source degrades to pass-through
    /// engine reads (in-memory memo only, no disk tier).
    ///
    /// # Errors
    ///
    /// Returns a [`Result`] only for shape reasons — construction reads no
    /// engine, so nothing here fails on engine state.
    pub fn new(
        source: KunaSource,
        workspace: impl AsRef<Path>,
        binary: impl Into<BinaryIdentity>,
        binary_path: impl AsRef<Path>,
    ) -> Result<Self> {
        Ok(Self::build(source, workspace, binary, binary_path, false))
    }

    /// Like [`new`](Self::new), but forces the disk tier cold first: the
    /// directory for this binary's current bytes is wiped before the
    /// manifest is opened, so every read goes to the engine and the cache
    /// is rewritten by write-through.
    ///
    /// This is the operator's escape hatch (issue #106): deleting the
    /// directory does the same by hand. The CLI's `--refresh-cache` flag
    /// routes a run through here.
    pub fn new_refresh(
        source: KunaSource,
        workspace: impl AsRef<Path>,
        binary: impl Into<BinaryIdentity>,
        binary_path: impl AsRef<Path>,
    ) -> Result<Self> {
        Ok(Self::build(source, workspace, binary, binary_path, true))
    }

    fn build(
        source: KunaSource,
        workspace: impl AsRef<Path>,
        binary: impl Into<BinaryIdentity>,
        binary_path: impl AsRef<Path>,
        refresh: bool,
    ) -> Self {
        let binary = binary.into();
        let binary_path = binary_path.as_ref();
        let cache_dir = match sha256_of_file(binary_path) {
            Ok(None) => {
                warn!(
                    binary = %binary,
                    path = %binary_path.display(),
                    "target binary file is missing — engine reads pass through uncached"
                );
                None
            }
            Ok(Some(hash)) => {
                let program = source.identity().to_string();
                let dir = cache_root(&workspace).join(binary.as_str()).join(&hash);
                let manifest = CacheManifest {
                    binary_sha256: hash,
                    format_version: CACHE_FORMAT_VERSION,
                    program,
                };
                match open_manifest(&dir, &manifest, refresh) {
                    Ok(()) => {
                        // The disk tier is live, so the workspace repo gets
                        // the rule that keeps the cache out of its commits.
                        ensure_gitignore(workspace.as_ref());
                        Some(dir)
                    }
                    Err(err) => {
                        warn!(
                            %err,
                            "scan cache directory is unusable — reads pass through uncached"
                        );
                        None
                    }
                }
            }
            Err(err) => {
                warn!(
                    %err,
                    path = %binary_path.display(),
                    "could not read the target binary — engine reads pass through uncached"
                );
                None
            }
        };
        Self {
            inner: Arc::new(Inner {
                source,
                cache_dir,
                memo: Mutex::new(HashMap::new()),
            }),
        }
    }

    /// The directory this instance's documents are filed under, or `None`
    /// when the disk tier is off (missing binary, unusable directory).
    pub fn cache_dir(&self) -> Option<&Path> {
        self.inner.cache_dir.as_deref()
    }

    // =========================================================
    // Write-side and heartbeat pass-throughs — never cached
    // =========================================================

    /// Attach `tag` to a function — refused by name.
    ///
    /// The Kuna engine has no function-tag write-back, and writes are never
    /// cached anyway; the refusal is named so a vtable scan can tolerate it
    /// (tagging is enrichment, not detection) rather than lose the scan.
    pub async fn add_function_tag(&self, _function: &str, _tag: &str) -> Result<()> {
        Err(EngineError::Reported {
            message: "the Kuna engine has no function-tag write-back; vtable tagging is \
                      enrichment, not detection, and the scan continues without it"
                .to_string(),
        })
    }

    /// Arm the wrapped engine's heartbeat for one analysis pass.
    ///
    /// Beats count work items consumed, not engine round trips: a cached
    /// decompile beats through the wrapped engine's heartbeat just like a
    /// live one, so a warm run's progress stays visible (issue #121).
    pub fn begin_pass(&self, binary: &str, pass: &str, events: &TranslationEvents) {
        self.inner.source.begin_pass(binary, pass, events);
    }

    /// Disarm the wrapped engine's heartbeat.
    pub fn end_pass(&self) {
        self.inner.source.end_pass();
    }

    // =========================================================
    // The read path: memo → disk → engine, writing through
    // =========================================================

    /// Resolve `key` through the three tiers, storing the engine answer in
    /// both. The memo cell is shared per key, so concurrent misses of one
    /// key fire exactly one engine request.
    async fn cached<T, Fut>(&self, key: CacheKey, live: impl FnOnce() -> Fut + Send) -> Result<T>
    where
        T: Serialize + DeserializeOwned,
        Fut: Future<Output = Result<T>> + Send,
    {
        self.cached_hit(key, live).await.map(|(value, _)| value)
    }

    /// Like [`cached`](Self::cached), also reporting whether the value was
    /// served without an engine round trip — a memo or disk hit. Callers
    /// that count consumed work items (the heartbeat) need the distinction:
    /// the engine path already beats inside the source, so only a hit must
    /// beat here.
    async fn cached_hit<T, Fut>(
        &self,
        key: CacheKey,
        live: impl FnOnce() -> Fut + Send,
    ) -> Result<(T, bool)>
    where
        T: Serialize + DeserializeOwned,
        Fut: Future<Output = Result<T>> + Send,
    {
        let cell = {
            let mut memo = self.inner.memo.lock().expect("memo lock poisoned");
            Arc::clone(
                memo.entry(key.clone())
                    .or_insert_with(|| Arc::new(OnceCell::new())),
            )
        };
        let went_engine = AtomicBool::new(false);
        let value = cell
            .get_or_try_init(|| async {
                if let Some(disk) = self.read_disk(&key) {
                    // A document that parses as JSON but not as this
                    // read's record is corrupt for our purposes.
                    if serde_json::from_value::<T>(disk.clone()).is_ok() {
                        return Ok::<Value, EngineError>(disk);
                    }
                    warn!(
                        ?key,
                        "cache document does not match its read — refetching from the engine"
                    );
                }
                went_engine.store(true, Ordering::Relaxed);
                let value =
                    serde_json::to_value(live().await?).map_err(|err| EngineError::Malformed {
                        kind: "a cache document",
                        detail: err.to_string(),
                    })?;
                self.write_disk(&key, &value);
                Ok(value)
            })
            .await?;
        // A memo hit never runs the init closure, and a disk hit stops
        // before the engine fetch — either way `went_engine` stays false.
        let from_cache = !went_engine.load(Ordering::Relaxed);
        serde_json::from_value(value.clone())
            .map(|parsed| (parsed, from_cache))
            .map_err(|err| EngineError::Malformed {
                kind: "a cached read",
                detail: err.to_string(),
            })
    }

    /// The disk tier's document for `key`, if there is a usable one.
    /// A missing document is an ordinary miss; a corrupt one is logged.
    fn read_disk(&self, key: &CacheKey) -> Option<Value> {
        let path = self
            .inner
            .cache_dir
            .as_ref()
            .map(|dir| doc_path(dir, key))?;
        match load_json::<Value>(&path) {
            Ok(value) => Some(value),
            Err(PersistError::NotFound { .. }) => None,
            Err(err) => {
                warn!(%err, "corrupt cache document — refetching from the engine");
                None
            }
        }
    }

    /// Write `value` through to disk. A failed write is logged, never
    /// fatal: the read already succeeded and the memo still holds it.
    fn write_disk(&self, key: &CacheKey, value: &Value) {
        if let Some(dir) = &self.inner.cache_dir {
            let path = doc_path(dir, key);
            if let Err(err) = save_json(&path, value) {
                warn!(%err, "could not write cache document — continuing without it");
            }
        }
    }
}

impl ScanSource for CachedScanSource {
    // The live tier is the wrapped engine read through the seam, so the
    // cached records are exactly the seam shapes every consumer expects.
    // The calls are trait-qualified so the engine's inherent methods (which
    // answer Kuna-native shapes) never shadow the seam's mapped reads.
    async fn functions(&self) -> Result<Vec<FunctionSummary>> {
        let (list, from_cache) = self
            .cached_hit(CacheKey::Functions, || {
                ScanSource::functions(&self.inner.source)
            })
            .await?;
        if from_cache {
            // A warm listing never reaches the engine, so an armed
            // heartbeat would never learn the work list — forward it here
            // to keep the pass's "n of m" honest on a warm run.
            self.inner.source.note_worklist(list.len());
        }
        Ok(list)
    }

    async fn decompile(&self, name: &str) -> Result<DecompiledFunction> {
        // The live tier fetches through `raw_decompile`, not the Kuna arm's
        // `ScanSource::decompile`: the noise pre-filter must sit above the
        // cache, so the memo and the disk document keep the engine's raw
        // text — debuggable, and reversible by deleting the cache
        // (ADR-0043, issue #271) — and the filter runs on the way out.
        let (body, from_cache) = self
            .cached_hit(CacheKey::Decompile(name.to_string()), || {
                raw_decompile(&self.inner.source, name)
            })
            .await?;
        if from_cache {
            // The engine path beats inside the source's decompile; a cached
            // body never gets there, so count the consumed work item here
            // (issue #121 — the dashboard's per-binary activity line).
            self.inner.source.tick(name);
        }
        Ok(crate::noise_filter::strip_decompiler_noise(body))
    }

    async fn disassembly(&self, name: &str) -> Result<String> {
        // The listing text is cached like every other read: a warm scan
        // never re-disassembles (issue #245). No heartbeat beat — the
        // read is not a decompile work item, and the scan's breaker-
        // gated window counts it beside the body it pairs with.
        self.cached(CacheKey::Disassembly(name.to_string()), || {
            ScanSource::disassembly(&self.inner.source, name)
        })
        .await
    }

    async fn strings(&self) -> Result<Vec<StringLiteral>> {
        self.cached(CacheKey::Strings, || {
            ScanSource::strings(&self.inner.source)
        })
        .await
    }

    async fn callers(&self, address: u64) -> Result<Vec<String>> {
        self.cached(CacheKey::Callers(address), || {
            ScanSource::callers(&self.inner.source, address)
        })
        .await
    }

    async fn xrefs_to(&self, address: u64) -> Result<Vec<Xref>> {
        self.cached(CacheKey::XrefsTo(address), || {
            ScanSource::xrefs_to(&self.inner.source, address)
        })
        .await
    }

    async fn data_types(&self, category: Option<&str>) -> Result<Vec<DataTypeEntry>> {
        let category = category.map(str::to_string);
        self.cached(CacheKey::DataTypes(category.clone()), || {
            ScanSource::data_types(&self.inner.source, category.as_deref())
        })
        .await
    }

    async fn struct_layout(&self, name: &str) -> Result<StructLayout> {
        self.cached(CacheKey::StructLayout(name.to_string()), || {
            ScanSource::struct_layout(&self.inner.source, name)
        })
        .await
    }

    async fn enum_values(&self, name: &str) -> Result<EnumDefinition> {
        self.cached(CacheKey::EnumValues(name.to_string()), || {
            ScanSource::enum_values(&self.inner.source, name)
        })
        .await
    }

    async fn data_items(&self) -> Result<Vec<DataItem>> {
        self.cached(CacheKey::DataItems, || {
            ScanSource::data_items(&self.inner.source)
        })
        .await
    }

    async fn imports(&self) -> Result<Vec<Symbol>> {
        self.cached(CacheKey::Imports, || {
            ScanSource::imports(&self.inner.source)
        })
        .await
    }

    async fn exports(&self) -> Result<Vec<Symbol>> {
        self.cached(CacheKey::Exports, || {
            ScanSource::exports(&self.inner.source)
        })
        .await
    }

    async fn image_base(&self) -> Result<u64> {
        self.cached(CacheKey::ImageBase, || {
            ScanSource::image_base(&self.inner.source)
        })
        .await
    }

    async fn read_memory(&self, address: u64, length: usize) -> Result<Vec<u8>> {
        self.cached(CacheKey::Memory(address, length), || {
            ScanSource::read_memory(&self.inner.source, address, length)
        })
        .await
    }

    fn engine_provenance(&self) -> Option<calxgloss_types::EngineProvenance> {
        // The cache answers from the engine it wraps, so the record names
        // that engine — a warm replay still says which engine and pin
        // produced it (issue #208).
        ScanSource::engine_provenance(&self.inner.source)
    }

    fn capability_report(&self) -> calxgloss_types::CapabilityReport {
        // A cache never changes capabilities, it only caches answers, so
        // the wrapped engine's declaration passes through untouched —
        // byte-identically on a warm replay as on the cold first read
        // (issue #354). A source whose engine declares nothing propagates
        // the empty, fully-unknown declaration.
        ScanSource::capability_report(&self.inner.source)
    }
}

// ============================================================
// Disk layout
// ============================================================

/// The cache convention: `{workspace}/re/cache`.
///
/// The directory was `re/ghidra-cache`, then `re/decomp-cache` (ADR-0041's
/// deferral, ADR-0042's uptake), and is `re/cache` from ADR-0043. The
/// cache-format version marker inside a directory invalidates anything an
/// old name held, and a directory under an old name is never opened again —
/// it stays in the workspace for its owner to delete.
///
/// Public because the surviving-scan readers below (#298) name their
/// document sets by this convention, and a consumer needs to find the
/// identity directory's sibling hash directories without restating the path.
pub fn cache_root(workspace: impl AsRef<Path>) -> PathBuf {
    workspace.as_ref().join("re").join("cache")
}

/// The rules the cache ensures in every workspace `.gitignore`. The read
/// cache is tens of thousands of regenerable JSON documents (22 MB on the
/// EverQuest workspace) that a rerun or `--refresh-cache` rebuilds, and a
/// workspace repo that commits them carries that dead weight through every
/// clone and every checkout.
const ENSURED_IGNORES: &[&str] = &["re/cache/"];

/// Ensure the workspace `.gitignore` carries [`ENSURED_IGNORES`], creating
/// the file or appending the missing rules as needed. The check runs on
/// every disk-tier open, so a workspace that predates the rule, renamed it
/// away, or deleted the file gets it back.
///
/// Failure is logged, never raised: a missing ignore rule is an
/// inconvenience to the workspace repo, not a broken run.
fn ensure_gitignore(workspace: &Path) {
    let path = workspace.join(".gitignore");
    let existing = match std::fs::read_to_string(&path) {
        Ok(body) => body,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(err) => {
            warn!(path = %path.display(), error = %err, "Could not read the workspace .gitignore");
            return;
        }
    };
    let missing: Vec<&str> = ENSURED_IGNORES
        .iter()
        .copied()
        .filter(|rule| !existing.lines().any(|line| line.trim() == *rule))
        .collect();
    if missing.is_empty() {
        return;
    }
    let mut updated = existing;
    if !updated.is_empty() && !updated.ends_with('\n') {
        updated.push('\n');
    }
    for rule in missing {
        updated.push_str(rule);
        updated.push('\n');
    }
    if let Err(err) = std::fs::write(&path, updated) {
        warn!(path = %path.display(), error = %err, "Could not update the workspace .gitignore");
    }
}

/// Where one key's document is filed inside a hash directory: whole-program
/// listings at the top level, per-item documents under per-read
/// subdirectories keyed by bare hex address or item name.
fn doc_path(root: &Path, key: &CacheKey) -> PathBuf {
    fn item(sub: &str, name: &str) -> PathBuf {
        Path::new(sub).join(format!("{name}.json"))
    }
    match key {
        CacheKey::Functions => root.join("functions.json"),
        CacheKey::Strings => root.join("strings.json"),
        CacheKey::Imports => root.join("imports.json"),
        CacheKey::Exports => root.join("exports.json"),
        CacheKey::ImageBase => root.join("image_base.json"),
        CacheKey::DataItems => root.join("data_items.json"),
        CacheKey::DataTypes(category) => root.join(item(
            "data_types",
            &safe_key(category.as_deref().unwrap_or("all")),
        )),
        CacheKey::Decompile(name) => root.join(item("decompile", &safe_key(name))),
        CacheKey::Disassembly(name) => root.join(item("disassembly", &safe_key(name))),
        CacheKey::Callers(address) => root.join(item("callers", &format!("{address:x}"))),
        CacheKey::XrefsTo(address) => root.join(item("xrefs_to", &format!("{address:x}"))),
        CacheKey::StructLayout(name) => root.join(item("struct_layout", &safe_key(name))),
        CacheKey::EnumValues(name) => root.join(item("enum_values", &safe_key(name))),
        CacheKey::Memory(address, length) => {
            root.join(item("memory", &format!("{address:x}-{length}")))
        }
    }
}

/// A file-name-safe rendering of an item name (function, type, or category).
/// Engine-generated names like `FUN_…` are already safe and stay verbatim,
/// so the documents stay hand-inspectable; anything else is sanitized with a
/// hash suffix so two different names can never collide on one document.
fn safe_key(name: &str) -> String {
    let safe = |c: char| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-');
    if !name.is_empty() && name != "." && name != ".." && name.chars().all(&safe) {
        return name.to_string();
    }
    let sanitized: String = name
        .chars()
        .map(|c| if safe(c) { c } else { '_' })
        .collect();
    let hash = sha256_hex(name.as_bytes());
    format!("{sanitized}-{}", &hash[..12])
}

// ============================================================
// Validity: the binary hash and the manifest
// ============================================================

/// SHA-256 (hex) over `path`'s bytes. `Ok(None)` when the file does not
/// exist — the missing-binary degradation the module docs promise.
/// Public because the version-pairing trigger (#298) recomputes the
/// current binary's hash to name the live hash directory.
pub fn sha256_of_file(path: &Path) -> std::io::Result<Option<String>> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(Some(sha256_hex(&bytes))),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err),
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
}

/// Establish the directory's manifest for this run.
///
/// A matching manifest leaves the warm documents in place. A mismatch on
/// any field — or a corrupt or absent manifest — means the directory's
/// entries cannot be trusted: it is wiped (so no stale entry can be served
/// later) and rewritten with this run's facts, leaving a cold but writable
/// directory.
///
/// `refresh` is the operator's escape hatch (issue #106): a refresh wipes
/// and rewrites regardless of what the manifest says.
fn open_manifest(
    dir: &Path,
    manifest: &CacheManifest,
    refresh: bool,
) -> std::result::Result<(), PersistError> {
    let path = dir.join("manifest.json");
    if refresh {
        // A failed wipe must not leave warm entries behind: the refresh
        // exists precisely to force engine reads, so the directory is
        // reported unusable and the run degrades to pass-through engine
        // reads rather than silently replaying stale ones.
        if let Err(err) = std::fs::remove_dir_all(dir) {
            return Err(PersistError::Io {
                path: dir.to_path_buf(),
                source: err,
            });
        }
        return save_json(&path, manifest);
    }
    match load_json::<CacheManifest>(&path) {
        Ok(existing) if existing == *manifest => Ok(()),
        Ok(existing) => {
            warn!(
                expected = ?manifest,
                found = ?existing,
                "cache manifest mismatch — treating the directory as cold"
            );
            let _ = std::fs::remove_dir_all(dir);
            save_json(&path, manifest)
        }
        Err(PersistError::NotFound { .. }) => save_json(&path, manifest),
        Err(err) => {
            warn!(%err, "cache manifest is corrupt — treating the directory as cold");
            let _ = std::fs::remove_dir_all(dir);
            save_json(&path, manifest)
        }
    }
}

// ============================================================
// Surviving-scan readers — the pairing trigger of track P18 (issue #298)
// ============================================================

/// Whether `dir` holds a surviving scan: a hash directory whose manifest
/// names the very hash it is filed under, at the current cache format
/// version, with its function listing still on disk — a document set the
/// pairing pass can read without an engine.
///
/// The three checks are exactly the conditions [`open_manifest`] uses
/// before replaying a directory warm, with one difference: a surviving
/// scan is only read, never opened. A mismatched or corrupt sibling is not
/// wiped — it stands for a different version's bytes, and this run's
/// manifest has no claim on it.
pub fn is_surviving_scan(dir: &Path) -> bool {
    let Some(name) = dir.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    match load_json::<CacheManifest>(&dir.join("manifest.json")) {
        Ok(manifest) => {
            manifest.binary_sha256 == name
                && manifest.format_version == CACHE_FORMAT_VERSION
                && dir.join("functions.json").is_file()
        }
        Err(err) => {
            debug!(path = %dir.display(), %err, "sibling scan directory carries no readable manifest");
            false
        }
    }
}

/// The `functions.json` listing a scan document directory kept, in the scan's
/// own listing order — the order the pairing pass ties on. `None` when the
/// document is missing (an ordinary miss) or corrupt (logged, like every
/// cache read degrades).
pub fn cached_functions(dir: &Path) -> Option<Vec<FunctionSummary>> {
    cached_doc(&doc_path(dir, &CacheKey::Functions))
}

/// The `exports.json` export listing the scan kept, with the same miss
/// rules as [`cached_functions`].
pub fn cached_exports(dir: &Path) -> Option<Vec<Symbol>> {
    cached_doc(&doc_path(dir, &CacheKey::Exports))
}

/// The decompiled body kept for `function` — the engine's raw text, before
/// the noise filter, exactly as write-through stored it (issue #271) — with
/// the same miss rules as [`cached_functions`]. The decompiler names the
/// document through the same [`safe_key`] spelling that wrote it.
pub fn cached_body(dir: &Path, function: &str) -> Option<String> {
    let document = cached_doc::<DecompiledFunction>(&doc_path(
        dir,
        &CacheKey::Decompile(function.to_string()),
    ))?;
    Some(document.body)
}

/// Reads one whole document out of a scan document directory: `None` on a
/// miss, and a corrupt document is logged once, never fatal.
fn cached_doc<T: DeserializeOwned>(path: &Path) -> Option<T> {
    match load_json::<T>(path) {
        Ok(document) => Some(document),
        Err(PersistError::NotFound { .. }) => None,
        Err(err) => {
            warn!(path = %path.display(), %err, "corrupt cached scan document");
            None
        }
    }
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_manifest() -> CacheManifest {
        CacheManifest {
            binary_sha256: "abc".into(),
            format_version: CACHE_FORMAT_VERSION,
            program: "eqmain.dll".into(),
        }
    }

    #[test]
    fn documents_are_filed_per_read_under_the_cache_directory() {
        let root = Path::new("root");
        assert_eq!(
            doc_path(root, &CacheKey::Functions),
            root.join("functions.json")
        );
        assert_eq!(
            doc_path(root, &CacheKey::Decompile("FUN_18003e750".into())),
            root.join("decompile").join("FUN_18003e750.json")
        );
        assert_eq!(
            doc_path(root, &CacheKey::Callers(0x18003e750)),
            root.join("callers").join("18003e750.json"),
            "addresses key documents in bare hex"
        );
        assert_eq!(
            doc_path(root, &CacheKey::Memory(0x1801306f0, 8)),
            root.join("memory").join("1801306f0-8.json"),
            "the length is part of the key: the same address at another length is another read"
        );
        assert_eq!(
            doc_path(root, &CacheKey::DataTypes(None)),
            root.join("data_types").join("all.json")
        );
        assert_eq!(
            doc_path(root, &CacheKey::DataTypes(Some("excpt.h".into()))),
            root.join("data_types").join("excpt.h.json")
        );
    }

    #[test]
    fn the_cache_open_creates_the_ignore_rule_where_no_gitignore_existed() {
        let workspace = tempfile::tempdir().expect("workspace");
        ensure_gitignore(workspace.path());
        let body = std::fs::read_to_string(workspace.path().join(".gitignore"))
            .expect("the cache creates the .gitignore");
        assert_eq!(
            body, "re/cache/\n",
            "the file carries the rule and nothing else"
        );
    }

    #[test]
    fn the_ignore_rule_is_appended_once_and_never_duplicated() {
        let workspace = tempfile::tempdir().expect("workspace");
        let path = workspace.path().join(".gitignore");
        // The workspace's own rules, with no trailing newline to inherit.
        std::fs::write(&path, "src/generated/").expect("existing gitignore");
        ensure_gitignore(workspace.path());
        ensure_gitignore(workspace.path());
        let body = std::fs::read_to_string(&path).expect("the gitignore reads back");
        assert_eq!(
            body, "src/generated/\nre/cache/\n",
            "the first pass appends the missing rule, the second changes nothing"
        );
    }

    #[test]
    fn a_rule_for_a_superseded_cache_name_does_not_stand_in_for_the_current_one() {
        let workspace = tempfile::tempdir().expect("workspace");
        let path = workspace.path().join(".gitignore");
        std::fs::write(&path, "ghidra/\nre/ghidra-cache/\n").expect("bridge-era gitignore");
        ensure_gitignore(workspace.path());
        let body = std::fs::read_to_string(&path).expect("the gitignore reads back");
        assert_eq!(
            body, "ghidra/\nre/ghidra-cache/\nre/cache/\n",
            "the workspace's own rules stay as it wrote them, and the current path is added"
        );
    }

    #[test]
    fn engine_names_stay_verbatim_but_unsafe_names_get_a_hash_suffix() {
        assert_eq!(safe_key("FUN_18003e750"), "FUN_18003e750");
        assert_eq!(safe_key("IMAGE_DOS_HEADER"), "IMAGE_DOS_HEADER");
        assert_eq!(safe_key("excpt.h"), "excpt.h");
        let odd = safe_key("weird/name with spaces");
        assert!(
            odd.starts_with("weird_name_with_spaces-"),
            "sanitized names keep a readable stem: {odd}"
        );
        assert_ne!(
            safe_key("a b"),
            safe_key("a_b"),
            "the suffix prevents collisions"
        );
        assert_ne!(safe_key("."), ".");
        assert_ne!(safe_key(".."), "..");
    }

    #[test]
    fn the_binary_hash_is_sha256_over_the_file_bytes() {
        let dir = tempfile::TempDir::new().expect("temp dir");
        let path = dir.path().join("eqmain.dll");
        std::fs::write(&path, b"abc").expect("binary written");
        assert_eq!(
            sha256_of_file(&path).expect("hashable").as_deref(),
            Some("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
            "the well-known SHA-256 of \"abc\""
        );
        assert_eq!(
            sha256_of_file(&dir.path().join("missing.dll")).expect("missing is not an error"),
            None
        );
    }

    #[test]
    fn a_matching_manifest_leaves_the_warm_documents_alone() {
        let dir = tempfile::TempDir::new().expect("temp dir");
        let cache = dir.path().join("cache");
        let manifest = sample_manifest();
        open_manifest(&cache, &manifest, false).expect("first open writes the manifest");
        save_json(&cache.join("functions.json"), &vec![1u8]).expect("entry written");

        open_manifest(&cache, &manifest, false).expect("matching manifest stays warm");
        assert!(
            cache.join("functions.json").is_file(),
            "warm entries survive"
        );
    }

    #[test]
    fn a_refresh_open_wipes_even_a_matching_manifest() {
        let dir = tempfile::TempDir::new().expect("temp dir");
        let cache = dir.path().join("cache");
        let manifest = sample_manifest();
        open_manifest(&cache, &manifest, false).expect("first open writes the manifest");
        save_json(&cache.join("functions.json"), &vec![1u8]).expect("entry written");

        // The refresh escape hatch (issue #106): a refresh run must wipe and
        // rewrite regardless of what the manifest says.
        open_manifest(&cache, &manifest, true).expect("refresh rewrites the manifest");
        assert!(
            !cache.join("functions.json").is_file(),
            "a refresh goes cold even over a matching manifest"
        );
        assert_eq!(
            load_json::<CacheManifest>(&cache.join("manifest.json")).expect("manifest rewritten"),
            manifest,
            "the refreshed directory still records this run's facts"
        );
    }

    #[test]
    fn a_mismatched_manifest_wipes_the_directory_cold() {
        let dir = tempfile::TempDir::new().expect("temp dir");
        let cache = dir.path().join("cache");
        let manifest = sample_manifest();
        open_manifest(&cache, &manifest, false).expect("first open writes the manifest");
        save_json(&cache.join("functions.json"), &vec![1u8]).expect("entry written");

        for stale in [
            CacheManifest {
                binary_sha256: "changed-bytes".into(),
                ..manifest.clone()
            },
            CacheManifest {
                format_version: manifest.format_version + 1,
                ..manifest.clone()
            },
            CacheManifest {
                program: "other.exe".into(),
                ..manifest.clone()
            },
        ] {
            open_manifest(&cache, &stale, false).expect("mismatch rewrites the manifest");
            assert!(
                !cache.join("functions.json").is_file(),
                "a mismatched directory must not keep entries that could be served stale"
            );
            let written =
                load_json::<CacheManifest>(&cache.join("manifest.json")).expect("new manifest");
            assert_eq!(written, stale, "the directory now records this run's facts");
        }
    }

    #[test]
    fn a_corrupt_manifest_is_replaced_and_the_directory_goes_cold() {
        let dir = tempfile::TempDir::new().expect("temp dir");
        let cache = dir.path().join("cache");
        std::fs::create_dir_all(&cache).expect("cache dir");
        std::fs::write(cache.join("manifest.json"), "{ not json").expect("corrupt manifest");
        std::fs::write(cache.join("functions.json"), "{}").expect("entry written");

        let manifest = sample_manifest();
        open_manifest(&cache, &manifest, false).expect("corrupt manifest is replaced");
        assert!(!cache.join("functions.json").is_file(), "cold means empty");
        assert_eq!(
            load_json::<CacheManifest>(&cache.join("manifest.json")).expect("new manifest"),
            manifest
        );
    }

    #[test]
    fn a_warm_directory_reads_back_as_a_surviving_scan_with_its_documents() {
        // The #298 surface: the same conditions a warm open replays on,
        // and the readers answer the whole documents the write side kept,
        // in the shapes the seam answers.
        let root = tempfile::TempDir::new().expect("temp dir");
        let scan = root.path().join("eqmain.dll").join("abc");
        open_manifest(&scan, &sample_manifest(), false).expect("manifest opened");
        let listing = vec![
            FunctionSummary {
                name: "FUN_18003e750".into(),
                address: 0x18003e750,
            },
            FunctionSummary {
                name: "entry".into(),
                address: 0x180040000,
            },
        ];
        save_json(&doc_path(&scan, &CacheKey::Functions), &listing).expect("listing saved");

        assert!(
            is_surviving_scan(&scan),
            "a manifest naming its own directory, at the current format version, with a listing"
        );
        assert_eq!(
            cached_functions(&scan).expect("the listing reads back"),
            listing,
            "scan order rides through the round trip"
        );
        assert!(
            cached_exports(&scan).is_none(),
            "an absent document is an ordinary miss"
        );
        assert!(
            cached_body(&scan, "FUN_18003e750").is_none(),
            "a body the scan never kept is a miss"
        );

        let body = DecompiledFunction {
            name: "FUN_18003e750".into(),
            signature: "undefined FUN_18003e750(void)".into(),
            body: "  return 1;".into(),
        };
        save_json(
            &doc_path(&scan, &CacheKey::Decompile("FUN_18003e750".into())),
            &body,
        )
        .expect("body saved");
        assert_eq!(
            cached_body(&scan, "FUN_18003e750").as_deref(),
            Some("  return 1;"),
            "the kept body reads back verbatim — the engine's raw text, not the filtered one"
        );

        let exports = vec![Symbol {
            name: "entry".into(),
            address: 0x180040000,
            imported: false,
        }];
        save_json(&doc_path(&scan, &CacheKey::Exports), &exports).expect("exports saved");
        assert_eq!(
            cached_exports(&scan).expect("the export listing reads back"),
            exports
        );
    }

    #[test]
    fn a_sibling_that_is_not_a_surviving_scan_is_refused() {
        let root = tempfile::TempDir::new().expect("temp dir");

        // A renamed directory: the manifest names one version's hash, the
        // directory stands under another's — detected, never trusted.
        let moved = root.path().join("eqmain.dll").join("renamed");
        open_manifest(&moved, &sample_manifest(), false).expect("manifest opened");
        save_json(
            &doc_path(&moved, &CacheKey::Functions),
            &Vec::<FunctionSummary>::new(),
        )
        .expect("listing saved");
        assert!(
            !is_surviving_scan(&moved),
            "a directory whose manifest disagrees with its name is not a surviving scan"
        );

        // A superseded format version: its documents are never read back,
        // exactly as a warm open refuses to replay them.
        let stale = root.path().join("eqmain.dll").join("stale-v3");
        let outdated = CacheManifest {
            format_version: CACHE_FORMAT_VERSION - 1,
            ..sample_manifest()
        };
        save_json(&stale.join("manifest.json"), &outdated).expect("stale manifest filed");
        save_json(
            &doc_path(&stale, &CacheKey::Functions),
            &Vec::<FunctionSummary>::new(),
        )
        .expect("listing saved");
        assert!(
            !is_surviving_scan(&stale),
            "an old cache-format version's scan is not a surviving scan"
        );

        // A cold directory this run only minted: a manifest and nothing else.
        let cold = root.path().join("eqmain.dll").join("abc");
        open_manifest(&cold, &sample_manifest(), false).expect("cold open writes the manifest");
        assert!(
            !is_surviving_scan(&cold),
            "a manifest without a scan listing is not a scan"
        );
    }
}
