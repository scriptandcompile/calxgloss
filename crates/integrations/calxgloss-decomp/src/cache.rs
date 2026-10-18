//! The two-tier read-through cache for engine reads (issue #103).
//!
//! [`CachedScanSource`] wraps a [`KunaSource`] and implements the shared
//! [`ScanSource`] seam, so every evidence engine pulls its program facts
//! through the cache without knowing it exists. Reads resolve in three
//! tiers: an in-memory memo first, then JSON documents on disk under the
//! record of effort, then the engine — and every engine result is written
//! through to disk immediately, so an interrupted run leaves a valid partial
//! cache and a second run over the same bytes replays with zero engine calls.
//!
//! **Validity is the key.** The disk tier lives at
//! `re/decomp-cache/{binary identity}/{sha256}/`, where the hash is SHA-256
//! over the target binary's file bytes. Changed bytes mean a different
//! directory, so staleness needs no invalidation logic; old hash directories
//! are kept (for switching back to a previous build) until pruned by hand.
//! A `manifest.json` in the directory records the binary hash, the cache
//! format version, and the program name as the engine named it — a mismatch
//! on any field (or a corrupt manifest) treats the directory as cold: it is
//! wiped and rewritten, so a stale entry is never served. The format version
//! went to 2 when Kuna became the only engine (issue #214): documents
//! written by the retired Ghidra bridge are never replayed under Kuna. (The
//! directory keeps its historical name; the rename is recorded as a deferral
//! in ADR-0041.) It went to 3 when the function listing dropped the engine's
//! import pointer slots: a v2 `functions` document still names every IAT
//! slot, and a consumer that decompiles each listed name then spends one
//! read per import on an entry the engine refuses.
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
//! **What is never cached:** write-side calls (function tags, type
//! write-back) never go through the cache, and `begin_pass`/`end_pass`
//! heartbeat control passes through to the wrapped engine. The heartbeat
//! counts *work items consumed*, not engine round trips: a cached decompile
//! beats through the wrapped engine's heartbeat just like a live one, so a
//! warm run's progress line keeps moving (issue #121). Concurrent misses of
//! one key share a single engine request.

use crate::error::{EngineError, Result};
use crate::model::{
    DataItem, DataTypeEntry, DecompiledFunction, EnumDefinition, FunctionSummary, StringLiteral,
    StructLayout, Symbol, Xref,
};
use crate::scan_source::ScanSource;
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
use tracing::warn;

/// Cache-format version, recorded in every manifest. Bump when a cached
/// document's shape changes: every existing directory then reads as cold
/// instead of serving records the new readers cannot interpret. Version 2
/// marks the Kuna-only engine (issue #214): the Ghidra bridge's documents
/// are never replayed under a different engine's decompiler. Version 3 marks
/// the function listing without import pointer slots — a v2 listing names
/// each IAT slot, and no `decompile` of one can succeed.
const CACHE_FORMAT_VERSION: u32 = 3;

/// The `manifest.json` beside a directory's cached documents. All three
/// fields must match this run's facts for the directory to be warm; the
/// binary hash duplicates the directory name on purpose, so a renamed or
/// moved directory is detected rather than trusted.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct CacheManifest {
    /// SHA-256 (hex) of the target binary's file bytes.
    binary_sha256: String,
    /// The [`CACHE_FORMAT_VERSION`] this directory was written under.
    format_version: u32,
    /// The program name as the engine named it.
    program: String,
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
    /// `re/decomp-cache/{identity}/{sha256}` — `None` when the binary file
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
                let dir = cache_root(workspace).join(binary.as_str()).join(&hash);
                let manifest = CacheManifest {
                    binary_sha256: hash,
                    format_version: CACHE_FORMAT_VERSION,
                    program,
                };
                match open_manifest(&dir, &manifest, refresh) {
                    Ok(()) => Some(dir),
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
        let (body, from_cache) = self
            .cached_hit(CacheKey::Decompile(name.to_string()), || {
                ScanSource::decompile(&self.inner.source, name)
            })
            .await?;
        if from_cache {
            // The engine path beats inside the source's decompile; a cached
            // body never gets there, so count the consumed work item here
            // (issue #121 — the dashboard's per-binary activity line).
            self.inner.source.tick(name);
        }
        Ok(body)
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
}

// ============================================================
// Disk layout
// ============================================================

/// The cache convention: `{workspace}/re/decomp-cache`.
///
/// The directory was `re/ghidra-cache` until ADR-0042 renamed it; the cache
///-format version marker inside it invalidates anything the old name held.
fn cache_root(workspace: impl AsRef<Path>) -> PathBuf {
    workspace.as_ref().join("re").join("decomp-cache")
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
pub(crate) fn sha256_of_file(path: &Path) -> std::io::Result<Option<String>> {
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
}
