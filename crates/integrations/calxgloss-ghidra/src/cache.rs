//! The two-tier read-through cache for Ghidra reads (issue #103).
//!
//! [`CachedGhidraSource`] wraps a [`GhidraClient`] and implements the shared
//! [`ScanSource`] seam, so every evidence engine pulls its program facts
//! through the cache without knowing it exists. Reads resolve in three tiers:
//! an in-memory memo first, then JSON documents on disk under the record of
//! effort, then the live client — and every live result is written through to
//! disk immediately, so an interrupted run leaves a valid partial cache and a
//! second run over the same bytes replays with zero live calls.
//!
//! **Validity is the key.** The disk tier lives at
//! `re/ghidra-cache/{binary identity}/{sha256}/`, where the hash is SHA-256
//! over the target binary's file bytes. Changed bytes mean a different
//! directory, so staleness needs no invalidation logic; old hash directories
//! are kept (for switching back to a previous build) until pruned by hand.
//! A `manifest.json` in the directory records the binary hash, the cache
//! format version, and the Ghidra program name from the server's probe — a
//! mismatch on any field (or a corrupt manifest) treats the directory as
//! cold: it is wiped and rewritten, so a stale entry is never served.
//!
//! **Forcing a cold cache:** delete the cache directory (or the binary's
//! whole identity directory). The bridge reports no Ghidra version, so a
//! re-analysis *inside* Ghidra over unchanged bytes cannot be detected —
//! clearing the directory is the documented way to honor one. Bumping
//! [`CACHE_FORMAT_VERSION`] invalidates every cache at once when the
//! record shape changes.
//!
//! **Degradation, never failure:** a missing or unreadable binary file drops
//! the disk tier entirely and reads pass straight through to the client; a
//! corrupt cache document is logged and refetched live; a failed cache write
//! is logged and the read still succeeds. Only the live fetch's own errors
//! reach the caller.
//!
//! **What is never cached:** write-side calls (function tags, type
//! write-back) delegate straight through, and `begin_pass`/`end_pass`
//! heartbeat control passes through to the wrapped client — beats then
//! reflect cache misses, which is the correct progress semantics for a warm
//! run. Concurrent misses of one key share a single live request.

use crate::client::{GhidraClient, GhidraError, Result};
use crate::model::{
    DataItem, DataTypeEntry, DecompiledFunction, EnumDefinition, FunctionSummary, StringLiteral,
    StructLayout, Symbol, Xref,
};
use crate::scan_source::ScanSource;
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
use std::sync::{Arc, Mutex};
use tokio::sync::OnceCell;
use tracing::warn;

/// Cache-format version, recorded in every manifest. Bump when a cached
/// document's shape changes: every existing directory then reads as cold
/// instead of serving records the new readers cannot interpret.
const CACHE_FORMAT_VERSION: u32 = 1;

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
    /// The Ghidra program name as the server's probe reported it.
    program: String,
}

/// One cached read, identifying both its endpoint and its argument.
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

/// A cached view of one Ghidra program, safe to clone and hand to every
/// engine in a batch.
///
/// See the [module docs](crate::cache) for the tiers, the validity key, and
/// the degradation rules. The instance is scoped to one target binary: the
/// memo and the disk directory can never serve one program's data for
/// another.
#[derive(Debug, Clone)]
pub struct CachedGhidraSource {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    client: GhidraClient,
    /// `re/ghidra-cache/{identity}/{sha256}` — `None` when the binary file
    /// was missing or unreadable, which drops the disk tier and leaves
    /// pass-through live reads.
    cache_dir: Option<PathBuf>,
    /// In-memory tier: one shared cell per key. The cell fills on the first
    /// miss (disk or live), and concurrent misses of the same key await the
    /// one in-flight fill instead of stampeding the server.
    memo: Mutex<HashMap<CacheKey, Arc<OnceCell<Value>>>>,
}

impl CachedGhidraSource {
    /// Wrap `client` with a cache for the binary `binary_path`, filed under
    /// the workspace's record of effort.
    ///
    /// The binary's file bytes are hashed once here, and the server is
    /// probed once for the program name the manifest records. A missing or
    /// unreadable `binary_path` is not an error: the source degrades to
    /// pass-through live reads (in-memory memo only, no disk tier).
    ///
    /// # Errors
    ///
    /// Returns the probe's [`GhidraError`] if the server is unreachable or
    /// no program is open — the same failure a live read would hit.
    pub async fn new(
        client: GhidraClient,
        workspace: impl AsRef<Path>,
        binary: impl Into<BinaryIdentity>,
        binary_path: impl AsRef<Path>,
    ) -> Result<Self> {
        let binary = binary.into();
        let binary_path = binary_path.as_ref();
        let cache_dir = match sha256_of_file(binary_path) {
            Ok(None) => {
                warn!(
                    binary = %binary,
                    path = %binary_path.display(),
                    "target binary file is missing — Ghidra reads pass through uncached"
                );
                None
            }
            Ok(Some(hash)) => {
                let program = client.probe().await?.program;
                let dir = cache_root(workspace).join(binary.as_str()).join(&hash);
                let manifest = CacheManifest {
                    binary_sha256: hash,
                    format_version: CACHE_FORMAT_VERSION,
                    program,
                };
                match open_manifest(&dir, &manifest) {
                    Ok(()) => Some(dir),
                    Err(err) => {
                        warn!(
                            %err,
                            "Ghidra cache directory is unusable — reads pass through uncached"
                        );
                        None
                    }
                }
            }
            Err(err) => {
                warn!(
                    %err,
                    path = %binary_path.display(),
                    "could not read the target binary — Ghidra reads pass through uncached"
                );
                None
            }
        };
        Ok(Self {
            inner: Arc::new(Inner {
                client,
                cache_dir,
                memo: Mutex::new(HashMap::new()),
            }),
        })
    }

    /// The directory this instance's documents are filed under, or `None`
    /// when the disk tier is off (missing binary, unusable directory).
    pub fn cache_dir(&self) -> Option<&Path> {
        self.inner.cache_dir.as_deref()
    }

    // =========================================================
    // Write-side and heartbeat pass-throughs — never cached
    // =========================================================

    /// Attach `tag` to a function, delegating straight to the client.
    ///
    /// Writes are facts about what the caller *did*, not read-only program
    /// facts, so they are never served from or stored in the cache.
    pub async fn add_function_tag(&self, function: &str, tag: &str) -> Result<()> {
        self.inner.client.add_function_tag(function, tag).await
    }

    /// Arm the wrapped client's heartbeat for one analysis pass.
    ///
    /// Beats fire on live decompiles the client completes, so a warm run
    /// beats only on cache misses — correct progress semantics, fewer
    /// "work done" counts, as the spec expects.
    pub fn begin_pass(&self, binary: &str, pass: &str, events: &TranslationEvents) {
        self.inner.client.begin_pass(binary, pass, events);
    }

    /// Disarm the wrapped client's heartbeat.
    pub fn end_pass(&self) {
        self.inner.client.end_pass();
    }

    // =========================================================
    // The read path: memo → disk → live, writing through
    // =========================================================

    /// Resolve `key` through the three tiers, storing the live answer in
    /// both. The memo cell is shared per key, so concurrent misses of one
    /// key fire exactly one live request.
    async fn cached<T, Fut>(&self, key: CacheKey, live: impl FnOnce() -> Fut + Send) -> Result<T>
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
        let value = cell
            .get_or_try_init(|| async {
                if let Some(disk) = self.read_disk(&key) {
                    // A document that parses as JSON but not as this
                    // endpoint's record is corrupt for our purposes.
                    if serde_json::from_value::<T>(disk.clone()).is_ok() {
                        return Ok::<Value, GhidraError>(disk);
                    }
                    warn!(
                        ?key,
                        "Ghidra cache document does not match its endpoint — refetching live"
                    );
                }
                let value =
                    serde_json::to_value(live().await?).map_err(|err| GhidraError::Malformed {
                        kind: "a cache document",
                        detail: err.to_string(),
                    })?;
                self.write_disk(&key, &value);
                Ok(value)
            })
            .await?;
        serde_json::from_value(value.clone()).map_err(|err| GhidraError::Malformed {
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
                warn!(%err, "corrupt Ghidra cache document — refetching live");
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
                warn!(%err, "could not write Ghidra cache document — continuing without it");
            }
        }
    }
}

impl ScanSource for CachedGhidraSource {
    async fn functions(&self) -> Result<Vec<FunctionSummary>> {
        self.cached(CacheKey::Functions, || self.inner.client.list_functions())
            .await
    }

    async fn decompile(&self, name: &str) -> Result<DecompiledFunction> {
        self.cached(CacheKey::Decompile(name.to_string()), || {
            self.inner.client.decompile_function_by_name(name)
        })
        .await
    }

    async fn strings(&self) -> Result<Vec<StringLiteral>> {
        self.cached(CacheKey::Strings, || self.inner.client.list_strings(None))
            .await
    }

    async fn callers(&self, address: u64) -> Result<Vec<String>> {
        self.cached(CacheKey::Callers(address), || {
            self.inner.client.callers(address)
        })
        .await
    }

    async fn xrefs_to(&self, address: u64) -> Result<Vec<Xref>> {
        self.cached(CacheKey::XrefsTo(address), || {
            self.inner.client.xrefs_to(address, None)
        })
        .await
    }

    async fn data_types(&self, category: Option<&str>) -> Result<Vec<DataTypeEntry>> {
        let category = category.map(str::to_string);
        self.cached(CacheKey::DataTypes(category.clone()), || {
            self.inner.client.list_data_types(category.as_deref())
        })
        .await
    }

    async fn struct_layout(&self, name: &str) -> Result<StructLayout> {
        self.cached(CacheKey::StructLayout(name.to_string()), || {
            self.inner.client.get_struct_layout(name)
        })
        .await
    }

    async fn enum_values(&self, name: &str) -> Result<EnumDefinition> {
        self.cached(CacheKey::EnumValues(name.to_string()), || {
            self.inner.client.get_enum_values(name)
        })
        .await
    }

    async fn data_items(&self) -> Result<Vec<DataItem>> {
        self.cached(CacheKey::DataItems, || self.inner.client.list_data_items())
            .await
    }

    async fn imports(&self) -> Result<Vec<Symbol>> {
        self.cached(CacheKey::Imports, || self.inner.client.imports(None))
            .await
    }

    async fn exports(&self) -> Result<Vec<Symbol>> {
        self.cached(CacheKey::Exports, || self.inner.client.exports(None))
            .await
    }

    async fn image_base(&self) -> Result<u64> {
        self.cached(CacheKey::ImageBase, || self.inner.client.image_base())
            .await
    }

    async fn read_memory(&self, address: u64, length: usize) -> Result<Vec<u8>> {
        self.cached(CacheKey::Memory(address, length), || {
            self.inner.client.read_memory(address, length)
        })
        .await
    }
}

// ============================================================
// Disk layout
// ============================================================

/// The cache convention: `{workspace}/re/ghidra-cache`.
fn cache_root(workspace: impl AsRef<Path>) -> PathBuf {
    workspace.as_ref().join("re").join("ghidra-cache")
}

/// Where one key's document is filed inside a hash directory: whole-program
/// listings at the top level, per-item documents under per-endpoint
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
/// Names Ghidra generates are already safe and stay verbatim, so the
/// documents stay hand-inspectable; anything else is sanitized with a hash
/// suffix so two different names can never collide on one document.
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
fn sha256_of_file(path: &Path) -> std::io::Result<Option<String>> {
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
fn open_manifest(dir: &Path, manifest: &CacheManifest) -> std::result::Result<(), PersistError> {
    let path = dir.join("manifest.json");
    match load_json::<CacheManifest>(&path) {
        Ok(existing) if existing == *manifest => Ok(()),
        Ok(existing) => {
            warn!(
                expected = ?manifest,
                found = ?existing,
                "Ghidra cache manifest mismatch — treating the directory as cold"
            );
            let _ = std::fs::remove_dir_all(dir);
            save_json(&path, manifest)
        }
        Err(PersistError::NotFound { .. }) => save_json(&path, manifest),
        Err(err) => {
            warn!(%err, "Ghidra cache manifest is corrupt — treating the directory as cold");
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
    fn documents_are_filed_per_endpoint_under_the_cache_directory() {
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
            "addresses key documents in bare hex, as the bridge itself writes them"
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
    fn ghidra_names_stay_verbatim_but_unsafe_names_get_a_hash_suffix() {
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
        open_manifest(&cache, &manifest).expect("first open writes the manifest");
        save_json(&cache.join("functions.json"), &vec![1u8]).expect("entry written");

        open_manifest(&cache, &manifest).expect("matching manifest stays warm");
        assert!(
            cache.join("functions.json").is_file(),
            "warm entries survive"
        );
    }

    #[test]
    fn a_mismatched_manifest_wipes_the_directory_cold() {
        let dir = tempfile::TempDir::new().expect("temp dir");
        let cache = dir.path().join("cache");
        let manifest = sample_manifest();
        open_manifest(&cache, &manifest).expect("first open writes the manifest");
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
            open_manifest(&cache, &stale).expect("mismatch rewrites the manifest");
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
        open_manifest(&cache, &manifest).expect("corrupt manifest is replaced");
        assert!(!cache.join("functions.json").is_file(), "cold means empty");
        assert_eq!(
            load_json::<CacheManifest>(&cache.join("manifest.json")).expect("new manifest"),
            manifest
        );
    }
}
