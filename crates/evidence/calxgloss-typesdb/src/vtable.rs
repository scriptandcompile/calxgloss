//! Vtable detection.
//!
//! [`VtableDetector`] with `detect_vtables()` scans paged `list_data_items`
//! output for vtable-shaped data objects — `vftable`-named items preceded by
//! `vftable_meta_ptr` entries (the MSVC RTTI pattern), keyed by address since
//! `vftable` names are not unique. It reads each table's bytes through
//! `read_memory` to resolve method pointers to names and addresses, follows
//! the RTTI chain (metadata pointer → CompleteObjectLocator → TypeDescriptor
//! and ClassHierarchyDescriptor) to recover the owning class and track
//! base-class inheritance, recognizes COM interfaces via the
//! QueryInterface/AddRef/Release pattern, and tags the methods of confirmed
//! vtables with `add_function_tag`.

use crate::error::{Result, TypesDbError};
use crate::types::{Vtable, VtableMethod};
use calxgloss_ghidra::{DataItem, FunctionSummary, GhidraClient, GhidraError};
use std::collections::{HashMap, HashSet};
use tracing::{debug, info, warn};

/// The reads a vtable scan performs.
///
/// [`GhidraClient`] implements it directly; tests implement it over canned
/// responses so the detection, RTTI-walking, and degradation logic runs
/// without a server. The futures are `Send` so a scan can be driven from an
/// orchestrating task.
pub trait VtableSource {
    /// Every defined data object in the listing, collected across pages.
    fn data_items(&self) -> impl std::future::Future<Output = Result<Vec<DataItem>>> + Send;

    /// Every function in the program, for naming method pointers.
    fn functions(&self) -> impl std::future::Future<Output = Result<Vec<FunctionSummary>>> + Send;

    /// The base address the program is loaded at, for resolving RTTI RVAs.
    fn image_base(&self) -> impl std::future::Future<Output = Result<u64>> + Send;

    /// The raw bytes at `address`.
    fn read_memory(
        &self,
        address: u64,
        length: usize,
    ) -> impl std::future::Future<Output = Result<Vec<u8>>> + Send;

    /// Attach `tag` to the function at `address`.
    fn add_function_tag(
        &self,
        address: u64,
        tag: &str,
    ) -> impl std::future::Future<Output = Result<()>> + Send;
}

impl VtableSource for GhidraClient {
    async fn data_items(&self) -> Result<Vec<DataItem>> {
        Ok(self.list_data_items().await?)
    }

    async fn functions(&self) -> Result<Vec<FunctionSummary>> {
        Ok(self.list_functions().await?)
    }

    async fn image_base(&self) -> Result<u64> {
        Ok(self.image_base().await?)
    }

    async fn read_memory(&self, address: u64, length: usize) -> Result<Vec<u8>> {
        Ok(self.read_memory(address, length).await?)
    }

    async fn add_function_tag(&self, address: u64, tag: &str) -> Result<()> {
        Ok(self.add_function_tag(&format!("{address:x}"), tag).await?)
    }
}

// ============================================================
// MSVC RTTI shapes
// ============================================================

/// Ghidra's label for an MSVC vtable.
const VTABLE_LABEL: &str = "vftable";

/// Ghidra's label for the RTTI metadata pointer that precedes each vtable.
const META_PTR_LABEL: &str = "vftable_meta_ptr";

/// The tag attached to the methods of confirmed vtables.
const DEFAULT_TAG: &str = "vtable-method";

/// Size of a CompleteObjectLocator: signature, displacement, cdOffset, and
/// the TypeDescriptor and ClassHierarchyDescriptor RVAs.
const COL_SIZE: usize = 20;

/// A CompleteObjectLocator's signature for a normal (1) or virtual (2)
/// inheritance relationship. Anything else is not a locator.
const COL_SIGNATURES: [u32; 2] = [1, 2];

/// Bytes a TypeDescriptor reserves before its mangled name: a vftable pointer
/// and a spare, each pointer-sized.
const fn td_header(pointer_size: usize) -> usize {
    2 * pointer_size
}

/// How much of a TypeDescriptor name to read past its header.
const TD_NAME_LEN: usize = 96;

/// Size of a ClassHierarchyDescriptor: signature, attributes, base-class
/// count, and the BaseClassArray RVA.
const CHD_SIZE: usize = 16;

/// Size of a BaseClassDescriptor: count, the PMD triple, the TypeDescriptor
/// RVA, and attributes.
const fn bcd_size(pointer_size: usize) -> usize {
    16 + 2 * pointer_size
}

/// Offset of a BaseClassDescriptor's TypeDescriptor RVA.
const fn bcd_type_descriptor(pointer_size: usize) -> usize {
    8 + 2 * pointer_size
}

/// A sanity cap on base-class counts; a larger count means the descriptor
/// was misread, not that the class has that many bases.
const MAX_BASE_CLASSES: usize = 64;

/// The method names that open every COM interface, in slot order.
const COM_PREFIX: [&str; 3] = ["queryinterface", "addref", "release"];

// ============================================================
// Detection helpers
// ============================================================

/// Whether a defined data item is a vtable.
///
/// Ghidra's MSVC analysis names every vtable `vftable`; other defined data —
/// jump tables, plain pointer arrays — carries different labels and is not a
/// vtable no matter how pointer-shaped it looks.
fn is_vtable_candidate(item: &DataItem) -> bool {
    item.label.eq_ignore_ascii_case(VTABLE_LABEL)
}

/// The declared element count of a `pointer[N]` type name.
fn pointer_array_count(type_name: &str) -> Option<u64> {
    let count = type_name.strip_suffix(']')?.strip_prefix("pointer[")?;
    count.parse().ok()
}

/// Read `width` bytes at the start of `bytes` as a little-endian integer.
fn read_uint_le(bytes: &[u8], width: usize) -> Option<u64> {
    let width = width.min(8);
    if bytes.len() < width {
        return None;
    }
    let mut value = 0u64;
    for (i, byte) in bytes[..width].iter().enumerate() {
        value |= (*byte as u64) << (8 * i);
    }
    Some(value)
}

/// Read a little-endian u32 at `at`, or 0 when the read came up short. A
/// short read yields an unusable RVA, which the next probe refuses rather
/// than following.
fn u32_le(bytes: &[u8], at: usize) -> u32 {
    bytes
        .get(at..at + 4)
        .and_then(|w| <[u8; 4]>::try_from(w).ok())
        .map(u32::from_le_bytes)
        .unwrap_or(0)
}

/// Demangle an MSVC RTTI TypeDescriptor name (`.?AVWidget@@`) to readable
/// form (`Widget`, `Namespace::Widget`).
///
/// The qualified name is written innermost-first (`Class@Namespace`), so the
/// segments are reversed for display. Anything that is not a class (`.?AV`)
/// or structure (`.?AU`) descriptor name is refused.
fn demangle_rtti_name(raw: &str) -> Option<String> {
    let core = raw
        .strip_prefix(".?AV")
        .or_else(|| raw.strip_prefix(".?AU"))?
        .strip_suffix("@@")?;
    let segments: Vec<&str> = core.split('@').filter(|s| !s.is_empty()).collect();
    if segments.is_empty() {
        return None;
    }
    Some(segments.into_iter().rev().collect::<Vec<_>>().join("::"))
}

/// Whether the leading method slots spell the COM `IUnknown` prefix.
fn looks_like_com_interface(methods: &[VtableMethod]) -> bool {
    COM_PREFIX.iter().enumerate().all(|(slot, signature)| {
        methods
            .get(slot)
            .and_then(|m| m.name.as_deref())
            .is_some_and(|name| name.to_ascii_lowercase().contains(signature))
    })
}

/// Whether an error means "nothing readable at that address" rather than
/// "the server could not answer".
///
/// A bad RTTI pointer produces `NotFound`/`Malformed` refusals from
/// `read_memory`, which degrade one vtable's class information. Anything
/// else — transport, a reported server failure — is a broken scan.
fn is_read_miss(error: &TypesDbError) -> bool {
    matches!(
        error,
        TypesDbError::Ghidra(GhidraError::NotFound { .. } | GhidraError::Malformed { .. })
    )
}

/// The class information an RTTI chain resolves.
#[derive(Debug, Default)]
struct Rtti {
    class_name: Option<String>,
    base_classes: Vec<String>,
}

// ============================================================
// Detector
// ============================================================

/// Vtable detection over the program's defined data.
///
/// The detector is generic over [`VtableSource`] so tests can drive it with
/// canned responses; [`new`](Self::new) builds one over a live
/// [`GhidraClient`].
#[derive(Debug, Clone)]
pub struct VtableDetector<S = GhidraClient> {
    source: S,
    pointer_size: usize,
    tag: Option<String>,
}

impl VtableDetector<GhidraClient> {
    /// A detector over a live GhidraMCP client.
    pub fn new(client: &GhidraClient) -> VtableDetector<GhidraClient> {
        Self::with_source(client.clone())
    }
}

impl<S> VtableDetector<S> {
    /// A detector over any source that can read the listing and memory.
    pub fn with_source(source: S) -> Self {
        Self {
            source,
            pointer_size: 8,
            tag: Some(DEFAULT_TAG.to_string()),
        }
    }

    /// Override the pointer size assumed for tables whose type name does not
    /// declare one (a 32-bit program uses 4).
    pub fn with_pointer_size(mut self, pointer_size: usize) -> Self {
        self.pointer_size = pointer_size.max(1);
        self
    }

    /// Tag confirmed vtable methods with `tag` instead of the default.
    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tag = Some(tag.into());
        self
    }

    /// Detect without writing anything back to the program.
    pub fn without_tagging(mut self) -> Self {
        self.tag = None;
        self
    }

    /// Detect every vtable the listing holds, sorted by address.
    ///
    /// A table paired with a preceding `vftable_meta_ptr` entry is confirmed
    /// by the RTTI pattern, and its class name, base classes, and method tags
    /// are recovered from there. A table whose RTTI chain misses is still
    /// reported at method-pointer fidelity — a vtable known to exist without
    /// its class is worth keeping. A failure of the listing itself aborts the
    /// whole scan, because every later table would hit it too.
    pub async fn detect_vtables(&self) -> Result<Vec<Vtable>>
    where
        S: VtableSource,
    {
        let items = self.source.data_items().await?;
        let candidates: Vec<&DataItem> = items.iter().filter(|i| is_vtable_candidate(i)).collect();
        if candidates.is_empty() {
            info!("No vtable-shaped data objects in the listing");
            return Ok(Vec::new());
        }
        debug!(count = candidates.len(), "Found vtable-shaped items");

        let by_address: HashMap<u64, &DataItem> = items.iter().map(|i| (i.address, i)).collect();
        let names: HashMap<u64, String> = self
            .source
            .functions()
            .await?
            .into_iter()
            .map(|f| (f.address, f.name))
            .collect();
        let image_base = self.source.image_base().await?;

        let mut vtables = Vec::new();
        let mut tagged = HashSet::new();
        for item in candidates {
            let element = self.element_size(item);
            let meta = meta_pointer(item, element, &by_address);
            let methods = self.read_methods(item, element, &names).await?;
            let rtti = match meta {
                Some(meta) => self.read_rtti(meta, image_base).await?,
                None => Rtti::default(),
            };
            if let (Some(tag), Some(_)) = (&self.tag, meta) {
                self.tag_methods(&methods, tag, &mut tagged).await;
            }
            let is_com = looks_like_com_interface(&methods);
            vtables.push(Vtable {
                address: item.address,
                label: item.label.clone(),
                size: item.length,
                meta_ptr_address: meta.map(|m| m.address),
                methods,
                class_name: rtti.class_name,
                base_classes: rtti.base_classes,
                is_com_interface: is_com,
            });
        }
        vtables.sort_by_key(|v| v.address);
        info!(
            count = vtables.len(),
            confirmed = vtables.iter().filter(|v| v.is_confirmed()).count(),
            "Detected vtables"
        );
        Ok(vtables)
    }

    /// The size of one table entry.
    ///
    /// Ghidra types vftables `pointer[N]`, so the declared count divides the
    /// item length into exact element sizes; a table typed otherwise falls
    /// back to the configured pointer size.
    fn element_size(&self, item: &DataItem) -> usize {
        if let Some(count) = pointer_array_count(&item.type_name)
            && count > 0
            && item.length >= count
        {
            return (item.length / count) as usize;
        }
        self.pointer_size
    }

    /// The method slots of one table, read from its bytes.
    ///
    /// Each entry is a pointer to the method's function; names come from the
    /// function listing, and a pointer landing outside any known function is
    /// reported with its address only. A table whose bytes cannot be read is
    /// reported with no methods.
    async fn read_methods(
        &self,
        item: &DataItem,
        element: usize,
        names: &HashMap<u64, String>,
    ) -> Result<Vec<VtableMethod>>
    where
        S: VtableSource,
    {
        let bytes = match self
            .source
            .read_memory(item.address, item.length as usize)
            .await
        {
            Ok(bytes) => bytes,
            Err(miss) if is_read_miss(&miss) => {
                debug!(
                    address = format_args!("{:#x}", item.address),
                    "Could not read vtable contents"
                );
                return Ok(Vec::new());
            }
            Err(e) => return Err(e),
        };
        Ok(bytes
            .chunks_exact(element)
            .enumerate()
            .filter_map(|(slot, entry)| {
                let address = read_uint_le(entry, element)?;
                Some(VtableMethod {
                    slot,
                    address,
                    name: names.get(&address).cloned(),
                })
            })
            .collect())
    }

    /// One `read_memory` that treats a refusal as a miss rather than a
    /// failure: the RTTI chain is enrichment, and a bad pointer degrades the
    /// one vtable that followed it.
    async fn probe_read(&self, address: u64, length: usize) -> Result<Option<Vec<u8>>>
    where
        S: VtableSource,
    {
        match self.source.read_memory(address, length).await {
            Ok(bytes) => Ok(Some(bytes)),
            Err(miss) if is_read_miss(&miss) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Walk one vtable's RTTI chain: metadata pointer → CompleteObjectLocator
    /// → TypeDescriptor (the class name) and ClassHierarchyDescriptor (its
    /// bases). Every step degrades to what the earlier steps established.
    async fn read_rtti(&self, meta: &DataItem, image_base: u64) -> Result<Rtti>
    where
        S: VtableSource,
    {
        let mut rtti = Rtti::default();
        let Some(col_address) = self
            .probe_read(meta.address, meta.length as usize)
            .await?
            .and_then(|bytes| read_uint_le(&bytes, meta.length as usize))
        else {
            return Ok(rtti);
        };
        let Some(col) = self.probe_read(col_address, COL_SIZE).await? else {
            return Ok(rtti);
        };
        if !COL_SIGNATURES.contains(&u32_le(&col, 0)) {
            return Ok(rtti);
        }
        rtti.class_name = self
            .read_type_descriptor(self.resolve_rva(u32_le(&col, 12), image_base))
            .await?;
        rtti.base_classes = self
            .read_base_classes(self.resolve_rva(u32_le(&col, 16), image_base), image_base)
            .await?;
        Ok(rtti)
    }

    /// The base classes listed by a ClassHierarchyDescriptor.
    async fn read_base_classes(&self, chd: u64, image_base: u64) -> Result<Vec<String>>
    where
        S: VtableSource,
    {
        let Some(header) = self.probe_read(chd, CHD_SIZE).await? else {
            return Ok(Vec::new());
        };
        let count = u32_le(&header, 8) as usize;
        if count == 0 || count > MAX_BASE_CLASSES {
            return Ok(Vec::new());
        }
        let Some(array) = self
            .probe_read(self.resolve_rva(u32_le(&header, 12), image_base), count * 4)
            .await?
        else {
            return Ok(Vec::new());
        };
        let mut names = Vec::new();
        for i in 0..count {
            let descriptor = self.resolve_rva(u32_le(&array, i * 4), image_base);
            let Some(bcd) = self
                .probe_read(descriptor, bcd_size(self.pointer_size))
                .await?
            else {
                continue;
            };
            let type_descriptor = self.resolve_rva(
                u32_le(&bcd, bcd_type_descriptor(self.pointer_size)),
                image_base,
            );
            if let Some(name) = self.read_type_descriptor(type_descriptor).await? {
                names.push(name);
            }
        }
        Ok(names)
    }

    /// The demangled name from a TypeDescriptor, refusing anything that is
    /// not an MSVC class or structure descriptor.
    async fn read_type_descriptor(&self, address: u64) -> Result<Option<String>>
    where
        S: VtableSource,
    {
        let header = td_header(self.pointer_size);
        let Some(bytes) = self.probe_read(address, header + TD_NAME_LEN).await? else {
            return Ok(None);
        };
        if bytes.len() <= header {
            return Ok(None);
        }
        let name = &bytes[header..];
        let end = name.iter().position(|b| *b == 0).unwrap_or(name.len());
        Ok(std::str::from_utf8(&name[..end])
            .ok()
            .and_then(demangle_rtti_name))
    }

    /// Tag the resolved methods of a confirmed vtable.
    ///
    /// Tagging is enrichment, not detection: a method that refuses a tag
    /// (a pointer into a thunk, say) is warned about and the scan continues.
    /// Each function is tagged once however many vtables dispatch to it.
    async fn tag_methods(&self, methods: &[VtableMethod], tag: &str, tagged: &mut HashSet<u64>)
    where
        S: VtableSource,
    {
        for method in methods.iter().filter(|m| m.name.is_some()) {
            if !tagged.insert(method.address) {
                continue;
            }
            if let Err(e) = self.source.add_function_tag(method.address, tag).await {
                warn!(
                    address = format_args!("{:#x}", method.address),
                    error = %e,
                    "Could not tag vtable method; continuing without it"
                );
            }
        }
    }

    /// Resolve an RTTI RVA to a virtual address.
    ///
    /// The x64 RTTI structures store RVAs relative to the image base; a
    /// 32-bit program stores direct virtual addresses instead.
    fn resolve_rva(&self, value: u32, image_base: u64) -> u64 {
        if self.pointer_size == 8 {
            image_base + value as u64
        } else {
            value as u64
        }
    }
}

/// The `vftable_meta_ptr` item immediately preceding a vtable, when one is
/// defined there — the RTTI confirmation.
fn meta_pointer<'a>(
    item: &DataItem,
    element: usize,
    by_address: &HashMap<u64, &'a DataItem>,
) -> Option<&'a DataItem> {
    let meta = by_address.get(&(item.address.checked_sub(element as u64)?))?;
    meta.label
        .eq_ignore_ascii_case(META_PTR_LABEL)
        .then_some(*meta)
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    fn le32(value: u32) -> Vec<u8> {
        value.to_le_bytes().to_vec()
    }

    fn le64(value: u64) -> Vec<u8> {
        value.to_le_bytes().to_vec()
    }

    fn item(label: &str, address: u64, type_name: &str, length: u64) -> DataItem {
        DataItem {
            label: label.to_string(),
            address,
            type_name: type_name.to_string(),
            length,
        }
    }

    /// A TypeDescriptor body: the header pair plus the mangled name.
    fn type_descriptor(name: &str) -> Vec<u8> {
        let mut bytes = vec![0u8; 16];
        bytes.extend_from_slice(name.as_bytes());
        bytes.push(0);
        bytes
    }

    /// The error a canned failure tag produces. `GhidraError` is not
    /// `Clone`, so failures are stored as tags and built fresh at read time.
    #[derive(Clone, Copy)]
    enum Failure {
        Unreadable,
        Garbage,
        Busy,
    }

    fn failure(error: u64, kind: Failure) -> TypesDbError {
        match kind {
            Failure::Unreadable => GhidraError::NotFound {
                kind: "memory",
                query: format!("{error:x}"),
            }
            .into(),
            Failure::Garbage => GhidraError::Malformed {
                kind: "memory bytes",
                detail: "not a byte list".into(),
            }
            .into(),
            Failure::Busy => GhidraError::Reported {
                status: Some(200),
                message: "Ghidra is busy".into(),
            }
            .into(),
        }
    }

    /// A source over canned listings and memory, recording every read and
    /// every tag so tests can assert what the scan touched.
    struct MockSource {
        items: Vec<DataItem>,
        functions: Vec<FunctionSummary>,
        image_base: u64,
        memory: HashMap<u64, Vec<u8>>,
        failures: HashMap<u64, Failure>,
        listing_failure: Option<Failure>,
        reads: Mutex<Vec<u64>>,
        tags: Mutex<Vec<(u64, String)>>,
    }

    impl MockSource {
        fn new(items: Vec<DataItem>) -> Self {
            Self {
                items,
                functions: Vec::new(),
                image_base: 0x1_8000_0000,
                memory: HashMap::new(),
                failures: HashMap::new(),
                listing_failure: None,
                reads: Mutex::new(Vec::new()),
                tags: Mutex::new(Vec::new()),
            }
        }

        fn memory_at(&mut self, address: u64, bytes: Vec<u8>) {
            self.memory.insert(address, bytes);
        }

        fn fail_at(&mut self, address: u64, kind: Failure) {
            self.failures.insert(address, kind);
        }

        fn function(&mut self, name: &str, address: u64) {
            self.functions.push(FunctionSummary {
                name: name.to_string(),
                address,
            });
        }

        fn read_log(&self) -> Vec<u64> {
            self.reads.lock().unwrap().clone()
        }

        fn tag_log(&self) -> Vec<(u64, String)> {
            self.tags.lock().unwrap().clone()
        }
    }

    impl VtableSource for MockSource {
        async fn data_items(&self) -> Result<Vec<DataItem>> {
            match self.listing_failure {
                Some(kind) => Err(failure(0, kind)),
                None => Ok(self.items.clone()),
            }
        }

        async fn functions(&self) -> Result<Vec<FunctionSummary>> {
            Ok(self.functions.clone())
        }

        async fn image_base(&self) -> Result<u64> {
            Ok(self.image_base)
        }

        async fn read_memory(&self, address: u64, _length: usize) -> Result<Vec<u8>> {
            self.reads.lock().unwrap().push(address);
            if let Some(kind) = self.failures.get(&address) {
                return Err(failure(address, *kind));
            }
            self.memory.get(&address).cloned().ok_or_else(|| {
                GhidraError::NotFound {
                    kind: "memory",
                    query: format!("{address:x}"),
                }
                .into()
            })
        }

        async fn add_function_tag(&self, address: u64, tag: &str) -> Result<()> {
            self.tags.lock().unwrap().push((address, tag.to_string()));
            Ok(())
        }
    }

    fn detector_over(source: MockSource) -> VtableDetector<MockSource> {
        VtableDetector {
            source,
            pointer_size: 8,
            tag: Some(DEFAULT_TAG.to_string()),
        }
    }

    /// The vftable at `1801306f0` as `eqmain.dll` lays it out: five method
    /// pointers, a metadata pointer to a CompleteObjectLocator, a TypeDescriptor
    /// naming `UdpRefCount` in `UdpLibrary`, and one base class.
    fn eqmain_fixture() -> MockSource {
        let mut source = MockSource::new(vec![
            item("vftable_meta_ptr", 0x1801_306e8, "pointer", 8),
            item("vftable", 0x1801_306f0, "pointer[5]", 40),
        ]);
        for (name, address) in [
            ("FUN_18003ab00", 0x1800_3ab00),
            ("FUN_18003e750", 0x1800_3e750),
            ("FUN_18003c9c0", 0x1800_3c9c0),
            ("FUN_18003b8d0", 0x1800_3b8d0),
            ("FUN_18003aad0", 0x1800_3aad0),
        ] {
            source.function(name, address);
        }
        source.memory_at(
            0x1801_306f0,
            [
                0x1800_3ab00,
                0x1800_3e750,
                0x1800_3c9c0,
                0x1800_3b8d0,
                0x1800_3aad0,
            ]
            .into_iter()
            .flat_map(le64)
            .collect(),
        );
        // Metadata pointer → CompleteObjectLocator at 18014e620.
        source.memory_at(0x1801_306e8, le64(0x1801_4e620));
        let mut col = le32(1); // signature
        col.extend(le32(0)); // displacement
        col.extend(le32(0)); // cdOffset
        col.extend(le32(0x17_a148)); // TypeDescriptor RVA
        col.extend(le32(0x14_e3e0)); // ClassHierarchyDescriptor RVA
        source.memory_at(0x1801_4e620, col);
        source.memory_at(
            0x1801_7a148,
            type_descriptor(".?AVUdpRefCount@UdpLibrary@@"),
        );
        let mut chd = le32(0); // signature
        chd.extend(le32(0)); // attributes
        chd.extend(le32(1)); // one base class
        chd.extend(le32(0x14_e3f8)); // BaseClassArray RVA
        source.memory_at(0x1801_4e3e0, chd);
        source.memory_at(0x1801_4e3f8, le32(0x14_e410));
        let mut bcd = le32(0); // numContainedBases
        bcd.extend(le32(0)); // PMD self
        bcd.extend([0u8; 8]); // PMD displacement
        bcd.extend([0u8; 8]); // PMD pointer offset
        bcd.extend(le32(0x17_a180)); // base TypeDescriptor RVA
        bcd.extend(le32(0)); // attributes
        source.memory_at(0x1801_4e410, bcd);
        source.memory_at(0x1801_7a180, type_descriptor(".?AVBase@@"));
        source
    }

    #[tokio::test]
    async fn detect_recovers_a_vftable_with_its_rtti_confirmation() {
        let vtables = detector_over(eqmain_fixture())
            .detect_vtables()
            .await
            .unwrap();
        assert_eq!(vtables.len(), 1);
        let vtable = &vtables[0];
        assert_eq!(vtable.address, 0x1801_306f0);
        assert_eq!(vtable.label, "vftable");
        assert_eq!(vtable.size, 40);
        assert_eq!(vtable.meta_ptr_address, Some(0x1801_306e8));
        assert!(vtable.is_confirmed());
    }

    #[tokio::test]
    async fn method_pointers_resolve_to_names_and_addresses() {
        let vtables = detector_over(eqmain_fixture())
            .detect_vtables()
            .await
            .unwrap();
        let methods = &vtables[0].methods;
        assert_eq!(methods.len(), 5);
        assert_eq!(methods[0].slot, 0);
        assert_eq!(methods[0].address, 0x1800_3ab00);
        assert_eq!(methods[0].name.as_deref(), Some("FUN_18003ab00"));
        assert_eq!(methods[4].slot, 4);
        assert_eq!(methods[4].name.as_deref(), Some("FUN_18003aad0"));
    }

    #[tokio::test]
    async fn an_unnamed_method_pointer_keeps_its_address() {
        let mut source = eqmain_fixture();
        // The third slot points at an address no function occupies.
        source.memory_at(
            0x1801_306f0,
            [
                0x1800_3ab00,
                0x1800_3e750,
                0x1800_dead,
                0x1800_3b8d0,
                0x1800_3aad0,
            ]
            .into_iter()
            .flat_map(le64)
            .collect(),
        );
        let vtables = detector_over(source).detect_vtables().await.unwrap();
        assert_eq!(vtables[0].methods[2].address, 0x1800_dead);
        assert_eq!(vtables[0].methods[2].name, None);
    }

    #[tokio::test]
    async fn the_rtti_chain_recovers_the_class_name() {
        let vtables = detector_over(eqmain_fixture())
            .detect_vtables()
            .await
            .unwrap();
        // The mangled name is written innermost-first; display reverses it.
        assert_eq!(
            vtables[0].class_name.as_deref(),
            Some("UdpLibrary::UdpRefCount")
        );
    }

    #[tokio::test]
    async fn base_classes_are_tracked_from_the_hierarchy() {
        let vtables = detector_over(eqmain_fixture())
            .detect_vtables()
            .await
            .unwrap();
        assert_eq!(vtables[0].base_classes, vec!["Base".to_string()]);
    }

    #[tokio::test]
    async fn com_interfaces_are_detected_from_the_iunknown_prefix() {
        let mut source = MockSource::new(vec![
            item("vftable_meta_ptr", 0x1801_30700, "pointer", 8),
            item("vftable", 0x1801_30708, "pointer[3]", 24),
        ]);
        for (name, address) in [
            ("QueryInterface", 0x1800_1000),
            ("AddRef", 0x1800_1010),
            ("Release", 0x1800_1020),
        ] {
            source.function(name, address);
        }
        source.memory_at(
            0x1801_30708,
            [0x1800_1000, 0x1800_1010, 0x1800_1020]
                .into_iter()
                .flat_map(le64)
                .collect(),
        );
        source.memory_at(0x1801_30700, le64(0x1801_4e700));
        let mut col = le32(1);
        col.extend(le32(0));
        col.extend(le32(0));
        col.extend(le32(0x17_b000));
        col.extend(le32(0x14_e800));
        source.memory_at(0x1801_4e700, col);
        source.memory_at(0x1801_7b000, type_descriptor(".?AVIFoo@@"));
        let mut chd = le32(0);
        chd.extend(le32(0));
        chd.extend(le32(0)); // IUnknown: no bases below it
        chd.extend(le32(0));
        source.memory_at(0x1801_4e800, chd);

        let vtables = detector_over(source).detect_vtables().await.unwrap();
        assert_eq!(vtables.len(), 1);
        assert!(vtables[0].is_com_interface);
        assert_eq!(vtables[0].class_name.as_deref(), Some("IFoo"));
        assert!(vtables[0].base_classes.is_empty());

        // The eqmain vtable's methods are ordinary functions: not COM.
        let vtables = detector_over(eqmain_fixture())
            .detect_vtables()
            .await
            .unwrap();
        assert!(!vtables[0].is_com_interface);
    }

    #[tokio::test]
    async fn an_unpaired_vftable_is_reported_without_confirmation() {
        // A `vftable` with no metadata pointer before it is still a vtable —
        // just one with no RTTI record to follow.
        let mut source = MockSource::new(vec![item("vftable", 0x1801_306f0, "pointer[2]", 16)]);
        source.function("FUN_18003ab00", 0x1800_3ab00);
        source.function("FUN_18003e750", 0x1800_3e750);
        source.memory_at(
            0x1801_306f0,
            [0x1800_3ab00, 0x1800_3e750]
                .into_iter()
                .flat_map(le64)
                .collect(),
        );

        let scanner = detector_over(source);
        let vtables = scanner.detect_vtables().await.unwrap();
        assert_eq!(vtables.len(), 1);
        assert!(!vtables[0].is_confirmed());
        assert_eq!(vtables[0].methods.len(), 2);
        assert_eq!(vtables[0].class_name, None);
        // Only the table itself was read; no RTTI walk, no tags.
        assert_eq!(scanner.source.read_log(), vec![0x1801_306f0]);
        assert!(scanner.source.tag_log().is_empty());
    }

    #[tokio::test]
    async fn non_vtable_items_are_ignored() {
        let source = MockSource::new(vec![
            item(
                "IMAGE_DOS_HEADER_180000000",
                0x1800_0000,
                "IMAGE_DOS_HEADER",
                128,
            ),
            item("DAT_1801780c8", 0x1801_780c8, "undefined8", 8),
            item(
                "UNWIND_INFO_180157b40",
                0x1801_57b40,
                "PEx64_UnwindInfo",
                12,
            ),
        ]);
        let scanner = detector_over(source);
        assert!(scanner.detect_vtables().await.unwrap().is_empty());
        assert!(
            scanner.source.read_log().is_empty(),
            "no memory reads expected without candidates"
        );
    }

    #[tokio::test]
    async fn rtti_misses_degrade_to_methods_only() {
        // The metadata pointer reads, but the locator it names is not there:
        // the vtable keeps its methods and loses its class information.
        let mut source = eqmain_fixture();
        source.fail_at(0x1801_4e620, Failure::Unreadable);

        let vtables = detector_over(source).detect_vtables().await.unwrap();
        assert_eq!(vtables.len(), 1);
        assert!(vtables[0].is_confirmed());
        assert_eq!(vtables[0].methods.len(), 5);
        assert_eq!(vtables[0].class_name, None);
        assert!(vtables[0].base_classes.is_empty());
    }

    #[tokio::test]
    async fn a_table_whose_bytes_are_unreadable_keeps_its_shape() {
        let mut source = eqmain_fixture();
        source.fail_at(0x1801_306f0, Failure::Garbage);

        let vtables = detector_over(source).detect_vtables().await.unwrap();
        assert_eq!(vtables.len(), 1);
        assert!(vtables[0].methods.is_empty());
        assert_eq!(vtables[0].size, 40);
        // The RTTI chain still resolves the class.
        assert_eq!(
            vtables[0].class_name.as_deref(),
            Some("UdpLibrary::UdpRefCount")
        );
    }

    #[tokio::test]
    async fn a_server_failure_on_the_listing_aborts_the_scan() {
        let mut source = eqmain_fixture();
        source.listing_failure = Some(Failure::Busy);

        let result = detector_over(source).detect_vtables().await;
        assert!(matches!(
            result,
            Err(TypesDbError::Ghidra(GhidraError::Reported { .. }))
        ));
    }

    #[tokio::test]
    async fn confirmed_methods_are_tagged_once_per_function() {
        // Two confirmed vtables sharing a method: the shared function is
        // tagged once, and an unconfirmed table's methods are not tagged.
        let mut source = eqmain_fixture();
        source
            .items
            .push(item("vftable_meta_ptr", 0x1801_30718, "pointer", 8));
        source
            .items
            .push(item("vftable", 0x1801_30720, "pointer[2]", 16));
        source
            .items
            .push(item("vftable", 0x1801_30740, "pointer[1]", 8));
        source.memory_at(
            0x1801_30720,
            [0x1800_3ab00, 0x1800_3e750]
                .into_iter()
                .flat_map(le64)
                .collect(),
        );
        source.memory_at(0x1801_30718, le64(0x1801_4e620));
        source.memory_at(
            0x1801_30740,
            [0x1800_3ab00].into_iter().flat_map(le64).collect(),
        );

        let scanner = detector_over(source);
        let vtables = scanner.detect_vtables().await.unwrap();
        assert_eq!(vtables.len(), 3);

        let tags = scanner.source.tag_log();
        let tagged: Vec<u64> = tags.iter().map(|(address, _)| *address).collect();
        assert_eq!(
            tagged,
            vec![
                0x1800_3ab00,
                0x1800_3e750,
                0x1800_3c9c0,
                0x1800_3b8d0,
                0x1800_3aad0
            ]
        );
        assert!(tags.iter().all(|(_, tag)| tag == DEFAULT_TAG));
    }

    #[tokio::test]
    async fn without_tagging_writes_nothing_back() {
        let scanner = detector_over(eqmain_fixture()).without_tagging();
        let vtables = scanner.detect_vtables().await.unwrap();
        assert_eq!(
            vtables[0].class_name.as_deref(),
            Some("UdpLibrary::UdpRefCount")
        );
        assert!(scanner.source.tag_log().is_empty());
    }

    #[test]
    fn demangles_msvc_rtti_names() {
        assert_eq!(
            demangle_rtti_name(".?AVWidget@@").as_deref(),
            Some("Widget")
        );
        assert_eq!(
            demangle_rtti_name(".?AVUdpRefCount@UdpLibrary@@").as_deref(),
            Some("UdpLibrary::UdpRefCount")
        );
        assert_eq!(
            demangle_rtti_name(".?AUMyStruct@@").as_deref(),
            Some("MyStruct")
        );
        assert_eq!(demangle_rtti_name("DAT_1801780c8"), None);
        assert_eq!(demangle_rtti_name(".?AV@@"), None);
    }

    #[test]
    fn pointer_array_element_count() {
        assert_eq!(pointer_array_count("pointer[5]"), Some(5));
        assert_eq!(pointer_array_count("pointer[0]"), Some(0));
        assert_eq!(pointer_array_count("pointer"), None);
        assert_eq!(pointer_array_count("undefined8[3]"), None);
    }

    #[test]
    fn element_size_prefers_the_declared_count() {
        let scanner = detector_over(MockSource::new(Vec::new()));
        // `pointer[5]` over 40 bytes: eight-byte entries, whatever the
        // configured default says.
        assert_eq!(
            scanner.element_size(&item("vftable", 0x100, "pointer[5]", 40)),
            8
        );
        // A table typed without a count falls back to the default.
        assert_eq!(
            scanner.element_size(&item("vftable", 0x100, "undefined8", 40)),
            8
        );
        let scanner = scanner.with_pointer_size(4);
        assert_eq!(
            scanner.element_size(&item("vftable", 0x100, "undefined4", 40)),
            4
        );
    }
}
