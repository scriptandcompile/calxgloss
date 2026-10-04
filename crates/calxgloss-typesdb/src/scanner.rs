//! Named type recovery from Ghidra's Type Manager.
//!
//! [`TypeLibraryScanner`] with `scan_named_types()` queries the bridge's
//! `list_data_types` / `get_struct_layout` / `get_enum_values` endpoints and
//! returns every named type in the Type Manager — including types never
//! applied to a symbol. Malformed or partially available type data degrades
//! gracefully rather than failing the whole scan.
//!
//! The listing itself carries no kind column (`name | category | N bytes |
//! path`), but the bridge's `category` filter matches the word against the
//! type's category name *or* its own classification (`struct`, `union`,
//! `enum`, `typedef`, `pointer`, `array`, `function`, `primitive`), as a
//! case-insensitive substring (verified against the v6.0.0 plugin's
//! `DataTypeService.listDataTypes`). So the scanner fetches one filtered
//! listing per kind to learn which bucket a type sits in, then confirms
//! structures and enumerations with layout probes. A type in no bucket is
//! never a structure or enumeration — the bridge classifies every one into
//! its bucket — so it is recorded without probing.

use crate::error::{Result, TypesDbError};
use crate::types::{NamedType, TypeKind};
use calxgloss_ghidra::{DataTypeEntry, EnumDefinition, GhidraClient, GhidraError, StructLayout};
use std::collections::HashSet;
use tracing::{debug, info};

/// The Type Manager reads a named-type scan performs.
///
/// [`GhidraClient`] implements it directly; tests implement it over canned
/// responses so the scan's classification and degradation logic runs without
/// a server. The futures are `Send` so a scan can be driven from an
/// orchestrating task.
pub trait TypeLibrarySource {
    /// Every named type in the Type Manager, optionally filtered by category
    /// or classification, collected across pages.
    fn list_types(
        &self,
        category: Option<&str>,
    ) -> impl std::future::Future<Output = Result<Vec<DataTypeEntry>>> + Send;

    /// Field layout of a structure.
    fn struct_layout(
        &self,
        name: &str,
    ) -> impl std::future::Future<Output = Result<StructLayout>> + Send;

    /// Members of an enumeration.
    fn enum_values(
        &self,
        name: &str,
    ) -> impl std::future::Future<Output = Result<EnumDefinition>> + Send;
}

impl TypeLibrarySource for GhidraClient {
    async fn list_types(&self, category: Option<&str>) -> Result<Vec<DataTypeEntry>> {
        Ok(self.list_data_types(category).await?)
    }

    async fn struct_layout(&self, name: &str) -> Result<StructLayout> {
        Ok(self.get_struct_layout(name).await?)
    }

    async fn enum_values(&self, name: &str) -> Result<EnumDefinition> {
        Ok(self.get_enum_values(name).await?)
    }
}

/// The classification words the bridge's `category` filter matches against
/// each type's own kind, in probe-priority order.
const KIND_BUCKETS: [(&str, TypeKind); 4] = [
    ("struct", TypeKind::Struct),
    ("enum", TypeKind::Enum),
    ("union", TypeKind::Union),
    ("typedef", TypeKind::Typedef),
];

/// The classification word a kind is bucketed under.
fn kind_word(kind: TypeKind) -> &'static str {
    match kind {
        TypeKind::Struct => "struct",
        TypeKind::Enum => "enum",
        TypeKind::Union => "union",
        TypeKind::Typedef => "typedef",
        // Class and Other are never bucket kinds.
        TypeKind::Class | TypeKind::Other => "",
    }
}

/// Whether a Type Manager entry is worth recovering.
///
/// Pointer and array variants arrive as separate entries (`name *`, `char[2]`)
/// whose base type is already covered, and Ghidra's builtin primitives and
/// demangler placeholders are vocabulary rather than recovered information.
fn is_recoverable_candidate(entry: &DataTypeEntry) -> bool {
    if entry.name.ends_with('*') || entry.name.ends_with(']') {
        return false;
    }
    !matches!(entry.category.as_str(), "builtin" | "demangler")
}

// ============================================================
// Kind hints
// ============================================================

/// Which classification buckets each Type Manager path appeared in.
///
/// Built from one filtered listing per classification word. A bucket is a
/// superset: the filter matches the classification *or* the category name,
/// so a typedef in a category named `struct.h` also lands in the struct
/// bucket. [`KindHints::hint_for`] flags those suspect memberships, and the
/// scanner confirms them with probes instead of trusting them.
#[derive(Debug, Default)]
pub struct KindHints {
    buckets: Vec<(TypeKind, HashSet<String>)>,
}

/// A type's bucket membership: which kind it was bucketed as, and whether
/// that membership can be trusted without a probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KindHint {
    /// The kind the type was bucketed as.
    pub kind: TypeKind,
    /// Whether the membership came from the classification alone. It is
    /// suspect when the type's category name also contains the kind word,
    /// because the filter would have matched on that instead.
    pub certain: bool,
}

impl KindHints {
    /// Bucket paths from one filtered listing per classification word, in
    /// `KIND_BUCKETS` order.
    fn from_buckets(listings: impl IntoIterator<Item = (TypeKind, Vec<DataTypeEntry>)>) -> Self {
        Self {
            buckets: listings
                .into_iter()
                .map(|(kind, entries)| (kind, entries.into_iter().map(|e| e.path).collect()))
                .collect(),
        }
    }

    /// The entry's memberships, in `KIND_BUCKETS` order, each marked with
    /// whether the category name could have produced it.
    ///
    /// The certainty test mirrors the bridge's category-side match exactly:
    /// both ask whether the (lowercased) category name contains the kind
    /// word. When it does not, the membership can only come from the
    /// classification side — and each kind word is a substring of only its
    /// own classification, so a certain membership *is* the bridge's verdict.
    fn memberships<'a>(
        &'a self,
        entry: &'a DataTypeEntry,
    ) -> impl Iterator<Item = KindHint> + 'a {
        self.buckets.iter().filter_map(move |(kind, paths)| {
            paths.contains(&entry.path).then_some(KindHint {
                kind: *kind,
                certain: !entry.category.contains(kind_word(*kind)),
            })
        })
    }

    /// The bucket to resolve the entry against: a certain membership first,
    /// since a suspect one may be nothing but the category name matching the
    /// filter; among equals, probe priority (`KIND_BUCKETS` order).
    fn hint_for(&self, entry: &DataTypeEntry) -> Option<KindHint> {
        let mut memberships: Vec<KindHint> = self.memberships(entry).collect();
        // Stable sort: certain before suspect, bucket order within each class.
        memberships.sort_by_key(|h| !h.certain);
        memberships.into_iter().next()
    }

    /// The kind to record when both layout probes missed.
    ///
    /// Only the union and typedef buckets remain usable: the struct and enum
    /// buckets were just disproven by the probes. A certain membership beats
    /// a suspect one — a typedef in a category named `unions` sits in both
    /// buckets, and only the typedef bucket reflects its classification.
    fn fallback_kind(&self, entry: &DataTypeEntry) -> TypeKind {
        let candidates: Vec<KindHint> = self
            .memberships(entry)
            .filter(|h| matches!(h.kind, TypeKind::Union | TypeKind::Typedef))
            .collect();
        candidates
            .iter()
            .find(|h| h.certain)
            .or_else(|| candidates.first())
            .map_or(TypeKind::Other, |h| h.kind)
    }
}

// ============================================================
// Scanner
// ============================================================

/// Named type recovery from Ghidra's Type Manager.
///
/// The scanner is generic over [`TypeLibrarySource`] so tests can drive it
/// with canned responses; [`new`](Self::new) builds one over a live
/// [`GhidraClient`].
#[derive(Debug, Clone)]
pub struct TypeLibraryScanner<S = GhidraClient> {
    source: S,
    category: Option<String>,
}

impl TypeLibraryScanner<GhidraClient> {
    /// A scanner over a live GhidraMCP client.
    pub fn new(client: &GhidraClient) -> TypeLibraryScanner<GhidraClient> {
        TypeLibraryScanner {
            source: client.clone(),
            category: None,
        }
    }
}

impl<S> TypeLibraryScanner<S> {
    /// Restrict the scan to a Type Manager category or name fragment.
    pub fn with_category(mut self, category: impl Into<String>) -> Self {
        self.category = Some(category.into());
        self
    }

    /// Recover every named type the Type Manager holds.
    ///
    /// Structures and enumerations are confirmed with layout probes; unions
    /// and typedefs are recorded from their bucket with size only; anything
    /// else is recorded as [`TypeKind::Other`]. A probe that misses or
    /// refuses degrades that one type to the listing-only shape — a server
    /// failure mid-scan aborts the whole scan instead, because every later
    /// type would hit it too.
    pub async fn scan_named_types(&self) -> Result<Vec<NamedType>>
    where
        S: TypeLibrarySource,
    {
        let listing = self.source.list_types(self.category.as_deref()).await?;
        debug!(count = listing.len(), "Listed Type Manager entries");
        let hints = self.collect_kind_hints().await?;

        let mut recovered = Vec::new();
        for entry in listing.iter().filter(|e| is_recoverable_candidate(e)) {
            recovered.push(self.recover_type(entry, &hints).await?);
        }
        // Type Manager paths are unique; names are not, so the database keys
        // by path and the scan returns a deterministic order.
        recovered.sort_by(|a, b| a.path.cmp(&b.path));
        recovered.dedup_by(|a, b| a.path == b.path);

        info!(count = recovered.len(), "Recovered named types");
        Ok(recovered)
    }

    /// One filtered listing per classification word, bucketed by path.
    async fn collect_kind_hints(&self) -> Result<KindHints>
    where
        S: TypeLibrarySource,
    {
        let mut listings = Vec::with_capacity(KIND_BUCKETS.len());
        for (word, kind) in KIND_BUCKETS {
            let entries = self.source.list_types(Some(word)).await?;
            listings.push((kind, entries));
        }
        Ok(KindHints::from_buckets(listings))
    }

    /// Resolve one entry to a `NamedType`, probing layouts where the buckets
    /// promise one.
    async fn recover_type(&self, entry: &DataTypeEntry, hints: &KindHints) -> Result<NamedType>
    where
        S: TypeLibrarySource,
    {
        let hint = hints.hint_for(entry);

        // A certain union or typedef membership comes from the bridge's own
        // classification, and neither kind has a layout endpoint to confirm
        // against, so the listing is the best available record.
        if let Some(h) = &hint
            && h.certain
            && matches!(h.kind, TypeKind::Union | TypeKind::Typedef)
        {
            return Ok(NamedType::from_listing(entry, h.kind));
        }

        // An entry in no bucket is never a structure or enumeration, so
        // there is nothing to probe.
        let Some(hint) = hint else {
            return Ok(NamedType::from_listing(entry, TypeKind::Other));
        };

        // Probe the promised kind first; the other kind second, because a
        // suspect membership can equally well be the classification and the
        // first probe the false positive (a typedef in a `struct.h` category).
        let probes: [Probe; 2] = if hint.kind == TypeKind::Enum {
            [Probe::Enum, Probe::Struct]
        } else {
            [Probe::Struct, Probe::Enum]
        };
        for probe in probes {
            match probe {
                Probe::Struct => match self.source.struct_layout(&entry.name).await {
                    Ok(layout) => return Ok(NamedType::from_struct(entry, &layout)),
                    Err(miss) if is_layout_miss(&miss) => continue,
                    Err(e) => return Err(e),
                },
                Probe::Enum => match self.source.enum_values(&entry.name).await {
                    Ok(definition) => return Ok(NamedType::from_enum(entry, &definition)),
                    Err(miss) if is_layout_miss(&miss) => continue,
                    Err(e) => return Err(e),
                },
            }
        }

        Ok(NamedType::from_listing(entry, hints.fallback_kind(entry)))
    }
}

/// The two layout probes the scan runs.
#[derive(Debug, Clone, Copy)]
enum Probe {
    Struct,
    Enum,
}

/// Whether an error means "this type is not that kind" rather than "the
/// server could not answer".
///
/// The bridge answers a kind mismatch as prose (`Structure not found: X`,
/// `Data type is not a structure: X`), which the client surfaces as
/// `NotFound` or `Malformed`. Both are expected misses: the other probe may
/// still resolve the type, and if neither does the type degrades. Anything
/// else — transport, a reported server failure — is a broken scan, not a
/// broken type.
fn is_layout_miss(error: &TypesDbError) -> bool {
    matches!(
        error,
        TypesDbError::Ghidra(GhidraError::NotFound { .. } | GhidraError::Malformed { .. })
    )
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use calxgloss_ghidra::{EnumMember, StructFieldLayout};
    use std::collections::HashMap;
    use std::sync::Mutex;

    fn entry(name: &str, category: &str, size: Option<u64>) -> DataTypeEntry {
        DataTypeEntry {
            name: name.to_string(),
            category: category.to_string(),
            size,
            path: format!("/{category}/{name}"),
        }
    }

    fn dos_header_layout() -> StructLayout {
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
        }
    }

    fn disposition_enum() -> EnumDefinition {
        EnumDefinition {
            name: "_EXCEPTION_DISPOSITION".into(),
            size: 4,
            members: vec![EnumMember {
                name: "ExceptionContinueExecution".into(),
                value: 0,
            }],
        }
    }

    /// A canned probe outcome. `GhidraError` is not `Clone`, so failures are
    /// stored as outcome tags and built fresh at probe time.
    #[derive(Clone)]
    enum Canned<T> {
        Found(T),
        NotFound,
        NotThatKind,
        ServerFailure,
    }

    /// A source over canned responses, recording every layout probe so tests
    /// can assert which types were probed at all.
    struct MockSource {
        listing: Vec<DataTypeEntry>,
        buckets: HashMap<&'static str, Vec<DataTypeEntry>>,
        layouts: HashMap<String, Canned<StructLayout>>,
        enums: HashMap<String, Canned<EnumDefinition>>,
        probes: Mutex<Vec<String>>,
    }

    impl MockSource {
        fn new(listing: Vec<DataTypeEntry>) -> Self {
            Self {
                listing,
                buckets: HashMap::new(),
                layouts: HashMap::new(),
                enums: HashMap::new(),
                probes: Mutex::new(Vec::new()),
            }
        }

        fn bucket(&mut self, word: &'static str, entries: Vec<DataTypeEntry>) {
            self.buckets.insert(word, entries);
        }

        fn layout(&mut self, name: &str, outcome: Canned<StructLayout>) {
            self.layouts.insert(name.to_string(), outcome);
        }

        fn enumeration(&mut self, name: &str, outcome: Canned<EnumDefinition>) {
            self.enums.insert(name.to_string(), outcome);
        }

        fn probe_log(&self) -> Vec<String> {
            self.probes.lock().unwrap().clone()
        }
    }

    /// The error a canned outcome produces for a structure probe.
    fn struct_error(name: &str, outcome: &Canned<StructLayout>) -> GhidraError {
        match outcome {
            Canned::NotFound => GhidraError::NotFound {
                kind: "structure",
                query: name.to_string(),
            },
            Canned::NotThatKind => GhidraError::Malformed {
                kind: "structure layout",
                detail: format!("Data type is not a structure: {name}"),
            },
            Canned::ServerFailure => GhidraError::Reported {
                status: Some(200),
                message: "Ghidra is busy".into(),
            },
            Canned::Found(_) => unreachable!("a found layout is not an error"),
        }
    }

    /// The error a canned outcome produces for an enumeration probe.
    fn enum_error(name: &str, outcome: &Canned<EnumDefinition>) -> GhidraError {
        match outcome {
            Canned::NotFound => GhidraError::NotFound {
                kind: "enumeration",
                query: name.to_string(),
            },
            Canned::NotThatKind => GhidraError::Malformed {
                kind: "enumeration values",
                detail: format!("Data type is not an enumeration: {name}"),
            },
            Canned::ServerFailure => GhidraError::Reported {
                status: Some(200),
                message: "Ghidra is busy".into(),
            },
            Canned::Found(_) => unreachable!("a found definition is not an error"),
        }
    }

    impl TypeLibrarySource for MockSource {
        async fn list_types(&self, category: Option<&str>) -> Result<Vec<DataTypeEntry>> {
            match category {
                None => Ok(self.listing.clone()),
                Some(word) => {
                    // A canned bucket wins; otherwise the filter matches on
                    // the category, as the bridge's does.
                    if let Some(bucket) = self.buckets.get(word) {
                        Ok(bucket.clone())
                    } else {
                        Ok(self
                            .listing
                            .iter()
                            .filter(|e| e.category.contains(word))
                            .cloned()
                            .collect())
                    }
                }
            }
        }

        async fn struct_layout(&self, name: &str) -> Result<StructLayout> {
            self.probes.lock().unwrap().push(format!("struct:{name}"));
            match self.layouts.get(name) {
                Some(Canned::Found(layout)) => Ok(layout.clone()),
                Some(outcome) => Err(struct_error(name, outcome).into()),
                None => Err(GhidraError::NotFound {
                    kind: "structure",
                    query: name.to_string(),
                }
                .into()),
            }
        }

        async fn enum_values(&self, name: &str) -> Result<EnumDefinition> {
            self.probes.lock().unwrap().push(format!("enum:{name}"));
            match self.enums.get(name) {
                Some(Canned::Found(definition)) => Ok(definition.clone()),
                Some(outcome) => Err(enum_error(name, outcome).into()),
                None => Err(GhidraError::NotFound {
                    kind: "enumeration",
                    query: name.to_string(),
                }
                .into()),
            }
        }
    }

    fn scanner_over(source: MockSource) -> TypeLibraryScanner<MockSource> {
        TypeLibraryScanner {
            source,
            category: None,
        }
    }

    #[tokio::test]
    async fn scan_recovers_a_struct_with_its_fields() {
        let mut source = MockSource::new(vec![entry("IMAGE_DOS_HEADER", "pe", Some(128))]);
        source.bucket("struct", vec![entry("IMAGE_DOS_HEADER", "pe", Some(128))]);
        source.layout("IMAGE_DOS_HEADER", Canned::Found(dos_header_layout()));

        let types = scanner_over(source).scan_named_types().await.unwrap();
        assert_eq!(types.len(), 1);
        assert_eq!(types[0].kind, TypeKind::Struct);
        assert_eq!(types[0].path, "/pe/IMAGE_DOS_HEADER");
        assert_eq!(types[0].alignment, Some(1));
        assert_eq!(types[0].fields[0].name, "e_magic");
        assert_eq!(types[0].fields[0].type_name, "char[2]");
    }

    #[tokio::test]
    async fn scan_recovers_an_enum_with_its_members() {
        let e = entry("_EXCEPTION_DISPOSITION", "excpt.h", Some(4));
        let mut source = MockSource::new(vec![e.clone()]);
        source.bucket("enum", vec![e]);
        source.enumeration("_EXCEPTION_DISPOSITION", Canned::Found(disposition_enum()));

        let types = scanner_over(source).scan_named_types().await.unwrap();
        assert_eq!(types.len(), 1);
        assert_eq!(types[0].kind, TypeKind::Enum);
        assert_eq!(types[0].members[0].name, "ExceptionContinueExecution");
        assert_eq!(types[0].members[0].value, 0);
    }

    #[tokio::test]
    async fn scan_degrades_a_type_whose_probes_all_miss() {
        // Bucketed as a struct but every probe refuses: the type is still
        // worth recording, at listing fidelity.
        let e = entry("GHOST_STRUCT", "pe", Some(16));
        let mut source = MockSource::new(vec![e.clone()]);
        source.bucket("struct", vec![e]);
        source.layout("GHOST_STRUCT", Canned::NotFound);

        let types = scanner_over(source).scan_named_types().await.unwrap();
        assert_eq!(types.len(), 1);
        assert_eq!(types[0].kind, TypeKind::Other);
        assert_eq!(types[0].size, Some(16));
        assert!(types[0].fields.is_empty());
        assert!(!types[0].has_layout());
    }

    #[tokio::test]
    async fn scan_falls_back_to_the_enum_probe_when_the_struct_probe_refuses() {
        // Both bucket memberships are suspect (the category name contains
        // both kind words), so probe priority decides: struct first, and the
        // type turns out to be an enum.
        let e = entry("MODES", "struct_enum.h", Some(4));
        let mut source = MockSource::new(vec![e.clone()]);
        source.bucket("struct", vec![e.clone()]);
        source.bucket("enum", vec![e]);
        source.layout("MODES", Canned::NotThatKind);
        source.enumeration(
            "MODES",
            Canned::Found(EnumDefinition {
                name: "MODES".into(),
                size: 4,
                members: vec![EnumMember {
                    name: "MODE_ON".into(),
                    value: 1,
                }],
            }),
        );

        let scanner = scanner_over(source);
        let types = scanner.scan_named_types().await.unwrap();
        assert_eq!(types[0].kind, TypeKind::Enum);
        assert_eq!(types[0].members[0].name, "MODE_ON");
        assert_eq!(
            scanner.source.probe_log(),
            vec!["struct:MODES", "enum:MODES"],
            "the suspect struct bucket is probed first"
        );
    }

    #[tokio::test]
    async fn scan_skips_pointer_array_builtin_and_demangler_entries() {
        let listing = vec![
            entry("IMAGE_DOS_HEADER *", "pe", Some(8)),
            entry("char[2]", "builtin", Some(2)),
            entry("u8", "builtin", Some(1)),
            entry("<lambda_01a7>", "demangler", Some(1)),
            entry("KEEP_ME", "pe", Some(4)),
        ];
        let mut source = MockSource::new(listing);
        source.bucket("struct", vec![entry("KEEP_ME", "pe", Some(4))]);
        source.layout(
            "KEEP_ME",
            Canned::Found(StructLayout {
                name: "KEEP_ME".into(),
                size: 4,
                alignment: 1,
                fields: Vec::new(),
            }),
        );

        let types = scanner_over(source).scan_named_types().await.unwrap();
        assert_eq!(types.len(), 1);
        assert_eq!(types[0].name, "KEEP_ME");
    }

    #[tokio::test]
    async fn certain_union_and_typedef_buckets_are_recorded_without_probing() {
        // Neither kind has a layout endpoint, and their certain bucket
        // membership came from the classification itself.
        let listing = vec![
            entry("MY_UNION", "sys", Some(8)),
            entry("MY_HANDLE", "winuser.h", Some(4)),
        ];
        let mut source = MockSource::new(listing.clone());
        source.bucket("union", vec![listing[0].clone()]);
        source.bucket("typedef", vec![listing[1].clone()]);

        let scanner = scanner_over(source);
        let types = scanner.scan_named_types().await.unwrap();
        // Sorted by path: /sys/MY_UNION before /winuser.h/MY_HANDLE.
        assert_eq!(types[0].kind, TypeKind::Union);
        assert_eq!(types[1].kind, TypeKind::Typedef);
        assert_eq!(types[1].size, Some(4));
        assert!(
            scanner.source.probe_log().is_empty(),
            "no layout probes expected"
        );
    }

    #[tokio::test]
    async fn a_typedef_in_a_struct_named_category_resolves_to_typedef() {
        // The struct bucket matched on the category name, not the
        // classification; the typedef bucket's membership is certain, and a
        // certain membership wins over a suspect one without any probing.
        let e = entry("WIDGET", "struct.h", Some(12));
        let mut source = MockSource::new(vec![e.clone()]);
        source.bucket("struct", vec![e.clone()]);
        source.bucket("typedef", vec![e]);
        source.layout("WIDGET", Canned::NotThatKind);

        let scanner = scanner_over(source);
        let types = scanner.scan_named_types().await.unwrap();
        assert_eq!(types[0].kind, TypeKind::Typedef);
        assert!(
            scanner.source.probe_log().is_empty(),
            "the certain typedef bucket needs no probe"
        );
    }

    #[tokio::test]
    async fn a_typedef_in_a_union_named_category_resolves_to_typedef() {
        // The live bridge matches its category filter as a substring against
        // the category name *or* the classification, so a typedef in a
        // category named `unions` lands in the (suspect) union bucket and the
        // (certain) typedef bucket. Trusting the bucket order would record a
        // Union; the certain membership must win.
        let e = entry("WIDGET", "unions", Some(12));
        let mut source = MockSource::new(vec![e.clone()]);
        source.bucket("union", vec![e.clone()]);
        source.bucket("typedef", vec![e]);

        let scanner = scanner_over(source);
        let types = scanner.scan_named_types().await.unwrap();
        assert_eq!(types[0].kind, TypeKind::Typedef);
        assert!(
            scanner.source.probe_log().is_empty(),
            "the certain typedef bucket needs no probe"
        );
    }

    #[tokio::test]
    async fn an_unbucketed_type_is_recorded_as_other_without_probing() {
        // Function signatures and stray primitives sit in no classification
        // bucket, and no bucket membership can make them a struct or enum.
        let source = MockSource::new(vec![entry("SOME_SIGNATURE", "windows.h", None)]);
        let scanner = scanner_over(source);
        let types = scanner.scan_named_types().await.unwrap();
        assert_eq!(types.len(), 1);
        assert_eq!(types[0].kind, TypeKind::Other);
        assert!(
            scanner.source.probe_log().is_empty(),
            "no layout probes expected"
        );
    }

    #[tokio::test]
    async fn a_server_failure_mid_scan_aborts_the_scan() {
        // A reported server failure is not a kind miss: every later probe
        // would hit it too, so the scan fails rather than degrading.
        let e = entry("IMAGE_DOS_HEADER", "pe", Some(128));
        let mut source = MockSource::new(vec![e.clone()]);
        source.bucket("struct", vec![e]);
        source.layout("IMAGE_DOS_HEADER", Canned::ServerFailure);

        let result = scanner_over(source).scan_named_types().await;
        assert!(matches!(
            result,
            Err(TypesDbError::Ghidra(GhidraError::Reported { .. }))
        ));
    }

    #[tokio::test]
    async fn scan_sorts_by_path_and_deduplicates() {
        let listing = vec![
            entry("ZED", "pe", Some(4)),
            entry("AMBER", "pe", Some(4)),
            entry("AMBER", "pe", Some(4)),
        ];
        let types = scanner_over(MockSource::new(listing))
            .scan_named_types()
            .await
            .unwrap();
        let paths: Vec<&str> = types.iter().map(|t| t.path.as_str()).collect();
        assert_eq!(paths, vec!["/pe/AMBER", "/pe/ZED"]);
    }

    #[tokio::test]
    async fn category_filter_reaches_the_listing() {
        // The mock filters an unbucketed category against the entry's own
        // category, so a matching filter keeps the entry and a non-matching
        // one would empty the listing.
        let mut source = MockSource::new(vec![entry("ANYWAY", "pe", Some(4))]);
        source.bucket("struct", vec![entry("ANYWAY", "pe", Some(4))]);
        source.layout(
            "ANYWAY",
            Canned::Found(StructLayout {
                name: "ANYWAY".into(),
                size: 4,
                alignment: 1,
                fields: Vec::new(),
            }),
        );

        let scanner = TypeLibraryScanner {
            source,
            category: Some("pe".into()),
        };
        let types = scanner.scan_named_types().await.unwrap();
        assert_eq!(types.len(), 1);
        assert_eq!(types[0].kind, TypeKind::Struct);

        let scanner = TypeLibraryScanner {
            source: scanner.source,
            category: Some("no_such_category".into()),
        };
        assert!(scanner.scan_named_types().await.unwrap().is_empty());
    }

    #[test]
    fn suspect_membership_is_flagged() {
        let hints = KindHints::from_buckets(vec![(
            TypeKind::Struct,
            vec![entry("WIDGET", "struct.h", Some(4))],
        )]);
        let hint = hints
            .hint_for(&entry("WIDGET", "struct.h", Some(4)))
            .expect("bucketed");
        assert_eq!(hint.kind, TypeKind::Struct);
        assert!(!hint.certain, "the category name alone could have matched");

        let hints = KindHints::from_buckets(vec![(
            TypeKind::Struct,
            vec![entry("IMAGE_DOS_HEADER", "pe", Some(128))],
        )]);
        let hint = hints
            .hint_for(&entry("IMAGE_DOS_HEADER", "pe", Some(128)))
            .expect("bucketed");
        assert!(hint.certain, "only the classification could have matched");
    }

    #[test]
    fn recoverable_candidate_filtering() {
        assert!(!is_recoverable_candidate(&entry(
            "HWND *",
            "winuser.h",
            Some(8)
        )));
        assert!(!is_recoverable_candidate(&entry(
            "char[2]",
            "builtin",
            Some(2)
        )));
        assert!(!is_recoverable_candidate(&entry("u8", "builtin", Some(1))));
        assert!(!is_recoverable_candidate(&entry(
            "<lambda_1>",
            "demangler",
            Some(1)
        )));
        assert!(is_recoverable_candidate(&entry(
            "IMAGE_DOS_HEADER",
            "pe",
            Some(128)
        )));
    }
}
