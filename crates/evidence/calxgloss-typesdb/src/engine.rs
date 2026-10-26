//! Type database recovery orchestration.
//!
//! [`TypesDBEngine`] runs the three recovery engines — named type recovery,
//! vtable detection, and string-guided inference — concurrently against one
//! loaded program and assembles their results into a single
//! [`TypeDatabase`] with its scan provenance.
//!
//! The three scans read disjoint seam reads (`data_types()`,
//! `data_items()` + `read_memory()`, and `strings()` + `xrefs_to()`),
//! so they run as concurrent tasks rather than one after another. Each engine
//! already degrades internally for missing or malformed data, so an error
//! surfacing here means the engine itself failed mid-scan; the run aborts
//! with that error rather than returning a database whose sections were
//! built against different programs or different moments.
//!
//! After the scans, a pure in-memory pass links string-inferred candidates
//! to RTTI-confirmed vtables: a candidate whose referencing functions include
//! a confirmed table's methods takes that table's demangled class name and
//! records the link. A second pass then merges candidates whose referencing
//! functions overlap — one struct read by a hub function splits into half-
//! candidates, and the overlap through the hub is what ties them back
//! together — keeping the stronger half's name and link and unioning the
//! fields. A third pass links struct fields to the recovered named types
//! they name, so a layout whose field is another recovered type reads as a
//! tree: the field records that type's Type Manager path and kind, and a
//! field typed as a recovered union carries the union kind. A fourth pass
//! then flags the records whose names match an STL/MFC shape, marking them
//! for the LLM without removing them (issue #140). All passes read only
//! what the scans already recovered, so they can neither fail the run
//! nor cost a record.

use crate::error::Result;
use crate::scanner::TypeLibraryScanner;
use crate::stl;
use crate::string_infer::StringInferenceEngine;
use crate::types::{
    Confidence, InferredField, InferredStruct, NameOrigin, NamedType, ScanMetadata, TypeDatabase,
    TypeKind, Vtable,
};
use crate::vtable::{TagSink, VtableDetector};
use calxgloss_kuna::KunaSource;
use calxgloss_types::{CoverageStatus, FacetCoverage, ScanCoverage};
use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet};
use std::time::Instant;
use tracing::info;

/// The shared trait from the decompiler seam crate, re-exported here
/// so the engine's generic shape names it where it always has;
/// [`KunaSource`] implements it over the in-process engine, and tests
/// implement it over canned listings so the orchestration runs without
/// a server. The futures are `Send` so a scan can be driven from an
/// orchestrating task.
pub use calxgloss_decomp::ScanSource;

/// The coverage record every typesdb scan stamps about itself (issue
/// #348), beside the provenance and the timing.
///
/// typesdb has one facet it can come up empty on: `vtables`, the RTTI
/// walk that recovers a class's method table. A target built without RTTI
/// (a stripped release build, a non-MSVC binary) yields nothing for the
/// detector to find, and zero recorded vtables is then a property of the
/// target, not of the program's shape — so the facet is `unavailable` with
/// that reason rather than a quiet zero. A scan that found at least one
/// table read the walk end to end and the facet is `complete`, and the
/// named types and string-inferred candidates beside it are unaffected
/// either way. The whole picture mirrors the single facet — there is
/// nothing else this engine examines over a vtable (the P19-4
/// admitted-semantics track).
fn coverage_stamp(vtables_found: usize) -> ScanCoverage {
    let (status, limitation) = if vtables_found == 0 {
        (
            CoverageStatus::Unavailable,
            Some("no vtable evidence on this target".to_string()),
        )
    } else {
        (CoverageStatus::Complete, None)
    };
    ScanCoverage {
        status,
        facets: vec![FacetCoverage {
            id: "vtables".to_string(),
            status,
            limitation,
        }],
    }
}

/// Orchestrates the three recovery engines into one [`TypeDatabase`].
///
/// The engine is generic over the same source traits as the scanners it
/// drives, so tests can run the whole orchestration over canned responses;
/// [`new`](Self::new) builds one over a loaded [`KunaSource`].
#[derive(Debug, Clone)]
pub struct TypesDBEngine<S = KunaSource> {
    scanner: TypeLibraryScanner<S>,
    vtables: VtableDetector<S>,
    strings: StringInferenceEngine<S>,
}

impl TypesDBEngine<KunaSource> {
    /// An engine over a loaded Kuna program.
    pub fn new(source: &KunaSource) -> TypesDBEngine<KunaSource> {
        TypesDBEngine {
            scanner: TypeLibraryScanner::new(source),
            vtables: VtableDetector::new(source),
            strings: StringInferenceEngine::new(source),
        }
    }
}

impl<S> TypesDBEngine<S> {
    /// An engine whose three scanners share one source.
    pub fn with_source(source: S) -> Self
    where
        S: Clone,
    {
        TypesDBEngine {
            scanner: TypeLibraryScanner::with_source(source.clone()),
            vtables: VtableDetector::with_source(source.clone()),
            strings: StringInferenceEngine::with_source(source),
        }
    }

    /// Restrict the named-type scan to a Type Manager category.
    pub fn with_category(mut self, category: impl Into<String>) -> Self {
        self.scanner = self.scanner.with_category(category);
        self
    }

    /// Tag confirmed vtable methods with `tag` instead of the default.
    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.vtables = self.vtables.with_tag(tag);
        self
    }

    /// Detect vtables without writing anything back to the program.
    pub fn without_tagging(mut self) -> Self {
        self.vtables = self.vtables.without_tagging();
        self
    }

    /// Regex the string listing is filtered by.
    pub fn with_string_filter(mut self, pattern: impl Into<String>) -> Self {
        self.strings = self.strings.with_string_filter(pattern);
        self
    }

    /// Report inferred candidates scoring `threshold` or higher.
    pub fn with_min_confidence(mut self, threshold: u8) -> Self {
        self.strings = self.strings.with_min_confidence(threshold);
        self
    }

    /// Report inferred candidates with at least `count` fields.
    pub fn with_min_fields(mut self, count: usize) -> Self {
        self.strings = self.strings.with_min_fields(count);
        self
    }

    /// Assume `pointer_size` for vtable entries and text-typed fields —
    /// one program, one pointer size, so the knob reaches both scanners.
    pub fn with_pointer_size(mut self, pointer_size: usize) -> Self {
        self.vtables = self.vtables.with_pointer_size(pointer_size);
        self.strings = self.strings.with_pointer_size(pointer_size as u64);
        self
    }

    /// Recover the whole type database for `binary`, running the three
    /// scans concurrently.
    ///
    /// `binary` names the program the scans read (e.g. `eqmain.dll`) and
    /// becomes the key a persisted database is filed under. The metadata is
    /// stamped when the scans finish, so it records when the database was
    /// built and how long the concurrent run took.
    pub async fn scan(&self, binary: impl Into<String>) -> Result<TypeDatabase>
    where
        S: ScanSource + TagSink,
    {
        let started = Instant::now();
        let (mut named_types, mut vtables, mut inferred_structs) = tokio::try_join!(
            self.scanner.scan_named_types(),
            self.vtables.detect_vtables(),
            self.strings.infer_structures(),
        )?;
        link_candidates_to_vtables(&mut inferred_structs, &vtables);
        let merged = merge_candidates(&mut inferred_structs);
        let nested = link_nested_fields(&mut named_types);
        let stl_flagged = flag_stl_types(&mut named_types, &mut vtables, &mut inferred_structs);

        let mut metadata = ScanMetadata::new(binary);
        // The engine admits its own coverage where the truth lives, beside
        // the provenance and the timing (issue #348).
        metadata.coverage = Some(coverage_stamp(vtables.len()));
        // The source names its engine and pin under `kuna` (issue #208). The three scanners share one source, so any of
        // them can answer for it.
        metadata.engine = self.scanner.source().engine_provenance();
        metadata.duration_secs = started.elapsed().as_secs();
        info!(
            binary = %metadata.binary,
            named_types = named_types.len(),
            vtables = vtables.len(),
            inferred_structs = inferred_structs.len(),
            merged_candidates = merged,
            nested_fields = nested,
            stl_flagged,
            duration_secs = metadata.duration_secs,
            "Recovered type database"
        );
        Ok(TypeDatabase {
            metadata,
            named_types,
            vtables,
            inferred_structs,
        })
    }
}

/// Link string-inferred candidates to RTTI-confirmed vtables and name them
/// from the class.
///
/// When the functions referencing a candidate's literals include methods of
/// a vtable whose RTTI chain resolved a class name, the literals most likely
/// belong to that class: the candidate records the link by vtable address,
/// takes the demangled class name — the strongest name origin — and its
/// confidence is re-scored for the stronger naming evidence. A candidate
/// matching several tables links to the one sharing the most methods; ties
/// go to the lowest address, so two scans of one program diff cleanly.
///
/// A table that is not RTTI-confirmed, or whose class name never resolved,
/// links nothing: the link exists to carry a real class name, and without
/// one there is nothing to take.
fn link_candidates_to_vtables(candidates: &mut [InferredStruct], vtables: &[Vtable]) {
    let named: Vec<&Vtable> = vtables
        .iter()
        .filter(|v| v.is_confirmed() && v.class_name.as_deref().is_some_and(|c| !c.is_empty()))
        .collect();
    for candidate in candidates.iter_mut() {
        let mut best: Option<(&Vtable, usize)> = None;
        for vtable in &named {
            let shared = candidate
                .referenced_by
                .iter()
                .filter(|function| {
                    vtable
                        .methods
                        .iter()
                        .any(|m| m.name.as_deref() == Some(function.as_str()))
                })
                .count();
            if shared > 0
                && best.is_none_or(|(previous, previous_shared)| {
                    shared > previous_shared
                        || (shared == previous_shared && vtable.address < previous.address)
                })
            {
                best = Some((vtable, shared));
            }
        }
        if let Some((vtable, _)) = best {
            // The filter above guarantees the class name; the pattern only
            // reborrow it.
            if let Some(class_name) = &vtable.class_name {
                let bump = NameOrigin::VtableClass.confidence_bonus()
                    - candidate.name_origin.confidence_bonus();
                candidate.linked_vtable = Some(vtable.address);
                candidate.name = class_name.clone();
                candidate.name_origin = NameOrigin::VtableClass;
                // Only the naming term of the score changes, so swapping the
                // two origins' payouts re-scores exactly; saturating keeps
                // the sum inside the scale before `new` clamps.
                candidate.confidence =
                    Confidence::new(candidate.confidence.value().saturating_add(bump));
            }
        }
    }
}

/// The cross-reference overlap needed to merge two candidates, as a
/// fraction of the smaller candidate's referencing-function set: half.
/// A single shared hub out of two references is enough; one out of three
/// is not, because a lone shared reader says less the more readers each
/// half has on its own.
const MERGE_OVERLAP_NUMERATOR: usize = 1;
const MERGE_OVERLAP_DENOMINATOR: usize = 2;

/// Merge candidates that describe the same struct in separate functions.
///
/// Clustering skips hub functions, so a struct whose fields are read by a
/// hub splits into half-candidates — the fields the hub shares with each
/// half cannot tie them together at the literal level. At the candidate
/// level the hub *is* evidence: two candidates whose referencing-function
/// sets overlap by at least [`MERGE_OVERLAP_NUMERATOR`] over
/// [`MERGE_OVERLAP_DENOMINATOR`] of the smaller set are read as one
/// struct, and unrelated candidates — whose sets cannot share a non-hub
/// function, since that would already have merged their literals — stay
/// separate.
///
/// The merge keeps the strongest half's name, name origin, and vtable
/// link (ties go to the lower first-field address), unions the fields in
/// literal-address order with offsets re-accumulated, and unions the
/// referencing functions. The score re-reads the merged evidence: the
/// strongest half's confidence plus the inference score's own breadth and
/// agreement payouts for the fields and functions the merge adds, so a
/// merge never scores below the half it grew from. The number of halves
/// is recorded in [`InferredStruct::merged_from`].
///
/// Candidates are visited in literal-address order and the final list is
/// re-sorted by confidence and name, so two scans of one program produce
/// identical databases. Returns how many candidates the pass folded away.
fn merge_candidates(candidates: &mut Vec<InferredStruct>) -> usize {
    if candidates.len() < 2 {
        return 0;
    }
    candidates.sort_by(|a, b| {
        first_field_address(a)
            .cmp(&first_field_address(b))
            .then_with(|| a.name.cmp(&b.name))
    });

    let mut parent: Vec<usize> = (0..candidates.len()).collect();
    for i in 0..candidates.len() {
        for j in i + 1..candidates.len() {
            if references_overlap(&candidates[i].referenced_by, &candidates[j].referenced_by) {
                union(&mut parent, i, j);
            }
        }
    }
    let mut groups: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for index in 0..candidates.len() {
        groups
            .entry(find(&mut parent, index))
            .or_default()
            .push(index);
    }

    let halves: Vec<InferredStruct> = std::mem::take(candidates);
    let mut merged = 0usize;
    for group in groups.values() {
        if group.len() > 1 {
            merged += group.len() - 1;
        }
        let members: Vec<&InferredStruct> = group.iter().map(|&index| &halves[index]).collect();
        if let Some(candidate) = merge_group(&members) {
            candidates.push(candidate);
        }
    }
    candidates.sort_by(|a, b| {
        b.confidence
            .cmp(&a.confidence)
            .then_with(|| a.name.cmp(&b.name))
    });
    merged
}

/// Whether two candidates' referencing-function sets overlap enough to
/// read them as one struct.
fn references_overlap(a: &[String], b: &[String]) -> bool {
    let shared = a.iter().filter(|function| b.contains(function)).count();
    let smaller = a.len().min(b.len());
    shared > 0 && shared * MERGE_OVERLAP_DENOMINATOR >= smaller * MERGE_OVERLAP_NUMERATOR
}

/// The lowest literal address backing a candidate, the key its halves are
/// ordered by; a candidate with no fields sorts first.
fn first_field_address(candidate: &InferredStruct) -> u64 {
    candidate
        .fields
        .first()
        .map_or(0, |field| field.source_address)
}

/// One overlap group as a single candidate. A group of one is that
/// candidate unchanged; a group of several takes the dominant half's
/// identity and unions the rest, as [`merge_candidates`] describes.
/// An empty group yields `None`; the grouping in [`merge_candidates`]
/// never produces one.
fn merge_group(members: &[&InferredStruct]) -> Option<InferredStruct> {
    let first = members.first()?;
    if members.len() == 1 {
        return Some((*first).clone());
    }
    // The dominant half: the strongest name origin, ties to the earlier
    // literal address — the order `members` already arrives in, so a
    // strict comparison keeps the first strongest.
    let dominant = members
        .iter()
        .fold(*first, |best: &InferredStruct, candidate| {
            if candidate.name_origin.confidence_bonus() > best.name_origin.confidence_bonus() {
                *candidate
            } else {
                best
            }
        });

    let mut fields: Vec<InferredField> = members
        .iter()
        .flat_map(|candidate| candidate.fields.iter().cloned())
        .collect();
    fields.sort_by(|a, b| {
        a.source_address
            .cmp(&b.source_address)
            .then_with(|| a.name.cmp(&b.name))
    });
    // Offsets re-accumulate over the merged field list exactly as
    // inference laid out one cluster's: each placed field starts on a
    // 4-byte boundary after the last.
    let mut cursor = 0u64;
    for field in fields.iter_mut() {
        field.offset = field.size.map(|size| {
            let at = cursor.div_ceil(4) * 4;
            cursor = at + size;
            at
        });
    }

    let referenced_by: BTreeSet<&String> = members
        .iter()
        .flat_map(|candidate| candidate.referenced_by.iter())
        .collect();

    // Re-score for the merged evidence with the inference score's own
    // payouts: 8 per field the merge adds past the widest half (up to
    // five counted), 5 per reader it adds past the widest half's reader
    // set (up to four counted), on top of the strongest half's score.
    let widest = members.iter().map(|c| c.fields.len()).max().unwrap_or(0);
    let breadth = fields.len().saturating_sub(widest).min(5) * 8;
    let widest_readers = members
        .iter()
        .map(|c| c.referenced_by.len())
        .max()
        .unwrap_or(0);
    let agreement = referenced_by.len().saturating_sub(widest_readers).min(4) * 5;
    let base = members
        .iter()
        .map(|c| c.confidence.value())
        .max()
        .unwrap_or(0);

    Some(InferredStruct {
        name: dominant.name.clone(),
        name_origin: dominant.name_origin,
        fields,
        confidence: Confidence::new(
            u64::from(base)
                .saturating_add(breadth as u64)
                .saturating_add(agreement as u64)
                .min(u64::from(u8::MAX)) as u8,
        ),
        referenced_by: referenced_by.into_iter().cloned().collect(),
        linked_vtable: dominant.linked_vtable,
        merged_from: Some(members.len()),
    })
}

/// The representative of `index`'s group, flattening the path on the way out.
fn find(parent: &mut [usize], mut index: usize) -> usize {
    let mut root = index;
    while parent[root] != root {
        root = parent[root];
    }
    while parent[index] != root {
        let next = parent[index];
        parent[index] = root;
        index = next;
    }
    root
}

/// Merge two candidates' groups.
fn union(parent: &mut [usize], a: usize, b: usize) {
    let (a, b) = (find(parent, a), find(parent, b));
    if a != b {
        parent[a.max(b)] = a.min(b);
    }
}

/// Link struct fields to the recovered named types they name, so a
/// recovered layout reads as a tree instead of a flat list.
///
/// A field whose `type_name` matches exactly one recovered named type
/// records that type's Type Manager path — the database's unique key,
/// since type *names* are not unique — and the linked type's kind, so a
/// field typed as a recovered union carries the union kind instead of
/// being misread as a struct. A field whose type name several recovered
/// types share stays unlinked: the field record carries no category, so
/// nothing in the scan can pick which type the field means, and a wrong
/// link would render a wrong subtree. A field typed as a primitive or a
/// type the scan never recovered simply names nothing to link.
///
/// Returns the number of fields linked, for the scan log.
fn link_nested_fields(named_types: &mut [NamedType]) -> usize {
    // Each name maps to its one type's (path, kind), or to `None` once a
    // second type shares it — the ambiguous marker.
    let mut named_by_name: BTreeMap<String, Option<(String, TypeKind)>> = BTreeMap::new();
    for named in named_types.iter() {
        match named_by_name.entry(named.name.clone()) {
            Entry::Occupied(mut entry) => *entry.get_mut() = None,
            Entry::Vacant(entry) => {
                entry.insert(Some((named.path.clone(), named.kind)));
            }
        }
    }

    let mut linked = 0;
    for named in named_types.iter_mut() {
        for field in named.fields.iter_mut() {
            if let Some(Some((path, kind))) = named_by_name.get(&field.type_name) {
                // A field never nests its own type: a by-value
                // self-reference is impossible, and a self-link would
                // render a cycle.
                if path == &named.path {
                    continue;
                }
                field.linked_type = Some(path.clone());
                field.linked_kind = Some(*kind);
                linked += 1;
            }
        }
    }
    linked
}

/// Flag every named type, vtable, and inferred field whose name matches an
/// STL/MFC shape (see [`crate::stl`]).
///
/// Flag-only: flagged records stay in every section and lookup, exactly the
/// way ADR-0009 keeps weak candidates — the flag tells the LLM what it is
/// looking at, it does not hide the record (issue #140). The pass runs last,
/// after merging and nesting, so each record is flagged once and the flag
/// lands on the record that survives rather than on a duplicate that gets
/// folded away. Returns the number of flagged records for the scan log.
fn flag_stl_types(
    named_types: &mut [NamedType],
    vtables: &mut [Vtable],
    inferred_structs: &mut [InferredStruct],
) -> usize {
    let mut flagged = 0;
    for named in named_types.iter_mut() {
        if let Some(kind) = stl::detect(&named.name) {
            named.stl_kind = Some(kind);
            flagged += 1;
        }
    }
    // RTTI-demangled class names carry the shapes the same way Type
    // Manager names do (issue #140).
    for vtable in vtables.iter_mut() {
        if let Some(class_name) = &vtable.class_name
            && let Some(kind) = stl::detect(class_name)
        {
            vtable.stl_kind = Some(kind);
            flagged += 1;
        }
    }
    for candidate in inferred_structs.iter_mut() {
        for field in candidate.fields.iter_mut() {
            // The suggested type is what the prompt entry shows, so that
            // is the string the shape has to match.
            if let Some(kind) = stl::detect(field.field_type.c_type()) {
                field.stl_kind = Some(kind);
                flagged += 1;
            }
        }
    }
    flagged
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::TypesDbError;
    use crate::stl::StlKind;
    use crate::types::{FieldType, StructField, VtableMethod};
    use calxgloss_decomp::{
        DataItem, DataTypeEntry, DecompiledFunction, EngineError, EnumDefinition, FunctionSummary,
        Result as EngineResult, StringLiteral, StructFieldLayout, StructLayout, Symbol, Xref,
    };
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use tokio::task::yield_now;

    fn le32(value: u32) -> Vec<u8> {
        value.to_le_bytes().to_vec()
    }

    fn le64(value: u64) -> Vec<u8> {
        value.to_le_bytes().to_vec()
    }

    fn entry(name: &str, category: &str, size: Option<u64>) -> DataTypeEntry {
        DataTypeEntry {
            name: name.to_string(),
            category: category.to_string(),
            size,
            path: format!("/{category}/{name}"),
        }
    }

    fn item(label: &str, address: u64, type_name: &str, length: u64) -> DataItem {
        DataItem {
            label: label.to_string(),
            address,
            type_name: type_name.to_string(),
            length,
        }
    }

    fn reference(function: &str) -> Xref {
        Xref {
            address: 0x1800_0100,
            function: Some(function.to_string()),
            kind: Some("DATA".to_string()),
        }
    }

    /// A TypeDescriptor body: the header pair plus the mangled name.
    fn type_descriptor(name: &str) -> Vec<u8> {
        let mut bytes = vec![0u8; 16];
        bytes.extend_from_slice(name.as_bytes());
        bytes.push(0);
        bytes
    }

    /// State shared by every clone of a [`FakeProgram`], so a test can read
    /// what the scans did after the engine has consumed its source.
    #[derive(Debug, Default)]
    struct Stats {
        in_flight: AtomicUsize,
        max_in_flight: AtomicUsize,
        tags: Mutex<Vec<(u64, String)>>,
    }

    /// A canned program implementing [`ScanSource`] and [`TagSink`], so the
    /// whole orchestration runs without a server. Every source call yields,
    /// the way a real HTTP call pends, which is what lets the concurrency
    /// test observe the scans overlapping.
    #[derive(Clone)]
    struct FakeProgram {
        listing: Vec<DataTypeEntry>,
        buckets: HashMap<&'static str, Vec<DataTypeEntry>>,
        layouts: HashMap<String, StructLayout>,
        enums: HashMap<String, EnumDefinition>,
        items: Vec<DataItem>,
        functions: Vec<FunctionSummary>,
        image_base: u64,
        memory: HashMap<u64, Vec<u8>>,
        literals: Vec<StringLiteral>,
        xrefs: HashMap<u64, Vec<Xref>>,
        fail_items: bool,
        stats: Arc<Stats>,
    }

    impl FakeProgram {
        fn empty() -> Self {
            Self {
                listing: Vec::new(),
                buckets: HashMap::new(),
                layouts: HashMap::new(),
                enums: HashMap::new(),
                items: Vec::new(),
                functions: Vec::new(),
                image_base: 0x1800_00000,
                memory: HashMap::new(),
                literals: Vec::new(),
                xrefs: HashMap::new(),
                fail_items: false,
                stats: Arc::new(Stats::default()),
            }
        }

        fn enter(&self) {
            let now = self.stats.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
            self.stats.max_in_flight.fetch_max(now, Ordering::SeqCst);
        }

        fn exit(&self) {
            self.stats.in_flight.fetch_sub(1, Ordering::SeqCst);
        }

        fn tagged(&self) -> Vec<(u64, String)> {
            self.stats.tags.lock().unwrap().clone()
        }
    }

    /// The canned program: one PE struct and one enum in the Type Manager,
    /// one RTTI-confirmed vtable with two methods, and a two-literal cluster
    /// that infers to a `Player` candidate.
    fn program() -> FakeProgram {
        let mut program = FakeProgram::empty();

        program.listing = vec![
            entry("IMAGE_DOS_HEADER", "pe", Some(128)),
            entry("_EXCEPTION_DISPOSITION", "excpt.h", Some(4)),
        ];
        program
            .buckets
            .insert("struct", vec![entry("IMAGE_DOS_HEADER", "pe", Some(128))]);
        program.buckets.insert(
            "enum",
            vec![entry("_EXCEPTION_DISPOSITION", "excpt.h", Some(4))],
        );
        program.layouts.insert(
            "IMAGE_DOS_HEADER".into(),
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
            },
        );
        program.enums.insert(
            "_EXCEPTION_DISPOSITION".into(),
            EnumDefinition {
                name: "_EXCEPTION_DISPOSITION".into(),
                size: 4,
                members: vec![calxgloss_decomp::EnumMember {
                    name: "ExceptionContinueExecution".into(),
                    value: 0,
                }],
            },
        );

        // vftable @ 1801306f0 preceded by its vftable_meta_ptr, whose COL
        // names the class Widget with base Base.
        program.items = vec![
            item("vftable_meta_ptr", 0x1801_306e8, "pointer", 8),
            item("vftable", 0x1801_306f0, "pointer[2]", 16),
        ];
        program.functions = vec![
            FunctionSummary {
                name: "FUN_18003ab00".into(),
                address: 0x1800_3ab00,
            },
            FunctionSummary {
                name: "FUN_18003e750".into(),
                address: 0x1800_3e750,
            },
        ];
        program.memory.insert(
            0x1801_306f0,
            [le64(0x1800_3ab00), le64(0x1800_3e750)].concat(),
        );
        program.memory.insert(0x1801_306e8, le64(0x1801_30700));
        program.memory.insert(
            0x1801_30700,
            [le32(1), le32(0), le32(0), le32(0x13_0800), le32(0x13_0900)].concat(),
        );
        program
            .memory
            .insert(0x1801_30800, type_descriptor(".?AVWidget@@"));
        program.memory.insert(
            0x1801_30900,
            [le32(0), le32(0), le32(1), le32(0x13_0a00)].concat(),
        );
        program.memory.insert(0x1801_30a00, le32(0x13_0b00));
        let mut bcd = vec![0u8; 24];
        bcd.extend_from_slice(&le32(0x13_0c00));
        bcd.extend_from_slice(&[0u8; 4]);
        program.memory.insert(0x1801_30b00, bcd);
        program
            .memory
            .insert(0x1801_30c00, type_descriptor(".?AVBase@@"));

        program.literals = vec![
            StringLiteral {
                address: 0x1801_29350,
                value: "player.x=1".into(),
            },
            StringLiteral {
                address: 0x1801_29360,
                value: "player.y=2".into(),
            },
        ];
        program
            .xrefs
            .insert(0x1801_29350, vec![reference("Player_update")]);
        program
            .xrefs
            .insert(0x1801_29360, vec![reference("Player_update")]);
        program
    }

    /// The same program, but the literals are read by the vtable's methods
    /// instead of `Player_update`, so the candidate should link to the table
    /// and take its class name.
    fn program_read_by_vtable_methods() -> FakeProgram {
        let mut program = program();
        program.xrefs.insert(
            0x1801_29350,
            vec![reference("FUN_18003ab00"), reference("FUN_18003e750")],
        );
        program
            .xrefs
            .insert(0x1801_29360, vec![reference("FUN_18003ab00")]);
        program
    }

    /// The same program, but the `Widget` fields are read across two
    /// methods plus a hub: the hub points at 25 literals, so it cannot
    /// cluster them, and the field list splits into two half-candidates
    /// that the merge pass has to stitch back together through the hub.
    fn program_split_by_a_hub() -> FakeProgram {
        let mut program = program();
        for (address, value) in [
            (0x1801_29400, "widget.width=1"),
            (0x1801_29410, "widget.height=2"),
            (0x1801_29420, "widget.label=hello"),
            (0x1801_29430, "widget.visible=true"),
        ] {
            program.literals.push(StringLiteral {
                address,
                value: value.into(),
            });
        }
        program.xrefs.insert(
            0x1801_29400,
            vec![reference("FUN_18003ab00"), reference("FUN_widget_access")],
        );
        program.xrefs.insert(
            0x1801_29410,
            vec![reference("FUN_18003ab00"), reference("FUN_widget_access")],
        );
        program.xrefs.insert(
            0x1801_29420,
            vec![reference("FUN_18003e750"), reference("FUN_widget_access")],
        );
        program.xrefs.insert(
            0x1801_29430,
            vec![reference("FUN_18003e750"), reference("FUN_widget_access")],
        );
        // 21 more literals read only by the hub: its fan-out reaches 25,
        // past the hub threshold, so it clusters none of them.
        for i in 0..21u64 {
            let address = 0x1801_29500 + 8 * i;
            program.literals.push(StringLiteral {
                address,
                value: format!("filler_{i}"),
            });
            program
                .xrefs
                .insert(address, vec![reference("FUN_widget_access")]);
        }
        program
    }

    /// The same program, plus a `WIDGET` struct whose fields name other
    /// recovered types: `MODES` (one enum), `MY_UNION` (one union), and
    /// `SHARED` (two types share the name), so the nesting pass has a
    /// unique link, a union link, and an ambiguous name to work through.
    fn program_with_nested_fields() -> FakeProgram {
        let mut program = program();
        program.listing.extend(vec![
            entry("WIDGET", "pe", Some(24)),
            entry("MODES", "excpt.h", Some(4)),
            entry("MY_UNION", "sys", Some(8)),
            entry("SHARED", "a", Some(4)),
            entry("SHARED", "b", Some(4)),
        ]);
        program.buckets.insert(
            "struct",
            vec![
                entry("IMAGE_DOS_HEADER", "pe", Some(128)),
                entry("WIDGET", "pe", Some(24)),
                entry("SHARED", "a", Some(4)),
                entry("SHARED", "b", Some(4)),
            ],
        );
        program.buckets.insert(
            "enum",
            vec![
                entry("_EXCEPTION_DISPOSITION", "excpt.h", Some(4)),
                entry("MODES", "excpt.h", Some(4)),
            ],
        );
        program
            .buckets
            .insert("union", vec![entry("MY_UNION", "sys", Some(8))]);
        program.layouts.insert(
            "WIDGET".into(),
            StructLayout {
                name: "WIDGET".into(),
                size: 24,
                alignment: 4,
                fields: vec![
                    StructFieldLayout {
                        offset: 0,
                        size: 4,
                        type_name: "MODES".into(),
                        field_name: "mode".into(),
                    },
                    StructFieldLayout {
                        offset: 4,
                        size: 8,
                        type_name: "MY_UNION".into(),
                        field_name: "payload".into(),
                    },
                    StructFieldLayout {
                        offset: 12,
                        size: 4,
                        type_name: "SHARED".into(),
                        field_name: "twin".into(),
                    },
                    StructFieldLayout {
                        offset: 16,
                        size: 4,
                        type_name: "dword".into(),
                        field_name: "raw".into(),
                    },
                ],
            },
        );
        program.layouts.insert(
            "SHARED".into(),
            StructLayout {
                name: "SHARED".into(),
                size: 4,
                alignment: 4,
                fields: Vec::new(),
            },
        );
        program.enums.insert(
            "MODES".into(),
            EnumDefinition {
                name: "MODES".into(),
                size: 4,
                members: vec![calxgloss_decomp::EnumMember {
                    name: "MODE_ON".into(),
                    value: 1,
                }],
            },
        );
        program
    }

    impl ScanSource for FakeProgram {
        async fn data_types(&self, category: Option<&str>) -> EngineResult<Vec<DataTypeEntry>> {
            self.enter();
            yield_now().await;
            self.exit();
            match category {
                None => Ok(self.listing.clone()),
                Some(word) if self.buckets.contains_key(word) => Ok(self.buckets[word].clone()),
                Some(word) => Ok(self
                    .listing
                    .iter()
                    .filter(|e| e.category.contains(word))
                    .cloned()
                    .collect()),
            }
        }

        async fn struct_layout(&self, name: &str) -> EngineResult<StructLayout> {
            self.enter();
            yield_now().await;
            self.exit();
            self.layouts
                .get(name)
                .cloned()
                .ok_or_else(|| EngineError::NotFound {
                    kind: "structure",
                    query: name.to_string(),
                })
        }

        async fn enum_values(&self, name: &str) -> EngineResult<EnumDefinition> {
            self.enter();
            yield_now().await;
            self.exit();
            self.enums
                .get(name)
                .cloned()
                .ok_or_else(|| EngineError::NotFound {
                    kind: "enumeration",
                    query: name.to_string(),
                })
        }

        async fn data_items(&self) -> EngineResult<Vec<DataItem>> {
            self.enter();
            yield_now().await;
            self.exit();
            if self.fail_items {
                return Err(EngineError::Reported {
                    message: "the engine is busy".into(),
                });
            }
            Ok(self.items.clone())
        }

        async fn functions(&self) -> EngineResult<Vec<FunctionSummary>> {
            self.enter();
            yield_now().await;
            self.exit();
            Ok(self.functions.clone())
        }

        async fn image_base(&self) -> EngineResult<u64> {
            self.enter();
            yield_now().await;
            self.exit();
            Ok(self.image_base)
        }

        async fn read_memory(&self, address: u64, _length: usize) -> EngineResult<Vec<u8>> {
            self.enter();
            yield_now().await;
            self.exit();
            self.memory
                .get(&address)
                .cloned()
                .ok_or_else(|| EngineError::NotFound {
                    kind: "memory",
                    query: format!("{address:x}"),
                })
        }

        async fn strings(&self) -> EngineResult<Vec<StringLiteral>> {
            self.enter();
            yield_now().await;
            self.exit();
            Ok(self.literals.clone())
        }

        async fn xrefs_to(&self, address: u64) -> EngineResult<Vec<Xref>> {
            self.enter();
            yield_now().await;
            self.exit();
            Ok(self.xrefs.get(&address).cloned().unwrap_or_default())
        }

        async fn decompile(&self, name: &str) -> EngineResult<DecompiledFunction> {
            Err(EngineError::NotFound {
                kind: "function",
                query: name.to_string(),
            })
        }

        async fn callers(&self, _address: u64) -> EngineResult<Vec<String>> {
            Ok(Vec::new())
        }

        async fn imports(&self) -> EngineResult<Vec<Symbol>> {
            Ok(Vec::new())
        }

        async fn exports(&self) -> EngineResult<Vec<Symbol>> {
            Ok(Vec::new())
        }
    }

    impl TagSink for FakeProgram {
        async fn add_function_tag(&self, address: u64, tag: &str) -> Result<()> {
            self.enter();
            yield_now().await;
            self.exit();
            self.stats
                .tags
                .lock()
                .unwrap()
                .push((address, tag.to_string()));
            Ok(())
        }
    }

    #[tokio::test]
    async fn scan_collects_all_three_sections() {
        let program = program();
        let db = TypesDBEngine::with_source(program.clone())
            .scan("eqmain.dll")
            .await
            .expect("scan");

        assert_eq!(db.metadata.binary, "eqmain.dll");
        assert!(db.metadata.scanned_at > 0);

        // Named types in Type Manager path order, layouts resolved.
        assert_eq!(db.named_types.len(), 2);
        assert_eq!(db.named_types[0].name, "_EXCEPTION_DISPOSITION");
        assert_eq!(
            db.named_types[0].members[0].name,
            "ExceptionContinueExecution"
        );
        assert_eq!(db.named_types[1].name, "IMAGE_DOS_HEADER");
        assert_eq!(db.named_types[1].fields[0].name, "e_magic");

        // The RTTI-confirmed vtable with its class chain and named methods.
        assert_eq!(db.vtables.len(), 1);
        let vtable = &db.vtables[0];
        assert!(vtable.is_confirmed());
        assert_eq!(vtable.class_name.as_deref(), Some("Widget"));
        assert_eq!(vtable.base_classes, vec!["Base"]);
        assert_eq!(vtable.methods.len(), 2);
        assert_eq!(vtable.methods[0].name.as_deref(), Some("FUN_18003ab00"));

        // The literal cluster as a candidate above the default threshold.
        assert_eq!(db.inferred_structs.len(), 1);
        let candidate = &db.inferred_structs[0];
        assert_eq!(candidate.name, "Player");
        assert_eq!(candidate.fields.len(), 2);
        assert!(candidate.confidence >= 40);

        // The default configuration tags confirmed vtable methods.
        let tags = program.tagged();
        assert_eq!(tags.len(), 2);
        assert!(tags.iter().all(|(_, tag)| tag == "vtable-method"));
    }

    #[tokio::test]
    async fn scan_runs_the_three_scans_concurrently() {
        // Every source call pends like an HTTP request, so a sequential
        // orchestration could never have two scans in flight at once.
        let program = program();
        TypesDBEngine::with_source(program.clone())
            .scan("eqmain.dll")
            .await
            .expect("scan");
        assert!(
            program.stats.max_in_flight.load(Ordering::SeqCst) >= 2,
            "the three scans should overlap, not run one after another"
        );
    }

    #[tokio::test]
    async fn a_failing_scan_fails_the_whole_run() {
        // Each engine degrades internally for missing data, so an error
        // here is a server failure: the run aborts rather than returning a
        // database with a silently missing section.
        let mut program = program();
        program.fail_items = true;
        let result = TypesDBEngine::with_source(program).scan("eqmain.dll").await;
        assert!(matches!(
            result,
            Err(TypesDbError::Engine(EngineError::Reported { .. }))
        ));
    }

    #[tokio::test]
    async fn an_empty_program_yields_an_empty_database() {
        let db = TypesDBEngine::with_source(FakeProgram::empty())
            .scan("nothing.dll")
            .await
            .expect("scan");
        assert!(db.is_empty());
        assert_eq!(db.metadata.binary, "nothing.dll");
        assert!(db.metadata.scanned_at > 0);
    }

    // -- admitted coverage (P19 admitted-semantics track, issue #348) -----

    /// The facet ids typesdb declares — the roster, spelled once here the
    /// way the CLI pairing pin (#342) spells its roster and the way
    /// apidetect (#346) and floatsimd (#347) spell theirs. Every facet a
    /// freshly stamped coverage record names is read against this list by
    /// the pin below, and every drift direction is a fault: a declared
    /// facet the scan stopped stamping, a facet stamped twice, and an id
    /// the scan invented outside the roster all fail loudly.
    const DECLARED_FACETS: &[&str] = &["vtables"];

    /// The data-level verdict of the roster pin: empty means the record
    /// names every declared facet exactly once, and each fault spells one
    /// drift.
    fn roster_faults(coverage: &ScanCoverage) -> Vec<String> {
        let mut faults = Vec::new();
        for declared in DECLARED_FACETS {
            let hits = coverage
                .facets
                .iter()
                .filter(|facet| facet.id == *declared)
                .count();
            if hits == 0 {
                faults.push(format!(
                    "declared facet `{declared}` is missing from the record"
                ));
            } else if hits > 1 {
                faults.push(format!(
                    "declared facet `{declared}` appears {hits} times in the record"
                ));
            }
        }
        for facet in &coverage.facets {
            if !DECLARED_FACETS.contains(&facet.id.as_str()) {
                faults.push(format!(
                    "record names `{}`, a facet the engine never declared",
                    facet.id
                ));
            }
        }
        faults
    }

    /// Runs the engine's own scan over `program`: the coverage stamp rides
    /// this call, the one definition the batch scan phase and the CLI's
    /// force-rescan both go through.
    async fn scan(program: FakeProgram) -> TypeDatabase {
        TypesDBEngine::with_source(program)
            .scan("eqmain.dll")
            .await
            .expect("scan")
    }

    #[tokio::test]
    async fn scan_stamps_coverage_naming_every_declared_facet_once() {
        let db = scan(program()).await;
        let coverage = db
            .metadata
            .coverage
            .expect("a fresh typesdb scan states its coverage");
        assert_eq!(
            coverage.status,
            CoverageStatus::Complete,
            "a fully examined target admits nothing"
        );
        assert!(
            roster_faults(&coverage).is_empty(),
            "a fresh document must name every declared facet exactly once"
        );
        let vtables = coverage
            .facets
            .iter()
            .find(|facet| facet.id == "vtables")
            .expect("vtables is named");
        assert_eq!(vtables.status, CoverageStatus::Complete);
        assert_eq!(vtables.limitation, None, "complete coverage names no limit");
    }

    #[tokio::test]
    async fn a_target_yielding_no_vtable_evidence_stamps_the_facet_unavailable_with_its_reason() {
        // The data objects the RTTI walk starts from are gone, so the walk
        // finds nothing to read — while the Type Manager listing and the
        // string clusters still carry their findings. Zero recorded vtables
        // beside a database that still names types reads as the target
        // carrying no RTTI, never as the program having no classes.
        let mut program = program();
        program.items.clear();
        let db = scan(program).await;
        assert!(
            db.vtables.is_empty(),
            "the target yields no vtable evidence"
        );
        assert_eq!(db.named_types.len(), 2, "the other scans read normally");
        assert_eq!(db.inferred_structs.len(), 1, "and so did this one");

        let coverage = db
            .metadata
            .coverage
            .expect("a fresh typesdb scan states its coverage");
        assert!(
            roster_faults(&coverage).is_empty(),
            "a scan that comes up empty still names every declared facet exactly once"
        );
        let vtables = coverage
            .facets
            .iter()
            .find(|facet| facet.id == "vtables")
            .expect("vtables is named");
        assert_eq!(vtables.status, CoverageStatus::Unavailable);
        assert_eq!(
            vtables.limitation.as_deref(),
            Some("no vtable evidence on this target"),
            "the facet that came up empty names its reason"
        );
        assert_eq!(
            coverage.status,
            CoverageStatus::Unavailable,
            "the single facet is the whole picture"
        );
        assert_eq!(
            coverage.admission().as_deref(),
            Some("unavailable — no vtable evidence on this target"),
            "what a reviewer reads is the shared type's own admission line"
        );
    }

    #[tokio::test]
    async fn the_roster_pin_fails_when_a_declared_facet_goes_missing() {
        let mut coverage = coverage_stamp(1);
        coverage.facets.clear();
        assert_eq!(
            roster_faults(&coverage),
            ["declared facet `vtables` is missing from the record"],
            "an engine quietly skipping a declared facet fails loudly"
        );
    }

    #[tokio::test]
    async fn the_roster_pin_fails_when_a_facet_is_doubled() {
        let mut coverage = coverage_stamp(1);
        coverage.facets.push(coverage.facets[0].clone());
        assert_eq!(
            roster_faults(&coverage),
            ["declared facet `vtables` appears 2 times in the record"],
            "a facet crowded into two entries fails loudly"
        );
    }

    #[tokio::test]
    async fn the_roster_pin_fails_when_coverage_names_an_orphan_facet() {
        let mut coverage = coverage_stamp(1);
        coverage.facets.push(FacetCoverage {
            id: "named-types".to_string(),
            status: CoverageStatus::Unexamined,
            limitation: None,
        });
        assert_eq!(
            roster_faults(&coverage),
            ["record names `named-types`, a facet the engine never declared"],
            "an id invented outside the declared roster fails loudly"
        );
    }

    #[tokio::test]
    async fn configuration_reaches_every_scanner() {
        let program = program();
        let db = TypesDBEngine::with_source(program.clone())
            .with_category("pe")
            .with_min_confidence(70)
            .without_tagging()
            .scan("eqmain.dll")
            .await
            .expect("scan");

        assert_eq!(
            db.named_types.len(),
            1,
            "the category filter reaches the scanner"
        );
        assert_eq!(db.named_types[0].name, "IMAGE_DOS_HEADER");
        assert!(
            db.inferred_structs.is_empty(),
            "the threshold reaches the inference engine"
        );
        assert!(program.tagged().is_empty(), "the detector stays read-only");
        assert_eq!(db.vtables.len(), 1, "detection itself still ran");
    }

    #[tokio::test]
    async fn a_candidate_read_by_vtable_methods_links_and_takes_the_class_name() {
        let db = TypesDBEngine::with_source(program_read_by_vtable_methods())
            .without_tagging()
            .scan("eqmain.dll")
            .await
            .expect("scan");

        assert_eq!(db.inferred_structs.len(), 1);
        let candidate = &db.inferred_structs[0];
        assert_eq!(
            candidate.name, "Widget",
            "the RTTI class name replaces the literal prefix"
        );
        assert_eq!(candidate.name_origin, NameOrigin::VtableClass);
        assert!(candidate.is_linked());
        assert_eq!(candidate.linked_vtable, Some(0x1801_306f0));
        let vtable = db
            .find_vtable(0x1801_306f0)
            .expect("the link names a recovered vtable");
        assert_eq!(
            candidate.name,
            vtable
                .class_name
                .as_deref()
                .expect("the canned RTTI resolves a class name")
        );
        // The cluster scored 16+10+25+20 = 71 as a literal-prefix name; the
        // vtable class origin pays 10 more.
        assert_eq!(candidate.confidence.value(), 81);
    }

    #[tokio::test]
    async fn a_candidate_outside_the_vtable_stays_unlinked() {
        // The stock program's candidate is read by `Player_update`, which is
        // not one of the table's methods: nothing links, nothing renames.
        let db = TypesDBEngine::with_source(program())
            .without_tagging()
            .scan("eqmain.dll")
            .await
            .expect("scan");
        let candidate = &db.inferred_structs[0];
        assert_eq!(candidate.name, "Player");
        assert_eq!(candidate.name_origin, NameOrigin::LiteralPrefix);
        assert!(!candidate.is_linked());
    }

    #[tokio::test]
    async fn a_struct_split_across_a_hub_merges_back_into_one_candidate() {
        let db = TypesDBEngine::with_source(program_split_by_a_hub())
            .without_tagging()
            .scan("eqmain.dll")
            .await
            .expect("scan");

        let widget = db
            .inferred_structs
            .iter()
            .find(|candidate| candidate.name == "Widget")
            .expect("the widget candidate");
        assert_eq!(widget.merged_from, Some(2), "two halves became one");
        assert_eq!(
            widget
                .fields
                .iter()
                .map(|field| field.name.as_str())
                .collect::<Vec<_>>(),
            ["width", "height", "label", "visible"],
            "the field union keeps literal-address order"
        );
        assert_eq!(
            widget.referenced_by,
            [
                "FUN_18003ab00".to_string(),
                "FUN_18003e750".to_string(),
                "FUN_widget_access".to_string()
            ]
        );
        // The linked half's vtable link and class name survive the merge.
        assert_eq!(widget.linked_vtable, Some(0x1801_306f0));
        assert_eq!(widget.name_origin, NameOrigin::VtableClass);
        // Each half scored 76 linked; the merge pays its own breadth and
        // agreement terms for what it adds: 76 + 2 fields * 8 + 1 function * 5.
        assert_eq!(widget.confidence.value(), 97);

        // The unrelated candidate, whose readers share nothing with the
        // widget's, stays separate and unmerged.
        assert_eq!(db.inferred_structs.len(), 2);
        let player = db
            .inferred_structs
            .iter()
            .find(|candidate| candidate.name == "Player")
            .expect("the player candidate");
        assert_eq!(player.merged_from, None);
        assert_eq!(player.fields.len(), 2);
    }

    #[tokio::test]
    async fn the_confidence_threshold_still_filters_with_the_merge_in_place() {
        // The hub-split halves each score 76; a threshold above that
        // filters them before they can merge, exactly as before the pass.
        let db = TypesDBEngine::with_source(program_split_by_a_hub())
            .with_min_confidence(80)
            .without_tagging()
            .scan("eqmain.dll")
            .await
            .expect("scan");
        assert!(
            db.inferred_structs.is_empty(),
            "halves below the threshold never reach the merge"
        );
    }

    fn confirmed_vtable(address: u64, class_name: Option<&str>, methods: &[&str]) -> Vtable {
        Vtable {
            address,
            label: "vftable".into(),
            size: 8 * methods.len() as u64,
            meta_ptr_address: Some(address - 8),
            methods: methods
                .iter()
                .enumerate()
                .map(|(slot, name)| VtableMethod {
                    slot,
                    address: 0,
                    name: Some((*name).into()),
                })
                .collect(),
            class_name: class_name.map(str::to_string),
            base_classes: Vec::new(),
            is_com_interface: false,
            stl_kind: None,
        }
    }

    fn address_named_candidate(referenced_by: &[&str]) -> InferredStruct {
        InferredStruct {
            name: "strings_at_180129350".into(),
            name_origin: NameOrigin::Address,
            fields: Vec::new(),
            confidence: Confidence::new(30),
            referenced_by: referenced_by.iter().map(|f| (*f).to_string()).collect(),
            linked_vtable: None,
            merged_from: None,
        }
    }

    #[test]
    fn linking_names_the_candidate_and_records_the_link() {
        let mut candidates = [address_named_candidate(&["FUN_18003ab00"])];
        let vtables = [confirmed_vtable(
            0x1801_306f0,
            Some("Widget"),
            &["FUN_18003ab00"],
        )];
        link_candidates_to_vtables(&mut candidates, &vtables);
        let candidate = &candidates[0];
        assert_eq!(candidate.name, "Widget");
        assert_eq!(candidate.name_origin, NameOrigin::VtableClass);
        assert_eq!(candidate.linked_vtable, Some(0x1801_306f0));
        // The address origin paid 0; the class name pays 35.
        assert_eq!(candidate.confidence.value(), 65);
    }

    #[test]
    fn an_unconfirmed_or_unnamed_table_links_nothing() {
        let mut unconfirmed = confirmed_vtable(0x1801_306f0, Some("Widget"), &["FUN_18003ab00"]);
        unconfirmed.meta_ptr_address = None;
        let unnamed = confirmed_vtable(0x1801_30700, None, &["FUN_18003ab00"]);
        let mut candidates = [address_named_candidate(&["FUN_18003ab00"])];
        link_candidates_to_vtables(&mut candidates, &[unconfirmed, unnamed]);
        assert!(!candidates[0].is_linked());
        assert_eq!(candidates[0].name, "strings_at_180129350");
        assert_eq!(candidates[0].confidence.value(), 30);
    }

    #[test]
    fn a_candidate_matching_several_tables_links_to_the_most_shared_methods() {
        let weak = confirmed_vtable(0x1801_306f0, Some("Weak"), &["FUN_18003ab00"]);
        let strong = confirmed_vtable(
            0x1801_30700,
            Some("Strong"),
            &["FUN_18003ab00", "FUN_18003e750"],
        );
        let mut candidates = [address_named_candidate(&["FUN_18003ab00", "FUN_18003e750"])];
        link_candidates_to_vtables(&mut candidates, &[weak, strong]);
        assert_eq!(candidates[0].name, "Strong");
        assert_eq!(candidates[0].linked_vtable, Some(0x1801_30700));
    }

    #[test]
    fn a_tie_between_tables_goes_to_the_lowest_address() {
        let low = confirmed_vtable(0x1801_306f0, Some("Low"), &["FUN_18003ab00"]);
        let high = confirmed_vtable(0x1801_30700, Some("High"), &["FUN_18003ab00"]);
        let mut candidates = [address_named_candidate(&["FUN_18003ab00"])];
        link_candidates_to_vtables(&mut candidates, &[high, low]);
        assert_eq!(candidates[0].linked_vtable, Some(0x1801_306f0));
        assert_eq!(candidates[0].name, "Low");
    }

    /// A candidate for the merge tests: fields at `addresses`, read by
    /// `referenced_by`.
    fn merge_candidate(
        name: &str,
        origin: NameOrigin,
        confidence: u8,
        addresses: &[u64],
        referenced_by: &[&str],
    ) -> InferredStruct {
        InferredStruct {
            name: name.to_string(),
            name_origin: origin,
            fields: addresses
                .iter()
                .enumerate()
                .map(|(index, &address)| InferredField {
                    name: format!("field_{index}"),
                    field_type: FieldType::Integer,
                    size: Some(4),
                    offset: Some(index as u64 * 4),
                    source_value: format!("{name}.field_{index}"),
                    source_address: address,
                    stl_kind: None,
                })
                .collect(),
            confidence: Confidence::new(confidence),
            referenced_by: referenced_by.iter().map(|f| (*f).to_string()).collect(),
            linked_vtable: None,
            merged_from: None,
        }
    }

    #[test]
    fn candidates_sharing_a_referencing_function_merge_into_one() {
        let mut candidates = vec![
            merge_candidate(
                "Widget",
                NameOrigin::LiteralPrefix,
                66,
                &[0x100, 0x108],
                &["FUN_a", "FUN_hub"],
            ),
            merge_candidate(
                "Widget",
                NameOrigin::LiteralPrefix,
                66,
                &[0x110, 0x118],
                &["FUN_b", "FUN_hub"],
            ),
        ];
        assert_eq!(merge_candidates(&mut candidates), 1);
        assert_eq!(candidates.len(), 1);
        let candidate = &candidates[0];
        assert_eq!(candidate.merged_from, Some(2));
        assert_eq!(
            candidate.referenced_by,
            [
                "FUN_a".to_string(),
                "FUN_b".to_string(),
                "FUN_hub".to_string()
            ]
        );
        assert_eq!(
            candidate
                .fields
                .iter()
                .map(|field| (field.name.as_str(), field.source_address, field.offset))
                .collect::<Vec<_>>(),
            [
                ("field_0", 0x100, Some(0)),
                ("field_1", 0x108, Some(4)),
                ("field_0", 0x110, Some(8)),
                ("field_1", 0x118, Some(12)),
            ],
            "the union keeps literal-address order and re-accumulates offsets"
        );
        // 66 plus the added breadth (2 fields * 8) and agreement (1 function * 5).
        assert_eq!(candidate.confidence.value(), 87);
    }

    #[test]
    fn a_below_threshold_overlap_keeps_candidates_separate() {
        // One shared reader out of three is not enough: a lone overlap
        // says less the more readers each half has on its own.
        let mut candidates = vec![
            merge_candidate(
                "Widget",
                NameOrigin::LiteralPrefix,
                66,
                &[0x100],
                &["FUN_a", "FUN_b", "FUN_c"],
            ),
            merge_candidate(
                "Widget",
                NameOrigin::LiteralPrefix,
                66,
                &[0x108],
                &["FUN_a", "FUN_d", "FUN_e"],
            ),
        ];
        assert_eq!(merge_candidates(&mut candidates), 0);
        assert_eq!(candidates.len(), 2);
        assert!(candidates.iter().all(|c| c.merged_from.is_none()));
    }

    #[test]
    fn an_overlap_at_the_threshold_merges() {
        // Two shared readers out of three clears the half.
        let mut candidates = vec![
            merge_candidate(
                "Widget",
                NameOrigin::LiteralPrefix,
                66,
                &[0x100],
                &["FUN_a", "FUN_b", "FUN_c"],
            ),
            merge_candidate(
                "Widget",
                NameOrigin::LiteralPrefix,
                66,
                &[0x108],
                &["FUN_a", "FUN_b", "FUN_d"],
            ),
        ];
        assert_eq!(merge_candidates(&mut candidates), 1);
        assert_eq!(candidates[0].merged_from, Some(2));
    }

    #[test]
    fn candidates_that_share_no_readers_stay_separate() {
        let mut candidates = vec![
            merge_candidate(
                "Widget",
                NameOrigin::LiteralPrefix,
                66,
                &[0x100],
                &["FUN_a"],
            ),
            merge_candidate(
                "Player",
                NameOrigin::LiteralPrefix,
                66,
                &[0x108],
                &["FUN_b"],
            ),
            merge_candidate("Strings", NameOrigin::Address, 30, &[0x110], &[]),
        ];
        assert_eq!(merge_candidates(&mut candidates), 0);
        assert_eq!(candidates.len(), 3);
    }

    #[test]
    fn the_strongest_half_names_the_merge_and_keeps_its_link() {
        let mut linked = merge_candidate(
            "Widget",
            NameOrigin::VtableClass,
            97,
            &[0x100, 0x108],
            &["FUN_m1", "FUN_hub"],
        );
        linked.linked_vtable = Some(0x1801_306f0);
        let address_named = merge_candidate(
            "strings_at_180129410",
            NameOrigin::Address,
            40,
            &[0x110],
            &["FUN_b", "FUN_hub"],
        );
        let mut candidates = vec![address_named, linked];
        merge_candidates(&mut candidates);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].name, "Widget");
        assert_eq!(candidates[0].name_origin, NameOrigin::VtableClass);
        assert_eq!(candidates[0].linked_vtable, Some(0x1801_306f0));
    }

    #[test]
    fn when_both_halves_are_linked_the_earlier_address_keeps_its_link() {
        let mut early = merge_candidate(
            "Widget",
            NameOrigin::LiteralPrefix,
            66,
            &[0x100],
            &["FUN_a", "FUN_hub"],
        );
        early.linked_vtable = Some(0x1801_306f0);
        let mut late = merge_candidate(
            "Widget",
            NameOrigin::LiteralPrefix,
            66,
            &[0x200],
            &["FUN_b", "FUN_hub"],
        );
        late.linked_vtable = Some(0x1801_30700);
        let mut candidates = vec![late.clone(), early.clone()];
        merge_candidates(&mut candidates);
        assert_eq!(candidates[0].linked_vtable, Some(0x1801_306f0));
    }

    #[test]
    fn the_merge_does_not_depend_on_input_order() {
        let first = merge_candidate(
            "Widget",
            NameOrigin::LiteralPrefix,
            66,
            &[0x100, 0x108],
            &["FUN_a", "FUN_hub"],
        );
        let second = merge_candidate(
            "Widget",
            NameOrigin::VtableClass,
            76,
            &[0x110],
            &["FUN_b", "FUN_hub"],
        );
        let mut forwards = vec![first.clone(), second.clone()];
        let mut backwards = vec![second.clone(), first.clone()];
        merge_candidates(&mut forwards);
        merge_candidates(&mut backwards);
        assert_eq!(forwards, backwards, "two scans merge in one order");
    }

    // ------------------------------------------------------------
    // Linking nested struct fields to their recovered types
    // ------------------------------------------------------------

    /// A struct named `name` in `category` with one field per
    /// `(field name, type name)` pair, links not yet filled in.
    fn nesting_struct(name: &str, category: &str, fields: &[(&str, &str)]) -> NamedType {
        let mut named = NamedType::from_listing(&entry(name, category, None), TypeKind::Struct);
        named.fields = fields
            .iter()
            .map(|(field_name, type_name)| StructField {
                name: (*field_name).into(),
                offset: 0,
                size: 4,
                type_name: (*type_name).into(),
                linked_type: None,
                linked_kind: None,
            })
            .collect();
        named
    }

    #[test]
    fn a_field_naming_one_recovered_type_links_to_its_path() {
        let mut types = vec![
            nesting_struct("WIDGET", "pe", &[("mode", "MODES")]),
            NamedType::from_listing(&entry("MODES", "excpt.h", Some(4)), TypeKind::Enum),
        ];
        let linked = link_nested_fields(&mut types);

        assert_eq!(linked, 1);
        let field = &types[0].fields[0];
        assert_eq!(field.linked_type.as_deref(), Some("/excpt.h/MODES"));
        assert_eq!(field.linked_kind, Some(TypeKind::Enum));
        assert!(field.is_nested());
    }

    #[test]
    fn a_field_naming_several_recovered_types_stays_unlinked() {
        // Paths, not names, are the unique keys: a name two recovered
        // types share names no single type, so the field gets no link.
        let mut types = vec![
            nesting_struct("WIDGET", "pe", &[("twin", "SHARED")]),
            NamedType::from_listing(&entry("SHARED", "a", Some(4)), TypeKind::Struct),
            NamedType::from_listing(&entry("SHARED", "b", Some(4)), TypeKind::Struct),
        ];
        let linked = link_nested_fields(&mut types);

        assert_eq!(linked, 0);
        assert_eq!(types[0].fields[0].linked_type, None);
        assert_eq!(types[0].fields[0].linked_kind, None);
    }

    #[test]
    fn a_field_naming_a_recovered_union_carries_the_union_kind() {
        let mut types = vec![
            nesting_struct("WIDGET", "pe", &[("payload", "MY_UNION")]),
            NamedType::from_listing(&entry("MY_UNION", "sys", Some(8)), TypeKind::Union),
        ];
        let linked = link_nested_fields(&mut types);

        assert_eq!(linked, 1);
        assert_eq!(types[0].fields[0].linked_kind, Some(TypeKind::Union));
    }

    #[test]
    fn a_field_naming_nothing_recovered_stays_unlinked() {
        // Primitives and types the scan never recovered name nothing to
        // link; the field keeps its bare type name.
        let mut types = vec![nesting_struct(
            "IMAGE_DOS_HEADER",
            "pe",
            &[("e_magic", "char[2]"), ("e_lfanew", "dword")],
        )];
        let linked = link_nested_fields(&mut types);

        assert_eq!(linked, 0);
        assert!(types[0].fields.iter().all(|f| !f.is_nested()));
    }

    #[test]
    fn a_field_naming_its_own_type_stays_unlinked() {
        // A field never nests its own type — a self-link would render a
        // cycle — even when the owner is the only recovered type of
        // that name.
        let mut types = vec![nesting_struct("WIDGET", "pe", &[("twin", "WIDGET")])];
        let linked = link_nested_fields(&mut types);

        assert_eq!(linked, 0);
        assert_eq!(types[0].fields[0].linked_type, None);
    }

    #[tokio::test]
    async fn a_scan_links_fields_that_name_recovered_types() {
        let db = TypesDBEngine::with_source(program_with_nested_fields())
            .without_tagging()
            .scan("eqmain.dll")
            .await
            .expect("scan");

        let widget = db
            .find_named_type("/pe/WIDGET")
            .expect("the canned widget struct");
        let field = |name: &str| {
            widget
                .fields
                .iter()
                .find(|f| f.name == name)
                .unwrap_or_else(|| panic!("the widget should carry a `{name}` field"))
        };

        assert_eq!(field("mode").linked_type.as_deref(), Some("/excpt.h/MODES"));
        assert_eq!(field("mode").linked_kind, Some(TypeKind::Enum));
        assert_eq!(
            field("payload").linked_type.as_deref(),
            Some("/sys/MY_UNION")
        );
        assert_eq!(
            field("payload").linked_kind,
            Some(TypeKind::Union),
            "a union-typed field carries the union kind"
        );
        assert_eq!(
            field("twin").linked_type,
            None,
            "an ambiguous name stays unlinked"
        );
        assert_eq!(
            field("raw").linked_type,
            None,
            "a primitive names nothing to link"
        );
    }

    // ------------------------------------------------------------
    // Flagging STL/MFC shapes (issue #140)
    // ------------------------------------------------------------

    #[test]
    fn the_flag_pass_marks_types_vtables_and_inferred_fields() {
        let mut types = vec![
            NamedType::from_listing(
                &entry("std::vector<CWidget>", "pe", Some(24)),
                TypeKind::Class,
            ),
            NamedType::from_listing(&entry("CWidget", "pe", Some(8)), TypeKind::Class),
        ];
        let mut vtables = vec![
            confirmed_vtable(0x1801_306f0, Some("std::basic_string<char>"), &["FUN_1"]),
            confirmed_vtable(0x1801_30700, Some("CWidget"), &["FUN_2"]),
            confirmed_vtable(0x1801_30710, None, &["FUN_3"]),
        ];
        let mut candidates = vec![InferredStruct {
            name: "strings_at_180129350".into(),
            name_origin: NameOrigin::Address,
            fields: vec![
                InferredField {
                    name: "label".into(),
                    field_type: FieldType::String,
                    size: Some(8),
                    offset: None,
                    source_value: "Player".into(),
                    source_address: 0x1801_29350,
                    stl_kind: None,
                },
                InferredField {
                    name: "count".into(),
                    field_type: FieldType::Integer,
                    size: Some(4),
                    offset: None,
                    source_value: "42".into(),
                    source_address: 0x1801_29360,
                    stl_kind: None,
                },
            ],
            confidence: Confidence::new(50),
            referenced_by: vec!["FUN_18000b620".into()],
            linked_vtable: None,
            merged_from: None,
        }];

        let flagged = flag_stl_types(&mut types, &mut vtables, &mut candidates);

        assert_eq!(flagged, 3, "one type, one vtable, one field");
        assert_eq!(types[0].stl_kind, Some(StlKind::Vector));
        assert_eq!(types[1].stl_kind, None, "a plain class stays unflagged");
        assert_eq!(vtables[0].stl_kind, Some(StlKind::String));
        assert_eq!(vtables[1].stl_kind, None);
        assert_eq!(
            vtables[2].stl_kind, None,
            "a table whose class name never resolved flags nothing"
        );
        assert_eq!(
            candidates[0].fields[0].stl_kind,
            Some(StlKind::String),
            "the suggested `char *` is a string shape"
        );
        assert_eq!(candidates[0].fields[1].stl_kind, None);
    }

    #[test]
    fn flagging_leaves_records_in_place() {
        // Flag-only (issue #140): the pass marks records, it never removes
        // or reorders them.
        let mut types = vec![
            NamedType::from_listing(&entry("CWidget", "pe", Some(8)), TypeKind::Class),
            NamedType::from_listing(&entry("std::list<int>", "pe", Some(16)), TypeKind::Class),
        ];
        let before: Vec<String> = types.iter().map(|t| t.path.clone()).collect();
        let flagged = flag_stl_types(&mut types, &mut [], &mut []);

        assert_eq!(flagged, 1);
        assert_eq!(
            types.iter().map(|t| t.path.clone()).collect::<Vec<_>>(),
            before
        );
    }
}
