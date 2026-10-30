//! Type database recovery orchestration.
//!
//! [`TypesDBEngine`] runs the three recovery scans — named type recovery,
//! vtable detection, and string-guided inference — concurrently against one
//! loaded program and assembles their results into a single
//! [`TypeDatabase`] with its scan provenance.
//!
//! The three scans read disjoint seam reads (`data_types()`,
//! `data_items()` + `read_memory()`, and `strings()` + `xrefs_to()`),
//! so they run as concurrent tasks rather than one after another. Each scan
//! already degrades internally for missing or malformed data, so an error
//! surfacing here means the analysis engine itself failed mid-scan; the
//! orchestration aborts with that error rather than returning a database
//! whose sections were built against different programs or different moments.
//!
//! After the scans, a pure in-memory pass links string-inferred candidates
//! to RTTI-confirmed vtables: a candidate whose referencing functions include
//! a confirmed table's methods takes that table's demangled class name and
//! records the link. A second pass then merges candidates whose referencing
//! functions overlap — one struct read by a hub function splits into half-
//! candidates, and the two halves' overlap at the hub is what shows them as
//! one struct. The merge keeps the stronger half's name and link and unions
//! the fields. A third pass links struct fields to the recovered named types
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
/// so this crate's generic scanners keep naming it directly;
/// [`KunaSource`] implements it over the in-process analysis engine, and
/// tests implement it over canned listings so the orchestration runs
/// without a server. The futures are `Send` so a scan can be driven from
/// an orchestrating task.
pub use calxgloss_decomp::ScanSource;

/// The facet ids typesdb declares — the roster, spelled once here the
/// way the CLI pairing pin (#342) spells its roster and the way
/// apidetect (#346) and floatsimd (#347) spell theirs. The pin below
/// reads every facet id a freshly stamped coverage record names against
/// this list. Every drift is a fault and fails loudly: a declared facet
/// the scan stopped stamping, a facet stamped twice, and an id the scan
/// invented outside the roster.
pub const DECLARED_FACETS: &[&str] = &["vtables"];

/// The coverage record every typesdb scan stamps about itself (issue
/// #348), beside the provenance and the timing.
///
/// typesdb has one facet it can come up empty on: `vtables`, the RTTI
/// walk that recovers a class's method table. A target built without RTTI
/// (a stripped release build, a non-MSVC binary) yields nothing for the
/// detector to find, and zero recorded vtables is then a property of the
/// target, not of the program's shape — so the facet is `unavailable` with
/// that reason rather than a quiet zero. A scan that found at least one
/// table read the walk end to end, so the facet is `complete`. The named
/// types and string-inferred candidates beside it are unaffected either
/// way. The whole picture mirrors the single facet: over a vtable, this
/// scan examines nothing else (the P19-4 admitted-semantics track).
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

/// Orchestrates the three recovery scans into one [`TypeDatabase`].
///
/// TypesDBEngine is generic over the same source traits as the scanners
/// it drives, so tests can run the whole orchestration over canned
/// responses; [`new`](Self::new) builds one over a loaded [`KunaSource`].
#[derive(Debug, Clone)]
pub struct TypesDBEngine<S = KunaSource> {
    scanner: TypeLibraryScanner<S>,
    vtables: VtableDetector<S>,
    strings: StringInferenceEngine<S>,
}

impl TypesDBEngine<KunaSource> {
    /// A TypesDBEngine over a loaded Kuna program.
    pub fn new(source: &KunaSource) -> TypesDBEngine<KunaSource> {
        TypesDBEngine {
            scanner: TypeLibraryScanner::new(source),
            vtables: VtableDetector::new(source),
            strings: StringInferenceEngine::new(source),
        }
    }
}

impl<S> TypesDBEngine<S> {
    /// A TypesDBEngine whose three scanners share one source.
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

    /// Filter the string listing by this regular expression.
    pub fn with_string_filter(mut self, pattern: impl Into<String>) -> Self {
        self.strings = self.strings.with_string_filter(pattern);
        self
    }

    /// Report only inferred candidates whose evidence confidence scores
    /// `threshold` or higher.
    pub fn with_min_confidence(mut self, threshold: u8) -> Self {
        self.strings = self.strings.with_min_confidence(threshold);
        self
    }

    /// Report inferred candidates with at least `count` fields.
    pub fn with_min_fields(mut self, count: usize) -> Self {
        self.strings = self.strings.with_min_fields(count);
        self
    }

    /// Assume `pointer_size` for vtable entries and text-typed fields.
    /// One program has one pointer size, so this setting reaches both
    /// scanners.
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
        // The orchestration stamps its own coverage where the truth
        // lives, beside the provenance and the timing (issue #348).
        metadata.coverage = Some(coverage_stamp(vtables.len()));
        // The source names its analysis engine and its pinned release
        // under `kuna` (issue #208). The three scanners share one
        // source, so any of them can answer for it.
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
/// evidence confidence is re-scored for the stronger naming evidence. A
/// candidate matching several tables links to the one sharing the most
/// methods; ties go to the lowest address, so two scans of one program diff
/// cleanly.
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
/// strongest half's evidence confidence plus the inference score's own
/// breadth and agreement payouts for the fields and functions the merge
/// adds, so a merge never scores below the half it grew from. The number
/// of halves is recorded in [`InferredStruct::merged_from`].
///
/// Candidates are visited in literal-address order and the final list is
/// re-sorted by evidence confidence and name, so two scans of one program
/// produce identical databases. Returns how many candidates the merge
/// removed.
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
    // payouts, on top of the strongest half's evidence confidence: 8 per
    // field the merge adds past the widest half (up to five counted),
    // and 5 per reader it adds past the widest half's reader set (up to
    // four counted).
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
/// looking at but does not hide the record (issue #140). The pass runs last,
/// after merging and nesting, so each record is flagged once: the flag marks
/// the record that survives, not a duplicate the merge removed. Returns the
/// number of flagged records for the scan log.
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
    // RTTI-demangled class names match the shapes the same way Type
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
mod tests;
