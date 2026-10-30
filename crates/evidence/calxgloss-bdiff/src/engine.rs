//! The pairing pass: pure text and structure over two in-memory scan
//! snapshots — documents in, one pairing document out.
//!
//! [`pair_versions`] is the crate's whole pass: it adds no `ScanSource`
//! methods (ADR-0026 stays untouched), reads nothing from the analysis
//! engine, writes nothing back to any program (ADR-0020), and runs no
//! LLM — a version diff costs milliseconds, not dollars. The pass runs
//! the match ladder (track #233).
//!
//! First, name identity: an exported name or a demangled name present
//! in both versions pairs the old function to the new at
//! [`crate::types::NAME_IDENTITY_CONFIDENCE`].
//!
//! Second, the normalized-body family: kept bodies go through the
//! shared libmatch normalizer (#294's public cross-crate rule — one
//! shared rule, one owner, never a second normalizer). Byte-equal
//! shapes pair at [`crate::types::BODY_EQUAL_CONFIDENCE`].
//!
//! Third, call-graph topology propagation (#297). The call map is
//! derived purely from the bodies the two snapshots carry (ADR-0024's
//! rails — no new reads). A function the first two families left
//! unpaired pairs when its callers and callees agree through already-
//! paired neighbors. The pass repeats this to a fixed point, so chains
//! of renamed functions pair through neighbors that converged
//! themselves. A claim requires at least
//! [`crate::types::TOPOLOGY_MIN_PAIRED_NEIGHBORS`] paired neighbors — a
//! lone paired neighbor claims nothing — scores
//! [`crate::types::TOPOLOGY_CONFIDENCE`], below the carry-over floor on
//! its own, and names its paired-neighbor evidence lines. When
//! topology instead corroborates a body-family pair, the flag-family
//! agreement precedent applies (P12.6 — agreement beats any single
//! reading): the body record gains
//! [`crate::types::TOPOLOGY_AGREEMENT_BUMP`].
//!
//! A lone signal claims nothing (ADR-0038): address equality pairs
//! nothing on its own, and neither does a matching address-derived
//! `FUN_…` spelling — that spelling *is* an address, so pairing on it
//! would pair on the lone relocation signal the rail exists to refuse.
//!
//! Pairings resolve one-to-one: each function pairs at most once per
//! side, the best score wins (ADR-0022's strongest-claim-wins rule),
//! and a tie keeps the first-seen pairing in scan order (ADR-0028's
//! positional precedent), so two documents of one version pair diff
//! cleanly and a candidate's second-best pairing is dropped.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use calxgloss_libmatch::normalize::normalize_lines;

use crate::error::{BdiffError, Result};
use crate::types::{
    BODY_EQUAL_CONFIDENCE, BODY_SIMILARITY_FLOOR, FunctionEntry, MatchFamily,
    NAME_IDENTITY_CONFIDENCE, PairingDocument, PairingRecord, ScanSnapshot,
    TOPOLOGY_AGREEMENT_BUMP, TOPOLOGY_CONFIDENCE, TOPOLOGY_MIN_PAIRED_NEIGHBORS,
};

/// Pair the old scan snapshot against the new one of one binary
/// identity and emit the pairing document.
///
/// The two snapshots must name the same [`calxgloss_types::BinaryIdentity`]
/// — the pass pairs *versions of one binary*, and mixing identities is a
/// caller error. It refuses the call instead of guessing at a pairing.
/// The emitted document names both snapshots' byte hashes and both full
/// function listings; its pairings stand in old scan order.
///
/// # Errors
///
/// Returns [`BdiffError::IdentityMismatch`] when the snapshots name
/// different binary identities.
pub fn pair_versions(old: &ScanSnapshot, new: &ScanSnapshot) -> Result<PairingDocument> {
    if old.binary != new.binary {
        return Err(BdiffError::IdentityMismatch {
            old: old.binary.as_str().to_string(),
            new: new.binary.as_str().to_string(),
        });
    }

    tracing::debug!(
        binary = %old.binary,
        old_hash = %old.bytes_sha256,
        new_hash = %new.bytes_sha256,
        old_functions = old.functions.len(),
        new_functions = new.functions.len(),
        "Pairing binary versions"
    );

    let mut candidates = name_identity_candidates(old, new);
    candidates.extend(body_candidates(old, new));
    let mut winners = resolve_one_to_one(candidates, &old.functions, &new.functions);

    // The ladder's third band (#297): the call map is derived only from
    // the bodies the two snapshots carry — no analysis-engine read
    // anywhere in the pass (ADR-0024's rails, ADR-0026 intact).
    let old_map = call_map(old);
    let new_map = call_map(new);
    propagate_topology(&mut winners, old, new, &old_map, &new_map);
    corroborate_body_pairs(&mut winners, old, new, &old_map, &new_map);
    winners.sort_by_key(|(old_index, new_index, _)| (*old_index, *new_index));

    Ok(PairingDocument {
        binary: old.binary.as_str().to_string(),
        old_bytes_sha256: old.bytes_sha256.clone(),
        new_bytes_sha256: new.bytes_sha256.clone(),
        old_functions: old.function_names(),
        new_functions: new.function_names(),
        pairings: winners.into_iter().map(|(_, _, record)| record).collect(),
    })
}

/// A proposed pairing before one-to-one resolution: indices into the
/// snapshots' function listings (the pass resolves ties by scan order),
/// beside the score and evidence the winning family would record.
struct Candidate {
    old: usize,
    new: usize,
    confidence: u8,
    family: MatchFamily,
    evidence: Vec<String>,
}

/// Collect every name-identity candidate pair, in scan order.
///
/// A pair is a candidate when the two listings spell one function the
/// same name *and* that spelling is the binary's own — an export-table
/// name present in both versions, or a name carrying the demangler's
/// spelling. Address-derived `FUN_…` matches and plain internal symbol
/// matches stay out of the family: on this ladder they are lone
/// signals, and a lone signal claims nothing (ADR-0038).
fn name_identity_candidates(old: &ScanSnapshot, new: &ScanSnapshot) -> Vec<Candidate> {
    let shared_exports: HashSet<&str> = old
        .exports
        .iter()
        .map(String::as_str)
        .filter(|name| new.exports.iter().any(|export| export == *name))
        .collect();

    let mut new_by_name: HashMap<&str, Vec<usize>> = HashMap::new();
    for (index, entry) in new.functions.iter().enumerate() {
        new_by_name
            .entry(entry.name.as_str())
            .or_default()
            .push(index);
    }

    let mut candidates = Vec::new();
    for (old_index, entry) in old.functions.iter().enumerate() {
        let name = entry.name.as_str();
        let Some(new_indexes) = new_by_name.get(name) else {
            continue;
        };
        // The exported candidate comes first, so an exported name that
        // also reads as demangled keeps the export's evidence — the
        // same pair claimed twice still resolves to one record, and the
        // first-seen claim stands (both readings score the same band).
        if shared_exports.contains(name) {
            for &new_index in new_indexes {
                candidates.push(Candidate {
                    old: old_index,
                    new: new_index,
                    confidence: NAME_IDENTITY_CONFIDENCE,
                    family: MatchFamily::NameIdentity,
                    evidence: vec![format!("exported name {name}")],
                });
            }
        }
        if carries_demangled_spelling(name) {
            for &new_index in new_indexes {
                candidates.push(Candidate {
                    old: old_index,
                    new: new_index,
                    confidence: NAME_IDENTITY_CONFIDENCE,
                    family: MatchFamily::NameIdentity,
                    evidence: vec![format!("demangled name {name}")],
                });
            }
        }
    }
    candidates
}

/// Whether a listing name carries the demangler's spelling — the
/// `::`-qualified chains and spelled parameter lists the decompiler
/// writes for C++ and Rust symbols, the demangled `operator.` dot form,
/// and `~`-prefixed destructors. This name-shape reading follows the
/// same precedent as ADR-0012's flagging-by-name-shape pass.
///
/// An address-derived `FUN_…` spelling is refused outright: it is an
/// address written as a name, and pairing on it would rely on the lone
/// relocation signal the rail refuses (ADR-0038).
fn carries_demangled_spelling(name: &str) -> bool {
    if name.starts_with("FUN_") {
        return false;
    }
    name.contains("::")
        || name.starts_with("operator")
        || name.starts_with('~')
        || (name.ends_with(')') && name.contains('('))
}

/// How many of a near-equal pair's line edits the evidence quotes.
/// That is enough for a quick audit of what the diff looks like, and it
/// keeps the pairing document from filling with quoted text. The
/// summary line always names the full edit count.
const MAX_QUOTED_EDITS: usize = 3;

/// The shared normalizer's shape of one kept body: the normalized line
/// sequence, whitespace-collapsed. This is what "same body shape" means
/// corpus-wide. The pairing tests use this rule without re-testing it —
/// the normalizer's contract stays pinned where it lives, in libmatch
/// (#294).
fn normalized_shape(body: &str) -> Vec<String> {
    normalize_lines(body)
        .into_iter()
        .map(|(_original, normalized)| normalized)
        .collect()
}

/// Whether a normalized shape holds nothing. A kept body that is blank
/// normalizes to blank lines, and equality between two blank shapes
/// says nothing: claiming it would pair on a lone structural
/// coincidence (ADR-0038).
fn is_blank(shape: &[String]) -> bool {
    shape.iter().all(|line| line.is_empty())
}

/// Collect every normalized-body candidate pair, in scan order.
///
/// A pair is a candidate when the two kept bodies, put through the
/// shared normalizer, come out one shape. Byte-equal shapes pair at
/// [`BODY_EQUAL_CONFIDENCE`]. A pair whose shapes differ only in line
/// edits scores on its structural-diff ratio beside that band — every
/// edit is a line that changed, was added, or was removed, and the
/// evidence line summarizes the diff and quotes it. A pair below
/// [`BODY_SIMILARITY_FLOOR`] similarity is a clearly different body: a
/// coincidence of listing rather than a moved function, and it claims
/// nothing (ADR-0038 again).
fn body_candidates(old: &ScanSnapshot, new: &ScanSnapshot) -> Vec<Candidate> {
    let old_shapes: Vec<Vec<String>> = old
        .functions
        .iter()
        .map(|entry| normalized_shape(&entry.body))
        .collect();
    let new_shapes: Vec<Vec<String>> = new
        .functions
        .iter()
        .map(|entry| normalized_shape(&entry.body))
        .collect();
    let old_joined: Vec<String> = old_shapes.iter().map(|shape| shape.join("\n")).collect();
    let new_joined: Vec<String> = new_shapes.iter().map(|shape| shape.join("\n")).collect();
    let old_blank: Vec<bool> = old_shapes.iter().map(|shape| is_blank(shape)).collect();
    let new_blank: Vec<bool> = new_shapes.iter().map(|shape| is_blank(shape)).collect();

    let mut new_by_shape: HashMap<&str, Vec<usize>> = HashMap::new();
    for (new_index, joined) in new_joined.iter().enumerate() {
        if new_blank[new_index] {
            continue;
        }
        new_by_shape
            .entry(joined.as_str())
            .or_default()
            .push(new_index);
    }

    let mut candidates = Vec::new();
    for (old_index, joined) in old_joined.iter().enumerate() {
        if old_blank[old_index] {
            continue;
        }
        let Some(new_indexes) = new_by_shape.get(joined.as_str()) else {
            continue;
        };
        for &new_index in new_indexes {
            candidates.push(Candidate {
                old: old_index,
                new: new_index,
                confidence: BODY_EQUAL_CONFIDENCE,
                family: MatchFamily::NormalizedBody,
                evidence: vec![format!(
                    "normalized bodies are byte-equal ({} lines)",
                    old_shapes[old_index].len()
                )],
            });
        }
    }

    for (old_index, old_shape) in old_shapes.iter().enumerate() {
        if old_blank[old_index] {
            continue;
        }
        for (new_index, new_shape) in new_shapes.iter().enumerate() {
            if new_blank[new_index] || old_joined[old_index] == new_joined[new_index] {
                continue; // byte-equal pairs already claimed above
            }
            let max_lines = old_shape.len().max(new_shape.len());
            // Cost model (this pass owes milliseconds, not dollars):
            // one edit costs at least the line-count gap, so a pair
            // whose line-count gap alone puts it below the floor never
            // reaches the diff matrix.
            let gap = old_shape.len().abs_diff(new_shape.len());
            if 100 - (100 * gap) / max_lines < BODY_SIMILARITY_FLOOR as usize {
                continue;
            }
            let (edits, ops) = line_edits(old_shape, new_shape);
            let similarity = 100 - (100 * edits) / max_lines;
            if similarity < BODY_SIMILARITY_FLOOR as usize {
                continue; // clearly different bodies claim nothing (ADR-0038)
            }
            // Round the penalty up so a near-equal pair can never land
            // on the byte-equal 90 itself: one edit always costs a band.
            let penalty = (10 * edits).div_ceil(max_lines);
            let mut evidence = vec![format!(
                "normalized body diff: {edits} of {max_lines} lines differ ({similarity}% similar)"
            )];
            for edit in ops.iter().take(MAX_QUOTED_EDITS) {
                match edit {
                    BodyEdit::Replace { old, new } => {
                        evidence.push(format!("changed: {old} -> {new}"));
                    }
                    BodyEdit::Delete { old } => evidence.push(format!("removed: {old}")),
                    BodyEdit::Insert { new } => evidence.push(format!("added: {new}")),
                }
            }
            if ops.len() > MAX_QUOTED_EDITS {
                evidence.push(format!("(+{} more edits)", ops.len() - MAX_QUOTED_EDITS));
            }
            candidates.push(Candidate {
                old: old_index,
                new: new_index,
                confidence: BODY_EQUAL_CONFIDENCE - penalty as u8,
                family: MatchFamily::NormalizedBody,
                evidence,
            });
        }
    }
    candidates
}

/// One line edit between two normalized bodies. This is what an
/// engineer reads to audit why a near-equal pair was judged one
/// function.
enum BodyEdit {
    /// One old line became one new line.
    Replace { old: String, new: String },
    /// One old line is gone from the new body.
    Delete { old: String },
    /// One new line is absent from the old body.
    Insert { new: String },
}

/// Levenshtein edits between two normalized line sequences. The result
/// is the edit count beside the edits themselves, in body order — each
/// changed, added, or removed line once. This uses the full distance
/// matrix, backtraced. The bodies are decompiled functions of tens of
/// lines, and the evidence quotes the edits, so the count and the
/// edits are computed together.
fn line_edits(old: &[String], new: &[String]) -> (usize, Vec<BodyEdit>) {
    let mut distance: Vec<Vec<usize>> = vec![vec![0; new.len() + 1]; old.len() + 1];
    for (row, cell) in distance.iter_mut().enumerate() {
        cell[0] = row;
    }
    distance[0] = (0..=new.len()).collect();
    for (i, old_line) in old.iter().enumerate() {
        for (j, new_line) in new.iter().enumerate() {
            distance[i + 1][j + 1] = if old_line == new_line {
                distance[i][j]
            } else {
                distance[i][j]
                    .min(distance[i][j + 1])
                    .min(distance[i + 1][j])
                    + 1
            };
        }
    }

    let mut edits = Vec::new();
    let (mut i, mut j) = (old.len(), new.len());
    while i > 0 || j > 0 {
        if i > 0 && j > 0 && old[i - 1] == new[j - 1] {
            i -= 1;
            j -= 1;
            continue;
        }
        let substitution = if i > 0 && j > 0 {
            distance[i - 1][j - 1]
        } else {
            usize::MAX
        };
        let deletion = if i > 0 {
            distance[i - 1][j]
        } else {
            usize::MAX
        };
        let insertion = if j > 0 {
            distance[i][j - 1]
        } else {
            usize::MAX
        };
        if substitution <= deletion && substitution <= insertion {
            edits.push(BodyEdit::Replace {
                old: old[i - 1].clone(),
                new: new[j - 1].clone(),
            });
            i -= 1;
            j -= 1;
        } else if deletion <= insertion {
            edits.push(BodyEdit::Delete {
                old: old[i - 1].clone(),
            });
            i -= 1;
        } else {
            edits.push(BodyEdit::Insert {
                new: new[j - 1].clone(),
            });
            j -= 1;
        }
    }
    edits.reverse();
    (distance[old.len()][new.len()], edits)
}

/// Resolve candidate pairs down to one pairing per function per side.
///
/// Highest score wins, and a tie keeps the first-seen pairing in scan
/// order. Candidate generation stands in old-then-new scan order, and
/// the sort is stable, so a candidate earlier in the scan beats a later
/// one at the same score. A candidate's second-best pairing is dropped
/// once its side is taken (ADR-0022's strongest-claim-wins,
/// ADR-0028's positional tie rule). Surviving `(old, new, record)`
/// triples come back in old scan order so two documents of one version
/// pair diff cleanly, and the topology band can build on the resolved
/// pairs by index.
fn resolve_one_to_one(
    candidates: Vec<Candidate>,
    old_entries: &[FunctionEntry],
    new_entries: &[FunctionEntry],
) -> Vec<(usize, usize, PairingRecord)> {
    let mut ordered = candidates;
    ordered.sort_by_key(|candidate| std::cmp::Reverse(candidate.confidence));

    let mut old_taken: HashSet<usize> = HashSet::new();
    let mut new_taken: HashSet<usize> = HashSet::new();
    let mut winners: Vec<(usize, usize, PairingRecord)> = Vec::new();
    for candidate in ordered {
        if old_taken.contains(&candidate.old) || new_taken.contains(&candidate.new) {
            continue;
        }
        old_taken.insert(candidate.old);
        new_taken.insert(candidate.new);
        winners.push((
            candidate.old,
            candidate.new,
            PairingRecord {
                old_function: old_entries[candidate.old].name.clone(),
                new_function: new_entries[candidate.new].name.clone(),
                family: candidate.family,
                confidence: candidate.confidence.into(),
                evidence: candidate.evidence,
            },
        ));
    }
    winners.sort_by_key(|(old, new, _)| (*old, *new));
    winners
}

// ------------------------------------------------------------
// Call-graph topology propagation (#297, the ladder's third band)
// ------------------------------------------------------------

/// How many paired neighbors a topology record's evidence quotes. The
/// body family's `MAX_QUOTED_EDITS` precedent applies again: quote the
/// first few neighbors for a quick audit, and name the remainder by
/// count.
const MAX_QUOTED_NEIGHBORS: usize = 3;

/// One snapshot's call map, derived from the bodies the snapshot itself
/// carries — ADR-0024's rails. Each body is read for whole identifier
/// tokens that are one of the snapshot's own listed function names, so
/// both call shapes that matter are covered (a direct call `FUN_x(…);`
/// and a callback handed to a host, `qsort(a, n, 4, FUN_y)`), and the
/// map costs the pass no analysis-engine read. A mention of a
/// function's own name — the signature line's spelling, self-recursion
/// — records no edge: a self-loop can never be a *paired* neighbor of
/// its own claim, so a pair can never corroborate or propagate itself.
struct CallMap {
    /// For each listed function, the listed functions whose names its
    /// body names as call targets, ascending by old/new scan index.
    callees: Vec<BTreeSet<usize>>,

    /// The same relation read backwards: for each listed function, the
    /// listed functions whose bodies name it, ascending by index.
    callers: Vec<BTreeSet<usize>>,
}

/// Derive one snapshot's call map purely from the bodies it carries:
/// the zero-extra-reads rule of ADR-0024, applied to pairing. A
/// demangled listing name (`::`-qualified chains, spelled parameter
/// lists) is not a single identifier token, so no body's tokens ever
/// name it — the same rail the scan's own correlation detector
/// accepted. A name listed twice (duplicates the scan can list) takes
/// an edge from every mention.
fn call_map(snapshot: &ScanSnapshot) -> CallMap {
    let mut listed: HashMap<&str, Vec<usize>> = HashMap::new();
    for (index, entry) in snapshot.functions.iter().enumerate() {
        listed.entry(entry.name.as_str()).or_default().push(index);
    }

    let mut callees: Vec<BTreeSet<usize>> = vec![BTreeSet::new(); snapshot.functions.len()];
    let mut callers: Vec<BTreeSet<usize>> = vec![BTreeSet::new(); snapshot.functions.len()];
    for (index, entry) in snapshot.functions.iter().enumerate() {
        for token in identifier_tokens(&entry.body) {
            let Some(targets) = listed.get(token) else {
                continue;
            };
            for &target in targets {
                if target == index {
                    continue;
                }
                callees[index].insert(target);
                callers[target].insert(index);
            }
        }
    }
    CallMap { callees, callers }
}

/// A body's whole identifier tokens: maximal runs of identifier
/// characters, so a mention only ever matches a listed name spelled as
/// one token, never a fragment inside a longer word or literal.
fn identifier_tokens(body: &str) -> Vec<&str> {
    fn is_identifier(ch: char) -> bool {
        ch.is_alphanumeric() || ch == '_'
    }

    let mut tokens = Vec::new();
    let mut start: Option<usize> = None;
    for (index, ch) in body.char_indices() {
        match (start, is_identifier(ch)) {
            (None, true) => start = Some(index),
            (Some(from), false) => {
                tokens.push(&body[from..index]);
                start = None;
            }
            _ => {}
        }
    }
    if let Some(from) = start {
        tokens.push(&body[from..]);
    }
    tokens
}

/// One already-paired function whose call edge corroborates a pair. An
/// edge between `old` and the old-side function has a matching edge in
/// the same direction between its partner `new` and the new-side
/// function. A neighbor counts once however many directions it agrees
/// in — the gate counts neighbors, not edges.
struct Neighbor {
    /// The neighbor's old-snapshot index; its listing name is what the
    /// evidence line names.
    old: usize,

    /// The partner the neighbor pairs with in the new snapshot.
    new: usize,

    /// The candidate calls the neighbor and its partner calls the
    /// partner: the callee sets agree through this pair.
    calls: bool,

    /// The neighbor calls the candidate and its partner calls the
    /// partner: the caller sets agree through this pair.
    called_by: bool,
}

/// Every paired neighbor agreeing on the pair `x` ↔ `y` through `pairs`
/// (old index to new index). The old-side neighbors of `x` are walked
/// in scan order, keeping each one whose partner reaches `y` along an
/// edge in the same direction. The call map records no self-loop, so
/// the pair under discussion can never agree with itself.
fn agreeing_neighbors(
    x: usize,
    y: usize,
    pairs: &BTreeMap<usize, usize>,
    old_map: &CallMap,
    new_map: &CallMap,
) -> Vec<Neighbor> {
    let mut neighbors = Vec::new();
    for &a in old_map.callees[x].union(&old_map.callers[x]) {
        let Some(&b) = pairs.get(&a) else {
            continue;
        };
        let calls = old_map.callees[x].contains(&a) && new_map.callees[y].contains(&b);
        let called_by = old_map.callers[x].contains(&a) && new_map.callers[y].contains(&b);
        if calls || called_by {
            neighbors.push(Neighbor {
                old: a,
                new: b,
                calls,
                called_by,
            });
        }
    }
    neighbors
}

/// The evidence lines a topology reading contributes. The summary line
/// comes first, then the paired-neighbor evidence lines the records
/// name: one line per paired neighbor naming both sides of the
/// neighbor and the direction of agreement, capped at
/// [`MAX_QUOTED_NEIGHBORS`] quotes with the remainder named.
fn topology_evidence(
    summary: &str,
    candidate: &str,
    neighbors: &[Neighbor],
    old_entries: &[FunctionEntry],
    new_entries: &[FunctionEntry],
) -> Vec<String> {
    let mut lines = vec![summary.to_string()];
    for neighbor in neighbors.iter().take(MAX_QUOTED_NEIGHBORS) {
        let direction = match (neighbor.calls, neighbor.called_by) {
            (true, true) => "calls and is called by",
            (true, false) => "calls",
            (false, _) => "is called by",
        };
        lines.push(format!(
            "{candidate} {direction} paired neighbor {} -> {}",
            old_entries[neighbor.old].name, new_entries[neighbor.new].name
        ));
    }
    if neighbors.len() > MAX_QUOTED_NEIGHBORS {
        lines.push(format!(
            "(+{} more paired neighbors)",
            neighbors.len() - MAX_QUOTED_NEIGHBORS
        ));
    }
    lines
}

/// The ladder's third band: pair the functions the first two families
/// left unpaired, because their caller and callee sets agree *through
/// already-paired neighbors*. Propagation runs over the [`CallMap`] to
/// a fixed point: every claim enters the pair set immediately, so a
/// chain of renamed functions pairs through neighbors that converged
/// themselves (ticket #297). A claim requires at least
/// [`TOPOLOGY_MIN_PAIRED_NEIGHBORS`] distinct paired neighbors — a lone
/// paired neighbor is a lone signal and claims nothing (ADR-0038). The
/// score is [`TOPOLOGY_CONFIDENCE`], below the carry-over floor on its
/// own: the document persists the record and only the carry-over
/// consumer applies the floor. Claims walk old scan order and take the
/// first agreeing partner in new scan order, so the fixed point is
/// deterministic and diff-clean (ADR-0028's positional rule again).
/// One-to-one holds because a claimed side never comes up again.
fn propagate_topology(
    winners: &mut Vec<(usize, usize, PairingRecord)>,
    old: &ScanSnapshot,
    new: &ScanSnapshot,
    old_map: &CallMap,
    new_map: &CallMap,
) {
    let mut pairs: BTreeMap<usize, usize> = winners.iter().map(|(o, n, _)| (*o, *n)).collect();
    let mut new_paired: BTreeSet<usize> = winners.iter().map(|(_, n, _)| *n).collect();

    loop {
        let mut grew = false;
        for x in 0..old.functions.len() {
            if pairs.contains_key(&x) {
                continue;
            }
            // Candidates on the new side: partners of `x`'s already-paired
            // neighbors — the only functions whose sets can agree with x's.
            let partners = old_map.callees[x]
                .union(&old_map.callers[x])
                .filter_map(|&a| pairs.get(&a).copied())
                .collect::<BTreeSet<usize>>();
            let candidates = partners
                .iter()
                .flat_map(|&b| new_map.callees[b].union(&new_map.callers[b]).copied())
                .collect::<BTreeSet<usize>>();
            for &y in &candidates {
                if new_paired.contains(&y) {
                    continue;
                }
                let neighbors = agreeing_neighbors(x, y, &pairs, old_map, new_map);
                if neighbors.len() < TOPOLOGY_MIN_PAIRED_NEIGHBORS {
                    continue;
                }
                let evidence = topology_evidence(
                    &format!(
                        "call-graph topology through {} paired neighbors",
                        neighbors.len()
                    ),
                    &old.functions[x].name,
                    &neighbors,
                    &old.functions,
                    &new.functions,
                );
                winners.push((
                    x,
                    y,
                    PairingRecord {
                        old_function: old.functions[x].name.clone(),
                        new_function: new.functions[y].name.clone(),
                        family: MatchFamily::CallTopology,
                        confidence: TOPOLOGY_CONFIDENCE.into(),
                        evidence,
                    },
                ));
                pairs.insert(x, y);
                new_paired.insert(y);
                grew = true;
                break;
            }
        }
        if !grew {
            break;
        }
    }
}

/// The agreement bump (ticket #297, the P12.6 flag-family precedent):
/// when the call map agrees on a pair the body family already claimed,
/// two independent families read the same pair, and agreement beats any
/// single reading — the record gains [`TOPOLOGY_AGREEMENT_BUMP`] above
/// its body score. A byte-equal pair corroborated by topology reaches
/// name identity's 95, never past it. The family stays
/// `normalized_body`: a corroborating topology is not a competing
/// claim, the stronger body claim stands, and the record keeps naming
/// its paired-neighbor evidence lines beside the body diff that won.
fn corroborate_body_pairs(
    winners: &mut [(usize, usize, PairingRecord)],
    old: &ScanSnapshot,
    new: &ScanSnapshot,
    old_map: &CallMap,
    new_map: &CallMap,
) {
    let pairs: BTreeMap<usize, usize> = winners.iter().map(|(o, n, _)| (*o, *n)).collect();
    for (x, y, record) in winners.iter_mut() {
        if record.family != MatchFamily::NormalizedBody {
            continue;
        }
        let neighbors = agreeing_neighbors(*x, *y, &pairs, old_map, new_map);
        if neighbors.len() < TOPOLOGY_MIN_PAIRED_NEIGHBORS {
            continue;
        }
        record.confidence = record
            .confidence
            .value()
            .saturating_add(TOPOLOGY_AGREEMENT_BUMP)
            .into();
        record.evidence.extend(topology_evidence(
            &format!(
                "call-graph topology corroborates through {} paired neighbors",
                neighbors.len()
            ),
            &old.functions[*x].name,
            &neighbors,
            &old.functions,
            &new.functions,
        ));
    }
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests;
