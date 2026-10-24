//! The pairing pass: pure text and structure over two in-memory scan
//! snapshots — documents in, one pairing document out.
//!
//! [`pair_versions`] is the crate's whole engine: it adds no `ScanSource`
//! methods (ADR-0026 untouched), reads no engine, writes nothing back
//! to any program (ADR-0020), and runs no LLM — a version diff costs
//! milliseconds, not dollars. The pass runs the match ladder (track
//! #233). First, name identity: an exported name or a
//! demangled name present in both versions pairs the old function to
//! the new at [`crate::types::NAME_IDENTITY_CONFIDENCE`]. Second, the
//! normalized-body family: kept bodies put through the shared libmatch
//! normalizer (#294's public cross-crate rule — one shared rule, one
//! owner, never a second normalizer), where byte-equal shapes pair at
//! [`crate::types::BODY_EQUAL_CONFIDENCE`]. Third, call-graph topology
//! propagation (#297): over a call map derived purely from the bodies
//! the two snapshots carry (ADR-0024's rails — no new reads), a
//! function the first two rungs left unpaired pairs when its callers
//! and callees agree through already-paired neighbors, iterated to a
//! fixed point so chains of renamed functions pair through neighbors
//! that converged themselves. A claim requires at least
//! [`crate::types::TOPOLOGY_MIN_PAIRED_NEIGHBORS`] paired neighbors — a
//! lone paired neighbor claims nothing — scores
//! [`crate::types::TOPOLOGY_CONFIDENCE`], below the carry-over floor on
//! its own, and names its paired-neighbor evidence lines. Topology
//! corroborating a body-family pair instead rides the flag-family
//! agreement precedent (P12.6 — agreement beats any single reading):
//! the body record gains [`crate::types::TOPOLOGY_AGREEMENT_BUMP`]. A
//! lone signal claims
//! nothing (ADR-0038): address equality pairs nothing on its own, and
//! neither does a matching address-derived `FUN_…` spelling — that
//! spelling *is* an address, so pairing on it would smuggle the
//! relocation signal the rail exists to refuse.
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
/// caller error it refuses rather than a pairing it guesses at. The
/// emitted document names both snapshots' byte hashes and both full
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

    // Ladder rung three (#297): the call map is derived only from the
    // bodies the two snapshots carry — no engine read anywhere in the
    // pass (ADR-0024's rails, ADR-0026 intact).
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
/// snapshots' function listings (scan order is what ties resolve on),
/// beside the score and evidence the winning family would carry.
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
        // The exported family claims first, so an exported name that
        // also reads as demangled keeps the export's evidence — the
        // same pair claimed twice still resolves to one record, the
        // stronger reading standing.
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
/// and `~`-prefixed destructors. Name-shape reading rides the same
/// precedent as ADR-0012's flagging-by-name-shape pass.
///
/// An address-derived `FUN_…` spelling is refused outright: it is an
/// address in name clothing, and pairing on it would claim from the
/// lone relocation signal the rail refuses (ADR-0038).
fn carries_demangled_spelling(name: &str) -> bool {
    if name.starts_with("FUN_") {
        return false;
    }
    name.contains("::")
        || name.starts_with("operator")
        || name.starts_with('~')
        || (name.ends_with(')') && name.contains('('))
}

/// How many of a near-equal pair's line edits the evidence quotes:
/// enough for an audit glance at the diff's character, never a wall
/// of text in the pairing document. The summary line always names the
/// full edit count.
const MAX_QUOTED_EDITS: usize = 3;

/// The shared normalizer's shape of one kept body: the normalized line
/// sequence, whitespace-collapsed, that "same body shape" means corpus-
/// wide. The pairing tests consume this rule without re-testing it —
/// the normalizer's contract stays pinned where it lives, in libmatch
/// (#294).
fn normalized_shape(body: &str) -> Vec<String> {
    normalize_lines(body)
        .into_iter()
        .map(|(_original, normalized)| normalized)
        .collect()
}

/// Whether a normalized shape holds nothing: a kept body that is blank
/// normalizes to blank lines, and blank-on-blank equality is vacuous —
/// claiming it would pair on a lone structural coincidence (ADR-0038).
fn is_blank(shape: &[String]) -> bool {
    shape.iter().all(|line| line.is_empty())
}

/// Collect every normalized-body candidate pair, in scan order.
///
/// A pair is a candidate when the two kept bodies, put through the
/// shared normalizer, come out one shape: byte-equal shapes pair at
/// [`BODY_EQUAL_CONFIDENCE`], and a pair whose shapes differ only in
/// line edits scores on its structural-diff ratio beside that band —
/// every edit is a line that changed, was added, or was removed, and
/// the evidence line summarizes the diff and quotes it. A pair below
/// [`BODY_SIMILARITY_FLOOR`] similarity is a clearly different body,
/// a coincidence of listing rather than a moved function, and claims
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
            // Cost model (the pass owes milliseconds, not dollars): an
            // edit is at least a line-count gap, so a pair whose gap
            // alone outruns the floor never reaches the diff matrix.
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

/// One line edit between two normalized bodies: the diff an engineer
/// reads to audit why a near-equal pair was called one function.
enum BodyEdit {
    /// One old line became one new line.
    Replace { old: String, new: String },
    /// One old line is gone from the new body.
    Delete { old: String },
    /// One new line is absent from the old body.
    Insert { new: String },
}

/// Levenshtein edits between two normalized line sequences: the edit
/// count beside the edits themselves, in body order — each changed,
/// added, or removed line once. The full distance matrix, backtraced:
/// bodies are decompiled functions, tens of lines, and the evidence
/// quotes the edits, so the script rides with the count.
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
/// order — candidate generation stands in old-then-new scan order, and
/// the sort is stable, so a candidate earlier in the scan beats a later
/// one at the same score, and a candidate's second-best pairing is
/// dropped once its side is taken (ADR-0022's strongest-claim-wins,
/// ADR-0028's positional tie rule). Surviving `(old, new, record)`
/// triples come back in old scan order so two documents of one version
/// pair diff cleanly, and the topology rung can build on the resolved
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
// Call-graph topology propagation (#297, ladder rung three)
// ------------------------------------------------------------

/// How many paired neighbors a topology record's evidence quotes: the
/// body family's `MAX_QUOTED_EDITS` precedent again — the first few
/// neighbors read as an audit glance, and the remainder are named.
const MAX_QUOTED_NEIGHBORS: usize = 3;

/// One snapshot's call map, derived from the bodies the snapshot itself
/// carries — ADR-0024's rails: each body is read for whole identifier
/// tokens that are one of the snapshot's own listed function names, so
/// both call shapes that matter are covered (a direct call `FUN_x(…);`
/// and a callback handed to a host, `qsort(a, n, 4, FUN_y)`), and the
/// map costs the pass no engine read. A mention of a function's own
/// name — the signature line's spelling, self-recursion — records no
/// edge: a self-loop can never be a *paired* neighbor of its own claim,
/// and a pair can therefore never corroborate or propagate itself.
struct CallMap {
    /// For each listed function, the listed functions whose names its
    /// body names as call targets, ascending by old/new scan index.
    callees: Vec<BTreeSet<usize>>,

    /// The same relation read backwards: for each listed function, the
    /// listed functions whose bodies name it, ascending by index.
    callers: Vec<BTreeSet<usize>>,
}

/// Derive one snapshot's call map purely from the bodies it carries:
/// the zero-extra-reads rule of ADR-0024, applied to pairing. A demangled
/// listing name (`::`-qualified chains, spelled parameter lists) spells
/// no identifier token, so bodies never edge toward it — the same rail
/// the scan's own correlation detector accepted. A name listed twice
/// (duplicates the scan can list) takes an edge from every mention.
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

/// One already-paired function whose call edge corroborates a pair: an
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
/// (old index to new index): the old-side neighbors of `x` walked in
/// scan order, keeping each one whose partner reaches `y` along an edge
/// in the same direction. Since the call map records no self-loop, the
/// pair under discussion can never agree with itself.
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

/// The evidence lines a topology reading contributes: the summary line
/// first, then the paired-neighbor evidence lines the records name —
/// one line per paired neighbor spelling both sides of the neighbor and
/// the direction of agreement, capped at [`MAX_QUOTED_NEIGHBORS`]
/// quotes with the remainder named.
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

/// Ladder rung three: pair the functions the first two rungs left
/// unpaired because their caller and callee sets agree *through already-
/// paired neighbors*, propagated to a fixed point over the [`CallMap`]:
/// every claim enters the pair set immediately, so a chain of renamed
/// functions pairs through neighbors that converged themselves (ticket
/// #297). A claim requires at least [`TOPOLOGY_MIN_PAIRED_NEIGHBORS`]
/// distinct paired neighbors — a lone paired neighbor is a lone signal
/// and claims nothing (ADR-0038). The score is [`TOPOLOGY_CONFIDENCE`],
/// below the carry-over floor on its own: the document persists the
/// record and only the carry-over consumer applies the floor. Claims
/// walk old scan order and take the first agreeing partner in new scan
/// order, so the fixed point is deterministic and diff-clean
/// (ADR-0028's positional rule again), and one-to-one holds because a
/// claimed side never comes up again.
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
/// two independent families read one pair, and agreement beats any
/// single reading — the record rides [`TOPOLOGY_AGREEMENT_BUMP`] above
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
mod tests {
    use super::*;
    use crate::types::CARRY_OVER_CONFIDENCE_FLOOR;
    use calxgloss_types::BinaryIdentity;

    /// One listed function with a body that names itself, so body-
    /// related tests can spell "unrelated bodies" honestly.
    fn function(name: &str, address: u64) -> FunctionEntry {
        FunctionEntry {
            name: name.into(),
            address,
            body: format!("// body of {name}"),
        }
    }

    /// One listed function with a spelled-out decompiled body, for the
    /// body-family fixtures that need real Ghidra spellings.
    fn function_with_body(name: &str, address: u64, body: &str) -> FunctionEntry {
        FunctionEntry {
            name: name.into(),
            address,
            body: body.into(),
        }
    }

    #[test]
    fn a_fun_renamed_function_with_byte_equal_normalized_bodies_pairs_at_90() {
        // The function merely moved: the new address minted a new FUN_
        // spelling and the rebuild re-lettered Ghidra's invented
        // variables, but through the shared normalizer the two bodies
        // are byte-equal shapes — the body family pairs them at 90
        // (track #233's ladder, rung two).
        let old_body = "\
{
   uint uVar1;
   uVar1 = DAT_140045a68;
   if (uVar1 != 0) {
      FUN_140002000(uVar1);
   }
   return;
}";
        let new_body = "\
{
   uint iVar4;
   iVar4 = DAT_140047120;
   if (iVar4 != 0) {
      FUN_140002000(iVar4);
   }
   return;
}";
        let old = snapshot(
            "game.dll",
            "old-hash",
            vec![function_with_body("FUN_140001000", 0x140001000, old_body)],
            &[],
        );
        let new = snapshot(
            "game.dll",
            "new-hash",
            vec![function_with_body("FUN_140009000", 0x140009000, new_body)],
            &[],
        );

        let document = pair_versions(&old, &new).expect("one identity");
        assert_eq!(
            document.pairings.len(),
            1,
            "the moved function pairs through the body family"
        );
        let record = &document.pairings[0];
        assert_eq!(record.old_function, "FUN_140001000");
        assert_eq!(record.new_function, "FUN_140009000");
        assert_eq!(record.family, MatchFamily::NormalizedBody);
        assert_eq!(record.confidence.value(), BODY_EQUAL_CONFIDENCE);
        assert_eq!(
            record.evidence,
            ["normalized bodies are byte-equal (8 lines)"],
            "the record carries the normalized-body summary as its evidence"
        );
    }

    /// One version's snapshot with a stable stand-in hash.
    fn snapshot(
        binary: &str,
        hash: &str,
        functions: Vec<FunctionEntry>,
        exports: &[&str],
    ) -> ScanSnapshot {
        ScanSnapshot {
            binary: BinaryIdentity::new(binary),
            bytes_sha256: hash.into(),
            functions,
            exports: exports.iter().map(|name| (*name).to_string()).collect(),
        }
    }

    #[test]
    fn an_exported_name_present_in_both_versions_pairs_at_95() {
        // The exported name is the program's own spelling; its address
        // shifting between versions changes nothing.
        let old = snapshot(
            "game.dll",
            "old-hash",
            vec![
                function("fixture_init", 0x1000),
                function("FUN_10001200", 0x1200),
            ],
            &["fixture_init"],
        );
        let new = snapshot(
            "game.dll",
            "new-hash",
            vec![function("fixture_init", 0x4000)],
            &["fixture_init"],
        );

        let document = pair_versions(&old, &new).expect("one identity");
        assert_eq!(document.pairings.len(), 1, "the export pairs once");
        let record = &document.pairings[0];
        assert_eq!(record.old_function, "fixture_init");
        assert_eq!(record.new_function, "fixture_init");
        assert_eq!(record.confidence.value(), NAME_IDENTITY_CONFIDENCE);
        assert_eq!(record.confidence.value(), 95);
        assert_eq!(record.family, MatchFamily::NameIdentity);
        assert_eq!(record.evidence, ["exported name fixture_init"]);
    }

    #[test]
    fn a_demangled_name_present_in_both_versions_pairs_at_95() {
        // A `::`-qualified demangled name pairs even with no export
        // table entry behind it — the demangler's spelling is the
        // binary's own name for the function.
        let old = snapshot(
            "game.dll",
            "old-hash",
            vec![function("Widget::render(void)", 0x1000)],
            &[],
        );
        let new = snapshot(
            "game.dll",
            "new-hash",
            vec![function("Widget::render(void)", 0x9000)],
            &[],
        );

        let document = pair_versions(&old, &new).expect("one identity");
        assert_eq!(document.pairings.len(), 1);
        assert_eq!(
            document.pairings[0].evidence,
            ["demangled name Widget::render(void)"]
        );
    }

    #[test]
    fn a_demangled_operator_spelling_pairs() {
        // The demangled `operator.` dot form the decompiler writes for
        // C++ operators keeps its dot and brackets in the listing.
        let old = snapshot(
            "game.dll",
            "old-hash",
            vec![function("operator.new(unsigned long long)", 0x1000)],
            &[],
        );
        let new = snapshot(
            "game.dll",
            "new-hash",
            vec![function("operator.new(unsigned long long)", 0x2000)],
            &[],
        );
        assert_eq!(
            pair_versions(&old, &new)
                .expect("one identity")
                .pairings
                .len(),
            1
        );
    }

    #[test]
    fn an_equal_address_derived_spelling_claims_nothing() {
        // A `FUN_…` name match means the address held — the address-
        // derived spelling is the relocation signal itself, and a lone
        // signal claims nothing (ADR-0038). The bodies stay unrelated so
        // no body-family evidence corroborates the lone address claim.
        let old = snapshot(
            "game.dll",
            "old-hash",
            vec![function_with_body(
                "FUN_140001000",
                0x140001000,
                "{\n   return uVar1 + 1;\n}",
            )],
            &[],
        );
        let new = snapshot(
            "game.dll",
            "new-hash",
            vec![function_with_body(
                "FUN_140001000",
                0x140001000,
                "{\n   DAT_140045a68 = 3;\n   return;\n}",
            )],
            &[],
        );

        let document = pair_versions(&old, &new).expect("one identity");
        assert!(
            document.pairings.is_empty(),
            "a FUN_ spelling pairing is a lone address claim"
        );
    }

    #[test]
    fn equal_address_with_unrelated_bodies_pairs_nothing() {
        // The lone-signal gate, spelled out: two functions sit at the
        // same address with different names and unrelated bodies — and
        // both are even exported, under different names. Nothing pairs:
        // relocations lie, and equal addresses claim nothing alone.
        let old = snapshot(
            "game.dll",
            "old-hash",
            vec![function("old_entry", 0x140001100)],
            &["old_entry"],
        );
        let new = snapshot(
            "game.dll",
            "new-hash",
            vec![function("new_entry", 0x140001100)],
            &["new_entry"],
        );

        let document = pair_versions(&old, &new).expect("one identity");
        assert!(
            document.pairings.is_empty(),
            "a lone address equality claims nothing"
        );
    }

    #[test]
    fn a_near_equal_body_pairs_on_the_structural_diff_ratio() {
        // Ten normalized lines, one changed statement between builds:
        // the shapes are not byte-equal, so the pair scores on its
        // structural-diff ratio — inside the band between the carry-
        // over floor and the byte-equal 90 (ticket #296) — and the
        // record carries the normalized-body diff as its evidence.
        let old_body = "\
{
   uint uVar1;
   uVar1 = DAT_140045a68;
   if (uVar1 != 0) {
      FUN_140002000(uVar1);
   }
   DAT_140045a70 = uVar1;
   uVar1 = uVar1 + 1;
   return;
}";
        // The rebuild stored the bumped counter instead: one normalized
        // line replaced out of ten, everything else the same shape.
        let new_body = "\
{
   uint iVar7;
   iVar7 = DAT_140047120;
   if (iVar7 != 0) {
      FUN_140002000(iVar7);
   }
   DAT_140047200 = iVar7;
   iVar7 = iVar7 + 2;
   return;
}";
        let old = snapshot(
            "game.dll",
            "old-hash",
            vec![function_with_body("FUN_140001000", 0x140001000, old_body)],
            &[],
        );
        let new = snapshot(
            "game.dll",
            "new-hash",
            vec![function_with_body("FUN_140009000", 0x140009000, new_body)],
            &[],
        );

        let document = pair_versions(&old, &new).expect("one identity");
        assert_eq!(document.pairings.len(), 1, "the near-equal pair pairs");
        let record = &document.pairings[0];
        assert_eq!(record.family, MatchFamily::NormalizedBody);
        assert!(
            record.confidence.value() > CARRY_OVER_CONFIDENCE_FLOOR
                && record.confidence.value() < BODY_EQUAL_CONFIDENCE,
            "a near-equal score stands inside the band, got {}",
            record.confidence.value()
        );
        // A worked example, not a recompute: one of ten normalized
        // lines changed, so the ratio puts the score at 89.
        assert_eq!(record.confidence.value(), 89);
        assert_eq!(
            record.evidence,
            [
                "normalized body diff: 1 of 10 lines differ (90% similar)",
                "changed: VAR = VAR + 1; -> VAR = VAR + 2;",
            ],
            "the evidence line summarizes the normalized-body diff and quotes it"
        );
    }

    #[test]
    fn an_added_line_reads_as_an_added_line_in_the_evidence() {
        // The new build's routine grew one extra call. The shapes still
        // pair, but the evidence must spell the edit honestly: a line
        // the new body has and the old one does not is *added*, not a
        // change squeezed onto the wrong pair of lines.
        let old_body = "\
{
   uint uVar1;
   uVar1 = DAT_140045a68;
   if (uVar1 != 0) {
      FUN_140002000(uVar1);
   }
   DAT_140045a70 = uVar1;
   uVar1 = uVar1 + 1;
   return;
}";
        let new_body = "\
{
   uint iVar7;
   iVar7 = DAT_140047120;
   if (iVar7 != 0) {
      FUN_140002000(iVar7);
      FUN_140002100(iVar7);
   }
   DAT_140047200 = iVar7;
   iVar7 = iVar7 + 1;
   return;
}";
        let old = snapshot(
            "game.dll",
            "old-hash",
            vec![function_with_body("FUN_140001000", 0x140001000, old_body)],
            &[],
        );
        let new = snapshot(
            "game.dll",
            "new-hash",
            vec![function_with_body("FUN_140009000", 0x140009000, new_body)],
            &[],
        );

        let document = pair_versions(&old, &new).expect("one identity");
        assert_eq!(document.pairings.len(), 1);
        let record = &document.pairings[0];
        // Eleven normalized lines, one added: 91% similar, score 89.
        assert_eq!(record.confidence.value(), 89);
        assert_eq!(
            record.evidence,
            [
                "normalized body diff: 1 of 11 lines differ (91% similar)",
                "added: FUN_140002100(VAR);",
            ]
        );
    }

    #[test]
    fn a_removed_line_reads_as_a_removed_line_in_the_evidence() {
        // The mirror image: the update dropped a call. The evidence
        // names it *removed*, from the old body's side.
        let old_body = "\
{
   uint uVar1;
   uVar1 = DAT_140045a68;
   if (uVar1 != 0) {
      FUN_140002000(uVar1);
      FUN_140002100(uVar1);
   }
   DAT_140045a70 = uVar1;
   uVar1 = uVar1 + 1;
   return;
}";
        let new_body = "\
{
   uint iVar7;
   iVar7 = DAT_140047120;
   if (iVar7 != 0) {
      FUN_140002000(iVar7);
   }
   DAT_140047200 = iVar7;
   iVar7 = iVar7 + 1;
   return;
}";
        let old = snapshot(
            "game.dll",
            "old-hash",
            vec![function_with_body("FUN_140001000", 0x140001000, old_body)],
            &[],
        );
        let new = snapshot(
            "game.dll",
            "new-hash",
            vec![function_with_body("FUN_140009000", 0x140009000, new_body)],
            &[],
        );

        let document = pair_versions(&old, &new).expect("one identity");
        assert_eq!(document.pairings.len(), 1);
        let record = &document.pairings[0];
        assert_eq!(record.confidence.value(), 89);
        assert_eq!(
            record.evidence,
            [
                "normalized body diff: 1 of 11 lines differ (91% similar)",
                "removed: FUN_140002100(VAR);",
            ]
        );
    }

    #[test]
    fn many_changed_lines_quote_three_edits_and_say_so() {
        // Five replaced statements in a 23-line shape: the summary
        // counts every edit, but the quoted evidence stays auditable —
        // the first few edits in body order, and a line naming the
        // ones it left out.
        let middle: Vec<String> = (0..20)
            .map(|i| format!("   FUN_140002000(uVar1, {i});"))
            .collect();
        let mut changed: Vec<String> = middle.clone();
        for i in [3usize, 7, 11, 15, 19] {
            changed[i] = format!("   FUN_140002000(uVar1, {i}) + 1;");
        }
        let old_body = format!("{{\n{}\n   return;\n}}", middle.join("\n"));
        let new_body = format!("{{\n{}\n   return;\n}}", changed.join("\n"));

        let old = snapshot(
            "game.dll",
            "old-hash",
            vec![function_with_body("FUN_140001000", 0x140001000, &old_body)],
            &[],
        );
        let new = snapshot(
            "game.dll",
            "new-hash",
            vec![function_with_body("FUN_140009000", 0x140009000, &new_body)],
            &[],
        );

        let document = pair_versions(&old, &new).expect("one identity");
        assert_eq!(document.pairings.len(), 1);
        let record = &document.pairings[0];
        // 5 edits over 23 lines: 79% similar, score 87.
        assert_eq!(record.confidence.value(), 87);
        assert_eq!(
            record.evidence,
            [
                "normalized body diff: 5 of 23 lines differ (79% similar)",
                "changed: FUN_140002000(VAR, 3); -> FUN_140002000(VAR, 3) + 1;",
                "changed: FUN_140002000(VAR, 7); -> FUN_140002000(VAR, 7) + 1;",
                "changed: FUN_140002000(VAR, 11); -> FUN_140002000(VAR, 11) + 1;",
                "(+2 more edits)",
            ]
        );
    }

    #[test]
    fn two_blank_kept_bodies_pair_nothing() {
        // A kept body that holds nothing — a decompile failure, a stub
        // the scan listed without a body — normalizes to nothing. Two
        // blanks are "byte-equal" only vacuously: a lone structural
        // coincidence claims nothing (ADR-0038).
        let old = snapshot(
            "game.dll",
            "old-hash",
            vec![function_with_body("FUN_140001000", 0x140001000, "")],
            &[],
        );
        let new = snapshot(
            "game.dll",
            "new-hash",
            vec![function_with_body("FUN_140009000", 0x140009000, "")],
            &[],
        );

        let document = pair_versions(&old, &new).expect("one identity");
        assert!(
            document.pairings.is_empty(),
            "blank bodies claiming a byte-equal pair is a lone-coincidence claim"
        );
    }

    #[test]
    fn two_clearly_different_bodies_pair_nothing() {
        // An initializer and a parser share only Ghidra's boilerplate —
        // the braces and the bare return — out of ten normalized lines
        // each: about 30% similar, under the floor, and the body
        // family (the only family in play here) claims nothing.
        let old_body = "\
{
   uint uVar1;
   uint uVar2;
   uVar1 = DAT_140045a68;
   uVar2 = DAT_140045a70;
   FUN_140002000(uVar1, uVar2);
   uVar2 = uVar1 & 0xff;
   FUN_140002100(uVar2);
   return;
}";
        let new_body = "\
{
   char cVar3;
   int iVar4;
   cVar3 = *(char *)0x1400460a0;
   iVar4 = *(int *)0x1400460a8;
   while (cVar3 != '\\0') {
      FUN_140004400(cVar3, iVar4);
      cVar3 = *(char *)(0x1400460a0 + 1);
   }
   return;
}";
        let old = snapshot(
            "game.dll",
            "old-hash",
            vec![function_with_body("FUN_140001000", 0x140001000, old_body)],
            &[],
        );
        let new = snapshot(
            "game.dll",
            "new-hash",
            vec![function_with_body("FUN_140009000", 0x140009000, new_body)],
            &[],
        );

        let document = pair_versions(&old, &new).expect("one identity");
        assert!(
            document.pairings.is_empty(),
            "a clearly different body pairs nothing, floor enforced"
        );
    }

    #[test]
    fn a_plain_internal_name_match_claims_nothing_yet() {
        // A stripped private symbol that kept its name across versions
        // is not an export and not demangled: no family pairs on that
        // spelling alone. The bodies here are unrelated, so the body
        // family that landed with #296 has nothing to corroborate —
        // equal bodies under one internal name would pair through the
        // body family, on the body evidence, never the name.
        let old = snapshot(
            "game.dll",
            "old-hash",
            vec![function_with_body(
                "helper_parse",
                0x1000,
                "{\n   return uVar1 + 1;\n}",
            )],
            &[],
        );
        let new = snapshot(
            "game.dll",
            "new-hash",
            vec![function_with_body(
                "helper_parse",
                0x3000,
                "{\n   DAT_140045a68 = 3;\n   return;\n}",
            )],
            &[],
        );

        let document = pair_versions(&old, &new).expect("one identity");
        assert!(document.pairings.is_empty());
    }

    #[test]
    fn a_second_best_pairing_is_dropped() {
        // One-to-one resolution over a mixed-strength candidate set —
        // the shape the whole ladder will hand resolution once #296 and
        // #297 land their families (scores here are synthetic stand-ins
        // for the body and topology families, the resolution rule is
        // the shipped one): A's best claim is X at 95, so A's 90 claim
        // on Y drops, and Y then pairs with B.
        let old = snapshot(
            "game.dll",
            "old-hash",
            vec![function("a", 1), function("b", 2)],
            &[],
        );
        let new = snapshot(
            "game.dll",
            "new-hash",
            vec![function("x", 3), function("y", 4)],
            &[],
        );
        let candidates = vec![
            Candidate {
                old: 0,
                new: 0,
                confidence: 95,
                family: MatchFamily::NameIdentity,
                evidence: vec!["best".into()],
            },
            Candidate {
                old: 0,
                new: 1,
                confidence: 90,
                family: MatchFamily::NameIdentity,
                evidence: vec!["second best".into()],
            },
            Candidate {
                old: 1,
                new: 1,
                confidence: 85,
                family: MatchFamily::NameIdentity,
                evidence: vec!["next".into()],
            },
        ];

        let winners = resolve_one_to_one(candidates, &old.functions, &new.functions);
        let records: Vec<&PairingRecord> = winners.iter().map(|(_, _, record)| record).collect();
        assert_eq!(records.len(), 2);
        assert_eq!(
            (
                records[0].old_function.as_str(),
                records[0].new_function.as_str()
            ),
            ("a", "x")
        );
        assert_eq!(
            (
                records[1].old_function.as_str(),
                records[1].new_function.as_str()
            ),
            ("b", "y")
        );
        assert!(
            !records
                .iter()
                .any(|r| r.old_function == "a" && r.new_function == "y"),
            "a candidate's second-best pairing is dropped"
        );
    }

    #[test]
    fn a_tie_keeps_the_first_seen_pairing_in_scan_order() {
        // Two old functions compete for one new function at equal
        // strength: the one first seen in the old scan's listing wins,
        // the other stays unpaired (ADR-0028's positional precedent).
        let old = snapshot(
            "game.dll",
            "old-hash",
            vec![function("a", 1), function("b", 2)],
            &[],
        );
        let new = snapshot("game.dll", "new-hash", vec![function("x", 3)], &[]);
        let candidates = vec![
            Candidate {
                old: 0,
                new: 0,
                confidence: 95,
                family: MatchFamily::NameIdentity,
                evidence: vec!["first".into()],
            },
            Candidate {
                old: 1,
                new: 0,
                confidence: 95,
                family: MatchFamily::NameIdentity,
                evidence: vec!["later".into()],
            },
        ];

        let winners = resolve_one_to_one(candidates, &old.functions, &new.functions);
        assert_eq!(winners.len(), 1);
        assert_eq!(
            old.functions[winners[0].0].name, "a",
            "the first seen in scan order keeps the pair"
        );
    }

    /// A decompiled body of listed calls followed by filler assignments:
    /// the filler pushes a new-side body past the line-gap skip, so a
    /// renamed pair can only meet through the call graph, never through
    /// the body family.
    fn padded_body(calls: &[&str], assignments: usize) -> String {
        let mut lines = vec!["{".to_string()];
        lines.extend(calls.iter().map(|call| format!("   {call}(uVar1);")));
        lines.extend((0..assignments).map(|i| format!("   uVar1 = uVar1 + {i};")));
        lines.push("}".to_string());
        lines.join("\n")
    }

    #[test]
    fn a_renamed_callee_pairs_at_70_through_two_paired_callers() {
        // Ladder rung three's headline (ticket #297): a FUN_-renamed
        // internal whose body changed too much to pair, but both its
        // callers are exported names that paired on their own — the
        // call map, built purely from the snapshots' bodies, agrees on
        // the callee through those two paired neighbors.
        let old = snapshot(
            "game.dll",
            "old-hash",
            vec![
                function_with_body("present(void)", 0x1000, "{\n\tFUN_140001337();\n}"),
                function_with_body("startup(void)", 0x1100, "{\n\tFUN_140001337();\n}"),
                function_with_body("FUN_140001337", 0x1200, "{\n\treturn;\n}"),
            ],
            &["present(void)", "startup(void)"],
        );
        let new = snapshot(
            "game.dll",
            "new-hash",
            vec![
                function_with_body("present(void)", 0x4000, "{\n\tFUN_140009937();\n}"),
                function_with_body("startup(void)", 0x4100, "{\n\tFUN_140009937();\n}"),
                function_with_body("FUN_140009937", 0x4200, &padded_body(&[], 10)),
            ],
            &["present(void)", "startup(void)"],
        );

        let document = pair_versions(&old, &new).expect("one identity");
        assert_eq!(
            document.pairings.len(),
            3,
            "the two callers pair by name, the callee through topology"
        );
        let record = document
            .pairings
            .iter()
            .find(|record| record.old_function == "FUN_140001337")
            .expect("the renamed callee pairs through the call graph");
        assert_eq!(record.new_function, "FUN_140009937");
        assert_eq!(record.family, MatchFamily::CallTopology);
        assert_eq!(record.confidence.value(), TOPOLOGY_CONFIDENCE);
        assert!(
            record.confidence.value() < CARRY_OVER_CONFIDENCE_FLOOR,
            "topology alone sits below the carry-over floor"
        );
        assert_eq!(
            record.evidence,
            [
                "call-graph topology through 2 paired neighbors",
                "FUN_140001337 is called by paired neighbor present(void) -> present(void)",
                "FUN_140001337 is called by paired neighbor startup(void) -> startup(void)",
            ],
            "the record names each paired-neighbor line it stood on"
        );
    }

    #[test]
    fn a_lone_paired_neighbor_claims_nothing() {
        // Same call graph, but only one of the two callers still calls
        // the renamed callee in the new listing: a lone agreeing
        // neighbor is a lone signal (ADR-0038) and the callee stays
        // unpaired.
        let old = snapshot(
            "game.dll",
            "old-hash",
            vec![
                function_with_body("present(void)", 0x1000, "{\n\tFUN_140001337();\n}"),
                function_with_body("startup(void)", 0x1100, "{\n\tFUN_140001337();\n}"),
                function_with_body("FUN_140001337", 0x1200, "{\n\treturn;\n}"),
            ],
            &["present(void)", "startup(void)"],
        );
        let new = snapshot(
            "game.dll",
            "new-hash",
            vec![
                function_with_body("present(void)", 0x4000, "{\n\treturn;\n}"),
                function_with_body("startup(void)", 0x4100, "{\n\tFUN_140009937();\n}"),
                function_with_body("FUN_140009937", 0x4200, &padded_body(&[], 10)),
            ],
            &["present(void)", "startup(void)"],
        );

        let document = pair_versions(&old, &new).expect("one identity");
        assert_eq!(
            document
                .pairings
                .iter()
                .filter(|record| record.family == MatchFamily::CallTopology)
                .count(),
            0,
            "one agreeing paired neighbor is not topology"
        );
        assert_eq!(
            document
                .pairings
                .iter()
                .map(|record| record.old_function.as_str())
                .collect::<Vec<_>>(),
            ["present(void)", "startup(void)"],
            "only the name pairs stand"
        );
    }

    #[test]
    fn a_renamed_chain_pairs_through_neighbors_that_converged_themselves() {
        // Propagation iterates to a fixed point (ticket #297's AC):
        // the snapshot lists the chain's leaf first, so the leaf's
        // neighbors are still unpaired when the first pass walks it —
        // it pairs only after the chain's roots have converged through
        // the exported callers. Three renamed links, three claim
        // rounds, one deterministic fixed point.
        let old = snapshot(
            "game.dll",
            "old-hash",
            vec![
                function_with_body("root_a(void)", 0x1000, "{\n\tFUN_14000a101();\n}"),
                function_with_body(
                    "root_b(void)",
                    0x1100,
                    "{\n\tFUN_14000a101();\n\tFUN_14000a202();\n}",
                ),
                function_with_body("FUN_14000a303", 0x1200, "{\n\treturn;\n}"),
                function_with_body("FUN_14000a202", 0x1300, "{\n\tFUN_14000a303();\n}"),
                function_with_body(
                    "FUN_14000a101",
                    0x1400,
                    "{\n\tFUN_14000a202();\n\tFUN_14000a303();\n}",
                ),
            ],
            &["root_a(void)", "root_b(void)"],
        );
        let new = snapshot(
            "game.dll",
            "new-hash",
            vec![
                function_with_body("root_a(void)", 0x4000, &padded_body(&["FUN_14000f777"], 8)),
                function_with_body(
                    "root_b(void)",
                    0x4100,
                    &padded_body(&["FUN_14000f777", "FUN_14000f888"], 7),
                ),
                function_with_body("FUN_14000f999", 0x4200, &padded_body(&[], 10)),
                function_with_body("FUN_14000f888", 0x4300, &padded_body(&["FUN_14000f999"], 9)),
                function_with_body(
                    "FUN_14000f777",
                    0x4400,
                    &padded_body(&["FUN_14000f888", "FUN_14000f999"], 8),
                ),
            ],
            &["root_a(void)", "root_b(void)"],
        );

        let document = pair_versions(&old, &new).expect("one identity");
        assert_eq!(
            document
                .pairings
                .iter()
                .map(|record| (record.old_function.as_str(), record.new_function.as_str()))
                .collect::<Vec<_>>(),
            [
                ("root_a(void)", "root_a(void)"),
                ("root_b(void)", "root_b(void)"),
                ("FUN_14000a303", "FUN_14000f999"),
                ("FUN_14000a202", "FUN_14000f888"),
                ("FUN_14000a101", "FUN_14000f777"),
            ],
            "every renamed link in the chain pairs through converged neighbors"
        );
        for record in document.pairings.iter().skip(2) {
            assert_eq!(record.family, MatchFamily::CallTopology);
            assert_eq!(record.confidence.value(), TOPOLOGY_CONFIDENCE);
        }
        let leaf = document
            .pairings
            .iter()
            .find(|record| record.old_function == "FUN_14000a303")
            .expect("the leaf paired through the chain");
        assert_eq!(
            leaf.evidence,
            [
                "call-graph topology through 2 paired neighbors",
                "FUN_14000a303 is called by paired neighbor FUN_14000a202 -> FUN_14000f888",
                "FUN_14000a303 is called by paired neighbor FUN_14000a101 -> FUN_14000f777",
            ],
            "the leaf names the links that had already converged when it claimed"
        );
    }

    #[test]
    fn a_body_pair_the_topology_agrees_on_rides_above_both_readings() {
        // The agreement bump (the P12.6 flag-family precedent): a
        // byte-equal body pair at 90 that the call graph also agrees
        // on through two paired callers is two independent families
        // reading one pair — the record rides above either single
        // reading, landing on name identity's band without leaving
        // the body family, and gains the neighbor evidence lines.
        let old_body = "\
{
   uint uVar1;
   uVar1 = DAT_140045a68;
   if (uVar1 != 0) {
      FUN_140002000(uVar1);
   }
   return;
}";
        let new_body = "\
{
   uint iVar4;
   iVar4 = DAT_140049a68;
   if (iVar4 != 0) {
      FUN_140002000(iVar4);
   }
   return;
}";
        let old = snapshot(
            "game.dll",
            "old-hash",
            vec![
                function_with_body("present(void)", 0x1000, "{\n\tFUN_14000c001();\n}"),
                function_with_body("startup(void)", 0x1100, "{\n\tFUN_14000c001();\n}"),
                function_with_body("FUN_14000c001", 0x1200, old_body),
            ],
            &["present(void)", "startup(void)"],
        );
        let new = snapshot(
            "game.dll",
            "new-hash",
            vec![
                function_with_body("present(void)", 0x4000, "{\n\tFUN_14000dd99();\n}"),
                function_with_body("startup(void)", 0x4100, "{\n\tFUN_14000dd99();\n}"),
                function_with_body("FUN_14000dd99", 0x4200, new_body),
            ],
            &["present(void)", "startup(void)"],
        );

        let document = pair_versions(&old, &new).expect("one identity");
        assert_eq!(
            document.pairings.len(),
            3,
            "two name pairs and the corroborated body pair"
        );
        let record = document
            .pairings
            .iter()
            .find(|record| record.old_function == "FUN_14000c001")
            .expect("the moved internal still pairs through the body family");
        assert_eq!(record.new_function, "FUN_14000dd99");
        assert_eq!(
            record.family,
            MatchFamily::NormalizedBody,
            "a corroborating topology is not a competing claim"
        );
        assert_eq!(
            record.confidence.value(),
            BODY_EQUAL_CONFIDENCE + TOPOLOGY_AGREEMENT_BUMP
        );
        assert!(record.confidence.value() > BODY_EQUAL_CONFIDENCE);
        assert!(record.confidence.value() > TOPOLOGY_CONFIDENCE);
        assert_eq!(
            record.evidence,
            [
                "normalized bodies are byte-equal (8 lines)",
                "call-graph topology corroborates through 2 paired neighbors",
                "FUN_14000c001 is called by paired neighbor present(void) -> present(void)",
                "FUN_14000c001 is called by paired neighbor startup(void) -> startup(void)",
            ],
            "the body record keeps its body line and gains the neighbor lines"
        );
        for record in document.pairings.iter().take(2) {
            assert_eq!(record.family, MatchFamily::NameIdentity);
            assert_eq!(record.confidence.value(), NAME_IDENTITY_CONFIDENCE);
            assert!(
                record
                    .evidence
                    .iter()
                    .all(|line| !line.contains("paired neighbor")),
                "name pairs that topology merely repeats are left alone"
            );
        }
    }

    #[test]
    fn an_exported_demangled_name_keeps_the_export_evidence() {
        // A C++ export reads as both families at once; generation puts
        // the exported claim first and resolution drops the candidate's
        // second claim on the very same pair.
        let name = "ns::widget_draw(void)";
        let old = snapshot(
            "game.dll",
            "old-hash",
            vec![function(name, 0x1000)],
            &[name],
        );
        let new = snapshot(
            "game.dll",
            "new-hash",
            vec![function(name, 0x8000)],
            &[name],
        );

        let document = pair_versions(&old, &new).expect("one identity");
        assert_eq!(document.pairings.len(), 1, "one pair, one record");
        assert_eq!(
            document.pairings[0].evidence,
            [format!("exported name {name}")]
        );
    }

    #[test]
    fn pairings_stand_in_old_scan_order() {
        // Two scans of one version pair diff cleanly: records come back
        // in the old listing's order, not the order they were resolved.
        let old = snapshot(
            "game.dll",
            "old-hash",
            vec![function("zeta", 1), function("alpha", 2)],
            &["zeta", "alpha"],
        );
        let new = snapshot(
            "game.dll",
            "new-hash",
            vec![function("alpha", 3), function("zeta", 4)],
            &["alpha", "zeta"],
        );

        let document = pair_versions(&old, &new).expect("one identity");
        let old_side: Vec<&str> = document
            .pairings
            .iter()
            .map(|r| r.old_function.as_str())
            .collect();
        assert_eq!(old_side, ["zeta", "alpha"]);
    }

    #[test]
    fn the_document_names_both_hashes_and_both_full_listings() {
        // A stale document must be detectable — it names the exact byte
        // pair it was computed for — and the review side (the CLI
        // breakdown, #300) derives old-only and new-only from the two
        // complete listings.
        let old = snapshot(
            "game.dll",
            "aaa",
            vec![
                function("fixture_init", 0x1000),
                function("FUN_10001200", 0x1200),
            ],
            &["fixture_init"],
        );
        let new = snapshot(
            "game.dll",
            "bbb",
            vec![
                function("fixture_init", 0x4000),
                function("brand_new", 0x5000),
            ],
            &["fixture_init", "brand_new"],
        );

        let document = pair_versions(&old, &new).expect("one identity");
        assert_eq!(document.binary, "game.dll");
        assert_eq!(document.old_bytes_sha256, "aaa");
        assert_eq!(document.new_bytes_sha256, "bbb");
        assert_eq!(document.old_functions, ["fixture_init", "FUN_10001200"]);
        assert_eq!(document.new_functions, ["fixture_init", "brand_new"]);
        assert_eq!(document.pairings.len(), 1);
    }

    #[test]
    fn two_different_binary_identities_are_refused() {
        // The pass pairs versions of one binary; mixing identities is a
        // caller error it names, not a pairing it guesses at.
        let old = snapshot("a.dll", "aaa", Vec::new(), &[]);
        let new = snapshot("b.dll", "bbb", Vec::new(), &[]);
        match pair_versions(&old, &new) {
            Err(BdiffError::IdentityMismatch { old, new }) => {
                assert_eq!(old, "a.dll");
                assert_eq!(new, "b.dll");
            }
            other => panic!("expected the identity refusal, got {other:?}"),
        }
    }
}
