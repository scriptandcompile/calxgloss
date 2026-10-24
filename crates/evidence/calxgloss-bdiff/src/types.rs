//! The document model: the two scan snapshots the pairing pass reads
//! and the one pairing document it writes.
//!
//! A [`ScanSnapshot`] is one scan's in-memory function listing — the
//! documents a scan already persists, assembled by the caller, never a
//! live engine read (ADR-0026). The pass pairs the old snapshot's
//! functions with the new snapshot's and emits one [`PairingDocument`]
//! per (binary identity, old bytes, new bytes): a resolved one-to-one
//! set of [`PairingRecord`]s, each naming its [`MatchFamily`] and its
//! evidence lines, beside both complete function listings so a consumer
//! can name the functions paired on neither side.
//!
//! The document names both byte hashes ([`PairingDocument::old_bytes_sha256`]
//! and [`PairingDocument::new_bytes_sha256`]) so a document left behind
//! by a since-replaced version is detectable rather than silently trusted.

use calxgloss_types::{BinaryIdentity, Confidence};
use serde::{Deserialize, Serialize};

/// Confidence of a name-identity pair: an exported name or a demangled
/// name is the binary's own name for the function, so one present in
/// both versions is the strongest pairing evidence this ladder opens
/// with — short of byte-proven body equivalence (track #233's match
/// ladder). It sits one band below certainty because stripped exports
/// and demangler rewrites can still rename the same code.
pub const NAME_IDENTITY_CONFIDENCE: u8 = 95;

/// Confidence of a byte-equal normalized body: two kept bodies that,
/// put through the shared libmatch normalizer, come out the same shape
/// are the same function moved — the address shift renamed its `FUN_…`
/// spelling and the rebuild re-lettered its variables, but the shape
/// survived (track #233's match ladder, rung two). One band below name
/// identity, because an inlined identical body can still be two
/// distinct functions; short of byte-proven, which nothing textual is.
pub const BODY_EQUAL_CONFIDENCE: u8 = 90;

/// The body family's similarity floor, in percent of normalized lines
/// a near-equal pair must still share: below it the two bodies are
/// clearly different shapes, and a pair that shares almost no line is
/// a coincidence of listing, not a moved function — the lone-
/// structural-coincidence refusal of ADR-0038 again. It is the band's
/// lower edge for this family: the ratio maps a passing pair to a
/// confidence strictly between the carry-over floor and 90, and
/// anything below claims nothing.
pub const BODY_SIMILARITY_FLOOR: u8 = 60;

/// Confidence of a call-graph-topology pair: a function neither the name
/// nor body families claimed pairs because its call neighborhood agrees —
/// already-paired functions reach it on both sides through call edges,
/// propagated to a fixed point over the body-derived call map (ADR-0024's
/// rails). The score is the scan correlation detector's band (ADR-0022's
/// ladder): two functions' neighborhoods agreeing on a pair beats any
/// single body's shape, but a *renamed* neighborhood still infers the
/// relationship rather than quoting it, so it sits below the body family —
/// and below the carry-over floor. Alone it cannot drive carry-over;
/// corroborating a body-family pair lifts that record instead (ticket
/// #297, track #233's ladder rung three).
pub const TOPOLOGY_CONFIDENCE: u8 = 70;

/// How many paired neighbors a topological propagation claim requires:
/// two neighbors corroborate the neighborhood from two readings; one
/// paired neighbor is a lone coincidence, and a lone signal claims
/// nothing (ADR-0038 again, ticket #297's propagation gate).
pub const TOPOLOGY_MIN_PAIRED_NEIGHBORS: usize = 2;

/// How much a corroborated reading rides up the record: when the call map
/// agrees on a pair the body family already claimed, two independent
/// families read one pair, and the flag-family agreement precedent
/// (P12.6's merged families scored above the per-function groups —
/// agreement beats any single reading) lifts the record one bump above
/// its family score. The bump keeps the ladder intact: a corroborated
/// byte-equal body pair reaches name identity's 95, never past it.
pub const TOPOLOGY_AGREEMENT_BUMP: u8 = 5;

/// The carry-over confidence floor: only pairings at or above this
/// score may seed a new-version unit from an old accepted translation
/// (track #233). Named after the libmatch Skip-classification floor's
/// precedent — same score, same discipline: the floor is an
/// instruction downstream consumers apply, not a filter on the record.
/// The pairing pass persists every resolved pairing regardless of the
/// floor, and a below-floor or unpaired function queues fresh exactly
/// as today, so a wrong pairing can never silently seed a wrong
/// translation.
pub const CARRY_OVER_CONFIDENCE_FLOOR: u8 = 80;

/// One function as a scan snapshot listed it.
///
/// The snapshot carries the listing's own spelling verbatim — an export
/// name, a demangled name, or the address-derived `FUN_…` name the
/// scan falls back to — because which spelling a name is decides which
/// pairing families can claim it. The body rides along so the
/// follow-up families of the ladder (normalized-body equivalence and
/// call-graph topology, track #233) consume the same snapshot without
/// a widening change; the name-identity pass reads only the name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionEntry {
    /// The name the scan lists the function under.
    pub name: String,

    /// The function entry point's address in the scan's image. Carried
    /// for audit and for the lone-signal gate's tests — a lone address
    /// equality (or a lone matching `FUN_…` spelling, which is itself
    /// address-derived) claims nothing (ADR-0038).
    pub address: u64,

    /// The decompiled body the scan kept for this function, as the
    /// scan wrote it. Read by the normalized-body family (#296), which
    /// puts it through the shared libmatch normalizer, and by the call-
    /// graph family (#297), whose call map is derived from these bodies
    /// with no engine read (ADR-0024's rails); unused by name-identity
    /// pairing.
    pub body: String,
}

/// One version's scan listing, as an in-memory document.
///
/// The pairing pass is pure text and structure over two snapshots:
/// documents in, pairing document out. Assembling a snapshot from a
/// scan's cached documents is the caller's job (the auto run's trigger,
/// #298); this crate never reads an engine (ADR-0026, ADR-0020).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanSnapshot {
    /// The binary identity the scan read — the join key both snapshots
    /// must share.
    pub binary: BinaryIdentity,

    /// SHA-256 (hex) of that version's file bytes, the same hash the
    /// scan cache directory is minted under (ADR-0043). The pairing
    /// document records both snapshots' hashes so a stale document is
    /// detectable.
    pub bytes_sha256: String,

    /// The scanned functions, in the scan's own listing order — scan
    /// order is what ties resolve by and what keeps two documents of
    /// one version pair diff-friendly.
    pub functions: Vec<FunctionEntry>,

    /// The names in this version's export table. A shared function name
    /// that appears here on both sides pairs through the name-identity
    /// family as an exported name.
    pub exports: Vec<String>,
}

impl ScanSnapshot {
    /// The full function listing as names, in scan order.
    pub fn function_names(&self) -> Vec<String> {
        self.functions
            .iter()
            .map(|entry| entry.name.clone())
            .collect()
    }
}

/// The evidence family that paired two functions. One family per
/// record: the pairing pass resolves competing families down to the
/// strongest claim per function (ADR-0022), so a record names the one
/// family that won.
///
/// The ladder opens with name identity (#295), adds the normalized-body
/// family with #296, and closes with the call-graph-topology family
/// (#297). A topology reading that corroborates a pair the body family
/// won stays corroboration, not a competing family: the record keeps
/// `NormalizedBody` and rides the agreement bump.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchFamily {
    /// An exported name or a demangled name matches exactly across the
    /// two versions — the binary's own spelling for the function on
    /// both sides. Scores [`NAME_IDENTITY_CONFIDENCE`].
    NameIdentity,
    /// The two kept bodies, put through the shared libmatch normalizer
    /// (#294's cross-crate entry point), come out one shape — byte-
    /// equal normalized bodies score [`BODY_EQUAL_CONFIDENCE`], and a
    /// near-equal pair scores on its structural-diff ratio beside it.
    NormalizedBody,
    /// The function's call neighborhood agrees: at least
    /// [`TOPOLOGY_MIN_PAIRED_NEIGHBORS`] already-paired callers and/or
    /// callees reach the pair on both sides through call edges of the
    /// body-derived call map (ADR-0024's rails), propagated to a fixed
    /// point. Scores [`TOPOLOGY_CONFIDENCE`] — below the carry-over
    /// floor on its own; records name their paired-neighbor evidence
    /// lines.
    CallTopology,
}

impl MatchFamily {
    /// The family's stable name, as the pairing document and the later
    /// CLI breakdown spell it.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::NameIdentity => "name_identity",
            Self::NormalizedBody => "normalized_body",
            Self::CallTopology => "call_topology",
        }
    }
}

/// One resolved old↔new function pairing.
///
/// The pair names are the snapshots' own spellings, so the record joins
/// to the corpus the way every other artifact does. The evidence lines
/// say *why* the pair claims — the shared name and the family that
/// carried it — so an engineer can audit a carry-over without
/// re-deriving the pass.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairingRecord {
    /// The old-version function's name, as the old snapshot listed it.
    pub old_function: String,

    /// The new-version function's name, as the new snapshot listed it.
    pub new_function: String,

    /// The evidence family that carried the pair.
    pub family: MatchFamily,

    /// The family's score on the Evidence scale, kept as the shared
    /// [`Confidence`] type the whole corpus rates evidence with.
    pub confidence: Confidence,

    /// The evidence lines that carried the claim, strongest reading
    /// first. Never empty: a pairing without evidence claims nothing.
    pub evidence: Vec<String>,
}

/// One version-pair's pairing document: the resolved pairings beside
/// the two complete function listings and both byte hashes, persisted
/// as one JSON document per (binary identity, old bytes, new bytes)
/// under `re/analysis/bdiff/` (see [`crate::persist::BdiffPersistor`]).
///
/// The two listings make the document self-contained for the review
/// side of the track: the functions paired on neither side — old-only
/// and new-only — are the listings minus the paired names (the CLI
/// breakdown, #300). The two hashes make staleness detectable: a
/// document naming a hash pair the workspace's current scans no longer
/// carries is a stale document, and nothing silently trusts it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairingDocument {
    /// The binary identity both snapshots share, spelled as every
    /// persisted artifact spells it — the bare filename.
    pub binary: String,

    /// SHA-256 (hex) of the old version's file bytes.
    pub old_bytes_sha256: String,

    /// SHA-256 (hex) of the new version's file bytes.
    pub new_bytes_sha256: String,

    /// The old snapshot's full function listing, in scan order.
    pub old_functions: Vec<String>,

    /// The new snapshot's full function listing, in scan order.
    pub new_functions: Vec<String>,

    /// The resolved pairings, in old scan order — two documents of one
    /// version pair diff cleanly. Every record stands at or above no
    /// floor: [`CARRY_OVER_CONFIDENCE_FLOOR`] is applied by the
    /// carry-over consumer (#299), never by the pass.
    pub pairings: Vec<PairingRecord>,
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_name_identity_band_is_95() {
        // The ladder's opening rung: the binary's own name, present on
        // both sides, is near-certain but not byte-proven.
        assert_eq!(NAME_IDENTITY_CONFIDENCE, 95);
    }

    #[test]
    fn the_carry_over_floor_is_the_libmatch_precedent_80() {
        // Named constant, named score: pairings at or above this can
        // drive carry-over; below it, today's fresh queue exactly.
        assert_eq!(CARRY_OVER_CONFIDENCE_FLOOR, 80);
        assert!(Confidence::new(NAME_IDENTITY_CONFIDENCE).at_least(CARRY_OVER_CONFIDENCE_FLOOR));
    }

    #[test]
    fn the_byte_equal_body_band_is_90() {
        // The body ladder's top rung: byte-equal normalized shapes are
        // the moved function itself, a band below the binary's own
        // spelling but still able to drive carry-over.
        assert_eq!(BODY_EQUAL_CONFIDENCE, 90);
        assert!(Confidence::new(BODY_EQUAL_CONFIDENCE).at_least(CARRY_OVER_CONFIDENCE_FLOOR));
    }

    #[test]
    fn the_body_similarity_floor_is_sixty_percent_of_normalized_lines() {
        // Below this share of shared normalized lines the bodies are
        // clearly different shapes and the family claims nothing; at
        // or above it the ratio maps the pair beside the 90.
        assert_eq!(BODY_SIMILARITY_FLOOR, 60);
    }

    #[test]
    fn the_topology_band_is_70_below_the_carry_over_floor() {
        // Ladder rung three, ADR-0024's band: two neighborhoods agreeing
        // outranks a single body reading, but a below-floor score alone
        // can never seed a carry-over — the record stands, the consumer
        // refuses it (#299 applies the floor).
        assert_eq!(TOPOLOGY_CONFIDENCE, 70);
        assert!(
            !Confidence::new(TOPOLOGY_CONFIDENCE).at_least(CARRY_OVER_CONFIDENCE_FLOOR),
            "a topology claim on its own never reaches the carry-over floor"
        );
    }

    #[test]
    fn a_propagation_claim_needs_two_paired_neighbors() {
        // A lone paired neighbor is a lone signal: the ADR-0038 refusal
        // spelled in neighborhood form (ticket #297).
        assert_eq!(TOPOLOGY_MIN_PAIRED_NEIGHBORS, 2);
    }

    #[test]
    fn the_agreement_bump_beats_either_reading_without_leaving_the_ladder() {
        // The flag-family precedent: agreement outranks any single
        // reading. The byte-equal 90 corroborated by topology rides the
        // bump to exactly name identity's 95 — never past the ladder's
        // top rung.
        assert_eq!(TOPOLOGY_AGREEMENT_BUMP, 5);
        assert_eq!(
            BODY_EQUAL_CONFIDENCE + TOPOLOGY_AGREEMENT_BUMP,
            NAME_IDENTITY_CONFIDENCE
        );
        assert!(
            Confidence::new(BODY_EQUAL_CONFIDENCE + TOPOLOGY_AGREEMENT_BUMP)
                .at_least(TOPOLOGY_CONFIDENCE + 1),
            "the corroborated pair outranks the topology reading alone"
        );
    }

    #[test]
    fn match_families_serialize_as_their_stable_names() {
        let json = serde_json::to_string(&MatchFamily::NameIdentity).expect("serializable");
        assert_eq!(json, "\"name_identity\"");
        assert_eq!(MatchFamily::NameIdentity.as_str(), "name_identity");
        let json = serde_json::to_string(&MatchFamily::CallTopology).expect("serializable");
        assert_eq!(json, "\"call_topology\"");
        assert_eq!(MatchFamily::CallTopology.as_str(), "call_topology");
    }

    #[test]
    fn a_function_listing_keeps_scan_order() {
        let snapshot = ScanSnapshot {
            binary: BinaryIdentity::new("game.dll"),
            bytes_sha256: "old".into(),
            functions: vec![
                FunctionEntry {
                    name: "second".into(),
                    address: 2,
                    body: String::new(),
                },
                FunctionEntry {
                    name: "first".into(),
                    address: 1,
                    body: String::new(),
                },
            ],
            exports: Vec::new(),
        };
        assert_eq!(snapshot.function_names(), ["second", "first"]);
    }
}
