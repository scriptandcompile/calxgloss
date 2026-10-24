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
    /// scan wrote it. Unused by name-identity pairing; held for the
    /// body-equivalence and call-map families that land with #296 and
    /// #297.
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
/// The ladder opens with name identity (this track's #295); the
/// normalized-body and call-graph-topology families land with #296 and
/// #297 and extend this enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchFamily {
    /// An exported name or a demangled name matches exactly across the
    /// two versions — the binary's own spelling for the function on
    /// both sides. Scores [`NAME_IDENTITY_CONFIDENCE`].
    NameIdentity,
}

impl MatchFamily {
    /// The family's stable name, as the pairing document and the later
    /// CLI breakdown spell it.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::NameIdentity => "name_identity",
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
    fn match_families_serialize_as_their_stable_names() {
        let json = serde_json::to_string(&MatchFamily::NameIdentity).expect("serializable");
        assert_eq!(json, "\"name_identity\"");
        assert_eq!(MatchFamily::NameIdentity.as_str(), "name_identity");
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
