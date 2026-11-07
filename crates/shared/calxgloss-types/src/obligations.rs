//! Whether a target binary's restitch work is finished is a claim, and the
//! obligation ledger is the record that claim must answer to. The record
//! shape grows here, ahead of the tickets that will file and read it
//! (track P26, issue #417).
//!
//! "Queue empty" is not "binary done". This module grows the record that
//! later tickets will file and read: one **obligation ledger** per target
//! binary, holding one entry per unit of restitch work. Each entry names the
//! unit's function and attempt, its owner (the attempt branch's head commit
//! digest), the **case kinds** its baseline suite must cover from a closed
//! roster, the verifier-receipt digest it cites wherever it claims green,
//! and its **disposition** from a closed roster. No free-text status exists
//! anywhere: invented values refuse at the deserializer. The document seals
//! itself with a **closure digest** over its canonical content, so a reader
//! who never saw the writer re-derives the same digest from the filed bytes
//! alone — a tampered or replaced ledger reads as an input error, never as
//! a clean run.

use std::path::{Path, PathBuf};

use serde::de::Error as _;
use serde::{Deserialize, Serialize};

use crate::display_serde_label;
use crate::error::TypesError;
use crate::identity::BinaryIdentity;
use crate::persist::{PersistError, load_json};

// ============================================================
// The closed sets: case kind and disposition
// ============================================================

/// What kind of try a baseline case is — the closed roster the P26 spec
/// decides (issue #417). A later track may narrow which kinds an obligation
/// requires by signature; this roster is what that track extends, and no
/// producer can invent a fourth kind of try.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaseKind {
    /// A try with an ordinary well-formed input: the unit is asked to do
    /// its normal job and the suite expects the honest result.
    Positive,
    /// A try with a well-formed input aimed at an error path: the unit is
    /// asked to reject or survive the input, and the suite expects that
    /// refusal, not a crash.
    Negative,
    /// A try with an input the function cannot honestly take: wrong shape,
    /// truncated, or out of range. The suite expects a safe refusal, never
    /// silent acceptance.
    Malformed,
}

display_serde_label!(CaseKind {
    Positive => "positive",
    Negative => "negative",
    Malformed => "malformed",
});

impl CaseKind {
    /// Every kind the roster declares, in declaration order. Every unit
    /// obligation requires exactly this set until a later track narrows
    /// requirements by signature (issue #417, decided with the spec).
    pub const ALL: [CaseKind; 3] = [CaseKind::Positive, CaseKind::Negative, CaseKind::Malformed];
}

/// The declared roster of case kinds, in declaration order — the same three
/// labels every producer and reader pairs against.
pub const DECLARED_CASE_KINDS: &[&str] = &["positive", "negative", "malformed"];

/// Where a unit's obligation stands, from the closed disposition roster the
/// P26 spec decides (issue #417). Each value records an honest fact about
/// the unit; none counts as verified work except [`Self::ClaimedVerified`],
/// and that one only rides with a cited verifier receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObligationDisposition {
    /// The unit claims green: its attempt merged and the entry cites the
    /// verifier receipt that justifies the claim. A claim with no citation
    /// is an input error for the reader, never a pass.
    ClaimedVerified,
    /// The operator held the unit out of work — the skip set named it.
    Skipped,
    /// Classification parked the unit: a do-not-translate binary's units
    /// carry the classification's reason, never ordinary work.
    Parked,
    /// An operator override replaced a system judgment about the unit;
    /// overruling never counts as verification.
    Overridden,
    /// The attempt reached review without an Accept action: review is the
    /// only door into verified, and an un-reviewed merge stays here.
    UnReviewed,
    /// No baseline case ever covered the unit's export: its behavior was
    /// never exercised.
    NoBaseline,
}

display_serde_label!(ObligationDisposition {
    ClaimedVerified => "claimed_verified",
    Skipped => "skipped",
    Parked => "parked",
    Overridden => "overridden",
    UnReviewed => "un_reviewed",
    NoBaseline => "no_baseline",
});

/// The declared roster of dispositions, in declaration order. Six names,
/// each an honest fact a producer can state at filing time; none is a
/// catch-all and no seventh exists.
pub const DECLARED_DISPOSITIONS: &[&str] = &[
    "claimed_verified",
    "skipped",
    "parked",
    "overridden",
    "un_reviewed",
    "no_baseline",
];

// ============================================================
// The obligation entry and the ledger document
// ============================================================

/// One unit's obligation in the ledger: the (function, attempt) pair joined
/// with the document's binary forms the unit key and attempt — the triple
/// everything else in the harness joins on (issue #417).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "ObligationEntryWire")]
pub struct ObligationEntry {
    /// The unit's function name, joined with the ledger document's binary
    /// verbatim to spell the unit key.
    pub function: String,
    /// The attempt this obligation is about, 1-based like every other
    /// attempt number in the harness.
    pub attempt: u32,
    /// The owner: the attempt branch's head commit digest, pinning the
    /// green claim to the exact content it was made about.
    pub owner_commit: String,
    /// The case kinds this obligation requires. Until a later track
    /// narrows by signature, that is the whole closed roster — every
    /// entry must demand all of [`CaseKind::ALL`]; the deserializer
    /// refuses a subset (issue #417).
    pub required_case_kinds: Vec<CaseKind>,
    /// The verifier-receipt digest this entry cites, present wherever the
    /// unit claims green. A green claim with no citation is an invalid
    /// entry: the deserializer refuses it rather than letting it read as
    /// a pass (issue #417).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receipt_digest: Option<String>,
    /// Where the unit stands, from the closed disposition roster. The
    /// fact and its provenance; a disposition never counts as verified
    /// work it did not do.
    pub disposition: ObligationDisposition,
}

/// The shape an [`ObligationEntry`] deserializes through: the fields
/// plain, plus the entry-level validity the filed record must carry —
/// the full case-kind roster and a receipt citation wherever the entry
/// claims verified (issue #417).
#[derive(Deserialize)]
struct ObligationEntryWire {
    function: String,
    attempt: u32,
    owner_commit: String,
    #[serde(deserialize_with = "deserialize_required_case_kinds")]
    required_case_kinds: Vec<CaseKind>,
    #[serde(default)]
    receipt_digest: Option<String>,
    disposition: ObligationDisposition,
}

impl TryFrom<ObligationEntryWire> for ObligationEntry {
    type Error = String;

    fn try_from(wire: ObligationEntryWire) -> Result<Self, Self::Error> {
        if wire.disposition == ObligationDisposition::ClaimedVerified
            && wire.receipt_digest.is_none()
        {
            return Err(format!(
                "the obligation entry for `{}` attempt {} claims verified without citing a verifier receipt",
                wire.function, wire.attempt
            ));
        }
        Ok(Self {
            function: wire.function,
            attempt: wire.attempt,
            owner_commit: wire.owner_commit,
            required_case_kinds: wire.required_case_kinds,
            receipt_digest: wire.receipt_digest,
            disposition: wire.disposition,
        })
    }
}

impl ObligationEntry {
    /// Build one entry for `(function, attempt)` owned by `owner_commit`,
    /// stamped with its disposition. A fresh obligation always requires
    /// every declared case kind and cites no receipt until the filing
    /// producer resolves the unit's verifier receipt.
    pub fn new(
        function: impl Into<String>,
        attempt: u32,
        owner_commit: impl Into<String>,
        disposition: ObligationDisposition,
    ) -> Self {
        Self {
            function: function.into(),
            attempt,
            owner_commit: owner_commit.into(),
            required_case_kinds: CaseKind::ALL.to_vec(),
            receipt_digest: None,
            disposition,
        }
    }
}

/// The entry-level roster closure (issue #417): an obligation's
/// `required_case_kinds` must name every declared case kind, in any
/// order and without repeats. Today every unit requires all three; a
/// later track that narrows requirements by signature extends this
/// fold rather than letting a reader quietly accept a subset.
fn deserialize_required_case_kinds<'de, D>(deserializer: D) -> Result<Vec<CaseKind>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let kinds = Vec::<CaseKind>::deserialize(deserializer)?;
    let mut sorted = kinds.clone();
    sorted.sort();
    sorted.dedup();
    if sorted != CaseKind::ALL.to_vec() {
        let label = |kinds: &[CaseKind]| {
            kinds
                .iter()
                .map(|kind| kind.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        };
        return Err(serde::de::Error::custom(format!(
            "an obligation must require every declared case kind ({}) — got a roster of ({})",
            label(&CaseKind::ALL),
            label(&kinds),
        )));
    }
    Ok(kinds)
}

/// The pipeline's per-binary obligation ledger: one entry per unit of
/// restitch work for one target binary, filed as
/// `re/obligations/<binary identity>.json` (issue #417).
///
/// Like the unknown ledger, each batch's filing replaces the last outright,
/// and the filing envelope — which binary the document speaks for and when
/// it was filed — is required at read: a document without it is refused,
/// not read. The `digest` is the document's own **closure digest**, stamped
/// at filing by [`Self::file`] and re-derivable by any reader from the
/// filed bytes alone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObligationLedger {
    /// The binary identity this ledger was filed for, verbatim including
    /// extension — the key that sidesteps the attempt-branch name
    /// normalization's collision shape and joins with the unknown ledgers.
    pub binary: BinaryIdentity,
    /// When the ledger was filed, as a Unix timestamp in seconds.
    pub filed_at: u64,
    /// The obligations, in the writer's deterministic scan order. The
    /// closure digest canonicalizes entry order itself, so a re-filing
    /// that hands in the same entries in another order seals the same.
    pub entries: Vec<ObligationEntry>,
    /// The closure digest over this document's canonical content (see
    /// [`Self::content_digest`]), stamped at filing. Every reader
    /// re-derives it; a mismatch is an input error, not a reading.
    pub digest: String,
}

impl ObligationLedger {
    /// File one binary's ledger: the envelope is stamped with `binary`
    /// verbatim and the filing time `now`, the entries keep the writer's
    /// scan order, and the closure digest is stamped over the canonical
    /// content so every later reader can re-derive it from the filed
    /// bytes alone (issue #417).
    pub fn file(
        binary: impl Into<BinaryIdentity>,
        entries: Vec<ObligationEntry>,
        now: u64,
    ) -> Result<Self, TypesError> {
        let mut ledger = Self {
            binary: binary.into(),
            filed_at: now,
            entries,
            digest: String::new(),
        };
        ledger.digest = ledger.content_digest()?;
        Ok(ledger)
    }

    /// The canonical closure digest: sha256 over the document's binary
    /// identity and its entries sorted into one deterministic order —
    /// unit key, then attempt, then every remaining field as a tie
    /// breaker — with fixed keys and lowercase hex, prefixed `sha256:`
    /// like every other content digest the record tree carries.
    ///
    /// Two things deliberately stay out of the fold. The `digest` field
    /// itself, so a reader of a filed document re-derives the same value
    /// from the filed bytes. And `filed_at`, so successive batches whose
    /// records did not change seal to the same digest and can be diffed
    /// by digest to see exactly what moved (issue #392, story 25).
    pub fn content_digest(&self) -> Result<String, TypesError> {
        use sha2::{Digest as _, Sha256};
        let mut sorted = self.entries.clone();
        sorted.sort_by(|a, b| {
            (
                &a.function,
                a.attempt,
                &a.owner_commit,
                a.receipt_digest.as_deref(),
                &a.required_case_kinds,
                &a.disposition,
            )
                .cmp(&(
                    &b.function,
                    b.attempt,
                    &b.owner_commit,
                    b.receipt_digest.as_deref(),
                    &b.required_case_kinds,
                    &b.disposition,
                ))
        });
        let canonical = serde_json::json!({
            "binary": self.binary.as_str(),
            "entries": sorted,
        });
        let bytes = serde_json::to_vec(&canonical)?;
        let sum = Sha256::digest(&bytes);
        let hex: String = sum.iter().map(|byte| format!("{byte:02x}")).collect();
        Ok(format!("sha256:{hex}"))
    }
}

/// The record tree's obligation-ledger directory: `re/obligations/<workspace>`,
/// beside the unknown ledgers. The pipeline owns the ledger documents filed
/// here, one per target binary (issue #417).
pub fn obligation_ledger_dir(workspace: impl AsRef<Path>) -> PathBuf {
    workspace.as_ref().join("re").join("obligations")
}

/// The path of one binary's obligation ledger:
/// `re/obligations/<binary identity>.json`, keyed by the binary identity
/// verbatim including extension.
pub fn obligation_ledger_path(workspace: impl AsRef<Path>, binary: &BinaryIdentity) -> PathBuf {
    obligation_ledger_dir(workspace).join(format!("{binary}.json"))
}

/// Read one binary's obligation ledger. The readings stay distinct the
/// way the unknown ledger keeps its three: no document at all is a
/// [`PersistError::NotFound`] — recomputable-missing, the state a later
/// verdict names as *no ledger filed* — while corrupt bytes, a tampered
/// document, and a replaced one are all [`PersistError::Json`], input
/// errors that fail loudly and are never read as clean. Concretely the
/// reader checks the envelope names the binary it was asked for (a
/// validly sealed ledger for another binary is a replaced document), and
/// re-derives the closure digest from the filed bytes and refuses unless
/// it matches the stamped one — so an edit that keeps the old seal is
/// caught, and a re-sealed document has to reproduce every entry to pass
/// at all. A filed document missing its envelope or digest fails here
/// too, at the deserializer.
pub fn read_obligation_ledger(
    workspace: impl AsRef<Path>,
    binary: &BinaryIdentity,
) -> Result<ObligationLedger, PersistError> {
    let path = obligation_ledger_path(workspace, binary);
    let ledger: ObligationLedger = load_json(&path)?;
    if ledger.binary != *binary {
        return Err(PersistError::Json {
            path,
            source: serde_json::Error::custom(format!(
                "obligation ledger names `{}` in its envelope, not the asked-for `{binary}` \u{2014} a replaced or misfiled document is an input error",
                ledger.binary
            )),
        });
    }
    let re_derived = ledger.content_digest().map_err(|err| PersistError::Json {
        path: path.clone(),
        source: match err {
            TypesError::Serialization(source) => source,
            other => serde_json::Error::custom(other.to_string()),
        },
    })?;
    if re_derived != ledger.digest {
        return Err(PersistError::Json {
            path,
            source: serde_json::Error::custom(format!(
                "obligation ledger digest mismatch: filed {}, re-derived {re_derived} from the filed bytes \u{2014} a tampered document is an input error, never a reading",
                ledger.digest
            )),
        });
    }
    Ok(ledger)
}

#[cfg(test)]
mod tests;
