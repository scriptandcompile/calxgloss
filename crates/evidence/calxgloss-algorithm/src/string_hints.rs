//! String-guided algorithm hints.
//!
//! This module provides [`StringHintEngine`], which carries the string
//! signatures — literal spellings that name a known algorithm, like
//! `CRC` or `inflate` — that a function's decompiled body and the
//! binary's string listing are scanned against. Each signature is a
//! [`StringSignature`]: a named algorithm, its category, the marker
//! spellings that suggest it, and whether those markers answer the
//! scanned text with case folded away.
//!
//! [`default_signatures`] carries the standard signature set — crc,
//! checksum, inflate, deflate, gzip, bz2, lzo, serialize, deserialize,
//! md5, sha, hmac, http, tcp, udp — and
//! [`StringHintEngine::with_default_signatures`] builds an engine that
//! scans against it.
//!
//! A scan reports each algorithm at most once per function: when
//! several signatures name the same algorithm, the hint with the
//! strongest evidence stands, in the place the algorithm first
//! appeared.
//!
//! Unlike a control flow match, which reads the shapes inside one
//! function, a string signature can also fire on program-wide evidence:
//! a marker that appears only in the binary's string listing ties the
//! program to the algorithm, not the function, so the engine weighs a
//! listing-only match below a match the function's own body carries.

use crate::cfg_patterns::line_at;
use crate::types::{AlgorithmCategory, AlgorithmHint, DetectionMethod};
use calxgloss_ghidra::{DecompiledFunction, StringLiteral};
use calxgloss_types::Confidence;
use serde::{Deserialize, Serialize};

// ============================================================
// Hint confidence
// ============================================================

/// Confidence of a body match: the function's own decompiled text
/// carries the marker, so the algorithm's name sits right where the
/// function's behavior is spelled out — but a substring hit is
/// approximate, a `CRC` in a format string evidences use rather than
/// implementation, so the hint sits beside a control flow match as a
/// hypothesis for the translation prompt, not a fact applied to the
/// program.
const BODY_CONFIDENCE: u8 = 60;

/// Confidence of a listing-only match: the marker appears somewhere in
/// the binary's string listing but not in this function's body, so the
/// evidence ties the program to the algorithm rather than the function
/// to its implementation — a weak lead worth carrying, not one to
/// weigh beside a body match or a control flow shape.
const LISTING_CONFIDENCE: u8 = 30;

// ============================================================
// String signatures
// ============================================================

/// One string signature: a known algorithm and the literal spellings
/// that suggest it.
///
/// A signature recognizes exactly one algorithm: its
/// [`name`](Self::name) and [`category`](Self::category) are what a
/// hint records when one of its [`markers`](Self::markers) appears.
/// Markers are matched as literal substrings of the scanned text, and
/// a signature fits when any one of them appears — several spellings
/// of the same algorithm (`CRC`, `crc32`) stand in one signature so
/// the algorithm is reported once however many of them turn up. A
/// signature answers only the exact casing its markers spell unless
/// it is built [`case_insensitive`](Self::case_insensitive), which
/// folds case away so one marker answers every casing of it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StringSignature {
    /// The algorithm this signature suggests, e.g. `crc32`.
    pub name: String,
    /// The family the suggested algorithm belongs to.
    pub category: AlgorithmCategory,
    /// The literal spellings that suggest the algorithm, e.g. `CRC`,
    /// `crc32` — a signature fits when any one of them appears.
    pub markers: Vec<String>,
    /// Whether the markers match the scanned text with case folded
    /// away. A case-sensitive signature — the default — answers only
    /// the exact spellings its markers carry.
    #[serde(default, skip_serializing_if = "is_false")]
    pub case_insensitive: bool,
}

impl StringSignature {
    /// A signature named `name` in `category`, suggested by any of
    /// `markers`, matching their exact spellings.
    pub fn new(
        name: impl Into<String>,
        category: AlgorithmCategory,
        markers: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self {
            name: name.into(),
            category,
            markers: markers.into_iter().map(Into::into).collect(),
            case_insensitive: false,
        }
    }

    /// A signature whose markers match the scanned text with case
    /// folded away: one marker answers every casing of it, so a set
    /// can name an algorithm once instead of spelling it upper and
    /// lower.
    pub fn case_insensitive(mut self) -> Self {
        self.case_insensitive = true;
        self
    }
}

// ============================================================
// Engine
// ============================================================

/// String-guided algorithm hinting over decompiled functions and the
/// binary's string listing.
///
/// The engine owns the signature set a scan reads against:
/// [`StringSignature`] records supplied whole through
/// [`with_signatures`](Self::with_signatures) or grown one at a time
/// with [`add_signature`](Self::add_signature), and
/// [`signatures`](Self::signatures) reports the set in configuration
/// order, so two engines built the same way scan identically and
/// results diff cleanly. The engine holds no Ghidra client and never
/// writes back to the program; one engine serves an entire scan and
/// can be shared by reference across concurrent per-function passes,
/// each handed that function's body beside the program's string
/// listing.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StringHintEngine {
    signatures: Vec<StringSignature>,
}

impl StringHintEngine {
    /// An engine with no signatures configured: every scan it is handed
    /// yields nothing until the standard set arrives through
    /// [`with_default_signatures`](Self::with_default_signatures) or
    /// signatures join one at a time through
    /// [`add_signature`](Self::add_signature).
    pub fn new() -> Self {
        Self::default()
    }

    /// An engine that scans against the standard signature set —
    /// [`default_signatures`] — in its configuration order.
    pub fn with_default_signatures() -> Self {
        Self::with_signatures(default_signatures())
    }

    /// An engine that scans against exactly `signatures`, kept in the
    /// order they are given.
    pub fn with_signatures(signatures: impl IntoIterator<Item = StringSignature>) -> Self {
        Self {
            signatures: signatures.into_iter().collect(),
        }
    }

    /// Add one signature to the set this engine scans against.
    pub fn add_signature(&mut self, signature: StringSignature) {
        self.signatures.push(signature);
    }

    /// The signatures this engine scans against, in configuration
    /// order.
    pub fn signatures(&self) -> &[StringSignature] {
        &self.signatures
    }

    /// Scan a decompiled body and the binary's string listing against
    /// every configured signature, in configuration order, and report
    /// a hint for each signature the function fits.
    ///
    /// A signature fits when one of its markers appears as a substring
    /// of the body or of a listing string — compared at its exact
    /// spelling, or with case folded away for a
    /// [`case_insensitive`](StringSignature::case_insensitive)
    /// signature. The body is read first: a marker the function's own
    /// text carries ties the algorithm to the function, while a
    /// marker only the listing carries ties it to the program, so a
    /// body match wins the hint's evidence and [`BODY_CONFIDENCE`],
    /// and a listing-only match stands at [`LISTING_CONFIDENCE`]. Each
    /// signature yields at most one hint per function, however many of
    /// its markers appear and however many places carry them; a
    /// signature that asserts no marker fits nothing.
    ///
    /// Signatures that name the same algorithm report it once: the
    /// hint with the strongest evidence stands, a tie keeps the
    /// signature configured first, and the survivor holds the place
    /// the algorithm first appeared, so the hints keep configuration
    /// order and two scans diff cleanly.
    ///
    /// Each hint names the signature and its category, is marked
    /// [`StringHint`](DetectionMethod::StringHint), and carries as its
    /// evidence the trimmed body line holding the first marker match —
    /// or, for a listing-only match, the listing string itself.
    pub fn detect_string_hints(
        &self,
        func: &DecompiledFunction,
        binary_strings: &[StringLiteral],
    ) -> Vec<AlgorithmHint> {
        let mut hints: Vec<AlgorithmHint> = Vec::new();
        for signature in &self.signatures {
            let (confidence, evidence) = match body_hit(&func.body, signature) {
                Some(line) => (BODY_CONFIDENCE, line),
                None => match listing_hit(binary_strings, signature) {
                    Some(value) => (LISTING_CONFIDENCE, value),
                    None => continue,
                },
            };
            let hint = AlgorithmHint {
                function: func.name.clone(),
                algorithm: signature.name.clone(),
                category: signature.category,
                method: DetectionMethod::StringHint,
                confidence: Confidence::new(confidence),
                evidence,
            };
            // One algorithm is reported once per function however
            // many signatures name it: the stronger evidence takes
            // the hint where the algorithm first stood.
            match hints.iter_mut().find(|h| h.algorithm == hint.algorithm) {
                Some(existing) => {
                    if hint.confidence > existing.confidence {
                        *existing = hint;
                    }
                }
                None => hints.push(hint),
            }
        }
        hints
    }
}

// ============================================================
// The standard signature set
// ============================================================

/// The standard string signatures: the algorithms a scan recognizes
/// out of the box — crc, checksum, inflate, deflate, gzip, bz2, lzo,
/// serialize, deserialize, md5, sha, hmac, http, tcp, and udp.
///
/// Each signature carries the spellings its algorithm actually
/// appears under: the uppercase acronym where strings and names
/// shout it (`CRC`, `HTTP`, `MD5Final`) and the lowercase spelling
/// decompiled identifiers carry (`crc_table`, `inflate`,
/// `sha1_block_data_order`), so one signature stands for both worlds
/// even though the set matches case-sensitively — it spells both
/// casings rather than leaning on the case-folding option, keeping
/// every marker an exact spelling of what it saw. Markers are plain
/// substrings, and the set leans on that deliberately: `crc` answers
/// every `crc32` or `crc_table` spelling, and `http` every `https`.
/// Where a substring would mislead, the set stays quiet — `sha` names
/// its digit-suffixed family rather than the bare syllable, which
/// prefixes common words like `shadow`. Where the overlap is real,
/// it reads through: `deserialize` carries `serialize` as a
/// substring, so a mention of one reads as the whole serialization
/// family.
pub fn default_signatures() -> Vec<StringSignature> {
    let crc = StringSignature::new("crc", AlgorithmCategory::Checksum, ["CRC", "crc"]);
    let checksum = StringSignature::new(
        "checksum",
        AlgorithmCategory::Checksum,
        ["checksum", "Checksum"],
    );
    let inflate = StringSignature::new(
        "inflate",
        AlgorithmCategory::Compression,
        ["inflate", "Inflate"],
    );
    let deflate = StringSignature::new(
        "deflate",
        AlgorithmCategory::Compression,
        ["deflate", "Deflate"],
    );
    let gzip = StringSignature::new("gzip", AlgorithmCategory::Compression, ["gzip", "GZIP"]);
    let bz2 = StringSignature::new("bz2", AlgorithmCategory::Compression, ["bz2", "BZ2"]);
    let lzo = StringSignature::new("lzo", AlgorithmCategory::Compression, ["lzo", "LZO"]);
    let serialize = StringSignature::new(
        "serialize",
        AlgorithmCategory::Serialization,
        ["serialize", "Serialize"],
    );
    let deserialize = StringSignature::new(
        "deserialize",
        AlgorithmCategory::Serialization,
        ["deserialize", "Deserialize"],
    );
    let md5 = StringSignature::new("md5", AlgorithmCategory::Hashing, ["MD5", "md5"]);
    // The digit-suffixed family rather than a bare lowercase `sha`:
    // the syllable alone would read every `shadow` as a digest.
    let sha = StringSignature::new(
        "sha",
        AlgorithmCategory::Hashing,
        ["SHA", "sha1", "sha2", "sha3"],
    );
    let hmac = StringSignature::new("hmac", AlgorithmCategory::Hashing, ["HMAC", "hmac"]);
    let http = StringSignature::new("http", AlgorithmCategory::NetworkProtocol, ["HTTP", "http"]);
    let tcp = StringSignature::new("tcp", AlgorithmCategory::NetworkProtocol, ["TCP", "tcp"]);
    let udp = StringSignature::new("udp", AlgorithmCategory::NetworkProtocol, ["UDP", "udp"]);

    vec![
        crc,
        checksum,
        inflate,
        deflate,
        gzip,
        bz2,
        lzo,
        serialize,
        deserialize,
        md5,
        sha,
        hmac,
        http,
        tcp,
        udp,
    ]
}

// ============================================================
// Scanning helpers
// ============================================================

/// The offset in `text` where `marker` first appears: a literal
/// substring compared at its exact spelling, or with case folded away
/// for a case-insensitive signature — the fold runs over characters,
/// so the offset it reports stays a boundary of the original text.
fn find_marker(text: &str, marker: &str, case_insensitive: bool) -> Option<usize> {
    if !case_insensitive {
        return text.find(marker);
    }
    let needle: Vec<char> = marker.chars().flat_map(char::to_lowercase).collect();
    if needle.is_empty() {
        return Some(0);
    }
    text.char_indices()
        .find(|(offset, _)| {
            let folded = text[*offset..].chars().flat_map(char::to_lowercase);
            needle.iter().copied().eq(folded.take(needle.len()))
        })
        .map(|(offset, _)| offset)
}

/// The trimmed body line carrying the first marker (in signature
/// order) that appears in the body.
fn body_hit(body: &str, signature: &StringSignature) -> Option<String> {
    signature
        .markers
        .iter()
        .find_map(|marker| find_marker(body, marker, signature.case_insensitive))
        .map(|offset| line_at(body, offset))
}

/// The value of the first listing string (in listing order) that
/// carries any of the markers.
fn listing_hit(strings: &[StringLiteral], signature: &StringSignature) -> Option<String> {
    strings
        .iter()
        .find(|entry| {
            signature.markers.iter().any(|marker| {
                find_marker(&entry.value, marker, signature.case_insensitive).is_some()
            })
        })
        .map(|entry| entry.value.clone())
}

/// serde helper: a case-sensitive signature — the default — keeps its
/// flag out of the persisted JSON.
fn is_false(flag: &bool) -> bool {
    !flag
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn signature(name: &str) -> StringSignature {
        StringSignature::new(name, AlgorithmCategory::Checksum, ["CRC"])
    }

    fn function(body: &str) -> DecompiledFunction {
        DecompiledFunction {
            name: "FUN_18003ab00".into(),
            signature: "void FUN_18003ab00(void)".into(),
            body: body.into(),
        }
    }

    fn listing(values: &[&str]) -> Vec<StringLiteral> {
        values
            .iter()
            .enumerate()
            .map(|(i, value)| StringLiteral {
                address: 0x1_8004_0000 + i as u64,
                value: (*value).into(),
            })
            .collect()
    }

    #[test]
    fn a_new_engine_starts_with_no_signatures() {
        // Construction is free: empty, equal however it is made, and
        // clones interchangeable.
        let engine = StringHintEngine::new();
        assert!(engine.signatures().is_empty());
        assert_eq!(engine, StringHintEngine::default());
        assert_eq!(engine.clone(), engine);
    }

    #[test]
    fn an_engine_keeps_the_signatures_it_is_configured_with() {
        let engine = StringHintEngine::with_signatures([
            signature("crc32"),
            StringSignature::new("md5", AlgorithmCategory::Hashing, ["MD5", "md5"]),
        ]);
        let signatures = engine.signatures();
        assert_eq!(signatures.len(), 2);
        // Configuration order is scan order: two engines built the
        // same way see the same signatures in the same order.
        assert_eq!(signatures[0].name, "crc32");
        assert_eq!(signatures[1].name, "md5");
        assert_eq!(signatures[1].markers, vec!["MD5", "md5"]);
    }

    #[test]
    fn an_added_signature_joins_the_set_in_order() {
        let mut engine = StringHintEngine::with_signatures([signature("crc32")]);
        engine.add_signature(signature("adler32"));
        engine.add_signature(signature("fletcher"));
        let names: Vec<&str> = engine
            .signatures()
            .iter()
            .map(|s| s.name.as_str())
            .collect();
        assert_eq!(names, ["crc32", "adler32", "fletcher"]);
    }

    #[test]
    fn an_engine_can_be_shared_across_scans() {
        // One engine is driven concurrently over a program's functions,
        // so sharing one by reference across tasks must stay sound.
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<StringHintEngine>();
    }

    #[test]
    fn a_signature_serde_round_trips() {
        let signature =
            StringSignature::new("inflate", AlgorithmCategory::Compression, ["inflate"]);
        let json = serde_json::to_string(&signature).unwrap();
        assert!(json.contains("\"category\":\"compression\""));
        let back: StringSignature = serde_json::from_str(&json).unwrap();
        assert_eq!(back, signature);
    }

    const BODY_WITH_MARKER: &str = "\
void FUN_18003ab00(uint *param_1,uint param_2)

{
  uint uVar1;

  uVar1 = 0;
  while (uVar1 < param_2) {
    uVar1 = uVar1 ^ param_1[uVar1];
  }
  /* accumulate the CRC of the block */
  return;
}";

    #[test]
    fn a_body_carrying_a_marker_yields_a_hint() {
        let engine = StringHintEngine::with_signatures([signature("crc32")]);
        let hints = engine.detect_string_hints(&function(BODY_WITH_MARKER), &[]);
        assert_eq!(hints.len(), 1);
        let hint = &hints[0];
        assert_eq!(hint.function, "FUN_18003ab00");
        assert_eq!(hint.algorithm, "crc32");
        assert_eq!(hint.category, AlgorithmCategory::Checksum);
        assert_eq!(hint.method, DetectionMethod::StringHint);
        assert_eq!(hint.confidence, Confidence::new(BODY_CONFIDENCE));
    }

    #[test]
    fn the_evidence_is_the_body_line_carrying_the_marker() {
        let engine = StringHintEngine::with_signatures([signature("crc32")]);
        let hints = engine.detect_string_hints(&function(BODY_WITH_MARKER), &[]);
        assert_eq!(hints[0].evidence, "/* accumulate the CRC of the block */");
    }

    #[test]
    fn a_body_without_the_marker_still_reads_the_string_listing() {
        // The function's text names nothing, but the program carries
        // the marker: a weak lead, weighed below a body match.
        let engine = StringHintEngine::with_signatures([signature("crc32")]);
        let body = "void FUN_18003ab00(void)\n\n{\n  return;\n}";
        let hints = engine.detect_string_hints(
            &function(body),
            &listing(&["compression stream", "bad CRC on block"]),
        );
        assert_eq!(hints.len(), 1);
        assert_eq!(hints[0].confidence, Confidence::new(LISTING_CONFIDENCE));
        assert_eq!(hints[0].evidence, "bad CRC on block");
    }

    #[test]
    fn a_body_match_outweighs_a_listing_match() {
        // Both carry the marker: the body match wins the hint's
        // evidence and confidence, and the listing adds nothing.
        let engine = StringHintEngine::with_signatures([signature("crc32")]);
        let hints = engine.detect_string_hints(&function(BODY_WITH_MARKER), &listing(&["CRC"]));
        assert_eq!(hints.len(), 1);
        assert_eq!(hints[0].confidence, Confidence::new(BODY_CONFIDENCE));
        assert_eq!(hints[0].evidence, "/* accumulate the CRC of the block */");
    }

    #[test]
    fn a_signature_nothing_carries_yields_no_hint() {
        let engine = StringHintEngine::with_signatures([signature("crc32")]);
        let body = "void FUN_18003ab00(void)\n\n{\n  return;\n}";
        assert!(
            engine
                .detect_string_hints(&function(body), &listing(&["no match here"]))
                .is_empty()
        );
    }

    #[test]
    fn an_engine_with_no_signatures_yields_no_hints() {
        let engine = StringHintEngine::new();
        assert!(
            engine
                .detect_string_hints(&function(BODY_WITH_MARKER), &listing(&["CRC"]))
                .is_empty()
        );
    }

    #[test]
    fn each_matching_signature_yields_its_own_hint_in_order() {
        let engine = StringHintEngine::with_signatures([
            StringSignature::new("md5", AlgorithmCategory::Hashing, ["md5"]),
            signature("crc32"),
        ]);
        let body = format!("{}\n  /* md5 digest beside the CRC */", BODY_WITH_MARKER);
        let hints = engine.detect_string_hints(&function(&body), &[]);
        let names: Vec<&str> = hints.iter().map(|h| h.algorithm.as_str()).collect();
        assert_eq!(names, ["md5", "crc32"]);
    }

    #[test]
    fn one_signature_yields_one_hint_however_many_markers_fit() {
        // Several spellings of one algorithm, carried by several
        // places at once: the algorithm is still reported once.
        let engine = StringHintEngine::with_signatures([StringSignature::new(
            "crc32",
            AlgorithmCategory::Checksum,
            ["CRC", "checksum"],
        )]);
        let body = format!("{}\n  checksum mismatch", BODY_WITH_MARKER);
        let hints = engine.detect_string_hints(&function(&body), &listing(&["CRC table"]));
        assert_eq!(hints.len(), 1);
    }

    #[test]
    fn a_signature_that_asserts_no_marker_fits_nothing() {
        // A signature with zero markers would vacuously fit every
        // body, so it fits none.
        let empty =
            StringSignature::new("crc32", AlgorithmCategory::Checksum, Vec::<String>::new());
        let engine = StringHintEngine::with_signatures([empty]);
        assert!(
            engine
                .detect_string_hints(&function(BODY_WITH_MARKER), &listing(&["CRC"]))
                .is_empty()
        );
    }

    #[test]
    fn markers_match_the_scanned_text_case_sensitively() {
        // A marker stands for its exact spelling: a lowercase `crc`
        // in the text does not answer an uppercase `CRC` signature.
        let engine = StringHintEngine::with_signatures([signature("crc32")]);
        let body = "void FUN_18003ab00(void)\n\n{\n  /* accumulate the crc */\n  return;\n}";
        assert!(engine.detect_string_hints(&function(body), &[]).is_empty());
    }

    // --------------------------------------------------------
    // Case-insensitive signatures
    // --------------------------------------------------------

    #[test]
    fn a_case_insensitive_signature_answers_any_casing() {
        // The marker's exact spelling is folded away: a lowercase
        // `crc` in the body answers an uppercase `CRC` marker.
        let engine = StringHintEngine::with_signatures([signature("crc32").case_insensitive()]);
        let body = "void FUN_18003ab00(void)\n\n{\n  /* accumulate the crc */\n  return;\n}";
        let hints = engine.detect_string_hints(&function(body), &[]);
        assert_eq!(hints.len(), 1);
        assert_eq!(hints[0].confidence, Confidence::new(BODY_CONFIDENCE));
    }

    #[test]
    fn the_evidence_keeps_the_text_s_own_casing() {
        // Folding case is how the marker was found, not what the
        // evidence reports: the body line stands as written.
        let engine = StringHintEngine::with_signatures([signature("crc32").case_insensitive()]);
        let body = "void FUN_18003ab00(void)\n\n{\n  /* Accumulate The Crc */\n  return;\n}";
        let hints = engine.detect_string_hints(&function(body), &[]);
        assert_eq!(hints[0].evidence, "/* Accumulate The Crc */");
    }

    #[test]
    fn case_insensitive_matching_reads_the_listing_too() {
        let engine = StringHintEngine::with_signatures([signature("crc32").case_insensitive()]);
        let body = "void FUN_18003ab00(void)\n\n{\n  return;\n}";
        let hints = engine.detect_string_hints(&function(body), &listing(&["Bad Crc On Block"]));
        assert_eq!(hints.len(), 1);
        assert_eq!(hints[0].confidence, Confidence::new(LISTING_CONFIDENCE));
        assert_eq!(hints[0].evidence, "Bad Crc On Block");
    }

    #[test]
    fn a_case_insensitive_signature_serde_round_trips_and_defaults_to_exact_spelling() {
        let folded = signature("crc32").case_insensitive();
        let json = serde_json::to_string(&folded).unwrap();
        assert!(json.contains("\"case_insensitive\":true"));
        let back: StringSignature = serde_json::from_str(&json).unwrap();
        assert_eq!(back, folded);
        // A case-sensitive signature keeps its flag out of the JSON,
        // and a spelling persisted before the option existed reads
        // back case-sensitive.
        let plain = serde_json::to_string(&signature("crc32")).unwrap();
        assert!(!plain.contains("\"case_insensitive\""));
        let back: StringSignature = serde_json::from_str(&plain).unwrap();
        assert!(!back.case_insensitive);
    }

    // --------------------------------------------------------
    // Deduplication
    // --------------------------------------------------------

    #[test]
    fn signatures_naming_one_algorithm_yield_one_hint() {
        // Two signatures carry the same algorithm name — a
        // case-sensitive spelling and a case-folded one: the
        // algorithm is still reported once per function.
        let engine = StringHintEngine::with_signatures([
            signature("crc32"),
            signature("crc32").case_insensitive(),
        ]);
        let hints = engine.detect_string_hints(&function(BODY_WITH_MARKER), &[]);
        assert_eq!(hints.len(), 1);
        assert_eq!(hints[0].algorithm, "crc32");
    }

    #[test]
    fn the_stronger_evidence_wins_when_signatures_share_an_algorithm() {
        // The listing-only signature is configured first, but the
        // body match carries stronger evidence and takes the hint.
        let engine = StringHintEngine::with_signatures([
            StringSignature::new("crc32", AlgorithmCategory::Checksum, ["CRC"]),
            StringSignature::new("crc32", AlgorithmCategory::Checksum, ["checksum"]),
        ]);
        let body = "void FUN_18003ab00(void)\n\n{\n  checksum mismatch;\n  return;\n}";
        let hints = engine.detect_string_hints(&function(body), &listing(&["CRC table"]));
        assert_eq!(hints.len(), 1);
        assert_eq!(hints[0].confidence, Confidence::new(BODY_CONFIDENCE));
        assert_eq!(hints[0].evidence, "checksum mismatch;");
    }

    #[test]
    fn a_tie_keeps_the_signature_configured_first() {
        // Both signatures match the body at the same weight: the
        // first one's evidence stands.
        let engine = StringHintEngine::with_signatures([
            StringSignature::new("crc32", AlgorithmCategory::Checksum, ["CRC"]),
            StringSignature::new("crc32", AlgorithmCategory::Checksum, ["checksum"]),
        ]);
        let body = format!("{}\n  checksum mismatch", BODY_WITH_MARKER);
        let hints = engine.detect_string_hints(&function(&body), &[]);
        assert_eq!(hints.len(), 1);
        assert_eq!(hints[0].evidence, "/* accumulate the CRC of the block */");
    }

    #[test]
    fn deduplication_keeps_the_survivor_in_scan_order() {
        // The repeated algorithm's hint holds the place the algorithm
        // first appeared, so the hints keep configuration order and
        // two scans diff cleanly.
        let engine = StringHintEngine::with_signatures([
            StringSignature::new("crc32", AlgorithmCategory::Checksum, ["CRC"]),
            StringSignature::new("md5", AlgorithmCategory::Hashing, ["md5"]),
            StringSignature::new("crc32", AlgorithmCategory::Checksum, ["checksum"]),
        ]);
        let body = format!(
            "{}\n  checksum mismatch\n  /* md5 digest */",
            BODY_WITH_MARKER
        );
        let hints = engine.detect_string_hints(&function(&body), &[]);
        let names: Vec<&str> = hints.iter().map(|h| h.algorithm.as_str()).collect();
        assert_eq!(names, ["crc32", "md5"]);
    }

    // --------------------------------------------------------
    // The standard signature set
    // --------------------------------------------------------

    /// The names of the algorithms the standard set reports for `body`
    /// read beside the listing `strings`.
    fn algorithms(body: &str, strings: &[&str]) -> Vec<String> {
        StringHintEngine::with_default_signatures()
            .detect_string_hints(&function(body), &listing(strings))
            .into_iter()
            .map(|hint| hint.algorithm)
            .collect()
    }

    /// A decompiled CRC-32: the table-folded digest loop over a block,
    /// the global named `crc_table`.
    fn crc_body() -> String {
        [
            "uint FUN_18003ab00(byte *param_1,uint param_2)",
            "",
            "{",
            "  uint uVar1;",
            "  uint uVar2;",
            "  ",
            "  uVar1 = 0xffffffff;",
            "  uVar2 = 0;",
            "  while (uVar2 < param_2) {",
            "    uVar1 = crc_table[(uint)(uVar1 ^ (uint)param_1[uVar2]) & 0xff] ^ (uVar1 >> 8);",
            "    uVar2 = uVar2 + 1;",
            "  }",
            "  return ~uVar1;",
            "}",
        ]
        .join("\n")
    }

    /// A decompiled zlib wrapper: the inflate call and its failure text.
    fn inflate_body() -> String {
        [
            "int FUN_18003ab00(z_stream *param_1)",
            "",
            "{",
            "  int iVar1;",
            "  ",
            "  iVar1 = inflate(param_1, 1);",
            "  if (iVar1 == -5) {",
            "    puts(\"inflate gave no progress\");",
            "  }",
            "  return iVar1;",
            "}",
        ]
        .join("\n")
    }

    /// A decompiled digest helper: the MD5 init/update/final trio.
    fn md5_body() -> String {
        [
            "void FUN_18003ab00(char *param_1,byte *param_2)",
            "",
            "{",
            "  size_t sVar1;",
            "  ",
            "  MD5Init(&local_88);",
            "  sVar1 = strlen(param_1);",
            "  MD5Update(&local_88,param_1,sVar1);",
            "  MD5Final(param_2,&local_88);",
            "  return;",
            "}",
        ]
        .join("\n")
    }

    #[test]
    fn the_standard_set_carries_the_expected_signatures() {
        let signatures = default_signatures();
        let names: Vec<&str> = signatures.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(
            names,
            [
                "crc",
                "checksum",
                "inflate",
                "deflate",
                "gzip",
                "bz2",
                "lzo",
                "serialize",
                "deserialize",
                "md5",
                "sha",
                "hmac",
                "http",
                "tcp",
                "udp",
            ]
        );
        let categories: Vec<AlgorithmCategory> = signatures.iter().map(|s| s.category).collect();
        assert_eq!(
            categories,
            [
                AlgorithmCategory::Checksum,
                AlgorithmCategory::Checksum,
                AlgorithmCategory::Compression,
                AlgorithmCategory::Compression,
                AlgorithmCategory::Compression,
                AlgorithmCategory::Compression,
                AlgorithmCategory::Compression,
                AlgorithmCategory::Serialization,
                AlgorithmCategory::Serialization,
                AlgorithmCategory::Hashing,
                AlgorithmCategory::Hashing,
                AlgorithmCategory::Hashing,
                AlgorithmCategory::NetworkProtocol,
                AlgorithmCategory::NetworkProtocol,
                AlgorithmCategory::NetworkProtocol,
            ]
        );
    }

    #[test]
    fn an_engine_built_with_the_standard_set_scans_against_it() {
        let engine = StringHintEngine::with_default_signatures();
        assert_eq!(engine.signatures(), default_signatures());
        assert_ne!(engine, StringHintEngine::new());
    }

    #[test]
    fn a_table_folded_digest_loop_reads_as_crc() {
        // The lowercase identifier spelling answers the signature's
        // lowercase marker; the digit spellings ride along with it.
        assert_eq!(algorithms(&crc_body(), &[]), ["crc"]);
    }

    #[test]
    fn an_inflate_call_reads_as_inflate() {
        assert_eq!(algorithms(&inflate_body(), &[]), ["inflate"]);
    }

    #[test]
    fn a_digest_trio_reads_as_md5() {
        assert_eq!(algorithms(&md5_body(), &[]), ["md5"]);
    }

    #[test]
    fn a_protocol_string_in_the_listing_reads_as_http() {
        // Nothing in the function's own text names the protocol; the
        // program's strings do, so the hint stands on listing
        // evidence.
        let body = "void FUN_18003ab00(void)\n\n{\n  return;\n}";
        let hints = StringHintEngine::with_default_signatures()
            .detect_string_hints(&function(body), &listing(&["GET /index.html HTTP/1.1"]));
        assert_eq!(hints.len(), 1);
        assert_eq!(hints[0].algorithm, "http");
        assert_eq!(hints[0].category, AlgorithmCategory::NetworkProtocol);
        assert_eq!(hints[0].confidence, Confidence::new(LISTING_CONFIDENCE));
    }

    #[test]
    fn a_deserialize_mention_reads_as_both_serialization_signatures() {
        // Markers are substrings and the overlap is real: `deserialize`
        // carries `serialize`, so a mention of one reads as the whole
        // family, each signature with its own hint.
        let body = "void FUN_18003ab00(stream *param_1)\n\n{\n  deserialize_header(param_1);\n  return;\n}";
        assert_eq!(algorithms(body, &[]), ["serialize", "deserialize"]);
    }

    #[test]
    fn the_standard_set_stays_quiet_on_an_unrelated_function() {
        // `shadow` carries the bare `sha` syllable, but the sha
        // signature names only its digit-suffixed family, so nothing
        // here suggests an algorithm.
        let body = "void FUN_18003ab00(void)\n\n{\n  render_frame();\n  return;\n}";
        assert!(algorithms(body, &["shadow quality", "player spawned"]).is_empty());
    }
}
