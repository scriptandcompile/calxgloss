//! Core data types for constant and enum information.
//!
//! This module holds the serialized shape of everything the constant
//! detectors produce:
//!
//! - `BitflagGroup`: the per-function flag-group record — the distinct
//!   bits a function combines through bitwise operations, and the
//!   bitflags-style struct they suggest.
//! - `EnumCandidate`: the per-function enumerated-dispatch record — a
//!   run of contiguous switch case values, and the Rust `enum` it
//!   suggests.
//! - `NamedConstant`: the program-level repeated-value record — an
//!   integer literal used across several functions often enough to
//!   deserve a name, and the `const` it suggests.
//! - `FlagFamily`: the program-level flag-family record — the whole
//!   flag surface the per-function bitflag groups add up to once
//!   groups sharing bits merge across the program, and the one
//!   `bitflags!`-style struct it suggests.
//! - `ProtocolConstant`: the program-level known-magic record — a
//!   literal the scan tallied that matches the built-in table of
//!   well-known protocol/format magics and sentinels, named after the
//!   table entry, single use included.
//! - `ConstFinding`: the union over the record kinds — one finding
//!   whichever detector or post-pass made it — serde-tagged by `kind`.
//! - `ConstResult`, `ScanMetadata`: the persisted per-binary result and
//!   its scan provenance.
//!
//! All types derive `Serialize`/`Deserialize`.

// `ScanMetadata` is the shared per-binary scan provenance and `Confidence`
// the shared 0–100 evidence score; both are re-exported so consumers name
// them through this crate, matching the typesdb, typeinfer, algorithm, and
// memory convention.
pub use calxgloss_types::{Confidence, ScanMetadata};
use serde::{Deserialize, Serialize};

// ============================================================
// Bitflag groups
// ============================================================

/// One bitflag-group observation about one function, with the evidence
/// behind it.
///
/// A group says the function combines a set of distinct single-bit
/// values — [`bits`](Self::bits), the bit positions seen — through
/// bitwise operations, the shape a flags field takes. The bits are
/// what a `bitflags!`-style struct would name, and
/// [`suggestion`](Self::suggestion) spells the struct out at the
/// integer width the highest bit fits; [`mask`](Self::mask) is the
/// union of the bits and [`bit_width`](Self::bit_width) the position
/// count they span. The bitwise lines are kept as
/// [`evidence`](Self::evidence) so a reviewer (or a translation
/// prompt) can check the reasoning.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BitflagGroup {
    /// The function the record is about, e.g. `FUN_18003ab00`.
    pub function: String,
    /// The distinct bit positions combined in the function, ascending.
    pub bits: Vec<u32>,
    /// The union of the bits, e.g. `0x500` for bits 8 and 10.
    pub mask: u64,
    /// The bit count the highest observed bit spans, e.g. 11.
    pub bit_width: u32,
    /// The Rust shape the group suggests, e.g. a `bitflags!` struct.
    pub suggestion: String,
    /// Confidence that the record is right, 0–100.
    pub confidence: Confidence,
    /// The decompiled lines that support the record — the bitwise
    /// operations — kept so a reviewer (or a translation prompt) can
    /// check the reasoning.
    pub evidence: String,
}

// ============================================================
// Enum candidates
// ============================================================

/// One enumerated-dispatch observation about one function, with the
/// evidence behind it.
///
/// A candidate says the function dispatches on a `switch` whose case
/// values include a contiguous ascending run —
/// [`values`](Self::values), the run, and [`count`](Self::count) its
/// length — the shape an enumerated state takes when the compiler
/// lowers it to a jump table. A run reads like
/// [`suggestion`](Self::suggestion) — a Rust `enum` with one variant
/// per value. The case lines are kept as [`evidence`](Self::evidence)
/// so a reviewer (or a translation prompt) can check the reasoning.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnumCandidate {
    /// The function the record is about, e.g. `FUN_18003ab00`.
    pub function: String,
    /// The contiguous ascending case values of the run, ascending.
    pub values: Vec<i64>,
    /// The length of the run.
    pub count: usize,
    /// The Rust shape the run suggests, e.g. an `enum`.
    pub suggestion: String,
    /// Confidence that the record is right, 0–100.
    pub confidence: Confidence,
    /// The decompiled lines that support the record — the case labels
    /// of the run — kept so a reviewer (or a translation prompt) can
    /// check the reasoning.
    pub evidence: String,
}

// ============================================================
// Named constants
// ============================================================

/// One repeated-value observation about the whole program, with the
/// evidence behind it.
///
/// A record says one integer literal — [`value`](Self::value) — is
/// used [`count`](Self::count) times across the program, in the
/// functions listed in [`functions`](Self::functions), often enough
/// and spread wide enough that the value is a named constant rather
/// than a situational literal. It reads like
/// [`suggestion`](Self::suggestion) — a named `const` standing in for
/// the repeated literal. The usage summary is kept as
/// [`evidence`](Self::evidence) so a reviewer (or a translation
/// prompt) can check the reasoning.
///
/// Unlike the other two records this one is program-level: it belongs
/// to every function that uses the value, not to a single one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NamedConstant {
    /// The repeated literal's value, e.g. `0x400`.
    pub value: u64,
    /// How many times the value is used across the program.
    pub count: usize,
    /// The functions that use the value, ascending.
    pub functions: Vec<String>,
    /// The name the bodies gave the value — `SIZE_0x280` for a `size =
    /// 0x280` standing in one of them — when a qualifying sighting
    /// carried one (see `naming::context_names`). Optional on disk, skipped
    /// when absent: documents persisted before context naming load
    /// unchanged, and an un-named record serializes exactly as it did
    /// before the field existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// The Rust shape the value suggests, e.g. a named `const` — the
    /// named form when [`name`](Self::name) carries one, the mechanical
    /// `VALUE_0x…` form when not (see [`render_suggestion`](Self::render_suggestion)).
    pub suggestion: String,
    /// Confidence that the record is right, 0–100.
    pub confidence: Confidence,
    /// The usage summary that supports the record — the value's count
    /// and the functions it appears in — kept so a reviewer (or a
    /// translation prompt) can check the reasoning.
    pub evidence: String,
}

/// The integer type a `const` spelling for one value uses — the
/// narrowest that holds it. Shared by the named-constant suggestion
/// and the codegen renderer so both spell the same width.
pub(crate) fn int_const_type(value: u64) -> &'static str {
    if value > u64::from(u32::MAX) {
        "u64"
    } else {
        "u32"
    }
}

impl NamedConstant {
    /// The `const` shape one value suggests: the context-derived name
    /// uppercased into the declaration when the bodies gave the value
    /// one, the mechanical `VALUE_0x…` spelling when they did not. The
    /// integer type is the narrowest that holds the value.
    pub fn render_suggestion(name: Option<&str>, value: u64) -> String {
        let ty = int_const_type(value);
        match name {
            Some(name) => format!("const {name}: {ty} = {value:#x};"),
            None => format!("const VALUE_{value:#x}: {ty} = {value:#x};"),
        }
    }
}

// ============================================================
// Flag families
// ============================================================

/// One program-level flag-family observation — the whole flag surface
/// the per-function bitflag groups add up to — with the evidence
/// behind it.
///
/// A family says the scan's per-function [`BitflagGroup`]s that share
/// at least one bit — directly or through a chain of shared bits —
/// describe one flags type: [`bits`](Self::bits) is their union,
/// [`mask`](Self::mask) the union as a mask, and
/// [`bit_width`](Self::bit_width) the position count the highest bit
/// spans; [`functions`](Self::functions) names the contributing
/// functions, ascending. It reads like
/// [`suggestion`](Self::suggestion) — one `bitflags!`-style struct
/// naming the whole family at the width its highest bit fits — and
/// the per-function groups stay beside it: the family is the
/// program-level claim, never a replacement for them. A group sharing
/// no bit with any other forms no family of its own — its
/// per-function record already says everything that body shows.
///
/// Like the named constant this one is program-level: it belongs to
/// every function that contributed bits, not to a single one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlagFamily {
    /// The union of the family's distinct bit positions, ascending.
    pub bits: Vec<u32>,
    /// The union of the bits, e.g. `0xd00` for bits 8, 10, and 11.
    pub mask: u64,
    /// The bit count the highest family bit spans, e.g. 12.
    pub bit_width: u32,
    /// The functions whose groups contributed bits, ascending.
    pub functions: Vec<String>,
    /// The Rust shape the family suggests — one `bitflags!` struct
    /// carrying every bit the family spans.
    pub suggestion: String,
    /// Confidence that the record is right, 0–100. Fixed, and above
    /// the per-function group's tier: the same flag surface
    /// corroborated across several functions is stronger evidence
    /// than one body's word alone.
    pub confidence: Confidence,
    /// Each contributing group's function and its own bits, e.g.
    /// `FUN_a: bits 0x100, 0x400; FUN_b: bits 0x400, 0x800` — kept
    /// so a reviewer (or a translation prompt) can check the merge
    /// against the per-function records it consumed.
    pub evidence: String,
}

// ============================================================
// Protocol constants
// ============================================================

/// One known-magic observation about the whole program — a literal the
/// scan tallied that matches the built-in table of well-known
/// protocol/format magics and sentinels — with the evidence behind it.
///
/// A record says one tallied literal — [`value`](Self::value) — is a
/// recognised value: it equals a table entry, so it carries that
/// entry's [`name`](Self::name) (`PNG_MAGIC`) and
/// [`protocol`](Self::protocol) label ("PNG image format") — a claim
/// checkable against the table — beside the usage data the tally
/// holds: [`count`](Self::count) uses across the functions listed in
/// [`functions`](Self::functions). It reads like
/// [`suggestion`](Self::suggestion) — a `const` named after the table
/// entry — and unlike the frequency reading it reports on a single
/// use: a magic-number check may appear exactly once in one parser.
/// The usage summary is kept as [`evidence`](Self::evidence) so a
/// reviewer (or a translation prompt) can check the reasoning.
///
/// A table-matched value lands exactly once: the protocol claim is
/// strictly stronger than the frequency-only named-constant reading
/// and carries the same usage data, so the frequency pass skips
/// matched values. Values outside the table are untouched and stay
/// ordinary named constants.
///
/// Like the named constant this one is program-level: it belongs to
/// every function that uses the value, not to a single one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtocolConstant {
    /// The matched literal's value, e.g. `0x89504e47`.
    pub value: u64,
    /// The table entry's display name, e.g. `PNG_MAGIC` — the name the
    /// suggestion spells the `const` with.
    pub name: String,
    /// The protocol or format the value belongs to, e.g. `PNG image
    /// format` — the table claim a reviewer can check.
    pub protocol: String,
    /// How many times the value is used across the program.
    pub count: usize,
    /// The functions that use the value, ascending.
    pub functions: Vec<String>,
    /// The Rust shape the value suggests — a `const` named after the
    /// table entry, e.g. `const PNG_MAGIC: u32 = 0x89504e47;`.
    pub suggestion: String,
    /// Confidence that the record is right, 0–100. Fixed, and above
    /// the frequency-only named-constant tier: the value is not just
    /// repeated, it is recognised, and the claim is checkable against
    /// the table.
    pub confidence: Confidence,
    /// The usage summary that supports the record — the value's count,
    /// the functions it appears in, and the table entry it matched —
    /// kept so a reviewer (or a translation prompt) can check the
    /// reasoning.
    pub evidence: String,
}

// ============================================================
// Color palettes
// ============================================================

/// One color-grouping observation about the whole program — the
/// color-shaped literals the scan tallied, read as one palette — with
/// the evidence behind it.
///
/// A record says the binary's tallied literals include
/// [`values`](Self::values) — distinct, ascending, each fitting in 24
/// bits and none a power of two, so no flag bit reads as a color —
/// appearing in the functions listed in [`functions`](Self::functions).
/// It reads like [`suggestion`](Self::suggestion) — a named `const`
/// per color, `COLOR_<hex>` — and the palette summary is kept as
/// [`evidence`](Self::evidence) so a reviewer (or a translation
/// prompt) can check the grouping. There is no color-name matching:
/// the claim is "these are colors", never "this one is red".
///
/// The floor is the honesty bar: at least two distinct qualifying
/// values must exist in the binary — a lone `0x123456` may be an
/// offset and claims nothing — and there is at most one record per
/// binary, so a rescan of one program diffs cleanly.
///
/// Like the named constant this one is program-level: it belongs to
/// every function that uses one of the colors, not to a single one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ColorConstant {
    /// The palette's distinct color-shaped values, ascending.
    pub values: Vec<u64>,
    /// The functions the values appear in, ascending.
    pub functions: Vec<String>,
    /// The Rust shape the palette suggests — a named `const` per
    /// color, e.g. `const COLOR_0x123456: u32 = 0x123456;`.
    pub suggestion: String,
    /// Confidence that the record is right, 0–100. Fixed, at the
    /// named-constant tier: the shape reading is as suggestive as a
    /// repeated literal, no stronger.
    pub confidence: Confidence,
    /// The palette summary that supports the record — each value's
    /// count and the functions it appears in — kept so a reviewer (or
    /// a translation prompt) can check the reasoning.
    pub evidence: String,
}

// ============================================================
// Data tables
// ============================================================

/// The ceiling on a data table's inline `values` list. Beyond it the
/// list truncates, `values_truncated` says so, and `count` still
/// carries the full entry count.
pub const MAX_INLINE_TABLE_VALUES: usize = 512;

/// One data-table reading of the whole program — a defined, uniformly
/// decoding data object the kept bodies index.
///
/// A record claims one defined data object — [`symbol`]/[`address`] —
/// holds [`count`](Self::count) uniform entries of
/// [`element_type`](Self::element_type): the object's engine-listed
/// length divided by the stride its bytes decode cleanly at (the
/// entries are the [`values`](Self::values)), with the entry count a
/// bounds-guarded indexed read (`DAT_x[idx]` under `if (idx < N)`) in
/// a kept body agreeing on the stride when more than one stride
/// decodes cleanly. [`functions`](Self::functions) names the
/// referencing functions from the engine's cross-references,
/// ascending; a body indexing the object is never a write claim —
/// mutation disqualification lands separately.
///
/// The `values` list is inline up to [`MAX_INLINE_TABLE_VALUES`];
/// beyond it the list truncates, [`values_truncated`](Self::values_truncated)
/// flags that, and [`count`](Self::count) still records the full entry
/// count. It reads like [`suggestion`](Self::suggestion) — a Rust
/// `const` array naming the [`rust_name`](Self::rust_name) the label
/// implies — the shape codegen and the prompts will later carry.
///
/// [`symbol`]: Self::symbol
/// [`address`]: Self::address
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataTable {
    /// The listing label of the data object, e.g. `DAT_1400a1b60` —
    /// exactly as the engine's data listing names it.
    pub symbol: String,
    /// The object's address.
    pub address: u64,
    /// The element type the entries decode as — `u8`, `u16`, `u32`, or
    /// `u64`.
    pub element_type: String,
    /// The full entry count, whether or not `values` carries them all.
    pub count: usize,
    /// The decoded entries, inline up to [`MAX_INLINE_TABLE_VALUES`];
    /// truncated beyond it.
    pub values: Vec<u64>,
    /// Whether `values` was truncated at the cap — `count` still
    /// records the full entry count.
    pub values_truncated: bool,
    /// The functions that reference the object, from the engine's
    /// cross-references, ascending.
    pub functions: Vec<String>,
    /// The Rust shape the reading suggests — `const` array, e.g.
    /// `const DAT_1400A1B60: [u16; 12];`.
    pub suggestion: String,
    /// Confidence that the record is right, 0–100. The corroborated
    /// reading — a clean decode with a bounds-guarded indexed read —
    /// sits in the high-mid band; the engine-applied-type tier above
    /// it and the unreferenced tiers below land with later tickets.
    pub confidence: Confidence,
    /// The indexed-read lines behind the claim, each prefixed with the
    /// function that carries it, so a reviewer can check the read the
    /// table was sized from.
    pub evidence: String,
}

impl DataTable {
    /// The Rust identifier the label implies: the context-name
    /// precedent — a meaningful listing label names the table as it
    /// stands; a bare `DAT_*` or `switchD_*` label yields its
    /// mechanical uppercase form, e.g. `DAT_1400a1b60` →
    /// `DAT_1400A1B60`.
    pub fn rust_name(symbol: &str) -> String {
        if is_bare_data_label(symbol) {
            symbol.to_uppercase()
        } else {
            symbol.to_string()
        }
    }

    /// Render the `const` array the reading suggests for one listing
    /// label.
    pub fn render_suggestion(symbol: &str, element_type: &str, count: usize) -> String {
        format!(
            "const {}: [{element_type}; {count}];",
            Self::rust_name(symbol)
        )
    }
}

/// Whether a listing label is a generated stand-in rather than a
/// meaningful name: the bare `DAT_*` and `switchD_*` forms the
/// decompiler gives unlabeled data.
fn is_bare_data_label(label: &str) -> bool {
    label.starts_with("DAT_") || label.starts_with("switchD_")
}

// ============================================================
// Finding union
// ============================================================

/// One constant finding, whichever detector or post-pass made it.
///
/// The detectors emit the concrete records and the engine's
/// flag-family merge post-pass emits the family; the union is what
/// the persisted result carries, so one list can hold every finding
/// for a binary and a consumer reads the shared shape — function,
/// suggestion, confidence, evidence — without naming which reading
/// produced it. Like sync's disjoint families, the detectors read
/// different shapes and make no competing claims, so nothing is
/// resolved between variants. The serde `kind` tag names the record
/// shape in the persisted JSON.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ConstFinding {
    /// A set of distinct bits combined through bitwise operations.
    BitflagGroup(BitflagGroup),
    /// A contiguous run of switch case values.
    EnumCandidate(EnumCandidate),
    /// A literal repeated across the program.
    NamedConstant(NamedConstant),
    /// The whole flag surface several per-function groups sharing
    /// bits add up to.
    FlagFamily(FlagFamily),
    /// A tallied literal matching the built-in table of well-known
    /// protocol/format magics and sentinels.
    ProtocolConstant(ProtocolConstant),
    /// The color-shaped literals the tally holds, grouped into one
    /// palette claim for the binary.
    ColorConstant(ColorConstant),
    /// A defined, uniformly decoding data object the kept bodies
    /// index, read as one constant-array table.
    DataTable(DataTable),
}

impl ConstFinding {
    /// The function the finding is about — empty for the program-level
    /// kinds: a named constant belongs to every function that uses
    /// the value, a flag family to every function that contributed
    /// bits (see [`ConstResult::for_function`]).
    pub fn function(&self) -> &str {
        match self {
            ConstFinding::BitflagGroup(record) => &record.function,
            ConstFinding::EnumCandidate(record) => &record.function,
            ConstFinding::NamedConstant(_) => "",
            ConstFinding::FlagFamily(_) => "",
            ConstFinding::ProtocolConstant(_) => "",
            ConstFinding::ColorConstant(_) => "",
            ConstFinding::DataTable(_) => "",
        }
    }

    /// The Rust shape the finding suggests.
    pub fn suggestion(&self) -> &str {
        match self {
            ConstFinding::BitflagGroup(record) => &record.suggestion,
            ConstFinding::EnumCandidate(record) => &record.suggestion,
            ConstFinding::NamedConstant(record) => &record.suggestion,
            ConstFinding::FlagFamily(record) => &record.suggestion,
            ConstFinding::ProtocolConstant(record) => &record.suggestion,
            ConstFinding::ColorConstant(record) => &record.suggestion,
            ConstFinding::DataTable(record) => &record.suggestion,
        }
    }

    /// Confidence that the finding is right.
    pub fn confidence(&self) -> Confidence {
        match self {
            ConstFinding::BitflagGroup(record) => record.confidence,
            ConstFinding::EnumCandidate(record) => record.confidence,
            ConstFinding::NamedConstant(record) => record.confidence,
            ConstFinding::FlagFamily(record) => record.confidence,
            ConstFinding::ProtocolConstant(record) => record.confidence,
            ConstFinding::ColorConstant(record) => record.confidence,
            ConstFinding::DataTable(record) => record.confidence,
        }
    }

    /// The decompiled lines (or usage summary, or contributing-group
    /// summary) that support the finding.
    pub fn evidence(&self) -> &str {
        match self {
            ConstFinding::BitflagGroup(record) => &record.evidence,
            ConstFinding::EnumCandidate(record) => &record.evidence,
            ConstFinding::NamedConstant(record) => &record.evidence,
            ConstFinding::FlagFamily(record) => &record.evidence,
            ConstFinding::ProtocolConstant(record) => &record.evidence,
            ConstFinding::ColorConstant(record) => &record.evidence,
            ConstFinding::DataTable(record) => &record.evidence,
        }
    }

    /// The serde `kind` tag — `bitflag_group`, `enum_candidate`,
    /// `named_constant`, `flag_family`, `protocol_constant`,
    /// `color_constant`, or `data_table` — naming the reading behind
    /// the finding.
    pub fn kind(&self) -> &'static str {
        match self {
            ConstFinding::BitflagGroup(_) => "bitflag_group",
            ConstFinding::EnumCandidate(_) => "enum_candidate",
            ConstFinding::NamedConstant(_) => "named_constant",
            ConstFinding::FlagFamily(_) => "flag_family",
            ConstFinding::ProtocolConstant(_) => "protocol_constant",
            ConstFinding::ColorConstant(_) => "color_constant",
            ConstFinding::DataTable(_) => "data_table",
        }
    }

    /// What the finding names, spelled for a report row: the group's
    /// or family's bit mask, the run's value range, the repeated or
    /// matched value, the palette's colors, or the table's label and
    /// array shape.
    pub fn target(&self) -> String {
        match self {
            ConstFinding::BitflagGroup(record) => format!("{:#x}", record.mask),
            ConstFinding::EnumCandidate(record) => {
                format!("{}..={}", record.values[0], record.values[record.count - 1])
            }
            ConstFinding::NamedConstant(record) => format!("{:#x}", record.value),
            ConstFinding::FlagFamily(record) => format!("{:#x}", record.mask),
            ConstFinding::ProtocolConstant(record) => format!("{:#x}", record.value),
            ConstFinding::ColorConstant(record) => record
                .values
                .iter()
                .map(|value| format!("{value:#x}"))
                .collect::<Vec<String>>()
                .join(", "),
            ConstFinding::DataTable(record) => {
                format!(
                    "{} [{}; {}]",
                    record.symbol, record.element_type, record.count
                )
            }
        }
    }
}

// ============================================================
// Prompt conversions
// ============================================================

/// Render a finding as prompt data: the function it is about, the kind
/// of constant structure the detector read, the Rust shape the finding
/// suggests, and the confidence and evidence behind the claim — so the
/// escalate prompt shows the hypothesis and how strongly it was made,
/// whichever detector produced it.
impl From<&ConstFinding> for calxgloss_prompts::ConstInfo {
    fn from(finding: &ConstFinding) -> Self {
        Self {
            function: finding.function().to_string(),
            kind: finding.kind().to_string(),
            suggestion: finding.suggestion().to_string(),
            confidence: finding.confidence().value(),
            evidence: finding.evidence().to_string(),
        }
    }
}

// ============================================================
// Persisted result
// ============================================================

/// The constant result for one binary — the document persisted to
/// `re/analysis/consts/{dll}.json`.
///
/// The findings are the readings' outputs in scan order: function by
/// function the bitmask groups then the enum candidates, and after
/// the per-function findings the program-level records — the named
/// constants the frequency analyzer tallied across the whole pass,
/// then the flag families the scan's own groups merged into, then
/// the protocol constants the known-magic reading matched, then the
/// color palette — each group internally sorted. The stable order
/// means two scans of the same program diff cleanly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConstResult {
    /// Provenance of the scan that produced these findings.
    pub metadata: ScanMetadata,
    /// Every finding the detectors made, in scan order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub findings: Vec<ConstFinding>,
}

impl ConstResult {
    /// An empty result for the binary described by `metadata`.
    pub fn new(metadata: ScanMetadata) -> Self {
        Self {
            metadata,
            findings: Vec::new(),
        }
    }

    /// The findings recorded for one function, e.g. `FUN_18003ab00`.
    ///
    /// A program-level finding that names its contributing functions
    /// — a named constant for every function that uses its value, a
    /// flag family for every function that contributed bits, a
    /// protocol constant for every function that uses the matched
    /// value, the color palette for every function that uses one of
    /// its colors — is yielded for each of them: the per-function
    /// view a translation prompt reads.
    pub fn for_function(&self, function: &str) -> impl Iterator<Item = &ConstFinding> {
        self.findings
            .iter()
            .filter(move |finding| match &**finding {
                ConstFinding::BitflagGroup(record) => record.function == function,
                ConstFinding::EnumCandidate(record) => record.function == function,
                ConstFinding::NamedConstant(record) => {
                    record.functions.iter().any(|f| f == function)
                }
                ConstFinding::FlagFamily(record) => record.functions.iter().any(|f| f == function),
                ConstFinding::ProtocolConstant(record) => {
                    record.functions.iter().any(|f| f == function)
                }
                ConstFinding::ColorConstant(record) => {
                    record.functions.iter().any(|f| f == function)
                }
                ConstFinding::DataTable(record) => record.functions.iter().any(|f| f == function),
            })
    }

    /// Whether the scan found nothing at all.
    pub fn is_empty(&self) -> bool {
        self.findings.is_empty()
    }
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn bitflag_group() -> BitflagGroup {
        BitflagGroup {
            function: "FUN_18003ab00".into(),
            bits: vec![8, 10],
            mask: 0x500,
            bit_width: 11,
            suggestion: "bitflags! struct Flags: u32 { /* bits: 0x100, 0x400 */ }".into(),
            confidence: Confidence::new(70),
            evidence: "if ((uVar1 & 0x400) != 0) { uVar1 |= 0x100; }".into(),
        }
    }

    fn enum_candidate() -> EnumCandidate {
        EnumCandidate {
            function: "FUN_18003ab00".into(),
            values: vec![0, 1, 2, 3],
            count: 4,
            suggestion: "enum State { /* variants for 0..=3 */ }".into(),
            confidence: Confidence::new(70),
            evidence: "case 0: case 1: case 2: case 3:".into(),
        }
    }

    fn named_constant() -> NamedConstant {
        NamedConstant {
            value: 0x400,
            count: 5,
            functions: vec!["FUN_18003ab00".into(), "FUN_18003e750".into()],
            name: None,
            suggestion: "const VALUE_0x400: u32 = 0x400;".into(),
            confidence: Confidence::new(60),
            evidence: "0x400 used 5 times in FUN_18003ab00, FUN_18003e750".into(),
        }
    }

    fn flag_family() -> FlagFamily {
        FlagFamily {
            bits: vec![8, 10, 11],
            mask: 0xd00,
            bit_width: 12,
            functions: vec!["FUN_18003ab00".into(), "FUN_18003e750".into()],
            suggestion: "bitflags! struct Flags: u16 { /* bits: 0x100, 0x400, 0x800 */ }".into(),
            confidence: Confidence::new(80),
            evidence: "FUN_18003ab00: bits 0x100, 0x400; FUN_18003e750: bits 0x400, 0x800".into(),
        }
    }

    fn protocol_constant() -> ProtocolConstant {
        ProtocolConstant {
            value: 0xdeadbeef,
            name: "DEAD_BEEF_MARKER".into(),
            protocol: "debug sentinel value".into(),
            count: 1,
            functions: vec!["FUN_18003ab00".into()],
            suggestion: "const DEAD_BEEF_MARKER: u32 = 0xdeadbeef;".into(),
            confidence: Confidence::new(75),
            evidence: "0xdeadbeef used 1 times in FUN_18003ab00 — table match: DEAD_BEEF_MARKER \
                       (debug sentinel value)"
                .into(),
        }
    }

    fn color_constant() -> ColorConstant {
        ColorConstant {
            values: vec![0x123456, 0xff00ff],
            functions: vec!["FUN_18003ab00".into(), "FUN_18003e750".into()],
            suggestion: "const COLOR_0x123456: u32 = 0x123456; const COLOR_0xff00ff: u32 = \
                         0xff00ff;"
                .into(),
            confidence: Confidence::new(60),
            evidence: "0x123456 used 2 times in FUN_18003ab00; 0xff00ff used 1 times in \
                       FUN_18003e750"
                .into(),
        }
    }

    fn data_table() -> DataTable {
        DataTable {
            symbol: "DAT_1400a1b60".into(),
            address: 0x1400_a1b60,
            element_type: "u16".into(),
            count: 12,
            values: (1..=12).collect(),
            values_truncated: false,
            functions: vec!["FUN_18003ab00".into()],
            suggestion: "const DAT_1400A1B60: [u16; 12];".into(),
            confidence: Confidence::new(70),
            evidence: "FUN_18003ab00: uVar3 = DAT_1400a1b60[uVar2];".into(),
        }
    }

    #[test]
    fn a_bitflag_group_serde_round_trips() {
        let record = bitflag_group();
        let json = serde_json::to_string(&record).unwrap();
        assert!(json.contains("\"bits\":[8,10]"));
        assert!(json.contains("\"confidence\":70"));
        let back: BitflagGroup = serde_json::from_str(&json).unwrap();
        assert_eq!(back, record);
    }

    #[test]
    fn an_enum_candidate_serde_round_trips() {
        let record = enum_candidate();
        let json = serde_json::to_string(&record).unwrap();
        assert!(json.contains("\"values\":[0,1,2,3]"));
        let back: EnumCandidate = serde_json::from_str(&json).unwrap();
        assert_eq!(back, record);
    }

    #[test]
    fn a_named_constant_serde_round_trips() {
        let record = named_constant();
        let json = serde_json::to_string(&record).unwrap();
        assert!(json.contains("\"value\":1024"));
        assert!(json.contains("\"confidence\":60"));
        let back: NamedConstant = serde_json::from_str(&json).unwrap();
        assert_eq!(back, record);
    }

    #[test]
    fn a_bitflag_finding_serde_round_trips_under_its_kind_tag() {
        let finding = ConstFinding::BitflagGroup(bitflag_group());
        let json = serde_json::to_string(&finding).expect("bitflag finding should serialize");
        assert!(json.contains("\"kind\":\"bitflag_group\""));
        assert!(json.contains("\"mask\":1280"));
        let back: ConstFinding =
            serde_json::from_str(&json).expect("bitflag finding should read back");
        assert_eq!(back, finding);
    }

    #[test]
    fn an_enum_finding_serde_round_trips_under_its_kind_tag() {
        let finding = ConstFinding::EnumCandidate(enum_candidate());
        let json = serde_json::to_string(&finding).expect("enum finding should serialize");
        assert!(json.contains("\"kind\":\"enum_candidate\""));
        let back: ConstFinding =
            serde_json::from_str(&json).expect("enum finding should read back");
        assert_eq!(back, finding);
    }

    #[test]
    fn a_named_constant_finding_serde_round_trips_under_its_kind_tag() {
        let finding = ConstFinding::NamedConstant(named_constant());
        let json =
            serde_json::to_string(&finding).expect("named-constant finding should serialize");
        assert!(json.contains("\"kind\":\"named_constant\""));
        let back: ConstFinding =
            serde_json::from_str(&json).expect("named-constant finding should read back");
        assert_eq!(back, finding);
    }

    #[test]
    fn a_flag_family_serde_round_trips() {
        let record = flag_family();
        let json = serde_json::to_string(&record).expect("flag-family record should serialize");
        assert!(json.contains("\"bits\":[8,10,11]"));
        assert!(json.contains("\"confidence\":80"));
        let back: FlagFamily =
            serde_json::from_str(&json).expect("the record should deserialize back");
        assert_eq!(back, record);
    }

    #[test]
    fn a_flag_family_finding_serde_round_trips_under_its_kind_tag() {
        let finding = ConstFinding::FlagFamily(flag_family());
        let json = serde_json::to_string(&finding).expect("flag-family finding should serialize");
        assert!(json.contains("\"kind\":\"flag_family\""));
        assert!(json.contains("\"mask\":3328"));
        let back: ConstFinding =
            serde_json::from_str(&json).expect("flag-family finding should read back");
        assert_eq!(back, finding);
    }

    #[test]
    fn a_protocol_constant_serde_round_trips() {
        let record = protocol_constant();
        let json =
            serde_json::to_string(&record).expect("protocol-constant record should serialize");
        assert!(json.contains("\"name\":\"DEAD_BEEF_MARKER\""));
        assert!(json.contains("\"protocol\":\"debug sentinel value\""));
        assert!(json.contains("\"confidence\":75"));
        let back: ProtocolConstant =
            serde_json::from_str(&json).expect("protocol-constant record should read back");
        assert_eq!(back, record);
    }

    #[test]
    fn a_protocol_constant_finding_serde_round_trips_under_its_kind_tag() {
        let finding = ConstFinding::ProtocolConstant(protocol_constant());
        let json =
            serde_json::to_string(&finding).expect("protocol-constant finding should serialize");
        assert!(json.contains("\"kind\":\"protocol_constant\""));
        assert!(json.contains("\"value\":3735928559"));
        let back: ConstFinding =
            serde_json::from_str(&json).expect("protocol-constant finding should read back");
        assert_eq!(back, finding);
    }

    #[test]
    fn a_color_constant_serde_round_trips() {
        let record = color_constant();
        let json = serde_json::to_string(&record).expect("color-constant record should serialize");
        assert!(json.contains("\"values\":[1193046,16711935]"));
        assert!(json.contains("\"confidence\":60"));
        let back: ColorConstant =
            serde_json::from_str(&json).expect("color-constant record should read back");
        assert_eq!(back, record);
    }

    #[test]
    fn a_color_constant_finding_serde_round_trips_under_its_kind_tag() {
        let finding = ConstFinding::ColorConstant(color_constant());
        let json =
            serde_json::to_string(&finding).expect("color-constant finding should serialize");
        assert!(json.contains("\"kind\":\"color_constant\""));
        assert!(json.contains("\"values\":[1193046,16711935]"));
        let back: ConstFinding =
            serde_json::from_str(&json).expect("color-constant finding should read back");
        assert_eq!(back, finding);
    }

    #[test]
    fn a_data_table_finding_serde_round_trips_under_its_kind_tag() {
        let finding = ConstFinding::DataTable(data_table());
        let json = serde_json::to_string(&finding).expect("data-table finding should serialize");
        assert!(json.contains("\"kind\":\"data_table\""));
        assert!(json.contains("\"element_type\":\"u16\""));
        assert!(json.contains("\"values\":[1,2,3,4,5,6,7,8,9,10,11,12]"));
        let back: ConstFinding =
            serde_json::from_str(&json).expect("data-table finding should read back");
        assert_eq!(back, finding);
    }

    #[test]
    fn documents_written_before_the_data_table_variant_load_unchanged() {
        // The literal on-disk shape of pre-variant findings — the new
        // variant changes no old tag, so a persisted document from
        // before it exists still loads finding-for-finding unchanged.
        let json = r#"[
            {"kind": "named_constant", "value": 1024, "count": 5,
             "functions": ["FUN_18003ab00", "FUN_18003e750"],
             "suggestion": "const VALUE_0x400: u32 = 0x400;",
             "confidence": 60,
             "evidence": "0x400 used 5 times in FUN_18003ab00, FUN_18003e750"},
            {"kind": "color_constant", "values": [1193046, 16711935],
             "functions": ["FUN_18003ab00", "FUN_18003e750"],
             "suggestion": "const COLOR_0x123456: u32 = 0x123456; const COLOR_0xff00ff: u32 = 0xff00ff;",
             "confidence": 60,
             "evidence": "0x123456 used 2 times in FUN_18003ab00; 0xff00ff used 1 times in FUN_18003e750"}
        ]"#;
        let back: Vec<ConstFinding> =
            serde_json::from_str(json).expect("a pre-variant document should load");
        assert_eq!(
            back,
            vec![
                ConstFinding::NamedConstant(named_constant()),
                ConstFinding::ColorConstant(color_constant()),
            ]
        );
    }

    #[test]
    fn a_context_name_renders_the_named_const_form() {
        // When the bodies named the value, the suggestion reads like
        // the code that uses it.
        assert_eq!(
            NamedConstant::render_suggestion(Some("SIZE_0x280"), 0x280),
            "const SIZE_0x280: u32 = 0x280;"
        );
    }

    #[test]
    fn no_context_name_renders_the_mechanical_const_form() {
        // A value the bodies never named keeps the spelling the deepening
        // replaced — the deepening never loses a constant the scan used
        // to report.
        assert_eq!(
            NamedConstant::render_suggestion(None, 0x400),
            "const VALUE_0x400: u32 = 0x400;"
        );
        assert_eq!(
            NamedConstant::render_suggestion(None, 1 << 40),
            "const VALUE_0x10000000000: u64 = 0x10000000000;"
        );
    }

    #[test]
    fn a_named_constant_with_a_context_name_serde_round_trips() {
        let record = NamedConstant {
            name: Some("SIZE_0x280".into()),
            ..named_constant()
        };
        let json = serde_json::to_string(&record).expect("named-constant record should serialize");
        assert!(json.contains("\"name\":\"SIZE_0x280\""));
        let back: NamedConstant =
            serde_json::from_str(&json).expect("named-constant record should read back");
        assert_eq!(back, record);
    }

    #[test]
    fn a_named_constant_without_a_context_name_omits_it_on_disk() {
        // The empty-skip rule: an un-named record serializes exactly as
        // it did before the deepening.
        let record = named_constant();
        let json = serde_json::to_string(&record).expect("named-constant record should serialize");
        assert!(!json.contains("\"name\""));
        let back: NamedConstant =
            serde_json::from_str(&json).expect("named-constant record should read back");
        assert_eq!(back, record);
    }

    #[test]
    fn a_document_written_before_the_name_field_loads_unchanged() {
        // The exact shape a pre-deepening document carried on disk — no
        // name key anywhere — still loads, with no name.
        let json = r#"{
            "value": 1024,
            "count": 5,
            "functions": ["FUN_18003ab00", "FUN_18003e750"],
            "suggestion": "const VALUE_0x400: u32 = 0x400;",
            "confidence": 60,
            "evidence": "0x400 used 5 times in FUN_18003ab00, FUN_18003e750"
        }"#;
        let back: NamedConstant =
            serde_json::from_str(json).expect("a pre-deepening document should load");
        assert_eq!(back, named_constant());
    }

    #[test]
    fn the_union_accessors_reach_through_every_variant() {
        let findings = [
            ConstFinding::BitflagGroup(bitflag_group()),
            ConstFinding::EnumCandidate(enum_candidate()),
            ConstFinding::NamedConstant(named_constant()),
            ConstFinding::FlagFamily(flag_family()),
            ConstFinding::ProtocolConstant(protocol_constant()),
            ConstFinding::ColorConstant(color_constant()),
            ConstFinding::DataTable(data_table()),
        ];
        let kinds: Vec<&str> = findings.iter().map(|f| f.kind()).collect();
        assert_eq!(
            kinds,
            vec![
                "bitflag_group",
                "enum_candidate",
                "named_constant",
                "flag_family",
                "protocol_constant",
                "color_constant",
                "data_table",
            ]
        );
        let targets: Vec<String> = findings.iter().map(|f| f.target()).collect();
        assert_eq!(
            targets,
            vec![
                "0x500",
                "0..=3",
                "0x400",
                "0xd00",
                "0xdeadbeef",
                "0x123456, 0xff00ff",
                "DAT_1400a1b60 [u16; 12]",
            ]
        );
        for finding in &findings {
            assert!(!finding.suggestion().is_empty());
            assert!(!finding.evidence().is_empty());
        }
        assert_eq!(findings[0].function(), "FUN_18003ab00");
        assert_eq!(findings[1].function(), "FUN_18003ab00");
        assert_eq!(findings[2].function(), "");
        assert_eq!(findings[3].function(), "");
        assert_eq!(findings[4].function(), "");
        assert_eq!(findings[5].function(), "");
        assert_eq!(findings[6].function(), "");
        assert_eq!(findings[2].confidence(), Confidence::new(60));
        assert_eq!(findings[3].confidence(), Confidence::new(80));
        assert_eq!(findings[4].confidence(), Confidence::new(75));
        assert_eq!(findings[5].confidence(), Confidence::new(60));
        assert_eq!(findings[6].confidence(), Confidence::new(70));
    }

    #[test]
    fn a_const_result_serde_round_trips() {
        let result = ConstResult {
            metadata: ScanMetadata {
                binary: "eqmain.dll".into(),
                scanned_at: 1_759_488_000,
                duration_secs: 12,
                engine: None,
            },
            findings: vec![
                ConstFinding::BitflagGroup(bitflag_group()),
                ConstFinding::EnumCandidate(enum_candidate()),
                ConstFinding::NamedConstant(named_constant()),
                ConstFinding::FlagFamily(flag_family()),
            ],
        };
        let json = serde_json::to_string(&result).expect("const result should serialize");
        let back: ConstResult = serde_json::from_str(&json).expect("const result should read back");
        assert_eq!(back, result);
    }

    #[test]
    fn a_result_without_findings_omits_them_and_reads_back_empty() {
        let result = ConstResult::new(ScanMetadata::new("eqmain.dll"));
        let json = serde_json::to_string(&result).expect("empty const result should serialize");
        assert!(!json.contains("\"findings\""));
        let back: ConstResult =
            serde_json::from_str(&json).expect("empty const result should read back");
        assert!(back.is_empty());
        assert_eq!(back.metadata.binary, "eqmain.dll");
    }

    #[test]
    fn for_function_yields_per_function_findings_and_program_level_findings_that_name_it() {
        let other = ConstFinding::BitflagGroup(BitflagGroup {
            function: "FUN_18003e750".into(),
            ..bitflag_group()
        });
        let named = ConstFinding::NamedConstant(NamedConstant {
            functions: vec!["FUN_18003e750".into()],
            ..named_constant()
        });
        let family = ConstFinding::FlagFamily(FlagFamily {
            functions: vec!["FUN_18003e750".into(), "FUN_180099998".into()],
            ..flag_family()
        });
        let protocol = ConstFinding::ProtocolConstant(ProtocolConstant {
            functions: vec!["FUN_18003e750".into(), "FUN_180099998".into()],
            ..protocol_constant()
        });
        let palette = ConstFinding::ColorConstant(ColorConstant {
            functions: vec!["FUN_18003e750".into(), "FUN_180099998".into()],
            ..color_constant()
        });
        let table = ConstFinding::DataTable(DataTable {
            functions: vec!["FUN_18003e750".into(), "FUN_180099998".into()],
            ..data_table()
        });
        let unrelated = ConstFinding::EnumCandidate(EnumCandidate {
            function: "FUN_180099999".into(),
            ..enum_candidate()
        });
        let result = ConstResult {
            metadata: ScanMetadata::new("eqmain.dll"),
            findings: vec![
                other.clone(),
                named.clone(),
                family.clone(),
                protocol.clone(),
                palette.clone(),
                table.clone(),
                unrelated,
            ],
        };
        let found: Vec<&ConstFinding> = result.for_function("FUN_18003e750").collect();
        assert_eq!(
            found,
            vec![&other, &named, &family, &protocol, &palette, &table]
        );
        assert_eq!(
            result.for_function("FUN_180099998").collect::<Vec<_>>(),
            vec![&family, &protocol, &palette, &table],
            "the family, the protocol constant, the palette, and the table \
             answer the lookup of every contributor"
        );
        assert!(result.for_function("FUN_180099997").next().is_none());
        assert!(!result.is_empty());
    }

    #[test]
    fn a_finding_renders_into_prompt_data_whichever_kind_it_is() {
        let bitflag = ConstFinding::BitflagGroup(bitflag_group());
        let info = calxgloss_prompts::ConstInfo::from(&bitflag);
        assert_eq!(info.function, "FUN_18003ab00");
        assert_eq!(info.kind, "bitflag_group");
        assert_eq!(info.confidence, 70);

        let enum_candidate = ConstFinding::EnumCandidate(enum_candidate());
        let info = calxgloss_prompts::ConstInfo::from(&enum_candidate);
        assert_eq!(info.kind, "enum_candidate");
        assert_eq!(info.confidence, 70);

        let named = ConstFinding::NamedConstant(named_constant());
        let info = calxgloss_prompts::ConstInfo::from(&named);
        assert_eq!(info.kind, "named_constant");
        assert_eq!(info.confidence, 60);
        assert_eq!(info.suggestion, "const VALUE_0x400: u32 = 0x400;");

        let family = ConstFinding::FlagFamily(flag_family());
        let info = calxgloss_prompts::ConstInfo::from(&family);
        assert_eq!(info.function, "");
        assert_eq!(info.kind, "flag_family");
        assert_eq!(info.confidence, 80);
        assert_eq!(
            info.suggestion,
            "bitflags! struct Flags: u16 { /* bits: 0x100, 0x400, 0x800 */ }"
        );

        let protocol = ConstFinding::ProtocolConstant(protocol_constant());
        let info = calxgloss_prompts::ConstInfo::from(&protocol);
        assert_eq!(info.function, "");
        assert_eq!(info.kind, "protocol_constant");
        assert_eq!(info.confidence, 75);
        assert_eq!(info.suggestion, "const DEAD_BEEF_MARKER: u32 = 0xdeadbeef;");
        assert!(info.evidence.contains("DEAD_BEEF_MARKER"));

        let palette = ConstFinding::ColorConstant(color_constant());
        let info = calxgloss_prompts::ConstInfo::from(&palette);
        assert_eq!(info.function, "");
        assert_eq!(info.kind, "color_constant");
        assert_eq!(info.confidence, 60);
        assert_eq!(
            info.suggestion,
            "const COLOR_0x123456: u32 = 0x123456; const COLOR_0xff00ff: u32 = 0xff00ff;"
        );
        assert!(info.evidence.contains("0x123456 used 2 times"));

        let table = ConstFinding::DataTable(data_table());
        let info = calxgloss_prompts::ConstInfo::from(&table);
        assert_eq!(info.function, "");
        assert_eq!(info.kind, "data_table");
        assert_eq!(info.confidence, 70);
        assert_eq!(info.suggestion, "const DAT_1400A1B60: [u16; 12];");
        assert!(info.evidence.contains("DAT_1400a1b60[uVar2]"));
    }

    #[test]
    fn a_bare_data_label_gets_its_mechanical_uppercase_name_a_meaningful_label_its_own() {
        assert_eq!(
            DataTable::render_suggestion("DAT_1400a1b60", "u16", 12),
            "const DAT_1400A1B60: [u16; 12];"
        );
        assert_eq!(
            DataTable::render_suggestion("switchD_1400a1b80_case_1", "u32", 4),
            "const SWITCHD_1400A1B80_CASE_1: [u32; 4];"
        );
        assert_eq!(
            DataTable::render_suggestion("weapon_stats", "u16", 12),
            "const weapon_stats: [u16; 12];"
        );
    }
}
