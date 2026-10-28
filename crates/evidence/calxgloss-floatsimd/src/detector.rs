//! The per-body float/SIMD evidence reading.
//!
//! [`FloatsimdDetector`] reads one decompiled body and yields at most
//! one flag record for it: the shape the body's float evidence spells,
//! the strongest evidence line the reading was based on, and the
//! confidence band that evidence family scores on the Evidence scale.
//!
//! The reading looks for four evidence families, each matched by its
//! own shape in the pseudo-C:
//!
//! - **Explicit float tokens** — a `float` or `double` type word in a
//!   declaration or cast, or a float literal (`1.0f`, `3.141593`) in
//!   an expression. The decompiler itself named the float; nothing in
//!   the body contradicts it, so this is the strongest family.
//! - **CRT math calls** — a call to a CRT math routine (`sqrt`,
//!   `sin`, `floor`, `fmod`, …). The float evidence comes from the
//!   library call rather than from a spelled-out type, so it scores
//!   below an explicit token but above any shape-only idiom.
//! - **Vector assembly idioms** — a `CONCAT44`-style concatenation or
//!   `SUB4`-style extraction, the shapes the decompiler mangles SIMD
//!   register work into. Real body evidence, but the reading keys on
//!   the idiom's shape, not on a stated float type.
//! - **Component triplets** — parallel reads of a variable's `x`, `y`
//!   and `z` members, the x/y/z shape a vector struct or array leaves
//!   behind. Weakest on its own: a plain integer point struct has the
//!   same members, so the flag only claims what its band says.
//!
//! The strongest family decides the record's confidence, and its body
//! line is quoted as the evidence (a tie keeps the first family seen).
//! Which families fired decides the *shape*: only scalar families
//! fired gives `scalar_float`; only vector families fired gives
//! `vector_matrix`; both give one `mixed` flag naming both shapes, not
//! two flags the consumer has to combine back into one. A body that
//! triggers no family gets no flag: an integer function lands none.

use crate::types::{FloatsimdFinding, FloatsimdRecord, ShapeKind};
use calxgloss_decomp::DecompiledFunction;
use regex::Regex;
use std::sync::OnceLock;

/// Evidence confidence of a body where the decompiler itself spelled
/// the float evidence — a `float`/`double` type word or a float
/// literal. The decompiler's own type knowledge stated the claim
/// outright, so this reading sits at the top of the Evidence scale for
/// this artifact.
pub const EXPLICIT_FLOAT_CONFIDENCE: u8 = 90;

/// Evidence confidence of a body whose float use shows through a CRT
/// math import call (`sqrt`, `sin`, `floor`, `fmod`). The call is
/// unambiguous float work, but it is a library-name sighting, not a
/// spelled-out type, so it reads below every explicit token.
pub const CRT_MATH_CONFIDENCE: u8 = 75;

/// Evidence confidence of a body showing `CONCAT44`/`SUB4`-style
/// vector assembly idioms. The mangling shape is real body evidence
/// that the decompiler was stitching SIMD register work back together,
/// but the float reading comes from the idiom's shape, not a stated
/// type — so the claim sits below every spelled float sighting.
pub const VECTOR_IDIOM_CONFIDENCE: u8 = 60;

/// Evidence confidence of a body that reads one variable's `x`, `y`
/// and `z` members side by side. The x/y/z triplet is the shape a
/// vector leaves behind, but integer points have the same members, so
/// the flag is a shape-only sighting — the weakest band in the
/// artifact, and no later pass raises it from repeated sightings in one
/// reading.
pub const COMPONENT_TRIPLET_CONFIDENCE: u8 = 40;

/// The Rust shape a scalar-float flag tells a translation to use:
/// plain float operations, never integer or pointer arithmetic over
/// the mangled body.
const SCALAR_SUGGESTION: &str =
    "translate as f32/f64 scalar float math, not integer or pointer arithmetic";

/// The Rust shape a vector/matrix flag tells a translation to use: the
/// packed-integer mangling is a vector read as integers — the
/// translation should model the components, not the packing.
const VECTOR_SUGGESTION: &str =
    "translate as a small vector struct or component array, not integer or pointer arithmetic";

/// The Rust shapes a mixed flag tells a translation to use: both
/// shapes in one body, scalars as floats and the mangled vector work
/// as components.
const MIXED_SUGGESTION: &str = "translate the float math as f32/f64 scalars and the vector idioms as component arrays or small vector structs";

// The band order is a rule, not a taste call: an explicit float token
// scores above a CRT math call, which scores above a vector assembly
// idiom, which scores above a component triplet. A test in this module
// pins the order, and the reading below relies on it.

/// Which half of the shape distinction an evidence family belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ShapeClass {
    /// The family's evidence spells scalar float math.
    Scalar,
    /// The family's evidence spells vector/matrix idioms.
    Vector,
}

/// An evidence family the body triggered: its band, its shape class,
/// and the first body line where the sighting appeared.
struct FamilyHit {
    confidence: u8,
    class: ShapeClass,
    evidence: String,
}

/// The per-body float/SIMD evidence reading.
///
/// The detector is stateless: every reading comes only from the body
/// it is handed, and no information passes between bodies. One
/// instance serves a whole scan, and each body is read once.
#[derive(Debug, Clone, Default)]
pub struct FloatsimdDetector;

impl FloatsimdDetector {
    /// A detector with the standard reading.
    pub fn new() -> Self {
        Self
    }

    /// Read one decompiled body and flag it, or stay silent when no
    /// evidence family fires.
    ///
    /// At most one flag comes out per function: the shape named by the
    /// families that fired, plus the confidence and evidence line of
    /// the strongest family among them (a tie keeps the first family
    /// seen — the families are checked from the highest band down).
    pub fn detect(&self, function: &DecompiledFunction) -> Option<FloatsimdFinding> {
        let body = &function.body;
        let mut hits = Vec::new();
        if let Some(line) = first_line_matching(body, explicit_floats()) {
            hits.push(FamilyHit {
                confidence: EXPLICIT_FLOAT_CONFIDENCE,
                class: ShapeClass::Scalar,
                evidence: line,
            });
        }
        if let Some(line) = first_line_matching(body, crt_math_calls()) {
            hits.push(FamilyHit {
                confidence: CRT_MATH_CONFIDENCE,
                class: ShapeClass::Scalar,
                evidence: line,
            });
        }
        if let Some(line) = first_line_matching(body, vector_idioms()) {
            hits.push(FamilyHit {
                confidence: VECTOR_IDIOM_CONFIDENCE,
                class: ShapeClass::Vector,
                evidence: line,
            });
        }
        if let Some(line) = component_triplet(body) {
            hits.push(FamilyHit {
                confidence: COMPONENT_TRIPLET_CONFIDENCE,
                class: ShapeClass::Vector,
                evidence: line,
            });
        }
        if hits.is_empty() {
            return None;
        }

        // The strongest family wins. On a tie the *first* hit stays,
        // so the family order above also settles ties.
        let mut best = &hits[0];
        for hit in &hits[1..] {
            if hit.confidence > best.confidence {
                best = hit;
            }
        }
        let saw_scalar = hits.iter().any(|hit| hit.class == ShapeClass::Scalar);
        let saw_vector = hits.iter().any(|hit| hit.class == ShapeClass::Vector);
        let (shape, suggestion) = match (saw_scalar, saw_vector) {
            (true, true) => (ShapeKind::Mixed, MIXED_SUGGESTION),
            (true, false) => (ShapeKind::ScalarFloat, SCALAR_SUGGESTION),
            (false, true) => (ShapeKind::VectorMatrix, VECTOR_SUGGESTION),
            (false, false) => return None,
        };
        let record = FloatsimdRecord {
            function: function.name.clone(),
            evidence: best.evidence.clone(),
            confidence: best.confidence.into(),
            suggestion: suggestion.to_string(),
        };
        Some(match shape {
            ShapeKind::ScalarFloat => FloatsimdFinding::ScalarFloat(record),
            ShapeKind::VectorMatrix => FloatsimdFinding::VectorMatrix(record),
            ShapeKind::Mixed => FloatsimdFinding::Mixed(record),
        })
    }
}

/// The first body line (trimmed) the pattern matches, if any — the
/// line where the family's sighting appeared, quoted as the flag's
/// evidence.
fn first_line_matching(body: &str, pattern: &Regex) -> Option<String> {
    body.lines()
        .find(|line| pattern.is_match(line))
        .map(|line| line.trim().to_string())
}

/// Whether one variable is read through all three of its `x`, `y` and
/// `z` members somewhere in the body, and the first line with such a
/// component read. All three reads must be on the *same* receiver —
/// `local_10.x`, `local_10.y`, `local_10.z` — because that is what
/// parallel reads of one vector look like. Three unrelated objects
/// with members named `x`, `y`, and `z` do not make a vector.
fn component_triplet(body: &str) -> Option<String> {
    let mut components: Vec<(String, [bool; 3])> = Vec::new();
    let mut first_line: Option<String> = None;
    for line in body.lines() {
        for capture in component_members().captures_iter(line) {
            let index = match &capture[2] {
                "x" => 0,
                "y" => 1,
                _ => 2,
            };
            let receiver = capture[1].to_string();
            let slot = match components.iter().position(|(name, _)| *name == receiver) {
                Some(position) => position,
                None => {
                    components.push((receiver, [false; 3]));
                    components.len() - 1
                }
            };
            let entry = &mut components[slot];
            entry.1[index] = true;
            if first_line.is_none() {
                first_line = Some(line.trim().to_string());
            }
            if entry.1 == [true, true, true] {
                return first_line;
            }
        }
    }
    None
}

/// `float`/`double` type words and float literals: the decompiler's
/// own spelled float evidence. `1.0f` and `3.141593` literals, and
/// the type words as whole identifiers — never the `float` inside
/// `floatVal` or a `DAT_float` naming.
fn explicit_floats() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| {
        Regex::new(r"\b(float|double)\b|\b\d+\.\d+[fF]?\b")
            .expect("a static float pattern compiles")
    })
}

/// Calls to CRT math routines — the import-call shape of float use the
/// decompiler never typed as float. In the pattern, longer spellings
/// come first at shared prefixes (`sqrtf` before `sqrt`), so one name
/// never hides its own suffixed sibling.
fn crt_math_calls() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| {
        Regex::new(concat!(
            r"\b(sqrtl|sqrtf|sqrt|sinhl|sinh|sinf|sin|coshl|cosh|cosf|cos|tanhl|tanh|tanf|tan|",
            r"asinl|asinf|asin|acosl|acosf|acos|atan2l|atan2f|atan2|atanl|atanf|atan|",
            r"floorl|floorf|floor|ceill|ceilf|ceil|fabsl|fabsf|fabs|fmodl|fmodf|fmod|",
            r"expl|expf|exp|log10l|log10f|log10|log2f|log2|logl|log|",
            r"frexpl|frexp|ldexpl|ldexp|modfl|modf|hypotl|hypotf|hypot|",
            r"truncl|truncf|trunc|roundl|roundf|round)\s*\(",
        ))
        .expect("a static CRT math pattern compiles")
    })
}

/// `CONCAT44`-style concatenations and `SUB4`-style extractions — the
/// pseudo-C shapes the decompiler mangles SIMD register work into.
fn vector_idioms() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| {
        Regex::new(r"\bCONCAT\d{2}\s*\(|\bSUB\d\s*\(")
            .expect("a static vector idiom pattern compiles")
    })
}

/// A named receiver read through an `x`, `y`, or `z` member — the
/// component reads a vector struct or array leaves behind.
fn component_members() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| {
        Regex::new(r"\b([A-Za-z_]\w*)(?:\.|->)([xyz])\b")
            .expect("a static component member pattern compiles")
    })
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn function(name: &str, body: &str) -> DecompiledFunction {
        DecompiledFunction {
            name: name.to_string(),
            signature: format!("undefined {name}(void)"),
            body: format!("undefined {name}(void)\n\n{{\n{body}}}\n"),
        }
    }

    fn detect(body: &str) -> Option<FloatsimdFinding> {
        FloatsimdDetector::new().detect(&function("FUN_18003ab00", body))
    }

    #[test]
    fn the_evidence_bands_strictly_descend_from_explicit_to_shape_only() {
        const {
            assert!(EXPLICIT_FLOAT_CONFIDENCE > CRT_MATH_CONFIDENCE);
            assert!(CRT_MATH_CONFIDENCE > VECTOR_IDIOM_CONFIDENCE);
            assert!(VECTOR_IDIOM_CONFIDENCE > COMPONENT_TRIPLET_CONFIDENCE);
        };
    }

    #[test]
    fn an_explicit_float_type_word_fires_at_the_top_band() {
        let flag = detect("  fVar1 = (float)uVar2;\n").expect("a spelled float fires");
        assert_eq!(flag.kind(), "scalar_float");
        assert_eq!(flag.confidence().value(), EXPLICIT_FLOAT_CONFIDENCE);
        assert_eq!(flag.evidence(), "fVar1 = (float)uVar2;");
        assert!(flag.suggestion().contains("f32/f64"));
    }

    #[test]
    fn a_double_declaration_fires_as_explicit_float_evidence() {
        let flag = detect("  double dVar1;\n  dVar1 = *param_1;\n").expect("a double fires");
        assert_eq!(flag.kind(), "scalar_float");
        assert_eq!(flag.confidence().value(), EXPLICIT_FLOAT_CONFIDENCE);
        assert_eq!(flag.evidence(), "double dVar1;");
    }

    #[test]
    fn a_float_literal_fires_as_explicit_float_evidence() {
        let flag = detect("  fVar3 = fVar1 * 1.5f;\n").expect("a float literal fires");
        assert_eq!(flag.kind(), "scalar_float");
        assert_eq!(flag.confidence().value(), EXPLICIT_FLOAT_CONFIDENCE);
        assert_eq!(flag.evidence(), "fVar3 = fVar1 * 1.5f;");
    }

    #[test]
    fn a_crt_math_call_fires_below_the_explicit_bands() {
        let flag = detect("  local_10 = sqrt(fVar1);\n").expect("a CRT call fires");
        assert_eq!(flag.kind(), "scalar_float");
        assert_eq!(flag.confidence().value(), CRT_MATH_CONFIDENCE);
        assert_eq!(flag.evidence(), "local_10 = sqrt(fVar1);");
    }

    #[test]
    fn a_suffixed_crt_call_fires_like_its_short_sibling() {
        for call in ["sqrtf(fVar1)", "atan2f(fVar1, fVar2)", "log10f(fVar1)"] {
            let flag = detect(&format!("  local_10 = {call};\n")).unwrap_or_else(|| {
                panic!("the suffixed CRT call `{call}` must fire as float evidence")
            });
            assert_eq!(flag.confidence().value(), CRT_MATH_CONFIDENCE);
        }
    }

    #[test]
    fn a_concat_mangling_fires_as_a_vector_shape() {
        let flag = detect("  local_10 = CONCAT44(uVar2 >> 4, uVar2 & 0xfffffff);\n")
            .expect("a CONCAT idiom fires");
        assert_eq!(flag.kind(), "vector_matrix");
        assert_eq!(flag.confidence().value(), VECTOR_IDIOM_CONFIDENCE);
        assert_eq!(
            flag.evidence(),
            "local_10 = CONCAT44(uVar2 >> 4, uVar2 & 0xfffffff);"
        );
        assert!(flag.suggestion().contains("component array"));
    }

    #[test]
    fn a_sub_extraction_fires_as_a_vector_shape() {
        let flag = detect("  fVar1 = SUB4(local_10, 0);\n").expect("a SUB idiom fires");
        assert_eq!(flag.kind(), "vector_matrix");
        assert_eq!(flag.confidence().value(), VECTOR_IDIOM_CONFIDENCE);
    }

    #[test]
    fn an_xyz_component_triplet_fires_at_the_weakest_band() {
        let flag = detect("  fVar1 = local_10.x;\n  fVar2 = local_10.y;\n  fVar3 = local_10.z;\n")
            .expect("a parallel x/y/z triplet fires");
        assert_eq!(flag.kind(), "vector_matrix");
        assert_eq!(flag.confidence().value(), COMPONENT_TRIPLET_CONFIDENCE);
        assert_eq!(flag.evidence(), "fVar1 = local_10.x;");
    }

    #[test]
    fn component_reads_on_different_variables_name_no_vector() {
        // Three unrelated objects, one member each — no receiver ever
        // read through all three components, so no triplet fires.
        let flag = detect("  a.x = 1;\n  b.y = 2;\n  c.z = 3;\n");
        assert!(flag.is_none(), "no one vector was read through x, y, z");
    }

    #[test]
    fn an_integer_body_fires_nothing() {
        // The guard against false flags: plain integer and pointer
        // arithmetic, hex constants, and ordinary decompiler variable
        // names — no family has anything to match.
        let flag = detect(
            "  uVar1 = param_1 + 4;\n  DAT_180064e80 = uVar1;\n  \
             iVar2 = *(int *)(param_1 + 8);\n  if (iVar2 != 0) {\n    uVar1 = uVar1 * 0x10;\n  }\n  \
             return uVar1;\n",
        );
        assert!(flag.is_none(), "an integer body must land no flag");
    }

    #[test]
    fn a_identifier_that_merely_holds_the_word_float_is_not_explicit_evidence() {
        let flag = detect("  uVar1 = floatVal + DAT_floatchart;\n");
        assert!(
            flag.is_none(),
            "the word inside an identifier names no float"
        );
    }

    #[test]
    fn both_shapes_in_one_body_land_one_mixed_flag() {
        // Flags count per function, not per signal: a body with
        // explicit scalar evidence and vector mangling lands one flag
        // naming both, with the strongest family's band and evidence
        // line.
        let flag = detect("  fVar1 = (float)uVar2;\n  local_10 = CONCAT44(uVar2 >> 4, uVar2);\n")
            .expect("both families fire");
        assert_eq!(flag.kind(), "mixed");
        assert_eq!(flag.confidence().value(), EXPLICIT_FLOAT_CONFIDENCE);
        assert_eq!(flag.evidence(), "fVar1 = (float)uVar2;");
        assert!(flag.suggestion().contains("f32/f64"));
        assert!(flag.suggestion().contains("vector"));
    }

    #[test]
    fn the_strongest_family_sets_the_band_across_scalar_and_vector() {
        // CRT math (scalar) with a vector idiom: mixed shape, the
        // higher of the two bands, the stronger family's line.
        let flag = detect("  local_10 = CONCAT44(uVar2 >> 4, uVar2);\n  sqrt(fVar1);\n")
            .expect("both families fire");
        assert_eq!(flag.kind(), "mixed");
        assert_eq!(flag.confidence().value(), CRT_MATH_CONFIDENCE);
        assert_eq!(flag.evidence(), "sqrt(fVar1);");
    }

    #[test]
    fn the_first_line_of_the_winning_family_carries_the_evidence() {
        let flag = detect("  fVar2 = 2.0f;\n  fVar1 = (float)uVar2;\n").expect("floats fire");
        assert_eq!(flag.evidence(), "fVar2 = 2.0f;", "the first sighting wins");
    }

    #[test]
    fn the_flag_names_the_function_whose_body_was_read() {
        let body = function("FUN_1800412a0", "  fVar1 = (float)uVar2;\n");
        let flag = FloatsimdDetector::new()
            .detect(&body)
            .expect("a spelled float fires");
        assert_eq!(flag.function(), "FUN_1800412a0");
    }
}
