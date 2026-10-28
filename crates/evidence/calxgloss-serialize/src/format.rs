//! Serialization format inference.
//!
//! This module provides [`FormatCombiner`]. It runs once per function,
//! after that function's readings are in, and combines the scan's
//! separate serialization readings into one composed claim. When a
//! function carries at least two readings — byte-swap calls and/or
//! bit-pack chains — the combiner joins them, in body order, into a
//! single [`SerializationFormat`] layout. The layout names each
//! field's width, the wire byte order for swapped fields, and the
//! bitfield widths for packed chains.
//!
//! The combiner reads no body of its own. It uses only the findings
//! the per-function pass already collected for the function, so
//! combining costs no extra reads from the analysis engine. It looks
//! at the body only to place the readings in body order. The readings
//! themselves are the whole claim.
//!
//! The honesty gates are the point. A function with one reading claims
//! no format: a lone `ntohl` never invents a message layout. The
//! layout names a reader or a writer direction only when all the
//! directional swap names point the same way — network-to-host reads
//! or host-to-network writes. Direction-neutral names (builtins, a
//! program's own swap spelling) neither corroborate nor contradict.
//! When the directional families disagree, the direction stays
//! absent. A direction-neutral swap also names no wire endianness for
//! its field; only the network-order family does that.

use crate::types::{
    BitPackRecord, ByteSwapOperation, FormatDirection, FormatField, SerializationFormat,
    WireEndianness,
};
use calxgloss_decomp::DecompiledFunction;

// ============================================================
// Combiner
// ============================================================

/// Composes one function's serialization readings into one layout.
///
/// The combiner has no configuration: the gate is the reading count,
/// and the honesty rules are fixed. It holds no state, and one
/// instance serves the whole scan. [`combine`](Self::combine) receives
/// the byte-swap and bit-pack records the scan just made for one
/// function, plus that function's body for ordering alone. It answers
/// with the composed [`SerializationFormat`], or `None` when the
/// function carries fewer than two readings.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FormatCombiner;

impl FormatCombiner {
    /// A combiner with the standard honesty rules.
    pub fn new() -> Self {
        FormatCombiner
    }

    /// The composed layout one function's readings add up to.
    ///
    /// Swap records and pack records each arrive in body order within
    /// their own kind. The combiner merges them by the body line each
    /// reading's evidence sits on, then builds the layout from that
    /// merged sequence. Each swap contributes one field at the width
    /// its signature swapped: [`WireEndianness::BigEndian`] for a
    /// network-order name, [`WireEndianness::ReversalOnly`] for a
    /// direction-neutral one. Each pack chain contributes one field
    /// per bitfield width it carved, with no endianness. The direction
    /// is named only when every directional swap name in the function
    /// points the same way. A function with fewer than two readings
    /// claims nothing and answers `None`.
    pub fn combine(
        &self,
        func: &DecompiledFunction,
        swaps: &[ByteSwapOperation],
        packs: &[BitPackRecord],
    ) -> Option<SerializationFormat> {
        if swaps.len() + packs.len() < 2 {
            // One swap call or one pack chain says nothing about a
            // message layout, so nothing composes and nothing is
            // claimed.
            return None;
        }

        // Merge the readings into body order. Each record's position
        // is the body line its evidence sits on. A record whose
        // evidence matches no line (a hand-built finding set) keeps
        // its given place, after every located one.
        let mut readings: Vec<(Option<usize>, Reading<'_>)> = Vec::new();
        for swap in swaps {
            readings.push((
                body_line_index(&func.body, &swap.evidence),
                Reading::Swap(swap),
            ));
        }
        for pack in packs {
            readings.push((
                body_line_index(&func.body, &pack.evidence),
                Reading::Pack(pack),
            ));
        }
        readings.sort_by_key(|(line, _)| *line);

        let mut fields: Vec<FormatField> = Vec::new();
        let mut evidence_lines: Vec<&str> = Vec::new();
        let mut saw_read = false;
        let mut saw_write = false;
        for (_, reading) in &readings {
            match reading {
                Reading::Swap(swap) => {
                    let endianness = if is_network_read(&swap.operation) {
                        saw_read = true;
                        WireEndianness::BigEndian
                    } else if is_network_write(&swap.operation) {
                        saw_write = true;
                        WireEndianness::BigEndian
                    } else {
                        // A direction-neutral name (a builtin, a
                        // program's own swap spelling) only reverses
                        // bytes; it claims no wire order.
                        WireEndianness::ReversalOnly
                    };
                    fields.push(FormatField {
                        width: swap.width,
                        endianness: Some(endianness),
                    });
                    evidence_lines.push(&swap.evidence);
                }
                Reading::Pack(pack) => {
                    for width in &pack.widths {
                        fields.push(FormatField {
                            width: *width,
                            endianness: None,
                        });
                    }
                    evidence_lines.push(&pack.evidence);
                }
            }
        }

        // A direction is named only when the directional families
        // agree. Direction-neutral names never set a direction on
        // their own, and they never contradict a direction the
        // directional names already agree on.
        let direction = match (saw_read, saw_write) {
            (true, false) => Some(FormatDirection::Reader),
            (false, true) => Some(FormatDirection::Writer),
            _ => None,
        };

        Some(SerializationFormat {
            function: func.name.clone(),
            suggestion: reader_sketch(&fields, direction),
            fields,
            direction,
            confidence: FORMAT_CONFIDENCE.into(),
            evidence: evidence_lines.join(" "),
        })
    }
}

/// One reading that contributes to the layout, kept in the merged
/// body-order sequence.
enum Reading<'a> {
    Swap(&'a ByteSwapOperation),
    Pack(&'a BitPackRecord),
}

// ============================================================
// The reading
// ============================================================

/// The evidence confidence of a composed layout. Two or more
/// independent readings corroborate the sequence, so it sits above
/// the strongest single reading that fed it (the byte-swap floor of
/// 70) and below the lone-magic floor of 80, whose signature match
/// names a whole format outright.
const FORMAT_CONFIDENCE: u8 = 75;

/// Whether a swap name moves bytes network-to-host, which is a read.
/// The protocol combiner uses this too: its promotion gate accepts
/// only the network-order family as a corroborating byte swap.
pub(crate) fn is_network_read(name: &str) -> bool {
    matches!(name, "ntohs" | "ntohl")
}

/// Whether a swap name moves bytes host-to-network, which is a write.
pub(crate) fn is_network_write(name: &str) -> bool {
    matches!(name, "htons" | "htonl")
}

/// Which body line a reading's evidence sits on. A one-line reading's
/// evidence is the trimmed body line itself. An unpack chain joins its
/// extraction lines together, so its first line leads. A record whose
/// evidence matches no line answers `None` and sorts last.
fn body_line_index(body: &str, evidence: &str) -> Option<usize> {
    let lines: Vec<&str> = body.lines().map(str::trim).collect();
    lines.iter().position(|line| *line == evidence).or_else(|| {
        lines
            .iter()
            .position(|line| !line.is_empty() && evidence.starts_with(line))
    })
}

/// The Rust pattern the composed sequence suggests: a typed field
/// sequence in `byteorder` style. Each swapped field becomes one sized
/// read, or one write for a writer layout. Consecutive packed
/// bitfields are grouped into one bitfield run. This lets the escalate
/// prompt suggest a real Rust reader instead of scattered per-call
/// hints.
fn reader_sketch(fields: &[FormatField], direction: Option<FormatDirection>) -> String {
    let (head, verb) = match direction {
        Some(FormatDirection::Reader) => ("byteorder reader: ", "read"),
        Some(FormatDirection::Writer) => ("byteorder writer: ", "write"),
        None => ("byteorder field sequence: ", "read"),
    };
    let mut parts: Vec<String> = Vec::new();
    let mut packed_run: Vec<u32> = Vec::new();
    for field in fields {
        match field.endianness {
            Some(WireEndianness::BigEndian) => {
                flush_packed_run(&mut parts, &mut packed_run);
                parts.push(format!("{verb}_u{}", field.width));
            }
            Some(WireEndianness::ReversalOnly) => {
                // A reversed-only field is spelled as the byte
                // reversal it is. The sketch claims no sized
                // big-endian read for a name that named no wire order.
                flush_packed_run(&mut parts, &mut packed_run);
                parts.push(format!("u{}.swap_bytes()", field.width));
            }
            None => packed_run.push(field.width),
        }
    }
    flush_packed_run(&mut parts, &mut packed_run);
    format!("{head}{}", parts.join(" then "))
}

/// Add one run of consecutive packed bitfield widths to the sketch as
/// a single `8+8 bitfields` entry.
fn flush_packed_run(parts: &mut Vec<String>, run: &mut Vec<u32>) {
    if !run.is_empty() {
        let widths: Vec<String> = run.iter().map(|w| w.to_string()).collect();
        parts.push(format!("{} bitfields", widths.join("+")));
        run.clear();
    }
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{BitPackPattern, Confidence};

    fn function(body: &str) -> DecompiledFunction {
        DecompiledFunction {
            name: "FUN_18003ab00".into(),
            signature: "undefined FUN_18003ab00(void)".into(),
            body: body.into(),
        }
    }

    fn swap(operation: &str, width: u32, evidence: &str) -> ByteSwapOperation {
        ByteSwapOperation {
            function: "FUN_18003ab00".into(),
            operation: operation.into(),
            width,
            suggestion: format!("byteorder::BE::read_u{width}"),
            confidence: Confidence::new(70),
            evidence: evidence.into(),
        }
    }

    fn pack(pattern: BitPackPattern, widths: &[u32], evidence: &str) -> BitPackRecord {
        BitPackRecord {
            function: "FUN_18003ab00".into(),
            pattern,
            widths: widths.to_vec(),
            suggestion: "bitvec or named-field masking/shifting".into(),
            confidence: Confidence::new(60),
            evidence: evidence.into(),
        }
    }

    const PACK_LINE: &str =
        "uVar2 = (uVar3 << 0x18) | ((uint)uVar4 << 0x10) | (uVar5 << 8) | (uint)uVar6;";

    #[test]
    fn two_swap_readings_compose_one_layout() {
        // The two-reading gate. Two swap calls in one function compose
        // one layout that names both fields, in call order. Its
        // evidence confidence is above the byte-swap floor.
        let body = "\
  uVar1 = ntohl(local_18);
  uVar3 = ntohl(local_20);
";
        let swaps = vec![
            swap("ntohl", 32, "uVar1 = ntohl(local_18);"),
            swap("ntohl", 32, "uVar3 = ntohl(local_20);"),
        ];
        let format = FormatCombiner
            .combine(&function(body), &swaps, &[])
            .expect("two readings compose a format");
        assert_eq!(format.function, "FUN_18003ab00");
        assert_eq!(
            format.fields,
            vec![
                FormatField {
                    width: 32,
                    endianness: Some(WireEndianness::BigEndian)
                },
                FormatField {
                    width: 32,
                    endianness: Some(WireEndianness::BigEndian)
                },
            ]
        );
        assert_eq!(format.direction, Some(FormatDirection::Reader));
        assert_eq!(format.confidence, Confidence::new(75));
        assert_eq!(
            format.suggestion,
            "byteorder reader: read_u32 then read_u32"
        );
        assert_eq!(
            format.evidence,
            "uVar1 = ntohl(local_18); uVar3 = ntohl(local_20);"
        );
    }

    #[test]
    fn a_single_reading_claims_no_format() {
        // A lone swap call, a lone pack chain, and an empty finding
        // set all say nothing about a layout.
        let body = "  uVar1 = ntohl(local_18);\n";
        let lone_swap = vec![swap("ntohl", 32, "uVar1 = ntohl(local_18);")];
        assert!(
            FormatCombiner
                .combine(&function(body), &lone_swap, &[])
                .is_none()
        );

        let lone_pack = vec![pack(BitPackPattern::ShiftOrPack, &[8, 8, 8, 8], PACK_LINE)];
        assert!(
            FormatCombiner
                .combine(&function(body), &[], &lone_pack)
                .is_none()
        );

        assert!(FormatCombiner.combine(&function(body), &[], &[]).is_none());
    }

    #[test]
    fn fields_land_in_body_order() {
        // The scan hands the combinator the swaps first and the packs
        // second. The layout follows the body, not the finding order,
        // so the pack chain above the swap call contributes its fields
        // first.
        let body = format!("  {PACK_LINE}\n  uVar1 = ntohl(local_18);\n");
        let swaps = vec![swap("ntohl", 32, "uVar1 = ntohl(local_18);")];
        let packs = vec![pack(BitPackPattern::ShiftOrPack, &[8, 8, 8, 8], PACK_LINE)];
        let format = FormatCombiner
            .combine(&function(&body), &swaps, &packs)
            .expect("two readings compose a format");
        assert_eq!(
            format.fields,
            vec![
                FormatField {
                    width: 8,
                    endianness: None
                },
                FormatField {
                    width: 8,
                    endianness: None
                },
                FormatField {
                    width: 8,
                    endianness: None
                },
                FormatField {
                    width: 8,
                    endianness: None
                },
                FormatField {
                    width: 32,
                    endianness: Some(WireEndianness::BigEndian)
                },
            ]
        );
    }

    #[test]
    fn an_unpack_chain_lands_at_its_first_extraction_line() {
        // An unpack chain's evidence joins its extraction lines, so the
        // chain is placed at its first line: before a swap call that
        // follows it in the body.
        let body = "\
  iVar2 = (uVar1 >> 0x18) & 0xff;
  iVar3 = (uVar1 >> 0x10) & 0xff;
  uVar4 = ntohl(local_20);
";
        let swaps = vec![swap("ntohl", 32, "uVar4 = ntohl(local_20);")];
        let packs = vec![pack(
            BitPackPattern::ShiftMaskUnpack,
            &[8, 8],
            "iVar2 = (uVar1 >> 0x18) & 0xff; iVar3 = (uVar1 >> 0x10) & 0xff;",
        )];
        let format = FormatCombiner
            .combine(&function(body), &swaps, &packs)
            .expect("two readings compose a format");
        assert_eq!(format.fields.len(), 3);
        assert_eq!(format.fields[0].endianness, None);
        assert_eq!(format.fields[1].endianness, None);
        assert_eq!(format.fields[2].endianness, Some(WireEndianness::BigEndian));
    }

    #[test]
    fn swapped_fields_carry_their_wire_endianness() {
        // The network-order family names big-endian wire order. A
        // direction-neutral builtin, or a program's own swap spelling,
        // says only that the bytes are reversed.
        let body = "\
  uVar1 = ntohl(local_18);
  uVar2 = htons(local_20);
  uVar3 = __builtin_bswap32(local_24);
  uVar4 = SwapBytes(local_28);
";
        let swaps = vec![
            swap("ntohl", 32, "uVar1 = ntohl(local_18);"),
            swap("htons", 16, "uVar2 = htons(local_20);"),
            swap(
                "__builtin_bswap32",
                32,
                "uVar3 = __builtin_bswap32(local_24);",
            ),
            swap("SwapBytes", 32, "uVar4 = SwapBytes(local_28);"),
        ];
        let format = FormatCombiner
            .combine(&function(body), &swaps, &[])
            .expect("four readings compose a format");
        let endianness: Vec<Option<WireEndianness>> =
            format.fields.iter().map(|f| f.endianness).collect();
        assert_eq!(
            endianness,
            vec![
                Some(WireEndianness::BigEndian),
                Some(WireEndianness::BigEndian),
                Some(WireEndianness::ReversalOnly),
                Some(WireEndianness::ReversalOnly),
            ]
        );
    }

    #[test]
    fn a_pack_chain_contributes_bitfield_width_entries() {
        // The widths a pack chain carves join the layout as packed
        // fields: widths with no endianness, because the chain moves
        // bits inside one word, not bytes over a wire.
        let body = format!("  uVar1 = ntohl(local_18);\n  {PACK_LINE}\n");
        let swaps = vec![swap("ntohl", 32, "uVar1 = ntohl(local_18);")];
        let packs = vec![pack(BitPackPattern::ShiftOrPack, &[8, 8, 8, 8], PACK_LINE)];
        let format = FormatCombiner
            .combine(&function(&body), &swaps, &packs)
            .expect("two readings compose a format");
        assert_eq!(format.fields.len(), 5);
        assert_eq!(
            format.fields[0],
            FormatField {
                width: 32,
                endianness: Some(WireEndianness::BigEndian)
            }
        );
        for field in &format.fields[1..] {
            assert_eq!(field.width, 8);
            assert_eq!(field.endianness, None);
        }
    }

    #[test]
    fn direction_is_named_only_when_the_swap_name_families_agree() {
        // Network-to-host names only: a reader layout.
        let read_body = "\
  uVar1 = ntohl(local_18);
  sVar2 = ntohs(local_20);
";
        let reads = vec![
            swap("ntohl", 32, "uVar1 = ntohl(local_18);"),
            swap("ntohs", 16, "sVar2 = ntohs(local_20);"),
        ];
        assert_eq!(
            FormatCombiner
                .combine(&function(read_body), &reads, &[])
                .expect("reader layout")
                .direction,
            Some(FormatDirection::Reader)
        );

        // Host-to-network names only: a writer layout.
        let write_body = "\
  local_14 = htons(0x1234);
  local_18 = htonl(uVar1);
";
        let writes = vec![
            swap("htons", 16, "local_14 = htons(0x1234);"),
            swap("htonl", 32, "local_18 = htonl(uVar1);"),
        ];
        assert_eq!(
            FormatCombiner
                .combine(&function(write_body), &writes, &[])
                .expect("writer layout")
                .direction,
            Some(FormatDirection::Writer)
        );

        // Reads mixed with writes: the families disagree, so the
        // direction stays absent.
        let mixed_body = "\
  uVar1 = ntohl(local_18);
  local_14 = htons(0x1234);
";
        let mixed = vec![
            swap("ntohl", 32, "uVar1 = ntohl(local_18);"),
            swap("htons", 16, "local_14 = htons(0x1234);"),
        ];
        assert_eq!(
            FormatCombiner
                .combine(&function(mixed_body), &mixed, &[])
                .expect("mixed layout")
                .direction,
            None
        );

        // Only direction-neutral names: no direction can be claimed.
        let builtin_body = "\
  uVar1 = __builtin_bswap32(local_18);
  uVar2 = (uVar3 << 0x18) | ((uint)uVar4 << 0x10) | (uVar5 << 8) | (uint)uVar6;
";
        let builtins = vec![swap(
            "__builtin_bswap32",
            32,
            "uVar1 = __builtin_bswap32(local_18);",
        )];
        let packs = vec![pack(BitPackPattern::ShiftOrPack, &[8, 8, 8, 8], PACK_LINE)];
        assert_eq!(
            FormatCombiner
                .combine(&function(builtin_body), &builtins, &packs)
                .expect("builtin layout")
                .direction,
            None
        );

        // Reads plus a direction-neutral name. The neutral name neither
        // corroborates nor contradicts, so the one directional family
        // still names the direction.
        let read_builtin_body = "\
  uVar1 = ntohl(local_18);
  uVar2 = __builtin_bswap32(local_20);
";
        let reads_and_builtins = vec![
            swap("ntohl", 32, "uVar1 = ntohl(local_18);"),
            swap(
                "__builtin_bswap32",
                32,
                "uVar2 = __builtin_bswap32(local_20);",
            ),
        ];
        assert_eq!(
            FormatCombiner
                .combine(&function(read_builtin_body), &reads_and_builtins, &[])
                .expect("read-plus-builtin layout")
                .direction,
            Some(FormatDirection::Reader)
        );
    }

    #[test]
    fn the_evidence_carries_the_sequence_s_body_lines() {
        // Each contributing reading's own evidence line appears in the
        // layout's evidence, in body order.
        let body = format!("  {PACK_LINE}\n  uVar1 = ntohl(local_18);\n");
        let swaps = vec![swap("ntohl", 32, "uVar1 = ntohl(local_18);")];
        let packs = vec![pack(BitPackPattern::ShiftOrPack, &[8, 8, 8, 8], PACK_LINE)];
        let format = FormatCombiner
            .combine(&function(&body), &swaps, &packs)
            .expect("two readings compose a format");
        assert_eq!(
            format.evidence,
            format!("{PACK_LINE} uVar1 = ntohl(local_18);")
        );
    }

    #[test]
    fn the_suggestion_sketches_a_typed_reader() {
        // A reader layout sketches sized big-endian reads, with the
        // packed run grouped. A writer layout spells writes. A layout
        // with no direction spells a field sequence, and a
        // reversed-only field is spelled as the byte reversal it is.
        let body = format!("  uVar1 = ntohl(local_18);\n  {PACK_LINE}\n");
        let swaps = vec![swap("ntohl", 32, "uVar1 = ntohl(local_18);")];
        let packs = vec![pack(BitPackPattern::ShiftOrPack, &[8, 8, 8, 8], PACK_LINE)];
        let reader = FormatCombiner
            .combine(&function(&body), &swaps, &packs)
            .expect("reader layout");
        assert_eq!(
            reader.suggestion,
            "byteorder reader: read_u32 then 8+8+8+8 bitfields"
        );

        let write_body = "\
  local_14 = htons(0x1234);
  local_18 = htonl(uVar1);
";
        let writes = vec![
            swap("htons", 16, "local_14 = htons(0x1234);"),
            swap("htonl", 32, "local_18 = htonl(uVar1);"),
        ];
        let writer = FormatCombiner
            .combine(&function(write_body), &writes, &[])
            .expect("writer layout");
        assert_eq!(
            writer.suggestion,
            "byteorder writer: write_u16 then write_u32"
        );

        let neutral_body = "\
  uVar1 = __builtin_bswap32(local_18);
  uVar2 = (uVar3 << 0x18) | ((uint)uVar4 << 0x10) | (uVar5 << 8) | (uint)uVar6;
";
        let neutral_swap = vec![swap(
            "__builtin_bswap32",
            32,
            "uVar1 = __builtin_bswap32(local_18);",
        )];
        let neutral = FormatCombiner
            .combine(&function(neutral_body), &neutral_swap, &packs)
            .expect("directionless layout");
        assert_eq!(
            neutral.suggestion,
            "byteorder field sequence: u32.swap_bytes() then 8+8+8+8 bitfields"
        );
    }
}
