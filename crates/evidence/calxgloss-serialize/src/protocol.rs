//! Protocol message identification.
//!
//! This module provides [`ProtocolMessageCombiner`], the per-function
//! combination pass that names the protocol message handlers the scan
//! can corroborate: when one function carries a comparison against a
//! protocol-table magic **and** at least one independent reading that
//! fits a message handler — a network-order byte swap or a cross-field
//! validation — the combiner promotes the pair to a single
//! [`ProtocolMessage`] finding naming the protocol and listing its
//! corroborating readings.
//!
//! The combiner reads no body of its own: it consumes exactly the
//! findings the single-pass scan already collected for the function,
//! so the deepening costs no extra Ghidra round trips. It consults the
//! configured signature table only to tell protocol entries apart from
//! file-format ones — a protocol magic that is not in the configured
//! table's protocol section claims nothing.
//!
//! The honesty gates are the point. A protocol magic on its own stays
//! a plain magic finding — a bare signature check never overclaims a
//! whole protocol. A file-format magic combined with swaps stays a
//! magic finding too — a PNG decoder is never mislabeled as a network
//! protocol handler. And a direction-neutral swap (`__builtin_bswap32`
//! and friends) corroborates nothing: only the network-order family
//! (`ntohl`/`ntohs`/`htons`/`htonl`) says the bytes arrive off a wire.
//! One function yields at most one protocol message finding, however
//! many protocol magics its body compares against.

use crate::format::{is_network_read, is_network_write};
use crate::magic_bytes::MagicSignature;
use crate::types::{ByteSwapOperation, CrossFieldValidation, MagicFormat, ProtocolMessage};

// ============================================================
// Combiner
// ============================================================

/// Promotes one function's corroborated protocol sniff to one
/// protocol message finding.
///
/// The combiner owns no configuration — the signature table it reads
/// is the scan's, and the honesty rules are fixed — so it carries no
/// state and serves the whole scan. [`identify`](Self::identify) is
/// handed the magic, swap, and validation records the scan just made
/// for one function (and the configured signature table, for the
/// protocol flag alone) and answers with the identified
/// [`ProtocolMessage`], or `None` when the function carries no
/// protocol magic or no corroborating reading.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProtocolMessageCombiner;

impl ProtocolMessageCombiner {
    /// A combiner with the standard honesty rules.
    pub fn new() -> Self {
        ProtocolMessageCombiner
    }

    /// The protocol message handler one function's findings add up
    /// to.
    ///
    /// The first magic record whose value matches a
    /// [`protocol`](MagicSignature::protocol)-flagged entry of
    /// `signatures` names the protocol; the corroborating readings are
    /// the function's network-order swaps and cross-field validations,
    /// each listed in the order the scan collected them. With no
    /// protocol magic, or with a protocol magic nothing corroborates,
    /// the function claims nothing and answers `None` — the sniff
    /// stays the plain magic finding the scan already made.
    pub fn identify(
        &self,
        signatures: &[MagicSignature],
        magic: &[MagicFormat],
        swaps: &[ByteSwapOperation],
        validations: &[CrossFieldValidation],
    ) -> Option<ProtocolMessage> {
        // A protocol magic only counts when the configured table
        // flags it as one: a custom table's entry is a file format
        // unless it was built through the protocol constructor, and a
        // value outside the table is just a number.
        let hit = magic.iter().find(|record| {
            signatures
                .iter()
                .any(|signature| signature.protocol && signature.magic == record.magic)
        })?;

        // The hit must be spelled in hex on its evidence line. A
        // protocol magic is also an ordinary number — IPv4's 0x800 is
        // 2048, a plausible buffer size — and a decimal comparison to
        // it is constant territory, not a wire sniff: the same honesty
        // line the validation detector draws at its own
        // literal-vs-variable comparisons. Only the hex spelling marks
        // a handler reading a wire value.
        if !hit.evidence.contains(&format!("{:#x}", hit.magic)) {
            return None;
        }

        // The corroborators are the readings a message handler makes
        // beside its sniff: network-order swaps move wire bytes, and
        // cross-field validations check the message's integrity. A
        // direction-neutral swap reverses bytes for any reason and
        // claims no wire, so it never corroborates.
        let mut corroborations: Vec<String> = Vec::new();
        let mut evidence_lines: Vec<&str> = vec![hit.evidence.as_str()];
        for swap in swaps {
            if is_network_read(&swap.operation) || is_network_write(&swap.operation) {
                corroborations.push(format!("{} swap", swap.operation));
                evidence_lines.push(&swap.evidence);
            }
        }
        for validation in validations {
            corroborations.push(format!("{} validation", validation.shape));
            evidence_lines.push(&validation.evidence);
        }
        if corroborations.is_empty() {
            // A protocol magic alone is a sniff, not a handler: the
            // promotion needs at least one independent reading beside
            // it, and until then the magic finding says all there is.
            return None;
        }

        Some(ProtocolMessage {
            function: hit.function.clone(),
            magic: hit.magic,
            protocol: hit.format.clone(),
            corroborations,
            suggestion: format!(
                "protocol-aware {} message decode (byteorder BE reads)",
                hit.format
            ),
            confidence: PROTOCOL_CONFIDENCE.into(),
            evidence: evidence_lines.join(" "),
        })
    }
}

// ============================================================
// The reading
// ============================================================

/// Confidence of an identified protocol message handler: the sniff is
/// corroborated by at least one independent reading, so it ranks above
/// the lone-magic floor (80) — a signature check plus a network-order
/// swap or an integrity check is stronger evidence than either
/// signal alone.
const PROTOCOL_CONFIDENCE: u8 = 85;

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ValidationShape;

    /// The hand-built table: one file-format entry and one protocol
    /// entry, mirroring the default table's two sections.
    fn signatures() -> Vec<MagicSignature> {
        vec![
            MagicSignature::new("PNG", 0x8950_4E47, "png::Decoder"),
            MagicSignature::protocol("IPv6", 0x86DD, "ipv6 header decode via byteorder BE reads"),
        ]
    }

    fn magic(magic: u64, format: &str) -> MagicFormat {
        MagicFormat {
            function: "FUN_18003ab00".into(),
            magic,
            format: format.into(),
            suggestion: format!("{format}::Decoder"),
            confidence: 80.into(),
            evidence: format!("if (uVar1 == {magic:#x}) {{"),
        }
    }

    fn swap(operation: &str) -> ByteSwapOperation {
        ByteSwapOperation {
            function: "FUN_18003ab00".into(),
            operation: operation.into(),
            width: 32,
            suggestion: "byteorder::BE::read_u32".into(),
            confidence: 70.into(),
            evidence: format!("uVar2 = {operation}(local_18);"),
        }
    }

    fn validation(shape: ValidationShape) -> CrossFieldValidation {
        CrossFieldValidation {
            function: "FUN_18003ab00".into(),
            field: "uVar7".into(),
            computed: "uVar5 + uVar6".into(),
            shape,
            suggestion: "checked parse or validate step on the Rust type".into(),
            confidence: 65.into(),
            evidence: "if (uVar7 == uVar5 + uVar6) {".into(),
        }
    }

    fn identify(
        signatures: &[MagicSignature],
        magic: &[MagicFormat],
        swaps: &[ByteSwapOperation],
        validations: &[CrossFieldValidation],
    ) -> Option<ProtocolMessage> {
        ProtocolMessageCombiner::new().identify(signatures, magic, swaps, validations)
    }

    #[test]
    fn a_protocol_magic_and_a_network_swap_promote() {
        let record = identify(
            &signatures(),
            &[magic(0x86DD, "IPv6")],
            &[swap("ntohl")],
            &[],
        )
        .expect("a protocol magic plus a network-order swap is a handler");
        assert_eq!(record.function, "FUN_18003ab00");
        assert_eq!(record.protocol, "IPv6");
        assert_eq!(record.magic, 0x86DD);
        assert_eq!(record.corroborations, vec!["ntohl swap"]);
        assert_eq!(record.confidence.value(), PROTOCOL_CONFIDENCE);
    }

    #[test]
    fn a_protocol_magic_and_a_cross_field_validation_promote() {
        let record = identify(
            &signatures(),
            &[magic(0x86DD, "IPv6")],
            &[],
            &[validation(ValidationShape::Checksum)],
        )
        .expect("a protocol magic plus a validation is a handler");
        assert_eq!(record.corroborations, vec!["checksum validation"]);
    }

    #[test]
    fn a_protocol_magic_alone_claims_nothing() {
        // The bare sniff stays the plain magic finding the scan
        // already made; nothing promotes on one signal.
        assert!(
            identify(&signatures(), &[magic(0x86DD, "IPv6")], &[], &[]).is_none(),
            "a protocol magic alone never names a handler"
        );
    }

    #[test]
    fn a_file_format_magic_with_swaps_claims_nothing() {
        // A PNG decoder is never mislabeled: the file-format section
        // of the table never feeds the promotion, however many swaps
        // the function carries.
        assert!(
            identify(
                &signatures(),
                &[magic(0x8950_4E47, "PNG")],
                &[swap("ntohl"), swap("htons")],
                &[validation(ValidationShape::Length)],
            )
            .is_none(),
            "a file-format magic stays a magic finding"
        );
    }

    #[test]
    fn a_direction_neutral_swap_corroborates_nothing() {
        // `__builtin_bswap32` reverses bytes for any reason — a
        // codec, a hash — and claims no wire, so it never stands as
        // the corroborating reading beside a protocol sniff.
        assert!(
            identify(
                &signatures(),
                &[magic(0x86DD, "IPv6")],
                &[swap("__builtin_bswap32")],
                &[],
            )
            .is_none(),
            "only the network-order family corroborates a swap"
        );
    }

    #[test]
    fn a_magic_outside_the_table_corroborates_nothing() {
        // A hand-built finding set naming a value the configured
        // table's protocol section does not carry claims no protocol,
        // even beside a network-order swap.
        assert!(
            identify(
                &signatures(),
                &[magic(0x1234, "SOMETHING")],
                &[swap("ntohl")],
                &[],
            )
            .is_none(),
            "the promotion reads the configured table, not the record's label"
        );
    }

    #[test]
    fn a_decimal_spelled_hit_never_promotes() {
        // A protocol magic is also an ordinary number: IPv4's 0x800 is
        // 2048, a plausible buffer size. A comparison spelled in
        // decimal is constant territory, not a wire sniff, however
        // many network-order swaps the function carries beside it.
        let sniff = MagicFormat {
            evidence: "if (local_18 == 2048) {".into(),
            ..magic(0x0800, "IPv4")
        };
        assert!(
            identify(
                &[MagicSignature::protocol(
                    "IPv4",
                    0x0800,
                    "ipv4 header decode"
                )],
                &[sniff],
                &[swap("ntohl")],
                &[],
            )
            .is_none(),
            "a decimal spelling of the same value is not a protocol sniff"
        );
    }

    #[test]
    fn one_function_yields_exactly_one_finding_naming_the_first_protocol() {
        // Two protocol magics and two swaps in one function still
        // compose one handler claim, naming the first magic in scan
        // order.
        let record = identify(
            &[
                MagicSignature::protocol("IPv4", 0x0800, "ipv4 header decode"),
                MagicSignature::protocol("IPv6", 0x86DD, "ipv6 header decode"),
            ],
            &[magic(0x0800, "IPv4"), magic(0x86DD, "IPv6")],
            &[swap("ntohl"), swap("htons")],
            &[],
        )
        .expect("two protocol magics still make one handler");
        assert_eq!(record.protocol, "IPv4");
        assert_eq!(record.corroborations, vec!["ntohl swap", "htons swap"]);
    }

    #[test]
    fn both_corroborating_kinds_are_listed() {
        let record = identify(
            &signatures(),
            &[magic(0x86DD, "IPv6")],
            &[swap("ntohl")],
            &[validation(ValidationShape::Checksum)],
        )
        .expect("a swap and a validation corroborate");
        assert_eq!(
            record.corroborations,
            vec!["ntohl swap", "checksum validation"]
        );
    }

    #[test]
    fn the_suggestion_names_the_protocol_and_a_decoding_pattern() {
        let record = identify(
            &signatures(),
            &[magic(0x86DD, "IPv6")],
            &[swap("ntohl")],
            &[],
        )
        .expect("a corroborated sniff names a handler");
        assert_eq!(
            record.suggestion,
            "protocol-aware IPv6 message decode (byteorder BE reads)"
        );
    }

    #[test]
    fn the_evidence_carries_the_magic_line_and_the_corroborating_lines() {
        // The identification is auditable: every contributing
        // finding's own evidence line rides the record.
        let record = identify(
            &signatures(),
            &[magic(0x86DD, "IPv6")],
            &[swap("ntohl")],
            &[validation(ValidationShape::Checksum)],
        )
        .expect("a corroborated sniff names a handler");
        assert_eq!(
            record.evidence,
            "if (uVar1 == 0x86dd) { uVar2 = ntohl(local_18); if (uVar7 == uVar5 + uVar6) {"
        );
    }
}
