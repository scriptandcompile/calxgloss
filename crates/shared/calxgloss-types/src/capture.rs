//! The captured call entry — what a mining lane records about one call
//! that really arrived at one export entry (glossary: *captured call
//! entry*).
//!
//! Every capture lane — the baseline-run hook, the reference-app run, the
//! minidump reader — hands the same record to the record-and-replay fold.
//! The record alone is never authority: it proves a real caller passed
//! these values; only the replay against the original binary observes what
//! the binary does with them.

use serde::{Deserialize, Serialize};

use crate::identity::BinaryIdentity;

/// The instrumented run shape a captured call entry rode in on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureLane {
    /// Recorded at an export-entry trampoline armed during a baseline run.
    BaselineHook,
    /// Recorded by a recording proxy while the operator's reference
    /// application called into it.
    ReferenceApp,
    /// Reconstructed from one faulting thread of a Windows minidump.
    Minidump,
}

/// Where to trace a capture back to: the run and event position that
/// recorded it, or the exact crash it was reconstructed from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureEvidence {
    /// From an instrumented run: the capture's id and the event's position
    /// within it.
    RunEvent {
        capture_id: String,
        event_sequence: u64,
    },
    /// From a minidump: the dump's content digest and the faulting
    /// thread's id.
    DumpThread { dump_digest: String, thread_id: u32 },
}

/// The harness's encode tag for a scalar the FFI boundary can marshal —
/// spelled exactly as the Wine harness's own wire tag spells it (the
/// `ScalarKind::tag` vocabulary of `calxgloss-testgen`), minus the floats.
///
/// `f32`/`f64` sit outside the capture vocabulary on purpose: a captured
/// float argument is refused-with-reason at the fold, never re-encoded
/// into some other shape that would mis-arrive at replay.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScalarTag {
    /// Signed 8-bit integer.
    I8,
    /// Signed 16-bit integer.
    I16,
    /// Signed 32-bit integer.
    I32,
    /// Signed 64-bit integer.
    I64,
    /// Unsigned 8-bit integer.
    U8,
    /// Unsigned 16-bit integer.
    U16,
    /// Unsigned 32-bit integer.
    U32,
    /// Unsigned 64-bit integer.
    U64,
}

/// The capture bound: the protocol constant that caps how many bytes one
/// argument's target may have captured (issue #397 — "no huge buffer
/// balloons a capture"). The same constant is honored at record time,
/// where [ArgumentDescriptor::captured_pointer] sizes the capture, and at
/// replay time, where the record-and-replay fold refuses a descriptor that
/// claims more than the bound could ever have captured. A capture over
/// the bound always states the truncation on the descriptor — a truncated
/// buffer never silently becomes a full one at replay.
pub const POINTER_CAPTURE_BOUND: u64 = 64 * 1024;

/// One argument as it arrived at the export entry, in arrival order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArgumentDescriptor {
    /// A scalar integer value, carried with its harness encode tag so the
    /// fold can marshal it across the FFI boundary unchanged.
    Scalar {
        tag: ScalarTag,
        /// An integer number under that tag's width; never a float — a
        /// float argument cannot enter this vocabulary at all
        /// ([`ScalarTag`] carries no float).
        value: serde_json::Value,
    },
    /// A pointer-like argument whose target was read out of the captured
    /// process: the bytes actually captured, the size the target was
    /// observed to have, and whether the capture ran out before that size.
    /// Replay materializes a fresh buffer from the captured bytes; a
    /// truncated capture the replay cannot use refuses the case with
    /// reason — a truncated buffer never silently becomes a full one.
    Pointer {
        bytes: Vec<u8>,
        captured_size: u64,
        truncated: bool,
    },
}

impl ArgumentDescriptor {
    /// Size a pointer capture at record time under the *capture bound*
    /// ([`POINTER_CAPTURE_BOUND`]): the recorded bytes never exceed the
    /// bound, the descriptor states the size the target was observed to
    /// have, and truncation is stamped whenever the capture did not deliver
    /// everything the bound allowed — never left for replay to guess at.
    /// This is the one capture-sizing rule every lane (export-entry hook,
    /// recording proxy, minidump reader) shares.
    pub fn captured_pointer(observed_size: u64, read: &[u8]) -> Self {
        // The descriptor never keeps more than the observation itself: bytes
        // past the observed size were never part of the argument.
        let observed = usize::try_from(observed_size).unwrap_or(usize::MAX);
        let kept = &read[..read.len().min(observed).min(POINTER_CAPTURE_BOUND as usize)];
        ArgumentDescriptor::Pointer {
            bytes: kept.to_vec(),
            captured_size: observed_size,
            truncated: (kept.len() as u64) < observed_size,
        }
    }
}

/// One call as it really arrived at one export entry: which target binary's
/// export, through which lane and backed by which evidence the call was
/// recorded, and the argument vector in order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapturedCallEntry {
    /// The binary whose export entry received the call — identity verbatim,
    /// as everywhere else in the harness.
    pub binary: BinaryIdentity,
    /// The export name as the binary exports it.
    pub export: String,
    /// Which instrumented run shape recorded it.
    pub lane: CaptureLane,
    /// The run event or crash the reviewer can trace this entry back to.
    pub evidence: CaptureEvidence,
    /// The argument vector in declaration order — the order it arrived.
    pub arguments: Vec<ArgumentDescriptor>,
}

/// One instrumented run's captured call entries, as the record-and-replay
/// fold receives them (glossary: *capture event log*).
///
/// The entry array is the first-seen capture order: the fold files mined
/// cases in exactly this order, so the same log always produces the same
/// filed suite. A run that stopped at its event budget states what it left
/// out through `events_dropped` — a truncation is never silent, and the
/// fold refuses what never arrived with the reason `truncated-capture`
/// rather than guessing the log was complete.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaptureEventLog {
    /// The capture's id — the run event every `run_event` evidence in this
    /// log names this id beside its event sequence.
    pub capture_id: String,
    /// The captured call entries, in first-seen capture order.
    pub entries: Vec<CapturedCallEntry>,
    /// Events the instrumented run recorded past its budget and never
    /// wrote into this log. Absent means the budget never fired: this log
    /// is what the run saw, whole.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub events_dropped: Option<u64>,
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use crate::{
        ArgumentDescriptor, CaptureEventLog, CaptureEvidence, CaptureLane, CapturedCallEntry,
        ScalarTag,
    };

    /// The capture bound caps a pointer capture at record time: bytes over
    /// the bound are left out of the record, the observed size is stated in
    /// full, and the truncation rides the descriptor — the record never
    /// pretends a huge buffer arrived whole.
    #[test]
    fn the_capture_bound_caps_a_pointer_capture_at_record_time() {
        use crate::POINTER_CAPTURE_BOUND;
        let bound = POINTER_CAPTURE_BOUND;

        // A read over the bound: the record keeps exactly the bound's
        // worth of bytes and says the rest never arrived.
        let huge = vec![0xABu8; POINTER_CAPTURE_BOUND as usize + 4096];
        let over = ArgumentDescriptor::captured_pointer(huge.len() as u64, &huge);
        match over {
            ArgumentDescriptor::Pointer {
                bytes,
                captured_size,
                truncated,
            } => {
                assert_eq!(
                    bytes.len(),
                    POINTER_CAPTURE_BOUND as usize,
                    "the bound caps the recorded bytes"
                );
                assert_eq!(
                    captured_size,
                    huge.len() as u64,
                    "the observed size is stated in full, bound or no bound"
                );
                assert!(truncated, "what the bound left out is stated, never silent");
            }
            other => panic!("a pointer capture stays a pointer descriptor: {other:?}"),
        }

        // A lane that hands over only the bound's worth of bytes against
        // an over-bound target still names the truncation: the record
        // never implies the buffer arrived whole.
        let capped_read =
            ArgumentDescriptor::captured_pointer(huge.len() as u64, &huge[..bound as usize]);
        assert!(
            matches!(
                capped_read,
                ArgumentDescriptor::Pointer {
                    truncated: true,
                    ..
                }
            ),
            "an over-bound target read to the bound is still truncated"
        );

        // A read under the bound, whole: nothing was left out, so nothing
        // is truncated — the replay may reconstruct the buffer in full.
        let whole = ArgumentDescriptor::captured_pointer(5, b"Hello");
        match whole {
            ArgumentDescriptor::Pointer {
                bytes,
                captured_size,
                truncated,
            } => {
                assert_eq!(bytes, b"Hello");
                assert_eq!(captured_size, 5);
                assert!(
                    !truncated,
                    "a whole capture under the bound is honest as full"
                );
            }
            other => panic!("a pointer capture stays a pointer descriptor: {other:?}"),
        }

        // A read longer than the observation keeps only what the argument
        // really was: the record never holds bytes past the observed size,
        // and the size it does hold arrived whole.
        let overshoot = ArgumentDescriptor::captured_pointer(3, b"Hello");
        match overshoot {
            ArgumentDescriptor::Pointer {
                bytes,
                captured_size,
                truncated,
            } => {
                assert_eq!(bytes, b"Hel", "no bytes past the observed size");
                assert_eq!(captured_size, 3);
                assert!(
                    !truncated,
                    "the observed part arrived whole, so nothing was left out"
                );
            }
            other => panic!("a pointer capture stays a pointer descriptor: {other:?}"),
        }
    }

    /// A captured call entry round-trips through JSON with the export,
    /// lane, capture evidence, and the ordered argument vector all intact:
    /// scalars carrying the harness's encode tags, pointer-like arguments
    /// carrying captured bytes, captured size, and the truncation flag.
    #[test]
    fn a_captured_call_entry_round_trips_with_its_ordered_arguments() {
        let wire = r#"{"binary":"game_logic.dll","export":"DrawSprite","lane":"baseline_hook","evidence":{"run_event":{"capture_id":"cap-2026-11-02-a","event_sequence":7}},"arguments":[{"scalar":{"tag":"i32","value":42}},{"scalar":{"tag":"u64","value":18446744073709551615}},{"pointer":{"bytes":[72,101,108,108,111],"captured_size":512,"truncated":true}}]}"#;
        let entry: CapturedCallEntry =
            serde_json::from_str(wire).expect("the record shape parses from its wire form");
        assert_eq!(entry.binary, "game_logic.dll");
        assert_eq!(entry.export, "DrawSprite");
        assert_eq!(entry.lane, CaptureLane::BaselineHook);
        assert_eq!(
            entry.evidence,
            CaptureEvidence::RunEvent {
                capture_id: "cap-2026-11-02-a".to_string(),
                event_sequence: 7,
            }
        );
        assert_eq!(
            entry.arguments,
            vec![
                ArgumentDescriptor::Scalar {
                    tag: ScalarTag::I32,
                    value: serde_json::json!(42),
                },
                ArgumentDescriptor::Scalar {
                    tag: ScalarTag::U64,
                    value: serde_json::json!(18446744073709551615u64),
                },
                ArgumentDescriptor::Pointer {
                    bytes: vec![72, 101, 108, 108, 111],
                    captured_size: 512,
                    truncated: true,
                },
            ],
            "the argument order is the arrival order — preserved through the round-trip"
        );
        assert_eq!(
            serde_json::to_string(&entry).unwrap(),
            wire,
            "the record re-saves byte-for-byte"
        );
    }

    /// The minidump lane names its crash: dump digest plus faulting thread.
    #[test]
    fn the_minidump_lane_carries_the_dump_digest_and_faulting_thread() {
        let entry = CapturedCallEntry {
            binary: "eqgame.exe".into(),
            export: "HandlePacket".to_string(),
            lane: CaptureLane::Minidump,
            evidence: CaptureEvidence::DumpThread {
                dump_digest: "sha256:2f2a9c".to_string(),
                thread_id: 3812,
            },
            arguments: vec![ArgumentDescriptor::Pointer {
                bytes: vec![0u8; 8],
                captured_size: 8,
                truncated: false,
            }],
        };
        let back: CapturedCallEntry =
            serde_json::from_str(&serde_json::to_string(&entry).unwrap()).expect("parses back");
        assert_eq!(
            back, entry,
            "the crash evidence rides the round-trip intact"
        );
    }

    /// Float arguments sit outside the capture vocabulary: the closed tag
    /// set never accepts an `f32`/`f64` tag, so a captured float never
    /// enters as a mis-encoded other shape — the value carried under a tag
    /// is validated by the later fold, where a refused float names its
    /// reason.
    #[test]
    fn a_float_argument_tag_never_enters_the_capture_vocabulary() {
        let float_scalar = r#"{"scalar":{"tag":"f32","value":1.5}}"#;
        assert!(
            serde_json::from_str::<ArgumentDescriptor>(float_scalar).is_err(),
            "the tag vocabulary has no float — the descriptor cannot carry one"
        );
        let double_scalar = r#"{"scalar":{"tag":"f64","value":1.5}}"#;
        assert!(
            serde_json::from_str::<ArgumentDescriptor>(double_scalar).is_err(),
            "nor a double"
        );
    }

    /// A capture event log round-trips with its entries in first-seen
    /// order and its dropped-events budget stated: an event budget that
    /// fired never leaves the omission to be guessed at, and a log that
    /// saw everything whole never writes the field at all.
    #[test]
    fn a_capture_event_log_round_trips_with_its_budget_stated() {
        let entry = |seq: u64| CapturedCallEntry {
            binary: "game_logic.dll".to_string().into(),
            export: "DrawSprite".to_string(),
            lane: CaptureLane::BaselineHook,
            evidence: CaptureEvidence::RunEvent {
                capture_id: "cap-a".to_string(),
                event_sequence: seq,
            },
            arguments: vec![ArgumentDescriptor::Scalar {
                tag: ScalarTag::I32,
                value: serde_json::json!(seq as i64),
            }],
        };
        let truncated = CaptureEventLog {
            capture_id: "cap-a".to_string(),
            entries: vec![entry(1), entry(2)],
            events_dropped: Some(118),
        };
        let wire = r#"{"capture_id":"cap-a","entries":[{"binary":"game_logic.dll","export":"DrawSprite","lane":"baseline_hook","evidence":{"run_event":{"capture_id":"cap-a","event_sequence":1}},"arguments":[{"scalar":{"tag":"i32","value":1}}]},{"binary":"game_logic.dll","export":"DrawSprite","lane":"baseline_hook","evidence":{"run_event":{"capture_id":"cap-a","event_sequence":2}},"arguments":[{"scalar":{"tag":"i32","value":2}}]}],"events_dropped":118}"#;
        let parsed: CaptureEventLog =
            serde_json::from_str(wire).expect("the log shape parses from its wire form");
        assert_eq!(parsed, truncated, "the budget lands beside the entries");
        assert_eq!(
            serde_json::to_string(&truncated).unwrap(),
            wire,
            "the log re-saves byte-for-byte, entries in first-seen order"
        );

        let whole = CaptureEventLog {
            capture_id: "cap-b".to_string(),
            entries: Vec::new(),
            events_dropped: None,
        };
        let whole_wire = serde_json::to_string(&whole).unwrap();
        assert!(
            !whole_wire.contains("events_dropped"),
            "an unbudgeted log states no omission: {whole_wire}"
        );
        let back: CaptureEventLog = serde_json::from_str(&whole_wire).expect("parses back");
        assert_eq!(back.events_dropped, None, "and reads back as none");
    }
}
