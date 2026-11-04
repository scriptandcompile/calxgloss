//! Types for test case generation and baseline execution.
//!
//! This module holds the records for test inputs, expected outputs, observed
//! side effects, and the results captured from running the original binary.

use serde::{Deserialize, Serialize};

/// The kind of side effect a function may produce.
///
/// The baseline test run observes side effects and records them, so
/// verification can check that the Rust translation behaves the same way.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SideEffectKind {
    /// A file was written or created.
    FileWrite,

    /// A file was read.
    FileRead,

    /// A registry key or value was written.
    RegistryWrite,

    /// A registry key or value was read.
    RegistryRead,

    /// A window's client area was updated (e.g., via `InvalidateRect`).
    WindowUpdate,

    /// A new window was created (`CreateWindowEx`).
    WindowCreate,

    /// A new thread was spawned (`CreateThread`).
    ThreadSpawn,

    /// Data was sent over the network.
    NetworkSend,

    /// Data was received from the network.
    NetworkReceive,

    /// Memory was allocated (`VirtualAlloc`, `HeapAlloc`).
    MemoryAlloc,

    /// Memory was freed (`VirtualFree`, `HeapFree`).
    MemoryFree,

    /// An audio sample was played.
    AudioPlay,

    /// Audio playback was stopped.
    AudioStop,

    /// A program global's value was read.
    ///
    /// The global's name — spelled exactly as the decompiler writes it —
    /// is stored in the [`SideEffect`] detail string. The kind identifies
    /// the effect, and the detail identifies which global. The expectation
    /// comes from the global-state reference sets, not from observing the
    /// original binary: the baseline harness does not capture global
    /// reads.
    GlobalRead,

    /// A program global was stored through.
    ///
    /// The global's name is stored in the [`SideEffect`] detail string,
    /// same as for [`SideEffectKind::GlobalRead`]. Having a typed kind for
    /// global writes means a global side effect never has to be a
    /// free-form [`SideEffectKind::Other`] string: consumers can match on
    /// the kind instead of parsing prose.
    GlobalWrite,

    /// A side effect not covered by the predefined kinds.
    Other(String),
}

/// A single observed side effect during test execution.
///
/// Side effects accompany a test case and its return value, capturing
/// file I/O, window updates, registry changes, and other observable
/// behaviors of the original function.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SideEffect {
    /// The type of side effect.
    pub kind: SideEffectKind,

    /// Human-readable description of the side effect (e.g., `"Wrote 1024 bytes to C:\\config.dat"`).
    pub detail: String,
}

/// A single test case for baseline execution.
///
/// Each test case specifies controlled inputs and the expected return value
/// and side effects observed when the original function is invoked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TestCase {
    /// The test inputs as a JSON value. Parameters are serialized according to
    /// their types (integers, strings, booleans, or null for pointers).
    pub inputs: serde_json::Value,

    /// The expected return value from the original function, as JSON.
    pub expected_return: serde_json::Value,

    /// Expected side effects the function produces when called with these inputs.
    pub expected_side_effects: Vec<SideEffect>,

    /// The ordered API-call trace: the sequence of API calls the original
    /// binary made when the baseline run captured this case, by API name.
    ///
    /// The trace is compared by order, not membership — the same calls in a
    /// different order are a divergence. `#[serde(default)]` keeps baseline
    /// documents saved before this dimension existed readable; an empty
    /// trace means the dimension is *unassessed* for the case, never a
    /// demand that the translation make no calls.
    #[serde(default)]
    pub expected_api_calls: Vec<String>,

    /// How this case came to exist: invented by testgen, or mined from a
    /// real caller's argument vector ([`CaseOrigin`], glossary: *case
    /// origin*).
    ///
    /// `#[serde(default)]` follows the precedent the API-trace field set:
    /// baseline documents saved before this field existed parse unchanged,
    /// with the origin reading [`CaseOrigin::Generated`]. The strongest
    /// claim a case supports is *derived* from this field at read time
    /// ([`CaseOrigin::authority`]), never stored beside it, so no second
    /// field can rot against the first.
    #[serde(default)]
    pub origin: CaseOrigin,
}

/// How a baseline case came to exist.
///
/// The closed vocabulary of case origins (glossary: *case origin*). A
/// generated case's input vector is a signature-derived guess; a mined
/// case's input vector is one a real caller actually passed, and the
/// variant names the capture or crash it was mined from, so any reviewer
/// can trace the case back to its source.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaseOrigin {
    /// Invented by call testgen from the export's signature and type
    /// evidence — the serde default, so documents saved before the field
    /// existed read as generated.
    #[default]
    Generated,
    /// Mined from a hooked export entry: a real call recorded during an
    /// instrumented run, by capture id and the event's position in it.
    MinedHook {
        capture_id: String,
        event_sequence: u64,
    },
    /// Mined from a Windows minidump: the crash's argument vector
    /// reconstructed at an export entry, by dump digest and faulting
    /// thread id.
    MinedMinidump {
        dump_digest: String,
        thread_id: u32,
        /// The address the fault happened at — the case names the
        /// crash it was mined from down to the instruction pointer.
        #[serde(default)]
        fault_address: u64,
    },
}

/// The strongest claim a passing case supports — read off the case origin
/// at read time, never stored on the case and never given a wire form.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaseAuthority {
    /// The case's expectations were observed by replaying its exact input
    /// vector through the controlled harness walk against the original
    /// binary — `controlled-replay` at `observed` confidence in the REA
    /// evidence table ([docs/research/rea/33](https://github.com/scriptandcompile/calxgloss)).
    /// P25's receipts and P26's ledger cite this read directly.
    ControlledReplayAtObserved,
}

impl CaseOrigin {
    /// The authority a case earned, derived at read time from the origin
    /// variant — there is no stored authority field to rot against the
    /// origin. Every case rides the same controlled ground-truth walk: the
    /// replay, not the capture, is what observed the expectations, so every
    /// origin reads as [`CaseAuthority::ControlledReplayAtObserved`] today.
    pub fn authority(&self) -> CaseAuthority {
        match self {
            CaseOrigin::Generated
            | CaseOrigin::MinedHook { .. }
            | CaseOrigin::MinedMinidump { .. } => CaseAuthority::ControlledReplayAtObserved,
        }
    }
}

/// The result of executing a single baseline test case.
///
/// Captures both the actual return value and side effects, along with
/// pass/fail status and an optional error message if the test diverged
/// from expected behavior.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TestResult {
    /// The test case that was executed.
    pub test_case: TestCase,

    /// The actual return value observed from the original function.
    pub actual_return: serde_json::Value,

    /// The actual side effects observed during execution.
    pub actual_side_effects: Vec<SideEffect>,

    /// The ordered API-call trace observed during this case: the sequence
    /// of API calls actually made, by API name, beside the return value.
    ///
    /// `#[serde(default)]` keeps baseline documents saved before this
    /// dimension existed readable; an empty trace means the capture is
    /// *unassessed* for the case, not that no call was made.
    #[serde(default)]
    pub actual_api_calls: Vec<String>,

    /// Whether the test passed (true if actual matches expected).
    pub passed: bool,

    /// Error message describing why the test failed, if any.
    pub error: Option<String>,
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// The AC that keeps every existing workspace flowing: a baseline case
    /// written before the case-origin field existed must parse unchanged,
    /// with the origin reading *generated* — the exact precedent the
    /// API-trace field set. No recapture, no rewrite.
    #[test]
    fn a_baseline_case_saved_before_the_origin_field_reads_as_generated() {
        let old = r#"{"inputs": {"x": 10}, "expected_return": 42, "expected_side_effects": [], "expected_api_calls": []}"#;
        let case: TestCase =
            serde_json::from_str(old).expect("a pre-origin baseline document still parses");
        assert_eq!(case.origin, CaseOrigin::Generated);
        assert_eq!(
            serde_json::to_string(&case).unwrap(),
            r#"{"inputs":{"x":10},"expected_return":42,"expected_side_effects":[],"expected_api_calls":[],"origin":"generated"}"#,
            "a re-saved pre-origin case is stamped generated — the default is explicit on disk"
        );
    }

    /// Mined cases round-trip through the baseline document with their
    /// evidence payload intact: capture id plus event sequence for the hook
    /// lane, dump digest plus faulting thread for the minidump lane.
    #[test]
    fn the_mined_origin_variants_round_trip_with_their_evidence() {
        let hook = TestCase {
            inputs: json!({"x": -5}),
            expected_return: json!(0),
            expected_side_effects: vec![],
            expected_api_calls: vec![],
            origin: CaseOrigin::MinedHook {
                capture_id: "cap-2026-11-02-a".to_string(),
                event_sequence: 12,
            },
        };
        let mined = r#"{"inputs":{"x":-5},"expected_return":0,"expected_side_effects":[],"expected_api_calls":[],"origin":{"mined_hook":{"capture_id":"cap-2026-11-02-a","event_sequence":12}}}"#;
        assert_eq!(serde_json::to_string(&hook).unwrap(), mined);
        let back: TestCase = serde_json::from_str(mined).expect("the mined-hook stamp parses");
        assert_eq!(
            back, hook,
            "the capture evidence rides the round-trip intact"
        );

        let dump = TestCase {
            inputs: json!(null),
            expected_return: json!(1),
            expected_side_effects: vec![],
            expected_api_calls: vec![],
            origin: CaseOrigin::MinedMinidump {
                dump_digest: "sha256:2f2a9c".to_string(),
                thread_id: 3812,
                fault_address: 0x1400_1234,
            },
        };
        let back: TestCase =
            serde_json::from_str(&serde_json::to_string(&dump).unwrap()).expect("parses back");
        assert_eq!(
            back, dump,
            "the dump digest and faulting thread ride intact"
        );
    }

    /// Authority is derived, never stored: the strongest claim reads off
    /// the origin variant at read time, and no serialized case carries an
    /// authority field that could rot against the origin.
    #[test]
    fn the_case_authority_is_read_off_the_origin_and_never_stored() {
        assert_eq!(
            CaseOrigin::Generated.authority(),
            CaseAuthority::ControlledReplayAtObserved
        );
        assert_eq!(
            CaseOrigin::MinedHook {
                capture_id: "cap-1".to_string(),
                event_sequence: 3,
            }
            .authority(),
            CaseAuthority::ControlledReplayAtObserved,
            "the replay — not the capture — observed the expectations"
        );
        assert_eq!(
            CaseOrigin::MinedMinidump {
                dump_digest: "sha256:ab".to_string(),
                thread_id: 7,
                fault_address: 0,
            }
            .authority(),
            CaseAuthority::ControlledReplayAtObserved
        );

        let case = TestCase {
            inputs: json!({}),
            expected_return: json!(0),
            expected_side_effects: vec![],
            expected_api_calls: vec![],
            origin: CaseOrigin::MinedHook {
                capture_id: "cap-1".to_string(),
                event_sequence: 3,
            },
        };
        let stored = serde_json::to_string(&case).unwrap();
        assert!(
            !stored.contains("authority"),
            "the record stores the origin, never an authority field: {stored}"
        );
    }
}
