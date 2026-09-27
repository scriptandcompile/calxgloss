/// Types for test case generation and baseline execution.
///
/// This module defines the data structures used to represent test inputs,
/// expected outputs, observed side effects, and test results captured from
/// running the original binary.

use serde::{Deserialize, Serialize};

/// The kind of side effect a function may produce.
///
/// Side effects are observed during baseline test execution and recorded
/// so the Rust translation can be verified for behavioral equivalence.
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

    /// A side effect not covered by the predefined kinds.
    Other(String),
}

/// A single observed side effect during test execution.
///
/// Side effects accompany a test case and its return value, capturing
/// file I/O, window updates, registry changes, and other observable
/// behaviors of the original function.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestCase {
    /// The test inputs as a JSON value. Parameters are serialized according to
    /// their types (integers, strings, booleans, or null for pointers).
    pub inputs: serde_json::Value,

    /// The expected return value from the original function, as JSON.
    pub expected_return: serde_json::Value,

    /// Expected side effects the function produces when called with these inputs.
    pub expected_side_effects: Vec<SideEffect>,
}

/// The result of executing a single baseline test case.
///
/// Captures both the actual return value and side effects, along with
/// pass/fail status and an optional error message if the test diverged
/// from expected behavior.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestResult {
    /// The test case that was executed.
    pub test_case: TestCase,

    /// The actual return value observed from the original function.
    pub actual_return: serde_json::Value,

    /// The actual side effects observed during execution.
    pub actual_side_effects: Vec<SideEffect>,

    /// Whether the test passed (true if actual matches expected).
    pub passed: bool,

    /// Error message describing why the test failed, if any.
    pub error: Option<String>,
}
