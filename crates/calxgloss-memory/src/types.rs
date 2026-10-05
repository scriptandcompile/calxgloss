//! Core data types for memory lifecycle information.
//!
//! This module holds the serialized shape of everything the lifecycle
//! detectors produce:
//!
//! - `MemoryHint`, `AllocationType`: per-function detection records —
//!   the resource a function manages, how it is allocated and released,
//!   and the Rust ownership pattern the pairing suggests.
//! - `HandleLifecycle`, `ReferenceCount`: the handle-lifecycle and
//!   reference-counting shapes beside plain allocations.
//! - `MemoryResult`, `ScanMetadata`: the persisted per-binary result
//!   and its scan provenance.
//!
//! All types derive `Serialize`/`Deserialize`.

// `ScanMetadata` is the shared per-binary scan provenance and `Confidence`
// the shared 0–100 evidence score; both are re-exported so consumers name
// them through this crate, matching the typesdb, typeinfer, and algorithm
// convention.
pub use calxgloss_types::{Confidence, ScanMetadata};
use serde::{Deserialize, Serialize};

// ============================================================
// Allocation type
// ============================================================

/// The allocation family a recognized allocation belongs to.
///
/// The family says how the function obtained the resource — a raw
/// `malloc` block, a zero-filled `calloc` block, a resized `realloc`
/// block, or C++ `operator new` storage — and which release closes it:
/// `free` for the C families, `operator delete` for the C++ ones. A
/// translation prompt weighs the family beside the pairing's shape when
/// choosing the Rust ownership pattern: a `malloc` block released
/// before return reads as `Box<T>`, while `operator new[]` storage
/// reads as a `Vec`-shaped allocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AllocationType {
    /// A raw heap block from `malloc`.
    Malloc,
    /// A zero-filled heap block from `calloc`.
    Calloc,
    /// A resized heap block from `realloc`, which also releases the
    /// block it grows or shrinks.
    Realloc,
    /// Storage for one constructed object, from C++ `operator new`.
    New,
    /// Storage for an array of constructed objects, from C++
    /// `operator new[]`.
    NewArray,
}

calxgloss_types::display_serde_label!(AllocationType {
    Malloc => "malloc",
    Calloc => "calloc",
    Realloc => "realloc",
    New => "new",
    NewArray => "new_array",
});

// ============================================================
// Memory hints
// ============================================================

/// One memory lifecycle observation about one function, with the
/// evidence behind it.
///
/// A hint is a hypothesis, not a fact applied to the program: it says
/// the function holds a resource of [`allocation_type`](Self::allocation_type)
/// and the allocation's pairing with its release reads like
/// [`suggestion`](Self::suggestion) — the Rust ownership pattern the
/// translation should aim at. The confidence and evidence together say
/// how strongly the pairing was read; detectors emit these records and
/// the survivors are persisted and rendered into translation prompts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryHint {
    /// The function the hint is about, e.g. `FUN_18003ab00`.
    pub function: String,
    /// The allocation family the recognized allocation belongs to.
    pub allocation_type: AllocationType,
    /// The Rust ownership pattern the pairing suggests, e.g. `Box<T>`
    /// or `stack allocation`.
    pub suggestion: String,
    /// Confidence that the hint is right, 0–100.
    pub confidence: Confidence,
    /// The decompiled lines that support the hint — the allocation and
    /// its release — kept so a reviewer (or a translation prompt) can
    /// check the reasoning.
    pub evidence: String,
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    const ALL_ALLOCATION_TYPES: [AllocationType; 5] = [
        AllocationType::Malloc,
        AllocationType::Calloc,
        AllocationType::Realloc,
        AllocationType::New,
        AllocationType::NewArray,
    ];

    fn hint() -> MemoryHint {
        MemoryHint {
            function: "FUN_18003ab00".into(),
            allocation_type: AllocationType::Malloc,
            suggestion: "Box<T>".into(),
            confidence: Confidence::new(70),
            evidence: "pvVar1 = malloc(0x20); /* ... */ free(pvVar1);".into(),
        }
    }

    #[test]
    fn a_memory_hint_serde_round_trips() {
        let record = hint();
        let json = serde_json::to_string(&record).unwrap();
        // The allocation family serializes snake_case and the
        // confidence as a plain number, matching the workspace's
        // serde convention.
        assert!(json.contains("\"allocation_type\":\"malloc\""));
        assert!(json.contains("\"confidence\":70"));
        let back: MemoryHint = serde_json::from_str(&json).unwrap();
        assert_eq!(back, record);
    }

    #[test]
    fn allocation_types_display_their_serde_labels() {
        for allocation_type in ALL_ALLOCATION_TYPES {
            let label = serde_json::to_value(allocation_type).unwrap();
            assert_eq!(allocation_type.to_string(), label.as_str().unwrap());
        }
        assert_eq!(AllocationType::NewArray.to_string(), "new_array");
    }

    #[test]
    fn a_hint_names_the_function_the_family_and_the_suggestion() {
        let json = serde_json::to_value(hint()).unwrap();
        assert_eq!(json["function"], "FUN_18003ab00");
        assert_eq!(json["allocation_type"], "malloc");
        assert_eq!(json["suggestion"], "Box<T>");
        assert_eq!(json["confidence"], 70);
    }

    #[test]
    fn a_new_array_allocation_hint_reads_back_from_json() {
        let json = r#"{
            "function": "FUN_18003e750",
            "allocation_type": "new_array",
            "suggestion": "Vec<T>",
            "confidence": 65,
            "evidence": "puVar2 = (ulonglong *)operator.new[](0x40);"
        }"#;
        let back: MemoryHint = serde_json::from_str(json).unwrap();
        assert_eq!(back.allocation_type, AllocationType::NewArray);
        assert_eq!(back.suggestion, "Vec<T>");
        assert_eq!(back.confidence, 65);
    }
}
