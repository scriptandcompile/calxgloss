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
// Handle lifecycle
// ============================================================

/// The handle family a recognized open or close belongs to.
///
/// The family says which opener spellings obtain the handle and which
/// closer releases it — a Win32 kernel object handle from a
/// `CreateFile` spelling closed by `CloseHandle`, or a C stdio stream
/// from `fopen` closed by `fclose`. A closer only ever closes a handle
/// of its own family: `fclose` on a kernel object handle names no
/// pairing, and neither does `CloseHandle` on a stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HandleType {
    /// A Win32 kernel object handle — file, event, mutex, pipe, or
    /// socket — obtained from a `CreateFile` spelling and released by
    /// `CloseHandle`.
    KernelObject,
    /// A C stdio stream, obtained from `fopen` and released by
    /// `fclose`.
    FileStream,
}

calxgloss_types::display_serde_label!(HandleType {
    KernelObject => "kernel_object",
    FileStream => "file_stream",
});

/// One handle lifecycle observation about one function, with the
/// evidence behind it.
///
/// A record says the function opens a handle of
/// [`handle_type`](Self::handle_type) — through the recognized opener
/// spelling [`opener`](Self::opener) — and closes it again through
/// [`closer`](Self::closer), the two tied by the variable the
/// decompiler stored the opener's result in. The pairing reads like
/// [`suggestion`](Self::suggestion) — the RAII guard pattern standing
/// in for the manual close — and the confidence says how strongly the
/// guard's shape was read. The opener and closer lines are kept as
/// [`evidence`](Self::evidence) so a reviewer (or a translation
/// prompt) can check the reasoning.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandleLifecycle {
    /// The function the record is about, e.g. `FUN_18003ab00`.
    pub function: String,
    /// The handle family the open and the close belong to.
    pub handle_type: HandleType,
    /// The opener spelling that obtained the handle, e.g. `CreateFileW`.
    pub opener: String,
    /// The closer spelling that released the handle, e.g. `CloseHandle`.
    pub closer: String,
    /// The Rust pattern the pairing suggests, e.g. `RAII guard struct
    /// with Drop impl`.
    pub suggestion: String,
    /// Confidence that the record is right, 0–100.
    pub confidence: Confidence,
    /// The decompiled lines that support the record — the open and
    /// its close — kept so a reviewer (or a translation prompt) can
    /// check the reasoning.
    pub evidence: String,
}

// ============================================================
// Reference counting
// ============================================================

/// The counting style a recognized bump or drop belongs to.
///
/// The style says how the code spells its reference counting —
/// arithmetic on a named count field, or the COM `AddRef`/`Release`
/// method pair — and what ties the two sides of a pairing: a bump
/// answers a drop on the same field of the same owner for
/// [`FieldArithmetic`](Self::FieldArithmetic), and on the same object
/// variable for [`ComMethods`](Self::ComMethods). A bump never
/// crosses styles: `AddRef` answers no field arithmetic, and neither
/// does a field drop answer a method call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CountStyle {
    /// A count the code keeps in a named field, raised and lowered by
    /// arithmetic on it: `ref_count++` and `ref_count--`.
    FieldArithmetic,
    /// A count the code keeps behind an object, raised and lowered
    /// through the COM `AddRef`/`Release` method pair.
    ComMethods,
}

calxgloss_types::display_serde_label!(CountStyle {
    FieldArithmetic => "field_arithmetic",
    ComMethods => "com_methods",
});

/// One reference-counting observation about one function, with the
/// evidence behind it.
///
/// A record says the function bumps a reference count — through
/// [`increment`](Self::increment) — and drops it again through
/// [`decrement`](Self::decrement), the two tied by what carries the
/// count: the same field of the same owner under
/// [`CountStyle::FieldArithmetic`](CountStyle::FieldArithmetic), the
/// same object variable under
/// [`CountStyle::ComMethods`](CountStyle::ComMethods). The pairing
/// reads like [`suggestion`](Self::suggestion) — the shared-ownership
/// pattern standing in for the manual counting, `Rc<T>` where the
/// counted object stays inside the function and `Arc<T>` where the
/// body hands it to a thread. The bump line and the drop line are
/// kept as [`evidence`](Self::evidence) so a reviewer (or a
/// translation prompt) can check the reasoning.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReferenceCount {
    /// The function the record is about, e.g. `FUN_18003ab00`.
    pub function: String,
    /// The counting style the bump and the drop belong to.
    pub style: CountStyle,
    /// The bump spelling that raised the count, e.g. `ref_count++` or
    /// `AddRef`.
    pub increment: String,
    /// The drop spelling that lowered the count, e.g. `ref_count--`
    /// or `Release`.
    pub decrement: String,
    /// The Rust pattern the pairing suggests, e.g. `Rc<T>` or
    /// `Arc<T>`.
    pub suggestion: String,
    /// Confidence that the record is right, 0–100.
    pub confidence: Confidence,
    /// The decompiled lines that support the record — the bump and
    /// its drop — kept so a reviewer (or a translation prompt) can
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

    const ALL_HANDLE_TYPES: [HandleType; 2] = [HandleType::KernelObject, HandleType::FileStream];

    const ALL_COUNT_STYLES: [CountStyle; 2] = [CountStyle::FieldArithmetic, CountStyle::ComMethods];

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

    fn handle_lifecycle() -> HandleLifecycle {
        HandleLifecycle {
            function: "FUN_18003ab00".into(),
            handle_type: HandleType::KernelObject,
            opener: "CreateFileW".into(),
            closer: "CloseHandle".into(),
            suggestion: "RAII guard struct with Drop impl".into(),
            confidence: Confidence::new(70),
            evidence: "hFile = CreateFileW(&DAT_3801a2b0,0xc0000000,0,(LPSECURITY_ATTRIBUTES)0x0,3,0x80,0); CloseHandle(hFile);".into(),
        }
    }

    #[test]
    fn a_handle_lifecycle_serde_round_trips() {
        let record = handle_lifecycle();
        let json = serde_json::to_string(&record).unwrap();
        // The handle family serializes snake_case and the confidence
        // as a plain number, matching the workspace's serde
        // convention.
        assert!(json.contains("\"handle_type\":\"kernel_object\""));
        assert!(json.contains("\"confidence\":70"));
        let back: HandleLifecycle = serde_json::from_str(&json).unwrap();
        assert_eq!(back, record);
    }

    #[test]
    fn handle_types_display_their_serde_labels() {
        for handle_type in ALL_HANDLE_TYPES {
            let label = serde_json::to_value(handle_type).unwrap();
            assert_eq!(handle_type.to_string(), label.as_str().unwrap());
        }
        assert_eq!(HandleType::KernelObject.to_string(), "kernel_object");
    }

    #[test]
    fn a_record_names_the_function_the_family_the_spellings_and_the_guard() {
        let json = serde_json::to_value(handle_lifecycle()).unwrap();
        assert_eq!(json["function"], "FUN_18003ab00");
        assert_eq!(json["handle_type"], "kernel_object");
        assert_eq!(json["opener"], "CreateFileW");
        assert_eq!(json["closer"], "CloseHandle");
        assert_eq!(json["suggestion"], "RAII guard struct with Drop impl");
        assert_eq!(json["confidence"], 70);
    }

    #[test]
    fn a_file_stream_record_reads_back_from_json() {
        let json = r#"{
            "function": "FUN_18003e750",
            "handle_type": "file_stream",
            "opener": "fopen",
            "closer": "fclose",
            "suggestion": "scoped RAII guard struct with Drop impl",
            "confidence": 65,
            "evidence": "local_10 = fopen(&DAT_3801a2b0,\"rb\"); fclose(local_10);"
        }"#;
        let back: HandleLifecycle = serde_json::from_str(json).unwrap();
        assert_eq!(back.handle_type, HandleType::FileStream);
        assert_eq!(back.opener, "fopen");
        assert_eq!(back.closer, "fclose");
        assert_eq!(back.suggestion, "scoped RAII guard struct with Drop impl");
        assert_eq!(back.confidence, 65);
    }

    fn reference_count() -> ReferenceCount {
        ReferenceCount {
            function: "FUN_18003ab00".into(),
            style: CountStyle::ComMethods,
            increment: "AddRef".into(),
            decrement: "Release".into(),
            suggestion: "Rc<T>".into(),
            confidence: Confidence::new(70),
            evidence: "AddRef((IUnknown *)param_1); Release((IUnknown *)param_1);".into(),
        }
    }

    #[test]
    fn a_reference_count_serde_round_trips() {
        let record = reference_count();
        let json = serde_json::to_string(&record).unwrap();
        // The counting style serializes snake_case and the confidence
        // as a plain number, matching the workspace's serde
        // convention.
        assert!(json.contains("\"style\":\"com_methods\""));
        assert!(json.contains("\"confidence\":70"));
        let back: ReferenceCount = serde_json::from_str(&json).unwrap();
        assert_eq!(back, record);
    }

    #[test]
    fn count_styles_display_their_serde_labels() {
        for style in ALL_COUNT_STYLES {
            let label = serde_json::to_value(style).unwrap();
            assert_eq!(style.to_string(), label.as_str().unwrap());
        }
        assert_eq!(CountStyle::FieldArithmetic.to_string(), "field_arithmetic");
    }

    #[test]
    fn a_record_names_the_function_the_style_and_the_spellings() {
        let json = serde_json::to_value(reference_count()).unwrap();
        assert_eq!(json["function"], "FUN_18003ab00");
        assert_eq!(json["style"], "com_methods");
        assert_eq!(json["increment"], "AddRef");
        assert_eq!(json["decrement"], "Release");
        assert_eq!(json["suggestion"], "Rc<T>");
        assert_eq!(json["confidence"], 70);
    }

    #[test]
    fn a_field_arithmetic_record_reads_back_from_json() {
        let json = r#"{
            "function": "FUN_18003e750",
            "style": "field_arithmetic",
            "increment": "ref_count++",
            "decrement": "ref_count--",
            "suggestion": "Arc<T>",
            "confidence": 65,
            "evidence": "param_1->ref_count++; param_1->ref_count--;"
        }"#;
        let back: ReferenceCount = serde_json::from_str(json).unwrap();
        assert_eq!(back.style, CountStyle::FieldArithmetic);
        assert_eq!(back.increment, "ref_count++");
        assert_eq!(back.decrement, "ref_count--");
        assert_eq!(back.suggestion, "Arc<T>");
        assert_eq!(back.confidence, 65);
    }
}
