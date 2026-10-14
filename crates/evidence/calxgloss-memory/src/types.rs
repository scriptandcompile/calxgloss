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
//! - `MemoryFinding`: the union over the three record kinds — one
//!   finding whichever detector made it — serde-tagged by `kind`.
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
// Cross-function lifecycle
// ============================================================

/// One memory lifecycle observation spanning two functions, with the
/// evidence behind it.
///
/// A record says the [`function`](Self::function) allocated a block of
/// [`allocation_type`](Self::allocation_type), bound it to
/// [`variable`](Self::variable), handed that variable to
/// [`partner`](Self::partner) at a call site, and the partner's body
/// released the parameter it arrived in: ownership crossed the call
/// boundary, which is what [`suggestion`](Self::suggestion) names. The
/// allocation line, the hand-off call line, and the partner's release
/// line are kept as [`evidence`](Self::evidence) so a reviewer (or a
/// translation prompt) can check the reasoning across both bodies.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossFunctionLifecycle {
    /// The function the record is about — the one that allocated.
    pub function: String,
    /// The callee that released the block.
    pub partner: String,
    /// The variable the allocation was bound to in the allocating
    /// function.
    pub variable: String,
    /// The allocation family the block belongs to.
    pub allocation_type: AllocationType,
    /// The Rust pattern the cross-function pairing suggests, e.g.
    /// `Box<T>` for ownership moved into the callee.
    pub suggestion: String,
    /// Confidence that the record is right, 0–100.
    pub confidence: Confidence,
    /// The decompiled lines that support the record — the allocation,
    /// the hand-off call, and the partner's release.
    pub evidence: String,
}

// ============================================================
// Ownership transfer
// ============================================================

/// The direction an allocated pointer crosses its function's boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransferDirection {
    /// The pointer was handed as a plain argument at a call site —
    /// ownership moves into the callee.
    HandedToCallee,
    /// The pointer was returned from the function — ownership moves
    /// out to the caller.
    ReturnedToCaller,
}

calxgloss_types::display_serde_label!(TransferDirection {
    HandedToCallee => "handed_to_callee",
    ReturnedToCaller => "returned_to_caller",
});

/// One ownership-transfer observation about one function, with the
/// evidence behind it.
///
/// A record says the [`function`](Self::function) allocated a block of
/// [`allocation_type`](Self::allocation_type), bound it to
/// [`variable`](Self::variable), and never released it in its own
/// body: the block crossed the function boundary in the direction of
/// [`direction`](Self::direction) — handed to
/// [`partner`](Self::partner) at a call site, or returned to whoever
/// calls this function — which is what [`suggestion`](Self::suggestion)
/// names as moved ownership. The allocation line and the escape line
/// are kept as [`evidence`](Self::evidence) so a reviewer (or a
/// translation prompt) can see the move.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnershipTransfer {
    /// The function the record is about — the one that allocated.
    pub function: String,
    /// The direction the pointer crossed the boundary.
    pub direction: TransferDirection,
    /// The callee the pointer was handed to; `None` for a return,
    /// whose receiving caller is not one known function.
    pub partner: Option<String>,
    /// The variable the allocation was bound to.
    pub variable: String,
    /// The allocation family the block belongs to.
    pub allocation_type: AllocationType,
    /// The Rust pattern the transfer suggests, e.g. `Box<T>` for
    /// ownership moved out of the allocating function.
    pub suggestion: String,
    /// Confidence that the record is right, 0–100.
    pub confidence: Confidence,
    /// The decompiled lines that support the record — the allocation
    /// and the escape.
    pub evidence: String,
}

// ============================================================
// Resource leak
// ============================================================

/// The resource a leak record is about: which recognized family the
/// unreleased resource belongs to — and for a handle, the opener
/// spelling that produced it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "resource", rename_all = "snake_case")]
pub enum LeakResource {
    /// A heap block of a recognized allocation family.
    Allocation {
        /// The allocation family the block belongs to.
        allocation_type: AllocationType,
    },
    /// A handle of a known family opened by a recognized opener.
    Handle {
        /// The handle family the opener belongs to.
        handle_type: HandleType,
        /// The opener spelling that produced the handle.
        opener: String,
    },
}

/// One resource-leak observation about one function, with the
/// evidence behind it.
///
/// A record says the [`function`](Self::function) acquired a
/// resource — a heap block or a handle — bound it to
/// [`variable`](Self::variable), and the body neither released it nor
/// let it escape: no release names the variable, no call site hands
/// it over as a plain argument, no return carries it out whole. The
/// leak is an absence, and the acquisition line is the only positive
/// fact, kept as [`evidence`](Self::evidence).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceLeak {
    /// The function the record is about — the one that acquired.
    pub function: String,
    /// The variable the resource was bound to.
    pub variable: String,
    /// The resource that went unreleased: the allocation family, or
    /// the handle family and its opener.
    pub resource: LeakResource,
    /// The Rust pattern the leak suggests, e.g. `Box<T>` for a block
    /// the scope should have owned, or a guard struct for a handle.
    pub suggestion: String,
    /// Confidence that the record is right, 0–100.
    pub confidence: Confidence,
    /// The decompiled line that acquired the resource.
    pub evidence: String,
}

// ============================================================
// Finding union
// ============================================================

/// One memory lifecycle finding, whichever detector made it.
///
/// The detectors emit the concrete records; the union is what the
/// persisted result carries, so one list can hold every finding for a
/// binary and a consumer reads the shared shape — function, suggestion,
/// confidence, evidence — without naming which detector produced it.
/// Unlike typeinfer's competing families, the detectors read
/// disjoint body shapes and can't make competing claims for one target,
/// so nothing is resolved between variants. The serde `kind` tag names
/// the record shape in the persisted JSON.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum MemoryFinding {
    /// An allocation paired with its release.
    Allocation(MemoryHint),
    /// A handle opened and closed again.
    Handle(HandleLifecycle),
    /// A reference-count bump paired with its drop.
    RefCount(ReferenceCount),
    /// An allocation released by a callee it was handed to.
    CrossFunction(CrossFunctionLifecycle),
    /// An allocated pointer that escaped its function without releasing.
    Ownership(OwnershipTransfer),
    /// A resource acquired and never released or handed on.
    Leak(ResourceLeak),
}

impl MemoryFinding {
    /// The function the finding is about.
    pub fn function(&self) -> &str {
        match self {
            MemoryFinding::Allocation(record) => &record.function,
            MemoryFinding::Handle(record) => &record.function,
            MemoryFinding::RefCount(record) => &record.function,
            MemoryFinding::CrossFunction(record) => &record.function,
            MemoryFinding::Ownership(record) => &record.function,
            MemoryFinding::Leak(record) => &record.function,
        }
    }

    /// The Rust pattern the pairing suggests.
    pub fn suggestion(&self) -> &str {
        match self {
            MemoryFinding::Allocation(record) => &record.suggestion,
            MemoryFinding::Handle(record) => &record.suggestion,
            MemoryFinding::RefCount(record) => &record.suggestion,
            MemoryFinding::CrossFunction(record) => &record.suggestion,
            MemoryFinding::Ownership(record) => &record.suggestion,
            MemoryFinding::Leak(record) => &record.suggestion,
        }
    }

    /// Confidence that the finding is right.
    pub fn confidence(&self) -> Confidence {
        match self {
            MemoryFinding::Allocation(record) => record.confidence,
            MemoryFinding::Handle(record) => record.confidence,
            MemoryFinding::RefCount(record) => record.confidence,
            MemoryFinding::CrossFunction(record) => record.confidence,
            MemoryFinding::Ownership(record) => record.confidence,
            MemoryFinding::Leak(record) => record.confidence,
        }
    }

    /// The decompiled lines that support the finding.
    pub fn evidence(&self) -> &str {
        match self {
            MemoryFinding::Allocation(record) => &record.evidence,
            MemoryFinding::Handle(record) => &record.evidence,
            MemoryFinding::RefCount(record) => &record.evidence,
            MemoryFinding::CrossFunction(record) => &record.evidence,
            MemoryFinding::Ownership(record) => &record.evidence,
            MemoryFinding::Leak(record) => &record.evidence,
        }
    }

    /// The serde `kind` tag — `allocation`, `handle`, `ref_count`,
    /// `cross_function`, `ownership`, or `leak` — naming the detector
    /// behind the finding.
    pub fn kind(&self) -> &'static str {
        match self {
            MemoryFinding::Allocation(_) => "allocation",
            MemoryFinding::Handle(_) => "handle",
            MemoryFinding::RefCount(_) => "ref_count",
            MemoryFinding::CrossFunction(_) => "cross_function",
            MemoryFinding::Ownership(_) => "ownership",
            MemoryFinding::Leak(_) => "leak",
        }
    }

    /// What the finding pairs, spelled for a report row: the allocation
    /// family, the opener/closer spellings, the bump/drop spellings, the
    /// allocation family and the releasing partner, the allocation
    /// family and the transfer direction, or the leaked resource — its
    /// allocation family or its opener.
    pub fn target(&self) -> String {
        match self {
            MemoryFinding::Allocation(record) => record.allocation_type.to_string(),
            MemoryFinding::Handle(record) => format!("{}→{}", record.opener, record.closer),
            MemoryFinding::RefCount(record) => format!("{}→{}", record.increment, record.decrement),
            MemoryFinding::CrossFunction(record) => {
                format!("{}→{}", record.allocation_type, record.partner)
            }
            MemoryFinding::Ownership(record) => {
                format!("{}→{}", record.allocation_type, record.direction)
            }
            MemoryFinding::Leak(record) => match &record.resource {
                LeakResource::Allocation { allocation_type } => allocation_type.to_string(),
                LeakResource::Handle { opener, .. } => opener.clone(),
            },
        }
    }
}

// ============================================================
// Prompt conversions
// ============================================================

/// Render a finding as prompt data: the function it is about, the kind
/// of lifecycle the detector read, the Rust pattern the pairing
/// suggests, and the confidence and evidence behind the claim — so the
/// escalate prompt shows the hypothesis and how strongly it was made,
/// whichever detector produced it.
impl From<&MemoryFinding> for calxgloss_prompts::MemoryInfo {
    fn from(finding: &MemoryFinding) -> Self {
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

/// The memory lifecycle result for one binary — the document persisted
/// to `re/analysis/memory/{dll}.json`.
///
/// The findings are the three detectors' outputs in scan order: function
/// by function, and within one function the allocation pairs, then the
/// handle lifetimes, then the reference counts — followed by the
/// cross-function pass's findings, also in listing order. The detectors
/// read disjoint body shapes, so a function can carry findings of every
/// kind at once and none competes with another; the stable order means
/// two scans of the same program diff cleanly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryResult {
    /// Provenance of the scan that produced these findings.
    pub metadata: ScanMetadata,
    /// Every finding the detectors made, in scan order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub findings: Vec<MemoryFinding>,
}

impl MemoryResult {
    /// An empty result for the binary described by `metadata`.
    pub fn new(metadata: ScanMetadata) -> Self {
        Self {
            metadata,
            findings: Vec::new(),
        }
    }

    /// The findings recorded for one function, e.g. `FUN_18003ab00`.
    pub fn for_function(&self, function: &str) -> impl Iterator<Item = &MemoryFinding> {
        self.findings
            .iter()
            .filter(move |finding| finding.function() == function)
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

    #[test]
    fn an_allocation_finding_serde_round_trips_under_its_kind_tag() {
        let finding = MemoryFinding::Allocation(hint());
        let json = serde_json::to_string(&finding).expect("allocation finding should serialize");
        // The union is internally tagged: the kind names the record
        // shape and the payload's own fields sit beside it.
        assert!(json.contains("\"kind\":\"allocation\""));
        assert!(json.contains("\"allocation_type\":\"malloc\""));
        let back: MemoryFinding =
            serde_json::from_str(&json).expect("allocation finding should read back");
        assert_eq!(back, finding);
    }

    #[test]
    fn a_handle_finding_serde_round_trips_under_its_kind_tag() {
        let finding = MemoryFinding::Handle(handle_lifecycle());
        let json = serde_json::to_string(&finding).expect("handle finding should serialize");
        assert!(json.contains("\"kind\":\"handle\""));
        assert!(json.contains("\"handle_type\":\"kernel_object\""));
        let back: MemoryFinding =
            serde_json::from_str(&json).expect("handle finding should read back");
        assert_eq!(back, finding);
    }

    #[test]
    fn a_ref_count_finding_serde_round_trips_under_its_kind_tag() {
        let finding = MemoryFinding::RefCount(reference_count());
        let json = serde_json::to_string(&finding).expect("ref count finding should serialize");
        assert!(json.contains("\"kind\":\"ref_count\""));
        assert!(json.contains("\"style\":\"com_methods\""));
        let back: MemoryFinding =
            serde_json::from_str(&json).expect("ref count finding should read back");
        assert_eq!(back, finding);
    }

    #[test]
    fn a_cross_function_finding_serde_round_trips_under_its_kind_tag() {
        let finding = MemoryFinding::CrossFunction(CrossFunctionLifecycle {
            function: "FUN_18003ab00".into(),
            partner: "FUN_18003e750".into(),
            variable: "pvVar1".into(),
            allocation_type: AllocationType::Malloc,
            suggestion: "Box<T>".into(),
            confidence: Confidence::new(70),
            evidence: "pvVar1 = malloc(0x20); FUN_18003e750(pvVar1); free(param_1);".into(),
        });
        let json =
            serde_json::to_string(&finding).expect("cross-function finding should serialize");
        // The union is internally tagged: the kind names the record
        // shape and the payload's own fields sit beside it.
        assert!(json.contains("\"kind\":\"cross_function\""));
        assert!(json.contains("\"partner\":\"FUN_18003e750\""));
        assert!(json.contains("\"variable\":\"pvVar1\""));
        let back: MemoryFinding =
            serde_json::from_str(&json).expect("cross-function finding should read back");
        assert_eq!(back, finding);
    }

    #[test]
    fn an_ownership_finding_serde_round_trips_under_its_kind_tag() {
        let finding = MemoryFinding::Ownership(OwnershipTransfer {
            function: "FUN_18003ab00".into(),
            direction: TransferDirection::HandedToCallee,
            partner: Some("FUN_18003e750".into()),
            variable: "pvVar1".into(),
            allocation_type: AllocationType::Malloc,
            suggestion: "Box<T>".into(),
            confidence: Confidence::new(65),
            evidence: "pvVar1 = malloc(0x20); FUN_18003e750(pvVar1);".into(),
        });
        let json = serde_json::to_string(&finding).expect("ownership finding should serialize");
        assert!(json.contains("\"kind\":\"ownership\""));
        assert!(json.contains("\"direction\":\"handed_to_callee\""));
        let back: MemoryFinding =
            serde_json::from_str(&json).expect("ownership finding should read back");
        assert_eq!(back, finding);
    }

    #[test]
    fn a_returned_ownership_finding_carries_no_partner() {
        let finding = MemoryFinding::Ownership(OwnershipTransfer {
            function: "FUN_18003ab00".into(),
            direction: TransferDirection::ReturnedToCaller,
            partner: None,
            variable: "pvVar1".into(),
            allocation_type: AllocationType::Malloc,
            suggestion: "Box<T>".into(),
            confidence: Confidence::new(65),
            evidence: "pvVar1 = malloc(0x20); return pvVar1;".into(),
        });
        let json = serde_json::to_string(&finding).expect("ownership finding should serialize");
        assert!(json.contains("\"direction\":\"returned_to_caller\""));
        let back: MemoryFinding =
            serde_json::from_str(&json).expect("ownership finding should read back");
        assert_eq!(back, finding);
    }

    #[test]
    fn a_leaked_allocation_serde_round_trips_under_its_kind_tag() {
        let finding = MemoryFinding::Leak(ResourceLeak {
            function: "FUN_18003ab00".into(),
            variable: "pvVar1".into(),
            resource: LeakResource::Allocation {
                allocation_type: AllocationType::Malloc,
            },
            suggestion: "Box<T>".into(),
            confidence: Confidence::new(60),
            evidence: "pvVar1 = malloc(0x20);".into(),
        });
        let json = serde_json::to_string(&finding).expect("leak finding should serialize");
        assert!(json.contains("\"kind\":\"leak\""));
        assert!(json.contains("\"resource\":\"allocation\""));
        let back: MemoryFinding =
            serde_json::from_str(&json).expect("leak finding should read back");
        assert_eq!(back, finding);
    }

    #[test]
    fn a_leaked_handle_names_its_opener_and_round_trips() {
        let finding = MemoryFinding::Leak(ResourceLeak {
            function: "FUN_18003ab00".into(),
            variable: "hFile".into(),
            resource: LeakResource::Handle {
                handle_type: HandleType::KernelObject,
                opener: "CreateFileW".into(),
            },
            suggestion: "RAII guard struct with Drop impl".into(),
            confidence: Confidence::new(60),
            evidence: "hFile = CreateFileW(...);".into(),
        });
        let json = serde_json::to_string(&finding).expect("handle leak should serialize");
        assert!(json.contains("\"resource\":\"handle\""));
        assert!(json.contains("\"opener\":\"CreateFileW\""));
        let back: MemoryFinding =
            serde_json::from_str(&json).expect("handle leak should read back");
        assert_eq!(back, finding);
        assert_eq!(back.target(), "CreateFileW");
    }

    #[test]
    fn the_union_accessors_reach_through_every_variant() {
        let findings = [
            MemoryFinding::Allocation(hint()),
            MemoryFinding::Handle(handle_lifecycle()),
            MemoryFinding::RefCount(reference_count()),
            MemoryFinding::CrossFunction(CrossFunctionLifecycle {
                function: "FUN_18003ab00".into(),
                partner: "FUN_18003e750".into(),
                variable: "pvVar1".into(),
                allocation_type: AllocationType::Malloc,
                suggestion: "Box<T>".into(),
                confidence: Confidence::new(70),
                evidence: "pvVar1 = malloc(0x20); free(param_1);".into(),
            }),
            MemoryFinding::Ownership(OwnershipTransfer {
                function: "FUN_18003ab00".into(),
                direction: TransferDirection::HandedToCallee,
                partner: Some("FUN_18003e750".into()),
                variable: "pvVar1".into(),
                allocation_type: AllocationType::Malloc,
                suggestion: "Box<T>".into(),
                confidence: Confidence::new(70),
                evidence: "pvVar1 = malloc(0x20); FUN_18003e750(pvVar1);".into(),
            }),
            MemoryFinding::Leak(ResourceLeak {
                function: "FUN_18003ab00".into(),
                variable: "pvVar1".into(),
                resource: LeakResource::Allocation {
                    allocation_type: AllocationType::Malloc,
                },
                suggestion: "Box<T>".into(),
                confidence: Confidence::new(70),
                evidence: "pvVar1 = malloc(0x20);".into(),
            }),
        ];
        for finding in &findings {
            assert_eq!(finding.function(), "FUN_18003ab00");
            assert_eq!(finding.confidence(), Confidence::new(70));
            assert!(!finding.suggestion().is_empty());
            assert!(!finding.evidence().is_empty());
        }
        let kinds: Vec<&str> = findings.iter().map(|f| f.kind()).collect();
        assert_eq!(
            kinds,
            vec![
                "allocation",
                "handle",
                "ref_count",
                "cross_function",
                "ownership",
                "leak"
            ]
        );
        let suggestions: Vec<&str> = findings.iter().map(|f| f.suggestion()).collect();
        assert_eq!(
            suggestions,
            vec![
                "Box<T>",
                "RAII guard struct with Drop impl",
                "Rc<T>",
                "Box<T>",
                "Box<T>",
                "Box<T>"
            ]
        );
        let targets: Vec<String> = findings.iter().map(|f| f.target()).collect();
        assert_eq!(
            targets,
            vec![
                "malloc",
                "CreateFileW→CloseHandle",
                "AddRef→Release",
                "malloc→FUN_18003e750",
                "malloc→handed_to_callee",
                "malloc"
            ]
        );
    }

    #[test]
    fn a_memory_result_serde_round_trips() {
        let result = MemoryResult {
            metadata: ScanMetadata {
                binary: "eqmain.dll".into(),
                scanned_at: 1_759_488_000,
                duration_secs: 12,
            },
            findings: vec![
                MemoryFinding::Allocation(hint()),
                MemoryFinding::Handle(handle_lifecycle()),
                MemoryFinding::RefCount(reference_count()),
            ],
        };
        let json = serde_json::to_string(&result).expect("memory result should serialize");
        let back: MemoryResult =
            serde_json::from_str(&json).expect("memory result should read back");
        assert_eq!(back, result);
    }

    #[test]
    fn a_result_without_findings_omits_them_and_reads_back_empty() {
        // Documents persisted before a finding landed still load, and an
        // empty scan stays small on disk.
        let result = MemoryResult::new(ScanMetadata::new("eqmain.dll"));
        let json = serde_json::to_string(&result).expect("empty memory result should serialize");
        assert!(!json.contains("\"findings\""));
        let back: MemoryResult =
            serde_json::from_str(&json).expect("empty memory result should read back");
        assert!(back.is_empty());
        assert_eq!(back.metadata.binary, "eqmain.dll");
    }

    #[test]
    fn for_function_yields_only_that_function_s_findings_in_order() {
        let other = MemoryFinding::RefCount(ReferenceCount {
            function: "FUN_18003e750".into(),
            style: CountStyle::FieldArithmetic,
            increment: "ref_count++".into(),
            decrement: "ref_count--".into(),
            suggestion: "Arc<T>".into(),
            confidence: Confidence::new(65),
            evidence: "param_1->ref_count++; param_1->ref_count--;".into(),
        });
        let result = MemoryResult {
            metadata: ScanMetadata::new("eqmain.dll"),
            findings: vec![other.clone(), MemoryFinding::Allocation(hint())],
        };
        let found: Vec<&MemoryFinding> = result.for_function("FUN_18003e750").collect();
        assert_eq!(found, vec![&other]);
        assert!(result.for_function("FUN_180099999").next().is_none());
        assert!(!result.is_empty());
    }

    #[test]
    fn a_finding_renders_into_prompt_data_whichever_kind_it_is() {
        // The prompt conversion reaches through the union, so every kind
        // carries its label, suggestion, confidence, and evidence whole
        // into `MemoryInfo`.
        let allocation = MemoryFinding::Allocation(hint());
        let info = calxgloss_prompts::MemoryInfo::from(&allocation);
        assert_eq!(info.function, "FUN_18003ab00");
        assert_eq!(info.kind, "allocation");
        assert_eq!(info.suggestion, "Box<T>");
        assert_eq!(info.confidence, 70);
        assert_eq!(
            info.evidence,
            "pvVar1 = malloc(0x20); /* ... */ free(pvVar1);"
        );

        let handle = MemoryFinding::Handle(handle_lifecycle());
        let info = calxgloss_prompts::MemoryInfo::from(&handle);
        assert_eq!(info.kind, "handle");
        assert_eq!(info.suggestion, "RAII guard struct with Drop impl");
        assert_eq!(info.confidence, 70);

        let ref_count = MemoryFinding::RefCount(reference_count());
        let info = calxgloss_prompts::MemoryInfo::from(&ref_count);
        assert_eq!(info.kind, "ref_count");
        assert_eq!(info.suggestion, "Rc<T>");
        assert_eq!(info.confidence, 70);

        let cross_function = MemoryFinding::CrossFunction(CrossFunctionLifecycle {
            function: "FUN_18003ab00".into(),
            partner: "FUN_18003e750".into(),
            variable: "pvVar1".into(),
            allocation_type: AllocationType::Malloc,
            suggestion: "Box<T>".into(),
            confidence: Confidence::new(70),
            evidence: "pvVar1 = malloc(0x20); free(param_1);".into(),
        });
        let info = calxgloss_prompts::MemoryInfo::from(&cross_function);
        assert_eq!(info.kind, "cross_function");
        assert_eq!(info.suggestion, "Box<T>");
        assert_eq!(info.confidence, 70);

        let ownership = MemoryFinding::Ownership(OwnershipTransfer {
            function: "FUN_18003ab00".into(),
            direction: TransferDirection::ReturnedToCaller,
            partner: None,
            variable: "pvVar1".into(),
            allocation_type: AllocationType::Malloc,
            suggestion: "Box<T>".into(),
            confidence: Confidence::new(65),
            evidence: "pvVar1 = malloc(0x20); return pvVar1;".into(),
        });
        let info = calxgloss_prompts::MemoryInfo::from(&ownership);
        assert_eq!(info.kind, "ownership");
        assert_eq!(info.suggestion, "Box<T>");
        assert_eq!(info.confidence, 65);
    }
}
