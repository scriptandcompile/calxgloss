//! Allocation/deallocation pair tracking.
//!
//! This module provides [`AllocatorTracker`], which carries the
//! allocator and deallocator names a scan reads decompiled bodies
//! against — the C trio `malloc`/`calloc`/`realloc` closed by `free`,
//! and the C++ `operator new` pair closed by `operator delete` —
//! pairing each allocation with its release inside a single function
//! so the prompt can suggest `Box<T>` or stack allocation for the
//! short-lived cases.
//!
//! Each allocator name is an [`AllocatorSignature`]: the callee
//! spelling as the decompiler writes it and the [`AllocationType`] it
//! stands for. [`default_allocators`] and [`default_deallocators`]
//! carry the standard name sets, and
//! [`AllocatorTracker::with_default_names`] builds a tracker that
//! scans against them.

use crate::types::AllocationType;
use serde::{Deserialize, Serialize};
// ============================================================
// Allocator names
// ============================================================

/// One allocator name the tracker recognizes: the callee spelling and
/// the allocation family it stands for.
///
/// A signature is a name, not a shape: it only says that a call to
/// [`name`](Self::name) obtained a resource of
/// [`allocation_type`](Self::allocation_type) — `calloc` a zero-filled
/// block, `operator.new[]` array storage — while where the call sits
/// in the function and what releases it is the tracker's reading.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AllocatorSignature {
    /// The callee spelling as the decompiler writes it, e.g. `malloc`,
    /// `operator.new`.
    pub name: String,
    /// The allocation family this spelling stands for.
    pub allocation_type: AllocationType,
}

impl AllocatorSignature {
    /// A signature recognizing the callee spelling `name` as an
    /// allocation of `allocation_type`.
    pub fn new(name: impl Into<String>, allocation_type: AllocationType) -> Self {
        Self {
            name: name.into(),
            allocation_type,
        }
    }
}

// ============================================================
// Tracker
// ============================================================

/// Allocation/deallocation pair tracking over decompiled functions.
///
/// The tracker owns the name set a scan reads bodies against:
/// [`AllocatorSignature`] records for the allocating side and plain
/// callee spellings for the releasing side. Both sets are configurable
/// — supply them whole through [`with_names`](Self::with_names) or
/// grow them one name at a time with [`add_allocator`](Self::add_allocator)
/// and [`add_deallocator`](Self::add_deallocator) — and
/// [`allocators`](Self::allocators) and [`deallocators`](Self::deallocators)
/// report them in configuration order, so two trackers built the same
/// way scan identically and results diff cleanly. The tracker holds no
/// Ghidra client of its own and never writes back to the program; one
/// tracker serves an entire scan and can be shared by reference across
/// concurrent per-function passes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AllocatorTracker {
    allocators: Vec<AllocatorSignature>,
    deallocators: Vec<String>,
}

impl AllocatorTracker {
    /// A tracker with no names configured: every body it is handed
    /// pairs nothing until the standard sets arrive through
    /// [`with_default_names`](Self::with_default_names) or names join
    /// one at a time through [`add_allocator`](Self::add_allocator)
    /// and [`add_deallocator`](Self::add_deallocator).
    pub fn new() -> Self {
        Self::default()
    }

    /// A tracker that scans against the standard name sets —
    /// [`default_allocators`] and [`default_deallocators`] — in their
    /// configuration order.
    pub fn with_default_names() -> Self {
        Self::with_names(default_allocators(), default_deallocators())
    }

    /// A tracker that scans against exactly `allocators` and
    /// `deallocators`, each kept in the order it is given.
    pub fn with_names(
        allocators: impl IntoIterator<Item = AllocatorSignature>,
        deallocators: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self {
            allocators: allocators.into_iter().collect(),
            deallocators: deallocators.into_iter().map(Into::into).collect(),
        }
    }

    /// Add one allocator name to the set this tracker scans against.
    pub fn add_allocator(&mut self, allocator: AllocatorSignature) {
        self.allocators.push(allocator);
    }

    /// Add one deallocator name to the set this tracker scans against.
    pub fn add_deallocator(&mut self, deallocator: impl Into<String>) {
        self.deallocators.push(deallocator.into());
    }

    /// The allocator names this tracker scans against, in
    /// configuration order.
    pub fn allocators(&self) -> &[AllocatorSignature] {
        &self.allocators
    }

    /// The deallocator names this tracker scans against, in
    /// configuration order.
    pub fn deallocators(&self) -> &[String] {
        &self.deallocators
    }
}
// ============================================================
// The standard name sets
// ============================================================

/// The standard allocator names: the spellings a scan recognizes as
/// allocations out of the box — the C trio `malloc`, `calloc`, and
/// `realloc`, and the C++ `operator.new` and `operator.new[]` as
/// Ghidra writes demangled `operator new`. Each name carries the
/// family it stands for, so a recognized call knows whether it
/// obtained a raw block, a zero-filled block, a resized block, object
/// storage, or array storage.
pub fn default_allocators() -> Vec<AllocatorSignature> {
    vec![
        AllocatorSignature::new("malloc", AllocationType::Malloc),
        AllocatorSignature::new("calloc", AllocationType::Calloc),
        AllocatorSignature::new("realloc", AllocationType::Realloc),
        AllocatorSignature::new("operator.new", AllocationType::New),
        AllocatorSignature::new("operator.new[]", AllocationType::NewArray),
    ]
}

/// The standard deallocator names: the spellings a scan recognizes as
/// releases — `free`, which closes every C allocation including the
/// block `realloc` replaces, and Ghidra's demangled `operator.delete`
/// and `operator.delete[]`, which close C++ object and array storage.
pub fn default_deallocators() -> Vec<String> {
    vec![
        "free".into(),
        "operator.delete".into(),
        "operator.delete[]".into(),
    ]
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_new_tracker_starts_with_no_names() {
        // Construction is free: empty, equal however it is made, and
        // clones interchangeable.
        let tracker = AllocatorTracker::new();
        assert!(tracker.allocators().is_empty());
        assert!(tracker.deallocators().is_empty());
        assert_eq!(tracker, AllocatorTracker::default());
        assert_eq!(tracker.clone(), tracker);
    }

    #[test]
    fn a_tracker_keeps_the_names_it_is_configured_with() {
        let tracker = AllocatorTracker::with_names(
            [
                AllocatorSignature::new("malloc", AllocationType::Malloc),
                AllocatorSignature::new("calloc", AllocationType::Calloc),
            ],
            ["free"],
        );
        // Configuration order is scan order: two trackers built the
        // same way see the same names in the same order.
        assert_eq!(tracker.allocators().len(), 2);
        assert_eq!(tracker.allocators()[0].name, "malloc");
        assert_eq!(
            tracker.allocators()[1].allocation_type,
            AllocationType::Calloc
        );
        assert_eq!(tracker.deallocators(), ["free"]);
    }

    #[test]
    fn added_names_join_their_sets_in_order() {
        let mut tracker = AllocatorTracker::new();
        tracker.add_allocator(AllocatorSignature::new("malloc", AllocationType::Malloc));
        tracker.add_allocator(AllocatorSignature::new("realloc", AllocationType::Realloc));
        tracker.add_deallocator("free");
        tracker.add_deallocator("operator.delete");
        let names: Vec<&str> = tracker
            .allocators()
            .iter()
            .map(|a| a.name.as_str())
            .collect();
        assert_eq!(names, ["malloc", "realloc"]);
        assert_eq!(tracker.deallocators(), ["free", "operator.delete"]);
    }

    #[test]
    fn a_tracker_can_be_shared_across_scans() {
        // One tracker is driven concurrently over a program's
        // functions, so sharing one by reference across tasks must
        // stay sound.
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<AllocatorTracker>();
    }

    #[test]
    fn an_allocator_signature_serde_round_trips() {
        let signature = AllocatorSignature::new("operator.new[]", AllocationType::NewArray);
        let json = serde_json::to_string(&signature).unwrap();
        assert!(json.contains("\"allocation_type\":\"new_array\""));
        let back: AllocatorSignature = serde_json::from_str(&json).unwrap();
        assert_eq!(back, signature);
    }

    #[test]
    fn an_allocator_signature_without_optional_fields_reads_back_with_its_spelling() {
        // Documents persisted for a custom name set still load.
        let json = r#"{
            "name": "my_alloc",
            "allocation_type": "malloc"
        }"#;
        let back: AllocatorSignature = serde_json::from_str(json).unwrap();
        assert_eq!(back.name, "my_alloc");
        assert_eq!(back.allocation_type, AllocationType::Malloc);
    }

    #[test]
    fn the_standard_allocators_name_the_c_and_cxx_families() {
        let allocators = default_allocators();
        let named: Vec<(&str, AllocationType)> = allocators
            .iter()
            .map(|a| (a.name.as_str(), a.allocation_type))
            .collect();
        assert_eq!(
            named,
            [
                ("malloc", AllocationType::Malloc),
                ("calloc", AllocationType::Calloc),
                ("realloc", AllocationType::Realloc),
                ("operator.new", AllocationType::New),
                ("operator.new[]", AllocationType::NewArray),
            ]
        );
    }

    #[test]
    fn the_standard_deallocators_name_free_and_the_delete_pair() {
        assert_eq!(
            default_deallocators(),
            ["free", "operator.delete", "operator.delete[]"]
        );
    }

    #[test]
    fn a_tracker_built_with_the_standard_sets_carries_them() {
        let tracker = AllocatorTracker::with_default_names();
        assert_eq!(tracker.allocators(), default_allocators());
        assert_eq!(tracker.deallocators(), default_deallocators());
    }
}
