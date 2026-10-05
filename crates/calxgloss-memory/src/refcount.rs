//! Reference counting detection.
//!
//! This module provides [`ReferenceCountDetector`], which carries the
//! counter names a scan reads decompiled bodies against — the named
//! count fields a body raises and lowers by arithmetic (`ref_count++`
//! and `ref_count--`) and the COM `AddRef`/`Release` method pair —
//! pairing each bump with its drop inside a single function so the
//! prompt can later weigh the manual counting against `Rc<T>` or
//! `Arc<T>`.
//!
//! The count is read in two shapes. Where the code counts through
//! arithmetic on a named field, a bump is a `++` or `+= 1` on a
//! configured field name hanging off a plain-owner variable and a
//! drop is a `--` or `-= 1` on the same field of the same owner.
//! Where the code counts through the COM method pair, a bump is a
//! call to a recognized increment name and a drop is a call to a
//! recognized decrement name, the two tied by the object variable
//! their first argument names; a body that hands the counted object
//! to a thread-spawn call counts across threads. [`default_field_names`],
//! [`default_increments`], [`default_decrements`] and
//! [`default_thread_spawns`] carry the standard name sets, and
//! [`ReferenceCountDetector::with_default_names`] builds a detector
//! that scans against them.

// ============================================================
// Detector
// ============================================================

/// Reference-count bump/drop pair tracking over decompiled functions.
///
/// The detector owns the name sets a scan reads bodies against:
/// counter field names for the arithmetic shape, increment and
/// decrement method names for the COM shape, and thread-spawn names
/// for the shared-across-threads reading that picks `Arc<T>` over
/// `Rc<T>`. All four sets are configurable — supply them whole
/// through [`with_names`](Self::with_names) or grow them one name at
/// a time with [`add_field`](Self::add_field),
/// [`add_increment`](Self::add_increment),
/// [`add_decrement`](Self::add_decrement) and
/// [`add_thread_spawn`](Self::add_thread_spawn) — and
/// [`fields`](Self::fields), [`increments`](Self::increments),
/// [`decrements`](Self::decrements) and
/// [`thread_spawns`](Self::thread_spawns) report them in configuration
/// order, so two detectors built the same way scan identically and
/// results diff cleanly. The detector holds no Ghidra client of its
/// own and never writes back to the program; one detector serves an
/// entire scan and can be shared by reference across concurrent
/// per-function passes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReferenceCountDetector {
    fields: Vec<String>,
    increments: Vec<String>,
    decrements: Vec<String>,
    thread_spawns: Vec<String>,
}

impl ReferenceCountDetector {
    /// A detector with no names configured: every body it is handed
    /// pairs nothing until the standard sets arrive through
    /// [`with_default_names`](Self::with_default_names) or names join
    /// one at a time through [`add_field`](Self::add_field),
    /// [`add_increment`](Self::add_increment),
    /// [`add_decrement`](Self::add_decrement) and
    /// [`add_thread_spawn`](Self::add_thread_spawn).
    pub fn new() -> Self {
        Self::default()
    }

    /// A detector that scans against the standard name sets —
    /// [`default_field_names`], [`default_increments`],
    /// [`default_decrements`] and [`default_thread_spawns`] — in their
    /// configuration order.
    pub fn with_default_names() -> Self {
        Self::with_names(
            default_field_names(),
            default_increments(),
            default_decrements(),
            default_thread_spawns(),
        )
    }

    /// A detector that scans against exactly `fields`, `increments`,
    /// `decrements` and `thread_spawns`, each kept in the order it is
    /// given.
    pub fn with_names(
        fields: impl IntoIterator<Item = impl Into<String>>,
        increments: impl IntoIterator<Item = impl Into<String>>,
        decrements: impl IntoIterator<Item = impl Into<String>>,
        thread_spawns: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self {
            fields: fields.into_iter().map(Into::into).collect(),
            increments: increments.into_iter().map(Into::into).collect(),
            decrements: decrements.into_iter().map(Into::into).collect(),
            thread_spawns: thread_spawns.into_iter().map(Into::into).collect(),
        }
    }

    /// Add one counter field name to the set this detector scans
    /// against.
    pub fn add_field(&mut self, field: impl Into<String>) {
        self.fields.push(field.into());
    }

    /// Add one increment method name to the set this detector scans
    /// against.
    pub fn add_increment(&mut self, increment: impl Into<String>) {
        self.increments.push(increment.into());
    }

    /// Add one decrement method name to the set this detector scans
    /// against.
    pub fn add_decrement(&mut self, decrement: impl Into<String>) {
        self.decrements.push(decrement.into());
    }

    /// Add one thread-spawn name to the set this detector scans
    /// against for the shared-across-threads reading.
    pub fn add_thread_spawn(&mut self, spawn: impl Into<String>) {
        self.thread_spawns.push(spawn.into());
    }

    /// The counter field names this detector scans against, in
    /// configuration order.
    pub fn fields(&self) -> &[String] {
        &self.fields
    }

    /// The increment method names this detector scans against, in
    /// configuration order.
    pub fn increments(&self) -> &[String] {
        &self.increments
    }

    /// The decrement method names this detector scans against, in
    /// configuration order.
    pub fn decrements(&self) -> &[String] {
        &self.decrements
    }

    /// The thread-spawn names this detector scans against, in
    /// configuration order.
    pub fn thread_spawns(&self) -> &[String] {
        &self.thread_spawns
    }
}

// ============================================================
// The standard name sets
// ============================================================

/// The standard counter field names: the field spellings a scan
/// recognizes as reference counts read through arithmetic —
/// `ref_count` and its compact and long spellings, and the
/// standard-library `use_count`. A bump on one name answers a drop on
/// that same name; the names never cross.
pub fn default_field_names() -> Vec<String> {
    vec![
        "ref_count".into(),
        "refcount".into(),
        "reference_count".into(),
        "use_count".into(),
    ]
}

/// The standard increment names: the method spellings a scan
/// recognizes as raising an object's reference count — the COM
/// `AddRef`.
pub fn default_increments() -> Vec<String> {
    vec!["AddRef".into()]
}

/// The standard decrement names: the method spellings a scan
/// recognizes as releasing an object's reference count — the COM
/// `Release`.
pub fn default_decrements() -> Vec<String> {
    vec!["Release".into()]
}

/// The standard thread-spawn names: the callee spellings a scan
/// recognizes as starting a thread that works through an argument —
/// the Win32 `CreateThread` and the CRT's `_beginthread`/
/// `_beginthreadex` twins, and the POSIX `pthread_create`. An object
/// handed to one of these reaches another thread, which is what turns
/// an `Rc<T>` reading into an `Arc<T>` one.
pub fn default_thread_spawns() -> Vec<String> {
    vec![
        "CreateThread".into(),
        "_beginthread".into(),
        "_beginthreadex".into(),
        "pthread_create".into(),
    ]
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_new_detector_starts_with_no_names() {
        // Construction is free: empty, equal however it is made, and
        // clones interchangeable.
        let detector = ReferenceCountDetector::new();
        assert!(detector.fields().is_empty());
        assert!(detector.increments().is_empty());
        assert!(detector.decrements().is_empty());
        assert!(detector.thread_spawns().is_empty());
        assert_eq!(detector, ReferenceCountDetector::default());
        assert_eq!(detector.clone(), detector);
    }

    #[test]
    fn a_detector_keeps_the_names_it_is_configured_with() {
        let detector = ReferenceCountDetector::with_names(
            ["ref_count", "use_count"],
            ["AddRef"],
            ["Release"],
            ["CreateThread"],
        );
        // Configuration order is scan order: two detectors built the
        // same way see the same names in the same order.
        assert_eq!(detector.fields(), ["ref_count", "use_count"]);
        assert_eq!(detector.increments(), ["AddRef"]);
        assert_eq!(detector.decrements(), ["Release"]);
        assert_eq!(detector.thread_spawns(), ["CreateThread"]);
    }

    #[test]
    fn added_names_join_their_sets_in_order() {
        let mut detector = ReferenceCountDetector::new();
        detector.add_field("ref_count");
        detector.add_field("use_count");
        detector.add_increment("AddRef");
        detector.add_decrement("Release");
        detector.add_decrement("release");
        detector.add_thread_spawn("CreateThread");
        detector.add_thread_spawn("pthread_create");
        assert_eq!(detector.fields(), ["ref_count", "use_count"]);
        assert_eq!(detector.increments(), ["AddRef"]);
        assert_eq!(detector.decrements(), ["Release", "release"]);
        assert_eq!(detector.thread_spawns(), ["CreateThread", "pthread_create"]);
    }

    #[test]
    fn a_detector_can_be_shared_across_scans() {
        // One detector is driven concurrently over a program's
        // functions, so sharing one by reference across tasks must
        // stay sound.
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<ReferenceCountDetector>();
    }

    #[test]
    fn the_standard_field_names_name_the_counter_spellings() {
        assert_eq!(
            default_field_names(),
            ["ref_count", "refcount", "reference_count", "use_count"]
        );
    }

    #[test]
    fn the_standard_com_names_name_the_add_ref_and_release_pair() {
        assert_eq!(default_increments(), ["AddRef"]);
        assert_eq!(default_decrements(), ["Release"]);
    }

    #[test]
    fn the_standard_thread_spawns_name_the_win32_crt_and_posix_spawn_calls() {
        assert_eq!(
            default_thread_spawns(),
            [
                "CreateThread",
                "_beginthread",
                "_beginthreadex",
                "pthread_create"
            ]
        );
    }

    #[test]
    fn a_detector_built_with_the_standard_sets_carries_them() {
        let detector = ReferenceCountDetector::with_default_names();
        assert_eq!(detector.fields(), default_field_names());
        assert_eq!(detector.increments(), default_increments());
        assert_eq!(detector.decrements(), default_decrements());
        assert_eq!(detector.thread_spawns(), default_thread_spawns());
    }
}
