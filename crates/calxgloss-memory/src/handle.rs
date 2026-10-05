//! Handle lifecycle detection.
//!
//! This module provides [`HandleDetector`], which carries the opener
//! and closer names a scan reads decompiled bodies against — the
//! Win32 `CreateFileW` and its ANSI twin `CreateFileA` closed by
//! `CloseHandle`, and the C stdio `fopen` closed by `fclose` —
//! pairing each open with its close inside a single function so the
//! prompt can suggest an RAII guard struct with a `Drop` impl
//! standing in for the manual close.
//!
//! Each recognized name is a [`HandleSignature`]: the callee spelling
//! as the decompiler writes it and the [`HandleType`] family it stands
//! for, on the opening side or the closing one. [`default_openers`]
//! and [`default_closers`] carry the standard name sets, and
//! [`HandleDetector::with_default_names`] builds a detector that
//! scans against them.

use crate::types::HandleType;
use serde::{Deserialize, Serialize};

// ============================================================
// Handle names
// ============================================================

/// One handle name the detector recognizes: the callee spelling and
/// the handle family it stands for, as an opener or as a closer.
///
/// A signature is a name, not a shape: it only says that a call to
/// [`name`](Self::name) opens or closes a handle of
/// [`handle_type`](Self::handle_type) — `CreateFileW` a kernel object
/// handle, `fclose` a stdio stream — while where the call sits in the
/// function and which open its closer answers is the detector's
/// reading. The family is what keeps the two sides straight: a closer
/// only pairs with an open of its own family.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandleSignature {
    /// The callee spelling as the decompiler writes it, e.g.
    /// `CreateFileW`, `fclose`.
    pub name: String,
    /// The handle family this spelling stands for.
    pub handle_type: HandleType,
}

impl HandleSignature {
    /// A signature recognizing the callee spelling `name` as an open
    /// or close of a `handle_type` handle.
    pub fn new(name: impl Into<String>, handle_type: HandleType) -> Self {
        Self {
            name: name.into(),
            handle_type,
        }
    }
}

// ============================================================
// Detector
// ============================================================

/// Handle open/close pair tracking over decompiled functions.
///
/// The detector owns the name set a scan reads bodies against:
/// [`HandleSignature`] records for the opening side and for the
/// closing side. Both sets are configurable — supply them whole
/// through [`with_names`](Self::with_names) or grow them one name at
/// a time with [`add_opener`](Self::add_opener) and
/// [`add_closer`](Self::add_closer) — and [`openers`](Self::openers)
/// and [`closers`](Self::closers) report them in configuration order,
/// so two detectors built the same way scan identically and results
/// diff cleanly. The detector holds no Ghidra client of its own and
/// never writes back to the program; one detector serves an entire
/// scan and can be shared by reference across concurrent per-function
/// passes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HandleDetector {
    openers: Vec<HandleSignature>,
    closers: Vec<HandleSignature>,
}

impl HandleDetector {
    /// A detector with no names configured: every body it is handed
    /// pairs nothing until the standard sets arrive through
    /// [`with_default_names`](Self::with_default_names) or names join
    /// one at a time through [`add_opener`](Self::add_opener) and
    /// [`add_closer`](Self::add_closer).
    pub fn new() -> Self {
        Self::default()
    }

    /// A detector that scans against the standard name sets —
    /// [`default_openers`] and [`default_closers`] — in their
    /// configuration order.
    pub fn with_default_names() -> Self {
        Self::with_names(default_openers(), default_closers())
    }

    /// A detector that scans against exactly `openers` and `closers`,
    /// each kept in the order it is given.
    pub fn with_names(
        openers: impl IntoIterator<Item = HandleSignature>,
        closers: impl IntoIterator<Item = HandleSignature>,
    ) -> Self {
        Self {
            openers: openers.into_iter().collect(),
            closers: closers.into_iter().collect(),
        }
    }

    /// Add one opener name to the set this detector scans against.
    pub fn add_opener(&mut self, opener: HandleSignature) {
        self.openers.push(opener);
    }

    /// Add one closer name to the set this detector scans against.
    pub fn add_closer(&mut self, closer: HandleSignature) {
        self.closers.push(closer);
    }

    /// The opener names this detector scans against, in
    /// configuration order.
    pub fn openers(&self) -> &[HandleSignature] {
        &self.openers
    }

    /// The closer names this detector scans against, in
    /// configuration order.
    pub fn closers(&self) -> &[HandleSignature] {
        &self.closers
    }
}

// ============================================================
// The standard name sets
// ============================================================

/// The standard opener names: the spellings a scan recognizes as
/// handle opens out of the box — the Win32 `CreateFileW` and its ANSI
/// twin `CreateFileA`, each standing for a kernel object handle, and
/// the C stdio `fopen`, standing for a stream. Each name carries the
/// family it stands for, so a recognized closer knows which opens it
/// could answer.
pub fn default_openers() -> Vec<HandleSignature> {
    vec![
        HandleSignature::new("CreateFileW", HandleType::KernelObject),
        HandleSignature::new("CreateFileA", HandleType::KernelObject),
        HandleSignature::new("fopen", HandleType::FileStream),
    ]
}

/// The standard closer names: the spellings a scan recognizes as
/// handle releases — `CloseHandle`, which closes any kernel object
/// handle however it was obtained, and `fclose`, which closes a stdio
/// stream. Each carries the family it closes, so a closer of one
/// family never answers an open of another.
pub fn default_closers() -> Vec<HandleSignature> {
    vec![
        HandleSignature::new("CloseHandle", HandleType::KernelObject),
        HandleSignature::new("fclose", HandleType::FileStream),
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
        let detector = HandleDetector::new();
        assert!(detector.openers().is_empty());
        assert!(detector.closers().is_empty());
        assert_eq!(detector, HandleDetector::default());
        assert_eq!(detector.clone(), detector);
    }

    #[test]
    fn a_detector_keeps_the_names_it_is_configured_with() {
        let detector = HandleDetector::with_names(
            [
                HandleSignature::new("CreateFileW", HandleType::KernelObject),
                HandleSignature::new("fopen", HandleType::FileStream),
            ],
            [HandleSignature::new("fclose", HandleType::FileStream)],
        );
        // Configuration order is scan order: two detectors built the
        // same way see the same names in the same order.
        assert_eq!(detector.openers().len(), 2);
        assert_eq!(detector.openers()[0].name, "CreateFileW");
        assert_eq!(detector.openers()[1].handle_type, HandleType::FileStream);
        assert_eq!(detector.closers().len(), 1);
        assert_eq!(detector.closers()[0].name, "fclose");
    }

    #[test]
    fn added_names_join_their_sets_in_order() {
        let mut detector = HandleDetector::new();
        detector.add_opener(HandleSignature::new(
            "CreateFileW",
            HandleType::KernelObject,
        ));
        detector.add_opener(HandleSignature::new("fopen", HandleType::FileStream));
        detector.add_closer(HandleSignature::new(
            "CloseHandle",
            HandleType::KernelObject,
        ));
        detector.add_closer(HandleSignature::new("fclose", HandleType::FileStream));
        let openers: Vec<&str> = detector.openers().iter().map(|o| o.name.as_str()).collect();
        let closers: Vec<&str> = detector.closers().iter().map(|c| c.name.as_str()).collect();
        assert_eq!(openers, ["CreateFileW", "fopen"]);
        assert_eq!(closers, ["CloseHandle", "fclose"]);
    }

    #[test]
    fn a_detector_can_be_shared_across_scans() {
        // One detector is driven concurrently over a program's
        // functions, so sharing one by reference across tasks must
        // stay sound.
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<HandleDetector>();
    }

    #[test]
    fn a_handle_signature_serde_round_trips() {
        let signature = HandleSignature::new("CreateFileA", HandleType::KernelObject);
        let json = serde_json::to_string(&signature).unwrap();
        assert!(json.contains("\"handle_type\":\"kernel_object\""));
        let back: HandleSignature = serde_json::from_str(&json).unwrap();
        assert_eq!(back, signature);
    }

    #[test]
    fn a_handle_signature_reads_back_with_its_spelling() {
        // Documents persisted for a custom name set still load.
        let json = r#"{
            "name": "open",
            "handle_type": "file_stream"
        }"#;
        let back: HandleSignature = serde_json::from_str(json).unwrap();
        assert_eq!(back.name, "open");
        assert_eq!(back.handle_type, HandleType::FileStream);
    }

    #[test]
    fn the_standard_openers_name_the_win32_and_stdio_families() {
        let openers = default_openers();
        let named: Vec<(&str, HandleType)> = openers
            .iter()
            .map(|o| (o.name.as_str(), o.handle_type))
            .collect();
        assert_eq!(
            named,
            [
                ("CreateFileW", HandleType::KernelObject),
                ("CreateFileA", HandleType::KernelObject),
                ("fopen", HandleType::FileStream),
            ]
        );
    }

    #[test]
    fn the_standard_closers_name_the_kernel_and_stdio_releases() {
        let closers = default_closers();
        let named: Vec<(&str, HandleType)> = closers
            .iter()
            .map(|c| (c.name.as_str(), c.handle_type))
            .collect();
        assert_eq!(
            named,
            [
                ("CloseHandle", HandleType::KernelObject),
                ("fclose", HandleType::FileStream),
            ]
        );
    }

    #[test]
    fn a_detector_built_with_the_standard_sets_carries_them() {
        let detector = HandleDetector::with_default_names();
        assert_eq!(detector.openers(), default_openers());
        assert_eq!(detector.closers(), default_closers());
    }
}
