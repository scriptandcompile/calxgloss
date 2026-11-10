//! The obligations seam: the one place the review reader derives the
//! unit obligation every review row carries (issue #462). It runs the
//! same ledger read and the same live-record join the terminal build
//! runs — [`calxgloss_reports::dashboard::conformance::derive_unit_obligations`]
//! over an [`OpenedConformanceJoin`] opened from this workspace — so the
//! web rows and the terminal rows read one derivation and can never
//! disagree (ADR-0060: surfaces render, none computes a second one).

use std::collections::{BTreeMap, BTreeSet, HashMap};

use calxgloss_reports::dashboard::conformance::{OpenedConformanceJoin, derive_unit_obligations};
use calxgloss_types::UnitObligation;

use super::*;

/// One binary's filed obligation entries, keyed by the `(function,
/// attempt)` pair each entry speaks for.
pub(super) type ObligationReadings = HashMap<String, BTreeMap<(String, u32), UnitObligation>>;

impl ReviewSurfaceReader {
    /// Derive the obligation readings for these binaries (issue #462):
    /// one ledger read each, joined at the read with the reviewer's live
    /// records. A binary whose ledger was never filed or could not be
    /// read yields no readings — its units keep the unknown reading, and
    /// the same build's per-binary conformance row names the cause
    /// (missing, corrupt, or tampered), never a clean run.
    pub(super) fn unit_obligations(
        &self,
        binaries: &BTreeSet<String>,
    ) -> Result<ObligationReadings, ServerError> {
        let join = OpenedConformanceJoin::open(&self.repo_path).map_err(|fault| {
            ServerError::internal(&format!(
                "the reviewer's live records are unreadable: {fault}"
            ))
        })?;
        Ok(derive_unit_obligations(
            &self.repo_path,
            binaries,
            &join.borrow(),
        ))
    }
}
