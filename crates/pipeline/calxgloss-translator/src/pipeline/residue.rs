//! Unknown residue beside translation: the coverage, export, and verification
//! gaps a run admits, folded per binary and filed as the unknown ledger.

use super::*;

impl TranslationPipeline {
    /// Record one unit's admitted residue into the batch accumulator —
    /// the coverage fold's facet admissions (issue #369) and the seam
    /// report's unavailable families (issue #371): they arrive in the
    /// unit's own derivation order, and an id already admitted is never
    /// recorded twice — the same gap re-derived is one question, not a
    /// second opinion. The accumulator opening to `Some` is also the
    /// writer's signal that a producer actually looked this batch over.
    pub(super) fn record_unknown_residue(&self, residue: Vec<calxgloss_types::UnknownRecord>) {
        let mut accumulator = self.unknown_residue.lock().expect("unknown residue lock");
        let admitted = accumulator.get_or_insert_with(Vec::new);
        for record in residue {
            if !admitted.iter().any(|landed| landed.id == record.id) {
                admitted.push(record);
            }
        }
    }

    /// File the batch's export-coverage residue (issue #373): one
    /// `export_uncovered` record for every export in the listing that no
    /// filed baseline document covers — the document testgen's own
    /// `re/baseline/<binary>/<export>/baseline.json` layout names. The
    /// check is the already-checkable fact, no new evidence work: a
    /// covered export asks nothing, and an export listing that never came
    /// back (a target that is not a PE, a target whose bytes went away)
    /// reads *unknown* and files nothing — the ledger's absence keeps
    /// the honest reading, exactly like the seam's undeclared family. No
    /// workspace means nowhere to look for documents and nowhere to
    /// file, so the check does not run at all.
    pub(super) async fn record_export_residue(&self, binary: &str) {
        let Some(workspace) = self.workspace.as_deref() else {
            return;
        };
        let generator = TestGenerator::new(workspace);
        let exports = match self.scan_source().exports().await {
            Ok(exports) => exports,
            Err(source) => {
                warn!(
                    binary,
                    error = %source,
                    "The export listing never came back — the export-coverage check \
                     reads unknown and files nothing"
                );
                return;
            }
        };
        let now = calxgloss_types::scan::now_unix_secs();
        let residue: Vec<calxgloss_types::UnknownRecord> = exports
            .iter()
            .filter(|export| !export.name.is_empty())
            .filter(|export| !generator.baseline_path(binary, &export.name).is_file())
            .map(|export| {
                crate::verification_residue::uncovered_export_residue(binary, &export.name, now)
            })
            .collect();
        if !residue.is_empty() {
            self.record_unknown_residue(residue);
        }
    }

    /// File (or re-file) the batch's per-binary unknown ledger,
    /// `re/unknowns/<binary identity>.json` (issue #369).
    ///
    /// The current derived set — every record the batch's producers have
    /// admitted so far, the folds' facet admissions and the seam report's
    /// unavailable families — merges through the shared
    /// [`UnknownLedger::file`](calxgloss_types::UnknownLedger::file)
    /// revision doctrine against the landed document: a re-run lands the
    /// same ids, a revision bumps only when a persisted field actually
    /// changed, and a reviewer's reopen mark fires exactly once. The
    /// document is replaced outright, so it is always the current derived
    /// set, never an append log — a source slot that stops deriving
    /// simply stops landing.
    ///
    /// The reviewer's resolutions document feeds the merge and is never
    /// touched: it is read here, and a corrupt or absent one reads as no
    /// reopen marks — the reviewer's own artifact, whose trouble never
    /// stops a batch. The pipeline's own landed ledger is different: an
    /// unreadable one fails the write loudly rather than guess past the
    /// document this write replaces. A batch whose folds never read a
    /// document files nothing — the ledger's absence reads as *unknown*
    /// (ADR-0053's absent-field rule), and filing a nothing nobody looked
    /// at would be the dishonest known-and-none.
    pub(super) fn file_unknown_ledger(&self, binary: &str) -> Result<()> {
        let Some(workspace) = self.workspace.as_ref() else {
            // No workspace configured: nowhere to file, nothing read.
            return Ok(());
        };
        let derived = self
            .unknown_residue
            .lock()
            .expect("unknown residue lock")
            .clone();
        let Some(derived) = derived else {
            return Ok(());
        };
        let identity = calxgloss_types::BinaryIdentity::new(binary);
        let landed = match calxgloss_types::load_json::<calxgloss_types::UnknownLedger>(
            &calxgloss_types::unknown_ledger_path(workspace, &identity),
        ) {
            Ok(ledger) => Some(ledger),
            Err(calxgloss_types::PersistError::NotFound { .. }) => None,
            Err(source) => {
                return Err(TranslatorError::UnknownLedger {
                    binary: binary.to_string(),
                    source,
                });
            }
        };
        let reopened = match calxgloss_types::load_json::<calxgloss_types::UnknownResolutions>(
            &calxgloss_types::unknown_resolutions_path(workspace),
        ) {
            Ok(resolutions) => resolutions.reopened,
            Err(calxgloss_types::PersistError::NotFound { .. }) => Default::default(),
            Err(e) => {
                debug!(
                    binary,
                    error = %e,
                    "The reviewer's unknown resolutions are unreadable; \
                     filing the ledger without reopen marks"
                );
                Default::default()
            }
        };
        let ledger = calxgloss_types::UnknownLedger::file(
            identity.clone(),
            landed.as_ref(),
            &derived,
            &reopened,
            calxgloss_types::scan::now_unix_secs(),
        );
        calxgloss_types::save_json(
            &calxgloss_types::unknown_ledger_path(workspace, &identity),
            &ledger,
        )
        .map_err(|source| TranslatorError::UnknownLedger {
            binary: binary.to_string(),
            source,
        })
    }
}
