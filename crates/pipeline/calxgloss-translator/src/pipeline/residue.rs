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
        let Some(mut derived) = derived else {
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
        // A record the record-and-replay fold named at capture time is
        // never silently dropped by a batch that does not re-derive it
        // (issue #396): the walk's residue closes by the source slot
        // disappearing from its own derivation, but a capture-origin record
        // is a named fact about one capture event — nothing in the walk
        // re-derives it, so it is carried into the derived set and stands
        // until its question closes. Content unchanged, the revision
        // doctrine keeps it un-numbered; only its last-seen refreshes.
        // The same carry holds for a verify run's receipt-unfiled record
        // (issue #415): the pair path it names is re-derived only by that
        // run itself, so a walk that never breaks its own filing must not
        // erase the admitted unknown one broken run left behind.
        if let Some(landed_doc) = landed.as_ref() {
            for record in landed_doc.records.iter().flatten() {
                if matches!(
                    record.origin,
                    calxgloss_types::UnknownOrigin::Capture { .. }
                        | calxgloss_types::UnknownOrigin::VerifyRun { .. }
                ) && !derived.iter().any(|mine| mine.id == record.id)
                {
                    derived.push(record.clone());
                }
            }
        }
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

    /// File (or re-file) the batch's per-binary obligation ledger,
    /// `re/obligations/<binary identity>.json` (issue #422, P26.6).
    /// The roster is the analysis record's own export listing: every
    /// named export stands as an obligation, in the listing's order,
    /// and the filing stamps the disposition that the batch's current
    /// state honestly shows.
    ///
    /// The roster comes from the listing, never the queue, so an export
    /// that never entered work still stands open. An export listing
    /// that never came back reads *unknown*: the filing writes nothing,
    /// and the ledger's absence keeps the honest reading — the same
    /// rule the export-coverage check above applies. A listing that
    /// names nothing files a sealed empty roster, a known-and-none
    /// fact that the reader itself reads as proving nothing.
    ///
    /// The filing joins the live state documents and keeps the
    /// precedence the conformance reader applies at read time (issue
    /// #420): classification parking first, then the batch's skip set,
    /// then a standing unit override record, then the P21 verification
    /// signal's fact — "no filed baseline document covers the export".
    /// The filing re-checks that fact against the baseline documents on
    /// disk, so an export a later batch covers moves off *no-baseline*;
    /// a stale record never pins an honest stamp to the ledger. With
    /// none of those standing the entry holds *un-reviewed*: no Accept
    /// action stands.
    ///
    /// No pipeline entry claims *claimed-verified*. Only a reader that
    /// can cite the attempt branch's filed receipt pair may claim
    /// green, and the batch cannot resolve that citation — so every
    /// entry this filing writes carries attempt 0, no owner commit, and
    /// no receipt citation. The filing also never copies the parking's
    /// reason or the skip record's wording into an entry: the reader
    /// joins those documents beside the ledger, and one fact lives in
    /// exactly one file.
    ///
    /// The filing replaces the previous document outright: the roster
    /// is always the current state, never an append log. The closure
    /// digest seals the filed entries, so successive batches over
    /// unchanged records seal the same digest, and every reader
    /// re-derives it from the filed bytes (issue #417's read contract).
    pub(super) async fn file_obligation_ledger(&self, binary: &str) -> Result<()> {
        let Some(workspace) = self.workspace.as_deref() else {
            // No workspace configured: nowhere to look, nowhere to file.
            return Ok(());
        };
        let exports = match self.scan_source().exports().await {
            Ok(exports) => exports,
            Err(source) => {
                warn!(
                    binary,
                    error = %source,
                    "The export listing never came back — the obligation ledger \
                     reads unknown and files nothing"
                );
                return Ok(());
            }
        };
        let parked = classification_parks_binary(workspace, binary);
        // The run's own shared control handles read the persisted scope
        // and override records, corrupt-record leniency and all: the
        // filing consults the same documents, by the same key rules,
        // that queue selection steered itself by this batch.
        let scope = calxgloss_types::ScopeControl::open(workspace).scope();
        let overrides = calxgloss_types::OverrideControl::open(workspace);
        let generator = TestGenerator::new(workspace);
        let entries: Vec<calxgloss_types::ObligationEntry> = exports
            .iter()
            .filter(|export| !export.name.is_empty())
            .map(|export| {
                let disposition = if parked {
                    calxgloss_types::ObligationDisposition::Parked
                } else if scope.is_skipped(binary, &export.name)
                    || overrides.is_skipped(binary, &export.name)
                {
                    calxgloss_types::ObligationDisposition::Skipped
                } else if overrides.get(binary, &export.name).is_some() {
                    calxgloss_types::ObligationDisposition::Overridden
                } else if !generator.baseline_path(binary, &export.name).is_file() {
                    // The P21 signal's fact, current at filing time: an
                    // export no baseline document on disk covers was
                    // never exercised. The filing re-checks the live
                    // documents rather than a filed record, so a later
                    // batch's covering moves this entry.
                    calxgloss_types::ObligationDisposition::NoBaseline
                } else {
                    calxgloss_types::ObligationDisposition::UnReviewed
                };
                // Attempt 0 with no owner commit and no citation: the
                // entry makes no green claim, and an honest hold names
                // the state it stands on.
                calxgloss_types::ObligationEntry::new(
                    export.name.clone(),
                    0,
                    String::new(),
                    disposition,
                )
            })
            .collect();
        let identity = calxgloss_types::BinaryIdentity::new(binary);
        let path = calxgloss_types::obligation_ledger_path(workspace, &identity);
        // Sealing the digest is the serialization of the very document
        // the filing is about to write: when it fails, the filing names
        // the path it could not produce, the way a write failure names
        // the path it could not reach.
        let ledger = calxgloss_types::ObligationLedger::file(
            identity,
            entries,
            calxgloss_types::scan::now_unix_secs(),
        )
        .map_err(|source| TranslatorError::ObligationLedger {
            binary: binary.to_string(),
            source: calxgloss_types::PersistError::Json {
                path: path.clone(),
                source: serde_json::Error::io(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    source,
                )),
            },
        })?;
        calxgloss_types::save_json(&path, &ledger).map_err(|source| {
            TranslatorError::ObligationLedger {
                binary: binary.to_string(),
                source,
            }
        })
    }
}

/// Whether the binary's in-force classification parks it (issue
/// #422). The check reads the same two documents the dashboard's
/// parked map builds from (issue #235): the parked set starts at the
/// binary's classification record, so an unclassified binary parks
/// nothing and an override alone never parks. Where a record stands,
/// the operator's classification override record wins over the
/// record's own category, and only a `DotNetManaged` category parks.
/// A record that fails to parse declares no category, like every
/// lenient read of that artifact; the filing never parks a binary on
/// a guess.
fn classification_parks_binary(workspace: &std::path::Path, binary: &str) -> bool {
    // The classify command's own file-name sanitization: the binary
    // name verbatim, with path separators folded to underscores.
    let sanitized: String = binary
        .chars()
        .map(|c| match c {
            '/' | '\\' => '_',
            other => other,
        })
        .collect();
    let path = workspace
        .join("re")
        .join("classify")
        .join(format!("{sanitized}.json"));
    if !path.is_file() {
        // No classification record: the dashboard parks no units for
        // this binary either, and the filing agrees with the reader.
        return false;
    }
    // The classify command writes the category as its serde spelling —
    // the variant name — so the parked check deserializes that one
    // field through DllCategory rather than binding the whole record.
    // Like every lenient read of that artifact, an unreadable record
    // declares nothing.
    let record_category = std::fs::read_to_string(&path)
        .ok()
        .and_then(|content| serde_json::from_str::<serde_json::Value>(&content).ok())
        .and_then(|record| record.get("category").cloned())
        .and_then(|category| serde_json::from_value::<calxgloss_types::DllCategory>(category).ok());
    let override_category = calxgloss_types::load_json::<calxgloss_types::ClassificationOverrides>(
        &calxgloss_types::classification_override_records_path(workspace),
    )
    .ok()
    .and_then(|overrides| {
        overrides
            .overrides
            .get(binary)
            .map(|record| record.category.clone())
    });
    override_category
        .or(record_category)
        .is_some_and(|category| category == calxgloss_types::DllCategory::DotNetManaged)
}
