//! This seam reads the patch documents behind the unit detail and the
//! attempt surfaces (issue #463). The pipeline and the patch actions file
//! them under `re/patches/{binary}/{function}/v{attempt}.json` as the
//! retained attempt history. Each handler used to walk to those documents
//! by hand, with its own path guess and its own corrupt-file policy that
//! silently dropped unreadable documents. Through the reader there is one
//! walk: the binary directory matches case-insensitively like every other
//! review comparison, a missing directory reads as no attempts at all, and
//! a document that cannot be read or parsed returns as a fault naming that
//! document.

use super::*;

impl ReviewSurfaceReader {
    /// Every patch document this unit owns, sorted by attempt number. A
    /// missing `re/patches` directory or a missing unit directory reads as no
    /// documents: the attempt was never filed. A document that cannot be read
    /// or parsed comes back as a fault naming it. The reader drops no filed
    /// attempt on the floor.
    pub(crate) fn patch_records(&self, unit: &UnitOfWork) -> Result<Vec<PatchRecord>, ServerError> {
        let Some(function) = unit.function.as_deref() else {
            return Ok(Vec::new());
        };
        let patches = self.repo_path.join("re").join("patches");
        let Ok(binary_dirs) = std::fs::read_dir(&patches) else {
            return Ok(Vec::new());
        };
        let mut records = Vec::new();
        for dir in binary_dirs.flatten() {
            let dir_name = dir.file_name().to_string_lossy().into_owned();
            if !binary_matches(&dir_name, unit.binary.as_str()) {
                continue;
            }
            let Ok(files) = std::fs::read_dir(dir.path().join(function)) else {
                continue;
            };
            for file in files.flatten() {
                let name = file.file_name().to_string_lossy().into_owned();
                if !name.ends_with(".json") {
                    continue;
                }
                let path = file.path();
                let text = std::fs::read_to_string(&path).map_err(|source| {
                    unreadable_patch_document(PersistError::Io {
                        path: path.clone(),
                        source,
                    })
                })?;
                let record = serde_json::from_str::<PatchRecord>(&text).map_err(|source| {
                    unreadable_patch_document(PersistError::Json { path, source })
                })?;
                records.push(record);
            }
        }
        records.sort_by_key(|record| record.attempt);
        Ok(records)
    }

    /// The unit detail's attempt history: this unit's patch documents rendered
    /// as [`AttemptRecord`]s in attempt order. A document with no compilation
    /// errors reads as compiled. The failure list stands in for pass counts,
    /// because no writer ever persisted those. This is the same rendering the
    /// unit-detail handler produced from these documents by hand. A corrupt
    /// document returns the same named fault [`Self::patch_records`] gives.
    pub(crate) fn attempt_history(
        &self,
        unit: &UnitOfWork,
    ) -> Result<Vec<AttemptRecord>, ServerError> {
        let records = self.patch_records(unit)?;
        Ok(records
            .into_iter()
            .map(|record| AttemptRecord {
                attempt: record.attempt,
                compiled: record.compilation_errors.is_empty(),
                compilation_errors: record.compilation_errors,
                tests_passed: 0,
                tests_total: record.test_failures.len(),
                failed_tests: record.test_failures,
                commit_hash: record.commit_hash,
                committed_at: record.committed_at,
            })
            .collect())
    }
}

/// A server fault naming the one patch document that failed, worded through
/// the shared persistence vocabulary: `PersistError`'s own message carries
/// the document's full path, so the fault names the document it could not
/// read (issue #463).
fn unreadable_patch_document(fault: PersistError) -> ServerError {
    ServerError::internal(&format!("the unit's patch records are unreadable: {fault}"))
}
