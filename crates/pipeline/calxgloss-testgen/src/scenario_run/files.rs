//! The scenario run's filesystem seam: snapshot the declared observation
//! paths on both sides of the run and classify how each changed.
//!
//! The standing rule: files are compared by content, not by existence.
//! The content identity a comparator weighs is the whole-file sha256 plus
//! the 4 KiB block digests of the same bytes, so a partial write shows
//! exactly which blocks moved.

use std::io::ErrorKind;
use std::path::Path;

use calxgloss_types::{FileChange, FileObservation};
use sha2::{Digest as _, Sha256};
use tracing::warn;

/// The block size the partial-write comparison works in.
const BLOCK_SIZE: usize = 4096;

/// One file's content identity: size, whole-file digest, and the in-order
/// digests of its 4 KiB blocks (the last block the short remainder).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ContentIdentity {
    pub(super) size_bytes: u64,
    pub(super) sha256: String,
    pub(super) block_hashes: Vec<String>,
}

/// Read one file's content identity; `None` when the path is not a file.
/// A present-but-unreadable path is stated by name in the log and reads
/// as no side — the capture never invents an identity it could not read.
pub(super) fn content_identity(path: &Path) -> Option<ContentIdentity> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == ErrorKind::NotFound => return None,
        Err(error) => {
            warn!(path = %path.display(), error = %error, "observation path could not be read");
            return None;
        }
    };
    let block_hashes = bytes
        .chunks(BLOCK_SIZE)
        .map(|block| {
            let mut hasher = Sha256::new();
            hasher.update(block);
            hex_digest(&hasher.finalize())
        })
        .collect();
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    Some(ContentIdentity {
        size_bytes: bytes.len() as u64,
        sha256: hex_digest(&hasher.finalize()),
        block_hashes,
    })
}

/// Snapshot every declared observation path under the run dir, in
/// declaration order.
pub(super) fn snapshot_paths(run_dir: &Path, declared: &[String]) -> Vec<Option<ContentIdentity>> {
    declared
        .iter()
        .map(|path| content_identity(&run_dir.join(path)))
        .collect()
}

/// Classify each declared path across the two snapshots. A path standing
/// on neither side is still one honest entry: unchanged, naming no side.
pub(super) fn classify_paths(
    declared: &[String],
    before: &[Option<ContentIdentity>],
    after: &[Option<ContentIdentity>],
) -> Vec<FileObservation> {
    declared
        .iter()
        .zip(before)
        .zip(after)
        .map(|((path, was), now)| {
            let (change, named_side) = match (was, now) {
                (None, Some(after)) => (FileChange::Created, Some(after)),
                (Some(before), None) => (FileChange::Deleted, Some(before)),
                (Some(before), Some(after)) => {
                    if before.sha256 == after.sha256 {
                        (FileChange::Unchanged, Some(after))
                    } else {
                        (FileChange::Modified, Some(after))
                    }
                }
                (None, None) => (FileChange::Unchanged, None),
            };
            FileObservation {
                path: path.clone(),
                change,
                size_bytes: named_side.map(|side| side.size_bytes),
                sha256: named_side.map(|side| side.sha256.clone()),
                block_hashes: named_side
                    .map(|side| side.block_hashes.clone())
                    .unwrap_or_default(),
            }
        })
        .collect()
}

pub(super) fn hex_digest(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
