//! Provenance shared by every per-binary scan artifact.
//!
//! The recovery and inference engines each persist a per-binary JSON document
//! that doubles as a cache. The part a consumer reads when deciding whether
//! that cache is still good — which binary it describes and when it was built —
//! is the same shape everywhere, so it lives here rather than being restated
//! in each engine crate.

use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

/// Provenance of the scan that produced a per-binary artifact.
///
/// A persisted artifact doubles as a cache, and this is the part a consumer
/// reads when deciding whether the cache is still good: which binary it
/// describes and when it was built. The persistor names the JSON file after
/// [`binary`](Self::binary).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanMetadata {
    /// The binary the scan read, e.g. `eqmain.dll`.
    pub binary: String,
    /// When the scan finished, as a Unix timestamp in seconds.
    pub scanned_at: u64,
    /// Wall-clock duration of the scan, in seconds.
    #[serde(default)]
    pub duration_secs: u64,
}

impl ScanMetadata {
    /// Metadata for a scan of `binary` finishing now. The engine fills in
    /// [`duration_secs`](Self::duration_secs) once the scan is done.
    pub fn new(binary: impl Into<String>) -> Self {
        Self {
            binary: binary.into(),
            scanned_at: now_unix_secs(),
            duration_secs: 0,
        }
    }
}

/// The current time as a Unix timestamp in seconds, `0` if the clock predates
/// the epoch.
pub fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_metadata_new_stamps_the_current_time() {
        let meta = ScanMetadata::new("eqmain.dll");
        assert_eq!(meta.binary, "eqmain.dll");
        assert!(meta.scanned_at > 0);
        assert_eq!(meta.duration_secs, 0);
    }

    #[test]
    fn scan_metadata_serde_round_trips() {
        let meta = ScanMetadata {
            binary: "eqmain.dll".into(),
            scanned_at: 1_759_488_000,
            duration_secs: 12,
        };
        let json = serde_json::to_string(&meta).unwrap();
        let back: ScanMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(back, meta);
    }
}
