//! Provenance shared by every per-binary scan artifact.
//!
//! The recovery and inference engines each persist a per-binary JSON document
//! that doubles as a cache. The part a consumer reads when deciding whether
//! that cache is still good — which binary it describes, when it was built,
//! and which engine produced it — is the same shape everywhere, so it lives
//! here rather than being restated in each engine crate.

use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

/// The decompiler engine that produced a scan, named by the source the
/// scan read through.
///
/// A `kuna` scan names its engine, its pinned release, and the source
/// fingerprint of that pin, so a reviewer can tell what produced any
/// decompilation in the record and re-create or blame it (issue #208).
/// The Ghidra path names nothing: its records predate the field and stay
/// byte-for-byte what they were.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EngineProvenance {
    /// The engine's name, e.g. `kuna`.
    pub name: String,
    /// The engine's release, e.g. the pinned Kuna tag `v1.878`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// The pinned engine source the build came from — the commit the
    /// dependency resolves to, e.g. `cb68db1`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
}

/// Provenance of the scan that produced a per-binary artifact.
///
/// A persisted artifact doubles as a cache, and this is the part a consumer
/// reads when deciding whether the cache is still good: which binary it
/// describes, when it was built, and — for a scan whose source names its
/// engine — which engine and pin produced it. The persistor names the JSON
/// file after [`binary`](Self::binary).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanMetadata {
    /// The binary the scan read, e.g. `eqmain.dll`.
    pub binary: String,
    /// When the scan finished, as a Unix timestamp in seconds.
    pub scanned_at: u64,
    /// Wall-clock duration of the scan, in seconds.
    #[serde(default)]
    pub duration_secs: u64,
    /// The engine that produced the scan, when its source names one.
    ///
    /// The engine stamps this from the scan source's `engine_provenance`
    /// read on the `ScanSource` seam — a `kuna` scan names its engine,
    /// pinned release, and source fingerprint beside the timing (issue
    /// #208). The Ghidra path names nothing, so the key stays absent from
    /// its JSON and Ghidra records are byte-for-byte what they were.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub engine: Option<EngineProvenance>,
}

impl ScanMetadata {
    /// Metadata for a scan of `binary` finishing now, naming no engine.
    /// The engine fills in [`duration_secs`](Self::duration_secs) once the
    /// scan is done, and [`engine`](Self::engine) from what its source names.
    pub fn new(binary: impl Into<String>) -> Self {
        Self {
            binary: binary.into(),
            scanned_at: now_unix_secs(),
            duration_secs: 0,
            engine: None,
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
        assert_eq!(meta.engine, None, "a fresh stamp names no engine yet");
    }

    #[test]
    fn scan_metadata_serde_round_trips() {
        let meta = ScanMetadata {
            binary: "eqmain.dll".into(),
            scanned_at: 1_759_488_000,
            duration_secs: 12,
            engine: None,
        };
        let json = serde_json::to_string(&meta).unwrap();
        let back: ScanMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(back, meta);
    }

    #[test]
    fn a_kuna_record_names_its_engine_release_and_pin() {
        // The issue's acceptance line: a scan record under `kuna` carries
        // engine name, Kuna version, and pinned source fingerprint, and
        // the whole provenance reads back off disk.
        let meta = ScanMetadata {
            binary: "eqmain.dll".into(),
            scanned_at: 1_759_488_000,
            duration_secs: 12,
            engine: Some(EngineProvenance {
                name: "kuna".into(),
                version: Some("v1.878".into()),
                fingerprint: Some("cb68db1".into()),
            }),
        };
        let json = serde_json::to_string(&meta).unwrap();
        let back: ScanMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(back, meta);
        let named = back.engine.expect("the record names its engine");
        assert_eq!(named.name, "kuna");
        assert_eq!(named.version.as_deref(), Some("v1.878"));
        assert_eq!(named.fingerprint.as_deref(), Some("cb68db1"));
    }

    #[test]
    fn a_record_from_an_unnaming_source_omits_the_engine_key() {
        // Ghidra scan records are unchanged: a metadata that names no
        // engine serializes exactly as it did before the field existed,
        // and a document written before it loads with the engine absent.
        let meta = ScanMetadata {
            binary: "eqmain.dll".into(),
            scanned_at: 1_759_488_000,
            duration_secs: 12,
            engine: None,
        };
        let json = serde_json::to_string(&meta).unwrap();
        assert!(!json.contains("engine"), "no engine key: {json}");
        let back: ScanMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(back.engine, None);
    }
}
