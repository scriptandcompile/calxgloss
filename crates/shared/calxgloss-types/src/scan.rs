//! Provenance and coverage shared by every per-binary scan artifact.
//!
//! The recovery and inference engines each persist a per-binary JSON document
//! that doubles as a cache. The part a consumer reads when deciding whether
//! that cache is still good — which binary it describes, when it was built,
//! and which engine produced it — is the same shape everywhere, so it lives
//! here rather than being restated in each engine crate. The other half of
//! that shape says what the scan examined and what it could not: a coverage
//! record beside the provenance, so an engine that looked and found nothing
//! never reads like one that saw nothing (track P19, issue #344).

use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::display_serde_label;

/// The decompiler engine that produced a scan, named by the source the
/// scan read through.
///
/// Kuna is the only engine (issue #214), and a scan names it, its pinned
/// release, and the source fingerprint of that pin, so a reviewer can tell
/// what produced any decompilation in the record and re-create or blame it
/// (issue #208). Artifacts written before the field existed carry no
/// provenance, so the field stays optional on read.
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

/// How far a scan got on one facet of its picture — the closed set an
/// engine stamps about its own work.
///
/// Facets are engine-declared (each scan crate owns the roster of its own
/// facet ids), and every coverage entry names its facet's state with one of
/// these four labels. The serde labels are the persisted wire format under
/// the coverage record, so they are a compatibility contract. There is
/// deliberately no `unknown` here: an engine admits `partial`, `unavailable`
/// or `unexamined` about its own scan, and the `unknown` a pre-coverage
/// document reads as is derived at read time
/// ([`EffectiveCoverage::Unknown`]), never written (issue #345).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoverageStatus {
    /// The facet was examined end to end: silence about it means absent.
    Complete,
    /// The facet was examined only partway; what the scan could not reach
    /// rides the entry's own limitation line.
    Partial,
    /// The facet could not be examined on this target at all — the evidence
    /// for it was not there to read.
    Unavailable,
    /// The scan never attempts this facet; it sits outside what the engine
    /// was built to examine.
    Unexamined,
}

display_serde_label!(CoverageStatus {
    Complete => "complete",
    Partial => "partial",
    Unavailable => "unavailable",
    Unexamined => "unexamined",
});

/// A read-side coverage status: the four writable statuses plus `unknown`.
///
/// This is what every consumer of a scan document branches on. `Unknown` is
/// the derived default of a document written before the coverage record
/// shipped — the field's own absence admitting it, the same graceful
/// degradation the engine-provenance field on this module already
/// practices. Because `Unknown` lives only on this read-side enum and never
/// on [`CoverageStatus`], no engine can stamp it about its own scan, and an
/// absent record can never be mistaken for a `complete` one (issue #345).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EffectiveCoverage {
    /// The document's coverage record claims the picture was examined end to
    /// end.
    Complete,
    /// The document's coverage record admits its picture was examined only
    /// partway.
    Partial,
    /// The document's coverage record says a facet could not be examined on
    /// this target.
    Unavailable,
    /// The document's coverage record says the engine never attempts the
    /// facet.
    Unexamined,
    /// The document carries no coverage record — written before the field
    /// shipped — so what the scan examined is unknown, and its silence
    /// establishes nothing either way.
    Unknown,
}

impl From<CoverageStatus> for EffectiveCoverage {
    fn from(status: CoverageStatus) -> Self {
        match status {
            CoverageStatus::Complete => Self::Complete,
            CoverageStatus::Partial => Self::Partial,
            CoverageStatus::Unavailable => Self::Unavailable,
            CoverageStatus::Unexamined => Self::Unexamined,
        }
    }
}

/// One engine-declared facet's coverage entry: which facet, how far the
/// scan got, and — when it fell short — a plain sentence saying so.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FacetCoverage {
    /// The engine's own facet id, a stable machine-comparable string (e.g.
    /// `delay-imports`) drawn from the engine's declared roster.
    pub id: String,
    /// How far this scan got on the facet.
    pub status: CoverageStatus,
    /// A human-readable limitation line, present only when there is
    /// something to admit. Free text belongs here and nowhere else: ids and
    /// statuses stay structured.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limitation: Option<String>,
}

/// The document-level coverage record a scan files beside its provenance:
/// what the scan examined and what it could not, in one shared shape every
/// consumer reads.
///
/// One record per scan document, holding the scan's overall verdict and its
/// per-facet entries. The entries keep the engine's own declared order and
/// survive write and read exactly — statuses, ids, order, and limitation
/// lines — so a report and a prompt render the same admission every time.
/// Provenance says who produced the document; this says what it examined:
/// the two halves of one envelope (issue #345).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanCoverage {
    /// What the scan says about its whole picture. An engine that examined
    /// everything says [`CoverageStatus::Complete`]; anything it skipped,
    /// could not reach, or never attempts lands lower.
    pub status: CoverageStatus,
    /// The engine's declared facets, in the engine's own order, with one
    /// entry per facet. A facet that needs no admission may carry an entry
    /// with no limitation line; a facet absent from the record was not
    /// declared at all.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub facets: Vec<FacetCoverage>,
}

/// Provenance and coverage of the scan that produced a per-binary artifact.
///
/// A persisted artifact doubles as a cache, and this is the part a consumer
/// reads when deciding whether the cache is still good: which binary it
/// describes, when it was built, and — for a scan whose source names its
/// engine — which engine and pin produced it, beside what that scan
/// examined and could not. The persistor names the JSON file after
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
    /// The engine that produced the scan, when its source names one.
    ///
    /// The engine stamps this from the scan source's `engine_provenance`
    /// read on the `ScanSource` seam — a Kuna scan names its engine,
    /// pinned release, and source fingerprint beside the timing (issue
    /// #208). Documents written before the field shipped carry no key and
    /// load with the engine absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub engine: Option<EngineProvenance>,
    /// What the scan examined and what it could not, when the engine states
    /// it.
    ///
    /// The engine stamps this at scan time, where the truth lives, beside
    /// the timing and the provenance. Documents written before the field
    /// shipped carry no key and load with coverage absent, which reads as
    /// [`EffectiveCoverage::Unknown`] — never as complete (see
    /// [`ScanMetadata::coverage_status`], issue #345).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coverage: Option<ScanCoverage>,
}

impl ScanMetadata {
    /// Metadata for a scan of `binary` finishing now, naming no engine and
    /// admitting no coverage yet. The engine fills in
    /// [`duration_secs`](Self::duration_secs) once the scan is done,
    /// [`engine`](Self::engine) from what its source names, and
    /// [`coverage`](Self::coverage) from what its scan examined — a fresh
    /// stamp defaults honestly, not to `complete`.
    pub fn new(binary: impl Into<String>) -> Self {
        Self {
            binary: binary.into(),
            scanned_at: now_unix_secs(),
            duration_secs: 0,
            engine: None,
            coverage: None,
        }
    }

    /// The coverage the document states, or [`EffectiveCoverage::Unknown`]
    /// when it states none.
    ///
    /// The read-side resolution every consumer branches on: a document
    /// written before coverage shipped admits nothing, so its coverage is
    /// unknown — the field's own absence admits it — and can never be read
    /// as examined-and-complete.
    pub fn coverage_status(&self) -> EffectiveCoverage {
        match &self.coverage {
            Some(coverage) => coverage.status.into(),
            None => EffectiveCoverage::Unknown,
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
        assert_eq!(meta.coverage, None, "a fresh stamp admits no coverage yet");
        assert_eq!(
            meta.coverage_status(),
            EffectiveCoverage::Unknown,
            "a fresh stamp defaults honestly, never to complete"
        );
    }

    #[test]
    fn scan_metadata_serde_round_trips() {
        let meta = ScanMetadata {
            binary: "eqmain.dll".into(),
            scanned_at: 1_759_488_000,
            duration_secs: 12,
            engine: None,
            coverage: None,
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
            coverage: None,
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
        // Pre-#208 records stay readable: a metadata that names no
        // engine serializes exactly as it did before the field existed,
        // and a document written before it loads with the engine absent.
        let meta = ScanMetadata {
            binary: "eqmain.dll".into(),
            scanned_at: 1_759_488_000,
            duration_secs: 12,
            engine: None,
            coverage: None,
        };
        let json = serde_json::to_string(&meta).unwrap();
        assert!(!json.contains("engine"), "no engine key: {json}");
        let back: ScanMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(back.engine, None);
    }

    // -- coverage envelope (P19, issue #345) -----------------------------

    /// A coverage record with one facet in each writable state, each
    /// limitation line where one belongs — the shared shape every engine
    /// fills in.
    fn admitted_coverage_fixture() -> ScanCoverage {
        ScanCoverage {
            status: CoverageStatus::Partial,
            facets: vec![
                FacetCoverage {
                    id: "imports".into(),
                    status: CoverageStatus::Complete,
                    limitation: None,
                },
                FacetCoverage {
                    id: "regions".into(),
                    status: CoverageStatus::Partial,
                    limitation: Some("two regions truncated at the per-function budget".into()),
                },
                FacetCoverage {
                    id: "vtables".into(),
                    status: CoverageStatus::Unavailable,
                    limitation: Some("the target yields no vtable evidence".into()),
                },
                FacetCoverage {
                    id: "delay-imports".into(),
                    status: CoverageStatus::Unexamined,
                    limitation: Some("the engine parses no delay imports".into()),
                },
            ],
        }
    }

    #[test]
    fn coverage_status_serde_round_trips_the_persisted_labels() {
        // The snake_case labels are the wire format under the coverage
        // record, so they are a compatibility contract like every other
        // closed set in this crate.
        let cases = [
            (CoverageStatus::Complete, r#""complete""#),
            (CoverageStatus::Partial, r#""partial""#),
            (CoverageStatus::Unavailable, r#""unavailable""#),
            (CoverageStatus::Unexamined, r#""unexamined""#),
        ];
        for (status, label) in cases {
            assert_eq!(serde_json::to_string(&status).expect("serializes"), label);
            let back: CoverageStatus =
                serde_json::from_str(label).expect("the persisted label deserializes");
            assert_eq!(back, status);
        }
    }

    #[test]
    fn display_re_emits_the_serde_label() {
        // Reports and prompts print the status word, and it must be the
        // exact word the document stores.
        for status in [
            CoverageStatus::Complete,
            CoverageStatus::Partial,
            CoverageStatus::Unavailable,
            CoverageStatus::Unexamined,
        ] {
            let label = serde_json::to_value(status).expect("serializes");
            assert_eq!(
                status.to_string(),
                label.as_str().expect("label is a string")
            );
        }
    }

    #[test]
    fn a_written_document_round_trips_its_coverage_exactly() {
        // Statuses, facet ids, order, and limitation lines all survive
        // write→read — the admission a report renders is the admission the
        // engine filed.
        let coverage = admitted_coverage_fixture();
        let meta = ScanMetadata {
            binary: "eqmain.dll".into(),
            scanned_at: 1_759_488_000,
            duration_secs: 12,
            engine: None,
            coverage: Some(coverage.clone()),
        };
        let json = serde_json::to_string(&meta).expect("serializes");
        let back: ScanMetadata = serde_json::from_str(&json).expect("deserializes");
        assert_eq!(back, meta);
        let back = back.coverage.expect("the record carries its coverage");
        assert_eq!(back.status, CoverageStatus::Partial);
        assert_eq!(
            back.facets
                .iter()
                .map(|f| f.id.as_str())
                .collect::<Vec<_>>(),
            ["imports", "regions", "vtables", "delay-imports"],
            "the engine's own facet order is preserved"
        );
        assert_eq!(
            back.facets.iter().map(|f| f.status).collect::<Vec<_>>(),
            [
                CoverageStatus::Complete,
                CoverageStatus::Partial,
                CoverageStatus::Unavailable,
                CoverageStatus::Unexamined,
            ]
        );
        assert_eq!(back.facets[0].limitation, None, "nothing to admit: no line");
        assert!(
            back.facets[1]
                .limitation
                .as_deref()
                .expect("a partial facet states its limit")
                .contains("truncated")
        );
        assert_eq!(
            back.facets[3].limitation.as_deref(),
            Some("the engine parses no delay imports")
        );
    }

    #[test]
    fn a_document_without_a_coverage_key_loads_and_reads_unknown() {
        // The fixture the whole track runs on: a pre-P19 artifact, written
        // before this field existed, loads without error — and its coverage
        // reads as unknown, never as complete. The field's own absence
        // admits it.
        let pre_p19 = r#"{"binary":"eqmain.dll","scanned_at":1759488000,"duration_secs":12}"#;
        let back: ScanMetadata =
            serde_json::from_str(pre_p19).expect("a pre-P19 document keeps loading");
        assert_eq!(back.binary, "eqmain.dll");
        assert_eq!(back.coverage, None, "the absent key loads as no record");
        assert_eq!(
            back.coverage_status(),
            EffectiveCoverage::Unknown,
            "absent coverage admits itself as unknown"
        );
        assert_ne!(
            back.coverage_status(),
            EffectiveCoverage::Complete,
            "unknown must never read as examined-and-absent"
        );
    }

    #[test]
    fn unknown_is_not_a_writable_status() {
        // The write-side set stays the four-valued closed set: `unknown`
        // has no variant in `CoverageStatus`, so a document — a facet entry
        // or a whole record — can never carry it. `unknown` exists only as
        // the derived read-side default.
        assert!(
            serde_json::from_str::<CoverageStatus>(r#""unknown""#).is_err(),
            "`unknown` is not a status an engine can stamp"
        );
        assert!(
            serde_json::from_str::<ScanCoverage>(r#"{"status":"unknown","facets":[]}"#).is_err(),
            "a coverage record cannot admit `unknown` about its own scan"
        );
        assert!(
            serde_json::from_str::<FacetCoverage>(r#"{"id":"imports","status":"unknown"}"#)
                .is_err(),
            "a facet entry cannot admit `unknown` either"
        );
    }

    #[test]
    fn a_fresh_stamp_writes_no_coverage_key() {
        // Until an engine fills in its admission, a metadata serializes
        // exactly as it did before the field existed, and those bytes load
        // back as unknown coverage — honest in both directions.
        let meta = ScanMetadata::new("eqmain.dll");
        let json = serde_json::to_string(&meta).expect("serializes");
        assert!(
            !json.contains("coverage"),
            "a stamp that admits nothing writes no coverage key: {json}"
        );
        let back: ScanMetadata = serde_json::from_str(&json).expect("deserializes");
        assert_eq!(back.coverage_status(), EffectiveCoverage::Unknown);
    }

    #[test]
    fn coverage_omits_the_facets_and_limitation_keys_when_it_has_nothing_to_admit() {
        // The complete-coverage rendering stays lean on disk: an empty
        // facet list and an absent limitation line write no keys, and the
        // bytes still load back exactly.
        let coverage = ScanCoverage {
            status: CoverageStatus::Complete,
            facets: vec![FacetCoverage {
                id: "imports".into(),
                status: CoverageStatus::Complete,
                limitation: None,
            }],
        };
        let json = serde_json::to_string(&coverage).expect("serializes");
        assert!(!json.contains("limitation"), "no line written: {json}");
        let back: ScanCoverage = serde_json::from_str(&json).expect("deserializes");
        assert_eq!(back, coverage);

        let empty = ScanCoverage {
            status: CoverageStatus::Unavailable,
            facets: vec![],
        };
        let json = serde_json::to_string(&empty).expect("serializes");
        assert!(!json.contains("facets"), "no entries: no key in {json}");
        let back: ScanCoverage = serde_json::from_str(&json).expect("deserializes");
        assert_eq!(back, empty);
    }
}
