//! The per-binary scenario status on the review surfaces (issue #409,
//! P24.8): the EXE-level evidence a review reads beside the unit queue.
//!
//! One derived join serves every reader, the way
//! [`audit`](super::audit) does for the unknown ledger. The pipeline's
//! scenario documents — the contract set at `re/scenarios/<binary>.json`,
//! the filed captures under `re/scenarios/captures/`, and the filed
//! verdicts under `re/scenarios/verdicts/` — join at read time into a
//! [`ScenarioStatus`] per scenario name per target binary. The terminal
//! dashboard renders the section from these lines, and the web review API
//! serves the same model through `ReviewDashboard`.

use std::collections::BTreeMap;
use std::path::Path;

use calxgloss_types::{
    BinaryScenarioStatus, DimensionVerdict, ScenarioCapture, ScenarioContracts, ScenarioStatus,
    ScenarioVerdictDocument, ScenarioVerdictReading, scenario_captures_dir, scenario_contracts_dir,
    scenario_file_key, scenario_verdicts_dir,
};

/// The review reading of one filed verdict document: any dimension
/// assessed fail makes the verdict an assessed fail naming every failed
/// dimension in the comparator's order (terminal, interaction, exit,
/// filesystem, process); all five assessed pass is the only assessed
/// pass; everything else — any dimension silent, every dimension silent —
/// reads unassessed, because silence never renders as a pass.
fn verdict_reading(document: &ScenarioVerdictDocument) -> ScenarioVerdictReading {
    let dimensions = [
        ("terminal", document.verdict.terminal),
        ("interaction", document.verdict.interaction),
        ("exit", document.verdict.exit),
        ("filesystem", document.verdict.filesystem),
        ("process", document.verdict.process),
    ];
    let failed: Vec<String> = dimensions
        .iter()
        .filter(|(_, verdict)| *verdict == DimensionVerdict::AssessedFail)
        .map(|(name, _)| (*name).to_string())
        .collect();
    if !failed.is_empty() {
        return ScenarioVerdictReading::AssessedFail {
            failed_dimensions: failed,
        };
    }
    if dimensions
        .iter()
        .all(|(_, verdict)| *verdict == DimensionVerdict::AssessedPass)
    {
        ScenarioVerdictReading::AssessedPass
    } else {
        ScenarioVerdictReading::Unassessed
    }
}

/// The header the review surfaces print above the per-binary scenario
/// status lines (issue #409).
pub fn scenario_status_header() -> String {
    "  Scenario status — EXE targets".to_string()
}

/// One binary's scenario-status lines, shared byte-for-byte by every
/// reader of the section (issue #409). Every scenario named by the filed
/// documents gets its own line with its three slot readings spelled out
/// — declared or not-declared, captured or not-captured, assessed pass,
/// assessed fail naming each failed dimension, or unassessed. No reading
/// is ever folded into a per-binary aggregate, and no line ever renders a
/// missing record as a success.
pub fn scenario_status_lines(status: &BinaryScenarioStatus) -> Vec<String> {
    let mut lines = vec![format!("  {}", status.binary)];
    for scenario in &status.scenarios {
        let verdict = match &scenario.verdict {
            ScenarioVerdictReading::AssessedPass => "assessed pass".to_string(),
            ScenarioVerdictReading::AssessedFail { failed_dimensions } => {
                format!("assessed fail ({})", failed_dimensions.join(", "))
            }
            ScenarioVerdictReading::Unassessed => "unassessed".to_string(),
        };
        let declared = if scenario.declared {
            "declared"
        } else {
            "not declared"
        };
        let captured = if scenario.captured {
            "captured"
        } else {
            "not captured"
        };
        lines.push(format!(
            "    • {} — {declared}, {captured}, {verdict}",
            scenario.scenario
        ));
    }
    lines
}

/// Every `*.json` document filed in one scenario directory, parsed where it
/// parses: the path, its file stem, and the document when it read. An
/// unreadable document is named on stderr beside the slot it leaves
/// unproven, never dropped in silence — the slot then degrades to its
/// honest negative like any missing record.
fn filed_documents<T: serde::de::DeserializeOwned>(
    dir: &Path,
    kind: &str,
    slot: &str,
) -> Vec<(std::path::PathBuf, String, Option<T>)> {
    let mut filed = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
                continue;
            }
            let Some(stem) = path
                .file_stem()
                .and_then(|stem| stem.to_str())
                .map(str::to_string)
            else {
                continue;
            };
            match calxgloss_types::load_json::<T>(&path) {
                Ok(document) => filed.push((path, stem, Some(document))),
                Err(err) => eprintln!(
                    "  [scenarios] {}: {kind} document unreadable, nothing reads as {slot}: {err}",
                    path.display()
                ),
            }
        }
    }
    filed
}

/// Derive the scenario status per target binary straight from the filed
/// documents. A missing document degrades its slot to the honest negative
/// — no contract renders not-declared, no capture renders not-captured,
/// no verdict renders unassessed — and an unreadable document degrades
/// the same way with a named warning, never into a laundered reading.
pub fn derive_scenario_statuses(workspace: &Path) -> Vec<BinaryScenarioStatus> {
    // Binary → scenario name → the slot reading, BTreeMaps so binaries
    // and scenarios both land in name order without a second sort.
    let mut by_binary: BTreeMap<String, BTreeMap<String, ScenarioStatus>> = BTreeMap::new();
    fn slot<'a>(
        by_binary: &'a mut BTreeMap<String, BTreeMap<String, ScenarioStatus>>,
        binary: &str,
        scenario: &str,
    ) -> &'a mut ScenarioStatus {
        by_binary
            .entry(binary.to_string())
            .or_default()
            .entry(scenario.to_string())
            .or_insert_with(|| ScenarioStatus {
                scenario: scenario.to_string(),
                declared: false,
                captured: false,
                verdict: ScenarioVerdictReading::Unassessed,
            })
    }

    // The declared slot: one contract document per target binary, named
    // by the binary identity itself; the envelope must speak for its own
    // binary, the same gate the CLI's reads face.
    for (path, stem, document) in filed_documents::<ScenarioContracts>(
        &scenario_contracts_dir(workspace),
        "contract",
        "declared",
    ) {
        let Some(documents) = document else { continue };
        if documents.binary.as_str() != stem.as_str() {
            eprintln!(
                "  [scenarios] {}: contract document speaks for {}, not {stem} — skipped",
                path.display(),
                documents.binary
            );
            continue;
        }
        for name in documents.scenarios.keys() {
            slot(&mut by_binary, &stem, name).declared = true;
        }
    }

    // The captured slot: the captures tree names the binary in its file
    // envelope, `<binary>-<scenario key>[-replay].json`, while the capture
    // document itself carries only the scenario name — so the key fold,
    // recomputable from the document's own name, is peeled off the
    // envelope to recover the binary. The exact-name reading is tried
    // first, so a scenario genuinely named `boot-replay` stays itself
    // rather than reading as a replay of `boot`. An envelope that
    // disagrees with the document's name is named and skipped, never
    // guessed at.
    for (path, stem, document) in
        filed_documents::<ScenarioCapture>(&scenario_captures_dir(workspace), "capture", "captured")
    {
        let Some(document) = document else { continue };
        let key = scenario_file_key(&document.scenario);
        let binary = stem
            .strip_suffix(&format!("-{key}"))
            .or_else(|| stem.strip_suffix(&format!("-{key}-replay")))
            .filter(|binary| !binary.is_empty());
        let Some(binary) = binary else {
            eprintln!(
                "  [scenarios] {}: capture document for scenario '{}' is not \
                 enveloped under its own name — skipped",
                path.display(),
                document.scenario
            );
            continue;
        };
        slot(&mut by_binary, binary, &document.scenario).captured = true;
    }

    // The verdict slot: one current verdict document per (binary, scenario
    // name), each naming its binary and scenario inside the document. The
    // envelope is checked against those names — an envelope speaking for
    // another pair is named and skipped, the same gate a contract faces.
    for (path, stem, document) in filed_documents::<ScenarioVerdictDocument>(
        &scenario_verdicts_dir(workspace),
        "verdict",
        "assessed",
    ) {
        let Some(document) = document else { continue };
        let envelope = format!(
            "{}-{}",
            document.binary,
            scenario_file_key(&document.scenario)
        );
        if stem != envelope {
            eprintln!(
                "  [scenarios] {}: verdict document for {} / '{}' stands under \
                 the envelope '{stem}' — skipped",
                path.display(),
                document.binary,
                document.scenario
            );
            continue;
        }
        slot(&mut by_binary, document.binary.as_str(), &document.scenario).verdict =
            verdict_reading(&document);
    }

    by_binary
        .into_iter()
        .map(|(binary, scenarios)| BinaryScenarioStatus {
            binary,
            scenarios: scenarios.into_values().collect(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use calxgloss_types::scenario_contracts_path;
    use serde_json::json;

    use super::*;

    /// Declare (or add to) the filed contract document, the way
    /// `scenario declare` keeps exactly one current contract per
    /// scenario name in one document per binary.
    fn file_contract(workspace: &std::path::Path, binary: &str, scenario: &str) {
        let path =
            scenario_contracts_path(workspace, &calxgloss_types::BinaryIdentity::from(binary));
        std::fs::create_dir_all(path.parent().expect("contracts dir")).expect("contracts dir");
        let mut document: serde_json::Value = match std::fs::read_to_string(&path) {
            Ok(text) => serde_json::from_str(&text).expect("existing contract document parses"),
            Err(_) => json!({ "binary": binary, "filed_at": 1, "scenarios": {} }),
        };
        document["scenarios"][scenario] = json!({
            "name": scenario,
            "working_dir": ".",
            "cols": 80,
            "rows": 24,
            "idle_timeout_ms": 5000,
            "max_run_ms": 15000,
            "finalization_grace_ms": 1000,
            "max_output_bytes": 65536,
            "normalization": { "version": "norm-v1" }
        });
        std::fs::write(&path, document.to_string()).expect("file contract document");
    }

    /// The filed capture document as `scenario capture` files one: the
    /// dimension blocks do not matter to the capture slot, only that the
    /// document stands.
    fn file_capture(workspace: &std::path::Path, binary: &str, scenario: &str) {
        let path = calxgloss_types::scenario_capture_path(
            workspace,
            &calxgloss_types::BinaryIdentity::from(binary),
            scenario,
        );
        std::fs::create_dir_all(path.parent().expect("captures dir")).expect("captures dir");
        std::fs::write(
            &path,
            json!({ "scenario": scenario, "filed_at": 1 }).to_string(),
        )
        .expect("file capture document");
    }

    /// The filed verdict document as the comparator files one, with the
    /// given dimension states standing in for the verdict block.
    fn file_verdict(
        workspace: &std::path::Path,
        binary: &str,
        scenario: &str,
        dimensions: serde_json::Value,
    ) {
        let path = calxgloss_types::scenario_verdict_path(
            workspace,
            &calxgloss_types::BinaryIdentity::from(binary),
            scenario,
        );
        std::fs::create_dir_all(path.parent().expect("verdicts dir")).expect("verdicts dir");
        std::fs::write(
            &path,
            json!({
                "binary": binary,
                "scenario": scenario,
                "filed_at": 1,
                "normalization_version": "norm-v1",
                "left_capture_sha256": "sha256:left-bytes",
                "right_capture_sha256": "sha256:right-bytes",
                "verdict": dimensions,
                "divergences": [],
                "residual_unknowns": [],
                "claims_complete_equivalence": false,
                "digest": "sha256:digest"
            })
            .to_string(),
        )
        .expect("file verdict document");
    }

    fn scenario_of<'a>(
        statuses: &'a [calxgloss_types::BinaryScenarioStatus],
        scenario: &str,
    ) -> &'a calxgloss_types::ScenarioStatus {
        statuses
            .iter()
            .flat_map(|status| &status.scenarios)
            .find(|status| status.scenario == scenario)
            .unwrap_or_else(|| panic!("scenario {scenario} renders"))
    }

    #[test]
    fn scenario_status_lines_spell_out_each_slot_and_name_the_failed_dimensions() {
        let status = BinaryScenarioStatus {
            binary: "eqgame.exe".to_string(),
            scenarios: vec![
                ScenarioStatus {
                    scenario: "boot".to_string(),
                    declared: true,
                    captured: true,
                    verdict: ScenarioVerdictReading::AssessedFail {
                        failed_dimensions: vec!["terminal".to_string(), "exit".to_string()],
                    },
                },
                ScenarioStatus {
                    scenario: "print-config".to_string(),
                    declared: true,
                    captured: false,
                    verdict: ScenarioVerdictReading::Unassessed,
                },
                ScenarioStatus {
                    scenario: "orphan".to_string(),
                    declared: false,
                    captured: true,
                    verdict: ScenarioVerdictReading::AssessedPass,
                },
            ],
        };

        assert_eq!(
            scenario_status_lines(&status),
            vec![
                "  eqgame.exe",
                "    • boot — declared, captured, assessed fail (terminal, exit)",
                "    • print-config — declared, not captured, unassessed",
                "    • orphan — not declared, captured, assessed pass",
            ],
            "every scenario stands on its own line with all three slots \
             spelled out — no aggregate, no laundered readings"
        );
    }

    #[test]
    fn several_scenarios_on_one_binary_render_side_by_side_never_one_aggregate() {
        let dir = tempfile::tempdir().expect("temp workspace");
        file_contract(dir.path(), "eqgame.exe", "boot");
        file_contract(dir.path(), "eqgame.exe", "print-config");
        file_capture(dir.path(), "eqgame.exe", "boot");
        file_verdict(
            dir.path(),
            "eqgame.exe",
            "boot",
            json!({ "exit": "assessed_fail" }),
        );

        let statuses = derive_scenario_statuses(dir.path());

        assert_eq!(statuses.len(), 1, "one binary speaks for both scenarios");
        assert_eq!(
            statuses[0].scenarios,
            vec![
                ScenarioStatus {
                    scenario: "boot".to_string(),
                    declared: true,
                    captured: true,
                    verdict: ScenarioVerdictReading::AssessedFail {
                        failed_dimensions: vec!["exit".to_string()],
                    },
                },
                ScenarioStatus {
                    scenario: "print-config".to_string(),
                    declared: true,
                    captured: false,
                    verdict: ScenarioVerdictReading::Unassessed,
                },
            ],
            "each scenario keeps its own reading — `boot`'s fail never \
             touches `print-config`, and nothing folds into one per-binary claim"
        );
    }

    #[test]
    fn a_verdict_that_assessed_every_dimension_pass_reads_assessed_pass() {
        let dir = tempfile::tempdir().expect("temp workspace");
        file_verdict(
            dir.path(),
            "eqgame.exe",
            "boot",
            json!({
                "terminal": "assessed_pass",
                "interaction": "assessed_pass",
                "exit": "assessed_pass",
                "filesystem": "assessed_pass",
                "process": "assessed_pass"
            }),
        );

        let statuses = derive_scenario_statuses(dir.path());

        assert_eq!(
            scenario_of(&statuses, "boot").verdict,
            ScenarioVerdictReading::AssessedPass,
            "the pass reading stands only when all five dimensions were \
             assessed and passed"
        );
    }

    #[test]
    fn a_filed_verdict_with_silent_dimensions_reads_unassessed_never_a_pass() {
        let dir = tempfile::tempdir().expect("temp workspace");
        // Filed, but the verdict block never spoke: absent dimension keys
        // default to unassessed (the ADR-0053 rule the comparator files
        // under), and silence never renders as a pass.
        file_verdict(dir.path(), "eqgame.exe", "boot", json!({}));

        let statuses = derive_scenario_statuses(dir.path());

        assert_eq!(
            scenario_of(&statuses, "boot").verdict,
            ScenarioVerdictReading::Unassessed,
            "a filed verdict that assessed nothing is unassessed, not a pass"
        );
    }

    #[test]
    fn a_filed_verdict_with_failing_dimensions_reads_assessed_fail_naming_each_one() {
        let dir = tempfile::tempdir().expect("temp workspace");
        file_verdict(
            dir.path(),
            "eqgame.exe",
            "boot",
            json!({
                "terminal": "assessed_fail",
                "interaction": "assessed_pass",
                "exit": "assessed_fail"
            }),
        );

        let statuses = derive_scenario_statuses(dir.path());

        assert_eq!(
            scenario_of(&statuses, "boot").verdict,
            ScenarioVerdictReading::AssessedFail {
                failed_dimensions: vec!["terminal".to_string(), "exit".to_string()],
            },
            "a failing verdict is assessed fail with every failed dimension \
             named, in the comparator's dimension order"
        );
    }

    #[test]
    fn a_scenario_named_like_a_replay_keeps_its_own_name_in_the_capture_envelope() {
        let dir = tempfile::tempdir().expect("temp workspace");
        // `boot-replay` files at `eqgame.exe-boot-replay.json`, the same
        // envelope shape a replay of `boot` wears. The exact-name reading
        // wins: the scenario keeps its own name instead of dropping out as
        // a replay whose base scenario never stood.
        file_capture(dir.path(), "eqgame.exe", "boot-replay");

        let statuses = derive_scenario_statuses(dir.path());

        assert_eq!(statuses.len(), 1, "the envelope still names the binary");
        assert_eq!(statuses[0].binary, "eqgame.exe");
        assert_eq!(
            statuses[0].scenarios,
            vec![ScenarioStatus {
                scenario: "boot-replay".to_string(),
                declared: false,
                captured: true,
                verdict: ScenarioVerdictReading::Unassessed,
            }],
            "the scenario named `boot-replay` renders as itself, captured"
        );
    }

    #[test]
    fn a_filed_capture_without_a_contract_renders_not_declared_yet_captured() {
        let dir = tempfile::tempdir().expect("temp workspace");
        file_capture(dir.path(), "eqgame.exe", "boot");

        let statuses = derive_scenario_statuses(dir.path());

        assert_eq!(
            statuses.len(),
            1,
            "the capture names its binary in its file name"
        );
        assert_eq!(statuses[0].binary, "eqgame.exe");
        assert_eq!(
            statuses[0].scenarios,
            vec![ScenarioStatus {
                scenario: "boot".to_string(),
                declared: false,
                captured: true,
                verdict: ScenarioVerdictReading::Unassessed,
            }],
            "a capture standing with no contract document reads not-declared \
             beside captured — the capture never launders a declaration"
        );
    }

    #[test]
    fn a_declared_scenario_with_no_other_record_reads_declared_not_captured_unassessed() {
        let dir = tempfile::tempdir().expect("temp workspace");
        file_contract(dir.path(), "eqgame.exe", "boot");

        let statuses = derive_scenario_statuses(dir.path());

        assert_eq!(statuses.len(), 1, "one target binary stands");
        assert_eq!(statuses[0].binary, "eqgame.exe");
        assert_eq!(
            statuses[0].scenarios,
            vec![ScenarioStatus {
                scenario: "boot".to_string(),
                declared: true,
                captured: false,
                verdict: ScenarioVerdictReading::Unassessed,
            }],
            "the declared scenario rides with its two missing records read \
             as their honest negatives — not-captured and unassessed"
        );
    }
}
