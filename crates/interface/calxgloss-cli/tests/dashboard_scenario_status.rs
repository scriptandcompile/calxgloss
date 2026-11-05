//! Behavior tests for the *scenario status* section at the terminal
//! dashboard seam (issue #409, P24.8). The built CLI renders the section
//! over a temp git repository whose filed scenario documents — a contract
//! set, a capture, and a verdict — are staged on disk, and the assertions
//! read only the printed section: every scenario's slot readings spelled
//! out, a failing verdict naming its dimensions, scenarios standing side
//! by side, and every missing record printed as its honest negative. The
//! web review API serves the same model through `ReviewDashboard`.

use std::path::Path;
use std::process::Command;

use calxgloss_types::{
    BinaryIdentity, scenario_capture_path, scenario_contracts_path, scenario_verdict_path,
};

/// Run the built CLI isolated from the ambient config, like the audit
/// ledger tests do: an empty config file and no ambient variables.
fn cli(dir: &Path) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_calxgloss-cli"));
    let empty = dir.join("empty-config.toml");
    std::fs::write(&empty, "# empty: every setting falls back to its default")
        .expect("empty config written");
    cmd.env("CALXGLOSS_CONFIG", &empty);
    for key in ["CALXGLOSS_TARGET_DIR", "CALXGLOSS_WORKSPACE"] {
        cmd.env_remove(key);
    }
    cmd
}

/// Run `cmd` in `dir` and return (success, stdout, stderr).
fn run(cmd: &mut Command, dir: &Path) -> (bool, String, String) {
    let out = cmd.current_dir(dir).output().expect("the CLI ran");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn git(dir: &Path, args: &[&str]) {
    let out = Command::new("git")
        .args([
            "-c",
            "user.name=calxgloss-test",
            "-c",
            "user.email=test@calxgloss.local",
        ])
        .args(args)
        .current_dir(dir)
        .output()
        .expect("git ran");
    assert!(
        out.status.success(),
        "git {args:?} failed:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// A git workspace with one translation branch and the given filed
/// scenario documents for `eqgame.exe`.
fn workspace_with_scenario_records(
    scenarios: &[(&str, bool, serde_json::Value)],
) -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("temp workspace");
    git(dir.path(), &["init", "-b", "main"]);
    git(dir.path(), &["commit", "--allow-empty", "-m", "baseline"]);
    git(
        dir.path(),
        &["branch", "re/game_logic.dll/DrawPrimitive/v1"],
    );

    let binary = BinaryIdentity::from("eqgame.exe");
    for (scenario, captured, verdict) in scenarios {
        let contract_path = scenario_contracts_path(dir.path(), &binary);
        let mut document: serde_json::Value = match std::fs::read_to_string(&contract_path) {
            Ok(text) => serde_json::from_str(&text).expect("standing contract document"),
            Err(_) => serde_json::json!({"binary": "eqgame.exe", "filed_at": 1, "scenarios": {}}),
        };
        document["scenarios"][scenario] = serde_json::json!({
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
        std::fs::create_dir_all(contract_path.parent().expect("contracts dir"))
            .expect("contracts dir");
        std::fs::write(&contract_path, document.to_string()).expect("file contract document");

        if *captured {
            let capture_path = scenario_capture_path(dir.path(), &binary, scenario);
            std::fs::create_dir_all(capture_path.parent().expect("captures dir"))
                .expect("captures dir");
            std::fs::write(
                &capture_path,
                serde_json::json!({"scenario": scenario, "filed_at": 1}).to_string(),
            )
            .expect("file capture document");
        }
        if !verdict.is_null() {
            let verdict_path = scenario_verdict_path(dir.path(), &binary, scenario);
            std::fs::create_dir_all(verdict_path.parent().expect("verdicts dir"))
                .expect("verdicts dir");
            std::fs::write(
                &verdict_path,
                serde_json::json!({
                    "binary": "eqgame.exe",
                    "scenario": scenario,
                    "filed_at": 1,
                    "normalization_version": "norm-v1",
                    "left_capture_sha256": "sha256:left-bytes",
                    "right_capture_sha256": "sha256:right-bytes",
                    "verdict": verdict,
                    "divergences": [],
                    "residual_unknowns": [],
                    "claims_complete_equivalence": false,
                    "digest": "sha256:digest"
                })
                .to_string(),
            )
            .expect("file verdict document");
        }
    }
    dir
}

#[test]
fn the_dashboard_prints_scenario_status_with_every_record_read_honestly() {
    let ws = workspace_with_scenario_records(&[
        (
            "boot",
            true,
            serde_json::json!({"terminal": "assessed_fail", "exit": "assessed_pass"}),
        ),
        ("print-config", false, serde_json::Value::Null),
    ]);

    let (ok, stdout, stderr) = run(
        cli(ws.path()).args(["--target-dir", ".", "dashboard"]),
        ws.path(),
    );
    assert!(ok, "the dashboard run failed:\n{stdout}\n{stderr}");

    assert!(stdout.contains("Scenario status — EXE targets"), "{stdout}");
    assert!(stdout.contains("  eqgame.exe"), "{stdout}");
    assert!(
        stdout.contains("• boot — declared, captured, assessed fail (terminal)"),
        "the failing verdict prints assessed fail naming its dimension: {stdout}"
    );
    assert!(
        stdout.contains("• print-config — declared, not captured, unassessed"),
        "the declared-only scenario prints its two missing records as honest \
         negatives, never as un-captured success or as a pass: {stdout}"
    );

    // The queue and footer keep their place: the scenario section rides
    // the same dashboard without disturbing the unit rows.
    assert!(stdout.contains("DrawPrimitive"), "{stdout}");
    assert!(stdout.contains("branches found in re/*"), "{stdout}");
}
