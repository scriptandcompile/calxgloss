//! Process-level e2e for the `verify` command (P25.2, issue #411).
//!
//! One standalone verify run files its *verification receipt* pair — the
//! JSON authority plus its Markdown twin, paired by content digest —
//! under `re/verification/<binary>/<function>/attempt-1.json`/`.md`,
//! prints the pair's digest on the terminal, and commits nothing: the
//! pair stands on disk, unstaged, until a branch build stages it. The
//! command's `--baseline-path` location rides the suite digest fold, so
//! the receipt names the very file the verdict was earned against.
//!
//! Like the verify crate's compile-backed pins, this e2e hides behind
//! `#[ignore]` — it really scaffolds, compiles, and runs the gate:
//!
//! ```text
//! cargo test -p calxgloss-cli --test verify_receipt -- --ignored
//! ```

use std::path::Path;
use std::process::Command;

use calxgloss_types::{
    BinaryIdentity, VerificationVerdict, VerifierCommand, persist, verification_receipt_path,
};

/// Run the built CLI isolated from the ambient config, as every engine
/// test does.
fn cli(dir: &Path) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_calxgloss-cli"));
    let empty = dir.join("empty-config.toml");
    std::fs::write(&empty, "# empty: every setting falls back to its default")
        .expect("empty config written");
    cmd.env("CALXGLOSS_CONFIG", &empty);
    for key in [
        "CALXGLOSS_TARGET_DIR",
        "CALXGLOSS_WORKSPACE",
        "CALXGLOSS_WINE",
    ] {
        cmd.env_remove(key);
    }
    cmd
}

/// A body that always returns 7 — the same fixture the verify crate's
/// receipt pins drive through the real runner.
const BODY: &str = "pub fn call_no_params() -> serde_json::Value { serde_json::Value::from(7) }";

#[test]
#[ignore = "scaffolds and cargo-runs a real scratch project + runner"]
fn the_verify_command_files_its_receipt_pair_prints_the_digest_and_commits_nothing() {
    let dir = tempfile::tempdir().expect("temp workspace");
    let workspace = dir.path();

    let source = workspace.join("receipt_cli.rs");
    std::fs::write(&source, BODY).expect("translated source written");
    let baseline = workspace.join("baseline.json");
    std::fs::write(
        &baseline,
        r#"[{"inputs": null, "expected_return": 7, "expected_side_effects": []}]"#,
    )
    .expect("baseline suite written");

    let out = cli(workspace)
        .args([
            "--workspace",
            &workspace.display().to_string(),
            "--target-dir",
            &workspace.display().to_string(),
            "verify",
            "--binary",
            "cli_receipt.dll",
            "--function",
            "receipt_cli",
            "--rust-source",
            &source.display().to_string(),
            "--baseline-path",
            &baseline.display().to_string(),
        ])
        .output()
        .expect("the CLI ran");
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        out.status.success(),
        "the verify command succeeds:\n{stdout}\n{stderr}"
    );

    // The pair stands under the record convention beside re/baseline/.
    let json_path = verification_receipt_path(
        workspace,
        &BinaryIdentity::new("cli_receipt.dll"),
        "receipt_cli",
        1,
    );
    assert!(json_path.is_file(), "the JSON authority was filed");
    let md_path = json_path.with_extension("md");
    assert!(md_path.is_file(), "the Markdown twin was filed with it");

    // The pair proves itself from its own contents.
    let filed: calxgloss_types::VerificationReceipt =
        persist::load_json(&json_path).expect("the filed authority reads");
    assert_eq!(
        filed.content_digest().expect("the fold"),
        filed.digest,
        "the JSON names itself"
    );
    let md = std::fs::read_to_string(&md_path).expect("the twin reads");
    assert!(
        md.contains(&filed.digest),
        "the twin carries the same digest"
    );

    // The gate as invoked and the verdict it reached, from a baseline
    // file handed over by path.
    assert_eq!(filed.verdict, VerificationVerdict::Passed);
    assert_eq!(
        filed.verifier_command,
        VerifierCommand::CompileAndBaselineTest,
        "a named baseline case ran — the full gate"
    );

    // The terminal prints the digest — the handle a green claim cites.
    assert!(
        stdout.contains("sha256:"),
        "the command prints the receipt digest:\n{stdout}"
    );
    assert!(
        stdout.contains(&filed.digest),
        "the printed digest is the filed pair's own"
    );

    // The `--baseline-path` location rode the suite digest fold, relative
    // to the workspace: the receipt names the very file it earned against.
    let cases: Vec<calxgloss_types::TestCase> =
        serde_json::from_str(&std::fs::read_to_string(&baseline).expect("the suite reads back"))
            .expect("the suite parses");
    assert_eq!(
        filed.baseline_suite_digest,
        calxgloss_types::baseline_suite_digest(&cases, Some("baseline.json"))
            .expect("the located suite folds"),
        "the fold names the baseline file's location relative to the workspace"
    );

    // Commits nothing: the command never touches git — no repo, no
    // branch, no staged record.
    assert!(
        !workspace.join(".git").exists(),
        "the verify command never initializes or commits a repo"
    );
}
