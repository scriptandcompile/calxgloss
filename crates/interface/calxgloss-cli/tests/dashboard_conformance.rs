//! Behavior tests for the *conformance* section at the terminal dashboard
//! seam (issue #419, P26.3). The built CLI renders the per-binary
//! conformance rows over a temp git workspace whose obligation ledger and
//! evidence are staged on disk, and the assertions read only the printed
//! section: a fully evidenced binary printing *complete* with its closure
//! seal, a never-filed ledger printing *unknown* naming its cause, and
//! the honest dispositions printing counted apart from the verified.

use std::path::Path;
use std::process::Command;

use calxgloss_git::GitManager;
use calxgloss_types::{
    BinaryIdentity, DimensionCounts, ObligationDisposition, ObligationEntry, ObligationLedger,
    VerificationReceipt, VerificationVerdict, VerifierCommand, obligation_ledger_path, save_json,
    verification_receipt_markdown,
};

/// Run the built CLI isolated from the ambient config, like the scenario
/// status tests do: an empty config file and no ambient variables.
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

/// A workspace whose single unit carries the full evidence chain — a
/// committed receipt pair, an Accept record, a merged branch, an
/// explicitly-none unknown ledger — plus the given extra obligation
/// entries filed in the binary's obligation ledger.
/// Drop the color escapes (ESC through `m`) so a wrapped, colored sentence
/// can be read as one logical line again.
fn strip_ansi(text: &str) -> String {
    let mut out = String::new();
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            for next in chars.by_ref() {
                if next == 'm' {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

fn fully_evidenced_workspace(extra_entries: Vec<ObligationEntry>) -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("temp workspace");
    let git = GitManager::init_repo(dir.path(), None).expect("init git repo");
    let branch = git
        .create_branch("game_logic.dll", "DrawPrimitive", 1, None)
        .expect("translation branch")
        .branch;

    let source = dir
        .path()
        .join("src")
        .join("game_logic.dll_DrawPrimitive_v1.rs");
    std::fs::create_dir_all(source.parent().expect("src dir")).expect("src dir");
    std::fs::write(&source, "// translated").expect("write source");

    // The verification receipt pair, committed on the branch beside the
    // translated source, the way the verify gate files it.
    let mut dimensions = std::collections::BTreeMap::new();
    dimensions.insert(
        "values".to_string(),
        DimensionCounts {
            assessed: 2,
            passed: 2,
        },
    );
    let identity = BinaryIdentity::from("game_logic.dll");
    let mut receipt = VerificationReceipt {
        binary: identity,
        function: "DrawPrimitive".to_string(),
        attempt: 1,
        retry_strategy: "initial".to_string(),
        attempt_path: "strategy_prompt".to_string(),
        verifier_command: VerifierCommand::CompileAndBaselineTest,
        baseline_suite_digest: "sha256:suite".to_string(),
        covered_case_kinds: calxgloss_types::CaseKind::ALL.iter().copied().collect(),
        dimensions,
        compile_ms: 10,
        test_run_ms: 5,
        total_ms: 15,
        verdict: VerificationVerdict::Passed,
        failed_cases: Vec::new(),
        digest: String::new(),
    };
    receipt.digest = receipt.content_digest().expect("digests");
    let json_path = dir
        .path()
        .join("re/verification/game_logic.dll/DrawPrimitive/attempt-1.json");
    std::fs::create_dir_all(json_path.parent().expect("receipt dir")).expect("receipt dir");
    std::fs::write(
        &json_path,
        serde_json::to_string(&receipt).expect("serializes"),
    )
    .expect("file receipt JSON");
    std::fs::write(
        json_path.with_extension("md"),
        verification_receipt_markdown(&receipt),
    )
    .expect("file receipt twin");
    let commit = git
        .commit(
            &branch,
            "re: translate DrawPrimitive",
            &[
                "src/game_logic.dll_DrawPrimitive_v1.rs",
                "re/verification/game_logic.dll/DrawPrimitive/attempt-1.json",
                "re/verification/game_logic.dll/DrawPrimitive/attempt-1.md",
            ],
        )
        .expect("attempt commit");
    git.accept_branch(&branch).expect("accept branch");

    // The unknown ledger filed with no records: the gate proven clean.
    let unknowns = dir.path().join("re/unknowns/game_logic.dll.json");
    std::fs::create_dir_all(unknowns.parent().expect("unknowns dir")).expect("unknowns dir");
    std::fs::write(
        &unknowns,
        serde_json::json!({"binary": "game_logic.dll", "filed_at": 1, "records": []}).to_string(),
    )
    .expect("file unknown ledger");

    let mut entries = vec![{
        let mut entry = ObligationEntry::new(
            "DrawPrimitive",
            1,
            &commit.hash,
            ObligationDisposition::ClaimedVerified,
        );
        entry.receipt_digest = Some(receipt.digest.clone());
        entry
    }];
    entries.extend(extra_entries);
    let ledger =
        ObligationLedger::file("game_logic.dll", entries, 1_700_000_000).expect("file the ledger");
    save_json(&obligation_ledger_path(dir.path(), &ledger.binary), &ledger)
        .expect("save the ledger");
    dir
}

#[test]
fn the_dashboard_prints_a_complete_verdict_sealed_by_its_ledger_digest() {
    let ws = fully_evidenced_workspace(Vec::new());

    let (ok, stdout, stderr) = run(
        cli(ws.path()).args(["--target-dir", ".", "dashboard"]),
        ws.path(),
    );
    assert!(ok, "the dashboard run failed:\n{stdout}\n{stderr}");

    let text = std::fs::read_to_string(obligation_ledger_path(
        ws.path(),
        &BinaryIdentity::from("game_logic.dll"),
    ))
    .expect("filed ledger text");
    let digest = serde_json::from_str::<serde_json::Value>(&text).expect("ledger json")["digest"]
        .as_str()
        .expect("digest field")
        .trim_start_matches("sha256:")
        .chars()
        .take(8)
        .collect::<String>();
    assert!(
        stdout.contains("Conformance — restitch closure per binary"),
        "{stdout}"
    );
    assert!(
        stdout.contains(&format!(
            "game_logic.dll — complete (1 verified, sealed {digest})"
        )),
        "the printed seal shortens the file's own digest\n{stdout}"
    );
}

#[test]
fn a_never_filed_ledger_prints_unknown_naming_no_ledger_filed() {
    let dir = tempfile::tempdir().expect("temp workspace");
    let git = GitManager::init_repo(dir.path(), None).expect("init git repo");
    git.create_branch("game_logic.dll", "DrawPrimitive", 1, None)
        .expect("translation branch");

    let (ok, stdout, stderr) = run(
        cli(dir.path()).args(["--target-dir", ".", "dashboard"]),
        dir.path(),
    );
    assert!(
        ok,
        "the dashboard never fails on a never-filed ledger:\n{stdout}\n{stderr}"
    );

    assert!(
        stdout.contains("Conformance — restitch closure per binary"),
        "{stdout}"
    );
    assert!(
        stdout.contains("game_logic.dll — unknown: no ledger filed — never a clean run"),
        "{stdout}"
    );
}

#[test]
fn honest_dispositions_print_counted_apart_from_verified() {
    let extras = vec![
        ObligationEntry::new(
            "SkipMe",
            1,
            "0000000000000000000000000000000000000000",
            ObligationDisposition::Skipped,
        ),
        ObligationEntry::new(
            "ParkMe",
            1,
            "0000000000000000000000000000000000000000",
            ObligationDisposition::Parked,
        ),
        ObligationEntry::new(
            "OverrideMe",
            1,
            "0000000000000000000000000000000000000000",
            ObligationDisposition::Overridden,
        ),
        ObligationEntry::new(
            "ReviewMeNot",
            1,
            "0000000000000000000000000000000000000000",
            ObligationDisposition::UnReviewed,
        ),
        ObligationEntry::new(
            "NoCover",
            1,
            "0000000000000000000000000000000000000000",
            ObligationDisposition::NoBaseline,
        ),
    ];
    let ws = fully_evidenced_workspace(extras);

    let (ok, stdout, stderr) = run(
        cli(ws.path()).args(["--target-dir", ".", "dashboard"]),
        ws.path(),
    );
    assert!(ok, "the dashboard run failed:\n{stdout}\n{stderr}");

    let joined: String = stdout
        .lines()
        .map(|line| strip_ansi(line).trim().to_string())
        .collect::<Vec<_>>()
        .join(" ");
    assert!(
        joined.contains(
            "game_logic.dll — incomplete (1 verified, 1 skipped, 1 parked, 1 overridden, \
             1 un-reviewed, 1 no-baseline)"
        ),
        "the whole tally reads across the wrap, nothing clipped:\n{stdout}"
    );
}

#[test]
fn a_join_derived_un_reviewed_unit_prints_counted_apart_from_verified() {
    // Issue #420 (P26.4), AC 6 at the terminal: the *un-reviewed* tally
    // comes from the read seam's join — a merged branch with no standing
    // Accept record — and the terminal counts it apart from the verified.
    let ws = fully_evidenced_workspace(Vec::new());
    std::fs::remove_file(ws.path().join("re/accepts/game_logic.dll/DrawPrimitive/v1.json"))
        .expect("withdraw the Accept record");

    let (ok, stdout, stderr) = run(
        cli(ws.path()).args(["--target-dir", ".", "dashboard"]),
        ws.path(),
    );
    assert!(ok, "the dashboard run failed:\n{stdout}\n{stderr}");

    let joined: String = stdout
        .lines()
        .map(|line| strip_ansi(line).trim().to_string())
        .collect::<Vec<_>>()
        .join(" ");
    assert!(
        joined.contains("game_logic.dll — incomplete (0 verified, 1 un-reviewed)"),
        "the join's un-reviewed count prints apart from the verified:\n{stdout}"
    );
    assert!(
        joined.contains("DrawPrimitive attempt 1 — no Accept review action stands"),
        "the broken review link names itself below the counts:\n{stdout}"
    );
}

#[test]
fn tampered_ledger_bytes_print_the_input_error_and_an_unknown_verdict() {
    // AC 3 at the terminal: tampered filed bytes are an input error named
    // at the read — stderr names it, and stdout prints the *unknown*
    // verdict with the digest-mismatch cause, never a stale complete.
    let ws = fully_evidenced_workspace(Vec::new());
    let path = obligation_ledger_path(ws.path(), &BinaryIdentity::from("game_logic.dll"));
    let filed = std::fs::read_to_string(&path).expect("filed ledger text");
    let mut doc: serde_json::Value = serde_json::from_str(&filed).expect("ledger json");
    let owner = doc["entries"][0]["owner_commit"]
        .as_str()
        .expect("the entry carries its owner")
        .to_string();
    let forged = if owner.starts_with("0") { "1" } else { "0" };
    doc["entries"][0]["owner_commit"] = serde_json::json!(format!("{forged}{}", &owner[1..]));
    std::fs::write(&path, doc.to_string()).expect("edit a sealed entry under the unchanged seal");

    let (ok, stdout, stderr) = run(
        cli(ws.path()).args(["--target-dir", ".", "dashboard"]),
        ws.path(),
    );
    assert!(
        ok,
        "the dashboard build survives tampered ledger bytes:\n{stdout}\n{stderr}"
    );

    let out: String = stdout
        .lines()
        .map(|line| strip_ansi(line).trim().to_string())
        .collect::<Vec<_>>()
        .join(" ");
    assert!(
        out.contains("game_logic.dll — unknown: digest mismatch"),
        "the verdict falls to unknown with the digest-mismatch cause:\n{stdout}"
    );
    assert!(
        stderr.contains("game_logic.dll") && stderr.contains("input error"),
        "the read names the input error where the operator sees it:\n{stderr}"
    );
}
