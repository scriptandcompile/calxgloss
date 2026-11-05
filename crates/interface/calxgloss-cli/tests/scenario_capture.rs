//! Process-level e2e for the `scenario capture` command (P24.3, issue
//! #404): one command runs a declared scenario contract against the
//! original target binary and files the first **scenario capture** in the
//! record tree at `re/scenarios/captures/{binary}-{scenario}.json` — the
//! document readable at that documented location, holding the exit
//! disposition, the capped terminal output, the before/after file
//! classification, the interaction acknowledgements, and the pairing
//! stamps.
//!
//! The refusal pins are ungated: capturing before any declaration names
//! the declare step, and a missing Wine fails the capture naming the
//! Wine it looked for — through the standing preflight line, never a
//! hang — with nothing filed. The full-run pins need Wine and the
//! fixture console EXE, so they stand ignored like the baseline Wine
//! pins.

use std::path::{Path, PathBuf};
use std::process::Command;

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

fn run(cmd: &mut Command, dir: &Path) -> (bool, String, String) {
    let out = cmd.current_dir(dir).output().expect("the CLI ran");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

const BINARY: &str = "fixture_console.exe";

fn workspace() -> tempfile::TempDir {
    tempfile::tempdir().expect("a scratch workspace")
}

/// Stage the fixture console EXE at the workspace root — the validation
/// root for these pins, so the binary identity names the staged copy.
fn stage_fixture_exe(ws: &Path) -> PathBuf {
    let source = calxgloss_testfixtures::console_target_path()
        .expect("the build script should have compiled the fixture console exe");
    let staged = ws.join(BINARY);
    std::fs::copy(source, &staged).expect("the fixture exe stages in the target dir");
    staged
}

/// Declare the boot scenario for the fixture: echo, file writes, delete,
/// and the declared exit code — the shapes the capture pins read. The
/// idle window outlasts Wine's own boot.
fn declare_boot_scenario(ws: &Path, scenario: &str, max_output_bytes: &str) {
    let mut cmd = cli(ws);
    cmd.args(["scenario", "declare"])
        .args(["--binary", BINARY, "--scenario", scenario])
        .args(["--input-at", "1000:echo hello-scene"])
        .args(["--input-at", "1500:write new.dat new-content"])
        .args(["--input-at", "2000:delete old.dat"])
        .args(["--input-at", "2500:exit 7"])
        .args(["--observe", "new.dat", "--observe", "old.dat"])
        .args(["--idle-timeout-ms", "15000", "--max-run-ms", "30000"])
        .args(["--max-output-bytes", max_output_bytes]);
    let (ok, stdout, stderr) = run(&mut cmd, ws);
    assert!(ok, "the scenario declares: {stdout}{stderr}");
}

fn capture(ws: &Path, scenario: &str) -> (bool, String, String) {
    let mut cmd = cli(ws);
    cmd.args(["scenario", "capture"])
        .args(["--binary", BINARY, "--scenario", scenario]);
    run(&mut cmd, ws)
}

fn capture_path(ws: &Path, scenario: &str) -> PathBuf {
    ws.join("re")
        .join("scenarios")
        .join("captures")
        .join(format!("{BINARY}-{scenario}.json"))
}

fn read_capture_document(ws: &Path, scenario: &str) -> serde_json::Value {
    let raw = std::fs::read_to_string(capture_path(ws, scenario))
        .expect("the filed capture document reads at its documented record-tree location");
    serde_json::from_str(&raw).expect("the capture document is JSON")
}

fn sha256_hex(path: &Path) -> String {
    use sha2::{Digest as _, Sha256};
    let bytes = std::fs::read(path).expect("the file reads");
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

// ============================================================
// Refusals: ungated, named, never a hang and never a filing
// ============================================================

#[test]
fn a_capture_with_nothing_declared_is_refused_toward_the_declare_step() {
    let ws = workspace();
    let (ok, _, stderr) = capture(ws.path(), "boot");
    assert!(!ok, "a capture with no contract document cannot succeed");
    assert!(
        stderr.contains("declare the scenario before capturing it"),
        "the refusal points at the missing declaration: {stderr}"
    );
    assert!(
        !ws.path().join("re").exists(),
        "a refused capture files nothing"
    );
}

#[test]
fn a_scenario_that_was_never_declared_is_refused_naming_what_stands() {
    let ws = workspace();
    declare_boot_scenario(ws.path(), "boot", "65536");
    let (ok, _, stderr) = capture(ws.path(), "not-declared");
    assert!(!ok, "an undeclared scenario name cannot capture");
    assert!(
        stderr.contains("not declared") && stderr.contains("boot"),
        "the refusal names the scenario and lists what is declared: {stderr}"
    );
    assert!(
        !capture_path(ws.path(), "not-declared").exists(),
        "a refused capture files nothing"
    );
}

#[test]
fn a_missing_wine_fails_the_capture_by_name_and_files_nothing() {
    // The standing preflight line governs the CLI too: the failure names
    // the Wine it looked for and carries the CALXGLOSS_WINE guidance —
    // before any process exists to hang.
    let ws = workspace();
    stage_fixture_exe(ws.path());
    declare_boot_scenario(ws.path(), "boot", "65536");
    std::fs::write(ws.path().join("old.dat"), b"old-bytes").expect("the before-side file stands");

    let mut cmd = cli(ws.path());
    cmd.env("CALXGLOSS_WINE", "/nonexistent/wine-not-on-this-machine")
        .args(["scenario", "capture"])
        .args(["--binary", BINARY, "--scenario", "boot"]);
    let (ok, _, stderr) = run(&mut cmd, ws.path());
    assert!(!ok, "a missing Wine must fail the capture");
    assert!(
        stderr.contains("/nonexistent/wine-not-on-this-machine"),
        "the failure names the Wine it looked for: {stderr}"
    );
    assert!(
        stderr.contains("CALXGLOSS_WINE"),
        "the failure carries the standing preflight guidance: {stderr}"
    );
    assert!(
        !capture_path(ws.path(), "boot").exists(),
        "a capture that never ran files nothing"
    );
}

#[test]
fn a_capture_refuses_a_binary_identity_that_is_not_a_staged_file() {
    // The run stands against the original target binary: the identity
    // must name a file in the target dir, and the refusal says so before
    // Wine is even asked.
    let ws = workspace();
    declare_boot_scenario(ws.path(), "boot", "65536");
    let (ok, stdout, stderr) = capture(ws.path(), "boot");
    let combined = format!("{stdout}{stderr}");
    assert!(!ok, "no staged binary, no capture");
    assert!(
        combined.contains("original target binary is not at"),
        "the refusal names the missing target file: {combined}"
    );
    assert!(
        !capture_path(ws.path(), "boot").exists(),
        "a refused capture files nothing"
    );
}

// ============================================================
// Full runs against the fixture console EXE (Wine-gated)
// ============================================================

#[test]
#[ignore = "needs Wine and the fixture console EXE"]
fn a_scenario_capture_files_a_readable_document_at_its_record_tree_location() {
    let ws = workspace();
    let staged = stage_fixture_exe(ws.path());
    std::fs::write(ws.path().join("old.dat"), b"old-bytes").expect("the before-side file stands");
    declare_boot_scenario(ws.path(), "boot", "65536");

    let (ok, stdout, stderr) = capture(ws.path(), "boot");
    assert!(
        ok,
        "the fixture scenario captures under Wine: {stdout}{stderr}"
    );
    assert!(
        stdout.contains("exited with code 7"),
        "the fixture's declared exit code lands in the summary: {stdout}"
    );

    let path = capture_path(ws.path(), "boot");
    assert!(
        path.exists(),
        "the capture stands where the record tree says"
    );
    let document = read_capture_document(ws.path(), "boot");

    assert_eq!(document["scenario"], "boot");
    assert!(
        document["filed_at"].as_u64().unwrap_or(0) > 0,
        "the filing clock stamps a real reading"
    );

    assert_eq!(document["exit"]["disposition"], "exited");
    assert_eq!(
        document["exit"]["exit_code"], 7,
        "the closed set holds *exited* with the declared code"
    );

    let joined: String = document["terminal"]["chunks"]
        .as_array()
        .expect("the terminal block names its chunks")
        .iter()
        .map(|chunk| chunk.as_str().unwrap_or(""))
        .collect();
    assert!(
        joined.contains("hello-scene"),
        "the fixture echoed the scripted input back: {joined}"
    );
    assert_eq!(
        document["terminal"]["output_capped"], false,
        "a small run never reports the cap"
    );

    let entries = document["filesystem"]["entries"]
        .as_array()
        .expect("the filesystem block classifies");
    let created = entries
        .iter()
        .find(|e| e["path"] == "new.dat")
        .expect("the created path reads");
    assert_eq!(created["change"], "created");
    assert_eq!(created["size_bytes"], 12, "'new-content' plus the newline");
    assert_eq!(
        created["sha256"].as_str().unwrap_or_default(),
        sha256_hex(&ws.path().join("new.dat")),
        "the whole-file digest matches the bytes on disk after the run"
    );
    assert_eq!(
        created["block_hashes"].as_array().map(Vec::len),
        Some(1),
        "12 bytes stand as one 4 KiB block"
    );
    let deleted = entries
        .iter()
        .find(|e| e["path"] == "old.dat")
        .expect("the deleted path reads");
    assert_eq!(deleted["change"], "deleted");
    assert_eq!(deleted["size_bytes"], 9, "the before side's size");

    assert_eq!(
        document["interaction"]["acknowledged_at_ms"],
        serde_json::json!([1000, 1500, 2000, 2500]),
        "every delivered interaction is acknowledged at its declared offset"
    );

    assert_eq!(
        document["pairing"]["program_sha256"]
            .as_str()
            .unwrap_or_default(),
        sha256_hex(&staged),
        "the capture stamps the sha256 of the very bytes it ran"
    );
    let wine_version = document["pairing"]["wine_version"].as_str().unwrap_or("");
    assert!(
        wine_version.contains("wine"),
        "the pairing names the Wine that ran it: {wine_version}"
    );

    let samples = document["process"]["samples"]
        .as_array()
        .expect("the process block stands");
    assert_eq!(samples.len(), 1, "one honest launch sample");
    assert_eq!(samples[0]["name"], BINARY);

    let captures_dir = ws.path().join("re").join("scenarios").join("captures");
    let filed: Vec<_> = std::fs::read_dir(&captures_dir)
        .expect("the captures directory stands")
        .flatten()
        .collect();
    assert_eq!(
        filed.len(),
        1,
        "exactly one current capture per scenario name"
    );
}

#[test]
#[ignore = "needs Wine and the fixture console EXE"]
fn a_re_capture_against_changed_bytes_states_the_pairing_mismatch_then_replaces() {
    // The pairing rule at the filing point: a re-capture replaces the
    // previous document outright — but changed program bytes are a
    // stated mismatch, never silent.
    let ws = workspace();
    let staged = stage_fixture_exe(ws.path());
    declare_boot_scenario(ws.path(), "boot", "65536");

    let (ok, stdout, stderr) = capture(ws.path(), "boot");
    assert!(ok, "the first capture runs under Wine: {stdout}{stderr}");
    let standing_digest = sha256_hex(&staged);

    // Different program bytes: one overlay byte appended, a stated
    // change of the very file the run stands on.
    let mut mutated = std::fs::read(&staged).expect("the staged program reads");
    mutated.push(0x00);
    std::fs::write(&staged, &mutated).expect("the program bytes change");

    let (ok, stdout, stderr) = capture(ws.path(), "boot");
    let combined = format!("{stdout}{stderr}");
    assert!(ok, "the re-capture still files: {combined}");
    assert!(
        combined.contains("PAIRING MISMATCH"),
        "the pairing rule speaks out loud before replacing: {combined}"
    );
    assert!(
        combined.contains(&standing_digest),
        "the mismatch names the standing capture's digest: {combined}"
    );

    let document = read_capture_document(ws.path(), "boot");
    assert_eq!(
        document["pairing"]["program_sha256"]
            .as_str()
            .unwrap_or_default(),
        sha256_hex(&staged),
        "the replacement is the current capture, stamped with the bytes it actually ran"
    );

    let captures_dir = ws.path().join("re").join("scenarios").join("captures");
    let filed: Vec<_> = std::fs::read_dir(&captures_dir)
        .expect("the captures directory stands")
        .flatten()
        .collect();
    assert_eq!(
        filed.len(),
        1,
        "re-capture replaces outright — never a second document for one name"
    );
}

#[test]
#[ignore = "needs Wine and the fixture console EXE"]
fn an_oversized_run_caps_its_output_and_says_so_in_the_document_and_the_print() {
    let ws = workspace();
    stage_fixture_exe(ws.path());
    let mut cmd = cli(ws.path());
    cmd.args(["scenario", "declare"])
        .args(["--binary", BINARY, "--scenario", "capped"])
        .args(["--input-at", &format!("1000:echo {}", "L".repeat(2_000))])
        .args(["--input-at", "1500:exit 0"])
        .args(["--idle-timeout-ms", "15000", "--max-run-ms", "30000"])
        .args(["--max-output-bytes", "64"]);
    let (ok, stdout, stderr) = run(&mut cmd, ws.path());
    assert!(ok, "the capped scenario declares: {stdout}{stderr}");

    let (ok, stdout, stderr) = capture(ws.path(), "capped");
    assert!(ok, "a capped run still files its capture: {stdout}{stderr}");
    assert!(
        stdout.contains("capped at 64 bytes"),
        "a capped capture states its cap out loud: {stdout}"
    );

    let document = read_capture_document(ws.path(), "capped");
    assert_eq!(
        document["terminal"]["output_capped"], true,
        "the truncation mark stands in the document"
    );
    assert_eq!(
        document["terminal"]["cap_bytes"], 64,
        "the document names its cap where a reader can see it"
    );
    let recorded: usize = document["terminal"]["chunks"]
        .as_array()
        .expect("the terminal block names its chunks")
        .iter()
        .map(|chunk| chunk.as_str().unwrap_or("").len())
        .sum();
    assert!(
        recorded <= 64,
        "the capture never claims more than it saw: {recorded} bytes"
    );
}
