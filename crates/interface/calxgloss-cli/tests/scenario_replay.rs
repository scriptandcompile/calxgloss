//! Process-level e2e for the `scenario replay` command (P24.7, issue
//! #408): the declared scenario contract runs against **any program the
//! operator names** — a restitched build checked out on an attempt
//! branch, standing in here for the byte-identical or rigged copy of the
//! fixture console EXE — and the replay's *scenario capture* files
//! beside the original's at
//! `re/scenarios/captures/{binary}-{scenario}-replay.json`. The operator
//! chain is declare → capture → replay → compare, and the compare pairs
//! the two filed captures when the operator names no `--left`/`--right`.
//!
//! The refusal pins are ungated: replaying before any declaration names
//! the declare step, a named program that is not there is refused by
//! path, and a missing Wine fails naming the Wine it looked for — every
//! refusal files nothing. The chain and rigged-fixture pins need Wine
//! and the fixture console EXE, so they stand ignored like the capture
//! suite's full-run pins.
//!
//! The rig pins prove the named-dimension failures end to end: a replay
//! whose observed paths drifted (the created file left standing, a
//! deleted file restaged with different bytes) fails the **filesystem
//! dimension** naming the file by both digests; a replay run whose argv
//! carries a `--say` line the original's run never printed fails the
//! **terminal dimension** naming the segment. The replay never depends
//! on any whole-EXE build machinery: a path is the only thing named.

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
/// and the declared exit code — the shapes the replay pins read. The
/// idle window outlasts Wine's own boot.
fn declare_boot_scenario(ws: &Path, scenario: &str) {
    let mut cmd = cli(ws);
    cmd.args(["scenario", "declare"])
        .args(["--binary", BINARY, "--scenario", scenario])
        .args(["--input-at", "1000:echo hello-scene"])
        .args(["--input-at", "1500:write new.dat new-content"])
        .args(["--input-at", "2000:delete old.dat"])
        .args(["--input-at", "2500:exit 7"])
        .args(["--observe", "new.dat", "--observe", "old.dat"])
        .args(["--idle-timeout-ms", "15000", "--max-run-ms", "30000"])
        .args(["--max-output-bytes", "65536"]);
    let (ok, stdout, stderr) = run(&mut cmd, ws);
    assert!(ok, "the scenario declares: {stdout}{stderr}");
}

/// Re-declare the same scenario name with one more argv entry each —
/// the contract evolves between the capture and the replay, and the
/// replay runs under the declaration that stands when it runs.
fn add_argv_to_declaration(ws: &Path, scenario: &str, argv: &[&str]) {
    let mut cmd = cli(ws);
    cmd.args(["scenario", "declare"])
        .args(["--binary", BINARY, "--scenario", scenario])
        .args(["--input-at", "1000:echo hello-scene"])
        .args(["--input-at", "1500:write new.dat new-content"])
        .args(["--input-at", "2000:delete old.dat"])
        .args(["--input-at", "2500:exit 7"])
        .args(["--observe", "new.dat", "--observe", "old.dat"])
        .args(["--idle-timeout-ms", "15000", "--max-run-ms", "30000"])
        .args(["--max-output-bytes", "65536"]);
    for entry in argv {
        cmd.args(["--arg", entry]);
    }
    let (ok, stdout, stderr) = run(&mut cmd, ws);
    assert!(ok, "the scenario re-declares: {stdout}{stderr}");
}

fn capture(ws: &Path, scenario: &str, prefix: Option<&Path>) -> (bool, String, String) {
    let mut cmd = cli(ws);
    cmd.args(["scenario", "capture"])
        .args(["--binary", BINARY, "--scenario", scenario]);
    if let Some(prefix) = prefix {
        cmd.env("WINEPREFIX", prefix);
    }
    run(&mut cmd, ws)
}

fn replay(
    ws: &Path,
    scenario: &str,
    program: &Path,
    prefix: Option<&Path>,
) -> (bool, String, String) {
    let mut cmd = cli(ws);
    cmd.args(["scenario", "replay"])
        .args(["--binary", BINARY, "--scenario", scenario])
        .args(["--program", &program.display().to_string()]);
    if let Some(prefix) = prefix {
        cmd.env("WINEPREFIX", prefix);
    }
    run(&mut cmd, ws)
}

/// The chain's compare: no `--left`/`--right` named — the command pairs
/// the two filed captures beside each other in the record tree.
fn compare_filed_pair(ws: &Path, scenario: &str) -> (bool, String, String) {
    let mut cmd = cli(ws);
    cmd.args(["scenario", "compare"])
        .args(["--binary", BINARY, "--scenario", scenario]);
    run(&mut cmd, ws)
}

/// Warm a Wine prefix owned by one workspace alone — the private-prefix
/// recipe from the run-seam pins, so a parallel pin's guests never ride
/// these runs' samples.
fn warm_private_prefix(ws: &Path) -> PathBuf {
    let prefix = ws.join("wine-prefix");
    std::fs::create_dir_all(&prefix).expect("the private prefix dir stands");
    let status = Command::new("wine")
        .args(["cmd.exe", "/c", "exit"])
        .env("WINEPREFIX", &prefix)
        .env("WINEDEBUG", "-all")
        .env("WINEDLLOVERRIDES", "mscoree,mshtml=")
        .status()
        .expect("the prefix initializer runs");
    assert!(status.success(), "the private prefix set up clean");
    prefix
}

fn capture_path(ws: &Path, scenario: &str) -> PathBuf {
    ws.join("re")
        .join("scenarios")
        .join("captures")
        .join(format!("{BINARY}-{scenario}.json"))
}

fn replay_capture_path(ws: &Path, scenario: &str) -> PathBuf {
    ws.join("re")
        .join("scenarios")
        .join("captures")
        .join(format!("{BINARY}-{scenario}-replay.json"))
}

fn filed_verdict(ws: &Path, scenario: &str) -> PathBuf {
    ws.join("re")
        .join("scenarios")
        .join("verdicts")
        .join(format!("{BINARY}-{scenario}.json"))
}

fn read_document(path: &Path) -> serde_json::Value {
    let raw = std::fs::read_to_string(path)
        .unwrap_or_else(|_| panic!("the document files at {}", path.display()));
    serde_json::from_str(&raw).expect("the document is JSON")
}

// ============================================================
// Refusals: ungated, named, never a filing
// ============================================================

#[test]
fn a_replay_with_nothing_declared_is_refused_toward_the_declare_step() {
    let ws = workspace();
    let (ok, _, stderr) = replay(ws.path(), "boot", &ws.path().join("any-program.exe"), None);
    assert!(!ok, "a replay with no contract document cannot succeed");
    assert!(
        stderr.contains("declare the scenario before replaying it"),
        "the refusal points at the missing declaration: {stderr}"
    );
    assert!(
        !ws.path().join("re").exists(),
        "a refused replay files nothing"
    );
}

#[test]
fn a_replay_naming_a_program_that_is_not_there_is_refused_naming_the_path() {
    // The replay runs a path the operator names — and a path that leads
    // nowhere is refused by that path, before Wine is even asked.
    let ws = workspace();
    declare_boot_scenario(ws.path(), "boot");
    let named = ws.path().join("attempt-branch").join("fixture_console.exe");
    let (ok, stdout, stderr) = replay(ws.path(), "boot", &named, None);
    let combined = format!("{stdout}{stderr}");
    assert!(!ok, "no program at the named path, no replay");
    assert!(
        combined.contains(&named.display().to_string()),
        "the refusal names the path the operator gave: {combined}"
    );
    assert!(
        !replay_capture_path(ws.path(), "boot").exists(),
        "a refused replay files nothing"
    );
}

#[test]
fn a_replay_with_no_wine_fails_by_name_and_files_nothing() {
    // The standing preflight line governs the replay too: the failure
    // names the Wine it looked for and carries the CALXGLOSS_WINE
    // guidance — the replay shares the capture's machinery exactly here.
    let ws = workspace();
    stage_fixture_exe(ws.path());
    declare_boot_scenario(ws.path(), "boot");
    std::fs::write(ws.path().join("old.dat"), b"old-bytes").expect("the before-side file stands");

    let mut cmd = cli(ws.path());
    cmd.env("CALXGLOSS_WINE", "/nonexistent/wine-not-on-this-machine")
        .args(["scenario", "replay"])
        .args(["--binary", BINARY, "--scenario", "boot"])
        .args(["--program", &ws.path().join(BINARY).display().to_string()]);
    let (ok, _, stderr) = run(&mut cmd, ws.path());
    assert!(!ok, "a missing Wine must fail the replay");
    assert!(
        stderr.contains("/nonexistent/wine-not-on-this-machine"),
        "the failure names the Wine it looked for: {stderr}"
    );
    assert!(
        stderr.contains("CALXGLOSS_WINE"),
        "the failure carries the standing preflight guidance: {stderr}"
    );
    assert!(
        !replay_capture_path(ws.path(), "boot").exists(),
        "a replay that never ran files nothing"
    );
}

// ============================================================
// The chain under Wine: capture → replay → compare, and the
// rigged replays that make the named-dimension failures real
// ============================================================

/// One declared before-side file's content for the boot scenario.
const OLD_BYTES: &[u8] = b"old-bytes";

fn sha256_of(bytes: &[u8]) -> String {
    use sha2::{Digest as _, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Restage the run dir (the workspace root, where the scenario's relative
/// working dir lands) to the state the declaration speaks for: old.dat
/// standing with its before-side bytes, new.dat nowhere. Capture and
/// replay then face the same starting state, so any dimension failure the
/// pins assert belongs to the rig, not to run-to-run drift.
fn reset_run_dir(ws: &Path) {
    std::fs::write(ws.join("old.dat"), OLD_BYTES).expect("old.dat restages");
    let _ = std::fs::remove_file(ws.join("new.dat"));
}

#[test]
#[ignore = "needs Wine and the fixture console EXE"]
fn the_declare_capture_replay_compare_chain_files_its_way_through_a_byte_identical_copy() {
    // The operator chain end to end: the scenario is captured against the
    // staged fixture, replayed against a byte-identical copy standing on
    // an attempt-branch-like path, and compared with neither --left nor
    // --right named — the filed pair beside each other. The replay
    // capture files at the `-replay` name beside the original's, the
    // pairing stamps match, and a re-replay replaces it outright: one
    // current replay per (binary, scenario name), same as the capture.
    let ws = workspace();
    let staged = stage_fixture_exe(ws.path());
    let prefix = warm_private_prefix(ws.path());
    std::fs::write(ws.path().join("old.dat"), OLD_BYTES).expect("the before-side file stands");
    declare_boot_scenario(ws.path(), "boot");

    let (ok, stdout, stderr) = capture(ws.path(), "boot", Some(&prefix));
    assert!(ok, "the original captures under Wine: {stdout}{stderr}");

    // The copy the replay names: same file name, same bytes, different
    // standing — what a restitched build is to its original.
    let branch = ws.path().join("attempt-branch");
    std::fs::create_dir_all(&branch).expect("the attempt-branch-like dir stands");
    let copy = branch.join(BINARY);
    std::fs::copy(&staged, &copy).expect("the byte-identical copy stages");

    reset_run_dir(ws.path());
    let (ok, stdout, stderr) = replay(ws.path(), "boot", &copy, Some(&prefix));
    assert!(ok, "the replay runs the named copy: {stdout}{stderr}");
    assert!(
        stdout.contains("identical program bytes"),
        "the replay states its pairing against the original: {stdout}"
    );

    // Re-replay: the previous replay's document is replaced, never
    // stacked — exactly one current replay stands for the name.
    reset_run_dir(ws.path());
    let (ok, _, stderr) = replay(ws.path(), "boot", &copy, Some(&prefix));
    assert!(ok, "the second replay runs too: {stdout}{stderr}");

    let captures_dir = ws.path().join("re").join("scenarios").join("captures");
    let replay_docs: Vec<_> = std::fs::read_dir(&captures_dir)
        .expect("the captures dir stands")
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.ends_with("-replay.json"))
        })
        .collect();
    assert_eq!(
        replay_docs.len(),
        1,
        "exactly one current replay capture per scenario name"
    );

    // The pairing stamps read beside both captures: byte-identical
    // programs pair, and the replay document says so with the same
    // digest the original's stamp carries.
    let original = read_document(&capture_path(ws.path(), "boot"));
    let replay_doc = read_document(&replay_capture_path(ws.path(), "boot"));
    assert_eq!(
        replay_doc["pairing"]["program_sha256"], original["pairing"]["program_sha256"],
        "byte-identical copies carry the same pairing stamp"
    );

    // The chain's compare: no --left/--right named — it pairs the filed
    // original on the left with the filed replay on the right.
    let (ok, stdout, stderr) = compare_filed_pair(ws.path(), "boot");
    assert!(ok, "the filed pair compares: {stdout}{stderr}");
    assert!(
        stdout.contains("identical program bytes"),
        "the compare reads the pairing rule out loud beside both captures: {stdout}"
    );
    let verdict = read_document(&filed_verdict(ws.path(), "boot"));
    for dimension in ["exit", "interaction", "filesystem"] {
        assert_eq!(
            verdict["verdict"][dimension].as_str(),
            Some("assessed_pass"),
            "the run dir stood reset, so {dimension} compares clean between \
             two runs of one program's bytes"
        );
    }
    // The terminal and process dimensions are deliberately not asserted
    // here: PTY chunk boundaries and wine-helper process rows drift
    // between two runs of one identical program, and this pin's job is
    // the chain's filing, not that flake.
    assert!(
        filed_verdict(ws.path(), "boot").is_file()
            && stdout.contains("filed at")
            && stdout.contains("digest"),
        "the verdict files at its record tree location with its digest: {stdout}"
    );
}

#[test]
#[ignore = "needs Wine and the fixture console EXE"]
fn a_rigged_replay_whose_run_dir_drifted_fails_the_filesystem_dimension_naming_both_digests() {
    // Rig A: the replay runs the same program bytes, but the run dir it
    // faces is not the declared state — the first run's new.dat is left
    // standing with different bytes, and old.dat is restaged with a
    // different before-side. The comparison then judges two different
    // filesystem stories and fails the dimension naming both files by
    // their digests — the record logic does its job on a real pair.
    let ws = workspace();
    let staged = stage_fixture_exe(ws.path());
    let prefix = warm_private_prefix(ws.path());
    std::fs::write(ws.path().join("old.dat"), OLD_BYTES).expect("the before-side file stands");
    declare_boot_scenario(ws.path(), "boot");
    let (ok, stdout, stderr) = capture(ws.path(), "boot", Some(&prefix));
    assert!(ok, "the original captures under Wine: {stdout}{stderr}");

    // The drift the rig stages: new.dat left with different bytes,
    // old.dat restaged different. No reset.
    std::fs::write(ws.path().join("new.dat"), b"leftover-different")
        .expect("the leftover new.dat stands with different bytes");
    std::fs::write(ws.path().join("old.dat"), b"different-old-bytes")
        .expect("old.dat restages with a different before-side");

    let (ok, stdout, stderr) = replay(ws.path(), "boot", &staged, Some(&prefix));
    assert!(ok, "the rigged replay runs: {stdout}{stderr}");
    let (ok, stdout, stderr) = compare_filed_pair(ws.path(), "boot");
    assert!(
        ok,
        "an assessed fail is a verdict, not a command failure: {stdout}{stderr}"
    );

    let verdict = read_document(&filed_verdict(ws.path(), "boot"));
    assert_eq!(
        verdict["verdict"]["filesystem"].as_str(),
        Some("assessed_fail"),
        "the drifted filesystem story is judged, not excused"
    );
    assert_eq!(
        verdict["verdict"]["exit"].as_str(),
        Some("assessed_pass"),
        "one program's bytes exit the same declared code — only the \
         rigged dimension fails: {stdout}"
    );
    // The files are named by digest, both sides beside the name.
    let combined = format!("{stdout}{stderr}");
    for name in ["new.dat", "old.dat"] {
        assert!(
            combined.contains(&format!("filesystem path {name}")),
            "the divergence names the file {name}: {combined}"
        );
    }
    // new.dat: the fixture wrote "new-content\n" again (the fixture's
    // write line appends a newline) — the replay side's digest carries
    // those bytes; the original's created-side digest too.
    let new_content_digest = sha256_of(b"new-content\n");
    assert!(
        combined.contains(&new_content_digest),
        "new.dat's new-content digest is stated: {combined}"
    );
    let before_digest = sha256_of(OLD_BYTES);
    let drifted_digest = sha256_of(b"different-old-bytes");
    assert!(
        combined.contains(&before_digest) && combined.contains(&drifted_digest),
        "old.dat's two different before-side digests stand beside the name: {combined}"
    );
}

#[test]
#[ignore = "needs Wine and the fixture console EXE"]
fn an_argv_injected_output_difference_fails_the_terminal_dimension_naming_the_segment() {
    // Rig B: the same program bytes run both times, but the declaration
    // gains a `--say <sentinel>` argv line between capture and replay —
    // the replay runs under the declaration that stands when it runs,
    // and the injected line makes the terminal story differ. The
    // comparison fails the terminal dimension naming the segment with
    // both sides' text beside it: the sentinel appears where the
    // original never printed it.
    const SENTINEL: &str = "GLOSSARY-REPLAY-RIG-9f3c2b";
    let ws = workspace();
    let staged = stage_fixture_exe(ws.path());
    let prefix = warm_private_prefix(ws.path());
    std::fs::write(ws.path().join("old.dat"), OLD_BYTES).expect("the before-side file stands");
    declare_boot_scenario(ws.path(), "boot");
    let (ok, stdout, stderr) = capture(ws.path(), "boot", Some(&prefix));
    assert!(ok, "the original captures under Wine: {stdout}{stderr}");

    // The declaration evolves; the replay follows it.
    add_argv_to_declaration(ws.path(), "boot", &["--say", SENTINEL]);
    reset_run_dir(ws.path());
    let (ok, stdout, stderr) = replay(ws.path(), "boot", &staged, Some(&prefix));
    assert!(
        ok,
        "the rigged replay runs under the new declaration: {stdout}{stderr}"
    );

    let (ok, stdout, stderr) = compare_filed_pair(ws.path(), "boot");
    assert!(
        ok,
        "an assessed fail is a verdict, not a command failure: {stdout}{stderr}"
    );
    let verdict = read_document(&filed_verdict(ws.path(), "boot"));
    assert_eq!(
        verdict["verdict"]["terminal"].as_str(),
        Some("assessed_fail"),
        "the argv-injected output difference is judged in the terminal dimension"
    );
    let combined = format!("{stdout}{stderr}");
    assert!(
        combined.contains(SENTINEL) && combined.contains("terminal segment"),
        "the divergence names the segment and shows the injected text: {combined}"
    );
    assert_eq!(
        verdict["verdict"]["exit"].as_str(),
        Some("assessed_pass"),
        "one program's declared exit stands while the rigged dimension fails: {stdout}"
    );
}
