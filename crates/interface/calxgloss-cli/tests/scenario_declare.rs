//! Process-level e2e for the `scenario declare` command (P24.1, issue
//! #402): the built CLI validates a declared scenario contract and files
//! it in the record tree as one owned document per target binary — and a
//! malformed declaration is refused naming the offending field, with
//! nothing filed at all. No Wine and no target file in sight: declaring
//! is authoring, and the contract document speaks for a binary by name.

use std::path::Path;
use std::process::Command;

/// Run the built CLI isolated from the ambient config, as every engine
/// test does.
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

fn run(cmd: &mut Command, dir: &Path) -> (bool, String, String) {
    let out = cmd.current_dir(dir).output().expect("the CLI ran");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// A workspace dir holding the `wd` working dir the declares point at.
fn workspace() -> tempfile::TempDir {
    let dir = tempfile::TempDir::new().expect("a temp workspace");
    std::fs::create_dir(dir.path().join("wd")).expect("the working dir exists");
    dir
}

/// The full-declaration command line every happy-path pin reuses.
/// `scenario`, `working_dir`, and `max_run_ms` are the parameters pins
/// override; everything else is the fixed full declaration.
fn declare<'a>(
    cli: &'a mut Command,
    scenario: &str,
    working_dir: &str,
    max_run_ms: &str,
) -> &'a mut Command {
    cli.arg("scenario")
        .arg("declare")
        .arg("--binary")
        .arg("eqgame.exe")
        .arg("--scenario")
        .arg(scenario)
        .arg("--working-dir")
        .arg(working_dir)
        .arg("--env")
        .arg("CALX_DEMO=1")
        .arg("--arg")
        .arg("--fast")
        .arg("--input-at")
        .arg("500:menu choice")
        .arg("--secret-at")
        .arg("900:hunter2secret")
        .arg("--resize-at")
        .arg("1200:120x40")
        .arg("--signal-at")
        .arg("1500:interrupt")
        .arg("--observe")
        .arg("save/out.dat")
        .arg("--observe")
        .arg("logs")
        .arg("--idle-timeout-ms")
        .arg("5000")
        .arg("--max-run-ms")
        .arg(max_run_ms)
}

#[test]
fn scenario_declare_files_one_owned_contract_document_per_binary() {
    let dir = workspace();
    let mut base = cli(dir.path());
    let (ok, stdout, stderr) = run(declare(&mut base, "boot", "wd", "30000"), dir.path());
    assert!(ok, "the declaration should succeed: {stderr}");

    let filed = dir
        .path()
        .join("re")
        .join("scenarios")
        .join("eqgame.exe.json");
    let raw = std::fs::read_to_string(&filed)
        .expect("the contract document lands at the documented record-tree path");
    let doc: serde_json::Value = raw.parse().expect("the filed document is JSON");
    assert_eq!(
        doc["binary"], "eqgame.exe",
        "the filing envelope names the binary"
    );
    let scenarios = doc["scenarios"].as_object().expect("a scenario map");
    assert_eq!(scenarios.len(), 1, "one scenario declared");
    let contract = &scenarios["boot"];
    assert_eq!(contract["working_dir"], "wd");
    assert_eq!(contract["env"]["CALX_DEMO"], "1");
    assert_eq!(contract["argv"][0], "--fast");
    assert_eq!(
        contract["observation_paths"].as_array().map(Vec::len),
        Some(2)
    );
    assert_eq!(contract["idle_timeout_ms"], 5_000);
    assert_eq!(contract["max_run_ms"], 30_000);
    assert_eq!(contract["normalization"]["version"], "norm-v1");
    let interactions = contract["interactions"].as_array().expect("interactions");
    assert_eq!(interactions.len(), 4, "input, secret, resize, signal");

    // Sensitive scripted inputs persist as byte-count placeholders: the
    // secret text appears nowhere in the filed document's raw bytes.
    assert!(raw.contains("\"byte_count\""), "the placeholder is filed");
    assert!(
        !raw.contains("hunter2secret"),
        "a declared secret never lands in the record tree"
    );
    println!("{stdout}");
}

#[test]
fn several_scenarios_coexist_and_re_declaring_replaces_by_name() {
    let dir = workspace();
    let mut base = cli(dir.path());
    let (ok, _, stderr) = run(declare(&mut base, "boot", "wd", "30000"), dir.path());
    assert!(ok, "the first declare: {stderr}");

    let mut login = cli(dir.path());
    login
        .arg("scenario")
        .arg("declare")
        .arg("--binary")
        .arg("eqgame.exe")
        .arg("--scenario")
        .arg("login")
        .arg("--working-dir")
        .arg("wd");
    let (ok, _, stderr) = run(&mut login, dir.path());
    assert!(ok, "the second scenario coexists: {stderr}");

    // Re-declare `boot` with a different window: replaced, not appended.
    let mut again_base = cli(dir.path());
    let again = declare(&mut again_base, "boot", "wd", "60000");
    let (ok, _, stderr) = run(again, dir.path());
    assert!(ok, "re-declaring is accepted: {stderr}");

    let filed = dir
        .path()
        .join("re")
        .join("scenarios")
        .join("eqgame.exe.json");
    let doc: serde_json::Value = std::fs::read_to_string(&filed)
        .expect("the document is still there")
        .parse()
        .expect("still JSON");
    let scenarios = doc["scenarios"].as_object().expect("a scenario map");
    assert_eq!(
        scenarios.len(),
        2,
        "exactly one current contract per scenario name"
    );
    assert_eq!(
        scenarios["boot"]["max_run_ms"], 60_000,
        "the re-declared contract replaced the old one outright"
    );
}

#[test]
fn an_unresolvable_working_dir_is_refused_naming_the_field_and_nothing_files() {
    let dir = workspace();
    let mut base = cli(dir.path());
    let cmd = declare(&mut base, "boot", "nowhere", "30000");
    let (ok, _, stderr) = run(cmd, dir.path());
    assert!(!ok, "an unresolvable working dir is refused");
    assert!(
        stderr.contains("working_dir"),
        "the refusal names the field: {stderr}"
    );
    assert!(
        !dir.path().join("re").join("scenarios").exists(),
        "nothing files on refusal"
    );
}

#[test]
fn an_observation_path_escaping_the_run_dir_is_refused_naming_the_field() {
    let dir = workspace();
    let mut base = cli(dir.path());
    let cmd = declare(&mut base, "boot", "wd", "30000");
    cmd.arg("--observe").arg("../escape");
    let (ok, _, stderr) = run(cmd, dir.path());
    assert!(!ok, "an escaping observation path is refused");
    assert!(
        stderr.contains("observation_paths"),
        "the refusal names the field: {stderr}"
    );
    assert!(
        !dir.path().join("re").join("scenarios").exists(),
        "nothing files on refusal"
    );
}

#[test]
fn an_absurd_timing_value_is_refused_naming_the_field() {
    let dir = workspace();
    let mut base = cli(dir.path());
    // Ten days, in ms: beyond any sane scenario window.
    let cmd = declare(&mut base, "boot", "wd", "864000001");
    let (ok, _, stderr) = run(cmd, dir.path());
    assert!(!ok, "an absurd max run duration is refused");
    assert!(
        stderr.contains("max_run_ms"),
        "the refusal names the field: {stderr}"
    );
    assert!(
        !dir.path().join("re").join("scenarios").exists(),
        "nothing files on refusal"
    );
}

#[test]
fn a_malformed_interaction_flag_names_its_flag_and_files_nothing() {
    let dir = workspace();
    let mut cmd = cli(dir.path());
    cmd.arg("scenario")
        .arg("declare")
        .arg("--binary")
        .arg("eqgame.exe")
        .arg("--scenario")
        .arg("boot")
        .arg("--working-dir")
        .arg("wd")
        .arg("--input-at")
        .arg("not-an-offset");
    let (ok, _, stderr) = run(&mut cmd, dir.path());
    assert!(!ok, "a malformed --input-at value is refused");
    assert!(
        stderr.contains("--input-at"),
        "the refusal names the flag: {stderr}"
    );
    assert!(
        !dir.path().join("re").join("scenarios").exists(),
        "nothing files on refusal"
    );
}

#[test]
fn a_path_shaped_binary_identity_is_refused_naming_the_flag_and_files_nothing() {
    let dir = workspace();
    let mut cmd = cli(dir.path());
    cmd.arg("scenario")
        .arg("declare")
        .arg("--binary")
        .arg("../evil")
        .arg("--scenario")
        .arg("boot")
        .arg("--working-dir")
        .arg("wd");
    let (ok, _, stderr) = run(&mut cmd, dir.path());
    assert!(!ok, "a path-shaped binary identity is refused");
    assert!(
        stderr.contains("--binary") && stderr.contains("bare binary identity"),
        "the refusal names the flag: {stderr}"
    );
    assert!(
        !dir.path().join("re").join("scenarios").exists(),
        "nothing files on refusal"
    );
    // And nothing escaped upward either.
    assert!(
        !dir.path()
            .parent()
            .map(|p| p.join("evil.json").exists())
            .unwrap_or(false),
        "the refused identity never files outside the owner directory"
    );
}
