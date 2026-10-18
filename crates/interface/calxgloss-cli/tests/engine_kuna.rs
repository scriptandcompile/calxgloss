//! End-to-end checks for the single-engine CLI (issue #214): the built
//! binary runs `doctor` against the fixture target — Kuna loads it
//! in-process, no Ghidra anywhere — and the retired engine-choice surface
//! is gone: `--engine` is an unknown argument and the stale env vars are
//! ignored.

use std::path::Path;
use std::process::Command;

/// Run the built CLI isolated from the ambient config: the user's global
/// file may hold anything, so each test points `CALXGLOSS_CONFIG` at an
/// empty file in its own temp dir and strips the target/workspace vars.
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

/// Run `cmd` in `dir` so no ambient `calxgloss.toml` is picked up, and
/// return (success, stdout, stderr).
fn run(cmd: &mut Command, dir: &Path) -> (bool, String, String) {
    let out = cmd.current_dir(dir).output().expect("the CLI ran");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn test_doctor_loads_the_fixture_and_reports_identity() {
    let fixture = calxgloss_testfixtures::fixture_target_path().expect("fixture target");
    let dir = tempfile::tempdir().expect("temp dir");
    let (ok, stdout, stderr) = run(
        cli(dir.path()).arg("doctor").arg("--binary").arg(&fixture),
        dir.path(),
    );
    assert!(ok, "doctor failed:\n{stdout}\n{stderr}");
    assert!(stdout.contains("Kuna Engine Report"), "{stdout}");
    // The engine reports the release it is pinned to — derived by the build
    // from the lockfile pin, so the report can never name a different one.
    assert!(stdout.contains("kuna v"), "{stdout}");
    // The fixture is an x86-64 PE: the engine resolved that language and
    // collected its symbols.
    assert!(stdout.contains("x86:LE:64:default"), "{stdout}");
    assert!(stdout.contains("entry point:"), "{stdout}");
    assert!(stdout.contains("function symbols:"), "{stdout}");
    // The retired stack checks are gone: the report names the in-process
    // engine, never an install or a server.
    assert!(!stdout.contains("Ghidra Stack Report"), "{stdout}");
    assert!(
        stdout.to_ascii_lowercase().contains("no install"),
        "the report should say there is nothing to install: {stdout}"
    );
}

#[test]
fn test_doctor_without_a_binary_fails_by_name() {
    let dir = tempfile::tempdir().expect("temp dir");
    let (ok, _, stderr) = run(cli(dir.path()).arg("doctor"), dir.path());
    assert!(!ok, "a doctor with no target should fail");
    assert!(stderr.contains("--binary"), "{stderr}");
}

#[test]
fn test_an_unloadable_target_fails_with_a_named_error_not_a_backtrace() {
    let dir = tempfile::tempdir().expect("temp dir");
    let junk = dir.path().join("junk.txt");
    std::fs::write(&junk, b"not a binary at all").expect("write junk");
    let (ok, _, stderr) = run(
        cli(dir.path()).arg("doctor").arg("--binary").arg(&junk),
        dir.path(),
    );
    assert!(!ok, "an unloadable target should fail");
    assert!(
        stderr.contains("could not load"),
        "the failure should name the engine's load failure: {stderr}"
    );
    assert!(!stderr.contains("backtrace"), "{stderr}");
}

#[test]
fn test_the_engine_flag_is_gone() {
    // #214: there is no engine choice to make, so `--engine` is not a flag
    // at all — clap refuses it as an unknown argument.
    let dir = tempfile::tempdir().expect("temp dir");
    let (ok, _, stderr) = run(
        cli(dir.path()).arg("--engine").arg("kuna").arg("config"),
        dir.path(),
    );
    assert!(!ok, "--engine should no longer be accepted");
    assert!(stderr.contains("--engine"), "{stderr}");
}

#[test]
fn test_config_runs_with_no_engine_surface_and_ignores_the_stale_env_vars() {
    // The retired variables are simply not read: setting them changes
    // nothing, and the rendered settings name no engine choice and no
    // Ghidra key.
    let dir = tempfile::tempdir().expect("temp dir");
    let (ok, stdout, stderr) = run(
        cli(dir.path())
            .env("CALXGLOSS_ANALYSIS_ENGINE", "kuna")
            .env("CALXGLOSS_GHIDRA_URL", "http://10.0.0.5:8080")
            .arg("config"),
        dir.path(),
    );
    assert!(ok, "config should succeed:\n{stdout}\n{stderr}");
    assert!(!stdout.to_ascii_lowercase().contains("ghidra"), "{stdout}");
}
