//! End-to-end checks for engine selection (issue #205): the built binary
//! runs `doctor` under the kuna engine against the fixture target — loaded
//! in-process, no Ghidra anywhere — and the one-engine gate stops
//! Ghidra-dependent commands under `kuna` by name.

use std::path::Path;
use std::process::Command;

/// Run the built CLI with the ambient config and engine env vars stripped,
/// so the test sees exactly the flags it passes.
fn cli() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_calxgloss-cli"));
    for key in [
        "CALXGLOSS_ANALYSIS_ENGINE",
        "CALXGLOSS_TARGET_DIR",
        "CALXGLOSS_WORKSPACE",
        "CALXGLOSS_CONFIG",
    ] {
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
fn test_doctor_under_kuna_loads_the_fixture_and_reports_identity() {
    let fixture = calxgloss_testfixtures::fixture_target_path().expect("fixture target");
    let dir = tempfile::tempdir().expect("temp dir");
    let (ok, stdout, stderr) = run(
        cli()
            .arg("doctor")
            .arg("--engine")
            .arg("kuna")
            .arg("--binary")
            .arg(&fixture),
        dir.path(),
    );
    assert!(ok, "doctor --engine kuna failed:\n{stdout}\n{stderr}");
    assert!(stdout.contains("Kuna Engine Report"), "{stdout}");
    // The fixture is an x86-64 PE: the engine resolved that language and
    // collected its symbols.
    assert!(stdout.contains("x86:LE:64:default"), "{stdout}");
    assert!(stdout.contains("entry point:"), "{stdout}");
    assert!(stdout.contains("function symbols:"), "{stdout}");
    // The Ghidra stack checks must not have run.
    assert!(!stdout.contains("Ghidra Stack Report"), "{stdout}");
}

#[test]
fn test_doctor_under_kuna_without_a_binary_fails_by_name() {
    let dir = tempfile::tempdir().expect("temp dir");
    let (ok, _, stderr) = run(cli().arg("doctor").arg("--engine").arg("kuna"), dir.path());
    assert!(!ok, "a kuna doctor with no target should fail");
    assert!(stderr.contains("--binary"), "{stderr}");
}

#[test]
fn test_an_unloadable_target_fails_with_the_named_fallback_not_a_backtrace() {
    let dir = tempfile::tempdir().expect("temp dir");
    let junk = dir.path().join("junk.txt");
    std::fs::write(&junk, b"not a binary at all").expect("write junk");
    let (ok, _, stderr) = run(
        cli()
            .arg("doctor")
            .arg("--engine")
            .arg("kuna")
            .arg("--binary")
            .arg(&junk),
        dir.path(),
    );
    assert!(!ok, "an unloadable target should fail");
    assert!(stderr.contains("--engine ghidra"), "{stderr}");
    assert!(!stderr.contains("backtrace"), "{stderr}");
}

#[test]
fn test_a_ghidra_command_under_kuna_names_the_engine_gate() {
    // The one-engine rule: a Ghidra-dependent command under `kuna` fails
    // pointing at the fallback, before any Ghidra work starts.
    let dir = tempfile::tempdir().expect("temp dir");
    let (ok, _, stderr) = run(
        cli()
            .arg("--engine")
            .arg("kuna")
            .arg("--target-dir")
            .arg(dir.path())
            .arg("classify")
            .arg("--binary")
            .arg("anything.dll"),
        dir.path(),
    );
    assert!(!ok, "classify under kuna should fail");
    assert!(stderr.contains("--engine ghidra"), "{stderr}");
}

#[test]
fn test_engine_independent_commands_run_under_kuna() {
    // `config` reads no engine, so it runs under either — and shows the
    // flag layer winning, like every other setting.
    let dir = tempfile::tempdir().expect("temp dir");
    let (ok, stdout, stderr) = run(cli().arg("--engine").arg("kuna").arg("config"), dir.path());
    assert!(ok, "config under kuna should succeed:\n{stdout}\n{stderr}");
    assert!(stdout.contains("engine"), "{stdout}");
    assert!(stdout.contains("kuna"), "{stdout}");
    assert!(stdout.contains("flag"), "{stdout}");
}
