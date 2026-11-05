//! Smoke test for the fixture console EXE (P24.2, issue #403).
//!
//! The scenario lane needs a console program it can run for real: one that
//! consumes stdin lines, writes observable files under its run dir, and
//! exits with declared codes. This test is the gate that fires when the
//! EXE stops being built or stops having the PE identity later scenario
//! slices will name — same rule as the DLL fixture's smoke test: the
//! fixture crate validates the shape with a named error, and this pin
//! catches a broken fixture before a scenario test fails deep inside
//! itself with it.

use std::path::Path;

use calxgloss_testfixtures::{
    CONSOLE_IDENTITY_LITERALS, CONSOLE_SUBSYSTEM, CONSOLE_TARGET_FILE_NAME, console_target_path,
    load_console_target,
};

#[test]
fn fixture_console_exe_is_built_and_reachable() {
    let path =
        console_target_path().expect("build script should have compiled the fixture console exe");
    assert!(path.ends_with(CONSOLE_TARGET_FILE_NAME));
    let size = path
        .metadata()
        .expect("fixture console exe should be readable")
        .len();
    assert!(size > 0, "fixture console exe should not be empty");
}

#[test]
fn fixture_console_exe_is_an_x8664_console_exe_not_a_dll() {
    // The scenario lane launches this as a child program: an exe, not a
    // DLL, x86-64 like the fixture DLLs, on the console subsystem. A
    // fixture that drifted to any other shape fails `load_console_target`
    // with the named error for that shape, so a clean load plus the
    // subsystem read pins the identity later scenario slices name.
    let target = load_console_target().expect("fixture console exe should load");
    assert_eq!(
        target.subsystem(),
        CONSOLE_SUBSYSTEM,
        "the console fixture must declare the console subsystem"
    );
    assert!(
        target.image_base() != 0,
        "the console fixture should carry an image base"
    );
}

#[test]
fn fixture_console_exe_carries_its_identity_literals() {
    // A reviewer (and the pairing stamps of a later scenario capture)
    // names this fixture by these facts, exactly like the DLL fixture's
    // string literals — never by a build path.
    let target = load_console_target().expect("fixture console exe should load");
    for literal in CONSOLE_IDENTITY_LITERALS {
        assert!(
            target.strings().iter().any(|found| found == literal),
            "the console fixture should carry its identity literal `{literal}`"
        );
    }
}

// ============================================================
// The scriptable protocol, under Wine (ignored by default)
// ============================================================

/// A named run dir for one Wine run: a `tempfile::TempDir` the EXE
/// executes in, so declared file writes land under it, concurrent tests
/// never collide, and cleanup happens on drop.
fn wine_run_dir(test: &str) -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix(&format!("calxgloss-console-fixture-{test}-"))
        .tempdir()
        .expect("run dir should be creatable")
}

/// Run the fixture console EXE under Wine in `dir`, with `stdin` piped
/// in and `args` appended; returns (exit code, stdout text). Honors
/// `CALXGLOSS_WINE` for the wine binary, same as the testgen harness.
fn run_under_wine(dir: &Path, args: &[&str], stdin: &[u8]) -> (i32, String) {
    let target = load_console_target().expect("fixture console exe should load");
    let wine = std::env::var("CALXGLOSS_WINE").unwrap_or_else(|_| "wine".into());
    let mut cmd = std::process::Command::new(wine);
    cmd.arg(target.path())
        .args(args)
        .current_dir(dir)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped());
    let mut child = cmd.spawn().expect("wine should launch the fixture");
    use std::io::Write;
    child
        .stdin
        .take()
        .expect("stdin is piped")
        .write_all(stdin)
        .expect("stdin should be accepted");
    let out = child
        .wait_with_output()
        .expect("the fixture run should finish");
    let code = out.status.code().expect("wine propagates the exit code");
    (code, String::from_utf8_lossy(&out.stdout).into_owned())
}

#[test]
#[ignore = "needs Wine and the mingw cross-toolchain"]
fn fixture_console_exe_consumes_stdin_and_files_writes_and_exits_with_a_declared_code() {
    // The interaction, terminal, filesystem, and exit dimensions in one
    // run: stdin lines are consumed and echoed, a declared file write
    // lands under the run dir, and `exit 7` ends the run with that code.
    let dir = wine_run_dir("stdin-protocol");
    let (code, stdout) = run_under_wine(
        dir.path(),
        &[],
        b"echo hello scenario\nwrite out.dat created by fixture\nexit 7\n",
    );
    assert_eq!(code, 7, "the declared stdin exit code propagates");
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(
        lines,
        [
            "calxgloss fixture console ready",
            "calxgloss-fixture-console-v1",
            "hello scenario",
            "wrote out.dat",
        ],
        "output is echo-ordered and every interaction is acknowledged"
    );
    let written = dir.path().join("out.dat");
    let content = std::fs::read_to_string(&written).expect("the declared write landed");
    assert_eq!(
        content, "created by fixture\n",
        "the file carries the declared content"
    );
}

#[test]
#[ignore = "needs Wine and the mingw cross-toolchain"]
fn fixture_console_exe_exits_with_the_code_named_in_argv_at_eof() {
    // EOF closes the run on the argv-declared code: the exit dimension
    // has two declaration routes, and rigged comparisons can force a
    // named divergence through either.
    let dir = wine_run_dir("argv-exit-code");
    let (code, stdout) = run_under_wine(dir.path(), &["--exit-code", "3"], b"echo before eof\n");
    assert_eq!(code, 3, "the argv-declared exit code propagates at EOF");
    assert!(
        stdout.contains("before eof"),
        "stdin lines before EOF are consumed: {stdout}"
    );
}

#[test]
#[ignore = "needs Wine and the mingw cross-toolchain"]
fn fixture_console_exe_prints_what_argv_says_injected_into_the_output() {
    // The terminal dimension's argv declaration route (P24.7, issue
    // #408): `--say TEXT` prints TEXT to stdout at start, so a rigged
    // comparison forces a named output difference through argv alone —
    // the same route the exit code has.
    let dir = wine_run_dir("argv-say");
    let (code, stdout) = run_under_wine(
        dir.path(),
        &["--say", "argv-injected-output-line"],
        b"echo after say\nexit 0\n",
    );
    assert_eq!(code, 0, "the run carries on after the injected line");
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(
        lines,
        [
            "calxgloss fixture console ready",
            "calxgloss-fixture-console-v1",
            "argv-injected-output-line",
            "after say",
        ],
        "the injected line prints after the identity lines, before stdin acks"
    );
}

#[test]
#[ignore = "needs Wine and the mingw cross-toolchain"]
fn fixture_console_exe_refuses_a_say_without_its_text_loudly() {
    // Like a malformed `--exit-code`, a `--say` stripped of its text is
    // refused loudly on stderr with exit 2: a rig that silently prints
    // nothing is the silence this fixture never allows.
    let dir = wine_run_dir("argv-say-missing");
    let wine = std::env::var("CALXGLOSS_WINE").unwrap_or_else(|_| "wine".into());
    let target = calxgloss_testfixtures::console_target_path()
        .expect("build script should have compiled the fixture console exe");
    let out = std::process::Command::new(wine)
        .arg(target)
        .args(["--say"])
        .current_dir(dir.path())
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .output()
        .expect("wine should launch the fixture");
    assert_eq!(
        out.status.code(),
        Some(2),
        "the flag missing its text ends the run with exit 2"
    );
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        stderr.contains("--say needs text"),
        "the refusal names the flag it missed: {stderr}"
    );
}
