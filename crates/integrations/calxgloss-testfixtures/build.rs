//! Build script: compiles the fixture target binary from C source.
//!
//! `fixtures/fixture_target.c` is assembled into `fixture_target.dll` (an
//! x86-64 Windows PE DLL) in the build script's `OUT_DIR` using the mingw-w64
//! cross-compiler, so the fixture builds from source as part of the test
//! fixtures with no manual steps and no proprietary code.
//!
//! A missing cross-compiler is a warning, not a build failure: the library
//! reports [`calxgloss_testfixtures::TestFixturesError::ToolchainMissing`]
//! when a test asks for a fixture that was never built. Set
//! `CALXGLOSS_FIXTURE_CC` to override the compiler command.

use std::path::Path;
use std::process::Command;

const SOURCE: &str = "fixtures/fixture_target.c";
const OUTPUT: &str = "fixture_target.dll";
const PLAIN_SOURCE: &str = "fixtures/fixture_plain.c";
const PLAIN_OUTPUT: &str = "fixture_plain.dll";
const CC_ENV: &str = "CALXGLOSS_FIXTURE_CC";
const DEFAULT_CC: &str = "x86_64-w64-mingw32-gcc";

fn main() {
    println!("cargo::rerun-if-changed={SOURCE}");
    println!("cargo::rerun-if-changed={PLAIN_SOURCE}");
    // Re-run when the override or PATH changes, so installing the
    // cross-toolchain later rebuilds the fixture without a `cargo clean`.
    println!("cargo::rerun-if-env-changed={CC_ENV}");
    println!("cargo::rerun-if-env-changed=PATH");

    let cc = std::env::var(CC_ENV).unwrap_or_else(|_| DEFAULT_CC.to_string());
    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR is set for build scripts");
    let out_path = Path::new(&out_dir).join(OUTPUT);
    let plain_path = Path::new(&out_dir).join(PLAIN_OUTPUT);

    if Command::new(&cc).arg("--version").output().is_err() {
        println!(
            "cargo::warning=fixture target not built: `{cc}` not found \
             (install mingw-w64 or set {CC_ENV})"
        );
        return;
    }

    // -O2 is load-bearing: the fixture's switch only lowers to a jump
    // table under an optimising compile.
    compile_fixture(&cc, &out_path, SOURCE, "fixture target", &[]);
    // The plain fixture is built with `-nostdlib` on purpose: no CRT startup
    // means no imports at all, which is the shape the test needs.
    compile_fixture(
        &cc,
        &plain_path,
        PLAIN_SOURCE,
        "plain fixture",
        &["-nostdlib"],
    );
}

fn compile_fixture(cc: &str, out: &Path, source: &str, what: &str, extra: &[&str]) {
    let mut cmd = Command::new(cc);
    cmd.args(["-O2"])
        .args(extra)
        .args(["-shared", "-o"])
        .arg(out)
        .arg(source);
    match cmd.status() {
        Ok(s) if s.success() => {}
        Ok(s) => panic!("{what} build failed: `{cc}` exited {s}"),
        Err(e) => panic!("{what} build failed: could not run `{cc}`: {e}"),
    }
}
