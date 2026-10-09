//! Cross-compile and run a Windows harness under Wine to capture a ground-truth
//! baseline from an original DLL.
//!
//! # Why this is not a link-time FFI
//!
//! The obvious way to call an original function is to generate an
//! `extern "C"` block and link against the DLL. That only works for *exported*
//! symbols. The interesting functions in a real binary are internal: Ghidra
//! names them `FUN_18008ed50` and they appear in no export table. Reaching them
//! means loading the module at runtime and calling `module_base + rva`, which is
//! what this module generates.
//!
//! # Address arithmetic
//!
//! Ghidra reports addresses at the image's preferred base, so the RVA is
//! `va - image_base` (see [`crate::PeImage::rva_from_va`]). The image is
//! normally *not* loaded at its preferred base — ASLR and Wine's allocator pick
//! the address — so the runtime call target is `actual_base + rva`.
//!
//! # Loading strategy
//!
//! Two load modes are supported, because Delphi binaries such as `eqmain.dll`
//! need runtime state that a bare mapping does not provide:
//!
//! * [`LoadMode::NoResolve`] — `LoadLibraryExW` with
//!   `DONT_RESOLVE_DLL_REFERENCES`. Maps the image without running `DllMain`
//!   and without resolving imports. Sufficient for functions that touch only
//!   caller-allocated memory. Nothing from the DLL's own runtime is available.
//! * [`LoadMode::Full`] — plain load, which runs `DllMain` and resolves imports.
//!   Required for functions that read runtime-initialised state, and the only
//!   mode in which named exports reliably resolve through their import stubs.
//!
//! # Wire protocol
//!
//! The generated harness deliberately has **no dependencies**, so the
//! cross-compile stays hermetic and fast. Test cases are encoded as a series
//! of `<tag>:<value>` lines on stdin. Results come back on stdout as
//! `<index>\t<ok|err>\t<value>`.
//!
//! # Crash isolation
//!
//! A function that faults kills the harness process, taking every later case
//! with it. When a batch run dies without reporting all cases, the runner
//! retries case-by-case so one bad input does not discard the rest. Note that
//! this only covers *crashes*; a hang is still fatal.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail};
use calxgloss_types::TestCase;
use tracing::{debug, info, instrument, warn};

use encode::decode_value;
pub use encode::encode_test_case;
use harness::HARNESS_CRASH_EXIT;
pub use harness::generate_harness;
pub use types::{
    FunctionLocator, HarnessReport, HarnessSpec, HarnessTestResult, LoadMode, ParamSpec,
    ScalarKind, UNIT_SEPARATOR, locator_for_function, locator_for_va,
};

pub mod encode;
pub mod harness;
pub mod types;

// ============================================================
// WineRunner
// ============================================================

/// Builds and runs generated harnesses under Wine.
#[derive(Debug, Clone)]
pub struct WineRunner {
    /// Directory that holds generated harness projects.
    work_dir: PathBuf,
    /// Wine executable to invoke.
    wine_bin: String,
    /// Wine prefix, used to translate host paths into Wine paths.
    prefix: PathBuf,
}

impl WineRunner {
    /// Create a runner, discovering the Wine prefix from the environment.
    pub fn new(work_dir: &Path) -> Self {
        let prefix = std::env::var("WINEPREFIX")
            .map(PathBuf::from)
            .unwrap_or_else(|_| {
                let home = std::env::var("HOME").unwrap_or_else(|_| "/".into());
                PathBuf::from(home).join(".wine")
            });
        Self {
            work_dir: work_dir.to_path_buf(),
            wine_bin: std::env::var("CALXGLOSS_WINE").unwrap_or_else(|_| "wine".into()),
            prefix,
        }
    }

    /// Override the Wine executable.
    pub fn with_wine_bin(mut self, wine_bin: impl Into<String>) -> Self {
        self.wine_bin = wine_bin.into();
        self
    }

    /// Override the Wine prefix.
    pub fn with_prefix(mut self, prefix: impl Into<PathBuf>) -> Self {
        self.prefix = prefix.into();
        self
    }

    /// The Wine prefix in use.
    pub fn prefix(&self) -> &Path {
        &self.prefix
    }

    /// Verify Wine is installed and the expected Rust target is available.
    pub fn preflight_wine(&self) -> Result<()> {
        let status = Command::new(&self.wine_bin)
            .arg("--version")
            .stdin(Stdio::null())
            .output()
            .with_context(|| {
                format!(
                    "Could not run '{} --version'. Baseline execution needs Wine to run the \
                     cross-compiled harness. Install it, or set CALXGLOSS_WINE.",
                    self.wine_bin
                )
            })?;
        if !status.status.success() {
            bail!("'{} --version' failed", self.wine_bin);
        }
        info!(
            wine = String::from_utf8_lossy(&status.stdout).trim(),
            prefix = %self.prefix.display(),
            "Wine is available"
        );
        Ok(())
    }

    /// Translate a host path into a path Wine can open.
    ///
    /// Paths inside the prefix become `C:\...`; anything else goes through the
    /// `Z:` drive, which Wine maps to the Unix root.
    pub fn to_wine_path(&self, host_path: &Path) -> Result<String> {
        let host = host_path
            .canonicalize()
            .with_context(|| format!("Path {} does not exist", host_path.display()))?;
        let drive_c = self.prefix.join("drive_c");
        let drive_c = if drive_c.exists() {
            drive_c.canonicalize().unwrap_or(drive_c)
        } else {
            drive_c
        };

        let relative = match host.strip_prefix(&drive_c) {
            Ok(rel) => format!("C:{}", to_windows_separators(&rel.to_string_lossy())),
            // Outside the prefix: reach it through the Z: drive.
            Err(_) => format!("Z:{}", to_windows_separators(&host.to_string_lossy())),
        };
        debug!(host = %host.display(), wine = %relative, "Translated path for Wine");
        Ok(relative)
    }

    /// Write, compile, and run a harness, returning its report.
    ///
    /// A batch run that dies before reporting every case is retried one case at
    /// a time so a single faulting input is attributed rather than discarding
    /// the whole batch.
    #[instrument(skip_all, fields(function = %spec.function_label))]
    pub fn run(
        &self,
        spec: &HarnessSpec,
        dll_path: &Path,
        tests: &[TestCase],
        target: crate::Machine,
    ) -> Result<HarnessReport> {
        let project_dir = self.write_project(spec)?;
        let exe = self.compile(&project_dir, target)?;
        let wine_dll = self.to_wine_path(dll_path)?;

        let payload: Vec<String> = tests
            .iter()
            .map(|t| encode_test_case(spec, t))
            .collect::<Result<Vec<_>>>()?;

        let mut report = self.invoke(spec, &exe, &wine_dll, &payload, None);

        // `results` is padded with synthesised crashed entries when the harness
        // dies, so its length can reach the full count even though the run fell
        // over. Compare the number the harness actually *reported* instead,
        // otherwise the placeholders for every case after the faulting one are
        // mistaken for real answers and never re-examined.
        if report.reported < tests.len() {
            // The process died partway through. Re-run each case on its own to
            // find out which one is responsible and recover the rest.
            warn!(
                function = %spec.function_label,
                reported = report.reported,
                expected = tests.len(),
                "Harness exited early; re-running each case in isolation"
            );
            let mut isolated = Vec::with_capacity(tests.len());
            for index in 0..tests.len() {
                let mut single = self.invoke(spec, &exe, &wine_dll, &payload, Some(index));
                // A case that succeeded in isolation may also have succeeded in
                // the batch; prefer the batch's reading when both agree, since
                // it came from a process that had the same runtime state.
                let batch_succeeded = report.results.iter().any(|b| b.index == index && b.ok);
                if single.reported == 1
                    && single.results[0].ok
                    && batch_succeeded
                    && let Some(batch) = report.results.iter().find(|b| b.index == index)
                {
                    single.results[0].returned = batch.returned.clone();
                }
                isolated.append(&mut single.results);
            }
            isolated.sort_by_key(|r| r.index);
            report.results = isolated;
            report.reported = report.results.iter().filter(|r| r.ok).count();
        }

        if report.results.len() < tests.len() {
            warn!(
                function = %spec.function_label,
                got = report.results.len(),
                expected = tests.len(),
                "Some test cases produced no result even in isolation"
            );
        }
        Ok(report)
    }

    /// Run the harness once, optionally restricted to a single case.
    fn invoke(
        &self,
        spec: &HarnessSpec,
        exe: &Path,
        wine_dll: &str,
        payload: &[String],
        isolate: Option<usize>,
    ) -> HarnessReport {
        let mut cmd = Command::new(&self.wine_bin);
        cmd.arg(exe)
            .arg("--binary")
            .arg(wine_dll)
            .args(spec.locator.harness_args())
            // Wine's own diagnostics drown out the harness output.
            .env("WINEDEBUG", "-all")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        if spec.load_mode.runs_dll_main() {
            cmd.arg("--run-binary-main");
        }
        if let Some(index) = isolate {
            cmd.arg("--isolate").arg(index.to_string());
        }

        let stdin_payload = match isolate {
            // A single-case run must still deliver the case at the right index,
            // since the harness numbers results by input line position.
            Some(index) => payload.get(index).cloned().unwrap_or_default(),
            None => payload.join("\n"),
        };

        debug!(
            isolate = ?isolate,
            cases = payload.len(),
            "Running harness under Wine"
        );

        let mut spawn = match cmd.spawn() {
            Ok(child) => child,
            Err(e) => {
                return HarnessReport {
                    results: failed_all(payload, isolate, format!("could not run Wine: {e}")),
                    stderr: format!("could not run Wine: {e}"),
                    ..Default::default()
                };
            }
        };

        let write_failed = match spawn.stdin.take() {
            Some(mut stdin) => stdin.write_all(stdin_payload.as_bytes()).is_err(),
            None => true,
        };
        // Dropping stdin signals EOF so the harness stops reading.

        let output = match spawn.wait_with_output() {
            Ok(out) => out,
            Err(e) => {
                return HarnessReport {
                    results: failed_all(payload, isolate, format!("harness wait failed: {e}")),
                    stderr: format!("harness wait failed: {e}"),
                    ..Default::default()
                };
            }
        };

        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();

        let mut results = parse_results(&stdout);
        let reported = results.len();
        let expected = match isolate {
            Some(_) => 1,
            None => payload.len(),
        };

        if results.len() < expected {
            // A fault inside the target is caught by the harness's own crash
            // handler, which terminates with a known status. A signal death is
            // the older fallback path, kept because a fault can also happen
            // outside the handler's reach, e.g. on a loader thread.
            let crashed_in_target =
                matches!(output.status.code(), Some(code) if code as u32 == HARNESS_CRASH_EXIT);
            let signal = terminating_signal(&output.status);
            let detail = match signal {
                Some(sig) => format!(
                    "harness terminated by signal {sig} — the function under test likely \
                     faulted (stderr: {})",
                    stderr.trim()
                ),
                None if write_failed => {
                    "harness could not receive its test cases on stdin".to_string()
                }
                None if crashed_in_target => {
                    "the function under test faulted and the harness caught it".to_string()
                }
                None if !output.status.success() => format!(
                    "harness exited with status {} (stderr: {})",
                    output.status,
                    stderr.trim()
                ),
                None => "harness produced no result for this case".to_string(),
            };
            warn!(function = %spec.function_label, detail, "Harness did not report every case");
            results.extend(crashed_results(&results, payload, isolate, &detail));
        }

        HarnessReport {
            results,
            reported,
            module_base: parse_module_base(&stderr),
            stderr,
        }
    }

    /// Write the harness project to disk, reusing the directory per function.
    fn write_project(&self, spec: &HarnessSpec) -> Result<PathBuf> {
        let dir = self.work_dir.join(sanitize(&spec.function_label));
        let src = dir.join("src");
        std::fs::create_dir_all(&src)
            .with_context(|| format!("Failed to create harness directory {}", dir.display()))?;

        let manifest = "[package]\n\
             name = \"calxgloss_harness\"\n\
             version = \"0.0.0\"\n\
             edition = \"2021\"\n\
             \n\
             [[bin]]\n\
             name = \"harness\"\n\
             path = \"src/main.rs\"\n\
             \n\
             [profile.release]\n\
             panic = \"unwind\"\n\
             debug = false\n";
        std::fs::write(dir.join("Cargo.toml"), manifest)
            .with_context(|| "Failed to write Cargo.toml".to_string())?;
        std::fs::write(src.join("main.rs"), &generate_harness(spec)?)
            .with_context(|| "Failed to write harness source".to_string())?;

        debug!(path = %dir.display(), "Wrote harness project");
        Ok(dir)
    }

    /// Cross-compile the harness and return the path to the Windows binary.
    fn compile(&self, project_dir: &Path, machine: crate::Machine) -> Result<PathBuf> {
        let triple = machine.target_triple();
        if triple == "unknown" {
            bail!("Unsupported target architecture; cannot build a baseline harness for it");
        }

        let output = Command::new("cargo")
            .arg("build")
            .arg("--release")
            .arg("--target")
            .arg(triple)
            .current_dir(project_dir)
            .output()
            .context("Failed to run 'cargo build' for the baseline harness")?;

        if !output.status.success() {
            bail!(
                "Baseline harness failed to compile for {triple}:\n{}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        let exe = project_dir
            .join("target")
            .join(triple)
            .join("release")
            .join("harness.exe");
        if !exe.exists() {
            bail!("Harness compiled but {} was not produced", exe.display());
        }
        Ok(exe)
    }
}

fn parse_results(stdout: &str) -> Vec<HarnessTestResult> {
    stdout
        .lines()
        .filter_map(|line| {
            let mut parts = line.splitn(3, '\t');
            let index = parts.next()?.trim().parse::<usize>().ok()?;
            let status = parts.next()?.trim();
            let payload = parts.next().unwrap_or("").trim();
            Some(match status {
                "ok" => HarnessTestResult {
                    index,
                    ok: true,
                    returned: decode_value(payload),
                    error: None,
                    crashed: false,
                },
                other => HarnessTestResult {
                    index,
                    ok: false,
                    returned: serde_json::Value::Null,
                    error: Some(format!("harness reported '{other}': {payload}")),
                    crashed: false,
                },
            })
        })
        .collect()
}

/// Fill in cases the harness never reported, marking them as crashed.
fn crashed_results(
    got: &[HarnessTestResult],
    payload: &[String],
    isolate: Option<usize>,
    detail: &str,
) -> Vec<HarnessTestResult> {
    let expected: Vec<usize> = match isolate {
        Some(index) => vec![index],
        None => (0..payload.len()).collect(),
    };
    expected
        .into_iter()
        .filter(|i| !got.iter().any(|r| r.index == *i))
        .map(|index| HarnessTestResult {
            index,
            ok: false,
            returned: serde_json::Value::Null,
            error: Some(detail.to_string()),
            crashed: true,
        })
        .collect()
}

fn failed_all(
    payload: &[String],
    isolate: Option<usize>,
    detail: String,
) -> Vec<HarnessTestResult> {
    let indices: Vec<usize> = match isolate {
        Some(index) => vec![index],
        None => (0..payload.len()).collect(),
    };
    indices
        .into_iter()
        .map(|index| HarnessTestResult {
            index,
            ok: false,
            returned: serde_json::Value::Null,
            error: Some(detail.clone()),
            crashed: true,
        })
        .collect()
}

fn parse_module_base(stderr: &str) -> Option<u64> {
    stderr.lines().find_map(|line| {
        let rest = line.split("module base = ").nth(1)?;
        parse_hex(rest.trim()).ok()
    })
}

fn parse_hex(s: &str) -> Result<u64, String> {
    use anyhow::Context as _;
    let t = s.trim();
    let t = t
        .strip_prefix("0x")
        .or_else(|| t.strip_prefix("0X"))
        .unwrap_or(t);
    u64::from_str_radix(t, 16)
        .with_context(|| format!("'{t}' is not a hex value"))
        .map_err(|e| e.to_string())
}

fn to_windows_separators(path: &str) -> String {
    path.replace('/', "\\")
}

/// Make a function label safe to use as a directory name.
fn sanitize(label: &str) -> String {
    let cleaned: String = label
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect();
    if cleaned.is_empty() {
        "harness".to_string()
    } else {
        cleaned
    }
}

/// The signal that killed a process, if it was killed by one.
///
/// Windows faults inside Wine surface this way, which is how a crash in the
/// function under test becomes visible to the runner.
fn terminating_signal(status: &std::process::ExitStatus) -> Option<i32> {
    use std::os::unix::process::ExitStatusExt;
    status.signal()
}
