//! Cargo execution helpers for the verifier.

use anyhow::Context;
use std::path::Path;
use std::process::Stdio;
use tracing::debug;

/// Run `cargo check` in the given project directory.
pub async fn run_cargo_check(project: &Path) -> anyhow::Result<String> {
    debug!(project = %project.display(), "Running cargo check");

    let output = tokio::process::Command::new("cargo")
        .arg("check")
        .current_dir(project)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .context("Failed to spawn cargo check")?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{}\n{}", stderr, stdout);

    if output.status.success() {
        debug!("cargo check succeeded");
    } else {
        debug!(
            output = &combined[..combined.len().min(500)],
            "cargo check failed"
        );
    }

    Ok(combined.to_owned())
}

/// Run the test runner binary in the given project directory.
pub async fn run_test_runner(project: &Path) -> anyhow::Result<String> {
    debug!(project = %project.display(), "Running test runner binary");

    let output = tokio::process::Command::new("cargo")
        .arg("run")
        .current_dir(project)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .context("Failed to spawn cargo run")?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{}\n{}", stderr, stdout);

    if output.status.success() {
        debug!("test runner succeeded");
    } else {
        debug!(
            output = &combined[..combined.len().min(500)],
            "test runner failed"
        );
    }

    Ok(combined.to_owned())
}
