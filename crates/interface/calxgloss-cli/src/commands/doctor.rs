//! `calxgloss doctor` — a read-only report of the whole Ghidra stack.
//!
//! Runs the lifecycle checks (install discovery, extension pairing, server
//! identity probe) in one pass and prints them through the reports crate.
//! Nothing is spawned, installed, or modified; any failing check exits
//! non-zero so CI can gate on the command.

use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use calxgloss_ghidra::GhidraClient;
use calxgloss_ghidra::GhidraConfig;
use calxgloss_ghidra::lifecycle::{self, StackRequest};
use calxgloss_reports::doctor::print_stack_report;
use tracing::info;

use crate::settings::Settings;

/// Check the whole stack and print the report; a failure is an error exit.
pub async fn handle_doctor(settings: &Settings) -> Result<()> {
    info!("Running the read-only Ghidra stack check");

    let mut config = GhidraConfig::new(&settings.ghidra_url.value).with_context(|| {
        format!(
            "Failed to parse GhidraMCP URL: {}",
            settings.ghidra_url.value
        )
    })?;
    if let Some(key) = &settings.ghidra_api_key {
        config = config.with_api_key(key.value.clone());
    }
    let client = GhidraClient::from_config(config).with_context(|| {
        format!(
            "Failed to build the GhidraMCP client: {}",
            settings.ghidra_url.value
        )
    })?;

    // The discovery inputs: Ghidra's own env var, then the layered config
    // value, then the home-directory glob — all read here so the lifecycle
    // checks themselves stay pure and testable.
    let env_install = std::env::var_os("GHIDRA_INSTALL_DIR").map(PathBuf::from);
    let home = std::env::var_os("HOME").map(PathBuf::from);
    let config_install = settings
        .ghidra_install_dir
        .as_ref()
        .map(|r| PathBuf::from(&r.value));
    let request = StackRequest {
        env_install_dir: env_install.as_deref(),
        config_install_dir: config_install.as_deref(),
        home: home.as_deref(),
    };

    let report = lifecycle::check_stack(&client, &request).await;
    print_stack_report(&report);
    if !report.all_ok() {
        bail!("the Ghidra stack check failed — see the report above");
    }
    Ok(())
}
