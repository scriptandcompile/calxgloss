//! `calxgloss doctor` — a read-only report of the whole Ghidra stack, and
//! with `--fix`, the bootstrap (G1-T8) that fills in what the report finds
//! missing.
//!
//! Without `--fix` nothing is spawned, installed, or modified; any failing
//! check exits non-zero so CI can gate on the command. With `--fix` the
//! lifecycle bootstrap runs — JDK-21 gate, plugin-first pairing, sha256
//! verification, install under the calxgloss prefix — behind the consent
//! rules the ticket demands, and the full read-only check runs again
//! afterwards as verification.
//!
//! Under `--engine kuna` (issue #205) the report changes shape: there is no
//! install, plugin, or port to check — the `--binary` target is loaded
//! in-process by the Kuna engine and its program identity is reported.

use std::io::Write as _;
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use calxgloss_ghidra::GhidraClient;
use calxgloss_ghidra::GhidraConfig;
use calxgloss_ghidra::GhidraError;
use calxgloss_ghidra::lifecycle::{self, BootstrapRequest, ReleasesApi, StackRequest, bootstrap};
use calxgloss_reports::doctor::{print_kuna_report, print_managed, print_stack_report};
use tracing::info;

use crate::cli_types::DoctorArgs;
use crate::settings::{Engine, Settings};
use crate::utils::{managed_install_prefix, state_dir};

/// The GitHub API the bootstrap fetches releases from.
const GITHUB_API: &str = "https://api.github.com";

/// Check the whole stack and print the report; a failure is an error exit.
/// With `--fix`, install what is missing first, then verify.
pub async fn handle_doctor(settings: &Settings, args: &DoctorArgs) -> Result<()> {
    // Under the kuna engine there is no stack to check: the doctor loads
    // the target in-process and reports its identity (issue #205).
    if settings.engine_choice()? == Engine::Kuna {
        return handle_doctor_kuna(settings, args);
    }

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
    // value, then the calxgloss install prefix, then the home-directory
    // glob — all read here so the lifecycle checks themselves stay pure
    // and testable.
    let env_install = std::env::var_os("GHIDRA_INSTALL_DIR").map(PathBuf::from);
    let home = std::env::var_os("HOME").map(PathBuf::from);
    let config_install = settings
        .ghidra_install_dir
        .as_ref()
        .map(|r| PathBuf::from(&r.value));
    let managed_prefix = home.as_deref().map(managed_install_prefix);
    let request = StackRequest {
        env_install_dir: env_install.as_deref(),
        config_install_dir: config_install.as_deref(),
        home: home.as_deref(),
        managed_prefix: managed_prefix.as_deref(),
    };

    let report = lifecycle::check_stack(&client, &request).await;
    print_stack_report(&report);
    print_managed_installs(home.as_deref());

    if args.fix {
        run_fix(settings, args, &request).await?;
        // The ticket's verification step: the full read-only check again,
        // so what follows the install is the same report CI gates on.
        println!("\nRe-running the stack check as verification:");
        let report = lifecycle::check_stack(&client, &request).await;
        print_stack_report(&report);
        print_managed_installs(home.as_deref());
        if !report.all_ok() {
            bail!(
                "the bootstrap finished but the stack still fails the check — \
                 see the report above"
            );
        }
        return Ok(());
    }

    if !report.all_ok() {
        bail!("the Ghidra stack check failed — see the report above");
    }
    Ok(())
}

/// The `kuna` engine's doctor (issue #205): load the target in-process and
/// report its program identity. There is no server whose open program could
/// be reported, so the binary must be named; an unloadable target arrives as
/// the named `KunaError` spelling out the `--engine ghidra` fallback.
fn handle_doctor_kuna(settings: &Settings, args: &DoctorArgs) -> Result<()> {
    info!("Running the kuna engine check: loading the target in-process");
    let Some(binary) = args.binary.as_ref() else {
        bail!(
            "engine = kuna (from {}) but no target binary was named: \
             re-run with --binary <FILE> — the kuna engine has no server \
             whose open program could be reported",
            settings.engine.source
        );
    };
    if args.fix {
        println!(
            "note: --fix has nothing to install for the kuna engine — it is \
             compiled into calxgloss; running the check as-is"
        );
    }
    let program = calxgloss_kuna::load(binary)?;
    print_kuna_report(
        binary,
        calxgloss_kuna::KUNA_RELEASE,
        program.identity(),
        program.entry(),
        program.num_symbols(),
    );
    Ok(())
}

/// The install manifest section: what calxgloss itself installed, read from
/// the manifest file the bootstrap wrote.
fn print_managed_installs(home: Option<&std::path::Path>) {
    let Some(state) = home.map(state_dir) else {
        return;
    };
    let manifest = lifecycle::load_manifest(&lifecycle::manifest_path(&state));
    print_managed(&manifest);
}

/// Run the bootstrap, asking for the one confirmation the rules require:
/// an old → new replacement of an existing install or extension.
async fn run_fix(settings: &Settings, args: &DoctorArgs, stack: &StackRequest<'_>) -> Result<()> {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .context("no $HOME, so there is no user-writable place to install into")?;
    let state = state_dir(&home);
    let cache = std::env::var_os("XDG_CACHE_HOME")
        .filter(|value| !value.as_os_str().is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| home.join(".cache"))
        .join("calxgloss");
    let mut api = ReleasesApi::new(GITHUB_API).context("the GitHub API base URL is invalid")?;
    // The ~570 MB Ghidra stream must not look like a hang: progress rides on
    // stderr so the report itself stays clean on stdout.
    api = api.with_progress(|downloaded, total| match total {
        Some(total) => eprintln!(
            "  … {} MB of {} MB downloaded",
            downloaded / 1_048_576,
            total / 1_048_576
        ),
        None => eprintln!("  … {} MB downloaded", downloaded / 1_048_576),
    });
    // Optional: users hitting the anonymous rate limit can raise it with a token.
    if let Some(token) = std::env::var("GHIDRA_MCP_GITHUB_TOKEN")
        .ok()
        .filter(|token| !token.trim().is_empty())
    {
        api = api.with_token(token);
    }
    let java = settings
        .ghidra_java_home
        .as_ref()
        .map(|r| PathBuf::from(&r.value).join("bin/java"));
    let pin = args.ghidra_version.as_deref().or(settings
        .ghidra_pin_version
        .as_ref()
        .map(|r| r.value.as_str()));
    let consent = args.install_ghidra || settings.ghidra_auto_install.value;

    let mut upgrade_approved = false;
    let report = loop {
        let request = BootstrapRequest {
            stack: *stack,
            state_dir: &state,
            cache_dir: &cache,
            api: &api,
            java: java.as_deref(),
            pin_version: pin,
            local_plugin_zip: args.plugin_zip.as_deref(),
            local_ghidra_zip: args.ghidra_zip.as_deref(),
            download_consent: consent,
            upgrade_approved,
        };
        match bootstrap(&request).await {
            Ok(report) => break report,
            Err(GhidraError::UpgradeConfirmation { what, from, to }) => {
                if upgrade_approved {
                    return Err(GhidraError::UpgradeConfirmation { what, from, to })
                        .context("the confirmation was granted but the bootstrap asked again");
                }
                if !confirm_replacement(&what, &from, &to)? {
                    bail!("bootstrap cancelled — nothing was changed");
                }
                upgrade_approved = true;
            }
            Err(other) => {
                return Err(other).context("the bootstrap stopped before installing anything");
            }
        }
    };

    for note in &report.notes {
        println!("  {note}");
    }
    Ok(())
}

/// The old → new confirmation: y to proceed, anything else (default N) stops.
fn confirm_replacement(what: &str, from: &str, to: &str) -> Result<bool> {
    print!("\ncalxgloss would replace {what}: {from} → {to}. Continue? [y/N] ");
    std::io::stdout()
        .flush()
        .context("could not write to the terminal")?;
    let mut answer = String::new();
    std::io::stdin()
        .read_line(&mut answer)
        .context("could not read the answer from stdin")?;
    Ok(matches!(answer.trim(), "y" | "Y" | "yes" | "YES"))
}
