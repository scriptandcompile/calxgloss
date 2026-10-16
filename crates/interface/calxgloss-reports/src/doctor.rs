//! Formatting for `calxgloss doctor`'s read-only Ghidra stack report.
//!
//! One line per check — install, extension, server — each with a pass/fail
//! mark, and a remediation hint under every failure so the fix does not
//! require reading the design doc. The data is the `calxgloss-ghidra`
//! lifecycle report; this module only decides how it reads.

use std::path::Path;

use calxgloss_ghidra::MIN_PLUGIN_VERSION;
use calxgloss_ghidra::lifecycle::{
    ExtensionVerdict, InstallDiscovery, InstallManifest, InstallSource, ServerDiscovery,
    StackReport,
};

use crate::{cyan_bold, dim, green_bold, red_bold, white_bold, yellow_bold};

/// Print the whole stack report: three checks, each with a hint when it fails.
pub fn print_stack_report(report: &StackReport) {
    let sep = cyan_bold(&"═".repeat(58));
    println!("{} Ghidra Stack Report", sep);
    println!();

    print_install(&report.install);
    println!();
    print_extension(report.extension.as_ref(), &report.install);
    println!();
    print_server(&report.server);

    println!();
    println!("{}", dim(&"─".repeat(58)));
    if report.all_ok() {
        println!("  {}", green_bold("the whole Ghidra stack checks out"));
    } else {
        println!(
            "  {}",
            red_bold("the Ghidra stack has failures — see the hints above")
        );
    }
}

/// The install line: path, version, and which layer named it.
fn print_install(discovery: &InstallDiscovery) {
    match discovery {
        InstallDiscovery::Found { install, source } => {
            pass(
                "Install",
                &format!("Ghidra {} at {}", install.version, install.path.display()),
            );
            note(&format!("discovered via {source}"));
            if *source == InstallSource::ManagedPrefix {
                note("calxgloss-managed install — `doctor --fix` upgrades it in place");
            }
        }
        InstallDiscovery::Invalid { path, source } => {
            fail(
                "Install",
                &format!(
                    "{} is not a valid Ghidra install (no Ghidra/Framework inside)",
                    path.display()
                ),
            );
            hint(&format!(
                "re-extract the official Ghidra zip, or fix the path {source} points at"
            ));
        }
        InstallDiscovery::NotFound => {
            fail("Install", "no Ghidra install found");
            hint(
                "run `calxgloss doctor --fix --install-ghidra` to install a paired \
                 Ghidra + GhidraMCP stack, or install Ghidra (https://ghidra-sre.org) \
                 and extract it into your home directory as ghidra_<version>_PUBLIC, \
                 or point $GHIDRA_INSTALL_DIR / ghidra.install_dir at the install",
            );
        }
    }
}

/// The extension line: judged against the discovered install (strict pairing,
/// ADR-0001), so it only runs when an install was found.
fn print_extension(verdict: Option<&ExtensionVerdict>, install: &InstallDiscovery) {
    match verdict {
        None => {
            // Two different reasons there is nothing to judge: no install to
            // pair against, or no home directory to find the state dir in.
            if matches!(install, InstallDiscovery::Found { .. }) {
                fail(
                    "Extension",
                    "not checked — the home directory is unknown, so Ghidra's state \
                     directory is",
                );
                hint("run doctor in a normal user shell, with $HOME set");
            } else {
                fail(
                    "Extension",
                    "not checked — there is no Ghidra install to pair it against",
                );
                hint("fix the install check first");
            }
        }
        Some(ExtensionVerdict::Ok {
            plugin_version,
            built_for,
        }) => {
            let plugin = plugin_version.as_deref().unwrap_or("unknown version");
            pass(
                "Extension",
                &format!("GhidraMCP {plugin}, built for Ghidra {built_for}"),
            );
        }
        Some(ExtensionVerdict::Missing { extensions_dir }) => {
            fail("Extension", "the GhidraMCP extension is not installed");
            hint(&format!(
                "run `calxgloss doctor --fix` to install the matching GhidraMCP release, \
                 or install the GhidraMCP {MIN_PLUGIN_VERSION} zip into {} (Ghidra: File → \
                 Install Extensions)",
                extensions_dir.display()
            ));
        }
        Some(ExtensionVerdict::WrongBuild {
            built_for,
            ghidra,
            extensions_dir,
        }) => {
            fail(
                "Extension",
                &format!("extension built for {built_for} but Ghidra is {ghidra}"),
            );
            hint(&format!(
                "reinstall the GhidraMCP {MIN_PLUGIN_VERSION} zip into {}",
                extensions_dir.display()
            ));
        }
        Some(ExtensionVerdict::TooOld {
            plugin_version,
            required,
        }) => {
            fail(
                "Extension",
                &format!("GhidraMCP plugin {plugin_version} is older than {required}"),
            );
            hint(&format!(
                "install the GhidraMCP {required} release into this Ghidra (ADR-0001)"
            ));
        }
        Some(ExtensionVerdict::Broken { dir }) => {
            fail(
                "Extension",
                &format!(
                    "the extension at {} has no readable manifest",
                    dir.display()
                ),
            );
            hint(&format!(
                "reinstall the GhidraMCP {MIN_PLUGIN_VERSION} zip into the Extensions \
                 directory beside it"
            ));
        }
    }
}

/// The server line: kind, version, and port via the identity probe; "none"
/// when nothing answered, never a crash.
fn print_server(discovery: &ServerDiscovery) {
    match discovery {
        ServerDiscovery::Up { url, info } => {
            let version = info
                .version
                .as_deref()
                .map(|v| format!(" v{v}"))
                .unwrap_or_default();
            let program = info
                .program
                .as_deref()
                .map(|p| format!(" (program '{p}')"))
                .unwrap_or_default();
            pass(
                "Server",
                &format!("{}{version} at {url}{program}", info.kind),
            );
        }
        ServerDiscovery::Unreachable { url } => {
            fail("Server", &format!("none — no server answered at {url}"));
            hint(
                "start Ghidra with the GhidraMCP extension loaded and a program open, \
                 or point ghidra.url at a running server",
            );
        }
        ServerDiscovery::NotGhidraMcp { url, hint: why } => {
            fail(
                "Server",
                &format!("none — the port at {url} answers, but it is not GhidraMCP"),
            );
            note(why);
            hint(
                "check the configured Ghidra URL (--ghidra-url, CALXGLOSS_GHIDRA_URL, \
                 ghidra.url) — 8080 is also a popular local-AI port",
            );
        }
        ServerDiscovery::TooOld {
            url,
            found,
            required,
        } => {
            fail(
                "Server",
                &format!("the plugin at {url} is v{found}, older than the pinned v{required}"),
            );
            hint(&format!(
                "install the GhidraMCP {required} release into this Ghidra (ADR-0001)"
            ));
        }
    }
}

/// Print the kuna engine's doctor report (issue #205): the target loaded
/// in-process and the program identity the engine reports. There is no
/// install, extension, or server to check — the engine is compiled into
/// calxgloss — so the report names that instead of dressing up as the
/// Ghidra stack report.
pub fn print_kuna_report(
    path: &Path,
    release: &str,
    identity: &str,
    entry: Option<u64>,
    symbols: usize,
) {
    let sep = cyan_bold(&"═".repeat(58));
    println!("{} Kuna Engine Report", sep);
    println!();
    pass(
        "Engine",
        &format!("kuna {release} — in-process; no install, extension, or port to check"),
    );
    println!();
    pass("Target", &path.display().to_string());
    note(&format!("language: {identity}"));
    match entry {
        Some(entry) => note(&format!("entry point: {entry:#x}")),
        None => note("entry point: none named by the file format"),
    }
    note(&format!("function symbols: {symbols}"));
    println!();
    println!("{}", dim(&"─".repeat(58)));
    println!("  {}", green_bold("the kuna engine loaded the target"));
}

/// Print the install manifest: what calxgloss itself installed, read from
/// `<state>/calxgloss/ghidra-install.json`. An empty manifest prints nothing.
pub fn print_managed(manifest: &InstallManifest) {
    if manifest.ghidra.is_none() && manifest.plugin.is_none() {
        return;
    }
    println!();
    println!("  {}", white_bold("Managed installs"));
    if let Some(ghidra) = &manifest.ghidra {
        note(&format!(
            "Ghidra {} at {}",
            ghidra.version,
            ghidra.path.display()
        ));
    }
    if let Some(plugin) = &manifest.plugin {
        let version = plugin.version.as_deref().unwrap_or("unknown version");
        note(&format!(
            "GhidraMCP {version}, built for Ghidra {}, at {}",
            plugin.built_for,
            plugin.path.display()
        ));
    }
}

/// A passing check line.
fn pass(label: &str, detail: &str) {
    println!("  {:<11}{}", white_bold(label), green_bold("✓"));
    println!("  {:<11}{}", "", detail);
}

/// A failing check line.
fn fail(label: &str, detail: &str) {
    println!("  {:<11}{}", white_bold(label), red_bold("✗"));
    println!("  {:<11}{}", "", detail);
}

/// A supporting detail under a check line.
fn note(text: &str) {
    println!("  {:<11}{}", "", dim(text));
}

/// The remediation hint under a failure. Long hints wrap at the terminal's
/// own width, like the rest of the reports' output.
fn hint(text: &str) {
    println!("  {:<11}{} {}", "", yellow_bold("→"), text);
}
