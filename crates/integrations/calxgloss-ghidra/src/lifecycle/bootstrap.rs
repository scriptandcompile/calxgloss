//! The bootstrap `calxgloss doctor --fix` runs: from nothing installed to a
//! working, paired Ghidra + GhidraMCP pair.
//!
//! The strategy is **plugin-first** (design §3.5): the extension jar is
//! compiled against exactly one Ghidra build (ADR-0001), so the plugin
//! release decides which Ghidra build to fetch — "latest of each" produces
//! a broken pair. The order is fixed:
//!
//! 1. **JDK gate** — `java -version` (or `ghidra.java_home`) must report 21+.
//!    A missing JDK stops the bootstrap with exact remediation *before any
//!    download*; calxgloss never installs a JDK itself.
//! 2. **Plugin** — the GhidraMCP release zip (small) is fetched, its sha256
//!    verified against the releases API digest, unzipped to the cache, and
//!    its `extension.properties` names the Ghidra build to fetch.
//! 3. **Ghidra** — exactly that release (tag `Ghidra_<ver>_build`, nearest
//!    ≥ fallback), ~570 MB streamed with progress, sha256-verified, unzipped.
//! 4. **Install** — Ghidra under a user-writable prefix (default
//!    `<state>/calxgloss/ghidra/`), exec bits restored; the plugin into the
//!    per-version `Extensions` dir Ghidra itself reads. The install manifest
//!    records both, distinguishing calxgloss-managed from user-managed.
//!
//! Selection rules cover the present-one-missing cases: Ghidra present and
//! the plugin missing or mismatched → the newest plugin release *matching
//! the installed Ghidra* (releases scanned backwards, the zip is small);
//! plugin present and Ghidra missing → exactly the build the existing
//! extension names; both missing → plugin-first. `ghidra.pin_version` /
//! `--ghidra-version` forces an exact pair: the newest plugin built for the
//! pinned build plus exactly that Ghidra build — no nearest-≥ fallback, and
//! a local zip contradicting the pin is refused.
//!
//! Safety, load-bearing:
//! * consent — the ~570 MB download needs `--install-ghidra` (or
//!   `ghidra.auto_install = true`); without it the bootstrap stops with the
//!   consent request, never a partial install;
//! * every download's sha256 is verified against the releases API digest
//!   before unzipping; a mismatch deletes the download;
//! * existing installs are never modified or upgraded without `--fix` plus
//!   an old → new confirmation — the bootstrap reports
//!   [`GhidraError::UpgradeConfirmation`] and the CLI asks;
//! * never sudo: the install prefix must be user-writable, and an unwritable
//!   one is a named failure, not a fallback;
//! * downloads stream into the XDG cache dir, resume over HTTP `Range`, and
//!   are reused by name; an optional `GHIDRA_MCP_GITHUB_TOKEN` raises the
//!   API rate limit, and an exhausted one fails with that knob named rather
//!   than a bare 403.
//!
//! Every input is a parameter — API base, cache, state dirs, java binary,
//! consent — so the integration tests drive the whole flow against a fake
//! releases API and fixture zips with no real download.

use std::io::Read;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};
use tracing::{debug, info, warn};
use zip::ZipArchive;

use super::StackRequest;
use super::extension::{self, ExtensionDiscovery, ExtensionVerdict, GhidraExtension};
use super::install::{self, InstallDiscovery};
use super::manifest::{self, InstallManifest, ManagedInstall, ManagedPlugin};
use super::properties_value;
use super::releases::{self, GHIDRA_REPO, PLUGIN_REPO, Release, ReleaseAsset, ReleasesApi};
use crate::client::{GhidraError, Result};

/// The Java major version Ghidra 12.x requires (design §3.5: Java 21 LTS).
pub const MIN_JDK_MAJOR: u32 = 21;

/// The injectable inputs of a bootstrap run — the same shape
/// [`StackRequest`] established for the checks, widened to everything the
/// acting half touches.
#[derive(Debug, Clone)]
pub struct BootstrapRequest<'a> {
    /// The filesystem discovery inputs (env / config / home / managed prefix).
    pub stack: StackRequest<'a>,
    /// The user's local state dir (`$XDG_DATA_HOME` or `~/.local/share`):
    /// the install prefix and the manifest hang off `calxgloss/` under it.
    pub state_dir: &'a Path,
    /// The download cache (`$XDG_CACHE_HOME/calxgloss`): retries do not
    /// refetch 570 MB.
    pub cache_dir: &'a Path,
    /// The GitHub releases API (base URL injectable for tests).
    pub api: &'a ReleasesApi,
    /// The java binary for the JDK gate — `ghidra.java_home`'s `bin/java`,
    /// or `java` on PATH when unset.
    pub java: Option<&'a Path>,
    /// `ghidra.pin_version` / `--ghidra-version`: force the exact pair —
    /// the newest plugin built for this Ghidra build, and exactly this
    /// build (no nearest ≥ fallback, and a local zip naming another build
    /// is refused).
    pub pin_version: Option<&'a str>,
    /// `--plugin-zip`: install this local extension zip instead of fetching
    /// one (no download, no checksum path).
    pub local_plugin_zip: Option<&'a Path>,
    /// `--ghidra-zip`: install this local Ghidra zip instead of fetching one.
    pub local_ghidra_zip: Option<&'a Path>,
    /// Whether the ~570 MB download is consented (`--install-ghidra` /
    /// `ghidra.auto_install = true`).
    pub download_consent: bool,
    /// Whether the human confirmed an old → new upgrade this run.
    pub upgrade_approved: bool,
}

/// What a bootstrap run installed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BootstrapReport {
    /// The Ghidra install now in place, when calxgloss made it.
    pub ghidra: Option<ManagedInstall>,
    /// The GhidraMCP extension now in place, when calxgloss installed it.
    pub plugin: Option<ManagedPlugin>,
    /// Human-readable lines of what happened, for the CLI to print.
    pub notes: Vec<String>,
}

/// Run the bootstrap. The caller (`doctor --fix`) follows with the full
/// read-only stack check as verification — this function installs, it does
/// not launch anything.
pub async fn bootstrap(request: &BootstrapRequest<'_>) -> Result<BootstrapReport> {
    // 1. The JDK gate comes before anything else: a doomed 570 MB download
    // is the exact failure this ordering exists to prevent.
    jdk_gate(request.java)?;

    let home = request
        .stack
        .home
        .ok_or_else(|| GhidraError::BootstrapBlocked {
            reason: "no home directory is known ($HOME), so there is no user-writable place to \
                 install into"
                .to_string(),
        })?;
    let config_root = home.join(".config").join("ghidra");
    let install_prefix = request.state_dir.join("calxgloss").join("ghidra");
    let manifest_file = manifest::manifest_path(request.state_dir);
    let mut manifest = manifest::load_manifest(&manifest_file);
    let mut report = BootstrapReport::default();

    let install = install::discover(
        request.stack.env_install_dir,
        request.stack.config_install_dir,
        request.stack.home,
        request.stack.managed_prefix,
    );

    match &install {
        // Ghidra present: the plugin is judged against it, strictly.
        InstallDiscovery::Found { install, source } => {
            // A pin naming a different build than the discovered install is
            // a contradiction: pairing against the installed version anyway
            // would silently ignore the pin, and installing a second Ghidra
            // beside a working one is not the bootstrap's call to make.
            if let Some(pin) = request.pin_version && install.version != pin {
                return Err(GhidraError::BootstrapBlocked {
                    reason: format!(
                        "ghidra.pin_version names Ghidra {pin}, but the discovered install \
                         is {} at {} — point ghidra.install_dir at a {pin} install, or \
                         drop the pin",
                        install.version,
                        install.path.display()
                    ),
                });
            }
            let discovery = extension::discover(&config_root, &install.version);
            let verdict = extension::verdict(&discovery, &install.version);
            match verdict {
                ExtensionVerdict::Ok {
                    plugin_version,
                    built_for,
                } => {
                    report.ghidra = manifest.ghidra.clone();
                    report.plugin = manifest.plugin.clone();
                    // Compatible as it stands. A newer plugin built for the
                    // same Ghidra build is an upgrade — offered, never
                    // forced, and probing the releases API needs download
                    // consent (the plugin zips are small and cached).
                    let fetched = match request.local_plugin_zip {
                        Some(zip) => Some(FetchedPlugin::from_local(zip)?),
                        None if request.download_consent => {
                            let release = request.api.latest_release(PLUGIN_REPO).await?;
                            let asset = plugin_asset(&release)?;
                            Some(FetchedPlugin::fetch(request, asset).await?)
                        }
                        None => None,
                    };
                    if let Some(fetched) = fetched {
                        let is_newer =
                            match (plugin_version.as_deref(), fetched.plugin_version.as_deref()) {
                                (Some(current), Some(latest)) => {
                                    releases::compare_versions(current, latest)
                                        == std::cmp::Ordering::Less
                                }
                                _ => false,
                            };
                        if fetched.built_for == built_for && is_newer {
                            let from = plugin_version.unwrap_or_else(|| "unknown".into());
                            if !request.upgrade_approved {
                                return Err(GhidraError::UpgradeConfirmation {
                                    what: "GhidraMCP extension".to_string(),
                                    from: from.clone(),
                                    to: fetched.label(),
                                });
                            }
                            let dir = install_plugin(&fetched.zip, &config_root, &install.version)?;
                            record_plugin(
                                &mut manifest,
                                &mut report,
                                &fetched,
                                &install.version,
                                dir,
                            );
                            report.notes.push(format!(
                                "upgraded the GhidraMCP extension from {from} to {} (both built for Ghidra {})",
                                fetched.label(),
                                install.version
                            ));
                        } else {
                            report.notes.push(format!(
                                "Ghidra {} at {} is already paired with a current GhidraMCP extension — nothing to install",
                                install.version,
                                install.path.display()
                            ));
                        }
                    } else {
                        report.notes.push(format!(
                            "Ghidra {} at {} is already paired with a compatible GhidraMCP extension — nothing to install",
                            install.version,
                            install.path.display()
                        ));
                    }
                }
                verdict => {
                    let old = old_plugin_label(&verdict);
                    let fetched = fetch_plugin_matching(request, &install.version).await?;
                    if let Some(from) = old {
                        // Replacing an existing extension is an upgrade:
                        // it needs the old → new confirmation first.
                        if !request.upgrade_approved {
                            return Err(GhidraError::UpgradeConfirmation {
                                what: "GhidraMCP extension".to_string(),
                                from,
                                to: fetched.label(),
                            });
                        }
                    }
                    let dir = install_plugin(&fetched.zip, &config_root, &install.version)?;
                    record_plugin(&mut manifest, &mut report, &fetched, &install.version, dir);
                    report.ghidra = manifest.ghidra.clone();
                    report.notes.push(format!(
                        "installed GhidraMCP {} into the Extensions dir for Ghidra {} \
                         (discovered via {source})",
                        fetched.label(),
                        install.version
                    ));
                }
            }
        }
        // A named path that does not validate is a misconfiguration the
        // bootstrap must not paper over by installing somewhere else.
        InstallDiscovery::Invalid { path, source } => {
            return Err(GhidraError::BootstrapBlocked {
                reason: format!(
                    "the Ghidra install named by {source} ({} ) is not a valid install; fix \
                     or remove that path before calxgloss can install anything",
                    path.display()
                ),
            });
        }
        InstallDiscovery::NotFound => {
            // Plugin present, Ghidra missing → fetch exactly the build the
            // existing extension names (unless a pin overrides it).
            let existing = find_any_extension(&config_root);
            let reuse = match (existing, request.pin_version) {
                (Some(ext), None) => Some(ext),
                (Some(ext), Some(pin)) if ext.built_for == pin => Some(ext),
                _ => None,
            };
            match reuse {
                Some(ext) => {
                    let ghidra =
                        install_ghidra(request, &ext.built_for, &install_prefix, &mut manifest)
                            .await?;
                    report.notes.push(format!(
                        "the installed GhidraMCP extension is built for Ghidra {}; fetched \
                         exactly that build",
                        ext.built_for
                    ));
                    report.notes.push(format!(
                        "installed Ghidra {} at {}",
                        ghidra.version,
                        ghidra.path.display()
                    ));
                    report.ghidra = Some(ghidra);
                    // The extension was already there — user-managed, not claimed.
                }
                None => {
                    plugin_first(
                        request,
                        &config_root,
                        &install_prefix,
                        &mut manifest,
                        &mut report,
                    )
                    .await?
                }
            }
        }
    }

    manifest::save_manifest(&manifest_file, &manifest);
    Ok(report)
}

/// The plugin-first path: fetch the newest plugin, read which Ghidra build
/// it was compiled against, fetch exactly that build, install both.
async fn plugin_first(
    request: &BootstrapRequest<'_>,
    config_root: &Path,
    install_prefix: &Path,
    manifest: &mut InstallManifest,
    report: &mut BootstrapReport,
) -> Result<()> {
    let fetched = if let Some(zip) = request.local_plugin_zip {
        FetchedPlugin::from_local(zip)?
    } else if let Some(pin) = request.pin_version {
        // A pin forces the whole pair: the newest plugin built for the
        // pinned build, never merely the newest plugin — the latest release
        // may be compiled against a different Ghidra and would land in the
        // pinned build's Extensions dir as a broken pairing.
        fetch_plugin_matching(request, pin).await?
    } else {
        require_download_consent(request, "the GhidraMCP extension zip")?;
        let release = request.api.latest_release(PLUGIN_REPO).await?;
        let asset = plugin_asset(&release)?;
        FetchedPlugin::fetch(request, asset).await?
    };
    // A local plugin zip that contradicts the pin names a pair that cannot
    // work; the strict pairing rule refuses it instead of installing a
    // plugin the pinned build will not load.
    if let Some(pin) = request.pin_version && fetched.built_for != pin {
        return Err(GhidraError::BootstrapBlocked {
            reason: format!(
                "the plugin zip is built for Ghidra {}, not the pinned {pin} — pass a \
                 plugin zip built for {pin}, or drop the pin",
                fetched.built_for
            ),
        });
    }
    let version = request.pin_version.unwrap_or(&fetched.built_for);
    let ghidra = install_ghidra(request, version, install_prefix, manifest).await?;
    // The plugin lands in the Extensions dir of the build actually
    // installed — the one the release tag named, fallback included.
    let dir = install_plugin(&fetched.zip, config_root, &ghidra.version)?;
    record_plugin(manifest, report, &fetched, &ghidra.version, dir);
    report.ghidra = Some(ghidra.clone());
    if ghidra.version != version {
        report.notes.push(format!(
            "no Ghidra {version} release was available; the nearest newer build {} was fetched instead",
            ghidra.version
        ));
    }
    report.notes.push(format!(
        "plugin-first: GhidraMCP {} is built for Ghidra {version}; fetched {} for it",
        fetched.label(),
        ghidra.version
    ));
    report.notes.push(format!(
        "installed Ghidra {} at {}",
        ghidra.version,
        ghidra.path.display()
    ));
    report.notes.push(format!(
        "installed GhidraMCP {} into {}",
        fetched.label(),
        manifest
            .plugin
            .as_ref()
            .map(|p| p.path.display().to_string())
            .unwrap_or_default()
    ));
    Ok(())
}

/// The newest GhidraMCP release whose `extension.properties` names exactly
/// `ghidra_version` — the rule for "Ghidra present, plugin missing or
/// mismatched". Releases are scanned newest-first; each zip is small, so
/// probing is cheap, and every probe lands in the cache for later runs.
async fn fetch_plugin_matching(
    request: &BootstrapRequest<'_>,
    ghidra_version: &str,
) -> Result<FetchedPlugin> {
    if let Some(zip) = request.local_plugin_zip {
        return FetchedPlugin::from_local(zip);
    }
    require_download_consent(
        request,
        &format!(
            "GhidraMCP extension zips while searching for one built for Ghidra {ghidra_version}"
        ),
    )?;
    let releases = request.api.list_releases(PLUGIN_REPO).await?;
    for release in releases {
        let Some(asset) = release.plugin_asset() else {
            continue;
        };
        let fetched = FetchedPlugin::fetch(request, asset).await?;
        if fetched.built_for == ghidra_version {
            return Ok(fetched);
        }
        debug!(
            tag = %release.tag,
            built_for = %fetched.built_for,
            "GhidraMCP release does not match the installed Ghidra; scanning older"
        );
    }
    Err(GhidraError::BootstrapBlocked {
        reason: if request.pin_version == Some(ghidra_version) {
            format!(
                "no {PLUGIN_REPO} release is built for the pinned Ghidra {ghidra_version}; \
                 pick a version the plugin actually supports, or drop the pin"
            )
        } else {
            format!(
                "no {PLUGIN_REPO} release is built for Ghidra {ghidra_version}; calxgloss \
                 will not modify the existing install — upgrade Ghidra, or pin a version \
                 with ghidra.pin_version"
            )
        },
    })
}

/// A plugin zip with the identity read out of it.
struct FetchedPlugin {
    zip: PathBuf,
    /// The Ghidra build `extension.properties` names.
    built_for: String,
    /// The plugin version, when the zip names one.
    plugin_version: Option<String>,
}

impl FetchedPlugin {
    async fn fetch(request: &BootstrapRequest<'_>, asset: &ReleaseAsset) -> Result<Self> {
        let zip = fetch_verified(request.api, asset, request.cache_dir).await?;
        let (built_for, plugin_version) = read_plugin_manifest(&zip)?;
        Ok(Self {
            zip,
            built_for,
            plugin_version,
        })
    }

    fn from_local(zip: &Path) -> Result<Self> {
        let (built_for, plugin_version) = read_plugin_manifest(zip)?;
        Ok(Self {
            zip: zip.to_path_buf(),
            built_for,
            plugin_version,
        })
    }

    /// The version label the confirmation and notes show.
    fn label(&self) -> String {
        self.plugin_version.clone().unwrap_or_else(|| {
            self.zip
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| "unknown".to_string())
        })
    }
}

/// The plugin zip asset of a GhidraMCP release, named by the release that
/// lacks one.
fn plugin_asset(release: &Release) -> Result<&ReleaseAsset> {
    release
        .plugin_asset()
        .ok_or_else(|| GhidraError::ArtifactInvalid {
            detail: format!(
                "the latest {PLUGIN_REPO} release ({}) carries no GhidraMCP-*.zip asset",
                release.tag
            ),
        })
}

/// Record an installed plugin in the manifest and mirror it into the report.
fn record_plugin(
    manifest: &mut InstallManifest,
    report: &mut BootstrapReport,
    fetched: &FetchedPlugin,
    built_for: &str,
    path: PathBuf,
) {
    manifest.plugin = Some(ManagedPlugin {
        version: fetched.plugin_version.clone(),
        built_for: built_for.to_string(),
        path,
    });
    report.plugin = manifest.plugin.clone();
}

/// Fetch exactly Ghidra `version` (tag `Ghidra_<ver>_build`, nearest ≥
/// fallback), verify, unzip, and install under `install_prefix`.
async fn install_ghidra(
    request: &BootstrapRequest<'_>,
    version: &str,
    install_prefix: &Path,
    manifest: &mut InstallManifest,
) -> Result<ManagedInstall> {
    // A pin is a demand for the exact build: no nearest-≥ sideways step,
    // because the plugin was built for the pinned version and any other
    // build breaks the pair the pin exists to guarantee.
    let pinned = request.pin_version == Some(version);
    let (zip, release_version) = match request.local_ghidra_zip {
        Some(zip) => (zip.to_path_buf(), None),
        None => {
            require_download_consent(request, "the Ghidra release (~570 MB)")?;
            let tag = releases::ghidra_tag(version);
            let release = match request.api.release_by_tag(GHIDRA_REPO, &tag).await? {
                Some(release) => Some(release),
                None if !pinned => {
                    // Nearest ≥ fallback: never a downgrade, never a silent
                    // jump past the build the plugin was compiled against
                    // when an exact match exists.
                    let releases = request.api.list_releases(GHIDRA_REPO).await?;
                    releases::nearest_release_at_least(&releases, version).cloned()
                }
                None => None,
            }
            .ok_or_else(|| GhidraError::BootstrapBlocked {
                reason: if pinned {
                    format!(
                        "{GHIDRA_REPO} has no release tagged {tag}: the pinned Ghidra \
                         {version} cannot be installed — pick a version the repository \
                         actually releases"
                    )
                } else {
                    format!(
                        "{GHIDRA_REPO} has no release for Ghidra {version} or a nearer \
                         newer one"
                    )
                },
            })?;
            let asset = release
                .ghidra_asset()
                .ok_or_else(|| GhidraError::ArtifactInvalid {
                    detail: format!(
                        "the {} release ({}) carries no ghidra_*.zip asset",
                        GHIDRA_REPO, release.tag
                    ),
                })?;
            let built = releases::version_from_tag(&release.tag).map(str::to_string);
            (
                fetch_verified(request.api, asset, request.cache_dir).await?,
                built,
            )
        }
    };
    // The build actually installed is the one the release tag (or a local
    // zip's canonical top-level directory) names — never the merely-requested
    // one, so a nearest-≥ fallback lands under the version it really is.
    let installed = release_version
        .or_else(|| zip_top_level_version(&zip))
        .unwrap_or_else(|| version.to_string());
    if pinned && installed != version {
        // Only a local zip can miss the pin this way: the exact-tag fetch
        // above already guarantees the match.
        return Err(GhidraError::BootstrapBlocked {
            reason: format!(
                "the Ghidra zip holds build {installed}, not the pinned {version} — pass a \
                 zip for {version}, or drop the pin"
            ),
        });
    } else if installed != version {
        info!(
            requested = %version,
            installed = %installed,
            "Ghidra release differs from the requested version"
        );
    }
    let dest = install_prefix.join(format!("ghidra_{installed}_PUBLIC"));
    extract_ghidra(&zip, &dest)?;
    let managed = ManagedInstall {
        version: installed,
        path: dest,
    };
    manifest.ghidra = Some(managed.clone());
    Ok(managed)
}

/// The version a release zip's canonical `ghidra_<ver>_PUBLIC` top-level
/// directory names, when it names one — how a local `--ghidra-zip` says
/// which build it actually holds.
fn zip_top_level_version(zip: &Path) -> Option<String> {
    let archive = zip::ZipArchive::new(std::fs::File::open(zip).ok()?).ok()?;
    let name = archive
        .file_names()
        .next()?
        .trim_end_matches('/')
        .to_string();
    let rest = name.strip_prefix("ghidra_")?.strip_suffix("_PUBLIC")?;
    install::parses_as_version(rest).then(|| rest.to_string())
}

/// The consent gate every network artifact passes through.
fn require_download_consent(request: &BootstrapRequest<'_>, what: &str) -> Result<()> {
    if request.download_consent {
        return Ok(());
    }
    Err(GhidraError::ConsentRequired {
        detail: format!("calxgloss would download {what}"),
    })
}

/// The old plugin's label for an upgrade confirmation, `None` when there is
/// nothing to replace (the Missing verdict).
fn old_plugin_label(verdict: &ExtensionVerdict) -> Option<String> {
    match verdict {
        ExtensionVerdict::Missing { .. } => None,
        ExtensionVerdict::WrongBuild { built_for, .. } => {
            Some(format!("an extension built for {built_for}"))
        }
        ExtensionVerdict::TooOld { plugin_version, .. } => {
            Some(format!("GhidraMCP {plugin_version}"))
        }
        ExtensionVerdict::Broken { dir } => {
            Some(format!("a broken extension at {}", dir.display()))
        }
        ExtensionVerdict::Ok { .. } => None,
    }
}

/// The JDK-21 gate: run `java -version` and require 21+.
fn jdk_gate(java: Option<&Path>) -> Result<()> {
    let java_bin = java.unwrap_or(Path::new("java"));
    match java_major(java_bin) {
        Some(major) if major >= MIN_JDK_MAJOR => Ok(()),
        Some(major) => Err(GhidraError::JdkGate {
            detail: format!(
                "`{}` reports Java {major}; Ghidra 12.x needs Java {MIN_JDK_MAJOR} or newer",
                java_bin.display()
            ),
        }),
        None => Err(GhidraError::JdkGate {
            detail: format!(
                "`{} -version` did not answer — no Java runtime is on PATH",
                java_bin.display()
            ),
        }),
    }
}

/// The Java major version `java_bin -version` reports, `None` when the
/// binary is missing or its output is unrecognisable.
fn java_major(java_bin: &Path) -> Option<u32> {
    let output = std::process::Command::new(java_bin)
        .arg("-version")
        .output()
        .ok()?;
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    parse_java_major(&text)
}

/// Parse the major version out of `java -version` output — both streams,
/// since the version line has lived on stderr for decades.
///
/// Handles the modern `openjdk version "21.0.5"` spelling and the legacy
/// `java version "1.8.0_401"` spelling, where the real major is the second
/// component.
fn parse_java_major(output: &str) -> Option<u32> {
    let line = output.lines().find(|line| line.contains("version \""))?;
    let version = line.split('"').nth(1)?;
    let core = version.split(['_', '-']).next()?;
    let mut components = core.split('.');
    let first: u32 = components.next()?.parse().ok()?;
    if first == 1 {
        // The Java 8-era spelling: `1.8` means 8.
        components.next()?.parse().ok()
    } else {
        Some(first)
    }
}

/// Download `asset` into `cache_dir` and verify its sha256 against the
/// releases API digest before it is ever unzipped.
///
/// A cached copy whose digest still matches is reused — retries do not
/// refetch 570 MB. A partial download resumes over HTTP Range. A digest
/// mismatch deletes the file and fails; nothing unverified reaches the
/// unzip step.
async fn fetch_verified(
    api: &ReleasesApi,
    asset: &ReleaseAsset,
    cache_dir: &Path,
) -> Result<PathBuf> {
    let expected = asset
        .sha256
        .clone()
        .ok_or_else(|| GhidraError::ReleasesApi {
            url: asset.download_url.clone(),
            detail: format!(
                "the asset {} carries no sha256 digest to verify against",
                asset.name
            ),
        })?;
    std::fs::create_dir_all(cache_dir).map_err(|source| GhidraError::BootstrapBlocked {
        reason: format!(
            "the download cache {} is not writable: {source}",
            cache_dir.display()
        ),
    })?;
    let cached = cache_dir.join(&asset.name);
    if cached.is_file() {
        let found = sha256_hex(&cached)?;
        if found == expected {
            debug!(asset = %asset.name, "Reusing the cached, digest-verified download");
            return Ok(cached);
        }
        warn!(asset = %asset.name, "The cached download no longer matches its digest; refetching");
        let _ = std::fs::remove_file(&cached);
    }
    let part = cache_dir.join(format!("{}.part", asset.name));
    api.download(&asset.download_url, &part).await?;
    let found = sha256_hex(&part)?;
    if found != expected {
        let _ = std::fs::remove_file(&part);
        return Err(GhidraError::DigestMismatch {
            asset: asset.name.clone(),
            expected,
            found,
        });
    }
    std::fs::rename(&part, &cached).map_err(|source| GhidraError::BootstrapBlocked {
        reason: format!(
            "the verified download could not be moved into {}: {source}",
            cache_dir.display()
        ),
    })?;
    info!(asset = %asset.name, "Downloaded and sha256-verified");
    Ok(cached)
}

/// The lowercase-hex sha256 of a file, streamed so a 570 MB artifact never
/// has to fit in memory.
fn sha256_hex(path: &Path) -> Result<String> {
    let mut file = std::fs::File::open(path).map_err(|source| GhidraError::BootstrapBlocked {
        reason: format!("could not read {} to hash it: {source}", path.display()),
    })?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|source| GhidraError::BootstrapBlocked {
                reason: format!("could not read {} to hash it: {source}", path.display()),
            })?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex(&hasher.finalize()))
}

/// Lowercase hex of digest bytes.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Read the plugin identity out of an extension zip: the `version=` key of
/// its `extension.properties` (the Ghidra build it was compiled against)
/// and the plugin version from the jar name or the description note.
fn read_plugin_manifest(zip: &Path) -> Result<(String, Option<String>)> {
    let file = std::fs::File::open(zip).map_err(|source| GhidraError::ArtifactInvalid {
        detail: format!("{} could not be opened: {source}", zip.display()),
    })?;
    let mut archive = ZipArchive::new(file).map_err(|source| GhidraError::ArtifactInvalid {
        detail: format!("{} is not a readable zip: {source}", zip.display()),
    })?;
    let mut properties = None;
    let mut jar_version = None;
    for index in 0..archive.len() {
        let mut entry = archive
            .by_index(index)
            .map_err(|source| GhidraError::ArtifactInvalid {
                detail: format!("{} has an unreadable entry: {source}", zip.display()),
            })?;
        let name = entry.mangled_name();
        let name = name.to_string_lossy().replace('\\', "/");
        if name.ends_with("extension.properties") {
            let mut body = String::new();
            entry
                .read_to_string(&mut body)
                .map_err(|source| GhidraError::ArtifactInvalid {
                    detail: format!("extension.properties could not be read: {source}"),
                })?;
            properties = Some(body);
        } else if let Some(version) = name
            .rsplit('/')
            .next()
            .and_then(|rest| rest.strip_prefix("GhidraMCP-"))
            .and_then(|rest| rest.strip_suffix(".jar"))
        {
            jar_version = Some(version.to_string());
        }
    }
    let properties = properties.ok_or_else(|| GhidraError::ArtifactInvalid {
        detail: format!(
            "{} contains no extension.properties — it is not a Ghidra extension zip",
            zip.display()
        ),
    })?;
    let built_for =
        properties_value(&properties, "version").ok_or_else(|| GhidraError::ArtifactInvalid {
            detail: "extension.properties carries no version= key".to_string(),
        })?;
    let plugin_version = jar_version.or_else(|| {
        let rest = properties.split("Plugin version ").nth(1)?;
        let version = rest.split_whitespace().next()?.trim_end_matches('.');
        (!version.is_empty()).then(|| version.to_string())
    });
    Ok((built_for, plugin_version))
}

/// Unzip a Ghidra release into `dest` (the canonical `ghidra_<ver>_PUBLIC`
/// name), restoring the exec bits the zip may not carry.
///
/// Extraction lands in a staging directory beside `dest` and only replaces
/// `dest` once the layout validates — a half-extracted install never
/// discovers as a working stack.
fn extract_ghidra(zip: &Path, dest: &Path) -> Result<()> {
    let staging = unpack_to_staging(zip, dest)?;
    let top = single_top_level_dir(&staging, zip)?;
    if !install::layout_valid(&top) {
        let _ = std::fs::remove_dir_all(&staging);
        return Err(GhidraError::ArtifactInvalid {
            detail: "the Ghidra zip's top-level directory has no Ghidra/Framework inside — it \
                     is not a Ghidra release layout"
                .to_string(),
        });
    }
    restore_exec_bits(&top);
    move_into_place(top, dest)?;
    let _ = std::fs::remove_dir_all(&staging);
    info!(path = %dest.display(), "Unzipped and installed Ghidra");
    Ok(())
}

/// Unzip the extension into the per-version `Extensions` dir Ghidra reads,
/// replacing any existing `GhidraMCP` directory (only reached with the
/// upgrade confirmation already granted).
fn install_plugin(zip: &Path, config_root: &Path, ghidra_version: &str) -> Result<PathBuf> {
    let extensions_dir = extension::state_dir(config_root, ghidra_version).join("Extensions");
    let dest = extensions_dir.join("GhidraMCP");
    let staging = unpack_to_staging(zip, &dest)?;
    let top = single_top_level_dir(&staging, zip)?;
    if !top.join("extension.properties").is_file() {
        let _ = std::fs::remove_dir_all(&staging);
        return Err(GhidraError::ArtifactInvalid {
            detail: "the extension zip's top-level directory has no extension.properties inside"
                .to_string(),
        });
    }
    if dest.exists() {
        std::fs::remove_dir_all(&dest).map_err(|source| GhidraError::BootstrapBlocked {
            reason: format!(
                "the existing extension at {} could not be replaced: {source}",
                dest.display()
            ),
        })?;
    }
    move_into_place(top, &dest)?;
    let _ = std::fs::remove_dir_all(&staging);
    info!(path = %dest.display(), "Installed the GhidraMCP extension");
    Ok(dest)
}

/// Unzip `zip` into a staging directory beside `dest`.
fn unpack_to_staging(zip: &Path, dest: &Path) -> Result<PathBuf> {
    let parent = dest.parent().ok_or_else(|| GhidraError::BootstrapBlocked {
        reason: format!(
            "{} has no parent directory to install beside",
            dest.display()
        ),
    })?;
    std::fs::create_dir_all(parent).map_err(|source| GhidraError::BootstrapBlocked {
        reason: format!("{} is not writable: {source}", parent.display()),
    })?;
    let name = dest
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "install".to_string());
    let staging = parent.join(format!(".{name}.staging"));
    let _ = std::fs::remove_dir_all(&staging);
    let file = std::fs::File::open(zip).map_err(|source| GhidraError::ArtifactInvalid {
        detail: format!("{} could not be opened: {source}", zip.display()),
    })?;
    let mut archive = ZipArchive::new(file).map_err(|source| GhidraError::ArtifactInvalid {
        detail: format!("{} is not a readable zip: {source}", zip.display()),
    })?;
    archive
        .extract(&staging)
        .map_err(|source| GhidraError::BootstrapBlocked {
            reason: format!(
                "{} could not be unzipped into {}: {source}",
                zip.display(),
                staging.display()
            ),
        })?;
    Ok(staging)
}

/// The single top-level directory a release zip carries, named for its error.
fn single_top_level_dir(staging: &Path, zip: &Path) -> Result<PathBuf> {
    let entries: Vec<PathBuf> = std::fs::read_dir(staging)
        .map_err(|source| GhidraError::BootstrapBlocked {
            reason: format!("could not read the staging directory: {source}"),
        })?
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.is_dir())
        .collect();
    match entries.as_slice() {
        [only] => Ok(only.clone()),
        _ => {
            let _ = std::fs::remove_dir_all(staging);
            Err(GhidraError::ArtifactInvalid {
                detail: format!(
                    "{} does not carry exactly one top-level directory (found {})",
                    zip.display(),
                    entries.len()
                ),
            })
        }
    }
}

/// Move the staged directory into place, replacing `dest` only when it was
/// already reached through the upgrade rules.
fn move_into_place(staged: PathBuf, dest: &Path) -> Result<()> {
    if dest.exists() {
        std::fs::remove_dir_all(dest).map_err(|source| GhidraError::BootstrapBlocked {
            reason: format!("{} could not be replaced: {source}", dest.display()),
        })?;
    }
    std::fs::rename(&staged, dest).map_err(|source| GhidraError::BootstrapBlocked {
        reason: format!(
            "the staged install could not be moved into place at {}: {source}",
            dest.display()
        ),
    })
}

/// Restore the exec bits the release zips are known to drop: `ghidraRun`
/// and every `support/*.sh`.
fn restore_exec_bits(install_dir: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let mut targets = vec![install_dir.join("ghidraRun")];
    if let Ok(entries) = std::fs::read_dir(install_dir.join("support")) {
        targets.extend(
            entries
                .flatten()
                .map(|entry| entry.path())
                .filter(|path| path.extension().is_some_and(|ext| ext == "sh")),
        );
    }
    for target in targets {
        if !target.is_file() {
            continue;
        }
        if let Err(source) =
            std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755))
        {
            warn!(path = %target.display(), error = %source, "Could not restore the exec bit");
        }
    }
}

/// The GhidraMCP extension in any per-version state dir — the "plugin
/// present, Ghidra missing" case. The highest `built_for` wins.
fn find_any_extension(config_root: &Path) -> Option<GhidraExtension> {
    let entries = std::fs::read_dir(config_root).ok()?;
    let mut best: Option<GhidraExtension> = None;
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let discovery = extension::discover(config_root, &dir_version(&path)?);
        if let ExtensionDiscovery::Found(extension) = discovery {
            let replace = best
                .as_ref()
                .is_none_or(|current| current.built_for < extension.built_for);
            if replace {
                best = Some(extension);
            }
        }
    }
    best
}

/// The version a `ghidra_<X.Y.Z>_PUBLIC` state dir name carries — the only
/// spelling whose extension can be paired with a Ghidra build.
fn dir_version(path: &Path) -> Option<String> {
    let name = path.file_name()?.to_str()?;
    let middle = name.strip_prefix("ghidra_")?.strip_suffix("_PUBLIC")?;
    install::parses_as_version(middle).then(|| middle.to_string())
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    #[test]
    fn test_parses_the_modern_version_line() {
        assert_eq!(
            parse_java_major(r#"openjdk version "21.0.5" 2024-10-15"#),
            Some(21)
        );
        assert_eq!(
            parse_java_major(r#"openjdk version "17.0.9" 2023"#),
            Some(17)
        );
    }

    #[test]
    fn test_parses_the_legacy_one_eight_spelling() {
        assert_eq!(parse_java_major(r#"java version "1.8.0_401""#), Some(8));
    }

    #[test]
    fn test_unrecognisable_output_is_none_not_a_guess() {
        assert_eq!(parse_java_major("no version line here"), None);
        assert_eq!(parse_java_major(r#"openjdk version "twenty""#), None);
    }

    #[test]
    fn test_the_jdk_gate_runs_a_real_binary() {
        // A fixture script standing in for a JDK: the gate must accept 21
        // and refuse 17, and a missing binary must be a named failure.
        let dir = tempfile::tempdir().expect("tempdir");
        let fake = dir.path().join("java");
        std::fs::write(&fake, "#!/bin/sh\necho 'openjdk version \"21.0.5\"' >&2\n")
            .expect("write fake java");
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755))
            .expect("chmod fake java");
        assert!(jdk_gate(Some(&fake)).is_ok());

        std::fs::write(&fake, "#!/bin/sh\necho 'openjdk version \"17.0.9\"' >&2\n")
            .expect("write old fake java");
        assert!(matches!(
            jdk_gate(Some(&fake)),
            Err(GhidraError::JdkGate { .. })
        ));

        assert!(matches!(
            jdk_gate(Some(&dir.path().join("nope"))),
            Err(GhidraError::JdkGate { .. })
        ));
    }

    #[test]
    fn test_old_plugin_labels_name_what_would_be_replaced() {
        assert_eq!(
            old_plugin_label(&ExtensionVerdict::Missing {
                extensions_dir: "/e".into()
            }),
            None
        );
        assert_eq!(
            old_plugin_label(&ExtensionVerdict::TooOld {
                plugin_version: "5.9.0".into(),
                required: "6.0.0".into()
            })
            .as_deref(),
            Some("GhidraMCP 5.9.0")
        );
        assert!(
            old_plugin_label(&ExtensionVerdict::WrongBuild {
                built_for: "12.1.1".into(),
                ghidra: "12.1.2".into(),
                extensions_dir: "/e".into()
            })
            .is_some()
        );
    }

    #[test]
    fn test_hex_is_lowercase_fixed_width() {
        assert_eq!(hex(&[0x0a, 0xff]), "0aff");
    }
}
