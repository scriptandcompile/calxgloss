//! End-to-end tests for the `doctor --fix` bootstrap path (G1-T8), against a
//! fake GitHub releases API and fixture zips — no real downloads.

use std::collections::HashMap;
use std::io::{Cursor, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use calxgloss_ghidra::lifecycle::{
    BootstrapRequest, ExtensionVerdict, InstallDiscovery, InstallManifest, InstallSource,
    ReleasesApi, StackRequest, bootstrap, check_stack, manifest_path,
};
use calxgloss_ghidra::{GhidraClient, GhidraError};
use sha2::{Digest as _, Sha256};

// ---------------------------------------------------------------- fake API

/// What the fake releases API serves: release lists per repo (newest first)
/// and raw bytes per asset name.
struct Spec {
    plugin: Vec<SpecRelease>,
    ghidra: Vec<SpecRelease>,
    /// Bytes served for each asset download URL; a name missing here 404s.
    assets: HashMap<String, Vec<u8>>,
    /// Every API call answers 403 with the rate-limit headers, the way
    /// GitHub does when the anonymous bucket is empty.
    rate_limited: bool,
}

struct SpecRelease {
    tag: String,
    /// (asset name, advertised sha256 digest)
    assets: Vec<(String, String)>,
}

impl Spec {
    fn empty() -> Self {
        Self {
            plugin: Vec::new(),
            ghidra: Vec::new(),
            assets: HashMap::new(),
            rate_limited: false,
        }
    }
}

/// Starts the fake API and returns its base URL for [`ReleasesApi::new`].
async fn serve(spec: Spec) -> String {
    serve_logged(spec, None).await
}

/// Like [`serve`], additionally recording the head of every request (request
/// line plus headers) into `log` — how tests prove a token rode along or a
/// download resumed with a `Range` header.
async fn serve_logged(
    spec: Spec,
    log: Option<std::sync::Arc<std::sync::Mutex<Vec<String>>>>,
) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("fake API binds an ephemeral port");
    let addr = listener.local_addr().expect("fake API has a local address");
    let spec = std::sync::Arc::new(spec);
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
            let spec = std::sync::Arc::clone(&spec);
            let log = log.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 8192];
                let n = stream.read(&mut buf).await.unwrap_or(0);
                let head = String::from_utf8_lossy(&buf[..n]).to_string();
                if let Some(log) = &log {
                    log.lock().expect("request log lock").push(head.clone());
                }
                let path = head
                    .lines()
                    .next()
                    .and_then(|line| line.split_whitespace().nth(1))
                    .unwrap_or("/")
                    .to_string();
                let (status, headers, body) = route(&spec, &path, &head, addr.port());
                let mut response =
                    format!("HTTP/1.1 {status}\r\nContent-Length: {}\r\n", body.len()).into_bytes();
                for header in headers {
                    response.extend_from_slice(header.as_bytes());
                    response.extend_from_slice(b"\r\n");
                }
                response.extend_from_slice(b"\r\n");
                response.extend_from_slice(&body);
                let _ = stream.write_all(&response).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    format!("http://{addr}")
}

fn route(spec: &Spec, path: &str, head: &str, port: u16) -> (u16, Vec<String>, Vec<u8>) {
    let (path, _) = path.split_once('?').unwrap_or((path, ""));
    let json = |value: serde_json::Value| (200, Vec::new(), value.to_string().into_bytes());

    if let Some(rest) = path.strip_prefix("/assets/") {
        return match spec.assets.get(rest) {
            Some(bytes) => serve_asset(bytes, head),
            None => (404, Vec::new(), b"{}".to_vec()),
        };
    }
    if spec.rate_limited {
        // GitHub's primary rate limit: 403 with the remaining budget at zero.
        return (
            403,
            vec![
                "x-ratelimit-remaining: 0".to_string(),
                "x-ratelimit-reset: 4100000000".to_string(),
            ],
            br#"{"message":"API rate limit exceeded for 127.0.0.1."}"#.to_vec(),
        );
    }
    let is_plugin = path.contains("ghidra-mcp");
    let releases = if is_plugin {
        &spec.plugin
    } else {
        &spec.ghidra
    };

    if path.ends_with("/releases/latest") {
        return match releases.first() {
            Some(release) => json(release_json(release, port)),
            None => (404, Vec::new(), b"{}".to_vec()),
        };
    }
    if let Some((_, tag)) = path.split_once("/tags/") {
        return match releases.iter().find(|release| release.tag == tag) {
            Some(release) => json(release_json(release, port)),
            None => (404, Vec::new(), b"{}".to_vec()),
        };
    }
    if path.ends_with("/releases") {
        let list: Vec<_> = releases.iter().map(|r| release_json(r, port)).collect();
        return json(serde_json::Value::Array(list));
    }
    (404, Vec::new(), b"{}".to_vec())
}

/// Serves an asset's bytes, honoring `Range: bytes=N-` with a 206 that
/// carries only the suffix — exactly like GitHub's download CDN, so the
/// resume path under test is the real one.
fn serve_asset(bytes: &[u8], head: &str) -> (u16, Vec<String>, Vec<u8>) {
    let start = head
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            if !name.trim().eq_ignore_ascii_case("range") {
                return None;
            }
            value
                .trim()
                .strip_prefix("bytes=")?
                .split('-')
                .next()?
                .parse::<usize>()
                .ok()
        })
        .unwrap_or(0);
    if start > 0 {
        if start >= bytes.len() {
            return (416, Vec::new(), Vec::new());
        }
        return (
            206,
            vec![format!(
                "Content-Range: bytes {}-{}/{}",
                start,
                bytes.len() - 1,
                bytes.len()
            )],
            bytes[start..].to_vec(),
        );
    }
    (200, Vec::new(), bytes.to_vec())
}

fn release_json(release: &SpecRelease, port: u16) -> serde_json::Value {
    serde_json::json!({
        "tag_name": release.tag,
        "assets": release.assets.iter().map(|(name, digest)| serde_json::json!({
            "name": name,
            "browser_download_url": format!("http://127.0.0.1:{port}/assets/{name}"),
            "digest": format!("sha256:{digest}"),
        })).collect::<Vec<_>>(),
    })
}

// -------------------------------------------------------------- fixtures

fn sha256_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn zip_bytes(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
    for (name, data) in entries {
        writer
            .start_file(*name, zip::write::SimpleFileOptions::default())
            .expect("fixture zip entry");
        writer.write_all(data).expect("write fixture entry");
    }
    writer.finish().expect("finish fixture zip").into_inner()
}

/// A GhidraMCP extension zip: `version=` names the Ghidra build (ADR-0001),
/// the jar name carries the plugin version.
fn plugin_zip_bytes(built_for: &str, plugin_version: &str) -> Vec<u8> {
    zip_bytes(&[
        (
            "GhidraMCP/extension.properties",
            format!("name=GhidraMCP\nversion={built_for}\n").as_bytes(),
        ),
        (
            &format!("GhidraMCP/lib/GhidraMCP-{plugin_version}.jar"),
            b"not-a-real-jar".as_slice(),
        ),
    ])
}

/// A Ghidra release zip: the canonical top-level dir with a validating
/// `Ghidra/Framework` layout inside.
fn ghidra_zip_bytes(version: &str) -> Vec<u8> {
    zip_bytes(&[
        (
            &format!("ghidra_{version}_PUBLIC/Ghidra/Framework/version.dat"),
            b"12".as_slice(),
        ),
        (
            &format!("ghidra_{version}_PUBLIC/ghidraRun"),
            b"#!/bin/sh\n".as_slice(),
        ),
    ])
}

/// Fake `java` printing a line shaped like a real version banner.
fn fake_java(dir: &Path, major: u32) -> PathBuf {
    let path = dir.join(format!("java{major}"));
    let mut f = std::fs::File::create(&path).expect("create fake java");
    writeln!(
        f,
        "#!/bin/sh\necho 'openjdk version \"{major}.0.5\" 2026-01-20' >&2"
    )
    .expect("write fake java");
    f.set_permissions(std::fs::Permissions::from_mode(0o755))
        .expect("make fake java executable");
    drop(f);
    // A freshly-written script can report ETXTBSY when exec'd immediately;
    // warm it up so the bootstrap's JDK gate is deterministic.
    for _ in 0..25 {
        if std::process::Command::new(&path)
            .arg("-version")
            .output()
            .is_ok()
        {
            return path;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    panic!("fake java at {} never became executable", path.display());
}

struct Sandbox {
    root: PathBuf,
    state: PathBuf,
    cache: PathBuf,
    config_root: PathBuf,
    managed_prefix: PathBuf,
}

impl Sandbox {
    fn new(tag: &str) -> Self {
        let root =
            std::env::temp_dir().join(format!("calxgloss-boot-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("create fixture dirs");
        let state = root.join("state");
        let cache = root.join("cache");
        let config_root = root.join(".config").join("ghidra");
        let managed_prefix = state.join("calxgloss/ghidra");
        Self {
            root,
            state,
            cache,
            config_root,
            managed_prefix,
        }
    }

    /// A managed-prefix Ghidra install with a validating layout.
    fn seed_managed_ghidra(&self, version: &str) {
        let dir = self.managed_prefix.join(format!("ghidra_{version}_PUBLIC"));
        std::fs::create_dir_all(dir.join("Ghidra/Framework")).expect("create fixture dirs");
        std::fs::write(dir.join("ghidraRun"), "#!/bin/sh\n").expect("write fixture");
    }

    /// An already-installed extension for `state_version`, built for
    /// `built_for`, with a `GhidraMCP-<plugin>.jar`.
    fn seed_extension(&self, state_version: &str, built_for: &str, plugin: &str) {
        let dir = self
            .config_root
            .join(format!("ghidra_{state_version}_PUBLIC"))
            .join("Extensions/GhidraMCP");
        std::fs::create_dir_all(dir.join("lib")).expect("create fixture dirs");
        std::fs::write(
            dir.join("extension.properties"),
            format!("name=GhidraMCP\nversion={built_for}\n"),
        )
        .expect("write fixture");
        std::fs::write(dir.join(format!("lib/GhidraMCP-{plugin}.jar")), b"jar")
            .expect("write fixture");
    }

    fn stack(&self) -> StackRequest<'_> {
        StackRequest {
            env_install_dir: None,
            config_install_dir: None,
            home: Some(&self.root),
            managed_prefix: Some(&self.managed_prefix),
        }
    }

    fn manifest(&self) -> InstallManifest {
        let body = std::fs::read_to_string(manifest_path(&self.state))
            .unwrap_or_else(|_| "{}".to_string());
        serde_json::from_str(&body).expect("manifest parses")
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn request<'a>(sb: &'a Sandbox, api: &'a ReleasesApi, java: &'a Path) -> BootstrapRequest<'a> {
    BootstrapRequest {
        stack: sb.stack(),
        state_dir: &sb.state,
        cache_dir: &sb.cache,
        api,
        java: Some(java),
        pin_version: None,
        local_plugin_zip: None,
        local_ghidra_zip: None,
        download_consent: true,
        upgrade_approved: false,
    }
}

/// A client pointed at a port nothing listens on: the server probe in
/// `check_stack` comes back `Unreachable`, which is not what these tests check.
fn dead_client() -> GhidraClient {
    GhidraClient::new("http://127.0.0.1:1").expect("dead client URL is valid")
}

// ------------------------------------------------------------------- tests

/// Both missing: the plugin's `extension.properties` decides which Ghidra gets
/// fetched — even when it is older than the newest release — and both downloads
/// are sha256-verified against the API digest on the way in.
#[tokio::test]
async fn plugin_first_pairing_installs_both() {
    let sb = Sandbox::new("pair");
    let plugin = plugin_zip_bytes("12.1.2", "6.0.0");
    let ghidra = ghidra_zip_bytes("12.1.2");
    let spec = Spec {
        plugin: vec![SpecRelease {
            tag: "v6.0.0".into(),
            assets: vec![("GhidraMCP-6.0.0.zip".into(), sha256_bytes(&plugin))],
        }],
        ghidra: vec![
            SpecRelease {
                tag: "Ghidra_12.1.4_build".into(),
                assets: vec![("ghidra_12.1.4_PUBLIC.zip".into(), "deadbeef".into())],
            },
            SpecRelease {
                tag: "Ghidra_12.1.2_build".into(),
                assets: vec![("ghidra_12.1.2_PUBLIC.zip".into(), sha256_bytes(&ghidra))],
            },
        ],
        assets: HashMap::from([
            ("GhidraMCP-6.0.0.zip".to_string(), plugin),
            ("ghidra_12.1.2_PUBLIC.zip".to_string(), ghidra),
        ]),
        ..Spec::empty()
    };
    let url = serve(spec).await;
    let api = ReleasesApi::new(&url).expect("fake API URL is valid");
    let java = fake_java(&sb.root, 21);

    let report = bootstrap(&request(&sb, &api, &java))
        .await
        .expect("bootstrap succeeds");
    assert_eq!(
        report.ghidra.as_ref().expect("report names Ghidra").version,
        "12.1.2"
    );
    assert_eq!(
        report
            .plugin
            .as_ref()
            .expect("report names the plugin")
            .built_for,
        "12.1.2"
    );
    assert_eq!(
        report
            .plugin
            .as_ref()
            .expect("report names the plugin")
            .version
            .as_deref(),
        Some("6.0.0")
    );

    // Ghidra landed in the managed prefix with a valid layout, plugin in the
    // per-version Extensions dir.
    let ghidra_dir = sb.managed_prefix.join("ghidra_12.1.2_PUBLIC");
    assert!(ghidra_dir.join("Ghidra/Framework").is_dir());
    let ext = sb
        .config_root
        .join("ghidra_12.1.2_PUBLIC/Extensions/GhidraMCP/extension.properties");
    assert!(ext.exists());

    // The manifest records both installs.
    let manifest = sb.manifest();
    assert_eq!(
        manifest
            .ghidra
            .as_ref()
            .expect("manifest names Ghidra")
            .version,
        "12.1.2"
    );
    assert_eq!(
        manifest
            .plugin
            .as_ref()
            .expect("manifest names the plugin")
            .built_for,
        "12.1.2"
    );

    // And discovery finds the managed install with no env or config input.
    let report = check_stack(&dead_client(), &sb.stack()).await;
    let InstallDiscovery::Found { source, .. } = report.install else {
        panic!(
            "expected a discovered managed install, got {:?}",
            report.install
        );
    };
    assert_eq!(source, InstallSource::ManagedPrefix);
    assert_eq!(
        report.extension,
        Some(ExtensionVerdict::Ok {
            plugin_version: Some("6.0.0".into()),
            built_for: "12.1.2".into(),
        })
    );
}

/// A digest mismatch deletes the download and stops before anything is
/// unzipped — the plugin lands, the Ghidra install does not.
#[tokio::test]
async fn digest_mismatch_refuses_to_unzip() {
    let sb = Sandbox::new("digest");
    let plugin = plugin_zip_bytes("12.1.2", "6.0.0");
    let spec = Spec {
        plugin: vec![SpecRelease {
            tag: "v6.0.0".into(),
            assets: vec![("GhidraMCP-6.0.0.zip".into(), sha256_bytes(&plugin))],
        }],
        ghidra: vec![SpecRelease {
            tag: "Ghidra_12.1.2_build".into(),
            assets: vec![("ghidra_12.1.2_PUBLIC.zip".into(), "deadbeef".into())],
        }],
        assets: HashMap::from([
            ("GhidraMCP-6.0.0.zip".to_string(), plugin),
            // Served bytes hash to something else than the advertised digest.
            (
                "ghidra_12.1.2_PUBLIC.zip".to_string(),
                ghidra_zip_bytes("12.1.2"),
            ),
        ]),
        ..Spec::empty()
    };
    let url = serve(spec).await;
    let api = ReleasesApi::new(&url).expect("fake API URL is valid");
    let java = fake_java(&sb.root, 21);

    let err = bootstrap(&request(&sb, &api, &java)).await.unwrap_err();
    assert!(
        matches!(&err, GhidraError::DigestMismatch { expected, .. } if expected == "deadbeef"),
        "expected DigestMismatch, got {err:?}"
    );
    // Nothing was installed, and the partial download was deleted.
    assert!(!sb.managed_prefix.exists());
    assert!(!sb.cache.join("ghidra_12.1.2_PUBLIC.zip.part").exists());
    assert!(sb.manifest().ghidra.is_none());
}

/// Without consent the bootstrap stops before touching the network.
#[tokio::test]
async fn no_consent_stops_before_downloads() {
    let sb = Sandbox::new("consent");
    let url = serve(Spec::empty()).await;
    let api = ReleasesApi::new(&url).expect("fake API URL is valid");
    let java = fake_java(&sb.root, 21);
    let mut req = request(&sb, &api, &java);
    req.download_consent = false;
    let err = bootstrap(&req).await.unwrap_err();
    assert!(
        matches!(err, GhidraError::ConsentRequired { .. }),
        "{err:?}"
    );
}

/// A too-old JDK aborts before any download, with the version in the message.
#[tokio::test]
async fn jdk_gate_blocks_old_java() {
    let sb = Sandbox::new("jdk");
    let url = serve(Spec::empty()).await;
    let api = ReleasesApi::new(&url).expect("fake API URL is valid");
    let java = fake_java(&sb.root, 17);
    let err = bootstrap(&request(&sb, &api, &java)).await.unwrap_err();
    let GhidraError::JdkGate { detail } = err else {
        panic!("expected JdkGate, got {err:?}");
    };
    assert!(
        detail.contains("17"),
        "the message names the version: {detail}"
    );
}

/// A missing JDK aborts with the same gate.
#[tokio::test]
async fn jdk_gate_blocks_missing_java() {
    let sb = Sandbox::new("jdk-missing");
    let url = serve(Spec::empty()).await;
    let api = ReleasesApi::new(&url).expect("fake API URL is valid");
    let err = bootstrap(&request(&sb, &api, &sb.root.join("nope")))
        .await
        .unwrap_err();
    assert!(matches!(err, GhidraError::JdkGate { .. }));
}

/// Ghidra present, plugin missing: the newest plugin built for the installed
/// version is chosen, not the newest plugin overall.
#[tokio::test]
async fn plugin_matching_scans_for_installed_version() {
    let sb = Sandbox::new("match");
    sb.seed_managed_ghidra("12.1.2");
    let spec = Spec {
        plugin: vec![
            SpecRelease {
                tag: "v7.0.0".into(),
                assets: vec![(
                    "GhidraMCP-7.0.0.zip".into(),
                    sha256_bytes(&plugin_zip_bytes("12.1.4", "7.0.0")),
                )],
            },
            SpecRelease {
                tag: "v6.0.0".into(),
                assets: vec![(
                    "GhidraMCP-6.0.0.zip".into(),
                    sha256_bytes(&plugin_zip_bytes("12.1.2", "6.0.0")),
                )],
            },
        ],
        ghidra: Vec::new(),
        assets: HashMap::from([
            (
                "GhidraMCP-7.0.0.zip".to_string(),
                plugin_zip_bytes("12.1.4", "7.0.0"),
            ),
            (
                "GhidraMCP-6.0.0.zip".to_string(),
                plugin_zip_bytes("12.1.2", "6.0.0"),
            ),
        ]),
        ..Spec::empty()
    };
    let url = serve(spec).await;
    let api = ReleasesApi::new(&url).expect("fake API URL is valid");
    let java = fake_java(&sb.root, 21);

    let report = bootstrap(&request(&sb, &api, &java))
        .await
        .expect("bootstrap succeeds");
    assert_eq!(
        report
            .plugin
            .as_ref()
            .expect("report names the plugin")
            .version
            .as_deref(),
        Some("6.0.0")
    );
    assert!(report.ghidra.is_none());
    let ext = sb
        .config_root
        .join("ghidra_12.1.2_PUBLIC/Extensions/GhidraMCP/extension.properties");
    assert!(ext.exists());
}

/// A paired but too-old extension is only replaced after the old → new
/// confirmation: the first pass asks, the approved pass installs.
#[tokio::test]
async fn plugin_upgrade_needs_confirmation() {
    let sb = Sandbox::new("upgrade");
    sb.seed_managed_ghidra("12.1.2");
    sb.seed_extension("12.1.2", "12.1.2", "5.9.0");
    let spec = Spec {
        plugin: vec![SpecRelease {
            tag: "v6.0.0".into(),
            assets: vec![(
                "GhidraMCP-6.0.0.zip".into(),
                sha256_bytes(&plugin_zip_bytes("12.1.2", "6.0.0")),
            )],
        }],
        ghidra: Vec::new(),
        assets: HashMap::from([(
            "GhidraMCP-6.0.0.zip".to_string(),
            plugin_zip_bytes("12.1.2", "6.0.0"),
        )]),
        ..Spec::empty()
    };
    let url = serve(spec).await;
    let api = ReleasesApi::new(&url).expect("fake API URL is valid");
    let java = fake_java(&sb.root, 21);

    // First pass: asks instead of replacing, and changes nothing.
    let err = bootstrap(&request(&sb, &api, &java)).await.unwrap_err();
    assert!(
        matches!(&err, GhidraError::UpgradeConfirmation { from, to, .. }
            if from == "GhidraMCP 5.9.0" && to == "6.0.0"),
        "expected UpgradeConfirmation, got {err:?}"
    );
    let jar = sb
        .config_root
        .join("ghidra_12.1.2_PUBLIC/Extensions/GhidraMCP/lib/GhidraMCP-5.9.0.jar");
    assert!(jar.exists());

    // Approved: the new extension replaces the old one.
    let mut req = request(&sb, &api, &java);
    req.upgrade_approved = true;
    let report = bootstrap(&req).await.expect("bootstrap succeeds");
    assert_eq!(
        report
            .plugin
            .as_ref()
            .expect("report names the plugin")
            .version
            .as_deref(),
        Some("6.0.0")
    );
    assert!(!jar.exists());
}

/// A pinned version overrides the build the plugin would pick — and the
/// pair stays strict: the plugin installed is one built for the pinned
/// build, not merely the newest release.
#[tokio::test]
async fn pin_overrides_pairing() {
    let sb = Sandbox::new("pin");
    let plugin = plugin_zip_bytes("12.1.4", "6.0.0");
    let ghidra = ghidra_zip_bytes("12.1.4");
    let spec = Spec {
        plugin: vec![SpecRelease {
            tag: "v6.0.0".into(),
            assets: vec![("GhidraMCP-6.0.0.zip".into(), sha256_bytes(&plugin))],
        }],
        ghidra: vec![SpecRelease {
            tag: "Ghidra_12.1.4_build".into(),
            assets: vec![("ghidra_12.1.4_PUBLIC.zip".into(), sha256_bytes(&ghidra))],
        }],
        assets: HashMap::from([
            ("GhidraMCP-6.0.0.zip".to_string(), plugin),
            ("ghidra_12.1.4_PUBLIC.zip".to_string(), ghidra),
        ]),
        ..Spec::empty()
    };
    let url = serve(spec).await;
    let api = ReleasesApi::new(&url).expect("fake API URL is valid");
    let java = fake_java(&sb.root, 21);

    let mut req = request(&sb, &api, &java);
    req.pin_version = Some("12.1.4");
    let report = bootstrap(&req).await.expect("bootstrap succeeds");
    assert_eq!(
        report.ghidra.as_ref().expect("report names Ghidra").version,
        "12.1.4"
    );
    assert_eq!(
        report
            .plugin
            .as_ref()
            .expect("report names the plugin")
            .built_for,
        "12.1.4"
    );
    assert!(sb.managed_prefix.join("ghidra_12.1.4_PUBLIC").is_dir());
}

/// A pin forces the whole pair: the newest plugin *built for the pinned
/// build* is chosen — not the newest plugin overall — and exactly that
/// Ghidra build is fetched.
#[tokio::test]
async fn pin_selects_the_plugin_built_for_the_pinned_build() {
    let sb = Sandbox::new("pin-pair");
    let spec = Spec {
        plugin: vec![
            SpecRelease {
                tag: "v7.0.0".into(),
                assets: vec![(
                    "GhidraMCP-7.0.0.zip".into(),
                    sha256_bytes(&plugin_zip_bytes("12.1.4", "7.0.0")),
                )],
            },
            SpecRelease {
                tag: "v6.0.0".into(),
                assets: vec![(
                    "GhidraMCP-6.0.0.zip".into(),
                    sha256_bytes(&plugin_zip_bytes("12.1.2", "6.0.0")),
                )],
            },
        ],
        ghidra: vec![
            SpecRelease {
                // Junk digest: had the bootstrap wrongly paired the newest
                // plugin with this build, the verification would refuse it.
                tag: "Ghidra_12.1.4_build".into(),
                assets: vec![("ghidra_12.1.4_PUBLIC.zip".into(), "deadbeef".into())],
            },
            SpecRelease {
                tag: "Ghidra_12.1.2_build".into(),
                assets: vec![(
                    "ghidra_12.1.2_PUBLIC.zip".into(),
                    sha256_bytes(&ghidra_zip_bytes("12.1.2")),
                )],
            },
        ],
        assets: HashMap::from([
            (
                "GhidraMCP-7.0.0.zip".to_string(),
                plugin_zip_bytes("12.1.4", "7.0.0"),
            ),
            (
                "GhidraMCP-6.0.0.zip".to_string(),
                plugin_zip_bytes("12.1.2", "6.0.0"),
            ),
            (
                "ghidra_12.1.4_PUBLIC.zip".to_string(),
                ghidra_zip_bytes("12.1.4"),
            ),
            (
                "ghidra_12.1.2_PUBLIC.zip".to_string(),
                ghidra_zip_bytes("12.1.2"),
            ),
        ]),
        ..Spec::empty()
    };
    let url = serve(spec).await;
    let api = ReleasesApi::new(&url).expect("fake API URL is valid");
    let java = fake_java(&sb.root, 21);

    let mut req = request(&sb, &api, &java);
    req.pin_version = Some("12.1.2");
    let report = bootstrap(&req).await.expect("bootstrap succeeds");
    assert_eq!(
        report
            .plugin
            .as_ref()
            .expect("report names the plugin")
            .version
            .as_deref(),
        Some("6.0.0"),
        "the plugin built for the pinned build wins over the newest release"
    );
    assert_eq!(
        report.ghidra.as_ref().expect("report names Ghidra").version,
        "12.1.2"
    );
    assert!(sb.managed_prefix.join("ghidra_12.1.2_PUBLIC").is_dir());
    assert!(!sb.managed_prefix.join("ghidra_12.1.4_PUBLIC").exists());
    assert!(
        sb.config_root
            .join("ghidra_12.1.2_PUBLIC/Extensions/GhidraMCP/lib/GhidraMCP-6.0.0.jar")
            .exists()
    );
}

/// A pin demands the exact build: no nearest-≥ sideways step, because the
/// plugin was built for the pinned version and a different build would
/// break the pair the pin exists to guarantee.
#[tokio::test]
async fn pin_refuses_a_ghidra_release_that_does_not_exist() {
    let sb = Sandbox::new("pin-missing");
    let plugin = plugin_zip_bytes("12.1.9", "8.0.0");
    let spec = Spec {
        plugin: vec![SpecRelease {
            tag: "v8.0.0".into(),
            assets: vec![("GhidraMCP-8.0.0.zip".into(), sha256_bytes(&plugin))],
        }],
        ghidra: vec![SpecRelease {
            tag: "Ghidra_12.1.8_build".into(),
            assets: vec![(
                "ghidra_12.1.8_PUBLIC.zip".into(),
                sha256_bytes(&ghidra_zip_bytes("12.1.8")),
            )],
        }],
        assets: HashMap::from([
            ("GhidraMCP-8.0.0.zip".to_string(), plugin),
            (
                "ghidra_12.1.8_PUBLIC.zip".to_string(),
                ghidra_zip_bytes("12.1.8"),
            ),
        ]),
        ..Spec::empty()
    };
    let url = serve(spec).await;
    let api = ReleasesApi::new(&url).expect("fake API URL is valid");
    let java = fake_java(&sb.root, 21);

    let mut req = request(&sb, &api, &java);
    req.pin_version = Some("12.1.9");
    let err = bootstrap(&req).await.unwrap_err();
    assert!(
        matches!(&err, GhidraError::BootstrapBlocked { reason } if reason.contains("12.1.9")),
        "expected a pin-naming block, got {err:?}"
    );
    assert!(!sb.managed_prefix.exists(), "nothing was installed");
}

/// A local plugin zip built for a different build than the pin names is a
/// pair that cannot work — refused rather than force-installed.
#[tokio::test]
async fn pin_rejects_a_local_plugin_zip_built_for_another_build() {
    let sb = Sandbox::new("pin-local");
    let dir = sb.root.join("downloads");
    std::fs::create_dir_all(&dir).expect("create fixture dirs");
    let plugin = dir.join("plugin.zip");
    std::fs::write(&plugin, plugin_zip_bytes("12.1.2", "6.0.0")).expect("write fixture");
    let spec = Spec {
        plugin: Vec::new(),
        ghidra: vec![SpecRelease {
            tag: "Ghidra_12.1.4_build".into(),
            assets: vec![(
                "ghidra_12.1.4_PUBLIC.zip".into(),
                sha256_bytes(&ghidra_zip_bytes("12.1.4")),
            )],
        }],
        assets: HashMap::from([(
            "ghidra_12.1.4_PUBLIC.zip".to_string(),
            ghidra_zip_bytes("12.1.4"),
        )]),
        ..Spec::empty()
    };
    let url = serve(spec).await;
    let api = ReleasesApi::new(&url).expect("fake API URL is valid");
    let java = fake_java(&sb.root, 21);

    let mut req = request(&sb, &api, &java);
    req.local_plugin_zip = Some(&plugin);
    req.pin_version = Some("12.1.4");
    let err = bootstrap(&req).await.unwrap_err();
    assert!(
        matches!(&err, GhidraError::BootstrapBlocked { reason }
            if reason.contains("12.1.2") && reason.contains("12.1.4")),
        "expected a pair-refusing block, got {err:?}"
    );
    assert!(!sb.managed_prefix.exists(), "nothing was installed");
}

/// A pin naming a different build than the discovered install is a
/// contradiction — refused, not quietly paired against the installed one.
#[tokio::test]
async fn pin_conflicts_with_the_discovered_install() {
    let sb = Sandbox::new("pin-found");
    sb.seed_managed_ghidra("12.1.2");
    let url = serve(Spec::empty()).await;
    let api = ReleasesApi::new(&url).expect("fake API URL is valid");
    let java = fake_java(&sb.root, 21);

    let mut req = request(&sb, &api, &java);
    req.pin_version = Some("12.1.4");
    let err = bootstrap(&req).await.unwrap_err();
    assert!(
        matches!(&err, GhidraError::BootstrapBlocked { reason }
            if reason.contains("12.1.2") && reason.contains("12.1.4")),
        "expected a pin-conflict block naming both versions, got {err:?}"
    );
}

/// An interrupted download resumes: a `.part` file holding the first half
/// rides on a `Range` request, and the merged file is digest-verified
/// before anything is unzipped.
#[tokio::test]
async fn interrupted_download_resumes_from_the_part_file() {
    let sb = Sandbox::new("resume");
    let plugin = plugin_zip_bytes("12.1.2", "6.0.0");
    let ghidra = ghidra_zip_bytes("12.1.2");
    std::fs::create_dir_all(&sb.cache).expect("create fixture dirs");
    let half = ghidra.len() / 2;
    std::fs::write(
        sb.cache.join("ghidra_12.1.2_PUBLIC.zip.part"),
        &ghidra[..half],
    )
    .expect("write the half-downloaded part file");

    let spec = Spec {
        plugin: vec![SpecRelease {
            tag: "v6.0.0".into(),
            assets: vec![("GhidraMCP-6.0.0.zip".into(), sha256_bytes(&plugin))],
        }],
        ghidra: vec![SpecRelease {
            tag: "Ghidra_12.1.2_build".into(),
            assets: vec![("ghidra_12.1.2_PUBLIC.zip".into(), sha256_bytes(&ghidra))],
        }],
        assets: HashMap::from([
            ("GhidraMCP-6.0.0.zip".to_string(), plugin),
            ("ghidra_12.1.2_PUBLIC.zip".to_string(), ghidra),
        ]),
        ..Spec::empty()
    };
    let log = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let url = serve_logged(spec, Some(std::sync::Arc::clone(&log))).await;
    let api = ReleasesApi::new(&url).expect("fake API URL is valid");
    let java = fake_java(&sb.root, 21);

    let report = bootstrap(&request(&sb, &api, &java))
        .await
        .expect("bootstrap succeeds over the resumed download");
    assert_eq!(
        report.ghidra.as_ref().expect("report names Ghidra").version,
        "12.1.2"
    );

    let requests = log.lock().expect("request log lock");
    let asset = requests
        .iter()
        .find(|request| request.contains("/assets/ghidra_12.1.2_PUBLIC.zip"))
        .expect("the Ghidra asset was requested");
    assert!(
        asset
            .to_lowercase()
            .contains(&format!("range: bytes={half}-")),
        "the request resumed from the part file, not from zero:\n{asset}"
    );
    // The merged download verified and landed under its final name.
    assert!(sb.cache.join("ghidra_12.1.2_PUBLIC.zip").is_file());
    assert!(!sb.cache.join("ghidra_12.1.2_PUBLIC.zip.part").exists());
}

/// A stale or corrupt `.part` file merges into a digest mismatch — the
/// verification after resuming is real, and the bad file is deleted rather
/// than unzipped.
#[tokio::test]
async fn resumed_download_with_a_corrupt_part_file_fails_verification() {
    let sb = Sandbox::new("resume-corrupt");
    let plugin = plugin_zip_bytes("12.1.2", "6.0.0");
    let ghidra = ghidra_zip_bytes("12.1.2");
    std::fs::create_dir_all(&sb.cache).expect("create fixture dirs");
    let half = ghidra.len() / 2;
    let mut corrupt = ghidra[..half].to_vec();
    corrupt[..8].copy_from_slice(b"NOTTHEPA");
    std::fs::write(sb.cache.join("ghidra_12.1.2_PUBLIC.zip.part"), &corrupt)
        .expect("write the corrupt part file");

    let spec = Spec {
        plugin: vec![SpecRelease {
            tag: "v6.0.0".into(),
            assets: vec![("GhidraMCP-6.0.0.zip".into(), sha256_bytes(&plugin))],
        }],
        ghidra: vec![SpecRelease {
            tag: "Ghidra_12.1.2_build".into(),
            assets: vec![("ghidra_12.1.2_PUBLIC.zip".into(), sha256_bytes(&ghidra))],
        }],
        assets: HashMap::from([
            ("GhidraMCP-6.0.0.zip".to_string(), plugin),
            ("ghidra_12.1.2_PUBLIC.zip".to_string(), ghidra),
        ]),
        ..Spec::empty()
    };
    let url = serve(spec).await;
    let api = ReleasesApi::new(&url).expect("fake API URL is valid");
    let java = fake_java(&sb.root, 21);

    let err = bootstrap(&request(&sb, &api, &java)).await.unwrap_err();
    assert!(
        matches!(err, GhidraError::DigestMismatch { .. }),
        "the resumed merge must fail the digest check, got {err:?}"
    );
    assert!(!sb.cache.join("ghidra_12.1.2_PUBLIC.zip.part").exists());
    assert!(!sb.managed_prefix.exists(), "nothing was unzipped");
}

/// The optional GitHub token rides on every API request — the rate-limit
/// escape hatch works without the user reading a doc.
#[tokio::test]
async fn token_rides_every_api_request() {
    let sb = Sandbox::new("token");
    let plugin = plugin_zip_bytes("12.1.2", "6.0.0");
    let ghidra = ghidra_zip_bytes("12.1.2");
    let spec = Spec {
        plugin: vec![SpecRelease {
            tag: "v6.0.0".into(),
            assets: vec![("GhidraMCP-6.0.0.zip".into(), sha256_bytes(&plugin))],
        }],
        ghidra: vec![SpecRelease {
            tag: "Ghidra_12.1.2_build".into(),
            assets: vec![("ghidra_12.1.2_PUBLIC.zip".into(), sha256_bytes(&ghidra))],
        }],
        assets: HashMap::from([
            ("GhidraMCP-6.0.0.zip".to_string(), plugin),
            ("ghidra_12.1.2_PUBLIC.zip".to_string(), ghidra),
        ]),
        ..Spec::empty()
    };
    let log = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let url = serve_logged(spec, Some(std::sync::Arc::clone(&log))).await;
    let api = ReleasesApi::new(&url)
        .expect("fake API URL is valid")
        .with_token("sekret-token");
    let java = fake_java(&sb.root, 21);

    bootstrap(&request(&sb, &api, &java))
        .await
        .expect("bootstrap succeeds");

    let requests = log.lock().expect("request log lock");
    let api_calls: Vec<&String> = requests
        .iter()
        .filter(|request| !request.contains("/assets/"))
        .collect();
    assert!(!api_calls.is_empty(), "the bootstrap made API calls");
    assert!(
        api_calls.iter().all(|request| request
            .to_lowercase()
            .contains("authorization: bearer sekret-token")),
        "every API request carried the token"
    );
}

/// A rate-limited API fails with the token knob named — not a bare 403 the
/// user has to decode.
#[tokio::test]
async fn rate_limited_api_fails_with_the_token_hint() {
    let sb = Sandbox::new("ratelimit");
    let spec = Spec {
        rate_limited: true,
        ..Spec::empty()
    };
    let url = serve(spec).await;
    let api = ReleasesApi::new(&url).expect("fake API URL is valid");
    let java = fake_java(&sb.root, 21);

    let err = bootstrap(&request(&sb, &api, &java)).await.unwrap_err();
    assert!(
        matches!(err, GhidraError::RateLimited { .. }),
        "expected RateLimited, got {err:?}"
    );
    let message = err.to_string();
    assert!(message.contains("rate limit"), "{message}");
    assert!(message.contains("GHIDRA_MCP_GITHUB_TOKEN"), "{message}");
}

/// A pre-downloaded zip skips the API entirely for that artifact.
#[tokio::test]
async fn local_zip_skips_download() {
    let sb = Sandbox::new("localzip");
    let dir = sb.root.join("downloads");
    std::fs::create_dir_all(&dir).expect("create fixture dirs");
    let plugin = dir.join("my-plugin.zip");
    let ghidra = dir.join("my-ghidra.zip");
    std::fs::write(&plugin, plugin_zip_bytes("12.1.2", "6.0.0")).expect("write fixture");
    std::fs::write(&ghidra, ghidra_zip_bytes("12.1.2")).expect("write fixture");

    // An empty spec: any API call would 404 and fail the bootstrap.
    let url = serve(Spec::empty()).await;
    let api = ReleasesApi::new(&url).expect("fake API URL is valid");
    let java = fake_java(&sb.root, 21);
    let mut req = request(&sb, &api, &java);
    req.local_ghidra_zip = Some(&ghidra);
    req.local_plugin_zip = Some(&plugin);
    let report = bootstrap(&req).await.expect("bootstrap succeeds");
    assert_eq!(
        report.ghidra.as_ref().expect("report names Ghidra").version,
        "12.1.2"
    );
    assert_eq!(
        report
            .plugin
            .as_ref()
            .expect("report names the plugin")
            .version
            .as_deref(),
        Some("6.0.0")
    );
    // The exec-bit fixup applies to local zips exactly as it does to
    // downloads: the fixture zip carries no exec bits, `ghidraRun` has them.
    let run = sb.managed_prefix.join("ghidra_12.1.2_PUBLIC/ghidraRun");
    let mode = std::fs::metadata(&run)
        .expect("ghidraRun landed")
        .permissions()
        .mode();
    assert!(mode & 0o111 != 0, "the exec bit was restored: {mode:o}");
}

/// A cached download with a matching digest is reused without refetching: the
/// fake server serves junk for the asset URL, so success proves the cache won.
#[tokio::test]
async fn cache_reuse_avoids_refetch() {
    let sb = Sandbox::new("cache");
    let cache = &sb.cache;
    std::fs::create_dir_all(cache).expect("create fixture dirs");
    let plugin = plugin_zip_bytes("12.1.2", "6.0.0");
    let ghidra = ghidra_zip_bytes("12.1.2");
    std::fs::write(cache.join("GhidraMCP-6.0.0.zip"), &plugin).expect("write fixture");
    std::fs::write(cache.join("ghidra_12.1.2_PUBLIC.zip"), &ghidra).expect("write fixture");

    let spec = Spec {
        plugin: vec![SpecRelease {
            tag: "v6.0.0".into(),
            assets: vec![("GhidraMCP-6.0.0.zip".into(), sha256_bytes(&plugin))],
        }],
        ghidra: vec![SpecRelease {
            tag: "Ghidra_12.1.2_build".into(),
            assets: vec![("ghidra_12.1.2_PUBLIC.zip".into(), sha256_bytes(&ghidra))],
        }],
        // Junk under the same names: a refetch would fail the digest check.
        assets: HashMap::from([
            ("GhidraMCP-6.0.0.zip".to_string(), b"junk".to_vec()),
            ("ghidra_12.1.2_PUBLIC.zip".to_string(), b"junk".to_vec()),
        ]),
        ..Spec::empty()
    };
    let url = serve(spec).await;
    let api = ReleasesApi::new(&url).expect("fake API URL is valid");
    let java = fake_java(&sb.root, 21);

    let report = bootstrap(&request(&sb, &api, &java))
        .await
        .expect("bootstrap succeeds");
    assert_eq!(
        report.ghidra.as_ref().expect("report names Ghidra").version,
        "12.1.2"
    );
}

/// The exact Ghidra tag missing: the nearest ≥ fallback installs the build it
/// actually fetched — prefix, manifest, and the plugin's Extensions dir all
/// name the fetched version, never the merely-requested one.
#[tokio::test]
async fn nearest_release_fallback_installs_the_build_it_fetched() {
    let sb = Sandbox::new("fallback");
    let plugin = plugin_zip_bytes("12.1.2", "6.0.0");
    let ghidra = ghidra_zip_bytes("12.1.3");
    let spec = Spec {
        plugin: vec![SpecRelease {
            tag: "v6.0.0".into(),
            assets: vec![("GhidraMCP-6.0.0.zip".into(), sha256_bytes(&plugin))],
        }],
        ghidra: vec![SpecRelease {
            tag: "Ghidra_12.1.3_build".into(),
            assets: vec![("ghidra_12.1.3_PUBLIC.zip".into(), sha256_bytes(&ghidra))],
        }],
        assets: HashMap::from([
            ("GhidraMCP-6.0.0.zip".to_string(), plugin),
            ("ghidra_12.1.3_PUBLIC.zip".to_string(), ghidra),
        ]),
        ..Spec::empty()
    };
    let url = serve(spec).await;
    let api = ReleasesApi::new(&url).expect("fake API URL is valid");
    let java = fake_java(&sb.root, 21);

    let report = bootstrap(&request(&sb, &api, &java))
        .await
        .expect("bootstrap succeeds");
    assert_eq!(
        report.ghidra.as_ref().expect("report names Ghidra").version,
        "12.1.3"
    );
    assert_eq!(
        report
            .plugin
            .as_ref()
            .expect("report names the plugin")
            .built_for,
        "12.1.3"
    );

    let ghidra_dir = sb.managed_prefix.join("ghidra_12.1.3_PUBLIC");
    assert!(ghidra_dir.join("Ghidra/Framework").is_dir());
    assert!(!sb.managed_prefix.join("ghidra_12.1.2_PUBLIC").exists());
    assert!(
        sb.config_root
            .join("ghidra_12.1.3_PUBLIC/Extensions/GhidraMCP/extension.properties")
            .exists()
    );

    let manifest = sb.manifest();
    assert_eq!(
        manifest
            .ghidra
            .as_ref()
            .expect("manifest names Ghidra")
            .version,
        "12.1.3"
    );
    assert_eq!(
        manifest
            .plugin
            .as_ref()
            .expect("manifest names the plugin")
            .built_for,
        "12.1.3"
    );
}

/// A second `--fix` over a completed install changes nothing: the pairing
/// check passes, the upgrade probe finds nothing newer, and the manifest
/// keeps its records.
#[tokio::test]
async fn second_fix_changes_nothing() {
    let sb = Sandbox::new("idempotent");
    let plugin = plugin_zip_bytes("12.1.2", "6.0.0");
    let ghidra = ghidra_zip_bytes("12.1.2");
    let spec = Spec {
        plugin: vec![SpecRelease {
            tag: "v6.0.0".into(),
            assets: vec![("GhidraMCP-6.0.0.zip".into(), sha256_bytes(&plugin))],
        }],
        ghidra: vec![SpecRelease {
            tag: "Ghidra_12.1.2_build".into(),
            assets: vec![("ghidra_12.1.2_PUBLIC.zip".into(), sha256_bytes(&ghidra))],
        }],
        assets: HashMap::from([
            ("GhidraMCP-6.0.0.zip".to_string(), plugin),
            ("ghidra_12.1.2_PUBLIC.zip".to_string(), ghidra),
        ]),
        ..Spec::empty()
    };
    let url = serve(spec).await;
    let api = ReleasesApi::new(&url).expect("fake API URL is valid");
    let java = fake_java(&sb.root, 21);

    bootstrap(&request(&sb, &api, &java))
        .await
        .expect("bootstrap succeeds");
    let report = bootstrap(&request(&sb, &api, &java))
        .await
        .expect("bootstrap succeeds");
    assert!(
        report
            .notes
            .iter()
            .any(|note| note.contains("nothing to install")),
        "second run should say it changed nothing: {:?}",
        report.notes
    );
    assert_eq!(
        sb.manifest()
            .ghidra
            .as_ref()
            .expect("manifest names Ghidra")
            .version,
        "12.1.2"
    );
}
