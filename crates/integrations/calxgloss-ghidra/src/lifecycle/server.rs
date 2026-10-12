//! Starting and supervising a headless GhidraMCP server.
//!
//! The launch recipe is the bridge's own — `docker/entrypoint.sh` in
//! bethington/ghidra-mcp v6.0.0, verified against the live stack on
//! 2026-10-03 (`docs/ghidra_integration.md` §1): a plain `java` invocation
//! with `-Dghidra.home` pointing at the install, the extension jar plus every
//! Ghidra Framework/Features/Processors jar on the classpath, and the
//! `com.xebyte.headless.GhidraMCPHeadlessServer` main class taking
//! `--port`/`--bind`/`--project`.
//!
//! The recipe is built as a pure [`LaunchPlan`] value before anything is
//! spawned, so the argv, the classpath globs, and the server args are unit-
//! testable without a JVM. The spawn itself runs the child with
//! `kill_on_drop`, sends its stdout/stderr to a log file beside the project,
//! and writes a pid file so a crashed run leaves something the next run can
//! clean up (pid-file *reuse* is G1-T7's job). Every spawned server carries
//! `GHIDRA_MCP_REQUIRE_PROGRAM_SELECTORS=1` — the other half of the
//! 2026-10-08 incident fix: with selectors required the bridge refuses any
//! program-scoped call that omits its target, so an endpoint can never
//! silently answer from the wrong program.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use tracing::{info, warn};

use super::extension::GhidraExtension;
use super::install::GhidraInstall;
use crate::client::{GhidraClient, GhidraError, Result};
use crate::model::ServerInfo;

/// The headless server's main class, per the bridge's javadoc and the
/// docker entrypoint.
const MAIN_CLASS: &str = "com.xebyte.headless.GhidraMCPHeadlessServer";

/// The env var that turns on strict program routing (README "Strict program
/// routing"): every program-scoped call must name its target.
const REQUIRE_SELECTORS_ENV: &str = "GHIDRA_MCP_REQUIRE_PROGRAM_SELECTORS";

/// The Ghidra jar categories the entrypoint puts on the classpath, in its
/// order: Framework, then Features, then Processors.
const JAR_CATEGORIES: [&str; 3] = ["Framework", "Features", "Processors"];

/// A fully-resolved headless launch, as data: everything the JVM invocation
/// needs, decided before a process exists so the recipe is testable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchPlan {
    /// The Ghidra install the server runs from — `-Dghidra.home`.
    pub install: GhidraInstall,
    /// The extension jar first on the classpath — what makes the server
    /// GhidraMCP rather than bare Ghidra.
    pub extension_jar: PathBuf,
    /// The full classpath in order: extension jar, then the Ghidra jars the
    /// entrypoint globs (Framework, Features, Processors).
    pub classpath: Vec<PathBuf>,
    /// The TCP port to serve on — the configured port, checked free first.
    pub port: u16,
    /// The address to bind. Loopback by default: the bridge's security
    /// posture is localhost-only, and calxgloss never exposes Ghidra.
    pub bind: String,
    /// The project to reopen, when one already exists on disk — the entrypoint
    /// only passes `--project` for a project that is there.
    pub project: Option<PathBuf>,
}

impl LaunchPlan {
    /// Build the launch for `install` + `extension` on `port`.
    ///
    /// `project` is the intended `.gpr` path; `--project` is only included
    /// when that file already exists, mirroring the entrypoint's guard —
    /// a first run has no project yet, and G1-T6 creates it through the
    /// server's own `create_project` endpoint instead.
    ///
    /// Returns `None` when the extension names no jar to load: an extension
    /// directory without a `GhidraMCP-*.jar` cannot start a server.
    pub fn build(
        install: &GhidraInstall,
        extension: &GhidraExtension,
        port: u16,
        bind: &str,
        project: Option<&Path>,
    ) -> Option<Self> {
        let extension_jar = extension_jar(&extension.dir)?;
        let classpath = std::iter::once(extension_jar.clone())
            .chain(ghidra_jars(&install.path))
            .collect();
        let project = project.filter(|path| path.is_file()).map(PathBuf::from);
        Some(Self {
            install: install.clone(),
            extension_jar,
            classpath,
            port,
            bind: bind.to_string(),
            project,
        })
    }

    /// The full argv after the `java` executable itself, exactly as the
    /// entrypoint assembles it.
    pub fn java_args(&self) -> Vec<String> {
        let mut args = vec![
            format!("-Dghidra.home={}", install_path(&self.install)),
            "-Dapplication.name=GhidraMCP".to_string(),
            "-classpath".to_string(),
            self.classpath
                .iter()
                .map(|jar| jar.to_string_lossy().into_owned())
                .collect::<Vec<_>>()
                .join(":"),
            MAIN_CLASS.to_string(),
            "--port".to_string(),
            self.port.to_string(),
            "--bind".to_string(),
            self.bind.clone(),
        ];
        if let Some(project) = &self.project {
            args.push("--project".to_string());
            args.push(project.to_string_lossy().into_owned());
        }
        args
    }
}

/// The install path as the JVM sees it — the entrypoint passes it verbatim.
fn install_path(install: &GhidraInstall) -> String {
    install.path.to_string_lossy().into_owned()
}

/// The extension's jar: `lib/GhidraMCP-<version>.jar` inside the extension
/// directory — the same jar [`plugin_version`](super::extension) reads the
/// plugin version from.
fn extension_jar(dir: &Path) -> Option<PathBuf> {
    let entries = std::fs::read_dir(dir.join("lib")).ok()?;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_str()?;
        if name.starts_with("GhidraMCP-") && name.ends_with(".jar") {
            return Some(entry.path());
        }
    }
    None
}

/// Every Ghidra jar the entrypoint globs, in its order: each category's
/// `*/lib/*.jar`, sorted within a category so the plan is deterministic.
fn ghidra_jars(install: &Path) -> Vec<PathBuf> {
    let mut jars = Vec::new();
    for category in JAR_CATEGORIES {
        let category_dir = install.join("Ghidra").join(category);
        let Ok(modules) = std::fs::read_dir(&category_dir) else {
            continue;
        };
        let mut module_jars = Vec::new();
        for module in modules.flatten() {
            let Ok(lib) = std::fs::read_dir(module.path().join("lib")) else {
                continue;
            };
            for jar in lib.flatten() {
                let name = jar.file_name();
                if name.to_str().is_some_and(|n| n.ends_with(".jar")) {
                    module_jars.push(jar.path());
                }
            }
        }
        module_jars.sort();
        jars.extend(module_jars);
    }
    jars
}

/// Whether `port` on `bind` is free to take: a bind test, not a probe —
/// calxgloss never binds a busy port (design risk 4), and a port that
/// answers HTTP but not as GhidraMCP has already failed earlier, at the
/// identity probe.
pub(crate) fn port_free(bind: &str, port: u16) -> bool {
    std::net::TcpListener::bind((bind, port)).is_ok()
}

/// A headless server process calxgloss started and therefore owns: killing
/// it, and closing its project first, is calxgloss's job — and only ever
/// calxgloss's job for a server it started (design risk 5).
#[derive(Debug)]
pub(crate) struct OwnedServer {
    /// The JVM child, armed with `kill_on_drop` so even a panic between
    /// spawn and shutdown cannot leak a Ghidra instance.
    child: tokio::process::Child,
    /// The child's PID, as written to the pid file.
    pub(crate) pid: u32,
    /// The pid file, removed when the server shuts down or is dropped.
    pid_file: PathBuf,
    /// Where the child's stdout/stderr went — every spawn failure names it.
    pub(crate) log: PathBuf,
}

impl OwnedServer {
    /// Close the project (best effort — a server that will not answer HTTP
    /// dies anyway), then kill the child and take the pid file away.
    pub(crate) async fn shutdown(mut self, client: &GhidraClient) {
        if let Err(err) = client.close_project().await {
            warn!(error = %err, "Owned Ghidra server would not close its project; killing it anyway");
        }
        if let Err(err) = self.child.start_kill() {
            warn!(error = %err, pid = self.pid, "Killing the owned Ghidra server failed");
        }
        if let Err(err) = self.child.wait().await {
            warn!(error = %err, pid = self.pid, "Waiting for the owned Ghidra server to die failed");
        }
        info!(
            pid = self.pid,
            "Stopped the Ghidra headless server calxgloss owned"
        );
        remove_pid_file(&self.pid_file);
    }
}

impl Drop for OwnedServer {
    fn drop(&mut self) {
        // `kill_on_drop` handles the process itself; the pid file is the
        // part a plain drop would otherwise leave behind for the next run
        // to mistake for a live server.
        remove_pid_file(&self.pid_file);
    }
}

fn remove_pid_file(path: &Path) {
    if let Err(err) = std::fs::remove_file(path)
        && err.kind() != std::io::ErrorKind::NotFound
    {
        warn!(path = %path.display(), error = %err, "Could not remove the Ghidra server pid file");
    }
}

/// Spawn the planned server: the child's stdout/stderr go to `log` beside
/// the project, its PID to `pid_file`, and its environment carries the
/// program-selector requirement.
///
/// The caller owns the returned [`OwnedServer`]; dropping it kills the
/// child (`kill_on_drop`), and [`shutdown`](Self::shutdown) closes the
/// project first.
pub(crate) fn spawn_server(plan: &LaunchPlan, log: &Path, pid_file: &Path) -> Result<OwnedServer> {
    if let Some(parent) = log.parent() {
        std::fs::create_dir_all(parent).map_err(|err| GhidraError::SpawnFailed {
            detail: format!(
                "could not create the log directory {}: {err}",
                parent.display()
            ),
            log: log.to_string_lossy().into_owned(),
        })?;
    }
    let log_file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log)
        .map_err(|err| GhidraError::SpawnFailed {
            detail: format!("could not open the log file {}: {err}", log.display()),
            log: log.to_string_lossy().into_owned(),
        })?;

    let mut command = tokio::process::Command::new("java");
    command
        .args(plan.java_args())
        .env(REQUIRE_SELECTORS_ENV, "1")
        .stdout(std::process::Stdio::from(log_file.try_clone().map_err(
            |err| GhidraError::SpawnFailed {
                detail: format!("could not duplicate the log handle: {err}"),
                log: log.to_string_lossy().into_owned(),
            },
        )?))
        .stderr(std::process::Stdio::from(log_file))
        .kill_on_drop(true);
    let child = command.spawn().map_err(|err| GhidraError::SpawnFailed {
        detail: format!("could not start java: {err}"),
        log: log.to_string_lossy().into_owned(),
    })?;
    // A freshly spawned child always reports a pid; a child that cannot be
    // identified cannot be supervised (pid file, kill logging), so that is a
    // spawn failure — and `kill_on_drop` takes the child with it.
    let pid = child.id().ok_or_else(|| GhidraError::SpawnFailed {
        detail: "java started but reported no pid to supervise".to_string(),
        log: log.to_string_lossy().into_owned(),
    })?;

    // The pid file goes up before the boot poll: a run that dies mid-boot
    // leaves the file, and the next run's cleanup (G1-T7) has something
    // to find.
    std::fs::write(pid_file, format!("{pid}\n")).map_err(|err| GhidraError::SpawnFailed {
        detail: format!(
            "started java (pid {pid}) but could not write the pid file {}: {err}",
            pid_file.display()
        ),
        log: log.to_string_lossy().into_owned(),
    })?;

    info!(pid, port = plan.port, log = %log.display(), "Started a Ghidra headless server calxgloss owns");
    Ok(OwnedServer {
        child,
        pid,
        pid_file: pid_file.to_path_buf(),
        log: log.to_string_lossy().into_owned().into(),
    })
}

/// Poll the identity probe until the spawned server answers or `timeout`
/// runs out, watching for a child that died mid-boot so the failure names
/// the log instead of waiting out the full JVM budget.
pub(crate) async fn wait_for_boot(
    server: &mut OwnedServer,
    client: &GhidraClient,
    timeout: Duration,
) -> Result<ServerInfo> {
    let deadline = Instant::now() + timeout;
    let mut delay = Duration::from_millis(250);
    loop {
        match client.check_connection().await {
            Ok(info) => return Ok(info),
            Err(GhidraError::ServerUnreachable { .. }) => {}
            // The port answered something that is not GhidraMCP, or an old
            // plugin answered: that is a real finding, not a boot delay.
            Err(other) => return Err(other),
        }
        if let Some(status) = server
            .child
            .try_wait()
            .map_err(|err| GhidraError::SpawnFailed {
                detail: format!("could not watch the spawned server: {err}"),
                log: server.log.display().to_string(),
            })?
        {
            return Err(GhidraError::SpawnFailed {
                detail: format!("java (pid {}) exited with {status}", server.pid),
                log: server.log.display().to_string(),
            });
        }
        if Instant::now() >= deadline {
            return Err(GhidraError::BootTimeout {
                url: client.base_url().to_string(),
                secs: timeout.as_secs(),
                log: server.log.display().to_string(),
            });
        }
        tokio::time::sleep(delay).await;
        delay = (delay * 2).min(Duration::from_secs(2));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fake install with one jar per category's `*/lib/`, matching the
    /// globs the entrypoint uses.
    fn fixture_install(home: &Path) -> GhidraInstall {
        let install = home.join("ghidra_12.1.2_PUBLIC");
        for (module, jar) in [
            ("Ghidra/Framework/util", "util.jar"),
            ("Ghidra/Framework/misc", "misc.jar"),
            ("Ghidra/Features/Decompiler", "decompiler.jar"),
            ("Ghidra/Processors/x86", "x86.jar"),
        ] {
            let dir = install.join(module).join("lib");
            std::fs::create_dir_all(&dir).expect("create fixture dir");
            std::fs::write(dir.join(jar), b"not a real jar").expect("write fixture jar");
        }
        GhidraInstall {
            path: install,
            version: "12.1.2".to_string(),
        }
    }

    /// A fake extension directory with the versioned jar inside `lib/`.
    fn fixture_extension(home: &Path) -> GhidraExtension {
        let dir = home.join("Extensions").join("GhidraMCP");
        std::fs::create_dir_all(dir.join("lib")).expect("create extension dirs");
        std::fs::write(
            dir.join("lib").join("GhidraMCP-6.0.0.jar"),
            b"not a real jar",
        )
        .expect("write extension jar");
        GhidraExtension {
            dir,
            built_for: "12.1.2".to_string(),
            plugin_version: Some("6.0.0".to_string()),
        }
    }

    fn plan(home: &Path, project: Option<&Path>) -> LaunchPlan {
        LaunchPlan::build(
            &fixture_install(home),
            &fixture_extension(home),
            8089,
            "127.0.0.1",
            project,
        )
        .expect("the fixture extension names a jar")
    }

    #[test]
    fn the_launch_plan_is_the_entrypoints_recipe() {
        let home = tempfile::tempdir().expect("tempdir");
        let plan = plan(home.path(), None);
        let args = plan.java_args();

        // The JVM system properties the entrypoint sets, in its order.
        assert_eq!(
            args[0],
            format!(
                "-Dghidra.home={}",
                home.path().join("ghidra_12.1.2_PUBLIC").display()
            )
        );
        assert_eq!(args[1], "-Dapplication.name=GhidraMCP");
        assert_eq!(args[2], "-classpath");

        // The classpath: extension jar first, then the Ghidra jars the
        // entrypoint globs — Framework, Features, Processors, each `*/lib/*.jar`.
        let classpath: Vec<&str> = args[3].split(':').collect();
        assert_eq!(
            classpath[0],
            home.path()
                .join("Extensions/GhidraMCP/lib/GhidraMCP-6.0.0.jar")
                .to_string_lossy(),
            "the extension jar leads the classpath"
        );
        let ghidra: Vec<String> = classpath[1..]
            .iter()
            .map(|jar| {
                jar.rsplit_once("/Ghidra/")
                    .map(|(_, rest)| rest.to_string())
                    .unwrap_or_else(|| jar.to_string())
            })
            .collect();
        assert_eq!(
            ghidra,
            [
                "Framework/misc/lib/misc.jar",
                "Framework/util/lib/util.jar",
                "Features/Decompiler/lib/decompiler.jar",
                "Processors/x86/lib/x86.jar",
            ],
            "Framework before Features before Processors, sorted within each"
        );

        // The main class and its server args.
        assert_eq!(args[4], MAIN_CLASS);
        assert_eq!(&args[5..], ["--port", "8089", "--bind", "127.0.0.1"]);
    }

    #[test]
    fn the_plan_passes_project_only_when_it_exists() {
        let home = tempfile::tempdir().expect("tempdir");
        let gpr = home.path().join("ghidra").join("EverQuest.gpr");

        // A first run: the .gpr is not on disk yet, so no `--project` —
        // the server starts projectless and G1-T6 creates it over HTTP.
        let first = plan(home.path(), Some(&gpr));
        assert_eq!(first.project, None);
        assert!(
            !first.java_args().contains(&"--project".to_string()),
            "a project that does not exist is not passed to the server"
        );

        // A later run: the .gpr exists, and the server reopens it.
        std::fs::create_dir_all(gpr.parent().expect("parent")).expect("create dir");
        std::fs::write(&gpr, b"").expect("write gpr");
        let later = plan(home.path(), Some(&gpr));
        assert_eq!(later.project.as_deref(), Some(gpr.as_path()));
        let args = later.java_args();
        let at = args
            .iter()
            .position(|arg| arg == "--project")
            .expect("--project is passed");
        assert_eq!(args[at + 1], gpr.to_string_lossy());
    }

    #[test]
    fn an_extension_without_a_jar_cannot_be_launched() {
        let home = tempfile::tempdir().expect("tempdir");
        let install = fixture_install(home.path());
        let dir = home.path().join("Extensions").join("GhidraMCP");
        std::fs::create_dir_all(&dir).expect("create extension dir");
        let extension = GhidraExtension {
            dir,
            built_for: "12.1.2".to_string(),
            plugin_version: Some("6.0.0".to_string()),
        };
        assert!(
            LaunchPlan::build(&install, &extension, 8089, "127.0.0.1", None).is_none(),
            "no jar, no server"
        );
    }

    #[test]
    fn a_held_port_is_not_free() {
        let held = std::net::TcpListener::bind("127.0.0.1:0").expect("bind a port");
        let port = held.local_addr().expect("address").port();
        assert!(!port_free("127.0.0.1", port), "a bound port is busy");
        drop(held);
        assert!(port_free("127.0.0.1", port), "a released port is free");
    }
}
