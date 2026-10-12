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
//! and writes a pid file (pid plus port) so a crashed run leaves something
//! the next run finds and reaps ([`reap_stale_pid_file`], G1-T7). Every
//! spawned server carries `GHIDRA_MCP_REQUIRE_PROGRAM_SELECTORS=1` — the
//! other half of the 2026-10-08 incident fix: with selectors required the
//! bridge refuses any program-scoped call that omits its target, so an
//! endpoint can never silently answer from the wrong program.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use tracing::{info, warn};

use super::extension::GhidraExtension;
use super::install::GhidraInstall;
use crate::client::{GhidraClient, GhidraConfig, GhidraError, Result};
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

/// The port a spawn takes: the configured one when it is free, else the
/// bridge default — never a busy port (design risk 4). `None` when both
/// are held, which the session reports as [`GhidraError::PortBusy`]
/// instead of attempting a bind.
pub(crate) fn spawn_port(bind: &str, configured: u16, fallback: u16) -> Option<u16> {
    if port_free(bind, configured) {
        return Some(configured);
    }
    if fallback != configured && port_free(bind, fallback) {
        return Some(fallback);
    }
    None
}

/// Any free port on `bind` — how `headless = always` finds somewhere to
/// spawn when the configured port and the fallback are both held (a GUI on
/// the configured port is exactly the case that preference exists for).
pub(crate) fn free_port(bind: &str) -> Option<u16> {
    let probe = std::net::TcpListener::bind((bind, 0)).ok()?;
    let port = probe.local_addr().ok()?.port();
    drop(probe);
    Some(port)
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

/// What a pid file beside the project records: the spawned pid, and — since
/// G1-T7 — the port that server took, so the next run can prove the process
/// behind the pid is its own orphan before touching it.
#[derive(Debug, PartialEq, Eq)]
struct PidRecord {
    pid: u32,
    port: Option<u16>,
}

/// Read a pid file tolerantly: `pid` alone (the G1-T4 spelling) or `pid port`
/// (the G1-T7 spelling). A body that names no pid is no record at all.
fn read_pid_file(path: &Path) -> Option<PidRecord> {
    let body = std::fs::read_to_string(path).ok()?;
    let mut fields = body.split_whitespace();
    let pid = fields.next()?.parse().ok()?;
    let port = fields.next().and_then(|field| field.parse().ok());
    Some(PidRecord { pid, port })
}

/// Handle the pid file a previous run left beside the project (G1-T7),
/// before a fresh spawn:
///
/// * no file, or a pid with nothing behind it — stale, removed;
/// * a live pid whose recorded port answers the identity probe as
///   GhidraMCP — the orphan of a crashed run (calxgloss died before its
///   own shutdown could kill the child): killed, and the file removed, so
///   the fresh spawn cannot collide with it;
/// * a live pid that is *not* our server — the OS reused the pid, or the
///   recorded port belongs to someone else — only the file is removed,
///   never a process calxgloss did not start (design risk 5).
pub(crate) async fn reap_stale_pid_file(pid_file: &Path) {
    let Some(record) = read_pid_file(pid_file) else {
        // A file that names no pid is garbage — a truncated write, a hand
        // edit — and leaving it would only confuse the next run.
        if pid_file.exists() {
            remove_pid_file(pid_file);
        }
        return;
    };
    if !super::discovery::pid_alive(record.pid) {
        info!(
            path = %pid_file.display(),
            pid = record.pid,
            "Removed the pid file of a dead Ghidra headless server"
        );
        remove_pid_file(pid_file);
        return;
    }
    // Alive: ours, or the OS handed the pid to someone else. The recorded
    // port answering as GhidraMCP is the ownership proof — this pid file's
    // writer was the only thing that ever bound that port as its own.
    let ours = match record.port {
        Some(port) => answers_as_ghidramcp(port).await,
        None => false,
    };
    match (ours, record.port) {
        (true, Some(port)) => {
            info!(
                pid = record.pid,
                port, "Killing the orphaned Ghidra headless server a crashed run left behind"
            );
            // SAFETY: `kill(2)` with SIGKILL on a pid verified above to be
            // the headless server this pid file records.
            if unsafe { libc::kill(record.pid as i32, libc::SIGKILL) } != 0 {
                warn!(
                    pid = record.pid,
                    "Killing the orphaned Ghidra headless server failed"
                );
            }
        }
        _ => {
            warn!(
                path = %pid_file.display(),
                pid = record.pid,
                "The Ghidra pid file names a live process that is not our server; removing the file only"
            );
        }
    }
    remove_pid_file(pid_file);
}

/// Whether `port` answers the identity probe as a GhidraMCP server — the
/// ownership check for a live pid-file entry. An under-versioned plugin
/// still counts: it identifies the shape of our bridge, and the crashed
/// run's server is exactly the orphan most likely to collide. A short
/// timeout: an orphan answers instantly, and anything slower than that is
/// not worth waiting for before a spawn decision.
async fn answers_as_ghidramcp(port: u16) -> bool {
    let url = format!("http://127.0.0.1:{port}");
    let config = match GhidraConfig::new(&url) {
        Ok(config) => config.with_timeout(std::time::Duration::from_secs(2)),
        Err(_) => return false,
    };
    match GhidraClient::from_config(config) {
        Ok(client) => matches!(
            client.check_connection().await,
            Ok(_) | Err(GhidraError::VersionMismatch { .. })
        ),
        Err(_) => false,
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
    // to find. The port rides along so the next run can verify the process
    // behind the pid is actually this server before touching it.
    std::fs::write(pid_file, format!("{pid} {}\n", plan.port)).map_err(|err| {
        GhidraError::SpawnFailed {
            detail: format!(
                "started java (pid {pid}) but could not write the pid file {}: {err}",
                pid_file.display()
            ),
            log: log.to_string_lossy().into_owned(),
        }
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
    use super::super::discovery::BRIDGE_DEFAULT_PORT;
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

    #[test]
    fn the_spawn_takes_the_configured_port_when_it_is_free() {
        let free = std::net::TcpListener::bind("127.0.0.1:0").expect("bind a port");
        let configured = free.local_addr().expect("address").port();
        drop(free);
        assert_eq!(
            spawn_port("127.0.0.1", configured, BRIDGE_DEFAULT_PORT),
            Some(configured),
            "the configured port wins while it is free"
        );
    }

    #[test]
    fn a_busy_configured_port_falls_back_to_the_bridge_default() {
        let held = std::net::TcpListener::bind("127.0.0.1:0").expect("hold a port");
        let configured = held.local_addr().expect("address").port();
        // A spare port stands in for the bridge default so the test never
        // touches a real 8080.
        let spare = std::net::TcpListener::bind("127.0.0.1:0").expect("bind a port");
        let fallback = spare.local_addr().expect("address").port();
        drop(spare);
        assert_eq!(
            spawn_port("127.0.0.1", configured, fallback),
            Some(fallback),
            "a held configured port yields the fallback, never a bind over the holder"
        );
    }

    #[test]
    fn two_busy_ports_spawn_nowhere() {
        let first = std::net::TcpListener::bind("127.0.0.1:0").expect("hold configured");
        let second = std::net::TcpListener::bind("127.0.0.1:0").expect("hold fallback");
        let configured = first.local_addr().expect("address").port();
        let fallback = second.local_addr().expect("address").port();
        assert_eq!(
            spawn_port("127.0.0.1", configured, fallback),
            None,
            "calxgloss never binds a busy port"
        );
        // The degenerate case: the configured port *is* the fallback.
        assert_eq!(spawn_port("127.0.0.1", configured, configured), None);
    }

    // --- pid-file cleanup across runs (issue #117, G1-T7) --------------

    /// A tiny HTTP stand-in answering every request with `body` — enough
    /// for the identity probe that proves a live pid-file entry is ours.
    fn fake_identity_server(body: &'static str) -> u16 {
        let listener =
            std::net::TcpListener::bind("127.0.0.1:0").expect("fake identity server should bind");
        let port = listener.local_addr().expect("address").port();
        std::thread::spawn(move || {
            while let Ok((mut stream, _)) = listener.accept() {
                use std::io::{Read as _, Write as _};
                // Read the request before answering, as the bridge does.
                let mut request = [0u8; 512];
                let _ = stream.read(&mut request);
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes());
            }
        });
        port
    }

    /// A PID guaranteed dead: a short-lived child, reaped.
    fn dead_pid() -> u32 {
        let mut child = std::process::Command::new("/bin/true")
            .spawn()
            .expect("spawn /bin/true");
        let pid = child.id();
        child.wait().expect("reap /bin/true");
        pid
    }

    #[test]
    fn the_pid_file_is_read_in_both_spellings() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("headless.pid");

        // G1-T7: pid plus the port the server took.
        std::fs::write(&path, "4242 8089\n").expect("write pid file");
        assert_eq!(
            read_pid_file(&path),
            Some(PidRecord {
                pid: 4242,
                port: Some(8089)
            })
        );

        // G1-T4's spelling, left by an upgrade mid-run: pid alone.
        std::fs::write(&path, "4242\n").expect("write pid file");
        assert_eq!(
            read_pid_file(&path),
            Some(PidRecord {
                pid: 4242,
                port: None
            })
        );

        // A body naming no pid is no record.
        std::fs::write(&path, "not a pid\n").expect("write pid file");
        assert_eq!(read_pid_file(&path), None);
        assert_eq!(read_pid_file(&dir.path().join("absent.pid")), None);
    }

    #[tokio::test]
    async fn a_pid_file_whose_process_is_gone_is_removed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("headless.pid");
        std::fs::write(&path, format!("{} 8089\n", dead_pid())).expect("write pid file");

        reap_stale_pid_file(&path).await;
        assert!(!path.exists(), "the stale file is cleaned up");
    }

    #[tokio::test]
    async fn a_malformed_pid_file_is_removed_too() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("headless.pid");
        std::fs::write(&path, "truncated by a crash").expect("write pid file");

        reap_stale_pid_file(&path).await;
        assert!(!path.exists(), "garbage does not survive into the next run");
    }

    #[tokio::test]
    async fn the_orphan_of_a_crashed_run_is_killed_and_the_file_removed() {
        // Live pid, and its recorded port answers as GhidraMCP: that is the
        // crashed run's own server, left when calxgloss died before its
        // shutdown. The next run takes it down before spawning.
        let mut orphan = std::process::Command::new("/bin/sleep")
            .arg("30")
            .spawn()
            .expect("spawn the fake orphan");
        let port = fake_identity_server("Connection OK - GhidraMCP Headless Server v6.0.0");
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("headless.pid");
        std::fs::write(&path, format!("{} {port}\n", orphan.id())).expect("write pid file");

        reap_stale_pid_file(&path).await;

        assert!(!path.exists(), "the pid file goes with its server");
        let status = orphan.wait().expect("reap the killed orphan");
        assert!(
            status.code().is_none(),
            "the orphan died by signal, not by finishing: {status}"
        );
    }

    #[tokio::test]
    async fn a_live_process_that_cannot_be_verified_is_left_alone() {
        // The pid is alive but its recorded port answers as something else
        // (here: nothing at all) — the OS may have handed the pid to a
        // stranger. Only the file is removed; design risk 5 forbids killing
        // a process calxgloss did not start.
        let mut stranger = std::process::Command::new("/bin/sleep")
            .arg("30")
            .spawn()
            .expect("spawn the stranger");
        let spare = std::net::TcpListener::bind("127.0.0.1:0").expect("bind a spare port");
        let port = spare.local_addr().expect("address").port();
        drop(spare);
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("headless.pid");
        std::fs::write(&path, format!("{} {port}\n", stranger.id())).expect("write pid file");

        reap_stale_pid_file(&path).await;

        assert!(!path.exists(), "the untrustworthy file is still removed");
        assert!(
            stranger.try_wait().expect("poll the stranger").is_none(),
            "the unverified process is never killed"
        );
        stranger.kill().expect("clean up the stranger");
        stranger.wait().expect("reap the stranger");
    }
}
