//! Discovery of live GhidraMCP servers through the bridge's runtime-socket
//! directory — the cure for a stale configured port.
//!
//! Every GhidraMCP server, GUI plugin or headless, registers a Unix domain
//! socket at `$XDG_RUNTIME_DIR/ghidra-mcp/ghidra-<pid>.sock` (the bridge's
//! `ServerManager`, verified against the live stack). The filename carries
//! the server's PID, and the socket itself serves the server's full HTTP API,
//! so `GET /mcp/instance_info` over it answers with the server's actual TCP
//! port and open project. A configured port that nothing answers is therefore
//! not the end of the road: [`discover`] names the live servers and their
//! ports, and [`super::session`] attaches to one — the reboot that moved a
//! GUI server to a new port no longer breaks the config (design risk 4).
//!
//! The scan is read-only: dead sockets (no `/proc` entry for the filename's
//! PID) are ignored, never deleted — the bridge cleans up its own stale
//! registrations — and a directory that does not exist simply discovers
//! nothing. Liveness is Linux-only (it reads `/proc`); on other Unix systems
//! the scan finds nothing and the session falls through to the spawn
//! decision untouched.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::Value;
use tracing::debug;

/// The bridge's default TCP port — the fallback a spawn takes when the
/// configured port is busy (ADR-0001: our *configured* load instance is
/// 8089; 8080 is the bridge's own default, never a fallback to bind over).
pub const BRIDGE_DEFAULT_PORT: u16 = 8080;

/// How long one `instance_info` query may take. The endpoint is answered
/// straight out of Ghidra's in-memory state, so a socket that has not
/// answered within this budget is not worth waiting on.
const QUERY_TIMEOUT: Duration = Duration::from_secs(2);

/// A live server the socket scan found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredServer {
    /// The PID the socket filename carries and `/proc` confirmed alive.
    pub pid: u32,
    /// The registration socket the query was answered on.
    pub socket: PathBuf,
    /// The project the server named, when it named one.
    pub project: Option<String>,
    /// The TCP port to attach over — `None` for a UDS-only instance
    /// (`tcp_port: -1`), which the HTTP client cannot reach.
    pub port: Option<u16>,
}

/// The bridge's runtime-socket directory: `$XDG_RUNTIME_DIR/ghidra-mcp`,
/// falling back to `/run/user/<uid>/ghidra-mcp` — the same resolution the
/// plugin's `ServerManager.getSocketDir()` and the Python bridge's candidate
/// list make. `None` when neither the environment nor the caller names a
/// runtime directory to scan.
pub fn socket_dir(xdg_runtime_dir: Option<&Path>, uid: Option<u32>) -> Option<PathBuf> {
    if let Some(xdg) = xdg_runtime_dir.filter(|dir| !dir.as_os_str().is_empty()) {
        return Some(xdg.join("ghidra-mcp"));
    }
    uid.map(|uid| {
        Path::new("/run/user")
            .join(uid.to_string())
            .join("ghidra-mcp")
    })
}

/// Scan `dir` for live registrations: every `ghidra-<pid>.sock` whose PID
/// still has a `/proc` entry is queried once for its TCP port and project.
/// Malformed names, dead PIDs, and sockets that do not answer `instance_info`
/// are ignored — the scan never deletes anything and never fails. Results
/// are sorted by PID so the attach decision is deterministic.
pub fn discover(dir: &Path) -> Vec<DiscoveredServer> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut servers: Vec<DiscoveredServer> = entries
        .flatten()
        .filter_map(|entry| {
            let path = entry.path();
            let name = path.file_name()?.to_str()?;
            let pid = socket_pid(name)?;
            if !pid_alive(pid) {
                debug!(socket = %path.display(), pid, "Ignoring a dead GhidraMCP registration");
                return None;
            }
            let info = instance_info(&path)?;
            Some(DiscoveredServer {
                pid,
                socket: path,
                project: info.project,
                port: info.tcp_port,
            })
        })
        .collect();
    servers.sort_by_key(|server| server.pid);
    servers
}

/// The PID a registration filename carries: `ghidra-<pid>.sock`, exactly as
/// the bridge's `ServerManager` names it. Anything else is not a registration.
fn socket_pid(name: &str) -> Option<u32> {
    name.strip_prefix("ghidra-")?
        .strip_suffix(".sock")?
        .parse()
        .ok()
}

/// Whether `pid` still has a process behind it — the `/proc` form of the
/// bridge's own `kill -0` liveness check. Shared with [`server`]'s pid-file
/// cleanup (G1-T7).
pub(crate) fn pid_alive(pid: u32) -> bool {
    Path::new("/proc").join(pid.to_string()).exists()
}

/// The part of `/mcp/instance_info` the reconciliation needs.
struct InstanceInfo {
    project: Option<String>,
    tcp_port: Option<u16>,
}

/// Query one registration socket: an HTTP `GET /mcp/instance_info` over the
/// Unix socket, answered by the server itself. `None` when the socket does
/// not answer, answers with a non-200, or answers with something that is not
/// the instance record — a live PID with an unqueryable socket is a server
/// calxgloss cannot reach, so it is ignored like a dead one.
fn instance_info(socket: &Path) -> Option<InstanceInfo> {
    let mut stream = UnixStream::connect(socket).ok()?;
    stream.set_read_timeout(Some(QUERY_TIMEOUT)).ok()?;
    stream.set_write_timeout(Some(QUERY_TIMEOUT)).ok()?;
    stream
        .write_all(
            b"GET /mcp/instance_info HTTP/1.0\r\nHost: ghidra-mcp\r\nConnection: close\r\n\r\n",
        )
        .ok()?;
    stream.shutdown(std::net::Shutdown::Write).ok()?;
    // The bridge's UDS server frames every answer with `Connection: close`,
    // so reading to EOF is the whole response.
    let mut response = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(read) => response.extend_from_slice(&buf[..read]),
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
            // A socket that hangs up rudely (an unread request earns an
            // RST) after having answered still delivered the answer: parse
            // what arrived rather than discarding it on the error.
            Err(_) => break,
        }
    }
    let body = http_body(&response)?;
    let mut value: Value = serde_json::from_str(body).ok()?;
    // The bridge wraps some answers in its `Response.ok()` envelope; the
    // Python bridge unwraps the same `"data"` key.
    if value.get("data").is_some_and(Value::is_object) {
        value = value["data"].take();
    }
    Some(InstanceInfo {
        project: value
            .get("project")
            .and_then(Value::as_str)
            .map(str::to_string),
        // -1 means UDS-only: no TCP port to attach over.
        tcp_port: value
            .get("tcp_port")
            .and_then(Value::as_i64)
            .filter(|port| *port > 0)
            .map(|port| port as u16),
    })
}

/// The body of a completed HTTP response, once its status line says `200`.
fn http_body(response: &[u8]) -> Option<&str> {
    let text = std::str::from_utf8(response).ok()?;
    let (head, body) = text.split_once("\r\n\r\n")?;
    head.lines()
        .next()
        .is_some_and(|line| line.split_whitespace().nth(1) == Some("200"))
        .then_some(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fake GhidraMCP registration: a UDS answering one HTTP request with
    /// `body`, framed exactly as the bridge's UDS server frames
    /// `instance_info` (`Content-Length` + `Connection: close`).
    fn fake_registration(dir: &Path, name: &str, body: &str) {
        let listener =
            std::os::unix::net::UnixListener::bind(dir.join(name)).expect("bind fake socket");
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                // Read the request before answering, as the bridge does —
                // closing over an unread request earns an RST.
                let mut request = [0u8; 1024];
                let _ = stream.read(&mut request);
                let _ = stream.write_all(response.as_bytes());
            }
        });
    }

    /// The instance record as the live bridge answers it (captured from a
    /// real GUI instance, programs trimmed).
    fn instance_body(pid: u32, project: &str, tcp_port: i64) -> String {
        format!(
            "{{\"pid\":{pid},\"project\":\"{project}\",\"project_path\":\"/eq/{project}\",\
             \"programs\":[],\"tcp_port\":{tcp_port},\"tools\":1}}"
        )
    }

    /// A PID guaranteed dead: a short-lived child, reaped.
    fn dead_pid() -> u32 {
        let mut child = std::process::Command::new("/bin/true")
            .spawn()
            .expect("spawn /bin/true");
        let pid = child.id();
        child.wait().expect("reap /bin/true");
        assert!(!pid_alive(pid), "the reaped pid should be dead");
        pid
    }

    #[test]
    fn the_scan_finds_live_servers_with_their_ports_and_projects() {
        let dir = tempfile::tempdir().expect("tempdir");
        let pid = std::process::id();
        fake_registration(
            dir.path(),
            &format!("ghidra-{pid}.sock"),
            &instance_body(pid, "EQ_Ghidra", 8089),
        );

        let found = discover(dir.path());
        assert_eq!(found.len(), 1, "the live registration is found");
        assert_eq!(found[0].pid, pid);
        assert_eq!(found[0].project.as_deref(), Some("EQ_Ghidra"));
        assert_eq!(found[0].port, Some(8089));
    }

    #[test]
    fn dead_sockets_are_ignored() {
        let dir = tempfile::tempdir().expect("tempdir");
        let dead = dead_pid();
        // A stale registration file: the name is well-formed, the process
        // is gone. It must not even be queried, let alone attached to.
        std::fs::write(dir.path().join(format!("ghidra-{dead}.sock")), "")
            .expect("write stale socket");

        assert!(discover(dir.path()).is_empty(), "a dead pid is ignored");
    }

    #[test]
    fn a_live_socket_that_never_answers_is_ignored() {
        let dir = tempfile::tempdir().expect("tempdir");
        let pid = std::process::id();
        let listener =
            std::os::unix::net::UnixListener::bind(dir.path().join(format!("ghidra-{pid}.sock")))
                .expect("bind silent socket");
        std::thread::spawn(move || {
            // Accept and hang up without answering: a live PID whose socket
            // cannot serve the instance record.
            if let Ok((stream, _)) = listener.accept() {
                drop(stream);
            }
        });

        assert!(
            discover(dir.path()).is_empty(),
            "an unqueryable socket is not a usable server"
        );
    }

    #[test]
    fn a_uds_only_instance_is_found_without_a_port() {
        // `tcp_port: -1` is the bridge's own "UDS only" marker — the server
        // is live and named, but the HTTP client has nothing to attach to.
        let dir = tempfile::tempdir().expect("tempdir");
        let pid = std::process::id();
        fake_registration(
            dir.path(),
            &format!("ghidra-{pid}.sock"),
            &instance_body(pid, "EQ_Ghidra", -1),
        );

        let found = discover(dir.path());
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].port, None);
        assert_eq!(found[0].project.as_deref(), Some("EQ_Ghidra"));
    }

    #[test]
    fn the_wrapped_answer_form_parses() {
        // Some bridge answers ride inside the `Response.ok()` envelope; the
        // Python bridge unwraps the same key, and so does this scan.
        let dir = tempfile::tempdir().expect("tempdir");
        let pid = std::process::id();
        let inner = instance_body(pid, "EQ_Ghidra", 8080);
        fake_registration(
            dir.path(),
            &format!("ghidra-{pid}.sock"),
            &format!("{{\"data\":{inner}}}"),
        );

        let found = discover(dir.path());
        assert_eq!(found.len(), 1, "the wrapped form is the same server");
        assert_eq!(found[0].port, Some(8080));
    }

    #[test]
    fn malformed_names_and_missing_dirs_discover_nothing() {
        let dir = tempfile::tempdir().expect("tempdir");
        for name in ["ghidra-abc.sock", "random.sock", "ghidra-123.txt", ".sock"] {
            std::fs::write(dir.path().join(name), "").expect("write fixture file");
        }
        assert!(discover(dir.path()).is_empty(), "only registrations count");
        assert!(
            discover(&dir.path().join("absent")).is_empty(),
            "a missing socket dir discovers nothing"
        );
    }

    #[test]
    fn several_registrations_sort_by_pid() {
        let dir = tempfile::tempdir().expect("tempdir");
        let pid = std::process::id();
        // One real registration; the others are dead names that must drop
        // out rather than shuffle the order.
        fake_registration(
            dir.path(),
            &format!("ghidra-{pid}.sock"),
            &instance_body(pid, "EQ_Ghidra", 8089),
        );
        std::fs::write(dir.path().join("ghidra-1.sock"), "").expect("write dead socket");

        let found = discover(dir.path());
        assert_eq!(found.iter().map(|s| s.pid).collect::<Vec<_>>(), vec![pid]);
    }

    #[test]
    fn the_socket_dir_follows_xdg_then_run_user() {
        assert_eq!(
            socket_dir(Some(Path::new("/run/user/1000")), Some(1000)).as_deref(),
            Some(Path::new("/run/user/1000/ghidra-mcp")),
            "$XDG_RUNTIME_DIR wins"
        );
        assert_eq!(
            socket_dir(Some(Path::new("")), Some(1000)).as_deref(),
            Some(Path::new("/run/user/1000/ghidra-mcp")),
            "an empty XDG_RUNTIME_DIR counts as unset"
        );
        assert_eq!(
            socket_dir(None, Some(1000)).as_deref(),
            Some(Path::new("/run/user/1000/ghidra-mcp")),
            "otherwise /run/user/<uid>"
        );
        assert_eq!(socket_dir(None, None), None, "nothing to scan");
    }
}
