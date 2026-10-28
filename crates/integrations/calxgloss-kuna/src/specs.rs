//! The compiled SLEIGH tree this build carries inside itself.
//!
//! The Kuna engine reads specs only through plain filesystem path reads.
//! So the `include_bytes!` table that `build.rs` generates is unpacked
//! once into a per-user cache directory, named from the contents of the
//! tree, and that directory is passed to the Kuna engine as its spec root.
//! Each unpack first writes into a private staging directory and renames
//! it into place only once it is complete, and a `.complete` marker
//! written last says a finished tree lives there. So a reader never sees a
//! partial tree, and concurrent first runs settle on one copy. This
//! mirrors Kuna's own `kuna-cli/src/embedded_specs.rs`; that module is not
//! reusable because it sits on the bin-only `kuna-cli` crate.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use crate::error::{KunaError, Result};

mod generated {
    include!(concat!(env!("OUT_DIR"), "/embedded_specs.rs"));
}

/// Written last into a finished unpack; a tree without it is not used.
const COMPLETE: &str = ".complete";

/// How long a caller waits on another process's unpack before giving up on
/// this cache location; an unpack takes well under a second.
const LOCK_WAIT: Duration = Duration::from_secs(30);

/// The spec root to pass to the Kuna engine, unpacked once per process.
pub(crate) fn spec_root() -> Result<String> {
    static ROOT: OnceLock<std::result::Result<PathBuf, String>> = OnceLock::new();
    let cached = ROOT.get_or_init(|| unpack_into_cache(generated::ID, generated::FILES));
    match cached {
        Ok(dir) => Ok(dir.to_string_lossy().into_owned()),
        Err(reason) => Err(KunaError::SpecsUnavailable {
            reason: reason.clone(),
        }),
    }
}

/// Unpack into the first cache location that accepts the tree.
fn unpack_into_cache(id: &str, files: &[(&str, &[u8])]) -> std::result::Result<PathBuf, String> {
    let mut failures = Vec::new();
    for base in cache_bases() {
        match unpack(&base, id, files) {
            Ok(dir) => return Ok(dir),
            Err(e) => failures.push(format!("{}: {e}", base.display())),
        }
    }
    Err(failures.join("; "))
}

/// Where unpacked trees live, most preferred first: the per-user calxgloss
/// cache directory, then the system temp directory.
fn cache_bases() -> Vec<PathBuf> {
    let var = |name: &str| {
        std::env::var_os(name)
            .filter(|value| !value.as_os_str().is_empty())
            .map(PathBuf::from)
    };
    let user_cache = var("XDG_CACHE_HOME")
        .filter(|dir| dir.is_absolute())
        .or_else(|| var("HOME").map(|home| home.join(".cache")))
        .map(|dir| dir.join("calxgloss/kuna"));
    let user = std::env::var("USER").unwrap_or_default();
    let temp = if user.is_empty() {
        std::env::temp_dir().join("calxgloss-kuna")
    } else {
        std::env::temp_dir().join(format!("calxgloss-kuna-{user}"))
    };
    user_cache.into_iter().chain([temp]).collect()
}

/// The tree for `id` under `base`, unpacking `files` there first if no
/// finished copy exists.
fn unpack(base: &Path, id: &str, files: &[(&str, &[u8])]) -> std::result::Result<PathBuf, String> {
    let dir = base.join(format!("specs-{id}"));
    if dir.join(COMPLETE).is_file() {
        return Ok(dir);
    }
    fs::create_dir_all(base).map_err(|e| e.to_string())?;
    // Keep the lock file: unlinking it would let later callers lock another inode.
    let lock = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(base.join(format!(".specs-{id}.lock")))
        .map_err(|e| e.to_string())?;
    acquire(&lock)?;
    if dir.join(COMPLETE).is_file() {
        return Ok(dir);
    }
    let staging = base.join(format!(".specs-{id}-{}", std::process::id()));
    if let Err(e) = write_tree(&staging, id, files) {
        let _ = fs::remove_dir_all(&staging);
        return Err(e);
    }
    if dir.is_dir() && !dir.join(COMPLETE).is_file() {
        let _ = fs::remove_dir_all(&dir);
    }
    let renamed = fs::rename(&staging, &dir);
    let _ = fs::remove_dir_all(&staging);
    if dir.join(COMPLETE).is_file() {
        return Ok(dir);
    }
    Err(match renamed {
        Err(e) => e.to_string(),
        Ok(()) => format!("{} has no {COMPLETE} marker", dir.display()),
    })
}

/// Take `lock`, giving up after [`LOCK_WAIT`]. If another process still
/// holds it, the caller moves on to the next cache location instead of
/// waiting forever.
fn acquire(lock: &fs::File) -> std::result::Result<(), String> {
    let deadline = Instant::now() + LOCK_WAIT;
    let mut pause = Duration::from_millis(1);
    loop {
        match lock.try_lock() {
            Ok(()) => return Ok(()),
            Err(fs::TryLockError::WouldBlock) if Instant::now() < deadline => {
                std::thread::sleep(pause);
                pause = (pause * 2).min(Duration::from_millis(25));
            }
            Err(fs::TryLockError::WouldBlock) => {
                return Err(format!(
                    "another process held the unpack lock for over {LOCK_WAIT:?}"
                ));
            }
            Err(fs::TryLockError::Error(e)) => return Err(e.to_string()),
        }
    }
}

/// Write every file plus the completion marker into the staging tree.
fn write_tree(
    staging: &Path,
    id: &str,
    files: &[(&str, &[u8])],
) -> std::result::Result<(), String> {
    for (rel, bytes) in files {
        let path = rel
            .split('/')
            .fold(staging.to_path_buf(), |p, part| p.join(part));
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| format!("{}: {e}", parent.display()))?;
        }
        fs::write(&path, bytes).map_err(|e| format!("{}: {e}", path.display()))?;
    }
    fs::write(staging.join(COMPLETE), id).map_err(|e| format!("{COMPLETE}: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_unpacked_tree_carries_the_compiled_x86_specs() {
        let base = tempfile::tempdir().expect("temp dir");
        let dir = unpack(base.path(), generated::ID, generated::FILES).expect("unpack");
        assert!(dir.join(COMPLETE).is_file());
        let languages = dir.join("Ghidra/Processors/x86/data/languages");
        assert!(languages.join("x86.ldefs").is_file());
        assert!(languages.join("x86-64.sla").is_file());
        // Sources are embedded for the build, not shipped in the tree.
        assert!(!languages.join("x86.slaspec").is_file());
        // A second unpack settles on the same finished copy.
        let again = unpack(base.path(), generated::ID, generated::FILES).expect("re-unpack");
        assert_eq!(again, dir);
    }
}
