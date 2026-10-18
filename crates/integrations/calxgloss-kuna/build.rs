//! Provisions the embedded SLEIGH specs the Kuna engine loads against
//! (issue #205).
//!
//! Kuna's own `embed-specs` feature lives on `kuna-cli`, a bin-only crate
//! that cannot be consumed as a library, and the compiled `.sla` files are
//! not checked into the Kuna repo — so this script does the same job for
//! this crate: locate the pinned Kuna git checkout cargo already fetched,
//! copy its x86 processor spec tree into `OUT_DIR`, compile every
//! `.slaspec` to its sibling `.sla` with `kuna-slacomp` — the same compiler
//! Kuna's own Makefile drives as `slacomp -a specs` — and generate the
//! `include_bytes!` table `src/specs.rs` unpacks at runtime, mirroring
//! Kuna's `kuna-cli/src/embedded_specs.rs`. Only x86 is embedded: the
//! fixture target and every current calxgloss target is x86/x86-64, and a
//! wider tree would embed megabytes no current run reads.

use std::env;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

/// Sources and lock files carry no loadable spec content (Kuna's own list).
const SKIPPED_EXTENSIONS: &[&str] = &["slaspec", "sinc", "lock"];

/// The Kuna pin, read from `Cargo.lock` — the one place the pin is
/// authoritative. The tag is what `src/engine.rs` reports as
/// `KUNA_RELEASE`, the short rev names the git-checkout directory whose
/// specs get embedded and the source fingerprint `KUNA_PIN_REV` reports,
/// so none of them can drift from the manifest pin.
struct Pin {
    tag: String,
    rev: String,
}

/// Pull the `kuna-base` source line out of the workspace lock file:
/// `git+<url>?tag=<tag>#<full commit>`.
fn read_pin() -> Pin {
    let lock = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../Cargo.lock")
        .canonicalize()
        .expect("the workspace lock file");
    println!("cargo:rerun-if-changed={}", lock.display());
    let text = fs::read_to_string(&lock).unwrap_or_else(|e| panic!("read {}: {e}", lock.display()));
    let mut source: Option<String> = None;
    let mut next_is_source = false;
    for line in text.lines() {
        let line = line.trim();
        if line == "name = \"kuna-base\"" {
            next_is_source = true;
        } else if next_is_source && let Some(rest) = line.strip_prefix("source = ") {
            source = Some(rest.trim_matches('"').to_string());
            break;
        }
    }
    let source = source.expect("no kuna-base entry in Cargo.lock — the pin is gone");
    let tag = source
        .split("?tag=")
        .nth(1)
        .and_then(|rest| rest.split('#').next())
        .expect("kuna-base pin carries no ?tag=")
        .to_string();
    let commit = source
        .split('#')
        .next_back()
        .expect("kuna-base pin carries no commit hash");
    Pin {
        tag,
        rev: commit[..7].to_string(),
    }
}

const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

fn fnv(mut hash: u64, bytes: &[u8]) -> u64 {
    for &b in bytes {
        hash ^= u64::from(b);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

/// True when `specs` carries the x86 language tree this build needs.
fn has_x86_specs(specs: &Path) -> bool {
    specs
        .join("Ghidra/Processors/x86/data/languages/x86.slaspec")
        .is_file()
}

/// Locate the Kuna `specs` directory: the `CALXGLOSS_KUNA_SPECS` override
/// first (for vendored or offline builds), then the cargo git checkout of
/// the pinned tag under `$CARGO_HOME/git/checkouts/kuna-*/<rev>/specs`.
/// Only the rev-matched checkout is ever embedded: a checkout of some other
/// Kuna revision fails the build by name rather than quietly shipping specs
/// the reported release did not produce.
fn locate_specs(pin: &Pin) -> PathBuf {
    if let Some(dir) = env::var_os("CALXGLOSS_KUNA_SPECS") {
        let dir = PathBuf::from(dir);
        assert!(
            has_x86_specs(&dir),
            "CALXGLOSS_KUNA_SPECS = {} has no Ghidra/Processors/x86 language tree",
            dir.display()
        );
        return dir;
    }
    let cargo_home = env::var_os("CARGO_HOME")
        .map(PathBuf::from)
        .or_else(|| env::var_os("HOME").map(|home| PathBuf::from(home).join(".cargo")))
        .expect("no $CARGO_HOME or $HOME to find the Kuna git checkout in");
    let mut pinned = None;
    let mut found = Vec::new();
    let checkouts = cargo_home.join("git/checkouts");
    if let Ok(entries) = fs::read_dir(&checkouts) {
        for entry in entries.flatten() {
            if !entry.file_name().to_string_lossy().starts_with("kuna-") {
                continue;
            }
            let Ok(revs) = fs::read_dir(entry.path()) else {
                continue;
            };
            for rev in revs.flatten() {
                let name = rev.file_name().to_string_lossy().to_string();
                let specs = rev.path().join("specs");
                if !has_x86_specs(&specs) {
                    continue;
                }
                if name.starts_with(&pin.rev) {
                    pinned = Some(specs);
                } else {
                    found.push(name);
                }
            }
        }
    }
    pinned.unwrap_or_else(|| {
        panic!(
            "could not find the Kuna {} SLEIGH specs: no git checkout of the pinned rev {} \
             under {} (checkouts seen: {}) — run `cargo fetch` first, or set \
             CALXGLOSS_KUNA_SPECS to a Kuna `specs` directory",
            pin.tag,
            pin.rev,
            checkouts.display(),
            if found.is_empty() {
                "none".to_string()
            } else {
                found.join(", ")
            },
        )
    })
}

/// Copy `src` and everything under it to `dst`.
fn copy_dir(src: &Path, dst: &Path) {
    fs::create_dir_all(dst).unwrap_or_else(|e| panic!("{}: {e}", dst.display()));
    for entry in fs::read_dir(src).unwrap_or_else(|e| panic!("{}: {e}", src.display())) {
        let entry = entry.expect("directory entry");
        let from = entry.path();
        let to = dst.join(entry.file_name());
        if from.is_dir() {
            copy_dir(&from, &to);
        } else {
            fs::copy(&from, &to)
                .unwrap_or_else(|e| panic!("copy {} → {}: {e}", from.display(), to.display()));
        }
    }
}

/// Every embeddable file under `dir`, as (`/`-joined path relative to
/// `root`, path) — Kuna's own collection rule.
fn collect(root: &Path, dir: &Path, out: &mut Vec<(String, PathBuf)>) {
    for entry in fs::read_dir(dir).unwrap_or_else(|e| panic!("{}: {e}", dir.display())) {
        let entry = entry.expect("directory entry");
        let path = entry.path();
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        if name.starts_with('.') {
            continue;
        }
        if path.is_dir() {
            collect(root, &path, out);
            continue;
        }
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or_default();
        if !path.is_file() || SKIPPED_EXTENSIONS.contains(&ext) {
            continue;
        }
        let rel = path.strip_prefix(root).expect("path under the root");
        let rel = rel
            .iter()
            .map(|c| c.to_str().expect("UTF-8 path"))
            .collect::<Vec<_>>()
            .join("/");
        out.push((rel, path));
    }
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR"));

    // The pin comes out of the lock file, and the tag and short rev ride
    // into the crate's environment so the reported release, the embedded
    // specs, and the source fingerprint a scan record names can never
    // drift apart from the pin.
    let pin = read_pin();
    println!("cargo:rustc-env=CALXGLOSS_KUNA_RELEASE={}", pin.tag);
    println!("cargo:rustc-env=CALXGLOSS_KUNA_PIN_REV={}", pin.rev);

    let specs = locate_specs(&pin);
    println!("cargo:rerun-if-changed={}", specs.display());

    // Copy the x86 tree, then compile in place: `slacomp -a` writes each
    // `.sla` beside its `.slaspec`, exactly as Kuna's Makefile does.
    let root = out.join("specs");
    let x86 = "Ghidra/Processors/x86";
    copy_dir(&specs.join(x86), &root.join(x86));
    let status = kuna_slacomp::slacompmain::main(vec![
        "slacomp".to_string(),
        "-a".to_string(),
        root.join(x86).display().to_string(),
    ]);
    assert_eq!(
        status,
        std::process::ExitCode::SUCCESS,
        "slacomp -a {} failed",
        root.join(x86).display()
    );

    let mut files = Vec::new();
    collect(&root, &root, &mut files);
    files.sort();
    assert!(
        files.iter().any(|(rel, _)| rel.ends_with(".sla")),
        "no compiled .sla under {} — slacomp produced nothing",
        root.display()
    );

    let mut hash = FNV_OFFSET;
    let mut table = String::new();
    for (rel, path) in &files {
        let bytes = fs::read(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        hash = fnv(hash, rel.as_bytes());
        hash = fnv(hash, &(bytes.len() as u64).to_le_bytes());
        hash = fnv(hash, &bytes);
        let source = path.to_str().expect("UTF-8 path");
        writeln!(table, "    ({rel:?}, include_bytes!({source:?})),").expect("write to String");
    }
    let generated = format!(
        "pub const ID: &str = \"{hash:016x}\";\n\
         pub static FILES: &[(&str, &[u8])] = &[\n{table}];\n"
    );
    fs::write(out.join("embedded_specs.rs"), generated)
        .unwrap_or_else(|e| panic!("write embedded_specs.rs: {e}"));
}
