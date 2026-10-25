//! Source-level pins for the pipeline assembly contract (issue #328).
//!
//! The compiler pins the crate boundary — the pipeline constructor and its
//! `with_*` setter surface are assembly-internal (`pub(crate)`), so no code
//! outside the pipeline context can hand-build a pass. What the compiler
//! cannot pin is the fact *inside* the crate: across every crate's `src/`
//! tree the constructor is called in exactly one production module, the
//! seam's own `assembly.rs`. This suite pins that source fact, so a fourth
//! builder dance cannot reappear silently.
//!
//! These tests read the source tree and assert nothing about behavior;
//! what an assembled pass honors is pinned by the seam's behavior suite in
//! the sibling file `tests/assembly.rs`.

use std::path::{Path, PathBuf};

/// The constructor's call-site spelling, composed so no file merely names
/// the contract (in a doc comment or an error message) can trip the pin.
const CONSTRUCTOR: &str = concat!("TranslationPipeline", "::new");

/// The one production module allowed to call it, relative to `crates/`.
const ASSEMBLY_MODULE: &str = "pipeline/calxgloss-translator/src/assembly.rs";

/// The workspace's `crates/` directory, as seen from this crate's manifest.
fn crates_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .join("crates")
        .canonicalize()
        .expect("the workspace crates directory")
}

/// Every `.rs` file living under a `src` directory anywhere in `root`,
/// as paths relative to `root`. Integration tests (`tests/`), build
/// scripts, and benches are not production modules and stay out of the scan.
fn source_files(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    collect(root, root, false, &mut out);
    out
}

fn collect(root: &Path, dir: &Path, in_src: bool, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("read the source tree") {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            let in_src = in_src || path.file_name().is_some_and(|name| name == "src");
            collect(root, &path, in_src, out);
        } else if in_src && path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path.strip_prefix(root).expect("relative path").to_path_buf());
        }
    }
}

/// How often `CONSTRUCTOR` appears as code in the file's production region.
/// The production region is everything before the first `#[cfg(test)]` line —
/// the repo's convention is that test modules sit at the bottom of the file
/// (`docs/standards.md`) — and comment lines never count: docs and prose
/// name the constructor without constructing anything.
fn production_calls(text: &str) -> usize {
    text.lines()
        .take_while(|line| !line.trim_start().starts_with("#[cfg(test)]"))
        .filter(|line| !line.trim_start().starts_with("//"))
        .filter(|line| line.contains(CONSTRUCTOR))
        .count()
}

#[test]
fn pipeline_constructor_is_called_in_exactly_one_production_module() {
    let crates = crates_dir();
    let files = source_files(&crates);
    assert!(
        files.len() > 100,
        "the source walk found only {} files — the scan itself is broken, \
         not the contract",
        files.len()
    );

    let hits: Vec<(String, usize)> = files
        .iter()
        .map(|file| {
            let text = std::fs::read_to_string(crates.join(file)).expect("read source file");
            (file.to_string_lossy().into_owned(), production_calls(&text))
        })
        .filter(|(_, calls)| *calls > 0)
        .collect();

    assert_eq!(
        hits,
        vec![(ASSEMBLY_MODULE.to_string(), 1)],
        "`{CONSTRUCTOR}` must be called in exactly one production module — \
         the assembly seam — so every pass provably arrives through assembly; \
         a second caller means a hand-built pass rejoined the tree (issue #328)"
    );
}
