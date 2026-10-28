//! Loading a target program with the Kuna engine.
//!
//! Kuna needs no server, bridge, or JVM: [`load`] is the whole session
//! start. It unpacks the embedded SLEIGH specs once, passes that spec root
//! to the Kuna engine, and drives Kuna's format-neutral object bootstrap —
//! PE, ELF, Mach-O, and COFF all arrive through the same call. What
//! [`load`] reports back is the program's identity: the language
//! description the loader resolved and the entry point the file format
//! names. These are the facts a run must agree on before any scan reads
//! the program.

use std::path::Path;

use kuna_console::engine::{self, ConsoleProgram};

use crate::error::{KunaError, Result};
use crate::specs;

/// The Kuna release this build is pinned to. `build.rs` derives it from the
/// `kuna-base` pin in the workspace lock file, so the reported release and
/// the embedded specs always name the same checkout.
pub const KUNA_RELEASE: &str = env!("CALXGLOSS_KUNA_RELEASE");

/// The pinned Kuna source fingerprint: the short commit hash of the
/// checkout that this build's Kuna code and embedded specs came from.
/// Beside [`KUNA_RELEASE`] it names the exact Kuna source that produced
/// a scan record, so the record can be re-created or a change blamed on
/// it (issue #208). `build.rs` derives it from the same lock-file pin.
pub const KUNA_PIN_REV: &str = env!("CALXGLOSS_KUNA_PIN_REV");

/// A program loaded by the Kuna engine.
///
/// The loaded program stays inside the crate. Scan reads answer through
/// this handle ([`source::KunaSource`](crate::source::KunaSource)), and
/// the handle never leaves the engine thread it was built on: Kuna's
/// program type is full of `Rc`/`RefCell` and is neither `Send` nor
/// `Sync`.
pub struct KunaProgram {
    /// The upstream program, crate-private. `source.rs` drives it on the
    /// engine thread, and nothing else may touch it.
    pub(crate) program: ConsoleProgram,
}

impl std::fmt::Debug for KunaProgram {
    /// Reports what this handle can report. The upstream program gives no
    /// useful debug output of its own, so the identity fields are printed
    /// in its place.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KunaProgram")
            .field("identity", &self.identity())
            .field("entry", &self.entry())
            .field("symbols", &self.num_symbols())
            .finish()
    }
}

impl KunaProgram {
    /// The Kuna engine's identity line for the loaded program — the
    /// resolved language, e.g. `x86:LE:64:default`.
    pub fn identity(&self) -> &str {
        self.program.description()
    }

    /// The program's entry point, when the file format names one.
    pub fn entry(&self) -> Option<u64> {
        self.program.image_metadata().and_then(|m| m.entry)
    }

    /// The number of function symbols the loader collected for the program.
    pub fn num_symbols(&self) -> usize {
        self.program.num_symbols()
    }
}

/// Load `path` as a program with the Kuna engine, selecting the language
/// from the file itself.
///
/// When loading fails, the error is always [`KunaError::LoadFailed`],
/// naming the path and Kuna's own reason. It never leaks a raw upstream
/// backtrace.
pub fn load(path: &Path) -> Result<KunaProgram> {
    let spec_root = specs::spec_root()?;
    let mut program = engine::bootstrap_from_object(&path.to_string_lossy(), "", &[spec_root])
        .map_err(|error| KunaError::LoadFailed {
            path: path.display().to_string(),
            reason: error.explain().to_string(),
        })?;
    // This mirrors the Kuna CLI's load sequence (bootstrap → options →
    // commit). Bootstrap only stores the object file's function entries as
    // pending synthetic ones. The commit installs them as the function
    // entries later listings answer with. Without this order, a scan
    // reading the program straight after bootstrap would see the
    // pre-commit view.
    apply_discovery_bundle(&mut program, path)?;
    program
        .commit_pending_analysis()
        .map_err(|error| KunaError::LoadFailed {
            path: path.display().to_string(),
            reason: error.explain().to_string(),
        })?;
    Ok(KunaProgram { program })
}

/// Apply Kuna's driver-default function-discovery options to a bootstrapped
/// program, before the analysis commit installs the function entries later
/// listings answer with.
///
/// Without these options, the commit installs only what the loader itself
/// knows: the entry point, the TLS callbacks, and the code pointers that
/// base relocations name. A stripped image would then list a couple dozen
/// functions where it holds thousands.
///
/// A 32-bit PE is the worst case. It has no `.pdata` exception table (the
/// x64 oracle that recovers nearly every function) and no symbol table, so
/// the entry oracles alone find almost nothing.
///
/// These options mirror the bundle `kuna decompile-all` injects for its own
/// decompiling driver (kuna DIV-15/DIV-20/DIV-68):
///
/// * `listing on` — turns on the recursive Listing walk, the direct-call
///   closure from the loader-backed roots, and the master gate of the
///   discovery bundle below.
/// * `funcstart_patterns on` and `aif on` — turn on the prologue-pattern
///   sweep and the aggressive instruction finder. These are the primary
///   discovery sources on a non-x86-64 image, where the cheap x86-64
///   oracles do nothing. x86-64 keeps them off, exactly as Kuna's driver
///   does: the entry oracles are enough there, and the aggressive scan can
///   find things that are not functions.
fn apply_discovery_bundle(program: &mut engine::ConsoleProgram, path: &Path) -> Result<()> {
    let non_x86_64 = std::fs::read(path)
        .map(|bytes| image_is_non_x86_64(&bytes))
        .unwrap_or(false);
    let mut set = |name: &str| -> Result<()> {
        program
            .arch_mut()
            .set_kuna_option(name, "on")
            .map(|_| ())
            .map_err(|error| KunaError::LoadFailed {
                path: path.display().to_string(),
                reason: format!("option {name} on: {}", error.explain()),
            })
    };
    set("listing")?;
    if non_x86_64 {
        set("funcstart_patterns")?;
        set("aif")?;
    }
    Ok(())
}

/// Whether the image bytes name an architecture other than x86-64.
///
/// An image that `object` cannot parse gets the x86-64 answer, matching
/// how the Kuna driver makes the same computation: no aggressive bundle on
/// an architecture that cannot be named.
fn image_is_non_x86_64(bytes: &[u8]) -> bool {
    use object::Object;
    object::read::File::parse(bytes)
        .map(|file| file.architecture() != object::Architecture::X86_64)
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The load arms the recursive Listing walk on every image, and the
    /// aggressive pattern/finder half of the bundle only on a non-x86-64
    /// one — so the x86-64 fixture takes the walk but not the aggressive pair.
    #[test]
    fn the_load_arms_the_discovery_bundle() {
        let fixture =
            calxgloss_testfixtures::load_target().expect("the fixture target builds and validates");
        let program = load(fixture.path()).expect("the fixture must load");
        let arch = program.program.arch();
        assert!(
            arch.analysis_listing,
            "the recursive Listing walk is armed on every load"
        );
        assert!(
            !arch.analysis_funcstart_patterns,
            "the x86-64 fixture keeps the prologue-pattern sweep off"
        );
        assert!(
            !arch.analysis_aif,
            "the x86-64 fixture keeps the aggressive instruction finder off"
        );
    }

    /// The aggressive half of the bundle keys off the image's architecture:
    /// a 32-bit image names it, an x86-64 image does not, and an image
    /// `object` cannot parse takes the x86-64 answer.
    #[test]
    fn the_aggressive_bundle_keys_on_the_architecture() {
        let fixture =
            calxgloss_testfixtures::load_target().expect("the fixture target builds and validates");
        let fixture_bytes = std::fs::read(fixture.path()).expect("the fixture target is readable");
        assert!(
            !image_is_non_x86_64(&fixture_bytes),
            "the x86-64 fixture takes the cheap x86-64 answer"
        );

        // A minimal ELF32 header — `e_machine = EM_386`, no sections — names
        // a non-x86-64 architecture all by itself.
        let mut elf32 = vec![0u8; 52];
        elf32[..4].copy_from_slice(b"\x7fELF");
        elf32[4] = 1; // ELFCLASS32
        elf32[5] = 1; // ELFDATA2LSB
        elf32[6] = 1; // EV_CURRENT
        elf32[16..18].copy_from_slice(&2u16.to_le_bytes()); // e_type = ET_EXEC
        elf32[18..20].copy_from_slice(&3u16.to_le_bytes()); // e_machine = EM_386
        elf32[40..42].copy_from_slice(&52u16.to_le_bytes()); // e_ehsize
        assert!(
            image_is_non_x86_64(&elf32),
            "a 32-bit image arms the aggressive bundle"
        );

        assert!(
            !image_is_non_x86_64(b"not an object file at all"),
            "an unparsable image takes the x86-64 answer"
        );
    }
}
