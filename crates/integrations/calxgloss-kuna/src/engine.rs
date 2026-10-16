//! Loading a target program with the Kuna engine.
//!
//! Kuna needs no server, bridge, or JVM: [`load`] is the whole session
//! start. It unpacks the embedded SLEIGH specs once, hands the engine that
//! spec root, and drives Kuna's format-neutral object bootstrap — PE, ELF,
//! Mach-O, and COFF all arrive through the same call. What the skeleton
//! reports back is the program's identity: the language description the
//! loader resolved and the entry point the format names, the facts a run
//! must agree on before any scan reads the program.

use std::path::Path;

use kuna_console::engine::{self, ConsoleProgram};

use crate::error::{KunaError, Result};
use crate::specs;

/// The Kuna release this build is pinned to. `build.rs` derives it from the
/// `kuna-base` pin in the workspace lock file, so the reported release and
/// the embedded specs always name the same checkout.
pub const KUNA_RELEASE: &str = env!("CALXGLOSS_KUNA_RELEASE");

/// A program loaded by the Kuna engine.
///
/// The loaded program stays inside: later tickets (#206 onward) read its
/// listings and p-code through this handle; this release reports identity.
pub struct KunaProgram {
    program: ConsoleProgram,
}

impl std::fmt::Debug for KunaProgram {
    /// Reports what the handle can report — the loaded program is opaque
    /// upstream, so the identity fields stand in.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KunaProgram")
            .field("identity", &self.identity())
            .field("entry", &self.entry())
            .field("symbols", &self.num_symbols())
            .finish()
    }
}

impl KunaProgram {
    /// The engine's identity line for the loaded program — the resolved
    /// language, e.g. `x86:LE:64:default`.
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
/// A failure is always [`KunaError::LoadFailed`] naming the path, Kuna's
/// own reason, and the `--engine ghidra` fallback — never a raw upstream
/// backtrace.
pub fn load(path: &Path) -> Result<KunaProgram> {
    let spec_root = specs::spec_root()?;
    let program = engine::bootstrap_from_object(&path.to_string_lossy(), "", &[spec_root])
        .map_err(|error| KunaError::LoadFailed {
            path: path.display().to_string(),
            reason: error.explain().to_string(),
        })?;
    Ok(KunaProgram { program })
}
