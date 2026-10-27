//! Information about a target DLL and its classification.
//!
//! This module holds the DLL metadata collected during binary analysis:
//! exported and imported symbols, and the DLL's strategy category.

use serde::{Deserialize, Serialize};

use crate::identity::BinaryIdentity;

/// Classification of a DLL, determining the reverse-engineering strategy.
///
/// The category drives whether a DLL is replaced with a crate shim,
/// mapped via the PAL, or reverse-engineered from disassembly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DllCategory {
    /// Core Windows OS DLLs (`kernel32.dll`, `user32.dll`, etc.).
    /// Strategy: PAL mapping to std / winit / etc.
    WindowsOs,

    /// Official Microsoft SDK DLLs with known Rust crate equivalents.
    /// Strategy: crate replacement + shim layer.
    MicrosoftSdk,

    /// Known third-party libraries with existing Rust crate counterparts.
    /// Strategy: crate replacement + shim layer.
    KnownThirdParty,

    /// DLLs built from this project's own source code.
    /// Strategy: reverse engineer from disassembly.
    ProjectSpecific,

    /// Third-party DLLs with no known Rust crate equivalent.
    /// Strategy: reverse engineer from disassembly.
    UnknownThirdParty,

    /// Runtime library DLLs (e.g. `msvcr*.dll`, `msvbvm60.dll`, `Qt5*.dll`,
    /// `SDL2.dll`). These are not target binaries — their functions should be
    /// skipped during translation.
    RuntimeLibrary,

    /// .NET (managed) assemblies — PE files with a COM descriptor
    /// (data directory 14). They are not native machine code, so the
    /// disassembly pipeline has nothing to translate; we do not yet
    /// decompile managed code. Strategy: `DoNotTranslate` (issue #235).
    /// Distinct from [`Self::RuntimeLibrary`]: the `known_runtime` flag
    /// stays false for managed assemblies. That flag marks runtime
    /// libraries, not every binary that is out of translation scope.
    DotNetManaged,
}

/// An exported symbol from a DLL.
///
/// A function or data item that a DLL makes available to the binaries that
/// use it. The decompiler records the address and signature from the
/// import/export tables and the disassembly.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Export {
    /// The exported symbol's name (e.g., `DrawPrimitive`).
    pub name: String,

    /// The virtual address of the export within the DLL.
    pub address: u64,

    /// The function signature as inferred by the decompiler (e.g., `int __stdcall DrawPrimitive(...)`).
    pub signature: String,
}

/// An import dependency — a DLL and function this binary calls.
///
/// Each import comes from either the PE import table or the decompiler's
/// analysis of imported symbols.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Import {
    /// The name of the DLL being imported (e.g., `gdi32.dll`).
    pub binary: BinaryIdentity,

    /// The function name imported from that DLL (e.g., `BitBlt`).
    pub function: String,
}

/// Complete analysis information for a single DLL.
///
/// Aggregates classification, exports, and imports into a single struct
/// that can be serialized for storage or passed between pipeline stages.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DllInfo {
    /// The DLL filename (e.g., `game_logic.dll`).
    pub name: String,

    /// Optional version string from the DLL's version resource.
    pub version: Option<String>,

    /// Classification category that determines the reverse-engineering strategy.
    pub category: DllCategory,

    /// Whether this DLL is a known runtime library (e.g. `msvcr*.dll`, `msvbvm60.dll`,
    /// `Qt5*.dll`, `SDL2.dll`). Runtime library DLLs should be skipped during translation.
    pub known_runtime: bool,

    /// Exported symbols from this DLL.
    pub exports: Vec<Export>,

    /// DLLs and functions this DLL imports.
    pub imports: Vec<Import>,
}
