//! Information about a target DLL and its classification.
//!
//! This module provides types for representing DLL metadata extracted during
//! the binary analysis phase, including exported/imported symbols and
//! classification into strategy categories.

use serde::{Deserialize, Serialize};

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
}

/// An exported symbol from a DLL.
///
/// Represents a function or data item that a DLL exposes to its consumers.
/// During Ghidra analysis, the address and signature are extracted from
/// the import/export table and disassembly.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Export {
    /// The exported symbol's name (e.g., `DrawPrimitive`).
    pub name: String,

    /// The virtual address of the export within the DLL.
    pub address: u64,

    /// The function signature as inferred by Ghidra (e.g., `int __stdcall DrawPrimitive(...)`).
    pub signature: String,
}

/// An import dependency — a DLL and function this binary calls.
///
/// Represents a cross-DLL call captured from the PE import table or
/// Ghidra's analysis of imported symbols.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Import {
    /// The name of the DLL being imported (e.g., `gdi32.dll`).
    pub dll: String,

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
