//! Error type for the test fixture crate.

use thiserror::Error;

/// Ways the fixture target binary can be missing or the wrong shape.
///
/// Each shape variant names the fixture element that an analysis engine
/// test relies on. So when the fixture stops compiling to the expected
/// shape, the failure names the missing element, instead of an analysis
/// engine test failing with an opaque parse error.
#[derive(Debug, Error)]
pub enum TestFixturesError {
    /// The cross-compiler was not on PATH when the build script ran, so the
    /// fixture target binary was never compiled.
    #[error(
        "cross-compiler `{compiler}` not found: the fixture target binary was never built; \
         install mingw-w64 or set CALXGLOSS_FIXTURE_CC and rebuild"
    )]
    ToolchainMissing {
        /// The compiler command the build script looked for.
        compiler: String,
    },
    /// The built fixture exists but could not be read from disk.
    #[error("failed to read fixture target binary at {path}")]
    Unreadable {
        /// Path the fixture was read from.
        path: String,
        /// Underlying I/O failure.
        #[source]
        source: std::io::Error,
    },
    /// The built fixture is not a parseable PE image.
    #[error("fixture target binary is not a parseable PE image")]
    NotPe(
        /// goblin's parse failure.
        #[source]
        goblin::error::Error,
    ),
    /// The built fixture is not an x86-64 DLL.
    #[error("fixture target binary is not an x86-64 DLL (machine {machine:#06x})")]
    NotX8664Dll {
        /// The machine the image actually declares.
        machine: u16,
    },
    /// A named export the analysis engine tests assert against is absent.
    #[error("fixture target is missing expected export `{name}`")]
    MissingExport {
        /// The export name that was not found.
        name: String,
    },
    /// An imported DLL the analysis engine tests assert against is absent.
    #[error("fixture target does not import from `{dll}`")]
    MissingImportDll {
        /// The DLL name that was not found in the import table.
        dll: String,
    },
    /// A named import the analysis engine tests assert against is absent.
    #[error("fixture target is missing expected import `{function}`")]
    MissingImportFunction {
        /// The imported function name that was not found.
        function: String,
    },
    /// A string literal the analysis engine's string scan must find is absent.
    #[error("fixture target does not contain string literal `{literal}`")]
    MissingStringLiteral {
        /// The literal that was not found.
        literal: String,
    },
    /// No jump table was found: no run of code-pointer entries in a
    /// read-only section is referenced by a rip-relative `lea` in code.
    #[error(
        "fixture target has no jump table: no run of {min}+ code-pointer entries \
         referenced from code was found in a read-only section"
    )]
    NoJumpTable {
        /// The minimum run length the fixture must exhibit.
        min: usize,
    },
}

/// Crate-wide result alias.
pub type Result<T> = std::result::Result<T, TestFixturesError>;
