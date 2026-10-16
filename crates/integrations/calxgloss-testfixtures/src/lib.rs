//! Checked-in test fixtures shared by the analysis engine test harnesses.
//!
//! The fixture target binary is a small x86-64 Windows PE DLL compiled from
//! `fixtures/fixture_target.c` by this crate's build script — built from
//! source as part of the test fixtures, with no manual steps and no
//! proprietary code. Its shape is the contract the Kuna engine tests (and
//! any future engine test) assert against: named exports, imports from two
//! DLLs, string literals, and a switch the compiler lowers to a jump table.
//!
//! [`load_target`] parses the built DLL and fails with a named error the
//! moment the fixture stops having that shape, so a broken fixture is
//! caught by this crate's smoke test rather than deep inside an engine test.
//! The fixture is reachable from the Integrations integration tests and the
//! web e2e harness as a dev-dependency; both keep a reachability test so the
//! wiring cannot rot.
//!
//! # Architecture
//!
//! - `error.rs` — `TestFixturesError` and the crate-wide `Result` alias.
//! - root — the fixture shape constants, `fixture_target_path` /
//!   `load_target`, and the parsed `FixtureTarget` view with its
//!   `ImportedFunction` and `JumpTable` records.

pub mod error;

pub use error::{Result, TestFixturesError};

use std::path::{Path, PathBuf};

use goblin::pe::PE;
use goblin::pe::header::COFF_MACHINE_X86_64;
use goblin::pe::section_table::IMAGE_SCN_MEM_EXECUTE;

/// File name of the built fixture inside the build script's `OUT_DIR`.
pub const TARGET_FILE_NAME: &str = "fixture_target.dll";

/// The named exports the fixture must carry.
pub const EXPORT_NAMES: &[&str] = &[
    "fixture_init",
    "fixture_status",
    "fixture_describe",
    "fixture_tick",
];

/// The DLLs the fixture must import from, as spelled in the import table.
pub const IMPORT_DLL_NAMES: &[&str] = &["KERNEL32.dll", "msvcrt.dll"];

/// The named imports the fixture must carry.
///
/// These are the functions the fixture source calls directly. `snprintf`
/// is deliberately absent: mingw implements it as a static wrapper that
/// bottoms out in `vfprintf`, so asserting on it would pin a wrapper detail
/// rather than the fixture's own import.
pub const IMPORT_FUNCTIONS: &[&str] = &[
    "GetTickCount",
    "OutputDebugStringA",
    "malloc",
    "free",
    "puts",
];

/// The string literals the engine's string scan must find in the image.
pub const STRING_LITERALS: &[&str] = &[
    "calxgloss fixture target: hello",
    "calxgloss-fixture-target-v1",
    "fixture counter %d",
];

/// Minimum run of code-pointer entries a jump table must exhibit.
///
/// The fixture's switch has 16 cases plus a default; a run this long cannot
/// occur by accident in a DLL this small.
pub const MIN_JUMP_TABLE_ENTRIES: usize = 16;

/// Path to the built fixture target binary.
///
/// The build script compiles the fixture into `OUT_DIR`; when the
/// cross-compiler was missing at build time the file is absent and this
/// reports [`TestFixturesError::ToolchainMissing`] naming the fix.
pub fn fixture_target_path() -> Result<PathBuf> {
    let path = Path::new(env!("OUT_DIR")).join(TARGET_FILE_NAME);
    if !path.exists() {
        return Err(TestFixturesError::ToolchainMissing {
            compiler: option_env!("CALXGLOSS_FIXTURE_CC")
                .unwrap_or("x86_64-w64-mingw32-gcc")
                .to_string(),
        });
    }
    Ok(path)
}

/// A single named import, as the engine tests see it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportedFunction {
    /// The DLL the symbol is imported from, as spelled in the import table.
    pub dll: String,
    /// The imported symbol name.
    pub function: String,
}

/// A jump table found in the fixture image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JumpTable {
    /// Name of the read-only section holding the table.
    pub section: String,
    /// RVA of the table's first entry.
    pub rva: u32,
    /// Number of consecutive code-pointer entries in the run.
    pub entries: usize,
}

/// The fixture target binary, parsed and validated against the shape the
/// engine tests rely on.
#[derive(Debug, Clone)]
pub struct FixtureTarget {
    path: PathBuf,
    image_base: u64,
    exports: Vec<String>,
    imports: Vec<ImportedFunction>,
    strings: Vec<String>,
    jump_table: JumpTable,
}

impl FixtureTarget {
    /// Path to the DLL on disk.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Preferred image base recorded in the optional header.
    pub fn image_base(&self) -> u64 {
        self.image_base
    }

    /// Named exports, in the order the export table lists them.
    pub fn exports(&self) -> &[String] {
        &self.exports
    }

    /// Named imports across all imported DLLs.
    pub fn imports(&self) -> &[ImportedFunction] {
        &self.imports
    }

    /// The fixture string literals found in the image.
    pub fn strings(&self) -> &[String] {
        &self.strings
    }

    /// The jump table the fixture's switch compiled to.
    pub fn jump_table(&self) -> &JumpTable {
        &self.jump_table
    }
}

/// Load the fixture target binary and validate its shape.
///
/// Every failure is a named [`TestFixturesError`] variant pointing at the
/// missing element, so a fixture regression says what broke instead of
/// failing an engine test with an opaque parse error.
pub fn load_target() -> Result<FixtureTarget> {
    let path = fixture_target_path()?;
    let bytes = std::fs::read(&path).map_err(|source| TestFixturesError::Unreadable {
        path: path.display().to_string(),
        source,
    })?;
    let pe = PE::parse(&bytes).map_err(TestFixturesError::NotPe)?;

    let machine = pe.header.coff_header.machine;
    if machine != COFF_MACHINE_X86_64 || !pe.is_lib {
        return Err(TestFixturesError::NotX8664Dll { machine });
    }

    let exports: Vec<String> = pe
        .exports
        .iter()
        .filter_map(|export| export.name.map(str::to_string))
        .collect();
    for expected in EXPORT_NAMES {
        if !exports.iter().any(|name| name == expected) {
            return Err(TestFixturesError::MissingExport {
                name: (*expected).to_string(),
            });
        }
    }

    let imports: Vec<ImportedFunction> = pe
        .imports
        .iter()
        .map(|import| ImportedFunction {
            dll: import.dll.to_string(),
            function: import.name.to_string(),
        })
        .collect();
    for dll in IMPORT_DLL_NAMES {
        if !imports
            .iter()
            .any(|import| import.dll.eq_ignore_ascii_case(dll))
        {
            return Err(TestFixturesError::MissingImportDll {
                dll: (*dll).to_string(),
            });
        }
    }
    for function in IMPORT_FUNCTIONS {
        if !imports.iter().any(|import| &import.function == function) {
            return Err(TestFixturesError::MissingImportFunction {
                function: (*function).to_string(),
            });
        }
    }

    let strings: Vec<String> = STRING_LITERALS
        .iter()
        .filter(|literal| contains_subslice(&bytes, literal.as_bytes()))
        .map(|literal| (*literal).to_string())
        .collect();
    for literal in STRING_LITERALS {
        if !strings.iter().any(|found| found == literal) {
            return Err(TestFixturesError::MissingStringLiteral {
                literal: (*literal).to_string(),
            });
        }
    }

    let jump_table = find_jump_table(&pe, &bytes).ok_or(TestFixturesError::NoJumpTable {
        min: MIN_JUMP_TABLE_ENTRIES,
    })?;

    let image_base = pe
        .header
        .optional_header
        .map(|header| header.windows_fields.image_base)
        .unwrap_or(0);

    Ok(FixtureTarget {
        path,
        image_base,
        exports,
        imports,
        strings,
        jump_table,
    })
}

/// True when `haystack` contains `needle` contiguously.
fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

/// Virtual address range `[start, end)` of an executable section.
struct CodeRange {
    start: u32,
    end: u32,
}

impl CodeRange {
    fn contains(&self, rva: u32) -> bool {
        self.start <= rva && rva < self.end
    }
}

/// Find the fixture's jump table: a run of [`MIN_JUMP_TABLE_ENTRIES`] or
/// more consecutive 4-byte entries in a non-executable section that name
/// code, with the table's start referenced by a rip-relative `lea` inside a
/// code section.
///
/// Entries are accepted in either spelling a compiler emits for a switch:
/// self-relative offsets from the entry itself (GCC/clang on Windows) or
/// absolute RVAs (MSVC).
fn find_jump_table(pe: &PE, bytes: &[u8]) -> Option<JumpTable> {
    let code: Vec<CodeRange> = pe
        .sections
        .iter()
        .filter(|section| section.characteristics & IMAGE_SCN_MEM_EXECUTE != 0)
        .map(|section| CodeRange {
            start: section.virtual_address,
            end: section.virtual_address + section.virtual_size.max(section.size_of_raw_data),
        })
        .collect();

    for section in pe
        .sections
        .iter()
        .filter(|section| section.characteristics & IMAGE_SCN_MEM_EXECUTE == 0)
    {
        // Only bytes present both in the file and in the mapped image can
        // hold table entries.
        let span = section.virtual_size.min(section.size_of_raw_data) as usize;
        let base = section.pointer_to_raw_data as usize;
        let section_va = section.virtual_address;

        let valid = |offset: usize| -> bool {
            let Some(raw) = bytes.get(base + offset..base + offset + 4) else {
                return false;
            };
            let value = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]);
            let entry_rva = section_va.wrapping_add(offset as u32);
            let relative = entry_rva.wrapping_add((value as i32) as u32);
            code.iter()
                .any(|range| range.contains(relative) || range.contains(value))
        };

        let mut offset = 0;
        while offset + 4 <= span {
            if !valid(offset) {
                offset += 4;
                continue;
            }
            let start = offset;
            let mut run = 0;
            while offset + 4 <= span && valid(offset) {
                offset += 4;
                run += 1;
            }
            if run >= MIN_JUMP_TABLE_ENTRIES {
                let table_rva = section_va.wrapping_add(start as u32);
                if referenced_by_rip_relative_lea(&pe.sections, bytes, table_rva) {
                    return Some(JumpTable {
                        section: section.name().ok()?.to_string(),
                        rva: table_rva,
                        entries: run,
                    });
                }
            }
        }
    }
    None
}

/// True when a code section loads `table_rva` with a rip-relative `lea`
/// (`48 8D <modrm>` with mod=00, rm=101): the compiler's table-address
/// setup that every switch lowering through a memory table carries.
fn referenced_by_rip_relative_lea(
    sections: &[goblin::pe::section_table::SectionTable],
    bytes: &[u8],
    table_rva: u32,
) -> bool {
    for section in sections
        .iter()
        .filter(|section| section.characteristics & IMAGE_SCN_MEM_EXECUTE != 0)
    {
        let base = section.pointer_to_raw_data as usize;
        let section_va = section.virtual_address;
        let span = section.virtual_size.min(section.size_of_raw_data) as usize;
        for offset in 0..span.saturating_sub(6) {
            let window = match bytes.get(base + offset..base + offset + 7) {
                Some(window) => window,
                None => break,
            };
            // REX.W lea, rip-relative ModRM (mod=00, rm=101; reg is any).
            if window[0] != 0x48 || window[1] != 0x8D || window[2] & 0xC7 != 0x05 {
                continue;
            }
            let disp = i32::from_le_bytes([window[3], window[4], window[5], window[6]]);
            let next_insn = section_va.wrapping_add(offset as u32 + 7);
            if next_insn.wrapping_add(disp as u32) == table_rva {
                return true;
            }
        }
    }
    false
}
