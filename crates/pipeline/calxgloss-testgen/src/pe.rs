//! PE image metadata needed to reach functions inside a Windows DLL.
//!
//! Baseline execution calls *internal* functions. The GhidraMCP plugin reports
//! those as virtual addresses, but they are absent from the export table, so
//! calling them requires three conversions:
//!
//! ```text
//!   Ghidra VA  --(subtract image_base)-->  RVA  --(add runtime base)-->  callable address
//! ```
//!
//! [`PeImage`] supplies the first conversion, plus enough of the import/export
//! tables to identify Windows API usage. Parsing is delegated to `goblin`.
//!
//! This module only reads bytes from disk and is host-independent, so it is
//! unit-testable on any platform, including Linux.

use std::collections::HashMap;
use std::path::Path;

use anyhow::{Context, Result, bail};
use goblin::pe::PE;
use goblin::pe::export::ExportAddressTableEntry;
use goblin::pe::header::{COFF_MACHINE_X86, COFF_MACHINE_X86_64};
use tracing::debug;

/// The target architecture of a PE image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Machine {
    /// 32-bit x86.
    X86,
    /// 64-bit x86.
    X86_64,
    /// Anything else.
    Other(u16),
}

impl Machine {
    /// The Rust target triple a baseline harness must be cross-compiled for.
    pub fn target_triple(self) -> &'static str {
        match self {
            Machine::X86 => "i686-pc-windows-gnu",
            Machine::X86_64 => "x86_64-pc-windows-gnu",
            Machine::Other(_) => "unknown",
        }
    }
}

/// A single exported symbol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportEntry {
    /// Export name, or empty when the symbol is exported by ordinal only.
    ///
    /// Plenty of DLLs export purely by ordinal, so an empty name is normal and
    /// not an error.
    pub name: String,
    /// The export's ordinal, including the ordinal base.
    pub ordinal: u32,
    /// Relative virtual address of the exported symbol.
    ///
    /// Meaningless for a forwarder; see [`is_forwarder`](Self::is_forwarder).
    pub rva: u32,
    /// True when this export forwards to another module.
    ///
    /// A forwarder's RVA points at a `"OTHER.dll.Symbol"` string, not at code,
    /// so it must never be called in-process.
    pub is_forwarder: bool,
}

/// A single imported symbol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportEntry {
    /// Name of the DLL the symbol is imported from.
    pub binary: String,
    /// Imported symbol name.
    ///
    /// Imports by ordinal with no hint/name entry are reported as
    /// `ORDINAL <n>`, mirroring what Ghidra calls `Ordinal_N`. Treating those
    /// as API identifiers is a false positive, so callers that tag Windows API
    /// usage should skip them via [`is_unnamed`](Self::is_unnamed).
    pub function: String,
}

impl ImportEntry {
    /// True when this import is by ordinal with no usable name.
    ///
    /// Such imports cannot be attributed to a named Windows API. eqmain.dll
    /// imports 20 of these from `WS2_32.dll` alone, where the ordinal actually
    /// does name a socket function, but nothing in the image records which.
    pub fn is_unnamed(&self) -> bool {
        self.function.starts_with("ORDINAL ") || self.function.starts_with("Ordinal_")
    }
}

/// A PE image, with the fields the baseline runner needs.
#[derive(Debug, Clone)]
pub struct PeImage {
    machine: Machine,
    image_base: u64,
    size_of_image: u32,
    image_end: u32,
    is_dll: bool,
    exports: Vec<ExportEntry>,
    exports_by_name: HashMap<String, u32>,
    exports_by_ordinal: HashMap<u32, u32>,
    imports: Vec<ImportEntry>,
    libraries: Vec<String>,
}

impl PeImage {
    /// Parse the PE headers of the image at `path`.
    ///
    /// Only headers and the import/export directories are read, so this is cheap
    /// even for a multi-megabyte DLL.
    pub fn parse(path: &Path) -> Result<Self> {
        let bytes = std::fs::read(path)
            .with_context(|| format!("Failed to read PE image at {}", path.display()))?;
        Self::parse_bytes(&bytes)
            .with_context(|| format!("Failed to parse PE image at {}", path.display()))
    }

    /// Parse a PE image from an in-memory buffer.
    pub fn parse_bytes(bytes: &[u8]) -> Result<Self> {
        let pe = PE::parse(bytes).context("Not a parseable PE image")?;

        let machine = match pe.header.coff_header.machine {
            COFF_MACHINE_X86 => Machine::X86,
            COFF_MACHINE_X86_64 => Machine::X86_64,
            other => Machine::Other(other),
        };

        // The mapped extent of the image, derived from the section table rather
        // than trusted from the header. This is what bounds an RVA: a value that
        // lands past the last section is not mapped and cannot be called.
        let image_end = pe
            .sections
            .iter()
            .map(|s| s.virtual_address + s.virtual_size.max(s.size_of_raw_data))
            .max()
            .unwrap_or(0);

        let size_of_image = pe
            .header
            .optional_header
            .as_ref()
            .map(|oh| oh.windows_fields.size_of_image)
            .unwrap_or(0);

        // The export address table is the authority on ordinals: slot `i` holds
        // ordinal `base + i`. goblin's `pe.exports` carries correct names and
        // RVAs but is *not* in address-table order, so ordinals cannot be
        // recovered from its position. Build the two views and join on RVA.
        let names_by_rva: HashMap<u32, &str> = pe
            .exports
            .iter()
            .filter_map(|e| e.name.map(|n| (e.rva as u32, n)))
            .collect();

        let (ordinal_base, address_table) = match &pe.export_data {
            Some(d) => (
                d.export_directory_table.ordinal_base,
                Some(&d.export_address_table),
            ),
            None => (1, None),
        };

        let exports: Vec<ExportEntry> = match address_table {
            // Walk the address table so ordinals are exact.
            Some(table) => table
                .iter()
                .enumerate()
                .map(|(i, entry)| {
                    let (rva, is_forwarder) = match entry {
                        ExportAddressTableEntry::ExportRVA(rva) => (*rva, false),
                        ExportAddressTableEntry::ForwarderRVA(rva) => (*rva, true),
                    };
                    ExportEntry {
                        name: names_by_rva
                            .get(&rva)
                            .copied()
                            .unwrap_or_default()
                            .to_string(),
                        ordinal: ordinal_base + i as u32,
                        rva,
                        is_forwarder,
                    }
                })
                // A zero RVA is a hole: the ordinal is reserved but exports nothing.
                .filter(|e| e.rva != 0)
                .collect(),
            // No export directory at all.
            None => Vec::new(),
        };

        let imports = pe
            .imports
            .iter()
            .map(|i| ImportEntry {
                binary: i.dll.to_string(),
                function: i.name.to_string(),
            })
            .collect();

        let mut image = PeImage {
            machine,
            image_base: pe.image_base,
            size_of_image,
            image_end,
            is_dll: pe.is_lib,
            exports: exports.clone(),
            exports_by_name: HashMap::new(),
            exports_by_ordinal: HashMap::new(),
            imports,
            libraries: pe.libraries.iter().map(|s| s.to_string()).collect(),
        };

        for e in &exports {
            if !e.name.is_empty() {
                image.exports_by_name.insert(e.name.clone(), e.rva);
            }
            // Forwarders are not callable in-process, so they are excluded from
            // ordinal lookup as well as by name.
            if !e.is_forwarder {
                image.exports_by_ordinal.insert(e.ordinal, e.rva);
            }
        }

        debug!(
            machine = ?image.machine,
            image_base = format_args!("0x{:x}", image.image_base),
            size_of_image = image.size_of_image,
            exports = image.exports.len(),
            imports = image.imports.len(),
            libraries = image.libraries.len(),
            "Parsed PE image"
        );
        Ok(image)
    }

    /// The target architecture.
    pub fn machine(&self) -> Machine {
        self.machine
    }

    /// The preferred load address declared in the optional header.
    ///
    /// This is the base Ghidra reports addresses against, which may differ from
    /// the address the module is actually loaded at once relocations apply.
    pub fn image_base(&self) -> u64 {
        self.image_base
    }

    /// `SizeOfImage` as declared in the optional header, in bytes.
    pub fn size_of_image(&self) -> u32 {
        self.size_of_image
    }

    /// True for a PE32+ (64-bit) image.
    pub fn is_64bit(&self) -> bool {
        matches!(self.machine, Machine::X86_64)
    }

    /// True when the image is flagged as a DLL.
    pub fn is_dll(&self) -> bool {
        self.is_dll
    }

    /// All exported symbols, in export-table order.
    pub fn exports(&self) -> &[ExportEntry] {
        &self.exports
    }

    /// All imported symbols, in import-table order.
    pub fn imports(&self) -> &[ImportEntry] {
        &self.imports
    }

    /// Names of every DLL this image imports from.
    pub fn libraries(&self) -> &[String] {
        &self.libraries
    }

    /// Imported symbols grouped by the DLL they come from.
    pub fn imports_by_dll(&self) -> HashMap<&str, Vec<&ImportEntry>> {
        let mut out: HashMap<&str, Vec<&ImportEntry>> = HashMap::new();
        for import in &self.imports {
            out.entry(import.binary.as_str()).or_default().push(import);
        }
        out
    }

    /// Convert a Ghidra virtual address to an RVA.
    ///
    /// Ghidra reports addresses at the image's preferred base, so the RVA is the
    /// offset from [`image_base`](Self::image_base).
    pub fn rva_from_va(&self, va: u64) -> Result<u32> {
        if va < self.image_base {
            bail!(
                "VA 0x{va:x} is below the image base 0x{:x} — is this a Ghidra address for this DLL?",
                self.image_base
            );
        }
        let rva = va - self.image_base;
        if rva > self.image_end as u64 {
            bail!(
                "RVA 0x{rva:x} (from VA 0x{va:x}) is outside the image, which is mapped \
                 to 0x{:x} bytes",
                self.image_end
            );
        }
        Ok(rva as u32)
    }

    /// Convert an RVA back to the Ghidra virtual address.
    pub fn va_from_rva(&self, rva: u32) -> u64 {
        self.image_base + rva as u64
    }

    /// Resolve an exported symbol by name to its RVA.
    pub fn export_rva_by_name(&self, name: &str) -> Result<u32> {
        self.exports_by_name
            .get(name)
            .copied()
            .with_context(|| format!("No export named '{name}' in this DLL"))
    }

    /// Resolve an exported symbol by ordinal to its RVA.
    pub fn export_rva_by_ordinal(&self, ordinal: u32) -> Result<u32> {
        self.exports_by_ordinal
            .get(&ordinal)
            .copied()
            .with_context(|| format!("No export with ordinal {ordinal} in this DLL"))
    }

    /// Look up an export by name, falling back to treating the name as an ordinal.
    ///
    /// This is what lets a caller that only knows a symbol string work against
    /// DLLs that export by ordinal only.
    pub fn resolve_symbol(&self, symbol: &str) -> Result<u32> {
        if let Ok(rva) = self.export_rva_by_name(symbol) {
            return Ok(rva);
        }
        if let Ok(ordinal) = symbol.parse::<u32>()
            && let Ok(rva) = self.export_rva_by_ordinal(ordinal)
        {
            return Ok(rva);
        }
        bail!(
            "'{symbol}' is not an export of this DLL (by name or ordinal); \
             non-exported functions must be addressed by VA/RVA"
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Path to a real DLL used by the opt-in integration test.
    fn real_dll() -> Option<std::path::PathBuf> {
        let path = std::env::var("CALXGLOSS_TEST_DLL").ok()?;
        let path = Path::new(&path);
        path.exists().then(|| path.to_path_buf())
    }

    fn synthetic() -> Option<PeImage> {
        // Reuse the opt-in real DLL when present; otherwise the unit tests that
        // need a concrete image are skipped rather than faked.
        real_dll().map(|p| PeImage::parse(&p).expect("parse real binary"))
    }

    #[test]
    fn test_rejects_non_pe() {
        assert!(PeImage::parse_bytes(b"not a pe file at all").is_err());
        assert!(PeImage::parse_bytes(&[]).is_err());
    }

    #[test]
    fn test_target_triples() {
        assert_eq!(Machine::X86_64.target_triple(), "x86_64-pc-windows-gnu");
        assert_eq!(Machine::X86.target_triple(), "i686-pc-windows-gnu");
        assert_eq!(Machine::Other(0xaa64).target_triple(), "unknown");
    }

    #[test]
    fn test_va_to_rva_roundtrip() {
        let Some(img) = synthetic() else { return };
        for rva in [0x0u32, 0xc690, 0x8ed50, 0x81be0] {
            assert_eq!(img.rva_from_va(img.va_from_rva(rva)).unwrap(), rva);
        }
    }

    #[test]
    fn test_rva_from_va_rejects_out_of_range() {
        let Some(img) = synthetic() else { return };
        // Below the image base.
        assert!(img.rva_from_va(img.image_base() - 1).is_err());
        // Beyond the mapped image.
        assert!(
            img.rva_from_va(img.image_base() + img.size_of_image() as u64)
                .is_err()
        );
    }

    #[test]
    fn test_resolve_symbol_prefers_name() {
        let Some(img) = synthetic() else { return };
        let Some(export) = img.exports().iter().find(|e| !e.name.is_empty()) else {
            return;
        };
        assert_eq!(img.resolve_symbol(&export.name).unwrap(), export.rva);
        // The ordinal, as a string, must reach the same place.
        assert_eq!(
            img.resolve_symbol(&export.ordinal.to_string()).unwrap(),
            export.rva
        );
    }

    #[test]
    fn test_resolve_symbol_rejects_internal_function() {
        let Some(img) = synthetic() else { return };
        // Ghidra's name for an internal function is never an export.
        assert!(img.resolve_symbol("FUN_18008ed50").is_err());
    }

    #[test]
    fn test_imports_group_by_dll() {
        let Some(img) = synthetic() else { return };
        let grouped = img.imports_by_dll();
        assert_eq!(
            grouped.values().map(Vec::len).sum::<usize>(),
            img.imports().len()
        );
        assert!(
            grouped
                .keys()
                .any(|d| d.to_lowercase().contains("kernel32"))
        );
    }

    #[test]
    fn test_unnamed_imports_are_flagged() {
        let Some(img) = synthetic() else { return };
        for import in img.imports() {
            if import.function.starts_with("ORDINAL ") {
                assert!(import.is_unnamed());
            } else {
                assert!(!import.is_unnamed());
            }
        }
    }

    /// Cross-checks the parser against a real DLL, confirming it agrees with what
    /// `objdump -p` and Ghidra report. Ignored by default because it needs a real
    /// file; eqmain.dll expectations are asserted below.
    ///
    /// ```text
    /// CALXGLOSS_TEST_DLL=/path/to/eqmain.dll cargo test -p calxgloss-testgen \
    ///     pe::tests::test_against_real_dll -- --ignored --nocapture
    /// ```
    #[test]
    #[ignore = "requires a real DLL path in CALXGLOSS_TEST_DLL"]
    fn test_against_real_dll() {
        let Some(path) = real_dll() else {
            eprintln!("CALXGLOSS_TEST_DLL not set or missing; nothing to check");
            return;
        };
        let img = PeImage::parse(&path).unwrap();
        println!("{}: {img:?}", path.display());
        println!("machine       : {:?}", img.machine());
        println!("image_base    : 0x{:x}", img.image_base());
        println!("size_of_image : 0x{:x}", img.size_of_image());
        println!("is_dll        : {}", img.is_dll());
        println!("exports       : {:?}", img.exports());
        println!("libraries     : {:?}", img.libraries());
        println!("imports (first 10):");
        for i in img.imports().iter().take(10) {
            println!("  {} :: {}", i.binary, i.function);
        }
    }

    /// Asserts the eqmain.dll facts this module was built against.
    ///
    /// ```text
    /// CALXGLOSS_TEST_DLL=/path/to/eqmain.dll cargo test -p calxgloss-testgen \
    ///     pe::tests::test_eqmain_expectations -- --ignored --nocapture
    /// ```
    #[test]
    #[ignore = "requires eqmain.dll at CALXGLOSS_TEST_DLL"]
    fn test_eqmain_expectations() {
        let Some(path) = real_dll() else { return };
        let img = PeImage::parse(&path).unwrap();

        // PE32+ x86-64, ImageBase 0x180000000 — matches `objdump -p`.
        assert!(img.is_64bit());
        assert_eq!(img.machine(), Machine::X86_64);
        assert_eq!(img.image_base(), 0x1_8000_0000);
        assert!(img.is_dll());

        // Ghidra addresses of the functions exercised during baseline probing.
        assert_eq!(img.rva_from_va(0x1_8008_ed50).unwrap(), 0x8ed50);
        assert_eq!(img.rva_from_va(0x1_8004_70a0).unwrap(), 0x470a0);
        assert_eq!(img.rva_from_va(0x1_8008_1be0).unwrap(), 0x81be0);

        // The export address table: ordinal 1 -> 0xc6a0, ordinal 2 -> 0xc690.
        assert_eq!(img.exports().len(), 2);
        assert_eq!(img.export_rva_by_ordinal(1).unwrap(), 0xc6a0);
        assert_eq!(img.export_rva_by_ordinal(2).unwrap(), 0xc690);
        assert_eq!(img.export_rva_by_name("new_dll_main").unwrap(), 0xc6a0);
        assert_eq!(img.export_rva_by_name("dll_main").unwrap(), 0xc690);

        // The function under test is internal, so it is not an export.
        assert!(img.resolve_symbol("FUN_18008ed50").is_err());
    }
}
