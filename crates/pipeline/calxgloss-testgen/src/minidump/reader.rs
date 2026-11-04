//! A minidump read the way a binary ninja headless script reads one:
//! against the published `MDMP` file format, never against any test's
//! idea of what a dump should contain.
//!
//! The published format is a header naming a stream directory; the
//! directory names typed streams. This reader pulls out the five the
//! minidump lane needs — module list, thread list, exception, system
//! info, and memory list — and leaves the rest (unloaded modules,
//! handle data, the rest) unread. Malformed or unsupported input is
//! refused with a message naming what was found; a dump with no
//! exception stream parses fine, it simply never faults.

use anyhow::{Result, anyhow, bail};

/// A stream the file says it carries.
mod stream {
    pub const THREAD_LIST: u32 = 3;
    pub const MODULE_LIST: u32 = 4;
    pub const MEMORY_LIST: u32 = 5;
    pub const EXCEPTION: u32 = 6;
    pub const SYSTEM_INFO: u32 = 7;
}

/// `IMAGE_FILE_MACHINE_AMD64`, the only architecture whose machine
/// context this reader decodes.
pub const AMD64: u16 = 9;

/// The published `MINIDUMP_MODULE` entry size.
const MODULE_ENTRY_SIZE: usize = 112;
/// The published `MINIDUMP_THREAD` entry size.
const THREAD_ENTRY_SIZE: usize = 56;
/// The fixed part of a `MINIDUMP_EXCEPTION_STREAM` — the thread id,
/// the exception record (code, flags, nested record, fault address,
/// parameter count, fifteen parameter slots), and the context
/// descriptor.
const EXCEPTION_HEAD_SIZE: usize = 168;

/// A module the dump saw loaded: its full path, where the image was
/// mapped, its mapped size, and the two identity stamps a crash reader
/// compares against a target PE.
#[derive(Debug, Clone)]
pub struct MinidumpModule {
    pub name: String,
    pub base_of_image: u64,
    pub size_of_image: u32,
    pub time_date_stamp: u32,
    pub checksum: u32,
}

impl MinidumpModule {
    /// The last path component, whatever the separator style, lowered —
    /// how a dump's loaded path names the same file the harness names.
    pub fn basename(&self) -> String {
        self.name
            .rsplit(['/', '\\'])
            .next()
            .unwrap_or(&self.name)
            .to_ascii_lowercase()
    }
}

/// One AMD64 `CONTEXT`'s general registers and instruction pointer,
/// decoded from the blob a thread carries.
#[derive(Debug, Clone, Copy, Default)]
pub struct X64Context {
    pub rax: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rbx: u64,
    pub rsp: u64,
    pub rbp: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
}

/// A thread the dump captured, with its machine context when one was
/// attached.
#[derive(Debug, Clone)]
pub struct MinidumpThread {
    pub id: u32,
    pub context: Option<X64Context>,
    /// The stack range the dump captured, and the bytes it stored for
    /// it — empty when the dump captured no stack.
    stack_start: u64,
    stack: Vec<u8>,
}

impl MinidumpThread {
    /// The thread's captured stack bytes, sitting at `stack_start`.
    pub fn stack(&self) -> (u64, &[u8]) {
        (self.stack_start, &self.stack)
    }
}

/// The exception a dump carries: the faulting thread, the exception
/// code, the address the fault happened at, and the context captured
/// with the record.
#[derive(Debug, Clone)]
pub struct MinidumpException {
    pub thread_id: u32,
    pub code: u32,
    pub fault_address: u64,
    pub context: Option<X64Context>,
}

/// A crash dump parsed from its bytes.
#[derive(Debug, Clone, Default)]
pub struct Minidump {
    modules: Vec<MinidumpModule>,
    threads: Vec<MinidumpThread>,
    exception: Option<MinidumpException>,
    /// The processor architecture the dump's system-info stream names;
    /// `None` when the file carries no such stream.
    pub processor_architecture: Option<u16>,
    /// Captured memory ranges by start address, for answering "what
    /// bytes does this dump hold at that address".
    memory: Vec<(u64, Vec<u8>)>,
}

impl Minidump {
    /// Parse the bytes of a `.dmp` file. A file that does not open with
    /// the `MDMP` signature is refused by name — an ELF core is said
    /// to be an ELF core, out of scope for this lane.
    pub fn parse_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() >= 4 && bytes[0..4] == *b"\x7fELF" {
            bail!(
                "ELF core: the minidump lane mines Windows minidumps; Linux ELF cores are out of scope"
            );
        }
        if bytes.len() < 32 || bytes[0..4] != *b"MDMP" {
            bail!(
                "not a minidump: file opens with {:02x?}, not the MDMP signature",
                &bytes[0..bytes.len().min(4)]
            );
        }
        let version = u32_at(bytes, 4).ok_or_else(|| anyhow!("minidump header is truncated"))?;
        if version & 0xFFFF != 0xA000 {
            bail!(
                "not a minidump: stream-directory version {version:#08x} is not the \
                 minidump 0xa000"
            );
        }
        let stream_count =
            u32_at(bytes, 8).ok_or_else(|| anyhow!("minidump header is truncated"))? as usize;
        let directory_rva =
            u32_at(bytes, 12).ok_or_else(|| anyhow!("minidump header is truncated"))? as usize;

        let mut modules = Vec::new();
        let mut threads = Vec::new();
        let mut exception = None;
        let mut architecture = None;
        let mut memory = Vec::new();
        for entry in 0..stream_count {
            let at = directory_rva + 12 * entry;
            let (kind, size, rva) = read_directory_entry(bytes, at)?;
            let body = slice(bytes, rva, size)
                .ok_or_else(|| anyhow!("minidump stream {kind} points outside the file"))?;
            match kind {
                stream::MODULE_LIST => modules = read_modules(bytes, body)?,
                stream::THREAD_LIST => threads = read_threads(bytes, body)?,
                stream::EXCEPTION => exception = Some(read_exception(bytes, body)?),
                stream::SYSTEM_INFO => {
                    if let Some(value) = u16_at(body, 0) {
                        architecture = Some(value);
                    }
                }
                stream::MEMORY_LIST => memory = read_memory_ranges(bytes, body)?,
                _ => {}
            }
        }

        let mut dump = Minidump {
            modules,
            threads,
            exception,
            processor_architecture: architecture,
            memory,
        };
        dump.threads.sort_by_key(|thread| thread.id);
        dump.modules.sort_by_key(|module| module.base_of_image);
        Ok(dump)
    }

    /// The modules the dump saw loaded.
    pub fn modules(&self) -> &[MinidumpModule] {
        &self.modules
    }

    /// The threads the dump captured, ordered by thread id.
    pub fn threads(&self) -> &[MinidumpThread] {
        &self.threads
    }

    /// The thread with that id.
    pub fn thread(&self, id: u32) -> Option<&MinidumpThread> {
        self.threads.iter().find(|thread| thread.id == id)
    }

    /// The exception the dump carries, when it carries one.
    pub fn exception(&self) -> Option<&MinidumpException> {
        self.exception.as_ref()
    }

    /// The module whose mapped range holds that address.
    pub fn module_at(&self, va: u64) -> Option<&MinidumpModule> {
        self.modules.iter().find(|module| {
            (module.base_of_image..module.base_of_image + u64::from(module.size_of_image))
                .contains(&va)
        })
    }

    /// The bytes the dump holds at that address, from the address to
    /// the end of the captured range — a window, not a promise of a
    /// fixed size. None when the dump holds nothing there.
    pub fn memory_window(&self, va: u64) -> Option<&[u8]> {
        // Ranges can be large; scan for the one containing the address.
        self.memory
            .iter()
            .find(|(start, bytes)| (*start..*start + bytes.len() as u64).contains(&va))
            .map(|(start, bytes)| &bytes[(va - start) as usize..])
    }
}

/// The bounded little-endian reads every stream decode goes through:
/// the file answers when its bytes are there, and a stream that
/// claims past the end comes back as `None` for the caller to refuse
/// by name.
fn u16_at(bytes: &[u8], at: usize) -> Option<u16> {
    let end = at.checked_add(2)?;
    Some(u16::from_le_bytes(bytes.get(at..end)?.try_into().ok()?))
}

fn u32_at(bytes: &[u8], at: usize) -> Option<u32> {
    let end = at.checked_add(4)?;
    Some(u32::from_le_bytes(bytes.get(at..end)?.try_into().ok()?))
}

fn u64_at(bytes: &[u8], at: usize) -> Option<u64> {
    let end = at.checked_add(8)?;
    Some(u64::from_le_bytes(bytes.get(at..end)?.try_into().ok()?))
}

fn read_directory_entry(bytes: &[u8], at: usize) -> Result<(u32, usize, usize)> {
    let outside = || anyhow!("minidump stream directory points outside the file");
    let kind = u32_at(bytes, at).ok_or_else(outside)?;
    let size = u32_at(bytes, at + 4).ok_or_else(outside)? as usize;
    let rva = u32_at(bytes, at + 8).ok_or_else(outside)? as usize;
    Ok((kind, size, rva))
}

fn read_modules(bytes: &[u8], body: &[u8]) -> Result<Vec<MinidumpModule>> {
    let count = u32_at(body, 0).ok_or_else(|| anyhow!("truncated module list"))? as usize;
    let mut modules = Vec::new();
    for index in 0..count {
        let entry = slice(body, 4 + MODULE_ENTRY_SIZE * index, MODULE_ENTRY_SIZE)
            .ok_or_else(|| anyhow!("module list entry points outside the stream"))?;
        let base_of_image =
            u64_at(entry, 0).ok_or_else(|| anyhow!("truncated module list entry"))?;
        let size_of_image =
            u32_at(entry, 8).ok_or_else(|| anyhow!("truncated module list entry"))?;
        let checksum = u32_at(entry, 12).ok_or_else(|| anyhow!("truncated module list entry"))?;
        let time_date_stamp =
            u32_at(entry, 16).ok_or_else(|| anyhow!("truncated module list entry"))?;
        let name_rva =
            u32_at(entry, 20).ok_or_else(|| anyhow!("truncated module list entry"))? as usize;
        let name = read_minidump_string(bytes, name_rva)?;
        modules.push(MinidumpModule {
            name,
            base_of_image,
            size_of_image,
            time_date_stamp,
            checksum,
        });
    }
    Ok(modules)
}

fn read_threads(bytes: &[u8], body: &[u8]) -> Result<Vec<MinidumpThread>> {
    let count = u32_at(body, 0).ok_or_else(|| anyhow!("truncated thread list"))? as usize;
    let mut threads = Vec::new();
    for index in 0..count {
        let entry = slice(body, 4 + THREAD_ENTRY_SIZE * index, THREAD_ENTRY_SIZE)
            .ok_or_else(|| anyhow!("thread list entry points outside the stream"))?;
        let id = u32_at(entry, 0).ok_or_else(|| anyhow!("truncated thread list entry"))?;
        // MINIDUMP_THREAD: id, suspend count, a memory descriptor, the
        // TeB, the stack memory descriptor, the context location
        // descriptor.
        let stack_start =
            u64_at(entry, 32).ok_or_else(|| anyhow!("truncated thread list entry"))?;
        let stack_size =
            u32_at(entry, 40).ok_or_else(|| anyhow!("truncated thread list entry"))? as usize;
        let stack_rva =
            u32_at(entry, 44).ok_or_else(|| anyhow!("truncated thread list entry"))? as usize;
        let stack = slice(bytes, stack_rva, stack_size).unwrap_or(&[]).to_vec();
        let context_size =
            u32_at(entry, 48).ok_or_else(|| anyhow!("truncated thread list entry"))? as usize;
        let context_rva =
            u32_at(entry, 52).ok_or_else(|| anyhow!("truncated thread list entry"))? as usize;
        let context = read_context(slice(bytes, context_rva, context_size));
        threads.push(MinidumpThread {
            id,
            context,
            stack_start,
            stack,
        });
    }
    Ok(threads)
}

fn read_exception(bytes: &[u8], body: &[u8]) -> Result<MinidumpException> {
    if body.len() < EXCEPTION_HEAD_SIZE {
        bail!("exception stream shorter than its fixed head");
    }
    let head = || anyhow!("truncated exception record");
    let thread_id = u32_at(body, 0).ok_or_else(head)?;
    let code = u32_at(body, 8).ok_or_else(head)?;
    let fault_address = u64_at(body, 24).ok_or_else(head)?;
    let context_size = u32_at(body, 160).ok_or_else(head)? as usize;
    let context_rva = u32_at(body, 164).ok_or_else(head)? as usize;
    let context = read_context(slice(bytes, context_rva, context_size));
    Ok(MinidumpException {
        thread_id,
        code,
        fault_address,
        context,
    })
}

/// `winnt.h` AMD64 `CONTEXT` field offsets.
mod context_offsets {
    pub const RAX: usize = 0x78;
    pub const RCX: usize = 0x80;
    pub const RDX: usize = 0x88;
    pub const RBX: usize = 0x90;
    pub const RSP: usize = 0x98;
    pub const RBP: usize = 0xA0;
    pub const RSI: usize = 0xA8;
    pub const RDI: usize = 0xB0;
    pub const R8: usize = 0xB8;
    pub const R9: usize = 0xC0;
    pub const R10: usize = 0xC8;
    pub const R11: usize = 0xD0;
    pub const R12: usize = 0xD8;
    pub const R13: usize = 0xE0;
    pub const R14: usize = 0xE8;
    pub const R15: usize = 0xF0;
    pub const RIP: usize = 0xF8;
}

fn read_context(blob: Option<&[u8]>) -> Option<X64Context> {
    let blob = blob?;
    if blob.len() < 0x100 {
        return None;
    }
    use context_offsets::*;
    Some(X64Context {
        rax: u64_at(blob, RAX)?,
        rcx: u64_at(blob, RCX)?,
        rdx: u64_at(blob, RDX)?,
        rbx: u64_at(blob, RBX)?,
        rsp: u64_at(blob, RSP)?,
        rbp: u64_at(blob, RBP)?,
        rsi: u64_at(blob, RSI)?,
        rdi: u64_at(blob, RDI)?,
        r8: u64_at(blob, R8)?,
        r9: u64_at(blob, R9)?,
        r10: u64_at(blob, R10)?,
        r11: u64_at(blob, R11)?,
        r12: u64_at(blob, R12)?,
        r13: u64_at(blob, R13)?,
        r14: u64_at(blob, R14)?,
        r15: u64_at(blob, R15)?,
        rip: u64_at(blob, RIP)?,
    })
}

fn read_memory_ranges(bytes: &[u8], body: &[u8]) -> Result<Vec<(u64, Vec<u8>)>> {
    let count = u32_at(body, 0).ok_or_else(|| anyhow!("truncated memory list"))? as usize;
    let mut ranges = Vec::new();
    for index in 0..count {
        let entry = slice(body, 4 + 16 * index, 16)
            .ok_or_else(|| anyhow!("memory list entry points outside the stream"))?;
        let start = u64_at(entry, 0).ok_or_else(|| anyhow!("truncated memory list entry"))?;
        let size = u32_at(entry, 8).ok_or_else(|| anyhow!("truncated memory list entry"))? as usize;
        let rva = u32_at(entry, 12).ok_or_else(|| anyhow!("truncated memory list entry"))? as usize;
        let stored = slice(bytes, rva, size)
            .ok_or_else(|| anyhow!("memory range {start:#x} points outside the file"))?;
        ranges.push((start, stored.to_vec()));
    }
    Ok(ranges)
}

fn read_minidump_string(bytes: &[u8], rva: usize) -> Result<String> {
    let header =
        slice(bytes, rva, 4).ok_or_else(|| anyhow!("module name points outside the file"))?;
    let len = u32_at(header, 0).ok_or_else(|| anyhow!("truncated module name"))? as usize;
    let body = slice(bytes, rva + 4, len)
        .ok_or_else(|| anyhow!("module name string points outside the file"))?;
    let units: Vec<u16> = body
        .chunks(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair.get(1).copied().unwrap_or(0)]))
        .collect();
    String::from_utf16(&units).map_err(|_| anyhow!("module name is not valid UTF-16"))
}

fn slice(bytes: &[u8], rva: usize, len: usize) -> Option<&[u8]> {
    bytes.get(rva..rva.checked_add(len)?)
}
