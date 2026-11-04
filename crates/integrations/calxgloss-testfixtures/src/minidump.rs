//! Hand-assembled Windows minidump fixtures (P23.7, issue #401).
//!
//! A `MinidumpBuilder` synthesizes a `MDMP` file — header, stream
//! directory, module list, thread list with per-thread AMD64 machine
//! context, exception stream, and memory list — from the parts a test
//! names. The bytes it writes follow the published minidump format, so a
//! reader built against these fixtures is built against the real shape;
//! nothing here mirrors a reader's internals.
//!
//! The AMD64 `CONTEXT` blob follows the `winnt.h` layout: the home
//! registers at 0x00, context flags at 0x30, the segment and debug
//! registers up to 0x78, the general registers from 0x78, and `RIP` at
//! 0xF8. Only the fields a real dump carries matter to these fixtures;
//! the rest stay zero.

/// One AMD64 `CONTEXT`'s general registers, named, as a test wants them.
/// The zero default is a real dump's unset register, not a stand-in.
#[derive(Debug, Clone, Copy, Default)]
pub struct ContextBytes {
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

/// `winnt.h` AMD64 `CONTEXT` field offsets, hand-worked from the
/// published structure — the fixture's own arithmetic, not any reader's.
mod ctx_off {
    pub const CONTEXT_FLAGS: usize = 0x30;
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
    pub const SIZE: usize = 0x2D0;
}

impl ContextBytes {
    /// The blob as a dump's `ThreadContext` carries it: the whole AMD64
    /// `CONTEXT` frame, the named registers at their published offsets,
    /// everything else zero.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut blob = vec![0u8; ctx_off::SIZE];
        let mut put = |offset: usize, value: u64| {
            blob[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        };
        put(ctx_off::RAX, self.rax);
        put(ctx_off::RCX, self.rcx);
        put(ctx_off::RDX, self.rdx);
        put(ctx_off::RBX, self.rbx);
        put(ctx_off::RSP, self.rsp);
        put(ctx_off::RBP, self.rbp);
        put(ctx_off::RSI, self.rsi);
        put(ctx_off::RDI, self.rdi);
        put(ctx_off::R8, self.r8);
        put(ctx_off::R9, self.r9);
        put(ctx_off::R10, self.r10);
        put(ctx_off::R11, self.r11);
        put(ctx_off::R12, self.r12);
        put(ctx_off::R13, self.r13);
        put(ctx_off::R14, self.r14);
        put(ctx_off::R15, self.r15);
        put(ctx_off::RIP, self.rip);
        // A context-flag word saying the control and integer registers
        // were captured: CONTEXT_AMD64 | CONTEXT_CONTROL | CONTEXT_INTEGER.
        blob[ctx_off::CONTEXT_FLAGS..ctx_off::CONTEXT_FLAGS + 4]
            .copy_from_slice(&0x0010_0063u32.to_le_bytes());
        blob
    }
}

struct ModuleSpec {
    name: String,
    base: u64,
    size_of_image: u32,
    time_date_stamp: u32,
    checksum: u32,
}

struct ThreadSpec {
    id: u32,
    stack_start: u64,
    stack: Vec<u8>,
    context: ContextBytes,
}

struct ExceptionSpec {
    thread_id: u32,
    code: u32,
    fault_address: u64,
    context: Option<ContextBytes>,
}

struct MemorySpec {
    start: u64,
    bytes: Vec<u8>,
}

/// A dump under assembly: the streams a test arms.
#[derive(Default)]
pub struct MinidumpBuilder {
    modules: Vec<ModuleSpec>,
    threads: Vec<ThreadSpec>,
    exception: Option<ExceptionSpec>,
    memory: Vec<MemorySpec>,
    processor_architecture: Option<u16>,
}

/// Stream type constants of the published minidump format.
mod stream {
    pub const THREAD_LIST: u32 = 3;
    pub const MODULE_LIST: u32 = 4;
    pub const MEMORY_LIST: u32 = 5;
    pub const EXCEPTION: u32 = 6;
    pub const SYSTEM_INFO: u32 = 7;
}

/// A MINIDUMP_MODULE entry: 8 + 4 + 4 + 4 + 4 address words, a 56-byte
/// VS_FIXEDFILEINFO, two 8-byte location descriptors, two reserved words.
const MODULE_ENTRY_SIZE: usize = 112;
/// A MINIDUMP_THREAD entry: six words, a TeB descriptor (8), a stack
/// memory descriptor (16), and a ThreadContext descriptor (8).
const THREAD_ENTRY_SIZE: usize = 56;
/// The fixed part of a MINIDUMP_EXCEPTION_STREAM.
const EXCEPTION_HEAD_SIZE: usize = 168;

impl MinidumpBuilder {
    /// A new dump with no streams armed.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a module: its loaded path, base of image, mapped size, and
    /// the identity stamp a crash reader compares against a target.
    pub fn module(
        mut self,
        name: impl Into<String>,
        base: u64,
        size_of_image: u32,
        time_date_stamp: u32,
    ) -> Self {
        self.modules.push(ModuleSpec {
            name: name.into(),
            base,
            size_of_image,
            time_date_stamp,
            checksum: 0,
        });
        self
    }

    /// Add a thread with its machine context and the stack bytes the
    /// dump captured, sitting at `stack_start`.
    pub fn thread(
        mut self,
        id: u32,
        context: ContextBytes,
        stack_start: u64,
        stack: impl Into<Vec<u8>>,
    ) -> Self {
        self.threads.push(ThreadSpec {
            id,
            stack_start,
            stack: stack.into(),
            context,
        });
        self
    }

    /// Arm the exception stream: the faulting thread, the exception
    /// code, the fault address, and the context captured with the
    /// exception record.
    pub fn exception_with_context(
        mut self,
        thread_id: u32,
        code: u32,
        fault_address: u64,
        context: ContextBytes,
    ) -> Self {
        self.exception = Some(ExceptionSpec {
            thread_id,
            code,
            fault_address,
            context: Some(context),
        });
        self
    }

    /// Arm the exception stream with no context of its own — the shape
    /// some writers use when the thread list's context is the live one.
    pub fn exception(mut self, thread_id: u32, code: u32, fault_address: u64) -> Self {
        self.exception = Some(ExceptionSpec {
            thread_id,
            code,
            fault_address,
            context: None,
        });
        self
    }

    /// Add a captured memory range: the range's start address and its
    /// bytes, as the dump's memory list carries them.
    pub fn memory(mut self, start: u64, bytes: impl Into<Vec<u8>>) -> Self {
        self.memory.push(MemorySpec {
            start,
            bytes: bytes.into(),
        });
        self
    }

    /// Stamp the system-info stream's processor architecture: 0 for x86,
    /// 9 for AMD64. A dump with no system-info stream sets nothing.
    pub fn processor_architecture(mut self, architecture: u16) -> Self {
        self.processor_architecture = Some(architecture);
        self
    }

    /// Lay the armed streams out into a complete `MDMP` file's bytes.
    pub fn build(&self) -> Vec<u8> {
        // Pass one sizes every part, so pass two resolves every RVA.
        let context_blobs: Vec<Vec<u8>> = self
            .threads
            .iter()
            .map(|thread| thread.context.to_bytes())
            .collect();
        let exception_blob = self
            .exception
            .as_ref()
            .and_then(|exception| exception.context.as_ref())
            .map(|context| context.to_bytes());
        let strings: Vec<Vec<u8>> = self
            .modules
            .iter()
            .map(|m| minidump_string(&m.name))
            .collect();

        let thread_stream_len = 4
            + THREAD_ENTRY_SIZE * self.threads.len()
            + context_blobs.iter().map(Vec::len).sum::<usize>()
            + self.threads.iter().map(|t| t.stack.len()).sum::<usize>();
        let module_stream_len = 4 + MODULE_ENTRY_SIZE * self.modules.len();
        let memory_stream_len =
            4 + 16 * self.memory.len() + self.memory.iter().map(|m| m.bytes.len()).sum::<usize>();
        let exception_stream_len = if self.exception.is_some() {
            EXCEPTION_HEAD_SIZE
                + match &exception_blob {
                    Some(blob) => blob.len(),
                    None => 0,
                }
        } else {
            0
        };
        let system_info_len = if self.processor_architecture.is_some() {
            36
        } else {
            0
        };

        let directory_entries = 3
            + usize::from(self.exception.is_some())
            + usize::from(self.processor_architecture.is_some());
        let header_size = 32usize;
        let streams_at = header_size + 12 * directory_entries;

        let mut cursor = streams_at;
        let thread_stream_rva = cursor;
        cursor += thread_stream_len;
        let module_stream_rva = cursor;
        cursor += module_stream_len;
        let memory_stream_rva = cursor;
        cursor += memory_stream_len;
        let exception_stream_rva = cursor;
        if self.exception.is_some() {
            cursor += exception_stream_len;
        }
        if self.processor_architecture.is_some() {
            cursor += system_info_len;
        }
        let string_rvas: Vec<u32> = strings
            .iter()
            .map(|string| {
                let at = cursor as u32;
                cursor += string.len();
                at
            })
            .collect();

        // Pass two: header, directory, streams, name strings.
        let mut out: Vec<u8> = Vec::with_capacity(cursor);
        out.extend_from_slice(b"MDMP");
        out.extend_from_slice(&0x0000_a000u32.to_le_bytes());
        out.extend_from_slice(&(directory_entries as u32).to_le_bytes());
        out.extend_from_slice(&(header_size as u32).to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes()); // checksum
        out.extend_from_slice(&0u32.to_le_bytes()); // timestamp slot
        out.extend_from_slice(&0u64.to_le_bytes()); // reserved word
        let mut directory = |kind: u32, len: usize, rva: usize| {
            out.extend_from_slice(&kind.to_le_bytes());
            out.extend_from_slice(&(len as u32).to_le_bytes());
            out.extend_from_slice(&(rva as u32).to_le_bytes());
        };
        directory(stream::THREAD_LIST, thread_stream_len, thread_stream_rva);
        directory(stream::MODULE_LIST, module_stream_len, module_stream_rva);
        directory(stream::MEMORY_LIST, memory_stream_len, memory_stream_rva);
        if self.exception.is_some() {
            directory(
                stream::EXCEPTION,
                exception_stream_len,
                exception_stream_rva,
            );
        }
        if self.processor_architecture.is_some() {
            directory(
                stream::SYSTEM_INFO,
                system_info_len,
                exception_stream_rva + exception_stream_len,
            );
        }

        // The thread list: entries first, then the context blobs and
        // stack bytes the descriptors resolve to.
        out.extend_from_slice(&(self.threads.len() as u32).to_le_bytes());
        let contexts_at = thread_stream_rva + 4 + THREAD_ENTRY_SIZE * self.threads.len();
        let mut context_offsets = Vec::with_capacity(self.threads.len());
        let mut at = contexts_at;
        for blob in &context_blobs {
            context_offsets.push(at as u32);
            at += blob.len();
        }
        let stacks_at = at;
        let mut stack_offsets = Vec::with_capacity(self.threads.len());
        let mut at = stacks_at;
        for thread in &self.threads {
            stack_offsets.push(at as u32);
            at += thread.stack.len();
        }
        for (thread, (context_rva, stack_rva)) in self
            .threads
            .iter()
            .zip(context_offsets.iter().zip(&stack_offsets))
        {
            out.extend_from_slice(&thread.id.to_le_bytes());
            out.extend_from_slice(&[0u8; 20]); // flags, terminate, suspend, priorities
            out.extend_from_slice(&[0u8; 8]); // TeB descriptor: absent
            out.extend_from_slice(&thread.stack_start.to_le_bytes());
            out.extend_from_slice(&(thread.stack.len() as u32).to_le_bytes());
            out.extend_from_slice(&stack_rva.to_le_bytes());
            out.extend_from_slice(&(ctx_off::SIZE as u32).to_le_bytes());
            out.extend_from_slice(&context_rva.to_le_bytes());
        }
        for blob in &context_blobs {
            out.extend_from_slice(blob);
        }
        for thread in &self.threads {
            out.extend_from_slice(&thread.stack);
        }

        // The module list, name-string RVAs resolved.
        out.extend_from_slice(&(self.modules.len() as u32).to_le_bytes());
        for (module, string_rva) in self.modules.iter().zip(&string_rvas) {
            out.extend_from_slice(&module.base.to_le_bytes());
            out.extend_from_slice(&module.size_of_image.to_le_bytes());
            out.extend_from_slice(&module.checksum.to_le_bytes());
            out.extend_from_slice(&module.time_date_stamp.to_le_bytes());
            out.extend_from_slice(&string_rva.to_le_bytes());
            // VS_FIXEDFILEINFO VersionInfo: signature and structure
            // version only, everything else zero.
            out.extend_from_slice(&0xFEEF_04BDu32.to_le_bytes());
            out.extend_from_slice(&0x0001_0000u32.to_le_bytes());
            out.extend_from_slice(&[0u8; 48]);
            out.extend_from_slice(&[0u8; 8]); // CvRecord: absent
            out.extend_from_slice(&[0u8; 8]); // MiscRecord: absent
            out.extend_from_slice(&[0u8; 16]); // reserved words
        }

        // The memory list: descriptors, then the bytes they resolve to.
        out.extend_from_slice(&(self.memory.len() as u32).to_le_bytes());
        let blobs_at = memory_stream_rva + 4 + 16 * self.memory.len();
        let mut at = blobs_at;
        for range in &self.memory {
            out.extend_from_slice(&range.start.to_le_bytes());
            out.extend_from_slice(&(range.bytes.len() as u32).to_le_bytes());
            out.extend_from_slice(&(at as u32).to_le_bytes());
            at += range.bytes.len();
        }
        for range in &self.memory {
            out.extend_from_slice(&range.bytes);
        }

        // The exception stream.
        if let Some(exception) = &self.exception {
            out.extend_from_slice(&exception.thread_id.to_le_bytes());
            out.extend_from_slice(&0u32.to_le_bytes()); // alignment
            out.extend_from_slice(&exception.code.to_le_bytes());
            out.extend_from_slice(&0u32.to_le_bytes()); // exception flags
            out.extend_from_slice(&0u64.to_le_bytes()); // nested record
            out.extend_from_slice(&exception.fault_address.to_le_bytes());
            out.extend_from_slice(&0u32.to_le_bytes()); // parameter count
            out.extend_from_slice(&0u32.to_le_bytes()); // alignment
            out.extend_from_slice(&[0u8; 15 * 8]); // parameter slots
            match &exception_blob {
                Some(blob) => {
                    let rva = exception_stream_rva + EXCEPTION_HEAD_SIZE;
                    out.extend_from_slice(&(blob.len() as u32).to_le_bytes());
                    out.extend_from_slice(&(rva as u32).to_le_bytes());
                    out.extend_from_slice(blob);
                }
                None => out.extend_from_slice(&[0u8; 8]), // absent context
            }
        }

        if let Some(architecture) = self.processor_architecture {
            let mut payload = vec![0u8; 36];
            payload[0..2].copy_from_slice(&architecture.to_le_bytes());
            out.extend_from_slice(&payload);
        }

        for string in &strings {
            out.extend_from_slice(string);
        }
        out
    }
}

fn minidump_string(value: &str) -> Vec<u8> {
    let utf16: Vec<u8> = value
        .encode_utf16()
        .flat_map(|unit| unit.to_le_bytes())
        .collect();
    let mut out = Vec::new();
    out.extend_from_slice(&(utf16.len() as u32).to_le_bytes());
    out.extend_from_slice(&utf16);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_built_dump_names_mdmp_and_lays_its_streams_in_the_directory() {
        let bytes = MinidumpBuilder::new()
            .module("C:\\game\\game.dll", 0x1000_0000, 0x2000, 0x66a0_0000)
            .build();
        assert_eq!(&bytes[0..4], b"MDMP");
        let stream_count = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
        assert_eq!(stream_count, 3, "thread, module, and memory lists");
        let directory = u32::from_le_bytes(bytes[12..16].try_into().unwrap()) as usize;
        assert_eq!(directory, 32);
        let kinds: Vec<u32> = (0..stream_count)
            .map(|index| {
                let entry = directory + 12 * index as usize;
                u32::from_le_bytes(bytes[entry..entry + 4].try_into().unwrap())
            })
            .collect();
        assert_eq!(kinds, vec![3, 4, 5]);
    }
}
