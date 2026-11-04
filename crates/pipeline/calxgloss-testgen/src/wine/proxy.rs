//! The recording proxy: a generated DLL that wears a target's binary
//! identity, exports its full export name set, and records calls as they
//! arrive through that identity before forwarding them to the real module.
//!
//! A reference-app run produces no baseline evidence of its own: the calls
//! it makes belong to the reference application's process, which calxgloss
//! does not control. What it can control is the *identity* an application
//! resolves its target through. This module generates a DLL exported under
//! the target's binary name — `fixture_target.dll`, where the app goes
//! looking for it — that records the argument vector of each arriving call
//! under the capture bound and then runs the real entry transparently. The
//! fold replays against the *real* binary, never this one.
//!
//! This is an evidence *collector*, not a capture engine: the capture bound
//! (64 KiB per pointer, [`calxgloss_types::POINTER_CAPTURE_BOUND`]) lives
//! here too, but unlike the baseline run's entry hooks this proxy does not
//! re-implement it — the harness owns that one, and a second copy would be
//! free to drift from it.
//!
//! ## Layout
//!
//! - [`generate_recording_proxy`] renders the proxy source and its export
//!   alias table; the pure codegen seam, asserted like the entry-hook family.
//! - [`WineRunner::build_recording_proxy`] lays the project out, builds it
//!   against the real fixture DLL, and places it under the target's binary
//!   identity next to the real module.
//! - [`WineRunner::px_capture_log`] assembles the proxy's entry events into
//!   a capture log on the `reference-app` lane.
//! - [`px_notes`] surfaces the proxy's honest refusals into the run's notes.

use anyhow::{Context, Result, bail};
use calxgloss_types::POINTER_CAPTURE_BOUND;
use serde_json::Value;
use std::process::Command;

use super::WineRunner;
use crate::pe::Machine;
use crate::wine::types::ScalarKind;

/// The capture-id prefix for reference-app runs: `{prefix}{binary}` names
/// one reference-app run against one target binary.
pub const REFERENCE_APP_CAPTURE_PREFIX: &str = "reference-app:";

/// The name the proxy resolves its real target under once the real module
/// is copied next to it: `fixture_target.dll` becomes
/// `fixture_target.real.dll`.
pub fn px_real_name(binary: &str) -> String {
    match binary.strip_suffix(".dll") {
        Some(stem) => format!("{stem}.real.dll"),
        None => format!("{binary}.real.dll"),
    }
}

/// One exported name in the proxy's table.
#[derive(Debug, Clone)]
pub struct ProxySlot {
    /// The export name, verbatim from the target's export table.
    pub export: String,
    /// Whether the slot records what arrives. `None` when no signature was
    /// published for the export or its argument kinds fall outside the
    /// recording vector (floating-point kinds, more than four register
    /// arguments): the slot still forwards, it just records nothing, so
    /// every arriving call reaches a real entry either way.
    pub recorded: Option<RecordedSlot>,
}

/// The recording half of a proxy slot.
#[derive(Debug, Clone)]
pub struct RecordedSlot {
    /// The declared argument kinds in register order — the baseline run's
    /// four-column shape, padded past the export's arity. At most four
    /// kinds: the shims carry the four register arguments and nothing else.
    pub arg_kinds: Vec<ScalarKind>,
}

impl ProxySlot {
    /// A slot that only forwards.
    pub fn forwarding(export: impl Into<String>) -> Self {
        Self {
            export: export.into(),
            recorded: None,
        }
    }

    /// A slot that records the arriving vector before forwarding.
    pub fn recorded(
        export: impl Into<String>,
        arg_kinds: impl IntoIterator<Item = ScalarKind>,
    ) -> Self {
        Self {
            export: export.into(),
            recorded: Some(RecordedSlot {
                arg_kinds: arg_kinds.into_iter().collect(),
            }),
        }
    }
}

/// The generated recording proxy: the cdylib source, the export alias
/// table, and the notes it states honestly.
#[derive(Debug, Clone)]
pub struct ProxyGeneration {
    /// The generated Rust source for the proxy project's cdylib.
    pub source: String,
    /// The export alias table (`proxy.def`) handed to the linker.
    pub def: String,
    /// Notes the proxy states about calls it will not record.
    pub notes: Vec<String>,
    /// How many slots record.
    pub recorded: usize,
}

/// Generate the recording proxy: every export name of the target becomes a
/// linker alias to its shim, so the built DLL answers for the full export
/// set under the target's binary identity; each shim records the arriving
/// vector when the slot records and then runs the real entry transparently.
///
/// The degrade rule mirrors the baseline run's: a target not built for
/// x86-64 cannot hold the shim machinery at all, and the caller gets a
/// coverage note stating that instead of a proxy — never faked events.
pub fn generate_recording_proxy(
    binary: &str,
    slots: &[ProxySlot],
    machine: Option<Machine>,
) -> Result<ProxyGeneration> {
    if slots.is_empty() {
        bail!("the recording proxy for '{binary}' has no exports to alias");
    }
    let count = slots.len();
    if let Some(machine @ (Machine::X86 | Machine::Other(_))) = machine {
        let arch = match machine {
            Machine::X86 => String::from("32-bit x86"),
            Machine::Other(word) => format!("PE machine word 0x{word:x}"),
            Machine::X86_64 => unreachable!("only non-x86-64 machines get here"),
        };
        bail!(
            "the recording proxy for '{binary}' admits defeat: the target binary \
             was built for {arch}, and the proxy's forwarding shims exist only \
             for x86-64; this run will state the coverage gap instead of faked events"
        );
    }

    // A slot's name is written into the linker table and the recorder's
    // name table as a quoted string; a name that cannot survive quoting
    // would mis-alias the export set, so it is refused at the seam rather
    // than half-carried.
    if let Some(bad) = slots.iter().find(|slot| {
        slot.export.is_empty()
            || slot
                .export
                .chars()
                .any(|c| matches!(c, '"' | '\\' | '\n' | '\r' | '\0'))
    }) {
        bail!(
            "the recording proxy for '{binary}' cannot alias export {:?}: a name \
             that will not survive quoting in the export table would misname the \
             forwarding set",
            bad.export
        );
    }
    // Four columns is the whole recording vocabulary — the same register
    // vector the baseline entry hooks capture. A slot claiming more would
    // silently file a partial vector, the one thing the capture vocabulary
    // forbids, so generation refuses it by name.
    if let Some(bad) = slots.iter().find(|slot| {
        slot.recorded
            .as_ref()
            .is_some_and(|r| r.arg_kinds.len() > 4)
    }) {
        bail!(
            "the recording proxy for '{binary}' cannot record '{}': its declared \
             argument list runs past the four-register vector the shims capture; \
             name the slot forwarding instead, and it answers transparently while \
             stating it records nothing",
            bad.export
        );
    }

    let notes = px_notes(binary, slots);
    let recorded = slots.iter().filter(|slot| slot.recorded.is_some()).count();

    // The export alias table: every name the real module exports, quoted
    // so a C++ mangled name survives, aliased to the shim that answers it.
    let def_lines = slots
        .iter()
        .enumerate()
        .map(|(i, slot)| format!("\"{}\" = calx_px_shim_{i}", slot.export))
        .collect::<Vec<_>>();
    let def = format!(
        "EXPORTS\n{}\n",
        def_lines
            .iter()
            .map(|line| format!("  {line}"))
            .collect::<Vec<_>>()
            .join("\n")
    );

    // The name table and per-slot tag rows the recorder reads.
    let names = slots
        .iter()
        .map(|slot| format!("\"{}\"", slot.export))
        .collect::<Vec<_>>()
        .join(", ");
    let rows = slots
        .iter()
        .map(|slot| {
            px_tag_row(
                slot.recorded
                    .as_ref()
                    .map(|recorded| recorded.arg_kinds.as_slice()),
            )
        })
        .collect::<Vec<_>>()
        .join(", ");

    // The forwarding shims, aliased to the export names in the table above.
    let mut shims = String::new();
    for i in 0..count {
        shims.push_str(
            &PX_SLOT
                .replace("__I__", &i.to_string())
                .replace("__O__", &(i * 8).to_string()),
        );
    }

    let body = PX_PROXY_TEMPLATE
        .replace("__N__", &count.to_string())
        .replace("__EXPORT_NAMES__", &names)
        .replace("__TAG_ROWS__", &rows)
        .replace("__REAL_MODULE__", &px_real_name(binary))
        .replace("__LINE_BOUND__", &POINTER_CAPTURE_BOUND.to_string())
        .replace("__SHIMS__", &shims);

    Ok(ProxyGeneration {
        source: body,
        def,
        notes,
        recorded,
    })
}

/// The notes the proxy states about calls it will not record: an export the
/// signature table cannot describe records nothing, and the run says so
/// rather than letting the gap hide inside a clean-looking log.
pub fn px_notes(binary: &str, slots: &[ProxySlot]) -> Vec<String> {
    slots
        .iter()
        .filter(|slot| slot.recorded.is_none())
        .map(|slot| {
            format!(
                "proxy: the call to '{}' on '{binary}' will not be recorded: no \
                 argument signature published for it is recordable within the \
                 four-register vector (floating-point kinds and wider argument \
                 lists fall outside it); the slot forwards transparently and \
                 records nothing",
                slot.export
            )
        })
        .collect()
}

/// The notes a proxy run stated on stderr: honest refusals begin with
/// `proxy:`, and a caller assembling the capture log must not lose them.
pub fn px_stderr_notes(stderr: &str) -> Vec<String> {
    stderr
        .lines()
        .filter(|line| line.starts_with("proxy:"))
        .map(str::to_owned)
        .collect()
}

/// The per-slot tag row inside the recorder's table: the same four-column
/// shape as the baseline run's hook table — a scalar kind is its one-letter
/// wire tag, a pointer is `p`, the unused tail is empty. An all-empty row
/// is the unrecorded slot: its shim records nothing.
pub(crate) fn px_tag_row(tags: Option<&[ScalarKind]>) -> String {
    let mut cols: Vec<String> = (0..4).map(|_| String::from("\"\"")).collect();
    if let Some(tags) = tags {
        for (slot, kind) in cols.iter_mut().zip(tags) {
            *slot = format!("\"{}\"", kind.tag());
        }
    }
    format!("[{}]", cols.join(", "))
}

/// One forwarding shim, aliased to one export name in the linker table.
/// Intel syntax, as rustc's asm dialect for Windows x86 targets. The frame
/// mirrors the baseline run's trampolines exactly: the save slots sit at
/// `[rsp+40..rsp+80]` of a `sub rsp, 104` frame — above the 32-byte shadow
/// space the recorder's `call` makes legal for itself — and the frame size
/// keeps the `call` and the tail `jmp` on 16-byte boundaries. The args
/// reach the recorder as (table index, pointer to the slots) and are fully
/// restored before the tail jump through `r11`. A slot whose real target
/// never resolved answers zero — no event was recorded, because a call
/// that never reached a real entry is not evidence for one.
const PX_SLOT: &str = "\
.p2align 4\n\
.globl calx_px_shim___I__\n\
calx_px_shim___I__:\n\
  sub rsp, 104\n\
  mov [rsp+40], rcx\n\
  mov [rsp+48], rdx\n\
  mov [rsp+56], r8\n\
  mov [rsp+64], r9\n\
  mov [rsp+72], rax\n\
  lea rdx, [rsp+40]\n\
  mov rcx, __I__\n\
  call calx_px_enter\n\
  mov rcx, [rsp+40]\n\
  mov rdx, [rsp+48]\n\
  mov r8, [rsp+56]\n\
  mov r9, [rsp+64]\n\
  mov rax, [rsp+72]\n\
  mov r11, [rip + CALX_PX_REALS + __O__]\n\
  add rsp, 104\n\
  test r11, r11\n\
  jz 9f\n\
  jmp r11\n\
9:\n\
  xor eax, eax\n\
  ret\n\
";

const PX_PROXY_TEMPLATE: &str = r##"//! generated by calxgloss-testgen — do not edit (recording proxy)

use std::arch::global_asm;
use std::ffi::c_void;

/// The capture bound for one pointer argument, mirrored from the shared
/// capture vocabulary at codegen: bytes beyond it are never taken.
const CALX_PX_CAPTURE_BOUND: usize = __LINE_BOUND__;

/// The line budget for one recorded event, sized at codegen from the
/// bound: a vector that could overflow the budget is caught by the
/// framing check in the recorder, never by a half-written line.
const CALX_PX_LINE_MAX: usize = CALX_PX_CAPTURE_BOUND * 5 + 1024;

/// The argument registers as the shim saved them.
#[repr(C)]
struct CalxPxSaves {
    rcx: u64,
    rdx: u64,
    r8: u64,
    r9: u64,
    rax: u64,
}

/// The committed memory view `VirtualQuery` answers with (Windows
/// `MEMORY_BASIC_INFORMATION`).
#[repr(C)]
struct CalxPxMbi {
    base_addr: *mut c_void,
    allocation_base: *mut c_void,
    allocation_protect: u32,
    region_size: usize,
    state: u32,
    protect: u32,
    type_: u32,
}

extern "system" {
    fn GetModuleHandleW(lp_module_name: *const u16) -> *mut c_void;
    fn GetModuleFileNameW(h_module: *mut c_void, lp_filename: *mut u16, n_size: u32) -> u32;
    fn LoadLibraryW(lp_lib_filename: *const u16) -> *mut c_void;
    fn GetProcAddress(h_module: *mut c_void, lp_proc_name: *const i8) -> *mut c_void;
    fn VirtualQuery(lp_address: *const c_void, lp_buffer: *mut CalxPxMbi, dw_length: usize) -> usize;
    fn GetStdHandle(n_std_handle: i32) -> *mut c_void;
    fn WriteFile(
        h_file: *mut c_void,
        lp_buffer: *const u8,
        n_number_of_bytes_to_write: u32,
        lp_number_of_bytes_written: *mut u32,
        lp_overlapped: *mut c_void,
    ) -> i32;
}

/// The name the real module beside this proxy answers under, filled at
/// codegen from the binary identity this proxy wears.
static CALX_PX_REAL_MODULE: &str = "__REAL_MODULE__";

/// The real target for each export slot, filled by the recorder once the
/// module beside this proxy resolves. A zero slot forwards to nothing and
/// answers zero.
#[no_mangle]
static mut CALX_PX_REALS: [usize; __N__] = [0usize; __N__];

/// The export names in the proxy's table, verbatim from the real module.
static CALX_PX_NAMES: [&str; __N__] = [
    __EXPORT_NAMES__,
];

/// The per-slot argument kinds in register order. An all-empty row is an
/// unrecorded slot.
static CALX_PX_TAGS: [[&str; 4]; __N__] = [
    __TAG_ROWS__,
];

/// This proxy's own directory (with the trailing separator), derived once
/// from the loaded module; see [`px_dir_ready`].
static mut PX_SELF_DIR: [u16; 1024] = [0u16; 1024];
static mut PX_SELF_DIR_LEN: usize = 0;
static mut PX_DIR_DONE: bool = false;

/// The real module beside this proxy, located once; null when it cannot
/// be found. Slots keep resolving names out of this handle thereafter.
static mut PX_REAL_MODULE: *mut c_void = std::ptr::null_mut();
static mut PX_REAL_DONE: bool = false;

std::arch::global_asm!(
    r#".text
__SHIMS__"#
);

/// Write one note line to stderr from assembly-safe code: a recorder that
/// reports honestly through `eprintln!` mid-shim risks panicking on a
/// locked stdout mutex it did not take, so notes go out through the raw
/// handle.
#[no_mangle]
extern "C" fn px_note(message: *const u8, len: usize) {
    let handle = unsafe { GetStdHandle(-12) };
    if handle.is_null() || handle == !0 as *mut c_void {
        return;
    }
    let mut written = 0u32;
    unsafe {
        WriteFile(handle, message, len as u32, &mut written, std::ptr::null_mut());
    }
}

/// Fill `PX_SELF_DIR` once with this proxy's own directory, trailing
/// separator included: the real module is looked up beside the proxy —
/// the honest answer to "where was this proxy loaded", wherever the
/// process happens to be working. `GetModuleFileNameW` given no module
/// answers with the *exe*'s path, so the proxy instead asks `VirtualQuery`
/// for the allocation base of one of its own functions — the base of this
/// very mapping — and takes that module's file name from it. (Wine's
/// `GetModuleHandleExW` with the FROM_ADDRESS flag answers nothing for a
/// loaded DLL — error 126 — so the proxy does not lean on it.)
unsafe fn px_dir_ready() -> bool {
    if PX_DIR_DONE {
        return PX_SELF_DIR_LEN > 0;
    }
    PX_DIR_DONE = true;
    let mut mbi = std::mem::zeroed::<CalxPxMbi>();
    if VirtualQuery(
        calx_px_enter as *const c_void,
        &mut mbi,
        std::mem::size_of::<CalxPxMbi>(),
    ) == 0
    {
        return false;
    }
    let written = GetModuleFileNameW(mbi.allocation_base, PX_SELF_DIR.as_mut_ptr(), 1024);
    if written == 0 || written >= 1024 {
        return false;
    }
    let mut cut = written as usize;
    while cut > 0 && PX_SELF_DIR[cut - 1] != 0x5c {
        cut -= 1;
    }
    if cut == 0 {
        return false;
    }
    PX_SELF_DIR[cut] = 0;
    PX_SELF_DIR_LEN = cut;
    true
}

/// One name as a null-terminated wide string, for the win32 loaders.
fn px_wide(name: &str) -> Vec<u16> {
    let mut wide: Vec<u16> = name.encode_utf16().collect();
    wide.push(0);
    wide
}

/// Locate the real module beside this proxy once: already loaded under
/// its alias name (the caller may have loaded it itself), else loaded
/// from the alias beside this proxy. Every slot resolves its names out of
/// this one handle, so the module is searched for at most once.
unsafe fn px_real_module() -> *mut c_void {
    if PX_REAL_DONE {
        return PX_REAL_MODULE;
    }
    PX_REAL_DONE = true;
    let alias_wide = px_wide(CALX_PX_REAL_MODULE);
    let loaded = GetModuleHandleW(alias_wide.as_ptr());
    PX_REAL_MODULE = if !loaded.is_null() {
        loaded
    } else if px_dir_ready() {
        let mut full: Vec<u16> = PX_SELF_DIR[..PX_SELF_DIR_LEN].to_vec();
        full.extend(CALX_PX_REAL_MODULE.encode_utf16());
        full.push(0);
        LoadLibraryW(full.as_ptr())
    } else {
        std::ptr::null_mut()
    };
    PX_REAL_MODULE
}

/// Resolve one slot's real target: the real module already loaded under
/// its alias name (the caller may have loaded it itself), else the alias
/// beside this proxy. A name the process cannot answer for leaves the
/// slot zero and names the reason on stderr — a call that never reached
/// a real entry must not be recorded as evidence for one.
#[no_mangle]
extern "C" fn calx_px_resolve(index: u64) {
    let Some(name) = CALX_PX_NAMES.get(index as usize) else {
        return;
    };
    let module = unsafe { px_real_module() };
    if module.is_null() {
        let note = format!(
            "proxy: the real module {} cannot be found beside this proxy; the call will \
             answer zero and record nothing\n",
            CALX_PX_REAL_MODULE
        );
        px_note(note.as_ptr(), note.len());
        return;
    }
    let c_name: Vec<i8> = name.bytes().map(|b| b as i8).chain(std::iter::once(0)).collect();
    let func = unsafe { GetProcAddress(module, c_name.as_ptr()) };
    if func.is_null() {
        let note = format!(
            "proxy: {name} is not exported by the real module beside this proxy; the call will \
             answer zero and record nothing\n"
        );
        px_note(note.as_ptr(), note.len());
        return;
    }
    unsafe {
        CALX_PX_REALS[index as usize] = func as usize;
    }
}

/// Read a pointer argument's target out of this process: `VirtualQuery`
/// first, because a recorder that faults takes the caller's process down,
/// and only bytes inside a committed readable region are ever touched.
/// The same probe discipline as the baseline run's entry hooks; the bound
/// is the shared capture bound.
/// The one shape a probe that never got to read returns: a pointer
/// capture stating it holds nothing. Every unreadable outcome — null,
/// uncommitted, guard page, non-readable — answers the same, because the
/// reader's job is to say what it saw, not to guess why.
const CALX_PX_UNREADABLE: &str =
    "{\"kind\":\"pointer\",\"bytes\":[],\"captured_size\":0,\"truncated\":false}";

unsafe fn px_probe(addr: u64) -> String {
    use std::fmt::Write as _;
    if addr == 0 {
        return String::from(CALX_PX_UNREADABLE);
    }
    let mut mbi = std::mem::zeroed::<CalxPxMbi>();
    if VirtualQuery(addr as *const c_void, &mut mbi, std::mem::size_of::<CalxPxMbi>()) == 0 {
        return String::from(CALX_PX_UNREADABLE);
    }
    if mbi.state != 0x1000 || mbi.protect & 0x100 != 0 {
        // Uncommitted, or a guard page: never readable.
        return String::from(CALX_PX_UNREADABLE);
    }
    let readable = mbi.protect & (0x02 | 0x04 | 0x08 | 0x20 | 0x40 | 0x80) != 0;
    if !readable {
        return String::from(CALX_PX_UNREADABLE);
    }
    let region_start = mbi.base_addr as u64;
    let observed = (region_start + mbi.region_size as u64).saturating_sub(addr);
    let kept = observed.min(CALX_PX_CAPTURE_BOUND as u64);
    let truncated = kept < observed;
    let mut bytes = String::new();
    for offset in 0..kept {
        if offset > 0 {
            bytes.push(',');
        }
        let byte = unsafe { *((addr + offset) as *const u8) };
        let _ = write!(bytes, "{byte}");
    }
    format!(
        "{{\"kind\":\"pointer\",\"bytes\":[{bytes}],\"captured_size\":{observed},\"truncated\":{truncated}}}"
    )
}

/// Cut a register back to the width its tag declared — never a guess at
/// a wider reading.
fn px_tagged(tag: &str, raw: u64) -> String {
    match tag {
        "i8" => format!("{}", (raw as u8) as i8),
        "i16" => format!("{}", (raw as u16) as i16),
        "i32" => format!("{}", (raw as u32) as i32),
        "i64" => format!("{}", raw as i64),
        "u8" => format!("{}", raw as u8),
        "u16" => format!("{}", raw as u16),
        "u32" => format!("{}", raw as u32),
        "u64" => format!("{raw}"),
        other => other.to_string(),
    }
}

/// Record one call as it arrived through the proxy, then make sure the
/// slot's real target is resolved. Entered from the shims with (table
/// index, pointer to the saved argument registers).
///
/// An unrecorded slot (all-empty tag row) resolves its target and records
/// nothing. A recorded slot prints its event to stdout before forwarding,
/// so the event survives even the case that faults inside the real entry.
#[no_mangle]
extern "C" fn calx_px_enter(index: u64, saves: *const CalxPxSaves) {
    let Some(name) = CALX_PX_NAMES.get(index as usize) else {
        return;
    };
    if saves.is_null() {
        return;
    }
    let tags = CALX_PX_TAGS[index as usize];
    // Resolve the real entry first: every arriving call reaches a real
    // entry either way, recorded slot or not.
    if unsafe { CALX_PX_REALS[index as usize] } == 0 {
        calx_px_resolve(index);
    }
    if tags.iter().all(|tag| tag.is_empty()) {
        // The unrecorded shape: the real entry is resolved and the shim
        // forwards to it; nothing is recorded.
        return;
    }
    let saves = unsafe { &*saves };
    let registers = [saves.rcx, saves.rdx, saves.r8, saves.r9];
    let mut args = String::new();
    for (slot, tag) in tags.iter().enumerate() {
        if tag.is_empty() {
            break;
        }
        if !args.is_empty() {
            args.push(',');
        }
        if *tag == "p" {
            args.push_str(&unsafe { px_probe(registers[slot]) });
        } else {
            args.push_str(&format!(
                "{{\"kind\":\"scalar\",\"tag\":\"{tag}\",\"value\":{}}}",
                px_tagged(tag, registers[slot])
            ));
        }
    }
    if args.len() + 256 > CALX_PX_LINE_MAX {
        // The line budget was sized at codegen; a vector that overflows it
        // drops the whole event with the reason named — never a
        // half-written event, and never a faked one.
        let note = format!(
            "proxy: the entry event for '{name}' was dropped: the argument \
             vector overflows the event line budget\n"
        );
        px_note(note.as_ptr(), note.len());
        return;
    }
    // The line goes out through the raw stdout handle, like notes do: the
    // proxy's own std::io::stdout state is a second copy living inside a
    // DLL that happens to be loaded into someone else's process, and
    // writing through it faults under Wine. A raw handle write shares the
    // harness's one console truth.
    let line = format!("EVENT\t{{\"export\":\"{name}\",\"args\":[{args}]}}\n");
    let handle = unsafe { GetStdHandle(-11) };
    let mut written = 0u32;
    let ok = handle != !0 as *mut c_void
        && !handle.is_null()
        && unsafe {
            WriteFile(handle, line.as_ptr(), line.len() as u32, &mut written, std::ptr::null_mut())
        } != 0
        && written as usize == line.len();
    if !ok {
        // The event could not reach the runner: honest note, and the call
        // still forwards — a recorder never takes the caller down.
        let note = format!(
            "proxy: the entry event for '{name}' was dropped: it could not \
             reach stdout\n"
        );
        px_note(note.as_ptr(), note.len());
    }
}
"##;

impl WineRunner {
    /// Build the recording proxy for a binary over its real DLL.
    ///
    /// The proxy project's cargo config carries the linker alias file as a
    /// project-local rustflag, so the alias table reaches the link without
    /// mutating this runner's cross-tool environment at all. The built DLL
    /// is then copied under the target's binary identity into `run_dir`.
    pub fn build_recording_proxy(
        &self,
        binary: &str,
        generation: &ProxyGeneration,
        machine: Machine,
        run_dir: &std::path::Path,
    ) -> Result<std::path::PathBuf> {
        if binary.is_empty()
            || binary == "."
            || binary == ".."
            || !binary
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
        {
            bail!("the proxy binary name '{binary}' is not a safe file name");
        }
        let triple = machine.target_triple();
        if triple == "unknown" {
            bail!("Unsupported target architecture; cannot build a recording proxy for it");
        }

        let project = self.work_dir.join("px-proxy");
        let src = project.join("src");
        std::fs::create_dir_all(&src)
            .with_context(|| format!("Failed to create proxy directory {}", project.display()))?;

        let manifest = "[package]\n\
             name = \"calx_px_proxy\"\n\
             version = \"0.0.0\"\n\
             edition = \"2021\"\n\
             \n\
             [lib]\n\
             crate-type = [\"cdylib\"]\n\
             \n\
             [profile.release]\n\
             panic = \"unwind\"\n\
             debug = false\n";
        std::fs::write(project.join("Cargo.toml"), manifest)
            .with_context(|| "Failed to write the proxy Cargo.toml".to_string())?;
        std::fs::write(src.join("lib.rs"), &generation.source)
            .with_context(|| "Failed to write the proxy source".to_string())?;

        // The export alias table rides the link as a project-local rustflag:
        // `link-arg` reaches the linker with one argument and cannot leak
        // into any other build this runner performs.
        let def = project.join("proxy.def");
        std::fs::write(&def, &generation.def)
            .with_context(|| "Failed to write the proxy export table".to_string())?;
        std::fs::create_dir_all(project.join(".cargo"))
            .with_context(|| "Failed to create the proxy cargo config directory".to_string())?;
        std::fs::write(
            project.join(".cargo").join("config.toml"),
            format!(
                "[build]\nrustflags = [\"-C\", \"link-arg=-Wl,{}\"]\n",
                def.display()
            ),
        )
        .with_context(|| "Failed to write the proxy cargo config".to_string())?;

        let output = Command::new("cargo")
            .arg("build")
            .arg("--release")
            .arg("--target")
            .arg(triple)
            .current_dir(&project)
            .output()
            .context("Failed to run 'cargo build' for the recording proxy")?;
        if !output.status.success() {
            bail!(
                "Recording proxy failed to compile for {triple}:\n{}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        let built = project
            .join("target")
            .join(triple)
            .join("release")
            .join("calx_px_proxy.dll");
        if !built.is_file() {
            bail!("Proxy compiled but {} was not produced", built.display());
        }
        std::fs::create_dir_all(run_dir)
            .with_context(|| format!("Failed to create run directory {}", run_dir.display()))?;
        let proxy = run_dir.join(binary);
        std::fs::copy(&built, &proxy)
            .with_context(|| format!("Failed to place the proxy at {}", proxy.display()))?;
        Ok(proxy)
    }

    /// Assemble the reference-app capture log for one proxy run: the
    /// proxy's entry events become captured call entries on the
    /// reference-app lane, each carrying the argument vector exactly as it
    /// arrived at the proxy. The capture id names one reference-app run
    /// against one target binary; the runner owns the event sequence, and
    /// events that could not be recorded leave the log with the reason
    /// riding a note — never silently.
    pub fn px_capture_log(&self, binary: &str, events: &[Value], notes: &[String]) -> Value {
        let capture_id = format!("{REFERENCE_APP_CAPTURE_PREFIX}{binary}");

        // A proxy that only stated honest refusals recorded everything
        // that arrived; any note about an event it could not keep leaves
        // what the run recorded short of that promise, and the fold
        // deserves to hear it.
        let all_kept = notes.iter().all(|note| {
            !note.contains("dropped")
                && !note.contains("cannot be found")
                && !note.contains("not exported by the real module")
        });

        // One pass over the arrivals: each event either converts whole —
        // every argument nameable, numbered in arrival order under the
        // one capture id — or leaves the log entirely and rides a note.
        // A dropped argument means the vector is incomplete; filing a
        // partial vector would misname it against the signature.
        let mut entries: Vec<Value> = Vec::new();
        let mut dropped_notes: Vec<String> = Vec::new();
        for (sequence, event) in events.iter().enumerate() {
            let (Some(export), Some(args)) = (
                event.get("export").and_then(Value::as_str),
                event.get("args").and_then(Value::as_array),
            ) else {
                continue;
            };
            let arguments = args
                .iter()
                .filter_map(super::harness_argument_to_descriptor)
                .collect::<Vec<Value>>();
            if arguments.len() != args.len() {
                dropped_notes.push(format!(
                    "entry event for '{export}' was dropped: an argument the runner could not name"
                ));
                continue;
            }
            entries.push(serde_json::json!({
                "binary": binary,
                "export": export,
                "lane": "reference_app",
                "evidence": {
                    "run_event": {
                        "capture_id": capture_id,
                        // The arrival number stands even when earlier
                        // arrivals dropped out of the log: the notes say
                        // which numbers are missing, never do the entries
                        // close ranks and pretend to be contiguous.
                        "event_sequence": (sequence + 1) as u64,
                    }
                },
                "arguments": arguments,
            }));
        }
        dropped_notes.extend(notes.iter().cloned());
        if !all_kept {
            dropped_notes.push(
                "the run named calls it could not fully record; the log may be short of the \
                 calls that arrived"
                    .to_string(),
            );
        }

        let mut log = serde_json::json!({
            "schema": "capture-log-v1",
            "capture_id": capture_id,
            "entries": entries,
        });
        if !dropped_notes.is_empty() {
            log["notes"] = serde_json::json!(dropped_notes);
        }
        log
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn slots() -> Vec<ProxySlot> {
        use ScalarKind::{I32, Ptr, U64};
        vec![
            ProxySlot::recorded("fixture_status", [I32, U64, Ptr, Ptr]),
            ProxySlot::forwarding("?mangled@@YAXXZ"),
            ProxySlot::recorded("fixture_ordered", [Ptr, Ptr, Ptr, Ptr]),
        ]
    }

    fn generation() -> ProxyGeneration {
        generate_recording_proxy("fixture_target.dll", &slots(), None)
            .expect("the fixture slot set should generate a proxy")
    }

    #[test]
    fn a_proxy_admits_a_target_that_is_not_x86_64_with_a_coverage_note() {
        // The x86-64-only rule, on the target's own machine: the run does
        // not half-generate a proxy that cannot forward, and it states the
        // coverage gap instead of faking events.
        let error = generate_recording_proxy("fixture_target.dll", &slots(), Some(Machine::X86))
            .unwrap_err();
        let message = error.to_string();
        assert!(
            message.contains("32-bit x86") && message.contains("coverage"),
            "{message}"
        );
        assert!(
            generate_recording_proxy("fixture_target.dll", &slots(), Some(Machine::X86_64)).is_ok()
        );
        assert!(generate_recording_proxy("fixture_target.dll", &slots(), None).is_ok());
    }

    #[test]
    fn a_proxy_without_exports_admits_defeat() {
        let error = generate_recording_proxy("fixture_target.dll", &[], None).unwrap_err();
        assert!(error.to_string().contains("no exports"));
    }

    #[test]
    fn a_recorded_slot_past_the_four_register_vector_is_refused_by_name() {
        // The documented recording vector is at most four registers wide.
        // A slot declaring longer would be recorded as a partial vector
        // behind the caller's back — the one shape the capture vocabulary
        // forbids — so generation refuses it naming the slot.
        let slots = vec![ProxySlot::recorded("fixture_wide", [ScalarKind::I32; 5])];
        let error = generate_recording_proxy("fixture_target.dll", &slots, Some(Machine::X86_64))
            .expect_err("a five-argument recorded slot must be refused");
        let message = error.to_string();
        assert!(
            message.contains("fixture_wide") && message.contains("four-register"),
            "{message}"
        );
    }

    #[test]
    fn an_export_name_that_will_not_survive_quoting_is_refused() {
        // The forwarding set is carried through quoted tables; a name that
        // breaks quoting would misname the whole set, so it is refused at
        // the seam rather than half-carried.
        let slots = vec![ProxySlot::forwarding("broken\"name")];
        let error = generate_recording_proxy("fixture_target.dll", &slots, Some(Machine::X86_64))
            .expect_err("an unquotable export name must be refused");
        assert!(error.to_string().contains("misname the forwarding set"));
    }

    #[test]
    fn codegen_aliases_every_export_name_to_its_forwarding_slot() {
        // The acceptance line for the identity: each export name of the
        // real module, C++ mangled names included, becomes a linker alias
        // naming the shim that answers for it.
        let generated = generation();
        for name in ["fixture_status", "?mangled@@YAXXZ", "fixture_ordered"] {
            assert!(
                generated
                    .def
                    .contains(&format!("\"{name}\" = calx_px_shim_")),
                "export alias for {name} missing from\n{}",
                generated.def
            );
        }
        assert!(generated.def.starts_with("EXPORTS"));
    }

    #[test]
    fn codegen_builds_the_recorder_statics_the_shim_family_reads() {
        // The template carries its export name table and its per-slot kind
        // rows, sized to the slots.
        let generated = generation();
        assert!(
            generated.source.contains("static CALX_PX_NAMES: [&str; 3]"),
            "name table missing"
        );
        assert!(
            generated
                .source
                .contains("static CALX_PX_TAGS: [[&str; 4]; 3]"),
            "kind table missing"
        );
        for name in ["fixture_status", "?mangled@@YAXXZ", "fixture_ordered"] {
            assert!(
                generated.source.contains(&format!("\"{name}\"")),
                "name table missing {name}"
            );
        }
    }

    #[test]
    fn codegen_wires_the_recording_shims_in_their_own_names() {
        // Same shape as the entry-hook family: each slot's shim is the
        // symbol the alias table points at, and it enters the recorder
        // which resolves the real target by name before the tail jump.
        let generated = generation();
        for i in 0..3 {
            assert!(
                generated.source.contains(&format!("calx_px_shim_{i}:")),
                "shim {i} missing"
            );
            assert!(
                generated
                    .source
                    .contains(&format!("[rip + CALX_PX_REALS + {}]", i * 8)),
                "shim {i} does not read its resolved slot"
            );
        }
        assert!(
            generated.source.contains("calx_px_resolve"),
            "the recorder's name resolution missing"
        );
    }

    #[test]
    fn codegen_marks_an_unrecorded_slot_and_keeps_its_shim() {
        // The unrecorded slot keeps a forwarding shim — every arriving call
        // reaches a real entry either way — and its tag row is the
        // all-empty row the recorder reads as "record nothing".
        let generated = generation();
        assert!(
            generated.source.contains(r#"["", "", "", ""]"#),
            "unrecorded tag row missing from\n{}",
            generated.source
        );
        assert_eq!(generated.recorded, 2);
        assert!(generated.source.contains("calx_px_shim_1:"));
    }

    #[test]
    fn an_unrecordable_export_admits_the_gap_in_a_named_note() {
        // Only slots that record nothing get a note; the note names the
        // export and states that the slot forwards while recording
        // nothing.
        let slots = vec![
            ProxySlot::forwarding("wide_one"),
            ProxySlot::recorded(
                "plain",
                [
                    ScalarKind::I32,
                    ScalarKind::Ptr,
                    ScalarKind::Unit,
                    ScalarKind::Unit,
                ],
            ),
            ProxySlot::forwarding("no_signature"),
        ];
        let notes = px_notes("fixture_target.dll", &slots);
        assert_eq!(notes.len(), 2);
        assert!(notes.iter().any(|note| note.contains("wide_one")));
        assert!(!notes.iter().any(|note| note.contains("'plain'")));
        assert!(notes.iter().all(|note| note.contains("records nothing")));
    }

    #[test]
    fn px_tag_rows_mirror_the_baseline_hook_table_shape() {
        use ScalarKind::{I32, Ptr};
        assert_eq!(px_tag_row(Some(&[I32, Ptr])), r#"["i32", "p", "", ""]"#);
        assert_eq!(px_tag_row(None), r#"["", "", "", ""]"#);
    }

    #[test]
    fn proxy_stderr_notes_are_the_honest_refusal_lines() {
        let stderr = "harness: module base = 0x10000000\n\
                      proxy: the real module 'fixture_target.real.dll' for export \
                      'fixture_status' cannot be found beside this proxy\n";
        let notes = px_stderr_notes(stderr);
        assert_eq!(notes.len(), 1);
        assert!(notes[0].starts_with("proxy:"));
    }

    #[test]
    fn the_real_module_alias_names_are_derived_from_the_binary() {
        assert_eq!(
            px_real_name("fixture_target.dll"),
            "fixture_target.real.dll"
        );
        assert_eq!(px_real_name("app.exe"), "app.exe.real.dll");
    }

    #[test]
    fn a_capture_log_numbers_entries_in_arrival_order_on_the_reference_app_lane() {
        // The runner owns the event sequence; the proxy never invents one.
        let runner = WineRunner::new(std::path::Path::new("/tmp/calxgen-px-log"));
        let events = vec![
            json!({"export": "fixture_status", "args": [
                {"kind": "scalar", "tag": "i32", "value": 7}
            ]}),
            json!({"export": "fixture_ordered", "args": [
                {"kind": "pointer", "bytes": [1], "captured_size": 1, "truncated": false}
            ]}),
        ];
        let log = runner.px_capture_log("fixture_target.dll", &events, &[]);
        assert_eq!(log["schema"], "capture-log-v1");
        assert_eq!(log["capture_id"], "reference-app:fixture_target.dll");
        let entries = log["entries"].as_array().expect("entries array");
        assert_eq!(entries.len(), 2);
        let first = &entries[0];
        assert_eq!(first["binary"], "fixture_target.dll");
        assert_eq!(first["export"], "fixture_status");
        assert_eq!(first["lane"], "reference_app");
        assert_eq!(first["evidence"]["run_event"]["event_sequence"], 1);
        assert_eq!(
            first["evidence"]["run_event"]["capture_id"],
            "reference-app:fixture_target.dll"
        );
        assert_eq!(entries[1]["evidence"]["run_event"]["event_sequence"], 2);
    }

    #[test]
    fn a_capture_log_keeps_scalar_and_pointer_arguments_verbatim() {
        let runner = WineRunner::new(std::path::Path::new("/tmp/calxgen-px-args"));
        let events = vec![json!({"export": "fixture_status", "args": [
            {"kind": "scalar", "tag": "i32", "value": -3},
            {"kind": "pointer", "bytes": [68, 85, 102, 119], "captured_size": 4, "truncated": false},
        ]})];
        let log = runner.px_capture_log("fixture_target.dll", &events, &[]);
        let arguments = log["entries"][0]["arguments"]
            .as_array()
            .expect("arguments array");
        assert_eq!(arguments[0], json!({"scalar": {"tag": "i32", "value": -3}}));
        assert_eq!(
            arguments[1],
            json!({"pointer": {"bytes": [68, 85, 102, 119], "captured_size": 4, "truncated": false}})
        );
    }

    #[test]
    fn a_capture_log_never_carries_more_than_the_bound_for_one_pointer() {
        // Whatever a proxy printed, the shared capture-sizing rule stands
        // at assembly: bytes past the bound never enter the log.
        let runner = WineRunner::new(std::path::Path::new("/tmp/calxgen-px-bound"));
        let bound = POINTER_CAPTURE_BOUND as usize;
        let events = vec![json!({"export": "wide_one", "args": [
            {
                "kind": "pointer",
                "bytes": vec![9u8; bound + 1],
                "captured_size": bound + 1,
                "truncated": true
            }
        ]})];
        let log = runner.px_capture_log("fixture_target.dll", &events, &[]);
        let pointer = &log["entries"][0]["arguments"][0]["pointer"];
        assert_eq!(
            pointer["bytes"].as_array().expect("bytes array").len(),
            bound
        );
        assert_eq!(pointer["captured_size"], (bound + 1) as u64);
        assert_eq!(pointer["truncated"], true);
    }

    #[test]
    fn an_unnameable_argument_drops_the_whole_event_with_a_named_reason() {
        // A partial vector would misname itself against the signature, so
        // the event leaves the log and the reason rides a note.
        let runner = WineRunner::new(std::path::Path::new("/tmp/calxgen-px-drop"));
        let events = vec![json!({"export": "floaty", "args": [
            {"kind": "scalar", "tag": "f32", "value": 1.5}
        ]})];
        let log = runner.px_capture_log("fixture_target.dll", &events, &[]);
        assert_eq!(log["entries"].as_array().expect("entries array").len(), 0);
        let notes = log["notes"].as_array().expect("notes array");
        assert!(notes.iter().any(|note| {
            note.as_str().is_some_and(|note| note.contains("floaty"))
                && note
                    .as_str()
                    .is_some_and(|note| note.contains("could not name"))
        }));
    }

    #[test]
    fn the_proxy_honest_refusals_ride_the_log_as_notes() {
        // A dropped event or an unresolvable real module never hides
        // inside a clean-looking log.
        let runner = WineRunner::new(std::path::Path::new("/tmp/calxgen-px-notes"));
        let notes = vec![String::from(
            "proxy: the real module 'fixture_target.real.dll' for export 'x' cannot be found \
             beside this proxy; the call will answer zero and record nothing",
        )];
        let log = runner.px_capture_log("fixture_target.dll", &[], &notes);
        let stated = log["notes"].as_array().expect("notes array");
        assert!(stated.iter().any(|note| {
            note.as_str()
                .is_some_and(|note| note.contains("may be short of the calls that arrived"))
        }));
    }

    #[test]
    fn the_template_names_the_probe_honoring_the_capture_bound() {
        // The proxy's probe reads through VirtualQuery and keeps only a
        // committed readable region, never more than the bound.
        let generated = generation();
        assert!(generated.source.contains("VirtualQuery"), "probe missing");
        assert!(
            generated.source.contains("CALX_PX_CAPTURE_BOUND"),
            "the bound is never read"
        );
        assert!(
            generated.source.contains("px_note"),
            "honest refusal missing"
        );
    }

    #[test]
    fn an_empty_log_assembles_with_nothing_to_fold() {
        let runner = WineRunner::new(std::path::Path::new("/tmp/calxgen-px-empty"));
        let log = runner.px_capture_log("fixture_target.dll", &[], &[]);
        assert_eq!(log["entries"].as_array().expect("entries array").len(), 0);
        assert!(log.get("notes").is_none());
    }
}
