//! The minidump lane (P23.7): crash dumps folded into filed crash
//! reproductions.
//!
//! A Windows minidump is a binary record of one moment in a process's
//! life: the modules it had loaded, the threads it had running, and —
//! when the dump was taken by a crash handler — the exception that
//! broke the process, with the faulting thread's machine context on
//! top of it. This lane mines that moment for what the record-and-
//! replay fold can act on.
//!
//! The mining has one honest constraint. A dump proves a call
//! *happened* — the arguments it left in registers, on the stack, in
//! captured memory — but it never proves *which* function received
//! them, and a dump stores no code. So a vector is reconstructible
//! only where a target binary's own exports supply both halves of the
//! picture: the module identity the dump names matches the binary's,
//! and the fault address lands **exactly on a target export entry**.
//! Anything else is a mapping candidate the lane claims nothing for;
//! the count is stated, never folded silently.
//!
//! What a matching fault gives the lane: the faulting thread's
//! context as evidence, the arguments the x64 calling convention left
//! in place reconstructed against the export's signature, and a
//! replayable case — folded through the same
//! [`fold_capture_event_log`] machinery the capture ingest path
//! uses, so the fold refuses what it cannot replay (a float
//! argument, an over-bound pointer capture, an address the dump
//! never held, a stack cut off before its arguments, a vector the
//! signature does not carry) with the reason named, and files the
//! crash reproduction it can replay. The dump's digest names the
//! capture; the thread id names the event; the case's origin names
//! the fault address too.
//!
//! ELF cores are out of scope, and managed (.NET) PEs stay parked
//! with their own minidump story (ADR-0044).
//!
//! [`fold_capture_event_log`]: crate::record_replay::fold_capture_event_log

mod reader;
#[cfg(test)]
mod tests;

use std::path::Path;

use anyhow::{Context as _, Result, bail};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use calxgloss_types::{ArgumentDescriptor, CaptureEvidence, CaptureLane, Export};

use crate::ffi::parse_signature;
use crate::generator::TestGenerator;
use crate::pe::PeImage;
use crate::record_replay::{MineReport, Replay, fold_capture_event_log};
pub use reader::{AMD64, Minidump, MinidumpException, MinidumpModule, MinidumpThread, X64Context};

/// What one dump folded into: its digest — the identity every record
/// the fold files under it carries — the fold's own count report, and
/// the number of fault pictures the lane declined to claim.
#[derive(Debug)]
pub struct MinidumpFolded {
    pub digest: String,
    pub report: MineReport,
    /// The `capture_refused`/`crash_reproduction` records the fold
    /// named — the CLI files them into the binary's unknown ledger.
    pub unknown_records: Vec<calxgloss_types::UnknownRecord>,
    /// Baseline suites the fold filed, per export, as the capture
    /// fold reports them.
    pub filed: Vec<(String, String, Vec<calxgloss_types::TestResult>)>,
    pub candidates_unclaimed: usize,
    /// Why a declined candidate was declined, stated for the count
    /// report — never folded silently.
    pub candidate_reason: Option<String>,
}

/// Fold a set of crash dumps against their target binary: each dump
/// parsed on its own bytes, matched to the binary by module identity,
/// and folded through the record-and-replay fold — capture id being
/// the dump's SHA-256 digest, event sequence the faulting thread's
/// id. A file that is not a minidump is refused by name; an ELF core
/// is said to be out of scope.
///
/// `exports` is the target's export listing — the same listing the
/// capture lane checks events against, with Kuna's prototype lines —
/// and `replay` says how the reconstructed vectors get replayed: the
/// live harness, or fake where the environment cannot run the target.
pub async fn fold_minidumps(
    generator: &TestGenerator,
    binary: &str,
    dll: &Path,
    exports: &[Export],
    dumps: &[&Path],
    replay: &Replay<'_>,
) -> Result<Vec<MinidumpFolded>> {
    let pe = PeImage::parse(dll)
        .with_context(|| format!("{binary}: the target's current bytes never parsed"))?;
    let mut folded = Vec::with_capacity(dumps.len());
    for path in dumps {
        let bytes = std::fs::read(path)
            .with_context(|| format!("{}: cannot read the dump", path.display()))?;
        folded.push(
            fold_dump_bytes(generator, binary, &pe, exports, &bytes, replay)
                .await
                .with_context(|| format!("{}", path.display()))?,
        );
    }
    Ok(folded)
}

/// Fold one dump's bytes. Separated from the file loop so a test can
/// feed a hand-assembled dump straight in.
async fn fold_dump_bytes(
    generator: &TestGenerator,
    binary: &str,
    pe: &PeImage,
    exports: &[Export],
    bytes: &[u8],
    replay: &Replay<'_>,
) -> Result<MinidumpFolded> {
    let dump = Minidump::parse_bytes(bytes)?;
    let digest = dump_digest(bytes);

    if let Some(architecture) = dump.processor_architecture.filter(|a| *a != AMD64) {
        bail!(
            "dump names processor architecture {architecture}; the minidump lane mines \
             AMD64 dumps"
        );
    }

    let mut folded = MinidumpFolded {
        digest: digest.clone(),
        report: MineReport::default(),
        unknown_records: Vec::new(),
        filed: Vec::new(),
        candidates_unclaimed: 0,
        candidate_reason: None,
    };

    // The claim gate: module identity, an exception, and a fault that
    // lands exactly on a target export entry. Everything else is a
    // mapping candidate the lane states and declines.
    let claim = match examine_dump(pe, binary, exports, &dump) {
        Ok(claim) => claim,
        Err(reason) => {
            folded.candidates_unclaimed = 1;
            folded.candidate_reason = Some(reason);
            return Ok(folded);
        }
    };

    // The one entry this dump contributes to the log: the faulting
    // thread's reconstructed vector, carrying the dump's evidence.
    let (export, thread, context, exception) = claim;
    let reconstruction = reconstruct_entry(&dump, thread, context, &export);

    let mut entry = json!({
        "binary": binary,
        "export": export.name,
        "lane": CaptureLane::Minidump,
        "evidence": CaptureEvidence::DumpThread {
            dump_digest: digest.clone(),
            thread_id: exception.thread_id,
            fault_address: exception.fault_address,
        },
        "truncated_stack": matches!(&reconstruction, Err(Failure::TruncatedStack)),
    });
    match &reconstruction {
        Ok(arguments) => entry["arguments"] = json!(arguments),
        // A vector the signature does not carry, or a stack cut off
        // before its slots, enters the log with an empty vector — too
        // few arguments for any signature that needs them — so the
        // fold itself names the refusal against its own checks. The
        // lane's own read on why the vector could not be filled goes
        // to the log.
        Err(failure) => {
            if let Failure::Shape(reason) = failure {
                tracing::debug!(dump = %folded.digest, reason, "the dump cannot fill this signature");
            }
            entry["arguments"] = json!([]);
        }
    }

    let log = json!({
        "capture_id": digest,
        "entries": [entry],
    });
    let fold = fold_capture_event_log(generator, binary, exports, &log, replay).await?;
    folded.report = fold.report;
    folded.unknown_records = fold.unknown_records;
    folded.filed = fold.filed;
    Ok(folded)
}

/// What a claim requires: the dump's module list names the target by
/// identity, the dump carries an exception, its fault lands inside
/// that module's mapped range and exactly on a listed export's entry,
/// and the faulting thread's machine context is there to read. The
/// reason it declines says which half was missing.
fn examine_dump<'dump>(
    pe: &PeImage,
    binary: &str,
    exports: &[Export],
    dump: &'dump Minidump,
) -> Result<
    (
        Export,
        &'dump MinidumpThread,
        &'dump X64Context,
        &'dump reader::MinidumpException,
    ),
    String,
> {
    let exception = dump
        .exception()
        .ok_or_else(|| "the dump carries no exception stream".to_string())?;
    let module = dump
        .modules()
        .iter()
        .find(|module| module_identity_matches(pe, binary, module))
        .ok_or_else(|| {
            format!("the dump names no module matching the target `{binary}` by identity")
        })?;
    if exception.fault_address < module.base_of_image
        || exception.fault_address >= module.base_of_image + u64::from(module.size_of_image)
    {
        return Err(format!(
            "the fault at {:#x} lands outside the matched module's mapped range",
            exception.fault_address
        ));
    }
    let fault_rva = exception.fault_address - module.base_of_image;
    // A listing addresses its exports either as RVAs or as VAs at the
    // preferred image base (Kuna's convention); both spell the same
    // entry. A near miss matches neither and claims nothing.
    let export = exports.iter().find(|export| {
        !export.name.is_empty()
            && (export.address == fault_rva
                || export.address.wrapping_sub(pe.image_base()) == fault_rva)
    });
    if let Some(export) = export {
        let export = export.clone();
        let thread = dump.thread(exception.thread_id).ok_or_else(|| {
            format!(
                "the dump's exception names thread {}, which its thread list does not carry",
                exception.thread_id
            )
        })?;
        let context = exception
            .context
            .as_ref()
            .or(thread.context.as_ref())
            .ok_or_else(|| {
                format!(
                    "the dump carries no machine context for the faulting thread {}",
                    exception.thread_id
                )
            })?;
        return Ok((export, thread, context, exception));
    }
    Err(format!(
        "the fault at {:#x} lands at rva {fault_rva:#x}, not exactly on a target export entry",
        exception.fault_address
    ))
}

/// Whether a dump's module matches the target: the same file name
/// (the dump stores the loaded path; the harness names the file), the
/// same mapped size, and the same timestamp — the identity a capture
/// entry must record to be taken at face value.
fn module_identity_matches(pe: &PeImage, binary: &str, module: &MinidumpModule) -> bool {
    !binary.is_empty()
        && module.basename() == binary.to_ascii_lowercase()
        && module.size_of_image == pe.size_of_image()
        && module.time_date_stamp == pe.time_date_stamp()
}

fn dump_digest(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let sum = hasher.finalize();
    let hex: String = sum.iter().map(|byte| format!("{byte:02x}")).collect();
    format!("sha256:{hex}")
}

/// Why a faulting thread's vector could not be reconstructed at all.
enum Failure {
    /// The dump's stack capture stops before the signature's stack
    /// argument slots — the vector's later arguments never arrived.
    TruncatedStack,
    /// The signature gives the vector a shape the dump cannot fill:
    /// a stack slot its memory does not hold, or similar. The reason
    /// is stated in the string.
    Shape(String),
}

/// The captured memory a vector reads through: the faulting thread's
/// own stack region first, then the dump's memory list. A dump keeps
/// thread stacks inside the thread list, not the memory list, and both
/// are memory the crash really had.
struct Captures<'a> {
    dump: &'a Minidump,
    stack: (u64, &'a [u8]),
}

impl Captures<'_> {
    /// The captured bytes from `va` to the end of the region that
    /// holds it — the widest window the dump can honestly state.
    fn window(&self, va: u64) -> Option<&[u8]> {
        let (start, bytes) = self.stack;
        let end = start.checked_add(bytes.len() as u64)?;
        if va >= start && va < end {
            return Some(&bytes[(va - start) as usize..]);
        }
        self.dump.memory_window(va)
    }
}

/// The vector a matching fault implies, reconstructed from the
/// faulting thread's machine context against the export's signature:
/// the x64 calling convention's first four arguments in `[rcx, rdx,
/// r8, r9]`, the rest in stack slots above the shadow space, read
/// through the dump's own captured memory; pointer targets read under
/// the shared capture-sizing rule ([`ArgumentDescriptor::captured_pointer`]).
///
/// A dump says where things were, never how big they were: a pointer
/// target's captured size is the memory the dump holds from that
/// address, and anything the bound cannot carry whole comes out
/// stamped truncated for the fold to refuse. Float parameters emit
/// float-tagged scalars the fold refuses with `float-argument` —
/// never re-encoded into some other shape that would mis-arrive.
fn reconstruct_entry(
    dump: &Minidump,
    thread: &MinidumpThread,
    context: &X64Context,
    export: &Export,
) -> Result<Vec<Value>, Failure> {
    let parsed = parse_signature(&export.signature)
        .map_err(|error| Failure::Shape(format!("the export signature does not parse: {error}")))?;
    let registers = [context.rcx, context.rdx, context.r8, context.r9];
    let (stack_start, stack) = thread.stack();
    let captures = Captures {
        dump,
        stack: (stack_start, stack),
    };

    // Does the captured stack reach the first stack-argument slot?
    // A signature asking for slots the capture fell short of is a
    // truncation the dump states, not a vector to guess at. At an
    // entry's first instruction `rsp` points at the return address,
    // so the fifth argument's slot sits at `rsp + 0x28` — the 32-byte
    // shadow space plus the pushed return address.
    let needs_slots = parsed.parameters.len().saturating_sub(4);
    let reaches_slots = !stack.is_empty()
        && context.rsp >= stack_start
        && stack_start.saturating_add(stack.len() as u64)
            >= context.rsp.saturating_add(0x28 + 8 * needs_slots as u64);
    if needs_slots > 0 && !reaches_slots {
        return Err(Failure::TruncatedStack);
    }

    let mut arguments = Vec::with_capacity(parsed.parameters.len());
    for (index, parameter) in parsed.parameters.iter().enumerate() {
        let slot_value = match registers.get(index) {
            Some(value) => *value,
            None => {
                let offset = (index - 4) as u64 * 8;
                let at = context
                    .rsp
                    .checked_add(0x28)
                    .and_then(|base| base.checked_add(offset));
                match at.and_then(|va| captures.window(va)) {
                    Some(window) if window.len() >= 8 => {
                        let mut slot = [0u8; 8];
                        slot.copy_from_slice(&window[..8]);
                        u64::from_le_bytes(slot)
                    }
                    _ => {
                        return Err(Failure::Shape(format!(
                            "the dump's memory does not hold stack slot {index} of {}",
                            export.name
                        )));
                    }
                }
            }
        };
        arguments.push(reconstruct_argument(&captures, parameter, slot_value));
    }
    Ok(arguments)
}

/// One argument, shaped by its signature entry, emitted as the raw
/// JSON the fold scans — raw rather than typed so a float tag can
/// appear at all (the typed vocabulary carries no floats, and the
/// fold's float scan happens before any typed decode).
fn reconstruct_argument(
    captures: &Captures<'_>,
    parameter: &crate::ffi::ParameterTypeInfo,
    slot_value: u64,
) -> Value {
    if parameter.r#type.contains("float") || parameter.r#type.contains("double") {
        let tag = if parameter.r#type.contains("double") {
            "f64"
        } else {
            "f32"
        };
        return json!({"scalar": {"tag": tag, "value": null}});
    }
    if parameter.is_pointer {
        let descriptor = match captures.window(slot_value) {
            // The dump holds bytes at the address: size what it holds
            // under the shared capture-sizing rule. A region wider
            // than the bound comes out truncated — a dump can never
            // prove a target fits under the bound.
            Some(window) => ArgumentDescriptor::captured_pointer(window.len() as u64, window),
            // Nothing there: a pointer the replay has nothing to
            // materialize, refused by the fold with the reason named.
            None => ArgumentDescriptor::Pointer {
                bytes: Vec::new(),
                captured_size: 0,
                truncated: false,
            },
        };
        return json!(descriptor);
    }
    // A scalar parameter whose shape the signature never stated gets
    // the default 32-bit tag the fold declares for it: the fold's own
    // signature fit still refuses a width or sign it cannot match,
    // with `argument-shape-not-in-signature` named.
    let width = parameter.bit_width.unwrap_or(32);
    let tag: ArgumentDescriptor = match (width, parameter.is_signed) {
        (8, true) => ArgumentDescriptor::Scalar {
            tag: calxgloss_types::ScalarTag::I8,
            value: json!((slot_value as u8) as i8),
        },
        (8, false) => ArgumentDescriptor::Scalar {
            tag: calxgloss_types::ScalarTag::U8,
            value: json!(slot_value & 0xFF),
        },
        (16, true) => ArgumentDescriptor::Scalar {
            tag: calxgloss_types::ScalarTag::I16,
            value: json!((slot_value as u16) as i16),
        },
        (16, false) => ArgumentDescriptor::Scalar {
            tag: calxgloss_types::ScalarTag::U16,
            value: json!(slot_value & 0xFFFF),
        },
        (32, true) => ArgumentDescriptor::Scalar {
            tag: calxgloss_types::ScalarTag::I32,
            value: json!((slot_value as u32) as i32),
        },
        (32, false) => ArgumentDescriptor::Scalar {
            tag: calxgloss_types::ScalarTag::U32,
            value: json!(slot_value & 0xFFFF_FFFF),
        },
        (_, true) => ArgumentDescriptor::Scalar {
            tag: calxgloss_types::ScalarTag::I64,
            value: json!(slot_value),
        },
        (_, false) => ArgumentDescriptor::Scalar {
            tag: calxgloss_types::ScalarTag::U64,
            value: json!(slot_value),
        },
    };
    json!(tag)
}
